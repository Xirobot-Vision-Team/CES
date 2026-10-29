#!/usr/bin/env python3
"""Read actual cgroup v2 counters for an EC256 *durably bound* OCI scope.

The read is intentionally narrower than generic container telemetry: a
successful result requires the signed lease's recorded kernel boot, full OCI
ID, cgroup path, device and inode to remain intact. All paths and filenames
are fixed by the host and opened with O_NOFOLLOW. In strict EC257 mode there
is no fallback to Podman stats, a container name, /proc PID sums, or zeros for
unavailable counters.

These are local kernel observations, NOT independent remote attestation or
proof that the container obeyed its isolation policy.
"""
from __future__ import annotations

import os
import re
import stat
from typing import Any

from ec256_cgroup_reaper import supervisor as cg
import quality_run_budget as budget

MAX_INTEGER = 2**63 - 1
MAX_FILE = 65536
DEVICE = re.compile(rb'[0-9]+:[0-9]+\Z')
FIELD = re.compile(rb'[a-z][a-z0-9_]*\Z')
DECIMAL = re.compile(rb'(?:0|[1-9][0-9]*)\Z')


class KernelMetricError(cg.CgroupError):
    pass


def require(value: bool, reason: str) -> None:
    if not value:
        raise KernelMetricError('CGROUP257_' + reason)


def _decimal(raw: bytes) -> int:
    require(bool(DECIMAL.fullmatch(raw)) and len(raw) <= 19,
            'COUNTER_FORMAT_INVALID')
    number = int(raw)
    require(number <= MAX_INTEGER, 'COUNTER_OVERFLOW')
    return number


def _file(dirfd: int, name: str) -> bytes:
    """Read a fixed cgroup kernfs file using the preverified directory fd."""
    require(name in ('cpu.stat', 'memory.peak', 'pids.peak', 'io.stat'),
            'COUNTER_FILE_NOT_APPROVED')
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=dirfd)
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode), 'COUNTER_NOT_FILE')
            raw = os.read(fd, MAX_FILE + 1)
            require(len(raw) <= MAX_FILE, 'COUNTER_OVERSIZED')
            return raw
        finally:
            os.close(fd)
    except KernelMetricError:
        raise
    except OSError as exc:
        raise KernelMetricError('CGROUP257_COUNTER_UNAVAILABLE_' +
                                name.replace('.', '_').upper()) from exc


def _peak(dirfd: int, name: str) -> int:
    raw = _file(dirfd, name)
    # Kernel counter files have precisely one decimal line; no 'max', JSON,
    # extra text, negative values or fabricated zero for an absent file.
    require(raw.endswith(b'\n') and raw.count(b'\n') == 1,
            'PEAK_FILE_FORMAT_INVALID')
    return _decimal(raw[:-1])


def _cpu(dirfd: int) -> int:
    fields: dict[bytes, int] = {}
    raw = _file(dirfd, 'cpu.stat')
    require(bool(raw) and raw.endswith(b'\n'), 'CPU_STAT_TRUNCATED')
    for line in raw.splitlines():
        parts = line.split()
        require(len(parts) == 2 and FIELD.fullmatch(parts[0]) is not None and
                parts[0] not in fields, 'CPU_STAT_INVALID')
        fields[parts[0]] = _decimal(parts[1])
    require(b'usage_usec' in fields, 'CPU_USAGE_MISSING')
    return fields[b'usage_usec'] // 1000


def _io(dirfd: int) -> int:
    """Sum blkdev rbytes+wbytes; empty io.stat is a legitimate kernel zero."""
    total = 0
    seen: set[bytes] = set()
    raw = _file(dirfd, 'io.stat')
    require(not raw or raw.endswith(b'\n'), 'IO_STAT_TRUNCATED')
    for line in raw.splitlines():
        parts = line.split()
        require(len(parts) >= 3 and DEVICE.fullmatch(parts[0]) is not None and
                parts[0] not in seen, 'IO_STAT_DEVICE_INVALID')
        seen.add(parts[0])
        fields: dict[bytes, int] = {}
        for part in parts[1:]:
            key, separator, value = part.partition(b'=')
            require(bool(separator) and FIELD.fullmatch(key) is not None and
                    key not in fields, 'IO_STAT_FIELD_INVALID')
            fields[key] = _decimal(value)
        require(b'rbytes' in fields and b'wbytes' in fields,
                'IO_STAT_REQUIRED_FIELDS_MISSING')
        total += fields[b'rbytes'] + fields[b'wbytes']
        require(total <= MAX_INTEGER, 'IO_STAT_OVERFLOW')
    return total


def _last(previous: dict[str, int]) -> dict[str, int]:
    require(type(previous) is dict and set(previous) == budget.RESOURCE_KEYS and
            all(type(x) is int and 0 <= x <= MAX_INTEGER
                for x in previous.values()), 'PREVIOUS_SAMPLE_INVALID')
    return previous


def validate_sample(sample: dict[str, Any], *, previous: dict[str, int]
                    ) -> dict[str, int]:
    """Validate a worker's final IPC sample before accepting it as a receipt."""
    _last(previous)
    require(type(sample) is dict and set(sample) == budget.RESOURCE_KEYS and
            all(type(v) is int and 0 <= v <= MAX_INTEGER for v in sample.values()),
            'WORKER_SAMPLE_INVALID')
    merged = {key: max(sample[key], previous[key])
              for key in budget.RESOURCE_KEYS}
    require(all(merged[k] <= budget.HARD_CEILINGS[k] for k in merged),
            'RESOURCE_LIMIT_EXCEEDED')
    return merged


def sample(container_id: str, durable_event: dict[str, Any],
           output_total: int, previous: dict[str, int]) -> dict[str, int]:
    """Return monotonic peak counters from precisely one bound OCI cgroup.

    cpu.stat: cumulative usage_usec (ms); memory.peak: memory high watermark;
    pids.peak: process high watermark; io.stat: all blkdev rbytes+wbytes.
    Count observed stdout/stderr bytes *in addition* to storage IO as a
    conservative local budget gate; never substitute an invented counter.
    """
    _last(previous)
    require(type(output_total) is int and 0 <= output_total <= MAX_INTEGER,
            'OUTPUT_METER_INVALID')
    record = cg._recorded(container_id, durable_event)
    cg._mount_root()
    require(cg._boot_id() == record.boot_id, 'BOOT_CHANGED')
    fd = cg._directory(record.cgroup_path, container_id)
    try:
        stat_before = os.fstat(fd)
        require((stat_before.st_dev, stat_before.st_ino) ==
                (record.cgroup_dev, record.cgroup_ino), 'CGROUP_INODE_CHANGED')
        cpu_ms = _cpu(fd)
        mem = _peak(fd, 'memory.peak')
        pids = _peak(fd, 'pids.peak')
        io = _io(fd)
        require(io + output_total <= MAX_INTEGER, 'IO_PLUS_OUTPUT_OVERFLOW')
        stat_after = os.fstat(fd)
        require((stat_after.st_dev, stat_after.st_ino) ==
                (record.cgroup_dev, record.cgroup_ino) and
                cg._boot_id() == record.boot_id, 'CGROUP_CHANGED_DURING_SAMPLE')
    finally:
        os.close(fd)
    current = {'cpu_ms': cpu_ms, 'memory_peak_bytes': mem,
               'processes': pids, 'io_bytes': io + output_total}
    # A trusted kernel stat file may be internally non-atomic with other
    # kernfs reads; each of these counters is monotonic within a cgroup.
    require(all(current[k] >= previous[k] for k in current),
            'KERNEL_COUNTER_REGRESSED')
    return validate_sample(current, previous=previous)
