#!/usr/bin/env python3
"""EC256: fail-closed, host-owned cgroup v2 process-tree reaper.

Only the fixed, signed EC253/EC255 Podman lease path may request this
supervisor. It first binds the full Podman ID+lease label to an actual
Linux /proc/<init-pid>/cgroup v2 directory and durable journal receipt.
To stop a live group it writes cgroup.kill and waits for populated=0,
then callers may remove the independently verified full OCI ID.

Podman and the host kernel are not independent remote attestations.
Non-delegated, non-v2 and differently laid-out hosts are refused rather
than falling back to `kill(pid)` or pretending to have killed a tree.
"""
from __future__ import annotations

import os
import re
import stat
import time
from dataclasses import dataclass
from typing import Any, Callable

from quality_run_host import broker as runner
from oci_identity import binding

CGROUP_MOUNT = '/sys/fs/cgroup'
BOOT_ID_PATH = '/proc/sys/kernel/random/boot_id'
MOUNTINFO_PATH = '/proc/self/mountinfo'
CGROUP_REAP_SECONDS = 3.0
BIND_SCHEMA = 'ces.ec256.cgroup_v2_binding.v1'
BOOT = re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z')
CGRP_LINE = re.compile(r'0::(/[^\r\n]*)\Z')
CGROUP_COMPONENT = re.compile(r'[a-zA-Z0-9_.@:-]{1,255}\Z')
PODMAN_STATE = re.compile(r'([0-9]{1,10})\|(true|false)\Z')


class CgroupError(runner.HostRunError):
    pass


def need(condition: bool, code: str) -> None:
    if not condition:
        raise CgroupError('CGROUP256_' + code)


def _bounded_read(path: str, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw = os.read(fd, maximum + 1)
        need(len(raw) <= maximum, 'KERNEL_FILE_OVERSIZED')
        return raw
    finally:
        os.close(fd)


def _boot_id() -> str:
    try:
        text = _bounded_read(BOOT_ID_PATH, 64).decode('ascii').strip()
        need(BOOT.fullmatch(text) is not None, 'BOOT_ID_INVALID')
        return text
    except (OSError, UnicodeError) as exc:
        raise CgroupError('CGROUP256_BOOT_ID_UNAVAILABLE') from exc


def _mount_root() -> None:
    """Accept only the original host's cgroup2 fs at /sys/fs/cgroup.

    A containerized or namespaced broker with a partial/subtree mount is
    deliberately unsupported. Mountinfo is inspected on every new bind.
    """
    try:
        raw = _bounded_read(MOUNTINFO_PATH, 1024 * 1024).decode('ascii')
        hits = []
        for row in raw.splitlines():
            left, sep, right = row.partition(' - ')
            need(bool(sep), 'MOUNTINFO_INVALID')
            a, b = left.split(), right.split()
            if len(a) >= 5 and len(b) >= 1 and a[4] == CGROUP_MOUNT:
                hits.append((a[3], b[0]))
        need(hits == [('/', 'cgroup2')], 'ROOT_CGROUP2_MOUNT_REQUIRED')
        fd = os.open(CGROUP_MOUNT, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(stat.S_ISDIR(os.fstat(fd).st_mode), 'CGROUP_MOUNT_INVALID')
            _bounded_read('/proc/self/cgroup', 4096)
        finally:
            os.close(fd)
    except CgroupError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise CgroupError('CGROUP256_MOUNT_UNAVAILABLE') from exc


def _path_for_pid(pid: int) -> str:
    need(type(pid) is int and 1 < pid < 2**31, 'PID_INVALID')
    try:
        text = _bounded_read(f'/proc/{pid}/cgroup', 4096).decode('ascii').strip()
    except (OSError, UnicodeError) as exc:
        raise CgroupError('CGROUP256_PID_CGROUP_UNAVAILABLE') from exc
    match = CGRP_LINE.fullmatch(text)
    need(match is not None, 'PID_NOT_IN_SINGLE_CGROUP2')
    return match.group(1)


def _validated_path(path: str, container_id: str) -> list[str]:
    """Rooted, no-traversal, exact libpod ID scope; never broker's own tree."""
    need(type(container_id) is str and
         binding.FULL_ID.fullmatch(container_id) is not None, 'ID_INVALID')
    need(type(path) is str and path.startswith('/') and
         len(path) <= 4096 and '//' not in path and
         not path.endswith('/'), 'PATH_INVALID')
    components = path[1:].split('/')
    need(len(components) >= 2 and
         all(c not in ('', '.', '..') and CGROUP_COMPONENT.fullmatch(c)
             for c in components), 'PATH_COMPONENT_INVALID')
    need(components[-1] in ('libpod-' + container_id,
                            'libpod-' + container_id + '.scope') and
         sum(c in ('libpod-' + container_id,
                   'libpod-' + container_id + '.scope')
             for c in components) == 1,
         'PATH_NOT_FULL_CONTAINER_SCOPE')
    own_path = _path_for_pid(os.getpid())
    need(not (own_path == path or own_path.startswith(path + '/')),
         'WOULD_KILL_BROKER')
    return components


def _scope_for_pid(pid_path: str, container_id: str) -> str:
    """Select the OCI scope ancestor, not an arbitrary descendant cgroup.

    Killing an init PID's leaf group could leave sibling worker cgroups alive.
    A single exact libpod-ID scope is therefore mandatory.
    """
    need(type(pid_path) is str and pid_path.startswith('/') and
         len(pid_path) <= 4096 and '//' not in pid_path and
         not pid_path.endswith('/'), 'PID_CGROUP_PATH_INVALID')
    parts = pid_path[1:].split('/')
    need(all(c not in ('', '.', '..') and CGROUP_COMPONENT.fullmatch(c)
             for c in parts), 'PID_CGROUP_PATH_INVALID')
    identity = ('libpod-' + container_id, 'libpod-' + container_id + '.scope')
    matches = [i for i, c in enumerate(parts) if c in identity]
    need(len(matches) == 1, 'PID_NOT_IN_UNIQUE_LIBPOD_SCOPE')
    scope = '/' + '/'.join(parts[:matches[0] + 1])
    _validated_path(scope, container_id)
    return scope


def _pid_starttime(pid: int) -> int:
    """Kernel proc stat field 22; check it twice to reject PID reuse/races."""
    try:
        raw = _bounded_read(f'/proc/{pid}/stat', 2048)
        pivot = raw.rfind(b') ')
        need(pivot > 0 and raw[:pivot].split(b' (', 1)[0] ==
             str(pid).encode('ascii'), 'PID_STAT_INVALID')
        columns = raw[pivot + 2:].split()
        need(len(columns) >= 20 and columns[0] not in (b'Z', b'X'),
             'PID_EXITED')
        value = int(columns[19])
        need(value > 0, 'PID_STARTTIME_INVALID')
        return value
    except CgroupError:
        raise
    except (OSError, ValueError, OverflowError) as exc:
        raise CgroupError('CGROUP256_PID_STAT_UNAVAILABLE') from exc


@dataclass(frozen=True)
class Binding:
    schema: str
    container_id: str
    boot_id: str
    cgroup_path: str
    cgroup_dev: int
    cgroup_ino: int
    pid_starttime: int

    def journal_event(self) -> dict[str, Any]:
        return {'event': 'cgroup_bound', 'boot_id': self.boot_id,
                'cgroup_path': self.cgroup_path, 'cgroup_dev': self.cgroup_dev,
                'cgroup_ino': self.cgroup_ino, 'pid_starttime': self.pid_starttime}


def _directory(path: str, container_id: str) -> int:
    parts = _validated_path(path, container_id)
    try:
        fd = os.open(CGROUP_MOUNT, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        root_dev = os.fstat(fd).st_dev
        try:
            for part in parts:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = nxt
                need(os.fstat(fd).st_dev == root_dev,
                     'CGROUP_CROSSES_FILESYSTEM')
            st = os.fstat(fd)
            need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid(),
                 'CGROUP_NOT_DELEGATED_TO_HOST_UID')
            return fd
        except Exception:
            os.close(fd)
            raise
    except CgroupError:
        raise
    except FileNotFoundError as exc:
        raise CgroupError('CGROUP256_CGROUP_DIRECTORY_ABSENT') from exc
    except OSError as exc:
        raise CgroupError('CGROUP256_CGROUP_DIRECTORY_UNAVAILABLE') from exc


def _populated(directory_fd: int) -> bool:
    try:
        fd = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=directory_fd)
        try:
            raw = os.read(fd, 1025)
        finally:
            os.close(fd)
        need(len(raw) <= 1024, 'EVENTS_OVERSIZED')
        values = [line.split() for line in raw.splitlines()]
        hits = [pair[1] for pair in values
                if len(pair) == 2 and pair[0] == b'populated']
        need(len(hits) == 1 and hits[0] in (b'0', b'1'), 'EVENTS_INVALID')
        return hits[0] == b'1'
    except CgroupError:
        raise
    except OSError as exc:
        raise CgroupError('CGROUP256_EVENTS_UNAVAILABLE') from exc


def _kill(directory_fd: int) -> None:
    try:
        fd = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=directory_fd)
        try:
            need(os.write(fd, b'1') == 1, 'KILL_SHORT_WRITE')
        finally:
            os.close(fd)
    except CgroupError:
        raise
    except OSError as exc:
        raise CgroupError('CGROUP256_KILL_NOT_DELEGATED') from exc
    until = time.monotonic() + CGROUP_REAP_SECONDS
    while _populated(directory_fd):
        need(time.monotonic() < until, 'GROUP_STILL_POPULATED')
        time.sleep(0.04)


def _state(pol: dict[str, Any], container_id: str) -> tuple[bool, int]:
    result = runner._run_command(
        pol, ['container', 'inspect', '--format',
              '{{.State.Pid}}|{{.State.Running}}', container_id],
        timeout=runner.MAX_CLEANUP_SECONDS, limit=1024)
    need(result.exit_code == 0 and len(result.stdout) <= 80,
         'PODMAN_STATE_UNAVAILABLE')
    try:
        match = PODMAN_STATE.fullmatch(result.stdout.decode('ascii').strip())
    except UnicodeError as exc:
        raise CgroupError('CGROUP256_PODMAN_STATE_INVALID') from exc
    need(match is not None, 'PODMAN_STATE_INVALID')
    pid = int(match.group(1))
    running = match.group(2) == 'true'
    need((running and 1 < pid < 2**31) or
         (not running and pid == 0), 'PODMAN_STATE_PID_CONFLICT')
    return running, pid


def _recorded(container_id: str, event: dict[str, Any]) -> Binding:
    keys = {'event', 'boot_id', 'cgroup_path', 'cgroup_dev',
            'cgroup_ino', 'pid_starttime'}
    need(type(event) is dict and set(event) == keys and
         event.get('event') == 'cgroup_bound' and
         type(event.get('boot_id')) is str and
         BOOT.fullmatch(event['boot_id']) is not None and
         all(type(event.get(k)) is int and event[k] > 0
             for k in ('cgroup_dev', 'cgroup_ino', 'pid_starttime')),
         'JOURNAL_CGROUP_BINDING_INVALID')
    _validated_path(event['cgroup_path'], container_id)
    return Binding(BIND_SCHEMA, container_id, event['boot_id'],
                   event['cgroup_path'], event['cgroup_dev'],
                   event['cgroup_ino'], event['pid_starttime'])


def bind_live(pol: dict[str, Any], container_id: str,
              label_sha256: str) -> Binding:
    """Double-probe the actual init PID and pin its cgroup identity."""
    _mount_root()
    binding.verify(pol, container_id, label_sha256)
    running, pid = _state(pol, container_id)
    need(running, 'CONTAINER_NOT_RUNNING_FOR_BIND')
    before = _pid_starttime(pid)
    pid_path = _path_for_pid(pid)
    path = _scope_for_pid(pid_path, container_id)
    fd = _directory(path, container_id)
    try:
        st = os.fstat(fd)
        need(_populated(fd), 'LIVE_GROUP_EMPTY')
        # Require ability to arm full-tree kill now, not after a timeout.
        try:
            kill_fd = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW |
                              os.O_CLOEXEC, dir_fd=fd)
        except OSError as exc:
            raise CgroupError('CGROUP256_KILL_NOT_DELEGATED') from exc
        else:
            os.close(kill_fd)
    finally:
        os.close(fd)
    need(_pid_starttime(pid) == before and
         _path_for_pid(pid) == pid_path and
         _state(pol, container_id) == (True, pid),
         'PID_OR_CGROUP_CHANGED_DURING_BIND')
    binding.verify(pol, container_id, label_sha256)
    return Binding(BIND_SCHEMA, container_id, _boot_id(),
                   path, st.st_dev, st.st_ino, before)


def _reap_record(container_id: str, record: Binding) -> None:
    """Kill recorded same-boot tree even if Podman now says 'stopped'."""
    _mount_root()
    if record.boot_id != _boot_id():
        # A real kernel reboot kills every process from the previous boot.
        # Container status and full-ID cleanup must still be checked by caller.
        return
    try:
        fd = _directory(record.cgroup_path, container_id)
    except CgroupError as exc:
        if exc.code == 'CGROUP256_CGROUP_DIRECTORY_ABSENT':
            # A vanished *specific* cgroup directory cannot retain processes.
            return
        raise
    try:
        st = os.fstat(fd)
        need((st.st_dev, st.st_ino) == (record.cgroup_dev, record.cgroup_ino),
             'RECORDED_CGROUP_INODE_REPLACED')
        if _populated(fd):
            _kill(fd)
    finally:
        os.close(fd)


def reap_before_remove(pol: dict[str, Any], label_sha256: str, name: str,
                       container_id: str | None,
                       *, recorded: dict[str, Any] | None = None,
                       on_bound: Callable[[Binding], None] | None = None) -> None:
    """Mandatory EC256 pre-rm gate. Raises on any uncertain live process.

    If no init PID was ever observed (a create that never started, or a very
    fast exit), no 'cgroup-bound' proof is fabricated. Session begin must
    separately require a durable live bind to claim EC256 protection.
    """
    need(binding.NAME.fullmatch(name) is not None and
         binding.FULL_ID.fullmatch(label_sha256) is not None and
         (container_id is None or
          binding.FULL_ID.fullmatch(container_id) is not None),
         'REAP_INPUT_INVALID')
    _mount_root()
    previous = (_recorded(container_id, recorded)
                if recorded is not None and container_id is not None else None)
    found = binding._labels(pol, label_sha256)
    if not found:
        need(binding._absent(pol, container_id or name),
             'DISAPPEARED_CONTAINER_ID_NOT_ABSENT')
        if previous is not None:
            _reap_record(container_id, previous)
        return
    identity = found[0]
    need(container_id is None or container_id == identity,
         'LABEL_MATCHED_DIFFERENT_CONTAINER')
    binding.verify(pol, identity, label_sha256,
                   expected_name=name if container_id is None else None)
    running, _ = _state(pol, identity)
    if running:
        current = bind_live(pol, identity, label_sha256)
        if previous is not None:
            need(current == previous, 'LIVE_CGROUP_CHANGED_FROM_LEDGER')
        else:
            need(on_bound is not None, 'LIVE_CGROUP_NOT_DURABLY_BOUND')
            on_bound(current)  # fsync exact kernel tree before dangerous action
        _reap_record(identity, current)
    elif previous is not None:
        _reap_record(identity, previous)
