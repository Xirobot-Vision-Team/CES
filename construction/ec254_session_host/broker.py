#!/usr/bin/env python3
"""EC254: bounded, operator-owned EC187 session transport over EC253 leases.

A Linux nonroot AF_UNIX host verifies kernel peer UID, EC253 policy and BOTH
EC186 MACs. A single forked worker uses the original EC252 OCI profile runner.
An EC253 fsynced one-use reservation and fork watchdog MUST precede the host
`begin` acknowledgement. `poll` returns real output frames and *sampled*
Podman host telemetry; missing telemetry fails closed, never invents zeros.
`stop_and_reap` kills the worker, confirms OCI+staging recovery and responds
conservatively. Nothing in this package is independent OCI/kernel/CI proof.

No project script or shell is invoked on the host. The existing EC252/253
endpoints remain unchanged; this is a separate opt-in service and client.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import sys
import time
from typing import Any, Callable

CONSTRUCTION = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CONSTRUCTION))
from ec250_finding_host import broker as fio
from ec252_quality_run_host import broker as runner
from ec253_lease_host import broker as lease
import quality_run_budget as budget
import quality_run_guard as guard

REQUEST_SCHEMA = 'ces.ec254.quality_session_request.v1'
RESPONSE_SCHEMA = 'ces.ec254.quality_session_response.v1'
MAX_WIRE = 8192
MAX_INNER = 4096
MAX_SESSIONS = 8
MAX_FRAMES = 1024
OUT_FRAME = 1024
MAX_BEGIN_SECONDS = runner.MAX_SETUP_SECONDS * 3
MAX_STOP_SECONDS = runner.MAX_CLEANUP_SECONDS * 3
# EC252 already requests exactly these hard maxima. Smaller per-run OCI
# budgets are NOT yet supported; decline before consuming the lease.
FIXED_LIMITS = dict(budget.HARD_CEILINGS)
BEGIN_KEYS = {'schema', 'operation', 'scope_id', 'profile_id', 'source_pin_sha256',
              'profile_sha256', 'approval_receipt_sha256', 'lease_receipt_sha256',
              'image_sha256', 'lease_id', 'deadline_monotonic_ns', 'limits'}
MAX_EVENT_BYTES = 2500
# EC260 opt-in: cadence is not a bound on Git/filesystem latency.
ACTIVE_RECHECK_SECONDS = 1.0
# EC261 opt-in only: do not let a non-reading client suspend active recall
# inside sendall(), or postpone mandatory OCI/ledger cleanup on an error.
ACTIVE_EGRESS_CHUNK = 1024
ACTIVE_DENIAL_WRITE_SECONDS = 0.25
SIZE = re.compile(r'([0-9]+(?:\.[0-9]{1,3})?)(B|kB|MB|GB|KiB|MiB|GiB)?\Z')
UNITS = {'': 1, 'B': 1, 'kB': 1000, 'MB': 1000**2, 'GB': 1000**3,
         'KiB': 1024, 'MiB': 1024**2, 'GiB': 1024**3}


class SessionHostError(lease.LeaseHostError):
    pass


class SessionEgressInterrupted(SessionHostError):
    """The socket already received part of a now-incomplete response frame.

    Do NOT append an error JSON object: the peer would receive a corrupted
    stream. A transport failure must never be mistaken for a safe stop ACK.
    """


def need(ok: bool, code: str, status: str = 'unavailable') -> None:
    if not ok:
        raise SessionHostError(code, status)


def _receive(conn: socket.socket, limit: int = MAX_WIRE) -> dict[str, Any]:
    try:
        raw = fio._receive(conn, limit)
        return lease._parse(raw, limit, trusted=False)
    except (fio.HostError, socket.timeout, OSError) as exc:
        raise SessionHostError('SESSION_WIRE_INCOMPLETE') from exc


def _receive_monitored(conn: socket.socket, deadline: float,
                       recheck: Callable[[], None]) -> dict[str, Any]:
    """Read an exact bounded wire frame and revoke even while the peer is idle.

    Unlike a blocking recv, this checks signed host authority independent of
    client polling and even while an attacker trickles a partial JSON line.
    The wire format stays one JSON object terminated by one final newline.
    Only the new opt-in host uses this path; pre-EC260 hosts use _receive().
    """
    body = bytearray()
    next_check = time.monotonic()
    while True:
        now = time.monotonic()
        need(now < deadline, 'SESSION_WALL_DEADLINE')
        if now >= next_check:
            recheck()  # Failures propagate to the unconditional cleanup path.
            next_check = time.monotonic() + ACTIVE_RECHECK_SECONDS
        now = time.monotonic()
        need(now < deadline, 'SESSION_WALL_DEADLINE')
        try:
            readable, _, _ = select.select(
                [conn], [], [], max(0.0, min(next_check, deadline) - now))
        except (OSError, ValueError) as exc:
            raise SessionHostError('SESSION_MONITOR_SOCKET_UNAVAILABLE') from exc
        if not readable:
            continue
        try:
            chunk = conn.recv(min(4096, MAX_WIRE + 2 - len(body)))
        except (OSError, socket.timeout) as exc:
            raise SessionHostError('SESSION_MONITOR_WIRE_UNAVAILABLE') from exc
        need(bool(chunk), 'SESSION_CLIENT_DISCONNECTED')
        body.extend(chunk)
        need(len(body) <= MAX_WIRE + 1, 'SESSION_WIRE_TOO_LARGE', 'invalid_input')
        if b'\n' in chunk:
            need(body.endswith(b'\n') and body.count(b'\n') == 1,
                 'SESSION_WIRE_TRAILING_BYTES', 'invalid_input')
            # No disclosure can rely on a pre-frame or pre-idle proof.
            recheck()
            need(time.monotonic() < deadline, 'SESSION_WALL_DEADLINE')
            return lease._parse(bytes(body[:-1]), MAX_WIRE, trusted=False)


def _send(conn: socket.socket, body: dict[str, Any], limit: int = MAX_WIRE) -> None:
    try:
        conn.sendall(fio._wire(body, limit=limit))
    except (fio.HostError, OSError, socket.timeout) as exc:
        raise SessionHostError('SESSION_SEND_UNAVAILABLE') from exc


def _send_monitored(conn: socket.socket, body: dict[str, Any],
                    deadline: float,
                    recheck: Callable[[], None] | None) -> None:
    """EC261: bounded, nonblocking response emission with ongoing authority.

    Call `recheck` before the first success byte and on a nominal one-second
    cadence, including when the peer stops draining the socket. The absolute
    session deadline always wins; fail responses use a separate short deadline
    and intentionally have no success-authority callback. No background thread
    or queue can outlive the signed worker/lease. The original wire stays a
    single bounded JSON line. Only EC260's active strict host opts in.

    POSIX send may write part of a line; on any later denial/error we propagate
    SessionEgressInterrupted, so the caller MUST close instead of appending a
    second JSON status to the incomplete first frame.
    """
    raw = fio._wire(body, limit=MAX_WIRE)
    original_timeout = conn.gettimeout()
    written = 0
    next_check = time.monotonic()
    try:
        conn.setblocking(False)
        while written < len(raw):
            now = time.monotonic()
            need(now < deadline, 'SESSION_WALL_DEADLINE')
            if recheck is not None and now >= next_check:
                recheck()
                now = time.monotonic()
                need(now < deadline, 'SESSION_WALL_DEADLINE')
                next_check = now + ACTIVE_RECHECK_SECONDS
            now = time.monotonic()
            need(now < deadline, 'SESSION_WALL_DEADLINE')
            until = min(deadline, next_check) if recheck is not None else deadline
            _, ready, _ = select.select([], [conn], [], max(0.0, until - now))
            if not ready:
                continue  # Explicitly recheck on timer expiration/backpressure.
            need(time.monotonic() < deadline, 'SESSION_WALL_DEADLINE')
            try:
                count = conn.send(raw[written:written + ACTIVE_EGRESS_CHUNK])
            except (BlockingIOError, InterruptedError):
                continue  # A readiness hint is not a send guarantee.
            need(count > 0, 'SESSION_SEND_PEER_CLOSED')
            written += count
    except BaseException as exc:
        if written:
            # A partial JSON line cannot be repaired with another response.
            raise SessionEgressInterrupted('SESSION_PARTIAL_EGRESS_ABORTED') from exc
        if isinstance(exc, SessionHostError):
            raise  # Preserve a precise wall, policy or signed-custody denial.
        if isinstance(exc, (fio.HostError, OSError, ValueError)):
            raise SessionHostError('SESSION_SEND_UNAVAILABLE') from exc
        raise
    finally:
        # Do not alter the legacy client/session socket timeout after egress.
        try:
            conn.settimeout(original_timeout)
        except OSError:
            pass


def _reply(status: str, code: str, **fields: Any) -> dict[str, Any]:
    return {'schema': RESPONSE_SCHEMA, 'status': status, 'exit_code': lease.EXIT[status],
            'reason_code': code, 'overall_quality_pass_verified': False,
            'independent_kernel_isolation_attested': False,
            'independent_source_git_binding_attested': False,
            'enterprise_actor_authenticated': False,
            'original_router_host_required_unlocked': False,
            **fields}


def _safe_status(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, runner.HostRunError):
        return _reply(exc.status, exc.code)
    return _reply('unavailable', 'SESSION_OPERATION_UNAVAILABLE')


def _begin(req: dict[str, Any], policy: dict[str, Any], uid: int
           ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    need(set(req) == BEGIN_KEYS and req.get('schema') == REQUEST_SCHEMA and
         req.get('operation') == 'begin', 'SESSION_BEGIN_FIELDS', 'invalid_input')
    need(type(req['scope_id']) is str and type(req['profile_id']) is str,
         'SESSION_BEGIN_SCOPE', 'invalid_input')
    raw_req = {'schema': runner.REQUEST_SCHEMA, 'scope_id': req['scope_id'],
               'profile_id': req['profile_id']}
    grant = runner._authorize(raw_req, lease._base_policy(policy), uid)
    auth = lease._tickets(policy, req['profile_id'])
    spec = guard.catalog_entry(req['profile_id'])
    expected = {
        'source_pin_sha256': policy['authorized_source_pin_sha256'],
        'profile_sha256': spec['profile_sha256'],
        'approval_receipt_sha256': auth['approval_receipt_sha256'],
        'lease_receipt_sha256': auth['lease_receipt_sha256'],
        'image_sha256': policy['image_id'][7:],
        'lease_id': auth['lease']['ticket_id'],
    }
    need(all(type(req[k]) is str and req[k] == v for k, v in expected.items()),
         'SESSION_SIGNED_SCOPE_MISMATCH', 'permission_denied')
    need(type(req['limits']) is dict and req['limits'] == FIXED_LIMITS and
         all(type(v) is int for v in req['limits'].values()),
         'SESSION_LOWER_LIMITS_NOT_YET_ARMED', 'invalid_input')
    now = time.monotonic_ns()
    deadline = req['deadline_monotonic_ns']
    need(type(deadline) is int and now + 1_000_000_000 < deadline <=
         now + runner.WALL_SECONDS * 1_000_000_000,
         'SESSION_DEADLINE_UNSAFE', 'invalid_input')
    return raw_req, auth, grant


def _receipt(req: dict[str, Any], policy: dict[str, Any],
             identity: str) -> dict[str, Any]:
    """Only a HOST DECLARATION; EC187 must not treat it as audited isolation."""
    return {
        'schema': budget.SESSION_SCHEMA,
        'session_id': identity,
        'profile_id': req['profile_id'],
        'profile_sha256': req['profile_sha256'],
        'source_pin_sha256': req['source_pin_sha256'],
        'approval_receipt_sha256': req['approval_receipt_sha256'],
        'lease_receipt_sha256': req['lease_receipt_sha256'],
        'image_sha256': req['image_sha256'],
        'sealed_source_sha256': policy['expected_source_tar_sha256'],
        'limits': dict(FIXED_LIMITS),
        'lease_atomically_consumed_once': True,
        'immutable_source_sealed': True,
        'kernel_isolation_rechecked': True,
        'hard_resource_limits_armed': True,
        'hard_watchdog_and_kill_armed': True,
        'output_stream_bounded': True,
    }


def _size(value: str) -> int:
    need(type(value) is str and (match := SIZE.fullmatch(value)) is not None,
         'SESSION_TELEMETRY_UNIT_INVALID')
    result = float(match.group(1)) * UNITS[match.group(2) or '']
    need(result.is_integer() or result < 2**63, 'SESSION_TELEMETRY_OVERFLOW')
    answer = int(result)
    need(0 <= answer <= 2**63 - 1, 'SESSION_TELEMETRY_OVERFLOW')
    return answer


def _metrics(policy: dict[str, Any], container_id: str, output_total: int,
             last: dict[str, int]) -> dict[str, int]:
    """Sample the running OCI container, never substitute invented counters.

    Template fields are Podman host *claims*, not independently observed
    kernel/cgroup counters. If Podman doesn't support this exact template, the
    session fails closed and must be stopped; do not report zeros or PASS.
    """
    # The signed lease's fsynced full ID, not a replaceable Podman name, is
    # the only acceptable telemetry target. The stats sample itself must
    # report that same full ID or no measurement can be disclosed.
    need(type(container_id) is str and runner.SHA.fullmatch(container_id)
         is not None, 'SESSION_CONTAINER_ID_INVALID')
    need(type(output_total) is int and 0 <= output_total <= runner.MAX_STDIO,
         'SESSION_OUTPUT_METER_INVALID')
    pol = lease._base_policy(policy)
    result = runner._run_command(
        pol, ['stats', '--no-stream', '--format',
              '{{.ContainerID}}|{{.CPUNano}}|{{.MemUsageBytes}}|{{.PIDs}}|{{.BlockIO}}',
              container_id],
        timeout=0.7, limit=1024)
    need(result.exit_code == 0 and len(result.stdout) <= 200,
         'SESSION_TELEMETRY_UNAVAILABLE')
    try:
        parts = result.stdout.decode('ascii').strip().split('|')
        need(len(parts) == 5 and parts[0] == container_id and
             parts[1].strip().isdigit() and parts[3].strip().isdigit(),
             'SESSION_TELEMETRY_ID_OR_FORMAT_INVALID')
        cpu_ns = int(parts[1].strip())
        mem = _size(parts[2].strip())
        pids = int(parts[3].strip())
        block = parts[4].split('/')
        need(len(block) == 2 and 0 <= cpu_ns <= 2**63 - 1 and
             0 <= pids <= 2**31 - 1, 'SESSION_TELEMETRY_INVALID')
        io_count = _size(block[0].strip()) + _size(block[1].strip())
    except SessionHostError:
        raise
    except (UnicodeError, ValueError, OverflowError, TypeError) as exc:
        raise SessionHostError('SESSION_TELEMETRY_INVALID') from exc
    current = {'cpu_ms': cpu_ns // 1_000_000,
               'memory_peak_bytes': mem,
               'io_bytes': max(output_total, io_count),
               'processes': pids}
    sampled_max = {k: max(last[k], v) for k, v in current.items()}
    need(all(v <= budget.HARD_CEILINGS[k] for k, v in sampled_max.items()),
         'SESSION_RESOURCE_SAMPLE_LIMIT_EXCEEDED')
    return sampled_max


def _inner_send(channel: socket.socket, message: dict[str, Any]) -> None:
    # SOCK_SEQPACKET preserves message boundaries, including early failures.
    raw = fio._wire(message, limit=MAX_INNER)
    need(len(raw) <= MAX_EVENT_BYTES, 'SESSION_INNER_FRAME_TOO_LARGE')
    need(channel.send(raw) == len(raw), 'SESSION_INNER_SEND_FAILED')


def _inner_read(channel: socket.socket) -> dict[str, Any]:
    raw = channel.recv(MAX_INNER + 1)
    need(bool(raw) and len(raw) <= MAX_INNER and raw.endswith(b'\n'),
         'SESSION_WORKER_CHANNEL_CLOSED')
    return lease._parse(raw[:-1], MAX_INNER)


def _worker(channel: socket.socket, caller: socket.socket, raw: bytes,
            policy_path: str, uid: int, ledger: lease.Ledger, deadline: float,
            allow_output: bool, require_cgroup: bool = False,
            require_kernel_metrics: bool = False) -> None:
    """Only forked child touches EC253.execute; watcher forks before profiles."""
    count = 0
    output_bytes = 0
    def interrupt(_sig: int, _frame: Any) -> None:
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupt)
    try:
        def ready(name: str, stage: str) -> None:
            _inner_send(channel, {'type': 'ready', 'container_name': name})

        def chunk(stream: str, content: bytes) -> None:
            nonlocal count, output_bytes
            for offset in range(0, len(content), OUT_FRAME):
                frame = content[offset:offset + OUT_FRAME]
                count += 1
                output_bytes += len(frame)
                need(count <= MAX_FRAMES, 'SESSION_WORKER_FRAME_LIMIT')
                if allow_output:
                    _inner_send(channel, {'type': 'output', 'stream': stream,
                                          'bytes': len(frame),
                                          'chunk_b64': base64.b64encode(frame).decode('ascii')})
                else:
                    # Preserve host I/O accounting without releasing content.
                    _inner_send(channel, {'type': 'meter', 'bytes': len(frame)})

        def created(name: str, container_id: str) -> None:
            # EC253 durably binds the full ID before invoking this callback.
            _inner_send(channel, {'type': 'created', 'container_name': name,
                                  'container_id': container_id})

        def started(_pid: int) -> None:
            _inner_send(channel, {'type': 'start_invoked'})

        def final_cgroup_meter(name: str, container_id: str | None,
                               record: dict[str, Any] | None) -> None:
            if not require_kernel_metrics:
                return
            # Called from the actual signed worker BEFORE EC256 cgroup.kill.
            # If a completed strict run lacks this final sample, its answer
            # is unavailable, while mandatory OCI cleanup still proceeds.
            from ec257_cgroup_metrics import metrics as kernel
            need(record is not None and type(container_id) is str,
                 'SESSION_FINAL_KERNEL_BINDING_ABSENT')
            measured = kernel.sample(
                container_id, record, output_bytes,
                {key: 0 for key in budget.RESOURCE_KEYS})
            _inner_send(channel, {'type': 'final_meter', 'resources': measured})

        answer = lease.execute(raw, policy_path, uid, ledger, caller=caller,
                               on_session_reserved=ready, on_output=chunk,
                               on_start_invoked=started,
                               on_container_created=created,
                               watchdog_deadline=deadline,
                               require_cgroup=require_cgroup,
                               on_before_cgroup_cleanup=(
                                   final_cgroup_meter if require_kernel_metrics
                                   else None))
        result = answer.get('result')
        _inner_send(channel, {'type': 'finished',
                              'status': answer.get('status'),
                              'container_cleanup_confirmed': answer.get('container_cleanup_confirmed'),
                              'durable_one_use_lease_reserved': answer.get('durable_one_use_lease_reserved'),
                              'container_exit_code_reported': (
                                  result.get('container_exit_code_reported')
                                  if type(result) is dict else None)})
    except BaseException:
        try:
            _inner_send(channel, {'type': 'failed'})
        except Exception:
            pass
    finally:
        channel.close()
        caller.close()
        # Only the parent server owns normal socket lifecycle; its forked
        # child must never unwind the caller's host listener or run atexit.
        os._exit(0)


class HostSession:
    def __init__(self, worker: int, channel: socket.socket,
                 ledger: lease.Ledger, policy: dict[str, Any], name: str,
                 grant: dict[str, Any], deadline: float,
                 require_cgroup: bool = False,
                 require_kernel_metrics: bool = False) -> None:
        self.require_cgroup = require_cgroup
        self.require_kernel_metrics = require_kernel_metrics
        self.ticket_name: str | None = None
        self.bound_record: dict[str, Any] | None = None
        self.final_meter_received = False
        self.missing_counter_polls = 0
        self.worker = worker
        self.channel = channel
        self.ledger = ledger
        self.policy = policy
        self.name = name
        self.container_id = ''  # Set only after EC253's fsynced ID event.
        self.grant = grant
        self.deadline = deadline
        self.output_total = 0
        self.metrics = {k: 0 for k in budget.RESOURCE_KEYS}
        self.saw_metrics = False
        self.frames = 0
        self.completed = False
        self.reaped = False

    def _wait_worker(self, max_seconds: float) -> bool:
        if self.reaped:
            return True
        until = time.monotonic() + max_seconds
        while time.monotonic() < until:
            try:
                pid, _ = os.waitpid(self.worker, os.WNOHANG)
            except ChildProcessError:
                pid = self.worker
            if pid == self.worker:
                self.reaped = True
                return True
            time.sleep(0.025)
        return False

    def stop(self) -> dict[str, bool]:
        forced_kill = False
        if not self.reaped:
            try:
                os.kill(self.worker, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if not self._wait_worker(0.7):
                forced_kill = True  # OS worker was not cooperatively reaped.
                try:
                    os.kill(self.worker, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self._wait_worker(1.0)
        # Reconcile remaining private journal and OCI by generated name, NOT
        # a user-specified identifier. Failure remains pending and fail-closed.
        clean = False
        try:
            if self.reaped:
                self.ledger.recover()
                clean = self.ledger.safe()
        except (OSError, runner.HostRunError):
            pass
        self.channel.close()
        return {'stop_acknowledged': True,
                'reaped': bool(self.reaped and clean and not forced_kill)}

    def _take_metrics(self) -> dict[str, int]:
        if not self.require_kernel_metrics:
            return _metrics(self.policy, self.container_id,
                            self.output_total, self.metrics)
        from ec256_cgroup_reaper import supervisor
        from ec257_cgroup_metrics import metrics as kernel
        need(self.ticket_name is not None and self.bound_record is not None and
             self.ledger.cgroup_record(self.ticket_name) == self.bound_record,
             'SESSION_CGROUP_METER_BINDING_DRIFT')
        try:
            result = kernel.sample(self.container_id, self.bound_record,
                                   self.output_total, self.metrics)
        except supervisor.CgroupError as exc:
            # The worker may have *already sampled* and cleaned up this
            # precise cgroup before the parent drains older output frames.
            # Allow only a short, bounded window for the ordered final_meter
            # frame; never accept exit without that real final sample.
            if exc.code != 'CGROUP256_CGROUP_DIRECTORY_ABSENT':
                raise
            self.missing_counter_polls += 1
            need(self.missing_counter_polls <= 4,
                 'SESSION_FINAL_KERNEL_SAMPLE_NOT_DELIVERED')
            return dict(self.metrics)
        self.missing_counter_polls = 0
        return result

    def poll(self, wait_ms: int, max_chunk_bytes: int) -> dict[str, Any]:
        need(not self.completed and type(wait_ms) is int and
             1 <= wait_ms <= FIXED_LIMITS['poll_wait_ms'] and
             type(max_chunk_bytes) is int and 1 <= max_chunk_bytes <= budget.MAX_CHUNK,
             'SESSION_POLL_FIELDS', 'invalid_input')
        need(time.monotonic() < self.deadline, 'SESSION_WALL_DEADLINE')
        need(self.frames < MAX_FRAMES, 'SESSION_POLL_FRAME_LIMIT')
        ready, _, _ = select.select([self.channel], [], [], wait_ms / 1000.0)
        evt: dict[str, Any] = ({'type': 'heartbeat'} if not ready else
                               _inner_read(self.channel))
        self.frames += 1
        kind = evt.get('type')
        need(kind in ('heartbeat', 'output', 'meter', 'final_meter', 'finished'),
             'SESSION_WORKER_EVENT_INVALID')
        need(not self.final_meter_received or kind in ('heartbeat', 'finished'),
             'SESSION_WORKER_EVENT_AFTER_FINAL_METER')
        if kind == 'output':
            need(set(evt) == {'type', 'stream', 'bytes', 'chunk_b64'} and
                 evt['stream'] in ('stdout', 'stderr') and
                 type(evt['bytes']) is int and 1 <= evt['bytes'] <=
                 min(max_chunk_bytes, OUT_FRAME), 'SESSION_WORKER_OUTPUT_INVALID')
            try:
                data = base64.b64decode(evt['chunk_b64'], validate=True)
            except (binascii.Error, TypeError, ValueError) as exc:
                raise SessionHostError('SESSION_WORKER_OUTPUT_BASE64_INVALID') from exc
            need(len(data) == evt['bytes'], 'SESSION_WORKER_OUTPUT_LENGTH_INVALID')
            self.output_total += len(data)
            need(self.output_total <= runner.MAX_STDIO, 'SESSION_TOTAL_OUTPUT_OVERFLOW')
        elif kind == 'meter':
            need(set(evt) == {'type', 'bytes'} and
                 type(evt['bytes']) is int and 1 <= evt['bytes'] <= OUT_FRAME,
                 'SESSION_WORKER_METER_INVALID')
            self.output_total += evt['bytes']
            need(self.output_total <= runner.MAX_STDIO, 'SESSION_TOTAL_OUTPUT_OVERFLOW')
        elif kind == 'heartbeat':
            need(set(evt) == {'type'}, 'SESSION_WORKER_EVENT_FIELDS')
        elif kind == 'final_meter':
            from ec257_cgroup_metrics import metrics as kernel
            need(self.require_kernel_metrics and
                 set(evt) == {'type', 'resources'} and
                 self.ticket_name is not None and self.bound_record is not None and
                 self.ledger.cgroup_record(self.ticket_name) == self.bound_record,
                 'SESSION_FINAL_METER_UNTRUSTED')
            self.metrics = kernel.validate_sample(evt['resources'],
                                                   previous=self.metrics)
            self.final_meter_received = True
            self.saw_metrics = True
            return {'kind': 'heartbeat', 'resources': dict(self.metrics)}
        if kind == 'finished':
            need(set(evt) == {'type', 'status', 'container_cleanup_confirmed',
                               'durable_one_use_lease_reserved',
                               'container_exit_code_reported'} and
                 evt['status'] == 'partial' and
                 evt['container_cleanup_confirmed'] is True and
                 evt['durable_one_use_lease_reserved'] is True and
                 type(evt['container_exit_code_reported']) is int and
                 0 <= evt['container_exit_code_reported'] <= 255,
                 'SESSION_WORKER_FINISH_UNCONFIRMED')
            need(self._wait_worker(1.0) and self.ledger.safe(),
                 'SESSION_WORKER_NOT_REAPED')
            # A session that completed before the first available real metric
            # is not silently assigned zero CPU/memory/PID telemetry.
            need(self.saw_metrics, 'SESSION_NO_OBSERVABLE_RESOURCE_TELEMETRY')
            need(not self.require_kernel_metrics or self.final_meter_received,
                 'SESSION_NO_FINAL_KERNEL_RESOURCE_SAMPLE')
            self.completed = True
            self.channel.close()
            return {'kind': 'exit', 'exit_code':
                    evt['container_exit_code_reported'],
                    'resources': dict(self.metrics)}
        # A final pre-reap watermark has already arrived. Cleanup may still
        # take time; heartbeat polls must neither reopen a killed cgroup nor
        # claim fresh usage. Only an eventual confirmed 'finished' may exit.
        if self.final_meter_received:
            return {'kind': 'heartbeat', 'resources': dict(self.metrics)}
        # EC257 never calls Podman stats. Legacy EC254/EC256 retain their
        # original Podman-sampled path and wire contract unchanged.
        self.metrics = self._take_metrics()
        self.saw_metrics = True
        if kind in ('heartbeat', 'meter'):
            return {'kind': 'heartbeat', 'resources': dict(self.metrics)}
        return {'kind': 'output', 'stream': evt['stream'], 'chunk_b64': evt['chunk_b64'],
                'resources': dict(self.metrics)}


def _serve_connection(conn: socket.socket, policy_path: str,
                      ledger: lease.Ledger, uid: int,
                      *, require_cgroup: bool = False,
                      require_kernel_metrics: bool = False,
                      before_begin_guard: Callable[[dict[str, Any], str,
                                                    dict[str, Any]], None] | None = None,
                       during_session_guard: Callable[[dict[str, Any], str,
                                                      dict[str, Any]], None] | None = None,
                       audit_event: Callable[[str, str, str], None] | None = None) -> None:
    session: HostSession | None = None
    # EC262: ephemeral internal-only correlation token; no request body,
    # usernames, commands, output, keys or paths enter the audit channel.
    trace = os.urandom(12).hex()
    audit_failed = False

    def audit(name: str, reason: str = 'NONE') -> None:
        nonlocal audit_failed
        if audit_event is None:
            return
        try:
            audit_event(name, trace, reason)
        except BaseException as exc:
            audit_failed = True
            raise SessionHostError('EC262_AUDIT_UNAVAILABLE') from exc

    try:
        audit('session_open')
        conn.settimeout(5)
        req = _receive(conn)
        pol, sha = lease._policy(policy_path)
        need(sha == ledger.policy_sha and pol == ledger.policy,
             'SESSION_POLICY_CHANGED')
        raw_req, auth, grant = _begin(req, pol, uid)
        # EC259 private operator callback: a strict opt-in host may recheck
        # Git object custody + signed TAR binding BEFORE any fork/lease use.
        # Existing EC254/256/257 public entrypoints do not set this hook.
        if before_begin_guard is not None:
            before_begin_guard(pol, sha, req)
        need(not ledger.used(lease._lease_filename(auth['lease']['ticket_id'])),
             'SESSION_LEASE_ALREADY_USED', 'permission_denied')
        source = runner._source_archive(lease._base_policy(pol))
        need(len(source) > 0, 'SESSION_SOURCE_UNAVAILABLE')
        # Commit the signed authorization decision before fork/lease/OCI.
        audit('begin_authorized')
        child_socket, parent_socket = socket.socketpair(socket.AF_UNIX,
                                                        socket.SOCK_SEQPACKET)
        deadline = req['deadline_monotonic_ns'] / 1e9
        try:
            child = os.fork()
        except OSError as exc:
            child_socket.close()
            parent_socket.close()
            raise SessionHostError('SESSION_WORKER_FORK_FAILED') from exc
        if child == 0:
            parent_socket.close()
            inner = lease._canonical({'schema': lease.REQUEST_SCHEMA,
                                      'scope_id': req['scope_id'],
                                      'profile_id': req['profile_id']})
            _worker(child_socket, conn, inner, policy_path, uid, ledger,
                    deadline, grant['allow_output_text'], require_cgroup,
                    require_kernel_metrics)
        child_socket.close()
        # Once a worker starts, any begin failure MUST kill and recover it.
        session = HostSession(child, parent_socket, ledger, pol, '', grant,
                              deadline, require_cgroup=require_cgroup,
                              require_kernel_metrics=require_kernel_metrics)
        ready, _, _ = select.select([parent_socket], [], [],
                                    min(MAX_BEGIN_SECONDS, max(0, deadline - time.monotonic())))
        need(bool(ready), 'SESSION_BEGIN_TIMEOUT')
        event = _inner_read(parent_socket)
        need(set(event) == {'type', 'container_name'} and
             event['type'] == 'ready' and type(event['container_name']) is str and
             lease.CONTAINER_NAME.fullmatch(event['container_name']) is not None,
             'SESSION_BEGIN_NO_DURABLE_LEASE')
        session.name = event['container_name']
        ticket_name = lease._lease_filename(auth['lease']['ticket_id'])
        session.ticket_name = ticket_name
        need(ledger.used(ticket_name) and ledger._read(ticket_name)[0]['container_name'] ==
             session.name, 'SESSION_BEGIN_LEDGER_NOT_CONFIRMED')
        # First bind a real created full ID to the durable journal, then
        # observe the OCI start invocation. Reordering is a hard failure.
        ready, _, _ = select.select([parent_socket], [], [],
                                    min(MAX_BEGIN_SECONDS, max(0, deadline - time.monotonic())))
        need(bool(ready), 'SESSION_CREATED_ID_NOT_REPORTED')
        created = _inner_read(parent_socket)
        need(set(created) == {'type', 'container_name', 'container_id'} and
             created['type'] == 'created' and
             created['container_name'] == session.name and
             type(created['container_id']) is str and
             runner.SHA.fullmatch(created['container_id']) is not None and
             any(evt == {'event': 'created',
                         'container_id': created['container_id']}
                 for evt in ledger._read(ticket_name)[1:]),
             'SESSION_CREATED_ID_NOT_DURABLY_BOUND')
        session.container_id = created['container_id']
        ready, _, _ = select.select([parent_socket], [], [],
                                    min(MAX_BEGIN_SECONDS, max(0, deadline - time.monotonic())))
        need(bool(ready) and _inner_read(parent_socket) == {'type': 'start_invoked'},
             'SESSION_START_NOT_INVOKED')
        if require_cgroup:
            from ec256_cgroup_reaper import supervisor
            # EC256 refuses begin without a live kernel cgroup and durable pin.
            need(any(e['event'] == 'start_armed'
                     for e in ledger._read(ticket_name)),
                 'SESSION_CGROUP_START_NOT_DURABLY_ARMED')
            until = min(deadline, time.monotonic() + 1.5)
            while True:
                try:
                    proof = supervisor.bind_live(
                        lease._base_policy(pol), session.container_id,
                        auth['lease_receipt_sha256'])
                    ledger.bind_cgroup(ticket_name, proof)
                    session.bound_record = ledger.cgroup_record(ticket_name)
                    need(session.bound_record == proof.journal_event(),
                         'SESSION_CGROUP_BOUND_EVENT_DRIFT')
                    break
                except runner.HostRunError as exc:
                    if (getattr(exc, 'code', '') not in (
                            'CGROUP256_CONTAINER_NOT_RUNNING_FOR_BIND',
                            'CGROUP256_PODMAN_STATE_UNAVAILABLE') or
                            time.monotonic() >= until):
                        raise
                    time.sleep(0.035)
        sample_until = min(deadline, time.monotonic() + 1.5)
        while True:
            try:
                session.metrics = session._take_metrics()
                session.saw_metrics = True
                break
            except SessionHostError as exc:
                if (exc.code != 'SESSION_TELEMETRY_UNAVAILABLE' or
                        time.monotonic() >= sample_until):
                    raise
                time.sleep(0.04)
        # EC260 must reject a policy/source change occurring DURING OCI setup
        # before acknowledging begin, not just on the next idle tick.
        # An EC260 caller opts into revocation checks *without* relying on
        # poll/stop traffic. Nothing in the legacy public request wire changes.
        def active_recheck() -> None:
            lease._recheck(policy_path, pol, sha,
                           {'schema': lease.REQUEST_SCHEMA,
                            'scope_id': req['scope_id'],
                            'profile_id': req['profile_id']},
                           uid, auth['material_sha256'])
            need(runner._source_archive(lease._base_policy(pol)) == source,
                 'SESSION_SOURCE_CHANGED_DURING_RUN')
            if during_session_guard is not None:
                during_session_guard(pol, sha, req)

        if during_session_guard is not None:
            active_recheck()
            # A slow Git proof must never turn an expired session deadline
            # into a successful late begin acknowledgement.
            need(time.monotonic() < deadline, 'SESSION_WALL_DEADLINE')
        identity = 'ec254-' + os.urandom(16).hex()
        begin_reply = _reply('partial', 'SESSION_BEGUN_HOST_CLAIMS_ONLY',
                             receipt=_receipt(req, pol, identity))
        audit('begin_egress_attempt')
        if during_session_guard is not None:
            _send_monitored(conn, begin_reply, deadline, active_recheck)
        else:
            _send(conn, begin_reply)
        # 'enqueued' asserts only complete local socket write, not peer receipt.
        audit('begin_egress_enqueued')
        conn.settimeout(max(1, min(runner.WALL_SECONDS, deadline - time.monotonic())))

        while True:
            message = (_receive_monitored(conn, deadline, active_recheck)
                       if during_session_guard is not None else _receive(conn))
            op = message.get('operation')
            need(message.get('schema') == REQUEST_SCHEMA, 'SESSION_OPERATION_SCHEMA',
                 'invalid_input')
            if op == 'poll':
                # Do not disclose buffered stdout/stderr or telemetry after
                # operator policy, signed tickets or UID grant was revoked.
                if during_session_guard is None:
                    # Legacy path keeps its original per-poll validation.
                    # EC260 has already checked before accepting this frame.
                    active_recheck()
                need(set(message) == {'schema', 'operation', 'wait_ms',
                                     'max_chunk_bytes'}, 'SESSION_POLL_REQUEST_FIELDS',
                     'invalid_input')
                event = session.poll(message['wait_ms'], message['max_chunk_bytes'])
                poll_reply = _reply('partial', 'SESSION_POLL_HOST_REPORT_ONLY', event=event)
                audit('poll_egress_attempt')
                if during_session_guard is not None:
                    # Polling and kernel metering may have taken time since
                    # the request's last authority proof. Check again before
                    # the first output/telemetry byte and while sending.
                    _send_monitored(conn, poll_reply, deadline, active_recheck)
                else:
                    _send(conn, poll_reply)
                audit('poll_egress_enqueued')
                if event['kind'] == 'exit':
                    return
            elif op == 'stop_and_reap':
                need(set(message) == {'schema', 'operation', 'reason'} and
                     type(message['reason']) is str and 1 <= len(message['reason']) <= 128,
                     'SESSION_STOP_REQUEST_FIELDS', 'invalid_input')
                audit('stop_requested')
                receipt = session.stop()
                stop_reply = _reply('partial', 'SESSION_STOP_HOST_REPORT_ONLY',
                                    stop=receipt)
                audit('stop_egress_attempt')
                if during_session_guard is not None:
                    _send_monitored(conn, stop_reply, deadline, active_recheck)
                else:
                    _send(conn, stop_reply)
                audit('stop_egress_enqueued')
                return
            else:
                raise SessionHostError('SESSION_OPERATION_UNKNOWN', 'invalid_input')
    except (Exception, KeyboardInterrupt) as exc:
        if audit_event is not None and not audit_failed:
            try:
                audit('session_denied', getattr(exc, 'code', 'SESSION_OPERATION_UNAVAILABLE'))
            except SessionHostError:
                # Even an audit write failure cannot displace OCI cleanup.
                pass
        # Never concatenate a new JSON error after a partially emitted frame.
        # The only truthful result for that client is a broken transport plus
        # durable server-side stop/recovery, not a fabricated complete reply.
        if not isinstance(exc, SessionEgressInterrupted) and not audit_failed:
            try:
                error_reply = _safe_status(
                    exc if isinstance(exc, Exception) else
                    SessionHostError('SESSION_INTERRUPTED'))
                if during_session_guard is not None:
                    # A non-reading peer cannot postpone the cleanup finally.
                    # Failed authority is NOT rechecked for a deny frame.
                    denial_until = time.monotonic() + ACTIVE_DENIAL_WRITE_SECONDS
                    if session is not None:
                        denial_until = min(denial_until, session.deadline)
                    _send_monitored(conn, error_reply, denial_until, None)
                else:
                    _send(conn, error_reply)
            except Exception:
                pass
    finally:
        try:
            if session is not None and not session.completed:
                session.stop()
        finally:
            # A complete EC253 ledger recovery is NOT a kernel attestation.
            # Keep the factual distinction in this local-only audit trail.
            if session is not None and audit_event is not None and not audit_failed:
                try:
                    audit('session_cleanup_state',
                          'LEDGER_SAFE' if ledger.safe() else 'LEDGER_UNCERTAIN')
                except SessionHostError:
                    pass
            # A broken audit writer cannot allow another session. Re-raise
            # only *after* the unconditional original recovery path.
            if audit_failed:
                raise SessionHostError('EC262_AUDIT_UNAVAILABLE')


def serve(policy_path: str, socket_path: str, *, max_sessions: int = 1,
          accept_timeout: float = 60.0,
          require_cgroup: bool = False,
          require_kernel_metrics: bool = False,
          startup_guard: Callable[[dict[str, Any], str], None] | None = None,
          before_begin_guard: Callable[[dict[str, Any], str,
                                        dict[str, Any]], None] | None = None,
          during_session_guard: Callable[[dict[str, Any], str,
                                         dict[str, Any]], None] | None = None,
          audit_event: Callable[[str, str, str], None] | None = None) -> None:
    fio._linux()
    need(os.geteuid() != 0, 'SESSION_NONROOT_REQUIRED')
    need(type(max_sessions) is int and 1 <= max_sessions <= MAX_SESSIONS and
         type(accept_timeout) in (int, float) and 1 <= accept_timeout <= 300,
         'SESSION_SERVICE_OPTIONS_INVALID')
    need(not require_kernel_metrics or require_cgroup,
         'SESSION_KERNEL_METER_REQUIRES_CGROUP_REAPER')
    need(during_session_guard is None or before_begin_guard is not None,
         'SESSION_ACTIVE_MONITOR_REQUIRES_BEGIN_GATE')
    # Old host entrypoints have no audit callback and preserve exact behaviour.
    # Only the new EC262 strict signed/active/kernel service can attach one.
    need(audit_event is None or (during_session_guard is not None and
         require_cgroup and require_kernel_metrics and
         startup_guard is not None and before_begin_guard is not None),
         'EC262_AUDIT_REQUIRES_STRICT_SIGNED_HOST')
    if require_cgroup:
        from ec256_cgroup_reaper import supervisor
        # Reject unsupported cgroup2 hosts before consuming a lease.
        supervisor._mount_root()
        supervisor._boot_id()
    pol, sha = lease._policy(policy_path)
    # EC259 startup check runs before accepting any socket connection or
    # creating an execution worker. Default None preserves earlier services.
    if startup_guard is not None:
        startup_guard(pol, sha)
    runner._source_archive(lease._base_policy(pol))
    runner._private_dir(pol['scratch_root'])
    target = fio._private_parent(socket_path, policy=False)
    need(len(os.fsencode(str(target))) < 100, 'SESSION_SOCKET_TOO_LONG')
    need(not os.path.lexists(target), 'SESSION_SOCKET_EXISTS')
    with lease.Ledger(pol, sha) as ledger:
        ledger.recover()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            created = None
            try:
                old = os.umask(0o117)
                try:
                    listener.bind(str(target))
                finally:
                    os.umask(old)
                st = os.lstat(target)
                created = (st.st_dev, st.st_ino)
                need(stat.S_ISSOCK(st.st_mode) and st.st_uid == os.geteuid() and
                     st.st_mode & 0o007 == 0, 'SESSION_SOCKET_UNSAFE')
                listener.listen(2)
                listener.settimeout(accept_timeout)
                for _ in range(max_sessions):
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        break
                    with conn:
                        try:
                            uid = fio._uid_from_peer(conn)
                            _serve_connection(conn, policy_path, ledger, uid,
                                              require_cgroup=require_cgroup,
                                              require_kernel_metrics=require_kernel_metrics,
                                              before_begin_guard=before_begin_guard,
                                              during_session_guard=during_session_guard,
                                              audit_event=audit_event)
                        except (Exception, KeyboardInterrupt) as exc:
                            # Fail CLOSED if mandatory audit lost durability.
                            # The connection's finally already cleaned OCI.
                            if audit_event is not None and getattr(
                                    exc, 'code', None) == 'EC262_AUDIT_UNAVAILABLE':
                                raise
                    need(ledger.safe(), 'SESSION_LEDGER_UNCERTAIN_STOP_SERVER')
            finally:
                if created is not None:
                    try:
                        st = os.lstat(target)
                        if stat.S_ISSOCK(st.st_mode) and (st.st_dev, st.st_ino) == created:
                            os.unlink(target)
                    except FileNotFoundError:
                        pass


class Session:
    """EC187 callback interface; network bytes remain under host bounds.

    If a direct caller abandons a session, it must call stop_and_reap or use
    a context manager; the server also has its own hard deadline and recovery.
    """
    def __init__(self, conn: socket.socket, receipt: dict[str, Any]) -> None:
        self.conn = conn
        self.receipt = receipt
        self.finished = False

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *_: Any) -> None:
        if not self.finished:
            self.stop_and_reap('context_exited')

    def poll(self, wait_ms: int, max_chunk_bytes: int) -> dict[str, Any]:
        need(not self.finished, 'SESSION_ALREADY_FINISHED')
        _send(self.conn, {'schema': REQUEST_SCHEMA, 'operation': 'poll',
                          'wait_ms': wait_ms, 'max_chunk_bytes': max_chunk_bytes})
        response = _receive(self.conn)
        need(response.get('schema') == RESPONSE_SCHEMA and
             response.get('status') == 'partial' and
             response.get('reason_code') == 'SESSION_POLL_HOST_REPORT_ONLY' and
             type(response.get('event')) is dict, 'SESSION_REMOTE_POLL_UNAVAILABLE')
        event = response['event']
        if event.get('kind') == 'output':
            try:
                chunk = base64.b64decode(event.pop('chunk_b64'), validate=True)
            except (binascii.Error, KeyError, ValueError, TypeError) as exc:
                raise SessionHostError('SESSION_REMOTE_OUTPUT_INVALID') from exc
            event['chunk'] = chunk
        if event.get('kind') == 'exit':
            self.finished = True
            self.conn.close()
        return event

    def stop_and_reap(self, reason: str) -> dict[str, bool]:
        if self.finished:
            return {'stop_acknowledged': True, 'reaped': True}
        try:
            _send(self.conn, {'schema': REQUEST_SCHEMA, 'operation': 'stop_and_reap',
                              'reason': str(reason)[:128] or 'stop'})
            response = _receive(self.conn)
            if (response.get('schema') == RESPONSE_SCHEMA and
                response.get('status') == 'partial' and
                response.get('reason_code') == 'SESSION_STOP_HOST_REPORT_ONLY' and
                type(response.get('stop')) is dict and
                set(response['stop']) == {'stop_acknowledged', 'reaped'} and
                all(type(v) is bool for v in response['stop'].values())):
                return response['stop']
            return {'stop_acknowledged': False, 'reaped': False}
        except (Exception, KeyboardInterrupt):
            return {'stop_acknowledged': False, 'reaped': False}
        finally:
            self.finished = True
            self.conn.close()


class TrustedBroker:
    """Connect an original EC187 controller to an independently owned host.

    The untrusted controller cannot choose Podman argv, TAR, grants, keys,
    journal, image, sample metrics or runtime namespace. Only default EC187
    ceilings are currently accepted (smaller limits fail closed).
    """
    def __init__(self, socket_path: str, expected_host_uid: int, scope_id: str):
        need(type(expected_host_uid) is int and 0 <= expected_host_uid <=
             runner.UID_MAX and type(scope_id) is str and
             runner.SCOPE.fullmatch(scope_id) is not None,
             'SESSION_CLIENT_CONFIGURATION_INVALID', 'invalid_input')
        self.socket_path = str(socket_path)
        self.uid = expected_host_uid
        self.scope = scope_id

    def begin(self, request: dict[str, Any]) -> Session:
        need(type(request) is dict and
             {'profile_id', 'source_pin_sha256', 'profile_sha256',
              'approval_receipt_sha256', 'lease_receipt_sha256', 'image_sha256',
              'lease_id', 'deadline_monotonic_ns', 'limits'} <= set(request),
             'SESSION_EC187_BEGIN_INVALID', 'invalid_input')
        begin = {k: request[k] for k in BEGIN_KEYS - {'schema', 'operation', 'scope_id'}}
        begin.update({'schema': REQUEST_SCHEMA, 'operation': 'begin',
                      'scope_id': self.scope})
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(MAX_BEGIN_SECONDS + 3)
            conn.connect(self.socket_path)
            need(fio._uid_from_peer(conn) == self.uid, 'SESSION_WRONG_HOST_UID',
                 'permission_denied')
            _send(conn, begin)
            response = _receive(conn)
            need(response.get('schema') == RESPONSE_SCHEMA and
                 response.get('status') == 'partial' and
                 response.get('reason_code') == 'SESSION_BEGUN_HOST_CLAIMS_ONLY' and
                 type(response.get('receipt')) is dict,
                 'SESSION_REMOTE_BEGIN_DENIED')
            receipt = response['receipt']
            # EC187 validates the exact receipt again against its own final
            # double-HMAC-authorized scope, and all claims remain host-only.
            budget._read_session(receipt, selected=request, limits=request['limits'])
            conn.settimeout(2.0)
            return Session(conn, receipt)
        except Exception:
            conn.close()
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC254 bounded EC187 session host')
    sub = parser.add_subparsers(dest='command', required=True)
    server = sub.add_parser('serve')
    server.add_argument('--policy', required=True)
    server.add_argument('--socket', required=True)
    server.add_argument('--max-sessions', type=int, default=1)
    server.add_argument('--accept-timeout', type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        serve(args.policy, args.socket, max_sessions=args.max_sessions,
              accept_timeout=args.accept_timeout)
        return 0
    except (runner.HostRunError, fio.HostError, OSError, ValueError) as exc:
        print(_reply('unavailable', getattr(exc, 'code', 'SESSION_SERVICE_UNAVAILABLE')))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
