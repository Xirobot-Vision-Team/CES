#!/usr/bin/env python3
"""EC187: bounded QualityRun controller for an *external trusted* runner.

The controller never starts an OS process, loads repository code, mounts a
container, executes shell, accesses the network or mutates a project. Its
external broker MUST, before starting a profile, seal an immutable checkout,
verify actual kernel isolation, atomically consume an EC186 lease and arm
hard cgroup/clock/output limits. A Python object reporting those facts is
not cryptographic evidence. No broker is included in this distribution.

All recorded results are `partial`/2, even for reported exit 0, because a
broker implementation, image, isolation and source bytes are not independently
attested by CES. Timed-out / cancelled / over-budget runs never report PASS.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Callable

import quality_detect as detect
import quality_run_guard as guard

SCHEMA = 'ces.quality_run_budget.v1'
SESSION_SCHEMA = 'ces.qualityrun.trusted_session.v1'
PREFIX = 'QUALITYRUNBUDGET_'
MAX_RESULT_SIZE = 96 * 1024
MAX_CHUNK = 4096  # even the trusted adapter may deliver only bounded frames
MAX_POLLS = 1024
# Real broker MUST independently enforce these hard ceilings, even if this
# controller is blocked in begin/poll/stop or is abruptly terminated.
HARD_CEILINGS: dict[str, int] = {
    'wall_ms': 60_000, 'cpu_ms': 40_000, 'memory_peak_bytes': 256 * 1024 * 1024,
    'io_bytes': 64 * 1024 * 1024, 'processes': 32,
    'capture_bytes': 12_288, 'poll_wait_ms': 250,
}
MINIMUMS: dict[str, int] = {
    'wall_ms': 100, 'cpu_ms': 100, 'memory_peak_bytes': 1024 * 1024,
    'io_bytes': 4096, 'processes': 1,
    'capture_bytes': 0, 'poll_wait_ms': 1,
}
IDENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{11,63}\Z', re.ASCII)
RESOURCE_KEYS = frozenset({'cpu_ms', 'memory_peak_bytes', 'io_bytes', 'processes'})
SESSION_FIELDS = frozenset({
    'schema', 'session_id', 'profile_id', 'profile_sha256',
    'source_pin_sha256', 'approval_receipt_sha256', 'lease_receipt_sha256',
    'image_sha256', 'sealed_source_sha256', 'limits',
    'lease_atomically_consumed_once', 'immutable_source_sealed',
    'kernel_isolation_rechecked', 'hard_resource_limits_armed',
    'hard_watchdog_and_kill_armed', 'output_stream_bounded',
})


class BudgetError(Exception):
    def __init__(self, code: str, status: str = 'unavailable') -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def require(value: Any, code: str, status: str = 'invalid_input') -> None:
    if value is not True:
        raise BudgetError(code, status)


def limits_for(overrides: dict[str, int] | None) -> dict[str, int]:
    """Only lower code-owned ceilings; reject booleans, unknowns and coercions."""
    require(overrides is None or type(overrides) is dict,
            'LIMITS_INVALID')
    selected = dict(HARD_CEILINGS)
    for field, value in (overrides or {}).items():
        require(type(field) is str and field in HARD_CEILINGS and
                type(value) is int and MINIMUMS[field] <= value <= HARD_CEILINGS[field],
                'LIMITS_INVALID')
        selected[field] = value
    safe_cpu = selected['wall_ms'] * selected['processes']
    if 'cpu_ms' not in (overrides or {}):
        selected['cpu_ms'] = min(selected['cpu_ms'], safe_cpu)
    require(selected['cpu_ms'] <= safe_cpu, 'LIMITS_INCONSISTENT')
    return selected


def _tick(clock: Callable[[], int]) -> int:
    try:
        value = clock()
        require(type(value) is int and value >= 0,
                'MONOTONIC_CLOCK_INVALID', 'unavailable')
        return value
    except BudgetError:
        raise
    except Exception:
        raise BudgetError('MONOTONIC_CLOCK_UNAVAILABLE') from None


def _cancelled(callback: Callable[[], bool] | None) -> bool:
    if callback is None:
        return False
    require(callable(callback), 'CANCELLATION_SOURCE_INVALID')
    try:
        answer = callback()
        require(type(answer) is bool, 'CANCELLATION_SOURCE_UNAVAILABLE', 'unavailable')
        return answer
    except BudgetError:
        raise
    except Exception:
        raise BudgetError('CANCELLATION_SOURCE_UNAVAILABLE') from None


def _run_grant(callback: Callable[[dict[str, Any]], bool] | None,
               stage: str, scope: dict[str, Any], counts: dict[str, Any]) -> None:
    require(callable(callback), 'EXECUTE_AUTHORIZER_REQUIRED', 'unavailable')
    counts['execution_grants_checked'] += 1
    try:
        # Do not expose mutable policy limits/selection to a host callback.
        # A callback must not be able to relax the later broker request.
        safe_scope = guard._safe_copy(scope, 'EXECUTION_SCOPE_INVALID', 8192)
        allowed = callback({'operation': 'QUALITYRUN_EXECUTE_EXTERNAL',
                            'stage': stage, 'schema': SCHEMA, **safe_scope})
    except Exception:
        raise BudgetError('EXECUTE_AUTHORIZER_UNAVAILABLE') from None
    require(allowed is True, 'EXECUTE_AUTHORIZATION_DENIED', 'unavailable')


def _read_session(receipt: Any, *, selected: dict[str, Any],
                  limits: dict[str, int]) -> dict[str, Any]:
    require(type(receipt) is dict and set(receipt) == SESSION_FIELDS,
            'BROKER_SESSION_RECEIPT_INVALID', 'unavailable')
    try:
        copy = guard._safe_copy(receipt, 'BROKER_SESSION_RECEIPT_INVALID', 4096)
    except guard.GateError:
        raise BudgetError('BROKER_SESSION_RECEIPT_INVALID') from None
    require(copy['schema'] == SESSION_SCHEMA and
            type(copy['session_id']) is str and IDENT.fullmatch(copy['session_id']) is not None,
            'BROKER_SESSION_RECEIPT_INVALID')
    for key in ('profile_id', 'profile_sha256', 'source_pin_sha256',
                'approval_receipt_sha256', 'lease_receipt_sha256', 'image_sha256'):
        require(type(copy[key]) is str and copy[key] == selected[key],
                'BROKER_SESSION_SCOPE_MISMATCH', 'unavailable')
    require(type(copy['sealed_source_sha256']) is str and
            guard.HEX.fullmatch(copy['sealed_source_sha256']) is not None,
            'BROKER_CONTENT_SEAL_INVALID', 'unavailable')
    require(type(copy['limits']) is dict and copy['limits'] == limits and
            all(type(v) is int for v in copy['limits'].values()),
            'BROKER_HARD_LIMITS_MISMATCH', 'unavailable')
    for field in ('lease_atomically_consumed_once', 'immutable_source_sealed',
                  'kernel_isolation_rechecked', 'hard_resource_limits_armed',
                  'hard_watchdog_and_kill_armed', 'output_stream_bounded'):
        require(copy[field] is True, 'BROKER_SECURITY_INCOMPLETE', 'unavailable')
    return copy


def _read_resources(event: dict[str, Any], previous: dict[str, int],
                    limits: dict[str, int]) -> dict[str, int]:
    info = event.get('resources')
    require(type(info) is dict and set(info) == RESOURCE_KEYS and
            all(type(v) is int and v >= 0 and v <= 2**63 - 1
                for v in info.values()), 'RESOURCE_TELEMETRY_INVALID', 'unavailable')
    # Resource counters are cumulative. Peak pid usage must not go backwards.
    for key in RESOURCE_KEYS:
        require(info[key] >= previous[key], 'RESOURCE_COUNTER_REGRESSED', 'unavailable')
    return dict(info)


def _read_event(raw: Any, previous: dict[str, int],
                limits: dict[str, int]) -> tuple[str, dict[str, int], bytes, str | None, int | None]:
    require(type(raw) is dict, 'BROKER_EVENT_INVALID', 'unavailable')
    kind = raw.get('kind')
    require(type(kind) is str and kind in ('heartbeat', 'output', 'exit'),
            'BROKER_EVENT_INVALID', 'unavailable')
    expected = {'kind', 'resources'}
    if kind == 'output':
        expected |= {'stream', 'chunk'}
    if kind == 'exit':
        expected.add('exit_code')
    require(set(raw) == expected, 'BROKER_EVENT_INVALID', 'unavailable')
    resources = _read_resources(raw, previous, limits)
    chunk, stream, code = b'', None, None
    if kind == 'output':
        stream, chunk = raw['stream'], raw['chunk']
        require(type(stream) is str and stream in ('stdout', 'stderr') and
                type(chunk) is bytes and 1 <= len(chunk) <= MAX_CHUNK,
                'BROKER_OUTPUT_FRAME_INVALID', 'unavailable')
    if kind == 'exit':
        code = raw['exit_code']
        require(type(code) is int and 0 <= code <= 255,
                'BROKER_EXIT_CODE_INVALID', 'unavailable')
    return kind, resources, chunk, stream, code


def _resource_reason(info: dict[str, int], limits: dict[str, int]) -> str | None:
    for key in ('cpu_ms', 'memory_peak_bytes', 'io_bytes', 'processes'):
        if info[key] > limits[key]:
            return 'RESOURCE_' + key.upper() + '_LIMIT'
    return None


def _cleanup(session: Any, why: str, effects: dict[str, Any]) -> None:
    effects['stop_requested'] = True
    try:
        response = session.stop_and_reap(why)
        if (type(response) is dict and set(response) == {'stop_acknowledged', 'reaped'} and
                type(response['stop_acknowledged']) is bool and
                type(response['reaped']) is bool):
            # Host claims only; CES has no kernel process observation.
            effects['stop_acknowledged_by_host'] = response['stop_acknowledged']
            effects['reaped_reported_by_host'] = response['reaped']
    except Exception:
        # Fail closed and retain partial/uncertain termination, never PASS.
        pass


def _effects() -> dict[str, Any]:
    return {
        'security_gate_authorized': False, 'execute_authorized': False,
        'execution_grants_checked': 0, 'additional_root_observations': 0,
        'external_broker_begin_called': False,
        'external_broker_session_reported': False,
        'lease_consumed_reported_by_host': False,
        'commands_launched_by_ces': False, 'tests_verified_by_ces': False,
        'real_kernel_isolation_verified_by_ces': False,
        'writes_performed_by_ces': False, 'stop_requested': False,
        'stop_acknowledged_by_host': False, 'reaped_reported_by_host': False,
        'poll_count': 0, 'output_events': 0,
    }


def _empty_result(reason: str, status: str, effects: dict[str, Any]) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': {'partial': 2, 'invalid_input': 4, 'unavailable': 5}[status],
        'reason_code': PREFIX + reason, 'profile_id': None,
        'limits': None, 'execution': None, 'resources': None,
        'output': None, 'proof': None, 'effects': effects,
        'trust_boundary': 'NO_RUNNER_RESULT_AND_NO_QUALITY_PASS',
    }


def _render(b: bytes) -> str:
    # Strip terminal controls rather than handing escape sequences to a UI.
    return ''.join(c if c == '\n' or (32 <= ord(c) != 127) else '?'
                   for c in b.decode('utf-8', 'replace'))


class QualityRunBudgetController:
    """A host-controlled orchestration boundary; never a subprocess runner.

    The broker MUST be independently trusted, NOT loaded from the repository.
    begin(request) MUST atomically consume the one-use lease and seal/check
    source image+kernel isolation+hard quotas *before* any profile can start;
    it returns a session with `receipt`, `poll(wait_ms, max_chunk_bytes)` and
    `stop_and_reap(reason)`. begin, poll and stop MUST be bounded externally;
    Python cannot preempt a stuck callback. A synthetic/mock session is useful
    for development but never proves real execution or isolation.
    """

    def __init__(self, security_gate: guard.QualityRunSafetyGate,
                 *, monotonic_ns: Callable[[], int] | None = None) -> None:
        if not isinstance(security_gate, guard.QualityRunSafetyGate):
            raise ValueError('An EC186 gate is required')
        if monotonic_ns is not None and not callable(monotonic_ns):
            raise ValueError('Invalid monotonic clock')
        self.gate = security_gate
        self.monotonic_ns = monotonic_ns or time.monotonic_ns

    def run(self, *, repo_root: str, source_pin: dict[str, Any],
            profile_id: str, policy_ticket: dict[str, Any],
            isolation_ticket: dict[str, Any],
            broker: Any = None, limits: dict[str, int] | None = None,
            allow_prepare: bool = False,
            allow_profile_approval: bool = False,
            allow_isolation_lease: bool = False,
            allow_external_execution: bool = False,
            allow_budget_controls: bool = False,
            authorize_root: Callable[[dict[str, Any]], bool] | None = None,
            authorize_gate: Callable[[dict[str, Any]], bool] | None = None,
            authorize_execute: Callable[[dict[str, Any]], bool] | None = None,
            cancel_requested: Callable[[], bool] | None = None) -> dict[str, Any]:
        effects = _effects()
        previous_tick_ns = -1
        def tick() -> int:
            nonlocal previous_tick_ns
            current_ns = _tick(self.monotonic_ns)
            if current_ns < previous_tick_ns:
                raise BudgetError('MONOTONIC_CLOCK_REGRESSED')
            previous_tick_ns = current_ns
            return current_ns
        session = None
        source_seal = None
        result_reason = 'RUNNER_UNAVAILABLE'
        run_state = 'not_started'
        reported_code: int | None = None
        output_raw = bytearray()
        stdout_capture = bytearray()
        stderr_capture = bytearray()
        output_bytes_seen = 0
        output_dropped = 0
        truncated = False
        last_resources = {k: 0 for k in RESOURCE_KEYS}
        begin_ns = 0
        stop_ns = 0
        max_ns = 0
        selected_limits = None
        try:
            require(type(allow_external_execution) is bool and allow_external_execution and
                    type(allow_budget_controls) is bool and allow_budget_controls,
                    'SEPARATE_EXECUTION_OPTINS_REQUIRED', 'unavailable')
            selected_limits = limits_for(limits)
            require(broker is not None and callable(getattr(broker, 'begin', None)),
                    'TRUSTED_BROKER_UNAVAILABLE', 'unavailable')
            require(cancel_requested is None or callable(cancel_requested),
                    'CANCELLATION_SOURCE_INVALID')
            # A fresh EC186 check, not an unsigned/cached EC186 plan used as a
            # bearer token. Produces no runnable argv and consumes no lease.
            gated = self.gate.prepare(
                repo_root=repo_root, source_pin=source_pin, profile_id=profile_id,
                policy_ticket=policy_ticket, isolation_ticket=isolation_ticket,
                allow_prepare=allow_prepare,
                allow_profile_approval=allow_profile_approval,
                allow_isolation_lease=allow_isolation_lease,
                authorize_root=authorize_root, authorize_gate=authorize_gate)
            require(gated['status'] == 'partial' and gated['plan'] is not None,
                    'EC186_GATE_' + gated['reason_code'], 'unavailable')
            effects['security_gate_authorized'] = True
            plan = gated['plan']
            scope = {
                'source_pin_sha256': plan['source_pin_sha256'],
                'profile_id': plan['profile_id'],
                'profile_sha256': plan['profile_sha256'],
                'approval_receipt_sha256': plan['approval_receipt_sha256'],
                'lease_receipt_sha256': plan['lease_receipt_sha256'],
                'image_sha256': gated['isolation']['pinned_image_sha256'],
                'limits': dict(selected_limits),
            }
            _run_grant(authorize_execute, 'BEFORE_BROKER', scope, effects)
            # Cancel before broker reservation/consumption without launching.
            if _cancelled(cancel_requested):
                return _empty_result('CANCELLED_BEFORE_START', 'partial', effects)
            _run_grant(authorize_execute, 'FINAL_BEFORE_BROKER', scope, effects)
            # Authorizer may change root or let approval/lease expire.
            fresh_effects = {'root_observations': 0}
            guard._checked_root(repo_root, source_pin, authorize_root,
                                self.gate.clock, fresh_effects)
            effects['additional_root_observations'] += fresh_effects['root_observations']
            now = guard._now(self.gate.clock)
            guard._fresh_source_pin(source_pin, repo_root, now)
            guard._fresh_ticket(policy_ticket, now, max_age=guard.MAX_APPROVAL_AGE,
                                max_lifetime=guard.MAX_APPROVAL_LIFETIME)
            guard._fresh_ticket(isolation_ticket, now, max_age=guard.MAX_LEASE_AGE,
                                max_lifetime=guard.MAX_LEASE_LIFETIME)
            # Final callbacks might have mutated their input dictionaries.
            # Revalidate BOTH role-specific MACs and the exact receipts from
            # the just-completed EC186 gate before any lease consumption.
            approval_again = guard._verify_ticket(
                policy_ticket, schema=guard.APPROVAL_SCHEMA,
                fields={'schema', 'ticket_id', 'profile_id', 'profile_sha256',
                        'source_pin_sha256', 'issued_at_utc', 'expires_at_utc',
                        'approved_purpose'},
                key=self.gate._policy_key, domain=guard.DOMAIN_APPROVAL, now=now,
                max_age=guard.MAX_APPROVAL_AGE, max_lifetime=guard.MAX_APPROVAL_LIFETIME)
            lease_again = guard._verify_ticket(
                isolation_ticket, schema=guard.LEASE_SCHEMA,
                fields={'schema', 'ticket_id', 'source_pin_sha256',
                        'profile_sha256', 'approval_receipt_sha256',
                        'image_sha256', 'controls', 'issued_at_utc',
                        'expires_at_utc'},
                key=self.gate._broker_key, domain=guard.DOMAIN_LEASE, now=now,
                max_age=guard.MAX_LEASE_AGE, max_lifetime=guard.MAX_LEASE_LIFETIME)
            require(guard._digest(guard.DOMAIN_RECEIPT, approval_again) ==
                    scope['approval_receipt_sha256'] and
                    guard._digest(guard.DOMAIN_RECEIPT, lease_again) ==
                    scope['lease_receipt_sha256'] and
                    approval_again['source_pin_sha256'] == scope['source_pin_sha256'] and
                    lease_again['source_pin_sha256'] == scope['source_pin_sha256'],
                    'FINAL_TICKET_SCOPE_DRIFT', 'unavailable')
            if _cancelled(cancel_requested):
                return _empty_result('CANCELLED_BEFORE_START', 'partial', effects)
            begin_ns = tick()
            max_ns = begin_ns + selected_limits['wall_ms'] * 1_000_000
            # begin MUST be a trusted host primitive; it MUST verify and seal
            # a private read-only immutable source snapshot, recheck actual
            # kernel sandboxing, atomically consume lease and arm quotas BEFORE
            # launching. This controller cannot prove any of those host facts.
            effects['external_broker_begin_called'] = True
            session = broker.begin({**scope, 'repo_root': repo_root,
                                    'source_pin': guard._safe_copy(
                                        source_pin, 'SOURCE_PIN_INVALID', 4096),
                                    'lease_id': isolation_ticket['ticket_id'],
                                    'profile_recipe': guard.catalog_entry(profile_id)['profile'],
                                    'deadline_monotonic_ns': max_ns,
                                    'poll_frame_max_bytes': MAX_CHUNK})
            stop_ns = tick()
            if _cancelled(cancel_requested):
                raise BudgetError('CANCELLED', 'partial')
            if stop_ns >= max_ns:
                raise BudgetError('WALL_TIMEOUT', 'partial')
            require(session is not None and callable(getattr(session, 'poll', None)) and
                    callable(getattr(session, 'stop_and_reap', None)),
                    'BROKER_SESSION_UNAVAILABLE', 'unavailable')
            receipt = _read_session(getattr(session, 'receipt', None),
                                    selected=scope, limits=selected_limits)
            source_seal = receipt['sealed_source_sha256']
            effects['external_broker_session_reported'] = True
            effects['lease_consumed_reported_by_host'] = True
            effects['execute_authorized'] = True
            run_state = 'running'
            while True:
                if _cancelled(cancel_requested):
                    raise BudgetError('CANCELLED', 'partial')
                current = tick()
                if current >= max_ns:
                    raise BudgetError('WALL_TIMEOUT', 'partial')
                if effects['poll_count'] >= MAX_POLLS:
                    raise BudgetError('POLL_EVENT_LIMIT', 'partial')
                wait_ms = min(selected_limits['poll_wait_ms'],
                              max(1, (max_ns - current) // 1_000_000))
                effects['poll_count'] += 1
                event = session.poll(wait_ms, MAX_CHUNK)
                # Verify budget *after* possibly blocking call. External hard
                # watchdog is mandatory; Python alone cannot kill a hung poll.
                after = tick()
                if _cancelled(cancel_requested):
                    raise BudgetError('CANCELLED', 'partial')
                if after >= max_ns:
                    raise BudgetError('WALL_TIMEOUT', 'partial')
                kind, metrics, chunk, stream, exit_code = _read_event(
                    event, last_resources, selected_limits)
                last_resources = metrics
                exceeded = _resource_reason(metrics, selected_limits)
                if exceeded:
                    raise BudgetError(exceeded, 'partial')
                if kind == 'output':
                    effects['output_events'] += 1
                    output_bytes_seen += len(chunk)
                    if output_bytes_seen > metrics['io_bytes']:
                        raise BudgetError('RESOURCE_IO_ACCOUNTING_INCONSISTENT', 'partial')
                    remaining = selected_limits['capture_bytes'] - len(output_raw)
                    kept = chunk[:max(0, remaining)]
                    output_raw.extend(kept)
                    if stream == 'stdout':
                        stdout_capture.extend(kept)
                    else:
                        stderr_capture.extend(kept)
                    output_dropped += len(chunk) - len(kept)
                    # Do not silently discard unlimited output; request hard
                    # stop and honestly preserve bounded partial output.
                    if output_dropped:
                        truncated = True
                        raise BudgetError('OUTPUT_CAPTURE_BUDGET', 'partial')
                elif kind == 'exit':
                    reported_code = exit_code
                    run_state = 'exited_host_reported'
                    result_reason = ('HOST_REPORTED_EXIT_ZERO_UNVERIFIED'
                                     if exit_code == 0 else 'HOST_REPORTED_NONZERO_EXIT')
                    break
            stop_ns = tick()
            if stop_ns >= max_ns:
                raise BudgetError('WALL_TIMEOUT', 'partial')
        except BudgetError as exc:
            result_reason = exc.code
            if not effects['external_broker_begin_called']:
                return _empty_result(exc.code, exc.status, effects)
            run_state = 'interrupted_or_unverified'
        except guard.GateError as exc:
            if not effects['external_broker_begin_called']:
                return _empty_result('EC186_FINAL_' + exc.code, 'unavailable', effects)
            result_reason = 'SOURCE_OR_LEASE_UNAVAILABLE'
            run_state = 'interrupted_or_unverified'
        except KeyboardInterrupt:
            if not effects['external_broker_begin_called']:
                return _empty_result('KEYBOARD_CANCELLED_BEFORE_START', 'partial', effects)
            result_reason = 'KEYBOARD_CANCELLED'
            run_state = 'interrupted_or_unverified'
        except Exception:
            if not effects['external_broker_begin_called']:
                return _empty_result('UNSAFE_OR_UNAVAILABLE_INPUT', 'unavailable', effects)
            result_reason = 'BROKER_OR_CONTROLLER_EXCEPTION'
            run_state = 'interrupted_or_unverified'
        # Any error or uncertainty after begin must attempt host termination.
        # A reported exit is not enough to prove process/descendants reaped;
        # caller broker must handle that in its contract and real implementation.
        if session is not None and run_state != 'exited_host_reported':
            _cleanup(session, result_reason, effects)
        if effects['external_broker_begin_called'] and session is None:
            effects['stop_requested'] = True  # begin's host atomic rollback required
        if begin_ns:
            try:
                stop_ns = max(stop_ns, tick())
            except BudgetError:
                stop_ns = max(stop_ns, begin_ns)
        elapsed_ms = min(2**63 - 1, max(0, (stop_ns - begin_ns) // 1_000_000)) if begin_ns else 0
        # Once a host broker may have begun, always retain a small partial
        # result with explicit uncertainty; never claim a verified run or PASS.
        execution = {
            'state': run_state,
            'host_reported_exit_code': reported_code,
            'elapsed_ms_observed_locally': elapsed_ms,
            'source_snapshot_sha256_host_claim': source_seal,
            'lease_consumption_only_host_reported': effects['lease_consumed_reported_by_host'],
            'actual_process_exit_independently_verified': False,
            'overall_pass_verified': False,
        }
        resources = dict(last_resources)
        resources['telemetry_host_reported_only'] = True
        output = {
            'stdout_preview': _render(bytes(stdout_capture)),
            'stderr_preview': _render(bytes(stderr_capture)),
            'captured_bytes': len(output_raw),
            'observed_bytes': output_bytes_seen,
            'discarded_bytes': output_dropped,
            'truncated': truncated,
            'observed_content_sha256': hashlib.sha256(bytes(output_raw)).hexdigest(),
            'complete': run_state == 'exited_host_reported' and not truncated,
        }
        proof = {
            'source_contents_independently_verified': False,
            'kernel_isolation_independently_verified': False,
            'broker_identity_independently_authenticated': False,
            'test_execution_verified_by_ces': False,
            'quality_pass_verified': False,
            'budget_enforcement_guaranteed_by_ces': False,
            'host_claims_only': True,
        }
        out = {
            'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
            'reason_code': PREFIX + result_reason,
            'profile_id': profile_id if effects['execute_authorized'] else None,
            'limits': selected_limits,
            'execution': execution, 'resources': resources,
            'output': output, 'proof': proof, 'effects': effects,
            'trust_boundary': 'HOST_SESSION_REPORT_ONLY_NO_ATTESTED_QUALITY_PASS',
        }
        # Defense against unbounded/unexpected output by a compromised adapter.
        # Return no success and no unauthorized enlarged response.
        try:
            require(len(guard._canonical(out)) <= MAX_RESULT_SIZE,
                    'RESULT_TOO_LARGE', 'unavailable')
            return out
        except (BudgetError, ValueError, TypeError):
            return _empty_result('RESULT_TOO_LARGE', 'unavailable', effects)
