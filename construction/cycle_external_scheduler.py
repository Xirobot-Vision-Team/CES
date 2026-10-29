#!/usr/bin/env python3
"""EC239 external recurring-scheduler *invocation boundary*, not a scheduler.

An external host can invoke a strictly allowlisted EC237 read-only Summary
inspection of an already saved, externally SHA-pinned EC231 Cycle Run.  No
cron/Task Scheduler installation, timer, job persistence, OS command execution,
native Cycle action, business step, permission grant or EC240 de-duplication is
performed.  Host scheduler, event ID and scheduled time are *caller claims*.

Plan returns instructions; invoke performs exactly one read-only inspection.
Nonzero exit codes (2/3/5) deliberately never mean business completion.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

if __package__:
    from . import cycle_run_metadata as md
    from . import cycle_summary as sm
else:
    import cycle_run_metadata as md
    import cycle_summary as sm

SCHEMA = 'ces.cycle_external_scheduler_boundary.v1'
ENTRYPOINT = 'construction/cycle_external_scheduler.py'
SCHEDULE_RE = re.compile(r'[A-Za-z][A-Za-z0-9._:-]{2,71}\Z')
EVENT_RE = re.compile(r'evt_[A-Za-z0-9_-]{12,80}\Z')
CADENCES = {'hourly': '0 * * * *', 'daily': '0 0 * * *',
            'weekly': '0 0 * * 1'}  # UTC; Monday at 00:00 UTC
SCHEDULER_KINDS = frozenset(('cron', 'windows_task', 'orchestrator'))
HOST_STATES = frozenset(('absent', 'claimed_configured'))
STATUS_CODES = {'INSTRUCTIONS_ONLY': 2, 'CONFIG_CLAIM_ONLY': 2,
                'CHECK_OBSERVED_ONLY': 2, 'CHECK_BLOCKED': 3,
                'PLAN_REJECTED': 3, 'TRIGGER_REJECTED': 3, 'UNKNOWN_BLOCKED': 5}
BLOCKED_SUMMARIES = frozenset((
    'BLOCKED_DAG_CYCLE', 'BLOCKED_NO_HANDLER', 'UNVERIFIED_PROGRESS_BLOCKED',
))
ALL_SUMMARIES = sm.STATES
MAX_JSON_OUTPUT = 196_608  # Nested EC237 report is limited to 128 KiB.


class ExternalScheduleError(ValueError):
    """A conservative non-secret machine error; known means caller can fix it."""
    def __init__(self, code: str, *, known: bool = True) -> None:
        super().__init__(code)
        self.code = code
        self.known = known


def _require(ok: bool, code: str, *, known: bool = True) -> None:
    if not ok:
        raise ExternalScheduleError(code, known=known)


def _utc_tick(value: str, cadence: str) -> None:
    """Validate a caller's *declared* scheduled tick, not actual host timing."""
    _require(type(value) is str and md.UTC_RE.fullmatch(value) is not None,
             'EXTERNAL_SCHEDULE_TICK_INVALID')
    try:
        t = md.timestamp(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ExternalScheduleError('EXTERNAL_SCHEDULE_TICK_INVALID') from exc
    _require(t.second == 0 and t.microsecond == 0 and t.minute == 0,
             'EXTERNAL_SCHEDULE_TICK_NOT_ON_CADENCE')
    if cadence in ('daily', 'weekly'):
        _require(t.hour == 0, 'EXTERNAL_SCHEDULE_TICK_NOT_ON_CADENCE')
    if cadence == 'weekly':
        _require(t.weekday() == 0, 'EXTERNAL_SCHEDULE_TICK_NOT_ON_CADENCE')


def _empty(operation: str) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'operation': operation, 'status': 'UNKNOWN_BLOCKED',
        'reason_code': 'EXTERNAL_SCHEDULE_UNKNOWN', 'run_id': None,
        'record_binding': None,
        'scheduler': {
            'kind': None, 'schedule_id': None, 'host_state_claim': None,
            'external_installation_verified': False, 'external_cadence_verified': False,
            'external_trigger_authenticated': False, 'scheduled_job_created': False,
        },
        'cadence': {'kind': None, 'timezone': 'UTC', 'cron_utc_reference': None,
                    'scheduled_for_utc_claim': None, 'tick_alignment_checked': False},
        'trigger': {'event_id_claim': None, 'supplied_by_caller': False,
                    'execution_on_schedule_proven': False, 'deduplication_checked': False},
        'invocation': {'command_argv_template': [], 'host_setup_required': True,
                       'command_executed_by_this_module': False,
                       'shell_used_by_this_module': False},
        'preconditions': {
            'existing_private_ec231_run_read': False,
            'three_caller_sha_pins_match_local_record': False,
            'external_scheduler_authority_verified': False,
            'actor_authenticated': False,
            'business_input_source_authenticated': False,
            'independent_permission_granted': False,
        },
        'check': {'kind': 'cycle_summary', 'called': False,
                  'summary_status': None, 'summary': None},
        'effects': {
            'local_read_only_summary_observed': False,
            'native_action_dispatched': False, 'cycle_steps_executed': False,
            'business_writes_performed': False, 'local_records_written': False,
            'scheduler_installed': False, 'permission_granted': False,
            'business_success_proven': False, 'external_delivery_proven': False,
            'duplicate_or_overlap_prevented': False,
        },
        'outstanding': {
            'scheduler_host_installation': 'NOT_VERIFIED',
            'trigger_origin_and_clock': 'UNVERIFIED_CALLER_CLAIMS',
            'duplicate_concurrent_delivery': 'NOT_IMPLEMENTED_EC240',
            'native_cycle_routing': 'NOT_IMPLEMENTED_EC241',
        },
    }


def _argv(*, store: Path, run_id: str, cadence: str, kind: str,
          schedule_id: str, pins: dict[str, str]) -> list[str]:
    """An argument vector, never an assembled/interpreted shell command."""
    return [sys.executable, str(Path(__file__).absolute()), 'invoke',
            '--store', str(store), '--run-id', run_id,
            '--cadence', cadence, '--scheduler-kind', kind,
            '--host-state', 'claimed_configured', '--schedule-id', schedule_id,
            '--expected-record-sha256', pins['record_sha256'],
            '--expected-action-set-sha256', pins['action_set_sha256'],
            '--expected-input-sha256', pins['input_sha256'],
            '--trigger-id', '<external-unique-event-id>',
            '--scheduled-for-utc', '<UTC-scheduled-tick-with-6-decimal-seconds>']


def _serialize(out: dict[str, Any]) -> bytes:
    """One full bounded ASCII JSON line; no partial output on overflow."""
    data = md.canonical(out)
    _require(len(data) + 1 <= MAX_JSON_OUTPUT, 'EXTERNAL_SCHEDULE_RESULT_TOO_LARGE',
             known=False)
    return data + b'\n'


class CycleExternalSchedulerBoundary:
    """No persisted state and no scheduler subprocess; read-only EC237 adapter.

    Pins MUST be saved independently of the current EC231 read. Hash pins
    defend some accidental state drift, not malicious same-UID edits or actor
    authenticity. This module must not be used to authorize execution.
    """

    def __init__(self, private_dir: str | Path, *,
                 package_root: str | Path | None = None) -> None:
        self.path = Path(private_dir)
        self.store = md.CycleMetadataStore(private_dir)
        self.reporter = sm.CycleSummaryReporter(private_dir, package_root=package_root)

    def plan(self, run_id: str, *, cadence: str, scheduler_kind: str,
             host_state: str, schedule_id: str,
             expected_record_sha256: str, expected_action_set_sha256: str,
             expected_input_sha256: str) -> dict[str, Any]:
        return self._run('plan', run_id, cadence=cadence,
                         scheduler_kind=scheduler_kind, host_state=host_state,
                         schedule_id=schedule_id,
                         expected_record_sha256=expected_record_sha256,
                         expected_action_set_sha256=expected_action_set_sha256,
                         expected_input_sha256=expected_input_sha256)

    def invoke(self, run_id: str, *, cadence: str, scheduler_kind: str,
               host_state: str, schedule_id: str,
               expected_record_sha256: str, expected_action_set_sha256: str,
               expected_input_sha256: str, trigger_id: str,
               scheduled_for_utc: str) -> dict[str, Any]:
        return self._run('invoke', run_id, cadence=cadence,
                         scheduler_kind=scheduler_kind, host_state=host_state,
                         schedule_id=schedule_id,
                         expected_record_sha256=expected_record_sha256,
                         expected_action_set_sha256=expected_action_set_sha256,
                         expected_input_sha256=expected_input_sha256,
                         trigger_id=trigger_id, scheduled_for_utc=scheduled_for_utc)

    def _run(self, operation: str, run_id: str, *, cadence: str,
             scheduler_kind: str, host_state: str, schedule_id: str,
             expected_record_sha256: str, expected_action_set_sha256: str,
             expected_input_sha256: str, trigger_id: str | None = None,
             scheduled_for_utc: str | None = None) -> dict[str, Any]:
        out = _empty(operation)
        pins = {'record_sha256': expected_record_sha256,
                'action_set_sha256': expected_action_set_sha256,
                'input_sha256': expected_input_sha256}
        try:
            _require(operation in ('plan', 'invoke'), 'EXTERNAL_SCHEDULE_OPERATION_INVALID')
            _require(self.path.is_absolute(), 'EXTERNAL_SCHEDULE_STORE_NOT_ABSOLUTE')
            _require(type(cadence) is str and cadence in CADENCES,
                     'EXTERNAL_SCHEDULE_CADENCE_INVALID')
            _require(type(scheduler_kind) is str and scheduler_kind in SCHEDULER_KINDS,
                     'EXTERNAL_SCHEDULE_KIND_INVALID')
            _require(type(host_state) is str and host_state in HOST_STATES,
                     'EXTERNAL_SCHEDULE_HOST_STATE_INVALID')
            _require(type(schedule_id) is str and SCHEDULE_RE.fullmatch(schedule_id) is not None,
                     'EXTERNAL_SCHEDULE_ID_INVALID')
            _require(type(run_id) is str and md.RUN_RE.fullmatch(run_id) is not None,
                     'EXTERNAL_SCHEDULE_RUN_ID_INVALID')
            for name, pin in pins.items():
                _require(type(pin) is str and md.SHA_RE.fullmatch(pin) is not None,
                         'EXTERNAL_SCHEDULE_' + name.upper() + '_PIN_INVALID')
            out['run_id'] = run_id
            out['scheduler'].update({'kind': scheduler_kind, 'schedule_id': schedule_id,
                                     'host_state_claim': host_state})
            out['cadence'].update({'kind': cadence,
                                   'cron_utc_reference': CADENCES[cadence]})
            _require((operation == 'invoke') == (trigger_id is not None and
                                                 scheduled_for_utc is not None),
                     'EXTERNAL_SCHEDULE_TRIGGER_FIELDS_INVALID')
            if operation == 'invoke':
                _require(type(trigger_id) is str and EVENT_RE.fullmatch(trigger_id) is not None,
                         'EXTERNAL_SCHEDULE_EVENT_ID_INVALID')
                out['trigger'].update({'event_id_claim': trigger_id,
                                       'supplied_by_caller': True})
                out['cadence']['scheduled_for_utc_claim'] = scheduled_for_utc
                _utc_tick(scheduled_for_utc, cadence)
                out['cadence']['tick_alignment_checked'] = True
                # An absent scheduler has no legitimate scheduled trigger,
                # even if a caller invents an event ID or calls the CLI.
                _require(host_state == 'claimed_configured',
                         'EXTERNAL_SCHEDULE_HOST_DECLARED_ABSENT')

            # Load genuine existing private EC231 metadata, not a caller's
            # arbitrary JSON record. A missing/malformed/pin-drift run is
            # UNKNOWN, not a newly schedulable Run or a partial summary.
            record = self.store.load(run_id)
            for key, actual in (('record_sha256', record['record_sha256']),
                                ('action_set_sha256', record['action_set_sha256']),
                                ('input_sha256', record['input']['sha256'])):
                _require(pins[key] == actual, 'EXTERNAL_SCHEDULE_PIN_MISMATCH', known=False)
            reread = self.store.load(run_id)
            _require(md.canonical(reread) == md.canonical(record),
                     'EXTERNAL_SCHEDULE_RECORD_DRIFT', known=False)
            out['record_binding'] = dict(pins)
            out['preconditions']['existing_private_ec231_run_read'] = True
            out['preconditions']['three_caller_sha_pins_match_local_record'] = True
            if operation == 'plan':
                out['invocation']['command_argv_template'] = _argv(
                    store=self.path, run_id=run_id, cadence=cadence, kind=scheduler_kind,
                    schedule_id=schedule_id, pins=pins)
                out['status'] = ('INSTRUCTIONS_ONLY' if host_state == 'absent'
                                 else 'CONFIG_CLAIM_ONLY')
                out['reason_code'] = ('EXTERNAL_SCHEDULE_NO_HOST_JOB_INSTRUCTIONS_ONLY'
                                      if host_state == 'absent' else
                                      'EXTERNAL_SCHEDULE_HOST_CONFIGURATION_UNVERIFIED')
                return out

            # One actual read-only inspection in this Python process. Never
            # execute argv, invoke handlers, install scheduler or write a run.
            summary = self.reporter.summary(
                run_id, expected_record_sha256=pins['record_sha256'],
                expected_action_set_sha256=pins['action_set_sha256'],
                expected_input_sha256=pins['input_sha256'])
            _require(type(summary) is dict and summary.get('status') in ALL_SUMMARIES,
                     'EXTERNAL_SCHEDULE_SUMMARY_INVALID', known=False)
            # The summary is already validated by EC237; revalidate shape to
            # avoid accepting a substituted result in this outer boundary.
            _require(sm.validate_result(summary) == summary,
                     'EXTERNAL_SCHEDULE_SUMMARY_INVALID', known=False)
            after = self.store.load(run_id)
            _require(md.canonical(after) == md.canonical(record),
                     'EXTERNAL_SCHEDULE_RECORD_CHANGED_DURING_CHECK', known=False)
            if summary['status'] == 'UNKNOWN_BLOCKED':
                raise ExternalScheduleError('EXTERNAL_SCHEDULE_SUMMARY_UNKNOWN', known=False)
            out['check'].update({'called': True, 'summary_status': summary['status'],
                                 'summary': summary})
            out['effects']['local_read_only_summary_observed'] = True
            if summary['status'] in BLOCKED_SUMMARIES:
                out.update({'status': 'CHECK_BLOCKED',
                            'reason_code': 'EXTERNAL_SCHEDULE_READ_ONLY_CHECK_BLOCKED'})
            else:
                out.update({'status': 'CHECK_OBSERVED_ONLY',
                            'reason_code': 'EXTERNAL_SCHEDULE_READ_ONLY_OBSERVATION_ONLY'})
            # Repeat/replay/overlap is NOT controlled in EC239. Never claim
            # repeated invocations are deduplicated or safe for business writes.
            _serialize(out)
            return out
        except ExternalScheduleError as exc:
            # No local result or command from a failed partial validation.
            failed = _empty(operation)
            failed['status'] = (('PLAN_REJECTED' if operation == 'plan' else 'TRIGGER_REJECTED')
                                if exc.known else 'UNKNOWN_BLOCKED')
            failed['reason_code'] = exc.code
            return failed
        except (md.CycleMetadataError, OSError, ValueError, TypeError, KeyError,
                OverflowError, RecursionError, RuntimeError) as exc:
            failed = _empty(operation)
            failed['reason_code'] = (exc.code if isinstance(exc, md.CycleMetadataError)
                                     else 'EXTERNAL_SCHEDULE_SOURCE_OR_IO_UNKNOWN')
            return failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC239 host-invoked READ-ONLY Cycle inspection; NOT a scheduler')
    parser.add_argument('operation', choices=('plan', 'invoke'))
    parser.add_argument('--store', required=True, help='absolute owner-private EC231 directory')
    parser.add_argument('--run-id', required=True, help='existing EC231 RunId')
    parser.add_argument('--cadence', choices=sorted(CADENCES), required=True)
    parser.add_argument('--scheduler-kind', choices=sorted(SCHEDULER_KINDS), required=True)
    parser.add_argument('--host-state', choices=sorted(HOST_STATES), required=True,
                        help='caller declaration, never discovered/verified on host')
    parser.add_argument('--schedule-id', required=True, help='opaque caller schedule ID, not proof')
    parser.add_argument('--expected-record-sha256', required=True)
    parser.add_argument('--expected-action-set-sha256', required=True)
    parser.add_argument('--expected-input-sha256', required=True)
    parser.add_argument('--trigger-id', default=None, help='external claimed unique event ID; invoke only')
    parser.add_argument('--scheduled-for-utc', default=None,
                        help='external claimed canonical scheduled UTC tick; invoke only')
    args = parser.parse_args(argv)
    boundary = CycleExternalSchedulerBoundary(args.store)
    common = dict(cadence=args.cadence, scheduler_kind=args.scheduler_kind,
                  host_state=args.host_state, schedule_id=args.schedule_id,
                  expected_record_sha256=args.expected_record_sha256,
                  expected_action_set_sha256=args.expected_action_set_sha256,
                  expected_input_sha256=args.expected_input_sha256)
    try:
        if args.operation == 'plan':
            if args.trigger_id is not None or args.scheduled_for_utc is not None:
                raise ExternalScheduleError('EXTERNAL_SCHEDULE_PLAN_TRIGGER_FIELDS_FORBIDDEN')
            out = boundary.plan(args.run_id, **common)
        else:
            if args.trigger_id is None or args.scheduled_for_utc is None:
                raise ExternalScheduleError('EXTERNAL_SCHEDULE_INVOKE_TRIGGER_REQUIRED')
            out = boundary.invoke(args.run_id, **common,
                                  trigger_id=args.trigger_id,
                                  scheduled_for_utc=args.scheduled_for_utc)
        payload = _serialize(out)
    except ExternalScheduleError as exc:
        out = _empty(args.operation)
        out['status'] = (('PLAN_REJECTED' if args.operation == 'plan' else 'TRIGGER_REJECTED')
                         if exc.known else 'UNKNOWN_BLOCKED')
        out['reason_code'] = exc.code
        payload = _serialize(out)
    # Flush exactly one complete message and no shell/subprocess. A stdout
    # pipe failure is not a successful check or a persisted scheduler receipt.
    try:
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
    except (OSError, BrokenPipeError):
        return 5
    return STATUS_CODES[out['status']]


if __name__ == '__main__':
    sys.exit(main())
