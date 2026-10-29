#!/usr/bin/env python3
"""EC240 guarded, durable *local* idempotency for two existing CES entrypoints.

An EC239 read-only scheduled check or EC238 local cross-artifact attachment is
reserved under a per-Cycle POSIX advisory flock and a fsynced private journal.
An unresolved reservation permanently blocks this guarded Run until human
reconciliation; no TTL/lease expiry or automatic retry can invent exactly-once
business effects. Business write/permission attempts are always denied here.

Only callers that use THIS wrapper get this single-host/single-filesystem guard;
old EC238/239 APIs and original PowerShell do not implicitly acquire it.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
try:
    import fcntl  # type: ignore[import-not-found]
except ImportError:  # Windows cannot use this POSIX-only guarded writer.
    fcntl = None  # type: ignore[assignment]
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Iterator

if __package__:
    from . import cycle_run_metadata as md
    from . import cycle_external_scheduler as ex
    from . import cycle_cross_action as cc
else:
    import cycle_run_metadata as md
    import cycle_external_scheduler as ex
    import cycle_cross_action as cc

SCHEMA = 'ces.cycle_conflict_guard.v1'
LEDGER_SCHEMA = 'ces.cycle_conflict_ledger.v1'
LEDGER_DOMAIN = b'CES-EC240-LOCAL-LEDGER-v1\x00'
MAX_ENTRIES = 1024
MAX_LEDGER_BYTES = 1_048_576
MAX_OUTPUT_BYTES = 16_384
UPLOAD_RE = re.compile(r'upl_[A-Za-z0-9_-]{12,80}\Z')
REQUEST_RE = re.compile(r'(?:evt_|upl_)[A-Za-z0-9_-]{12,80}\Z')
RESULT_CODES = {
    'RECORDED_OBSERVATION': 2,
    'RECORDED_CHECK_BLOCK': 3,
    'RECORDED_LOCAL_ATTACHMENT': 2,
    'REPLAY_SUPPRESSED': 2,
    'NO_RECEIPT': 2,
    'RECEIPT_OBSERVED': 2,
    'REJECTED': 3,
    'CONFLICT_BLOCKED': 3,
    'OVERLAP_BLOCKED': 3,
    'PERMISSION_DENIED': 3,
    'UNKNOWN_BLOCKED': 5,
}
VALID_OPERATIONS = frozenset(('scheduled_summary', 'artifact_attach',
                              'inspect', 'business_write_attempt'))
ENTRY_KINDS = frozenset(('scheduled_summary', 'artifact_attach'))
FINAL_SOURCE_STATES = frozenset(('CHECK_OBSERVED_ONLY', 'CHECK_BLOCKED',
                                 'ATTACHED_LOCAL_ONLY'))


class ConflictError(Exception):
    def __init__(self, code: str, *, unknown: bool = False,
                 status: str = 'REJECTED') -> None:
        super().__init__(code)
        self.code, self.unknown, self.status = code, unknown, status


def need(condition: bool, code: str, *, unknown: bool = False,
         status: str = 'REJECTED') -> None:
    if not condition:
        raise ConflictError(code, unknown=unknown, status=status)


def _sha(value: Any) -> bool:
    return type(value) is str and md.SHA_RE.fullmatch(value) is not None


def _now() -> str:
    # Audit metadata, not an authenticated clock or lease expiration.
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def _hash(value: Any) -> str:
    return hashlib.sha256(md.canonical(value)).hexdigest()


def _ledger_hash(value: dict[str, Any]) -> str:
    return md.digest(LEDGER_DOMAIN, value)


def _record_binding(record: dict[str, Any]) -> dict[str, str]:
    return {'record_sha256': record['record_sha256'],
            'action_set_sha256': record['action_set_sha256'],
            'input_sha256': record['input']['sha256']}


def _empty(operation: str) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'operation': operation, 'status': 'UNKNOWN_BLOCKED',
        'reason_code': 'CONFLICT_GUARD_UNKNOWN', 'run_id': None,
        'request_id': None, 'receipt': None,
        'source_observation': {'status': None, 'reason_code': None,
                               'result_sha256': None, 'called_now': False,
                               'returned_prior_result': False},
        'effects': {'ec239_summary_called': False,
                    'ec238_local_artifact_attach_called': False,
                    'new_guard_reservation_persisted': False,
                    'new_guard_final_receipt_persisted': False,
                    'repeat_operation_suppressed': False,
                    'business_code_executed': False,
                    'business_write_performed': False,
                    'native_action_dispatched': False,
                    'permission_granted': False,
                    'external_scheduler_installed': False},
        'guarantees': {
            'scope': 'GUARDED_EC239_EC238_LOCAL_POSIX_PROCESS_ONLY',
            'cross_process_advisory_lock': True,
            'local_receipt_self_hash_not_signature': True,
            'automatic_retry_on_ambiguity': False,
            'exactly_once_business_effects_proven': False,
            'source_actor_permission_authenticated': False,
            'unguarded_old_entrypoints_protected': False,
            'same_uid_rollback_nfs_multihost_os_crash_proven': False,
            'native_cycle_routing': False,
        },
    }


def _result(operation: str, status: str, code: str, *, run_id: str | None = None,
            request_id: str | None = None, entry: dict[str, Any] | None = None,
            first_result: dict[str, Any] | None = None, effects: dict[str, bool] | None = None
            ) -> dict[str, Any]:
    out = _empty(operation)
    out.update({'status': status, 'reason_code': code,
                'run_id': run_id, 'request_id': request_id})
    if entry is not None:
        out['receipt'] = {
            'kind': entry['kind'], 'slot_sha256': entry['slot_sha256'],
            'intent_sha256': entry['intent_sha256'], 'phase': entry['phase'],
            'first_request_id': entry['request_id'],
            'started_at_utc_unverified': entry['started_at_utc_unverified'],
            'finalized_at_utc_unverified': entry['finalized_at_utc_unverified'],
        }
        if entry['phase'] == 'FINAL':
            out['source_observation'].update({
                'status': entry['source_status'],
                'reason_code': entry['source_reason_code'],
                'result_sha256': entry['result_sha256'],
            })
    if first_result is not None:
        out['source_observation']['called_now'] = True
    if effects:
        out['effects'].update(effects)
    return out


def _encoded(value: dict[str, Any], maximum: int) -> bytes:
    raw = md.canonical(value) + b'\n'
    need(len(raw) <= maximum, 'CONFLICT_SERIALIZED_SIZE_EXCEEDED', unknown=True)
    return raw


def validate_ledger(value: Any, run_id: str, binding: dict[str, str]) -> dict[str, Any]:
    """Check all receipt fields and self-hash; never trust arbitrary JSON."""
    err = 'CONFLICT_LEDGER_CORRUPT_OR_ROLLED_BACK'
    need(type(value) is dict and set(value) == {
        'schema', 'run_id', 'record_binding', 'entries', 'ledger_sha256'},
        err, unknown=True)
    need(value['schema'] == LEDGER_SCHEMA and value['run_id'] == run_id and
         value['record_binding'] == binding and
         type(value['entries']) is list and len(value['entries']) <= MAX_ENTRIES and
         _sha(value['ledger_sha256']), err, unknown=True)
    ids, slots = set(), set()
    for e in value['entries']:
        need(type(e) is dict and set(e) == {
            'kind', 'request_id', 'slot_sha256', 'intent_sha256', 'phase',
            'started_at_utc_unverified', 'finalized_at_utc_unverified',
            'source_status', 'source_reason_code', 'result_sha256',
        }, err, unknown=True)
        need(e['kind'] in ENTRY_KINDS and type(e['request_id']) is str and
             REQUEST_RE.fullmatch(e['request_id']) is not None and
             ((e['kind'] == 'scheduled_summary' and e['request_id'].startswith('evt_')) or
              (e['kind'] == 'artifact_attach' and e['request_id'].startswith('upl_'))) and
             _sha(e['slot_sha256']) and _sha(e['intent_sha256']) and
             e['phase'] in ('RESERVED', 'FINAL') and
             type(e['started_at_utc_unverified']) is str and
             md.UTC_RE.fullmatch(e['started_at_utc_unverified']) is not None and
             e['request_id'] not in ids and e['slot_sha256'] not in slots,
             err, unknown=True)
        try:
            md.timestamp(e['started_at_utc_unverified'])
        except (ValueError, TypeError, OverflowError) as exc:
            raise ConflictError(err, unknown=True) from exc
        ids.add(e['request_id'])
        slots.add(e['slot_sha256'])
        if e['phase'] == 'RESERVED':
            need(e['finalized_at_utc_unverified'] is None and
                 e['source_status'] is None and e['source_reason_code'] is None and
                 e['result_sha256'] is None, err, unknown=True)
        else:
            need(e['source_status'] in FINAL_SOURCE_STATES and
                 type(e['source_reason_code']) is str and
                 re.fullmatch(r'[A-Z][A-Z0-9_]{2,127}', e['source_reason_code']) is not None and
                 _sha(e['result_sha256']) and
                 type(e['finalized_at_utc_unverified']) is str and
                 md.UTC_RE.fullmatch(e['finalized_at_utc_unverified']) is not None,
                 err, unknown=True)
            try:
                md.timestamp(e['finalized_at_utc_unverified'])
            except (ValueError, TypeError, OverflowError) as exc:
                raise ConflictError(err, unknown=True) from exc
    need(value['ledger_sha256'] == _ledger_hash({k: v for k, v in value.items()
                                                if k != 'ledger_sha256'}),
         err, unknown=True)
    need(len(md.canonical(value) + b'\n') <= MAX_LEDGER_BYTES,
         err, unknown=True)
    return value


def _name(run_id: str, suffix: str) -> str:
    return run_id + '.ec240.' + suffix


def _open_regular(fd: int, name: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    f = os.open(name, flags, dir_fd=fd)
    try:
        s = os.fstat(f)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and
             stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and
             0 < s.st_size <= maximum, 'CONFLICT_FILE_NOT_PRIVATE', unknown=True)
        chunks, remaining = [], maximum + 1
        while remaining:
            raw = os.read(f, min(65536, remaining))
            if not raw:
                break
            chunks.append(raw)
            remaining -= len(raw)
        data = b''.join(chunks)
        need(len(data) == s.st_size, 'CONFLICT_FILE_CHANGED_DURING_READ', unknown=True)
        return data
    finally:
        os.close(f)


def _assert_no_orphan(fd: int, run_id: str) -> None:
    # An interrupted atomic replacement leaves a temp; do not silently delete.
    try:
        os.stat(_name(run_id, 'swap'), dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ConflictError('CONFLICT_ORPHAN_SWAP_MANUAL_RECONCILIATION', unknown=True)


def _load(fd: int, run_id: str, binding: dict[str, str]) -> dict[str, Any] | None:
    _assert_no_orphan(fd, run_id)
    try:
        raw = _open_regular(fd, _name(run_id, 'ledger.json'), MAX_LEDGER_BYTES)
    except FileNotFoundError:
        return None
    try:
        document = md.strict_json(raw, MAX_LEDGER_BYTES)
    except md.CycleMetadataError as exc:
        raise ConflictError('CONFLICT_LEDGER_CORRUPT_OR_ROLLED_BACK', unknown=True) from exc
    return validate_ledger(document, run_id, binding)


def _save(fd: int, run_id: str, binding: dict[str, str],
          value: dict[str, Any], previous: dict[str, Any] | None) -> None:
    body = {k: v for k, v in value.items() if k != 'ledger_sha256'}
    candidate = {**body, 'ledger_sha256': _ledger_hash(body)}
    validate_ledger(candidate, run_id, binding)
    raw = _encoded(candidate, MAX_LEDGER_BYTES)
    current = _load(fd, run_id, binding)
    need(current == previous, 'CONFLICT_LEDGER_CHANGED_DURING_COMMIT', unknown=True)
    name = _name(run_id, 'ledger.json')
    temporary = _name(run_id, 'swap')
    target = name if previous is None else temporary
    created = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                      os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), 0o600, dir_fd=fd)
    try:
        os.fchmod(created, 0o600)
        md._write_all(created, raw)
        os.fsync(created)
    finally:
        os.close(created)
    if previous is not None:
        # No existing ledger is modified in-place. Rename is a single-file
        # atomic visibility boundary, NOT a cross-file business transaction.
        os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)
    need(_load(fd, run_id, binding) == candidate,
         'CONFLICT_LEDGER_COMMIT_READBACK_UNKNOWN', unknown=True)


@contextmanager
def _locked(fd: int, run_id: str) -> Iterator[None]:
    """Process-scoped nonblocking flock; file itself persists after release."""
    need(os.name == 'posix' and fcntl is not None,
         'CONFLICT_POSIX_FLOCK_REQUIRED', unknown=True)
    name = _name(run_id, 'lock')
    flags = os.O_RDWR | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    try:
        lockfd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
    except FileExistsError:
        lockfd = os.open(name, flags, dir_fd=fd)
    try:
        s = os.fstat(lockfd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and
             stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1,
             'CONFLICT_LOCK_FILE_NOT_PRIVATE', unknown=True)
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ConflictError('CONFLICT_PARALLEL_ACTIVE', status='OVERLAP_BLOCKED') from exc
        try:
            # Ensure lock file creation itself is durable where locally supported.
            os.fsync(lockfd)
            os.fsync(fd)
            yield
        finally:
            fcntl.flock(lockfd, fcntl.LOCK_UN)
    finally:
        os.close(lockfd)


class CycleConflictGuard:
    """Only existing EC239 Summary + EC238 *local* artifact receipts; no writer."""

    def __init__(self, cycle_store: str | Path, *, package_root: str | Path | None = None):
        self.path = Path(cycle_store)
        self.store = md.CycleMetadataStore(cycle_store)
        self.scheduler = ex.CycleExternalSchedulerBoundary(cycle_store,
                                                            package_root=package_root)

    def _binding(self, run_id: str, pins: dict[str, str]) -> dict[str, str]:
        need(type(run_id) is str and md.RUN_RE.fullmatch(run_id) is not None,
             'CONFLICT_RUN_ID_INVALID')
        need(type(pins) is dict and set(pins) == {
            'record_sha256', 'action_set_sha256', 'input_sha256'} and
            all(_sha(v) for v in pins.values()), 'CONFLICT_EXTERNAL_PINS_INVALID')
        record = self.store.load(run_id)
        need(_record_binding(record) == pins,
             'CONFLICT_EXTERNAL_RUN_BINDING_DRIFT', unknown=True)
        return _record_binding(record)

    def _guarded(self, kind: str, run_id: str, pins: dict[str, str],
                 request_id: str, slot: dict[str, Any], intent: dict[str, Any],
                 preflight: Callable[[], None], operation: Callable[[], dict[str, Any]],
                 validate_source: Callable[[dict[str, Any]], None]
                 ) -> dict[str, Any]:
        binding = self._binding(run_id, pins)
        slot_sha, intent_sha = _hash(slot), _hash(intent)
        fd = md._safe_dir(self.path, create=False)
        try:
            with _locked(fd, run_id):
                self._binding(run_id, pins)  # original private EC231 still genuine
                ledger = _load(fd, run_id, binding)
                entries = [] if ledger is None else ledger['entries']
                # Unknown reservation poisons the whole *guarded* Run: new IDs,
                # other ticks and artifact attachment all fail closed.
                pending = next((r for r in entries if r['phase'] == 'RESERVED'), None)
                if pending is not None:
                    return _result(kind, 'UNKNOWN_BLOCKED',
                                   'CONFLICT_INTERRUPTED_RESERVATION_REQUIRES_RECONCILIATION')
                by_id = next((r for r in entries if r['request_id'] == request_id), None)
                by_slot = next((r for r in entries if r['slot_sha256'] == slot_sha), None)
                if by_id is not None and (by_id['slot_sha256'] != slot_sha or
                                         by_id['intent_sha256'] != intent_sha):
                    return _result(kind, 'CONFLICT_BLOCKED',
                                   'CONFLICT_REQUEST_ID_REUSED_WITH_DIFFERENT_INTENT')
                if by_slot is not None:
                    if by_slot['kind'] != kind or by_slot['intent_sha256'] != intent_sha:
                        return _result(kind, 'CONFLICT_BLOCKED',
                                       'CONFLICT_SLOT_ALREADY_OWNED_BY_DIFFERENT_INTENT')
                    # A different upload ID for identical bytes on the same
                    # declared step is also suppressed. Do not write an alias.
                    return _result(kind, 'REPLAY_SUPPRESSED',
                                   'CONFLICT_COMPLETED_LOCAL_OPERATION_NOT_REPEATED',
                                   run_id=run_id, request_id=request_id, entry=by_slot,
                                   effects={'repeat_operation_suppressed': True})
                need(len(entries) < MAX_ENTRIES,
                     'CONFLICT_LEDGER_CAPACITY_REQUIRES_NEW_RUN', status='CONFLICT_BLOCKED')
                # No durable reservation for invalid source, stage, handler or
                # unlinked artifact; preflight never calls a business writer.
                preflight()
                self._binding(run_id, pins)
                entry = {
                    'kind': kind, 'request_id': request_id,
                    'slot_sha256': slot_sha, 'intent_sha256': intent_sha,
                    'phase': 'RESERVED', 'started_at_utc_unverified': _now(),
                    'finalized_at_utc_unverified': None, 'source_status': None,
                    'source_reason_code': None, 'result_sha256': None,
                }
                reserved = {'schema': LEDGER_SCHEMA, 'run_id': run_id,
                            'record_binding': dict(binding), 'entries': entries + [entry]}
                _save(fd, run_id, binding, reserved, ledger)
                # Any exception, crash, signal, uncertain source result or
                # failed fsync below retains RESERVED indefinitely. Never
                # infer that an interrupted business write can be retried.
                observed = operation()
                need(type(observed) is dict and
                     observed.get('status') in FINAL_SOURCE_STATES and
                     type(observed.get('reason_code')) is str and
                     re.fullmatch(r'[A-Z][A-Z0-9_]{2,127}', observed['reason_code'])
                     is not None and observed.get('run_id') == run_id and
                     not observed.get('business_write_performed', False) and
                     not observed.get('permission_granted', False),
                     'CONFLICT_SOURCE_RESULT_UNTRUSTED', unknown=True)
                if kind == 'scheduled_summary':
                    need(observed['status'] in ('CHECK_OBSERVED_ONLY', 'CHECK_BLOCKED') and
                         observed.get('effects', {}).get('business_writes_performed') is False and
                         observed.get('effects', {}).get('cycle_steps_executed') is False and
                         observed.get('effects', {}).get('local_records_written') is False,
                         'CONFLICT_SCHEDULE_SOURCE_NOT_READ_ONLY', unknown=True)
                else:
                    need(observed['status'] == 'ATTACHED_LOCAL_ONLY' and
                         observed.get('local_identity_consistent') is True and
                         observed.get('business_write_performed') is False and
                         observed.get('permission_granted') is False,
                         'CONFLICT_ATTACHMENT_SOURCE_NOT_LOCAL_ONLY', unknown=True)
                validate_source(observed)
                self._binding(run_id, pins)
                finalized = {**entry, 'phase': 'FINAL',
                             'finalized_at_utc_unverified': _now(),
                             'source_status': observed['status'],
                             'source_reason_code': observed['reason_code'],
                             'result_sha256': _hash(observed)}
                updated = {**reserved, 'entries': entries + [finalized]}
                persisted_reserved = _load(fd, run_id, binding)
                need(persisted_reserved is not None and
                     persisted_reserved['entries'] == reserved['entries'],
                     'CONFLICT_RESERVED_RECEIPT_CHANGED', unknown=True)
                _save(fd, run_id, binding, updated, persisted_reserved)
                status = ('RECORDED_OBSERVATION' if kind == 'scheduled_summary' and
                          observed['status'] == 'CHECK_OBSERVED_ONLY' else
                          'RECORDED_CHECK_BLOCK' if kind == 'scheduled_summary' else
                          'RECORDED_LOCAL_ATTACHMENT')
                return _result(kind, status, 'CONFLICT_OPERATION_RECORDED_LOCAL_ONLY',
                               run_id=run_id, request_id=request_id, entry=finalized,
                               first_result=observed,
                               effects={'new_guard_reservation_persisted': True,
                                        'new_guard_final_receipt_persisted': True,
                                        'ec239_summary_called': kind == 'scheduled_summary',
                                        'ec238_local_artifact_attach_called': kind == 'artifact_attach'})
        finally:
            os.close(fd)

    @staticmethod
    def _convert(operation: str, fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        try:
            return fn()
        except ConflictError as exc:
            return _result(operation, 'UNKNOWN_BLOCKED' if exc.unknown else exc.status,
                           exc.code)
        except ex.ExternalScheduleError as exc:
            return _result(operation, 'UNKNOWN_BLOCKED' if not exc.known else 'REJECTED',
                           exc.code)
        except cc.CrossActionError as exc:
            return _result(operation, 'UNKNOWN_BLOCKED' if exc.unknown else 'REJECTED',
                           exc.code)
        except md.CycleMetadataError:
            return _result(operation, 'UNKNOWN_BLOCKED', 'CONFLICT_PRIVATE_RUN_UNKNOWN')
        except (OSError, ValueError, TypeError, KeyError, RuntimeError,
                OverflowError, RecursionError):
            return _result(operation, 'UNKNOWN_BLOCKED', 'CONFLICT_STORAGE_OR_SOURCE_UNKNOWN')

    def scheduled_summary(self, run_id: str, *, expected_record_sha256: str,
                          expected_action_set_sha256: str, expected_input_sha256: str,
                          scheduler_kind: str, schedule_id: str, cadence: str,
                          host_state: str, trigger_id: str,
                          scheduled_for_utc: str) -> dict[str, Any]:
        def impl():
            pins = {'record_sha256': expected_record_sha256,
                    'action_set_sha256': expected_action_set_sha256,
                    'input_sha256': expected_input_sha256}
            need(type(trigger_id) is str and ex.EVENT_RE.fullmatch(trigger_id) is not None,
                 'CONFLICT_EVENT_ID_INVALID')
            need(host_state == 'claimed_configured', 'CONFLICT_SCHEDULER_HOST_ABSENT')
            ex._utc_tick(scheduled_for_utc, cadence)
            args = dict(cadence=cadence, scheduler_kind=scheduler_kind,
                        schedule_id=schedule_id, host_state=host_state,
                        expected_record_sha256=expected_record_sha256,
                        expected_action_set_sha256=expected_action_set_sha256,
                        expected_input_sha256=expected_input_sha256)

            def preflight():
                plan = self.scheduler.plan(run_id, **args)
                need(plan['status'] == 'CONFIG_CLAIM_ONLY',
                     'CONFLICT_EXTERNAL_SCHEDULER_PREFLIGHT_' + plan['status'],
                     unknown=plan['status'] == 'UNKNOWN_BLOCKED')

            # Bind per schedule/tick, even if a caller uses a fresh event ID.
            slot = {'kind': 'scheduled_summary', 'schedule_id': schedule_id,
                    'cadence': cadence, 'scheduled_for_utc': scheduled_for_utc}
            intent = {**slot, 'scheduler_kind': scheduler_kind,
                      'host_state': host_state, 'pins': pins,
                      'trigger_id': trigger_id}
            def validate_source(out):
                check = out.get('check')
                effects = out.get('effects')
                trigger = out.get('trigger')
                cadence_claim = out.get('cadence')
                need(out.get('schema') == ex.SCHEMA and
                     out.get('operation') == 'invoke' and
                     out.get('record_binding') == pins and
                     type(check) is dict and check.get('called') is True and
                     type(effects) is dict and
                     all(effects.get(key) is False for key in (
                         'business_writes_performed', 'native_action_dispatched',
                         'cycle_steps_executed', 'permission_granted',
                         'local_records_written', 'business_success_proven')) and
                     effects.get('local_read_only_summary_observed') is True and
                     type(trigger) is dict and trigger.get('event_id_claim') == trigger_id and
                     type(cadence_claim) is dict and
                     cadence_claim.get('scheduled_for_utc_claim') == scheduled_for_utc and
                     cadence_claim.get('tick_alignment_checked') is True and
                     out.get('scheduler', {}).get('schedule_id') == schedule_id and
                     type(check.get('summary')) is dict and
                     check.get('summary_status') == check['summary'].get('status') and
                     check['summary']['status'] in ex.ALL_SUMMARIES and
                     (out['status'] == 'CHECK_BLOCKED') ==
                         (check['summary']['status'] in ex.BLOCKED_SUMMARIES) and
                     ex.sm.validate_result(check['summary']) == check['summary'],
                     'CONFLICT_SCHEDULE_SOURCE_SHAPE_UNTRUSTED', unknown=True)

            return self._guarded('scheduled_summary', run_id, pins, trigger_id,
                                 slot, intent, preflight,
                                 lambda: self.scheduler.invoke(run_id, **args,
                                     trigger_id=trigger_id,
                                     scheduled_for_utc=scheduled_for_utc),
                                 validate_source)
        return self._convert('scheduled_summary', impl)

    def artifact_attach(self, run_id: str, *, expected_record_sha256: str,
                        expected_action_set_sha256: str, expected_input_sha256: str,
                        upload_id: str, stage_store: str | Path,
                        business_repo_root: str | Path, handoff_id: str,
                        expected_stage_parent_pin: str, family: str, step_id: str,
                        artifact_bytes: bytes) -> dict[str, Any]:
        def impl():
            pins = {'record_sha256': expected_record_sha256,
                    'action_set_sha256': expected_action_set_sha256,
                    'input_sha256': expected_input_sha256}
            need(type(upload_id) is str and UPLOAD_RE.fullmatch(upload_id) is not None,
                 'CONFLICT_UPLOAD_ID_INVALID')
            need(isinstance(stage_store, (str, Path)) and Path(stage_store).is_absolute() and
                 isinstance(business_repo_root, (str, Path)) and
                 Path(business_repo_root).is_absolute(),
                 'CONFLICT_ATTACHMENT_STORE_PATHS_INVALID')
            need(type(artifact_bytes) is bytes and
                 1 <= len(artifact_bytes) <= cc.MAX_ARTIFACT_BYTES,
                 'CONFLICT_ARTIFACT_BYTES_INVALID')
            need(type(handoff_id) is str and md.HANDOFF_RE.fullmatch(handoff_id) is not None and
                 type(expected_stage_parent_pin) is str and
                 _sha(expected_stage_parent_pin) and
                 type(family) is str and family in cc.FAMILY_SCHEMAS and
                 type(step_id) is str and md.STEP_RE.fullmatch(step_id) is not None,
                 'CONFLICT_ATTACHMENT_DECLARATION_INVALID')
            cross = cc.CycleCrossActionLedger(self.path, stage_store, business_repo_root)
            rawsha = hashlib.sha256(artifact_bytes).hexdigest()

            def preflight():
                owner = cross._live_owner(run_id, handoff_id, expected_stage_parent_pin)
                cross._step(run_id, family, step_id)
                cc._producer(artifact_bytes, family, cycle_run=run_id,
                             staged_run=owner['stage_run_id'], handoff=handoff_id,
                             context=owner['source_context_sha256'],
                             identity=owner['source_identity_sha256'])

            slot = {'kind': 'artifact_attach', 'handoff_id': handoff_id,
                    'family': family, 'step_id': step_id}
            intent = {**slot, 'pins': pins,
                      'stage_store_path_claim': str(Path(stage_store)),
                      'business_repo_path_claim': str(Path(business_repo_root)),
                      'stage_parent_pin': expected_stage_parent_pin,
                      'artifact_sha256': rawsha, 'artifact_byte_length': len(artifact_bytes)}
            def validate_source(out):
                artifacts = out.get('artifacts')
                need(out.get('schema') == cc.SCHEMA and
                     out.get('run_id') == run_id and
                     out.get('handoff_id') == handoff_id and
                     out.get('cycle_record_sha256') == pins['record_sha256'] and
                     out.get('reason_code') in ('CROSS_ARTIFACT_ATTACHED', 'CROSS_ARTIFACT_REPLAY') and
                     out.get('producer_authenticated') is False and
                     out.get('actor_authenticated') is False and
                     out.get('source_authenticated') is False and
                     out.get('business_steps_executed_proven') is False and
                     out.get('native_cycle_action_registered') is False and
                     type(artifacts) is list and len(artifacts) == 1 and
                     type(artifacts[0]) is dict and
                     artifacts[0].get('family') == family and
                     artifacts[0].get('step_id') == step_id and
                     artifacts[0].get('artifact_sha256') == rawsha and
                     artifacts[0].get('artifact_bytes') == len(artifact_bytes),
                     'CONFLICT_ATTACHMENT_SOURCE_SHAPE_UNTRUSTED', unknown=True)

            return self._guarded('artifact_attach', run_id, pins, upload_id,
                                 slot, intent, preflight,
                                 lambda: cross.attach(run_id, handoff_id,
                                     expected_stage_parent_pin=expected_stage_parent_pin,
                                     family=family, step_id=step_id,
                                     artifact_bytes=artifact_bytes),
                                 validate_source)
        return self._convert('artifact_attach', impl)

    def inspect(self, run_id: str, *, expected_record_sha256: str,
                expected_action_set_sha256: str, expected_input_sha256: str,
                request_id: str) -> dict[str, Any]:
        """Observe one durable receipt; no file creation and NO lease recovery."""
        def impl():
            need(type(request_id) is str and REQUEST_RE.fullmatch(request_id) is not None,
                 'CONFLICT_INSPECT_REQUEST_ID_INVALID')
            pins = {'record_sha256': expected_record_sha256,
                    'action_set_sha256': expected_action_set_sha256,
                    'input_sha256': expected_input_sha256}
            binding = self._binding(run_id, pins)
            fd = md._safe_dir(self.path, create=False)
            try:
                ledger = _load(fd, run_id, binding)
            finally:
                os.close(fd)
            if ledger is None:
                return _result('inspect', 'NO_RECEIPT', 'CONFLICT_NO_GUARD_RECEIPT',
                               run_id=run_id, request_id=request_id)
            if any(e['phase'] == 'RESERVED' for e in ledger['entries']):
                return _result('inspect', 'UNKNOWN_BLOCKED',
                               'CONFLICT_INTERRUPTED_RESERVATION_REQUIRES_RECONCILIATION')
            entry = next((e for e in ledger['entries'] if e['request_id'] == request_id), None)
            if entry is None:
                return _result('inspect', 'NO_RECEIPT', 'CONFLICT_NO_GUARD_RECEIPT',
                               run_id=run_id, request_id=request_id)
            if entry['phase'] == 'RESERVED':
                return _result('inspect', 'UNKNOWN_BLOCKED',
                               'CONFLICT_INTERRUPTED_RESERVATION_REQUIRES_RECONCILIATION')
            return _result('inspect', 'RECEIPT_OBSERVED',
                           'CONFLICT_PRIOR_LOCAL_RECEIPT_ONLY', run_id=run_id,
                           request_id=request_id, entry=entry)
        return self._convert('inspect', impl)

    def business_write_attempt(self, run_id: str, *, expected_record_sha256: str,
                               expected_action_set_sha256: str,
                               expected_input_sha256: str) -> dict[str, Any]:
        """Explicit rejection of any attempted business mutation/permission grant."""
        def impl():
            self._binding(run_id, {'record_sha256': expected_record_sha256,
                                    'action_set_sha256': expected_action_set_sha256,
                                    'input_sha256': expected_input_sha256})
            return _result('business_write_attempt', 'PERMISSION_DENIED',
                           'CONFLICT_BUSINESS_WRITE_REQUIRES_NATIVE_INDEPENDENT_APPROVAL',
                           run_id=run_id)
        return self._convert('business_write_attempt', impl)


def _file(path: str, maximum: int) -> bytes:
    p = Path(path)
    need(p.is_absolute(), 'CONFLICT_ARTIFACT_INPUT_PATH_NOT_ABSOLUTE')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and 0 < s.st_size <= maximum,
             'CONFLICT_ARTIFACT_INPUT_FILE_INVALID')
        data = os.read(fd, maximum + 1)
        need(len(data) == s.st_size, 'CONFLICT_ARTIFACT_INPUT_FILE_CHANGED', unknown=True)
        return data
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='EC240 local guarded EC239/EC238; never business success')
    p.add_argument('operation', choices=('scheduled_summary', 'artifact_attach',
                                         'inspect', 'business_write_attempt'))
    p.add_argument('--store', required=True)
    p.add_argument('--run-id', required=True)
    p.add_argument('--expected-record-sha256', required=True)
    p.add_argument('--expected-action-set-sha256', required=True)
    p.add_argument('--expected-input-sha256', required=True)
    p.add_argument('--scheduler-kind')
    p.add_argument('--schedule-id')
    p.add_argument('--cadence')
    p.add_argument('--host-state', default='claimed_configured')
    p.add_argument('--trigger-id')
    p.add_argument('--scheduled-for-utc')
    p.add_argument('--upload-id')
    p.add_argument('--handoff-id')
    p.add_argument('--stage-store')
    p.add_argument('--business-root')
    p.add_argument('--stage-parent-pin')
    p.add_argument('--family')
    p.add_argument('--step-id')
    p.add_argument('--artifact-file')
    p.add_argument('--request-id')
    args = p.parse_args(argv)
    guard = CycleConflictGuard(args.store)
    pins = dict(expected_record_sha256=args.expected_record_sha256,
                expected_action_set_sha256=args.expected_action_set_sha256,
                expected_input_sha256=args.expected_input_sha256)
    try:
        if args.operation == 'scheduled_summary':
            out = guard.scheduled_summary(args.run_id, **pins,
                scheduler_kind=args.scheduler_kind, schedule_id=args.schedule_id,
                cadence=args.cadence, host_state=args.host_state,
                trigger_id=args.trigger_id, scheduled_for_utc=args.scheduled_for_utc)
        elif args.operation == 'artifact_attach':
            need(args.artifact_file is not None, 'CONFLICT_ARTIFACT_FILE_REQUIRED')
            artifact = _file(args.artifact_file, cc.MAX_ARTIFACT_BYTES)
            out = guard.artifact_attach(args.run_id, **pins,
                upload_id=args.upload_id, stage_store=args.stage_store,
                business_repo_root=args.business_root, handoff_id=args.handoff_id,
                expected_stage_parent_pin=args.stage_parent_pin, family=args.family,
                step_id=args.step_id, artifact_bytes=artifact)
        elif args.operation == 'inspect':
            out = guard.inspect(args.run_id, **pins, request_id=args.request_id)
        else:
            out = guard.business_write_attempt(args.run_id, **pins)
        payload = _encoded(out, MAX_OUTPUT_BYTES)
    except ConflictError as exc:
        out = _result(args.operation, 'UNKNOWN_BLOCKED' if exc.unknown else exc.status,
                      exc.code)
        payload = _encoded(out, MAX_OUTPUT_BYTES)
    except (OSError, ValueError, TypeError, KeyError):
        out = _result(args.operation, 'UNKNOWN_BLOCKED', 'CONFLICT_ARTIFACT_IO_UNKNOWN')
        payload = _encoded(out, MAX_OUTPUT_BYTES)
    try:
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
    except (OSError, BrokenPipeError):
        return 5
    return RESULT_CODES[out['status']]


if __name__ == '__main__':
    sys.exit(main())
