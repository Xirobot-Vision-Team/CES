#!/usr/bin/env python3
"""EC237: source-bound, read-only summary of a *real* EC231 private Cycle run.

Summarizes EC231 declared steps/evidence/capture counters, EC232 actual DAG,
EC233 live source-backed Next route and (if present) EC235 immutable DENY
checkpoint. No historical EC231/235 record can attest completed or failed
business work; these reports therefore NEVER assert verified task success,
verified failure, billed cost, execution time or authority to dispatch.

An unsigned local SHA is a consistency check, not identity/source/approval
attestation. This module neither invokes native actions nor persists results.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

if __package__:
    from . import cycle_run_metadata as md
    from . import cycle_dag as dag
    from . import cycle_next as nxt
    from . import cycle_permission_pause as pp
else:
    import cycle_run_metadata as md
    import cycle_dag as dag
    import cycle_next as nxt
    import cycle_permission_pause as pp

SCHEMA = 'ces.cycle_summary.v1'
MAX_SUMMARY_BYTES = 131_072
STATES = frozenset((
    'NOT_STARTED', 'AWAIT_PERMISSION_NO_CHECKPOINT',
    'PAUSED_PERMISSION_REQUIRED', 'OPERATOR_HANDOFF_REQUIRED',
    'UNVERIFIED_PROGRESS_BLOCKED', 'BLOCKED_NO_HANDLER',
    'BLOCKED_DAG_CYCLE', 'UNKNOWN_BLOCKED',
))
STEP_KINDS = frozenset((
    'NOT_STARTED_UNEXECUTED', 'DEPENDENCY_UNPROVEN',
    'AWAITING_PERMISSION_UNEXECUTED', 'PAUSED_DENY_UNEXECUTED',
    'OPERATOR_HANDOFF_UNEXECUTED', 'DECLARED_PARTIAL_UNVERIFIED',
    'UNKNOWN_UNVERIFIED',
))
TRUST_KEYS = frozenset((
    'record_authenticated', 'input_source_authenticated', 'actor_authenticated',
    'declared_evidence_authenticated', 'execution_verified',
    'failure_verified', 'external_cost_verified', 'permission_granted',
    'handler_runtime_verified', 'entire_cycle_success_verified',
))
EFFECT_KEYS = frozenset((
    'metadata_written', 'pause_written', 'handler_invoked', 'steps_executed',
    'dependencies_advanced', 'write_authorized', 'can_dispatch', 'can_resume',
    'native_cycle_action_registered', 'billing_record_created',
))
RECORD_KEYS = frozenset((
    'record_sha256', 'action_set_sha256', 'input_sha256', 'graph_sha256',
    'proposal_sha256', 'pause_sha256',
))
CHECK_KEYS = frozenset((
    'record_valid', 'dag_valid', 'route_source_checked', 'pause_present',
    'pause_valid', 'double_read_stable', 'independent_pins_provided',
))
COUNTER_KEYS = frozenset((
    'total_steps', 'not_started', 'declared_partial', 'unknown',
    'dependency_blocked', 'permission_blocked',
    'verified_success', 'verified_failure',
))
STEP_KEYS = frozenset((
    'step_id', 'action', 'mode', 'depends_on', 'blocked_by_unproven_dependencies',
    'metadata_state', 'report_state', 'reason_code', 'declared_evidence_sha256',
    'declared_observed_at_utc', 'declared_handoff_id',
    'execution_verified', 'success_verified', 'failure_verified',
))
COST_KEYS = frozenset((
    'capture_input_bytes', 'capture_declared_usage', 'capture_budget_limits',
    'persisted_pause_budget_observation', 'execution_wall_ms',
    'execution_cpu_ms', 'execution_evidence_bytes', 'external_cost_usd',
    'accounting_scope',
))
ROOT_KEYS = frozenset((
    'schema', 'run_id', 'status', 'reason_code', 'overall_success_proven',
    'record_binding', 'checks', 'steps', 'counts', 'cost', 'trust', 'effects',
))
USAGE_KEYS = frozenset(md.USAGE_FIELDS)
LIMIT_KEYS = frozenset(md.LIMIT_FIELDS)
UNSUPPORTED = frozenset((
    'CYCLE_NEXT_ACTION_OR_MODE_UNREGISTERED',
    'CYCLE_NEXT_AI_ROUTE_UNREGISTERED',
))


class CycleSummaryError(md.CycleMetadataError):
    """Summary cannot establish a consistent view of one saved run."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CycleSummaryError(code, code)


def _blank(run_id: str | None, reason: str = 'CYCLE_SUMMARY_RUN_UNAVAILABLE') -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'run_id': run_id, 'status': 'UNKNOWN_BLOCKED',
        'reason_code': reason, 'overall_success_proven': False,
        'record_binding': {k: None for k in RECORD_KEYS},
        'checks': {k: False for k in CHECK_KEYS},
        'steps': [],
        'counts': {k: 0 for k in COUNTER_KEYS},
        'cost': {'capture_input_bytes': None,
                 'capture_declared_usage': {k: None for k in USAGE_KEYS},
                 'capture_budget_limits': {k: None for k in LIMIT_KEYS},
                 'persisted_pause_budget_observation': None,
                 'execution_wall_ms': None, 'execution_cpu_ms': None,
                 'execution_evidence_bytes': None, 'external_cost_usd': None,
                 'accounting_scope': 'EC231_DECLARATIONS_ONLY_NO_EXECUTION_METER'},
        'trust': {k: False for k in TRUST_KEYS},
        'effects': {k: False for k in EFFECT_KEYS},
    }


def _sidecar_exists(path: Path, run_id: str) -> bool:
    """Missing != unreadable. Do not follow a symlink masquerading as a pause."""
    fd = md._safe_dir(path, create=False)
    try:
        try:
            os.stat(run_id + pp.PAUSE_SUFFIX, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True
    finally:
        os.close(fd)


def _fill_steps(record: dict[str, Any], *, status: str, selected: str | None) -> list[dict[str, Any]]:
    steps = []
    for action, saved in zip(record['action_set'], record['steps']):
        dep_ids = list(action['depends_on'])
        metadata_state = saved['state']
        if metadata_state == 'UNKNOWN':
            state = 'UNKNOWN_UNVERIFIED'
            reason = saved['reason_code']
        elif metadata_state == 'DECLARED_PARTIAL':
            state = 'DECLARED_PARTIAL_UNVERIFIED'
            reason = saved['reason_code']
        elif dep_ids:
            # EC231 has no verified SUCCEEDED state, so *every* dependency
            # remains unproven, including a previously declared partial one.
            state = 'DEPENDENCY_UNPROVEN'
            reason = 'CYCLE_SUMMARY_DEPENDENCIES_NOT_EXECUTION_PROVEN'
        elif action['step_id'] == selected and status in (
                'PAUSED_PERMISSION_REQUIRED', 'AWAIT_PERMISSION_NO_CHECKPOINT'):
            state = ('PAUSED_DENY_UNEXECUTED' if status == 'PAUSED_PERMISSION_REQUIRED'
                     else 'AWAITING_PERMISSION_UNEXECUTED')
            reason = 'CYCLE_SUMMARY_INDEPENDENT_PERMISSION_REQUIRED'
        elif action['step_id'] == selected and status == 'OPERATOR_HANDOFF_REQUIRED':
            state = 'OPERATOR_HANDOFF_UNEXECUTED'
            reason = 'CYCLE_SUMMARY_OPERATOR_HANDOFF_UNVERIFIED'
        else:
            state = 'NOT_STARTED_UNEXECUTED'
            reason = 'CYCLE_SUMMARY_NO_EXECUTION_EVIDENCE'
        steps.append({
            'step_id': action['step_id'], 'action': action['action'],
            'mode': action['mode'], 'depends_on': dep_ids,
            'blocked_by_unproven_dependencies': dep_ids,
            'metadata_state': metadata_state, 'report_state': state,
            'reason_code': reason,
            'declared_evidence_sha256': saved['evidence_sha256'],
            'declared_observed_at_utc': saved['observed_at_utc'],
            'declared_handoff_id': saved['handoff_id'],
            'execution_verified': False, 'success_verified': False,
            'failure_verified': False,
        })
    return steps


def validate_result(out: Any) -> dict[str, Any]:
    """Validate report syntax and non-escalation invariants (not an attestor)."""
    _require(type(out) is dict and set(out) == ROOT_KEYS, 'CYCLE_SUMMARY_RESULT_SHAPE_INVALID')
    _require(out['schema'] == SCHEMA and out['status'] in STATES and
             out['overall_success_proven'] is False, 'CYCLE_SUMMARY_RESULT_STATUS_INVALID')
    md.token(out['reason_code'], md.REASON_RE, 'CYCLE_SUMMARY_RESULT_REASON_INVALID')
    if out['run_id'] is not None:
        md.token(out['run_id'], md.RUN_RE, 'CYCLE_SUMMARY_RESULT_RUN_INVALID')
    for key, expected in (('record_binding', RECORD_KEYS), ('checks', CHECK_KEYS),
                          ('counts', COUNTER_KEYS), ('cost', COST_KEYS),
                          ('trust', TRUST_KEYS), ('effects', EFFECT_KEYS)):
        _require(type(out[key]) is dict and set(out[key]) == expected,
                 'CYCLE_SUMMARY_RESULT_SECTION_INVALID')
    _require(all(v is False for v in out['trust'].values()) and
             all(v is False for v in out['effects'].values()),
             'CYCLE_SUMMARY_FALSE_AUTHORITY_FORBIDDEN')
    _require(all(type(v) is bool for v in out['checks'].values()),
             'CYCLE_SUMMARY_CHECKS_INVALID')
    for value in out['record_binding'].values():
        if value is not None:
            md.token(value, md.SHA_RE, 'CYCLE_SUMMARY_DIGEST_INVALID')
    for k in COUNTER_KEYS:
        md.count(out['counts'][k], 0, md.MAX_STEPS, 'CYCLE_SUMMARY_COUNT_INVALID')
    _require(out['counts']['verified_success'] == out['counts']['verified_failure'] == 0,
             'CYCLE_SUMMARY_UNVERIFIED_COMPLETION_FORBIDDEN')
    _require(type(out['steps']) is list and len(out['steps']) <= md.MAX_STEPS and
             len(out['steps']) == out['counts']['total_steps'],
             'CYCLE_SUMMARY_STEPS_INVALID')
    seen = set()
    for item in out['steps']:
        _require(type(item) is dict and set(item) == STEP_KEYS,
                 'CYCLE_SUMMARY_STEP_SHAPE_INVALID')
        md.token(item['step_id'], md.STEP_RE, 'CYCLE_SUMMARY_STEP_ID_INVALID')
        md.token(item['action'], md.ACTION_RE, 'CYCLE_SUMMARY_ACTION_INVALID')
        if item['mode'] is not None:
            md.token(item['mode'], md.MODE_RE, 'CYCLE_SUMMARY_MODE_INVALID')
        _require(item['step_id'] not in seen, 'CYCLE_SUMMARY_STEP_DUPLICATE')
        seen.add(item['step_id'])
        _require(item['metadata_state'] in md.STEP_STATES and item['report_state'] in STEP_KINDS,
                 'CYCLE_SUMMARY_STEP_STATE_INVALID')
        _require(all(item[k] is False for k in ('execution_verified', 'success_verified', 'failure_verified')),
                 'CYCLE_SUMMARY_STEP_SUCCESS_UNPROVEN')
        for k in ('depends_on', 'blocked_by_unproven_dependencies'):
            _require(type(item[k]) is list and len(item[k]) <= md.MAX_STEPS,
                     'CYCLE_SUMMARY_DEPENDENCIES_INVALID')
            for d in item[k]:
                md.token(d, md.STEP_RE, 'CYCLE_SUMMARY_DEPENDENCY_INVALID')
        _require(item['blocked_by_unproven_dependencies'] == item['depends_on'],
                 'CYCLE_SUMMARY_FALSE_DEPENDENCY_COMPLETION')
        md.token(item['reason_code'], md.REASON_RE, 'CYCLE_SUMMARY_STEP_REASON_INVALID')
        if item['declared_evidence_sha256'] is not None:
            md.token(item['declared_evidence_sha256'], md.SHA_RE, 'CYCLE_SUMMARY_EVIDENCE_INVALID')
        if item['declared_handoff_id'] is not None:
            md.token(item['declared_handoff_id'], md.HANDOFF_RE, 'CYCLE_SUMMARY_HANDOFF_INVALID')
        if item['declared_observed_at_utc'] is not None:
            md.timestamp(item['declared_observed_at_utc'])
        if item['metadata_state'] == 'NOT_STARTED':
            _require(item['declared_evidence_sha256'] is None and
                     item['declared_observed_at_utc'] is None and
                     item['declared_handoff_id'] is None,
                     'CYCLE_SUMMARY_NOT_STARTED_EVIDENCE_FORBIDDEN')
        if item['metadata_state'] == 'DECLARED_PARTIAL':
            _require(item['report_state'] == 'DECLARED_PARTIAL_UNVERIFIED',
                     'CYCLE_SUMMARY_PARTIAL_NOT_PROOF')
        if item['metadata_state'] == 'UNKNOWN':
            _require(item['report_state'] == 'UNKNOWN_UNVERIFIED',
                     'CYCLE_SUMMARY_UNKNOWN_NOT_PROOF')
    c = out['counts']
    _require(c['not_started'] == sum(s['metadata_state'] == 'NOT_STARTED' for s in out['steps']) and
             c['declared_partial'] == sum(s['metadata_state'] == 'DECLARED_PARTIAL' for s in out['steps']) and
             c['unknown'] == sum(s['metadata_state'] == 'UNKNOWN' for s in out['steps']) and
             c['dependency_blocked'] == sum(bool(s['depends_on']) for s in out['steps']) and
             c['permission_blocked'] == sum(s['report_state'] in (
                 'AWAITING_PERMISSION_UNEXECUTED', 'PAUSED_DENY_UNEXECUTED') for s in out['steps']) and
             c['not_started'] + c['declared_partial'] + c['unknown'] == c['total_steps'],
             'CYCLE_SUMMARY_COUNTS_INCONSISTENT')
    cost = out['cost']
    _require(cost['accounting_scope'] == 'EC231_DECLARATIONS_ONLY_NO_EXECUTION_METER' and
             all(cost[k] is None for k in ('execution_wall_ms', 'execution_cpu_ms',
                                           'execution_evidence_bytes', 'external_cost_usd')),
             'CYCLE_SUMMARY_COST_PROOF_FORBIDDEN')
    for key, fields in (('capture_declared_usage', USAGE_KEYS),
                        ('capture_budget_limits', LIMIT_KEYS)):
        section = cost[key]
        _require(type(section) is dict and set(section) == fields, 'CYCLE_SUMMARY_COST_SHAPE_INVALID')
        for value in section.values():
            _require(value is None or (type(value) is int and 0 <= value <= 86_400_000),
                     'CYCLE_SUMMARY_COST_RANGE_INVALID')
    inp = cost['capture_input_bytes']
    _require(inp is None or (type(inp) is int and 1 <= inp <= md.MAX_SNAPSHOT_BYTES),
             'CYCLE_SUMMARY_INPUT_COST_INVALID')
    observation = cost['persisted_pause_budget_observation']
    if observation is not None:
        _require(type(observation) is dict and set(observation) == {
            'admitted_inspections', 'output_bytes', 'independently_attested'},
            'CYCLE_SUMMARY_PAUSE_COST_SHAPE_INVALID')
        md.count(observation['admitted_inspections'], 1, md.MAX_STEPS,
                 'CYCLE_SUMMARY_PAUSE_INSPECTIONS_INVALID')
        md.count(observation['output_bytes'], 1, md.LIMIT_MAX['output_bytes'],
                 'CYCLE_SUMMARY_PAUSE_OUTPUT_INVALID')
        _require(observation['independently_attested'] is False,
                 'CYCLE_SUMMARY_PAUSE_COST_PROOF_FORBIDDEN')
    if out['status'] != 'UNKNOWN_BLOCKED':
        _require(out['checks']['record_valid'] and out['checks']['double_read_stable'] and
                 out['counts']['total_steps'] > 0, 'CYCLE_SUMMARY_UNGROUNDED_REPORT')
    if out['status'] == 'PAUSED_PERMISSION_REQUIRED':
        _require(out['checks']['pause_valid'] and out['checks']['pause_present'] and
                 c['permission_blocked'] == 1,
                 'CYCLE_SUMMARY_UNGROUNDED_PAUSE')
    if out['status'] == 'UNKNOWN_BLOCKED':
        _require(len(out['steps']) == 0 and not out['checks']['record_valid'],
                 'CYCLE_SUMMARY_UNKNOWN_MUST_NOT_LEAK_STALE_PROOF')
    _require(len(md.canonical(out)) <= MAX_SUMMARY_BYTES,
             'CYCLE_SUMMARY_OUTPUT_SIZE_EXCEEDED')
    return out


class CycleSummaryReporter:
    """Reopen immutable private files on every call; report only what is known."""

    def __init__(self, private_dir: str | Path, *, package_root: str | Path | None = None) -> None:
        self.path = Path(private_dir)
        self.store = md.CycleMetadataStore(private_dir)
        self.dag = dag.CycleDagInspector(private_dir)
        self.next = nxt.CycleNextHandler(private_dir, package_root=package_root)
        self.pauses = pp.CyclePermissionPauseStore(private_dir, package_root=package_root)

    def summary(self, run_id: str, *, expected_record_sha256: str | None = None,
                expected_action_set_sha256: str | None = None,
                expected_input_sha256: str | None = None,
                expected_pause_sha256: str | None = None) -> dict[str, Any]:
        display_id = run_id if type(run_id) is str and md.RUN_RE.fullmatch(run_id) else None
        failure = _blank(display_id)
        try:
            md.token(run_id, md.RUN_RE, 'CYCLE_SUMMARY_RUN_INVALID')
            for pin in (expected_record_sha256, expected_action_set_sha256,
                        expected_input_sha256, expected_pause_sha256):
                if pin is not None:
                    md.token(pin, md.SHA_RE, 'CYCLE_SUMMARY_PIN_INVALID')
            original = self.store.load(run_id)
            for expected, actual, code in (
                (expected_record_sha256, original['record_sha256'], 'CYCLE_SUMMARY_RECORD_PIN_DRIFT'),
                (expected_action_set_sha256, original['action_set_sha256'], 'CYCLE_SUMMARY_ACTION_PIN_DRIFT'),
                (expected_input_sha256, original['input']['sha256'], 'CYCLE_SUMMARY_INPUT_PIN_DRIFT'),
            ):
                _require(expected is None or expected == actual, code)
            graph = self.dag.check(run_id,
                                   expected_record_sha256=original['record_sha256'],
                                   expected_action_set_sha256=original['action_set_sha256'],
                                   expected_input_sha256=original['input']['sha256'])
            _require(graph['status'] != dag.UNKNOWN, graph['reason_code'])
            _require(graph['record_sha256'] == original['record_sha256'] and
                     graph['action_set_sha256'] == original['action_set_sha256'] and
                     graph['input_sha256'] == original['input']['sha256'],
                     'CYCLE_SUMMARY_DAG_BINDING_CHANGED')
            present = _sidecar_exists(self.path, run_id)
            if expected_pause_sha256 is not None:
                _require(present, 'CYCLE_SUMMARY_EXPECTED_PAUSE_MISSING')
            saved_pause = self.pauses.load(run_id) if present else None
            if saved_pause is not None:
                _require(saved_pause['metadata_binding']['record_sha256'] == original['record_sha256'] and
                         saved_pause['metadata_binding']['graph_sha256'] == graph['graph_sha256'],
                         'CYCLE_SUMMARY_PAUSE_RUN_DRIFT')
                _require(expected_pause_sha256 is None or
                         saved_pause['pause_sha256'] == expected_pause_sha256,
                         'CYCLE_SUMMARY_PAUSE_PIN_DRIFT')
            decision = self.next.next(run_id,
                                      expected_record_sha256=original['record_sha256'],
                                      expected_action_set_sha256=original['action_set_sha256'],
                                      expected_input_sha256=original['input']['sha256'])
            _require(decision['status'] != nxt.UNKNOWN, decision['reason_code'])
            _require(graph['status'] != dag.VALID or
                     (decision['record_sha256'] == original['record_sha256'] and
                      decision['graph_sha256'] == graph['graph_sha256']),
                     'CYCLE_SUMMARY_NEXT_BINDING_DRIFT')
            if saved_pause is not None:
                _require(decision['next_kind'] == 'await_permission' and
                         decision['next_step'] is not None and
                         saved_pause['step_id'] == decision['next_step']['step_id'] and
                         saved_pause['metadata_binding']['proposal_sha256'] == decision['proposal_sha256'],
                         'CYCLE_SUMMARY_PAUSE_NEXT_CHANGED')
                status, reason = 'PAUSED_PERMISSION_REQUIRED', 'CYCLE_SUMMARY_PERSISTED_DENY_ONLY'
            elif graph['status'] == dag.CYCLIC:
                status, reason = 'BLOCKED_DAG_CYCLE', 'CYCLE_SUMMARY_DAG_CYCLE_NO_EXECUTION'
            elif original['run_state'] != 'NOT_STARTED':
                status, reason = ('UNVERIFIED_PROGRESS_BLOCKED',
                                  'CYCLE_SUMMARY_DECLARED_PROGRESS_NOT_EXECUTION_PROOF')
            elif decision['next_kind'] == 'await_permission':
                status, reason = ('AWAIT_PERMISSION_NO_CHECKPOINT',
                                  'CYCLE_SUMMARY_APPROVAL_REQUIRED_NO_PAUSE_SAVED')
            elif decision['next_kind'] == 'ai_handoff':
                status, reason = 'OPERATOR_HANDOFF_REQUIRED', 'CYCLE_SUMMARY_AI_HANDOFF_NOT_EXECUTED'
            elif decision['next_kind'] == 'cli_action':
                status, reason = 'NOT_STARTED', 'CYCLE_SUMMARY_SOURCE_BACKED_PROPOSAL_ONLY'
            else:
                _require(decision['status'] == nxt.BLOCKED, 'CYCLE_SUMMARY_NEXT_UNEXPECTED')
                _require(decision['reason_code'] in UNSUPPORTED, decision['reason_code'])
                status, reason = 'BLOCKED_NO_HANDLER', 'CYCLE_SUMMARY_NO_IMPLEMENTED_ROOT_HANDLER'
            if saved_pause is not None:
                _require(graph['status'] == dag.VALID and
                         original['run_state'] == 'NOT_STARTED', 'CYCLE_SUMMARY_INVALID_PAUSE_GRAPH')
            # A second independent live route inspection catches observable
            # source/route replacement while the summary is assembled. This
            # still does NOT authenticate a host filesystem or prevent a
            # same-UID rollback before/after the read window.
            second_decision = self.next.next(
                run_id, expected_record_sha256=original['record_sha256'],
                expected_action_set_sha256=original['action_set_sha256'],
                expected_input_sha256=original['input']['sha256'])
            _require(md.canonical(second_decision) == md.canonical(decision),
                     'CYCLE_SUMMARY_NEXT_SOURCE_CHANGED_DURING_READ')
            # Detect observed drift across the whole dependency/source review.
            reread = self.store.load(run_id)
            _require(md.canonical(reread) == md.canonical(original),
                     'CYCLE_SUMMARY_ORIGINAL_CHANGED_DURING_READ')
            if saved_pause is not None:
                second_pause = self.pauses.load(run_id)
                _require(md.canonical(second_pause) == md.canonical(saved_pause),
                         'CYCLE_SUMMARY_PAUSE_CHANGED_DURING_READ')
            else:
                _require(not _sidecar_exists(self.path, run_id),
                         'CYCLE_SUMMARY_PAUSE_APPEARED_DURING_READ')
            chosen = (decision['next_step']['step_id'] if decision['next_step'] else None)
            entries = _fill_steps(original, status=status, selected=chosen)
            counts = {
                'total_steps': len(entries),
                'not_started': sum(s['metadata_state'] == 'NOT_STARTED' for s in entries),
                'declared_partial': sum(s['metadata_state'] == 'DECLARED_PARTIAL' for s in entries),
                'unknown': sum(s['metadata_state'] == 'UNKNOWN' for s in entries),
                'dependency_blocked': sum(bool(s['depends_on']) for s in entries),
                'permission_blocked': sum(s['report_state'] in (
                    'AWAITING_PERMISSION_UNEXECUTED', 'PAUSED_DENY_UNEXECUTED') for s in entries),
                'verified_success': 0, 'verified_failure': 0,
            }
            report = _blank(run_id)
            report.update({
                'status': status, 'reason_code': reason,
                'record_binding': {
                    'record_sha256': original['record_sha256'],
                    'action_set_sha256': original['action_set_sha256'],
                    'input_sha256': original['input']['sha256'],
                    'graph_sha256': graph['graph_sha256'],
                    'proposal_sha256': decision['proposal_sha256'],
                    'pause_sha256': saved_pause['pause_sha256'] if saved_pause else None,
                },
                'checks': {'record_valid': True, 'dag_valid': graph['status'] == dag.VALID,
                           'route_source_checked': decision['next_step'] is not None,
                           'pause_present': present, 'pause_valid': saved_pause is not None,
                           'double_read_stable': True,
                           'independent_pins_provided': any(v is not None for v in (
                               expected_record_sha256, expected_action_set_sha256,
                               expected_input_sha256, expected_pause_sha256))},
                'steps': entries, 'counts': counts,
                'cost': {
                    'capture_input_bytes': original['input']['byte_length'],
                    'capture_declared_usage': dict(original['budget']['usage']),
                    'capture_budget_limits': dict(original['budget']['limits']),
                    'persisted_pause_budget_observation': ({
                        'admitted_inspections': saved_pause['budget_observation']['admitted_inspections'],
                        'output_bytes': saved_pause['budget_observation']['output_bytes'],
                        'independently_attested': False,
                    } if saved_pause else None),
                    'execution_wall_ms': None, 'execution_cpu_ms': None,
                    'execution_evidence_bytes': None, 'external_cost_usd': None,
                    'accounting_scope': 'EC231_DECLARATIONS_ONLY_NO_EXECUTION_METER',
                },
            })
            return validate_result(report)
        except (md.CycleMetadataError, OSError, ValueError, TypeError, KeyError,
                IndexError, OverflowError) as exc:
            failure['reason_code'] = (exc.code if isinstance(exc, md.CycleMetadataError)
                                      else 'CYCLE_SUMMARY_READ_OR_SHAPE_UNAVAILABLE')
            # A failure must not return potentially stale or partly-verified
            # steps, cost figures, or an apparent recovered permission state.
            return validate_result(failure)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC237 read-only Cycle Summary; no task result/approval is certified')
    parser.add_argument('summary', choices=['summary'])
    parser.add_argument('--store', required=True, help='existing absolute owner-private EC231 directory')
    parser.add_argument('--run-id', required=True, help='real EC231 RunId')
    parser.add_argument('--expected-record-sha256', default=None)
    parser.add_argument('--expected-action-set-sha256', default=None)
    parser.add_argument('--expected-input-sha256', default=None)
    parser.add_argument('--expected-pause-sha256', default=None)
    args = parser.parse_args(argv)
    out = CycleSummaryReporter(args.store).summary(
        args.run_id, expected_record_sha256=args.expected_record_sha256,
        expected_action_set_sha256=args.expected_action_set_sha256,
        expected_input_sha256=args.expected_input_sha256,
        expected_pause_sha256=args.expected_pause_sha256)
    print(json.dumps(out, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False))
    # 2 = report generated but success unproven; 3 = blocked; 5 = unknown.
    # No successful task-completion or privileged-action exit code.
    return (5 if out['status'] == 'UNKNOWN_BLOCKED' else
            3 if out['status'] in ('BLOCKED_DAG_CYCLE', 'BLOCKED_NO_HANDLER',
                                   'UNVERIFIED_PROGRESS_BLOCKED') else 2)


if __name__ == '__main__':
    sys.exit(main())
