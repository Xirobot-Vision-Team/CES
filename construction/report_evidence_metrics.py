#!/usr/bin/env python3
"""EC196: bounded, read-only cross-repository report evidence and coverage.

Consumes an exact EC195 canonical scope, NOT a path, Git repository, provider
connection or authenticated grant. No report preparation, scoring, publishing,
file/network access or writes. Counts mean *submitted declarations*, not actual
work done. Actor references require a matching EC194 evidence witness; this is
still no proof of real-world authorship or personal performance.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

from cross_repository_report_scope import CrossRepositoryReportScope

SCHEMA = 'ces.report_evidence_metrics.v1'
MAX_JSON_BYTES = 1048576
MAX_EVENTS = 512
MAX_PER_REPOSITORY = 128
MAX_EVENT_ID = 128
MAX_OUTPUT_BYTES = 1048576
CHANNELS = ('ai_conclusion', 'ci_execution', 'git_activity', 'unknown_signal')
KINDS = {
    'git_activity': frozenset({'commit_claim', 'pull_request_claim',
                               'change_claim'}),
    'ai_conclusion': frozenset({'analysis_claim', 'finding_claim',
                                'recommendation_claim'}),
    'ci_execution': frozenset({'completed_pass_claim', 'completed_fail_claim',
                               'completed_inconclusive_claim', 'running_claim',
                               'not_run_claim', 'canceled_claim'}),
    'unknown_signal': frozenset({'not_collected', 'unavailable',
                                 'redacted', 'unattributable'}),
}
ORIGINS = {
    'git_activity': 'EXTERNAL_GIT_RECORD_CLAIM_UNVERIFIED',
    'ai_conclusion': 'AI_OUTPUT_REFERENCE_CLAIM_UNVERIFIED',
    'ci_execution': 'EXTERNAL_CI_RUN_CLAIM_UNVERIFIED',
    'unknown_signal': 'DECLARED_INFORMATION_GAP_UNVERIFIED',
}
COVERAGE_STATES = frozenset({'COMPLETE_DECLARED', 'PARTIAL_DECLARED', 'UNKNOWN'})
REASONS = frozenset({'COLLECTION_NOT_RUN', 'SOURCE_UNAVAILABLE',
                     'RECORDS_WITHHELD', 'SCOPE_SUBSET', 'INVENTORY_UNKNOWN',
                     'CI_NOT_CONFIGURED', 'RECORDS_PARTIAL',
                     'DATA_NOT_PROVIDED', 'UNRESOLVED_SOURCE',
                     'UNRESOLVED_ACTOR', 'UNVERIFIED_PERIOD'})
HEX64 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
REPO_ID = re.compile(r'cesrepo1:[0-9a-f]{64}\Z', re.ASCII)
REPORT_ID = re.compile(r'cesrs1:[0-9a-f]{64}\Z', re.ASCII)
ACTOR_ID = re.compile(r'cesra1:[0-9a-f]{64}\Z', re.ASCII)
EVENT_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z', re.ASCII)
UTC_STAMP = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z', re.ASCII)
CLAIMS = {
    'original_provider_events_authenticated': False,
    'git_activity_or_delivery_verified': False,
    'ai_conclusions_verified_as_facts': False,
    'ci_runs_executed_or_completed_verified': False,
    'completeness_of_repository_or_period_verified': False,
    'identity_or_evidence_attribution_authenticated': False,
    'individual_productivity_or_performance_assessed': False,
    'employee_scores_or_rankings_generated': False,
    'report_prepared_rendered_or_published': False,
    'native_powershell_report_registered': False,
    'remote_or_business_code_written': False,
}


class MetricsError(ValueError):
    """Safe reason-code-only error: never echo caller event/identity strings."""

    def __init__(self, reason: str, status: str = 'invalid_input') -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise MetricsError(reason)


def exact(value: Any, keys: set[str], reason: str) -> dict[str, Any]:
    need(type(value) is dict and set(value) == keys, reason)
    return value


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':'))


def digest(domain: str, payload: Any) -> str:
    return hashlib.sha256(domain.encode('ascii') + b'\0' +
                          canonical(payload).encode('ascii')).hexdigest()


def valid_id(value: Any, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def valid_sha(value: Any) -> bool:
    return valid_id(value, HEX64)


def utc(value: Any, reason: str) -> datetime:
    need(valid_id(value, UTC_STAMP), reason)
    try:
        dt = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(
            tzinfo=timezone.utc)
    except ValueError as exc:
        raise MetricsError(reason) from exc
    need(dt.strftime('%Y-%m-%dT%H:%M:%SZ') == value, reason)
    return dt


def byte_len(value: str) -> int:
    try:
        return len(value.encode('utf-8'))
    except UnicodeError as exc:
        raise MetricsError('INVALID_TEXT_ENCODING') from exc


def duplicate_guard(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    lowered: set[str] = set()
    for key, val in pairs:
        if key.casefold() in lowered:
            raise MetricsError('JSON_DUPLICATE_KEY')
        lowered.add(key.casefold())
        result[key] = val
    return result


def parse_json(value: Any) -> dict[str, Any]:
    need(type(value) is str and 1 <= byte_len(value) <= MAX_JSON_BYTES,
         'JSON_SIZE_INVALID')
    try:
        d = json.loads(value, object_pairs_hook=duplicate_guard,
                       parse_float=lambda _: (_ for _ in ()).throw(
                           MetricsError('JSON_FLOAT_FORBIDDEN')),
                       parse_constant=lambda _: (_ for _ in ()).throw(
                           MetricsError('JSON_NONFINITE_FORBIDDEN')))
    except MetricsError:
        raise
    except (ValueError, TypeError, RecursionError, OverflowError,
            UnicodeError) as exc:
        raise MetricsError('JSON_INVALID') from exc
    need(type(d) is dict and canonical(d) == value, 'JSON_NONCANONICAL')
    return d


def scope_replay(scope_json: Any, people_subject_witnesses: Any) -> dict[str, Any]:
    need(type(scope_json) is str and byte_len(scope_json) <= MAX_JSON_BYTES,
         'SCOPE_INPUT_SIZE_INVALID')
    need(people_subject_witnesses is None or
         type(people_subject_witnesses) is dict, 'PEOPLE_WITNESSES_INVALID')
    result = CrossRepositoryReportScope().from_json(
        serialized=scope_json,
        people_subject_witnesses=people_subject_witnesses)
    if result['status'] != 'partial':
        status = 'unavailable' if result['status'] == 'unavailable' else 'invalid_input'
        raise MetricsError('UPSTREAM_SCOPE_' + result['reason_code'], status)
    return result['subject']


def _enabled(scope: dict[str, Any]) -> bool:
    return (scope['requested_operation'] == 'report.evidence.read' and
            scope['requested_operation_declared_for_all'] is True and
            'report.evidence.read' in scope['effective_operations'] and
            all(r['status'] == 'READY' for r in scope['repository_set']))


def _coverage_input(raw: Any, repo: dict[str, Any]) -> dict[str, Any]:
    c = exact(raw, {'repository_id', 'channels'}, 'COVERAGE_ROW_FIELDS_INVALID')
    need(c['repository_id'] == repo['repository_id'], 'COVERAGE_REPOSITORY_MISMATCH')
    need(type(c['channels']) is list and len(c['channels']) == len(CHANNELS),
         'COVERAGE_CHANNEL_SET_INVALID')
    parsed: list[dict[str, Any]] = []
    for record in c['channels']:
        v = exact(record, {'channel', 'state', 'receipt_sha256', 'reason_codes'},
                  'COVERAGE_CHANNEL_FIELDS_INVALID')
        need(type(v['channel']) is str and v['channel'] in CHANNELS and
             type(v['state']) is str and v['state'] in COVERAGE_STATES,
             'COVERAGE_CHANNEL_OR_STATE_INVALID')
        need(type(v['reason_codes']) is list and
             all(type(s) is str and s in REASONS for s in v['reason_codes']) and
             v['reason_codes'] == sorted(set(v['reason_codes'])),
             'COVERAGE_REASON_CODES_INVALID')
        if v['state'] == 'COMPLETE_DECLARED':
            need(v['reason_codes'] == [] and valid_sha(v['receipt_sha256']),
                 'COMPLETE_DECLARATION_INVALID')
        elif v['state'] == 'PARTIAL_DECLARED':
            need(bool(v['reason_codes']) and valid_sha(v['receipt_sha256']),
                 'PARTIAL_DECLARATION_INVALID')
        else:
            need(bool(v['reason_codes']) and v['receipt_sha256'] is None,
                 'UNKNOWN_DECLARATION_INVALID')
        parsed.append(dict(v))
    need([c['channel'] for c in parsed] == list(CHANNELS),
         'COVERAGE_CHANNEL_ORDER_OR_DUPLICATE_INVALID')
    return {'repository_id': c['repository_id'], 'channels': parsed}


def _event(raw: Any, *, scope: dict[str, Any],
           row: dict[str, Any], witnesses: dict[str, Any] | None) -> dict[str, Any]:
    keys = {'repository_id', 'report_subject_id', 'repository_binding_sha256',
            'people_binding_sha256', 'period_id', 'evidence_id', 'channel',
            'kind', 'occurred_at_utc', 'recorded_at_utc', 'evidence_sha256',
            'source_receipt_sha256', 'actor_key'}
    e = exact(raw, keys, 'EVIDENCE_FIELDS_INVALID')
    p = row['report']
    need(e['repository_id'] == row['repository_id'] and
         e['report_subject_id'] == p['report_subject_id'] and
         e['repository_binding_sha256'] == p['repository_binding_sha256'] and
         e['people_binding_sha256'] == p['people_binding_sha256'] and
         e['period_id'] == scope['period']['period_id'],
         'EVIDENCE_SCOPE_OR_PIN_MISMATCH')
    need(valid_id(e['evidence_id'], EVENT_ID) and
         all(x not in ('', '.', '..') for x in e['evidence_id'].split('/')),
         'EVIDENCE_ID_INVALID')
    need(type(e['channel']) is str and e['channel'] in CHANNELS and
         type(e['kind']) is str and e['kind'] in KINDS[e['channel']],
         'EVIDENCE_CHANNEL_KIND_INVALID')
    occurrence = utc(e['occurred_at_utc'], 'EVIDENCE_TIME_INVALID')
    recorded = utc(e['recorded_at_utc'], 'RECORD_TIME_INVALID')
    need(utc(scope['period']['start_utc'], 'PERIOD_START_INVALID') <= occurrence <
         utc(scope['period']['end_exclusive_utc'], 'PERIOD_END_INVALID'),
         'EVIDENCE_OUTSIDE_PERIOD')
    need(recorded >= occurrence, 'RECORD_BEFORE_OCCURRENCE')
    need(valid_sha(e['evidence_sha256']), 'EVIDENCE_DIGEST_INVALID')
    need((e['source_receipt_sha256'] is None if e['channel'] == 'unknown_signal'
          else valid_sha(e['source_receipt_sha256'])),
         'SOURCE_RECEIPT_INVALID')
    actor_state = 'NO_ACTOR_REFERENCE'
    if e['actor_key'] is not None:
        need(e['channel'] != 'unknown_signal' and valid_id(e['actor_key'], ACTOR_ID),
             'ACTOR_REFERENCE_INVALID')
        need(witnesses is not None and row['repository_id'] in witnesses,
             'ACTOR_REFERENCE_REQUIRES_EC194_WITNESS')
        actors = witnesses[row['repository_id']]['actors']
        found = next((a for a in actors if a['actor_key'] == e['actor_key']), None)
        need(found is not None and found['identity_receipt_sha256'] is not None,
             'ACTOR_NOT_ELIGIBLE_IN_EC194')
        # A matching actor ID alone is not contribution ownership. Match the
        # exact EC194 evidence reference and original source/time as well.
        expected = {
            'evidence_id': e['evidence_id'],
            'evidence_sha256': e['evidence_sha256'],
            'occurred_at_utc': e['occurred_at_utc'],
            'source_binding_sha256': e['repository_binding_sha256'],
        }
        need(expected in found['evidence_refs'],
             'ACTOR_EVIDENCE_NOT_LINKED_IN_EC194')
        actor_state = 'EC194_DECLARED_EVIDENCE_LINK_UNVERIFIED'
    return {**e, 'origin': ORIGINS[e['channel']],
            'actor_reference_state': actor_state}


def _witness_subjects(scope: dict[str, Any], witnesses: Any) -> dict[str, Any] | None:
    if witnesses is None:
        return None
    # CrossRepositoryReportScope already validated all exact READY witnesses.
    # Parse again only to collect actor evidence reference lists, with true
    # EC194 replay mandatory on the original upstream call above.
    from actor_report_subject import ActorReportSubject
    ready = {r['repository_id'] for r in scope['repository_set']
             if r['status'] == 'READY'}
    need(type(witnesses) is dict and set(witnesses) == ready,
         'PEOPLE_WITNESS_SET_MISMATCH')
    result: dict[str, Any] = {}
    for repo_id, raw in witnesses.items():
        check = ActorReportSubject().from_json(serialized=raw)
        need(check['status'] == 'partial', 'PEOPLE_WITNESS_REPLAY_FAILED')
        result[repo_id] = check['subject']
    return result


def _ci_signal(items: list[dict[str, Any]]) -> str:
    kinds = {e['kind'] for e in items}
    completed = kinds & {
        'completed_pass_claim', 'completed_fail_claim',
        'completed_inconclusive_claim'}
    if len(completed) > 1:
        return 'CONFLICTING_COMPLETION_CLAIMS_UNVERIFIED'
    if 'completed_fail_claim' in completed:
        return 'FAILURE_COMPLETION_CLAIM_UNVERIFIED'
    if 'completed_inconclusive_claim' in completed:
        return 'INCONCLUSIVE_COMPLETION_CLAIM_UNVERIFIED'
    if 'completed_pass_claim' in completed:
        return 'PASS_COMPLETION_CLAIM_UNVERIFIED'
    return 'NO_CI_COMPLETION_CLAIM'


def _effective_coverage(declared: dict[str, Any], row: dict[str, Any]) -> tuple[str, list[str]]:
    state = declared['state']
    reasons = set(declared['reason_codes'])
    soft = set(row['reason_codes'])
    if 'PARTIAL_PERIOD_WINDOW' in soft:
        reasons.add('UPSTREAM_PERIOD_PARTIAL')
    if 'SELECTED_PATH_SCOPE' in soft:
        reasons.add('UPSTREAM_SELECTED_PATHS')
    if 'PATH_INVENTORY_UNVERIFIED' in soft:
        reasons.add('UPSTREAM_INVENTORY_UNVERIFIED')
    if state == 'COMPLETE_DECLARED' and soft:
        state = 'PARTIAL_DECLARED'
    if 'PATH_INVENTORY_UNVERIFIED' in soft or declared['state'] == 'UNKNOWN':
        state = 'UNKNOWN'
    return state, sorted(reasons)


def _build(scope: dict[str, Any], scope_json: str,
           coverage: Any, evidence: Any, witnesses: Any) -> dict[str, Any]:
    need(type(coverage) is list and len(coverage) <= 32 and
         type(evidence) is list and len(evidence) <= MAX_EVENTS,
         'COLLECTION_LIST_INVALID')
    authorized = _enabled(scope)
    # Even a READY subset must not bypass the intersection over a GAP row.
    if not authorized:
        need(coverage == [] and evidence == [],
             'EVIDENCE_SUPPLIED_WITHOUT_SET_WIDE_PERMISSION')
    rows = scope['repository_set']
    by_repo = {r['repository_id']: r for r in rows}
    raw_cov: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    if authorized:
        need(len(coverage) == len(rows), 'COVERAGE_REPOSITORIES_INCOMPLETE')
        need(all(type(v) is dict and type(v.get('repository_id')) is str
                 for v in coverage), 'COVERAGE_ROW_FIELDS_INVALID')
        ids = [v['repository_id'] for v in coverage]
        need(len(set(ids)) == len(ids) and set(ids) == set(by_repo),
             'COVERAGE_REPOSITORY_SET_INVALID')
        for row in sorted(coverage, key=lambda v: v['repository_id']):
            raw_cov.append(_coverage_input(row, by_repo[row['repository_id']]))
        witness_subjects = _witness_subjects(scope, witnesses)
        for raw in evidence:
            need(type(raw) is dict and
                 type(raw.get('repository_id')) is str and
                 raw['repository_id'] in by_repo, 'EVIDENCE_UNKNOWN_REPOSITORY')
            items.append(_event(raw, scope=scope,
                                row=by_repo[raw['repository_id']],
                                witnesses=witness_subjects))
        items.sort(key=lambda e: (e['repository_id'], e['occurred_at_utc'],
                                  e['evidence_id']))
        keys = [(e['repository_id'], e['evidence_id']) for e in items]
        need(len(keys) == len(set(keys)), 'DUPLICATE_EVIDENCE_ID')
        for repo_id in by_repo:
            need(sum(e['repository_id'] == repo_id for e in items) <=
                 MAX_PER_REPOSITORY, 'REPOSITORY_EVENT_LIMIT_EXCEEDED')

    by_cov = {r['repository_id']: r['channels'] for r in raw_cov}
    summaries: list[dict[str, Any]] = []
    for row in rows:
        p = row['report']
        row_items = [e for e in items if e['repository_id'] == row['repository_id']]
        channel_summaries: list[dict[str, Any]] = []
        for channel in CHANNELS:
            grouped = [e for e in row_items if e['channel'] == channel]
            if not authorized:
                summary = {
                    'channel': channel, 'declared_coverage_state': 'NOT_SUBMITTED',
                    'effective_coverage_state': 'BLOCKED',
                    'coverage_receipt_sha256': None, 'coverage_reason_codes':
                    sorted(set(row['reason_codes']) |
                           {'EVIDENCE_PERMISSION_NOT_GRANTED_FOR_SET'}),
                    'declaration_count': 0, 'kinds_present': [],
                    'ci_completion_signal': 'NO_CI_COMPLETION_CLAIM',
                    'empty_observation_meaning': 'NOT_ASSESSED',
                }
            else:
                declared = next(c for c in by_cov[row['repository_id']]
                                if c['channel'] == channel)
                state, reasons = _effective_coverage(declared, row)
                summary = {
                    'channel': channel, 'declared_coverage_state': declared['state'],
                    'effective_coverage_state': state,
                    'coverage_receipt_sha256': declared['receipt_sha256'],
                    'coverage_reason_codes': reasons,
                    'declaration_count': len(grouped),
                    'kinds_present': sorted({e['kind'] for e in grouped}),
                    'ci_completion_signal': (_ci_signal(grouped) if channel ==
                                             'ci_execution' else 'NOT_APPLICABLE'),
                    'empty_observation_meaning': ('HAS_DECLARED_REFERENCES'
                                                   if grouped else
                                                   'ZERO_SUBMITTED_NOT_VERIFIED_ZERO'),
                }
            channel_summaries.append(summary)
        summaries.append({
            'repository': row['repository'],
            'repository_id': row['repository_id'],
            'scope_status': row['status'],
            'report_subject_id': p['report_subject_id'] if p else None,
            'source_mode': p['source_mode'] if p else None,
            'repository_binding_sha256': (p['repository_binding_sha256']
                                          if p else None),
            'people_binding_sha256': p['people_binding_sha256'] if p else None,
            'scope_reason_codes': list(row['reason_codes']),
            'channels': channel_summaries,
        })
    gaps = set(scope['global_gaps'])
    gaps.update({'ORIGINAL_PROVIDER_PROVENANCE_NOT_AUTHENTICATED',
                 'DECLARED_COVERAGE_NOT_VERIFIED',
                 'UNKNOWN_REPOSITORY_UNIVERSE_COMPLETENESS',
                 'NO_INDIVIDUAL_PERFORMANCE_INFERENCE'})
    if not authorized:
        gaps.add('SET_WIDE_REPORT_EVIDENCE_PERMISSION_BLOCKED')
    elif not items:
        gaps.add('NO_EVIDENCE_REFERENCES_SUBMITTED')
    if any(r['source_mode'] == 'ProposedPR' for r in summaries):
        gaps.add('PROPOSED_PR_NOT_DELIVERED_TARGET')
    if any(c['effective_coverage_state'] != 'COMPLETE_DECLARED'
           for row in summaries for c in row['channels']):
        gaps.add('PARTIAL_UNKNOWN_OR_BLOCKED_CHANNEL_COVERAGE')
    out = {
        'schema': SCHEMA,
        'scope_id': scope['scope_id'],
        'scope_binding_sha256': scope['binding_sha256'],
        'scope_canonical_sha256': hashlib.sha256(scope_json.encode('ascii')).hexdigest(),
        'period': json.loads(canonical(scope['period'])),
        'cross_repository_permission_state': ('DECLARED_SET_WIDE_UNVERIFIED'
                                              if authorized else 'BLOCKED'),
        'coverage_declarations': raw_cov,
        'evidence_refs': items,
        'repository_metrics': summaries,
        'global_gaps': sorted(gaps),
        'claims': dict(CLAIMS),
    }
    out['binding_sha256'] = digest('CES-EC196-METRICS-BINDING-v1', out)
    need(byte_len(canonical(out)) <= MAX_OUTPUT_BYTES, 'METRICS_RESULT_TOO_LARGE')
    return out


def _envelope() -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
            'reason_code': 'REPORT_EVIDENCE_METRICS_INPUT_INVALID',
            'subject': None, 'canonical_json': None,
            'limitations': dict(CLAIMS)}


def _success(out: dict[str, Any], subject: dict[str, Any], code: str) -> dict[str, Any]:
    out.update(status='partial', exit_code=2, reason_code=code,
               subject=subject, canonical_json=canonical(subject))
    return out


def _error(out: dict[str, Any], error: MetricsError) -> dict[str, Any]:
    out.update(status=error.status,
               exit_code=(5 if error.status == 'unavailable' else 4),
               reason_code='REPORT_EVIDENCE_METRICS_' + error.reason)
    return out


class ReportEvidenceMetrics:
    """EC196 callable offline evidence declarations; never a performance engine."""

    def bind(self, *, scope_json: str, coverage: list[dict[str, Any]],
             evidence: list[dict[str, Any]],
             people_subject_witnesses: dict[str, str] | None = None) -> dict[str, Any]:
        out = _envelope()
        try:
            scope = scope_replay(scope_json, people_subject_witnesses)
            return _success(out, _build(scope, scope_json, coverage, evidence,
                                        people_subject_witnesses),
                            'REPORT_EVIDENCE_METRICS_BOUND_DECLARATIONS_ONLY')
        except MetricsError as exc:
            return _error(out, exc)

    def from_json(self, *, serialized: str, scope_json: str,
                  people_subject_witnesses: dict[str, str] | None = None) -> dict[str, Any]:
        """Replay *against exact EC195 scope*; actor links also require EC194.

        Hashes and supplied witnesses are not authenticated signatures, and
        source claims remain unverified even when replay is successful.
        """
        out = _envelope()
        try:
            record = parse_json(serialized)
            exact(record, {'schema', 'scope_id', 'scope_binding_sha256',
                           'scope_canonical_sha256', 'period',
                           'cross_repository_permission_state',
                           'coverage_declarations', 'evidence_refs',
                           'repository_metrics', 'global_gaps', 'claims',
                           'binding_sha256'}, 'RECORD_FIELDS_INVALID')
            need(record['schema'] == SCHEMA, 'RECORD_SCHEMA_INVALID')
            need(type(record['coverage_declarations']) is list and
                 type(record['evidence_refs']) is list,
                 'REPLAY_COLLECTION_TYPE_INVALID')
            inputs = []
            for event in record['evidence_refs']:
                exact(event, {'repository_id', 'report_subject_id',
                              'repository_binding_sha256', 'people_binding_sha256',
                              'period_id', 'evidence_id', 'channel', 'kind',
                              'occurred_at_utc', 'recorded_at_utc',
                              'evidence_sha256', 'source_receipt_sha256',
                              'actor_key', 'origin', 'actor_reference_state'},
                      'REPLAY_EVIDENCE_FIELDS_INVALID')
                inputs.append({k: v for k, v in event.items()
                               if k not in ('origin', 'actor_reference_state')})
            scope = scope_replay(scope_json, people_subject_witnesses)
            rebuilt = _build(scope, scope_json, record['coverage_declarations'],
                             inputs, people_subject_witnesses)
            need(canonical(record) == canonical(rebuilt),
                 'REPLAY_DERIVATION_OR_BINDING_MISMATCH')
            return _success(out, rebuilt,
                            'REPORT_EVIDENCE_METRICS_REPLAYED_WITH_SCOPE')
        except MetricsError as exc:
            return _error(out, exc)
