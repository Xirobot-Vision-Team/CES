#!/usr/bin/env python3
"""EC190: bounded, source-provenance-aware cross-mode quality *relations*.

Unlike a union of projected QualityShow JSON, every source is independently
queried through the real EC188 producer reader (all pages and grants). A saved
CodeInsight is read as its original bytes and checked by the EC158 v1 inspector.
Each cross-mode relation requires a separately read, exactly bound, typed host
source-event record, independent authorization, and a fresh host revalidation
before publication. Host attestations do NOT establish Git, CI, merge, delivery,
authorship or actual test execution to CES.

Relationships transfer *context* only, never quality PASS, Finding confirmation,
source equivalence, review status or deployment/currentness. No writes.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from typing import Any, Callable

import quality_show as qs
import quality_finding_link as ec189
import schema_compat as schema_v1

SCHEMA = 'ces.cross_mode_quality_flow.v1'
EVENT_SCHEMA = 'ces.cross_mode_source_event.v1'
REVOKE_SCHEMA = 'ces.cross_mode_revocation.v1'
SOURCE_DOMAIN = b'CES-EC190-SOURCE-IDENTITY-v1\0'
REQUEST_DOMAIN = b'CES-EC190-FLOW-REQUEST-v1\0'
FLOW_DOMAIN = b'CES-EC190-FLOW-RESULT-v1\0'
MAX_EVENTS = 16
MAX_REVOKES = 16
MAX_ITEMS_PER_SIDE = 8
MAX_EVENT_BYTES = 8192
MAX_CODE_BYTES = 512 * 1024
MAX_REQUEST_BYTES = 7 * 1024 * 1024
MAX_QUALITY_PAGES = 4
MAX_AGE_SECONDS = 300
MODES = frozenset({'ProposedPR', 'DeliveredTarget', 'WorkingTree', 'CodeInsight'})
RELATIONS = frozenset({'PROPOSAL_TO_DELIVERED', 'DELIVERED_TO_WORKTREE',
                       'CODE_INSIGHT_TO_SOURCE', 'CONTEXT_COMPARISON'})
CLAIMS = frozenset({'SUPPORTED', 'DISPUTED'})
REVOCATION_REASONS = frozenset({'SOURCE_RETRACTED', 'EVIDENCE_SUPERSEDED',
                                'HOST_PERMISSION_WITHDRAWN', 'MAPPING_CORRECTED'})
TRUST = ('HOST_REVALIDATED_BOUND_SOURCE_EVENT_IS_HOST_DECLARATION_NOT_CES_GIT_MERGE_'
         'OR_DEPLOYMENT_AUTHENTICATION; EC188_RECEIPTS_ARE_CALLER_SUPPLIED_CHECKSUMS; '
         'CODE_INSIGHT_IS_STATIC_UNVERIFIED_V1_SAVED_BYTES; NO_EXECUTED_TEST_'
         'CONFIRMED_DEFECT_SOURCE_EQUIVALENCE_QUALITY_PASS_OR_WRITES')


class FlowError(ValueError):
    def __init__(self, reason: str, status: str = 'invalid_input') -> None:
        super().__init__(reason)
        self.reason, self.status = reason, status


def need(condition: bool, reason: str, status: str = 'invalid_input') -> None:
    if not condition:
        raise FlowError(reason, status)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode('utf-8')


def digest(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + canonical(value)).hexdigest()


def _sha(value: Any) -> bool:
    return type(value) is str and qs.HEX64.fullmatch(value) is not None


def _now(clock: Callable[[], datetime] | None) -> datetime:
    return qs._now(clock)


def _time(stamp: Any) -> datetime:
    return qs._timestamp(stamp)


def _grant(callback: Any, facts: dict[str, Any], reason: str) -> None:
    need(callable(callback), reason, 'unavailable')
    try:
        decision = callback(copy.deepcopy(facts))
    except Exception as exc:
        raise FlowError(reason, 'unavailable') from exc
    need(decision is True, reason, 'unavailable')


def _read(callback: Any, facts: dict[str, Any], max_bytes: int, reason: str) -> bytes:
    need(callable(callback), reason, 'unavailable')
    try:
        raw = callback(copy.deepcopy(facts))
    except Exception as exc:
        raise FlowError(reason, 'unavailable') from exc
    need(type(raw) is bytes and 0 < len(raw) <= max_bytes, reason, 'unavailable')
    return raw


def _parse_bytes(raw: bytes, schema: str, expected_keys: set[str]) -> dict[str, Any]:
    try:
        obj = schema_v1.decode_one(raw)
    except (schema_v1.SchemaInputError, TypeError, ValueError, RecursionError) as exc:
        raise FlowError('QUALITYFLOW_ORIGINAL_PROOF_BYTES_INVALID', 'unavailable') from exc
    need(type(obj) is dict and set(obj) == expected_keys and obj.get('schema') == schema,
         'QUALITYFLOW_PROOF_FORMAT_OR_VERSION_INVALID', 'unavailable')
    return obj


def _effects() -> dict[str, bool]:
    return {
        'read_only': True, 'ces_store_written': False,
        'business_repository_or_git_written': False, 'provider_or_issue_written': False,
        'test_or_ci_executed_by_flow': False, 'quality_pass_verified': False,
        'defect_confirmed': False, 'finding_or_review_state_modified': False,
        'proposed_pr_declared_delivered': False, 'deployment_or_currentness_verified': False,
        'cross_mode_source_equivalence_proven': False,
        'code_insight_semantics_or_authorship_verified': False,
        'source_text_or_model_summary_exposed': False,
    }


def _denied(reason: str, status: str) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': 4 if status == 'invalid_input' else 5,
        'reason_code': reason, 'flow_revision_sha256': None, 'sources': [],
        'relations': [], 'revocations': [], 'counts': None, 'coverage': None,
        'effects': _effects(), 'trust_boundary': TRUST,
    }


def _scope_inputs(raw: Any, now: datetime, *, acknowledgement: bool) -> dict[str, dict[str, Any]]:
    need(type(raw) is dict and 1 <= len(raw) <= 3 and
         set(raw) <= {'ProposedPR', 'DeliveredTarget', 'WorkingTree'},
         'QUALITYFLOW_QUALITY_SOURCE_SET_INVALID')
    output = {}
    for mode, source in raw.items():
        need(type(source) is dict and set(source) == {
            'source_scope', 'evidence', 'captured_at_utc'},
            'QUALITYFLOW_QUALITY_SOURCE_EXACT_FIELDS_REQUIRED')
        scope = qs._scope(source['source_scope'])
        need(scope['source_mode'] == mode, 'QUALITYFLOW_MODE_SCOPE_MISMATCH')
        need(type(source['evidence']) is list and len(source['evidence']) <= qs.MAX_RECORDS,
             'QUALITYFLOW_SOURCE_EVIDENCE_LIMIT_INVALID')
        captured = _time(source['captured_at_utc'])
        need(captured <= now + timedelta(seconds=qs.MAX_SKEW_SECONDS),
             'QUALITYFLOW_SOURCE_CAPTURE_FROM_FUTURE', 'unavailable')
        if mode == 'ProposedPR':
            need(acknowledgement, 'QUALITYFLOW_PROPOSAL_HISTORY_ACK_REQUIRED', 'unavailable')
        scope_sha = qs.digest(qs.DOMAIN_SCOPE, scope)
        output[mode] = {
            'mode': mode, 'scope': scope, 'scope_sha256': scope_sha,
            'captured_at_utc': source['captured_at_utc'],
            'source_id': digest(SOURCE_DOMAIN, {'mode': mode, 'scope_sha256': scope_sha}),
            'receipt_input': source['evidence'],
        }
    return output


def _code_input(raw: Any, now: datetime) -> dict[str, Any]:
    need(type(raw) is dict and set(raw) == {
        'record_id', 'native_source_mode', 'captured_at_utc'},
        'QUALITYFLOW_CODE_INSIGHT_EXACT_FIELDS_REQUIRED')
    record_id = raw['record_id']
    need(type(record_id) is str and schema_v1.RECORD_ID.fullmatch(record_id) is not None and
         raw['native_source_mode'] in ('working_tree_diff', 'delivered_target_diff'),
         'QUALITYFLOW_CODE_INSIGHT_ID_OR_NATIVE_MODE_INVALID')
    need(_time(raw['captured_at_utc']) <= now + timedelta(seconds=qs.MAX_SKEW_SECONDS),
         'QUALITYFLOW_CODE_INSIGHT_CAPTURE_FROM_FUTURE', 'unavailable')
    scope = {'source_mode': 'CodeInsight', 'record_id': record_id,
             'native_source_mode': raw['native_source_mode']}
    scope_sha = digest(SOURCE_DOMAIN, scope)
    return {
        'mode': 'CodeInsight', 'scope': scope, 'scope_sha256': scope_sha,
        'captured_at_utc': raw['captured_at_utc'],
        'source_id': digest(SOURCE_DOMAIN, {'mode': 'CodeInsight',
                                           'scope_sha256': scope_sha}),
        'receipt_input': None,
    }


def _selection(raw: Any) -> list[dict[str, Any]]:
    need(type(raw) is list and 1 <= len(raw) <= MAX_EVENTS,
         'QUALITYFLOW_RELATION_LIMIT_INVALID')
    result = []
    seen: set[str] = set()
    for choice in raw:
        need(type(choice) is dict and set(choice) == {
            'event_sha256', 'from_item_ids', 'to_item_ids'},
            'QUALITYFLOW_EVENT_SELECTION_FIELDS_INVALID')
        eid = choice['event_sha256']
        need(_sha(eid) and eid not in seen, 'QUALITYFLOW_DUPLICATE_OR_INVALID_EVENT_ID')
        seen.add(eid)
        for key in ('from_item_ids', 'to_item_ids'):
            ids = choice[key]
            need(type(ids) is list and len(ids) <= MAX_ITEMS_PER_SIDE and
                 all(type(v) is str and 1 <= len(v) <= 128 and
                     not any(ord(c) < 33 or ord(c) > 126 for c in v) for v in ids) and
                 len(ids) == len(set(ids)), 'QUALITYFLOW_ITEM_SELECTION_INVALID')
        result.append(copy.deepcopy(choice))
    return result


def _revocation_selections(raw: Any, known: set[str]) -> list[dict[str, str]]:
    need(type(raw) is list and len(raw) <= MAX_REVOKES,
         'QUALITYFLOW_REVOCATION_LIMIT_INVALID')
    seen = set()
    result = []
    for item in raw:
        need(type(item) is dict and set(item) == {'event_sha256', 'revocation_sha256'} and
             item['event_sha256'] in known and _sha(item['revocation_sha256']) and
             item['revocation_sha256'] not in seen,
             'QUALITYFLOW_REVOCATION_SELECTION_INVALID')
        seen.add(item['revocation_sha256'])
        result.append(copy.deepcopy(item))
    return result


def _validate_proof(proof: Any, relation: str,
                    source: dict[str, Any], target: dict[str, Any]) -> None:
    need(type(proof) is dict, 'QUALITYFLOW_SOURCE_PROOF_REQUIRED', 'unavailable')
    s, t = source['scope'], target['scope']
    if relation == 'PROPOSAL_TO_DELIVERED':
        need(source['mode'] == 'ProposedPR' and target['mode'] == 'DeliveredTarget' and
             set(proof) == {'provider', 'repository', 'project_id', 'proposal_number',
                            'proposal_head_sha', 'delivered_commit_sha', 'merge_event_sha256'} and
             all(proof.get(k) == s[k] == t[k] for k in
                 ('provider', 'repository', 'project_id')) and
             proof.get('proposal_number') == s['proposal_number'] and
             proof.get('proposal_head_sha') == s['commit_sha'] and
             proof.get('delivered_commit_sha') == t['commit_sha'] and
             _sha(proof.get('merge_event_sha256')),
             'QUALITYFLOW_PROPOSAL_DELIVERY_PROOF_NOT_BOUND', 'unavailable')
    elif relation == 'DELIVERED_TO_WORKTREE':
        need(source['mode'] == 'DeliveredTarget' and target['mode'] == 'WorkingTree' and
             set(proof) == {'provider', 'repository', 'project_id', 'delivered_commit_sha',
                            'worktree_base_commit_sha', 'root_pin_sha256',
                            'local_snapshot_event_sha256'} and
             all(proof.get(k) == s[k] for k in
                 ('provider', 'repository', 'project_id')) and
             proof.get('delivered_commit_sha') == s['commit_sha'] and
             proof.get('worktree_base_commit_sha') == s['commit_sha'] and
             proof.get('root_pin_sha256') == t['root_pin_sha256'] and
             _sha(proof.get('local_snapshot_event_sha256')),
             'QUALITYFLOW_WORKTREE_ANCHOR_PROOF_NOT_BOUND', 'unavailable')
    elif relation == 'CODE_INSIGHT_TO_SOURCE':
        want_mode = {'working_tree_diff': 'WorkingTree',
                     'delivered_target_diff': 'DeliveredTarget'}
        need(source['mode'] == 'CodeInsight' and
             target['mode'] == want_mode.get(s['native_source_mode']) and
             set(proof) == {'record_id', 'record_sha256', 'native_source_mode',
                            'target_scope_sha256', 'native_packet_sha256',
                            'native_collect_sha256', 'snapshot_map_event_sha256'} and
             proof.get('record_id') == s['record_id'] and
             proof.get('record_sha256') == s['record_id'][3:] and
             proof.get('native_source_mode') == s['native_source_mode'] and
             proof.get('target_scope_sha256') == target['scope_sha256'] and
             all(_sha(proof.get(k)) for k in
                 ('native_packet_sha256', 'native_collect_sha256',
                  'snapshot_map_event_sha256')),
             'QUALITYFLOW_CODE_INSIGHT_SNAPSHOT_PROOF_NOT_BOUND', 'unavailable')
    elif relation == 'CONTEXT_COMPARISON':
        need(source['mode'] != target['mode'] and
             set(proof) == {'source_capture_ref_sha256', 'target_capture_ref_sha256'} and
             all(_sha(proof.get(k)) for k in proof),
             'QUALITYFLOW_CONTEXT_EVIDENCE_NOT_BOUND', 'unavailable')
    else:
        raise FlowError('QUALITYFLOW_RELATION_KIND_UNSUPPORTED', 'unavailable')


def _validate_event(raw: bytes, sources: dict[str, dict[str, Any]],
                    expected_sha: str, now: datetime) -> dict[str, Any]:
    need(hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha),
         'QUALITYFLOW_EVENT_BYTES_SHA_MISMATCH', 'unavailable')
    event = _parse_bytes(raw, EVENT_SCHEMA, {
        'schema', 'relation_kind', 'claim', 'from_mode', 'to_mode',
        'from_scope_sha256', 'to_scope_sha256', 'occurred_at_utc',
        'recorded_at_utc', 'proof'})
    kind, claim = event['relation_kind'], event['claim']
    a, b = event['from_mode'], event['to_mode']
    need(type(kind) is str and kind in RELATIONS and
         type(claim) is str and claim in CLAIMS and
         type(a) is str and type(b) is str and a in sources and
         b in sources and a != b and
         event['from_scope_sha256'] == sources[a]['scope_sha256'] and
         event['to_scope_sha256'] == sources[b]['scope_sha256'],
         'QUALITYFLOW_EVENT_SOURCE_SCOPE_NOT_BOUND', 'unavailable')
    occured = _time(event['occurred_at_utc'])
    recorded = _time(event['recorded_at_utc'])
    need(occured <= recorded <= now + timedelta(seconds=qs.MAX_SKEW_SECONDS),
         'QUALITYFLOW_EVENT_CHRONOLOGY_INVALID', 'unavailable')
    _validate_proof(event['proof'], kind, sources[a], sources[b])
    return event


def _validate_revoke(raw: bytes, event_sha: str, event: dict[str, Any],
                     expected_sha: str, now: datetime) -> dict[str, Any]:
    need(hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha),
         'QUALITYFLOW_REVOCATION_BYTES_SHA_MISMATCH', 'unavailable')
    revoked = _parse_bytes(raw, REVOKE_SCHEMA, {
        'schema', 'event_sha256', 'reason', 'revoked_at_utc', 'recorded_at_utc',
        'host_revocation_event_sha256'})
    need(revoked['event_sha256'] == event_sha and
         revoked['reason'] in REVOCATION_REASONS and
         _sha(revoked['host_revocation_event_sha256']),
         'QUALITYFLOW_REVOCATION_NOT_BOUND', 'unavailable')
    t, recorded = _time(revoked['revoked_at_utc']), _time(revoked['recorded_at_utc'])
    need(_time(event['occurred_at_utc']) <= t <= recorded <= now + timedelta(seconds=qs.MAX_SKEW_SECONDS),
         'QUALITYFLOW_REVOCATION_CHRONOLOGY_INVALID', 'unavailable')
    return revoked


def _chronology(event: dict[str, Any], sources: dict[str, dict[str, Any]]) -> str:
    """Only label inconsistent capture/event ordering, never prove actual Git time."""
    a = _time(sources[event['from_mode']]['captured_at_utc'])
    b = _time(sources[event['to_mode']]['captured_at_utc'])
    t = _time(event['occurred_at_utc'])
    slack = timedelta(seconds=qs.MAX_SKEW_SECONDS)
    if event['relation_kind'] == 'CODE_INSIGHT_TO_SOURCE':
        # CI record read occurs after the source snapshot it purports to analyze.
        return 'CALLER_CAPTURE_ORDER_CONSISTENT' if b <= a + slack and t <= a + slack else \
               'CALLER_CAPTURE_ORDER_CONTRADICTED'
    if event['relation_kind'] in ('PROPOSAL_TO_DELIVERED', 'DELIVERED_TO_WORKTREE'):
        return 'CALLER_CAPTURE_ORDER_CONSISTENT' if a <= t + slack and t <= b + slack else \
               'CALLER_CAPTURE_ORDER_CONTRADICTED'
    return 'NOT_ORDERED_CONTEXT_COMPARISON'


def _real_quality(view: qs.QualityShow, source: dict[str, Any],
                  *, authorize_scope: Any, authorize_evidence: Any,
                  historical: bool) -> dict[str, Any]:
    params = {
        'source_scope': source['scope'], 'evidence': source['receipt_input'],
        'allow_query': True, 'allow_evidence_read': True,
        'authorize_scope': authorize_scope, 'authorize_evidence': authorize_evidence,
        'page_size': qs.MAX_PAGE, 'include_numeric_metrics': False,
        'acknowledge_historical_proposal': historical,
    }
    entries = {}
    first = None
    cursor = None
    revision = None
    query_sha = None
    for _ in range(MAX_QUALITY_PAGES):
        result = view.query(**params, cursor=cursor)
        revision, query_sha = ec189._validate_quality_page(
            result, revision=revision, query=query_sha)
        if first is None:
            first = result
        for item in result['entries']:
            key = item['evidence_id']
            need(_sha(key) and key not in entries and
                 item['summary']['quality_pass_verified'] is False,
                 'QUALITYFLOW_REPEATED_OR_UNSAFE_QUALITY_RECEIPT', 'unavailable')
            entries[key] = item
        cursor = result['next_cursor']
        if cursor is None:
            break
    need(first is not None and cursor is None and
         len(entries) == first['counts']['matched'],
         'QUALITYFLOW_QUALITY_PAGINATION_INCOMPLETE', 'unavailable')
    return {'entries': entries, 'first': first, 'revision': revision,
            'query_sha256': query_sha, 'params': params}


def _code_record(raw: bytes, record_id: str, native_mode: str) -> dict[str, Any]:
    need(len(raw) <= MAX_CODE_BYTES, 'QUALITYFLOW_CODE_INSIGHT_SIZE_INVALID', 'unavailable')
    try:
        report = schema_v1.inspect_bytes(raw, kind='code_insight_saved',
                                         path='-', record_id=record_id)
        original = schema_v1.decode_one(raw)
    except (ValueError, TypeError, UnicodeError, RecursionError,
            schema_v1.SchemaInputError) as exc:
        raise FlowError('QUALITYFLOW_CODE_INSIGHT_RECORD_INVALID', 'unavailable') from exc
    need(report['compatible_for_offline_read'] is True and
         original['source_mode'] == native_mode and
         original['model_origin_authenticated'] is False and
         original['ci_verified'] is False and
         original['remote_delivery_verified'] is False,
         'QUALITYFLOW_CODE_INSIGHT_RECORD_INVALID', 'unavailable')
    return {'raw_sha256': report['content_sha256'],
            'record_id': record_id,
            'finding_count': original['finding_count'],
            'finding_ids': {item['id'] for item in original['checked_findings']},
            'packet_sha256': original['packet_sha256'],
            'collect_sha256': original['saved_collect_sha256']}


def _selected(source: dict[str, Any], indices: list[str],
              quality_data: dict[str, Any] | None,
              code_data: dict[str, Any] | None) -> dict[str, Any]:
    if source['mode'] == 'CodeInsight':
        need(code_data is not None and set(indices) <= code_data['finding_ids'],
             'QUALITYFLOW_CODE_FINDING_ID_NOT_IN_ORIGINAL_RECORD', 'unavailable')
        return {'selected_ids': sorted(indices), 'evidence_kind': 'STATIC_CODE_INSIGHT',
                'failure_claims': 0, 'pass_claims': 0, 'context_only': len(indices),
                'static_findings_are_not_test_results': True}
    need(quality_data is not None and len(indices) >= 1 and
         all(_sha(key) and key in quality_data['entries'] for key in indices),
         'QUALITYFLOW_QUALITY_EVIDENCE_ID_NOT_IN_ORIGINAL_QUERY', 'unavailable')
    signals = [ec189._quality_claim(quality_data['entries'][key])[0] for key in indices]
    return {'selected_ids': sorted(indices), 'evidence_kind': 'EC188_QUALITY_CLAIMS',
            'failure_claims': signals.count('FAILURE_CLAIM'),
            'pass_claims': signals.count('PASS_CLAIM'),
            'context_only': signals.count('UNDETERMINED'),
            'static_findings_are_not_test_results': False}


class CrossModeQualityFlow:
    """Compose genuine same-source readers; a host must supply independent proof.

    read_* callbacks resolve ORIGINAL bytes from separately authorized storage.
    verify_event / verify_revocation are host-side independent provenance checks
    (not predicates computed only from supplied SHA, echo fields, or results).
    The component cannot and does not certify such host checks as authentic Git.
    """

    def __init__(self, quality_view: qs.QualityShow,
                 *, clock: Callable[[], datetime] | None = None) -> None:
        if not isinstance(quality_view, qs.QualityShow):
            raise ValueError('Original EC188 QualityShow implementation required')
        if clock is not None and not callable(clock):
            raise ValueError('Clock must be callable')
        self.quality_view, self._clock = quality_view, clock

    def relate(self, *, quality_sources: dict[str, dict[str, Any]],
               relations: list[dict[str, Any]],
               code_insight: dict[str, Any] | None = None,
               revocations: list[dict[str, str]] | None = None,
               allow_flow: bool = False, allow_quality_query: bool = False,
               allow_quality_evidence_read: bool = False,
               authorize_quality_scope: Any = None,
               authorize_quality_evidence: Any = None,
               allow_code_insight_read: bool = False,
               authorize_code_insight: Any = None,
               read_code_insight: Any = None,
               authorize_source_event: Any = None,
               read_source_event: Any = None,
               verify_source_event: Any = None,
               authorize_revocation: Any = None,
               read_revocation: Any = None,
               verify_revocation: Any = None,
               acknowledge_historical_proposal: bool = False) -> dict[str, Any]:
        try:
            need(allow_flow is True and allow_quality_query is True and
                 allow_quality_evidence_read is True,
                 'QUALITYFLOW_THREE_SEPARATE_QUALITY_OPT_INS_REQUIRED', 'unavailable')
            need(type(acknowledge_historical_proposal) is bool,
                 'QUALITYFLOW_PROPOSAL_ACK_TYPE_INVALID')
            now = _now(self._clock)
            source_set = _scope_inputs(quality_sources, now,
                                       acknowledgement=acknowledge_historical_proposal)
            if code_insight is not None:
                need(allow_code_insight_read is True,
                     'QUALITYFLOW_CODE_INSIGHT_SEPARATE_OPT_IN_REQUIRED', 'unavailable')
                source_set['CodeInsight'] = _code_input(code_insight, now)
            need(2 <= len(source_set) <= 4, 'QUALITYFLOW_TWO_TO_FOUR_MODES_REQUIRED')
            choices = _selection(relations)
            normalized_revocations = [] if revocations is None else revocations
            revoke_choices = _revocation_selections(normalized_revocations,
                                                     {r['event_sha256'] for r in choices})
            input_snapshot = canonical({
                'sources': quality_sources, 'code_insight': code_insight,
                'relations': relations, 'revocations': normalized_revocations,
                'ack': acknowledge_historical_proposal,
            })
            need(len(input_snapshot) <= MAX_REQUEST_BYTES, 'QUALITYFLOW_INPUT_TOO_LARGE')
            request_id = digest(REQUEST_DOMAIN, {
                'entire_input_sha256': hashlib.sha256(input_snapshot).hexdigest(),
                'source_ids': sorted(s['source_id'] for s in source_set.values()),
                'events': choices, 'revocations': revoke_choices})
            # All sources are re-read, separately and with their original per-item
            # grants. No caller-supplied pre-projected QualityShow is authoritative.
            source_results: dict[str, dict[str, Any]] = {}
            code_result = None
            code_raw_sha = None
            for mode in sorted(source_set):
                s = source_set[mode]
                if mode == 'CodeInsight':
                    facts = {'purpose': 'READ_EXACT_SAVED_STATIC_CODE_INSIGHT',
                             'phase': 'BEFORE_READ', 'request_sha256': request_id,
                             'record_id': s['scope']['record_id'],
                             'source_id': s['source_id'],
                             'native_source_mode': s['scope']['native_source_mode']}
                    _grant(authorize_code_insight, facts,
                           'QUALITYFLOW_CODE_INSIGHT_AUTHORIZATION_DENIED')
                    raw = _read(read_code_insight, facts, MAX_CODE_BYTES,
                                'QUALITYFLOW_CODE_INSIGHT_BYTES_UNAVAILABLE')
                    code_result = _code_record(raw, s['scope']['record_id'],
                                               s['scope']['native_source_mode'])
                    code_raw_sha = hashlib.sha256(raw).hexdigest()
                else:
                    source_results[mode] = _real_quality(
                        self.quality_view, s,
                        authorize_scope=authorize_quality_scope,
                        authorize_evidence=authorize_quality_evidence,
                        historical=acknowledge_historical_proposal)

            records: list[dict[str, Any]] = []
            event_objs: dict[str, dict[str, Any]] = {}
            event_facts: dict[str, dict[str, Any]] = {}
            event_verification: dict[str, dict[str, Any]] = {}
            for selection in choices:
                eid = selection['event_sha256']
                facts = {'purpose': 'READ_CROSS_MODE_SOURCE_EVENT_NOT_SOURCE_EQUIVALENCE',
                         'phase': 'BEFORE_READ', 'event_sha256': eid,
                         'request_sha256': request_id,
                         'source_ids': sorted(s['source_id'] for s in source_set.values()),
                         'source_scopes': {mode: copy.deepcopy(source_set[mode]['scope'])
                                           for mode in sorted(source_set)},
                         'selected_from_ids': sorted(selection['from_item_ids']),
                         'selected_to_ids': sorted(selection['to_item_ids'])}
                _grant(authorize_source_event, facts,
                       'QUALITYFLOW_SOURCE_EVENT_PERMISSION_DENIED')
                raw = _read(read_source_event, facts, MAX_EVENT_BYTES,
                            'QUALITYFLOW_SOURCE_EVENT_UNAVAILABLE')
                evt = _validate_event(raw, source_set, eid, now)
                a, b = evt['from_mode'], evt['to_mode']
                verify_facts = {**facts, 'event': evt,
                    'from_scope': copy.deepcopy(source_set[a]['scope']),
                    'to_scope': copy.deepcopy(source_set[b]['scope']),
                    'from_capture_at_utc_caller_supplied': source_set[a]['captured_at_utc'],
                    'to_capture_at_utc_caller_supplied': source_set[b]['captured_at_utc'],
                    'from_quality_revision_sha256': source_results[a]['revision']
                        if a in source_results else None,
                    'to_quality_revision_sha256': source_results[b]['revision']
                        if b in source_results else None,
                    'code_insight_record_sha256': code_raw_sha}
                _grant(verify_source_event, verify_facts,
                       'QUALITYFLOW_HOST_EVENT_REVALIDATION_FAILED')
                left = _selected(source_set[a], selection['from_item_ids'],
                                 source_results.get(a), code_result)
                right = _selected(source_set[b], selection['to_item_ids'],
                                  source_results.get(b), code_result)
                if evt['relation_kind'] == 'CODE_INSIGHT_TO_SOURCE':
                    need(code_result is not None and
                         evt['proof']['native_packet_sha256'] == code_result['packet_sha256'] and
                         evt['proof']['native_collect_sha256'] == code_result['collect_sha256'],
                         'QUALITYFLOW_CODE_PACKET_IDENTITY_MISMATCH', 'unavailable')
                event_objs[eid], event_facts[eid] = evt, facts
                event_verification[eid] = verify_facts
                records.append({
                    'event_sha256': eid, 'from_mode': a, 'to_mode': b,
                    'from_source_id': source_set[a]['source_id'],
                    'to_source_id': source_set[b]['source_id'],
                    'relationship': evt['relation_kind'], 'claim': evt['claim'],
                    'occurred_at_utc_host_declared': evt['occurred_at_utc'],
                    'recorded_at_utc_host_declared': evt['recorded_at_utc'],
                    'capture_order': _chronology(evt, source_set),
                    'from_evidence': left, 'to_evidence': right,
                    'status': None, 'revoked_by_sha256': [],
                    'conflicting_active_evidence_ids': [],
                    'source_event_verified_by_ces_git': False,
                    'independent_source_equivalence_proven': False,
                    'quality_state_transferred': False,
                    'tests_executed_by_relation': False,
                })

            revoked_items: list[dict[str, Any]] = []
            revoke_facts: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for selection in revoke_choices:
                eid, rid = selection['event_sha256'], selection['revocation_sha256']
                facts = {'purpose': 'READ_CROSS_MODE_RELATION_REVOCATION',
                         'phase': 'BEFORE_READ', 'request_sha256': request_id,
                         'event_sha256': eid, 'revocation_sha256': rid}
                _grant(authorize_revocation, facts,
                       'QUALITYFLOW_REVOCATION_PERMISSION_DENIED')
                raw = _read(read_revocation, facts, MAX_EVENT_BYTES,
                            'QUALITYFLOW_REVOCATION_UNAVAILABLE')
                rev = _validate_revoke(raw, eid, event_objs[eid], rid, now)
                _grant(verify_revocation, {**facts, 'revocation': rev,
                                            'original_source_event': event_objs[eid]},
                       'QUALITYFLOW_HOST_REVOCATION_REVALIDATION_FAILED')
                revoked_items.append({
                    'event_sha256': eid, 'revocation_sha256': rid,
                    'reason': rev['reason'],
                    'revoked_at_utc_host_declared': rev['revoked_at_utc'],
                    'recorded_at_utc_host_declared': rev['recorded_at_utc'],
                    'host_revocation_verified_by_ces': False,
                })
                revoke_facts.append((facts, rev))

            for record in records:
                record['revoked_by_sha256'] = sorted(
                    item['revocation_sha256'] for item in revoked_items
                    if item['event_sha256'] == record['event_sha256'])
                if record['revoked_by_sha256']:
                    record['status'] = 'REVOKED_NOT_ACTIVE'
                elif record['capture_order'] == 'CALLER_CAPTURE_ORDER_CONTRADICTED':
                    record['status'] = 'TEMPORAL_CONTRADICTION_NOT_ACTIVE'
                elif record['claim'] == 'DISPUTED':
                    record['status'] = 'DISPUTED_NOT_ACTIVE'
                else:
                    record['status'] = 'CONTEXT_ASSOCIATION_ONLY'
            for record in records:
                peers = [other['event_sha256'] for other in records
                         if other is not record and
                         other['from_source_id'] == record['from_source_id'] and
                         other['to_source_id'] == record['to_source_id'] and
                         other['relationship'] == record['relationship'] and
                         other['claim'] != record['claim'] and
                         not other['revoked_by_sha256'] and
                         not record['revoked_by_sha256']]
                record['conflicting_active_evidence_ids'] = sorted(peers)
                if peers and record['status'] != 'TEMPORAL_CONTRADICTION_NOT_ACTIVE':
                    record['status'] = 'CONTRADICTED_NOT_ACTIVE'

            # Before any result is released: re-authorize all source events,
            # re-read original proof bytes and invoke host verification again.
            # This detects source-record retraction as well as authorization
            # changes, but it is not a multi-system atomic transaction.
            for eid, facts in event_facts.items():
                fresh = {**facts, 'phase': 'FINALIZE'}
                _grant(authorize_source_event, fresh,
                       'QUALITYFLOW_SOURCE_EVENT_PERMISSION_REVOKED')
                raw = _read(read_source_event, fresh, MAX_EVENT_BYTES,
                            'QUALITYFLOW_SOURCE_EVENT_CHANGED')
                need(hashlib.sha256(raw).hexdigest() == eid and
                     _validate_event(raw, source_set, eid, _now(self._clock)) == event_objs[eid],
                     'QUALITYFLOW_SOURCE_EVENT_CHANGED', 'unavailable')
                _grant(verify_source_event, {**event_verification[eid],
                                             'phase': 'FINALIZE'},
                       'QUALITYFLOW_SOURCE_EVENT_VERIFICATION_REVOKED')
            for facts, rev in revoke_facts:
                fresh = {**facts, 'phase': 'FINALIZE'}
                _grant(authorize_revocation, fresh,
                       'QUALITYFLOW_REVOCATION_PERMISSION_REVOKED')
                raw = _read(read_revocation, fresh, MAX_EVENT_BYTES,
                            'QUALITYFLOW_REVOCATION_CHANGED')
                need(_validate_revoke(raw, facts['event_sha256'],
                     event_objs[facts['event_sha256']], facts['revocation_sha256'],
                     _now(self._clock)) == rev,
                     'QUALITYFLOW_REVOCATION_CHANGED', 'unavailable')
                _grant(verify_revocation, {**fresh, 'revocation': rev,
                                            'original_source_event':
                                                event_objs[facts['event_sha256']]},
                       'QUALITYFLOW_REVOCATION_VERIFICATION_REVOKED')
            if code_result is not None:
                s = source_set['CodeInsight']
                facts = {'purpose': 'READ_EXACT_SAVED_STATIC_CODE_INSIGHT',
                         'phase': 'FINALIZE', 'request_sha256': request_id,
                         'record_id': s['scope']['record_id'],
                         'source_id': s['source_id'],
                         'native_source_mode': s['scope']['native_source_mode']}
                _grant(authorize_code_insight, facts,
                       'QUALITYFLOW_CODE_INSIGHT_PERMISSION_REVOKED')
                raw = _read(read_code_insight, facts, MAX_CODE_BYTES,
                            'QUALITYFLOW_CODE_INSIGHT_CHANGED')
                need(hashlib.sha256(raw).hexdigest() == code_raw_sha and
                     _code_record(raw, s['scope']['record_id'],
                                  s['scope']['native_source_mode']) == code_result,
                     'QUALITYFLOW_CODE_INSIGHT_CHANGED', 'unavailable')
            for mode, data in source_results.items():
                again = self.quality_view.query(**data['params'], cursor=None)
                ec189._validate_quality_page(
                    again, revision=data['revision'], query=data['query_sha256'])
                need(canonical(again['entries']) == canonical(data['first']['entries']),
                     'QUALITYFLOW_QUALITY_SOURCE_CHANGED', 'unavailable')
            need(canonical({'sources': quality_sources, 'code_insight': code_insight,
                            'relations': relations, 'revocations': normalized_revocations,
                            'ack': acknowledge_historical_proposal}) == input_snapshot,
                 'QUALITYFLOW_INPUT_MUTATED_DURING_READ', 'unavailable')
            _now(self._clock)
            records.sort(key=lambda r: (r['occurred_at_utc_host_declared'],
                                        r['event_sha256']))
            revoked_items.sort(key=lambda r: (r['revoked_at_utc_host_declared'],
                                              r['revocation_sha256']))
            summary = []
            for mode in sorted(source_set):
                s = source_set[mode]
                data = source_results.get(mode)
                summary.append({
                    'source_mode': mode, 'source_id': s['source_id'],
                    'scope_sha256': s['scope_sha256'],
                    'captured_at_utc_caller_supplied': s['captured_at_utc'],
                    'quality_revision_sha256': data['revision'] if data else None,
                    'quality_evidence_count': len(data['entries']) if data else 0,
                    'code_insight_record_id': code_result['record_id'] if mode == 'CodeInsight' else None,
                    'code_insight_static_finding_count': code_result['finding_count']
                    if mode == 'CodeInsight' else None,
                    'historical_proposal_only': mode == 'ProposedPR',
                    'source_currentness_verified': False,
                    'test_execution_verified': False,
                })
            revision = digest(FLOW_DOMAIN, {
                'request_sha256': request_id, 'sources': summary,
                'relations': records, 'revocations': revoked_items})
            return {
                'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                'reason_code': 'QUALITYFLOW_SOURCE_SCOPED_CONTEXT_ONLY',
                'flow_revision_sha256': revision,
                'sources': summary, 'relations': records,
                'revocations': revoked_items,
                'counts': {
                    'source_modes': len(summary), 'relations': len(records),
                    'context_only_relations': sum(r['status'] == 'CONTEXT_ASSOCIATION_ONLY'
                                                  for r in records),
                    'revoked_relations': sum(r['status'] == 'REVOKED_NOT_ACTIVE'
                                             for r in records),
                    'contradicted_relations': sum(r['status'] == 'CONTRADICTED_NOT_ACTIVE'
                                                  for r in records),
                    'time_inconsistent_relations': sum(
                        r['status'] == 'TEMPORAL_CONTRADICTION_NOT_ACTIVE' for r in records),
                    'revocation_records': len(revoked_items),
                },
                'coverage': {
                    'all_caller_supplied_quality_receipts_scoped_and_requeried': True,
                    'code_insight_original_bytes_inspected_when_selected': code_result is not None,
                    'host_event_records_revalidated_at_finalization': True,
                    'source_event_host_authorization_is_git_proof': False,
                    'source_or_ci_currentness_independently_verified': False,
                    'historical_proposed_pr_auto_promoted_to_delivery': False,
                    'static_code_insight_promoted_to_executed_test': False,
                    'quality_or_finding_state_transferred_across_modes': False,
                    'rechecks_are_cross_system_atomic': False,
                    'full_provider_or_repository_coverage': False,
                },
                'effects': _effects(), 'trust_boundary': TRUST,
            }
        except FlowError as exc:
            return _denied(exc.reason, exc.status)
        except (qs.QualityShowError, ec189.LinkError, schema_v1.SchemaInputError) as exc:
            return _denied('QUALITYFLOW_UPSTREAM_SOURCE_OR_SCOPE_UNAVAILABLE', 'unavailable')
        except (KeyError, TypeError, ValueError, AttributeError, IndexError,
                OverflowError, RecursionError, UnicodeError, OSError, MemoryError):
            return _denied('QUALITYFLOW_UNTRUSTED_SOURCE_UNAVAILABLE', 'unavailable')
