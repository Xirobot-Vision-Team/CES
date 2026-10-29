#!/usr/bin/env python3
"""EC189: explicit, non-causal QualityShow <-> sealed FindingShow association.

Does not accept copied display receipts as authority. Calls the actual EC188
query, which checks bounded producer outputs and re-authorizes EACH receipt, and
EC179, which verifies the EC178 private HMAC ledger on EACH Finding query.

A host-approved bridge between an EC177 source binding and an EC188 scope is
*only an authorization to compare*: it does not prove identical source bytes,
CI provenance, repository currentness or the causal relevance of a failing job.
There is no cross-mode bridge (reserved for a later EC). All output is partial.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from typing import Any, Callable

import finding_show as finding
import quality_show as quality

SCHEMA = 'ces.quality_finding_link.v1'
DOMAIN_BINDING = b'CES-EC189-FINDING-BINDING-v1\0'
DOMAIN_BRIDGE = b'CES-EC189-QUALITY-FINDING-BRIDGE-v1\0'
DOMAIN_ASSOCIATION = b'CES-EC189-QUALITY-FINDING-ASSOCIATION-v1\0'
DOMAIN_REQUEST = b'CES-EC189-LINK-REQUEST-v1\0'
DOMAIN_NOTE_MAC = b'CES-EC189-PRIVATE-REPRODUCTION-NOTE-v1\0'
MAX_ASSOCIATIONS = 24
MAX_FINDINGS = 16
MAX_PAGES = 4  # 96 EC188 items, 25/page; no silent partial traversal.
MAX_REQUEST_BYTES = 3 * 1024 * 1024
MAX_NOTE_BYTES = 2048
SIGNALS = frozenset({'support', 'counter', 'context'})
RATIONALES = frozenset({'SHARED_HYPOTHESIS_UNVERIFIED',
                       'POSSIBLY_UNRELATED', 'UNDETERMINED'})
REPRO_STATES = frozenset({'NOT_ATTEMPTED', 'ATTEMPT_REPORTED_UNVERIFIED',
                          'REPRODUCED_REPORTED_UNVERIFIED',
                          'NOT_REPRODUCED_REPORTED_UNVERIFIED'})
TRUST = ('EC179_HMAC_LOCAL_FINDING_DECLARATION_AND_EC188_CALLER_SUPPLIED_CI_HOST_CLAIMS; '
         'HOST_BRIDGE_AUTHORISATION_IS_NOT_SOURCE_EQUIVALENCE_OR_CAUSAL_PROOF; '
         'NO_AUTOMATIC_DEFECT_CREATION_TEST_PASS_REVIEW_PROMOTION_OR_WRITE')


class LinkError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def require(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if not ok:
        raise LinkError(code, status)


def canonical(data: Any) -> bytes:
    # Reject NaN and non-JSON objects; no fallback conversion of bytes, keys,
    # dates, or caller-specific objects into an ambiguous source identity.
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def digest(domain: bytes, data: Any) -> str:
    return hashlib.sha256(domain + canonical(data)).hexdigest()


def _clock(clock: Callable[[], datetime] | None) -> datetime:
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    require(isinstance(now, datetime) and now.tzinfo is not None and
            now.utcoffset() == timedelta(0), 'QUALITYFINDING_UTC_CLOCK_REQUIRED', 'unavailable')
    return now.astimezone(timezone.utc)


def _grant(callback: Any, facts: dict[str, Any], code: str) -> None:
    require(callable(callback), code, 'unavailable')
    try:
        allowed = callback(copy.deepcopy(facts))
    except Exception as exc:
        raise LinkError(code, 'unavailable') from exc
    require(allowed is True, code, 'unavailable')


def _effects() -> dict[str, bool]:
    return {
        'read_only': True, 'finding_created_or_modified': False,
        'finding_review_state_changed': False, 'ces_store_written': False,
        'business_repository_written': False, 'git_or_issue_written': False,
        'provider_requests_or_tests_executed_by_linker': False,
        'model_or_source_text_disclosed': False,
        'defect_confirmed': False, 'test_or_quality_pass_verified': False,
        'cross_source_equivalence_proven': False,
    }


def _refused(code: str, status: str) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status, 'exit_code': 4 if status == 'invalid_input' else 5,
        'reason_code': code, 'scope': None, 'quality_revision_sha256': None,
        'finding_revision_sha256': None, 'link_revision_sha256': None,
        'counts': None, 'links': [], 'coverage': None,
        'effects': _effects(), 'trust_boundary': TRUST,
    }


def _parse_associations(raw: Any, *, now: datetime) -> tuple[list[dict[str, Any]], set[str]]:
    require(type(raw) is list and 1 <= len(raw) <= MAX_ASSOCIATIONS,
            'QUALITYFINDING_ASSOCIATION_LIMIT_INVALID')
    seen: set[tuple[str, str]] = set()
    finding_ids: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for row in raw:
        require(type(row) is dict and set(row) == {
            'finding_id', 'quality_evidence_id', 'direction', 'rationale', 'reproduction'},
            'QUALITYFINDING_ASSOCIATION_EXACT_FIELDS_REQUIRED')
        f_id, q_id = row['finding_id'], row['quality_evidence_id']
        require(type(f_id) is str and quality.HEX64.fullmatch(f_id) is not None and
                type(q_id) is str and quality.HEX64.fullmatch(q_id) is not None,
                'QUALITYFINDING_EXACT_DIGEST_IDS_REQUIRED')
        require(type(row['direction']) is str and row['direction'] in SIGNALS and
                type(row['rationale']) is str and row['rationale'] in RATIONALES,
                'QUALITYFINDING_DIRECTION_OR_RATIONALE_INVALID')
        require((f_id, q_id) not in seen,
                'QUALITYFINDING_DUPLICATE_PAIR_FORBIDDEN')
        seen.add((f_id, q_id))
        finding_ids.add(f_id)
        reproduction = row['reproduction']
        require(type(reproduction) is dict and set(reproduction) == {
            'state', 'statement', 'reported_at_utc'},
            'QUALITYFINDING_REPRODUCTION_EXACT_FIELDS_REQUIRED')
        state, text, at = reproduction['state'], reproduction['statement'], reproduction['reported_at_utc']
        require(type(state) is str and state in REPRO_STATES,
                'QUALITYFINDING_REPRODUCTION_STATE_INVALID')
        if state == 'NOT_ATTEMPTED':
            require(text is None and at is None,
                    'QUALITYFINDING_UNATTEMPTED_REPRODUCTION_MUST_BE_EMPTY')
        else:
            require(type(text) is str and 1 <= len(text.encode('utf-8')) <= MAX_NOTE_BYTES and
                    not any(ord(c) < 32 and c not in '\n\t' for c in text),
                    'QUALITYFINDING_REPRODUCTION_STATEMENT_INVALID')
            recorded = quality._timestamp(at)
            require(recorded <= now + timedelta(seconds=quality.MAX_SKEW_SECONDS),
                    'QUALITYFINDING_REPRODUCTION_TIMESTAMP_IN_FUTURE', 'unavailable')
        normalized.append(copy.deepcopy(row))
    require(len(finding_ids) <= MAX_FINDINGS, 'QUALITYFINDING_DISTINCT_FINDINGS_LIMIT')
    return normalized, finding_ids


def _quality_claim(row: dict[str, Any]) -> tuple[str, str]:
    """Return only typed, limited evidence direction; do not infer causation.

    Provider job/run conclusion does not necessarily describe a test suite.
    Mixed provider statuses and host exit codes are deliberately neutral.
    """
    category, c, info = row['kind'], row['classification'], row['summary']
    if category in ('ci_evidence', 'observation') and c == 'fail':
        return 'FAILURE_CLAIM', 'PROVIDER_CONTENT_NOT_INDEPENDENTLY_REPRODUCED'
    if category in ('ci_evidence', 'observation') and c == 'pass':
        return 'PASS_CLAIM', 'PROVIDER_CONTENT_NOT_INDEPENDENTLY_REPRODUCED'
    if category == 'ci_metadata':
        job = info.get('provider_job_conclusion')
        run = info.get('provider_run_conclusion')
        failures = {'failure', 'failed', 'timed_out'}
        if job in failures and run in failures | {'unknown'}:
            return 'FAILURE_CLAIM', 'PROVIDER_JOB_METADATA_ONLY_NOT_TEST_PROOF'
        if job == 'success' and run in ('success', 'unknown'):
            return 'PASS_CLAIM', 'PROVIDER_JOB_METADATA_ONLY_NOT_TEST_PROOF'
        return 'UNDETERMINED', 'PROVIDER_RUN_JOB_MIXED_OR_INCOMPLETE'
    if category == 'run_session':
        return 'UNDETERMINED', 'HOST_EXIT_OR_INTERRUPTION_NOT_ATTESTED_TEST_OUTCOME'
    return 'UNDETERMINED', 'CONFIG_BINDING_OR_PREFLIGHT_NOT_TEST_OUTCOME'


def _validate_quality_page(result: Any, *, revision: str | None,
                           query: str | None) -> tuple[str, str]:
    require(type(result) is dict and result.get('schema') == quality.SCHEMA and
            result.get('status') == 'partial' and result.get('exit_code') == 2,
            'QUALITYFINDING_QUALITYSHOW_REQUERY_REFUSED', 'unavailable')
    require(type(result.get('entries')) is list and
            type(result.get('revision_sha256')) is str and
            type(result.get('query_sha256')) is str and
            (revision is None or result['revision_sha256'] == revision) and
            (query is None or result['query_sha256'] == query),
            'QUALITYFINDING_QUALITY_SOURCE_CHANGED_BETWEEN_PAGES', 'unavailable')
    require(result['coverage']['quality_pass_independently_verified'] is False and
            result['effects']['quality_pass_verified'] is False,
            'QUALITYFINDING_UNSUPPORTED_UPSTREAM_PROOF_CLAIM', 'unavailable')
    return result['revision_sha256'], result['query_sha256']


def _validate_finding_result(result: Any, *, revision: str | None,
                             expected_id: str) -> str:
    require(type(result) is dict and result.get('schema') == finding.SCHEMA and
            result.get('status') == 'partial' and result.get('exit_code') == 2,
            'QUALITYFINDING_FINDINGSHOW_REQUERY_REFUSED', 'unavailable')
    require(type(result.get('revision_sha256')) is str and
            (revision is None or result['revision_sha256'] == revision) and
            result.get('matched_count') == 1 and
            result.get('returned_count') == 1 and len(result.get('findings', [])) == 1,
            'QUALITYFINDING_FINDING_MISSING_OR_LEDGER_CHANGED', 'unavailable')
    item = result['findings'][0]
    require(item['finding_id'] == expected_id and
            item['actual_test_or_ci_verified'] is False and
            item['semantic_defect_verified'] is False and
            item['expired_at_query_time'] is False and
            item['assessment_state'] in ('UNVERIFIED', 'REVIEWED', 'REJECTED', 'INCONCLUSIVE') and
            'digest_details' in item and
            len(item['digest_details']['counter_evidence_sha256']) ==
            item['counter_evidence_count'],
            'QUALITYFINDING_FINDING_NOT_ACTIVE_OR_FALSE_VERIFICATION', 'unavailable')
    return result['revision_sha256']


class QualityFindingLinker:
    """Link on each call, without modifying either existing store or receipt.

    Both upstream viewers must be genuinely configured by the host. EC188's
    source selection is NOT interchangeable with EC177's source binding; a
    distinct host bridge callback must authorize their comparison each time.
    Separate per-pair authorization cannot be inherited from either viewer.
    """

    def __init__(self, quality_view: quality.QualityShow,
                 finding_view: finding.FindingShower, *,
                 note_reference_key: bytes,
                 clock: Callable[[], datetime] | None = None) -> None:
        if (not isinstance(quality_view, quality.QualityShow) or
                not isinstance(finding_view, finding.FindingShower)):
            raise ValueError('Real EC188/EC179 viewers are required')
        if type(note_reference_key) is not bytes or len(note_reference_key) < 32:
            raise ValueError('Separate host-controlled >=32-byte private note HMAC key required')
        if clock is not None and not callable(clock):
            raise ValueError('Clock must be callable')
        self.quality_view = quality_view
        self.finding_view = finding_view
        self._note_key = note_reference_key
        self._clock = clock

    def link(self, *, source_scope: dict[str, Any], evidence: list[dict[str, Any]],
             finding_source_binding: dict[str, Any], expected_finding_store_pin: str,
             associations: list[dict[str, Any]], allow_link: bool = False,
             allow_quality_query: bool = False, allow_quality_evidence_read: bool = False,
             authorize_quality_scope: Callable[[dict[str, Any]], bool] | None = None,
             authorize_quality_evidence: Callable[[dict[str, Any]], bool] | None = None,
             allow_finding_store_read: bool = False, allow_finding_query: bool = False,
             allow_finding_digest_details: bool = False,
             authorize_source_bridge: Callable[[dict[str, Any]], bool] | None = None,
             authorize_association: Callable[[dict[str, Any]], bool] | None = None,
             acknowledge_historical_proposal: bool = False) -> dict[str, Any]:
        try:
            require(allow_link is True and allow_quality_query is True and
                    allow_quality_evidence_read is True and
                    allow_finding_store_read is True and allow_finding_query is True and
                    allow_finding_digest_details is True,
                    'QUALITYFINDING_SIX_SEPARATE_OPT_INS_REQUIRED', 'unavailable')
            require(type(acknowledge_historical_proposal) is bool,
                    'QUALITYFINDING_HISTORICAL_ACK_TYPE_INVALID')
            scope = quality._scope(source_scope)
            require(type(finding_source_binding) is dict and
                    finding_source_binding.get('source_mode') == scope['source_mode'],
                    'QUALITYFINDING_CROSS_MODE_LINK_FORBIDDEN', 'unavailable')
            binding = finding._binding(finding_source_binding, scope['source_mode'])
            if scope['source_mode'] == 'ProposedPR':
                require(acknowledge_historical_proposal,
                        'QUALITYFINDING_HISTORICAL_PROPOSAL_ACK_REQUIRED', 'unavailable')
            require(type(expected_finding_store_pin) is str and
                    quality.HEX64.fullmatch(expected_finding_store_pin) is not None,
                    'QUALITYFINDING_EXACT_STORE_PIN_REQUIRED')
            now = _clock(self._clock)
            rows, ids = _parse_associations(associations, now=now)
            before = canonical({'scope': source_scope, 'binding': finding_source_binding,
                                'evidence': evidence, 'associations': associations,
                                'store_pin': expected_finding_store_pin})
            require(len(before) <= MAX_REQUEST_BYTES, 'QUALITYFINDING_INPUT_TOO_LARGE')
            scope_sha = quality.digest(quality.DOMAIN_SCOPE, scope)
            binding_sha = digest(DOMAIN_BINDING, binding)
            bridge_sha = digest(DOMAIN_BRIDGE, {
                'quality_scope_sha256': scope_sha, 'finding_binding_sha256': binding_sha,
                'source_mode': scope['source_mode']})
            request_sha = digest(DOMAIN_REQUEST, {
                'bridge_sha256': bridge_sha,
                'store_pin_sha256': digest(DOMAIN_BINDING, expected_finding_store_pin),
                'associations': rows,
            })
            bridge_facts = {'purpose': 'AUTHORIZE_COMPARISON_NOT_ATTEST_SOURCE_EQUIVALENCE',
                            'quality_source_scope': scope,
                            'finding_source_binding': binding,
                            'bridge_sha256': bridge_sha, 'request_sha256': request_sha}
            _grant(authorize_source_bridge, {**bridge_facts, 'phase': 'BEFORE_READ'},
                   'QUALITYFINDING_HOST_SOURCE_BRIDGE_NOT_AUTHORIZED')
            pair_facts = []
            for row in rows:
                facts = {'purpose': 'READ_ONLY_QUALITY_FINDING_PAIR',
                         'request_sha256': request_sha, 'bridge_sha256': bridge_sha,
                         'finding_id': row['finding_id'],
                         'quality_evidence_id': row['quality_evidence_id'],
                         'direction': row['direction'], 'rationale': row['rationale'],
                         'reproduction_reference_sha256': digest(DOMAIN_REQUEST, row['reproduction'])}
                _grant(authorize_association, {**facts, 'phase': 'BEFORE_READ'},
                       'QUALITYFINDING_PAIR_NOT_AUTHORIZED')
                pair_facts.append(facts)

            # Re-open actual EC188 query over the entire supplied evidence set.
            # Per-page reauthorization validates even records excluded by a future
            # link selection; the HMAC cursor keeps all pages on one revision.
            quality_args = {
                'source_scope': source_scope, 'evidence': evidence,
                'allow_query': allow_quality_query,
                'allow_evidence_read': allow_quality_evidence_read,
                'authorize_scope': authorize_quality_scope,
                'authorize_evidence': authorize_quality_evidence,
                'page_size': quality.MAX_PAGE,
                'include_numeric_metrics': False,
                'acknowledge_historical_proposal': acknowledge_historical_proposal,
            }
            quality_entries: dict[str, dict[str, Any]] = {}
            q_revision = q_query = None
            q_first = None
            cursor = None
            for i in range(MAX_PAGES):
                page = self.quality_view.query(**quality_args, cursor=cursor)
                q_revision, q_query = _validate_quality_page(
                    page, revision=q_revision, query=q_query)
                if i == 0:
                    q_first = page
                for item in page['entries']:
                    evidence_id = item['evidence_id']
                    require(evidence_id not in quality_entries and
                            type(item['summary']) is dict and
                            item['summary']['quality_pass_verified'] is False,
                            'QUALITYFINDING_QUALITY_PAGE_DUPLICATE_OR_UNSAFE', 'unavailable')
                    quality_entries[evidence_id] = item
                cursor = page['next_cursor']
                if cursor is None:
                    break
            require(cursor is None and q_first is not None and
                    len(quality_entries) == q_first['counts']['matched'],
                    'QUALITYFINDING_QUALITY_PAGINATION_NOT_COMPLETE', 'unavailable')

            # FindingShow queries 1 exact HMAC-ledger ID at a time, never a
            # caller's forged row or projected assessment state. The store
            # revision must remain identical across all requested ID reads.
            finding_args = {
                'expected_finding_store_pin': expected_finding_store_pin,
                'authorize_store_read': allow_finding_store_read,
                'authorize_query': allow_finding_query,
                'authorized_source_binding': finding_source_binding,
                'query_content_for': scope['source_mode'], 'page_size': 1,
                'include_digest_details': True,
                'authorize_digest_details': allow_finding_digest_details,
                'include_expired': False,
                'acknowledge_historical_proposal_metadata': acknowledge_historical_proposal,
            }
            findings: dict[str, dict[str, Any]] = {}
            f_revision = None
            for fid in sorted(ids):
                returned = self.finding_view.query(**finding_args,
                                                   filters={'finding_id': fid})
                f_revision = _validate_finding_result(returned, revision=f_revision,
                                                      expected_id=fid)
                findings[fid] = returned['findings'][0]

            linked: list[dict[str, Any]] = []
            for row in rows:
                evidence_id, fid = row['quality_evidence_id'], row['finding_id']
                require(evidence_id in quality_entries,
                        'QUALITYFINDING_SELECTED_EVIDENCE_NOT_IN_AUTHORIZED_BATCH', 'unavailable')
                ev = quality_entries[evidence_id]
                f = findings[fid]
                signal, signal_boundary = _quality_claim(ev)
                selected_direction = row['direction']
                require(selected_direction == 'context' or
                        (selected_direction == 'support' and signal == 'FAILURE_CLAIM') or
                        (selected_direction == 'counter' and signal == 'PASS_CLAIM'),
                        'QUALITYFINDING_DIRECTION_NOT_SUPPORTED_BY_EVIDENCE_CLAIM')
                require(not (selected_direction == 'support' and
                             f['assessment_state'] == 'REJECTED'),
                        'QUALITYFINDING_REJECTED_FINDING_CANNOT_GAIN_SUPPORT')
                original_rep = row['reproduction']
                statement = original_rep['statement']
                # Keyed reference instead of SHA of a short/common or sensitive
                # reproduction explanation; NEVER return plaintext steps/paths.
                note_mac = (hmac.new(self._note_key, DOMAIN_NOTE_MAC + canonical({
                    'finding_id': fid, 'quality_evidence_id': evidence_id,
                    'state': original_rep['state'], 'text': statement,
                    'reported_at_utc': original_rep['reported_at_utc']}),
                    hashlib.sha256).hexdigest() if statement is not None else None)
                annotation_shas = list(f['digest_details']['counter_evidence_sha256'])
                statement_state = 'NO_REPRODUCTION_ATTEMPT_REPORTED' if statement is None else \
                                  'CALLER_REPRODUCTION_DECLARATION_NOT_INDEPENDENTLY_VERIFIED'
                detail = {
                    'finding': {
                        'finding_id': fid, 'assessment_state': f['assessment_state'],
                        'review_is_local_key_holder_declaration_only': True,
                        'severity_claim': f['severity_claim'],
                        'confidence_claim': f['confidence_claim'],
                        'positive_anchor_count': f['positive_anchor_count'],
                        'counter_evidence_count': f['counter_evidence_count'],
                        'counter_evidence_annotation_sha256': annotation_shas,
                        'coverage_complete_for_selected_source':
                            f['coverage_complete_for_selected_source'],
                        'coverage_missing_requirements_count':
                            f['coverage_missing_requirements_count'],
                        'historical_proposal_only': f['historical_proposal_only'],
                        'path_index_state': f['path_index_state'],
                        'saved_at_utc': f['saved_at_utc'],
                        'expires_at_utc': f['expires_at_utc'],
                    },
                    'quality': {
                        'evidence_id': evidence_id, 'kind': ev['kind'],
                        'classification': ev['classification'],
                        'declared_claim_signal': signal,
                        'signal_boundary': signal_boundary,
                        'binding_strength': ev['binding_strength'],
                        'recorded_at_utc_caller_supplied': ev['recorded_at_utc'],
                        'incompleteness': sorted(set(ev['incompleteness'])),
                    },
                    'relationship': {
                        'direction_is_caller_hypothesis': selected_direction,
                        'rationale_is_caller_hypothesis': row['rationale'],
                        'assessment': ('POTENTIAL_SUPPORT_NEVER_DEFECT_PROOF'
                                       if selected_direction == 'support' else
                                       'POTENTIAL_COUNTEREVIDENCE_NEVER_EXONERATION'
                                       if selected_direction == 'counter' else
                                       'CONTEXT_ONLY_NO_CAUSAL_FINDING'),
                        'underlying_causal_link_proven': False,
                    },
                    'reproduction': {
                        'state': original_rep['state'],
                        'reported_at_utc_caller_supplied': original_rep['reported_at_utc'],
                        'private_statement_reference_mac_sha256': note_mac,
                        'statement_state': statement_state,
                        'reproduced_or_disproved_by_ces': False,
                    },
                    'declared_defect_confirmed': False,
                    'actual_test_or_ci_execution_independently_verified': False,
                }
                detail['link_id'] = digest(DOMAIN_ASSOCIATION, detail)
                linked.append(detail)

            # Deterministic output independent of operator selection order.
            linked.sort(key=lambda e: (e['finding']['finding_id'],
                                       e['quality']['evidence_id']))
            # Re-read both sources after both authorizations and complete
            # traversal; not a cross-system atomic transaction or a proof of
            # externally immutable snapshots. Check no data/grants changed.
            _grant(authorize_source_bridge, {**bridge_facts, 'phase': 'FINALIZE'},
                   'QUALITYFINDING_SOURCE_BRIDGE_REVOKED')
            for facts in pair_facts:
                _grant(authorize_association, {**facts, 'phase': 'FINALIZE'},
                       'QUALITYFINDING_PAIR_PERMISSION_REVOKED')
            q_check = self.quality_view.query(**quality_args)
            _validate_quality_page(q_check, revision=q_revision, query=q_query)
            require(canonical(q_check['entries']) == canonical(q_first['entries']),
                    'QUALITYFINDING_QUALITY_FIRST_PAGE_CHANGED', 'unavailable')
            first_fid = sorted(ids)[0]
            f_check = self.finding_view.query(**finding_args,
                                              filters={'finding_id': first_fid})
            _validate_finding_result(f_check, revision=f_revision,
                                     expected_id=first_fid)
            require(canonical(f_check['findings'][0]) == canonical(findings[first_fid]) and
                    canonical({'scope': source_scope, 'binding': finding_source_binding,
                               'evidence': evidence, 'associations': associations,
                               'store_pin': expected_finding_store_pin}) == before,
                    'QUALITYFINDING_SOURCE_INPUT_OR_FINDING_CHANGED_DURING_QUERY', 'unavailable')
            _clock(self._clock)  # explicit host UTC requirement on finalization
            revision = digest(DOMAIN_ASSOCIATION, {
                'bridge_sha256': bridge_sha, 'quality_revision_sha256': q_revision,
                'finding_revision_sha256': f_revision,
                'link_ids': [e['link_id'] for e in linked]})
            return {
                'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                'reason_code': 'QUALITYFINDING_READ_ONLY_CONTEXT_NOT_CONFIRMED_DEFECT',
                'scope': {
                    'source_mode': scope['source_mode'],
                    'quality_scope_sha256': scope_sha,
                    'finding_binding_sha256': binding_sha,
                    'bridge_sha256': bridge_sha,
                    'bridge_authorized_by_host_not_source_equivalence_proof': True,
                    'historical_proposal_only': scope['source_mode'] == 'ProposedPR',
                },
                'quality_revision_sha256': q_revision,
                'finding_revision_sha256': f_revision,
                'link_revision_sha256': revision,
                'counts': {
                    'links': len(linked), 'distinct_findings': len(ids),
                    'scoped_quality_receipts_read': len(quality_entries),
                    'possible_support_claim_links': sum(
                        e['relationship']['direction_is_caller_hypothesis'] == 'support'
                        for e in linked),
                    'possible_counterevidence_claim_links': sum(
                        e['relationship']['direction_is_caller_hypothesis'] == 'counter'
                        for e in linked),
                    'context_only_links': sum(
                        e['relationship']['direction_is_caller_hypothesis'] == 'context'
                        for e in linked),
                },
                'links': linked,
                'coverage': {
                    'selected_quality_receipts_are_full_provider_history': False,
                    'complete_repository_or_test_suite_coverage': False,
                    'findings_all_exist_in_real_exact_source_hmac_store': True,
                    'independent_same_source_content_attestation': False,
                    'read_consistency_is_cross_system_atomic': False,
                    'ci_failure_is_defect_proof': False,
                    'ci_pass_is_defect_disproof': False,
                    'reproduction_statement_independently_verified': False,
                    'source_currentness_verified': False,
                    'unauthorized_cross_mode_comparison': False,
                },
                'effects': _effects(), 'trust_boundary': TRUST,
            }
        except LinkError as exc:
            return _refused(exc.code, exc.status)
        except (quality.QualityShowError, finding.FindingShowError) as exc:
            return _refused('QUALITYFINDING_UPSTREAM_SCOPE_OR_REPRODUCTION_INVALID',
                            exc.status if exc.status in ('invalid_input', 'unavailable')
                            else 'unavailable')
        except (ValueError, TypeError, KeyError, IndexError, AttributeError,
                RecursionError, OverflowError, MemoryError, UnicodeError, OSError):
            return _refused('QUALITYFINDING_UNTRUSTED_SOURCE_OR_LEDGER_UNAVAILABLE',
                            'unavailable')
