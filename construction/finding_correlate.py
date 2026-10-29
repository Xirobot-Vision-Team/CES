#!/usr/bin/env python3
"""EC180: permissioned, bounded, read-only correlation over real EC178 records.

This is *not* deduplication of real defects. Local exact identity identifies a
sealed declaration only. Evidence overlap yields a candidate, never a repair,
CI result, current Git state, or verified semantic equivalence.

Optional native CodeInsight v1 bytes are independently hash/schema checked via
EC158, but their origin and current repository state are NOT authenticated.
No native CodeShow or CI adapter exists in this standalone implementation.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta
import hashlib
import hmac
from itertools import combinations
import re
from typing import Any, Callable

import finding_schema as fs
import finding_show as show
import finding_save as save
import handoff_lifecycle as lc
import schema_compat as compat
import task_staging as st

SCHEMA = 'ces.finding_correlation_result.v1'
CURSOR_SCHEMA = 'ces.finding_correlation_cursor.v1'
DOMAIN_QUERY = b'CES-EC180-CORRELATION-QUERY-v1\x00'
DOMAIN_GRAPH = b'CES-EC180-CORRELATION-GRAPH-v1\x00'
DOMAIN_NODE = b'CES-EC180-CORRELATION-NODE-v1\x00'
DOMAIN_CURSOR = b'CES-EC180-CORRELATION-CURSOR-HMAC-v1\x00'
MAX_SCOPES = 4
MAX_CODEINSIGHT_RECORDS = 4
MAX_NODES = 64
MAX_EDGES = MAX_NODES * (MAX_NODES - 1) // 2
MAX_PAGE = 25
MAX_CURSOR_SECONDS = 180
MAX_CURSOR_BYTES = 4096
MAX_RESPONSE_BYTES = 160 * 1024
CI_MODES = {'working_tree_diff': 'WorkingTree',
            'delivered_target_diff': 'DeliveredTarget'}
STATES = frozenset({'EQUIVALENT_DECLARATION', 'CANDIDATE_SIMILARITY',
                    'UNKNOWN', 'INELIGIBLE'})
TRUST = ('LOCAL_HMAC_FINDING_DECLARATIONS_AND_OPTIONAL_UNAUTHENTICATED_'
         'OFFLINE_CODEINSIGHT_BYTES_NOT_SAME_DEFECT_FIX_CI_GIT_OR_HUMAN_PROOF')
SCOPE_FIELDS = frozenset({
    'authorized_source_binding', 'query_content_for',
    'authorize_store_read', 'authorize_query', 'authorize_scope_correlation',
    'authorize_digest_details', 'acknowledge_historical_proposal_metadata',
})
SCOPE_OPTIONAL_FIELDS = frozenset({'finding_id_allowlist'})
CI_FIELDS = frozenset({'record_id', 'raw_bytes'})
TOKEN_RE = re.compile(r'[A-Za-z0-9_-]{16,3900}\.[0-9a-f]{64}\Z')


class CorrelationError(save.FindingSaveError):
    pass


def _require(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if not ok:
        raise CorrelationError(code, status)


def _sha(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + st._canonical(value)).hexdigest()


def _effects() -> dict[str, bool]:
    return {
        'ces_records_written': False, 'business_repository_written': False,
        'git_or_issue_written': False, 'source_code_or_tests_executed': False,
        'network_or_provider_accessed': False, 'raw_text_released': False,
        'defect_or_duplicate_semantically_verified': False, 'fix_verified': False,
        'current_git_verified': False, 'ci_or_actual_test_verified': False,
        'human_identity_authenticated': False,
    }


def _refused(code: str, status: str) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': 4 if status == 'invalid_input' else 5,
        'reason_code': code, 'store_revision_sha256': None,
        'query_sha256': None, 'graph_sha256': None, 'nodes': [], 'edges': [],
        'node_count': 0, 'candidate_edge_count': 0, 'pair_counts': None,
        'edge_count': 0, 'returned_count': 0, 'next_cursor': None,
        'cursor_expires_at_utc': None, 'scope_coverage': [],
        'codeinsight_coverage': None, 'effects': _effects(),
        'trust_boundary': TRUST,
    }


def _scope(raw: Any) -> tuple[dict[str, Any], str, bool, list[str] | None]:
    _require(type(raw) is dict and SCOPE_FIELDS.issubset(set(raw)) and
             set(raw).issubset(SCOPE_FIELDS | SCOPE_OPTIONAL_FIELDS),
             'FINDINGCORRELATE_EXACT_SCOPE_FIELDS_REQUIRED')
    _require(all(raw[k] is True for k in (
        'authorize_store_read', 'authorize_query',
        'authorize_scope_correlation', 'authorize_digest_details')),
        'FINDINGCORRELATE_EACH_SCOPE_NEEDS_FRESH_INDEPENDENT_GRANTS')
    _require(type(raw['acknowledge_historical_proposal_metadata']) is bool,
             'FINDINGCORRELATE_HISTORICAL_FLAG_NOT_BOOLEAN')
    mode = raw['query_content_for']
    _require(type(mode) is str and mode in lc.SOURCE_MODES,
             'FINDINGCORRELATE_SOURCE_MODE_UNKNOWN')
    binding = show._binding(raw['authorized_source_binding'], mode)
    _require(mode != 'ProposedPR' or raw['acknowledge_historical_proposal_metadata'],
             'FINDINGCORRELATE_HISTORICAL_REQUIRES_SEPARATE_ACK')
    allowed = raw.get('finding_id_allowlist')
    if allowed is not None:
        _require(type(allowed) is list and 1 <= len(allowed) <= MAX_NODES and
                 all(save._digest(v) for v in allowed) and
                 allowed == sorted(set(allowed)),
                 'FINDINGCORRELATE_FINDING_ALLOWLIST_MUST_BE_SORTED_UNIQUE_DIGESTS')
    # Detach from caller-mutable dictionaries before querying the private store.
    safe_binding = st._strict_stored(st._canonical(binding) + b'\n', 4096)
    return safe_binding, mode, raw['acknowledge_historical_proposal_metadata'], (
        list(allowed) if allowed is not None else None)


def _ci_records(raw_records: Any, *, allow: bool,
                repo_root: str) -> tuple[list[dict[str, Any]], list[str]]:
    if raw_records is None:
        return [], []
    _require(type(raw_records) is list and 1 <= len(raw_records) <= MAX_CODEINSIGHT_RECORDS,
             'FINDINGCORRELATE_CODEINSIGHT_LIST_BOUND')
    _require(allow is True, 'FINDINGCORRELATE_CODEINSIGHT_NEEDS_SEPARATE_GRANTS')
    records: list[dict[str, Any]] = []
    names: set[str] = set()
    for entry in raw_records:
        _require(type(entry) is dict and set(entry) == CI_FIELDS,
                 'FINDINGCORRELATE_CODEINSIGHT_ENTRY_FIELDS')
        rid, raw = entry['record_id'], entry['raw_bytes']
        _require(type(rid) is str and compat.RECORD_ID.fullmatch(rid) is not None and
                 type(raw) is bytes and len(raw) <= compat.LIMITS['code_insight_saved'],
                 'FINDINGCORRELATE_CODEINSIGHT_ID_OR_BYTE_BOUND')
        _require(rid not in names, 'FINDINGCORRELATE_DUPLICATE_CODEINSIGHT_RECORD')
        names.add(rid)
        try:
            report = compat.inspect_bytes(raw, kind='code_insight_saved', record_id=rid)
        except (compat.SchemaInputError, UnicodeError, ValueError, OverflowError) as exc:
            raise CorrelationError('FINDINGCORRELATE_CODEINSIGHT_UNDECODABLE') from exc
        _require(report['compatible_for_offline_read'] is True and
                 report['identity'].get('record_id_bound') is True and
                 report['content_sha256'] == rid[3:],
                 'FINDINGCORRELATE_CODEINSIGHT_OFFLINE_SCHEMA_OR_HASH_INVALID')
        doc = compat.decode_one(raw)
        # Exact equality intentionally avoids inventing cross-OS root aliases.
        # A matching literal source_root is a claim in the bytes, NOT authentication.
        _require(doc['source_root'] == repo_root and doc['source_mode'] in CI_MODES,
                 'FINDINGCORRELATE_CODEINSIGHT_ROOT_OR_MODE_NOT_EXACTLY_AUTHORIZED')
        records.append(doc | {'_record_id': rid})
    return records, sorted(names)


def _paths(node: dict[str, Any]) -> set[str]:
    return {x[0] for x in node['anchors'] if x[0] is not None}


def _quotes(node: dict[str, Any]) -> set[str]:
    return {x[1] for x in node['anchors'] if x[1] is not None}


def _paired(node: dict[str, Any]) -> set[tuple[str, str]]:
    return {(p, q) for p, q, _ in node['anchors'] if p is not None and q is not None}


def _compare(a: dict[str, Any], b: dict[str, Any], *, allow_path: bool) -> dict[str, Any]:
    # Match facts are about SHA declarations only; no source or model text read.
    same_finding = (a['kind'] == b['kind'] == 'FINDING_HMAC' and
                    a['finding_id'] == b['finding_id'] and
                    a['source_binding'] == b['source_binding'])
    exact_claim = (a['kind'] == b['kind'] == 'FINDING_HMAC' and
                   a['source_binding'] == b['source_binding'] and
                   a['original_sha256'] == b['original_sha256'] and
                   a['anchors'] == b['anchors'] and bool(a['anchors']))
    identical_anchor = (a['kind'] == b['kind'] == 'FINDING_HMAC' and
                        bool({x[2] for x in a['anchors'] if x[2]} &
                             {x[2] for x in b['anchors'] if x[2]}))
    quote_overlap = bool(_quotes(a) & _quotes(b))
    path_overlap = allow_path and bool(_paths(a) & _paths(b))
    paired_overlap = allow_path and bool(_paired(a) & _paired(b))
    signals = []
    if same_finding:
        signals.append('SAME_EC177_LOCAL_ID')
    if exact_claim:
        signals.append('SAME_ASSERTION_AND_ANCHOR_DIGESTS_IN_ONE_SOURCE')
    if identical_anchor:
        signals.append('SHARED_SEALED_ANCHOR_DIGEST')
    if paired_overlap:
        signals.append('SHARED_PATH_AND_QUOTE_DIGEST_SAME_ANCHOR')
    elif path_overlap:
        signals.append('SHARED_PATH_DIGEST_ONLY')
    if quote_overlap:
        signals.append('SHARED_QUOTE_DIGEST')
    ineligible = []
    if a['expired'] or b['expired']:
        ineligible.append('EXPIRED_LOCAL_DECLARATION')
    if a['assessment_state'] == 'REJECTED' or b['assessment_state'] == 'REJECTED':
        ineligible.append('REJECTED_LOCAL_CLAIM')
    if a['source_mode'] != b['source_mode']:
        ineligible.append('DIFFERENT_SOURCE_MODE_NO_CROSS_REVISION_WITNESS')
    if ((a['historical'] or b['historical']) and
        a['source_binding'] != b['source_binding']):
        ineligible.append('HISTORICAL_PROPOSAL_NOT_CURRENT_DELIVERED_WITNESS')
    # Hash-bound old CodeInsight bytes are not a verified current source or CI.
    if ineligible:
        state, basis = 'INELIGIBLE', ineligible[0]
    elif same_finding:
        state, basis = 'EQUIVALENT_DECLARATION', 'SAME_LOCALLY_PINNED_FINDING_ID_NOT_SAME_DEFECT'
    elif exact_claim:
        state, basis = 'EQUIVALENT_DECLARATION', 'SAME_LOCAL_ASSERTION_AND_ANCHORS_NOT_SAME_DEFECT'
    elif identical_anchor or paired_overlap:
        state, basis = 'CANDIDATE_SIMILARITY', 'MULTIPLE_LOCAL_EVIDENCE_SIGNALS_ONLY'
    else:
        state, basis = 'UNKNOWN', ('WEAK_SINGLE_SIGNAL_ONLY' if signals else
                                   'NO_COMPARABLE_POSITIVE_EVIDENCE_NOT_DISJOINTNESS')
    caution = []
    if a['kind'] == 'CODEINSIGHT_V1_OFFLINE' or b['kind'] == 'CODEINSIGHT_V1_OFFLINE':
        caution.append('CODEINSIGHT_BYTES_HASHED_NOT_NATIVE_SOURCE_AUTHENTICATED')
    if (a['path_state'] != 'COMPLETE' or b['path_state'] != 'COMPLETE'):
        caution.append('PATH_INDEX_UNAVAILABLE_OR_PARTIAL_CANNOT_PROVE_NEGATIVE')
    if (not a['coverage_complete'] or not b['coverage_complete']):
        caution.append('SELECTED_SOURCE_COVERAGE_INCOMPLETE_OR_UNVERIFIED')
    if a['counter_count'] or b['counter_count']:
        caution.append('COUNTER_EVIDENCE_PRESENT_NOT_SEMANTICALLY_RESOLVED')
    if (a['assessment_state'] != 'REVIEWED' or b['assessment_state'] != 'REVIEWED'):
        caution.append('SUBJECTIVE_REVIEW_NOT_BOTH_REVIEWED')
    return {
        'left': a['node_id'], 'right': b['node_id'],
        'relation_state': state, 'basis': basis,
        'signals': signals, 'cautions': caution,
        'same_real_defect_proven': False,
        'duplicate_bug_proven': False, 'fixed_or_regressed_proven': False,
        'actual_test_or_ci_proven': False,
    }


def _token(key: bytes, body: dict[str, Any]) -> str:
    payload = st._canonical(body)
    mac = hmac.new(key, DOMAIN_CURSOR + payload, hashlib.sha256).hexdigest()
    out = base64.urlsafe_b64encode(payload).rstrip(b'=').decode() + '.' + mac
    _require(len(out) <= MAX_CURSOR_BYTES, 'FINDINGCORRELATE_CURSOR_TOO_LARGE', 'unavailable')
    return out


def _cursor(key: bytes, value: str, now: datetime, *,
            query_sha256: str, revision: str, graph_sha256: str,
            edge_count: int) -> tuple[int, datetime, datetime]:
    _require(type(value) is str and len(value) <= MAX_CURSOR_BYTES and
             TOKEN_RE.fullmatch(value) is not None,
             'FINDINGCORRELATE_CURSOR_FORMAT_INVALID')
    encoded, mac = value.split('.')
    payload = show._b64decode(encoded)
    _require(hmac.compare_digest(mac, hmac.new(key, DOMAIN_CURSOR + payload,
                                             hashlib.sha256).hexdigest()),
             'FINDINGCORRELATE_CURSOR_SIGNATURE_INVALID', 'unavailable')
    obj = st._strict_stored(payload + b'\n', MAX_CURSOR_BYTES)
    _require(type(obj) is dict and set(obj) == {
        'schema', 'query_sha256', 'revision_sha256', 'graph_sha256',
        'edge_count', 'offset', 'issued_at_utc', 'expires_at_utc',
    }, 'FINDINGCORRELATE_CURSOR_FIELDS_INVALID')
    _require(obj['schema'] == CURSOR_SCHEMA and
             obj['query_sha256'] == query_sha256 and
             obj['revision_sha256'] == revision and
             obj['graph_sha256'] == graph_sha256 and
             type(obj['edge_count']) is int and obj['edge_count'] == edge_count and
             type(obj['offset']) is int and 0 < obj['offset'] < edge_count,
             'FINDINGCORRELATE_CURSOR_QUERY_OR_GRAPH_DRIFT', 'unavailable')
    issued = st._parse_stamp(obj['issued_at_utc'])
    expiry = st._parse_stamp(obj['expires_at_utc'])
    _require(issued <= now + timedelta(seconds=st.MAX_SKEW_SECONDS) and
             now < expiry and issued < expiry and
             expiry <= issued + timedelta(seconds=MAX_CURSOR_SECONDS),
             'FINDINGCORRELATE_CURSOR_EXPIRED', 'unavailable')
    return obj['offset'], issued, expiry


class FindingCorrelator:
    """Analyze a sealed store without mutating it or invoking Git/CI/Provider.

    Each source is a new independently approved FindingShow-style partition.
    Caller-provided serialized FindingShow pages/receipts are never accepted.
    """

    def __init__(self, stage_root: str, business_repo_root: str,
                 finding_store_root: str, *, codesave_root: str | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.show = show.FindingShower(stage_root, business_repo_root,
                                       finding_store_root,
                                       codesave_root=codesave_root, clock=clock)
        self.clock = clock

    def correlate(self, *, expected_finding_store_pin: str,
                  authorize_correlation: bool,
                  scopes: list[dict[str, Any]],
                  authorize_cross_source_correlation: bool = False,
                  authorize_path_correlation: bool = False,
                  include_expired: bool = False,
                  authorize_expired_audit: bool = False,
                  codeinsight_records: list[dict[str, Any]] | None = None,
                  authorize_codeinsight_byte_inspection: bool = False,
                  authorize_codeinsight_correlation: bool = False,
                  include_unknown_pairs: bool = False,
                  page_size: int = 20,
                  cursor: str | None = None) -> dict[str, Any]:
        try:
            _require(authorize_correlation is True,
                     'FINDINGCORRELATE_INDEPENDENT_CORRELATION_GRANT_REQUIRED')
            _require(save._digest(expected_finding_store_pin),
                     'FINDINGCORRELATE_STORE_PIN_REQUIRED')
            _require(type(scopes) is list and 1 <= len(scopes) <= MAX_SCOPES,
                     'FINDINGCORRELATE_SOURCE_SCOPE_BOUND')
            _require(type(page_size) is int and 1 <= page_size <= MAX_PAGE,
                     'FINDINGCORRELATE_PAGE_SIZE_BOUND')
            for flag in (authorize_cross_source_correlation,
                         authorize_path_correlation, include_expired,
                         authorize_expired_audit, authorize_codeinsight_byte_inspection,
                         authorize_codeinsight_correlation, include_unknown_pairs):
                _require(type(flag) is bool, 'FINDINGCORRELATE_GRANT_FLAG_NOT_BOOLEAN')
            _require(not include_expired or authorize_expired_audit,
                     'FINDINGCORRELATE_EXPIRED_NEEDS_SEPARATE_AUDIT_GRANT')
            approved = [_scope(s) for s in scopes]
            canonical = [st._canonical(s[0]) for s in approved]
            _require(len(set(canonical)) == len(canonical),
                     'FINDINGCORRELATE_DUPLICATE_SOURCE_SCOPE')
            if len(approved) > 1 or codeinsight_records is not None:
                _require(authorize_cross_source_correlation is True,
                         'FINDINGCORRELATE_CROSS_SOURCE_NEEDS_NEW_GRANT')
            _require(codeinsight_records is None or
                     (authorize_codeinsight_byte_inspection is True and
                      authorize_codeinsight_correlation is True),
                     'FINDINGCORRELATE_CODEINSIGHT_NEEDS_SEPARATE_GRANTS')
            ci_data, ci_ids = _ci_records(
                codeinsight_records, allow=(authorize_codeinsight_byte_inspection and
                                            authorize_codeinsight_correlation),
                repo_root=self.show.ledger.business_repo_root)
            query = {
                'full_source_bindings': [a for a, _, _, _ in approved],
                'source_modes': [m for _, m, _, _ in approved],
                'historical_acks': [a for _, _, a, _ in approved],
                'finding_id_allowlists': [v for _, _, _, v in approved],
                'include_expired': include_expired,
                'allow_path': authorize_path_correlation,
                'codeinsight_record_ids': ci_ids,
                'codeinsight_byte_sha256': [hashlib.sha256(x['raw_bytes']).hexdigest()
                                            for x in (codeinsight_records or [])],
                'include_unknown_pairs': include_unknown_pairs,
                'page_size': page_size,
            }
            query_sha = _sha(DOMAIN_QUERY, query)
            ledger = self.show.ledger
            with ledger._locked() as (fd, manifest, key, pins):
                assert manifest is not None and key is not None
                pin = save._pin(manifest)
                _require(hmac.compare_digest(pin, expected_finding_store_pin),
                         'FINDINGCORRELATE_STORE_PIN_CHANGED', 'unavailable')
                records = ledger._all(fd, key, manifest)  # full historical HMAC/chain check
                revision = show._sha(show.DOMAIN_REVISION, {
                    'store_pin': pin, 'batch_count': len(records),
                    'record_shas': [r['record_sha256'] for r in records],
                })
                now = st._now(self.clock)
                _require(all(now + timedelta(seconds=st.MAX_SKEW_SECONDS) >=
                             st._parse_stamp(r['committed_at_utc']) for r in records),
                         'FINDINGCORRELATE_LEDGER_CLOCK_ROLLBACK', 'unavailable')
                nodes: list[dict[str, Any]] = []
                active_expiries: list[datetime] = []
                coverage = []
                for index, (binding, mode, _, allowed_ids) in enumerate(approved):
                    selected = 0
                    v1 = 0
                    partial = 0
                    expired_skipped = 0
                    filtered_out = 0
                    for record in records:
                        if record['source_binding'] != binding:
                            continue
                        expiry = st._parse_stamp(record['expires_at_utc'])
                        expired = now >= expiry
                        if expired and not include_expired:
                            expired_skipped += len(record['findings'])
                            continue
                        for i, row in enumerate(record['findings']):
                            if allowed_ids is not None and row['finding_id'] not in allowed_ids:
                                filtered_out += 1
                                continue
                            detail = record.get('path_index')
                            p = detail[i] if detail is not None else None
                            state = ('LEGACY_V1_UNAVAILABLE' if p is None else
                                     'COMPLETE' if p['path_index_complete'] else
                                     'PARTIAL_OR_UNPATHED')
                            v1 += (p is None)
                            partial += (p is not None and not p['path_index_complete'])
                            selected += 1
                            node = {
                                'kind': 'FINDING_HMAC', 'scope': f'F{index}',
                                'finding_id': row['finding_id'],
                                'record_id': None, 'batch_sequence': record['sequence'],
                                'source_binding': binding, 'source_mode': mode,
                                'historical': record['historical_proposal_only'],
                                'expired': expired, 'assessment_state': row['assessment_state'],
                                'severity_claim': row['severity'],
                                'coverage_complete': record['coverage']['complete'],
                                'counter_count': len(row['counter_evidence']),
                                'path_state': state,
                                'original_sha256': row['original_finding_sha256'],
                                'anchors': list(zip(
                                    p['positive_anchor_path_sha256'] if p is not None
                                    else [None] * len(row['positive_anchor_sha256']),
                                    row['positive_quote_sha256'],
                                    row['positive_anchor_sha256'],
                                )),
                            }
                            node['node_id'] = _sha(DOMAIN_NODE, {
                                'kind': node['kind'], 'scope': node['scope'],
                                'sequence': record['sequence'], 'finding_id': row['finding_id'],
                            })
                            nodes.append(node)
                            if not expired:
                                active_expiries.append(expiry)
                            _require(len(nodes) <= MAX_NODES,
                                     'FINDINGCORRELATE_TOO_MANY_NODES_REFINE_SCOPES',
                                     'invalid_input')
                    coverage.append({
                        'scope': f'F{index}', 'source_mode': mode,
                        'selected_findings': selected,
                        'expired_hidden': expired_skipped,
                        'excluded_by_explicit_finding_id_allowlist': filtered_out,
                        'legacy_v1_unindexed': v1,
                        'partial_v2_path_index': partial,
                        'whole_source_defect_absence_proven': False,
                        'historical_source_possible': mode == 'ProposedPR',
                    })
                for record in ci_data:
                    mode = CI_MODES[record['source_mode']]
                    for row in record['checked_findings']:
                        node = {
                            'kind': 'CODEINSIGHT_V1_OFFLINE', 'scope': 'CI',
                            'finding_id': row['id'],
                            'record_id': record['_record_id'], 'batch_sequence': None,
                            'source_binding': None, 'source_mode': mode,
                            'historical': False, 'expired': False,
                            'assessment_state': 'UNVERIFIED',
                            'severity_claim': row['severity'],
                            'coverage_complete': False, 'counter_count': 0,
                            'path_state': 'OFFLINE_DECLARED_PATH',
                            'original_sha256': None,
                            'anchors': [(fs._sha(fs.DOMAIN_PATH, row['path']),
                                         row['quote_sha256'], None)],
                        }
                        node['node_id'] = _sha(DOMAIN_NODE, {
                            'kind': node['kind'], 'record_id': record['_record_id'],
                            'finding_id': row['id'],
                        })
                        nodes.append(node)
                        _require(len(nodes) <= MAX_NODES,
                                 'FINDINGCORRELATE_TOO_MANY_NODES_REFINE_SCOPES',
                                 'invalid_input')
                # Node publication has no sensitive assertion text/path/model notes.
                public_nodes = [{
                    'node_id': n['node_id'], 'kind': n['kind'], 'scope': n['scope'],
                    'finding_id': n['finding_id'], 'batch_sequence': n['batch_sequence'],
                    'codeinsight_record_id': n['record_id'],
                    'source_mode': n['source_mode'],
                    'assessment_state': n['assessment_state'],
                    'severity_claim': n['severity_claim'],
                    'path_index_state': n['path_state'],
                    'historical_proposal_only': n['historical'],
                    'expired_at_query_time': n['expired'],
                    'coverage_complete_for_selected_source': n['coverage_complete'],
                    'semantic_equivalence_proven': False,
                } for n in nodes]
                all_edges = []
                pair_counts = {state: 0 for state in sorted(STATES)}
                for a, b in combinations(nodes, 2):
                    edge = _compare(a, b, allow_path=authorize_path_correlation)
                    pair_counts[edge['relation_state']] += 1
                    if (include_unknown_pairs or edge['relation_state'] != 'UNKNOWN'):
                        all_edges.append(edge)
                # Determinism across pages is independent of model-provided wording.
                rank = {'EQUIVALENT_DECLARATION': 0, 'CANDIDATE_SIMILARITY': 1,
                        'INELIGIBLE': 2, 'UNKNOWN': 3}
                all_edges.sort(key=lambda e: (rank[e['relation_state']],
                                              e['left'], e['right']))
                _require(len(all_edges) <= MAX_EDGES,
                         'FINDINGCORRELATE_EDGE_BOUND', 'unavailable')
                graph_sha = _sha(DOMAIN_GRAPH, {
                    'revision_sha256': revision, 'query_sha256': query_sha,
                    'nodes': public_nodes, 'edges': all_edges, 'pair_counts': pair_counts,
                })
                offset = 0
                issued: datetime | None = None
                previous_expiry: datetime | None = None
                if cursor is not None:
                    offset, issued, previous_expiry = _cursor(
                        key, cursor, now, query_sha256=query_sha,
                        revision=revision, graph_sha256=graph_sha,
                        edge_count=len(all_edges))
                window = all_edges[offset:offset+page_size]
                next_token = None
                deadline = None
                if offset + len(window) < len(all_edges):
                    expiry = min([now + timedelta(seconds=MAX_CURSOR_SECONDS)] +
                                 active_expiries)
                    if previous_expiry is not None:
                        expiry = min(expiry, previous_expiry)
                    _require(now < expiry,
                             'FINDINGCORRELATE_SNAPSHOT_EXPIRED', 'unavailable')
                    issue_time = issued or now
                    next_token = _token(key, {
                        'schema': CURSOR_SCHEMA, 'query_sha256': query_sha,
                        'revision_sha256': revision, 'graph_sha256': graph_sha,
                        'edge_count': len(all_edges), 'offset': offset + len(window),
                        'issued_at_utc': st._stamp(issue_time),
                        'expires_at_utc': st._stamp(expiry),
                    })
                    deadline = st._stamp(expiry)
                ledger._live_pins(pins)
                result = {
                    'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                    'reason_code': 'FINDINGCORRELATE_DECLARATION_RELATIONSHIPS_NOT_DEFECT_DUPLICATES',
                    'store_revision_sha256': revision, 'query_sha256': query_sha,
                    'graph_sha256': graph_sha, 'nodes': public_nodes,
                    'node_count': len(public_nodes), 'edges': window,
                    'edge_count': len(all_edges),
                    'candidate_edge_count': pair_counts['CANDIDATE_SIMILARITY'],
                    'pair_counts': pair_counts, 'returned_count': len(window),
                    'next_cursor': next_token, 'cursor_expires_at_utc': deadline,
                    'scope_coverage': coverage,
                    'codeinsight_coverage': {
                        'mode': ('OFFLINE_V1_BYTES_HASH_AND_SCHEMA_ONLY' if ci_data else
                                 'NOT_PROVIDED_NO_CODEINSIGHT_CLAIM'),
                        'checked_record_count': len(ci_data),
                        'checked_finding_count': sum(r['finding_count'] for r in ci_data),
                        'native_store_or_git_authenticated': False,
                        'ci_test_observations_available': False,
                        'ci_reader_state': 'NOT_IMPLEMENTED_UNTIL_LATER_EC',
                    },
                    'limitations': {
                        'graph_relations_are_not_semantic_bug_deduplication': True,
                        'no_edge_does_not_prove_different_or_fixed': True,
                        'hmac_does_not_authenticate_human_or_source_currentness': True,
                        'cross_store_snapshot_atomicity_proven': False,
                        'legacy_unindexed_or_partial_paths_never_negative_proof': True,
                        'codeinsight_offline_bytes_are_not_native_codeshow_verification': True,
                        'real_ci_witness_not_available_in_ec180': True,
                    },
                    'effects': _effects(), 'trust_boundary': TRUST,
                }
                _require(len(st._canonical(result)) <= MAX_RESPONSE_BYTES,
                         'FINDINGCORRELATE_RESPONSE_SIZE_BOUND', 'unavailable')
                return result
        except (CorrelationError, show.FindingShowError, save.FindingSaveError,
                st.StageError, lc.LifecycleError) as exc:
            status = exc.status if exc.status in ('invalid_input', 'unavailable') else 'unavailable'
            return _refused(exc.code, status)
        except (OSError, TypeError, ValueError, KeyError, IndexError, OverflowError,
                RuntimeError, RecursionError, MemoryError, AssertionError):
            return _refused('FINDINGCORRELATE_PRIVATE_STORE_OR_INPUT_UNAVAILABLE',
                            'unavailable')
