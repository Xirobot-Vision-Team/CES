#!/usr/bin/env python3
"""EC201 knowledge-currentness boundary: deterministic, in-memory, read-only.

Never treat ProposedPR, an AI/CI claim, a matching caller-supplied SHA, or an
unverified DeliveredTarget selector as trusted delivered architecture.
The only checked content proof here is equality of supplied bytes to the
separately supplied SHA256, *not* a Git object/target branch/provider proof.
EC202+ must supply independent real source access, exact Git target binding,
conflict handling and separately authorised versioned persistence.
"""
from __future__ import annotations

import base64
import binascii
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

SCHEMA = 'ces.knowledge_boundary.v1'
REQUEST_SCHEMA = 'ces.knowledge_boundary_request.v1'
POLICY_SCHEMA = 'ces.knowledge_boundary_read_policy.v1'
PURPOSE = 'knowledge_boundary_read_only'
MAX_REQUEST = 1048576
MAX_POLICY = 131072
MAX_OBSERVATIONS = 128
MAX_CLAIMS = 64
MAX_CONTENT = 4096
MAX_PERIOD_SECONDS = 366 * 86400
REPO = re.compile(r'cesrepo1:[0-9a-f]{64}\Z', re.ASCII)
SHA = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
KEY = re.compile(r'[A-Za-z][A-Za-z0-9._-]{0,63}\Z', re.ASCII)
UTC = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z', re.ASCII)
ORIGINS = frozenset({'delivered_source', 'proposed_pr', 'working_tree',
                     'ai_assertion', 'ci_assertion', 'unknown'})
SOURCE_KINDS = frozenset({'delivered_source', 'proposed_pr', 'working_tree'})
COVERAGE = frozenset({'complete_declared', 'partial_declared', 'unknown'})
SOURCE_MODE = {
    'delivered_source': 'DeliveredTarget',
    'proposed_pr': 'ProposedPR',
    'working_tree': 'WorkingTree',
    'ai_assertion': 'AI', 'ci_assertion': 'CI', 'unknown': 'Unknown',
}
ASSERTION_STATE = {
    'proposed_pr': 'CANDIDATE_NOT_DELIVERED',
    'working_tree': 'WORKTREE_NOT_DELIVERED',
    'ai_assertion': 'UNVERIFIED_AI_ASSERTION',
    'ci_assertion': 'UNVERIFIED_CI_ASSERTION',
    'unknown': 'UNKNOWN_UNAVAILABLE',
}
LIMITATIONS = {
    'real_delivered_source_authenticated': False,
    'target_commit_git_object_verified': False,
    'repository_or_branch_identity_authenticated': False,
    'provider_or_source_receipts_authenticated': False,
    'ai_or_ci_assertions_verified_as_facts': False,
    'candidate_promoted_to_current': False,
    'current_architecture_verified': False,
    'knowledge_bootstrap_or_impact_implemented': False,
    'knowledge_saved_or_published': False,
    'business_git_issue_or_provider_written': False,
    'native_powershell_knowledge_registered': False,
}


class KnowledgeBoundaryError(ValueError):
    """Fixed reason codes; do not echo untrusted input or content."""

    def __init__(self, reason: str, status: str = 'invalid_input') -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


def need(condition: bool, reason: str, status: str = 'invalid_input') -> None:
    if not condition:
        raise KnowledgeBoundaryError(reason, status)


def exact(obj: Any, keys: set[str], reason: str) -> dict[str, Any]:
    need(type(obj) is dict and set(obj) == keys, reason)
    return obj


def sha(value: Any) -> bool:
    return type(value) is str and SHA.fullmatch(value) is not None


def key(value: Any) -> bool:
    return type(value) is str and KEY.fullmatch(value) is not None


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False)


def digest(domain: str, value: Any) -> str:
    return hashlib.sha256(domain.encode('ascii') + b'\0' +
                          canonical(value).encode('ascii')).hexdigest()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    found: set[str] = set()
    for k, value in pairs:
        folded = k.casefold()
        need(folded not in found, 'JSON_DUPLICATE_KEY')
        found.add(folded)
        result[k] = value
    return result


def _reject_float(_: str) -> Any:
    raise KnowledgeBoundaryError('JSON_NUMBER_UNSUPPORTED')


def _json(data: Any, max_bytes: int) -> dict[str, Any]:
    need(type(data) is str, 'JSON_TYPE_INVALID')
    try:
        encoded = data.encode('utf-8', errors='strict')
    except UnicodeError as ex:
        raise KnowledgeBoundaryError('JSON_ENCODING_INVALID') from ex
    need(1 <= len(encoded) <= max_bytes, 'JSON_SIZE_INVALID')
    try:
        parsed = json.loads(data, object_pairs_hook=_unique_pairs,
                            parse_float=_reject_float, parse_constant=_reject_float)
    except KnowledgeBoundaryError:
        raise
    except (TypeError, ValueError, RecursionError, OverflowError, UnicodeError) as ex:
        raise KnowledgeBoundaryError('JSON_INVALID') from ex
    need(type(parsed) is dict and canonical(parsed) == data, 'JSON_NONCANONICAL')
    return parsed


def _time(value: Any) -> datetime:
    need(type(value) is str and UTC.fullmatch(value) is not None,
         'UTC_TIME_INVALID')
    try:
        parsed = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(
            tzinfo=timezone.utc)
    except ValueError as ex:
        raise KnowledgeBoundaryError('UTC_TIME_INVALID') from ex
    need(parsed.strftime('%Y-%m-%dT%H:%M:%SZ') == value, 'UTC_TIME_INVALID')
    return parsed


def _revision(value: Any) -> None:
    exact(value, {'algorithm', 'oid'}, 'REVISION_FIELDS_INVALID')
    algorithm = value['algorithm']
    need(type(algorithm) is str and algorithm in ('sha1', 'sha256'),
         'REVISION_ALGORITHM_INVALID')
    length = 40 if algorithm == 'sha1' else 64
    oid = value['oid']
    need(type(oid) is str and len(oid) == length and
         re.fullmatch(r'[0-9a-f]+', oid, re.ASCII) is not None,
         'REVISION_OID_INVALID')


def _request(raw: dict[str, Any]) -> dict[str, Any]:
    exact(raw, {'schema', 'operation', 'scope', 'observations'},
          'REQUEST_FIELDS_INVALID')
    need(raw['schema'] == REQUEST_SCHEMA and
         raw['operation'] == 'knowledge.boundary.inspect',
         'REQUEST_OPERATION_INVALID')
    s = exact(raw['scope'], {'repository_ref', 'knowledge_space_key', 'period',
                             'target', 'source_policy_revision'}, 'SCOPE_FIELDS_INVALID')
    need(type(s['repository_ref']) is str and REPO.fullmatch(s['repository_ref']) is not None and
         key(s['knowledge_space_key']) and key(s['source_policy_revision']),
         'SCOPE_IDENTITY_INVALID')
    period = exact(s['period'], {'period_id', 'start_utc', 'end_utc'},
                   'PERIOD_FIELDS_INVALID')
    need(key(period['period_id']), 'PERIOD_ID_INVALID')
    start, end = period['start_utc'], period['end_utc']
    need((start is None) == (end is None), 'PERIOD_PARTIAL_WINDOW_INVALID')
    if start is not None:
        t0, t1 = _time(start), _time(end)
        need(t0 < t1 and (t1 - t0).total_seconds() <= MAX_PERIOD_SECONDS,
             'PERIOD_WINDOW_INVALID')
    target = exact(s['target'], {'mode', 'revision', 'source_receipt_sha256'},
                   'TARGET_FIELDS_INVALID')
    need(target['mode'] == 'DeliveredTarget', 'TARGET_MODE_INVALID')
    need(target['revision'] is not None or target['source_receipt_sha256'] is None,
         'TARGET_RECEIPT_WITHOUT_REVISION')
    if target['revision'] is not None:
        _revision(target['revision'])
    need(target['source_receipt_sha256'] is None or sha(target['source_receipt_sha256']),
         'TARGET_RECEIPT_INVALID')
    rows = raw['observations']
    need(type(rows) is list and len(rows) <= MAX_OBSERVATIONS,
         'OBSERVATION_COUNT_INVALID')
    observed_keys: list[str] = []
    claim_keys: set[str] = set()
    for row in rows:
        exact(row, {'observation_key', 'claim_key', 'origin', 'source_revision',
                    'evidence_receipt_sha256', 'content_sha256', 'content_base64',
                    'observed_at_utc', 'coverage'}, 'OBSERVATION_FIELDS_INVALID')
        need(key(row['observation_key']) and key(row['claim_key']),
             'OBSERVATION_KEY_INVALID')
        observed_keys.append(row['observation_key'])
        claim_keys.add(row['claim_key'])
        origin = row['origin']
        need(type(origin) is str and origin in ORIGINS,
             'OBSERVATION_ORIGIN_INVALID')
        need(type(row['coverage']) is str and row['coverage'] in COVERAGE,
             'OBSERVATION_COVERAGE_INVALID')
        receipt = row['evidence_receipt_sha256']
        need(receipt is None or sha(receipt), 'OBSERVATION_RECEIPT_INVALID')
        content_sha = row['content_sha256']
        need(content_sha is None or sha(content_sha), 'OBSERVATION_DIGEST_INVALID')
        content = row['content_base64']
        need(content is None or (type(content) is str and
             1 <= len(content) <= ((MAX_CONTENT + 2) // 3) * 4),
             'OBSERVATION_CONTENT_SIZE_INVALID')
        stamp = row['observed_at_utc']
        if stamp is not None:
            _time(stamp)
        if origin in SOURCE_KINDS:
            _revision(row['source_revision'])
            need(content is None or content_sha is not None,
                 'OBSERVATION_CONTENT_WITHOUT_DIGEST')
        else:
            need(row['source_revision'] is None and content is None and
                 content_sha is None, 'ASSERTION_SOURCE_ESCALATION')
        if origin == 'unknown':
            need(receipt is None and row['coverage'] == 'unknown',
                 'UNKNOWN_EVIDENCE_ESCALATION')
    need(observed_keys == sorted(set(observed_keys)),
         'OBSERVATION_KEYS_NOT_SORTED_UNIQUE')
    need(len(claim_keys) <= MAX_CLAIMS, 'CLAIM_COUNT_INVALID')
    return raw


def _binding(req: dict[str, Any]) -> dict[str, Any]:
    return {
        'request_binding_sha256': digest('CES-EC201-REQUEST-v1', req),
        'scope_binding_sha256': digest('CES-EC201-SOURCE-SCOPE-v1', req['scope']),
        'observation_bindings': [
            {'observation_key': r['observation_key'],
             'observation_binding_sha256': digest('CES-EC201-OBSERVATION-v1', r)}
            for r in req['observations']
        ],
    }


def _policy(raw: dict[str, Any], request: dict[str, Any], bindings: dict[str, Any]) -> None:
    exact(raw, {'schema', 'purpose', 'repository_ref', 'knowledge_space_key',
                'period_id', 'source_policy_revision', 'request_binding_sha256',
                'scope_binding_sha256', 'permit_boundary_read',
                'permit_provenance_projection', 'permit_content_digest',
                'permit_knowledge_write', 'permit_business_source_write',
                'permit_issue_write', 'permit_publish', 'read_receipt_sha256',
                'observation_grants'}, 'POLICY_FIELDS_INVALID')
    need(raw['schema'] == POLICY_SCHEMA and raw['purpose'] == PURPOSE,
         'POLICY_PURPOSE_INVALID', 'unavailable')
    s = request['scope']
    need(all(raw[k] == s[k] for k in ('repository_ref', 'knowledge_space_key',
                                      'source_policy_revision')) and
         raw['period_id'] == s['period']['period_id'] and
         raw['request_binding_sha256'] == bindings['request_binding_sha256'] and
         raw['scope_binding_sha256'] == bindings['scope_binding_sha256'],
         'POLICY_SOURCE_PIN_MISMATCH', 'unavailable')
    for perm in ('permit_boundary_read', 'permit_provenance_projection',
                 'permit_content_digest', 'permit_knowledge_write',
                 'permit_business_source_write', 'permit_issue_write',
                 'permit_publish'):
        need(type(raw[perm]) is bool, 'POLICY_PERMISSION_TYPE_INVALID')
    need(raw['permit_boundary_read'] and sha(raw['read_receipt_sha256']),
         'POLICY_READ_NOT_AUTHORIZED', 'unavailable')
    need(not any(raw[perm] for perm in ('permit_knowledge_write',
                                       'permit_business_source_write',
                                       'permit_issue_write', 'permit_publish')),
         'POLICY_WRITE_INTENT_FORBIDDEN', 'unavailable')
    grants = raw['observation_grants']
    need(type(grants) is list and len(grants) == len(bindings['observation_bindings']),
         'SOURCE_GRANTS_INCOMPLETE', 'unavailable')
    for g, expected, obs in zip(grants, bindings['observation_bindings'],
                                request['observations']):
        exact(g, {'observation_key', 'observation_binding_sha256',
                  'permit_observation_read', 'permit_content_digest',
                  'read_receipt_sha256'}, 'SOURCE_GRANT_FIELDS_INVALID')
        need(g['observation_key'] == expected['observation_key'] and
             g['observation_binding_sha256'] == expected['observation_binding_sha256'],
             'SOURCE_GRANT_BINDING_MISMATCH', 'unavailable')
        need(type(g['permit_observation_read']) is bool and
             type(g['permit_content_digest']) is bool,
             'SOURCE_GRANT_PERMISSION_TYPE_INVALID')
        need(g['permit_observation_read'] and sha(g['read_receipt_sha256']),
             'SOURCE_GRANT_READ_NOT_AUTHORIZED', 'unavailable')
        if obs['content_base64'] is not None:
            need(raw['permit_content_digest'] and g['permit_content_digest'],
                 'SOURCE_CONTENT_PERMISSION_MISSING', 'unavailable')
        # A per-row grant never overrides the top-level content prohibition.
        need(not g['permit_content_digest'] or raw['permit_content_digest'],
             'SOURCE_GRANT_ESCALATION', 'unavailable')


def _byte_integrity(row: dict[str, Any]) -> str:
    if row['content_base64'] is None:
        return 'NOT_CHECKED'
    try:
        value = base64.b64decode(row['content_base64'], validate=True)
    except (ValueError, binascii.Error) as ex:
        raise KnowledgeBoundaryError('CONTENT_ENCODING_INVALID') from ex
    need(0 < len(value) <= MAX_CONTENT and
         base64.b64encode(value).decode('ascii') == row['content_base64'],
         'CONTENT_ENCODING_INVALID')
    need(hashlib.sha256(value).hexdigest() == row['content_sha256'],
         'CONTENT_DIGEST_MISMATCH', 'unavailable')
    return 'CALLER_SUPPLIED_BYTES_SHA256_MATCH'


def _period_relation(stamp: Any, period: dict[str, Any]) -> str:
    if stamp is None or period['start_utc'] is None:
        return 'UNKNOWN'
    instant = _time(stamp)
    if instant < _time(period['start_utc']):
        return 'BEFORE_PERIOD'
    if instant >= _time(period['end_utc']):
        return 'AFTER_PERIOD'
    return 'WITHIN_DECLARED_PERIOD'


def _classify(row: dict[str, Any], scope: dict[str, Any],
              item_binding: str, show: bool) -> dict[str, Any]:
    proof = _byte_integrity(row)
    origin = row['origin']
    target_revision = scope['target']['revision']
    relation = 'NOT_APPLICABLE'
    if origin == 'delivered_source':
        if target_revision is None:
            relation = 'TARGET_UNKNOWN'
            assessment = 'TARGET_REVISION_UNKNOWN'
        elif row['source_revision'] != target_revision:
            relation = 'OTHER_REVISION'
            assessment = 'OTHER_DELIVERED_SOURCE_UNVERIFIED'
        else:
            relation = 'EXACT_DECLARED_REVISION'
            assessment = ('BYTES_MATCH_EXPECTED_HASH_DELIVERY_UNVERIFIED' if
                          proof == 'CALLER_SUPPLIED_BYTES_SHA256_MATCH' else
                          'DELIVERED_SOURCE_DIGEST_DECLARED_ONLY')
    else:
        assessment = ASSERTION_STATE[origin]
        if origin == 'proposed_pr':
            relation = ('SAME_OID_NOT_DELIVERY_PROOF' if
                        target_revision is not None and
                        row['source_revision'] == target_revision else
                        'CANDIDATE_HEAD_NOT_BOUND_TO_DELIVERY')
    return {
        'observation_key': row['observation_key'],
        'claim_key': row['claim_key'],
        'observation_ref': 'ceskobs1:' + item_binding,
        'source_mode': SOURCE_MODE[origin],
        'assessment': assessment,
        'content_integrity': proof,
        'target_revision_relation': relation,
        'period_relation': _period_relation(row['observed_at_utc'], scope['period']),
        'coverage': row['coverage'],
        'source_revision': row['source_revision'] if show else None,
        'content_sha256': row['content_sha256'] if show else None,
        'evidence_receipt_sha256': row['evidence_receipt_sha256'] if show else None,
    }


def _claim_group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    delivered = [r for r in rows if r['source_mode'] == 'DeliveredTarget' and
                 r['target_revision_relation'] == 'EXACT_DECLARED_REVISION' and
                 r['period_relation'] == 'WITHIN_DECLARED_PERIOD']
    checked = [r for r in delivered if
               r['content_integrity'] == 'CALLER_SUPPLIED_BYTES_SHA256_MATCH']
    hashes = {r['content_sha256'] for r in delivered if r['content_sha256'] is not None}
    # Compare only internal (non-redacted) projections. Never compare null
    # display fields or count outside-period claims as current evidence.
    conflict = len(hashes) > 1
    if conflict:
        evidence_state = 'CONFLICTING_DELIVERED_SOURCE_DECLARATIONS'
    elif checked:
        evidence_state = 'LOCAL_BYTES_INTEGRITY_ONLY_DELIVERY_UNVERIFIED'
    elif delivered:
        evidence_state = 'DELIVERED_SOURCE_DECLARATION_UNVERIFIED'
    else:
        evidence_state = 'NO_ELIGIBLE_DELIVERED_SOURCE'
    return {
        'claim_key': rows[0]['claim_key'],
        'current_architecture_state': 'UNKNOWN_NOT_AUTHENTICATED',
        'evidence_state': evidence_state,
        'source_conflict': conflict,
        'delivered_source_refs': [r['observation_ref'] for r in rows if
                                  r['source_mode'] == 'DeliveredTarget'],
        'candidate_refs': [r['observation_ref'] for r in rows if
                           r['source_mode'] in ('ProposedPR', 'WorkingTree')],
        'unverified_assertion_refs': [r['observation_ref'] for r in rows if
                                      r['source_mode'] in ('AI', 'CI')],
        'unknown_refs': [r['observation_ref'] for r in rows if
                         r['source_mode'] == 'Unknown'],
    }


def _base() -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
        'reason_code': 'KNOWLEDGE_BOUNDARY_INVALID_INPUT',
        'subject': None, 'canonical_json': None,
        'limitations': dict(LIMITATIONS),
    }


class KnowledgeBoundary:
    """Independent, non-persistent authority-limited knowledge evidence model."""

    def binding_preview(self, *, request_json: str) -> dict[str, Any]:
        """Build content-addressed pins for a *later, separate* read policy.

        This only parses caller-supplied metadata. It is not an authorization
        ticket, delivery receipt, source inspection or semantic validation.
        """
        out = _base()
        try:
            request = _request(_json(request_json, MAX_REQUEST))
            out.update(status='partial', exit_code=2,
                       reason_code='KNOWLEDGE_BOUNDARY_BINDINGS_ONLY',
                       subject=_binding(request))
            out['canonical_json'] = canonical(out['subject'])
        except KnowledgeBoundaryError as ex:
            out.update(status=ex.status, exit_code=5 if ex.status == 'unavailable' else 4,
                       reason_code='KNOWLEDGE_BOUNDARY_' + ex.reason)
        except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
            out.update(reason_code='KNOWLEDGE_BOUNDARY_INPUT_UNAVAILABLE',
                       status='unavailable', exit_code=5)
        return out

    def inspect(self, *, request_json: str, read_policy_json: str) -> dict[str, Any]:
        """Evaluate the exact authorised in-memory envelope; never perform IO.

        All successful outcomes are partial/2. In particular, no result from
        this method can put a claim into trusted current architecture state.
        """
        out = _base()
        try:
            req = _request(_json(request_json, MAX_REQUEST))
            bindings = _binding(req)
            policy = _json(read_policy_json, MAX_POLICY)
            _policy(policy, req, bindings)
            detailed = []
            exposed = []
            summary = {
                'total_observations': len(req['observations']),
                'total_claims': 0, 'local_source_bytes_checked': 0,
                'delivered_source_declarations': 0, 'proposed_candidates': 0,
                'working_tree_observations': 0, 'ai_assertions': 0,
                'ci_assertions': 0, 'unknown_evidence': 0,
                'outside_period': 0, 'other_delivered_revision': 0,
                'source_conflicts': 0, 'authenticated_delivered_facts': 0,
            }
            for row, bind in zip(req['observations'], bindings['observation_bindings']):
                checked = _classify(row, req['scope'],
                                    bind['observation_binding_sha256'], True)
                detailed.append(checked)
                if checked['content_integrity'] == 'CALLER_SUPPLIED_BYTES_SHA256_MATCH':
                    summary['local_source_bytes_checked'] += 1
                summary[{
                    'delivered_source': 'delivered_source_declarations',
                    'proposed_pr': 'proposed_candidates',
                    'working_tree': 'working_tree_observations',
                    'ai_assertion': 'ai_assertions',
                    'ci_assertion': 'ci_assertions',
                    'unknown': 'unknown_evidence',
                }[row['origin']]] += 1
                if checked['period_relation'] in ('BEFORE_PERIOD', 'AFTER_PERIOD'):
                    summary['outside_period'] += 1
                if checked['assessment'] == 'OTHER_DELIVERED_SOURCE_UNVERIFIED':
                    summary['other_delivered_revision'] += 1
                if policy['permit_provenance_projection']:
                    exposed.append(checked)
                else:
                    redacted = dict(checked)
                    redacted.update(source_revision=None, content_sha256=None,
                                    evidence_receipt_sha256=None)
                    exposed.append(redacted)
            grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for r in detailed:
                grouped[r['claim_key']].append(r)
            claims = [_claim_group(grouped[k]) for k in sorted(grouped)]
            summary['total_claims'] = len(claims)
            summary['source_conflicts'] = sum(1 for c in claims if c['source_conflict'])
            scope = req['scope']
            subject = {
                'model_revision': 'EC201_BOUNDARY_ONLY',
                'knowledge_scope_ref': 'ceskscope1:' + bindings['scope_binding_sha256'],
                'request_binding_sha256': bindings['request_binding_sha256'],
                'read_policy_binding_sha256': digest('CES-EC201-READ-POLICY-v1', policy),
                'repository_ref': scope['repository_ref'],
                'knowledge_space_key': scope['knowledge_space_key'],
                'period_id': scope['period']['period_id'],
                'source_policy_revision': scope['source_policy_revision'],
                'target_revision': scope['target']['revision'] if
                                   policy['permit_provenance_projection'] else None,
                'current_architecture_state': 'UNKNOWN_NOT_AUTHENTICATED',
                'verified_delivered_facts': [],
                'observations': exposed, 'claims': claims, 'summary': summary,
                'no_write_actions_performed': True,
                'next_unimplemented': ['EC202_KNOWLEDGE_BOOTSTRAP',
                                       'EC203_TRUSTED_TARGET_SHA_BINDING',
                                       'EC204_KNOWLEDGE_IMPACT',
                                       'EC206_CANDIDATE_SEPARATION_STORE',
                                       'EC208_KNOWLEDGE_SAVE',
                                       'EC210_KNOWLEDGE_UPDATE_CHAIN'],
            }
            out.update(status='partial', exit_code=2,
                       reason_code='KNOWLEDGE_BOUNDARY_READ_ONLY_UNVERIFIED_CURRENT',
                       subject=subject, canonical_json=canonical(subject))
        except KnowledgeBoundaryError as ex:
            out.update(status=ex.status, exit_code=5 if ex.status == 'unavailable' else 4,
                       reason_code='KNOWLEDGE_BOUNDARY_' + ex.reason)
        except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
            out.update(status='unavailable', exit_code=5,
                       reason_code='KNOWLEDGE_BOUNDARY_INPUT_UNAVAILABLE')
        return out
