#!/usr/bin/env python3
"""EC201 local synthetic development cases, NOT live delivery/acceptance."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest

from knowledge_boundary import KnowledgeBoundary, canonical

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

HERE = Path(__file__).resolve().parent
SCHEMA_DIR = HERE.parent / 'references'
REPO = 'cesrepo1:' + 'a' * 64
REV = {'algorithm': 'sha1', 'oid': 'b' * 40}
OTHER = {'algorithm': 'sha1', 'oid': 'c' * 40}
H = 'd' * 64


def obs(k, claim, origin, rev=None, payload=None, stamp='2026-10-10T12:00:00Z'):
    known = origin in ('delivered_source', 'proposed_pr', 'working_tree')
    result = {
        'observation_key': k, 'claim_key': claim, 'origin': origin,
        'source_revision': rev if known else None,
        'evidence_receipt_sha256': None if origin == 'unknown' else H,
        'content_sha256': hashlib.sha256(payload).hexdigest() if payload is not None else None,
        'content_base64': base64.b64encode(payload).decode('ascii') if payload is not None else None,
        'observed_at_utc': stamp,
        'coverage': 'unknown' if origin == 'unknown' else 'partial_declared',
    }
    return result


def sample(*rows, target=REV, start='2026-10-01T00:00:00Z',
           end='2026-11-01T00:00:00Z'):
    return {'schema': 'ces.knowledge_boundary_request.v1',
            'operation': 'knowledge.boundary.inspect',
            'scope': {'repository_ref': REPO, 'knowledge_space_key': 'architecture',
                      'period': {'period_id': 'month-2026-10', 'start_utc': start,
                                 'end_utc': end},
                      'target': {'mode': 'DeliveredTarget', 'revision': target,
                                 'source_receipt_sha256': H if target else None},
                      'source_policy_revision': 'policy-v1'},
            'observations': list(rows)}


def pol(req, *, provenance=False, content=True):
    api = KnowledgeBoundary()
    bindings = api.binding_preview(request_json=canonical(req))
    assert bindings['status'] == 'partial'
    b = bindings['subject']
    return {'schema': 'ces.knowledge_boundary_read_policy.v1',
            'purpose': 'knowledge_boundary_read_only',
            'repository_ref': req['scope']['repository_ref'],
            'knowledge_space_key': req['scope']['knowledge_space_key'],
            'period_id': req['scope']['period']['period_id'],
            'source_policy_revision': req['scope']['source_policy_revision'],
            'request_binding_sha256': b['request_binding_sha256'],
            'scope_binding_sha256': b['scope_binding_sha256'],
            'permit_boundary_read': True,
            'permit_provenance_projection': provenance,
            'permit_content_digest': content,
            'permit_knowledge_write': False,
            'permit_business_source_write': False,
            'permit_issue_write': False,
            'permit_publish': False,
            'read_receipt_sha256': H,
            'observation_grants': [
                {'observation_key': it['observation_key'],
                 'observation_binding_sha256': it['observation_binding_sha256'],
                 'permit_observation_read': True,
                 'permit_content_digest': content,
                 'read_receipt_sha256': H}
                for it in b['observation_bindings']]}


def inspect(req, policy=None):
    if policy is None:
        policy = pol(req)
    return KnowledgeBoundary().inspect(request_json=canonical(req),
                                       read_policy_json=canonical(policy))


class KnowledgeBoundaryTests(unittest.TestCase):
    def success(self, req, policy=None):
        out = inspect(req, policy)
        self.assertEqual((out['status'], out['exit_code']), ('partial', 2), out)
        self.assertEqual(json.loads(out['canonical_json']), out['subject'])
        self.assertFalse(any(out['limitations'].values()))
        self.assertEqual(out['subject']['verified_delivered_facts'], [])
        self.assertEqual(out['subject']['current_architecture_state'],
                         'UNKNOWN_NOT_AUTHENTICATED')
        return out

    def denied(self, req, policy, reason, status='unavailable'):
        out = inspect(req, policy)
        self.assertEqual(out['status'], status, out)
        self.assertEqual(out['reason_code'], 'KNOWLEDGE_BOUNDARY_' + reason, out)
        self.assertIsNone(out['subject'])
        self.assertIsNone(out['canonical_json'])

    def test_empty_source_is_unknown(self):
        req = sample()
        out = self.success(req)
        self.assertEqual(out['subject']['summary']['total_claims'], 0)
        self.assertTrue(out['subject']['no_write_actions_performed'])

    def test_exact_declared_delivered_bytes_are_not_current(self):
        req = sample(obs('o1', 'facts', 'delivered_source', REV, b'not a git proof'))
        out = self.success(req)
        row = out['subject']['observations'][0]
        self.assertEqual(row['assessment'], 'BYTES_MATCH_EXPECTED_HASH_DELIVERY_UNVERIFIED')
        self.assertEqual(row['content_integrity'], 'CALLER_SUPPLIED_BYTES_SHA256_MATCH')
        self.assertEqual(out['subject']['summary']['authenticated_delivered_facts'], 0)
        self.assertEqual(out['subject']['claims'][0]['evidence_state'],
                         'LOCAL_BYTES_INTEGRITY_ONLY_DELIVERY_UNVERIFIED')
        self.assertIsNone(row['source_revision'])
        self.assertIsNone(row['content_sha256'])
        self.assertNotIn('not a git proof', out['canonical_json'])

    def test_delivered_revision_mismatch_cannot_match(self):
        req = sample(obs('o1', 'facts', 'delivered_source', OTHER, b'v2'))
        out = self.success(req)
        self.assertEqual(out['subject']['observations'][0]['assessment'],
                         'OTHER_DELIVERED_SOURCE_UNVERIFIED')
        self.assertEqual(out['subject']['claims'][0]['evidence_state'],
                         'NO_ELIGIBLE_DELIVERED_SOURCE')

    def test_unknown_target_explicit_null(self):
        req = sample(obs('o1', 'facts', 'delivered_source', REV, b'x'), target=None)
        out = self.success(req)
        self.assertEqual(out['subject']['observations'][0]['assessment'],
                         'TARGET_REVISION_UNKNOWN')

    def test_same_revision_candidate_is_not_delivered(self):
        req = sample(obs('o1', 'facts', 'proposed_pr', REV, b'candidate'))
        out = self.success(req)
        row = out['subject']['observations'][0]
        self.assertEqual(row['target_revision_relation'], 'SAME_OID_NOT_DELIVERY_PROOF')
        self.assertEqual(row['assessment'], 'CANDIDATE_NOT_DELIVERED')
        self.assertEqual(len(out['subject']['claims'][0]['candidate_refs']), 1)

    def test_claim_union_no_escalation(self):
        rows = [obs('a', 'architecture', 'proposed_pr', OTHER, b'patch'),
                obs('b', 'architecture', 'ai_assertion'),
                obs('c', 'architecture', 'ci_assertion'),
                obs('d', 'architecture', 'unknown')]
        out = self.success(sample(*rows))
        c = out['subject']['claims'][0]
        self.assertEqual([len(c[k]) for k in ('candidate_refs', 'unverified_assertion_refs',
                                              'unknown_refs')], [1, 2, 1])
        self.assertEqual(c['evidence_state'], 'NO_ELIGIBLE_DELIVERED_SOURCE')

    def test_worktree_separate_from_delivery(self):
        req = sample(obs('o1', 'facts', 'working_tree', REV, b'local'))
        out = self.success(req)
        self.assertEqual(out['subject']['observations'][0]['assessment'],
                         'WORKTREE_NOT_DELIVERED')

    def test_delivered_conflict_no_silent_selection(self):
        rows = [obs('a', 'scope', 'delivered_source', REV, b'bytes a'),
                obs('b', 'scope', 'delivered_source', REV, b'bytes b')]
        out = self.success(sample(*rows))
        self.assertEqual(out['subject']['summary']['source_conflicts'], 1)
        self.assertEqual(out['subject']['claims'][0]['evidence_state'],
                         'CONFLICTING_DELIVERED_SOURCE_DECLARATIONS')

    def test_unknown_period_missing_bounds(self):
        req = sample(obs('a', 'facts', 'delivered_source', REV, b'x'), start=None, end=None)
        out = self.success(req)
        self.assertEqual(out['subject']['observations'][0]['period_relation'], 'UNKNOWN')

    def test_outside_declared_period_is_visible(self):
        req = sample(obs('a', 'facts', 'delivered_source', REV, b'v',
                         stamp='2026-11-01T00:00:00Z'))
        out = self.success(req)
        self.assertEqual(out['subject']['summary']['outside_period'], 1)
        self.assertEqual(out['subject']['observations'][0]['period_relation'], 'AFTER_PERIOD')

    def test_explicit_read_policy_required(self):
        req = sample()
        p = pol(req)
        p['permit_boundary_read'] = False
        self.denied(req, p, 'POLICY_READ_NOT_AUTHORIZED')

    def test_source_grant_missing(self):
        req = sample(obs('a', 'facts', 'ai_assertion'))
        p = pol(req)
        p['observation_grants'] = []
        self.denied(req, p, 'SOURCE_GRANTS_INCOMPLETE')

    def test_source_grant_revoked(self):
        req = sample(obs('a', 'facts', 'ai_assertion'))
        p = pol(req)
        p['observation_grants'][0]['permit_observation_read'] = False
        self.denied(req, p, 'SOURCE_GRANT_READ_NOT_AUTHORIZED')

    def test_content_digest_needs_independent_read(self):
        req = sample(obs('a', 'facts', 'delivered_source', REV, b'x'))
        p = pol(req)
        p['observation_grants'][0]['permit_content_digest'] = False
        self.denied(req, p, 'SOURCE_CONTENT_PERMISSION_MISSING')

    def test_forged_policy_binding(self):
        req = sample(obs('a', 'facts', 'proposed_pr', REV))
        p = pol(req)
        p['request_binding_sha256'] = H
        self.denied(req, p, 'POLICY_SOURCE_PIN_MISMATCH')

    def test_policy_replay_against_another_period(self):
        req = sample(obs('a', 'facts', 'ai_assertion'))
        p = pol(req)
        req['scope']['period']['period_id'] = 'month-2026-11'
        self.denied(req, p, 'POLICY_SOURCE_PIN_MISMATCH')

    def test_policy_replay_against_changed_source_revision(self):
        req = sample(obs('a', 'facts', 'delivered_source', REV))
        p = pol(req)
        req['scope']['target']['revision'] = OTHER
        self.denied(req, p, 'POLICY_SOURCE_PIN_MISMATCH')

    def test_forbids_all_write_intents(self):
        req = sample()
        for field in ('permit_knowledge_write', 'permit_business_source_write',
                      'permit_issue_write', 'permit_publish'):
            p = pol(req)
            p[field] = True
            with self.subTest(field=field):
                self.denied(req, p, 'POLICY_WRITE_INTENT_FORBIDDEN')

    def test_provenance_requires_disclosure_permission(self):
        req = sample(obs('a', 'facts', 'proposed_pr', OTHER, b'patch'))
        out = self.success(req, pol(req, provenance=True))
        self.assertEqual(out['subject']['observations'][0]['source_revision'], OTHER)
        self.assertEqual(out['subject']['observations'][0]['evidence_receipt_sha256'], H)
        self.assertNotIn(base64.b64encode(b'patch').decode(), out['canonical_json'])

    def test_malformed_content_never_classifies(self):
        req = sample(obs('a', 'facts', 'delivered_source', REV, b'a'))
        req['observations'][0]['content_base64'] = '***'
        p = pol(req)
        self.denied(req, p, 'CONTENT_ENCODING_INVALID', 'invalid_input')

    def test_content_digest_mismatch_fails_all(self):
        req = sample(obs('a', 'facts', 'delivered_source', REV, b'a'))
        req['observations'][0]['content_sha256'] = H
        p = pol(req)
        self.denied(req, p, 'CONTENT_DIGEST_MISMATCH')

    def test_unsorted_and_duplicate_observations(self):
        r1 = obs('b', 'facts', 'ai_assertion')
        r2 = obs('a', 'facts', 'ci_assertion')
        for rows in ([r1,r2], [r1,r1]):
            req = sample(*rows)
            b = KnowledgeBoundary().binding_preview(request_json=canonical(req))
            self.assertEqual(b['reason_code'],
                             'KNOWLEDGE_BOUNDARY_OBSERVATION_KEYS_NOT_SORTED_UNIQUE')

    def test_claim_unsupported_assertion_payload(self):
        r = obs('a', 'facts', 'ai_assertion')
        r['content_sha256'] = H
        req = sample(r)
        b = KnowledgeBoundary().binding_preview(request_json=canonical(req))
        self.assertEqual(b['reason_code'],
                         'KNOWLEDGE_BOUNDARY_ASSERTION_SOURCE_ESCALATION')

    def test_duplicate_json_keys_are_rejected(self):
        req = canonical(sample())
        malicious = req.replace('"schema":', '"SCHEMA":"bad","schema":', 1)
        res = KnowledgeBoundary().binding_preview(request_json=malicious)
        self.assertEqual(res['reason_code'], 'KNOWLEDGE_BOUNDARY_JSON_DUPLICATE_KEY')

    def test_noncanonical_json_rejected(self):
        req = sample()
        res = KnowledgeBoundary().binding_preview(request_json=json.dumps(req))
        self.assertEqual(res['reason_code'], 'KNOWLEDGE_BOUNDARY_JSON_NONCANONICAL')

    def test_schema_contract_on_both_outputs_and_policies(self):
        if Draft202012Validator is None:
            self.skipTest('jsonschema dependency absent')
        schemas = {n:json.loads((SCHEMA_DIR/f'knowledge-boundary-{n}.v1.schema.json').read_text())
                   for n in ('request','read-policy','result')}
        for schema in schemas.values():
            Draft202012Validator.check_schema(schema)
        req = sample(obs('a', 'a', 'delivered_source', REV, b'v1'),
                     obs('b', 'a', 'proposed_pr', OTHER, b'candidate'),
                     obs('c', 'b', 'unknown'))
        policy = pol(req)
        Draft202012Validator(schemas['request']).validate(req)
        Draft202012Validator(schemas['read-policy']).validate(policy)
        for out in (inspect(req,policy),
                    KnowledgeBoundary().binding_preview(request_json=canonical(req)),
                    inspect(req,{**policy,'permit_boundary_read':False})):
            Draft202012Validator(schemas['result']).validate(out)


if __name__ == '__main__':
    unittest.main()
