#!/usr/bin/env python3
"""EC215 synthetic contract/regression cases; NEVER live provider/org acceptance."""
from __future__ import annotations

import base64
import copy
from dataclasses import replace, asdict
from datetime import datetime, timedelta, timezone
import json
import subprocess
import sys
from pathlib import Path
import unittest

import jsonschema

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

import issue_provider as ip
import issue_match as im
import issue_eligibility as ie
from test_issue_match import FakeBatch, context, grants, anchor, NOW

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))  # synthetic test ONLY
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
CURRENT = NOW + timedelta(seconds=30)
CLOCK = lambda: CURRENT


def stamp(dt):
    return dt.isoformat(timespec='seconds').replace('+00:00', 'Z')


def base(provider='github', *, duplicate=False, n=1, privacy='PUBLIC', visibility='PUBLIC'):
    ctx = context(provider)
    a = anchor()
    repo = 'example/repo' if provider == 'github' else 'team/subteam/service'
    candidates = tuple(im.MatchCandidate(17 + i, (500421 if provider == 'github' else 812065) + i,
                                         (a,) if duplicate and i == 0 else ()) for i in range(n))
    mr = im.IssueMatchRequest(repo, 73142 if provider == 'github' else 903210,
                              candidates, (a,))
    mg, tg, rg = grants(ctx, mr)
    result = im.match_issues(ctx, mr, match_grant=mg, title_grant=tg,
                             issue_read_grants=rg, allow_network=True,
                             transport=FakeBatch(provider, mr),
                             token_supplier=lambda: 'synthetic-token',
                             clock=lambda: NOW)
    assert result['status'] == 'partial', result
    basis = ie.FindingBasis(
        finding_id='f'*64, finding_record_sha256='d'*64,
        source_binding_sha256='b'*64, source_mode='DeliveredTarget',
        source_revision=a.commit_sha,
        evidence_anchor_set_sha256=ie.anchor_set_sha256(mr.subject_anchors),
        positive_anchor_count=1, counter_anchor_count=0,
        assessment_state='REVIEWED', selected_source_count=1,
        observed_source_count=1, source_coverage='COMPLETE_SELECTED',
        observed_at_utc=stamp(NOW))
    policy = ie.PrivacyScope(privacy, visibility,
                             'ALLOW_REDACTED_LOCAL_REVIEW', 'e'*64)
    req = ie.EligibilityRequest(repo, mr.expected_repository_id, basis, policy)
    return ctx, req, mr, result


def model_live_shaped(synthetic_output):
    """SIMULATED provider shape ONLY; NOT attestation of a real provider call."""
    out = copy.deepcopy(synthetic_output)
    out['synthetic'] = False
    out['read_state'] = 'PROVIDER_OBSERVED'
    for e in out['entries']:
        if e['source'] is not None:
            e['source']['origin'] = 'FIXED_PROVIDER_HTTPS_VIA_EC211'
    return out


def signed(ctx, req, mr, result, *, expires=160, **override):
    doc = ie.HumanReviewReceipt(
        schema=ie.REVIEW_SCHEMA, method=ie.REVIEW_METHOD,
        reviewer_key_id='host-ec215-reviewer',
        evaluation_sha256=ie.evaluation_fingerprint(ctx, req, mr, result),
        decision='ACKNOWLEDGE_FOR_LOCAL_PROPOSAL_ONLY',
        acknowledges_selected_issues_not_inventory=True,
        acknowledges_duplicate_absence_unproven=True,
        acknowledges_source_and_signer_authority_unverified=True,
        issued_at_utc=stamp(NOW), expires_at_utc=stamp(NOW + timedelta(seconds=expires)),
        signature_base64='')
    doc = replace(doc, **override)
    return replace(doc, signature_base64=base64.b64encode(
        KEY.sign(ie.review_signing_bytes(doc))).decode('ascii'))


def check(ctx, req, mr, res, *, receipt=None, keys=None):
    return ie.evaluate_issue_eligibility(ctx, req, mr, res,
            review_receipt=receipt, trusted_review_keys=keys, clock=CLOCK)


class EC215(unittest.TestCase):
    def setUp(self):
        self.ctx, self.req, self.mr, self.synthetic = base()
        self.res = model_live_shaped(self.synthetic)
        self.receipt = signed(self.ctx, self.req, self.mr, self.res)
        self.keys = {'host-ec215-reviewer': PUB}

    def evaluate(self, **changes):
        data = dict(ctx=self.ctx, req=self.req, mr=self.mr, res=self.res,
                    receipt=self.receipt, keys=self.keys)
        data.update(changes)
        return check(*[data[k] for k in ('ctx', 'req', 'mr', 'res')],
                     receipt=data['receipt'], keys=data['keys'])

    def test_clean_host_review_allows_only_local_proposal(self):
        out = self.evaluate()
        self.assertEqual(out['eligibility'], 'ELIGIBLE_TO_PROPOSE')
        self.assertEqual(out['exit_code'], 2)
        self.assertEqual(out['authorization'], 'NOT_GRANTED')
        self.assertTrue(out['review_signature_cryptographically_valid'])
        self.assertTrue(out['unknown_missing_issue_inventory'])
        self.assertTrue(all(v is False for k, v in out.items() if k.endswith('_written')
                            or k in ('issue_create_authorized', 'issue_created',
                                     'duplicate_confirmed', 'no_duplicate_confirmed')))
        self.assertNotIn('\"title\":', json.dumps(out))
        self.assertNotIn('src/core/logic.py', json.dumps(out))

    def test_cryptographic_signature_cannot_grant_issue_create(self):
        out = self.evaluate()
        self.assertFalse(out['eligibility_is_authorization'])
        self.assertFalse(out['provider_or_existing_issue_written'])
        self.assertEqual(out['safe_next_step'], 'LOCAL_REDACTED_DRAFT_REVIEW_ONLY')

    def test_review_missing_needs_review(self):
        self.assertEqual(self.evaluate(receipt=None)['reason_code'],
                         'ISSUE_ELIGIBILITY_INDEPENDENT_REVIEW_RECEIPT_REQUIRED')

    def test_review_wrong_key_needs_review(self):
        self.assertEqual(self.evaluate(keys={'host-ec215-reviewer': bytes(32)})['eligibility'],
                         'NEEDS_REVIEW')

    def test_review_absent_key_mapping_needs_review(self):
        self.assertEqual(self.evaluate(keys=None)['eligibility'], 'NEEDS_REVIEW')

    def test_review_tampered_signature_needs_review(self):
        swapped = replace(self.receipt, signature_base64='A'*88)
        self.assertEqual(self.evaluate(receipt=swapped)['eligibility'], 'NEEDS_REVIEW')

    def test_review_binds_privacy_change_even_if_allowed(self):
        req = replace(self.req, privacy=replace(self.req.privacy,
                           policy_revision_sha256='c'*64))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'NEEDS_REVIEW')

    def test_review_binds_full_match_data(self):
        res = copy.deepcopy(self.res)
        res['entries'][0]['source']['snapshot_sha256'] = 'e'*64
        self.assertEqual(self.evaluate(res=res)['eligibility'], 'NEEDS_REVIEW')

    def test_review_expiration(self):
        late = signed(self.ctx, self.req, self.mr, self.res, expires=29)
        self.assertEqual(self.evaluate(receipt=late)['eligibility'], 'NEEDS_REVIEW')

    def test_reviewer_must_acknowledge_no_absence_proof(self):
        receipt = signed(self.ctx, self.req, self.mr, self.res,
                         acknowledges_duplicate_absence_unproven=False)
        self.assertEqual(self.evaluate(receipt=receipt)['eligibility'], 'NEEDS_REVIEW')

    def test_selected_no_hint_never_claims_repo_absence(self):
        out = self.evaluate()
        self.assertEqual(out['issue_match_selection_state'], 'SELECTED_NO_POSITIVE_HINT')
        self.assertFalse(out['no_duplicate_confirmed'])
        self.assertFalse(out['provider_repository_issue_inventory_complete'])
        self.assertFalse(out['match_receipt_source_authenticated'])

    def test_real_ec214_synthetic_shape_needs_review(self):
        receipt = signed(self.ctx, self.req, self.mr, self.synthetic)
        out = self.evaluate(res=self.synthetic, receipt=receipt)
        self.assertEqual(out['eligibility'], 'NEEDS_REVIEW')
        self.assertEqual(out['issue_match_selection_state'], 'SYNTHETIC_NEEDS_REVIEW')

    def test_declared_match_candidate_is_review_not_confirmed_duplicate(self):
        ctx, req, mr, result = base(duplicate=True)
        result = model_live_shaped(result)
        review = signed(ctx, req, mr, result)
        out = check(ctx, req, mr, result, receipt=review, keys=self.keys)
        self.assertEqual(out['eligibility'], 'NEEDS_REVIEW')
        self.assertEqual(out['issue_match_selection_state'], 'CANDIDATE_NEEDS_REVIEW')
        self.assertFalse(out['duplicate_confirmed'])

    def test_selected_issue_hidden_partial_means_unknown(self):
        ctx, req, mr, result = base(n=2)
        result = model_live_shaped(result)
        bad = result['entries'][1]
        bad.update(state='UNKNOWN', review_hint='UNKNOWN', anchor_matches=None,
                   title_similarity_hint='UNKNOWN', provider_confidentiality=None,
                   source=None, reason_code='ISSUE_MATCH_PROVIDER_UNKNOWN_OR_UNAVAILABLE')
        result['observed_count'] = 1
        result['unknown_count'] = 1
        result['coverage'] = 'PARTIAL_EXPLICIT_SELECTION_UNKNOWN'
        result['reason_code'] = 'ISSUE_MATCH_PARTIAL_SELECTION_UNKNOWN'
        att = signed(ctx, req, mr, result)
        self.assertEqual(check(ctx, req, mr, result, receipt=att,
                               keys=self.keys)['eligibility'], 'UNKNOWN')

    def test_no_match_receipt_means_unknown(self):
        out = self.evaluate(res=None)
        self.assertEqual(out['eligibility'], 'UNKNOWN')
        self.assertEqual(out['exit_code'], 5)

    def test_match_wrong_global_issue_id_unknown(self):
        res = copy.deepcopy(self.res)
        res['entries'][0]['expected_provider_issue_id'] = '9'
        self.assertEqual(self.evaluate(res=res)['eligibility'], 'UNKNOWN')

    def test_match_case_sensitive_path_drift_unknown(self):
        res = copy.deepcopy(self.res)
        res['scope']['repository'] = 'Example/repo'
        self.assertEqual(self.evaluate(res=res)['eligibility'], 'UNKNOWN')

    def test_match_added_raw_title_field_is_untrusted_unknown(self):
        res = copy.deepcopy(self.res)
        res['entries'][0]['source']['title'] = 'sensitive title'
        out = self.evaluate(res=res)
        self.assertEqual(out['eligibility'], 'UNKNOWN')
        self.assertNotIn('sensitive title', json.dumps(out))

    def test_match_altered_truth_flags_are_rejected(self):
        res = copy.deepcopy(self.res)
        res['no_duplicate_confirmed'] = True
        self.assertEqual(self.evaluate(res=res)['eligibility'], 'UNKNOWN')

    def test_match_identity_hash_unsafe_unknown(self):
        res = copy.deepcopy(self.res)
        res['entries'][0]['source']['identity_sha256'] = 'Z'*64
        self.assertEqual(self.evaluate(res=res)['eligibility'], 'UNKNOWN')

    def test_stale_match_observation_unknown(self):
        res = copy.deepcopy(self.res)
        res['entries'][0]['source']['observed_at_utc'] = stamp(NOW - timedelta(hours=1))
        self.assertEqual(self.evaluate(res=res)['eligibility'], 'UNKNOWN')

    def test_future_match_observation_unknown(self):
        res = copy.deepcopy(self.res)
        res['entries'][0]['source']['observed_at_utc'] = stamp(NOW + timedelta(hours=1))
        self.assertEqual(self.evaluate(res=res)['eligibility'], 'UNKNOWN')

    def test_stale_finding_evidence_unknown(self):
        old = replace(self.req.finding, observed_at_utc=stamp(NOW - timedelta(days=2)))
        out = self.evaluate(req=replace(self.req, finding=old))
        self.assertEqual(out['eligibility'], 'UNKNOWN')

    def test_future_finding_evidence_unknown(self):
        future = replace(self.req.finding, observed_at_utc=stamp(NOW + timedelta(days=1)))
        out = self.evaluate(req=replace(self.req, finding=future))
        self.assertEqual(out['eligibility'], 'UNKNOWN')

    def test_finding_rejected_blocks(self):
        req = replace(self.req, finding=replace(self.req.finding, assessment_state='REJECTED'))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'BLOCKED')

    def test_confidential_on_public_blocks(self):
        req = replace(self.req, privacy=replace(self.req.privacy, classification='CONFIDENTIAL'))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'BLOCKED')

    def test_internal_on_public_blocks(self):
        req = replace(self.req, privacy=replace(self.req.privacy, classification='INTERNAL'))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'BLOCKED')

    def test_restricted_on_private_blocks(self):
        req = replace(self.req, privacy=replace(self.req.privacy,
                      classification='RESTRICTED', target_visibility='PRIVATE'))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'BLOCKED')

    def test_explicit_privacy_deny_blocks(self):
        req = replace(self.req, privacy=replace(self.req.privacy, decision='DENY'))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'BLOCKED')

    def test_private_confidential_local_review_may_propose_not_publish(self):
        ctx, req, mr, res = base(privacy='CONFIDENTIAL', visibility='PRIVATE')
        res = model_live_shaped(res)
        att = signed(ctx, req, mr, res)
        out = check(ctx, req, mr, res, receipt=att, keys=self.keys)
        self.assertEqual(out['eligibility'], 'ELIGIBLE_TO_PROPOSE')
        self.assertFalse(out['raw_finding_or_issue_content_disclosed'])
        self.assertFalse(out['report_or_issue_content_published'])

    def test_unknown_visibility_unknown(self):
        req = replace(self.req, privacy=replace(self.req.privacy, target_visibility='UNKNOWN'))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'UNKNOWN')

    def test_privacy_revision_required_for_propose(self):
        req = replace(self.req, privacy=replace(self.req.privacy, policy_revision_sha256=None))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'NEEDS_REVIEW')

    def test_counterevidence_needs_review(self):
        req = replace(self.req, finding=replace(self.req.finding, counter_anchor_count=1))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'NEEDS_REVIEW')

    def test_unreviewed_semantics_needs_review(self):
        req = replace(self.req, finding=replace(self.req.finding, assessment_state='UNVERIFIED'))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'NEEDS_REVIEW')

    def test_worktree_not_promoted_to_delivered(self):
        req = replace(self.req, finding=replace(self.req.finding, source_mode='WorkingTree'))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'NEEDS_REVIEW')

    def test_proposed_pr_not_promoted_to_delivered(self):
        req = replace(self.req, finding=replace(self.req.finding, source_mode='ProposedPR'))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'NEEDS_REVIEW')

    def test_partial_source_coverage_needs_review(self):
        req = replace(self.req, finding=replace(self.req.finding,
                      selected_source_count=2, observed_source_count=1,
                      source_coverage='PARTIAL_SELECTED'))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'NEEDS_REVIEW')

    def test_unknown_source_coverage_unknown(self):
        req = replace(self.req, finding=replace(self.req.finding, source_coverage='UNKNOWN'))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'UNKNOWN')

    def test_positive_evidence_missing_unknown(self):
        req = replace(self.req, finding=replace(self.req.finding, positive_anchor_count=0))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'INVALID_INPUT')

    def test_anchor_hash_drift_invalid(self):
        req = replace(self.req, finding=replace(self.req.finding,
                      evidence_anchor_set_sha256='0'*64))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'INVALID_INPUT')

    def test_revision_binding_mismatch_invalid(self):
        req = replace(self.req, finding=replace(self.req.finding, source_revision='1'*40))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'INVALID_INPUT')

    def test_boolean_source_counts_invalid(self):
        req = replace(self.req, finding=replace(self.req.finding, observed_source_count=True))
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'INVALID_INPUT')

    def test_target_repo_mismatch_invalid(self):
        req = replace(self.req, repository='Another/repo')
        self.assertEqual(self.evaluate(req=req)['eligibility'], 'INVALID_INPUT')

    def test_gitlab_example(self):
        ctx, req, mr, res = base('gitlab')
        res = model_live_shaped(res)
        att = signed(ctx, req, mr, res)
        out = check(ctx, req, mr, res, receipt=att, keys=self.keys)
        self.assertEqual(out['eligibility'], 'ELIGIBLE_TO_PROPOSE')

    def test_fingerprint_changes_with_match_result(self):
        orig = ie.evaluation_fingerprint(self.ctx, self.req, self.mr, self.res)
        res = copy.deepcopy(self.res)
        res['entries'][0]['source']['snapshot_sha256'] = 'a'*64
        self.assertNotEqual(orig, ie.evaluation_fingerprint(self.ctx, self.req, self.mr, res))

    def test_cli_offline_untrusted_input_never_approves(self):
        payload = {
            'context': asdict(self.ctx),
            'request': asdict(self.req),
            'match_request': asdict(self.mr),
            'match_result': self.res,
        }
        proc = subprocess.run([sys.executable, str(Path(__file__).parent / 'issue_eligibility.py'),
                               '--stdin-json'], input=json.dumps(payload),
                              text=True, capture_output=True)
        out = json.loads(proc.stdout)
        self.assertIn(out['eligibility'], ('NEEDS_REVIEW', 'UNKNOWN'))  # no independent reviewer keys
        self.assertEqual(out['authorization'], 'NOT_GRANTED')
        self.assertEqual(proc.returncode, out['exit_code'])

    def test_three_json_schemas_enforce_request_review_result(self):
        root = Path(__file__).parent.parent / 'references'
        sreq, sreview, sout = [json.loads((root / f'issue-eligibility-{name}.v1.schema.json').read_text())
                               for name in ('request', 'review', 'result')]
        for sch in (sreq, sreview, sout):
            jsonschema.Draft202012Validator.check_schema(sch)
        jsonschema.validate(asdict(self.req), sreq)
        jsonschema.validate(asdict(self.receipt), sreview)
        for out in (self.evaluate(), self.evaluate(receipt=None), self.evaluate(res=None)):
            jsonschema.validate(out, sout)

    def test_result_schema_forbids_any_issue_write_claim(self):
        sch = json.loads((Path(__file__).parent.parent / 'references' /
                          'issue-eligibility-result.v1.schema.json').read_text())
        forged = self.evaluate()
        forged['issue_created'] = True
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(forged, sch)
        forged = self.evaluate()
        forged['authorization'] = 'GRANTED'
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(forged, sch)

    def test_signature_schema_forbids_weakening_acknowledgements(self):
        sch = json.loads((Path(__file__).parent.parent / 'references' /
                          'issue-eligibility-review.v1.schema.json').read_text())
        bad = asdict(self.receipt)
        bad['acknowledges_duplicate_absence_unproven'] = False
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(bad, sch)

    def test_receipt_cannot_hide_anchor_match(self):
        ctx, req, mr, res = base(duplicate=True)
        res = model_live_shaped(res)
        res['entries'][0]['anchor_matches'] = 0
        res['entries'][0]['review_hint'] = 'NO_POSITIVE_SIGNAL'
        res['review_candidate_count'] = 0
        att = signed(ctx, req, mr, res)
        out = check(ctx, req, mr, res, receipt=att, keys=self.keys)
        self.assertEqual(out['eligibility'], 'UNKNOWN')

    def test_cli_duplicate_object_key_rejected(self):
        proc = subprocess.run([sys.executable, str(Path(__file__).parent / 'issue_eligibility.py'),
                               '--stdin-json'], input='{"x":1,"x":2}',
                              text=True, capture_output=True)
        out = json.loads(proc.stdout)
        self.assertEqual(out['eligibility'], 'INVALID_INPUT')
        self.assertEqual(proc.returncode, 4)


if __name__ == '__main__':
    unittest.main()
