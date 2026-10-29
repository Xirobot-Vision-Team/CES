#!/usr/bin/env python3
"""EC216 focused local/synthetic tests, NOT real provider/source acceptance."""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import jsonschema

import issue_provider as ip
import issue_match as im
import issue_eligibility as ie
import issue_plan as plan
from test_issue_eligibility import base, model_live_shaped, signed, PUB, CURRENT, CLOCK


def prepared(provider='github', **kwargs):
    ctx, req, mr, simulated = base(provider, **kwargs)
    receipt_data = model_live_shaped(simulated)  # fabricated provider origin!
    review = signed(ctx, req, mr, receipt_data)
    keys = {'host-ec215-reviewer': PUB}
    eligibility = ie.evaluate_issue_eligibility(
        ctx, req, mr, receipt_data, review_receipt=review,
        trusted_review_keys=keys, clock=CLOCK)
    assert eligibility['eligibility'] == 'ELIGIBLE_TO_PROPOSE', eligibility
    anchor = mr.subject_anchors[0]
    intent = plan.IssuePlanRequest(
        target_provider=ctx.provider, target_repository=mr.repository,
        expected_repository_id=mr.expected_repository_id,
        target_visibility=req.privacy.target_visibility,
        expected_evaluation_sha256=eligibility['evaluation_sha256'],
        expected_match_receipt_sha256=eligibility['issue_match_receipt_sha256'],
        expected_eligibility_result_sha256=plan.eligibility_result_sha256(eligibility),
        expected_review_receipt_sha256=plan.review_receipt_sha256(review),
        finding_record_sha256=req.finding.finding_record_sha256,
        source_binding_sha256=req.finding.source_binding_sha256,
        source_mode=req.finding.source_mode,
        source_revision=req.finding.source_revision,
        evidence_anchor_set_sha256=req.finding.evidence_anchor_set_sha256,
        policy_revision_sha256=req.privacy.policy_revision_sha256,
        topic='RELIABILITY', concern='ERROR_HANDLING',
        selected_sources=(plan.SelectedSourceRef(
            0, plan.source_anchor_sha256(anchor)),),
    )
    return dict(context=ctx, intent=intent, eligibility_request=req,
                match_request=mr, match_result=receipt_data,
                eligibility_result=eligibility, review_receipt=review,
                trusted_review_keys=keys, clock=CLOCK)


class EC216(unittest.TestCase):
    def setUp(self):
        self.args = prepared()

    def run_plan(self, **changes):
        return plan.draft_issue_plan(**{**self.args, **changes})

    def test_clean_local_preview_requires_exact_eligible_result(self):
        out = self.run_plan()
        self.assertEqual(out['plan_state'], 'DRAFT_READY')
        self.assertEqual(out['status'], 'partial')
        self.assertEqual(out['exit_code'], 2)
        self.assertTrue(out['draft_generated_locally'])
        self.assertEqual(out['delivery_state'], 'NOT_ATTEMPTED')
        self.assertEqual(out['approval'], 'NOT_GRANTED')
        self.assertEqual(out['draft']['authorization'], 'NOT_GRANTED')
        self.assertFalse(out['draft']['issue_created'])
        self.assertEqual(out['draft']['content_source'],
                         'BUILT_IN_CLOSED_VOCABULARY')
        self.assertTrue(out['draft']['suggested_title'].startswith('Investigate potential'))
        self.assertTrue(all(v is False for k, v in out.items()
                            if k in plan._flags()))

    def test_gitlab_exact_repository_pin_is_bound(self):
        out = plan.draft_issue_plan(**prepared('gitlab'))
        self.assertEqual(out['plan_state'], 'DRAFT_READY')
        self.assertEqual(out['draft']['target']['provider'], 'gitlab')
        self.assertNotIn('subteam', json.dumps(out))

    def test_draft_omits_remote_titles_private_paths_repo_ids_and_tokens(self):
        out = self.run_plan()
        dumped = json.dumps(out, ensure_ascii=False)
        for private in ('example/repo', 'src/core/logic.py',
                        self.args['match_request'].subject_anchors[0].path,
                        'synthetic-token', '73142', '500421',
                        self.args['intent'].source_revision, 'host-ec215-reviewer'):
            self.assertNotIn(private, dumped)
        self.assertIn('E01', out['draft']['suggested_body'])
        self.assertNotIn('E01', out['draft']['suggested_title'])

    def test_closed_topic_templates_are_bounded_and_are_not_raw_finding(self):
        for topic, (_, choices) in plan.TOPICS.items():
            for concern in choices:
                with self.subTest(topic=topic, concern=concern):
                    intent = replace(self.args['intent'], topic=topic, concern=concern)
                    out = self.run_plan(intent=intent)
                    self.assertEqual(out['plan_state'], 'DRAFT_READY')
                    self.assertLessEqual(len(out['draft']['suggested_body']),
                                         plan.MAX_BODY_CHARS)
                    self.assertLessEqual(len(out['draft']['suggested_title']),
                                         plan.MAX_TITLE_CHARS)
                    self.assertNotIn('example/repo', out['draft']['suggested_body'])

    def test_draft_fingerprint_changes_for_a_different_approved_topic(self):
        a = self.run_plan()
        b = self.run_plan(intent=replace(self.args['intent'],
                                         topic='PERFORMANCE', concern='LATENCY'))
        self.assertNotEqual(a['draft']['plan_sha256'], b['draft']['plan_sha256'])
        self.assertEqual(a['evaluation_sha256'], b['evaluation_sha256'])

    def test_explicit_reference_index_and_digest_bound_to_original_anchor(self):
        out = self.run_plan()
        self.assertEqual(out['draft']['references'][0]['anchor_index'], 0)
        self.assertTrue(out['draft']['references'][0]['locator_redacted'])
        self.assertEqual(out['draft']['references'][0]['anchor_binding_sha256'],
                         self.args['intent'].selected_sources[0].expected_anchor_sha256)

    def test_empty_sources_invalid(self):
        out = self.run_plan(intent=replace(self.args['intent'], selected_sources=()))
        self.assertEqual(out['plan_state'], 'INVALID_INPUT')
        self.assertIsNone(out['draft'])

    def test_duplicate_source_index_invalid(self):
        ref = self.args['intent'].selected_sources[0]
        out = self.run_plan(intent=replace(self.args['intent'],
                                           selected_sources=(ref, ref)))
        self.assertEqual(out['reason_code'], 'ISSUE_PLAN_SOURCE_SELECTION_INVALID')

    def test_unsorted_source_indices_invalid(self):
        ref = self.args['intent'].selected_sources[0]
        out = self.run_plan(intent=replace(self.args['intent'],
            selected_sources=(replace(ref, anchor_index=1), ref)))
        self.assertEqual(out['plan_state'], 'INVALID_INPUT')

    def test_out_of_range_reference_index_invalid(self):
        ref = replace(self.args['intent'].selected_sources[0], anchor_index=1)
        out = self.run_plan(intent=replace(self.args['intent'], selected_sources=(ref,)))
        self.assertEqual(out['reason_code'], 'ISSUE_PLAN_SOURCE_INDEX_OUT_OF_RANGE')

    def test_reference_sha_mismatch_unknown(self):
        ref = replace(self.args['intent'].selected_sources[0],
                      expected_anchor_sha256='0'*64)
        out = self.run_plan(intent=replace(self.args['intent'],
                                           selected_sources=(ref,)))
        self.assertEqual(out['plan_state'], 'UNKNOWN')
        self.assertEqual(out['reason_code'], 'ISSUE_PLAN_SOURCE_REFERENCE_STALE')

    def test_missing_result_unknown_even_if_review_was_signed(self):
        out = self.run_plan(eligibility_result=None)
        self.assertEqual(out['reason_code'], 'ISSUE_PLAN_EC215_RESULT_DRIFT')
        self.assertIsNone(out['draft'])

    def test_forged_eligible_result_never_bypasses_expired_gate(self):
        late = lambda: CURRENT + timedelta(days=3)
        out = self.run_plan(clock=late)
        self.assertEqual(out['plan_state'], 'UNKNOWN')
        self.assertIsNone(out['draft'])

    def test_forged_result_modified_reason_unknown(self):
        spoof = copy.deepcopy(self.args['eligibility_result'])
        spoof['reason_code'] = 'ISSUE_ELIGIBILITY_FORGED_SUCCESS'
        out = self.run_plan(eligibility_result=spoof)
        self.assertEqual(out['reason_code'], 'ISSUE_PLAN_EC215_RESULT_DRIFT')

    def test_forged_result_boolean_as_integer_unknown(self):
        spoof = copy.deepcopy(self.args['eligibility_result'])
        spoof['review_signature_cryptographically_valid'] = 1  # 1 == True in Python!
        out = self.run_plan(eligibility_result=spoof)
        self.assertEqual(out['reason_code'], 'ISSUE_PLAN_EC215_RESULT_DRIFT')

    def test_missing_reviewer_key_no_draft(self):
        out = self.run_plan(trusted_review_keys=None)
        self.assertEqual(out['plan_state'], 'NEEDS_REVIEW')
        self.assertIsNone(out['draft'])

    def test_review_signature_tampering_no_draft(self):
        review = replace(self.args['review_receipt'], signature_base64='A'*88)
        out = self.run_plan(review_receipt=review)
        self.assertEqual(out['plan_state'], 'NEEDS_REVIEW')

    def test_review_signature_hash_pin_changed_unknown(self):
        intent = replace(self.args['intent'], expected_review_receipt_sha256='1'*64)
        out = self.run_plan(intent=intent)
        self.assertEqual(out['reason_code'], 'ISSUE_PLAN_INPUT_REVIEW_OR_RECEIPT_DRIFT')

    def test_eligibility_result_digest_pin_changed_unknown(self):
        intent = replace(self.args['intent'], expected_eligibility_result_sha256='1'*64)
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'UNKNOWN')

    def test_original_evaluation_digest_pin_changed_unknown(self):
        intent = replace(self.args['intent'], expected_evaluation_sha256='1'*64)
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'UNKNOWN')

    def test_original_match_receipt_digest_pin_changed_unknown(self):
        intent = replace(self.args['intent'], expected_match_receipt_sha256='1'*64)
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'UNKNOWN')

    def test_inconsistent_original_match_result_fails_closed(self):
        res = copy.deepcopy(self.args['match_result'])
        res['entries'][0]['source']['snapshot_sha256'] = '1'*64
        out = self.run_plan(match_result=res)
        self.assertNotEqual(out['plan_state'], 'DRAFT_READY')
        self.assertIsNone(out['draft'])

    def test_unknown_missing_match_receipt_no_draft(self):
        out = self.run_plan(match_result=None)
        self.assertEqual(out['plan_state'], 'UNKNOWN')
        self.assertIsNone(out['draft'])

    def test_synthetic_observation_not_promoted(self):
        args = prepared()
        syn = base()[3]
        args['match_result'] = syn
        args['review_receipt'] = signed(args['context'], args['eligibility_request'],
                                        args['match_request'], syn)
        out = plan.draft_issue_plan(**args)
        self.assertEqual(out['plan_state'], 'NEEDS_REVIEW')

    def test_positive_candidate_hint_requires_review(self):
        ctx, req, mr, syn = base(duplicate=True)
        res = model_live_shaped(syn)
        review = signed(ctx, req, mr, res)
        out = self.run_plan(context=ctx, eligibility_request=req, match_request=mr,
                            match_result=res, review_receipt=review)
        self.assertEqual(out['plan_state'], 'NEEDS_REVIEW')

    def test_misdirected_target_repo_blocked(self):
        intent = replace(self.args['intent'], target_repository='different/repo')
        out = self.run_plan(intent=intent)
        self.assertEqual(out['reason_code'],
                         'ISSUE_PLAN_TARGET_REPOSITORY_OR_VISIBILITY_CONFLICT')
        self.assertEqual(out['plan_state'], 'BLOCKED')

    def test_misdirected_numeric_repository_id_blocked(self):
        intent = replace(self.args['intent'], expected_repository_id=73143)
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'BLOCKED')

    def test_misdirected_visibility_blocked(self):
        intent = replace(self.args['intent'], target_visibility='PRIVATE')
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'BLOCKED')

    def test_wrong_provider_blocked(self):
        intent = replace(self.args['intent'], target_provider='gitlab')
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'BLOCKED')

    def test_replaced_source_revision_unknown(self):
        intent = replace(self.args['intent'], source_revision='b'*40)
        out = self.run_plan(intent=intent)
        self.assertEqual(out['reason_code'], 'ISSUE_PLAN_FINDING_SOURCE_OR_POLICY_DRIFT')

    def test_replaced_source_binding_unknown(self):
        intent = replace(self.args['intent'], source_binding_sha256='a'*64)
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'UNKNOWN')

    def test_replaced_finding_record_unknown(self):
        intent = replace(self.args['intent'], finding_record_sha256='a'*64)
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'UNKNOWN')

    def test_replaced_policy_revision_unknown(self):
        intent = replace(self.args['intent'], policy_revision_sha256='a'*64)
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'UNKNOWN')

    def test_confidential_private_still_only_redacted(self):
        args = prepared(privacy='CONFIDENTIAL', visibility='PRIVATE')
        out = plan.draft_issue_plan(**args)
        self.assertEqual(out['plan_state'], 'DRAFT_READY')
        self.assertEqual(out['draft']['target']['visibility'], 'PRIVATE')
        self.assertNotIn('CONFIDENTIAL', out['draft']['suggested_body'])

    def test_internal_public_is_hard_blocked(self):
        args = prepared()
        req = replace(args['eligibility_request'], privacy=replace(
            args['eligibility_request'].privacy, classification='INTERNAL'))
        out = self.run_plan(eligibility_request=req)
        self.assertEqual(out['plan_state'], 'BLOCKED')

    def test_denied_privacy_hard_blocked(self):
        req = replace(self.args['eligibility_request'], privacy=replace(
            self.args['eligibility_request'].privacy, decision='DENY'))
        out = self.run_plan(eligibility_request=req)
        self.assertEqual(out['plan_state'], 'BLOCKED')

    def test_unknown_privacy_does_not_draft(self):
        req = replace(self.args['eligibility_request'], privacy=replace(
            self.args['eligibility_request'].privacy, decision='UNKNOWN'))
        out = self.run_plan(eligibility_request=req)
        self.assertEqual(out['plan_state'], 'UNKNOWN')

    def test_invalid_request_category_no_preview(self):
        intent = replace(self.args['intent'], topic='SECRET_CUSTOM_LABEL')
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'INVALID_INPUT')

    def test_mismatched_topic_concern_no_preview(self):
        intent = replace(self.args['intent'], topic='PERFORMANCE',
                         concern='ERROR_HANDLING')
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'INVALID_INPUT')

    def test_invalid_hash_pin_no_preview(self):
        intent = replace(self.args['intent'], expected_evaluation_sha256='x')
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'INVALID_INPUT')

    def test_bool_as_expected_repo_id_is_rejected(self):
        intent = replace(self.args['intent'], expected_repository_id=True)
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'INVALID_INPUT')

    def test_ref_index_bool_is_rejected(self):
        ref = replace(self.args['intent'].selected_sources[0], anchor_index=True)
        intent = replace(self.args['intent'], selected_sources=(ref,))
        out = self.run_plan(intent=intent)
        self.assertEqual(out['plan_state'], 'INVALID_INPUT')

    def test_input_is_bounded_and_nonfinite_receipt_denied(self):
        res = copy.deepcopy(self.args['match_result'])
        res['injected'] = 'x' * (plan.MAX_INPUT_BYTES + 1)
        self.assertEqual(self.run_plan(match_result=res)['plan_state'], 'INVALID_INPUT')
        res = copy.deepcopy(self.args['match_result'])
        res['injected'] = float('nan')
        self.assertNotEqual(self.run_plan(match_result=res)['plan_state'], 'DRAFT_READY')

    def test_untrusted_eligibility_result_oversized_rejected(self):
        res = copy.deepcopy(self.args['eligibility_result'])
        res['injected'] = 'x' * (plan.MAX_INPUT_BYTES + 1)
        self.assertEqual(self.run_plan(eligibility_result=res)['plan_state'],
                         'INVALID_INPUT')

    def test_no_network_or_provider_read_invocation_from_ec216(self):
        with patch.object(im, 'match_issues', side_effect=AssertionError('remote')):
            with patch.object(ip, 'read_issue', side_effect=AssertionError('remote')):
                out = self.run_plan()
        self.assertEqual(out['plan_state'], 'DRAFT_READY')

    def test_schema_rejects_forged_creation_and_draft_on_block(self):
        schema = json.loads((Path(__file__).resolve().parent.parent /
                             'references/issue-plan-result.v1.schema.json').read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        original = self.run_plan()
        validator.validate(original)
        bad = copy.deepcopy(original)
        bad['issue_create_authorized'] = True
        self.assertFalse(validator.is_valid(bad))
        bad = self.run_plan(eligibility_result=None)
        validator.validate(bad)
        bad['draft'] = original['draft']
        self.assertFalse(validator.is_valid(bad))

    def test_request_schema_validates_and_rejects_extras(self):
        from dataclasses import asdict
        schema = json.loads((Path(__file__).resolve().parent.parent /
                             'references/issue-plan-request.v1.schema.json').read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        wire = json.loads(json.dumps(asdict(self.args['intent'])))
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(wire)
        wire['raw_source_bytes'] = 'private'
        self.assertFalse(validator.is_valid(wire))

    def test_output_states_have_explicit_exit_code_mapping(self):
        eligible = self.run_plan()
        unknown = self.run_plan(eligibility_result=None)
        invalid = self.run_plan(intent=replace(self.args['intent'], topic='NOT_ALLOWED'))
        blocked = self.run_plan(intent=replace(self.args['intent'], target_visibility='PRIVATE'))
        review = self.run_plan(trusted_review_keys=None)
        self.assertEqual([(x['plan_state'], x['exit_code']) for x in
                          (eligible, unknown, invalid, blocked, review)], [
                              ('DRAFT_READY', 2), ('UNKNOWN', 5),
                              ('INVALID_INPUT', 4), ('BLOCKED', 2),
                              ('NEEDS_REVIEW', 2)])


if __name__ == '__main__':
    unittest.main()
