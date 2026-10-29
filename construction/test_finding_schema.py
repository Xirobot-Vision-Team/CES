#!/usr/bin/env python3
"""EC177 local synthetic behavior checks; no real Provider/AI/human/Git/CI acceptance."""
from __future__ import annotations

import copy
from datetime import timedelta
import json
import unittest
from unittest.mock import patch

import ai_handoff_router as ar
import codevalidate_staged as cv
import codesave_staged as cs
import finding_schema as fs
import handoff_lifecycle as lc
import task_staging as st
import test_codesave_staged as saved_fixtures
import test_codevalidate_staged as validation_fixtures
import codeprepare_multisource as ec170
import test_codeprepare_multisource as source_fixtures
from test_handoff_input import refreshed


class FindingSchemaCases(unittest.TestCase):
    # Reuse fixture creators, NOT the predecessor's entire test classes.
    setUp = saved_fixtures.CodeSaveCases.setUp
    setup_input = saved_fixtures.CodeSaveCases.setup_input
    act = saved_fixtures.CodeSaveCases.act
    candidate = saved_fixtures.CodeSaveCases.candidate
    callback = saved_fixtures.CodeSaveCases.callback
    dispatch = saved_fixtures.CodeSaveCases.dispatch
    prepare = validation_fixtures.CodeValidateCases.prepare
    validate = validation_fixtures.CodeValidateCases.validate
    review = validation_fixtures.CodeValidateCases.review
    review_key = staticmethod(validation_fixtures.CodeValidateCases.review_key)
    with_review = validation_fixtures.CodeValidateCases.with_review
    setup_save_store = saved_fixtures.CodeSaveCases.setup_save_store
    start = saved_fixtures.CodeSaveCases.start
    save = saved_fixtures.CodeSaveCases.save

    def setup_projection(self, *, signed=None, saved=False, historical=False):
        if saved:
            self.start(historical=historical)
            committed = self.save(
                approve_historical_proposal_metadata_save=historical,
                acknowledge_partial_coverage=historical)
            self.assertEqual(committed["status"], "partial", committed)
            self.original = self.validation
            self.review_receipt = self.signed_review
        else:
            self.prepare(historical=historical)
            self.review_receipt = self.review(signed) if signed is not None else None
            self.original = (self.with_review(receipt=self.review_receipt)
                             if signed is not None else self.validate())
        self.assertEqual(self.original["status"], "partial", self.original)
        self.projector = fs.FindingProjector(
            str(self.root), str(self.repo),
            save_root=str(self.save_root) if saved else None, clock=self.clock)
        self.proj_kw = dict(
            expected_parent_pin=self.pin, run_id=self.kw["run_id"],
            handoff_id=self.kw["handoff_id"], expected_revision=self.kw["expected_revision"],
            expected_event_sha256=self.kw["expected_event_sha256"],
            input_operation_key=self.kw["input_operation_key"],
            validation_operation_key=self.kw["validation_operation_key"],
            finding_operation_key="finding-schema-0001",
            expected_candidate_sha256=self.kw["expected_candidate_sha256"],
            expected_validation_receipt_sha256=self.original["validation_receipt_sha256"],
            authorize_project=True, authorize_read=True,
            project_content_for=self.prepared["source_mode"],
            allow_historical_proposal=historical,
            acknowledge_historical_only=historical,
        )
        if signed is not None or saved:
            self.proj_kw.update(
                manual_review=self.review_receipt, authorize_manual_review=True,
                manual_review_content_for=self.prepared["source_mode"],
                trusted_verifier_id="synthetic-reviewer",
                trusted_verifier_key=self.review_key(),
            )
        if saved:
            self.proj_kw.update(
                expected_save_store_pin=self.store_pin,
                save_operation_key="codesave-staged-0001",
                authorize_saved_link=True, authorize_saved_record_read=True)

    def project(self, **overrides):
        kw = dict(self.proj_kw)
        kw.update(overrides)
        return self.projector.project(self.prepared, self.outcome, self.original, **kw)

    def refused(self, response, expected=None):
        self.assertIn(response["status"], ("invalid_input", "unavailable"), response)
        if expected:
            self.assertEqual(response["reason_code"], expected, response)
        self.assertEqual(response["findings"], [])
        self.assertFalse(response["effects"]["findings_persisted"])
        self.assertFalse(response["effects"]["business_repository_written"])

    def test_unsigned_projection_has_stable_id_and_strict_semantics(self):
        self.setup_projection()
        first, second = self.project(), self.project()
        self.assertEqual((first["status"], first["exit_code"]), ("partial", 2), first)
        self.assertEqual(first, second)
        self.assertEqual(first["findings_count"], 1)
        item = first["findings"][0]
        self.assertEqual(item["schema"], fs.FINDING_SCHEMA)
        self.assertEqual(item["assessment"]["state"], "UNVERIFIED")
        self.assertEqual(item["classification"]["severity"]["value"], "medium")
        self.assertEqual(item["classification"]["confidence"]["value"], "low")
        self.assertEqual(item["assessment"]["possible_states"], list(fs.STATES))
        self.assertFalse(item["assessment"]["actually_tested"])
        self.assertFalse(item["assessment"]["semantically_confirmed_defect"])
        self.assertEqual(item["assertion"]["title"], None)
        self.assertEqual(item["evidence"]["positive_anchors"][0]["quote"], None)
        self.assertFalse(first["effects"]["ces_records_written"])

    def test_default_no_source_text_paths_or_notes_exfiltration(self):
        self.setup_projection()
        blob = json.dumps(self.project(), ensure_ascii=False)
        for phrase in ("diff --git", "+new", "read-only.py", "synthetic-test-actor",
                       "The added line", "Review the change manually",
                       "Synthetic patch line requires review"):
            self.assertNotIn(phrase, blob)
        self.assertIn("source_path_sha256", blob)
        self.assertIn("title_sha256", blob)

    def test_reviewed_is_only_hmac_key_holder_declaration(self):
        self.setup_projection(signed=("confirm",))
        result = self.project()
        self.assertEqual(result["status"], "partial", result)
        item = result["findings"][0]
        self.assertEqual(item["assessment"]["state"], "REVIEWED")
        self.assertIn("NOT_TRUTH", item["assessment"]["basis"])
        self.assertFalse(item["assessment"]["reviewer_real_identity_authenticated"])
        self.assertFalse(item["assessment"]["semantically_confirmed_defect"])
        self.assertIn("REMOTE_PROVIDER_AND_REVIEWER_REAL_IDENTITY_NOT_AUTHENTICATED",
                      item["uncertainty"])

    def test_rejected_declared_claim_is_not_objectively_proven_false(self):
        self.setup_projection(signed=("reject",))
        record = self.project()
        self.assertEqual(record["status"], "partial", record)
        self.assertEqual(record["findings"][0]["assessment"]["state"], "REJECTED")
        self.assertFalse(record["findings"][0]["assessment"]["actually_tested"])

    def test_inconclusive_claim_is_not_a_test_result(self):
        self.setup_projection(signed=("inconclusive",))
        record = self.project()
        self.assertEqual(record["status"], "partial", record)
        self.assertEqual(record["findings"][0]["assessment"]["state"], "INCONCLUSIVE")
        self.assertFalse(record["findings"][0]["assessment"]["actually_tested"])

    def test_multiple_distinct_claims_keep_independent_state_and_identity(self):
        self.setup_projection()
        def adapter(data, _provider, _timeout):
            obj = self.candidate(json.loads(data))
            other = copy.deepcopy(obj["findings"][0])
            other["title"] = "Independent second synthetic question"
            obj["findings"].append(other)
            return json.dumps(obj).encode()
        self.outcome = self.dispatch(adapter=adapter)
        self.kw["expected_candidate_sha256"] = self.outcome["result"]["candidate_sha256"]
        review = self.review(("confirm", "reject"))
        self.original = self.with_review(receipt=review)
        self.proj_kw.update(expected_candidate_sha256=self.kw["expected_candidate_sha256"],
                            expected_validation_receipt_sha256=self.original["validation_receipt_sha256"],
                            manual_review=review, authorize_manual_review=True,
                            manual_review_content_for=self.prepared["source_mode"],
                            trusted_verifier_id="synthetic-reviewer",
                            trusted_verifier_key=self.review_key())
        projected = self.project()
        self.assertEqual(projected["status"], "partial", projected)
        self.assertEqual([f["assessment"]["state"] for f in projected["findings"]],
                         ["REVIEWED", "REJECTED"])
        self.assertNotEqual(projected["findings"][0]["finding_id"],
                            projected["findings"][1]["finding_id"])

    def test_unkeyed_receipt_cannot_authenticate_edited_validation(self):
        self.setup_projection()
        faked = copy.deepcopy(self.original)
        faked["proof"]["ci_or_test_execution_observed"] = True
        faked["validation_receipt_sha256"] = cv._sha(cv.DOMAIN_RECEIPT, {
            k:v for k,v in faked.items() if k != "validation_receipt_sha256"
        })
        self.original = faked
        self.refused(self.project(expected_validation_receipt_sha256=faked["validation_receipt_sha256"]),
                     "CODESAVE_VALIDATION_SOURCE_CANDIDATE_REVIEW_OR_EFFECTS_CHANGED")

    def test_denies_any_missing_independent_projection_read_or_wrong_scope(self):
        self.setup_projection()
        for edit in ({"authorize_project": False}, {"authorize_read": False},
                     {"project_content_for": "ProposedPR"},
                     {"finding_operation_key": self.kw["input_operation_key"]},
                     {"finding_operation_key": self.kw["validation_operation_key"]}):
            with self.subTest(edit=edit):
                self.refused(self.project(**edit))

    def test_text_needs_separate_exact_source_grant(self):
        self.setup_projection()
        self.refused(self.project(disclose_text=True),
                     "FINDING_EXPLICIT_SOURCE_SCOPED_TEXT_DISCLOSURE_REQUIRED")
        self.refused(self.project(disclose_text=True, authorize_text_disclosure=True,
                                  disclose_content_for="ProposedPR"),
                     "FINDING_EXPLICIT_SOURCE_SCOPED_TEXT_DISCLOSURE_REQUIRED")
        self.refused(self.project(disclose_text=False, authorize_text_disclosure=True,
                                  disclose_content_for="WorkingTree"),
                     "FINDING_UNUSED_TEXT_GRANT_NOT_ACCEPTED")
        row = self.project(disclose_text=True, authorize_text_disclosure=True,
                           disclose_content_for="WorkingTree")["findings"][0]
        self.assertEqual(row["assertion"]["title"], "Synthetic patch line requires review")
        self.assertEqual(row["evidence"]["positive_anchors"][0]["quote"], "+new")
        self.assertNotIn("source_path", row["evidence"]["positive_anchors"][0])

    def test_counter_evidence_exact_line_observation_separate_from_interpretation(self):
        self.setup_projection()
        rows = [{"ordinal": 1, "anchors": [{
            "segment_index": 0, "item_index": None, "line_number": 4, "quote": "+new"
        }], "interpretation": "This line might not be executed."}]
        public = self.project(counter_evidence=rows)
        self.assertEqual(public["status"], "partial", public)
        evidence = public["findings"][0]["evidence"]
        self.assertEqual(len(evidence["counter_evidence"]), 1)
        self.assertIsNone(evidence["counter_evidence"][0]["interpretation"])
        self.assertFalse(evidence["counter_evidence"][0]["contradiction_semantically_proven"])
        disclosed = self.project(counter_evidence=rows, disclose_text=True,
                                 authorize_text_disclosure=True, disclose_content_for="WorkingTree")
        self.assertEqual(disclosed["findings"][0]["evidence"]["counter_evidence"][0]["anchors"][0]["quote"], "+new")
        self.assertIn("might", disclosed["findings"][0]["evidence"]["counter_evidence"][0]["interpretation"])
        self.assertNotEqual(public["projection_sha256"], disclosed["projection_sha256"])
        self.assertEqual(public["findings"][0]["finding_id"], disclosed["findings"][0]["finding_id"])

    def test_counter_evidence_fake_quote_and_wrong_source_anchor_refused(self):
        self.setup_projection()
        base = {"ordinal":1, "anchors":[{"segment_index":0,"item_index":None,
                                         "line_number":4,"quote":"+new"}],
                "interpretation":"Alternative reading"}
        for change in ({"quote":"fake"}, {"line_number":99999}, {"segment_index":33}):
            row = copy.deepcopy(base)
            row["anchors"][0].update(change)
            self.refused(self.project(counter_evidence=[row]))

    def test_counter_evidence_cannot_assert_external_test_truth_or_exfiltrate(self):
        self.setup_projection()
        base = {"ordinal":1, "anchors":[{"segment_index":0,"item_index":None,
                                         "line_number":4,"quote":"+new"}],
                "interpretation":"This was tested and proven"}
        extra=copy.deepcopy(base); extra["actually_tested"]=True
        self.refused(self.project(counter_evidence=[extra]),
                     "FINDING_COUNTER_EVIDENCE_FIELDS")
        secret=copy.deepcopy(base); secret["interpretation"]="-----BEGIN RSA PRIVATE KEY-----"
        self.refused(self.project(counter_evidence=[secret]))
        self.refused(self.project(counter_evidence=[base,base]),
                     "FINDING_COUNTER_DUPLICATE_ANCHOR")
        self.refused(self.project(counter_evidence=[dict(base,ordinal=2)]),
                     "FINDING_COUNTER_EVIDENCE_ORDINAL")

    def test_unsigned_no_records_can_still_form_empty_partial_projection(self):
        self.setup_projection()
        def adapter(data, _provider, _timeout):
            obj = self.candidate(json.loads(data))
            obj["findings"]=[]
            return json.dumps(obj).encode()
        self.outcome=self.dispatch(adapter=adapter)
        self.kw["expected_candidate_sha256"]=self.outcome["result"]["candidate_sha256"]
        self.original=self.validate(expected_candidate_sha256=self.kw["expected_candidate_sha256"])
        self.proj_kw.update(expected_candidate_sha256=self.kw["expected_candidate_sha256"],
                            expected_validation_receipt_sha256=self.original["validation_receipt_sha256"])
        result = self.project()
        self.assertEqual((result["status"], result["findings_count"]), ("partial", 0), result)
        self.assertFalse(result["effects"]["findings_persisted"])

    def test_real_saved_hmac_metadata_can_link_but_not_upgrade_truth(self):
        self.setup_projection(saved=True)
        result = self.project()
        self.assertEqual(result["status"], "partial", result)
        link = result["saved_metadata_link"]
        self.assertTrue(link["private_hmac_verified_this_call"])
        self.assertFalse(link["finding_was_persisted"])
        self.assertEqual(link["record_sha256"],
                         json.loads(next(self.save_root.glob("save_*.json")).read_text())["record_sha256"])
        self.assertEqual(result["findings"][0]["assessment"]["state"], "REVIEWED")
        self.assertFalse(result["findings"][0]["assessment"]["actually_tested"])

    def test_saved_link_rejects_independent_grant_pin_and_store_absence(self):
        self.setup_projection(saved=True)
        self.refused(self.project(authorize_saved_link=False),
                     "FINDING_INDEPENDENT_SAVED_LINK_AND_READ_GRANTS_REQUIRED")
        self.refused(self.project(authorize_saved_record_read=False))
        self.refused(self.project(expected_save_store_pin="a"*64))
        self.refused(self.project(save_operation_key="different-save-operation"))
        self.refused(self.project(save_operation_key=self.kw["input_operation_key"]))
        # Supplying an unauthenticated JSON copy never provides a saved record.
        detached = fs.FindingProjector(str(self.root),str(self.repo),clock=self.clock)
        response=detached.project(self.prepared,self.outcome,self.original,**self.proj_kw)
        self.refused(response,"FINDING_INDEPENDENT_SAVED_LINK_AND_READ_GRANTS_REQUIRED")

    def test_saved_hmac_edit_is_detected_without_finding_emission(self):
        self.setup_projection(saved=True)
        record_file=next(self.save_root.glob("save_*.json"))
        blob=json.loads(record_file.read_text())
        blob["verified_ci_or_test"]=True
        record_file.write_text(json.dumps(blob))
        self.refused(self.project())

    def test_saved_record_without_current_review_cannot_link(self):
        self.setup_projection(saved=True)
        self.refused(self.project(manual_review=None,
                                  authorize_manual_review=False,
                                  manual_review_content_for=None,
                                  trusted_verifier_id=None,
                                  trusted_verifier_key=None))

    def test_saved_private_record_expiry_refuses_replay(self):
        self.setup_projection(saved=True)
        self.clock.value += timedelta(seconds=150)  # review/store expired at 120s
        self.refused(self.project())

    def test_counter_evidence_is_not_writable_and_source_root_untouched(self):
        self.setup_projection()
        stage_bytes={p.name:p.read_bytes() for p in self.root.iterdir() if p.is_file()}
        repo_bytes=(self.repo/"read-only.py").read_bytes()
        self.project(counter_evidence=[{"ordinal":1,"anchors":[{
            "segment_index":0,"item_index":None,"line_number":4,"quote":"+new"}],
            "interpretation":"Uncertain alternate explanation"}])
        self.assertEqual(stage_bytes,{p.name:p.read_bytes() for p in self.root.iterdir() if p.is_file()})
        self.assertEqual(repo_bytes,(self.repo/"read-only.py").read_bytes())

    def test_expired_source_and_tampered_sealed_input_refuse(self):
        self.setup_projection()
        self.clock.value += timedelta(seconds=340)
        self.refused(self.project())
        self.clock.value -= timedelta(seconds=340)
        self.input_path.write_bytes(b"not an HMAC sealed input")
        self.refused(self.project())

    def test_postflight_validation_change_fail_closed(self):
        self.setup_projection()
        genuine=self.projector.validator.validate
        counter=[0]
        def altered(*args,**kwargs):
            counter[0]+=1
            result=genuine(*args,**kwargs)
            if counter[0]==2:
                result["status"]="unavailable"
                result["reason_code"]="SYNTHETIC_SOURCE_CHANGED_AFTER_READ"
            return result
        with patch.object(self.projector.validator,"validate",side_effect=altered):
            self.refused(self.project(),"FINDING_POSTFLIGHT_VALIDATION_REFUSED_SYNTHETIC_SOURCE_CHANGED_AFTER_READ")

    def test_caller_mutation_after_final_validation_cannot_retarget_finding(self):
        self.setup_projection()
        genuine = self.projector.validator.validate
        calls = [0]
        def mutate_after_validation(*args, **kwargs):
            calls[0] += 1
            checked = genuine(*args, **kwargs)
            if calls[0] == 2:
                # Simulate concurrent attacker changing caller-owned route object
                # only after the genuine second EC175 pass was completed.
                self.outcome["result"]["findings"][0]["title"] = "INJECTED POST VALIDATION"
            return checked
        with patch.object(self.projector.validator, "validate",
                          side_effect=mutate_after_validation):
            output = self.project(disclose_text=True,
                                  authorize_text_disclosure=True,
                                  disclose_content_for="WorkingTree")
        self.assertEqual(output["status"], "partial", output)
        self.assertEqual(output["findings"][0]["assertion"]["title"],
                         "Synthetic patch line requires review")
        self.assertNotIn("INJECTED POST VALIDATION", json.dumps(output))

    def test_saved_link_nonboolean_permission_is_not_ignored(self):
        self.setup_projection()
        self.refused(self.project(authorize_saved_link="yes"),
                     "FINDING_SAVED_LINK_PERMISSION_TYPE_INVALID")
        self.refused(self.project(authorize_saved_record_read=1),
                     "FINDING_SAVED_LINK_PERMISSION_TYPE_INVALID")

    def test_historical_proposal_ack_preserves_not_current(self):
        snap,_=source_fixtures.ec165.create(selected=("src/service.py",),include=True)
        source=ec170.prepare_context("ProposedPR",proposed_snapshot=snap,
                                      content_permission="ProposedPR")
        self.setup_input(refreshed(source,self.clock.value),historical=True)
        self.validator=cv.StagedCodeValidator(str(self.root),str(self.repo),clock=self.clock)
        def adapter(data,_p,_t):
            return json.dumps(self.candidate(json.loads(data),anchors=[{
                "segment_index":0,"item_index":0,"line_number":3,"quote":"+new = 2"}])).encode()
        self.outcome=self.dispatch(adapter=adapter)
        self.kw=dict(expected_parent_pin=self.pin,run_id=self.route_opts["run_id"],
                     handoff_id=self.route_opts["handoff_id"],
                     expected_revision=self.route_opts["expected_revision"],
                     expected_event_sha256=self.route_opts["expected_event_sha256"],
                     input_operation_key=self.route_opts["operation_key"],
                     validation_operation_key="codevalidate-staged-0001",
                     authorize_validate=True,authorize_read=True,
                     validate_content_for="ProposedPR",
                     expected_candidate_sha256=self.outcome["result"]["candidate_sha256"],
                     allow_historical_proposal=True,max_source_age_seconds=600)
        self.original=self.validate()
        self.projector=fs.FindingProjector(str(self.root),str(self.repo),clock=self.clock)
        self.proj_kw=dict(expected_parent_pin=self.pin,run_id=self.kw["run_id"],
                          handoff_id=self.kw["handoff_id"],
                          expected_revision=self.kw["expected_revision"],
                          expected_event_sha256=self.kw["expected_event_sha256"],
                          input_operation_key=self.kw["input_operation_key"],
                          validation_operation_key=self.kw["validation_operation_key"],
                          finding_operation_key="finding-schema-0001",
                          expected_candidate_sha256=self.kw["expected_candidate_sha256"],
                          expected_validation_receipt_sha256=self.original["validation_receipt_sha256"],
                          authorize_project=True,authorize_read=True,
                          project_content_for="ProposedPR",allow_historical_proposal=True,
                          acknowledge_historical_only=True)
        self.refused(self.project(acknowledge_historical_only=False),
                     "FINDING_HISTORICAL_ONLY_SEPARATE_ACKNOWLEDGMENT_REQUIRED")
        row=self.project()
        self.assertEqual(row["status"],"partial",row)
        self.assertTrue(row["findings"][0]["coverage"]["historical_proposal_only"])
        self.assertIn("HISTORICAL_PROPOSAL_NOT_CURRENT_DELIVERED_CODE",
                      row["findings"][0]["uncertainty"])

    def test_new_projection_operation_does_not_change_stable_identity(self):
        self.setup_projection()
        a=self.project()
        b=self.project(finding_operation_key="finding-schema-0002")
        self.assertEqual(a["findings"][0]["finding_id"],b["findings"][0]["finding_id"])
        self.assertEqual(a["projection_sha256"],b["projection_sha256"])


if __name__=="__main__":
    unittest.main(verbosity=2)
