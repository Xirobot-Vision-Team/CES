#!/usr/bin/env python3
"""EC175 focused synthetic Staged CodeValidate tests; NOT live AI/Git/CI."""
from __future__ import annotations

import copy
from datetime import timedelta
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import ai_handoff_router as ar
import codevalidate_staged as cv
import codeprepare_multisource as ec170
import task_staging as st
import test_codeprepare_multisource as fx
import test_ai_handoff_router as route_fixtures
from test_handoff_input import refreshed


class CodeValidateCases(unittest.TestCase):
    # Use only the EC174 fixture *builder* methods, not inherited EC174 tests.
    setUp = route_fixtures.RouteCases.setUp
    setup_input = route_fixtures.RouteCases.setup_input
    act = route_fixtures.RouteCases.act
    candidate = route_fixtures.RouteCases.candidate
    callback = route_fixtures.RouteCases.callback
    dispatch = route_fixtures.RouteCases.dispatch

    def prepare(self, *, historical=False, prepared=None, input_ttl=300):
        self.setup_input(prepared, historical=historical, input_ttl=input_ttl)
        self.validator = cv.StagedCodeValidator(str(self.root), str(self.repo), clock=self.clock)
        self.outcome = self.dispatch()
        self.assertEqual(self.outcome["reason_code"], "AI_CANDIDATE_RECEIVED_UNVERIFIED")
        self.kw = dict(
            expected_parent_pin=self.pin,
            run_id=self.route_opts["run_id"], handoff_id=self.route_opts["handoff_id"],
            expected_revision=self.route_opts["expected_revision"],
            expected_event_sha256=self.route_opts["expected_event_sha256"],
            input_operation_key=self.route_opts["operation_key"],
            validation_operation_key="codevalidate-staged-0001",
            authorize_validate=True, authorize_read=True,
            validate_content_for=self.prepared["source_mode"],
            expected_candidate_sha256=self.outcome["result"]["candidate_sha256"],
            allow_historical_proposal=historical,
            max_source_age_seconds=600,
        )
        return self.outcome

    def validate(self, **overrides):
        args = dict(self.kw)
        args.update(overrides)
        return self.validator.validate(self.prepared, self.outcome, **args)

    def deny(self, code, response, status=None):
        self.assertEqual(response["reason_code"], code, response)
        if status:
            self.assertEqual(response["status"], status)
        self.assertEqual(response["candidate"]["state"], "REJECTED")
        self.assertEqual(response["candidate"]["findings"], [])
        self.assertFalse(response["effects"]["codesave_authorized"])
        self.assertFalse(response["effects"]["ces_record_or_finding_saved"])

    def review(self, decisions=("confirm",), **changes):
        now = self.clock.value
        receipt = {
            "schema": cv.REVIEW_SCHEMA,
            "method": "independent_manual_source_review",
            "verifier_id": "synthetic-reviewer",
            "source_binding": self.outcome["source_binding"],
            "candidate_sha256": self.outcome["result"]["candidate_sha256"],
            "validation_operation_key": self.kw["validation_operation_key"],
            "reviewed_at_utc": st._stamp(now),
            "expires_at_utc": st._stamp(now + timedelta(seconds=120)),
            "decisions": [{
                "ordinal": i,
                "finding_sha256": cv._sha(cv.DOMAIN_FINDING, f),
                "verdict": d,
                "review_notes": "Independent synthetic review has inspected the source anchor.",
            } for i, (d, f) in enumerate(zip(decisions, self.outcome["result"]["findings"]), 1)],
        }
        receipt.update(changes)
        receipt["mac_sha256"] = hmac.new(
            self.review_key(), cv.DOMAIN_REVIEW + st._canonical(receipt), hashlib.sha256
        ).hexdigest()
        return receipt

    @staticmethod
    def review_key():
        return b"fixture-review-key-DO-NOT-USE" + bytes(range(16))

    def with_review(self, *, receipt=None, **changes):
        args = dict(manual_review=receipt or self.review(), authorize_manual_review=True,
                    manual_review_content_for=self.prepared["source_mode"],
                    trusted_verifier_id="synthetic-reviewer",
                    trusted_verifier_key=self.review_key())
        args.update(changes)
        return self.validate(**args)

    def test_real_ec170_171_172_173_174_chain_is_consumed_read_only(self):
        self.prepare()
        before_root = {f: (self.root / f).read_bytes() for f in self.root.iterdir() if f.is_file()}
        before_repo = (self.repo / "read-only.py").read_bytes()
        response = self.validate()
        self.assertEqual((response["status"], response["exit_code"]), ("partial", 2))
        self.assertEqual(response["mode"], "Staged")
        self.assertEqual(response["candidate"]["state"], "STRUCTURALLY_CHECKED_DRAFT")
        self.assertEqual(response["candidate"]["findings_count"], 1)
        self.assertEqual(response["candidate"]["findings"][0]["review_state"],
                         "UNVERIFIED_SEMANTIC_ASSERTION")
        self.assertTrue(response["proof"]["ec172_ec173_integrity_and_expiry_rechecked"])
        self.assertFalse(response["proof"]["source_currentness_proven"])
        self.assertFalse(response["effects"]["eligible_for_automatic_codesave"])
        self.assertEqual(before_root, {f: (self.root / f).read_bytes() for f in self.root.iterdir() if f.is_file()})
        self.assertEqual((self.repo / "read-only.py").read_bytes(), before_repo)
        self.assertNotIn("+new", json.dumps(response))
        self.assertNotIn("diff --git", json.dumps(response))
        self.assertEqual(len(response["validation_receipt_sha256"]), 64)

    def test_explicit_independent_validation_and_input_read_grants(self):
        self.prepare()
        self.deny("CODEVALIDATE_INDEPENDENT_VALIDATION_APPROVAL_REQUIRED",
                  self.validate(authorize_validate=False))
        self.deny("CODEVALIDATE_INDEPENDENT_INPUT_READ_APPROVAL_REQUIRED",
                  self.validate(authorize_read=False))
        self.deny("CODEVALIDATE_SOURCE_GRANT_INVALID",
                  self.validate(validate_content_for="All"))
        self.deny("INPUT_CONTENT_GRANT_SOURCE_MISMATCH",
                  self.validate(validate_content_for="DeliveredTarget"), "invalid_input")

    def test_schema_only_is_not_an_ai_draft(self):
        self.prepare()
        schema_only = self.act()
        r = self.validator.validate(self.prepared, schema_only, **self.kw)
        self.deny("CODEVALIDATE_SCHEMA_ONLY_OR_NONCANDIDATE_NOT_A_DRAFT", r)

    def test_wrong_route_id_task_schema_and_action_refused(self):
        self.prepare()
        for key, value in (("schema", "other.v1"), ("route_id", "ces.route.other.v1"),
                           ("task_kind", "report_writing"), ("action", "schema_only")):
            altered = copy.deepcopy(self.outcome)
            altered[key] = value
            r = self.validator.validate(self.prepared, altered, **self.kw)
            self.assertIn(r["reason_code"],
                          ("CODEVALIDATE_UNKNOWN_ROUTE_OR_TASK",
                           "CODEVALIDATE_SCHEMA_ONLY_OR_NONCANDIDATE_NOT_A_DRAFT"))
            self.assertEqual(r["candidate"]["state"], "REJECTED")

    def test_fake_success_and_provider_or_test_proof_flags_rejected(self):
        self.prepare()
        alternatives = (
            ("status", "success"), ("exit_code", 0),
            ("reason_code", "AI_CANDIDATE_VERIFIED"),
        )
        for key, value in alternatives:
            tampered = copy.deepcopy(self.outcome)
            tampered[key] = value
            r = self.validator.validate(self.prepared, tampered, **self.kw)
            self.deny("CODEVALIDATE_SCHEMA_ONLY_OR_NONCANDIDATE_NOT_A_DRAFT", r)
        for field in ("actor_or_provider_authenticated", "external_model_execution_verified"):
            tampered = copy.deepcopy(self.outcome)
            tampered["provider"][field] = True
            self.deny("CODEVALIDATE_PROVIDER_NOT_AUTHENTICATED_OR_NO_CANDIDATE",
                      self.validator.validate(self.prepared, tampered, **self.kw))
        tampered = copy.deepcopy(self.outcome)
        tampered["result"]["semantic_validation"] = "PASS"
        self.deny("CODEVALIDATE_MODEL_SEMANTIC_VERIFICATION_ESCALATION",
                  self.validator.validate(self.prepared, tampered, **self.kw))

    def test_wrong_run_handoff_event_revision_source_hash_rejected(self):
        self.prepare()
        for key, value in (("run_id", "run_v1_" + "b" * 48),
                           ("handoff_id", "handoff_v1_" + "b" * 48),
                           ("stage_revision", self.kw["expected_revision"] + 1),
                           ("stage_event_sha256", "a" * 64),
                           ("source_context_sha256", "b" * 64),
                           ("source_identity_sha256", "c" * 64),
                           ("evidence_hash", "d" * 64),
                           ("material_sha256", "e" * 64)):
            altered = copy.deepcopy(self.outcome)
            altered["source_binding"][key] = value
            self.deny("CODEVALIDATE_ROUTE_RUN_SOURCE_REVISION_DRIFT",
                      self.validator.validate(self.prepared, altered, **self.kw))

    def test_operation_key_and_caller_pinned_candidate_are_required(self):
        self.prepare()
        self.deny("CODEVALIDATE_OPERATION_KEY_MUST_BE_DISTINCT_FROM_INPUT",
                  self.validate(validation_operation_key=self.kw["input_operation_key"]))
        self.deny("CODEVALIDATE_OPERATION_KEY_INVALID",
                  self.validate(validation_operation_key="bad op with spaces"))
        self.deny("CODEVALIDATE_EXPECTED_CANDIDATE_SHA_REQUIRED",
                  self.validate(expected_candidate_sha256=None))
        self.deny("CODEVALIDATE_CANDIDATE_UNKNOWN_OR_EDITED",
                  self.validate(expected_candidate_sha256="b" * 64))

    def test_altered_draft_summary_findings_actor_and_context_refused(self):
        self.prepare()
        original = cv._draft_from_route(self.outcome)
        self.assertEqual(self.validate(draft=original)["status"], "partial")
        for field, value in (("summary", "altered description"),
                             ("actor_claim", "another-actor"),
                             ("source_binding", dict(original["source_binding"],
                                                      source_mode="ProposedPR"))):
            changed = copy.deepcopy(original)
            changed[field] = value
            self.deny("CODEVALIDATE_DRAFT_EDITED_OR_MIXED", self.validate(draft=changed))
        changed = copy.deepcopy(original)
        changed["findings"][0]["analysis"] = "model rewrote its analysis"
        self.deny("CODEVALIDATE_DRAFT_EDITED_OR_MIXED", self.validate(draft=changed))
        changed = copy.deepcopy(original)
        changed["status"] = "success"
        self.deny("CODEVALIDATE_DRAFT_FIELDS_INVALID", self.validate(draft=changed))

    def test_route_content_modified_without_candidate_sha_refused(self):
        self.prepare()
        tampered = copy.deepcopy(self.outcome)
        tampered["result"]["findings"][0]["analysis"] = "Malicious other claim"
        self.deny("CODEVALIDATE_CANDIDATE_UNKNOWN_OR_EDITED",
                  self.validator.validate(self.prepared, tampered, **self.kw))

    def test_route_source_coverage_and_effects_attestation_rejected(self):
        self.prepare()
        cases = (("source", "source_currentness_proven", True),
                 ("coverage", "complete_for_selected_source", False),
                 ("effects", "business_repository_written", True))
        for group, key, value in cases:
            changed = copy.deepcopy(self.outcome)
            changed[group][key] = value
            self.assertEqual(self.validator.validate(self.prepared, changed, **self.kw)
                             ["candidate"]["state"], "REJECTED")

    def test_anchor_line_quote_sha_path_and_git_line_rechecked_against_ec173(self):
        self.prepare()
        for field, value in (("quote", "+not-in-source"),
                             ("anchor_sha256", "f" * 64),
                             ("line_number_in_segment_or_item", 9000),
                             ("source_path", "forged.py"),
                             ("line_number_is_git_file_line", True)):
            edited = copy.deepcopy(self.outcome)
            edited["result"]["findings"][0]["anchors"][0][field] = value
            response = self.validator.validate(self.prepared, edited, **self.kw)
            self.assertEqual(response["candidate"]["state"], "REJECTED", field)

    def test_tampered_seal_and_uncommitted_stage_block_validation(self):
        self.prepare()
        self.deny("STAGING_PARENT_PIN_MISMATCH",
                  self.validate(expected_parent_pin="a" * 64), "unavailable")
        obj = json.loads(self.input_path.read_text())
        obj["material"]["segments"] = []
        self.input_path.write_text(json.dumps(obj), encoding="utf-8")
        self.assertEqual(self.validate()["status"], "unavailable")

    def test_expired_input_and_stale_observed_source_refused(self):
        self.prepare(input_ttl=60)
        self.clock.value += timedelta(seconds=61)
        self.deny("INPUT_EXPIRED_OR_CLOCK_UNSAFE", self.validate(), "unavailable")

    def test_prepared_permission_revocation_is_not_inherited(self):
        self.prepare()
        self.prepared["permission"]["content_granted"] = False
        self.deny("EC170_CONTENT_RELEASE_NOT_AUTHORIZED_FOR_SOURCE",
                  self.validate(), "invalid_input")

    def test_postflight_source_permission_loss_invalidates_result(self):
        self.prepare()
        original = self.validator.input.load_authorized
        called = [0]
        def reentry(*args, **kwargs):
            called[0] += 1
            if called[0] == 2:
                self.prepared["permission"]["content_granted"] = False
            return original(*args, **kwargs)
        with patch.object(self.validator.input, "load_authorized", side_effect=reentry):
            response = self.validate()
        self.assertEqual(called[0], 2)
        self.deny("EC170_CONTENT_RELEASE_NOT_AUTHORIZED_FOR_SOURCE", response)

    def test_manual_review_needs_a_separate_complete_grant(self):
        self.prepare()
        self.deny("CODEVALIDATE_MANUAL_REVIEW_PARTIAL_OR_UNAPPROVED",
                  self.validate(manual_review=self.review()))
        self.deny("CODEVALIDATE_MANUAL_REVIEW_SOURCE_SCOPE_MISMATCH",
                  self.with_review(manual_review_content_for="ProposedPR"))
        self.deny("CODEVALIDATE_PINNED_VERIFIER_CONFIGURATION_REQUIRED",
                  self.with_review(trusted_verifier_key=b"too-short"))
        self.deny("CODEVALIDATE_PINNED_VERIFIER_CONFIGURATION_REQUIRED",
                  self.with_review(trusted_verifier_id="bad id with spaces"))

    def test_signed_manual_confirm_proves_only_pinned_key_possession_not_ci(self):
        self.prepare()
        response = self.with_review()
        self.assertEqual((response["status"], response["exit_code"]), ("partial", 2))
        self.assertEqual(response["candidate"]["manual_verified_count"], 1)
        self.assertEqual(response["candidate"]["findings"][0]["review_state"],
                         "VERIFIED_BY_PINNED_MANUAL_REVIEW_SIGNATURE")
        self.assertTrue(response["manual_review"]["key_possession_checked"])
        self.assertFalse(response["manual_review"]["verifier_identity_independently_authenticated"])
        self.assertFalse(response["proof"]["ci_or_test_execution_observed"])
        self.assertFalse(response["effects"]["eligible_for_automatic_codesave"])
        self.assertEqual(response["reason_code"],
                         "CODEVALIDATE_PINNED_MANUAL_REVIEW_RECORDED_NOT_SOURCE_PROOF")
        self.assertNotIn("Independent synthetic review", json.dumps(response))

    def test_signed_manual_reject_and_inconclusive_do_not_become_pass(self):
        self.prepare()
        reject = self.with_review(receipt=self.review(("reject",)))
        self.assertEqual(reject["candidate"]["manual_rejected_count"], 1)
        self.assertEqual(reject["candidate"]["findings"][0]["review_state"],
                         "REJECTED_BY_PINNED_MANUAL_REVIEW")
        inconclusive = self.with_review(receipt=self.review(("inconclusive",)))
        self.assertEqual(inconclusive["candidate"]["manual_verified_count"], 0)
        self.assertEqual(inconclusive["candidate"]["findings"][0]["review_state"],
                         "UNVERIFIED_REVIEW_INCONCLUSIVE")

    def test_manual_signature_tamper_wrong_key_verifier_and_replay_refused(self):
        self.prepare()
        receipt = self.review()
        for field, value in (("verifier_id", "untrusted-actor"),
                             ("candidate_sha256", "a" * 64),
                             ("validation_operation_key", "different-op")):
            edited = copy.deepcopy(receipt)
            edited[field] = value
            self.deny("CODEVALIDATE_ATTESTATION_IDENTITY_OR_CONTEXT_MISMATCH",
                      self.with_review(receipt=edited))
        edited = copy.deepcopy(receipt)
        edited["decisions"][0]["review_notes"] = "Unsigned edited note"
        self.deny("CODEVALIDATE_REVIEW_SIGNATURE_NOT_TRUSTED",
                  self.with_review(receipt=edited), "unavailable")
        self.deny("CODEVALIDATE_REVIEW_SIGNATURE_NOT_TRUSTED",
                  self.with_review(trusted_verifier_key=b"some-other-key-is-different-012345"),
                  "unavailable")
        edited = copy.deepcopy(receipt)
        edited["decisions"][0]["finding_sha256"] = "d" * 64
        self.deny("CODEVALIDATE_REVIEW_DECISION_OR_FINDING_HASH_MISMATCH",
                  self.with_review(receipt=edited))

    def test_review_timestamp_ttl_and_future_review_are_bounded(self):
        self.prepare(input_ttl=120)
        self.deny("CODEVALIDATE_ATTESTATION_STALE_OR_OUTSIDE_INPUT_TTL",
                  self.with_review(receipt=self.review(expires_at_utc=st._stamp(
                      self.clock.value + timedelta(seconds=350)))), "unavailable")
        self.deny("CODEVALIDATE_ATTESTATION_STALE_OR_OUTSIDE_INPUT_TTL",
                  self.with_review(receipt=self.review(reviewed_at_utc=st._stamp(
                      self.clock.value + timedelta(seconds=90)))), "unavailable")
        self.deny("CODEVALIDATE_ATTESTATION_STALE_OR_OUTSIDE_INPUT_TTL",
                  self.with_review(receipt=self.review(expires_at_utc=st._stamp(
                      self.clock.value - timedelta(seconds=1)))), "unavailable")

    def test_valid_zero_findings_stays_partial_and_cannot_get_fake_manual_verification(self):
        self.prepare()
        def empty_callback(data, provider, timeout):
            candidate = self.candidate(json.loads(data))
            candidate["findings"] = []
            return json.dumps(candidate).encode()
        self.outcome = self.dispatch(adapter=empty_callback)
        self.kw["expected_candidate_sha256"] = self.outcome["result"]["candidate_sha256"]
        clean = self.validate()
        self.assertEqual(clean["candidate"]["findings_count"], 0)
        self.assertEqual((clean["status"], clean["exit_code"]), ("partial", 2))
        self.deny("CODEVALIDATE_ATTESTATION_REQUIRES_EXACT_FINDING_DECISIONS",
                  self.with_review(receipt=self.review(())))

    def test_hist_proposed_pr_selected_path_preserved_and_never_current(self):
        snap, _ = fx.ec165.create(selected=("src/service.py",), include=True)
        source = ec170.prepare_context("ProposedPR", proposed_snapshot=snap,
                                      content_permission="ProposedPR")
        self.setup_input(refreshed(source, self.clock.value), historical=True)
        self.validator = cv.StagedCodeValidator(str(self.root), str(self.repo), clock=self.clock)
        def callback(data, _p, _t):
            candidate = self.candidate(json.loads(data), anchors=[{
                "segment_index": 0, "item_index": 0, "line_number": 3, "quote": "+new = 2"
            }])
            return json.dumps(candidate).encode()
        self.outcome = self.dispatch(adapter=callback)
        self.kw = dict(expected_parent_pin=self.pin,
                       run_id=self.route_opts["run_id"], handoff_id=self.route_opts["handoff_id"],
                       expected_revision=self.route_opts["expected_revision"],
                       expected_event_sha256=self.route_opts["expected_event_sha256"],
                       input_operation_key=self.route_opts["operation_key"],
                       validation_operation_key="codevalidate-staged-0001",
                       authorize_validate=True, authorize_read=True,
                       validate_content_for="ProposedPR",
                       expected_candidate_sha256=self.outcome["result"]["candidate_sha256"],
                       allow_historical_proposal=True, max_source_age_seconds=600)
        r = self.validate()
        self.assertEqual((r["status"], r["exit_code"]), ("partial", 2))
        self.assertTrue(r["proof"]["historical_proposal_only"])
        self.assertFalse(r["coverage"]["complete_for_selected_source"])
        self.deny("HISTORICAL_PROPOSAL_NEEDS_EXPLICIT_LIMITED_CONSENT",
                  self.validate(allow_historical_proposal=False))

    def test_delivered_target_never_mixed_with_working_tree(self):
        source = ec170.prepare_context("DeliveredTarget",
                                      local_codeprepare=fx.local_result("DeliveredTarget"),
                                      content_permission="DeliveredTarget")
        self.prepare(prepared=refreshed(source, self.clock.value))
        r = self.validate()
        self.assertEqual(r["source_binding"]["source_mode"], "DeliveredTarget")
        self.deny("INPUT_CONTENT_GRANT_SOURCE_MISMATCH",
                  self.validate(validate_content_for="WorkingTree"), "invalid_input")

    def test_cli_loads_real_bound_files_and_requires_independent_grants(self):
        self.prepare()
        prepared_path = self.root.parent / "ec170_prepared.json"
        result_path = self.root.parent / "ec174_route.json"
        prepared_path.write_text(json.dumps(self.prepared), encoding="utf-8")
        result_path.write_text(json.dumps(self.outcome), encoding="utf-8")
        cmd = [sys.executable, str(Path(cv.__file__)),
               "--prepared", str(prepared_path), "--route-result", str(result_path),
               "--root", str(self.root), "--business-repo-root", str(self.repo),
               "--parent-pin", self.pin, "--run-id", self.kw["run_id"],
               "--handoff-id", self.kw["handoff_id"],
               "--expected-revision", str(self.kw["expected_revision"]),
               "--expected-event-sha256", self.kw["expected_event_sha256"],
               "--input-operation-key", self.kw["input_operation_key"],
               "--validation-operation-key", self.kw["validation_operation_key"],
               "--expected-candidate-sha256", self.kw["expected_candidate_sha256"],
               "--allow-content-for", "WorkingTree"]
        denied = subprocess.run(cmd, capture_output=True, text=True, check=False)
        self.assertEqual(denied.returncode, 4, denied.stderr)
        self.assertEqual(json.loads(denied.stdout)["reason_code"],
                         "CODEVALIDATE_INDEPENDENT_VALIDATION_APPROVAL_REQUIRED")
        allowed = subprocess.run(cmd + ["--approve-validate", "--approve-read"],
                                 capture_output=True, text=True, check=False)
        self.assertEqual(allowed.returncode, 2, allowed.stderr)
        self.assertEqual(json.loads(allowed.stdout)["candidate"]["findings_count"], 1)
        self.assertNotIn("+new", allowed.stdout)
        self.assertNotIn("diff --git", allowed.stdout)
        self.assertNotIn("--trusted-verifier-key", subprocess.run(
            [sys.executable, str(Path(cv.__file__)), "--help"],
            capture_output=True, text=True).stdout)

    def test_arbitrary_shell_text_in_finding_is_never_executed(self):
        self.prepare()
        content = "$(touch /tmp/never_execute_ec175)"
        altered = copy.deepcopy(self.outcome)
        altered["result"]["findings"][0]["suggested_action"] = content
        # The candidate digest cannot be recomputed from an edited draft by
        # default; source content is never passed to a shell.
        self.deny("CODEVALIDATE_CANDIDATE_UNKNOWN_OR_EDITED",
                  self.validator.validate(self.prepared, altered, **self.kw))
        self.assertFalse(Path("/tmp/never_execute_ec175").exists())


    def test_partial_ec170_missing_requirements_remain_visible(self):
        import handoff_lifecycle as lc
        prepared = copy.deepcopy(self.prepared)
        cov = prepared["context"]["coverage"]
        cov["content_complete_for_selected_source"] = False
        cov["missing_requirements"] = ["SYNTHETIC_COVERAGE_UNKNOWN"]
        prepared["coverage"] = copy.deepcopy(cov)
        prepared["status"], prepared["exit_code"] = "partial", 2
        prepared["context_sha256"] = lc._hash(lc.DOMAIN_CONTEXT, prepared["context"])
        self.prepare(prepared=prepared)
        result = self.validate()
        self.assertEqual((result["status"], result["exit_code"]), ("partial", 2))
        self.assertEqual(result["coverage"]["source_quality"], "partial")
        self.assertFalse(result["coverage"]["complete_for_selected_source"])
        self.assertEqual(result["coverage"]["missing_requirements"],
                         ["SYNTHETIC_COVERAGE_UNKNOWN"])
        self.assertFalse(result["effects"]["codesave_authorized"])

    def test_two_findings_have_independent_signed_verdicts_and_hashes(self):
        self.prepare()
        def callback(data, _provider, _timeout):
            obj = self.candidate(json.loads(data))
            second = copy.deepcopy(obj["findings"][0])
            second["title"] = "Independent second synthetic observation"
            second["anchors"] = [{"segment_index": 0, "item_index": None,
                                  "line_number": 4, "quote": "+new"}]
            obj["findings"].append(second)
            return json.dumps(obj).encode()
        self.outcome = self.dispatch(adapter=callback)
        self.kw["expected_candidate_sha256"] = self.outcome["result"]["candidate_sha256"]
        self.assertEqual(self.outcome["status"], "partial")
        receipt = self.review(("confirm", "reject"))
        result = self.with_review(receipt=receipt)
        self.assertEqual(result["candidate"]["manual_verified_count"], 1)
        self.assertEqual(result["candidate"]["manual_rejected_count"], 1)
        self.assertNotEqual(result["candidate"]["findings"][0]["finding_sha256"],
                            result["candidate"]["findings"][1]["finding_sha256"])
        self.assertEqual(result["status"], "partial")

    def test_review_cannot_be_dated_before_source_observation(self):
        self.prepare()
        receipt = self.review(reviewed_at_utc=st._stamp(
            self.clock.value - timedelta(seconds=1)))
        self.deny("CODEVALIDATE_ATTESTATION_STALE_OR_OUTSIDE_INPUT_TTL",
                  self.with_review(receipt=receipt), "unavailable")

    def test_manual_verdict_notes_secrets_extra_fields_and_lost_decisions_rejected(self):
        self.prepare()
        with_note = self.review()
        with_note["decisions"][0]["review_notes"] = "-----BEGIN RSA PRIVATE KEY-----"
        self.deny("CANDIDATE_TEXT_UNSAFE_OR_SECRET",
                  self.with_review(receipt=with_note), "unavailable")
        extra = self.review()
        extra["server_authenticated"] = True
        self.deny("CODEVALIDATE_ATTESTATION_FIELDS_INVALID",
                  self.with_review(receipt=extra))
        missing = self.review()
        missing["decisions"] = []
        self.deny("CODEVALIDATE_ATTESTATION_REQUIRES_EXACT_FINDING_DECISIONS",
                  self.with_review(receipt=missing))
        fake_pass = self.review()
        fake_pass["decisions"][0]["verdict"] = "ci_pass"
        self.deny("CODEVALIDATE_REVIEW_DECISION_OR_FINDING_HASH_MISMATCH",
                  self.with_review(receipt=fake_pass))

    def test_unexpected_model_status_keys_bool_alias_and_unknown_provider_are_rejected(self):
        self.prepare()
        extra = copy.deepcopy(self.outcome)
        extra["test_results"] = {"pass": True}
        self.deny("CODEVALIDATE_ROUTE_FIELDS_INVALID",
                  self.validator.validate(self.prepared, extra, **self.kw))
        fake_bool = copy.deepcopy(self.outcome)
        fake_bool["source_binding"]["stage_revision"] = True
        self.deny("CODEVALIDATE_ROUTE_RUN_SOURCE_REVISION_DRIFT",
                  self.validator.validate(self.prepared, fake_bool, **self.kw))
        untrusted = copy.deepcopy(self.outcome)
        untrusted["provider"]["callback_invoked"] = False
        self.deny("CODEVALIDATE_PROVIDER_NOT_AUTHENTICATED_OR_NO_CANDIDATE",
                  self.validator.validate(self.prepared, untrusted, **self.kw))

    def test_postflight_time_expiry_refuses_previously_valid_draft(self):
        self.prepare(input_ttl=60)
        original = self.validator.input.load_authorized
        counter = [0]
        def expire_during_verify(*args, **kwargs):
            counter[0] += 1
            if counter[0] == 2:
                self.clock.value += timedelta(seconds=61)
            return original(*args, **kwargs)
        with patch.object(self.validator.input, "load_authorized", side_effect=expire_during_verify):
            response = self.validate()
        self.assertEqual(counter[0], 2)
        self.deny("INPUT_EXPIRED_OR_CLOCK_UNSAFE", response, "unavailable")

    def test_cli_strict_json_duplicate_case_key_refused(self):
        self.prepare()
        prepared_path = self.root.parent / "ec170_prepared.json"
        route_path = self.root.parent / "ec174_route_bad.json"
        prepared_path.write_text(json.dumps(self.prepared), encoding="utf-8")
        route_path.write_text('{"route_id":1,"ROUTE_ID":2}', encoding="utf-8")
        cmd = [sys.executable, str(Path(cv.__file__)),
               "--prepared", str(prepared_path), "--route-result", str(route_path),
               "--root", str(self.root), "--business-repo-root", str(self.repo),
               "--parent-pin", self.pin, "--run-id", self.kw["run_id"],
               "--handoff-id", self.kw["handoff_id"],
               "--expected-revision", str(self.kw["expected_revision"]),
               "--expected-event-sha256", self.kw["expected_event_sha256"],
               "--input-operation-key", self.kw["input_operation_key"],
               "--validation-operation-key", self.kw["validation_operation_key"],
               "--expected-candidate-sha256", self.kw["expected_candidate_sha256"],
               "--allow-content-for", "WorkingTree", "--approve-read", "--approve-validate"]
        r = subprocess.run(cmd, capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 4)
        self.assertEqual(json.loads(r.stdout)["reason_code"], "CODEVALIDATE_CLI_INPUT_INVALID")


if __name__ == "__main__":
    unittest.main()
