#!/usr/bin/env python3
"""EC176 focused functional cases; disposable POSIX synthetic chain only."""
from __future__ import annotations

import copy
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import os
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

import ai_handoff_router as ar
import codeprepare_multisource as ec170
import codesave_staged as cs
import codevalidate_staged as cv
import handoff_lifecycle as lc
import task_staging as st
import test_codeprepare_multisource as fx
import test_codevalidate_staged as vf
import test_ai_handoff_router as route_fixtures
from test_handoff_input import refreshed


class CodeSaveCases(unittest.TestCase):
    # Reuse real fixture builders without running inherited case classes.
    setUp = route_fixtures.RouteCases.setUp
    setup_input = route_fixtures.RouteCases.setup_input
    act = route_fixtures.RouteCases.act
    candidate = route_fixtures.RouteCases.candidate
    callback = route_fixtures.RouteCases.callback
    dispatch = route_fixtures.RouteCases.dispatch
    prepare = vf.CodeValidateCases.prepare
    validate = vf.CodeValidateCases.validate
    review = vf.CodeValidateCases.review
    review_key = staticmethod(vf.CodeValidateCases.review_key)
    with_review = vf.CodeValidateCases.with_review

    def setup_save_store(self):
        self.save_parent = self.root.parent.parent / "independent_save_parent"
        self.save_parent.mkdir(mode=0o700)
        self.save_root = self.save_parent / "ces_metadata"
        self.save_root.mkdir(mode=0o700)
        self.saver = cs.StagedCodeSaver(str(self.root), str(self.repo), str(self.save_root),
                                        clock=self.clock)
        initialized = self.saver.initialize(approve_init=True)
        self.assertEqual(initialized["status"], "success")
        self.store_pin = initialized["save_store_pin"]

    def start(self, *, prepared=None, historical=False, review_decisions=("confirm",)):
        self.prepare(prepared=prepared, historical=historical)
        self.setup_save_store()
        self.signed_review = self.review(review_decisions)
        self.validation = self.with_review(receipt=self.signed_review)
        self.assertEqual(self.validation["status"], "partial", self.validation)
        self.save_kw = dict(
            expected_save_store_pin=self.store_pin, expected_parent_pin=self.pin,
            run_id=self.kw["run_id"], handoff_id=self.kw["handoff_id"],
            expected_revision=self.kw["expected_revision"],
            expected_event_sha256=self.kw["expected_event_sha256"],
            input_operation_key=self.kw["input_operation_key"],
            validation_operation_key=self.kw["validation_operation_key"],
            save_operation_key="codesave-staged-0001",
            expected_candidate_sha256=self.kw["expected_candidate_sha256"],
            expected_validation_receipt_sha256=self.validation["validation_receipt_sha256"],
            authorize_save=True, authorize_read=True,
            save_content_for=self.prepared["source_mode"],
            manual_review=self.signed_review, authorize_manual_review=True,
            manual_review_content_for=self.prepared["source_mode"],
            trusted_verifier_id="synthetic-reviewer", trusted_verifier_key=self.review_key(),
            allow_historical_proposal=historical, max_source_age_seconds=600,
        )

    def save(self, **changes):
        values = dict(self.save_kw)
        values.update(changes)
        return self.saver.save(self.prepared, self.outcome, self.validation, **values)

    def deny(self, result, reason=None, *, status=None):
        self.assertNotEqual(result["status"], "partial", result)
        if reason:
            self.assertEqual(result["reason_code"], reason, result)
        if status:
            self.assertEqual(result["status"], status, result)
        self.assertFalse(result["effects"]["business_repository_written"])
        self.assertFalse(result["effects"]["finding_created"])
        self.assertFalse(result["effects"]["code_text_or_review_notes_persisted"])

    def test_end_to_end_commits_an_actual_hmac_metadata_record_without_source_text(self):
        self.start()
        prior_stage = {p.name: p.read_bytes() for p in self.root.iterdir()}
        prior_repo = (self.repo / "read-only.py").read_bytes()
        result = self.save()
        self.assertEqual((result["status"], result["exit_code"]), ("partial", 2), result)
        self.assertTrue(result["effects"]["ces_metadata_record_committed"])
        self.assertFalse(result["effects"]["finding_created"])
        self.assertFalse(result["stored"]["source_currentness_proven"])
        self.assertEqual(prior_stage, {p.name: p.read_bytes() for p in self.root.iterdir()})
        self.assertEqual((self.repo / "read-only.py").read_bytes(), prior_repo)
        files = list(self.save_root.glob("save_*.json"))
        self.assertEqual(len(files), 1)
        content = files[0].read_text()
        self.assertNotIn("+new", content)
        self.assertNotIn("diff --git", content)
        self.assertNotIn("Synthetic patch line", content)
        self.assertNotIn("Independent synthetic review", content)
        self.assertNotIn("Review the change", content)
        self.assertNotIn("read-only.py", content)
        saved = self.saver.read_saved(expected_save_store_pin=self.store_pin,
                                      save_operation_key="codesave-staged-0001",
                                      authorize_read=True, read_content_for="WorkingTree")
        self.assertEqual(saved["status"], "partial", saved)
        self.assertEqual(saved["record"]["record_sha256"], result["record_sha256"])
        self.assertEqual(saved["record"]["source_binding"], self.outcome["source_binding"])
        self.assertFalse(saved["record"]["verified_ci_or_test"])
        self.assertEqual(self.saver.inspect(expected_save_store_pin=self.store_pin)["record_count"], 1)

    def test_duplicate_same_operation_is_safe_idempotent_without_timestamp_extension(self):
        self.start()
        first = self.save()
        original = (self.save_root / ("save_" + first["save_operation_id"] + ".json")).read_bytes()
        second = self.save()
        self.assertEqual((second["status"], second["exit_code"]), ("partial", 2), second)
        self.assertTrue(second["idempotent_reentry"])
        self.assertEqual(second["record_sha256"], first["record_sha256"])
        self.assertEqual(original, (self.save_root / ("save_" + first["save_operation_id"] + ".json")).read_bytes())

    def test_same_candidate_different_save_operation_is_not_duplicated(self):
        self.start()
        self.assertEqual(self.save()["status"], "partial")
        self.deny(self.save(save_operation_key="codesave-staged-0002"),
                  "CODESAVE_SAME_CANDIDATE_DIFFERENT_OPERATION_CONFLICT")
        self.assertEqual(self.saver.inspect(expected_save_store_pin=self.store_pin)["record_count"], 1)


    def test_two_simultaneous_saves_one_commit_and_one_read_only_reentry(self):
        self.start()
        outputs = []
        failures = []
        barrier = threading.Barrier(2)
        def write():
            try:
                barrier.wait(timeout=4)
                outputs.append(self.save())
            except Exception as exc:
                failures.append(str(exc))
        threads = [threading.Thread(target=write) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=8)
        self.assertFalse(failures, failures)
        self.assertEqual(len(outputs), 2, outputs)
        self.assertEqual(sorted(x["reason_code"] for x in outputs), sorted((
            "CODESAVE_IDEMPOTENT_METADATA_REENTRY_NO_NEW_WRITE",
            "CODESAVE_PRIVATE_METADATA_COMMITTED_NOT_FINDING_OR_SOURCE_PROOF",
        )))
        self.assertEqual(self.saver.inspect(expected_save_store_pin=self.store_pin)["record_count"], 1)

    def test_persisted_link_then_directory_sync_error_reports_unknown_not_success(self):
        self.start()
        real_fsync = os.fsync
        calls = [0]
        def uncertain(fd):
            calls[0] += 1
            if calls[0] == 2:  # new private temp fsync succeeded; target link already exists
                raise OSError("synthetic crash at first directory fsync")
            return real_fsync(fd)
        with patch.object(cs.os, "fsync", side_effect=uncertain):
            result = self.save()
        self.deny(result, "CODESAVE_PUBLISH_DURABILITY_UNCERTAIN", status="unavailable")
        self.assertIsNone(result["effects"]["ces_metadata_record_committed"])
        self.assertEqual(result["effects"]["ces_metadata_commit_state"],
                         "UNCERTAIN_MANUAL_REVIEW_REQUIRED")
        self.assertEqual(len(list(self.save_root.glob("save_*.json"))), 1)
        self.assertEqual(len(list(self.save_root.glob(".pending-save-*"))), 1)
        self.deny(self.save(), "CODESAVE_UNFINISHED_TRANSACTION_MANUAL_REVIEW_REQUIRED",
                  status="unavailable")

    def test_preexisting_record_conflict_never_overwrites_even_if_own_key_reused(self):
        self.start()
        first = self.save()
        self.assertEqual(first["status"], "partial")
        target = next(self.save_root.glob("save_*.json"))
        original = target.read_bytes()
        # Caller signs the SAME exact candidate under a new EC175 validation op.
        # This is a different authorization history, not permission to mutate
        # the old immutable EC176 record associated with the save operation.
        key = "codevalidate-staged-0002"
        new_review = copy.deepcopy(self.signed_review)
        new_review["validation_operation_key"] = key
        new_review["mac_sha256"] = __import__("hmac").new(
            self.review_key(), cv.DOMAIN_REVIEW + st._canonical({
                k: v for k, v in new_review.items() if k != "mac_sha256"
            }), hashlib.sha256).hexdigest()
        new_validation = self.validate(
            validation_operation_key=key, manual_review=new_review,
            authorize_manual_review=True, manual_review_content_for="WorkingTree",
            trusted_verifier_id="synthetic-reviewer", trusted_verifier_key=self.review_key())
        self.assertEqual(new_validation["status"], "partial", new_validation)
        args = dict(self.save_kw)
        args.update(validation_operation_key=key, manual_review=new_review,
                    expected_validation_receipt_sha256=new_validation["validation_receipt_sha256"])
        denied = self.saver.save(self.prepared, self.outcome, new_validation, **args)
        self.deny(denied, "CODESAVE_IDEMPOTENCY_CONTENT_OR_APPROVAL_CONFLICT")
        self.assertEqual(target.read_bytes(), original)

    def test_no_store_creation_without_explicit_initialization_approval(self):
        self.prepare()
        self.save_parent = self.root.parent.parent / "independent_save_parent"
        self.save_parent.mkdir(mode=0o700)
        self.save_root = self.save_parent / "ces_metadata"
        self.save_root.mkdir(mode=0o700)
        service = cs.StagedCodeSaver(str(self.root), str(self.repo), str(self.save_root))
        with self.assertRaises(cs.CodeSaveError):
            service.initialize(approve_init=False)
        self.assertEqual(os.listdir(self.save_root), [])
        self.assertEqual(service.initialize(approve_init=True)["status"], "success")
        with self.assertRaises(cs.CodeSaveError):
            service.initialize(approve_init=True)

    def test_save_requires_independent_write_read_scope_and_distinct_ops(self):
        self.start()
        for change, reason in (
            ({"authorize_save": False}, "CODESAVE_INDEPENDENT_EXPLICIT_SAVE_APPROVAL_REQUIRED"),
            ({"authorize_read": False}, "CODESAVE_INDEPENDENT_SOURCE_READ_APPROVAL_REQUIRED"),
            ({"save_content_for": "bad"}, "CODESAVE_EXACT_SOURCE_SCOPE_REQUIRED"),
            ({"save_operation_key": "codevalidate-staged-0001"},
             "CODESAVE_NEW_OPERATION_KEY_MUST_BE_DISTINCT"),
            ({"save_operation_key": "input-write-0001"},
             "CODESAVE_NEW_OPERATION_KEY_MUST_BE_DISTINCT"),
            ({"authorize_manual_review": False},
             "CODESAVE_INDEPENDENT_MANUAL_REVIEW_SOURCE_SCOPE_REQUIRED"),
            ({"manual_review_content_for": "DeliveredTarget"},
             "CODESAVE_INDEPENDENT_MANUAL_REVIEW_SOURCE_SCOPE_REQUIRED"),
        ):
            with self.subTest(change=change):
                self.deny(self.save(**change), reason)
        self.assertEqual(self.saver.inspect(expected_save_store_pin=self.store_pin)["record_count"], 0)

    def test_prior_unkeyed_result_receipt_is_not_a_save_permission(self):
        self.start()
        forged = copy.deepcopy(self.validation)
        forged["proof"]["ci_or_test_execution_observed"] = True
        forged["validation_receipt_sha256"] = cv._sha(cv.DOMAIN_RECEIPT, {
            k: v for k, v in forged.items() if k != "validation_receipt_sha256"
        })
        self.deny(self.saver.save(self.prepared, self.outcome, forged, **{
            **self.save_kw, "expected_validation_receipt_sha256": forged["validation_receipt_sha256"]
        }), "CODESAVE_VALIDATION_SOURCE_CANDIDATE_REVIEW_OR_EFFECTS_CHANGED")
        self.assertEqual(self.saver.inspect(expected_save_store_pin=self.store_pin)["record_count"], 0)

    def test_prior_validation_with_edited_attestation_claim_is_denied(self):
        self.start()
        forged = copy.deepcopy(self.validation)
        forged["manual_review"]["verifier_id"] = "forged"
        forged["validation_receipt_sha256"] = cv._sha(cv.DOMAIN_RECEIPT, {
            k: v for k, v in forged.items() if k != "validation_receipt_sha256"
        })
        self.deny(self.saver.save(self.prepared, self.outcome, forged, **{
            **self.save_kw, "expected_validation_receipt_sha256": forged["validation_receipt_sha256"]
        }), "CODESAVE_VALIDATION_SOURCE_CANDIDATE_REVIEW_OR_EFFECTS_CHANGED")

    def test_prior_result_pin_wrong_or_raw_receipt_modified(self):
        self.start()
        self.deny(self.save(expected_validation_receipt_sha256="1" * 64),
                  "CODESAVE_PRIOR_VALIDATION_RECEIPT_EDITED_OR_UNPINNED")
        forged = copy.deepcopy(self.validation)
        forged["candidate"]["findings"][0]["review_state"] = "FAKE_CI_PASS"
        self.deny(self.saver.save(self.prepared, self.outcome, forged, **self.save_kw),
                  "CODESAVE_PRIOR_VALIDATION_RECEIPT_EDITED_OR_UNPINNED")

    def test_unverified_or_rejected_review_never_saved(self):
        self.start(review_decisions=("reject",))
        self.deny(self.save(), "CODESAVE_EACH_FINDING_REQUIRES_EXPLICIT_SIGNED_CONFIRMATION", status="unavailable")
        self.assertEqual(self.saver.inspect(expected_save_store_pin=self.store_pin)["record_count"], 0)
        self.signed_review = self.review(("inconclusive",))
        self.validation = self.with_review(receipt=self.signed_review)
        self.save_kw["manual_review"] = self.signed_review
        self.save_kw["expected_validation_receipt_sha256"] = self.validation["validation_receipt_sha256"]
        self.deny(self.save(), "CODESAVE_EACH_FINDING_REQUIRES_EXPLICIT_SIGNED_CONFIRMATION", status="unavailable")

    def test_wrong_manual_secret_or_unsigned_review_rejected_by_fresh_validator(self):
        self.start()
        self.deny(self.save(trusted_verifier_key=b"different-key-too-long-and-almost-correct-xxxx"),
                  "CODESAVE_FRESH_VALIDATION_REFUSED_CODEVALIDATE_REVIEW_SIGNATURE_NOT_TRUSTED",
                  status="unavailable")
        altered = copy.deepcopy(self.signed_review)
        altered["decisions"][0]["review_notes"] = "A different unsigned statement"
        self.deny(self.save(manual_review=altered),
                  "CODESAVE_FRESH_VALIDATION_REFUSED_CODEVALIDATE_REVIEW_SIGNATURE_NOT_TRUSTED",
                  status="unavailable")

    def test_wrong_run_id_revision_event_candidate_digest_deny_and_no_write(self):
        self.start()
        for change in (
            {"run_id": "run_v1_" + "f" * 48},
            {"expected_revision": self.kw["expected_revision"] + 1},
            {"expected_event_sha256": "b" * 64},
            {"expected_candidate_sha256": "a" * 64},
        ):
            with self.subTest(change=change):
                response = self.save(**change)
                self.deny(response, status="unavailable")
        self.assertEqual(self.saver.inspect(expected_save_store_pin=self.store_pin)["record_count"], 0)

    def test_route_draft_change_or_fake_provider_success_is_rejected(self):
        self.start()
        route = copy.deepcopy(self.outcome)
        route["result"]["findings"][0]["analysis"] = "Changed unreviewed text"
        self.deny(self.saver.save(self.prepared, route, self.validation, **self.save_kw),
                  "CODESAVE_FRESH_VALIDATION_REFUSED_CODEVALIDATE_CANDIDATE_UNKNOWN_OR_EDITED")
        route = copy.deepcopy(self.outcome)
        route["provider"]["external_model_execution_verified"] = True
        self.deny(self.saver.save(self.prepared, route, self.validation, **self.save_kw),
                  "CODESAVE_FRESH_VALIDATION_REFUSED_CODEVALIDATE_PROVIDER_NOT_AUTHENTICATED_OR_NO_CANDIDATE")

    def test_input_tamper_expiry_and_lost_permission_never_reuse_receipt(self):
        self.start()
        self.input_path.write_bytes(self.input_path.read_bytes().replace(b"\"mac_sha256\"", b"\"mac_sha25z\""))
        self.deny(self.save(), status="unavailable")
        self.assertEqual(self.saver.inspect(expected_save_store_pin=self.store_pin)["record_count"], 0)

    def test_review_or_input_expiry_stops_new_writes_and_replays(self):
        self.start()
        original = self.save()
        self.assertEqual(original["status"], "partial")
        self.clock.value += timedelta(seconds=125)
        self.deny(self.save(), status="unavailable")
        self.deny(self.saver.read_saved(expected_save_store_pin=self.store_pin,
                                        save_operation_key="codesave-staged-0001",
                                        authorize_read=True, read_content_for="WorkingTree"),
                  "CODESAVE_STORED_EVIDENCE_EXPIRED", status="unavailable")

    def test_store_pin_wrong_and_root_identity_stale_deny(self):
        self.start()
        self.deny(self.save(expected_save_store_pin="f" * 64),
                  "CODESAVE_TARGET_STORE_IDENTITY_OR_PIN_CHANGED", status="unavailable")
        self.assertEqual(self.saver.inspect(expected_save_store_pin=self.store_pin)["record_count"], 0)

    def test_store_link_unknown_entry_and_unsafe_modes_fail_closed(self):
        self.start()
        unknown = self.save_root / "unexpected.txt"
        unknown.write_text("unknown")
        self.deny(self.save(), "CODESAVE_STORE_UNKNOWN_OR_UNSAFE_ENTRY", status="unavailable")
        unknown.unlink()
        pending = self.save_root / (".pending-save-" + "a" * 32)
        pending.touch()
        self.deny(self.save(), "CODESAVE_UNFINISHED_TRANSACTION_MANUAL_REVIEW_REQUIRED", status="unavailable")
        pending.unlink()
        self.save_root.chmod(0o755)
        self.deny(self.save(), status="unavailable")

    def test_existing_record_hmac_edit_and_hardlink_are_rejected(self):
        self.start()
        result = self.save()
        self.assertEqual(result["status"], "partial")
        item = next(self.save_root.glob("save_*.json"))
        raw = item.read_bytes()
        item.write_bytes(raw.replace(b"code_analysis", b"code_analyzzz"))
        self.deny(self.save(), status="unavailable")
        item.write_bytes(raw)
        external = self.save_parent / "alias.json"
        os.link(item, external)
        self.deny(self.save(), status="unavailable")

    def test_read_is_separate_scoped_authority_and_store_inspect_does_not_leak(self):
        self.start()
        self.save()
        kw = dict(expected_save_store_pin=self.store_pin,
                  save_operation_key="codesave-staged-0001",
                  authorize_read=True, read_content_for="WorkingTree")
        self.deny(self.saver.read_saved(**{**kw, "authorize_read": False}),
                  "CODESAVE_RECORD_READ_REQUIRES_NEW_APPROVAL")
        self.deny(self.saver.read_saved(**{**kw, "read_content_for": "ProposedPR"}),
                  "CODESAVE_READ_SOURCE_SCOPE_MISMATCH")
        self.deny(self.saver.read_saved(**{**kw, "expected_save_store_pin": "0" * 64}),
                  "CODESAVE_READ_STORE_PIN_MISMATCH", status="unavailable")
        inspector = self.saver.inspect(expected_save_store_pin=self.store_pin)
        self.assertNotIn("+new", json.dumps(inspector))
        self.assertNotIn("run_v1", json.dumps(inspector))
        self.assertEqual(inspector["record_count"], 1)

    def test_manual_confirmations_are_required_for_every_finding(self):
        self.start()
        def callback(data, _provider, _timeout):
            o = self.candidate(json.loads(data))
            second = copy.deepcopy(o["findings"][0])
            second["title"] = "Second independent synthetic finding"
            o["findings"].append(second)
            return json.dumps(o).encode()
        self.outcome = self.dispatch(adapter=callback)
        self.kw["expected_candidate_sha256"] = self.outcome["result"]["candidate_sha256"]
        self.signed_review = self.review(("confirm", "reject"))
        self.validation = self.with_review(receipt=self.signed_review)
        self.save_kw["expected_candidate_sha256"] = self.kw["expected_candidate_sha256"]
        self.save_kw["manual_review"] = self.signed_review
        self.save_kw["expected_validation_receipt_sha256"] = self.validation["validation_receipt_sha256"]
        self.deny(self.save(), "CODESAVE_EACH_FINDING_REQUIRES_EXPLICIT_SIGNED_CONFIRMATION", status="unavailable")

    def test_partial_coverage_requires_ack_not_a_fake_complete_source(self):
        prepared = copy.deepcopy(self.prepared)
        cov = prepared["context"]["coverage"]
        cov["content_complete_for_selected_source"] = False
        cov["missing_requirements"] = ["SYNTHETIC_COVERAGE_UNKNOWN"]
        prepared["coverage"] = copy.deepcopy(cov)
        prepared["status"], prepared["exit_code"] = "partial", 2
        prepared["context_sha256"] = lc._hash(lc.DOMAIN_CONTEXT, prepared["context"])
        self.start(prepared=prepared)
        self.deny(self.save(), "CODESAVE_PARTIAL_COVERAGE_REQUIRES_SEPARATE_ACKNOWLEDGMENT")
        r = self.save(acknowledge_partial_coverage=True)
        self.assertEqual(r["status"], "partial", r)
        self.assertFalse(self.saver.read_saved(
            expected_save_store_pin=self.store_pin, save_operation_key="codesave-staged-0001",
            authorize_read=True, read_content_for="WorkingTree"
        )["record"]["coverage_complete_for_selected_source"])

    def test_historical_proposal_needs_own_opt_in_and_retains_historical_limitation(self):
        snap, _ = fx.ec165.create(selected=("src/service.py",), include=True)
        source = ec170.prepare_context("ProposedPR", proposed_snapshot=snap,
                                      content_permission="ProposedPR")
        self.setup_input(refreshed(source, self.clock.value), historical=True)
        self.validator = cv.StagedCodeValidator(str(self.root), str(self.repo), clock=self.clock)
        def callback(data, _p, _t):
            return json.dumps(self.candidate(json.loads(data), anchors=[{
                "segment_index": 0, "item_index": 0, "line_number": 3, "quote": "+new = 2"
            }])).encode()
        self.outcome = self.dispatch(adapter=callback)
        self.kw = dict(expected_parent_pin=self.pin, run_id=self.route_opts["run_id"],
                       handoff_id=self.route_opts["handoff_id"],
                       expected_revision=self.route_opts["expected_revision"],
                       expected_event_sha256=self.route_opts["expected_event_sha256"],
                       input_operation_key=self.route_opts["operation_key"],
                       validation_operation_key="codevalidate-staged-0001",
                       authorize_validate=True, authorize_read=True,
                       validate_content_for="ProposedPR",
                       expected_candidate_sha256=self.outcome["result"]["candidate_sha256"],
                       allow_historical_proposal=True, max_source_age_seconds=600)
        self.setup_save_store()
        self.signed_review = self.review()
        self.validation = self.with_review(receipt=self.signed_review)
        self.save_kw = dict(
            expected_save_store_pin=self.store_pin, expected_parent_pin=self.pin,
            run_id=self.kw["run_id"], handoff_id=self.kw["handoff_id"],
            expected_revision=self.kw["expected_revision"],
            expected_event_sha256=self.kw["expected_event_sha256"],
            input_operation_key=self.kw["input_operation_key"],
            validation_operation_key=self.kw["validation_operation_key"],
            save_operation_key="codesave-staged-0001",
            expected_candidate_sha256=self.kw["expected_candidate_sha256"],
            expected_validation_receipt_sha256=self.validation["validation_receipt_sha256"],
            authorize_save=True, authorize_read=True, save_content_for="ProposedPR",
            manual_review=self.signed_review, authorize_manual_review=True,
            manual_review_content_for="ProposedPR", trusted_verifier_id="synthetic-reviewer",
            trusted_verifier_key=self.review_key(), allow_historical_proposal=True,
            max_source_age_seconds=600, acknowledge_partial_coverage=True,
        )
        self.deny(self.save(), "CODESAVE_HISTORICAL_PROPOSAL_SEPARATE_SAVE_APPROVAL_REQUIRED")
        result = self.save(approve_historical_proposal_metadata_save=True)
        self.assertEqual(result["status"], "partial", result)
        self.assertEqual(result["stored"]["source_mode"], "ProposedPR")
        self.assertFalse(result["stored"]["source_currentness_proven"])

    def test_no_save_root_inside_repo_or_staging_root(self):
        self.prepare()
        with self.assertRaises(st.StageError):
            subroot = self.repo / "save"
            subroot.mkdir(mode=0o700)
            cs.StagedCodeSaver(str(self.root), str(self.repo), str(subroot)).initialize(approve_init=True)
        with self.assertRaises(st.StageError):
            nested = self.root / "save"
            nested.mkdir(mode=0o700)
            cs.StagedCodeSaver(str(self.root), str(self.repo), str(nested)).initialize(approve_init=True)

    def test_cli_initialization_inspect_and_read_do_not_accept_review_keys_or_source_text(self):
        self.prepare()
        self.save_parent = self.root.parent.parent / "isolated_save_parent"
        self.save_parent.mkdir(mode=0o700)
        self.save_root = self.save_parent / "metadata"
        self.save_root.mkdir(mode=0o700)
        argv = [sys.executable, str(Path(cs.__file__)),
                "--stage-root", str(self.root), "--business-repo-root", str(self.repo),
                "--save-root", str(self.save_root)]
        denied = subprocess.run(argv + ["--init"], capture_output=True, text=True)
        self.assertEqual(denied.returncode, 4, denied.stdout)
        permitted = subprocess.run(argv + ["--init", "--approve-init"], capture_output=True, text=True)
        self.assertEqual(permitted.returncode, 0, permitted.stdout + permitted.stderr)
        pin = json.loads(permitted.stdout)["save_store_pin"]
        inspect = subprocess.run(argv + ["--inspect", "--save-store-pin", pin],
                                 capture_output=True, text=True)
        self.assertEqual(inspect.returncode, 0, inspect.stdout)
        self.assertEqual(json.loads(inspect.stdout)["record_count"], 0)
        help_text = subprocess.run([sys.executable, str(Path(cs.__file__)), "--help"],
                                   capture_output=True, text=True).stdout
        self.assertNotIn("--trusted-verifier-key", help_text)
        self.assertNotIn("--save ", help_text)


if __name__ == "__main__":
    unittest.main()
