#!/usr/bin/env python3
"""EC178 local synthetic FindingSave behavior: no external actor, CI, Git or native acceptance."""
from __future__ import annotations

import copy
from datetime import timedelta
from pathlib import Path
import json
import os
import threading
import unittest
from unittest.mock import patch

import finding_save as fsave
import finding_schema as fs
import codevalidate_staged as cv
import codeprepare_multisource as ec170
import test_codeprepare_multisource as source_fixtures
from test_handoff_input import refreshed
import task_staging as st
import test_finding_schema as older


class FindingSaveCases(unittest.TestCase):
    setUp = older.FindingSchemaCases.setUp
    setup_projection = older.FindingSchemaCases.setup_projection
    setup_input = older.FindingSchemaCases.setup_input
    act = older.FindingSchemaCases.act
    callback = older.FindingSchemaCases.callback
    setup_save_store = older.FindingSchemaCases.setup_save_store
    project = older.FindingSchemaCases.project
    prepare = older.FindingSchemaCases.prepare
    validate = older.FindingSchemaCases.validate
    review = older.FindingSchemaCases.review
    with_review = older.FindingSchemaCases.with_review
    candidate = older.FindingSchemaCases.candidate
    dispatch = older.FindingSchemaCases.dispatch
    review_key = staticmethod(older.FindingSchemaCases.review_key)
    start = older.FindingSchemaCases.start
    save = older.FindingSchemaCases.save

    def setup_historical(self, signed):
        snap, _ = source_fixtures.ec165.create(selected=("src/service.py",), include=True)
        source = ec170.prepare_context("ProposedPR", proposed_snapshot=snap,
                                       content_permission="ProposedPR")
        self.setup_input(refreshed(source, self.clock.value), historical=True)
        self.validator = cv.StagedCodeValidator(str(self.root), str(self.repo), clock=self.clock)
        def adapter(payload, _provider, _timeout):
            item = self.candidate(json.loads(payload), anchors=[{
                "segment_index": 0, "item_index": 0,
                "line_number": 3, "quote": "+new = 2"}])
            return json.dumps(item).encode()
        self.outcome = self.dispatch(adapter=adapter)
        self.kw = {
            "expected_parent_pin": self.pin,
            "run_id": self.route_opts["run_id"], "handoff_id": self.route_opts["handoff_id"],
            "expected_revision": self.route_opts["expected_revision"],
            "expected_event_sha256": self.route_opts["expected_event_sha256"],
            "input_operation_key": self.route_opts["operation_key"],
            "validation_operation_key": "codevalidate-staged-0001",
            "authorize_validate": True, "authorize_read": True,
            "validate_content_for": "ProposedPR",
            "expected_candidate_sha256": self.outcome["result"]["candidate_sha256"],
            "allow_historical_proposal": True, "max_source_age_seconds": 600,
        }
        self.review_receipt = self.review(signed) if signed is not None else None
        self.original = (self.with_review(receipt=self.review_receipt)
                         if signed is not None else self.validate())
        self.projector = fs.FindingProjector(str(self.root), str(self.repo), clock=self.clock)
        self.proj_kw = {
            "expected_parent_pin": self.pin, "run_id": self.kw["run_id"],
            "handoff_id": self.kw["handoff_id"],
            "expected_revision": self.kw["expected_revision"],
            "expected_event_sha256": self.kw["expected_event_sha256"],
            "input_operation_key": self.kw["input_operation_key"],
            "validation_operation_key": self.kw["validation_operation_key"],
            "finding_operation_key": "finding-schema-0001",
            "expected_candidate_sha256": self.kw["expected_candidate_sha256"],
            "expected_validation_receipt_sha256": self.original["validation_receipt_sha256"],
            "authorize_project": True, "authorize_read": True,
            "project_content_for": "ProposedPR",
            "allow_historical_proposal": True, "acknowledge_historical_only": True,
        }
        if signed is not None:
            self.proj_kw.update({
                "manual_review": self.review_receipt,
                "authorize_manual_review": True, "manual_review_content_for": "ProposedPR",
                "trusted_verifier_id": "synthetic-reviewer",
                "trusted_verifier_key": self.review_key(),
            })

    def start_finding(self, *, signed=("confirm",), saved=False, historical=False):
        if historical and not saved:
            self.setup_historical(signed)
        else:
            self.setup_projection(signed=signed, saved=saved, historical=historical)
        self.preview = self.project()
        self.assertEqual(self.preview["status"], "partial", self.preview)
        self.ledger_parent = self.root.parent.parent / "finding_ledger_parent"
        self.ledger_parent.mkdir(mode=0o700)
        self.ledger_root = self.ledger_parent / "ces_findings"
        self.ledger_root.mkdir(mode=0o700)
        self.finder = fsave.FindingSaver(
            str(self.root), str(self.repo), str(self.ledger_root),
            codesave_root=(str(self.save_root) if saved else None), clock=self.clock)
        init = self.finder.initialize(approve_init=True)
        self.assertEqual(init["status"], "success", init)
        self.ledger_pin = init["save_store_pin"]
        self.save_args = {
            "expected_finding_store_pin": self.ledger_pin,
            "finding_save_operation_key": "findingsave-ec178-00001",
            "authorized_finding_ids": [f["finding_id"] for f in self.preview["findings"]],
            "authorize_save": True, "authorize_source_read": True,
            "save_content_for": self.prepared["source_mode"],
            "projection_kwargs": dict(self.proj_kw),
            "operator_label": "fixture-caller-not-authenticated",
            "expected_projection_sha256": self.preview["projection_sha256"],
            "approve_historical_proposal_save": historical,
            "acknowledge_partial_coverage": historical,
        }

    def commit(self, **overrides):
        kw = dict(self.save_args)
        kw.update(overrides)
        return self.finder.save(self.prepared, self.outcome, self.original, **kw)

    def denied(self, result, reason=None, *, status=None):
        self.assertIn(result["status"], ("invalid_input", "unavailable"), result)
        if reason:
            self.assertEqual(result["reason_code"], reason, result)
        if status:
            self.assertEqual(result["status"], status, result)
        self.assertFalse(result["effects"]["business_repository_written"])
        self.assertFalse(result["effects"]["git_or_issue_written"])
        self.assertFalse(result["effects"]["source_or_model_text_persisted"])

    def files(self):
        return list(self.ledger_root.glob("finding_batch_*.json"))

    def test_actual_ces_only_finding_persistence_with_provenance_and_no_raw_text(self):
        self.start_finding()
        repo_before = (self.repo / "read-only.py").read_bytes()
        stage_before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        result = self.commit()
        self.assertEqual((result["status"], result["exit_code"]), ("partial", 2), result)
        self.assertTrue(result["effects"]["finding_declarations_persisted"])
        self.assertTrue(result["effects"]["ces_finding_batch_committed"])
        self.assertEqual(result["saved_count"], 1)
        self.assertEqual(result["stored"]["status_counts"]["REVIEWED"], 1)
        self.assertFalse(result["stored"]["actual_tests_or_ci_proven"])
        self.assertEqual(len(self.files()), 1)
        raw = self.files()[0].read_text()
        for literal in ("+new", "read-only.py", "diff --git", "Synthetic patch line",
                        "Independent synthetic review", "Review the change", "synthetic-reviewer"):
            self.assertNotIn(literal, raw)
        record = json.loads(raw)
        self.assertEqual(record["schema"], fsave.RECORD_SCHEMA_V2)
        self.assertEqual(record["findings"][0]["assessment_state"], "REVIEWED")
        self.assertEqual(record["findings"][0]["finding_id"], result["saved_finding_ids"][0])
        self.assertEqual(record["authorization_audit"]["approved_count"], 1)
        self.assertFalse(record["authorization_audit"]["operator_identity_authenticated"])
        self.assertFalse(record["defect_semantically_confirmed"])
        self.assertEqual(repo_before, (self.repo / "read-only.py").read_bytes())
        self.assertEqual(stage_before, {p.name: p.read_bytes() for p in self.root.iterdir()})
        ins = self.finder.inspect(expected_finding_store_pin=self.ledger_pin, authorize_inspect=True)
        self.assertEqual((ins["batch_count"], ins["finding_declarations_count"]), (1, 1), ins)

    def test_idempotent_reentry_never_changes_immutable_file_or_expiration(self):
        self.start_finding()
        first = self.commit()
        self.assertEqual(first["status"], "partial", first)
        prior = self.files()[0].read_bytes()
        later = self.commit()
        self.assertEqual(later["status"], "partial", later)
        self.assertTrue(later["idempotent_reentry"])
        self.assertEqual(first["batch_record_sha256"], later["batch_record_sha256"])
        self.assertEqual(first["expires_at_utc"], later["expires_at_utc"])
        self.assertEqual(self.files()[0].read_bytes(), prior)

    def test_source_or_approval_grant_change_under_same_operation_is_conflict(self):
        self.start_finding()
        self.assertEqual(self.commit()["status"], "partial")
        self.denied(self.commit(operator_label="different-caller"),
                    "FINDINGSAVE_SAME_OPERATION_DIFFERENT_SOURCE_GRANTS_OR_FINDINGS")
        self.assertEqual(len(self.files()), 1)

    def test_different_operation_cannot_duplicate_same_finding(self):
        self.start_finding()
        self.assertEqual(self.commit()["status"], "partial")
        self.denied(self.commit(finding_save_operation_key="findingsave-ec178-00002"),
                    "FINDINGSAVE_DUPLICATE_FINDING_DIFFERENT_OPERATION_REFUSED")

    def test_missing_or_unrelated_per_finding_authorization_fails_without_write(self):
        self.start_finding()
        for ids in ([], ["0"*64], [self.preview["findings"][0]["finding_id"]]*2,
                    "anything", [True]):
            self.denied(self.commit(authorized_finding_ids=ids),
                        "FINDINGSAVE_EXACT_PER_FINDING_APPROVAL_IDS_REQUIRED")
        self.assertEqual(self.files(), [])

    def test_independent_save_and_source_grants_are_not_inherited(self):
        self.start_finding()
        for changes in ({"authorize_save": False}, {"authorize_source_read": False},
                        {"save_content_for": "DeliveredTarget"},
                        {"expected_finding_store_pin": "0"*64},
                        {"finding_save_operation_key": self.proj_kw["finding_operation_key"]}):
            self.denied(self.commit(**changes))
        self.assertEqual(self.files(), [])

    def test_unsigned_claim_requires_explicit_both_acknowledgments(self):
        self.start_finding(signed=None)
        self.assertEqual(self.preview["findings"][0]["assessment"]["state"], "UNVERIFIED")
        self.denied(self.commit(),
                    "FINDINGSAVE_UNREVIEWED_REJECTED_OR_INCONCLUSIVE_REQUIRES_EXPLICIT_ACK")
        self.denied(self.commit(allow_non_reviewed=True),
                    "FINDINGSAVE_UNREVIEWED_REJECTED_OR_INCONCLUSIVE_REQUIRES_EXPLICIT_ACK")
        result = self.commit(allow_non_reviewed=True, acknowledge_non_reviewed=True)
        self.assertEqual(result["status"], "partial", result)
        self.assertEqual(result["stored"]["status_counts"]["UNVERIFIED"], 1)
        self.assertFalse(result["stored"]["defect_truth_proven"])

    def test_rejected_and_inconclusive_are_storable_only_as_unverified_declarations(self):
        for verdict, state in (("reject", "REJECTED"), ("inconclusive", "INCONCLUSIVE")):
            with self.subTest(verdict=verdict):
                self.start_finding(signed=(verdict,))
                self.denied(self.commit())
                result = self.commit(allow_non_reviewed=True, acknowledge_non_reviewed=True)
                self.assertEqual(result["status"], "partial", result)
                self.assertEqual(result["stored"]["status_counts"][state], 1)
                # Reset fixture for independent source/stage/store per subcase.
                self.setUp()

    def test_historical_proposal_requires_a_new_findingsave_grant(self):
        self.start_finding(historical=True)
        self.denied(self.commit(approve_historical_proposal_save=False),
                    "FINDINGSAVE_HISTORICAL_PROPOSAL_REQUIRES_NEW_SAVE_APPROVAL")
        result = self.commit()
        self.assertEqual(result["status"], "partial", result)
        self.assertTrue(result["stored"]["historical_proposal_only"])

    def test_incomplete_coverage_requires_separate_ack(self):
        self.start_finding(historical=True)
        self.denied(self.commit(acknowledge_partial_coverage=False),
                    "FINDINGSAVE_INCOMPLETE_SOURCE_REQUIRES_SEPARATE_ACKNOWLEDGMENT")

    def test_old_unkeyed_projection_digest_does_not_bypass_real_replay(self):
        self.start_finding()
        self.denied(self.commit(expected_projection_sha256="f"*64),
                    "FINDINGSAVE_UNKEYED_PROJECTION_PIN_DIFFERS_FROM_REAL_SOURCE")
        altered = copy.deepcopy(self.original)
        altered["candidate"]["findings"][0]["review_state"] = "FAKE_VERIFIED"
        self.original = altered
        self.denied(self.commit())
        self.assertEqual(self.files(), [])

    def test_missing_or_changed_manual_review_key_causes_real_replay_failure(self):
        self.start_finding()
        kw = dict(self.proj_kw)
        kw["trusted_verifier_key"] = b"0"*32
        self.denied(self.commit(projection_kwargs=kw))
        self.assertEqual(self.files(), [])

    def test_expired_source_or_validation_not_eligible_even_with_copied_hashes(self):
        self.start_finding()
        self.clock.value += timedelta(seconds=330)
        self.denied(self.commit())
        self.assertEqual(self.files(), [])

    def test_optional_ec176_record_requires_true_hmac_link_read_and_new_permissions(self):
        self.start_finding(saved=True)
        result = self.commit()
        self.assertEqual(result["status"], "partial", result)
        data = json.loads(self.files()[0].read_bytes())
        self.assertEqual(data["saved_metadata_record_sha256"],
                         self.preview["saved_metadata_link"]["record_sha256"])
        self.assertFalse(data["defect_semantically_confirmed"])

    def test_optional_ec176_saved_link_rejects_revocation(self):
        self.start_finding(saved=True)
        kw = dict(self.proj_kw)
        kw["authorize_saved_record_read"] = False
        self.denied(self.commit(projection_kwargs=kw))
        self.assertEqual(self.files(), [])

    def test_counter_evidence_is_persisted_as_sealed_anchor_and_interpretation_hashes_only(self):
        self.start_finding()
        counter = [{"ordinal": 1, "anchors": [{"segment_index": 0,
                    "item_index": None, "line_number": 1, "quote": "+new"}],
                    "interpretation": "Caller proposes non-executable code branch."}]
        # The old synthetic fixture may use a different line/quote. Use actual
        # sealed EC173 line from its candidate's own verified positive anchor.
        original = self.outcome["result"]["findings"][0]["anchors"][0]
        counter[0]["anchors"] = [{"segment_index": original["segment_index"],
                                   "item_index": original["item_index"],
                                   "line_number": original["line_number_in_segment_or_item"],
                                   "quote": original["quote"]}]
        kw = dict(self.proj_kw, counter_evidence=counter)
        projection = self.project(counter_evidence=counter)
        self.assertEqual(projection["status"], "partial", projection)
        result = self.commit(projection_kwargs=kw,
                             expected_projection_sha256=projection["projection_sha256"])
        self.assertEqual(result["status"], "partial", result)
        raw = self.files()[0].read_text()
        self.assertNotIn(counter[0]["interpretation"], raw)
        self.assertNotIn(original["quote"], raw)
        rec = json.loads(raw)
        self.assertEqual(len(rec["findings"][0]["counter_evidence"]), 1)

    def test_text_grant_is_not_a_permission_to_persist_source_or_model_words(self):
        self.start_finding()
        kw = dict(self.proj_kw, disclose_text=True,
                  authorize_text_disclosure=True, disclose_content_for="WorkingTree")
        self.denied(self.commit(projection_kwargs=kw),
                    "FINDINGSAVE_FRESH_READ_SCOPED_METADATA_ONLY_PROJECTION_REQUIRED")

    def test_permission_store_root_identity_symlink_or_overlap_denied(self):
        self.start_finding()
        bad = fsave.FindingSaver(str(self.root), str(self.repo), str(self.root), clock=self.clock)
        with self.assertRaises(st.StageError):
            bad.initialize(approve_init=True)
        extra = self.ledger_parent / "alias"
        extra.symlink_to(self.ledger_root, target_is_directory=True)
        aliased = fsave.FindingSaver(str(self.root), str(self.repo), str(extra), clock=self.clock)
        with self.assertRaises(st.StageError):
            aliased.initialize(approve_init=True)

    def test_unknown_file_poisoning_detected_and_no_more_writes(self):
        self.start_finding()
        (self.ledger_root / "unknown.tmp").write_text("untrusted")
        self.denied(self.commit(), "FINDINGSAVE_UNKNOWN_STORE_ENTRY_REFUSED")

    def test_private_key_tamper_and_record_tamper_refused(self):
        self.start_finding()
        self.assertEqual(self.commit()["status"], "partial")
        target = self.files()[0]
        data = bytearray(target.read_bytes())
        pos = data.index(b'REVIEWED')
        data[pos] ^= 0x01
        target.write_bytes(data)
        self.denied(self.commit(), status="unavailable")
        self.denied(self.finder.inspect(expected_finding_store_pin=self.ledger_pin,
                                       authorize_inspect=True), status="unavailable")

    def test_hardlink_and_symlink_record_rejected(self):
        self.start_finding()
        self.assertEqual(self.commit()["status"], "partial")
        target = self.files()[0]
        os.link(target, self.ledger_parent / "external-hardlink")
        self.denied(self.finder.inspect(expected_finding_store_pin=self.ledger_pin,
                                       authorize_inspect=True), status="unavailable")

    def test_unfinished_pending_transaction_blocks_retries(self):
        self.start_finding()
        (self.ledger_root / (".pending-finding-" + "a"*32)).write_text("unfinished")
        self.denied(self.commit(), "FINDINGSAVE_UNFINISHED_PUBLISH_REQUIRES_MANUAL_REVIEW")

    def test_linked_but_unconfirmed_fsync_failure_reports_uncertain_commit(self):
        self.start_finding()
        original = os.fsync
        calls = [0]
        def fsync_crash(fd):
            calls[0] += 1
            if calls[0] == 2:  # one pending file fsync then linked target dir fsync
                raise OSError("synthetic sync interruption")
            return original(fd)
        with patch.object(fsave.os, "fsync", side_effect=fsync_crash):
            result = self.commit()
        self.denied(result, "FINDINGSAVE_PUBLISH_DURABILITY_UNCERTAIN", status="unavailable")
        self.assertIsNone(result["effects"]["ces_finding_batch_committed"])
        self.assertEqual(len(self.files()), 1)

    def test_simultaneous_saves_get_one_atomic_batch_and_one_read_only_replay(self):
        self.start_finding()
        barrier = threading.Barrier(2)
        outputs = []
        def worker():
            barrier.wait(timeout=5)
            outputs.append(self.commit())
        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=25)
        self.assertEqual(len(outputs), 2, outputs)
        self.assertEqual([r["status"] for r in outputs], ["partial", "partial"], outputs)
        self.assertEqual(sum(r["idempotent_reentry"] for r in outputs), 1)
        self.assertEqual(len(self.files()), 1)

    def test_expired_record_never_renews_under_same_or_other_operation(self):
        self.start_finding()
        self.assertEqual(self.commit()["status"], "partial")
        self.clock.value += timedelta(seconds=180)
        self.denied(self.commit())
        self.assertEqual(len(self.files()), 1)

    def test_per_finding_subset_two_atomic_batches_append_link_and_conflict(self):
        self.start_finding()
        def model_adapter(payload, _provider, _timeout):
            candidate = self.candidate(json.loads(payload))
            second = copy.deepcopy(candidate["findings"][0])
            second["title"] = "A second independently approved synthetic claim"
            candidate["findings"].append(second)
            return json.dumps(candidate).encode()
        self.outcome = self.dispatch(adapter=model_adapter)
        self.kw["expected_candidate_sha256"] = self.outcome["result"]["candidate_sha256"]
        self.review_receipt = self.review(("confirm", "confirm"))
        self.original = self.with_review(receipt=self.review_receipt)
        self.proj_kw.update({
            "expected_candidate_sha256": self.kw["expected_candidate_sha256"],
            "expected_validation_receipt_sha256": self.original["validation_receipt_sha256"],
            "manual_review": self.review_receipt,
        })
        self.preview = self.project()
        self.assertEqual(self.preview["findings_count"], 2)
        ids = [r["finding_id"] for r in self.preview["findings"]]
        self.save_args.update({
            "expected_projection_sha256": self.preview["projection_sha256"],
            "projection_kwargs": dict(self.proj_kw),
        })
        one = self.commit(authorized_finding_ids=[ids[0]])
        self.assertEqual((one["status"], one["saved_count"]), ("partial", 1), one)
        two = self.commit(finding_save_operation_key="findingsave-second-batch-0001",
                          authorized_finding_ids=[ids[1]])
        self.assertEqual((two["status"], two["saved_count"]), ("partial", 1), two)
        self.assertEqual(len(self.files()), 2)
        raw = [json.loads(p.read_text()) for p in sorted(self.files())]
        self.assertEqual(raw[0]["sequence"], 1)
        self.assertIsNone(raw[0]["previous_record_sha256"])
        self.assertEqual(raw[1]["previous_record_sha256"], raw[0]["record_sha256"])
        self.assertEqual(raw[1]["sequence"], 2)
        self.assertEqual(self.finder.inspect(expected_finding_store_pin=self.ledger_pin,
                                            authorize_inspect=True)["finding_declarations_count"], 2)
        self.denied(self.commit(finding_save_operation_key="findingsave-third-batch-0001",
                                authorized_finding_ids=[ids[0], ids[1]]),
                    "FINDINGSAVE_DUPLICATE_FINDING_DIFFERENT_OPERATION_REFUSED")

    def test_narrower_expiry_policy_rejects_same_operation_reentry(self):
        self.start_finding()
        first = self.commit(ttl_seconds=300)
        self.assertEqual(first["status"], "partial", first)
        self.denied(self.commit(ttl_seconds=60),
                    "FINDINGSAVE_SAME_OPERATION_DIFFERENT_SOURCE_GRANTS_OR_FINDINGS")
        self.assertEqual(len(self.files()), 1)

    def test_old_expired_record_not_resurrected_before_source_validation_expires(self):
        self.start_finding()
        first = self.commit(ttl_seconds=60)
        self.assertEqual(first["status"], "partial", first)
        self.clock.value += timedelta(seconds=65)
        self.denied(self.commit(ttl_seconds=60),
                    "FINDINGSAVE_EXPIRED_RECORD_CANNOT_BE_REVIVED")
        self.assertEqual(len(self.files()), 1)

    def test_prior_chain_link_integrity_rejects_deleted_or_wrong_sequence(self):
        self.start_finding()
        self.assertEqual(self.commit()["status"], "partial")
        target = self.files()[0]
        tampered = json.loads(target.read_text())
        tampered["sequence"] = 2
        target.write_text(json.dumps(tampered) + "\n")
        result = self.finder.inspect(expected_finding_store_pin=self.ledger_pin,
                                     authorize_inspect=True)
        self.denied(result, status="unavailable")

    def test_machine_schema_accepts_real_hmac_batch_and_rejects_false_ci_claim(self):
        from jsonschema import Draft202012Validator
        self.start_finding()
        result = self.commit()
        self.assertEqual(result["status"], "partial", result)
        schema = json.loads((Path(__file__).resolve().parent.parent / "references" /
                             "finding-save-batch.v2.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        record = json.loads(self.files()[0].read_text())
        Draft202012Validator(schema).validate(record)
        record["verified_actual_ci_or_test"] = True
        self.assertFalse(Draft202012Validator(schema).is_valid(record))
        record["verified_actual_ci_or_test"] = False
        record["findings"][0]["raw_code"] = "code should never persist"
        self.assertFalse(Draft202012Validator(schema).is_valid(record))

    def test_store_init_and_inspect_have_distinct_grants(self):
        self.start_finding()
        self.denied(self.finder.inspect(expected_finding_store_pin=self.ledger_pin,
                                       authorize_inspect=False),
                    "FINDINGSAVE_INSPECT_REQUIRES_SEPARATE_GRANT")
        with self.assertRaises(fsave.FindingSaveError):
            self.finder.initialize(approve_init=False)


if __name__ == "__main__":
    unittest.main()
