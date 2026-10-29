#!/usr/bin/env python3
"""EC179 focused, disposable, synthetic-only FindingShow functional cases.

No real source/Provider/reviewer identity/Git currentness/CI or native PowerShell
is certified by these tests. Genuine EC178 private stores are created by fixtures.
"""
from __future__ import annotations

import copy
from datetime import timedelta
import json
from pathlib import Path
import unittest

import finding_show as show
import finding_save as save
import task_staging as st
import test_finding_save as older


class FindingShowCases(unittest.TestCase):
    setUp = older.FindingSaveCases.setUp
    setup_projection = older.FindingSaveCases.setup_projection
    setup_input = older.FindingSaveCases.setup_input
    act = older.FindingSaveCases.act
    callback = older.FindingSaveCases.callback
    setup_save_store = older.FindingSaveCases.setup_save_store
    project = older.FindingSaveCases.project
    prepare = older.FindingSaveCases.prepare
    validate = older.FindingSaveCases.validate
    review = older.FindingSaveCases.review
    with_review = older.FindingSaveCases.with_review
    candidate = older.FindingSaveCases.candidate
    dispatch = older.FindingSaveCases.dispatch
    review_key = staticmethod(older.FindingSaveCases.review_key)
    start = older.FindingSaveCases.start
    save = older.FindingSaveCases.save
    setup_historical = older.FindingSaveCases.setup_historical
    start_finding = older.FindingSaveCases.start_finding
    commit = older.FindingSaveCases.commit
    files = older.FindingSaveCases.files

    def begin(self, *, signed=("confirm",), historical=False, saved=False,
              ttl_seconds=300):
        self.start_finding(signed=signed, historical=historical, saved=saved)
        opts = {}
        if signed is None:
            opts = {"allow_non_reviewed": True, "acknowledge_non_reviewed": True}
        self.commit_result = self.commit(ttl_seconds=ttl_seconds, **opts)
        self.assertEqual(self.commit_result["status"], "partial", self.commit_result)
        self.show = show.FindingShower(
            str(self.root), str(self.repo), str(self.ledger_root),
            codesave_root=(str(self.save_root) if saved else None), clock=self.clock)
        self.params = {
            "expected_finding_store_pin": self.ledger_pin,
            "authorize_store_read": True,
            "authorize_query": True,
            "authorized_source_binding": dict(self.preview["source_binding"]),
            "query_content_for": self.prepared["source_mode"],
            "acknowledge_historical_proposal_metadata": historical,
        }

    def lookup(self, **kw):
        opts = dict(self.params)
        opts.update(kw)
        return self.show.query(**opts)

    def denied(self, result, code=None, status=None):
        self.assertIn(result["status"], ("unavailable", "invalid_input"), result)
        self.assertEqual(result["findings"], [], result)
        self.assertIsNone(result["next_cursor"], result)
        self.assertFalse(result["effects"]["external_transfer"])
        self.assertFalse(result["effects"]["plaintext_source_or_model_released"])
        if code:
            self.assertEqual(result["reason_code"], code, result)
        if status:
            self.assertEqual(result["status"], status, result)

    def second_batch(self, *, count=2, commits=2):
        """Create 2-3 real source-revalidated IDs and append 1-3 genuine batches."""
        # Like EC178 multi-batch fixture, but reuse exactly sealed EC175 sources.
        def adapter(payload, _provider, _timeout):
            candidate = self.candidate(json.loads(payload))
            for n in range(2, count + 1):
                next_claim = copy.deepcopy(candidate["findings"][0])
                next_claim["title"] = f"Synthetic independent claim {n}"
                candidate["findings"].append(next_claim)
            return json.dumps(candidate).encode()
        self.outcome = self.dispatch(adapter=adapter)
        self.kw["expected_candidate_sha256"] = self.outcome["result"]["candidate_sha256"]
        self.review_receipt = self.review(("confirm",) * count)
        self.original = self.with_review(receipt=self.review_receipt)
        self.proj_kw.update({
            "expected_candidate_sha256": self.kw["expected_candidate_sha256"],
            "expected_validation_receipt_sha256": self.original["validation_receipt_sha256"],
            "manual_review": self.review_receipt,
        })
        self.preview = self.project()
        self.assertEqual(self.preview["findings_count"], count)
        ids = sorted(f["finding_id"] for f in self.preview["findings"])
        self.save_args.update({
            "expected_projection_sha256": self.preview["projection_sha256"],
            "projection_kwargs": dict(self.proj_kw),
        })
        for i in range(commits):
            op = "findingsave-ec178-00001" if i == 0 else f"show-batch-{i+1:03}-001"
            self.assertEqual(self.commit(finding_save_operation_key=op,
                                         authorized_finding_ids=[ids[i]])["status"], "partial")
        self.show = show.FindingShower(str(self.root), str(self.repo),
                                       str(self.ledger_root), clock=self.clock)
        self.params = {
            "expected_finding_store_pin": self.ledger_pin,
            "authorize_store_read": True, "authorize_query": True,
            "authorized_source_binding": dict(self.preview["source_binding"]),
            "query_content_for": self.prepared["source_mode"],
        }
        return ids

    def new_empty_store(self):
        self.start_finding()
        self.show = show.FindingShower(str(self.root), str(self.repo),
                                       str(self.ledger_root), clock=self.clock)
        self.params = {
            "expected_finding_store_pin": self.ledger_pin,
            "authorize_store_read": True, "authorize_query": True,
            "authorized_source_binding": dict(self.preview["source_binding"]),
            "query_content_for": self.prepared["source_mode"],
        }

    def make_legacy_v1_record(self):
        """Fixture only: reconstruct correctly signed EC178 v1 bytes from a v2 row.

        This simulates an already-existing genuine EC178 v1 ledger; production
        FindingShow does not rewrite, migrate, or modify any old records.
        """
        target = self.files()[0]
        record = json.loads(target.read_text())
        self.assertEqual(record.pop("schema"), save.RECORD_SCHEMA_V2)
        record.pop("path_index")
        record["schema"] = save.RECORD_SCHEMA
        record.pop("record_sha256")
        record.pop("mac_sha256")
        record["record_sha256"] = save._sha(save.DOMAIN_RECORD, record)
        key = (self.ledger_root / save.ROOT_KEY).read_bytes()
        record["mac_sha256"] = save._mac(key, record)
        target.write_bytes(st._canonical(record) + b"\n")
        return target, record

    def test_real_sealed_store_query_has_semantic_boundaries_and_no_plaintext(self):
        self.begin()
        result = self.lookup()
        self.assertEqual((result["status"], result["exit_code"]), ("partial", 2), result)
        self.assertEqual(result["matched_count"], 1)
        self.assertEqual(result["findings"][0]["finding_id"], self.preview["findings"][0]["finding_id"])
        self.assertEqual(result["findings"][0]["assessment_state"], "REVIEWED")
        self.assertFalse(result["findings"][0]["semantic_defect_verified"])
        self.assertFalse(result["findings"][0]["current_git_verified"])
        self.assertTrue(result["provenance"]["complete_private_manifest_key_and_hash_chain_checked"])
        self.assertNotIn("digest_details", result["findings"][0])
        literal = json.dumps(result)
        for text in ("read-only.py", "diff --git", "Synthetic patch line", "Independent synthetic review",
                     "+new", "synthetic-reviewer", "key_holder_review_attestation_sha256"):
            self.assertNotIn(text, literal)
        self.assertFalse(result["effects"]["ces_records_written"])
        self.assertFalse(result["effects"]["source_code_or_tests_executed"])

    def test_grants_must_be_independent_for_each_page(self):
        self.begin()
        for overrides in ({"authorize_store_read": False}, {"authorize_query": False},
                          {"authorize_store_read": 1}, {"authorize_query": "true"}):
            self.denied(self.lookup(**overrides),
                        "FINDINGSHOW_INDEPENDENT_STORE_READ_AND_QUERY_GRANTS_REQUIRED")

    def test_missing_wrong_or_other_store_pin_fails_closed(self):
        self.begin()
        self.denied(self.lookup(expected_finding_store_pin="0" * 64),
                    "FINDINGSHOW_STORE_PIN_OR_ROOT_MISMATCH", "unavailable")
        self.denied(self.lookup(expected_finding_store_pin="insecure"),
                    "FINDINGSHOW_STORE_PIN_REQUIRED", "invalid_input")

    def test_exact_full_source_binding_capability_not_just_mode(self):
        self.begin()
        source = dict(self.params["authorized_source_binding"])
        source["source_context_sha256"] = "f" * 64
        r = self.lookup(authorized_source_binding=source)
        self.assertEqual(r["matched_count"], 0, r)
        self.assertEqual(r["findings"], [], r)
        self.assertEqual(r["status"], "partial")
        self.denied(self.lookup(authorized_source_binding={"source_mode": "WorkingTree"}),
                    "FINDINGSHOW_EXACT_SOURCE_BINDING_SCOPE_REQUIRED")

    def test_forbidden_cross_source_mode_and_missing_historical_ack(self):
        self.begin(historical=True)
        self.denied(self.lookup(query_content_for="WorkingTree"),
                    "FINDINGSHOW_SOURCE_SCOPE_SHAPE_OR_MODE_INVALID")
        self.denied(self.lookup(acknowledge_historical_proposal_metadata=False),
                    "FINDINGSHOW_HISTORICAL_PROPOSAL_REQUIRES_METADATA_ACK")
        self.assertTrue(self.lookup()["findings"][0]["historical_proposal_only"])

    def test_exact_finding_id_and_severity_confidence_state_queries(self):
        self.begin()
        item = self.preview["findings"][0]
        self.assertEqual(self.lookup(filters={"finding_id": item["finding_id"]})["matched_count"], 1)
        for filters in ({"severity": "medium"}, {"confidence_claim": "low"},
                        {"assessment_state": "REVIEWED"},
                        {"run_id": item["identity"]["source_binding"]["run_id"]}):
            # Test against the actual stored value rather than assuming model states.
            if "severity" in filters:
                filters = {"severity": item["classification"]["severity"]["value"]}
            if "confidence_claim" in filters:
                filters = {"confidence_claim": item["classification"]["confidence"]["value"]}
            self.assertEqual(self.lookup(filters=filters)["matched_count"], 1, filters)
        self.assertEqual(self.lookup(filters={"finding_id": "0" * 64})["matched_count"], 0)

    def test_source_and_batch_scope_fields_are_exact_not_fuzzy(self):
        self.begin()
        src = self.preview["source_binding"]
        record = json.loads(self.files()[0].read_text())
        for key in show.SOURCE_FILTERS:
            self.assertEqual(self.lookup(filters={key: src[key]})["matched_count"], 1, key)
        self.assertEqual(self.lookup(filters={"candidate_sha256": record["candidate_sha256"]})["matched_count"], 1)
        self.assertEqual(self.lookup(filters={"coverage_complete": True})["matched_count"], 1)
        self.assertEqual(self.lookup(filters={"historical_proposal_only": False})["matched_count"], 1)
        self.assertEqual(self.lookup(filters={"candidate_sha256": "0" * 64})["matched_count"], 0)
        self.assertEqual(self.lookup(filters={"coverage_complete": False})["matched_count"], 0)

    def test_invalid_wildcard_raw_path_unknown_keys_and_type_confusion(self):
        self.begin()
        for filters in ({"raw_path": "src/service.py"}, {"path_identity_sha256": "src/service.py"},
                        {"severity": "*"}, {"severity": 1}, {"assessment_state": "ACTUALLY_TESTED"},
                        {"coverage_complete": 1}, {"run_id": "unknown"},
                        {"source_identity_sha256": "ABC"}, {"stage_revision": True},
                        ["any"], "severity=high"):
            self.denied(self.lookup(filters=filters))
        self.denied(self.lookup(page_size=26), "FINDINGSHOW_PAGE_SIZE_OUT_OF_BOUNDS")
        self.denied(self.lookup(page_size=0), "FINDINGSHOW_PAGE_SIZE_OUT_OF_BOUNDS")
        self.denied(self.lookup(page_size=True), "FINDINGSHOW_PAGE_SIZE_OUT_OF_BOUNDS")

    def test_v2_exact_path_digest_only_with_separate_grant(self):
        self.begin(historical=True)
        path = self.preview["findings"][0]["evidence"]["positive_anchors"][0]["source_path_sha256"]
        self.assertIsNotNone(path)
        self.denied(self.lookup(filters={"path_identity_sha256": path}),
                    "FINDINGSHOW_PATH_DIGEST_SEARCH_NEEDS_NEW_GRANT")
        one = self.lookup(filters={"path_identity_sha256": path}, authorize_path_digest_query=True)
        self.assertEqual(one["matched_count"], 1, one)
        self.assertTrue(one["path_index"]["path_filter_exhaustive_for_authorized_records"])
        self.assertEqual(one["findings"][0]["path_index_state"], "COMPLETE")
        self.assertEqual(self.lookup(filters={"path_identity_sha256": "f" * 64},
                                     authorize_path_digest_query=True)["matched_count"], 0)
        self.assertNotIn("src/service.py", json.dumps(one))

    def test_unpathable_positive_anchor_does_not_fake_full_path_coverage(self):
        self.begin()
        r = self.lookup(filters={"path_identity_sha256": "a" * 64},
                        authorize_path_digest_query=True)
        self.assertEqual(r["matched_count"], 0)
        self.assertFalse(r["path_index"]["path_filter_exhaustive_for_authorized_records"])
        self.assertEqual(r["path_index"]["partial_v2_unpathable_in_authorized_nonpath_scope"], 1)
        self.assertEqual(self.lookup()["findings"][0]["path_index_state"], "PARTIAL_OR_UNPATHED")

    def test_existing_ec178_v1_batch_supported_without_inferred_path(self):
        self.begin(historical=True)
        target, old = self.make_legacy_v1_record()
        self.assertEqual(json.loads(target.read_text())["schema"], save.RECORD_SCHEMA)
        result = self.lookup()
        self.assertEqual(result["matched_count"], 1, result)
        self.assertEqual(result["findings"][0]["path_index_state"], "LEGACY_V1_UNAVAILABLE")
        path = self.preview["findings"][0]["evidence"]["positive_anchors"][0]["source_path_sha256"]
        by_path = self.lookup(filters={"path_identity_sha256": path}, authorize_path_digest_query=True)
        self.assertEqual(by_path["matched_count"], 0)
        self.assertFalse(by_path["path_index"]["path_filter_exhaustive_for_authorized_records"])
        self.assertEqual(by_path["path_index"]["legacy_v1_unindexed_in_authorized_nonpath_scope"], 1)

    def test_no_digest_details_by_default_and_separate_authorization_to_reveal(self):
        self.begin(historical=True)
        self.denied(self.lookup(include_digest_details=True),
                    "FINDINGSHOW_HASH_DETAILS_NEED_SEPARATE_GRANT")
        detailed = self.lookup(include_digest_details=True, authorize_digest_details=True)
        dig = detailed["findings"][0]["digest_details"]
        self.assertEqual(len(dig["positive_anchor_sha256"]), 1)
        self.assertEqual(dig["positive_anchor_path_sha256"][0],
                         self.preview["findings"][0]["evidence"]["positive_anchors"][0]["source_path_sha256"])
        self.assertNotIn("src/service.py", json.dumps(detailed))

    def test_expiry_hidden_by_default_and_explicit_stale_audit_never_renews(self):
        self.begin(ttl_seconds=60)
        first = self.lookup()
        self.assertEqual(first["matched_count"], 1)
        raw_before = self.files()[0].read_bytes()
        self.clock.value += timedelta(seconds=61)
        self.assertEqual(self.lookup()["matched_count"], 0)
        self.denied(self.lookup(include_expired=True),
                    "FINDINGSHOW_EXPIRED_AUDIT_NEEDS_SEPARATE_GRANT")
        history = self.lookup(include_expired=True, authorize_expired_audit=True)
        self.assertEqual(history["matched_count"], 1)
        self.assertTrue(history["findings"][0]["expired_at_query_time"])
        self.assertFalse(history["findings"][0]["semantic_defect_verified"])
        self.assertEqual(raw_before, self.files()[0].read_bytes())

    def test_clock_rollback_rejected_before_exposing_record(self):
        self.begin()
        self.clock.value -= timedelta(seconds=60)
        self.denied(self.lookup(), "FINDINGSHOW_LEDGER_CLOCK_ROLLBACK", "unavailable")

    def test_corrupt_record_hmac_blocks_even_unmatched_query(self):
        self.begin()
        target = self.files()[0]
        target.write_bytes(target.read_bytes().replace(b'"confidence_claim":"low"',
                                                         b'"confidence_claim":"high"'))
        self.denied(self.lookup(filters={"finding_id": "0" * 64}), status="unavailable")

    def test_malformed_or_poisoned_manifest_key_and_pending_blocks_all_reads(self):
        self.begin()
        pending = self.ledger_root / (".pending-finding-" + "0" * 32)
        pending.write_bytes(b"test")
        self.denied(self.lookup(), status="unavailable")
        pending.unlink()
        (self.ledger_root / save.ROOT_KEY).write_bytes(b"1" * 32)
        self.denied(self.lookup(), status="unavailable")

    def test_store_lock_and_root_permissions_cannot_be_bypassed(self):
        self.begin()
        self.ledger_root.chmod(0o755)
        self.denied(self.lookup(), status="unavailable")
        self.ledger_root.chmod(0o700)
        self.ledger_root.rename(self.ledger_root.with_name("relocated"))
        self.denied(self.lookup(), status="unavailable")

    def test_pagination_hmac_cursor_stable_order_and_expiry_cannot_be_extended(self):
        self.new_empty_store()
        ids = self.second_batch()
        first = self.lookup(page_size=1)
        self.assertEqual(first["matched_count"], 2, first)
        self.assertEqual(first["returned_count"], 1, first)
        self.assertEqual(first["findings"][0]["finding_id"], ids[0])
        self.assertIsInstance(first["next_cursor"], str)
        second = self.lookup(page_size=1, cursor=first["next_cursor"])
        self.assertEqual(second["findings"][0]["finding_id"], ids[1])
        self.assertIsNone(second["next_cursor"])
        self.assertEqual(self.lookup(page_size=1, cursor=first["next_cursor"]), second)
        self.assertEqual(second["status"], "partial")

    def test_tampered_cursor_and_bearer_token_without_grants_refused(self):
        self.new_empty_store()
        self.second_batch()
        first = self.lookup(page_size=1)
        cursor = first["next_cursor"]
        self.assertIsNotNone(cursor)
        changed = ("a" if cursor[0] != "a" else "b") + cursor[1:]
        self.denied(self.lookup(page_size=1, cursor=changed), status="unavailable")
        self.denied(self.lookup(page_size=1, cursor=cursor, authorize_query=False),
                    "FINDINGSHOW_INDEPENDENT_STORE_READ_AND_QUERY_GRANTS_REQUIRED")
        self.denied(self.lookup(page_size=1, cursor="invalid"))

    def test_cursor_rejects_filter_page_size_and_scope_switch(self):
        self.new_empty_store()
        self.second_batch()
        cursor = self.lookup(page_size=1)["next_cursor"]
        self.denied(self.lookup(page_size=2, cursor=cursor),
                    "FINDINGSHOW_CURSOR_SCOPE_OR_STORE_REVISION_CHANGED", "unavailable")
        self.denied(self.lookup(page_size=1, cursor=cursor, filters={"severity": "high"}),
                    "FINDINGSHOW_CURSOR_SCOPE_OR_STORE_REVISION_CHANGED", "unavailable")
        scope = dict(self.params["authorized_source_binding"])
        scope["material_sha256"] = "e" * 64
        self.denied(self.lookup(page_size=1, cursor=cursor, authorized_source_binding=scope),
                    "FINDINGSHOW_CURSOR_SCOPE_OR_STORE_REVISION_CHANGED", "unavailable")

    def test_cursor_expires_without_refresh_and_does_not_skip_after_record_ttl(self):
        self.new_empty_store()
        self.second_batch()
        first = self.lookup(page_size=1)
        cursor = first["next_cursor"]
        self.clock.value += timedelta(seconds=301)
        self.denied(self.lookup(page_size=1, cursor=cursor), status="unavailable")

    def test_cursor_invalid_after_real_append_with_valid_new_hmac_batch(self):
        self.new_empty_store()
        ids = self.second_batch(count=3, commits=2)
        original = self.lookup(page_size=1)
        self.assertEqual(original["matched_count"], 2)
        token = original["next_cursor"]
        third = self.commit(finding_save_operation_key="show-third-batch-001",
                            authorized_finding_ids=[ids[2]])
        self.assertEqual(third["status"], "partial", third)
        fresh = self.lookup()
        self.assertEqual(fresh["matched_count"], 3, fresh)
        self.denied(self.lookup(page_size=1, cursor=token),
                    "FINDINGSHOW_CURSOR_SCOPE_OR_STORE_REVISION_CHANGED", "unavailable")

    def test_v1_record_can_be_replayed_and_extended_with_real_v2_batch(self):
        self.new_empty_store()
        ids = self.second_batch(count=3, commits=1)
        _, legacy = self.make_legacy_v1_record()
        self.assertEqual(self.lookup()["findings"][0]["path_index_state"],
                         "LEGACY_V1_UNAVAILABLE")
        # Old data and old EC178 idempotent permission semantics are unchanged.
        replay = self.commit(authorized_finding_ids=[ids[0]])
        self.assertTrue(replay["idempotent_reentry"], replay)
        self.assertEqual(replay["stored"]["schema"], save.RECORD_SCHEMA)
        new = self.commit(finding_save_operation_key="show-second-batch-001",
                          authorized_finding_ids=[ids[1]])
        self.assertEqual(new["status"], "partial", new)
        rows = [json.loads(p.read_text()) for p in sorted(self.files())]
        self.assertEqual([r["schema"] for r in rows],
                         [save.RECORD_SCHEMA, save.RECORD_SCHEMA_V2])
        self.assertEqual(rows[1]["previous_record_sha256"], rows[0]["record_sha256"])
        query = self.lookup()
        self.assertEqual(query["matched_count"], 2)
        self.assertEqual([i["path_index_state"] for i in query["findings"]],
                         ["LEGACY_V1_UNAVAILABLE", "PARTIAL_OR_UNPATHED"])

    def test_empty_private_store_read_is_not_missing_defect_proof(self):
        self.new_empty_store()
        r = self.lookup()
        self.assertEqual(r["matched_count"], 0)
        self.assertEqual(r["status"], "partial")
        self.assertIn("NOT_ABSENCE_PROOF", r["reason_code"])
        self.assertTrue(r["provenance"]["complete_private_manifest_key_and_hash_chain_checked"])

    def test_nonreviewed_state_remains_unverified_not_tested(self):
        self.begin(signed=None)
        r = self.lookup(filters={"assessment_state": "UNVERIFIED"})
        self.assertEqual(r["matched_count"], 1, r)
        self.assertTrue(r["findings"][0]["assessment_is_only_local_key_holder_declaration"])
        self.assertFalse(r["findings"][0]["actual_test_or_ci_verified"])

    def test_deferred_machine_schema_for_both_accept_and_refuse(self):
        # The schema is authored with this round and checked in execution.
        from jsonschema import Draft202012Validator
        self.begin()
        schema = json.loads((Path(__file__).parent.parent / "references" /
                             "finding-show-result.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        good = self.lookup()
        bad = self.lookup(authorize_query=False)
        Draft202012Validator(schema).validate(good)
        Draft202012Validator(schema).validate(bad)
        changed = copy.deepcopy(good)
        changed["effects"]["current_git_verified"] = True
        self.assertFalse(Draft202012Validator(schema).is_valid(changed))
        changed = copy.deepcopy(good)
        changed["findings"][0]["raw_code"] = "must not leak"
        self.assertFalse(Draft202012Validator(schema).is_valid(changed))


if __name__ == "__main__":
    unittest.main()
