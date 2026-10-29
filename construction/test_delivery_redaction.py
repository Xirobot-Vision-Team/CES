#!/usr/bin/env python3
"""EC222 focused local functional tests; disposable EC200+EC179 HMAC stores.

No production identity/recipient/organizational policy, external send, Git/CI,
PowerShell or OS/NFS multi-host acceptance is implied by these tests.
"""
from __future__ import annotations

from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

import delivery_preview as dp
import delivery_redaction as dr
import test_delivery_preview as fixtures

SCHEMA = json.loads((Path(__file__).resolve().parent.parent / "references" /
                     "delivery-redaction-result.v1.schema.json").read_text("utf-8"))
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)


def request_for(sources):
    return fixtures.request(sources, policy_revision_sha256=dr.ACTIVE_POLICY_SHA256)


def review_request(base, expected, *, report=True, finding=False, witnesses=()):
    return dr.SensitiveReviewRequest(
        base, expected, dr.ACTIVE_POLICY_SHA256, True, report, finding, tuple(witnesses)
    )


class Checks(unittest.TestCase):
    def checked(self, result, state):
        failures = list(VALIDATOR.iter_errors(result))
        self.assertEqual(failures, [], failures)
        self.assertEqual(result["status"], state, result)
        self.assertFalse(any(result["effects"].values()))
        self.assertEqual(result["delivery_state"], "NO_DELIVERY_OR_PUBLICATION")
        self.assertNotIn("read-only.py", json.dumps(result))
        self.assertNotIn("Synthetic patch line", json.dumps(result))
        if state in ("partial", "blocked"):
            self.assertFalse(result["review"]["safe_for_external_send"])
            self.assertFalse(result["review"]["ready_to_send"])
            self.assertFalse(result["review"]["is_deliverable_payload"])
            self.assertEqual(result["review"]["review_id"], result["review_id"])
            self.assertEqual(result["review"]["policy_revision_sha256"],
                             dr.ACTIVE_POLICY_SHA256)
        else:
            self.assertIsNone(result["review"])
        if state == "partial":
            self.assertEqual(hashlib.sha256(result["redacted_markdown"].encode()).hexdigest(),
                             result["redacted_markdown_sha256"])
        else:
            self.assertIsNone(result["redacted_markdown"])
            self.assertIsNone(result["redacted_markdown_sha256"])
        return result


class ReportCases(Checks):
    def setUp(self):
        self.fixture = fixtures.ReportPreviewCases()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        policy = f.fx.policy(f.tmp.name, f.saved, markdown=True)
        self.selection = replace(f.selection, read_policy=policy)
        self.base = request_for((self.selection,))
        self.preview = dp.preview_delivery(self.base)
        self.assertEqual(self.preview["status"], "partial")

    def do(self, **kwargs):
        req = replace(review_request(self.base, self.preview["preview_id"]), **kwargs)
        return dr.review_sensitive_delivery(req)

    def test_genuine_saved_report_exact_plaintext_scanned_and_only_metadata_emitted(self):
        result = self.checked(self.do(), "partial")
        self.assertEqual(result["review"]["verdict"], "SAFE_REDACTED_SUMMARY")
        self.assertTrue(result["review"]["source_assessments"][0]["content_examined"])
        original = self.fixture.saved["subject"]["rendered_markdown"]
        self.assertNotIn(original, json.dumps(result, ensure_ascii=False))
        self.assertEqual(result["review"]["effective_minimum_privacy_class"], "INTERNAL")
        self.assertNotEqual(result["redacted_markdown_sha256"],
                            self.selection.expected_rendered_sha256)

    def test_fresh_sensitive_review_and_report_plaintext_permissions_preflight(self):
        for kw, code in (
            ({"permit_independent_sensitive_policy_review": False},
             "INDEPENDENT_SENSITIVE_POLICY_REVIEW_GRANT_REQUIRED"),
            ({"permit_exact_report_plaintext_review": False},
             "FRESH_REPORT_PLAINTEXT_REVIEW_GRANT_REQUIRED"),
            ({"permit_independent_sensitive_policy_review": 1},
             "SENSITIVE_REVIEW_GRANT_TYPE_INVALID"),
        ):
            with self.subTest(kw=kw), patch.object(
                self.fixture.fx.history, "show",
                side_effect=AssertionError("No local store read should occur")
            ):
                res = self.checked(self.do(**kw),
                                   "invalid_input" if 1 in kw.values() else "unavailable")
                self.assertIn(code, res["reason_code"])

    def test_report_existing_ec200_per_repository_markdown_grants_needed(self):
        policy = self.fixture.fx.policy(self.fixture.tmp.name, self.fixture.saved,
                                        markdown=False)
        base = replace(self.base, sources=(replace(self.selection, read_policy=policy),))
        with patch.object(self.fixture.fx.history, "show",
                          side_effect=AssertionError("Must fail before read")):
            result = dr.review_sensitive_delivery(
                review_request(base, self.preview["preview_id"]))
        self.checked(result, "unavailable")
        self.assertIn("EC200_EXACT_MARKDOWN_GRANTS_REQUIRED", result["reason_code"])

    def test_policy_fingerprint_is_fixed_not_untrusted_arbitrary_hash(self):
        bad_policy = replace(self.base, policy_revision_sha256="a" * 64)
        with patch.object(self.fixture.fx.history, "show",
                          side_effect=AssertionError("Should not read")):
            res = dr.review_sensitive_delivery(
                review_request(bad_policy, self.preview["preview_id"]))
            self.checked(res, "invalid_input")
            self.assertIn("UNKNOWN_OR_MISMATCHED_POLICY_REVISION", res["reason_code"])

    def test_stale_preview_or_mutated_destination_denied(self):
        changed = replace(self.base, destination=fixtures.dest(
            recipient_identity_sha256=fixtures.digest("different-recipient")))
        res = dr.review_sensitive_delivery(
            review_request(changed, self.preview["preview_id"]))
        self.checked(res, "unavailable")
        self.assertIn("EXACT_EC221_PREVIEW_UNAVAILABLE_OR_STALE", res["reason_code"])

    def test_tampered_underlying_report_reader_cannot_upgrade_to_safe(self):
        owner = self.fixture.fx.history
        original = owner.show
        def forged(**kwargs):
            doc = original(**kwargs)
            if kwargs.get("include_markdown") and doc["status"] == "partial":
                doc["subject"]["rendered_markdown"] += "\nsecret_token=xxxxxxxxxxx"
            return doc
        with patch.object(owner, "show", side_effect=forged):
            self.checked(self.do(), "unavailable")

    def test_sensitive_detector_blocks_patch_secret_paths_person_and_obfuscated(self):
        vectors = (
            ("diff --git a/src/a.py b/src/a.py\n@@ -1,1 +1,1 @@", "PATCH_OR_DIFF_CONTENT"),
            ("- Credentials: password=correct-horse-battery", "CREDENTIAL_OR_TOKEN_MATERIAL"),
            ("See src/engine/reader.py", "REPOSITORY_PATH_OR_SOURCE_FILENAME"),
            ("contact: alice@example.org", "PERSON_OR_CONTACT_CONTENT"),
            ("Call +1 212 555 0101", "PERSON_OR_CONTACT_CONTENT"),
            ("- Report slot: `malicious\u202e`", "OBFUSCATED_OR_UNCLASSIFIABLE_CONTENT"),
            ("- path: %2fsecret%2frepo", "OBFUSCATED_OR_UNCLASSIFIABLE_CONTENT"),
        )
        for text, code in vectors:
            with self.subTest(code=code, text=text[:16]):
                self.assertIn(code, dr._check_report_text(text))

    def test_unrecognized_report_freeform_is_not_automatically_safe(self):
        self.assertIn("REPORT_LINE_OUTSIDE_STRICT_TEMPLATE",
                      dr._check_report_text("- Human performance: excellent"))
        self.assertIn("REPORT_LINE_OUTSIDE_STRICT_TEMPLATE",
                      dr._check_report_text("# Different report template"))

    def test_read_error_does_not_leak_secret_exception_text(self):
        with patch.object(self.fixture.fx.history, "show",
                          side_effect=OSError("account secret=PRIVATE-DATA")):
            res = self.checked(self.do(), "unavailable")
            self.assertNotIn("PRIVATE-DATA", json.dumps(res))


class FindingCases(Checks):
    def setUp(self):
        self.fixture = fixtures.FindingPreviewCases()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.selection = self.fixture.selection
        self.raw = copy.deepcopy(self.fixture.fx.outcome["result"]["findings"][0])
        self.base = request_for((self.selection,))
        self.preview = dp.preview_delivery(self.base)
        self.assertEqual(self.preview["status"], "partial")

    def do(self, witnesses=(), **kwargs):
        req = replace(review_request(self.base, self.preview["preview_id"],
                                     report=False, finding=True,
                                     witnesses=witnesses), **kwargs)
        return dr.review_sensitive_delivery(req)

    def test_private_finding_only_hashes_missing_plaintext_blocks(self):
        result = self.checked(self.do(), "blocked")
        self.assertEqual(result["review"]["reason_codes"],
                         ["FINDING_TEXT_NOT_AVAILABLE_IN_PRIVATE_STORE"])
        self.assertFalse(result["review"]["source_assessments"][0]["content_examined"])

    def test_real_hash_bound_original_can_be_examined_but_unreviewed_content_blocks(self):
        w = dr.FindingTextWitness(0, self.raw)
        result = self.checked(self.do((w,)), "blocked")
        self.assertTrue(result["review"]["source_assessments"][0]["content_examined"])
        self.assertIn("FINDING_TEXT_OUTSIDE_NARROW_SAFE_VOCABULARY",
                      result["review"]["reason_codes"])
        self.assertNotIn(self.raw["analysis"], json.dumps(result))

    def test_modified_original_witness_does_not_pass_hash_binding(self):
        modified = copy.deepcopy(self.raw)
        modified["title"] = "Not the same original text"
        result = self.checked(self.do((dr.FindingTextWitness(0, modified),)), "blocked")
        self.assertEqual(result["review"]["reason_codes"],
                         ["FINDING_ORIGINAL_WITNESS_HASH_MISMATCH"])
        self.assertFalse(result["review"]["source_assessments"][0]["content_examined"])

    def test_non_finding_or_duplicate_witnesses_preflight_before_private_read(self):
        for ws in (
            (dr.FindingTextWitness(1, self.raw),),
            (dr.FindingTextWitness(0, self.raw), dr.FindingTextWitness(0, self.raw)),
            (dr.FindingTextWitness(True, self.raw),),
            (dr.FindingTextWitness(0, {"raw": "unverifiable"}),),
        ):
            with self.subTest(n=len(ws)), patch.object(
                self.selection.reader, "query",
                side_effect=AssertionError("Must reject witness before private read")
            ):
                self.checked(self.do(ws), "invalid_input")

    def test_independent_finding_plaintext_grant_before_store_read(self):
        with patch.object(self.selection.reader, "query",
                          side_effect=AssertionError("Must fail before store read")):
            self.checked(self.do(permit_exact_finding_plaintext_review=False),
                         "unavailable")

    def test_finding_policy_fails_closed_on_real_selected_revision_drift(self):
        altered = replace(self.selection, expected_revision_sha256="b"*64)
        base = replace(self.base, sources=(altered,))
        result = dr.review_sensitive_delivery(review_request(
            base, self.preview["preview_id"], report=False, finding=True))
        self.checked(result, "unavailable")

    def test_finding_scanner_blocks_any_repository_path_even_neutral_quote(self):
        changed = copy.deepcopy(self.raw)
        changed["title"] = "Synthetic local example only"
        changed["analysis"] = "Generic local metadata only"
        changed["suggested_action"] = "No change"
        changed["anchors"][0]["source_path"] = "src/secrets.py"
        self.assertIn("REPOSITORY_PATH_OR_SOURCE_FILENAME",
                      dr._check_finding_text(changed))


class MixedCases(Checks):
    def test_mixed_real_local_private_sources_block_without_leaking_first_report(self):
        rep = fixtures.ReportPreviewCases(); rep.setUp()
        self.addCleanup(rep.doCleanups)
        find = fixtures.FindingPreviewCases(); find.setUp()
        self.addCleanup(find.doCleanups)
        source = replace(rep.selection, read_policy=rep.fx.policy(
            rep.tmp.name, rep.saved, markdown=True))
        base = request_for((source, find.selection))
        p = dp.preview_delivery(base)
        self.assertEqual(p["status"], "partial")
        res = dr.review_sensitive_delivery(review_request(
            base, p["preview_id"], finding=True))
        self.checked(res, "blocked")
        self.assertEqual([x["source_kind"] for x in res["review"]["source_assessments"]],
                         ["REPORT", "FINDING"])
        self.assertNotIn(rep.saved["subject"]["rendered_markdown"], json.dumps(res))
        self.assertNotIn(find.fx.outcome["result"]["findings"][0]["analysis"], json.dumps(res))


if __name__ == "__main__":
    unittest.main()
