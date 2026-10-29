#!/usr/bin/env python3
"""EC166 development fixtures only: no live provider or native CES execution."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

import proposed_pr_reconcile as reconcile
import proposed_pr_snapshot as snapshot
import proposed_pr_source as source
import test_proposed_pr_paths as ec163
import test_proposed_pr_snapshot as ec165


class SingleGet:
    def __init__(self, item: dict | Exception) -> None:
        self.item = item if isinstance(item, Exception) else copy.deepcopy(item)
        self.calls: list[str] = []
        self.urls: list[str] = []

    def get_object(self, url, headers, timeout):
        self.calls.append("META")
        self.urls.append(url)
        if isinstance(self.item, Exception):
            raise self.item
        return copy.deepcopy(self.item)

    def get_page(self, url, headers, timeout):
        self.calls.append("PAGE")
        raise AssertionError("EC166 must not request historical file pages")


def request(provider="github", prior=None, *, current=None, pin=None,
            allow_network=True, token_supplier=None, key=None):
    count = 3 if provider == "github" else "2"
    if prior is None and pin is None:
        prior, _ = ec165.create(provider)
    if current is None:
        current = ec163.metadata(provider, count)
    tx = SingleGet(current)
    target = key or source.RequestKey(
        provider, "example/repo" if provider == "github" else "my-group/sub-group/repo", 8)
    result = reconcile.reconcile_proposed_pr(
        target, prior_snapshot=prior, expected_pin=pin,
        allow_network=allow_network, transport=tx,
        token_supplier=token_supplier or (lambda: "SYNTHETIC-SAFE-TOKEN"),
    )
    return result, tx


class ReconcileTests(unittest.TestCase):
    def test_github_matching_snapshot_reobserves_one_metadata_without_reusing_pages(self):
        out, tx = request()
        self.assertEqual((out["status"], out["exit_code"]), ("partial", 2))
        self.assertEqual(out["reconciliation_state"], "FRESH_OBSERVATION")
        self.assertEqual(out["comparison"]["pin_state"], "MATCHED")
        self.assertEqual(out["comparison"]["count_state"], "MATCHED_EXACT_CLAIM")
        self.assertEqual(out["comparison"]["changed_fields"], [])
        self.assertEqual(out["current_observation"]["source"], "GITHUB_PULL_METADATA_SINGLE_GET")
        self.assertEqual(out["current_observation"]["reported_files"], 3)
        self.assertTrue(out["current_observation"]["observed_at_utc"])
        self.assertEqual(tx.calls, ["META"])
        self.assertEqual(len(tx.urls), 1)
        self.assertTrue(tx.urls[0].startswith("https://api.github.com/repos/example/repo/pulls/8"))
        self.assertFalse(out["evidence_policy"]["prior_snapshot_currentness_proven"])
        self.assertFalse(out["evidence_policy"]["cross_page_atomicity_proven"])
        self.assertFalse(out["diff_snapshot_proven"])
        self.assertFalse(out["write_authorized"])
        self.assertFalse(out["delivery_or_merge_proven"])
        self.assertFalse(out["native_cli_action_registered"])
        self.assertEqual(out["prior"]["coverage_state"], "COMPLETE")

    def test_gitlab_matching_snapshot_describes_diff_refs_semantics(self):
        out, tx = request("gitlab")
        self.assertEqual(out["reconciliation_state"], "FRESH_OBSERVATION")
        self.assertEqual(out["current_observation"]["source"],
                         "GITLAB_MERGE_REQUEST_METADATA_SINGLE_GET")
        self.assertEqual(out["current_observation"]["pin"]["base_semantics"],
                         "gitlab_diff_refs_merge_base_not_target_branch_tip")
        self.assertEqual(tx.calls, ["META"])
        self.assertNotIn("title", json.dumps(out))

    def test_pin_only_comparison_must_not_invent_earlier_file_count(self):
        pin = ec163.prior("github", 3)
        out, _ = request(prior=None, pin=pin)
        # request() supplies no EC165 if a standalone pin is supplied.
        self.assertEqual(out["reconciliation_state"], "FRESH_OBSERVATION")
        self.assertEqual(out["prior"]["kind"], "EC162_PIN")
        self.assertEqual(out["comparison"]["count_state"], "NOT_BASELINED")
        self.assertEqual(out["reason_code"], "IDENTITY_OBSERVATION_MATCHED_COUNT_NOT_BASELINED")
        self.assertIsNone(out["prior"]["observation_ref"])

    def test_optional_pin_and_snapshot_both_match(self):
        old, _ = ec165.create()
        pin = ec163.prior("github", 3)
        out, _ = request(prior=old, pin=pin)
        self.assertEqual(out["reconciliation_state"], "FRESH_OBSERVATION")
        self.assertEqual(out["prior"]["kind"], "EC165_SNAPSHOT_AND_EC162_PIN")
        self.assertEqual(out["prior"]["observation_ref"], old["observation_ref"])

    def test_head_and_base_drift_do_not_return_old_file_list(self):
        for segment in ("head", "base"):
            with self.subTest(segment=segment):
                modified = ec163.metadata("github", 3)
                modified[segment]["sha"] = "d" * 40
                out, tx = request(current=modified)
                self.assertEqual(out["reconciliation_state"], "STALE_BY_DRIFT")
                self.assertEqual(out["status"], "partial")
                self.assertEqual(out["exit_code"], 2)
                self.assertEqual(out["comparison"]["pin_state"], "DRIFT")
                self.assertIn(segment + "_sha", out["comparison"]["changed_fields"])
                self.assertTrue(out["comparison"]["prior_evidence_invalidated_by_metadata"])
                self.assertEqual(tx.calls, ["META"])
                self.assertNotIn("ordered_pages", json.dumps(out))
                self.assertNotIn("patch_text", json.dumps(out))

    def test_gitlab_target_tip_only_drift_is_stale(self):
        modified = ec163.metadata("gitlab", "2")
        modified["diff_refs"]["start_sha"] = "d" * 40
        out, _ = request("gitlab", current=modified)
        self.assertEqual(out["reconciliation_state"], "STALE_BY_DRIFT")
        self.assertEqual(out["comparison"]["changed_fields"], ["target_tip_sha"])
        self.assertFalse(out["delivery_or_merge_proven"])

    def test_github_target_repo_identity_drift_is_not_just_branch_change(self):
        modified = ec163.metadata("github", 3)
        modified["base"]["repo"]["id"] = 933
        out, _ = request(current=modified)
        self.assertEqual(out["reconciliation_state"], "STALE_BY_DRIFT")
        self.assertEqual(out["comparison"]["changed_fields"], ["target_repository_id"])
        detail = out["comparison"]["changes"][0]
        self.assertEqual(detail["previous"], "404")
        self.assertEqual(detail["current"], "933")

    def test_source_fork_transfer_and_proposal_id_change_detected(self):
        for change, field in (("fork", "source_repository_id"),
                              ("object", "proposal_object_id")):
            with self.subTest(change=change):
                modified = ec163.metadata("github", 3)
                if change == "fork":
                    modified["head"]["repo"]["id"] = 999
                    modified["head"]["repo"]["full_name"] = "new-fork/repo"
                else:
                    modified["id"] = 1333
                out, _ = request(current=modified)
                self.assertEqual(out["reconciliation_state"], "STALE_BY_DRIFT")
                self.assertIn(field, out["comparison"]["changed_fields"])

    def test_merge_and_state_claim_changed_only_as_metadata_not_delivery(self):
        for provider in ("github", "gitlab"):
            with self.subTest(provider=provider):
                modified = ec163.metadata(provider, 3 if provider == "github" else "2")
                if provider == "github":
                    modified["state"] = "closed"
                    modified["merged"] = True
                else:
                    modified["state"] = "merged"
                out, _ = request(provider, current=modified)
                self.assertEqual(out["reconciliation_state"], "STALE_BY_DRIFT")
                self.assertIn("provider_state", out["comparison"]["changed_fields"])
                self.assertIn("provider_reports_merged", out["comparison"]["changed_fields"])
                self.assertFalse(out["evidence_policy"]["delivery_or_merge_proven"])

    def test_count_change_invalidates_even_when_all_oids_unchanged(self):
        for provider, updated in (("github", 5), ("gitlab", "5")):
            with self.subTest(provider=provider):
                modified = ec163.metadata(provider, updated)
                out, _ = request(provider, current=modified)
                self.assertEqual(out["reconciliation_state"], "STALE_BY_DRIFT")
                self.assertEqual(out["comparison"]["pin_state"], "MATCHED")
                self.assertEqual(out["comparison"]["count_state"], "CHANGED")
                self.assertEqual(out["comparison"]["changed_fields"],
                                 ["provider_reported_changed_files"])
                self.assertTrue(out["comparison"]["prior_evidence_invalidated_by_metadata"])

    def test_unavailable_auth_never_uses_previous_etag_to_guess(self):
        old, _ = ec165.create()
        tx = SingleGet(source.SourceFailure("PROVIDER_AUTH_UNAVAILABLE", "untrusted token text"))
        result = reconcile.reconcile_proposed_pr(
            source.RequestKey("github", "example/repo", 8),
            prior_snapshot=old, allow_network=True, transport=tx,
            token_supplier=lambda: "token-not-for-output",
        )
        self.assertEqual(result["reconciliation_state"], "UNAVAILABLE_UNKNOWN")
        self.assertEqual(result["reason_code"], "PROVIDER_AUTH_UNAVAILABLE")
        self.assertIsNone(result["current_observation"])
        self.assertIsNone(result["comparison"]["prior_evidence_invalidated_by_metadata"])
        self.assertFalse(result["evidence_policy"]["old_etags_used_as_remote_proof"])
        self.assertNotIn("token-not-for-output", json.dumps(result))
        self.assertNotIn("untrusted token text", json.dumps(result))

    def test_missing_fork_gitlab_diff_refs_unknown_state_all_unavailable(self):
        cases = []
        data = ec163.metadata("github", 3)
        data["head"]["repo"] = None
        cases.append(("github", data))
        data = ec163.metadata("gitlab", "2")
        data["diff_refs"] = None
        cases.append(("gitlab", data))
        data = ec163.metadata("gitlab", "2")
        data["state"] = "unknown-future-state"
        cases.append(("gitlab", data))
        for provider, current in cases:
            with self.subTest(provider=provider, case=str(current)[:50]):
                out, tx = request(provider, current=current)
                self.assertEqual(out["reconciliation_state"], "UNAVAILABLE_UNKNOWN")
                self.assertEqual(out["status"], "unavailable")
                self.assertIsNone(out["current_observation"])
                self.assertEqual(tx.calls, ["META"])

    def test_gitlab_head_diff_refs_mismatch_is_unknown_not_stale(self):
        data = ec163.metadata("gitlab", "2")
        data["diff_refs"]["head_sha"] = "d" * 40
        out, _ = request("gitlab", current=data)
        self.assertEqual(out["reconciliation_state"], "UNAVAILABLE_UNKNOWN")
        self.assertEqual(out["reason_code"], "PROVIDER_METADATA_INCONSISTENT")

    def test_capped_gitlab_count_cannot_establish_freshness(self):
        old, _ = ec165.create("gitlab", count="1000+")
        out, _ = request("gitlab", prior=old, current=ec163.metadata("gitlab", "1000+"))
        self.assertEqual(out["reconciliation_state"], "UNAVAILABLE_UNKNOWN")
        self.assertEqual(out["comparison"]["count_state"], "INDETERMINATE")
        self.assertEqual(out["reason_code"], "CHANGE_COUNT_NOT_COMPARABLE")
        self.assertFalse(out["evidence_policy"]["prior_snapshot_currentness_proven"])

    def test_old_count_unreported_then_exact_becomes_stale_not_fresh(self):
        meta = ec163.metadata("github", None)
        old, _ = ec165.create("github", prior=ec163.prior("github", None),
                              metadata_reads=[meta, meta])
        self.assertEqual(old["evidence_material"]["path_coverage"]["state"], "UNKNOWN")
        new = ec163.metadata("github", 3)
        out, _ = request(prior=old, current=new)
        self.assertEqual(out["reconciliation_state"], "STALE_BY_DRIFT")
        self.assertEqual(out["comparison"]["count_state"], "CHANGED")
        self.assertIn("provider_change_count_quality", out["comparison"]["changed_fields"])

    def test_old_and_new_unreported_counts_remain_unknown(self):
        meta = ec163.metadata("github", None)
        old, _ = ec165.create("github", prior=ec163.prior("github", None),
                              metadata_reads=[meta, meta])
        out, _ = request(prior=old, current=meta)
        self.assertEqual(out["reconciliation_state"], "UNAVAILABLE_UNKNOWN")
        self.assertEqual(out["comparison"]["changed_fields"], [])

    def test_no_prior_rejects_without_looking_up_provider(self):
        tx = SingleGet(ec163.metadata("github", 3))
        called = []
        out = reconcile.reconcile_proposed_pr(
            source.RequestKey("github", "example/repo", 8),
            allow_network=True, transport=tx,
            token_supplier=lambda: called.append("token") or "abc",
        )
        self.assertEqual(out["reason_code"], "PRIOR_EVIDENCE_REQUIRED")
        self.assertEqual(tx.calls, [])
        self.assertEqual(called, [])

    def test_snapshot_tampering_mismatched_prior_pin_and_locator_fails_preflight(self):
        old, _ = ec165.create()
        fake = copy.deepcopy(old)
        fake["observation_ref"] = "sha256:" + "0" * 64
        for prior, pin, key, reason in (
            (fake, None, source.RequestKey("github", "example/repo", 8), "INVALID_PRIOR_SNAPSHOT"),
            (old, ec163.prior("gitlab", "2"), source.RequestKey("github", "example/repo", 8),
             "PRIOR_EVIDENCE_CONFLICT"),
            (old, None, source.RequestKey("github", "other/repo", 8), "PRIOR_LOCATOR_MISMATCH"),
        ):
            with self.subTest(reason=reason):
                out, tx = request(prior=prior, pin=pin, key=key,
                                  token_supplier=lambda: self.fail("premature token read"))
                self.assertEqual(out["reason_code"], reason)
                self.assertEqual(tx.calls, [])

    def test_network_default_off_never_consults_tokens(self):
        old, _ = ec165.create()
        out, tx = request(prior=old, allow_network=False,
                          token_supplier=lambda: self.fail("unexpected token"))
        self.assertEqual(out["reason_code"], "NETWORK_NOT_AUTHORIZED")
        self.assertEqual(out["reconciliation_state"], "UNAVAILABLE_UNKNOWN")
        self.assertEqual(tx.calls, [])

    def test_synthetic_and_declared_live_cannot_be_mixed(self):
        old, _ = ec165.create()
        old = copy.deepcopy(old)
        old["synthetic"] = False
        old["evidence_material"]["synthetic"] = False
        old["patch_evidence"]["synthetic"] = False
        old["patch_evidence"]["path_evidence"]["synthetic"] = False
        old["observation_ref"] = snapshot.fingerprint(old["evidence_material"])
        out, tx = request(prior=old)
        self.assertEqual(out["reason_code"], "PIN_PROVENANCE_CHANGED")
        self.assertEqual(tx.calls, [])

    def test_no_private_patch_even_when_previous_receipt_contains_approved_code(self):
        old, _ = ec165.create(selected=("src/service.py",), include=True)
        self.assertTrue(old["patch_evidence"]["patches"][0]["patch_text"])
        out, _ = request(prior=old)
        rendered = json.dumps(out)
        self.assertNotIn("patch_text", rendered)
        self.assertNotIn("+new = 2", rendered)
        self.assertNotIn("ordered_files_digest", rendered)
        self.assertNotIn("selected_file_versions", rendered)

    def test_prior_missing_token_conservatively_unknown(self):
        out, tx = request(token_supplier=lambda: None)
        self.assertEqual(out["reconciliation_state"], "UNAVAILABLE_UNKNOWN")
        self.assertEqual(out["reason_code"], "CREDENTIALS_UNAVAILABLE")
        self.assertEqual(tx.calls, [])

    def test_bad_and_oversized_cli_baseline_files_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="ces-ec166-files-") as temp:
            path = Path(temp) / "invalid.json"
            path.write_text('{"schema":1,"schema":2}', encoding="utf-8")
            with self.assertRaises(source.SourceFailure):
                reconcile._read_bounded(str(path), 4096)
            path.write_bytes(b"x" * 4097)
            with self.assertRaises(ValueError):
                reconcile._read_bounded(str(path), 4096)

    def test_baseline_corrupt_pretends_complete_without_exact_count_rejected(self):
        old, _ = ec165.create("gitlab", count="1000+")
        fake = copy.deepcopy(old)
        fake["evidence_material"]["path_coverage"]["state"] = "COMPLETE"
        fake["patch_evidence"]["path_evidence"]["coverage"]["state"] = "COMPLETE"
        fake["observation_ref"] = snapshot.fingerprint(fake["evidence_material"])
        out, tx = request("gitlab", prior=fake)
        self.assertEqual(out["reason_code"], "INVALID_PRIOR_SNAPSHOT")
        self.assertEqual(tx.calls, [])

    def test_mock_single_get_is_never_provider_authenticated(self):
        out, _ = request()
        self.assertTrue(out["synthetic"])
        self.assertTrue(out["prior"]["synthetic"])
        self.assertEqual(out["current_observation"]["provider_origin_claim"], "synthetic_fixture")
        self.assertFalse(out["prior"]["receipt_authenticity_verified"])


if __name__ == "__main__":
    unittest.main()
