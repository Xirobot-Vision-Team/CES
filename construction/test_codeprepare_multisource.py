#!/usr/bin/env python3
"""EC170 focused offline development tests; not native/live acceptance."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import codeprepare_multisource as multi
import test_proposed_pr_paths as ec163
import test_proposed_pr_reconcile as ec166
import test_proposed_pr_snapshot as ec165


def local_result(mode="WorkingTree", *, content=True, empty=False, extra_entries=0):
    source_mode = "working_tree_diff" if mode == "WorkingTree" else "delivered_target_diff"
    if empty:
        return {
            "schema_version": "ces.cli.v1", "action": "CodePrepare", "status": "success",
            "reason_code": "CODE_PREPARE_EMPTY", "read_only": True, "next_step": "none",
            "coverage": {"code_packet_built": False, "content_release_authorized": False},
            "data": {"prepared": False, "can_persist_ces_state": False,
                     "source_root": "/safe/repo", "stable_root_verified": True,
                     "scope": {"source_mode": source_mode, "source_root": "/safe/repo",
                               "head_sha": "a" * 40 if mode == "WorkingTree" else None,
                               "base_sha": "a" * 40,
                               "target_sha": "b" * 40 if mode == "DeliveredTarget" else None,
                               "target_ref": "refs/heads/main" if mode == "DeliveredTarget" else None,
                               "remote_delivery_verified": False, "pr_association_verified": False,
                               "ci_verified": False, "deployment_verified": False},
                     "preparation": {"saved_collect_sha256": "e" * 64},
                     "review_packet": None, "packet_sha256": None},
        }
    paths = [{"status": "M", "path": "src/service.py", "old_path": None,
              "sensitive_path": False}]
    for i in range(extra_entries):
        paths.append({"status": "A", "path": f"src/extra-{i}.py", "old_path": None,
                      "sensitive_path": False})
    scope = {
        "source_mode": source_mode,
        "source_root": "/safe/repo",
        "head_sha": "a" * 40 if mode == "WorkingTree" else None,
        "base_sha": "a" * 40,
        "target_sha": "b" * 40 if mode == "DeliveredTarget" else None,
        "target_ref": "refs/heads/main" if mode == "DeliveredTarget" else None,
        "verification_scope": "two_non_atomic_local_observations",
        "remote_delivery_verified": False, "pr_association_verified": False,
        "ci_verified": False, "deployment_verified": False,
        "layer_counts": {}, "focus_areas": [],
    }
    patch = "diff --git a/src/service.py b/src/service.py\n@@ -1 +1 @@\n-old\n+new\n" if content else None
    if mode == "WorkingTree":
        layers = {
            "staged": {"name": "staged", "count": len(paths), "inventory_state": "complete",
                       "entries": paths, "patch_state": "included", "patch_sha256": "c" * 64,
                       "patch": patch},
            "unstaged": {"name": "unstaged", "count": 0, "inventory_state": "complete",
                         "entries": [], "patch_state": "empty", "patch_sha256": None,
                         "patch": None},
            "untracked": {"name": "untracked", "count": 1, "inventory_state": "complete",
                          "entries": [{"path": "notes.txt", "content_state": "included",
                                       "size_bytes": 5, "sha256": "d" * 64,
                                       "content": "hello" if content else None}]},
        }
    else:
        layers = {"changes": {"name": "changes", "count": len(paths), "inventory_state": "complete",
                              "entries": paths, "patch_state": "included", "patch_sha256": "c" * 64,
                              "patch": patch}}
    packet = {
        "schema_version": "ces.code_packet.v1", "task_kind": "code_analysis",
        "scope": scope, "layers": layers, "review_guidance": [],
        "provenance": {"saved_collect_sha256": "e" * 64,
                       "observed_at_utc": "2026-10-22T15:00:00+00:00",
                       "independently_authenticated": False,
                       "current_scope_reconciled": True, "atomic_capture": False},
    }
    return {
        "schema_version": "ces.cli.v1", "action": "CodePrepare", "status": "success",
        "reason_code": "CODE_PREPARE_READY", "read_only": True, "next_step": "none",
        "coverage": {"code_packet_built": True, "content_release_authorized": True},
        "data": {"prepared": True, "can_persist_ces_state": False,
                 "source_root": "/safe/repo", "stable_root_verified": True,
                 "packet_sha256": "f" * 64, "review_packet": packet},
    }


def receipt(schema="ces.proposed_pr_reconcile.v1"):
    return {
        "schema": "ces.proposed_pr_evidence_receipt.v1",
        "record_id": "1" * 64,
        "integrity_mac": "2" * 64,
        "body": {
            "source_schema": schema, "source_status": "partial", "source_state": "FRESH_OBSERVATION",
            "provider": "github", "provider_observed_at_utc": "2026-10-22T15:00:00+00:00",
            "expires_at_utc": "2026-10-22T15:15:00+00:00",
            "source_result_authenticated": False,
            "target_repository_membership_authenticated": False,
            "provider_merge_or_delivery_proven": False,
        },
    }


class MultiSourceTests(unittest.TestCase):
    def test_source_mode_is_never_inferred(self):
        out = multi.prepare_context(None, local_codeprepare=local_result())
        self.assertEqual((out["status"], out["reason_code"]), ("invalid_input", "SOURCE_MODE_REQUIRED"))
        self.assertIsNone(out["context"])

    def test_working_tree_metadata_only_by_default(self):
        out = multi.prepare_context("WorkingTree", local_codeprepare=local_result())
        self.assertEqual(out["status"], "partial")
        self.assertFalse(out["coverage"]["content_released"])
        self.assertEqual(out["context"]["source_mode"], "WorkingTree")
        self.assertIsNone(out["context"]["segments"][0]["content"])
        self.assertIn("SOURCE_SPECIFIC_CONTENT_PERMISSION_NOT_GRANTED",
                      out["coverage"]["missing_requirements"])
        self.assertFalse(out["write_authorized"])

    def test_working_tree_explicit_matching_grant_releases_existing_native_content(self):
        out = multi.prepare_context("WorkingTree", local_codeprepare=local_result(),
                                    content_permission="WorkingTree")
        self.assertEqual(out["status"], "success")
        self.assertTrue(out["coverage"]["content_released"])
        self.assertIn("+new", out["context"]["segments"][0]["content"])
        untracked = out["context"]["segments"][2]["content"]
        self.assertEqual(untracked[0]["text"], "hello")
        self.assertRegex(out["context_sha256"], r"^[0-9a-f]{64}$")

    def test_permission_cannot_cross_source_modes(self):
        out = multi.prepare_context("WorkingTree", local_codeprepare=local_result(),
                                    content_permission="DeliveredTarget")
        self.assertEqual(out["reason_code"], "CONTENT_PERMISSION_SOURCE_MISMATCH")
        self.assertIsNone(out["context"])

    def test_delivered_target_is_single_changes_segment(self):
        out = multi.prepare_context("DeliveredTarget", local_codeprepare=local_result("DeliveredTarget"),
                                    content_permission="DeliveredTarget")
        self.assertEqual(out["status"], "success")
        self.assertEqual([x["label"] for x in out["context"]["segments"]], ["changes"])
        self.assertEqual(out["context"]["source_identity"]["target_sha"], "b" * 40)
        self.assertFalse(out["coverage"]["remote_delivery_proven"])

    def test_explicit_local_source_mismatch_is_rejected(self):
        out = multi.prepare_context("DeliveredTarget", local_codeprepare=local_result("WorkingTree"))
        self.assertEqual(out["reason_code"], "SOURCE_MODE_MISMATCH")

    def test_local_mode_rejects_proposed_inputs_instead_of_ignoring_them(self):
        snap, _ = ec165.create()
        out = multi.prepare_context("WorkingTree", local_codeprepare=local_result(), proposed_snapshot=snap)
        self.assertEqual(out["reason_code"], "SOURCE_INPUT_MIXING_FORBIDDEN")

    def test_proposed_mode_rejects_local_packet_mixing(self):
        snap, _ = ec165.create()
        out = multi.prepare_context("ProposedPR", local_codeprepare=local_result(), proposed_snapshot=snap)
        self.assertEqual(out["reason_code"], "SOURCE_INPUT_MIXING_FORBIDDEN")

    def test_empty_native_snapshot_remains_compatible_and_does_not_fabricate_content(self):
        out = multi.prepare_context("WorkingTree", local_codeprepare=local_result(empty=True))
        self.assertEqual(out["status"], "success")
        self.assertEqual(out["reason_code"], "CODE_CONTEXT_METADATA_READY")
        self.assertEqual(out["context"]["segments"], [])
        self.assertFalse(out["coverage"]["content_released"])

    def test_empty_native_snapshot_still_binds_source_mode(self):
        out = multi.prepare_context("DeliveredTarget", local_codeprepare=local_result("WorkingTree", empty=True))
        self.assertEqual(out["reason_code"], "LOCAL_EMPTY_SCOPE_INVALID")

    def test_local_path_budget_withholds_all_content(self):
        out = multi.prepare_context("WorkingTree", local_codeprepare=local_result(extra_entries=3),
                                    content_permission="WorkingTree", max_paths=2)
        self.assertEqual(out["status"], "partial")
        self.assertFalse(out["coverage"]["content_released"])
        self.assertIn("PATH_LIMIT_EXCEEDED_CONTENT_WITHHELD", out["coverage"]["missing_requirements"])
        self.assertTrue(all(seg["content"] is None for seg in out["context"]["segments"]))

    def test_local_content_budget_withholds_every_raw_segment(self):
        out = multi.prepare_context("WorkingTree", local_codeprepare=local_result(),
                                    content_permission="WorkingTree", max_content_bytes=8)
        self.assertEqual(out["status"], "partial")
        self.assertFalse(out["coverage"]["content_released"])
        self.assertIn("CONTENT_BUDGET_EXCEEDED_ALL_RAW_CONTENT_WITHHELD",
                      out["coverage"]["missing_requirements"])

    def test_native_ready_claims_must_keep_remote_proofs_false(self):
        obj = local_result()
        obj["data"]["review_packet"]["scope"]["remote_delivery_verified"] = True
        out = multi.prepare_context("WorkingTree", local_codeprepare=obj)
        self.assertEqual(out["reason_code"], "LOCAL_PACKET_PROOF_CLAIM_INVALID")

    def test_native_stable_root_is_required(self):
        obj = local_result()
        obj["data"]["stable_root_verified"] = False
        out = multi.prepare_context("WorkingTree", local_codeprepare=obj)
        self.assertEqual(out["reason_code"], "LOCAL_REPOSITORY_IDENTITY_UNSTABLE")

    def test_local_windows_absolute_or_backslash_path_is_rejected(self):
        obj = local_result()
        obj["data"]["review_packet"]["layers"]["staged"]["entries"][0]["path"] = r"C:\temp\escape.py"
        out = multi.prepare_context("WorkingTree", local_codeprepare=obj)
        self.assertEqual(out["reason_code"], "SOURCE_PATH_INVALID")

    def test_local_git_scope_requires_full_consistent_object_ids(self):
        obj = local_result()
        obj["data"]["review_packet"]["scope"]["base_sha"] = "a" * 39
        out = multi.prepare_context("WorkingTree", local_codeprepare=obj)
        self.assertEqual(out["reason_code"], "LOCAL_GIT_SCOPE_INVALID")

    def test_proposed_metadata_context_is_built_from_valid_ec165(self):
        snap, _ = ec165.create()
        out = multi.prepare_context("ProposedPR", proposed_snapshot=snap)
        self.assertEqual(out["status"], "partial")
        self.assertEqual(out["context"]["source_identity"]["provider"], "github")
        self.assertEqual(out["context"]["source_identity"]["pin_fingerprint"],
                         snap["evidence_material"]["pin_fingerprint"])
        self.assertFalse(out["coverage"]["source_currentness_proven"])
        self.assertFalse(out["coverage"]["content_released"])

    def test_proposed_patch_needs_new_ec170_source_specific_grant(self):
        snap, _ = ec165.create(selected=("src/service.py",), include=True)
        denied = multi.prepare_context("ProposedPR", proposed_snapshot=snap)
        self.assertFalse(denied["coverage"]["content_released"])
        allowed = multi.prepare_context("ProposedPR", proposed_snapshot=snap,
                                        content_permission="ProposedPR")
        self.assertTrue(allowed["coverage"]["content_released"])
        self.assertIn("+new = 2", allowed["context"]["segments"][0]["content"][0]["text"])
        self.assertEqual(allowed["status"], "partial")

    def test_proposed_selected_patch_subset_is_not_labeled_complete_source_content(self):
        snap, _ = ec165.create(selected=("src/service.py",), include=True)
        out = multi.prepare_context("ProposedPR", proposed_snapshot=snap,
                                    content_permission="ProposedPR")
        self.assertTrue(out["coverage"]["content_released"])
        self.assertTrue(out["coverage"]["path_inventory_complete"])
        self.assertFalse(out["coverage"]["content_complete_for_selected_source"])

    def test_ec166_fresh_does_not_upgrade_old_pages_to_current(self):
        snap, _ = ec165.create(selected=("src/service.py",), include=True)
        rec, _ = ec166.request(prior=snap)
        out = multi.prepare_context("ProposedPR", proposed_snapshot=snap,
                                    proposed_reconcile=rec, content_permission="ProposedPR")
        self.assertTrue(out["coverage"]["content_released"])
        self.assertFalse(out["coverage"]["source_currentness_proven"])
        self.assertIn("EC166 metadata matched", " ".join(out["coverage"]["missing_requirements"]))

    def test_ec166_stale_blocks_old_raw_patch_even_with_permission(self):
        snap, _ = ec165.create(selected=("src/service.py",), include=True)
        changed = ec163.metadata("github", 3)
        changed["head"]["sha"] = "d" * 40
        rec, _ = ec166.request(prior=snap, current=changed)
        out = multi.prepare_context("ProposedPR", proposed_snapshot=snap,
                                    proposed_reconcile=rec, content_permission="ProposedPR")
        self.assertFalse(out["coverage"]["content_released"])
        self.assertIn("EC166_DRIFT_BLOCKS_EC165_CONTENT_RELEASE",
                      out["coverage"]["missing_requirements"])
        self.assertIsNone(out["context"]["segments"][0]["content"])

    def test_ec166_from_another_snapshot_is_rejected(self):
        snap, _ = ec165.create()
        other, _ = ec165.create("gitlab")
        rec, _ = ec166.request("gitlab", prior=other)
        out = multi.prepare_context("ProposedPR", proposed_snapshot=snap, proposed_reconcile=rec)
        self.assertEqual(out["reason_code"], "PROPOSED_RECONCILE_BASELINE_MISMATCH")

    def test_incomplete_proposed_paths_withhold_raw_content(self):
        items = ec165.ec164.rows("github")
        first = ec165.tagged(items[:1], nextlink=ec163.gh_link(2, 1))
        snap, _ = ec165.create(selected=("src/service.py",), include=True,
                               page_reads=[first], per_page=1, max_pages=1)
        out = multi.prepare_context("ProposedPR", proposed_snapshot=snap,
                                    content_permission="ProposedPR")
        self.assertFalse(out["coverage"]["path_inventory_complete"])
        self.assertFalse(out["coverage"]["content_released"])

    def test_historical_ec169_receipt_never_grants_permission_or_currentness(self):
        snap, _ = ec165.create(selected=("src/service.py",), include=True)
        out = multi.prepare_context("ProposedPR", proposed_snapshot=snap,
                                    historical_receipt=receipt())
        self.assertFalse(out["coverage"]["content_released"])
        self.assertFalse(out["historical_receipt"]["grants_content_permission"])
        self.assertFalse(out["historical_receipt"]["proves_current_source"])
        self.assertFalse(out["historical_receipt"]["bound_to_context_identity"])

    def test_historical_ec169_receipt_rejects_impossible_status_state_pair(self):
        snap, _ = ec165.create()
        rec = receipt()
        rec["body"]["source_status"] = "unavailable"
        out = multi.prepare_context("ProposedPR", proposed_snapshot=snap, historical_receipt=rec)
        self.assertEqual(out["reason_code"], "RECEIPT_STATE_INVALID")

    def test_delivery_association_receipt_is_not_mixed_into_proposal_context(self):
        snap, _ = ec165.create()
        out = multi.prepare_context("ProposedPR", proposed_snapshot=snap,
                                    historical_receipt=receipt("ces.proposed_pr_linear.v1"))
        self.assertEqual(out["reason_code"], "RECEIPT_SOURCE_MIXING_FORBIDDEN")

    def test_ec169_receipt_is_not_applicable_to_local_mode(self):
        out = multi.prepare_context("DeliveredTarget", local_codeprepare=local_result("DeliveredTarget"),
                                    historical_receipt=receipt())
        self.assertEqual(out["reason_code"], "RECEIPT_NOT_APPLICABLE")

    def test_tampered_ec165_receipt_is_rejected(self):
        snap, _ = ec165.create()
        snap = copy.deepcopy(snap)
        snap["evidence_material"]["path_coverage"]["listed_files"] += 1
        out = multi.prepare_context("ProposedPR", proposed_snapshot=snap)
        self.assertEqual(out["reason_code"], "PROPOSED_SNAPSHOT_INVALID")

    def test_output_never_claims_write_delivery_actor_or_deployment(self):
        snap, _ = ec165.create(selected=("src/service.py",), include=True)
        out = multi.prepare_context("ProposedPR", proposed_snapshot=snap,
                                    content_permission="ProposedPR")
        for field in ("write_authorized", "remote_delivery_proven", "provider_actor_verified",
                      "deployment_proven", "writes_performed"):
            self.assertFalse(out[field])
        self.assertFalse(out["native_cli_multisource_registered"])

    def test_cli_rejects_duplicate_json_without_writing_siblings(self):
        script = Path(multi.__file__).resolve()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            inp = root / "bad.json"
            inp.write_text('{"schema_version":"ces.cli.v1","schema_version":"ces.cli.v1"}', encoding="utf-8")
            before = sorted(p.name for p in root.iterdir())
            run = subprocess.run([sys.executable, str(script), "--source-mode", "WorkingTree",
                                  "--local-codeprepare", str(inp), "--json"],
                                 text=True, capture_output=True, check=False)
            after = sorted(p.name for p in root.iterdir())
            self.assertEqual(run.returncode, 4)
            self.assertEqual(json.loads(run.stdout)["reason_code"], "INPUT_JSON_INVALID")
            self.assertEqual(before, after)

    def test_cli_success_is_stdout_only(self):
        script = Path(multi.__file__).resolve()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            inp = root / "local.json"
            inp.write_text(json.dumps(local_result()), encoding="utf-8")
            before = {p.name: p.stat().st_mtime_ns for p in root.iterdir()}
            run = subprocess.run([sys.executable, str(script), "--source-mode", "WorkingTree",
                                  "--local-codeprepare", str(inp),
                                  "--allow-content-for", "WorkingTree", "--json"],
                                 text=True, capture_output=True, check=False)
            after = {p.name: p.stat().st_mtime_ns for p in root.iterdir()}
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertTrue(json.loads(run.stdout)["coverage"]["content_released"])
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
