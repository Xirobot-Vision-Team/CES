#!/usr/bin/env python3
"""EC-162 narrowly-scoped offline behavior examples; no provider account/network."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import proposed_pr_identity as identity
import proposed_pr_source as source

HERE = Path(__file__).resolve().parent


def raw_fixture(provider="github"):
    return json.loads((HERE / "fixtures" / "provider_metadata" / f"{provider}.synthetic.json").read_text("utf-8"))


class SyntheticTransport:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def get_object(self, url, headers, timeout):
        self.calls.append(url)
        return copy.deepcopy(self.payload)


def observe(provider="github", repository="example/repo", prior=None, data=None,
            local_repo=None, number=8):
    if provider == "gitlab" and repository == "example/repo":
        repository = "my-group/sub-group/repo"
    transport = SyntheticTransport(raw_fixture(provider) if data is None else data)
    result = identity.confirm_proposed_pr_identity(
        source.RequestKey(provider, repository, number),
        allow_network=True, token_supplier=lambda: "NOT-REAL-TOKEN",
        transport=transport, expected_pin=prior,
        local_git_repository=local_repo,
    )
    return result, transport


class Ec162IdentityTests(unittest.TestCase):
    def test_no_network_and_no_credential_read_by_default(self):
        result = identity.confirm_proposed_pr_identity(
            source.RequestKey("github", "example/repo", 8),
            token_supplier=lambda: self.fail("token was accessed"))
        self.assertEqual((result["status"], result["reason_code"], result["exit_code"]),
                         ("unavailable", "NETWORK_NOT_AUTHORIZED", 5))
        self.assertIsNone(result["pin"])

    def test_github_pin_uses_real_provider_id_fields_and_not_ref_name(self):
        out, tx = observe()
        self.assertEqual((out["status"], out["exit_code"], out["synthetic"]), ("partial", 2, True))
        pin = out["pin"]
        self.assertEqual(pin["target_repository_id"], "404")
        self.assertEqual(pin["source_repository_id"], "405")
        self.assertEqual(pin["proposal_object_id"], "101")
        self.assertEqual(pin["base_sha"], "a" * 40)
        self.assertEqual(pin["head_sha"], "b" * 40)
        self.assertEqual(pin["target_tip_sha"], "a" * 40)
        self.assertEqual(pin["base_semantics"], "base_branch_tip_at_provider_observation")
        self.assertTrue(pin["cross_fork"])
        self.assertNotIn("ref", json.dumps(pin))
        self.assertEqual(len(tx.calls), 1)
        self.assertFalse(out["write_authorized"])
        self.assertFalse(out["diff_snapshot_proven"])

    def test_gitlab_start_tip_is_distinct_from_merge_base(self):
        out, _ = observe("gitlab")
        pin = out["pin"]
        self.assertEqual(pin["target_repository_id"], "404")
        self.assertEqual(pin["source_repository_id"], "405")
        self.assertEqual(pin["base_sha"], "a" * 40)
        self.assertEqual(pin["head_sha"], "b" * 40)
        self.assertEqual(pin["target_tip_sha"], "c" * 40)
        self.assertEqual(pin["base_semantics"], "gitlab_diff_refs_merge_base_not_target_branch_tip")
        self.assertEqual(pin["target_tip_semantics"], "gitlab_diff_refs_start_target_tip_at_diff_version")

    def test_same_observation_without_local_objects_is_still_partial(self):
        first, _ = observe()
        later, _ = observe(prior=first)
        self.assertEqual(later["status"], "partial")
        self.assertEqual(later["reason_code"], "SYNTHETIC_OBSERVATION_ONLY")
        self.assertEqual(later["drift"]["status"], "PIN_MATCHED")
        self.assertEqual(first["pin_fingerprint"], later["pin_fingerprint"])

    def test_branch_name_is_not_part_of_identity(self):
        first, _ = observe()
        updated = raw_fixture()
        updated["head"]["ref"] = "renamed-branch"
        updated["base"]["ref"] = "new-main"
        second, _ = observe(prior=first, data=updated)
        self.assertEqual(second["drift"]["status"], "PIN_MATCHED")

    def test_head_push_or_force_push_invalidates_pin(self):
        first, _ = observe()
        changed = raw_fixture()
        changed["head"]["sha"] = "d" * 40
        second, _ = observe(prior=first, data=changed)
        self.assertEqual(second["status"], "unavailable")
        self.assertEqual(second["reason_code"], "PIN_DRIFT_HEAD_SHA_CHANGED")
        self.assertIsNone(second["pin"])
        self.assertIn("head_sha", second["drift"]["changed_fields"])

    def test_target_branch_tip_advances_invalidates_github_pin(self):
        first, _ = observe()
        changed = raw_fixture()
        changed["base"]["sha"] = "d" * 40
        second, _ = observe(prior=first, data=changed)
        self.assertEqual(second["reason_code"], "PIN_DRIFT_BASE_SHA_CHANGED")
        self.assertIn("target_tip_sha", second["drift"]["changed_fields"])

    def test_source_fork_repository_replaced_invalidates_pin(self):
        first, _ = observe()
        changed = raw_fixture()
        changed["head"]["repo"]["id"] = 888
        second, _ = observe(prior=first, data=changed)
        self.assertEqual(second["reason_code"], "PIN_DRIFT_SOURCE_REPOSITORY_ID_CHANGED")

    def test_target_repository_path_reused_with_different_id_fails(self):
        first, _ = observe()
        changed = raw_fixture()
        changed["base"]["repo"]["id"] = 407
        later, _ = observe(prior=first, data=changed)
        self.assertEqual(later["reason_code"], "PIN_DRIFT_TARGET_REPOSITORY_ID_CHANGED")

    def test_repository_rename_retains_id_but_invalidates_locator(self):
        first, _ = observe()
        changed = raw_fixture()
        changed["base"]["repo"]["full_name"] = "example/renamed"
        second, _ = observe(repository="example/renamed", prior=first, data=changed)
        self.assertEqual(second["reason_code"], "PIN_DRIFT_REPOSITORY_PATH_CHANGED")

    def test_fork_rename_invalidates_source_path(self):
        first, _ = observe()
        changed = raw_fixture()
        changed["head"]["repo"]["full_name"] = "fork/renamed"
        later, _ = observe(prior=first, data=changed)
        self.assertEqual(later["reason_code"], "PIN_DRIFT_SOURCE_PATH_CHANGED")

    def test_pr_provider_object_identity_change(self):
        first, _ = observe()
        changed = raw_fixture()
        changed["id"] = 123456
        second, _ = observe(prior=first, data=changed)
        self.assertEqual(second["reason_code"], "PIN_DRIFT_PROPOSAL_OBJECT_ID_CHANGED")

    def test_provider_state_change_invalidates(self):
        first, _ = observe()
        changed = raw_fixture()
        changed["state"] = "closed"
        changed["merged"] = True
        second, _ = observe(prior=first, data=changed)
        self.assertEqual(second["reason_code"], "PIN_DRIFT_PROPOSAL_STATE_CHANGED")

    def test_gitlab_target_tip_of_diff_version_change_invalidates(self):
        first, _ = observe("gitlab")
        changed = raw_fixture("gitlab")
        changed["diff_refs"]["start_sha"] = "d" * 40
        second, _ = observe("gitlab", prior=first, data=changed)
        self.assertEqual(second["reason_code"], "PIN_DRIFT_TARGET_TIP_SHA_CHANGED")

    def test_gitlab_source_project_change(self):
        first, _ = observe("gitlab")
        changed = raw_fixture("gitlab")
        changed["source_project_id"] = 999
        second, _ = observe("gitlab", prior=first, data=changed)
        self.assertEqual(second["reason_code"], "PIN_DRIFT_SOURCE_REPOSITORY_ID_CHANGED")

    def test_missing_fork_project_ids_fail_closed(self):
        gh = raw_fixture()
        gh["head"]["repo"] = None
        out, _ = observe(data=gh)
        self.assertEqual(out["reason_code"], "PROVIDER_METADATA_INCOMPLETE")
        self.assertIsNone(out["pin"])
        gl = raw_fixture("gitlab")
        del gl["source_project_id"]
        out, _ = observe("gitlab", data=gl)
        self.assertEqual(out["reason_code"], "PROVIDER_METADATA_INCOMPLETE")

    def test_github_rename_transfer_response_mixture_unavailable(self):
        # A repo cannot claim the same path with a new ID, nor two paths for
        # the same ID within a single observation.
        for bad in ("same_path_different_id", "same_id_different_path"):
            gh = raw_fixture()
            if bad == "same_path_different_id":
                gh["head"]["repo"]["full_name"] = "example/repo"
            else:
                gh["head"]["repo"]["id"] = gh["base"]["repo"]["id"]
            with self.subTest(variant=bad):
                out, _ = observe(data=gh)
                self.assertEqual(out["reason_code"], "PROVIDER_METADATA_INCONSISTENT")
                self.assertIsNone(out["pin"])

    def test_gitlab_provider_fields_inconsistent(self):
        for bad in ("bad_project", "bad_reference", "missing_start", "head_mismatch"):
            data = raw_fixture("gitlab")
            if bad == "bad_project":
                data.update(project_id=999)
            elif bad == "bad_reference":
                data["references"] = {"full": "other/repo!8"}
            elif bad == "missing_start":
                data["diff_refs"].pop("start_sha")
            else:
                data["sha"] = "f" * 40
            with self.subTest(case=bad):
                out, _ = observe("gitlab", data=data)
                self.assertEqual(out["status"], "unavailable")
                self.assertIsNone(out["pin"])

    def test_gitlab_locked_state_supported_without_merge_proof(self):
        data = raw_fixture("gitlab")
        data["state"] = "locked"
        out, _ = observe("gitlab", data=data)
        self.assertEqual(out["status"], "partial")
        self.assertFalse(out["delivery_or_merge_proven"])
        self.assertFalse(out["pin"]["provider_reports_merged"])

    def test_expected_pin_tampering_is_input_error_before_credentials(self):
        first, _ = observe()
        expected = copy.deepcopy(first)
        expected["pin"]["head_sha"] = "f" * 40
        result = identity.confirm_proposed_pr_identity(
            source.RequestKey("github", "example/repo", 8), expected_pin=expected,
            allow_network=True, token_supplier=lambda: self.fail("looked up token"))
        self.assertEqual(result["reason_code"], "INVALID_EXPECTED_PIN")
        self.assertEqual(result["exit_code"], 4)

    def test_previous_pin_injection_extra_fields_rejected(self):
        previous, _ = observe()
        previous["pin"]["new_future_permission"] = True
        previous["pin_fingerprint"] = identity.fingerprint_of(previous["pin"])
        second, _ = observe(prior=previous)
        self.assertEqual(second["reason_code"], "INVALID_EXPECTED_PIN")

    def test_synthetic_to_provider_provenance_change_is_invalidation(self):
        previous, _ = observe()
        data = raw_fixture()
        data.pop("_ces_fixture")  # a simulated live-shaped payload, never a real HTTP call
        # Only simulate the networking implementation for an offline test.
        with patch.object(source, "StrictHttpsTransport") as mocked:
            mocked.return_value.get_object.return_value = data
            actual = identity.confirm_proposed_pr_identity(
                source.RequestKey("github", "example/repo", 8), allow_network=True,
                token_supplier=lambda: "not-a-real-secret", expected_pin=previous)
        self.assertEqual(actual["reason_code"], "PIN_PROVENANCE_CHANGED")

    def test_short_sha_and_mixed_formats_not_stable(self):
        fixture = raw_fixture()
        fixture["base"]["sha"] = "a" * 64
        out, _ = observe(data=fixture)
        self.assertEqual(out["status"], "unavailable")

    def test_invalid_local_git_path_no_token_lookup(self):
        out = identity.confirm_proposed_pr_identity(
            source.RequestKey("github", "example/repo", 8), allow_network=True,
            token_supplier=lambda: self.fail("read token"), local_git_repository="relative")
        self.assertEqual(out["reason_code"], "INVALID_LOCAL_GIT_PATH")

    @unittest.skipUnless(shutil.which("git"), "Optional Git binary not available")
    def test_local_git_probe_checks_commit_type_not_ref_or_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            subprocess.run(["git", "-C", tmp, "-c", "user.name=CES",
                            "-c", "user.email=ces@example.invalid",
                            "commit", "-q", "--allow-empty", "-m", "synthetic fixture"],
                           check=True, capture_output=True)
            sha = subprocess.check_output(["git", "-C", tmp, "rev-parse", "HEAD"],
                                          text=True).strip()
            first, _ = observe()
            pin = copy.deepcopy(first["pin"])
            pin["base_sha"] = pin["head_sha"] = pin["target_tip_sha"] = sha
            local = identity.check_local_commit_objects(tmp, pin)
            self.assertEqual(local["status"], "ALL_COMMIT_OBJECTS_PRESENT")
            self.assertEqual(set(local["present_commit_roles"]), {"base", "head", "target_tip"})
            pin["head_sha"] = "b" * len(sha)
            missing = identity.check_local_commit_objects(tmp, pin)
            self.assertEqual(missing["status"], "INCOMPLETE_COMMIT_OBJECTS")
            self.assertIn("head", missing["missing_commit_roles"])


    @unittest.skipUnless(shutil.which("git"), "Optional Git binary not available")
    def test_success_limited_to_matched_non_synthetic_shape_plus_local_objects(self):
        """Mocking the live transport still is NOT an actual Provider online test."""
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            subprocess.run(["git", "-C", tmp, "-c", "user.name=CES",
                            "-c", "user.email=ces@example.invalid",
                            "commit", "-q", "--allow-empty", "-m", "synthetic object"],
                           check=True, capture_output=True)
            oid = subprocess.check_output(["git", "-C", tmp, "rev-parse", "HEAD"],
                                          text=True).strip()
            mock_live = raw_fixture()
            mock_live.pop("_ces_fixture")
            mock_live["base"]["sha"] = mock_live["head"]["sha"] = oid
            with patch.object(source, "StrictHttpsTransport") as mocked:
                mocked.return_value.get_object.return_value = mock_live
                request = source.RequestKey("github", "example/repo", 8)
                first = identity.confirm_proposed_pr_identity(
                    request, allow_network=True, token_supplier=lambda: "fixture-token")
                final = identity.confirm_proposed_pr_identity(
                    request, allow_network=True, token_supplier=lambda: "fixture-token",
                    expected_pin=first, local_git_repository=tmp)
            self.assertEqual(first["status"], "partial")
            self.assertEqual(final["status"], "success")
            self.assertEqual(final["reason_code"], "READONLY_PIN_MATCH_AND_LOCAL_OBJECTS_PRESENT")
            self.assertEqual(final["evidence_level"], "MATCHED_AND_LOCAL_OBJECTS_PRESENT")
            self.assertFalse(final["write_authorized"])
            self.assertFalse(final["delivery_or_merge_proven"])

    def test_cli_offline_exit5_and_no_side_effect(self):
        proc = subprocess.run(
            [sys.executable, str(HERE / "proposed_pr_identity.py"),
             "--provider", "github", "--repository", "example/repo",
             "--number", "8", "--json"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(json.loads(proc.stdout)["reason_code"], "NETWORK_NOT_AUTHORIZED")
        self.assertFalse(proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
