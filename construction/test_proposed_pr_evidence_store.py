#!/usr/bin/env python3
"""EC169 local development scenarios; no real Provider, CES CLI or business repo."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import proposed_pr_evidence_store as store
import proposed_pr_identity as identity
import proposed_pr_reconcile as reconcile
import proposed_pr_linear as linear
import proposed_pr_merge as merge
import test_proposed_pr_linear as upstream


def stamp(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def example(*, now: datetime | None = None, schema: str = linear.SCHEMA,
            state: str = "LOCAL_GITLAB_SQUASH_TREE_VERIFIED") -> dict:
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    if schema == merge.SCHEMA:
        state = "LOCAL_MERGE_GRAPH_VERIFIED"
    modes = {
        "LOCAL_GITLAB_SQUASH_TREE_VERIFIED": "READONLY_GITLAB_SQUASH_COMMIT_AND_NET_TREE_VERIFIED",
        "LOCAL_MERGE_GRAPH_VERIFIED": "READONLY_OBJECT_TREE_AND_PARENT_GRAPH_VERIFIED",
        "LOCAL_SINGLE_COMMIT_NET_TREE_VERIFIED_METHOD_UNKNOWN": "READONLY_PROVIDER_LINKED_NET_TREE_VERIFIED",
        "LOCAL_EXACT_HEAD_GRAPH_VERIFIED_METHOD_UNKNOWN": "READONLY_EXACT_HEAD_TARGET_ANCESTRY_AND_TREE_VERIFIED",
    }
    return {
        "schema": schema, "status": "partial", "exit_code": 2,
        "association_state": state, "reason_code": "LOCAL_GRAPH_MATCHED",
        "identity_scope": {
            "provider": "gitlab", "repository_locator": "private/team/source-repo",
            "request_number": 44, "target_repository_id_claim": "12345",
            "source_repository_id_claim": "12346", "proposal_object_id_claim": "9911",
            "object_format": "sha1", "pin_fingerprint": "sha256:" + "a" * 64,
            "local_target_repository_selected_by_operator_not_verified": True,
        },
        "observations": {"ec167_provider_observed_at_utc": stamp(now) if schema == merge.SCHEMA else None,
                         "ec168_provider_observed_at_utc": stamp(now) if schema == linear.SCHEMA else None,
                         "local_git_observed_at_utc": stamp(now)},
        "provider_claim": {"observed_at_utc": stamp(now),
                           "provider_origin_claim": "synthetic_fixture", "provider_reports_merged": True},
        "local_git": {"state": modes[state], "SECRET_PATH": "very-secret-patch-body"},
        "synthetic": True, "local_association_verified": True,
        "local_merge_graph_verified": state == "LOCAL_MERGE_GRAPH_VERIFIED",
        "write_authorized": False, "native_cli_action_registered": False,
        "provider_actor_verified": False, "delivery_or_merge_proven": False,
        "target_repository_membership_authenticated": False,
        "raw_patch": "MY_SUPER_SECRET_PATCH", "access_token": "VERY_SENSITIVE_TOKEN",
    }


class StoreScenarios(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ces-ec169-")
        self.addCleanup(self.tmp.cleanup)
        self.root = str(Path(self.tmp.name) / "private")
        os.mkdir(self.root, 0o700)
        self.store_id = "team_evidence"
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.input = example(now=self.now)
        result = store.init_evidence_store(self.root, self.store_id, allow_initialize=True, now=self.now)
        self.assertEqual(result["gate_state"], "STORE_INITIALIZED", result)

    def preview(self, evidence=None, ttl=900, at=None):
        return store.preview_evidence_receipt(evidence or self.input, root=self.root, store_id=self.store_id,
                                             ttl_seconds=ttl, now=at or self.now)

    def commit(self, evidence=None, ttl=900, at=None, allow=True, grant=None):
        evidence = evidence or self.input
        if grant is None:
            grant = self.preview(evidence, ttl, at)["details"].get("authorization_digest")
        return store.persist_evidence_receipt(evidence, root=self.root, store_id=self.store_id,
                                              ttl_seconds=ttl, allow_evidence_write=allow,
                                              authorization_digest=grant, now=at or self.now)

    def files(self):
        return list((Path(self.root) / "records").iterdir())

    def test_readonly_preview_does_not_write(self):
        preview = self.preview()
        self.assertEqual(preview["gate_state"], "PREVIEW_READY_NO_PERMISSION_GRANTED")
        self.assertFalse(preview["local_store_write_performed"])
        self.assertEqual(self.files(), [])
        self.assertIsNone(preview["details"]["prior_receipt_id"])
        self.assertFalse(preview["provider_merge_or_delivery_proven"])

    def test_denied_and_missing_authorization_never_create_files(self):
        prior = self.preview()["details"]["authorization_digest"]
        self.assertEqual(self.commit(allow=False, grant=prior)["gate_state"], "WRITE_DENIED")
        self.assertEqual(self.commit(grant=None, allow=False)["gate_state"], "WRITE_DENIED")
        self.assertEqual(self.commit(grant="sha256:" + "f" * 64)["reason_code"],
                         "AUTHORIZATION_SCOPE_MISMATCH_OR_HISTORY_CHANGED")
        missing = store.persist_evidence_receipt(self.input, root=self.root, store_id=self.store_id,
                                                  allow_evidence_write=True)
        self.assertEqual(missing["reason_code"], "AUTHORIZATION_DIGEST_REQUIRED")
        self.assertEqual(self.files(), [])

    def test_append_dedupe_and_no_input_raw_content(self):
        result = self.commit()
        self.assertEqual(result["gate_state"], "APPEND_ONLY_RECEIPT_PERSISTED", result)
        self.assertTrue(result["local_store_write_performed"])
        names = self.files()
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0].name, r"^[a-f0-9]{64}\.000001\.json$")
        content = names[0].read_text()
        for secret in ("MY_SUPER_SECRET_PATCH", "VERY_SENSITIVE_TOKEN", "private/team/source-repo",
                       "very-secret-patch-body", "9911", "12345"):
            self.assertNotIn(secret, content)
        self.assertEqual(stat.S_IMODE(names[0].stat().st_mode), 0o600)
        # Reusing exactly the original authorization is read-only/idempotent.
        original_grant = json.loads(content)["body"]["authorization_digest"]
        duplicate = self.commit(grant=original_grant)
        self.assertEqual(duplicate["gate_state"], "DUPLICATE_NO_WRITE")
        self.assertFalse(duplicate["local_store_write_performed"])
        self.assertEqual(len(self.files()), 1)

    def test_missing_version_or_unavailable_success_never_qualifies(self):
        for mutate in (lambda v: v.update(status="success", exit_code=0),
                       lambda v: v.update(write_authorized=True),
                       lambda v: v.update(provider_actor_verified=True),
                       lambda v: v.update(delivery_or_merge_proven=True),
                       lambda v: v.update(schema="ces.proposed_pr_linear.v2"),
                       lambda v: v.update(local_association_verified=False),
                       lambda v: v.update(local_git={"state": "NOT_VERIFIED"}),
                       lambda v: v.update(provider_claim={"observed_at_utc": stamp(self.now),
                                                        "provider_origin_claim": "synthetic_fixture"}),
                       lambda v: v.update(synthetic=False),
                       lambda v: v.update(association_state="PUBLISHED_TO_REMOTE")):
            evidence = copy.deepcopy(self.input)
            mutate(evidence)
            rejected = self.preview(evidence)
            self.assertNotEqual(rejected["gate_state"], "PREVIEW_READY_NO_PERMISSION_GRANTED", rejected)
        self.assertEqual(self.files(), [])

    def test_ttl_earliest_observation_and_expiry(self):
        item = copy.deepcopy(self.input)
        item["observations"]["local_git_observed_at_utc"] = stamp(self.now + timedelta(seconds=50))
        self.assertEqual(self.preview(item, 180)["details"]["expires_at_utc"], store._stamp(self.now + timedelta(seconds=180)))
        self.assertEqual(self.preview(item, 30)["reason_code"], "RECEIPT_TTL_OUT_OF_BOUNDS")
        self.assertEqual(self.preview(item, 5000)["reason_code"], "RECEIPT_TTL_OUT_OF_BOUNDS")
        self.assertEqual(self.preview(item, 60, at=self.now + timedelta(seconds=61))["reason_code"],
                         "SOURCE_OBSERVATION_TTL_ALREADY_EXPIRED")
        item["observations"]["local_git_observed_at_utc"] = stamp(self.now + timedelta(seconds=61))
        self.assertEqual(self.preview(item)["reason_code"], "SOURCE_OBSERVATION_IN_FUTURE")
        self.assertEqual(self.preview(at=self.now + timedelta(seconds=901))["reason_code"],
                         "SOURCE_OBSERVATION_STALE_REOBSERVE")

    def test_expired_duplicate_never_renews(self):
        initial = self.preview(ttl=60)["details"]["authorization_digest"]
        self.assertTrue(self.commit(ttl=60, grant=initial)["local_store_write_performed"])
        current = self.preview(ttl=60, at=self.now + timedelta(seconds=60))
        self.assertEqual(current["gate_state"], "EXPIRED_DUPLICATE_REOBSERVE")
        self.assertEqual(self.commit(ttl=60, grant=initial, at=self.now + timedelta(seconds=65))["reason_code"],
                         "EXPIRED_SOURCE_CANNOT_BE_REAUTHORIZED")
        self.assertEqual(len(self.files()), 1)

    def test_refresh_after_expiry_links_prior_without_overwrite(self):
        self.commit(ttl=60)
        original = self.files()[0]
        old = original.read_bytes()
        updated = copy.deepcopy(self.input)
        t2 = self.now + timedelta(seconds=90)
        updated["provider_claim"]["observed_at_utc"] = stamp(t2)
        updated["observations"]["ec168_provider_observed_at_utc"] = stamp(t2)
        updated["observations"]["local_git_observed_at_utc"] = stamp(t2)
        updated["identity_scope"]["pin_fingerprint"] = "sha256:" + "b" * 64
        preview = self.preview(updated, ttl=60, at=t2)
        self.assertEqual(preview["details"]["next_revision"], 2)
        self.assertTrue(preview["details"]["prior_pin_changed"])
        second = self.commit(updated, ttl=60, at=t2, grant=preview["details"]["authorization_digest"])
        self.assertEqual(second["gate_state"], "APPEND_ONLY_RECEIPT_PERSISTED", second)
        self.assertEqual(second["details"]["prior_state_at_write"], "EXPIRED")
        self.assertTrue(second["details"]["prior_pin_changed"])
        self.assertEqual(original.read_bytes(), old)
        history = store.inspect_evidence_history(updated, root=self.root, store_id=self.store_id, now=t2)
        self.assertEqual(history["details"]["total_subject_revisions"], 2)
        self.assertEqual([item["current_ttl_state"] for item in history["details"]["records"]],
                         ["EXPIRED_HISTORICAL", "ACTIVE_LOCAL_ONLY"])

    def test_refresh_without_new_observation_denied(self):
        self.commit()
        updated = copy.deepcopy(self.input)
        updated["reason_code"] = "SECOND_ATTEMPT_SAME_TIME"
        self.assertEqual(self.preview(updated)["reason_code"], "REFRESH_REQUIRES_NEWER_PROVIDER_OBSERVATION")
        # A backwards wall clock must not write a revision that would make
        # persisted-at order impossible to validate later.
        updated["provider_claim"]["observed_at_utc"] = stamp(self.now + timedelta(seconds=10))
        updated["observations"]["ec168_provider_observed_at_utc"] = stamp(self.now + timedelta(seconds=10))
        updated["observations"]["local_git_observed_at_utc"] = stamp(self.now + timedelta(seconds=10))
        self.assertEqual(self.preview(updated, at=self.now - timedelta(seconds=1))["reason_code"],
                         "STORE_CLOCK_MOVED_BACKWARDS")
        self.assertEqual(len(self.files()), 1)

    def test_prior_revision_grant_is_invalid_after_another_writer(self):
        old_grant = self.preview()["details"]["authorization_digest"]
        different = copy.deepcopy(self.input)
        different["provider_claim"]["observed_at_utc"] = stamp(self.now + timedelta(seconds=10))
        different["observations"]["ec168_provider_observed_at_utc"] = stamp(self.now + timedelta(seconds=10))
        different["observations"]["local_git_observed_at_utc"] = stamp(self.now + timedelta(seconds=10))
        self.commit(different, at=self.now + timedelta(seconds=10))
        # New record came first; stale grant cannot append a forked revision.
        self.assertEqual(self.commit(grant=old_grant, at=self.now + timedelta(seconds=10))["reason_code"],
                         "REFRESH_REQUIRES_NEWER_PROVIDER_OBSERVATION")
        self.assertEqual(len(self.files()), 1)

    def test_history_modification_blocks_further_reads_and_writes(self):
        self.commit()
        receipt = self.files()[0]
        raw = receipt.read_bytes()
        receipt.write_bytes(raw.replace(b"LOCAL_GRAPH_MATCHED", b"PRIOR_GRAPH_MATCHED"))
        self.assertEqual(self.preview()["gate_state"], "GATE_CLOSED")
        self.assertEqual(store.inspect_evidence_history(self.input, root=self.root,
                         store_id=self.store_id)["gate_state"], "GATE_CLOSED")
        self.assertEqual(len(self.files()), 1)

    def test_manifest_identity_and_symlink_traversal_blocked(self):
        old = Path(self.tmp.name) / "linked"
        os.symlink(self.root, old)
        result = store.preview_evidence_receipt(self.input, root=str(old), store_id=self.store_id)
        self.assertEqual(result["gate_state"], "GATE_CLOSED")
        swapped = store.preview_evidence_receipt(self.input, root=self.root, store_id="other_store")
        self.assertEqual(swapped["gate_state"], "GATE_CLOSED")
        self.assertEqual(self.preview()["gate_state"], "PREVIEW_READY_NO_PERMISSION_GRANTED")

    def test_symlinked_record_directory_and_unknown_entries_blocked(self):
        folder = Path(self.root) / "records"
        folder.rename(Path(self.root) / "moved")
        os.symlink(Path(self.root) / "moved", folder)
        self.assertEqual(self.preview()["gate_state"], "GATE_CLOSED")
        folder.unlink()
        (Path(self.root) / "moved").rename(folder)
        (folder / "unexpected.txt").write_text("unauthorized")
        self.assertEqual(self.preview()["reason_code"], "STORE_UNKNOWN_ENTRY_OR_INTERRUPTED_OPERATION")

    def test_root_owner_private_required_and_init_deny(self):
        os.chmod(self.root, 0o755)
        self.assertEqual(self.preview()["reason_code"], "STORE_ROOT_OWNER_OR_PERMISSIONS_UNSAFE")
        os.chmod(self.root, 0o700)
        empty = Path(self.tmp.name) / "new"
        empty.mkdir(mode=0o700)
        denied = store.init_evidence_store(str(empty), "another_store", allow_initialize=False)
        self.assertFalse(denied["local_store_write_performed"])
        self.assertEqual(list(empty.iterdir()), [])
        repeated = store.init_evidence_store(self.root, self.store_id, allow_initialize=True)
        self.assertEqual(repeated["reason_code"], "STORE_INIT_REQUIRES_EMPTY_PRIVATE_DIRECTORY")

    def test_unknown_with_no_new_provider_is_short_lived_history_only(self):
        item = copy.deepcopy(self.input)
        item["status"], item["exit_code"] = "unavailable", 5
        item["association_state"], item["reason_code"] = "UNAVAILABLE_UNKNOWN", "NETWORK_NOT_AUTHORIZED"
        item["local_association_verified"] = False
        item["local_git"]["state"] = "NOT_VERIFIED"
        item["provider_claim"] = None
        item["observations"]["ec168_provider_observed_at_utc"] = None
        preview = self.preview(item, ttl=900)
        self.assertEqual(preview["details"]["observation_kind"], "NO_FRESH_PROVIDER_OBSERVATION")
        self.assertEqual(preview["details"]["expires_at_utc"], store._stamp(self.now + timedelta(seconds=300)))
        persisted = self.commit(item, grant=preview["details"]["authorization_digest"])
        self.assertEqual(persisted["details"]["source_status"], "unavailable")
        self.assertFalse(persisted["provider_merge_or_delivery_proven"])
        history = store.inspect_evidence_history(item, root=self.root, store_id=self.store_id)
        self.assertEqual(history["details"]["records"][0]["source_status"], "unavailable")

    def test_source_input_can_be_labeled_unknown_without_asserting_local_read(self):
        item = copy.deepcopy(self.input)
        item.update(status="unavailable", exit_code=5, association_state="UNAVAILABLE_UNKNOWN",
                    reason_code="LOCAL_BLOB_MISSING", local_association_verified=False)
        item["local_git"] = {"state": "NOT_VERIFIED"}
        data = self.preview(item)
        self.assertEqual(data["details"]["observation_kind"], "PROVIDER_METADATA_ONLY")
        self.assertEqual(data["details"]["local_git_source"], "NOT_VERIFIED")

    def test_tampered_parent_record_chain_denied(self):
        self.commit()
        receipt = self.files()[0]
        obj = json.loads(receipt.read_text())
        obj["body"]["revision"] = 2
        receipt.write_text(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
        self.assertEqual(self.preview()["gate_state"], "GATE_CLOSED")

    def test_cancel_after_preview_has_no_side_effects(self):
        authorized_preview = self.preview()
        self.assertIsNotNone(authorized_preview["details"]["authorization_digest"])
        # The caller can cancel here; preview never creates a receipt.
        self.assertEqual(self.files(), [])

    def test_authorization_digest_bound_to_ttl_and_instance(self):
        grant = self.preview(ttl=600)["details"]["authorization_digest"]
        self.assertEqual(self.commit(ttl=601, grant=grant)["reason_code"],
                         "AUTHORIZATION_SCOPE_MISMATCH_OR_HISTORY_CHANGED")
        self.assertEqual(self.files(), [])

    def test_prepopulated_revision_filename_cannot_be_overwritten(self):
        plan = self.preview()["details"]
        fixed = Path(self.root) / "records" / (plan["subject_key"] + ".000001.json")
        fixed.write_text("UNTRUSTED")
        original = fixed.read_bytes()
        self.assertEqual(self.commit(grant=plan["authorization_digest"])["gate_state"], "GATE_CLOSED")
        self.assertEqual(fixed.read_bytes(), original)

    def test_store_hmac_key_not_leaked_from_any_response(self):
        manifest = json.loads((Path(self.root) / "manifest.json").read_text())
        data = [self.preview(), self.commit(),
                store.inspect_evidence_history(self.input, root=self.root, store_id=self.store_id)]
        for output in data:
            self.assertNotIn(manifest["key_hex"], json.dumps(output))
            self.assertFalse(output["source_result_authenticated"])
            self.assertFalse(output["store_hmac_is_external_authority"])

    def test_no_source_json_version_auto_migration(self):
        bad = copy.deepcopy(self.input)
        bad["schema"] = "ces.proposed_pr_linear.v2"
        self.assertEqual(self.preview(bad)["reason_code"], "UNSUPPORTED_EVIDENCE_SCHEMA")
        self.assertEqual(self.files(), [])

    def test_reject_malformed_store_id_and_unsafe_path(self):
        bad = store.preview_evidence_receipt(self.input, root=self.root + "/../private", store_id=self.store_id)
        self.assertEqual(bad["reason_code"], "STORE_ROOT_NOT_CANONICAL_ABSOLUTE_PATH")
        bad = store.preview_evidence_receipt(self.input, root=self.root, store_id="../other")
        self.assertEqual(bad["reason_code"], "STORE_ID_INVALID")

    def test_real_ec168_provider_and_local_objects_feed_local_gate(self):
        repo = upstream.Repo("squash")
        self.addCleanup(repo.close)
        raw = upstream.metadata(repo, "gitlab")
        pin, recent = upstream.chain(raw, "gitlab")
        consumer = linear.associate_linear_change(
            upstream.key("gitlab"), expected_pin=pin, ec166_reconciliation=recent,
            local_git_repository=str(repo.root), allow_network=True,
            allow_local_git=True, transport=upstream.Transport(raw),
            token_supplier=lambda: "TEST_TOKEN")
        self.assertEqual(consumer["association_state"], "LOCAL_GITLAB_SQUASH_TREE_VERIFIED")
        preview = self.preview(consumer)
        self.assertEqual(preview["gate_state"], "PREVIEW_READY_NO_PERMISSION_GRANTED", preview)
        committed = self.commit(consumer, grant=preview["details"]["authorization_digest"])
        self.assertEqual(committed["gate_state"], "APPEND_ONLY_RECEIPT_PERSISTED", committed)
        self.assertEqual(len(self.files()), 1)

    def test_real_ec166_metadata_refresh_input_as_separate_evidence_source(self):
        repo = upstream.Repo("squash")
        self.addCleanup(repo.close)
        raw = upstream.metadata(repo, "gitlab")
        _, checked = upstream.chain(raw, "gitlab")
        preview = self.preview(checked)
        self.assertEqual(preview["details"]["observation_kind"], "PROVIDER_METADATA_ONLY")
        done = self.commit(checked, grant=preview["details"]["authorization_digest"])
        self.assertEqual(done["details"]["source_status"], "partial")
        history = store.inspect_evidence_history(checked, root=self.root, store_id=self.store_id)
        self.assertEqual(history["details"]["records"][0]["local_git_source"], "NOT_VERIFIED")

    def test_real_ec167_two_parent_merge_supported_as_partial_only(self):
        repo = upstream.Repo("two-parent")
        self.addCleanup(repo.close)
        raw = upstream.metadata(repo, "gitlab", kind="two-parent")
        pin, recent = upstream.chain(raw, "gitlab")
        result = merge.associate_merge_commit(
            upstream.key("gitlab"), expected_pin=pin, ec166_reconciliation=recent,
            local_git_repository=str(repo.root), allow_network=True, allow_local_git=True,
            transport=upstream.Transport(raw), token_supplier=lambda: "TEST_TOKEN")
        self.assertEqual(result["association_state"], "LOCAL_MERGE_GRAPH_VERIFIED", result)
        prepared = self.preview(result)
        self.assertEqual(prepared["gate_state"], "PREVIEW_READY_NO_PERMISSION_GRANTED", prepared)
        done = self.commit(result, grant=prepared["details"]["authorization_digest"])
        self.assertEqual(done["gate_state"], "APPEND_ONLY_RECEIPT_PERSISTED", done)
        self.assertFalse(done["provider_merge_or_delivery_proven"])


if __name__ == "__main__":
    unittest.main()
