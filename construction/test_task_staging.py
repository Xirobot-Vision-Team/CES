#!/usr/bin/env python3
"""EC172 focused offline staging tests; no live OS/AI acceptance is implied."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import handoff_lifecycle as lc
import task_staging as st
from test_handoff_lifecycle import context


class Time:
    def __init__(self):
        self.value = datetime.now(timezone.utc)

    def __call__(self):
        return self.value


class StagingCases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ces-ec172-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "private-stage"
        self.repo = self.base / "business-repo"
        self.root.mkdir(mode=0o700)
        self.repo.mkdir(mode=0o700)
        (self.repo / "business.py").write_text("important = 'unchanged'\n", encoding="utf-8")
        self.clock = Time()
        self.stager = st.TaskStaging(str(self.root), str(self.repo), clock=self.clock)
        self.src = context()

    def init(self):
        result = self.stager.initialize(approve_init=True)
        self.pin = result["parent_pin"]
        return result

    def start(self, **kwargs):
        opts = dict(operation_key="create-run-0001", expected_parent_pin=self.pin,
                    authorize_stage=True)
        opts.update(kwargs)
        return self.stager.start(self.src, **opts)

    def reenter(self, result=None, **kwargs):
        if result is None:
            result = self.first
        opts = dict(operation_key="create-run-0001", expected_parent_pin=self.pin,
                    run_id=result["run_id"], expected_revision=result["revision"])
        opts.update(kwargs)
        return self.stager.reenter(self.src, **opts)

    def record_path(self, response):
        return self.root / (response["run_id"] + ".stage.json")

    def err(self, expected, fn):
        with self.assertRaises((st.StageError, lc.LifecycleError)) as caught:
            fn()
        self.assertEqual(caught.exception.code, expected)

    def test_init_requires_explicit_opt_in_and_empty_private_root(self):
        self.err("EXPLICIT_STAGING_INIT_APPROVAL_REQUIRED",
                 lambda: self.stager.initialize(approve_init=False))
        r = self.init()
        self.assertRegex(r["parent_pin"], r"^[0-9a-f]{64}$")
        self.assertEqual(set(os.listdir(self.root)), {".staging-key", ".staging-lock", "manifest.json"})
        self.err("INIT_REQUIRES_EMPTY_PRIVATE_DIRECTORY", lambda: self.init())
        self.assertEqual((self.repo / "business.py").read_text(), "important = 'unchanged'\n")

    def test_stage_actual_transaction_and_no_raw_content(self):
        self.init()
        self.first = self.start()
        r = self.first
        self.assertEqual(r["reason_code"], "STAGING_CREATED_LOCAL_ONLY")
        self.assertTrue(r["stage_committed"])
        self.assertFalse(r["ai_dispatched"])
        self.assertFalse(r["mutable_lifecycle_restored"])
        self.assertRegex(r["run_id"], r"^run_v1_[a-f0-9]{48}$")
        raw = self.record_path(r).read_bytes()
        self.assertNotIn(b"diff --git", raw)
        self.assertNotIn(b"business.py", raw)
        self.assertNotIn(b"important", raw)
        self.assertEqual(self.record_path(r).stat().st_mode & 0o077, 0)
        self.assertEqual(self.stager.inspect(expected_parent_pin=self.pin)["staged_count"], 1)
        self.assertEqual((self.repo / "business.py").read_text(), "important = 'unchanged'\n")
        self.assertEqual(set(os.listdir(self.repo)), {"business.py"})

    def test_stage_approval_and_parent_pin_before_any_run_id(self):
        self.init()
        self.err("EXPLICIT_LOCAL_STAGING_APPROVAL_REQUIRED",
                 lambda: self.start(authorize_stage=False))
        self.err("EXPECTED_PARENT_PIN_REQUIRED", lambda: self.start(expected_parent_pin=None))
        self.err("STAGING_PARENT_PIN_MISMATCH", lambda: self.start(expected_parent_pin="f" * 64))
        self.assertEqual(self.stager.inspect(expected_parent_pin=self.pin)["staged_count"], 0)

    def test_idempotent_start_same_key_not_second_id(self):
        self.init()
        a = self.start()
        b = self.start()
        self.assertEqual(a["run_id"], b["run_id"])
        self.assertTrue(b["idempotent_reentry"])
        self.assertEqual(b["reason_code"], "STAGING_IDEMPOTENT_REENTRY_READ_ONLY")
        self.assertEqual(self.stager.inspect(expected_parent_pin=self.pin)["staged_count"], 1)

    def test_explicit_run_reentry_across_store_instances(self):
        self.init()
        self.first = self.start()
        new_process_like = st.TaskStaging(str(self.root), str(self.repo), clock=self.clock)
        b = new_process_like.reenter(self.src, operation_key="create-run-0001",
                                     expected_parent_pin=self.pin, run_id=self.first["run_id"],
                                     expected_revision=1)
        self.assertEqual(b["run_id"], self.first["run_id"])
        self.assertFalse(b["mutable_lifecycle_restored"])
        self.err("STAGING_RUN_NOT_FOUND", lambda: self.reenter(run_id="run_v1_" + "e" * 48))

    def test_expired_cannot_reenter_or_restage_existing_key(self):
        self.init()
        self.first = self.start(ttl_seconds=60)
        self.clock.value += timedelta(seconds=60)
        self.err("STAGING_EXPIRED_NO_REENTRY", lambda: self.start(ttl_seconds=60))
        self.err("STAGING_EXPIRED_NO_REENTRY", lambda: self.reenter())
        inspect = self.stager.inspect(expected_parent_pin=self.pin)
        self.assertEqual((inspect["expired_count"], inspect["staged_count"]), (1, 1))
        self.assertTrue(self.record_path(self.first).is_file())

    def test_clock_rollback_blocks_expiry_bypass(self):
        self.init()
        self.first = self.start()
        self.clock.value -= timedelta(seconds=600)
        self.err("STAGING_CLOCK_ROLLBACK_UNAVAILABLE", lambda: self.reenter())

    def test_duplicate_ttl_and_actor_labels_conflict(self):
        self.init()
        self.start(actor_claim=lc.declared_actor("human", "operator-a"))
        self.err("STAGING_REENTRY_ACTOR_LABEL_CONFLICT",
                 lambda: self.start(actor_claim=lc.declared_actor("human", "operator-b")))
        self.err("STAGING_REENTRY_IDENTITY_REVISION_OR_TTL_CONFLICT",
                 lambda: self.start(ttl_seconds=600))

    def test_source_revision_operation_identity_pin(self):
        self.init()
        self.first = self.start()
        self.err("STAGING_REENTRY_IDENTITY_REVISION_OR_TTL_CONFLICT",
                 lambda: self.reenter(expected_revision=2))
        self.err("STAGING_REENTRY_IDENTITY_REVISION_OR_TTL_CONFLICT",
                 lambda: self.reenter(operation_key="other-run-0001"))
        self.err("STAGING_REENTRY_IDENTITY_REVISION_OR_TTL_CONFLICT",
                 lambda: self.stager.reenter(context("DeliveredTarget"), operation_key="create-run-0001",
                     expected_parent_pin=self.pin, run_id=self.first["run_id"], expected_revision=1))
        self.err("STAGING_REENTRY_IDENTITY_REVISION_OR_TTL_CONFLICT",
                 lambda: self.stager.start(context("DeliveredTarget"), operation_key="create-run-0001",
                     expected_parent_pin=self.pin, authorize_stage=True))

    def test_invalid_context_fails_without_creating_stage(self):
        self.init()
        invalid = context()
        invalid["context_sha256"] = "f" * 64
        self.err("CONTEXT_HASH_MISMATCH", lambda: self.stager.start(
            invalid, operation_key="create-run-0001", expected_parent_pin=self.pin,
            authorize_stage=True))
        self.assertEqual(self.stager.inspect(expected_parent_pin=self.pin)["staged_count"], 0)

    def test_ttl_bound_revision_type_count(self):
        self.init()
        for ttl in (1, 86401, True):
            self.err("STAGING_TTL_OUT_OF_RANGE", lambda: self.start(ttl_seconds=ttl))
        for rev in (0, 2, True):
            self.err("INITIAL_STAGING_REVISION_MUST_BE_ONE", lambda: self.start(expected_revision=rev))
        self.assertEqual(self.stager.inspect(expected_parent_pin=self.pin)["staged_count"], 0)
        with patch.object(st, "MAX_STAGE_COUNT", 1):
            self.start()
            self.err("STAGING_RECORD_CAPACITY_EXHAUSTED",
                     lambda: self.start(operation_key="create-run-0002"))

    def test_symlinked_root_and_ancestor_denied(self):
        external = self.base / "root-link"
        external.symlink_to(self.root, target_is_directory=True)
        bad = st.TaskStaging(str(external), str(self.repo))
        self.err("STAGE_DIRECTORY_UNAVAILABLE_OR_SYMLINKED", lambda: bad.initialize(approve_init=True))
        stage_sub = self.base / "parent-link" / "private-stage"
        (self.base / "parent-link").symlink_to(self.base)
        bad = st.TaskStaging(str(stage_sub), str(self.repo))
        self.err("STAGE_DIRECTORY_UNAVAILABLE_OR_SYMLINKED", lambda: bad.initialize(approve_init=True))

    def test_owner_private_root_and_parent_required(self):
        self.root.chmod(0o755)
        self.err("STAGING_ROOT_MUST_BE_OWNER_PRIVATE", lambda: self.stager.initialize(approve_init=True))
        self.root.chmod(0o700)
        self.base.chmod(0o755)
        self.err("STAGING_PARENT_MUST_BE_OWNER_PRIVATE", lambda: self.stager.initialize(approve_init=True))
        self.base.chmod(0o700)

    def test_repo_or_stage_containment_refused(self):
        child = self.repo / "secret-stage"
        child.mkdir(mode=0o700)
        bad = st.TaskStaging(str(child), str(self.repo))
        self.err("BUSINESS_REPOSITORY_OVERLAPS_STAGE", lambda: bad.initialize(approve_init=True))
        bad2 = st.TaskStaging(str(self.base), str(child))
        self.err("STAGING_PARENT_MUST_BE_OWNER_PRIVATE", lambda: bad2.initialize(approve_init=True))
        # Same physical directory via different spelling, no symlink.
        bad3 = st.TaskStaging(str(self.repo), str(self.repo))
        self.err("BUSINESS_REPOSITORY_OVERLAPS_STAGE", lambda: bad3.initialize(approve_init=True))

    def test_symlinked_repo_is_not_accepted(self):
        repo_alias = self.base / "repo-link"
        repo_alias.symlink_to(self.repo, target_is_directory=True)
        bad = st.TaskStaging(str(self.root), str(repo_alias))
        self.err("BUSINESS_DIRECTORY_UNAVAILABLE_OR_SYMLINKED", lambda: bad.initialize(approve_init=True))

    def test_stage_symlink_leaf_and_hardlink_refused(self):
        self.init()
        self.first = self.start()
        p = self.record_path(self.first)
        p.unlink()
        p.symlink_to(self.repo / "business.py")
        self.err("STAGING_FILE_UNAVAILABLE_OR_SYMLINKED", lambda: self.reenter())
        p.unlink()
        self.err("STAGING_RUN_NOT_FOUND", lambda: self.reenter())
        other = self.start(operation_key="create-run-0002")
        p = self.record_path(other)
        os.link(p, self.root / "extra.stage.json")
        self.err("STAGING_DIRECTORY_UNEXPECTED_ENTRY", lambda: self.stager.inspect(expected_parent_pin=self.pin))
        (self.root / "extra.stage.json").unlink()
        os.link(p, self.base / "hardlink.outside")
        self.err("STAGE_FILE_PERMISSIONS_TYPE_SIZE_OR_LINK_COUNT_UNSAFE",
                 lambda: self.stager.inspect(expected_parent_pin=self.pin))

    def test_corrupt_hmac_record_is_unavailable(self):
        self.init()
        r = self.start()
        p = self.record_path(r)
        raw = json.loads(p.read_text())
        raw["operation_key"] = "attacker-run-0001"
        p.write_text(json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n")
        self.err("STAGING_RECORD_HMAC_INVALID", lambda: self.stager.inspect(expected_parent_pin=self.pin))

    def test_checkpoint_tampering_even_with_resealed_hmac_rejected(self):
        self.init()
        r = self.start()
        p = self.record_path(r)
        obj = json.loads(p.read_text())
        obj["checkpoint"]["run"]["state"] = "COMPLETED"
        obj["checkpoint_sha256"] = st._sha(st.DOMAIN_CHECKPOINT, st._canonical(obj["checkpoint"]))
        key = (self.root / ".staging-key").read_bytes()
        obj["mac_sha256"] = st._mac(key, {k: v for k, v in obj.items() if k != "mac_sha256"})
        p.write_bytes(st._canonical(obj) + b"\n")
        self.err("STAGING_RECORD_CHECKPOINT_DRIFT", lambda: self.stager.inspect(expected_parent_pin=self.pin))

    def test_pending_crash_artifact_fails_closed_no_auto_resume(self):
        self.init()
        (self.root / (".pending-" + "a" * 32)).write_bytes(b"partial")
        self.err("INCOMPLETE_STAGING_TRANSACTION_REQUIRES_MANUAL_REVIEW", lambda: self.start())
        self.assertEqual(list(self.root.glob("run_*.stage.json")), [])

    def test_injected_commit_race_refuses_and_rolls_back(self):
        self.init()
        with patch.object(st, "_pinned", return_value=False):
            self.err("STAGING_PARENT_CHANGED_DURING_LOCK", lambda: self.start())
        self.assertEqual(self.stager.inspect(expected_parent_pin=self.pin)["staged_count"], 0)
        real_pinned = st._pinned
        count = 0

        def fail_publish(*a):
            nonlocal count
            count += 1
            return count < 2 and real_pinned(*a)
        with patch.object(st, "_pinned", side_effect=fail_publish):
            self.err("STAGING_PARENT_CHANGED_BEFORE_PUBLISH", lambda: self.start())
        self.assertEqual(self.stager.inspect(expected_parent_pin=self.pin)["staged_count"], 0)
        self.assertFalse(any(name.startswith(".pending") for name in os.listdir(self.root)))

    def test_injected_link_failure_rolls_back_cleanly(self):
        self.init()
        with patch.object(st.os, "link", side_effect=OSError("simulated link refusal")):
            with patch.object(st, "_supported", return_value=None):
                self.err("STAGING_CREATE_FAILED_NO_ID_COMMITTED", lambda: self.start())
        self.assertFalse(any(name.startswith(".pending") for name in os.listdir(self.root)))
        self.assertEqual(self.stager.inspect(expected_parent_pin=self.pin)["staged_count"], 0)

    def test_linked_but_commit_sync_failed_fails_closed(self):
        self.init()
        real_sync = st.os.fsync
        sync_count = 0

        def sync_with_failed_directory(fd):
            nonlocal sync_count
            if os.path.isdir(f"/proc/self/fd/{fd}"):
                sync_count += 1
                if sync_count == 1:
                    raise OSError("simulated failure after link")
            return real_sync(fd)

        with patch.object(st.os, "fsync", side_effect=sync_with_failed_directory):
            self.err("STAGING_PUBLISH_DURABILITY_UNCERTAIN", lambda: self.start())
        self.err("INCOMPLETE_STAGING_TRANSACTION_REQUIRES_MANUAL_REVIEW",
                 lambda: self.stager.inspect(expected_parent_pin=self.pin))

    def test_unknown_entry_rejected(self):
        self.init()
        (self.root / "rogue.txt").write_text("rogue")
        self.err("STAGING_DIRECTORY_UNEXPECTED_ENTRY", lambda: self.start())

    def test_concurrent_same_key_commits_one_run(self):
        self.init()
        barrier = threading.Barrier(3)
        results = []
        errors = []

        def worker():
            try:
                barrier.wait()
                results.append(self.start())
            except Exception as exc:
                errors.append(exc)

        workers = [threading.Thread(target=worker) for _ in range(2)]
        for w in workers:
            w.start()
        barrier.wait()
        for w in workers:
            w.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["run_id"], results[1]["run_id"])
        self.assertEqual(sum(r["idempotent_reentry"] for r in results), 1)
        self.assertEqual(self.stager.inspect(expected_parent_pin=self.pin)["staged_count"], 1)

    def test_stage_live_with_existing_handoff_snapshot(self):
        self.init()
        session = lc.Lifecycle.create(self.src, "stage-live-0001")
        s = session.snapshot()
        s = session.advance_run("READY", expected_revision=s["revision"],
             context_sha256=s["source"]["context_sha256"], operation_key="ready-live-0001")
        s = session.advance_run("ACTIVE", expected_revision=s["revision"],
             context_sha256=s["source"]["context_sha256"], operation_key="active-live-0001")
        s = session.create_handoff(expected_revision=s["revision"],
             context_sha256=s["source"]["context_sha256"], operation_key="handoff-live-0001")
        response = self.stager.stage_live(session, expected_parent_pin=self.pin,
             expected_revision=4, context_sha256=s["source"]["context_sha256"],
             operation_key="stage-live-0001", authorize_stage=True)
        self.assertEqual(response["revision"], 4)
        same = self.stager.stage_live(session, expected_parent_pin=self.pin,
             expected_revision=4, context_sha256=s["source"]["context_sha256"],
             operation_key="stage-live-0001", authorize_stage=True)
        self.assertTrue(same["idempotent_reentry"])
        self.err("STAGING_LIVE_REVISION_SOURCE_OR_CREATE_KEY_MISMATCH", lambda:
             self.stager.stage_live(session, expected_parent_pin=self.pin,
             expected_revision=3, context_sha256=s["source"]["context_sha256"],
             operation_key="stage-live-0001", authorize_stage=True))

    def test_path_canonicalization_enforced(self):
        bad_paths = ["relative/dir", "/tmp/../tmp/dir", "/tmp//dir", "/tmp/dir/", "/tmp/a\n"]
        for path in bad_paths:
            with self.subTest(path=path):
                self.err("STAGE_PATH_INVALID", lambda: st.TaskStaging(path, str(self.repo)))

    def test_repo_identity_swap_fails_on_access(self):
        self.init()
        moved = self.base / "repo-moved"
        self.repo.rename(moved)
        self.repo.mkdir(mode=0o700)
        self.err("STAGING_PARENT_IDENTITY_OR_KEY_CHANGED", lambda: self.start())

    def test_manifest_key_change_fails_closed(self):
        self.init()
        (self.root / ".staging-key").write_bytes(b"x" * 32)
        self.err("STAGING_PARENT_IDENTITY_OR_KEY_CHANGED", lambda: self.start())

    def test_second_valid_operation_creates_distinct_run(self):
        self.init()
        one = self.start()
        two = self.start(operation_key="create-run-0002")
        self.assertNotEqual(one["run_id"], two["run_id"])
        self.assertEqual(self.stager.inspect(expected_parent_pin=self.pin)["staged_count"], 2)

    def test_cli_end_to_end(self):
        prepared = self.base / "ec170.json"
        prepared.write_bytes(st._canonical(self.src))
        def call(*parts):
            result = subprocess.run([sys.executable, str(Path(st.__file__)), "--root", str(self.root),
                                     "--business-repo-root", str(self.repo), *parts],
                                    capture_output=True, text=True, check=False)
            return result.returncode, json.loads(result.stdout)
        rc, data = call("--init", "--approve-init")
        self.assertEqual((rc, data["reason_code"]), (0, "PRIVATE_STAGING_INITIALIZED"))
        rc, stage = call("--start", str(prepared), "--approve-stage", "--parent-pin", data["parent_pin"],
                         "--operation-key", "create-run-0001")
        self.assertEqual((rc, stage["reason_code"]), (0, "STAGING_CREATED_LOCAL_ONLY"))
        rc, retry = call("--start", str(prepared), "--approve-stage", "--parent-pin", data["parent_pin"],
                         "--operation-key", "create-run-0001")
        self.assertEqual(rc, 0)
        self.assertEqual(stage["run_id"], retry["run_id"])
        rc, reopened = call("--reenter", str(prepared), "--parent-pin", data["parent_pin"],
                            "--run-id", stage["run_id"], "--operation-key", "create-run-0001")
        self.assertEqual((rc, reopened["run_id"]), (0, stage["run_id"]))
        rc, inspect = call("--inspect", "--parent-pin", data["parent_pin"])
        self.assertEqual((rc, inspect["staged_count"]), (0, 1))


if __name__ == "__main__":
    unittest.main()
