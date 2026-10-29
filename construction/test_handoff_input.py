#!/usr/bin/env python3
"""EC173 offline functional scenarios with synthetic sources and disposable POSIX roots."""
from __future__ import annotations

import copy
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

import codeprepare_multisource as ec170
import handoff_lifecycle as lc
import handoff_input as hi
import task_staging as st
from test_handoff_lifecycle import context, ready_active, add_handoff, step_handoff
import test_codeprepare_multisource as fx


class Clock:
    def __init__(self):
        self.value = datetime.now(timezone.utc).replace(microsecond=0)

    def __call__(self):
        return self.value


def refreshed(prepared: dict, observed: datetime) -> dict:
    result = copy.deepcopy(prepared)
    result["context"]["source_observed_at_utc"] = observed.isoformat()
    result["context_sha256"] = lc._hash(lc.DOMAIN_CONTEXT, result["context"])
    return result


class HandoffInputCases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ces-ec173-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "ces_private"
        self.repo = self.base / "real-business"
        self.root.mkdir(mode=0o700)
        self.repo.mkdir(mode=0o700)
        (self.repo / "business.py").write_bytes(b"no write to business repo\n")
        self.clock = Clock()
        self.stage = st.TaskStaging(str(self.root), str(self.repo), clock=self.clock)
        self.pin = self.stage.initialize(approve_init=True)["parent_pin"]
        self.service = hi.HandoffInput(str(self.root), str(self.repo), clock=self.clock)
        self.src = refreshed(context(), self.clock.value)

    def err(self, code, callback):
        with self.assertRaises((hi.InputError, st.StageError, lc.LifecycleError)) as error:
            callback()
        self.assertEqual(error.exception.code, code)

    def setup_live(self, prepared=None, *, handoff_ready=True, run_active=True,
                   store_ttl=900):
        prepared = prepared or self.src
        session = lc.Lifecycle.create(prepared, "create-run-0001")
        if run_active:
            ready_active(session)
        if run_active:
            add_handoff(session)
            if handoff_ready:
                step_handoff(session, "READY", "handoff-ready-0001",
                             acknowledge_partial=(prepared["status"] == "partial"))
        snap = session.snapshot()
        self.stage.stage_live(session, expected_parent_pin=self.pin,
                              expected_revision=snap["revision"],
                              context_sha256=prepared["context_sha256"],
                              operation_key="create-run-0001", authorize_stage=True,
                              ttl_seconds=store_ttl)
        self.src = prepared
        self.snap = snap
        self.opts = {
            "expected_parent_pin": self.pin,
            "run_id": snap["run"]["run_id"],
            "handoff_id": snap["handoffs"][0]["handoff_id"] if snap["handoffs"] else
                          "handoff_v1_" + "f" * 48,
            "expected_revision": snap["revision"],
            "expected_event_sha256": snap["last_event_sha256"],
            "operation_key": "input-write-0001",
            "allow_content_for": prepared["source_mode"],
        }
        self.path = self.root / (self.opts["handoff_id"] + ".input.json")
        return snap

    def create(self, **more):
        params = dict(self.opts, authorize_input=True)
        params.update(more)
        return self.service.create(self.src, **params)

    def reenter(self, **more):
        params = dict(self.opts)
        params.update(more)
        return self.service.reenter(self.src, **params)

    def test_complete_local_input_is_exactly_source_and_handoff_pinned(self):
        self.setup_live()
        out = self.create()
        self.assertEqual(out["status"], "success")
        self.assertEqual(out["exit_code"], 0)
        self.assertEqual(out["input_path"], str(self.path))
        self.assertTrue(out["input_committed"])
        self.assertFalse(out["ai_dispatched"])
        self.assertFalse(out["source_currentness_proven"])
        self.assertEqual(out["stage_revision"], self.snap["revision"])
        self.assertEqual(self.path.stat().st_mode & 0o077, 0)
        self.assertEqual(os.stat(self.path).st_nlink, 1)
        saved = json.loads(self.path.read_bytes())
        self.assertEqual(saved["material"]["task_kind"], "code_analysis")
        self.assertEqual(saved["evidence_hash"], out["evidence_hash"])
        self.assertEqual(saved["stage_event_sha256"], self.snap["last_event_sha256"])
        self.assertEqual(saved["subject"], out["subject"])
        self.assertEqual(saved["material"]["segments"], self.src["context"]["segments"])
        self.assertEqual((self.repo / "business.py").read_bytes(), b"no write to business repo\n")
        self.assertEqual(sorted(x.name for x in self.repo.iterdir()), ["business.py"])

    def test_existing_ec172_stage_read_paths_remain_functional(self):
        self.setup_live()
        self.create()
        self.assertEqual(self.stage.inspect(expected_parent_pin=self.pin)["staged_count"], 1)
        self.assertEqual(self.stage.reenter(self.src, operation_key="create-run-0001",
                                            expected_parent_pin=self.pin,
                                            run_id=self.opts["run_id"],
                                            expected_revision=self.opts["expected_revision"])["status"], "success")

    def test_identical_retry_is_read_only_and_preserves_bytes(self):
        self.setup_live()
        a = self.create()
        old = self.path.read_bytes()
        b = self.create()
        self.assertEqual(a["input_path"], b["input_path"])
        self.assertTrue(b["idempotent_reentry"])
        self.assertEqual(b["reason_code"], "AI_INPUT_IDEMPOTENT_READ_ONLY_REENTRY")
        self.assertEqual(self.path.read_bytes(), old)
        self.assertEqual(self.reenter()["reason_code"], "AI_INPUT_READ_ONLY_REENTRY")

    def test_read_only_reentry_never_returns_patch(self):
        self.setup_live()
        self.create()
        out = self.reenter()
        self.assertNotIn("diff --git", json.dumps(out))
        self.assertFalse(out["mutable_lifecycle_restored"])

    def test_separate_in_memory_read_grant_is_required(self):
        self.setup_live()
        self.create()
        args = {k: v for k, v in self.opts.items() if k != "allow_content_for"}
        self.err("EXPLICIT_AI_INPUT_CONTENT_READ_APPROVAL_REQUIRED",
                 lambda: self.service.load_authorized(self.src, authorize_read=False,
                                                      read_content_for="WorkingTree", **args))
        got = self.service.load_authorized(self.src, authorize_read=True,
                                            read_content_for="WorkingTree", **args)
        self.assertIn("diff --git", json.dumps(got["material"]))
        self.assertFalse(got["metadata"]["ai_dispatched"])
        self.err("INPUT_CONTENT_GRANT_SOURCE_MISMATCH",
                 lambda: self.service.load_authorized(self.src, authorize_read=True,
                                                      read_content_for="ProposedPR", **args))

    def test_denied_input_grant_and_bad_parent_pin_never_write(self):
        self.setup_live()
        self.err("EXPLICIT_AI_INPUT_STAGING_APPROVAL_REQUIRED",
                 lambda: self.create(authorize_input=False))
        self.err("STAGING_PARENT_PIN_MISMATCH",
                 lambda: self.create(expected_parent_pin="a" * 64))
        self.assertFalse(self.path.exists())

    def test_ec170_permission_cannot_be_inherited_from_prior_step(self):
        self.setup_live()
        changed = copy.deepcopy(self.src)
        changed["permission"]["inherited_from_prior_tools"] = True
        self.err("EC170_CONTENT_RELEASE_NOT_AUTHORIZED_FOR_SOURCE",
                 lambda: self.service.create(changed, authorize_input=True, **self.opts))
        self.assertFalse(self.path.exists())

    def test_denied_ec170_context_cannot_disclose_raw_content(self):
        self.setup_live()
        self.src["permission"]["content_granted"] = False
        self.err("EC170_CONTENT_RELEASE_NOT_AUTHORIZED_FOR_SOURCE", self.create)
        self.assertFalse(self.path.exists())

    def test_source_mode_grant_must_match_current_context(self):
        self.setup_live()
        self.err("INPUT_CONTENT_GRANT_SOURCE_MISMATCH",
                 lambda: self.create(allow_content_for="DeliveredTarget"))
        self.assertFalse(self.path.exists())

    def test_local_native_delivered_target_supported(self):
        prepared = ec170.prepare_context("DeliveredTarget", local_codeprepare=fx.local_result("DeliveredTarget"),
                                         content_permission="DeliveredTarget")
        self.assertEqual(prepared["status"], "success")
        self.setup_live(refreshed(prepared, self.clock.value))
        out = self.create()
        self.assertEqual(out["source_mode"], "DeliveredTarget")
        self.assertTrue(out["input_committed"])

    def test_handoff_must_exist_in_committed_snapshot(self):
        self.setup_live(handoff_ready=False)
        self.err("INPUT_HANDOFF_NOT_READY_IN_COMMITTED_STAGE", self.create)
        self.assertFalse(self.path.exists())

    def test_run_must_be_active_and_real_handoff_created(self):
        self.setup_live(run_active=False)
        self.err("INPUT_HANDOFF_NOT_READY_IN_COMMITTED_STAGE", self.create)

    def test_revision_event_and_run_cannot_be_swapped(self):
        self.setup_live()
        self.err("INPUT_STAGE_REVISION_EVENT_OR_SOURCE_MISMATCH",
                 lambda: self.create(expected_revision=self.opts["expected_revision"] - 1))
        self.err("INPUT_STAGE_REVISION_EVENT_OR_SOURCE_MISMATCH",
                 lambda: self.create(expected_event_sha256="f" * 64))
        self.err("INPUT_COMMITTED_RUN_STAGE_NOT_FOUND",
                 lambda: self.create(run_id="run_v1_" + "b" * 48))
        self.assertFalse(self.path.exists())

    def test_stored_input_must_match_original_stage_identity_and_operation(self):
        self.setup_live()
        self.create()
        self.err("INPUT_IDEMPOTENCY_OR_TTL_CONFLICT",
                 lambda: self.create(operation_key="other-input-0001"))
        self.err("INPUT_IDEMPOTENCY_OR_TTL_CONFLICT",
                 lambda: self.create(ttl_seconds=120))
        self.err("INPUT_OPERATION_REPLAY_OR_CONFLICT",
                 lambda: self.reenter(operation_key="other-input-0001"))

    def test_evidence_is_bound_to_prepared_source_bytes(self):
        self.setup_live()
        self.create()
        altered = copy.deepcopy(self.src)
        altered["context"]["segments"][0]["content"] += "\n+unreviewed addition\n"
        altered["context"]["coverage"]["content_candidate_bytes"] += len("\n+unreviewed addition\n")
        altered["coverage"] = copy.deepcopy(altered["context"]["coverage"])
        altered["context_sha256"] = lc._hash(lc.DOMAIN_CONTEXT, altered["context"])
        self.err("INPUT_STAGE_REVISION_EVENT_OR_SOURCE_MISMATCH",
                 lambda: self.service.reenter(altered, **self.opts))

    def test_stale_observation_and_future_clock_fail_closed(self):
        self.setup_live()
        self.clock.value += timedelta(seconds=601)
        self.err("SOURCE_OBSERVATION_OLD_OR_FUTURE_NO_CURRENTNESS_PROOF", self.create)
        self.clock.value -= timedelta(seconds=641)
        self.err("SOURCE_OBSERVATION_OLD_OR_FUTURE_NO_CURRENTNESS_PROOF", self.create)
        self.assertFalse(self.path.exists())

    def test_reentry_age_does_not_extend_on_reentry(self):
        self.setup_live()
        self.create(ttl_seconds=900)
        self.clock.value += timedelta(seconds=601)
        self.err("SOURCE_OBSERVATION_OLD_OR_FUTURE_NO_CURRENTNESS_PROOF", self.reenter)

    def test_input_expiry_blocks_read_even_with_still_live_stage(self):
        self.setup_live()
        self.create(ttl_seconds=60)
        self.clock.value += timedelta(seconds=60)
        self.err("INPUT_EXPIRED_OR_CLOCK_UNSAFE", self.reenter)
        self.err("INPUT_EXPIRED_OR_CLOCK_UNSAFE",
                 lambda: self.create(ttl_seconds=60))

    def test_stage_expiry_does_not_get_renewed_by_input(self):
        self.setup_live(store_ttl=60)
        self.create(ttl_seconds=300)
        self.assertEqual(json.loads(self.path.read_bytes())["expires_at_utc"],
                         st._stamp(self.clock.value + timedelta(seconds=60)))
        self.clock.value += timedelta(seconds=60)
        self.err("STAGING_EXPIRED_NO_REENTRY", self.reenter)

    def test_partial_content_keeps_partial_exit_code_and_missing_coverage(self):
        partial = copy.deepcopy(self.src)
        c = partial["context"]["coverage"]
        c["content_complete_for_selected_source"] = False
        c["missing_requirements"] = ["SYNTHETIC_PARTIAL_COVERAGE"]
        partial["coverage"] = copy.deepcopy(c)
        partial["status"] = "partial"
        partial["exit_code"] = 2
        partial["context_sha256"] = lc._hash(lc.DOMAIN_CONTEXT, partial["context"])
        self.setup_live(partial)
        out = self.create()
        self.assertEqual(out["status"], "partial")
        self.assertEqual(out["exit_code"], 2)
        self.assertIn("SYNTHETIC_PARTIAL_COVERAGE", out["coverage"]["missing_requirements"])
        self.assertFalse(out["coverage"]["complete_for_selected_source"])

    def test_forged_success_must_not_silence_missing_coverage(self):
        changed = copy.deepcopy(self.src)
        changed["context"]["coverage"]["content_complete_for_selected_source"] = False
        changed["context"]["coverage"]["missing_requirements"] = ["HIDDEN_GAP"]
        changed["coverage"] = copy.deepcopy(changed["context"]["coverage"])
        changed["context_sha256"] = lc._hash(lc.DOMAIN_CONTEXT, changed["context"])
        self.setup_live(changed)
        self.err("INPUT_SUCCESS_CANNOT_HIDE_INCOMPLETE_COVERAGE", self.create)

    def test_historical_proposed_requires_distinct_opt_in_and_partial_label(self):
        snap, _ = fx.ec165.create(selected=("src/service.py",), include=True)
        p = ec170.prepare_context("ProposedPR", proposed_snapshot=snap,
                                  content_permission="ProposedPR")
        self.assertEqual(p["status"], "partial")
        self.setup_live(refreshed(p, self.clock.value))
        self.err("HISTORICAL_PROPOSAL_NEEDS_EXPLICIT_LIMITED_CONSENT", self.create)
        out = self.create(allow_historical_proposal=True)
        self.assertEqual(out["status"], "partial")
        self.assertTrue(out["historical_proposal_only"])
        self.assertFalse(out["source_currentness_proven"])
        self.assertFalse(out["coverage"]["complete_for_selected_source"])

    def test_stale_proposed_reconciliation_rejected_even_with_permission(self):
        snap, _ = fx.ec165.create(selected=("src/service.py",), include=True)
        changed = fx.ec163.metadata("github", 3)
        changed["head"]["sha"] = "d" * 40
        rec, _ = fx.ec166.request(prior=snap, current=changed)
        prepared = ec170.prepare_context("ProposedPR", proposed_snapshot=snap,
                                         proposed_reconcile=rec, content_permission="ProposedPR")
        self.setup_live(refreshed(prepared, self.clock.value))
        self.err("EC170_CONTENT_RELEASE_NOT_AUTHORIZED_FOR_SOURCE",
                 lambda: self.create(allow_historical_proposal=True))

    def test_metadata_only_context_not_persisted_as_ai_code(self):
        prepared = refreshed(context(incomplete=True), self.clock.value)
        self.setup_live(prepared)
        self.err("EC170_CONTENT_RELEASE_NOT_AUTHORIZED_FOR_SOURCE", self.create)
        self.assertFalse(self.path.exists())

    def test_detect_obvious_secrets_without_echo(self):
        raw = copy.deepcopy(self.src)
        raw["context"]["segments"][0]["content"] += "\n+password = 'verySecretValue123456789'\n"
        raw["context"]["coverage"]["content_candidate_bytes"] += len("\n+password = 'verySecretValue123456789'\n")
        raw["coverage"] = copy.deepcopy(raw["context"]["coverage"])
        raw["context_sha256"] = lc._hash(lc.DOMAIN_CONTEXT, raw["context"])
        self.setup_live(raw)
        self.err("INPUT_POTENTIAL_SECRET_OR_PRIVATE_PATH_REJECTED", self.create)
        self.assertFalse(self.path.exists())

    def test_sensitive_file_paths_and_traversal_are_rejected(self):
        for path in (".env", "../../escape.py", "C:/secret.txt", "../../.aws/credentials"):
            with self.subTest(path=path):
                p = copy.deepcopy(self.src)
                p["context"]["segments"][0]["entries"][0]["path"] = path
                p["context_sha256"] = lc._hash(lc.DOMAIN_CONTEXT, p["context"])
                if not hasattr(self, "opts"):
                    self.setup_live(p)
                else:
                    self.src = p
                code = "INPUT_SENSITIVE_PATH_REJECTED" if path == ".env" else "INPUT_PATH_METADATA_UNSAFE"
                self.err(code, self.create)
                self.assertFalse(self.path.exists())

    def test_payload_size_limit_before_any_write(self):
        self.setup_live()
        with patch.object(hi, "MAX_INPUT_BYTES", 100):
            self.err("INPUT_MATERIAL_TOO_LARGE", self.create)
        self.assertFalse(self.path.exists())

    def test_bad_input_hmac_and_symlink_leaf_rejected(self):
        self.setup_live()
        self.create()
        raw = json.loads(self.path.read_text())
        raw["material"]["guidance"] = ["injected command"]
        self.path.write_bytes(st._canonical(raw) + b"\n")
        self.err("INPUT_RECORD_HMAC_INVALID", self.reenter)
        self.path.unlink()
        self.path.symlink_to(self.base / "target")
        self.err("STAGING_FILE_UNAVAILABLE_OR_SYMLINKED", self.reenter)

    def test_hardlinked_or_world_readable_input_rejected(self):
        self.setup_live()
        self.create()
        other = self.base / "linked"
        os.link(self.path, other)
        self.err("STAGE_FILE_PERMISSIONS_TYPE_SIZE_OR_LINK_COUNT_UNSAFE", self.reenter)
        other.unlink()
        self.path.chmod(0o644)
        self.err("STAGE_FILE_PERMISSIONS_TYPE_SIZE_OR_LINK_COUNT_UNSAFE", self.reenter)

    def test_pending_crash_uncertain_fail_closed_for_ec172_and_ec173(self):
        self.setup_live()
        (self.root / (".pending-input-" + "1" * 32)).write_bytes(b"partial uncommitted")
        self.err("INCOMPLETE_STAGING_TRANSACTION_REQUIRES_MANUAL_REVIEW", self.create)
        self.err("INCOMPLETE_STAGING_TRANSACTION_REQUIRES_MANUAL_REVIEW",
                 lambda: self.stage.inspect(expected_parent_pin=self.pin))

    def test_prelink_failure_cleans_owned_pending(self):
        self.setup_live()
        with patch.object(hi.os, "link", side_effect=OSError("forced fail")), \
             patch.object(st, "_supported", return_value=None):
            self.err("INPUT_CREATE_FAILED_NO_PATH_COMMITTED", self.create)
        self.assertFalse(self.path.exists())
        self.assertFalse(any(x.name.startswith(".pending-input-") for x in self.root.iterdir()))

    def test_postlink_fsync_failure_does_not_report_success_or_auto_recover(self):
        self.setup_live()
        original = hi.os.fsync
        calls = [0]
        def fsync(fd):
            calls[0] += 1
            if calls[0] == 2:
                raise OSError("simulate unresolved commit")
            return original(fd)
        with patch.object(hi.os, "fsync", side_effect=fsync):
            self.err("INPUT_PUBLISH_DURABILITY_UNCERTAIN", self.create)
        self.assertTrue(self.path.exists())
        self.assertTrue(any(x.name.startswith(".pending-input-") for x in self.root.iterdir()))
        self.err("INCOMPLETE_STAGING_TRANSACTION_REQUIRES_MANUAL_REVIEW", self.reenter)

    def test_parallel_same_handoff_only_one_input_and_same_identity(self):
        self.setup_live()
        outputs, errors = [], []
        def run():
            try:
                outputs.append(self.create())
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=run) for _ in range(2)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(outputs), 2)
        self.assertEqual({r["input_path"] for r in outputs}, {str(self.path)})
        self.assertEqual(sum(not r["idempotent_reentry"] for r in outputs), 1)

    def test_cli_success_and_denied_status_do_not_print_raw_patch(self):
        self.setup_live()
        source_file = self.base / "ec170.json"
        source_file.write_bytes(st._canonical(self.src) + b"\n")
        script = Path(hi.__file__).resolve()
        args = [sys.executable, str(script), "--create", str(source_file),
                "--root", str(self.root), "--business-repo-root", str(self.repo),
                "--parent-pin", self.pin, "--run-id", self.opts["run_id"],
                "--handoff-id", self.opts["handoff_id"],
                "--expected-revision", str(self.opts["expected_revision"]),
                "--expected-event-sha256", self.opts["expected_event_sha256"],
                "--operation-key", self.opts["operation_key"],
                "--allow-content-for", "WorkingTree"]
        denied = subprocess.run(args, text=True, capture_output=True)
        self.assertEqual(denied.returncode, 4, denied.stdout)
        self.assertEqual(json.loads(denied.stdout)["reason_code"],
                         "EXPLICIT_AI_INPUT_STAGING_APPROVAL_REQUIRED")
        committed = subprocess.run(args + ["--approve-input"], text=True, capture_output=True)
        self.assertEqual(committed.returncode, 0, committed.stdout + committed.stderr)
        result = json.loads(committed.stdout)
        self.assertEqual(result["input_path"], str(self.path))
        self.assertNotIn("diff --git", committed.stdout)
        self.assertNotIn("diff --git", denied.stdout)
        read = subprocess.run([*args[:2], "--reenter", str(source_file), *args[4:]],
                              text=True, capture_output=True)
        self.assertEqual(read.returncode, 0, read.stdout + read.stderr)
        self.assertEqual(json.loads(read.stdout)["reason_code"], "AI_INPUT_READ_ONLY_REENTRY")


if __name__ == "__main__":
    unittest.main()
