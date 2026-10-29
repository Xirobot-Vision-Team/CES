#!/usr/bin/env python3
"""EC171 feature-focused offline cases. Synthetic EC170 context is not live proof."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import codeprepare_multisource as ec170
import handoff_lifecycle as lc
import test_codeprepare_multisource as fx


def context(mode="WorkingTree", *, incomplete=False):
    native = fx.local_result(mode)
    assert mode in ("WorkingTree", "DeliveredTarget")
    result = ec170.prepare_context(mode, local_codeprepare=native,
                                   content_permission=None if incomplete else mode)
    assert result["status"] == ("partial" if incomplete else "success"), result
    return result


def new_session(prepared=None):
    return lc.Lifecycle.create(prepared or context(), "create-run-0001")


def step_run(session, target, key, **more):
    state = session.snapshot()
    return session.advance_run(target, expected_revision=state["revision"],
                               context_sha256=state["source"]["context_sha256"],
                               operation_key=key, **more)


def add_handoff(session, key="new-handoff-0001"):
    state = session.snapshot()
    return session.create_handoff(expected_revision=state["revision"],
                                  context_sha256=state["source"]["context_sha256"],
                                  operation_key=key)


def step_handoff(session, target, key, **more):
    state = session.snapshot()
    return session.advance_handoff(state["handoffs"][0]["handoff_id"], target,
                                   expected_revision=state["revision"],
                                   context_sha256=state["source"]["context_sha256"],
                                   operation_key=key, **more)


def ready_active(session):
    step_run(session, "READY", "run-ready-0001", acknowledge_partial=session.snapshot()["source"]["quality"] == "partial")
    step_run(session, "ACTIVE", "run-active-0001")


def assert_code(test, code, fn):
    with test.assertRaises(lc.LifecycleError) as e:
        fn()
    test.assertEqual(e.exception.code, code)


class IdentityAndBinding(unittest.TestCase):
    def test_preview_has_no_id(self):
        p = lc.Lifecycle.preview(context())
        self.assertIsNone(p["run_id"])
        self.assertIsNone(p["handoff_id"])
        self.assertEqual(p["state"], "NOT_CREATED")

    def test_create_cryptographic_shape_and_distinctness(self):
        a, b = new_session(), new_session()
        one = a.snapshot()["run"]["run_id"]
        two = b.snapshot()["run"]["run_id"]
        self.assertRegex(one, r"^run_v1_[a-f0-9]{48}$")
        self.assertNotEqual(one, two)
        self.assertEqual(a.snapshot()["revision"], 1)

    def test_create_failure_has_no_id_or_event(self):
        bad = context()
        bad["context_sha256"] = "0" * 64
        assert_code(self, "CONTEXT_HASH_MISMATCH", lambda: new_session(bad))
        assert_code(self, "SOURCE_SCHEMA_INVALID", lambda: lc.Lifecycle.create({}, "create-run-0001"))

    def test_reject_fabricated_external_proof(self):
        bad = context()
        bad["provider_actor_verified"] = True
        assert_code(self, "SOURCE_PROOF_ESCALATION_FORBIDDEN", lambda: new_session(bad))

    def test_reject_source_mode_mismatch_even_rehashed(self):
        bad = context()
        bad["context"]["source_mode"] = "ProposedPR"
        bad["context_sha256"] = lc._hash(lc.DOMAIN_CONTEXT, bad["context"])
        assert_code(self, "CONTEXT_BINDING_INVALID", lambda: new_session(bad))

    def test_no_raw_source_in_checkpoint(self):
        raw = context()
        self.assertIn("diff --git", json.dumps(raw))
        s = new_session(raw)
        text = s.checkpoint_json().decode()
        self.assertNotIn("diff --git", text)
        self.assertNotIn("/safe/repo", text)
        self.assertIn(raw["context_sha256"], text)

    def test_source_identity_and_mode_are_immutable(self):
        s = new_session()
        self.assertNotEqual(s.snapshot()["source"]["identity_sha256"], "0" * 64)
        original = s.snapshot()
        altered = context("DeliveredTarget")
        assert_code(self, "SOURCE_CONTEXT_MISMATCH", lambda: s.advance_run(
            "READY", expected_revision=1, context_sha256=altered["context_sha256"],
            operation_key="swap-context-0001"))
        self.assertEqual(s.snapshot(), original)

    def test_actor_claim_cannot_grant_auth(self):
        bad = {"origin": "human", "subject": "alice", "verified": True, "write_authorized": False}
        assert_code(self, "ACTOR_CLAIM_INVALID", lambda: lc.Lifecycle.create(context(), "start-run-001", actor_claim=bad))
        actor = lc.declared_actor("external", "system:opaque")
        s = lc.Lifecycle.create(context(), "start-run-001", actor_claim=actor)
        ev = s.snapshot()["events"][0]
        self.assertEqual(ev["actor_claim"], actor)
        self.assertFalse(s.snapshot()["authority"]["actor_authenticated"])
        self.assertFalse(s.snapshot()["authority"]["write_authorized"])

    def test_handoff_id_appears_only_after_eligible_creation(self):
        s = new_session()
        assert_code(self, "HANDOFF_PARENT_NOT_ACTIVE", lambda: add_handoff(s))
        self.assertEqual(s.snapshot()["handoffs"], [])
        ready_active(s)
        snapshot = add_handoff(s)
        hid = snapshot["handoffs"][0]["handoff_id"]
        self.assertRegex(hid, r"^handoff_v1_[a-f0-9]{48}$")
        self.assertNotEqual(hid, snapshot["run"]["run_id"])
        self.assertEqual(snapshot["handoffs"][0]["source_context_sha256"], snapshot["source"]["context_sha256"])

    def test_proposed_pr_historical_context_binding(self):
        snap, _ = fx.ec165.create()
        prepared = ec170.prepare_context("ProposedPR", proposed_snapshot=snap)
        self.assertEqual(prepared["status"], "partial")
        run = new_session(prepared)
        self.assertEqual(run.snapshot()["source"]["source_mode"], "ProposedPR")
        assert_code(self, "PARTIAL_CONTEXT_ACK_REQUIRED", lambda: step_run(
            run, "READY", "run-ready-0001"))
        step_run(run, "READY", "run-ready-0001", acknowledge_partial=True)
        self.assertEqual(run.snapshot()["run"]["state"], "READY")

    def test_source_envelope_mode_must_match(self):
        wrong = context()
        wrong["source_mode"] = "ProposedPR"
        assert_code(self, "SOURCE_MODE_MISMATCH", lambda: new_session(wrong))

    def test_direct_constructor_must_not_restore_untrusted_events(self):
        session = new_session()
        state = session.snapshot()
        assert_code(self, "UNTRUSTED_RESTORE_FORBIDDEN", lambda: lc.Lifecycle(
            state["source"], state["events"]))

    def test_task_kind_is_not_a_future_route(self):
        s = new_session()
        ready_active(s)
        r = s.snapshot()
        assert_code(self, "TASK_KIND_NOT_SUPPORTED", lambda: s.create_handoff(
            expected_revision=r["revision"], context_sha256=r["source"]["context_sha256"],
            operation_key="handoff-badkind-001", task_kind="report_writing"))
        self.assertEqual(s.snapshot()["handoffs"], [])


class RunTransitions(unittest.TestCase):
    def test_legal_run_sequence_and_unverified_completion(self):
        s = new_session()
        ready_active(s)
        add_handoff(s)
        step_handoff(s, "READY", "handoff-ready-0001")
        step_handoff(s, "ACTIVE", "handoff-active-0001")
        step_handoff(s, "COMPLETED", "handoff-done-0001", result_sha256="a" * 64)
        final = step_run(s, "COMPLETED", "run-done-0001", result_sha256="b" * 64)
        self.assertEqual(final["run"]["state"], "COMPLETED")
        self.assertFalse(final["authority"]["external_handoff_executed_verified"])
        self.assertFalse(final["authority"]["result_digests_authenticated"])

    def test_no_skipped_or_reversed_stages(self):
        s = new_session()
        assert_code(self, "RUN_TRANSITION_INVALID", lambda: step_run(s, "ACTIVE", "run-skip-0001"))
        step_run(s, "READY", "run-ready-0001")
        assert_code(self, "RUN_TRANSITION_INVALID", lambda: step_run(s, "CREATED", "run-back-0001"))
        self.assertEqual(s.snapshot()["revision"], 2)

    def test_duplicate_stage_is_forbidden(self):
        s = new_session()
        step_run(s, "READY", "run-ready-0001")
        assert_code(self, "RUN_TRANSITION_INVALID", lambda: step_run(s, "READY", "run-ready-0002"))

    def test_complete_without_handoff_rejected(self):
        s = new_session()
        ready_active(s)
        assert_code(self, "RUN_COMPLETION_UNSUPPORTED", lambda: step_run(
            s, "COMPLETED", "run-done-0001", result_sha256="a" * 64))

    def test_run_cannot_finish_while_handoff_pending(self):
        s = new_session()
        ready_active(s)
        add_handoff(s)
        assert_code(self, "PENDING_HANDOFFS", lambda: step_run(
            s, "UNAVAILABLE", "run-unavailable-0001", reason_code="DEPENDENCY_MISSING"))

    def test_safe_early_cancel_and_early_unavailable(self):
        for stage, goal in (("CREATED", "CANCELLED"), ("CREATED", "UNAVAILABLE"),
                            ("READY", "CANCELLED"), ("READY", "UNAVAILABLE")):
            s = new_session()
            if stage == "READY":
                step_run(s, "READY", "run-ready-0001")
            result = step_run(s, goal, "end-run-0001", reason_code="USER_CANCELLED")
            self.assertEqual(result["run"]["state"], goal)
            assert_code(self, "RUN_TRANSITION_INVALID", lambda: step_run(s, "ACTIVE", "after-end-0001"))

    def test_partial_source_requires_ack_and_blocks_success(self):
        s = new_session(context(incomplete=True))
        assert_code(self, "PARTIAL_CONTEXT_ACK_REQUIRED", lambda: step_run(s, "READY", "run-ready-0001"))
        step_run(s, "READY", "run-ready-0001", acknowledge_partial=True)
        step_run(s, "ACTIVE", "run-active-0001")
        add_handoff(s)
        assert_code(self, "PARTIAL_CONTEXT_ACK_REQUIRED", lambda: step_handoff(s, "READY", "handoff-ready-0001"))
        step_handoff(s, "READY", "handoff-ready-0001", acknowledge_partial=True)
        step_handoff(s, "ACTIVE", "handoff-active-0001")
        assert_code(self, "INCOMPLETE_SOURCE_CANNOT_COMPLETE", lambda: step_handoff(
            s, "COMPLETED", "handoff-completed-0001", result_sha256="a" * 64))
        step_handoff(s, "PARTIAL", "handoff-partial-0001", reason_code="EVIDENCE_GAP")
        step_run(s, "PARTIAL", "run-partial-0001", reason_code="EVIDENCE_GAP")
        self.assertEqual(s.snapshot()["run"]["state"], "PARTIAL")

    def test_partial_handoff_prevents_successful_run(self):
        s = new_session()
        ready_active(s)
        add_handoff(s)
        step_handoff(s, "READY", "handoff-ready-0001")
        step_handoff(s, "ACTIVE", "handoff-active-0001")
        step_handoff(s, "PARTIAL", "handoff-partial-0001", reason_code="EVIDENCE_GAP")
        assert_code(self, "RUN_COMPLETION_UNSUPPORTED", lambda: step_run(
            s, "COMPLETED", "run-done-0001", result_sha256="a" * 64))

    def test_terminal_outcomes_require_reason_or_digest(self):
        s = new_session()
        ready_active(s)
        assert_code(self, "TERMINAL_REASON_REQUIRED", lambda: step_run(s, "UNAVAILABLE", "run-unavailable-0001"))
        assert_code(self, "RESULT_DIGEST_REQUIRED", lambda: step_run(s, "COMPLETED", "run-done-0001"))
        self.assertEqual(s.snapshot()["run"]["state"], "ACTIVE")

    def test_handoff_terminal_is_immutable(self):
        s = new_session()
        ready_active(s)
        add_handoff(s)
        step_handoff(s, "CANCELLED", "handoff-cancel-0001", reason_code="USER_CANCELLED")
        assert_code(self, "HANDOFF_TRANSITION_INVALID", lambda: step_handoff(s, "READY", "handoff-ready-0001"))
        result = step_run(s, "UNAVAILABLE", "run-unavailable-0001", reason_code="ALL_HANDOFFS_CANCELLED")
        self.assertEqual(result["run"]["state"], "UNAVAILABLE")


class ConcurrencyReplayAndRecovery(unittest.TestCase):
    def test_stale_revision_is_conflict_and_snapshot_unchanged(self):
        s = new_session()
        p = s.snapshot()
        assert_code(self, "REVISION_CONFLICT", lambda: s.advance_run("READY", expected_revision=0,
            context_sha256=p["source"]["context_sha256"], operation_key="run-ready-0001"))
        self.assertEqual(s.snapshot(), p)

    def test_same_operation_replay_and_conflict(self):
        s = new_session()
        p = step_run(s, "READY", "run-ready-0001")
        assert_code(self, "OPERATION_REPLAY", lambda: s.advance_run("READY", expected_revision=1,
            context_sha256=p["source"]["context_sha256"], operation_key="run-ready-0001"))
        assert_code(self, "OPERATION_CONFLICT", lambda: s.advance_run("ACTIVE", expected_revision=2,
            context_sha256=p["source"]["context_sha256"], operation_key="run-ready-0001"))
        self.assertEqual(s.snapshot(), p)

    def test_duplicate_handoff_creation_does_not_allocate_second_id(self):
        s = new_session()
        ready_active(s)
        once = add_handoff(s)
        assert_code(self, "OPERATION_REPLAY", lambda: add_handoff(s))
        self.assertEqual(s.snapshot(), once)

    def test_two_thread_cas_only_one_wins(self):
        s = new_session()
        p = s.snapshot()
        seen = []
        lock = threading.Lock()
        def call(k):
            try:
                s.advance_run("READY", expected_revision=p["revision"],
                              context_sha256=p["source"]["context_sha256"], operation_key=k)
                code = "COMMITTED"
            except lc.LifecycleError as e:
                code = e.code
            with lock:
                seen.append(code)
        threads = [threading.Thread(target=call, args=(f"thread-ready-000{i}",)) for i in range(2)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertCountEqual(seen, ["COMMITTED", "REVISION_CONFLICT"])
        self.assertEqual(s.snapshot()["revision"], 2)

    def test_strict_monotonic_time_and_sequence(self):
        clock = iter([datetime(2026, 10, 22, tzinfo=timezone.utc),
                      datetime(2026, 10, 21, tzinfo=timezone.utc)])
        s = lc.Lifecycle.create(context(), "create-run-0001", clock=lambda: next(clock))
        p = s.snapshot()
        assert_code(self, "CLOCK_ROLLBACK", lambda: step_run(s, "READY", "run-ready-0001"))
        self.assertEqual(s.snapshot(), p)

    def test_serialization_is_canonical_and_immutable_copy(self):
        s = new_session()
        original = s.snapshot()
        tampered = s.snapshot()
        tampered["run"]["state"] = "COMPLETED"
        self.assertEqual(s.snapshot(), original)
        encoded = s.checkpoint_json()
        self.assertEqual(encoded, lc._canonical(original))
        inspected = lc.inspect_checkpoint(encoded)
        self.assertEqual(inspected["reason_code"], "RECOVERY_NOT_ATTESTED")
        self.assertFalse(inspected["resume_allowed"])
        self.assertIsNone(inspected["run_id"])

    def test_untrusted_snapshot_not_resumable(self):
        self.assertFalse(hasattr(lc.Lifecycle, "load"))
        self.assertFalse(hasattr(lc.Lifecycle, "resume"))
        s = new_session()
        self.assertEqual(lc.inspect_checkpoint(s.checkpoint_json())["status"], "unavailable")

    def test_event_hash_tamper_rejected_even_if_projection_looks_plausible(self):
        p = new_session().snapshot()
        p["events"][0]["to_state"] = "COMPLETED"
        assert_code(self, "EVENT_CHAIN_INVALID", lambda: lc.inspect_checkpoint(lc._canonical(p)))

    def test_rehashed_self_consistent_claim_still_untrusted(self):
        s = new_session()
        ready_active(s)
        add_handoff(s)
        step_handoff(s, "READY", "handoff-ready-0001")
        step_handoff(s, "ACTIVE", "handoff-active-0001")
        step_handoff(s, "COMPLETED", "handoff-done-0001", result_sha256="e" * 64)
        step_run(s, "COMPLETED", "run-done-0001", result_sha256="f" * 64)
        status = lc.inspect_checkpoint(s.checkpoint_json())
        self.assertEqual(status["structural_consistency"], "PASS_UNAUTHENTICATED")
        self.assertFalse(status["prior_success_authenticated"])
        self.assertIsNone(status["run_id"])

    def test_skipped_event_and_projection_forgery_rejected(self):
        p = new_session().snapshot()
        p["revision"] = 42
        assert_code(self, "CHECKPOINT_DRIFT", lambda: lc.inspect_checkpoint(lc._canonical(p)))

    def test_malformed_json_event_type_fail_closed(self):
        p = new_session().snapshot()
        p["events"][0]["kind"] = []
        assert_code(self, "EVENT_CHAIN_INVALID", lambda: lc.inspect_checkpoint(lc._canonical(p)))
        p = new_session().snapshot()
        p["source"]["source_mode"] = []
        assert_code(self, "CHECKPOINT_SOURCE_INVALID", lambda: lc.inspect_checkpoint(lc._canonical(p)))

    def test_duplicate_json_keys_rejected(self):
        raw = b'{"schema":1,"schema":2}'
        assert_code(self, "INPUT_JSON_INVALID", lambda: lc.inspect_checkpoint(raw))
        assert_code(self, "INPUT_JSON_INVALID", lambda: lc.inspect_checkpoint(b'{"SCHEMA":1,"schema":2}'))

    def test_bom_nonfinite_and_limit_rejected(self):
        assert_code(self, "INPUT_BOM_FORBIDDEN", lambda: lc.inspect_checkpoint(b'\xef\xbb\xbf{}'))
        assert_code(self, "INPUT_JSON_INVALID", lambda: lc.inspect_checkpoint(b'{"x":NaN}'))
        assert_code(self, "INPUT_JSON_INVALID", lambda: lc.inspect_checkpoint(b'{"x":1e10000}'))
        assert_code(self, "INPUT_SIZE_INVALID", lambda: lc.inspect_checkpoint(b' ' * (lc.MAX_CHECKPOINT_BYTES + 1)))

    def test_event_cap_fails_closed_without_history_pruning(self):
        s = new_session()
        ready_active(s)
        # Synthetic limit override is only an in-process test; no external I/O.
        with patch.object(lc, "MAX_EVENTS", 3):
            p = s.snapshot()
            assert_code(self, "EVENT_LIMIT", lambda: add_handoff(s))
            self.assertEqual(s.snapshot(), p)

    def test_checkpoint_bytes_are_bounded(self):
        s = new_session()
        p = s.snapshot()
        with patch.object(lc, "MAX_CHECKPOINT_BYTES", 100):
            before = len(s._events)
            assert_code(self, "CHECKPOINT_SIZE_LIMIT", lambda: s.advance_run(
                "READY", expected_revision=p["revision"],
                context_sha256=p["source"]["context_sha256"], operation_key="run-ready-0001"))
            self.assertEqual(len(s._events), before)

    def test_invalid_operation_and_result_are_rejected(self):
        s = new_session()
        p = s.snapshot()
        assert_code(self, "OPERATION_KEY_INVALID", lambda: s.advance_run(
            "READY", expected_revision=1, context_sha256=p["source"]["context_sha256"],
            operation_key="x"))
        assert_code(self, "PARTIAL_CONTEXT_ACK_REQUIRED", lambda: step_run(
            s, "READY", "run-ready-0001", acknowledge_partial=True))

    def test_no_file_side_effects_in_lifecycle(self):
        with tempfile.TemporaryDirectory() as d:
            before = set(Path(d).iterdir())
            s = new_session()
            ready_active(s)
            add_handoff(s)
            self.assertEqual(before, set(Path(d).iterdir()))
            self.assertFalse(s.snapshot()["authority"]["writes_performed"])


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        cmd = [sys.executable, str(Path(lc.__file__).resolve()), *args]
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=8)
        return p.returncode, json.loads(p.stdout)

    def test_preview_create_and_inspect(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp = root / "context.json"
            inp.write_bytes(lc._canonical(context()))
            rc, preview = self.run_cli("--preview", str(inp))
            self.assertEqual(rc, 0)
            self.assertIsNone(preview["run_id"])
            rc, created = self.run_cli("--create-run", str(inp), "--operation-key", "cli-created-0001")
            self.assertEqual(rc, 0)
            self.assertRegex(created["snapshot"]["run"]["run_id"], r"^run_v1_[0-9a-f]{48}$")
            self.assertFalse(created["persisted"])
            cp = root / "checkpoint.json"
            cp.write_bytes(lc._canonical(created["snapshot"]))
            rc, check = self.run_cli("--inspect-checkpoint", str(cp))
            self.assertEqual(rc, 5)
            self.assertFalse(check["resume_allowed"])
            self.assertIsNone(check["run_id"])

    def test_cli_no_opkey_cannot_generate_id(self):
        with tempfile.TemporaryDirectory() as d:
            inp = Path(d) / "context.json"
            inp.write_bytes(lc._canonical(context()))
            rc, error = self.run_cli("--create-run", str(inp))
            self.assertEqual(rc, 4)
            self.assertEqual(error["reason_code"], "OPERATION_KEY_REQUIRED")
            self.assertIsNone(error["run_id"])

    def test_cli_rejects_symlink_input(self):
        with tempfile.TemporaryDirectory() as d:
            inp = Path(d) / "context.json"
            inp.write_bytes(lc._canonical(context()))
            link = Path(d) / "link.json"
            try:
                link.symlink_to(inp)
            except OSError:
                self.skipTest("symlinks unavailable")
            rc, error = self.run_cli("--preview", str(link))
            self.assertEqual(rc, 5)
            self.assertEqual(error["reason_code"], "INPUT_FILE_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
