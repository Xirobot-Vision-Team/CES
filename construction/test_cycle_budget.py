#!/usr/bin/env python3
"""EC234 focused local development: genuine EC231 private record/EC233 routes.

All repositories, actors and evidence payloads are synthetic. These tests do
not claim native PowerShell, OS watchdog, external runner, or enterprise proof.
"""
from __future__ import annotations

import concurrent.futures
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

try:
    from . import cycle_budget as bg
    from . import cycle_run_metadata as md
except ImportError:
    import cycle_budget as bg
    import cycle_run_metadata as md


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def task(i: int, action: str = "Inspect", mode: str | None = None,
         deps: list[str] | None = None) -> dict:
    return {"step_id": f"step_{i}", "action": action, "mode": mode,
            "depends_on": deps if deps is not None else []}


class CycleBudgetCases(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ec234_")
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "private"
        self.store = md.CycleMetadataStore(self.dir)
        self.snapshot = b"real synthetic snapshot for EC234\n"

    def create(self, actions=None, limits=None):
        return self.store.create(
            snapshot_bytes=self.snapshot, source_ref="git:ec234/synthetic",
            actor_origin="human", actor_subject="anonymous-tester",
            actions=actions if actions is not None else [task(1)],
            limits=limits)

    def guard(self, rec, **overrides):
        return bg.CycleBudgetGuard(self.dir, rec["run_id"],
                                   overrides=overrides or None)

    def read(self, result):
        self.assertEqual(result.payload[-1:], b"\n")
        self.assertEqual(result.payload.count(b"\n"), 1)
        data = json.loads(result.payload)
        self.assertEqual(data["schema"], bg.SCHEMA)
        self.assertEqual(set(data["effects"].values()), {False})
        self.assertEqual(set(data["trust"].values()), {False})
        self.assertGreaterEqual(data["usage"]["output_bytes"], len(result.payload))
        return data

    def test_actual_route_proposal_not_an_execution(self):
        rec = self.create()
        original = (self.dir / (rec["run_id"] + ".cycle.json")).read_bytes()
        got = self.guard(rec).inspect()
        data = self.read(got)
        self.assertEqual((got.status, got.exit_code), ("NO_EXECUTION_PROPOSAL", 0))
        self.assertEqual(data["next_proposal"]["next_step"]["handler"]["route_id"], "Inspect")
        self.assertEqual(data["next_proposal"]["next_kind"], "cli_action")
        self.assertEqual(data["remaining_step_ids"], ["step_1"])
        self.assertEqual(data["unperformed_count"], 1)
        self.assertEqual(data["usage"]["admitted_inspections"], 1)
        self.assertEqual(self.store.load(rec["run_id"])["budget"]["usage"]["steps"], 0)
        self.assertEqual((self.dir / (rec["run_id"] + ".cycle.json")).read_bytes(), original)

    def test_stops_before_second_inspection_when_step_quota_spent(self):
        rec = self.create([task(1), task(2)])
        ctrl = self.guard(rec, max_step_inspections=1)
        first = self.read(ctrl.inspect())
        self.assertEqual(first["next_proposal"]["next_step"]["step_id"], "step_1")
        second = self.read(ctrl.inspect())
        self.assertEqual(second["status"], "STOPPED_BUDGET")
        self.assertEqual(second["reason_code"], "CYCLE_BUDGET_STEP_INSPECTION_LIMIT")
        self.assertEqual(second["usage"]["admitted_inspections"], 1)
        self.assertIsNone(second["next_proposal"])
        self.assertEqual(second["remaining_step_ids"], ["step_1", "step_2"])

    def test_rate_cap_triggers_without_more_next_calls(self):
        rec = self.create([task(i) for i in range(1, 6)])
        ctrl = self.guard(rec, rate_max_calls=2, rate_window_ms=60_000)
        self.assertEqual(ctrl.inspect().status, "NO_EXECUTION_PROPOSAL")
        self.assertEqual(ctrl.inspect().status, "NO_EXECUTION_PROPOSAL")
        last = self.read(ctrl.inspect())
        self.assertEqual(last["reason_code"], "CYCLE_BUDGET_RATE_LIMIT")
        self.assertEqual(last["usage"]["rate_window_calls"], 2)
        self.assertEqual(last["usage"]["admitted_inspections"], 2)
        self.assertEqual(last["unperformed_count"], 5)

    def test_rate_window_age_expires_old_calls(self):
        rec = self.create([task(i) for i in range(1, 5)])
        ctrl = self.guard(rec, rate_max_calls=1, rate_window_ms=1)
        ctrl.window.append(ctrl.start_wall_ns - 2_000_000)
        data = self.read(ctrl.inspect())
        self.assertEqual(data["status"], "NO_EXECUTION_PROPOSAL")
        self.assertEqual(data["usage"]["rate_window_calls"], 1)

    def test_output_bytes_are_exact_and_cumulative(self):
        rec = self.create([task(1), task(2)])
        ctrl = self.guard(rec)
        one = ctrl.inspect()
        two = ctrl.inspect()
        a, b = json.loads(one.payload), json.loads(two.payload)
        self.assertEqual(a["usage"]["output_bytes"], len(one.payload))
        self.assertEqual(b["usage"]["output_bytes"], len(one.payload) + len(two.payload))
        self.assertEqual(b["usage"]["material_bytes"],
                         len(self.snapshot) + len(one.payload) + len(two.payload))
        self.assertEqual(a["next_proposal"]["next_step"]["step_id"], "step_1")
        self.assertEqual(b["next_proposal"]["next_step"]["step_id"], "step_1")

    def test_unrepresentably_small_output_must_emit_nothing(self):
        rec = self.create()
        ctrl = self.guard(rec, output_bytes=1)
        result = ctrl.inspect()
        self.assertEqual(result.status, "STOPPED_BUDGET")
        self.assertEqual(result.payload, b"")
        self.assertEqual(ctrl.output_bytes, 0)
        self.assertEqual(ctrl.inspections, 1)  # already inspected but NOT executed

    def test_output_limit_blocks_large_proposal_and_stays_closed(self):
        rec = self.create([task(i) for i in range(1, 10)])
        ctrl = self.guard(rec, output_bytes=1600)
        result = ctrl.inspect()
        self.assertEqual(result.status, "STOPPED_BUDGET")
        self.assertIsNone(result.parsed() if not result.payload else result.parsed()["next_proposal"])
        self.assertLessEqual(len(result.payload), 1600)
        self.assertEqual(ctrl.closed_reason, "CYCLE_BUDGET_OUTPUT_OR_MATERIAL_LIMIT")

    def test_diagnostics_measured_bytes_not_authority_and_not_echoed(self):
        rec = self.create()
        ctrl = self.guard(rec)
        secret = b"private_ec234_diagnostic_do_not_echo"
        result = ctrl.inspect(diagnostic_bytes=secret)
        self.assertNotIn(secret, result.payload)
        data = self.read(result)
        self.assertEqual(data["usage"]["evidence_bytes"], len(secret))
        self.assertEqual(data["usage"]["material_bytes"],
                         len(self.snapshot) + len(secret) + len(result.payload))

    def test_evidence_limit_fails_before_call_and_never_reflects_secret(self):
        rec = self.create()
        ctrl = self.guard(rec, evidence_bytes=1)
        secret = b"SENSITIVE_EVIDENCE" * 200
        got = ctrl.inspect(diagnostic_bytes=secret)
        self.assertEqual(got.status, "STOPPED_BUDGET")
        self.assertEqual(got.reason_code, "CYCLE_BUDGET_EVIDENCE_LIMIT")
        self.assertEqual(ctrl.inspections, 0)
        self.assertEqual(ctrl.evidence_bytes, 0)
        self.assertNotIn(secret, got.payload)

    def test_material_budget_fails_before_next(self):
        rec = self.create()
        ctrl = self.guard(rec, material_bytes=len(self.snapshot))
        got = ctrl.inspect(diagnostic_bytes=b"x")
        self.assertEqual(got.status, "STOPPED_BUDGET")
        self.assertEqual(got.reason_code, "CYCLE_BUDGET_MATERIAL_LIMIT")
        self.assertEqual(ctrl.inspections, 0)

    def test_wall_deadline_blocks_without_next_call(self):
        rec = self.create()
        ctrl = self.guard(rec, wall_ms=1)
        ctrl.start_wall_ns -= 10_000_000
        got = ctrl.inspect()
        self.assertEqual(got.status, "STOPPED_BUDGET")
        self.assertEqual(got.reason_code, "CYCLE_BUDGET_WALL_TIME_LIMIT")
        self.assertEqual(ctrl.inspections, 0)

    def test_cpu_deadline_blocks_without_next_call(self):
        rec = self.create()
        ctrl = self.guard(rec, cpu_ms=1)
        ctrl.start_cpu_ns -= 10_000_000
        got = ctrl.inspect()
        self.assertEqual(got.status, "STOPPED_BUDGET")
        self.assertEqual(got.reason_code, "CYCLE_BUDGET_CPU_LIMIT")
        self.assertEqual(ctrl.inspections, 0)

    def test_post_inspection_elapsed_timeout_drops_next(self):
        rec = self.create()
        ctrl = self.guard(rec, wall_ms=50)
        native = ctrl.next_handler.next

        def slow(*args, **kwargs):
            ctrl.start_wall_ns -= 100_000_000
            return native(*args, **kwargs)

        with mock.patch.object(ctrl.next_handler, "next", side_effect=slow):
            got = ctrl.inspect()
        self.assertEqual(got.status, "STOPPED_BUDGET")
        self.assertIsNone(got.parsed() if not got.payload else got.parsed()["next_proposal"])
        self.assertEqual(got.reason_code, "CYCLE_BUDGET_WALL_TIME_LIMIT")

    def test_saved_record_drift_fails_closed(self):
        rec = self.create()
        ctrl = self.guard(rec)
        path = self.dir / (rec["run_id"] + ".cycle.json")
        tampered = copy.deepcopy(rec)
        tampered["input"]["source_ref"] = "git:another/source"
        tampered["record_sha256"] = md.digest(md.DOMAIN_RECORD, md._without_digest(tampered))
        path.write_bytes(md.canonical(tampered))
        got = ctrl.inspect()
        self.assertEqual((got.status, got.reason_code),
                         ("UNKNOWN_BLOCKED", "CYCLE_BUDGET_RECORD_DRIFT"))
        data = self.read(got)
        self.assertFalse(data["remaining_known"])
        self.assertIsNone(data["unperformed_count"])
        self.assertIsNone(data["next_proposal"])

    def test_record_drift_during_next_rejects_stale_proposal(self):
        rec = self.create()
        ctrl = self.guard(rec)
        path = self.dir / (rec["run_id"] + ".cycle.json")
        def rewrite_then_next(*args, **kwargs):
            other = copy.deepcopy(rec)
            other["input"]["source_ref"] = "git:modified/source"
            other["record_sha256"] = md.digest(md.DOMAIN_RECORD, md._without_digest(other))
            path.write_bytes(md.canonical(other))
            return {"run_id": rec["run_id"], "status": bg.nxt.UNKNOWN}
        with mock.patch.object(ctrl.next_handler, "next", side_effect=rewrite_then_next):
            got = ctrl.inspect()
        self.assertEqual(got.status, "UNKNOWN_BLOCKED")
        self.assertEqual(got.reason_code, "CYCLE_BUDGET_RECORD_DRIFT")

    def test_corrupt_saved_metadata_is_unavailable_not_scheduled(self):
        rec = self.create()
        path = self.dir / (rec["run_id"] + ".cycle.json")
        path.write_bytes(b"invalid")
        with self.assertRaises(md.CycleMetadataError):
            self.guard(rec)

    def test_bad_external_pins_fail_before_start(self):
        rec = self.create()
        with self.assertRaisesRegex(bg.CycleBudgetError, "PIN_MISMATCH"):
            bg.CycleBudgetGuard(self.dir, rec["run_id"], expected_record_sha256="0" * 64)
        with self.assertRaisesRegex(bg.CycleBudgetError, "PIN_MISMATCH"):
            bg.CycleBudgetGuard(self.dir, rec["run_id"], expected_action_set_sha256="0" * 64)
        with self.assertRaisesRegex(bg.CycleBudgetError, "PIN_MISMATCH"):
            bg.CycleBudgetGuard(self.dir, rec["run_id"], expected_input_sha256="0" * 64)

    def test_no_operator_override_may_expand_ec231_limits(self):
        rec = self.create()
        for override in ({"output_bytes": 9_000_000}, {"evidence_bytes": 9_000_000},
                         {"wall_ms": 86_400_001}, {"max_step_inspections": 2},
                         {"rate_max_calls": 999}, {"unknown": 1},
                         {"cpu_ms": True}, {"output_bytes": -1},
                         {"material_bytes": 999_999_999}):
            with self.subTest(override=override):
                with self.assertRaises(bg.CycleBudgetError):
                    bg.CycleBudgetGuard(self.dir, rec["run_id"], overrides=override)

    def test_write_route_never_grants_code_save(self):
        rec = self.create([task(1, "CodeSave", "Snapshot")])
        got = self.guard(rec).inspect()
        data = self.read(got)
        self.assertEqual(got.status, "AWAIT_OPERATOR_ONLY")
        self.assertEqual(got.exit_code, 2)
        self.assertEqual(data["next_proposal"]["next_kind"], "await_permission")
        self.assertFalse(data["effects"]["write_authorized"])
        self.assertEqual(data["remaining_step_ids"], ["step_1"])

    def test_ai_route_never_invokes_router(self):
        rec = self.create([task(1, "AIHandoff", "CodeAnalysis")])
        got = self.guard(rec).inspect()
        data = self.read(got)
        self.assertEqual(got.status, "AWAIT_OPERATOR_ONLY")
        self.assertEqual(data["next_proposal"]["next_kind"], "ai_handoff")
        self.assertFalse(data["effects"]["handler_invoked"])

    def test_cyclic_and_unsupported_roots_do_not_advance(self):
        for actions in ([task(1, deps=["step_2"]), task(2, deps=["step_1"])],
                        [task(1, action="Unimplemented"), task(2)]):
            with self.subTest(actions=actions):
                rec = self.create(actions)
                out = self.read(self.guard(rec).inspect())
                self.assertEqual(out["status"], "NO_EXECUTION_BLOCKED")
                self.assertEqual(out["unperformed_count"], 2)
                self.assertIsNone(out["next_proposal"])

    def test_thread_shares_one_real_step_counter(self):
        rec = self.create([task(i) for i in range(1, 5)])
        ctrl = self.guard(rec, max_step_inspections=1)
        gate = threading.Barrier(4)
        def call(_):
            gate.wait()
            return ctrl.inspect().status
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(call, range(4)))
        self.assertEqual(outcomes.count("NO_EXECUTION_PROPOSAL"), 1)
        self.assertEqual(outcomes.count("STOPPED_BUDGET"), 3)
        self.assertEqual(ctrl.inspections, 1)
        self.assertEqual(ctrl.attempts, 4)

    def test_cli_emits_exact_metered_line_and_exit_status(self):
        rec = self.create()
        proc = subprocess.run([sys.executable, str(HERE / "cycle_budget.py"), "inspect",
                               "--store", str(self.dir), "--run-id", rec["run_id"]],
                              capture_output=True, timeout=12)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertEqual(proc.stdout.count(b"\n"), 1)
        data = json.loads(proc.stdout)
        self.assertEqual(data["usage"]["output_bytes"], len(proc.stdout))
        self.assertEqual(data["remaining_step_ids"], ["step_1"])

    @unittest.skipUnless(Draft202012Validator is not None, "jsonschema not provisioned")
    def test_embedded_ec233_strict_schema_and_negative_escalation(self):
        schema = json.loads((ROOT / "references/cycle-budget-result.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        cases = [
            self.guard(self.create()).inspect(),
            self.guard(self.create([task(1, "CodeSave", "Snapshot")])).inspect(),
            self.guard(self.create([task(1, "AIHandoff", "CodeAnalysis")])).inspect(),
            self.guard(self.create([task(1, "Unimplemented")])).inspect(),
        ]
        stopped = self.guard(self.create([task(1), task(2)]), max_step_inspections=1)
        stopped.inspect()
        cases.append(stopped.inspect())
        for result in cases:
            with self.subTest(status=result.status):
                data = result.parsed()
                self.assertIsNotNone(data)
                self.assertEqual(list(validator.iter_errors(data)), [])
        original = cases[0].parsed()
        for change in (
                lambda d: d["effects"].__setitem__("steps_executed", True),
                lambda d: d["trust"].__setitem__("global_rate_enforced", True),
                lambda d: d["next_proposal"]["effects"].__setitem__("handler_invoked", True),
                lambda d: d.__setitem__("unexpected_route", "write"),
                lambda d: d.__setitem__("remaining_step_ids", []),
                lambda d: d.__setitem__("next_proposal", None),
        ):
            falsified = copy.deepcopy(original)
            change(falsified)
            self.assertFalse(validator.is_valid(falsified))

    def test_fake_authoritative_next_is_rejected_without_leaking_elevated_result(self):
        rec = self.create()
        ctrl = self.guard(rec)
        prior = ctrl.next_handler.next(rec["run_id"])
        prior["effects"]["handler_invoked"] = True
        with mock.patch.object(ctrl.next_handler, "next", return_value=prior):
            result = ctrl.inspect()
        self.assertEqual(result.status, "UNKNOWN_BLOCKED")
        self.assertIsNone(result.parsed()["next_proposal"])

    def test_same_session_missing_prior_delivery_stays_unknown(self):
        rec = self.create()
        ctrl = self.guard(rec)
        missing = self.dir / (rec["run_id"] + ".cycle.json")
        missing.unlink()
        msg = ctrl.inspect()
        self.assertEqual(msg.status, "UNKNOWN_BLOCKED")
        self.assertFalse(msg.parsed()["remaining_known"])

    def test_cli_absent_run_no_fabricated_quota_or_worklist(self):
        proc = subprocess.run([sys.executable, str(HERE / "cycle_budget.py"), "inspect",
                               "--store", str(self.dir), "--run-id", "run_v1_" + "0" * 48],
                              capture_output=True, timeout=12)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"CYCLE_STORE", proc.stderr)


if __name__ == "__main__":
    unittest.main()
