#!/usr/bin/env python3
"""EC233 focused functional checks against real saved EC231 records.

These test handler selection, evidence binding, and denial transitions; they
DO NOT execute native PowerShell, external AI, enterprise permissions, or an
EC234+ executor. Uses disposable local POSIX 0700/0600 metadata only.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import cycle_next as nxt
import cycle_run_metadata as md

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_FILE = ROOT / "references/cycle-next-result.v1.schema.json"


def task(name: str, action: str = "Inspect", mode: str | None = None,
         *dependencies: str) -> dict:
    return {"step_id": "step_" + name, "action": action, "mode": mode,
            "depends_on": ["step_" + x for x in dependencies]}


@unittest.skipUnless(os.name == "posix", "EC231 private metadata store requires POSIX")
class CycleNextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ec233-next-")
        self.addCleanup(self.tmp.cleanup)
        self.private = Path(self.tmp.name) / "runs"
        self.store = md.CycleMetadataStore(self.private)
        self.service = nxt.CycleNextHandler(self.private)
        self.input_bytes = b"ec233 exact snapshot from one caller\x00\n"

    def create(self, actions=None) -> dict:
        return self.store.create(snapshot_bytes=self.input_bytes,
                                 source_ref="git:dev/snapshot",
                                 actor_origin="human", actor_subject="declared-operator",
                                 actions=actions if actions is not None else [task("one")])

    def next(self, rec: dict, **pins) -> dict:
        return self.service.next(rec["run_id"], **pins)

    def path(self, rec: dict) -> Path:
        return self.private / (rec["run_id"] + ".cycle.json")

    def rewrite(self, rec: dict) -> dict:
        rec["record_sha256"] = md.digest(md.DOMAIN_RECORD, md._without_digest(rec))
        self.path(rec).write_bytes(md.canonical(rec))
        return rec

    def assert_safe(self, output: dict) -> None:
        self.assertEqual(set(output["effects"].values()), {False})
        self.assertEqual(output["trust"]["metadata_integrity"], "UNSIGNED_LOCAL_SELF_HASH_ONLY")
        self.assertFalse(any(v for k, v in output["trust"].items() if k != "metadata_integrity"))

    def test_source_backed_inspect_default_single_root(self):
        rec = self.create()
        original = self.path(rec).read_bytes()
        out = self.next(rec)
        self.assertEqual((out["status"], out["next_kind"], out["reason_code"]),
                         (nxt.PROPOSED, "cli_action", "CYCLE_NEXT_READ_ONLY_HANDLER_PROPOSED"))
        step = out["next_step"]
        self.assertEqual((step["step_id"], step["action"], step["effective_mode"]),
                         ("step_one", "Inspect", None))
        self.assertEqual(step["handler"]["handler_file"], "scripts/ces.ps1")
        self.assertEqual(step["handler"]["handler_symbol"], "Inspect-Repository")
        self.assertEqual(step["handler"]["entrypoint"], "scripts/ces.ps1")
        self.assertEqual(out["ready_root_step_ids"], ["step_one"])
        self.assertEqual(out["unproven_step_ids"], ["step_one"])
        self.assertEqual(out["blocked_by_step_ids"], [])
        self.assertEqual(self.path(rec).read_bytes(), original)
        self.assertEqual(self.store.load(rec["run_id"])["run_state"], "NOT_STARTED")
        self.assert_safe(out)

    def test_original_dependency_barrier_never_promotes_downstream(self):
        rec = self.create([task("first", "CodePrepare", "Snapshot"),
                           task("second", "CodeValidate", "Snapshot", "first"),
                           task("third", "CodeShow", "Findings", "second")])
        out = self.next(rec)
        self.assertEqual(out["next_step"]["step_id"], "step_first")
        self.assertEqual(out["next_step"]["handler"]["route_id"], "CodePrepare:Snapshot")
        self.assertEqual(out["ready_root_step_ids"], ["step_first"])
        self.assertEqual(out["blocked_by_step_ids"], ["step_second", "step_third"])
        self.assert_safe(out)

    def test_multiple_roots_return_first_declared_only(self):
        rec = self.create([task("b", "Collect"), task("a", "Inspect"),
                           task("c", "CodeShow", "Detail", "a")])
        out = self.next(rec)
        self.assertEqual(out["ready_root_step_ids"], ["step_b", "step_a"])
        self.assertEqual(out["next_step"]["step_id"], "step_b")
        self.assertEqual(out["blocked_by_step_ids"], ["step_c"])
        self.assertEqual(out["next_step"]["handler"]["route_id"], "Collect:WorkingTree")

    def test_native_snapshot_default_resolves_actual_route(self):
        for act in ("Reconcile", "CodePrepare", "CodeValidate"):
            with self.subTest(act=act):
                out = self.next(self.create([task("a", act)]))
                self.assertEqual(out["next_kind"], "cli_action")
                self.assertEqual(out["next_step"]["effective_mode"], "Snapshot")
                self.assertEqual(out["next_step"]["handler"]["route_id"], act + ":Snapshot")

    def test_collect_modes_canonical_case_insensitive_without_execution(self):
        for act, mode, expected in (("COLLECT", None, "Collect:WorkingTree"),
                                    ("Collect", "DeliveredTarget", "Collect:DeliveredTarget")):
            with self.subTest(mode=mode):
                out = self.next(self.create([task("a", act, mode)]))
                self.assertEqual(out["next_step"]["handler"]["route_id"], expected)
                self.assertEqual(out["next_step"]["action"], "Collect")
                self.assert_safe(out)

    def test_code_show_submode_anchors_real_source(self):
        for mode in ("Findings", "Sequence", "Detail"):
            with self.subTest(mode=mode):
                out = self.next(self.create([task("s", "CodeShow", mode)]))
                self.assertEqual(out["next_step"]["handler"]["route_id"], "CodeShow:" + mode)
                self.assertEqual(out["next_step"]["handler"]["handler_file"], "scripts/codeshow.ps1")

    def test_inspect_ignores_explicit_mode_like_native_dispatch(self):
        out = self.next(self.create([task("a", "Inspect", "Nonexistent")]))
        self.assertEqual(out["next_kind"], "cli_action")
        self.assertIsNone(out["next_step"]["effective_mode"])
        self.assertEqual(out["next_step"]["declared_mode"], "Nonexistent")

    def test_code_show_without_explicit_mode_is_blocked(self):
        out = self.next(self.create([task("a", "CodeShow")]))
        self.assertEqual((out["status"], out["next_kind"]), (nxt.BLOCKED, "none"))
        self.assertEqual(out["reason_code"], "CYCLE_NEXT_ACTION_OR_MODE_UNREGISTERED")
        self.assertIsNone(out["next_step"])

    def test_invalid_snapshot_mode_not_routed_to_default(self):
        out = self.next(self.create([task("a", "CodePrepare", "WorkingTree")]))
        self.assertEqual(out["status"], nxt.BLOCKED)
        self.assertEqual(out["ready_root_step_ids"], ["step_a"])
        self.assertIsNone(out["next_step"])

    def test_code_save_explicit_permission_required(self):
        out = self.next(self.create([task("write", "CodeSave", "Snapshot")]))
        self.assertEqual((out["next_kind"], out["status"]), ("await_permission", nxt.OPERATOR))
        self.assertEqual(out["reason_code"], "CYCLE_NEXT_PERSIST_PERMISSION_REQUIRED")
        self.assertIn("ApprovePersist (explicit native switch)",
                      out["next_step"]["handler"]["operator_parameters_required"])
        self.assertFalse(out["next_step"]["handler"]["read_only"])
        self.assert_safe(out)

    def test_ai_handoff_points_to_real_ec174_input_specific_route(self):
        rec = self.create([task("ai", "AIHandoff", "CodeAnalysis")])
        out = self.next(rec)
        self.assertEqual((out["status"], out["next_kind"]), (nxt.OPERATOR, "ai_handoff"))
        binding = out["next_step"]["handler"]
        self.assertEqual(binding["route_id"], "ces.route.code_analysis.v1")
        self.assertEqual(binding["handler_file"], "construction/ai_handoff_router.py")
        self.assertEqual(binding["handler_symbol"], "HandoffRouter.route")
        self.assertIn("EC173_AUTHORIZED_PREPARED_INPUT", binding["operator_parameters_required"])
        self.assert_safe(out)

    def test_ai_handoff_unimplemented_task_kind_blocked(self):
        for mode in (None, "ReportWriting", "Unknown"):
            with self.subTest(mode=mode):
                out = self.next(self.create([task("ai", "AIHandoff", mode)]))
                self.assertEqual(out["status"], nxt.BLOCKED)
                self.assertEqual(out["reason_code"], "CYCLE_NEXT_AI_ROUTE_UNREGISTERED")
                self.assertIsNone(out["next_step"])

    def test_named_but_unimplemented_actions_cannot_be_next(self):
        for action in ("QualityRun", "ReportPrepare", "IssueCreate", "DocsOnlyPublish", "Cycle", "Resume"):
            with self.subTest(action=action):
                out = self.next(self.create([task("a", action)]))
                self.assertEqual((out["status"], out["next_kind"]), (nxt.BLOCKED, "none"))
                self.assertEqual(out["reason_code"], "CYCLE_NEXT_ACTION_OR_MODE_UNREGISTERED")
                self.assert_safe(out)

    def test_unsupported_first_root_cannot_be_silently_skipped(self):
        rec = self.create([task("bad", "QualityRun"), task("good", "Inspect")])
        out = self.next(rec)
        self.assertEqual(out["ready_root_step_ids"], ["step_bad", "step_good"])
        self.assertEqual(out["blocked_by_step_ids"], ["step_bad"])
        self.assertEqual(out["next_kind"], "none")

    def test_cycle_is_blocked_without_partial_next(self):
        rec = self.create([task("one", "Inspect", None, "two"),
                           task("two", "Collect", None, "one"), task("free")])
        out = self.next(rec)
        self.assertEqual((out["status"], out["reason_code"]),
                         (nxt.BLOCKED, "CYCLE_NEXT_DAG_CYCLE_BLOCKED"))
        self.assertIsNone(out["next_step"])
        self.assertEqual(out["ready_root_step_ids"], [])
        self.assertIsNone(out["record_sha256"])
        self.assert_safe(out)

    def test_missing_run_id_unknown_not_completed(self):
        rec = self.create()
        self.path(rec).unlink()
        out = self.next(rec)
        self.assertEqual(out["status"], nxt.UNKNOWN)
        self.assertIsNone(out["record_sha256"])
        self.assertIsNone(out["next_step"])
        self.assert_safe(out)

    def test_corrupt_record_unknown_not_routable(self):
        rec = self.create()
        self.path(rec).write_bytes(b"{not json}")
        out = self.next(rec)
        self.assertEqual(out["status"], nxt.UNKNOWN)
        self.assertEqual(out["next_kind"], "none")

    def test_all_three_external_pins_bind_dag_and_refuse_mismatch(self):
        rec = self.create()
        good = self.next(rec, expected_record_sha256=rec["record_sha256"],
                         expected_action_set_sha256=rec["action_set_sha256"],
                         expected_input_sha256=hashlib.sha256(self.input_bytes).hexdigest())
        self.assertEqual(good["next_kind"], "cli_action")
        for name in ("expected_record_sha256", "expected_action_set_sha256", "expected_input_sha256"):
            with self.subTest(name=name):
                out = self.next(rec, **{name: "0"*64})
                self.assertEqual(out["status"], nxt.UNKNOWN)
                self.assertIsNone(out["next_step"])
                self.assertIsNone(out["graph_sha256"])

    def test_modified_and_self_rehashed_record_rejected_by_external_pin(self):
        rec = self.create()
        original = rec["record_sha256"]
        altered = copy.deepcopy(rec)
        altered["input"]["source_ref"] = "git:other"
        self.rewrite(altered)
        self.assertEqual(self.next(rec, expected_record_sha256=original)["status"], nxt.UNKNOWN)
        # Unsigned self-hash without an external pin alone cannot detect a
        # hostile same-UID rewrite: never advertise authenticity.
        unpinned = self.next(rec)
        self.assertEqual(unpinned["status"], nxt.PROPOSED)
        self.assertFalse(unpinned["trust"]["source_authenticated"])

    def test_declared_partial_is_not_success_or_dependency_completion(self):
        rec = self.create([task("first"), task("second", "Inspect", None, "first")])
        mod = copy.deepcopy(rec)
        mod["steps"][0].update(state="DECLARED_PARTIAL", observed_at_utc=rec["created_at_utc"],
                               handoff_id=None, evidence_sha256="a"*64,
                               reason_code="CALLER_DECLARED_UNVERIFIED")
        mod["run_state"] = "PARTIAL"
        self.rewrite(mod)
        out = self.next(rec)
        self.assertEqual((out["status"], out["reason_code"]),
                         (nxt.BLOCKED, "CYCLE_NEXT_UNPROVEN_STEP_STATE"))
        self.assertEqual(out["blocked_by_step_ids"], ["step_first"])
        self.assertIsNone(out["next_step"])
        self.assertEqual(out["metadata_run_state"], "PARTIAL")

    def test_unknown_state_does_not_skip_to_independent_root(self):
        rec = self.create([task("one"), task("two")])
        mod = copy.deepcopy(rec)
        mod["steps"][0].update(state="UNKNOWN", reason_code="UNTRUSTED_SOURCE")
        mod["run_state"] = "UNKNOWN"
        self.rewrite(mod)
        out = self.next(rec)
        self.assertEqual(out["status"], nxt.BLOCKED)
        self.assertEqual(out["blocked_by_step_ids"], ["step_one"])
        self.assertEqual(out["ready_root_step_ids"], [])

    def test_repeat_next_is_stable_not_durable_cursor_or_replay(self):
        rec = self.create([task("a", "Inspect"), task("b", "CodePrepare")])
        before = self.path(rec).read_bytes()
        first, second = self.next(rec), self.next(rec)
        self.assertEqual(first, second)
        self.assertEqual(self.path(rec).read_bytes(), before)
        self.assertEqual(first["next_step"]["step_id"], "step_a")
        self.assert_safe(second)

    def test_source_hash_bindings_match_actual_package_bytes(self):
        rec = self.create([task("a", "CodeValidate", "Snapshot")])
        step = self.next(rec)["next_step"]
        binding = step["handler"]
        self.assertEqual(binding["handler_sha256"], hashlib.sha256(
            (ROOT / binding["handler_file"]).read_bytes()).hexdigest())
        self.assertEqual(binding["entrypoint_sha256"], hashlib.sha256(
            (ROOT / binding["entrypoint"]).read_bytes()).hexdigest())
        self.assertFalse(binding["runtime_verified"])

    def test_missing_source_or_replaced_cli_blocks_route(self):
        rec = self.create()
        with mock.patch.object(nxt, "_cli_route", side_effect=nxt.CycleNextError(
                "CYCLE_NEXT_CLI_SOURCE_UNVERIFIED", "No source")):
            out = self.next(rec)
        self.assertEqual((out["status"], out["next_kind"]), (nxt.BLOCKED, "none"))
        self.assertIsNone(out["proposal_sha256"])

    def test_missing_ai_module_binding_blocks_proposal(self):
        rec = self.create([task("a", "AIHandoff", "CodeAnalysis")])
        with mock.patch.object(nxt.ai, "TASK_ROUTES", {"code_analysis": {"ec173_input_supported": False}}):
            out = self.next(rec)
        self.assertEqual(out["status"], nxt.BLOCKED)
        self.assertEqual(out["reason_code"], "CYCLE_NEXT_AI_HANDLER_UNAVAILABLE")

    def test_graph_to_record_race_drops_all_stale_evidence(self):
        rec = self.create()
        original = self.service.inspector.check
        def intercepted(*args, **kwargs):
            graph = original(*args, **kwargs)
            modified = copy.deepcopy(rec)
            modified["input"]["source_ref"] = "git:changed"
            self.rewrite(modified)
            return graph
        with mock.patch.object(self.service.inspector, "check", side_effect=intercepted):
            out = self.next(rec)
        self.assertEqual(out["status"], nxt.UNKNOWN)
        self.assertEqual(out["reason_code"], "CYCLE_NEXT_RECORD_CHANGED")
        self.assertIsNone(out["record_sha256"])
        self.assertIsNone(out["next_step"])

    def test_source_selection_to_final_reread_race_drops_candidate(self):
        rec = self.create()
        original = nxt._cli_route
        def intercepted(*args):
            decision, bind = original(*args)
            modified = copy.deepcopy(rec)
            modified["input"]["source_ref"] = "git:changed"
            self.rewrite(modified)
            return decision, bind
        with mock.patch.object(nxt, "_cli_route", side_effect=intercepted):
            out = self.next(rec)
        self.assertEqual(out["status"], nxt.UNKNOWN)
        self.assertIsNone(out["proposal_sha256"])

    def test_registry_or_handler_drift_fails_closed_real_package_copy(self):
        rec = self.create()
        target = Path(self.tmp.name) / "package"
        shutil.copytree(ROOT / "scripts", target / "scripts")
        (target / "references").mkdir()
        (target / "construction").mkdir()
        for relative in ("references/cli-action-mode-registry.json",
                         "construction/ACTION_TRACE.json",
                         "construction/CAPABILITY_MATRIX.json",
                         "construction/SOURCE_BASELINE.json",
                         "construction/LEGACY_SECURITY_DRIFT.json",
                         "construction/LEGACY_PATH_DRIFT.json"):
            src = ROOT / relative
            if src.exists():
                shutil.copy2(src, target / relative)
        (target / "scripts/ces.ps1").write_bytes(b"# fake dispatcher")
        out = nxt.CycleNextHandler(self.private, package_root=target).next(rec["run_id"])
        self.assertEqual(out["next_kind"], "none")
        self.assertEqual(out["status"], nxt.BLOCKED)
        self.assert_safe(out)

    def test_ai_source_not_from_same_package_rejected(self):
        rec = self.create([task("a", "AIHandoff", "CodeAnalysis")])
        pkg = Path(self.tmp.name) / "bad-package"
        (pkg / "construction").mkdir(parents=True)
        shutil.copy2(ROOT / "construction/ai_handoff_router.py", pkg / "construction/ai_handoff_router.py")
        out = nxt.CycleNextHandler(self.private, package_root=pkg).next(rec["run_id"])
        self.assertEqual((out["status"], out["next_kind"]), (nxt.BLOCKED, "none"))
        self.assertEqual(out["reason_code"], "CYCLE_NEXT_AI_HANDLER_UNAVAILABLE")

    def test_invalid_run_id_never_echoed_as_valid_route(self):
        for run_id in ("../../etc/passwd", "run_v1_" + "Z"*48, None, 44):
            with self.subTest(run_id=run_id):
                out = self.service.next(run_id)
                self.assertEqual(out["status"], nxt.UNKNOWN)
                self.assertIsNone(out["run_id"])
                self.assertIsNone(out["next_step"])

    @unittest.skipUnless(Draft202012Validator is not None, "jsonschema not provisioned")
    def test_machine_contract_accepts_all_four_kinds_rejects_escalation(self):
        schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        samples = [self.next(self.create([task("cli")])),
                   self.next(self.create([task("ai", "AIHandoff", "CodeAnalysis")])),
                   self.next(self.create([task("write", "CodeSave")])),
                   self.next(self.create([task("missing", "QualityRun")]))]
        missing_rec = self.create()
        self.path(missing_rec).unlink()
        samples.append(self.next(missing_rec))
        self.assertEqual([a["next_kind"] for a in samples],
                         ["cli_action", "ai_handoff", "await_permission", "none", "none"])
        for row in samples:
            with self.subTest(kind=row["next_kind"], status=row["status"]):
                validator.validate(row)
                forged = copy.deepcopy(row)
                forged["effects"]["handler_invoked"] = True
                self.assertFalse(validator.is_valid(forged))
                forged = copy.deepcopy(row)
                forged["trust"]["actor_verified"] = True
                self.assertFalse(validator.is_valid(forged))
                forged = copy.deepcopy(row)
                forged["unknown_field"] = "promote"
                self.assertFalse(validator.is_valid(forged))
                forged = copy.deepcopy(row)
                forged["next_kind"] = "cli_action" if row["next_kind"] != "cli_action" else "await_permission"
                self.assertFalse(validator.is_valid(forged), "Kind/status/handler cannot be forged")

    def test_cli_status_codes_are_proposal_only(self):
        for actions, expected in (([task("a")], 0),
                                  ([task("a", "AIHandoff", "CodeAnalysis")], 2),
                                  ([task("a", "CodeSave")], 2),
                                  ([task("a", "QualityRun")], 3),
                                  ([task("a", "Inspect", None, "b"),
                                    task("b", "Inspect", None, "a")], 3)):
            with self.subTest(expected=expected, actions=actions):
                rec = self.create(actions)
                p = subprocess.run([sys.executable, str(ROOT / "construction/cycle_next.py"),
                                    "next", "--store", str(self.private), "--run-id", rec["run_id"]],
                                   capture_output=True, text=True, check=False)
                self.assertEqual(p.returncode, expected, p.stderr)
                self.assertEqual(json.loads(p.stdout)["run_id"], rec["run_id"])
                self.assertEqual(json.loads(p.stdout)["effects"]["steps_executed"], False)
        absent = subprocess.run([sys.executable, str(ROOT / "construction/cycle_next.py"),
                                 "next", "--store", str(self.private),
                                 "--run-id", "run_v1_" + "1"*48],
                                capture_output=True, text=True, check=False)
        self.assertEqual(absent.returncode, 5)


if __name__ == "__main__":
    unittest.main()
