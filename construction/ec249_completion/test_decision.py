#!/usr/bin/env python3
"""Focused EC249 development tests; never a substitute for native/operator QA."""
import copy
import json
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory
import unittest

# Allow running as an isolated file with python3 -I -B.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from decision import ROOT, EvidenceError, _safe_rel, markdown, review


class FullFunctionReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current = review(ROOT)

    def test_existing_real_snapshot_is_blocked_and_not_accepted(self):
        result = self.current
        self.assertEqual(result["determination"], "FULL_FUNCTION_NOT_COMPLETE")
        self.assertFalse(result["can_claim_full_function_completion"])
        self.assertFalse(result["may_enter_final_acceptance"])
        self.assertFalse(result["may_freeze_ec250_candidate"])
        self.assertEqual(result["counts"]["authored_reported_rounds"], 99)
        self.assertEqual(result["counts"]["remaining_planned_rounds"], 1)
        self.assertEqual(len(result["per_round"]), 100)
        self.assertEqual(result["per_round"][-1]["reported_state"], "PLANNED")

    def test_real_route_and_source_risks_not_confused_with_authority(self):
        result = self.current
        self.assertEqual(result["counts"]["source_sha_local_matches"], 307)
        self.assertEqual(result["counts"]["host_required_denied_routes"], 11)
        self.assertEqual(result["counts"]["legacy_smoke_source_matches"], 15)
        self.assertEqual(int(result["counts"]["legacy_smoke_executed"]), 0)
        self.assertEqual(result["counts"]["rounds_without_explicit_artifact_index"], 22)
        self.assertEqual(result["counts"]["missing_declared_artifacts"], 0)
        self.assertEqual(result["integrity_issues"], [])
        self.assertTrue(all(not round_info["execution_or_external_acceptance_proven"] for round_info in result["per_round"]))
        self.assertEqual(len(result["host_required_routes"]), 11)

    def test_gaps_distinguish_implementation_and_external_evidence(self):
        types = {g["id"]: g["category"] for g in self.current["gaps"]}
        for k in ("G249-HOST", "G249-CYCLE", "G249-QUALITY", "G249-WRITES"):
            self.assertEqual(types[k], "IMPLEMENTATION")
        self.assertEqual(types["G249-NATIVE"], "VERIFICATION")
        self.assertEqual(types["G249-UPSTREAM"], "SOURCE_AUTHORITY")
        text = markdown(self.current)
        self.assertIn("不得认定全功能已完成", text)
        self.assertIn("EC250 保持 PLANNED", text)

    def test_unsafe_refs_are_rejected_not_followed(self):
        for ref in ("../other", "construction/../../outside", "/root/file", r"C:\\tmp\\x", "\x00"):
            with self.subTest(ref=ref), self.assertRaises(EvidenceError):
                _safe_rel(ref)

    def test_malformed_round_plan_blocks_decision(self):
        with TemporaryDirectory(prefix="ces_ec249_negative_") as td:
            copyroot = Path(td) / "ces"
            shutil.copytree(ROOT, copyroot, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            p = copyroot / "construction/LEGACY_PLAN.json"
            value = json.loads(p.read_text(encoding="utf-8"))
            value["rounds"][34]["round"] = 999
            p.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(EvidenceError):
                review(copyroot)

    def test_actual_source_byte_tamper_blocks_clean_readiness(self):
        with TemporaryDirectory(prefix="ces_ec249_source_") as td:
            copyroot = Path(td) / "ces"
            shutil.copytree(ROOT, copyroot, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            target = copyroot / "scripts/ces_router.py"
            with target.open("ab") as f:
                f.write(b"\n# intentional development-fixture modification\n")
            result = review(copyroot)
            self.assertEqual(result["determination"], "SOURCE_EVIDENCE_INCONSISTENT_BLOCKED")
            self.assertIn("frozen_source_sha_drift", result["integrity_issues"])
            self.assertFalse(result["may_enter_final_acceptance"])


if __name__ == "__main__":
    unittest.main()
