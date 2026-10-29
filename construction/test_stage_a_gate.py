#!/usr/bin/env python3
"""Small EC-160 offline behavior fixtures. NOT native tests or acceptance."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

import stage_a_gate as gate


class PhaseAGateFixtures(unittest.TestCase):
    def test_clean_package_is_static_only(self) -> None:
        result = gate.evaluate()
        self.assertEqual(result["static_verdict"], "PASS_STATIC")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["native_verdict"], "NOT_RUN_NATIVE")
        self.assertEqual(result["final_acceptance"], "NOT_STARTED")
        self.assertEqual(len(result["checks"]), 8)
        self.assertEqual([i["id"] for i in result["outstanding_dependencies"]],
                         ["B-001", "B-002", "B-003"])

    def _with_copy(self, change) -> dict:
        with tempfile.TemporaryDirectory(prefix="ces-ec160-") as tmp:
            dest = Path(tmp) / "ces"
            shutil.copytree(gate.ROOT, dest)
            change(dest)
            return gate.evaluate(dest)

    def test_unreviewed_native_shared_module_change_blocks(self) -> None:
        def mutate(root: Path):
            f = root / "scripts/pathidentity.ps1"
            f.write_bytes(f.read_bytes() + b"\n# unsanctioned edit\n")
        result = self._with_copy(mutate)
        self.assertEqual(result["static_verdict"], "BLOCKED")
        ids = {r["id"] for r in result["checks"] if r["status"] == "BLOCKED"}
        self.assertIn("native_source_scope", ids)
        self.assertIn("archived_provenance", ids)
        self.assertEqual(result["native_verdict"], "NOT_RUN_NATIVE")

    def test_wire_contract_divergence_blocks(self) -> None:
        def mutate(root: Path):
            f = root / "references/cli-response-contract.v1.json"
            doc = json.loads(f.read_text(encoding="utf-8"))
            doc["source"]["entry_sha256"] = "0" * 64
            f.write_text(json.dumps(doc), encoding="utf-8")
        result = self._with_copy(mutate)
        ids = {r["id"] for r in result["checks"] if r["status"] == "BLOCKED"}
        self.assertIn("cli_wire_and_coverage", ids)
        self.assertEqual(result["exit_code"], 2)

    def test_first_phase_cannot_skip_ec(self) -> None:
        def mutate(root: Path):
            f = root / "construction/LEGACY_PROJECT_STATE.json"
            doc = json.loads(f.read_text(encoding="utf-8"))
            doc["next_ec"] = "EC-162"
            f.write_text(json.dumps(doc), encoding="utf-8")
        result = self._with_copy(mutate)
        check = next(c for c in result["checks"] if c["id"] == "package_plan")
        self.assertEqual(check["reason_code"], "STAGE_PLAN_INVALID")
        self.assertEqual(result["static_verdict"], "BLOCKED")

    def test_missing_native_module_fails_closed(self) -> None:
        def mutate(root: Path):
            (root / "scripts/pathidentity.ps1").unlink()
        result = self._with_copy(mutate)
        self.assertEqual(result["static_verdict"], "BLOCKED")
        self.assertIn("native_source_scope", [c["id"] for c in result["checks"]
                                             if c["status"] == "BLOCKED"])
        self.assertEqual(result["exit_code"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
