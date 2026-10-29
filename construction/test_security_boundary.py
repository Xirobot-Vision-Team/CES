#!/usr/bin/env python3
"""EC-157 focused source/contract guards; NOT native PowerShell or security certification."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from action_registry import _ec157_reviewed_drift, _ec159_reviewed_drift, check_registry, read_registry
from response_contract import load_contract, source_alignment

ROOT = Path(__file__).resolve().parent.parent


class SecurityBoundarySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cli = (ROOT / "scripts/ces.ps1").read_text(encoding="utf-8-sig")
        cls.save = (ROOT / "scripts/codesave.ps1").read_text(encoding="utf-8-sig")
        cls.ledger = json.loads((ROOT / "construction/LEGACY_SECURITY_DRIFT.json").read_text())
        cls.current_review = json.loads((ROOT / "construction/LEGACY_PATH_DRIFT.json").read_text())
        cls.boundaries = json.loads((ROOT / "construction/SECURITY_BOUNDARIES.json").read_text())

    def test_cli_rejects_unapproved_codesave_before_git_and_handler(self):
        start = self.cli.index("$envelope = New-Envelope -ActionName $Action")
        preflight = self.cli.index("if ($Action -ieq 'CodeSave' -and -not $ApprovePersist.IsPresent)", start)
        rejected = self.cli.index("Finish -Envelope $envelope -ExitCode 4", preflight)
        git = self.cli.index("$git = Get-Command -Name 'git'", rejected)
        handler = self.cli.index("$resultCode = CodeSave-Snapshot", git)
        self.assertLess(start, preflight)
        self.assertLess(preflight, rejected)
        self.assertLess(rejected, git)
        self.assertLess(git, handler)
        scope = self.cli[preflight:rejected]
        for text in ("CODE_SAVE_AUTHORIZATION_REQUIRED", "persisted = $false", "can_persist_ces_state = $false"):
            self.assertIn(text, scope)

    def test_handler_defense_in_depth_still_precedes_source_and_write(self):
        denied = self.save.index("if (-not $ApprovePersist)")
        validate = self.save.index("$verifyCode = CodeValidate-Snapshot")
        write = self.save.index("Write-CodeSaveAtomicNewFile -Directory $records")
        self.assertLess(denied, validate)
        self.assertLess(validate, write)
        self.assertIn("CODE_SAVE_AUTHORIZATION_REQUIRED", self.save[denied:validate])

    def test_git_config_environment_overlays_scrubbed(self):
        env = self.cli[self.cli.index("function Invoke-ReadOnlyGit"):self.cli.index("function Git-In")]
        self.assertIn("if ($key -match '^GIT_CONFIG(?:_|$)')", env)
        self.assertIn("GIT_OPTIONAL_LOCKS", env)
        self.assertIn("GIT_NO_LAZY_FETCH", env)
        self.assertIn("ArgumentList.Add($argument)", env)

    def test_store_existing_records_rejected_before_owner_marker_creation(self):
        store = self.save[self.save.index("function Initialize-CodeSaveStore"):self.save.index("function CodeSave-Snapshot")]
        records_check = store.index("Get-CodeSaveOptionalItem -Path $records")
        owner_write = store.index("Write-CodeSaveAtomicNewFile -Directory $store")
        self.assertLess(records_check, owner_write)
        self.assertIn("Get-Item -LiteralPath $Path -Force -ErrorAction Stop", self.save)
        self.assertIn("if ($IsWindows -or $IsMacOS)", self.save)
        self.assertIn("Test-CodeSaveRegularItem -Path $records -Directory $true", store)

    def test_current_baseline_and_historical_drift_chain_are_separate(self):
        baseline = json.loads((ROOT / "construction/SOURCE_BASELINE.json").read_text())
        self.assertEqual(self.ledger["ec"], "EC-157")
        for path, record in self.ledger["changed_powershell_sources"].items():
            old = baseline["fingerprints"][path]
            new = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            self.assertEqual(new, old)
            historical_base = record["r150_sha256"]
            historical_current = self.current_review["changed_powershell_sources"][path]["current_sha256"]
            self.assertEqual(record["current_sha256"], self.current_review["changed_powershell_sources"][path]["previous_sha256"])
            self.assertTrue(_ec157_reviewed_drift(ROOT, path, historical_base, record["current_sha256"]))
            self.assertTrue(_ec159_reviewed_drift(ROOT, path, historical_base, historical_current))
            self.assertFalse(_ec159_reviewed_drift(ROOT, path, historical_base, "0"*64))
            self.assertFalse(_ec159_reviewed_drift(ROOT, path, "1"*64, historical_current))

    def test_old_response_wire_contract_remains_aligned(self):
        result = source_alignment(load_contract())
        self.assertTrue(result["aligned"], result["problems"])
        self.assertFalse(result["native_powershell_executed"])

    def test_16_routes_29_unimplemented_and_explicit_code_save_effect(self):
        registry = read_registry()
        self.assertEqual(len(registry["routes"]), 16)
        self.assertEqual(len(registry["planned_capabilities"]), 29)
        save = [r for r in registry["routes"] if r["action"] == "CodeSave"]
        self.assertEqual(len(save), 1)
        self.assertEqual(save[0]["effect"], "LOCAL_CES_METADATA_WRITE_WITH_EXPLICIT_AUTHORIZATION")
        check = check_registry(registry)
        self.assertEqual(check["verdict"], "STATIC_CONTRACT_MATCH", check["problems"])
        self.assertEqual(check["details"]["cli_source_provenance"], "UNCHANGED_BASELINE")
        self.assertEqual(check["details"]["codesave_source_provenance"], "UNCHANGED_BASELINE")

    def test_risk_register_never_calls_unrun_native_cases_pass(self):
        self.assertEqual(self.boundaries["native_cases_status"], "NOT_RUN_NO_PWSH_IN_BUILDER")
        self.assertEqual(len(self.boundaries["action_classes"]), 7)
        self.assertTrue(any(x["classification"] == "RESIDUAL_RISK" for x in self.boundaries["recorded_risks"]))
        self.assertEqual(sum(1 for _ in (ROOT / "tests").glob("*.Smoke.ps1")), 15)
        self.assertTrue((ROOT / "tests/CodeSecurity.EC157.ps1").is_file())


if __name__ == "__main__":
    unittest.main()
