#!/usr/bin/env python3
"""EC-156 focused *offline* consumer tests; never runs PowerShell/Git/Smoke."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "ces_ec156_response_contract", HERE / "response_contract.py"
)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class ResponseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = module.load_contract()
        cls.fixtures = HERE / "fixtures" / "ec156"

    def fixture(self, name: str) -> dict:
        return module.parse_one_json((self.fixtures / f"{name}.json").read_bytes())

    def evaluate(self, obj: dict, exit_code: int | None = None) -> dict:
        return module.evaluate(obj, self.contract, exit_code)

    def test_five_wire_statuses_are_distinct(self) -> None:
        for name, exit_code in [
            ("success", 0), ("partial", 2), ("not_implemented", 3),
            ("invalid_input", 4), ("unavailable", 5)
        ]:
            with self.subTest(name=name):
                result = self.evaluate(self.fixture(name), exit_code)
                self.assertTrue(result["conforms"], result["issues"])
                self.assertEqual(result["expected_process_exit_code"], exit_code)
                self.assertEqual(result["exit_matches_status"], True)
                self.assertFalse(result["runtime_or_business_claims_verified"])

    def test_exit_not_supplied_is_not_invented(self) -> None:
        result = self.evaluate(self.fixture("partial"))
        self.assertTrue(result["conforms"])
        self.assertIsNone(result["observed_process_exit_code"])
        self.assertIsNone(result["exit_matches_status"])
        self.assertFalse(result["exit_code_observed"])

    def test_exit_mismatch_fails_closed(self) -> None:
        result = self.evaluate(self.fixture("partial"), 0)
        self.assertFalse(result["conforms"])
        self.assertIn("EXIT_MISMATCH", [v["code"] for v in result["issues"]])

    def test_codesave_auth_denial_is_not_persistence(self) -> None:
        obj = self.fixture("codesave_denied")
        result = self.evaluate(obj, 4)
        self.assertTrue(result["conforms"])
        self.assertFalse(result["read_only_action_reported"])
        self.assertFalse(result["code_save_write_confirmed"])
        self.assertEqual(result["coverage"]["reported_true"], [])
        obj["coverage"]["code_result_persisted"] = True
        denial = self.evaluate(obj, 4)
        self.assertFalse(denial["conforms"])
        self.assertIn("UNAUTHORIZED_WRITE_CONTRADICTION",
                      [v["code"] for v in denial["issues"]])

    def test_unimplemented_action_cannot_claim_success(self) -> None:
        obj = self.fixture("not_implemented")
        obj["status"] = "success"
        obj["reason_code"] = "QUALITY_OK"
        result = self.evaluate(obj, 0)
        self.assertIn("UNREGISTERED_ACTION_RESULT",
                      [v["code"] for v in result["issues"]])

    def test_inspect_success_requires_its_source_flags(self) -> None:
        obj = self.fixture("success")
        obj["coverage"]["stable_root_verified"] = False
        result = self.evaluate(obj, 0)
        self.assertIn("INSPECT_SUCCESS_FLAG_MISSING",
                      [v["code"] for v in result["issues"]])

    def test_codesave_success_requires_persisted_self_report(self) -> None:
        obj = self.fixture("codesave_denied")
        obj["status"] = "success"
        obj["reason_code"] = "CODE_SAVE_OK"
        obj["data"] = {"persisted": False}
        result = self.evaluate(obj, 0)
        codes = {i["code"] for i in result["issues"]}
        self.assertIn("CODE_SAVE_SUCCESS_FLAG_MISSING", codes)
        self.assertIn("CODE_SAVE_SUCCESS_DATA_MISSING", codes)

    def test_missing_and_wrong_type_coverage_are_rejected(self) -> None:
        obj = self.fixture("partial")
        del obj["coverage"]["repository_checked"]
        result = self.evaluate(obj, 2)
        self.assertIn("MISSING_COVERAGE_FLAG",
                      [v["code"] for v in result["issues"]])
        obj["coverage"]["repository_checked"] = 1
        result = self.evaluate(obj, 2)
        self.assertIn("COVERAGE_FLAG_TYPE",
                      [v["code"] for v in result["issues"]])

    def test_extras_are_labeled_but_opaque(self) -> None:
        obj = self.fixture("partial")
        obj["new_optional_envelope_property"] = {"not_reprinted": "sensitive"}
        obj["coverage"]["future_probe"] = True
        result = self.evaluate(obj, 2)
        self.assertTrue(result["conforms"], result["issues"])
        self.assertEqual(result["coverage"]["unknown_flags"], ["future_probe"])
        self.assertNotIn("new_optional_envelope_property", json.dumps(result))
        self.assertTrue(result["advisories"])

    def test_nested_codeshow_sequence_payload_is_not_flattened(self) -> None:
        obj = self.fixture("partial")
        obj["action"] = "CodeShow"
        obj["status"] = "success"
        obj["reason_code"] = "CODE_SHOW_OK"
        obj["coverage"] = {k: False for k in self.contract["coverage"]["fields"]}
        data = {"mode": "Sequence", "path_focus": {"k56": {
            "order": [1, 2, {"token": "retained"}],
            "ratio": {"numerator": 23, "denominator": 101}
        }}}
        obj["data"] = data
        before = copy.deepcopy(data)
        result = self.evaluate(obj, 0)
        self.assertTrue(result["conforms"], result["issues"])
        self.assertEqual(obj["data"], before)
        self.assertEqual(result["coverage"]["reported_true"], [])
        self.assertNotIn("path_focus", json.dumps(result))

    def test_unknown_codeshow_mode_is_not_accepted(self) -> None:
        obj = self.fixture("partial")
        obj["action"] = "CodeShow"
        obj["data"] = {"mode": "FantasyMode"}
        result = self.evaluate(obj, 2)
        self.assertIn("UNREGISTERED_CODESHOW_MODE",
                      [v["code"] for v in result["issues"]])

    def test_duplicate_members_even_deep_are_rejected(self) -> None:
        for raw in (b'{"status":"success","status":"partial"}',
                    b'{"coverage":{"repository_checked":true,'
                    b'"repository_checked":false}}'):
            with self.subTest(raw=raw):
                with self.assertRaises(module.ContractError):
                    module.parse_one_json(raw)

    def test_json_requires_one_object_and_real_json_numbers(self) -> None:
        for raw in (b'[]', b'{"status":"success"} {}',
                    b'{"x":NaN}', b'\xef\xbb\xbf{"x":1}',
                    b'{"x":', b'\xff'):
            with self.subTest(raw=raw):
                with self.assertRaises(module.ContractError):
                    module.parse_one_json(raw)

    def test_read_limit_does_not_partially_parse_large_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "response.json"
            file.write_bytes(b'{"status":"success"}')
            with self.assertRaises(module.ContractError):
                module.read_limited(str(file), max_bytes=8)

    def test_source_alignment_is_readonly_and_reports_provenance(self) -> None:
        result = module.source_alignment(self.contract)
        self.assertTrue(result["aligned"], result["problems"])
        self.assertFalse(result["native_powershell_executed"])
        forged = copy.deepcopy(self.contract)
        forged["source"]["handler_sha256"]["scripts/codesave.ps1"] = "0" * 64
        changed = module.source_alignment(forged)
        self.assertFalse(changed["aligned"])
        self.assertTrue(any("codesave" in x for x in changed["problems"]))


if __name__ == "__main__":
    unittest.main()
