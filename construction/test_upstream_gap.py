#!/usr/bin/env python3
"""Small EC-153 development fixtures, not native CES CLI/PowerShell acceptance."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import upstream_gap


class SourceGapTests(unittest.TestCase):
    def test_missing_sources_do_not_close_blocker(self):
        report = upstream_gap.generate_report()
        self.assertEqual(report["state"], "OPEN_NO_UPSTREAM_CANDIDATES")
        self.assertTrue(report["evidence"]["evidence_consistent"])
        self.assertEqual(report["evidence"]["original_inventory_count"], 305)
        self.assertFalse(report["evidence"]["original_rounds_in_inventory"])
        self.assertEqual(report["blocker_resolution"], "NOT_AUTHORIZED_BY_THIS_TOOL")
        self.assertEqual(report["upstream_acceptance_equivalence"], "NOT_PROVEN")

    def test_rounds_diff_is_overlap_only_and_does_not_echo_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "ROUNDS.json"
            p.write_text(json.dumps({"rounds": [
                {"ec": "EC-153", "round": 153, "title": "Original title", "scope": "PRIVATE_NOT_FOR_OUTPUT"},
                {"ec": "EC-017", "round": 17, "title": "Unrelated old EC"},
            ]}, ensure_ascii=False), encoding="utf-8")
            report = upstream_gap.generate_report(rounds=str(p))
        candidate = report["candidate_rounds"]
        self.assertEqual(report["state"], "OPEN_PARTIAL_UNAUTHENTICATED_CANDIDATES")
        self.assertEqual(candidate["source_trust"], "USER_SUPPLIED_UNAUTHENTICATED")
        self.assertEqual(candidate["comparison_status"], "STRUCTURAL_OVERLAP_ONLY")
        self.assertEqual(candidate["overlap_count"], 1)
        self.assertEqual(candidate["candidate_only_count"], 1)
        self.assertIn("title", candidate["overlapping_diff_fields"][0]["differing_fields"])
        self.assertNotIn("PRIVATE_NOT_FOR_OUTPUT", json.dumps(report, ensure_ascii=False))

    def test_duplicate_and_conflicting_identifiers_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "ROUNDS.json"
            p.write_text(json.dumps({"rounds": [
                {"ec": "EC-153", "round": 153},
                {"ec": "EC-153", "round": 153},
                {"ec": "EC-152", "round": 999},
            ]}), encoding="utf-8")
            candidate = upstream_gap.generate_report(rounds=str(p))["candidate_rounds"]
        self.assertEqual(candidate["comparison_status"], "AMBIGUOUS_IDENTIFIERS_NO_COMPARISON")
        self.assertNotIn("overlap_count", candidate)
        self.assertEqual(candidate["conflicting_identifiers"], 1)

    def test_bad_json_and_unknown_schema_report_no_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "ROUNDS.json"
            p.write_text("{not json", encoding="utf-8")
            invalid = upstream_gap.generate_report(rounds=str(p))["candidate_rounds"]
            p.write_text('{"schedule": ["A", "B"]}', encoding="utf-8")
            unknown = upstream_gap.generate_report(rounds=str(p))["candidate_rounds"]
        self.assertEqual(invalid["comparison_status"], "INVALID_JSON_NO_COMPARISON")
        self.assertEqual(unknown["comparison_status"], "UNRECOGNIZED_SCHEMA")

    def test_both_inputs_still_do_not_authenticate_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "v3.10.md"
            rounds = Path(tmp) / "ROUNDS.json"
            spec.write_text("# V3.10\nText is only a candidate.", encoding="utf-8")
            rounds.write_text('{"rounds": []}', encoding="utf-8")
            report = upstream_gap.generate_report(spec=str(spec), rounds=str(rounds))
        self.assertEqual(report["state"], "OPEN_BOTH_CANDIDATES_UNAUTHENTICATED")
        self.assertEqual(report["candidate_spec"]["semantic_comparison"], "NO_AUTHENTICATED_COMPARATOR")
        self.assertEqual(report["candidate_rounds"]["overlap_count"], 0)
        self.assertEqual(report["blocker_resolution"], "NOT_AUTHORIZED_BY_THIS_TOOL")

    def test_duplicate_object_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "ROUNDS.json"
            p.write_text('{"rounds": [{"ec": "EC-153", "ec": "EC-154"}]}', encoding="utf-8")
            candidate = upstream_gap.generate_report(rounds=str(p))["candidate_rounds"]
        self.assertEqual(candidate["comparison_status"], "INVALID_JSON_NO_COMPARISON")

    def test_nonexistent_or_oversized_candidate_rejected(self):
        with self.assertRaises(upstream_gap.InputError):
            upstream_gap.generate_report(spec="/some/nonexistent/original_v3.10.bin")
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "large.bin"
            with p.open("wb") as stream:
                stream.truncate(upstream_gap.MAX_INPUT_BYTES + 1)
            with self.assertRaises(upstream_gap.InputError):
                upstream_gap.generate_report(spec=str(p))


if __name__ == "__main__":
    unittest.main(verbosity=2)
