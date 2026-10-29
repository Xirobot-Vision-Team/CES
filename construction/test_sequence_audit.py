#!/usr/bin/env python3
"""Focused EC-154 development fixtures; DOES NOT execute native CES Smoke."""
from __future__ import annotations

from copy import deepcopy
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('ces_ec154_sequence_audit', HERE / 'sequence_audit.py')
assert SPEC is not None and SPEC.loader is not None
seq = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seq)


class StaticSequenceAuditFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.actual = seq.build_audit()

    def test_real_import_chain_and_k56_regression_keys(self):
        audit = self.actual
        self.assertEqual(audit['source_evidence']['cli_dot_source_modules'], 123)
        self.assertEqual(audit['source_evidence']['k_modules'], 56)
        self.assertEqual(audit['source_evidence']['original_sha_mismatches'], [])
        self.assertEqual(len(audit['k_chain']), 56)
        self.assertEqual(audit['k_chain'][0]['k'], 1)
        self.assertEqual(audit['k_chain'][-1]['parent_replay_k'], 55)
        self.assertEqual(audit['k_chain'][-1]['transitive_k_dependencies'], list(range(37, 56)))
        self.assertIn('genuine_global_threshold_endpoint_sexquinquagintuple_interaction',
                      audit['k_chain'][-1]['final_child_public_fields'])
        self.assertIn('path_focus', audit['contract']['public_json_fields'])

    def test_snapshot_detects_fields_order_and_selector_drift(self):
        expected = {'schema_version': self.actual['schema_version'],
                    'source_evidence': deepcopy(self.actual['source_evidence']),
                    'compatibility_invariants': deepcopy(self.actual['compatibility_invariants'])}
        self.assertEqual(seq.check_snapshot(self.actual, expected), [])
        expected['compatibility_invariants']['k_outputs_in_order'][55]['public_fields'].pop()
        self.assertIn('contract_drift:k_outputs_in_order', seq.check_snapshot(self.actual, expected))
        expected = {'schema_version': self.actual['schema_version'],
                    'source_evidence': deepcopy(self.actual['source_evidence']),
                    'compatibility_invariants': deepcopy(self.actual['compatibility_invariants'])}
        expected['compatibility_invariants']['selector_bounds']['MaxTop'] = 999
        self.assertIn('contract_drift:selector_bounds', seq.check_snapshot(self.actual, expected))
        expected = {'schema_version': self.actual['schema_version'],
                    'source_evidence': deepcopy(self.actual['source_evidence']),
                    'compatibility_invariants': deepcopy(self.actual['compatibility_invariants'])}
        expected['source_evidence']['source_sha256']['scripts/codesequence.ps1'] = '0' * 64
        self.assertIn('source_sha_drift_requires_review:scripts/codesequence.ps1',
                      seq.check_snapshot(self.actual, expected))

    def test_reject_fake_k57_from_sequence_source_without_touching_script(self):
        real = seq.source_bytes
        def injected(root: Path, relative: str) -> bytes:
            raw = real(root, relative)
            if relative == 'scripts/codesequence.ps1':
                candidate = ("                $pathFocus['selected_original_finding_pair_profile_retention_endpoint_extra_interaction'] = `\n"
                             "                    Get-CodeSequenceOriginalFindingPairProfileRetentionEndpointExtraInteraction -PathFocus $pathFocus\n")
                raw = raw.replace(b'    $afterIds = @(Get-CodeShowRecordIds -Directory $Directory)',
                                  candidate.encode() + b'    $afterIds = @(Get-CodeShowRecordIds -Directory $Directory)')
            return raw
        with patch.object(seq, 'source_bytes', side_effect=injected):
            with self.assertRaisesRegex(seq.AuditError, 'new/unclassified endpoint'):
                seq.build_audit()

    def test_reject_missing_final_child_json_field(self):
        real = seq.source_bytes
        def injected(root: Path, relative: str) -> bytes:
            raw = real(root, relative)
            if relative == 'scripts/codeprofileretentionendpointsexquinquagintupleinteraction.ps1':
                raw = raw.replace(b'        counts = [ordered]@{', b'        removed_counts = [ordered]@{')
            return raw
        with patch.object(seq, 'source_bytes', side_effect=injected):
            with self.assertRaisesRegex(seq.AuditError, 'counts map missing'):
                seq.build_audit()

    def test_unrelated_future_cli_import_is_reported_without_rewriting_ec151(self):
        real = seq.source_bytes
        def injected(root: Path, relative: str) -> bytes:
            if relative == 'scripts/registry_future.ps1':
                return b'function Get-FutureRegistry { return 1 }\n'
            raw = real(root, relative)
            if relative == 'scripts/ces.ps1':
                raw = raw.replace(b'$envelope = New-Envelope -ActionName $Action',
                                  b". (Join-Path $PSScriptRoot 'registry_future.ps1')\n" +
                                  b'$envelope = New-Envelope -ActionName $Action')
            return raw
        with patch.object(seq, 'source_bytes', side_effect=injected):
            audit = seq.build_audit()
        self.assertEqual(audit['source_evidence']['cli_dot_source_modules'], 124)
        self.assertEqual(audit['source_evidence']['ec151_cli_dot_source_modules'], 123)
        self.assertFalse(audit['source_evidence']['ec151_cli_imports_match_current'])
        self.assertIn('scripts/registry_future.ps1',
                      audit['source_evidence']['cli_imports_added_since_ec151'])
        self.assertEqual(len(audit['k_chain']), 56)

    def test_reject_lost_sequence_dispatch(self):
        real = seq.source_bytes
        def injected(root: Path, relative: str) -> bytes:
            raw = real(root, relative)
            if relative == 'scripts/codeshow.ps1':
                raw = raw.replace(b'$Envelope.data = Get-CodeShowSequence', b'$Envelope.data = Get-FutureSequence')
            return raw
        with patch.object(seq, 'source_bytes', side_effect=injected):
            with self.assertRaisesRegex(seq.AuditError, 'route to Get-CodeShowSequence absent'):
                seq.build_audit()

    def test_cli_queries_and_reject_out_of_range_k(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(seq.main(['--k', '56']), 0)
        self.assertIn('codeprofileretentionendpointsexquinquagintupleinteraction.ps1', out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(seq.main(['--k', '57']), 2)
        self.assertIn('no k57+', err.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
