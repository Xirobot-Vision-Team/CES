#!/usr/bin/env python3
"""EC314 focused tests use ACTUAL local EC294-309 Ed25519-signed originals.

They reuse EC313's four independently signed consecutive CAS fork decisions
and both distinct original Ed25519 observer chains. No previous PASS audit is
fabricated. Outside-the-lab organization, CAS store, WORM and global latest
remain entirely untested.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from delivery_anchor import anchor as a
from portable_bundle import bundle as b
from cas_receipt import test_receipt as cas_fixtures
from cas_readback import readback as rb
from cas_readback import test_readback as observer_fixtures
from cas_decision_history import test_decisions as historical_fixtures
from window_intersection import test_intersection as intersection_fixtures
from . import mesh as m

ROOT = Path(__file__).resolve().parents[2]


class EC314OriginalSignedMeshCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        intersection_fixtures.EC313OriginalSignedIntersectionCases.setUpClass()
        try:
            cls.w1 = copy.deepcopy(intersection_fixtures.EC313OriginalSignedIntersectionCases.w1)   # D1,D2
            cls.w2 = copy.deepcopy(intersection_fixtures.EC313OriginalSignedIntersectionCases.w2)   # D2,D3
            cls.w3 = copy.deepcopy(intersection_fixtures.EC313OriginalSignedIntersectionCases.w3)   # D3,D4
            cls.cycle_window = copy.deepcopy(cls.w1)
            cls.cycle_window['decisions'].append(copy.deepcopy(intersection_fixtures.EC313OriginalSignedIntersectionCases.fresh[0]))
        except BaseException:
            intersection_fixtures.EC313OriginalSignedIntersectionCases.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        intersection_fixtures.EC313OriginalSignedIntersectionCases.tearDownClass()

    @classmethod
    def _outer(cls, *windows: dict) -> tuple[str, str]:
        # Unique private manifests, each independently whole-byte pinned.
        pieces = []
        for i, window in enumerate(windows):
            name = f'ec314-window-{i}'
            path, sha = historical_fixtures.EC311SignedDecisionHistoryCases._private_json(window, name)
            pieces.append({'window_id': f'window_{i+1}',
                           'manifest_file': path,
                           'expected_manifest_sha256': sha})
        doc = {
            'schema': m.MANIFEST_SCHEMA,
            'cas_authority_id': cls.w1['cas_authority_id'],
            'cas_authority_public_hex': cls.w1['cas_authority_public_hex'],
            'cas_store_namespace_id': cls.w1['cas_store_namespace_id'],
            'expected_registry_id': cas_fixtures.EC308CasReceiptCases.fork_report['registry_id'],
            'windows': pieces,
        }
        return historical_fixtures.EC311SignedDecisionHistoryCases._private_json(doc, 'ec314-external-mesh-manifest')

    @classmethod
    def _evaluate(cls, *windows: dict) -> dict:
        path, sha = cls._outer(*windows)
        return m.evaluate(manifest_file=path, expected_manifest_sha256=sha)

    @classmethod
    def _run(cls, script: str, args: list[str], rc: int) -> dict:
        output = subprocess.run(
            [sys.executable, '-I', '-B', str(ROOT/'scripts'/script), *args],
            capture_output=True, text=True, timeout=1800,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        assert output.returncode == rc, (output.returncode, output.stdout,
                                         output.stderr)
        return json.loads(output.stdout.strip())

    def test_01_three_node_transitive_real_signed_overlap_no_direct_end_edge(self):
        result = self._evaluate(self.w1, self.w2, self.w3)
        self.assertEqual(result['status'], m.SUCCESS)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['unique_true_issuer_signed_original_count'], 4)
        self.assertEqual(result['connected_component_count'], 1)
        self.assertEqual(result['exact_original_signed_intersection_edge_count'], 2)
        self.assertEqual([x['window_a']+':'+x['window_b'] for x in
                          result['original_signed_issuer_receipt_intersection_edges']],
                         ['window_1:window_2', 'window_2:window_3'])
        self.assertEqual(result['deterministic_verified_original_overlap_paths'][-1][
            'verified_original_overlap_path'], ['window_1','window_2','window_3'])
        self.assertTrue(result['signed_observer_cross_window_predecessor_links_verified'])
        self.assertEqual(len(result['opaque_boundaries_verified_by_other_signed_original']),4)
        self.assertIsNotNone(result['last_candidate_sha256_of_bounded_compatible_signed_claims_only'])
        self.assertNotIn(str(historical_fixtures.EC311SignedDecisionHistoryCases.home), json.dumps(result))
        self.assertFalse(result['actual_physical_single_linearizable_cas_or_global_latest_proven'])

    def test_02_triangle_real_original_cycle_edges_and_path_consistency(self):
        result = self._evaluate(self.w1, self.w2, self.cycle_window)
        self.assertEqual(result['status'], m.SUCCESS)
        self.assertEqual(result['exact_original_signed_intersection_edge_count'],3)
        self.assertEqual(len(result['extra_cycle_edges_and_independent_true_original_paths']),1)
        self.assertEqual(result['unique_true_issuer_signed_original_count'],3)
        self.assertFalse(result['cross_mesh_signed_observer_predecessor_conflicts'])

    def test_03_disjoint_genuine_signed_newer_window_cannot_bridge_by_revision(self):
        # Build D5 with independent real EC307 forks, issuer and two observers.
        prev = {}
        for item in intersection_fixtures.EC313OriginalSignedIntersectionCases.fresh[1]['readbacks']:
            _, claim = rb._parse_readback(item['readback_file'],
                                          item['expected_readback_sha256'])
            prev[item['observer_id']] = {
                'sequence': claim['readback_sequence'],
                'raw_sha256': item['expected_readback_sha256'],
                'observed_revision': claim['observed_cas_revision'],
                'observed_head_raw_sha256': claim['observed_head_chain_raw_sha256'],
            }
        fifth, _, _ = intersection_fixtures.EC313OriginalSignedIntersectionCases._next_signed_decision(intersection_fixtures.EC313OriginalSignedIntersectionCases.stage, prev, 5)
        isolated = intersection_fixtures.EC313OriginalSignedIntersectionCases._window([intersection_fixtures.EC313OriginalSignedIntersectionCases.fresh[1], fifth], previous=intersection_fixtures.EC313OriginalSignedIntersectionCases.fresh[0])
        result = self._evaluate(self.w1, self.w2, isolated)
        self.assertEqual(result['status'], m.DISCONNECTED)
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['connected_component_count'], 2)
        self.assertEqual(result['exact_original_signed_intersection_edge_count'],1)
        self.assertFalse(result['cross_mesh_signed_issuer_parent_or_revision_gaps'])
        self.assertIsNone(result['last_candidate_sha256_of_bounded_compatible_signed_claims_only'])

    def test_04_cross_path_real_signed_observer_predecessor_contradiction(self):
        changed = copy.deepcopy(self.w3)
        wrong = 'aa'*32
        changed['observers'][0]['boundary']['raw_sha256'] = wrong
        first = changed['decisions'][0]['readbacks'][0]
        doc = json.loads(Path(first['readback_file']).read_text())
        doc['claim']['previous_readback_raw_sha256'] = wrong
        doc['observer_signature_ed25519'] = observer_fixtures.EC309CasReadbackCases.key.sign(
            rb.DOMAIN + a.canonical(doc['claim'])).hex()
        path, sha = historical_fixtures.EC311SignedDecisionHistoryCases._private_json(doc,'ec314-true-new-previous-signature')
        first.update(readback_file=path,expected_readback_sha256=sha)
        second = changed['decisions'][1]['readbacks'][0]
        doc = json.loads(Path(second['readback_file']).read_text())
        doc['claim']['previous_readback_raw_sha256'] = sha
        doc['observer_signature_ed25519'] = observer_fixtures.EC309CasReadbackCases.key.sign(
            rb.DOMAIN + a.canonical(doc['claim'])).hex()
        path, sha = historical_fixtures.EC311SignedDecisionHistoryCases._private_json(doc,'ec314-true-resigned-followup')
        second.update(readback_file=path,expected_readback_sha256=sha)
        result = self._evaluate(self.w1, self.w2, changed)
        self.assertEqual(result['status'], m.SIGNED_CONFLICT)
        self.assertTrue(result['cross_mesh_signed_observer_predecessor_conflicts'])
        self.assertTrue(result['opaque_boundaries_contradicted_by_true_signed_original'])
        self.assertIsNone(result['last_candidate_sha256_of_bounded_compatible_signed_claims_only'])

    def test_05_new_original_issuer_double_sign_with_same_revision(self):
        alternate = intersection_fixtures.EC313OriginalSignedIntersectionCases._fresh_site_window(different_issuer_original=True)
        result = self._evaluate(self.w1, self.w2, alternate)
        self.assertEqual(result['status'],m.ISSUER_AMBIGUITY)
        self.assertTrue(result['different_true_issuer_originals_claim_same_revision'])
        self.assertEqual(result['connected_component_count'],1)

    def test_06_entire_raw_sha_pins_exact_fields_and_original_signature_reject(self):
        path, sha = self._outer(self.w1,self.w2,self.w3)
        with self.assertRaises(a.AnchorError):
            m.evaluate(manifest_file=path,expected_manifest_sha256='f'*64)
        bad = json.loads(Path(path).read_text())
        bad['windows'][1]['expected_manifest_sha256'] = bad['windows'][0][
            'expected_manifest_sha256']
        path, sha = historical_fixtures.EC311SignedDecisionHistoryCases._private_json(bad,'ec314-duplicate-outer-manifest')
        with self.assertRaisesRegex(a.AnchorError,'EC314_EACH_EC312_MANIFEST_MUST_BE_DIFFERENT'):
            m.evaluate(manifest_file=path,expected_manifest_sha256=sha)
        changed = copy.deepcopy(self.w3)
        item = changed['decisions'][1]['readbacks'][1]
        doc = json.loads(Path(item['readback_file']).read_text())
        doc['claim']['observed_head_chain_raw_sha256'] = 'ab'*32
        fp, fs = historical_fixtures.EC311SignedDecisionHistoryCases._private_json(doc,'ec314-actual-forged-ed25519')
        item.update(readback_file=fp,expected_readback_sha256=fs)
        with self.assertRaisesRegex(a.AnchorError,'EC309_OBSERVER_ED25519_SIGNATURE_INVALID'):
            self._evaluate(self.w1,self.w2,changed)

    def test_07_owner_private_audit_repeat_original_replay_and_exclusive(self):
        path, sha = self._outer(self.w1,self.w2,self.w3)
        out = str(historical_fixtures.EC311SignedDecisionHistoryCases.home/'ec314-private-mesh-audit.json')
        result = m.verify(manifest_file=path,expected_manifest_sha256=sha,out=out)
        self.assertEqual(result['exit_code'],0)
        self.assertEqual(os.stat(out).st_mode & 0o777,0o600)
        self.assertEqual(b.digest(Path(out).read_bytes()),result['audit_report_raw_sha256'])
        verify = m.verify_report(manifest_file=path,expected_manifest_sha256=sha,
                                 audit_report_file=out,
                                 expected_audit_report_sha256=result['audit_report_raw_sha256'])
        self.assertEqual(verify['exit_code'],0)
        with self.assertRaises(a.AnchorError):
            m.verify(manifest_file=path,expected_manifest_sha256=sha,out=out)

    def test_08_isolated_cli_and_console_actions_only_read_verify(self):
        path, sha = self._outer(self.w1,self.w2,self.w3)
        args = ['--manifest-file',path,'--expected-manifest-sha256',sha]
        cli = self._run('ces_cas_mesh.py',['verify',*args],0)
        self.assertEqual(cli['schema'],m.RESULT_SCHEMA)
        self.assertEqual(cli['connected_component_count'],1)
        console = self._run('ces_next.py',[ 'audit-mesh','DeliveryAudit',
                'ReconcileSignedCasWindowMesh',*args],0)
        self.assertEqual(console['status'],m.SUCCESS)
        self.assertFalse(console['external_cas_access_performed'])
        denied = self._run('ces_next.py',[
            'audit-mesh','DeliveryAudit','AuthorizeCasMutation',*args],3)
        self.assertEqual(denied['status'],'permission_denied')
        bad = subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_next.py'),
               'audit-mesh','DeliveryAudit','ReconcileSignedCasWindowMesh',
               *args,'--out','/tmp/forbidden'],capture_output=True,text=True,timeout=20)
        self.assertNotEqual(bad.returncode,0)


if __name__ == '__main__':
    unittest.main()
