#!/usr/bin/env python3
"""EC315 focused genuine Ed25519 original-source append tests.

The EC313 fixture actually builds four distinct signed issuer CAS decisions
with Ed25519-signed observer readbacks; no unsigned older report is used as
an original. This suite does NOT certify an external real CAS/WORM/provider.
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
from cas_receipt import test_receipt as cas_fixture
from cas_readback import readback as rb
from cas_decision_history import test_decisions as fixture
from window_intersection import test_intersection as intersection_fixture
from window_mesh import test_mesh as mesh_fixture
from . import ledger as l

ROOT = Path(__file__).resolve().parents[2]


class EC315SignedDeliveryLedgerCases(unittest.TestCase):
    @classmethod
    def _write(cls, doc: dict, name: str) -> tuple[str, str]:
        return fixture.EC311SignedDecisionHistoryCases._private_json(doc, name)

    @classmethod
    def _window(cls, wid: str, doc: dict) -> dict:
        path, sha = cls._write(doc, 'ec315-original-'+wid)
        return {'window_id': wid, 'manifest_file': path,
                'expected_manifest_sha256': sha}

    @classmethod
    def _delivery(cls, sequence: int, windows: list[dict],
                  previous: str = 'GENESIS', previous_commitment: str = 'GENESIS') -> dict:
        path, sha = cls._write({
            'schema': l.DELIVERY_SCHEMA, 'sequence': sequence,
            'previous_delivery_sha256': previous,
            'previous_verified_originals_commitment_sha256': previous_commitment,
            'windows': windows,
        }, 'ec315-pinned-delivery')
        return {'sequence': sequence, 'delivery_file': path,
                'expected_delivery_sha256': sha}

    @classmethod
    def _root(cls, deliveries: list[dict]) -> tuple[str, str]:
        return cls._write({
            'schema': l.ROOT_SCHEMA,
            'cas_authority_id': cls.w1['cas_authority_id'],
            'cas_authority_public_hex': cls.w1['cas_authority_public_hex'],
            'cas_store_namespace_id': cls.w1['cas_store_namespace_id'],
            'expected_registry_id': cas_fixture.EC308CasReceiptCases.fork_report['registry_id'],
            'deliveries': deliveries,
        }, 'ec315-independent-ledger-root')

    @classmethod
    def setUpClass(cls):
        mesh_fixture.EC314OriginalSignedMeshCases.setUpClass()
        try:
            cls.w1 = copy.deepcopy(mesh_fixture.EC314OriginalSignedMeshCases.w1)
            cls.w2 = copy.deepcopy(mesh_fixture.EC314OriginalSignedMeshCases.w2)
            cls.w3 = copy.deepcopy(mesh_fixture.EC314OriginalSignedMeshCases.w3)
            cls.w4 = copy.deepcopy(mesh_fixture.EC314OriginalSignedMeshCases.cycle_window)
            cls.w5 = copy.deepcopy(cls.w1)
            cls.w5['decisions'] += copy.deepcopy(
                intersection_fixture.EC313OriginalSignedIntersectionCases.fresh)
            cls.e1 = cls._window('win_01', cls.w1)
            cls.e2 = cls._window('win_02', cls.w2)
            cls.e3 = cls._window('win_03', cls.w3)
            cls.e4 = cls._window('win_04', cls.w4)
            cls.e5 = cls._window('win_05', cls.w5)
            cls.d1 = cls._delivery(1, [cls.e1, cls.e2, cls.e3])
            cls.root1 = cls._root([cls.d1])
            cls.initial = l.evaluate(manifest_file=cls.root1[0],
                                     expected_manifest_sha256=cls.root1[1])
            cls.d2 = cls._delivery(2, [cls.e4],
                previous=cls.d1['expected_delivery_sha256'],
                previous_commitment=cls.initial[
                    'checkpoint_cumulative_replayed_originals_commitment_sha256'])
            cls.root2 = cls._root([cls.d1, cls.d2])
        except BaseException:
            mesh_fixture.EC314OriginalSignedMeshCases.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        mesh_fixture.EC314OriginalSignedMeshCases.tearDownClass()

    @classmethod
    def _evaluate(cls, root: tuple[str, str], **kwargs) -> dict:
        return l.evaluate(manifest_file=root[0], expected_manifest_sha256=root[1],
                          **kwargs)

    @classmethod
    def _run(cls, script: str, argv: list[str], code: int) -> dict:
        proc = subprocess.run([sys.executable, '-I','-B',
            str(ROOT/'scripts'/script), *argv], capture_output=True,
            text=True, timeout=2400,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        assert proc.returncode == code, (proc.returncode,proc.stdout,proc.stderr)
        return json.loads(proc.stdout)

    def test_01_genesis_genuine_three_signed_windows_checkpoint(self):
        rep = self.initial
        self.assertEqual(rep['status'], l.SUCCESS)
        self.assertEqual(rep['exit_code'], 0)
        self.assertEqual(rep['delivery_count'], 1)
        self.assertEqual(rep['total_unique_ec312_windows_fully_original_signed_replayed'], 3)
        self.assertEqual(rep['final_bounded_unique_issuer_signed_sources'], 4)
        self.assertEqual(rep['checkpoint_tip_delivery_original_raw_sha256'],
                         self.d1['expected_delivery_sha256'])
        self.assertEqual(len(rep['checkpoint_cumulative_replayed_originals_commitment_sha256']), 64)
        self.assertFalse(rep['external_prior_tip_and_replayed_sources_pins_supplied'])
        self.assertFalse(rep['actual_physical_single_cas_or_global_latest_proven'])

    def test_02_append_fourth_window_verified_real_cross_delivery_bridge(self):
        rep = self._evaluate(self.root2,
            expected_prior_delivery_sha256=self.d1['expected_delivery_sha256'],
            expected_prior_originals_commitment_sha256=self.initial[
                'checkpoint_cumulative_replayed_originals_commitment_sha256'])
        self.assertEqual(rep['status'], l.SUCCESS)
        self.assertEqual(rep['exit_code'],0)
        self.assertEqual(rep['delivery_count'],2)
        self.assertEqual(rep['total_unique_ec312_windows_fully_original_signed_replayed'],4)
        self.assertTrue(rep['each_append_prefix_full_original_signed_replay'][1][
            'new_delivery_signed_issuer_bridge_anchors'])
        self.assertTrue(rep['external_prior_tip_and_replayed_sources_pins_supplied'])
        self.assertEqual(rep['previous_checkpoint_verified_for_this_append'][
            'delivery_sha256'], self.d1['expected_delivery_sha256'])
        self.assertIsNotNone(rep['bounded_candidate_only_if_every_prefix_valid'])
        self.assertNotIn(str(fixture.EC311SignedDecisionHistoryCases.home), json.dumps(rep))

    def test_03_three_deliveries_unchanged_prefix_and_different_new_original(self):
        second = self._evaluate(self.root2)
        self.assertEqual(second['status'], l.SUCCESS)
        d3 = self._delivery(3,[self.e5],previous=self.d2['expected_delivery_sha256'],
            previous_commitment=second[
                'checkpoint_cumulative_replayed_originals_commitment_sha256'])
        root3 = self._root([self.d1,self.d2,d3])
        report = self._evaluate(root3,
            expected_prior_delivery_sha256=self.d2['expected_delivery_sha256'],
            expected_prior_originals_commitment_sha256=second[
                'checkpoint_cumulative_replayed_originals_commitment_sha256'])
        self.assertEqual(report['status'], l.SUCCESS)
        self.assertEqual([x['prefix_exit_code'] for x in
                          report['each_append_prefix_full_original_signed_replay']],
                         [0,0,0])
        self.assertEqual(report['total_unique_ec312_windows_fully_original_signed_replayed'], 5)
        self.assertEqual(report['final_bounded_unique_issuer_signed_sources'], 4)

    def test_04_wrong_external_prior_or_changed_delivery_chain_fail_closed(self):
        with self.assertRaisesRegex(a.AnchorError,
                'EC315_EXTERNAL_PREVIOUS_ORIGINALS_COMMITMENT_DIFFERS_FROM_REPLAY'):
            self._evaluate(self.root2,
                expected_prior_delivery_sha256=self.d1['expected_delivery_sha256'],
                expected_prior_originals_commitment_sha256='ab'*32)
        broken = self._delivery(2, [self.e4], previous='ab'*32,
            previous_commitment=self.initial[
                'checkpoint_cumulative_replayed_originals_commitment_sha256'])
        with self.assertRaisesRegex(a.AnchorError,
                'EC315_DELIVERY_PREDECESSOR_WHOLE_RAW_SHA_LINK_BROKEN'):
            self._evaluate(self._root([self.d1,broken]))
        with self.assertRaises(a.AnchorError):
            self._evaluate((self.root1[0],'fa'*32))

    def test_05_disconnected_prior_prefix_cannot_be_healed_by_later_real_bridge(self):
        # Make another distinct WHOLE original EC312 manifest with the SAME
        # authenticated D1/D2 readback/issuer bytes, simply stored under a
        # distinct private path. This does not invent or resign any evidence.
        clone = copy.deepcopy(self.w1)
        original_path = Path(clone['decisions'][0]['receipt_file'])
        copied_path = fixture.EC311SignedDecisionHistoryCases.home/'ec315-identical-signed-original-copy.json'
        copied_path.write_bytes(original_path.read_bytes())
        copied_path.chmod(0o600)
        clone['decisions'][0]['receipt_file'] = str(copied_path)
        clone_ref = self._window('win_06', clone)
        first = self._delivery(1,[self.e1,self.e3,clone_ref])
        earlier = self._evaluate(self._root([first]))
        self.assertEqual(earlier['final_bounded_graph_status'],
                         'multi_window_signed_receipt_intersection_graph_disconnected')
        self.assertEqual(earlier['exit_code'],2)
        later = self._delivery(2,[self.e2],previous=first['expected_delivery_sha256'],
            previous_commitment=earlier[
                'checkpoint_cumulative_replayed_originals_commitment_sha256'])
        late = self._evaluate(self._root([first,later]))
        self.assertEqual(late['final_bounded_graph_status'],
                         'replayed_signed_window_mesh_connected_and_consistent_not_cas_store_proof')
        self.assertEqual(late['status'],l.HISTORICAL_CONFLICT)
        self.assertEqual(late['first_failing_append_prefix_sequence'],1)
        self.assertIsNone(late['bounded_candidate_only_if_every_prefix_valid'])

    def test_06_new_real_issuer_same_revision_double_signature_no_winner(self):
        competing = intersection_fixture.EC313OriginalSignedIntersectionCases._fresh_site_window(
            different_issuer_original=True)
        ref = self._window('win_07', competing)
        next_delivery = self._delivery(2,[ref],
            previous=self.d1['expected_delivery_sha256'],
            previous_commitment=self.initial[
                'checkpoint_cumulative_replayed_originals_commitment_sha256'])
        result = self._evaluate(self._root([self.d1,next_delivery]))
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['final_bounded_issuer_same_revision_distinct_true_signatures'])
        self.assertIsNone(result['bounded_candidate_only_if_every_prefix_valid'])

    def test_07_signature_tampering_does_not_become_a_new_ledger_append(self):
        changed = copy.deepcopy(self.w4)
        item = changed['decisions'][2]['readbacks'][1]
        raw = json.loads(Path(item['readback_file']).read_text())
        raw['claim']['observed_head_chain_raw_sha256'] = 'a1'*32
        path, sha = self._write(raw, 'ec315-untrustworthy-unsigned-altered-observer')
        item.update(readback_file=path, expected_readback_sha256=sha)
        wrong = self._window('win_08',changed)
        delivery = self._delivery(2,[wrong],
            previous=self.d1['expected_delivery_sha256'],
            previous_commitment=self.initial[
                'checkpoint_cumulative_replayed_originals_commitment_sha256'])
        with self.assertRaisesRegex(a.AnchorError, 'EC309_OBSERVER_ED25519_SIGNATURE_INVALID'):
            self._evaluate(self._root([self.d1,delivery]))

    def test_08_private_exclusive_audit_independent_pin_and_full_replay(self):
        out = str(fixture.EC311SignedDecisionHistoryCases.home/'ec315-audit-private.json')
        first = l.verify(manifest_file=self.root2[0],expected_manifest_sha256=self.root2[1],
                         out=out,expected_prior_delivery_sha256=self.d1['expected_delivery_sha256'],
                         expected_prior_originals_commitment_sha256=self.initial[
                            'checkpoint_cumulative_replayed_originals_commitment_sha256'])
        self.assertEqual(first['exit_code'],0)
        self.assertEqual(os.stat(out).st_mode & 0o777,0o600)
        self.assertEqual(b.digest(Path(out).read_bytes()), first['audit_report_raw_sha256'])
        again = l.verify_report(
            manifest_file=self.root2[0], expected_manifest_sha256=self.root2[1],
            audit_report_file=out,expected_audit_report_sha256=first['audit_report_raw_sha256'],
            expected_prior_delivery_sha256=self.d1['expected_delivery_sha256'],
            expected_prior_originals_commitment_sha256=self.initial[
                'checkpoint_cumulative_replayed_originals_commitment_sha256'])
        self.assertEqual(again['exit_code'],0)
        with self.assertRaises(a.AnchorError):
            l.verify(manifest_file=self.root2[0],expected_manifest_sha256=self.root2[1],
                     out=out)

    def test_09_standalone_and_console_fixed_isolated_read_only(self):
        flags = ['--manifest-file',self.root2[0],
                 '--expected-manifest-sha256',self.root2[1],
                 '--expected-prior-delivery-sha256',self.d1['expected_delivery_sha256'],
                 '--expected-prior-originals-commitment-sha256',self.initial[
                     'checkpoint_cumulative_replayed_originals_commitment_sha256']]
        standalone = self._run('ces_cas_ledger.py',['verify-append',*flags],0)
        self.assertEqual(standalone['schema'],l.RESULT_SCHEMA)
        self.assertEqual(standalone['status'],l.SUCCESS)
        console = self._run('ces_next.py',['audit-ledger','DeliveryAudit',
            'VerifySignedCasDeliveryLedger',*flags],0)
        self.assertEqual(console['status'],l.SUCCESS)
        denied = self._run('ces_next.py',['audit-ledger','DeliveryAudit',
            'AuthorizeCasWrite',*flags],3)
        self.assertEqual(denied['status'],'permission_denied')
        forbidden = subprocess.run([sys.executable,'-I','-B',
            str(ROOT/'scripts'/'ces_next.py'),'audit-ledger','DeliveryAudit',
            'VerifySignedCasDeliveryLedger',*flags,'--out','/tmp/no-authority'],
            capture_output=True,text=True,timeout=20)
        self.assertNotEqual(forbidden.returncode,0)


    def test_10_fully_signed_adjacent_but_no_original_issuer_bridge_fails(self):
        # Genesis covers true D1-D3. An entirely genuinely-signed D4/D5
        # window has adjacent parent revisions, but no shared D1-D3 original
        # signed issuer receipt; adjacency is not an authenticated bridge.
        clone = copy.deepcopy(self.w1)
        original = Path(clone['decisions'][1]['receipt_file'])
        copied = fixture.EC311SignedDecisionHistoryCases.home/'ec315-disconnected-source-copy.json'
        copied.write_bytes(original.read_bytes())
        copied.chmod(0o600)
        clone['decisions'][1]['receipt_file'] = str(copied)
        clone_ref = self._window('win_09', clone)
        early_delivery = self._delivery(1, [self.e1,self.e2,clone_ref])
        early = self._evaluate(self._root([early_delivery]))
        self.assertEqual(early['exit_code'],0)
        previous = {}
        for item in intersection_fixture.EC313OriginalSignedIntersectionCases.fresh[1]['readbacks']:
            _, claim = rb._parse_readback(item['readback_file'], item['expected_readback_sha256'])
            previous[item['observer_id']] = {
                'sequence': claim['readback_sequence'],
                'raw_sha256': item['expected_readback_sha256'],
                'observed_revision': claim['observed_cas_revision'],
                'observed_head_raw_sha256': claim['observed_head_chain_raw_sha256'],
            }
        fifth, _, _ = intersection_fixture.EC313OriginalSignedIntersectionCases._next_signed_decision(
            intersection_fixture.EC313OriginalSignedIntersectionCases.stage,
            previous, 5)
        disconnected = intersection_fixture.EC313OriginalSignedIntersectionCases._window(
            [intersection_fixture.EC313OriginalSignedIntersectionCases.fresh[1],fifth],
            previous=intersection_fixture.EC313OriginalSignedIntersectionCases.fresh[0])
        new = self._window('win_10', disconnected)
        next_delivery = self._delivery(2,[new],
            previous=early_delivery['expected_delivery_sha256'],
            previous_commitment=early[
                'checkpoint_cumulative_replayed_originals_commitment_sha256'])
        report = self._evaluate(self._root([early_delivery,next_delivery]))
        self.assertEqual(report['final_bounded_graph_status'],
                         'multi_window_signed_receipt_intersection_graph_disconnected')
        self.assertEqual(report['status'],l.APPEND_DISCONNECTED)
        self.assertEqual(report['exit_code'],2)
        self.assertEqual(report['each_append_prefix_full_original_signed_replay'][1][
                         'new_delivery_genuine_signed_issuer_bridge_count'],0)
        self.assertIsNone(report['bounded_candidate_only_if_every_prefix_valid'])


if __name__ == '__main__':
    unittest.main()
