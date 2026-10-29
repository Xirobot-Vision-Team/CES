#!/usr/bin/env python3
"""EC332 focused functionality tests; eighth/ninth Ed25519 genuine, old deep
EC317/EC318 test histories structurally MOCKED. Isolated -I -B must DENY.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from ec295_delivery_anchor import anchor
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt
from ec331_offline_report_set_crosscheck import crosscheck
from ec331_offline_report_set_crosscheck import test_crosscheck as old_suite
from scripts import ces_next
from . import delta, operator


class TwoPinnedSetDeltaTests(unittest.TestCase):
    def setUp(self):
        self.old = old_suite.OfflineReportSetTests(methodName=
            'test_two_signed_reports_reveal_true_same_parent_siblings_not_global_latest')
        self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        self.root = self.old.root
        self.lpath = str(self.root/'ec332-left-owner-private-manifest.json')
        self.rpath = str(self.root/'ec332-right-owner-private-manifest.json')
        self.lsha = None
        self.rsha = None

    def build(self, *, role_reuse=False, second_same=False):
        r1 = self.old.make_report('base', self.old.p1)
        r2 = (r1 if second_same else self.old.make_report(
            'different-signed-branch', self.old.sibling(reused=role_reuse)))
        self.lsha = self._manifest(self.lpath, [
            r1, self._report_copy(r1, 'left')])
        if second_same:
            receipt._write_exclusive(self.rpath, Path(self.lpath).read_bytes())
            self.rsha = case.sha(Path(self.rpath).read_bytes())
        else:
            self.rsha = self._manifest(self.rpath, [
                r2, self._report_copy(r2, 'right')])
        return r1, r2

    def _report_copy(self, observation, name):
        cp = str(self.root/('ec332-copy-'+name+'.json'))
        receipt._write_exclusive(cp, Path(observation['report_file']).read_bytes())
        return dict(observation, report_file=cp)

    def _manifest(self, path, observations):
        receipt._write_exclusive(path, receipt._raw({
            'schema':crosscheck.MANIFEST_SCHEMA, 'reports':observations}))
        return case.sha(Path(path).read_bytes())

    def check(self):
        return delta.compare(left_manifest_file=self.lpath,
                             left_expected_manifest_sha256=self.lsha,
                             right_manifest_file=self.rpath,
                             right_expected_manifest_sha256=self.rsha)

    def kwargs(self):
        return {'left_manifest_file':self.lpath,
                'left_expected_manifest_sha256':self.lsha,
                'right_manifest_file':self.rpath,
                'right_expected_manifest_sha256':self.rsha}

    def test_distinct_local_signed_siblings_differ_without_global_latest_claim(self):
        r1,r2 = self.build()
        doc=self.check()
        self.assertEqual(doc['exit_code'],2)
        self.assertEqual(doc['combined_unique_report_original_count'],2)
        self.assertEqual(doc['combined_unique_ledger_original_count'],3)
        self.assertEqual(doc['combined_unique_signed_ninth_receipt_original_count'],3)
        self.assertEqual(doc['left_observation_counts']['report_rows'],2)
        self.assertEqual(doc['left_observation_counts']['distinct_report_originals'],1)
        self.assertEqual(doc['right_observation_counts']['distinct_report_originals'],1)
        self.assertEqual(doc['cross_input_only_ledger_pair_count'],1)
        self.assertEqual(doc['cross_input_only_ledger_pair_relationship_counts'],{
            'verified_two_distinct_one_row_appends_to_same_parent_unresolved':1})
        self.assertEqual(len(doc['cross_input_only_ledger_pair_examples']),1)
        self.assertEqual(doc['report_original_observation_difference'][
            'only_in_left_observation'],[r1['expected_report_sha256']])
        self.assertEqual(doc['report_original_observation_difference'][
            'only_in_right_observation'],[r2['expected_report_sha256']])
        self.assertEqual(len(doc['signed_ninth_receipt_original_observation_difference'][
            'observed_in_both']),1)
        self.assertTrue(doc['both_ec331_sets_and_every_inherited_signed_history_genuinely_replayed'])
        self.assertTrue(doc['both_sets_original_source_report_and_manifest_pins_rechecked_after_union'])
        self.assertFalse(any(doc[flag] for flag in delta.FALSE_FIELDS))
        data=json.dumps(doc)
        self.assertNotIn(str(self.root),data)
        self.assertNotIn(self.old.old.original_rows[0]['receipt_file'],data)

    def test_same_original_bytes_at_two_distinct_pinned_manifest_paths_are_not_new_evidence(self):
        self.build(second_same=True)
        result=self.check()
        self.assertNotEqual(self.lpath,self.rpath)
        self.assertEqual(self.lsha,self.rsha)
        self.assertTrue(result['same_manifest_original_bytes_at_two_distinct_paths'])
        self.assertEqual(result['combined_unique_report_original_count'],1)
        self.assertEqual(result['combined_unique_ledger_original_count'],2)
        self.assertEqual(result['combined_unique_signed_ninth_receipt_original_count'],2)
        self.assertEqual(result['cross_input_only_ledger_pair_count'],0)
        for key in ('report_original_observation_difference',
                    'ledger_original_observation_difference',
                    'signed_ninth_receipt_original_observation_difference'):
            self.assertEqual(result[key]['only_in_left_observation'],[])
            self.assertEqual(result[key]['only_in_right_observation'],[])
        self.assertEqual(result['cross_input_only_ninth_role_reuse_groups'],0)

    def test_cross_input_distinct_signed_receipts_reusing_role_not_a_second_vote(self):
        self.build(role_reuse=True)
        result=self.check()
        self.assertGreater(result['cross_input_only_ninth_role_reuse_groups'],0)
        self.assertTrue(any(row['reused_field']=='ninth_responder_id'
            for row in result['combined_ninth_role_reuse_group_examples']))
        self.assertEqual(result['combined_unique_signed_ninth_receipt_original_count'],3)
        self.assertFalse(result['source_pin_argument_proves_real_independent_custody'])

    def test_two_manifests_must_be_distinct_paths_even_if_same_bytes(self):
        self.build()
        with self.assertRaisesRegex(anchor.AnchorError,'TWO_DISTINCT_MANIFEST'):
            delta.compare(left_manifest_file=self.lpath,
                          left_expected_manifest_sha256=self.lsha,
                          right_manifest_file=self.lpath,
                          right_expected_manifest_sha256=self.lsha)

    def test_wrong_independent_second_manifest_raw_sha_fails_closed(self):
        self.build()
        self.rsha='ab'*32
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.check()

    def test_rewritten_second_manifest_canonical_with_reissued_pin_does_not_accept_unknown_keys(self):
        self.build()
        d=json.loads(Path(self.rpath).read_bytes())
        d['real_remote_cas_success']=True
        Path(self.rpath).write_bytes(receipt._raw(d))
        self.rsha=case.sha(Path(self.rpath).read_bytes())
        with self.assertRaisesRegex(anchor.AnchorError,'TWO_TO_EIGHT_EXACT'):
            self.check()

    def test_world_readable_second_manifest_rejected(self):
        self.build()
        os.chmod(self.rpath,0o644)
        with self.assertRaises((anchor.AnchorError,OSError)):
            self.check()

    def test_ninth_receipt_modified_after_both_replays_is_caught_by_late_repin(self):
        self.build()
        real=delta._cross_only_pairs
        def mutate(*args):
            result=real(*args)
            with open(self.old.old.original_rows[0]['receipt_file'],'ab') as file:
                file.write(b'changed after signed verification')
            return result
        with patch.object(delta,'_cross_only_pairs',side_effect=mutate):
            with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self.check()

    def test_first_manifest_modified_during_second_replay_is_caught_at_end(self):
        self.build()
        real=delta._verified_view
        def switch(manifest_file,sha):
            result=real(manifest_file,sha)
            if manifest_file==self.rpath:
                with open(self.lpath,'ab') as stream:stream.write(b' ')
            return result
        with patch.object(delta,'_verified_view',side_effect=switch):
            with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self.check()

    def test_old_unsigned_result_cannot_be_reused_as_fake_ec331_authority(self):
        self.build()
        with patch.object(crosscheck,'cross_reference',return_value={
                'schema':crosscheck.RESULT_SCHEMA,'exit_code':0,
                'every_listed_report_and_both_signed_histories_replayed':True}):
            with self.assertRaisesRegex(anchor.AnchorError,'REQUIRE_REAL_EC331'):
                self.check()

    def test_different_old_signed_request_context_is_rejected(self):
        self.build()
        real=delta._verified_view
        def mismatch(path,sha):
            result=real(path,sha)
            if path==self.rpath:
                result['context']={**result['context'],'request_id':'another-request'}
            return result
        with patch.object(delta,'_verified_view',side_effect=mismatch):
            with self.assertRaisesRegex(anchor.AnchorError,'DIFFERENT_SIGNED_EIGHTH'):
                self.check()

    def test_standalone_success_and_failure_both_keep_unresolved_semantics(self):
        self.build()
        stream=StringIO()
        argv=['compare-report-set-observations','--left-manifest-file',self.lpath,
              '--left-expected-manifest-sha256',self.lsha,
              '--right-manifest-file',self.rpath,
              '--right-expected-manifest-sha256',self.rsha]
        with redirect_stdout(stream):
            code=operator.main(argv)
        good=json.loads(stream.getvalue())
        self.assertEqual(code,2)
        self.assertEqual(good['schema'],delta.RESULT_SCHEMA)
        stream=StringIO()
        argv[-1]='ab'*32
        with redirect_stdout(stream):
            code=operator.main(argv)
        denial=json.loads(stream.getvalue())
        self.assertIn(code,(3,4,5))
        self.assertEqual(denial['schema'],delta.DENIAL_SCHEMA)
        self.assertFalse(denial['both_ec331_sets_and_every_inherited_signed_history_genuinely_replayed'])
        self.assertFalse(any(denial[flag] for flag in delta.FALSE_FIELDS))

    def test_unified_only_fixed_I_B_read_only_child_and_no_signer_writer(self):
        self.build()
        real=self.check()
        captured=[]
        def fake_command(cmd, **kw):
            captured.append((cmd,kw))
            return 2,real
        output=StringIO()
        with patch.object(ces_next,'_command',side_effect=fake_command):
            with redirect_stdout(output):
                rc=ces_next.audit_hold_report_set_delta(
                    'DeliveryAudit','ComparePinnedReportSetObservations',**self.kwargs())
        self.assertEqual(rc,2)
        self.assertEqual(len(captured),1)
        cmd=captured[0][0]
        self.assertEqual(cmd[1:3],['-I','-B'])
        self.assertEqual(cmd[4],'compare-report-set-observations')
        self.assertFalse(any(x in cmd for x in ('sign','create-report','--out','--private-key')))
        self.assertEqual(json.loads(output.getvalue())['schema'],delta.RESULT_SCHEMA)
        with self.assertRaises(ces_next.ConsoleError):
            ces_next.audit_hold_report_set_delta(
                'DeliveryAudit','SignOrWriteRemoteCAS',**self.kwargs())

    def test_unified_rejects_forged_remote_claim_and_unexpected_exit_zero(self):
        self.build()
        genuine=self.check()
        with patch.object(ces_next,'_command',return_value=(2,{
                **genuine,'remote_global_latest_or_winner_proven':True})):
            with self.assertRaisesRegex(ces_next.ConsoleError,'UNGROUNDED'):
                ces_next.audit_hold_report_set_delta(
                    'DeliveryAudit','ComparePinnedReportSetObservations',**self.kwargs())
        with patch.object(ces_next,'_command',return_value=(0,genuine)):
            with self.assertRaisesRegex(ces_next.ConsoleError,'PROCESS_EXIT_INVALID'):
                ces_next.audit_hold_report_set_delta(
                    'DeliveryAudit','ComparePinnedReportSetObservations',**self.kwargs())

    def test_real_isolated_process_refuses_fixture_mock_deep_history_not_fake_pass(self):
        self.build()
        script=Path(__file__).resolve().parents[2]/'scripts'/'ces_cas_report_set_delta.py'
        child=subprocess.run([sys.executable,'-I','-B',str(script),
              'compare-report-set-observations',
              '--left-manifest-file',self.lpath,
              '--left-expected-manifest-sha256',self.lsha,
              '--right-manifest-file',self.rpath,
              '--right-expected-manifest-sha256',self.rsha],
            capture_output=True,text=True,timeout=60)
        self.assertEqual(child.returncode,4)
        rejection=json.loads(child.stdout)
        self.assertEqual(rejection['status'],'invalid_input')
        self.assertFalse(rejection['both_ec331_sets_and_every_inherited_signed_history_genuinely_replayed'])
        self.assertFalse(rejection['remote_global_latest_or_winner_proven'])


if __name__=='__main__':
    unittest.main()
