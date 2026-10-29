#!/usr/bin/env python3
"""EC329 focused functional tests using genuine 8th/9th Ed25519 fixtures.

Parent EC321 structural fixture mocks EC317/318 deep old signatures. The
actual isolated EC329 process must reject those mocks; tests never claim a
complete unmocked production EC294->329 historical acceptance.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from delivery_anchor import anchor
from fork_case_transport import case
from offline_review_ledger import ledger
from offline_review_ledger import test_ledger as fixture
from scripts import ces_next as console
from . import comparison, operator


class GenuineDualLedgerComparisonTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.IndependentOfflineMultiReviewLedgerTests(
            methodName='test_two_genuine_independent_offline_dispositions_are_detected_as_divergent')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.folder = self.f.folder
        self.original_rows = list(self.f.rows)
        # Snapshot A = independently SHA-pinned one-review genesis candidate.
        self.a_file = self._make('a-genesis', self.original_rows[:1])
        self.a_sha = case.sha(Path(self.a_file).read_bytes())
        self.b_file = self._make('b-one-append', self.original_rows,
                                 prior_sha=self.a_sha)
        self.b_sha = case.sha(Path(self.b_file).read_bytes())
        self.a_parent_file = None
        self.b_parent_file = self.a_file
        self.a_parent_sha = ledger.ZERO
        self.b_parent_sha = self.a_sha

    def _make(self, suffix, rows, *, prior_sha=ledger.ZERO):
        self.f.rows = rows
        self.f.meta['previous_ledger_original_raw_sha256'] = prior_sha
        self.f.ledger_file = str(self.folder / ('ec329-' + suffix + '.json'))
        self.f.write_draft_and_prepare()
        return self.f.ledger_file

    def params(self, **changes):
        args = {key: value for key, value in self.f.f.args.items()
                if key not in ('receipt_file', 'decision_id', 'ninth_responder_id',
                               'ninth_responder_public_hex',
                               'response_challenge_sha256',
                               'expected_disposition', 'expected_reason_code')}
        args.update(dict(
            branch_a_ledger_file=self.a_file,
            expected_branch_a_ledger_sha256=self.a_sha,
            branch_b_ledger_file=self.b_file,
            expected_branch_b_ledger_sha256=self.b_sha,
            branch_a_prior_ledger_file=self.a_parent_file,
            expected_branch_a_prior_ledger_sha256=self.a_parent_sha,
            branch_b_prior_ledger_file=self.b_parent_file,
            expected_branch_b_prior_ledger_sha256=self.b_parent_sha,
        ))
        args.update(changes)
        return args

    def compare(self, **changes):
        return comparison.compare_ledgers(**self.params(**changes))

    def argv(self, **changes):
        args=self.params(**changes)
        out=['compare-ledgers']
        for key, value in args.items():
            if key in ('left','right') or value is None:
                continue
            out.extend(('--'+key.replace('_','-'),str(value)))
        for side in ('left','right'):
            for key,value in args[side].items():
                out.extend(('--'+side+'-'+key.replace('_','-'),str(value)))
        return out

    def test_two_original_true_signature_chain_replays_direct_append(self):
        data=self.compare()
        self.assertEqual(data['relationship'],
                         'verified_one_entry_append_from_a_to_b_unresolved')
        self.assertEqual(data['common_exact_entry_prefix_length'],1)
        self.assertEqual(data['unique_signed_receipt_raw_sha_count'],2)
        self.assertTrue(data['verified_direct_one_entry_append'])
        self.assertTrue(data['both_ledgers_all_ninth_signatures_and_eighth_two_original_histories_verified'])
        self.assertEqual(data['exit_code'],2)
        for flag in comparison.FALSE_FIELDS:
            self.assertIs(data[flag],False)

    def test_reversed_order_is_verified_backward_direct_append(self):
        args=self.params(
            branch_a_ledger_file=self.b_file,
            expected_branch_a_ledger_sha256=self.b_sha,
            branch_a_prior_ledger_file=self.a_file,
            expected_branch_a_prior_ledger_sha256=self.a_sha,
            branch_b_ledger_file=self.a_file,
            expected_branch_b_ledger_sha256=self.a_sha,
            branch_b_prior_ledger_file=None,
            expected_branch_b_prior_ledger_sha256=ledger.ZERO)
        data=comparison.compare_ledgers(**args)
        self.assertEqual(data['relationship'],
                         'verified_one_entry_append_from_b_to_a_unresolved')

    def test_same_byte_identical_snapshots_are_not_two_new_opinions(self):
        twin=self._make('twin-a',self.original_rows[:1])
        result=self.compare(
            branch_b_ledger_file=twin,
            expected_branch_b_ledger_sha256=case.sha(Path(twin).read_bytes()),
            branch_b_prior_ledger_file=None,
            expected_branch_b_prior_ledger_sha256=ledger.ZERO)
        self.assertEqual(result['relationship'],'same_pinned_original_bytes_unresolved')
        self.assertEqual(result['unique_signed_receipt_raw_sha_count'],1)
        self.assertTrue(result['both_snapshot_rows_equal_and_whole_original_sha_equal'])

    def test_two_distinct_signed_appends_same_previous_original_form_local_siblings(self):
        alternate=self.f.add_review(3,'deferred_without_submission',
                                    'external_transaction_evidence_unavailable')
        alternate['position']=2
        new_b=self._make('b-sibling', [self.original_rows[0], alternate],
                         prior_sha=self.a_sha)
        # Both snapshots extend SAME independently pinned one-row parent.
        a_extension=self.b_file
        data=comparison.compare_ledgers(**self.params(
            branch_a_ledger_file=a_extension,
            expected_branch_a_ledger_sha256=self.b_sha,
            branch_a_prior_ledger_file=self.a_file,
            expected_branch_a_prior_ledger_sha256=self.a_sha,
            branch_b_ledger_file=new_b,
            expected_branch_b_ledger_sha256=case.sha(Path(new_b).read_bytes())))
        self.assertEqual(data['relationship'],
                         'different_one_row_appends_to_same_pinned_predecessor_unresolved')
        self.assertEqual(data['common_exact_entry_prefix_length'],1)
        self.assertEqual(data['first_differing_position_if_both_have_an_entry'],2)
        self.assertEqual(data['unique_signed_receipt_raw_sha_count'],3)
        self.assertFalse(data['verified_direct_one_entry_append'])
        self.assertFalse(data['cross_snapshot_reused_role_or_nonce_detected'])

    def test_same_two_reviews_in_different_order_are_not_new_independent_reviews(self):
        reversed_rows=[dict(row,position=i) for i,row in
                       enumerate(reversed(self.original_rows),1)]
        reordered=self._make('genesis-reordered',reversed_rows)
        first=self._make('genesis-order-original',self.original_rows)
        observed=self.compare(
            branch_a_ledger_file=first,
            expected_branch_a_ledger_sha256=case.sha(Path(first).read_bytes()),
            branch_a_prior_ledger_file=None,
            expected_branch_a_prior_ledger_sha256=ledger.ZERO,
            branch_b_ledger_file=reordered,
            expected_branch_b_ledger_sha256=case.sha(Path(reordered).read_bytes()),
            branch_b_prior_ledger_file=None,
            expected_branch_b_prior_ledger_sha256=ledger.ZERO)
        self.assertEqual(observed['unique_signed_receipt_raw_sha_count'],2)
        self.assertEqual(len(observed[
            'cross_snapshot_same_receipt_at_different_position_or_with_different_row']),2)
        self.assertEqual(observed['relationship'],
                         'divergent_locally_pinned_signed_review_lists_unresolved')

    def test_cross_snapshot_real_signed_reuse_of_ninth_id_is_reported(self):
        reused=self.f.add_review(3,'declined_without_submission',
                    'declined_by_local_reviewer',changes={
                        'ninth_responder_id':self.original_rows[1]['ninth_responder_id']})
        reused['position']=2
        new_b=self._make('signed-id-reused', [self.original_rows[0],reused],
                         prior_sha=self.a_sha)
        data=comparison.compare_ledgers(**self.params(
            branch_a_ledger_file=self.b_file,
            expected_branch_a_ledger_sha256=self.b_sha,
            branch_a_prior_ledger_file=self.a_file,
            expected_branch_a_prior_ledger_sha256=self.a_sha,
            branch_b_ledger_file=new_b,
            expected_branch_b_ledger_sha256=case.sha(Path(new_b).read_bytes())))
        self.assertTrue(data['cross_snapshot_reused_role_or_nonce_detected'])
        self.assertIn('ninth_responder_id',data[
            'cross_snapshot_distinct_receipts_with_reused_role_nonce_decision_or_path'][0]
            ['reused_fields'])
        self.assertFalse(data['two_pins_alone_prove_global_uniqueness_or_authoritative_order'])

    def test_matching_row_prefix_without_whole_ledger_bridge_is_not_ancestry(self):
        genesis_two=self._make('genesis-two-rows',self.original_rows)
        report=self.compare(
            branch_b_ledger_file=genesis_two,
            expected_branch_b_ledger_sha256=case.sha(Path(genesis_two).read_bytes()),
            branch_b_prior_ledger_file=None,
            expected_branch_b_prior_ledger_sha256=ledger.ZERO)
        self.assertEqual(report['common_exact_entry_prefix_length'],1)
        self.assertEqual(report['relationship'],
            'observed_common_row_prefix_unproven_snapshot_ancestry_unresolved')
        self.assertFalse(report['verified_direct_one_entry_append'])

    def test_same_signed_rows_with_different_unsigned_parent_header_not_same_original(self):
        genesis_two=self._make('genesis-two-signed-rows',self.original_rows)
        report=self.compare(
            branch_a_ledger_file=self.b_file,
            expected_branch_a_ledger_sha256=self.b_sha,
            branch_a_prior_ledger_file=self.a_file,
            expected_branch_a_prior_ledger_sha256=self.a_sha,
            branch_b_ledger_file=genesis_two,
            expected_branch_b_ledger_sha256=case.sha(Path(genesis_two).read_bytes()),
            branch_b_prior_ledger_file=None,
            expected_branch_b_prior_ledger_sha256=ledger.ZERO)
        self.assertEqual(report['relationship'],
            'same_signed_entries_different_unsigned_snapshot_metadata_unresolved')
        self.assertEqual(report['unique_signed_receipt_raw_sha_count'],2)
        self.assertFalse(report['both_snapshot_rows_equal_and_whole_original_sha_equal'])

    def test_cross_snapshot_reuse_of_signed_nonce_reported_without_erasing_evidence(self):
        reused=self.f.add_review(3,'declined_without_submission',
            'external_transaction_evidence_unavailable',changes={
                'response_challenge_sha256':self.original_rows[1]
                    ['response_challenge_sha256']})
        reused['position']=2
        alternate=self._make('signed-nonce-reuse',
                            [self.original_rows[0],reused],prior_sha=self.a_sha)
        report=self.compare(
            branch_a_ledger_file=self.b_file,
            expected_branch_a_ledger_sha256=self.b_sha,
            branch_a_prior_ledger_file=self.a_file,
            expected_branch_a_prior_ledger_sha256=self.a_sha,
            branch_b_ledger_file=alternate,
            expected_branch_b_ledger_sha256=case.sha(Path(alternate).read_bytes()))
        conflicts=report['cross_snapshot_distinct_receipts_with_reused_role_nonce_decision_or_path']
        self.assertTrue(report['cross_snapshot_reused_role_or_nonce_detected'])
        self.assertTrue(any('response_challenge_sha256' in c['reused_fields']
                            for c in conflicts))
        self.assertEqual(report['unique_signed_receipt_raw_sha_count'],3)

    def test_missing_or_wrong_independently_pinned_second_original_does_not_pass(self):
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.compare(expected_branch_b_ledger_sha256='ab'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'INDEPENDENT_PRIOR_LEDGER'):
            self.compare(expected_branch_b_prior_ledger_sha256='bc'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'PRIOR_LEDGER_WHOLE_ORIGINAL'):
            self.compare(branch_b_prior_ledger_file=None)

    def test_mismatched_scope_or_noncanonical_second_ledger_fails_closed(self):
        # Build another signed candidate whose unsigned request binding differs.
        self.f.meta['target_store_namespace_id']='different_target'
        alternate=self._make('wrong-target-genesis',self.original_rows[:1])
        with self.assertRaisesRegex(anchor.AnchorError,'DIFFERENT_SIGNED_EIGHTH_REQUEST'):
            self.compare(branch_b_ledger_file=alternate,
                         expected_branch_b_ledger_sha256=case.sha(Path(alternate).read_bytes()),
                         branch_b_prior_ledger_file=None,
                         expected_branch_b_prior_ledger_sha256=ledger.ZERO)

    def test_second_original_or_first_signature_changed_during_deep_verification_denied(self):
        observed=ledger.verify_ledger
        calls={'number':0}
        def mutate(**kwargs):
            result=observed(**kwargs)
            calls['number']+=1
            if calls['number']==2:
                with open(self.original_rows[0]['receipt_file'],'ab') as stream:
                    stream.write(b' ')
            return result
        with patch.object(ledger,'verify_ledger',side_effect=mutate):
            with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self.compare()
        self.assertEqual(calls['number'],2)

    def test_no_read_only_console_can_trigger_candidate_creation_or_remote_commit(self):
        data=self.compare()
        args=self.params()
        captures=[]
        def stub(cmd,**kwargs):
            captures.append(cmd)
            return 2,{'schema':comparison.RESULT_SCHEMA,
                      'command':'compare-ledgers',**data}
        with patch.object(console,'_command',side_effect=stub):
            output=StringIO()
            with redirect_stdout(output):
                rc=console.audit_hold_ledger_compare(
                    'DeliveryAudit','CompareOfflineReviewLedgers',**args)
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(output.getvalue())['exit_code'],2)
        self.assertEqual(captures[0][1:3],['-I','-B'])
        self.assertIn('compare-ledgers',captures[0])
        for prohibited in ('prepare-unsigned-ledger','--out','--private-key-file',
                           '--sign','--cas-endpoint','--write-token'):
            self.assertNotIn(prohibited,captures[0])
        with self.assertRaisesRegex(console.ConsoleError,'EC329_ONLY_DELIVERYAUDIT'):
            console.audit_hold_ledger_compare('DeliveryAudit','PrepareUnsigned',**args)
        forged={**data,'actual_external_nonexecution_or_hold_proven':True}
        with patch.object(console,'_command',return_value=(2,{
            'schema':comparison.RESULT_SCHEMA,'command':'compare-ledgers',**forged})):
            with self.assertRaisesRegex(console.ConsoleError,'MUST_BE_GROUNDED_AND_UNRESOLVED'):
                console.audit_hold_ledger_compare(
                    'DeliveryAudit','CompareOfflineReviewLedgers',**args)

    def test_standalone_cli_and_router_arg_parser(self):
        output=StringIO()
        with redirect_stdout(output):
            rc=operator.main(self.argv())
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(output.getvalue())['schema'],comparison.RESULT_SCHEMA)
        args=console.build_parser().parse_args(['audit-hold-ledger-compare',
            'DeliveryAudit','CompareOfflineReviewLedgers',*self.argv()[1:]])
        self.assertEqual(args.command,'audit-hold-ledger-compare')

    def test_fresh_isolated_program_rejects_deliberately_mocked_deep_history(self):
        root=Path(__file__).resolve().parents[2]
        argv=self.argv()
        for script,cmd in (
            (root/'scripts'/'ces_cas_review_compare.py',argv),
            (root/'scripts'/'ces_next.py',[
                'audit-hold-ledger-compare','DeliveryAudit',
                'CompareOfflineReviewLedgers',*argv[1:]])):
            with self.subTest(script=str(script)):
                p=subprocess.run([sys.executable,'-I','-B',str(script),*cmd],
                                 capture_output=True,text=True,timeout=80)
                self.assertEqual(p.returncode,4,p.stdout+p.stderr)
                doc=json.loads(p.stdout)
                self.assertFalse(doc['external_atomic_cas_or_worm_write_performed'])


if __name__=='__main__':
    unittest.main()
