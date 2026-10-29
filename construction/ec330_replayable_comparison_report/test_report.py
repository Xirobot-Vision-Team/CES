#!/usr/bin/env python3
"""EC330 report semantics tests. Eighth/ninth Ed25519 signatures are genuine;
inherited EC317/318 old deep signatures are MOCKED by the EC321 fixture.
Do NOT treat these tests as production unmocked EC294->330 validation.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from unittest.mock import patch

from ec295_delivery_anchor import anchor
from ec321_fork_case_transport import case
from ec329_offline_ledger_comparison import test_comparison as old_tests
from scripts import ces_next
from . import operator, report


class ReplayablePinnedComparisonReportTests(unittest.TestCase):
    def setUp(self):
        self.old = old_tests.GenuineDualLedgerComparisonTests(
            methodName='test_two_original_true_signature_chain_replays_direct_append')
        self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        self.params = self.old.params()
        self.out = str(self.old.folder/'ec330-unsigned-comparison-original.json')

    def create(self):
        return report.create_report(out=self.out,**self.params)

    def verify(self,pin=None,**changes):
        return report.verify_report(
            report_file=self.out,
            expected_report_sha256=pin or case.sha(Path(self.out).read_bytes()),
            **dict(self.params,**changes))

    def argv(self, command, **option_overrides):
        args = self.params.copy()
        if command == 'create-report':
            args['out'] = self.out
        else:
            args['report_file'] = self.out
            args['expected_report_sha256'] = case.sha(Path(self.out).read_bytes())
        args.update(option_overrides)
        tokens = [command]
        for name,value in args.items():
            if name in ('left','right') or value is None: continue
            tokens.extend(('--'+name.replace('_','-'),str(value)))
        for side in ('left','right'):
            for name,value in args[side].items():
                tokens.extend(('--'+side+'-'+name.replace('_','-'),str(value)))
        return tokens

    def test_real_eighth_ninth_signed_replay_report_exact_and_owner_private(self):
        made=self.create()
        self.assertEqual(made['exit_code'],2)
        self.assertEqual(made['relationship'],
                         'verified_one_entry_append_from_a_to_b_unresolved')
        self.assertEqual(made['unique_signed_receipt_raw_sha_count'],2)
        raw=Path(self.out).read_bytes()
        self.assertEqual(case.sha(raw),made['report_original_raw_sha256'])
        self.assertTrue(raw.endswith(b'\n'))
        self.assertEqual(os.stat(self.out).st_mode & 0o777,0o600)
        obj=json.loads(raw)
        self.assertEqual(set(obj),{'schema','interpretation',
            'source_pin_claims_not_self_authenticating','recomputed_ec329_comparison',
            'offline_unresolved_exit_code',*report.REMOTE_FALSE_FIELDS})
        self.assertNotIn(self.out,raw.decode('utf8'))
        self.assertNotIn(self.params['request_file'],raw.decode('utf8'))
        self.assertEqual(raw,report.receipt._raw(obj))
        self.assertEqual(obj['recomputed_ec329_comparison']['exit_code'],2)
        result=self.verify(made['report_original_raw_sha256'])
        self.assertTrue(result['original_report_exactly_reconstructed_from_pinned_inputs'])
        self.assertTrue(result['all_current_signed_histories_genuinely_replayed_locally'])
        self.assertTrue(all(result[k] is False for k in report.REMOTE_FALSE_FIELDS))

    def test_second_report_deterministic_across_private_output_paths(self):
        self.create()
        original=Path(self.out).read_bytes()
        other=str(self.old.folder/'ec330-other-independent-local-candidate.json')
        made=report.create_report(out=other,**self.params)
        self.assertEqual(Path(other).read_bytes(),original)
        self.assertEqual(made['report_original_raw_sha256'],case.sha(original))
        self.assertEqual(report.verify_report(report_file=other,
             expected_report_sha256=made['report_original_raw_sha256'],
             **self.params)['exit_code'],2)

    def test_output_exclusive_and_disallows_aliasing_or_symlink(self):
        self.create()
        original=Path(self.out).read_bytes()
        with self.assertRaisesRegex(anchor.AnchorError,'CANDIDATE_OUTPUT_ALREADY_EXISTS'):
            self.create()
        self.assertEqual(Path(self.out).read_bytes(),original)
        with self.assertRaisesRegex(anchor.AnchorError,'DISTINCT_NORMALIZED'):
            report.create_report(out=self.params['request_file'],**self.params)
        link=str(self.old.folder/'ec330-symlink.json')
        os.symlink(self.out,link)
        with self.assertRaisesRegex(anchor.AnchorError,'ALREADY_EXISTS'):
            report.create_report(out=link,**self.params)

    def test_wrong_whole_raw_pin_wrong_externally_pinned_trust_or_missing_report(self):
        made=self.create()
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.verify('ab'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'REPORT_PIN_CLAIMS'):
            self.verify(made['report_original_raw_sha256'],
                        eighth_signer_id='another_ninth_claim')
        with self.assertRaisesRegex(anchor.AnchorError,'WHOLE_RAW_SHA_REQUIRED'):
            self.verify('0'*64)
        os.unlink(self.out)
        with self.assertRaises((anchor.AnchorError, OSError)):
            self.verify(made['report_original_raw_sha256'])

    def test_repinning_changed_report_cannot_forge_remote_success(self):
        self.create()
        obj=json.loads(Path(self.out).read_bytes())
        obj['external_atomic_cas_or_worm_write_performed']=True
        Path(self.out).write_bytes(report.receipt._raw(obj))
        # Even a separately supplied new SHA cannot turn forged fields into proof.
        with self.assertRaisesRegex(anchor.AnchorError,
                                    'REPORT_SCHEMA_AND_UNRESOLVED_SAFETY_FLAGS'):
            self.verify()
        self.assertFalse(obj['report_is_signed_or_organizationally_authorized'])

    def test_mutated_valid_looking_comparison_still_fails_full_replay(self):
        self.create()
        obj=json.loads(Path(self.out).read_bytes())
        obj['recomputed_ec329_comparison']['relationship']='fake_unresolved'
        Path(self.out).write_bytes(report.receipt._raw(obj))
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EXACTLY_RECONSTRUCTED'):
            self.verify()

    def test_report_does_not_trust_its_own_original_claims(self):
        self.create()
        obj=json.loads(Path(self.out).read_bytes())
        obj['source_pin_claims_not_self_authenticating'][
            'branch_a_ledger_original_raw_sha256']='ab'*32
        Path(self.out).write_bytes(report.receipt._raw(obj))
        with self.assertRaisesRegex(anchor.AnchorError,'REPORT_PIN_CLAIMS'):
            self.verify()
        self.assertEqual(self.params['expected_branch_a_ledger_sha256'],
                         self.old.a_sha)

    def test_noncanonical_whitespace_or_read_permission_is_rejected(self):
        self.create()
        raw=Path(self.out).read_bytes()
        Path(self.out).write_bytes(raw+b' ')
        with self.assertRaisesRegex(anchor.AnchorError,'NONCANONICAL'):
            self.verify()
        Path(self.out).write_bytes(raw)
        os.chmod(self.out,0o644)
        with self.assertRaises((anchor.AnchorError, OSError)):
            self.verify()

    def test_changed_signed_ninth_original_after_report_must_fail_closed(self):
        self.create()
        receipt_file=self.old.original_rows[0]['receipt_file']
        with open(receipt_file,'ab') as f: f.write(b' ')
        with self.assertRaisesRegex(anchor.AnchorError,
                                    'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.verify()

    def test_late_signed_original_mutation_in_full_verification_is_detected(self):
        self.create()
        from ec329_offline_ledger_comparison import comparison
        native=comparison.compare_ledgers
        def after_success(**kw):
            result=native(**kw)
            with open(self.old.original_rows[0]['receipt_file'],'ab') as f:
                f.write(b' ')
            return result
        with patch.object(comparison,'compare_ledgers',side_effect=after_success):
            with self.assertRaisesRegex(anchor.AnchorError,
                                        'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self.verify()

    def test_report_mutation_after_signed_replay_is_caught_by_second_read(self):
        self.create()
        from ec329_offline_ledger_comparison import comparison
        native=comparison.compare_ledgers
        def after_success(**kw):
            result=native(**kw)
            with open(self.out,'ab') as f: f.write(b' ')
            return result
        with patch.object(comparison,'compare_ledgers',side_effect=after_success):
            with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self.verify()

    def test_candidate_removed_if_postwrite_signed_source_repin_fails(self):
        from ec329_offline_ledger_comparison import comparison
        real_check=comparison._recheck_originals
        calls={'n':0}
        def check(**kw):
            calls['n']+=1
            if calls['n']==3:
                raise anchor.AnchorError('EC330_TEST_FINAL_REPIN_FAILED',
                                         'permission_denied')
            return real_check(**kw)
        # 1 in original EC329 compare, 2 before write, 3 after write.
        with patch.object(comparison,'_recheck_originals',side_effect=check):
            with self.assertRaisesRegex(anchor.AnchorError,'TEST_FINAL_REPIN_FAILED'):
                self.create()
        self.assertFalse(Path(self.out).exists())
        self.assertEqual(calls['n'],3)

    def test_standalone_cli_both_commands_return_exit2_and_no_success(self):
        out=StringIO()
        with redirect_stdout(out):
            rc=operator.main(self.argv('create-report'))
        self.assertEqual(rc,2)
        created=json.loads(out.getvalue())
        self.assertEqual(created['schema'],report.RESULT_SCHEMA)
        out=StringIO()
        with redirect_stdout(out):
            rc=operator.main(self.argv('verify-report'))
        self.assertEqual(rc,2)
        self.assertTrue(json.loads(out.getvalue())[
            'original_report_exactly_reconstructed_from_pinned_inputs'])

    def test_unified_action_console_only_fixed_isolated_verify_and_no_writer(self):
        made=self.create()
        expected=[]
        def stub(cmd,**kwargs):
            expected.append(cmd)
            return 2,{'command':'verify-report',
                      **report._success(
                          json.loads(Path(self.out).read_bytes()),
                          Path(self.out).read_bytes(),verified=True)}
        with patch.object(ces_next,'_command',side_effect=stub):
            output=StringIO()
            with redirect_stdout(output):
                rc=ces_next.audit_hold_ledger_report(
                    'DeliveryAudit','VerifyReplayableOfflineLedgerComparisonReport',
                    report_file=self.out,
                    expected_report_sha256=made['report_original_raw_sha256'],
                    **self.params)
        self.assertEqual(rc,2)
        self.assertTrue(json.loads(output.getvalue())[
            'original_report_exactly_reconstructed_from_pinned_inputs'])
        self.assertEqual(expected[0][1:3],['-I','-B'])
        self.assertIn('verify-report',expected[0])
        for banned in ('create-report','--out','--private-key-file',
                       'sign-request','--cas-endpoint'):
            self.assertNotIn(banned,expected[0])
        with self.assertRaisesRegex(ces_next.ConsoleError,
                                    'ONLY_DELIVERYAUDIT_VERIFY'):
            ces_next.audit_hold_ledger_report(
                'DeliveryAudit','CreateUnsignedReport',
                report_file=self.out,
                expected_report_sha256=made['report_original_raw_sha256'],
                **self.params)
        fake={**report._success(json.loads(Path(self.out).read_bytes()),
                                Path(self.out).read_bytes(),verified=True),
              'command':'verify-report','report_is_signed_or_organizationally_authorized':True}
        with patch.object(ces_next,'_command',return_value=(2,fake)):
            with self.assertRaisesRegex(ces_next.ConsoleError,'NOT_GROUNDED'):
                ces_next.audit_hold_ledger_report(
                    'DeliveryAudit','VerifyReplayableOfflineLedgerComparisonReport',
                    report_file=self.out,
                    expected_report_sha256=made['report_original_raw_sha256'],
                    **self.params)

    def test_unified_parser_is_readonly_and_input_replay_required(self):
        self.create()
        args=ces_next.build_parser().parse_args([
            'audit-hold-ledger-report','DeliveryAudit',
            'VerifyReplayableOfflineLedgerComparisonReport',
            *self.argv('verify-report')[1:]])
        self.assertEqual(args.command,'audit-hold-ledger-report')
        from contextlib import redirect_stderr
        with self.assertRaises(SystemExit):
            with redirect_stderr(StringIO()):
                ces_next.build_parser().parse_args([
                    'audit-hold-ledger-report','DeliveryAudit',
                    'VerifyReplayableOfflineLedgerComparisonReport',
                    *self.argv('verify-report')[1:],
                    '--out',self.out])

    def test_real_isolated_cli_and_console_both_deny_mocked_old_history(self):
        self.create()
        root=Path(__file__).resolve().parents[2]
        args=self.argv('verify-report')
        for exe, cmd in (
            (root/'scripts'/'ces_cas_review_report.py',args),
            (root/'scripts'/'ces_next.py',[
                'audit-hold-ledger-report','DeliveryAudit',
                'VerifyReplayableOfflineLedgerComparisonReport',*args[1:]])):
            with self.subTest(command=str(exe)):
                p=subprocess.run([sys.executable,'-I','-B',str(exe),*cmd],
                                 capture_output=True,text=True,timeout=80)
                self.assertEqual(p.returncode,4,p.stdout+p.stderr)
                doc=json.loads(p.stdout)
                self.assertEqual(doc['exit_code'],4)
                self.assertFalse(doc.get(
                    'actual_external_nonexecution_or_hold_proven',False))


if __name__=='__main__':
    unittest.main()
