#!/usr/bin/env python3
"""EC325 offline sibling conflict functionality with real 5th/6th/7th signing.

The reusable EC321/323 fixture mocks OLD EC317/318 historical replay only.
These scenarios do NOT prove the full real production EC294->EC325 chain.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from delivery_anchor import anchor
from fork_case_transport import case
from composite_fork_capsule import test_capsule_structure as fixture
from dual_channel_receipt import receipt as r
from scripts import ces_next as console
from . import proof as p, operator


class TwoPinnedSiblingReceiptCases(unittest.TestCase):
    def setUp(self):
        self.f = fixture.CompositeOriginalCaseAndAckCases(
            methodName='test_seal_preserves_both_exact_original_bytes_and_successful_replay')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.sealed = self.f.seal()
        self.dir = self.f.f.f.dir
        self.registry_id = 'ec325_registry'
        self.case_file = str(self.dir/'dispute-case.json')
        self.left = self._make('left', 'handoff_left')
        self.right = self._make('right', 'handoff_right')
        self.kw = dict(left=self.left, right=self.right,
                       registry_id=self.registry_id,
                       expected_sequence=1,
                       expected_prior_registry_sha256=r.ZERO,
                       prior_registry_file=None)

    def _make(self, label, handoff, *, seq=1, parent_sha=r.ZERO,
              parent_file=None, f=None, sealed=None):
        f = f or self.f
        sealed = sealed or self.sealed
        base=dict(f.trust,
                  expected_capsule_sha256=sealed['capsule_original_raw_sha256'],
                  handoff_id=handoff, registry_id=self.registry_id,
                  expected_sequence=seq,
                  expected_prior_registry_raw_sha256=parent_sha)
        values={}
        for role in ('origin','recipient'):
            filename=str(self.dir / (label+'-'+role+'.json'))
            made=r.prepare_channel(
                out=filename, channel_role=role,
                operator_id=label+'_'+role,
                **base)
            values[role+'_file']=filename
            values['expected_'+role+'_sha256']=made['channel_original_raw_sha256']
        file=str(self.dir/(label+'-head.json'))
        made=r.receive(out=file, capsule_file=f.outer,
                       registry_id=self.registry_id,expected_sequence=seq,
                       expected_prior_registry_sha256=parent_sha,
                       prior_registry_file=parent_file,**values)
        self.assertEqual(made['exit_code'],2)
        return dict(registry_file=file,
                    expected_registry_sha256=made['registry_snapshot_original_raw_sha256'],
                    capsule_file=f.outer,**values)

    def _create(self, **overrides):
        return p.create_case(out=self.case_file, **{**self.kw, **overrides})

    def _verify(self, **overrides):
        return p.verify_case(
            case_file=self.case_file,
            expected_case_sha256=case.sha(Path(self.case_file).read_bytes()),
            **{**self.kw, **overrides})

    def test_creates_two_sibling_case_with_true_current_signatures(self):
        result=self._create()
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['common_parent_original_raw_sha256'],r.ZERO)
        self.assertTrue(result['both_children_current_complete_original_signed_histories_replayed'])
        self.assertFalse(result['external_cas_worm_global_latest_or_fork_winner_proven'])
        self.assertFalse(result['case_is_a_new_signature_or_an_authoritative_cas_decision'])
        self.assertEqual(Path(self.case_file).stat().st_mode & 0o777,0o600)
        doc=json.loads(Path(self.case_file).read_bytes())
        self.assertEqual(len(doc['proposals']),2)
        self.assertEqual(set(doc),p.CASE_FIELDS)
        self.assertEqual(doc['proposals'][0]['registry_snapshot_original_raw_sha256'],
                         min(self.left['expected_registry_sha256'],
                             self.right['expected_registry_sha256']))
        self.assertEqual(result['dispute_case_original_raw_sha256'],
                         case.sha(Path(self.case_file).read_bytes()))
        self.assertEqual(self._verify()['exit_code'],2)

    def test_order_invariant_canonical_bytes_and_recomputed_case(self):
        a=p.derive(**self.kw)
        b=p.derive(**{**self.kw,'left':self.right,'right':self.left})
        self.assertEqual(r._raw(a),r._raw(b))
        self._create()
        self.assertEqual(self._verify(left=self.right,right=self.left)['exit_code'],2)

    def test_same_head_is_not_a_dispute(self):
        with self.assertRaisesRegex(anchor.AnchorError,'SAME_RAW_RECEIPT_HEAD'):
            p.derive(**{**self.kw,'right':self.left})
        self.assertFalse(Path(self.case_file).exists())

    def test_different_pinned_parent_fails_even_if_both_have_real_signature(self):
        with self.assertRaisesRegex(anchor.AnchorError,'REGISTRY_AND_BOUNDED_PARENT'):
            p.derive(**{**self.kw,
                        'expected_prior_registry_sha256':'a1'*32})
        self.assertFalse(Path(self.case_file).exists())

    def test_wrong_outside_pin_is_not_replaceable_with_case_report_assertion(self):
        damaged=dict(self.right,expected_registry_sha256='bb'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            p.derive(**{**self.kw,'right':damaged})
        self.assertFalse(Path(self.case_file).exists())

    def test_forged_case_even_when_repinned_cannot_pass(self):
        self._create()
        doc=json.loads(Path(self.case_file).read_bytes())
        doc['proposals'][0]['handoff_id']='fake_handoff'
        Path(self.case_file).write_bytes(r._raw(doc))
        Path(self.case_file).chmod(0o600)
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_TWO_REVERIFIED'):
            self._verify()

    def test_extra_case_key_denied_even_with_new_raw_sha(self):
        self._create()
        doc=json.loads(Path(self.case_file).read_bytes())
        doc['signed_cas_winner']='left'
        Path(self.case_file).write_bytes(r._raw(doc))
        Path(self.case_file).chmod(0o600)
        with self.assertRaises(anchor.AnchorError):
            self._verify()

    def test_noncanonical_case_whitespace_denied_even_with_new_sha(self):
        self._create()
        with open(self.case_file,'ab') as f:
            f.write(b' ')
        with self.assertRaisesRegex(anchor.AnchorError,'NONCANONICAL'):
            self._verify()

    def test_source_changes_after_case_creation_are_denied(self):
        self._create()
        with open(self.right['registry_file'],'ab') as f:
            f.write(b' ')
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self._verify()

    def test_existing_output_never_overwritten(self):
        self._create()
        before=Path(self.case_file).read_bytes()
        with self.assertRaisesRegex(anchor.AnchorError,'OUTPUT_ALREADY_EXISTS'):
            self._create()
        self.assertEqual(before,Path(self.case_file).read_bytes())

    def test_report_path_overlapping_original_is_refused(self):
        with self.assertRaisesRegex(anchor.AnchorError,'CASE_FILE_CANNOT_OVERLAP'):
            p.derive(extra_file=self.left['registry_file'],**self.kw)

    def test_operator_cli_in_process_and_invalid_role_rejected(self):
        args=self._args(command='create-case')
        output=StringIO()
        with redirect_stdout(output):
            rc=operator.main(args)
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(output.getvalue())['schema'],p.RESULT_SCHEMA)
        output=StringIO()
        with redirect_stdout(output):
            rc=operator.main(self._args(command='verify-case'))
        self.assertEqual(rc,2)
        self.assertFalse(json.loads(output.getvalue())['external_cas_worm_global_latest_or_fork_winner_proven'])
        output=StringIO()
        with redirect_stdout(output):
            rc=operator.main(self._args(command='verify-case',
                        replacements={'expected-case-sha256':'aa'*32}))
        self.assertEqual(rc,3)
        self.assertFalse(json.loads(output.getvalue())['two_complete_original_signed_histories_accepted'])

    def _args(self, *, command, replacements=None):
        kw=dict(replacements or {})
        out=[command]
        params={'registry-id':self.registry_id,'expected-sequence':'1',
                'expected-prior-registry-sha256':r.ZERO}
        params.update({'out':self.case_file} if command=='create-case' else {
            'case-file':self.case_file,
            'expected-case-sha256':case.sha(Path(self.case_file).read_bytes())})
        for side, doc in (('left',self.left),('right',self.right)):
            for key,val in doc.items():
                params[side+'-'+key.replace('_','-')]=val
        params.update(kw)
        for k,v in params.items():
            out.extend(('--'+k,str(v)))
        return out

    def test_console_only_fixed_isolated_verify_case_and_rejection(self):
        self._create()
        actual=self._verify()
        result={'schema':p.RESULT_SCHEMA,'command':'verify-case',**actual}
        kw=dict(self.kw)
        captured=[]
        def fake_run(command,**opts):
            captured.append(command)
            return 2,result
        with patch.object(console,'_command',side_effect=fake_run):
            buf=StringIO()
            with redirect_stdout(buf):
                rc=console.audit_receipt_siblings(
                    'DeliveryAudit','VerifyOfflineReceiptSiblingDispute',
                    case_file=self.case_file,
                    expected_case_sha256=case.sha(Path(self.case_file).read_bytes()),
                    pretty=False,**kw)
            self.assertEqual(rc,2)
            self.assertEqual(json.loads(buf.getvalue())['exit_code'],2)
        cmd=captured[0]
        self.assertEqual(cmd[1:3],['-I','-B'])
        self.assertIn('verify-case',cmd)
        self.assertNotIn('create-case',cmd)
        self.assertNotIn('--out',cmd)
        with self.assertRaisesRegex(console.ConsoleError,'ONLY_DELIVERYAUDIT'):
            console.audit_receipt_siblings(
                'DeliveryAudit','CreateDisputeCase',
                case_file=self.case_file,expected_case_sha256='ab'*32,
                pretty=False,**kw)

    def test_multi_record_same_parent_requires_original_pinned_previous_snapshot(self):
        # A separate genuine 7th-signed capsule for row 2 avoids reusing
        # the same capsule SHA already present in the common parent lineage.
        f2=fixture.CompositeOriginalCaseAndAckCases(
            methodName='test_seal_preserves_both_exact_original_bytes_and_successful_replay')
        f2.setUp()
        self.addCleanup(f2.doCleanups)
        sealed2=f2.seal()
        prior=self.left['registry_file']
        prior_sha=self.left['expected_registry_sha256']
        # The second suite's old signatures are generated independently;
        # its own deep EC317/318 replay is still mocked by its fixture.
        left=self._make('second_left','handoff_second_left',seq=2,
                        parent_sha=prior_sha,parent_file=prior,
                        f=f2,sealed=sealed2)
        right=self._make('second_right','handoff_second_right',seq=2,
                         parent_sha=prior_sha,parent_file=prior,
                         f=f2,sealed=sealed2)
        opts={**self.kw,'left':left,'right':right,
              'expected_sequence':2,
              'expected_prior_registry_sha256':prior_sha,
              'prior_registry_file':prior}
        self.assertEqual(p.create_case(out=self.case_file,**opts)['exit_code'],2)
        self.assertEqual(p.verify_case(
            case_file=self.case_file,
            expected_case_sha256=case.sha(Path(self.case_file).read_bytes()),
            **opts)['exit_code'],2)
        with self.assertRaisesRegex(anchor.AnchorError,'GENESIS_HAS_NO_PRIOR_FILE'):
            p.derive(**{**opts,'prior_registry_file':None})
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            p.derive(**{**opts,
                        'expected_prior_registry_sha256':'ab'*32})

    def test_tampered_first_proposal_source_during_second_history_fails_closed(self):
        # Inject a source swap ONLY after the first child's successful replay.
        original=p._check_actual_signed_history
        calls=[0]
        def mutate_on_second(side,**kwargs):
            calls[0]+=1
            if calls[0]==2:
                with open(self.left['origin_file'],'ab') as f:
                    f.write(b' ')
            return original(side,**kwargs)
        with patch.object(p,'_check_actual_signed_history',side_effect=mutate_on_second):
            with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self._create()
        self.assertFalse(Path(self.case_file).exists())


if __name__=='__main__':
    unittest.main()
