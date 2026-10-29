#!/usr/bin/env python3
"""EC326 focused real eighth + fifth/sixth/seventh Ed25519 scenarios.

The reused EC321 structure fixture mocks EC317/318 deep replay ONLY. This is
not a full authentic production EC294->326 integration or external CAS test.
"""
from __future__ import annotations
from contextlib import redirect_stdout
from io import StringIO
import json
import os
import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from delivery_anchor import anchor
from fork_case_transport import case
from dual_channel_receipt import receipt as r
from offline_receipt_siblings import test_siblings as older_fixture
from scripts import ces_next as console
from . import hold, operator


class IndependentEighthConflictHoldTests(unittest.TestCase):
    def setUp(self):
        self.f = older_fixture.TwoPinnedSiblingReceiptCases(
            methodName='test_creates_two_sibling_case_with_true_current_signatures')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f._create()
        self.key=Ed25519PrivateKey.generate()
        self.pub=self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()
        self.secret=str(self.f.dir/'ec326-eighth-secret.bin')
        Path(self.secret).write_bytes(self.key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()))
        Path(self.secret).chmod(0o600)
        self.out=str(self.f.dir/'conditional-hold-request.json')
        self.params={
            **self.f.kw,
            'case_file': self.f.case_file,
            'expected_case_sha256':case.sha(Path(self.f.case_file).read_bytes()),
            'request_id':'ec326_conflict_hold',
            'target_store_namespace_id':'test_external_namespace',
            'eighth_signer_id':'new_eighth_hold_signer',
            'eighth_signer_public_hex':self.pub,
            'request_challenge_sha256':case.sha(b'EC326 isolated role challenge 2026'),
        }

    def sign(self,**changes):
        return hold.sign_request(**{**self.params,
             'out':self.out,'private_key_file':self.secret,**changes})

    def verify(self,**changes):
        return hold.verify_request(
            request_file=self.out,
            expected_request_sha256=case.sha(Path(self.out).read_bytes()),
            **{**self.params,**changes})

    def test_sign_real_eighth_key_after_full_both_branch_replays(self):
        signed=self.sign()
        self.assertEqual(signed['exit_code'],2)
        self.assertFalse(signed['external_cas_worm_global_latest_winner_or_commit_proven'])
        self.assertEqual(Path(self.out).stat().st_mode & 0o777,0o600)
        req=json.loads(Path(self.out).read_bytes())
        self.assertEqual(req['schema'],hold.SIGNED_SCHEMA)
        self.assertEqual(req['claim']['requested_operation'],hold.OPERATION)
        self.assertEqual(req['claim']['proposed_competing_child_raw_sha256'],sorted((
            self.f.left['expected_registry_sha256'],
            self.f.right['expected_registry_sha256'])))
        self.assertEqual(self.verify()['exit_code'],2)

    def test_reversed_siblings_get_same_signed_claim_and_signature(self):
        self.sign()
        original=Path(self.out).read_bytes()
        Path(self.out).unlink()
        self.sign(left=self.f.right,right=self.f.left)
        self.assertEqual(Path(self.out).read_bytes(),original)
        self.assertEqual(self.verify(left=self.f.right,right=self.f.left)['exit_code'],2)

    def test_seventh_role_public_key_reuse_denied_before_private_key_read(self):
        with patch.object(hold.io,'private_from_file',side_effect=AssertionError(
                'secret read before authorization')):
            with self.assertRaisesRegex(anchor.AnchorError,'EIGHTH_SIGNER_MUST_NOT_REUSE'):
                self.sign(eighth_signer_public_hex=
                    self.f.f.trust['seventh_receiver_public_hex'])
        self.assertFalse(Path(self.out).exists())

    def test_seventh_name_reuse_denied(self):
        with self.assertRaisesRegex(anchor.AnchorError,'EIGHTH_SIGNER_MUST_NOT_REUSE'):
            self.sign(eighth_signer_id=self.f.f.trust['seventh_receiver_id'])

    def test_visible_seventh_challenge_replay_denied(self):
        with self.assertRaisesRegex(anchor.AnchorError,'EIGHTH_NONCE_MUST_NOT_REUSE'):
            self.sign(request_challenge_sha256=
                    self.f.f.trust['seventh_receiver_challenge_sha256'])

    def test_old_fifth_registrar_role_reuse_denied(self):
        with self.assertRaisesRegex(anchor.AnchorError,'EIGHTH_SIGNER_MUST_NOT_REUSE'):
            self.sign(eighth_signer_public_hex=
                    self.f.f.trust['registrar_public_hex'])

    def test_wrong_private_key_cannot_sign_as_selected_eighth(self):
        another=Ed25519PrivateKey.generate()
        raw=another.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
        Path(self.secret).write_bytes(raw)
        with self.assertRaisesRegex(anchor.AnchorError,'PRIVATE_KEY_NOT_EQUAL'):
            self.sign()
        self.assertFalse(Path(self.out).exists())

    def test_no_old_case_validation_cannot_issue_signature(self):
        with patch.object(hold.proof,'verify_case',side_effect=anchor.AnchorError(
                'EC325_CASE_REPLAY_FAILED','permission_denied')):
            with patch.object(hold.io,'private_from_file',side_effect=AssertionError(
                    'read secret before proof')):
                with self.assertRaisesRegex(anchor.AnchorError,'EC325_CASE_REPLAY_FAILED'):
                    self.sign()
        self.assertFalse(Path(self.out).exists())

    def test_forged_signature_even_after_repin_rejected(self):
        self.sign()
        doc=json.loads(Path(self.out).read_bytes())
        doc['signature_ed25519']='0'*128
        Path(self.out).write_bytes(r._raw(doc))
        with self.assertRaisesRegex(anchor.AnchorError,'ED25519_SIGNATURE_NOT_AUTHENTIC'):
            self.verify()

    def test_re_signed_fake_cas_success_cannot_pass_even_with_new_raw_sha(self):
        self.sign()
        doc=json.loads(Path(self.out).read_bytes())
        doc['claim']['remote_latest_winner_or_commit_receipt_proven']=True
        doc['signature_ed25519']=self.key.sign(
            hold.SIGN_DOMAIN+hold.reg.canonical(doc['claim'])).hex()
        Path(self.out).write_bytes(r._raw(doc))
        with self.assertRaisesRegex(anchor.AnchorError,'NO_FAKE_REMOTE_SUCCESS'):
            self.verify()

    def test_new_valid_signature_over_changed_expected_parent_is_refused(self):
        self.sign()
        doc=json.loads(Path(self.out).read_bytes())
        doc['claim']['expected_remote_parent_original_raw_sha256']='be'*32
        doc['signature_ed25519']=self.key.sign(
            hold.SIGN_DOMAIN+hold.reg.canonical(doc['claim'])).hex()
        Path(self.out).write_bytes(r._raw(doc))
        with self.assertRaisesRegex(anchor.AnchorError,'SIGNED_REQUEST_NOT_EQUAL_EXPLICIT'):
            self.verify()

    def test_request_target_nonce_and_signer_pin_required_outside_request(self):
        self.sign()
        for changes in (
            {'request_id':'other_request'},
            {'target_store_namespace_id':'other_namespace'},
            {'request_challenge_sha256':'bf'*32},
            {'eighth_signer_public_hex':'bd'*32},
            {'expected_case_sha256':'bc'*32},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises((anchor.AnchorError,hold.io.HostError)):
                    self.verify(**changes)

    def test_missing_original_case_rejected_even_with_true_eighth_signature(self):
        self.sign()
        Path(self.f.case_file).unlink()
        with self.assertRaises((anchor.AnchorError,hold.io.HostError)):
            self.verify()

    def test_no_overwrite_or_private_key_original_alias(self):
        self.sign()
        saved=Path(self.out).read_bytes()
        with self.assertRaisesRegex(anchor.AnchorError,'OUTPUT_EXISTS'):
            self.sign()
        self.assertEqual(Path(self.out).read_bytes(),saved)
        with self.assertRaisesRegex(anchor.AnchorError,'CANNOT_OVERLAP'):
            self.sign(out=self.f.case_file)
        with self.assertRaisesRegex(anchor.AnchorError,'CANNOT_OVERLAP'):
            self.sign(private_key_file=self.f.left['capsule_file'])

    def test_input_mutation_during_roles_inspection_rejected(self):
        original=hold._visible_roles_and_challenges
        calls=[0]
        def mutate_second(**kwargs):
            calls[0]+=1
            result=original(**kwargs)
            if calls[0]==2:
                with open(self.f.left['recipient_file'],'ab') as stream:
                    stream.write(b' ')
            return result
        with patch.object(hold,'_visible_roles_and_challenges',side_effect=mutate_second):
            with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self.sign()
        self.assertFalse(Path(self.out).exists())

    def _argv(self,cmd,**changes):
        values={k.replace('_','-'):v for k,v in self.params.items()
                if k not in ('left','right','prior_registry_file')}
        values['expected-sequence']=str(values['expected-sequence'])
        for label,side in (('left',self.f.left),('right',self.f.right)):
            values.update({label+'-'+k.replace('_','-'):v for k,v in side.items()})
        if cmd=='sign-request':
            values.update({'out':self.out,'private-key-file':self.secret})
        else:
            values.update({'request-file':self.out,
                'expected-request-sha256':case.sha(Path(self.out).read_bytes())})
        values.update(changes)
        argv=[cmd]
        for key,value in values.items():
            argv.extend(('--'+key,str(value)))
        return argv

    def test_standalone_cli_sign_and_verify_exit_two_denials_not_success(self):
        out=StringIO()
        with redirect_stdout(out):
            self.assertEqual(operator.main(self._argv('sign-request')),2)
        self.assertEqual(json.loads(out.getvalue())['schema'],hold.RESULT_SCHEMA)
        out=StringIO()
        with redirect_stdout(out):
            self.assertEqual(operator.main(self._argv('verify-request')),2)
        self.assertFalse(json.loads(out.getvalue())[
            'external_cas_worm_global_latest_winner_or_commit_proven'])
        out=StringIO()
        with redirect_stdout(out):
            self.assertEqual(operator.main(self._argv('verify-request',
                **{'expected-request-sha256':'de'*32})),3)
        self.assertFalse(json.loads(out.getvalue())[
            'signed_request_and_both_signed_histories_accepted'])

    def test_unified_console_only_exposes_isolated_verifier_not_signing(self):
        self.sign()
        result=self.verify()
        calls=[]
        def stub(cmd,**opts):
            calls.append(cmd)
            return 2,{'schema':hold.RESULT_SCHEMA,'command':'verify-request',**result}
        args=dict(self.params,request_file=self.out,
                  expected_request_sha256=case.sha(Path(self.out).read_bytes()))
        with patch.object(console,'_command',side_effect=stub):
            out=StringIO()
            with redirect_stdout(out):
                rc=console.audit_conflict_hold(
                    'DeliveryAudit','VerifySignedConditionalConflictHoldRequest',
                    pretty=False,**args)
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(out.getvalue())['exit_code'],2)
        self.assertEqual(calls[0][1:3],['-I','-B'])
        self.assertIn('verify-request',calls[0])
        self.assertNotIn('sign-request',calls[0])
        self.assertNotIn('--private-key-file',calls[0])
        self.assertNotIn('--out',calls[0])
        with self.assertRaisesRegex(console.ConsoleError,'EC326_ONLY_DELIVERYAUDIT'):
            console.audit_conflict_hold('DeliveryAudit','SignRequest',**args)


    def test_second_sequence_original_parent_bound_to_signed_hold(self):
        from composite_fork_capsule import test_capsule_structure as old_case_fixture
        f2=old_case_fixture.CompositeOriginalCaseAndAckCases(
            methodName='test_seal_preserves_both_exact_original_bytes_and_successful_replay')
        f2.setUp()
        self.addCleanup(f2.doCleanups)
        sealed2=f2.seal()
        prior=self.f.left['registry_file']
        prior_sha=self.f.left['expected_registry_sha256']
        second_left=self.f._make('ec326_nextleft','handoff_326_left',
            seq=2,parent_sha=prior_sha,parent_file=prior,f=f2,sealed=sealed2)
        second_right=self.f._make('ec326_nextright','handoff_326_right',
            seq=2,parent_sha=prior_sha,parent_file=prior,f=f2,sealed=sealed2)
        case2=str(self.f.dir/'ec326-second-sequence-case.json')
        values={**self.f.kw,'left':second_left,'right':second_right,
            'expected_sequence':2,'expected_prior_registry_sha256':prior_sha,
            'prior_registry_file':prior}
        hold.proof.create_case(out=case2,**values)
        updated={**values,'case_file':case2,
                 'expected_case_sha256':case.sha(Path(case2).read_bytes())}
        self.assertEqual(self.sign(**updated)['exit_code'],2)
        doc=json.loads(Path(self.out).read_bytes())
        self.assertEqual(doc['claim']['sequence'],2)
        self.assertEqual(doc['claim']['expected_remote_parent_original_raw_sha256'],prior_sha)
        self.assertEqual(self.verify(**updated)['exit_code'],2)
        with self.assertRaisesRegex(anchor.AnchorError,'GENESIS_HAS_NO_PRIOR_FILE'):
            self.verify(**{**updated,'prior_registry_file':None})


    def test_actual_isolated_process_refuses_mocked_deep_history(self):
        self.sign()
        root=Path(__file__).resolve().parents[2]
        args=self._argv('verify-request')[1:]
        script=root/'scripts'/'ces_cas_conflict_hold.py'
        result=subprocess.run([sys.executable,'-I','-B',str(script),
                               'verify-request',*args],
                              capture_output=True,text=True,timeout=50)
        # The inherited fixture mocks old EC317/318 ONLY in-process; a fresh
        # -I -B subprocess correctly FAILS CLOSED on the unmocked old history.
        self.assertEqual(result.returncode,4,result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['schema'],hold.DENIAL_SCHEMA)
        console_script=root/'scripts'/'ces_next.py'
        result=subprocess.run([sys.executable,'-I','-B',str(console_script),
                 'audit-conflict-hold','DeliveryAudit',
                 'VerifySignedConditionalConflictHoldRequest',*args],
                 capture_output=True,text=True,timeout=50)
        self.assertEqual(result.returncode,4,result.stdout+result.stderr)
        self.assertFalse(json.loads(result.stdout)[
            'external_cas_worm_global_latest_winner_or_commit_proven'])


if __name__=='__main__':
    unittest.main()
