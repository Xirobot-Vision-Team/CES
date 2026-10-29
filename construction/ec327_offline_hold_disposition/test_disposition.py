#!/usr/bin/env python3
"""EC327 genuine ninth and eighth Ed25519 with explicit mocked deep legacy history.

The existing EC326 fixture emulates EC317/318 for speed. Therefore these
focused cases are NOT a production EC294->327 unmocked signed-chain pass.
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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ec295_delivery_anchor import anchor
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt as r
from ec326_conditional_conflict_hold import hold
from ec326_conditional_conflict_hold import test_hold as original_fixture
from scripts import ces_next as console
from . import disposition as d, operator


class IndependentNinthNoExecutionDispositionTests(unittest.TestCase):
    def setUp(self):
        self.f=original_fixture.IndependentEighthConflictHoldTests(
            methodName='test_sign_real_eighth_key_after_full_both_branch_replays')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.sign()
        self.key=Ed25519PrivateKey.generate()
        self.pub=self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()
        self.response_file=str(self.f.f.dir/'ninth-independent-nonexecution.json')
        self.args={**self.f.params,
            'request_file':self.f.out,
            'expected_request_sha256':case.sha(Path(self.f.out).read_bytes()),
            'receipt_file':self.response_file,
            'decision_id':'ninth_offline_review',
            'ninth_responder_id':'ninth_external_reviewer',
            'ninth_responder_public_hex':self.pub,
            'response_challenge_sha256':case.sha(b'EC327 unique external offline reply challenge'),
            'expected_disposition':'deferred_without_submission',
            'expected_reason_code':'awaiting_authorized_external_executor'}
        self.make_response()

    def make_response(self, **changes):
        request=json.loads(Path(self.f.out).read_bytes())
        claim={'schema':d.CLAIM_SCHEMA,
               **d._binding_from_request(request['claim'],self.args['expected_request_sha256']),
               'decision_id':self.args['decision_id'],
               'ninth_responder_id':self.args['ninth_responder_id'],
               'ninth_responder_public_hex':self.pub,
               'response_challenge_sha256':self.args['response_challenge_sha256'],
               'disposition':self.args['expected_disposition'],
               'reason_code':self.args['expected_reason_code'],
               'offline_review_only':True,
               'external_store_contacted_or_atomic_cas_attempted':False,
               'actual_remote_hold_or_nonexecution_independently_proven':False,
               'remote_head_or_global_latest_verified':False,
               'any_child_winner_or_business_commit_proven':False,
               'organization_authority_or_cross_device_uniqueness_proven':False}
        claim.update(changes)
        doc={'schema':d.SCHEMA,'claim':claim,
             'signature_ed25519':self.key.sign(
                 d.DOMAIN+hold.reg.canonical(claim)).hex()}
        Path(self.response_file).write_bytes(r._raw(doc))
        Path(self.response_file).chmod(0o600)
        return doc

    def verify(self, **changes):
        values={**self.args,
            'expected_receipt_sha256':case.sha(Path(self.response_file).read_bytes())}
        values.update(changes)
        return d.verify_nonexecution(**values)

    def _argv(self, **changes):
        values={**self.args,
            'expected_receipt_sha256':case.sha(Path(self.response_file).read_bytes())}
        values.update(changes)
        args=[]
        for key,value in values.items():
            if key in ('left','right','prior_registry_file'):
                continue
            args.extend(('--'+key.replace('_','-'),str(value)))
        if values.get('prior_registry_file') is not None:
            args.extend(('--prior-registry-file',values['prior_registry_file']))
        for label in ('left','right'):
            for key,value in values[label].items():
                args.extend(('--'+label+'-'+key.replace('_','-'),str(value)))
        return ['verify-nonexecution',*args]

    def test_valid_ninth_signature_verifies_after_eighth_and_two_histories(self):
        result=self.verify()
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['status'],
                         'ninth_offline_nonexecution_statement_authentic_unresolved')
        self.assertTrue(result['ninth_signature_eighth_signature_and_both_original_histories_verified'])
        self.assertFalse(result['actual_external_nonexecution_hold_or_remote_head_proven'])
        self.assertFalse(result['external_atomic_cas_or_worm_write_performed'])
        self.assertEqual(result['two_competing_heads_original_raw_sha256'],sorted((
            self.f.f.left['expected_registry_sha256'],
            self.f.f.right['expected_registry_sha256'])))

    def test_declined_is_equally_noncommittal_and_wholly_pinned(self):
        self.args['expected_disposition']='declined_without_submission'
        self.args['expected_reason_code']='declined_by_local_reviewer'
        self.make_response()
        self.assertEqual(self.verify()['disposition'],'declined_without_submission')

    def test_two_original_siblings_swappable_only_if_pins_agree(self):
        self.assertEqual(self.verify(left=self.f.f.right,
                                     right=self.f.f.left)['exit_code'],2)

    def test_refuse_forged_ninth_signature_even_after_repin(self):
        doc=json.loads(Path(self.response_file).read_bytes())
        doc['signature_ed25519']='0'*128
        Path(self.response_file).write_bytes(r._raw(doc))
        with self.assertRaisesRegex(anchor.AnchorError,'NINTH_ED25519_REPLY_SIGNATURE_NOT_AUTHENTIC'):
            self.verify()

    def test_resigned_claim_of_remote_success_cannot_pass(self):
        for field in ('external_store_contacted_or_atomic_cas_attempted',
                      'actual_remote_hold_or_nonexecution_independently_proven',
                      'remote_head_or_global_latest_verified',
                      'any_child_winner_or_business_commit_proven',
                      'organization_authority_or_cross_device_uniqueness_proven'):
            with self.subTest(field=field):
                self.make_response(**{field:True})
                with self.assertRaisesRegex(anchor.AnchorError,'NO_FAKE_EXTERNAL_EXECUTION'):
                    self.verify()

    def test_remote_committed_or_accepted_disposition_denied(self):
        self.make_response(disposition='remote_commit_succeeded')
        with self.assertRaisesRegex(anchor.AnchorError,'NO_FAKE_EXTERNAL_EXECUTION'):
            self.verify()

    def test_ninth_signer_id_pub_and_challenge_are_external_trust_not_claims(self):
        for value in (
            {'decision_id':'wrong_decision'},
            {'ninth_responder_id':'wrong_reviewer'},
            {'ninth_responder_public_hex':self.f.pub},
            {'response_challenge_sha256':'cb'*32},
            {'expected_disposition':'declined_without_submission'},
            {'expected_reason_code':'declined_by_local_reviewer'},
        ):
            with self.subTest(value=value):
                with self.assertRaises((anchor.AnchorError,hold.io.HostError)):
                    self.verify(**value)

    def test_request_original_sha_and_identity_changed_after_ninth_signature(self):
        self.make_response(request_id='other_request')
        with self.assertRaisesRegex(anchor.AnchorError,'NINTH_REPLY_MUST_BIND_EXACT'):
            self.verify()
        self.make_response()
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.verify(expected_request_sha256='ba'*32)

    def test_new_correct_ninth_signature_cannot_change_parent_or_child(self):
        self.make_response(expected_remote_parent_original_raw_sha256='aa'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'NINTH_REPLY_MUST_BIND_EXACT'):
            self.verify()
        self.make_response(proposed_competing_child_raw_sha256=['bb'*32,'cc'*32])
        with self.assertRaisesRegex(anchor.AnchorError,'NINTH_REPLY_MUST_BIND_EXACT'):
            self.verify()

    def test_ninth_cannot_reuse_eighth_identity_public_key_or_nonce(self):
        for value in (
            {'ninth_responder_id':self.f.params['eighth_signer_id']},
            {'ninth_responder_public_hex':self.f.pub},
            {'response_challenge_sha256':self.f.params['request_challenge_sha256']},
            {'decision_id':self.f.params['request_id']},
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(anchor.AnchorError,'MUST_DIFFER_FROM_EIGHTH'):
                    self.verify(**value)

    def test_ninth_cannot_reuse_visible_seventh_signer_identity(self):
        self.args['ninth_responder_id']=self.f.f.f.trust['seventh_receiver_id']
        self.make_response(ninth_responder_id=self.args['ninth_responder_id'])
        with self.assertRaisesRegex(anchor.AnchorError,'REUSES_VISIBLE_PRIOR'):
            self.verify()

    def test_ninth_cannot_reuse_visible_historical_challenge(self):
        # Re-sign after selecting an actually seen seventh receiver challenge.
        nonce=self.f.f.f.trust['seventh_receiver_challenge_sha256']
        self.args['response_challenge_sha256']=nonce
        self.make_response()
        with self.assertRaisesRegex(anchor.AnchorError,'NINTH_CHALLENGE_REUSES'):
            self.verify()

    def test_sequence_two_preserves_independently_pinned_true_parent(self):
        from ec323_composite_fork_capsule import test_capsule_structure as original_bundle
        inherited=original_bundle.CompositeOriginalCaseAndAckCases(
            methodName='test_seal_preserves_both_exact_original_bytes_and_successful_replay')
        inherited.setUp()
        self.addCleanup(inherited.doCleanups)
        sealed=inherited.seal()
        prior=self.f.f.left['registry_file']
        parent_sha=self.f.f.left['expected_registry_sha256']
        left=self.f.f._make('ec327_child_left','handoff_327_left',
            seq=2,parent_sha=parent_sha,parent_file=prior,f=inherited,sealed=sealed)
        right=self.f.f._make('ec327_child_right','handoff_327_right',
            seq=2,parent_sha=parent_sha,parent_file=prior,f=inherited,sealed=sealed)
        sibling_case=str(self.f.f.dir/'ec327-second-sequence-case.json')
        values={**self.f.f.kw,'left':left,'right':right,
            'expected_sequence':2,'expected_prior_registry_sha256':parent_sha,
            'prior_registry_file':prior}
        hold.proof.create_case(out=sibling_case,**values)
        new_values={**values,'case_file':sibling_case,
            'expected_case_sha256':case.sha(Path(sibling_case).read_bytes())}
        Path(self.f.out).unlink()
        self.f.sign(**new_values)
        self.args.update(new_values)
        self.args['expected_request_sha256']=case.sha(Path(self.f.out).read_bytes())
        self.make_response()
        result=self.verify()
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['sequence'],2)
        self.assertEqual(result['expected_remote_parent_original_raw_sha256'],parent_sha)
        with self.assertRaisesRegex(anchor.AnchorError,'SIGNED_EIGHTH_REQUEST_NOT_EQUAL'):
            self.verify(expected_prior_registry_sha256='bd'*32)

    def test_lost_original_history_rejected_despite_two_valid_new_signatures(self):
        self.assertEqual(self.verify()['exit_code'],2)
        Path(self.f.f.case_file).unlink()
        with self.assertRaises((anchor.AnchorError,hold.io.HostError)):
            self.verify()

    def test_missing_signed_request_rejected_even_if_reply_genuine(self):
        Path(self.f.out).unlink()
        # The receipt still contains valid ninth Ed25519; the verifier needs
        # the independently pinned EIGHTH original, not just ninth's claim.
        with self.assertRaises((anchor.AnchorError,hold.io.HostError)):
            d.verify_nonexecution(**{**self.args,
                 'expected_receipt_sha256':case.sha(Path(self.response_file).read_bytes())})

    def test_noncanonical_extra_field_and_duplicate_json_key_denied(self):
        raw=Path(self.response_file).read_bytes()
        Path(self.response_file).write_bytes(raw+b'\n')
        with self.assertRaisesRegex(anchor.AnchorError,'NONCANONICAL'):
            self.verify()
        self.make_response(unexpected_authority='global_winner')
        with self.assertRaisesRegex(anchor.AnchorError,'EXACT_NONEXECUTION'):
            self.verify()
        self.make_response()
        raw=Path(self.response_file).read_bytes()
        # A duplicate top-level key, even with a re-pinned whole SHA, is invalid.
        Path(self.response_file).write_bytes(raw.replace(b'{',b'{"schema":"duplicate",',1))
        with self.assertRaises(hold.io.HostError):
            self.verify()

    def test_response_cannot_alias_signed_request_or_original_case(self):
        for path in (self.f.out,self.f.f.case_file,self.f.f.left['registry_file']):
            with self.subTest(path=path):
                with self.assertRaisesRegex(anchor.AnchorError,'RECEIPT_PATH'):
                    self.verify(receipt_file=path)

    def test_change_reply_during_visible_legacy_role_reads_rejected(self):
        original=hold._visible_roles_and_challenges
        calls=[0]
        def mutate(**kwargs):
            result=original(**kwargs)
            calls[0]+=1
            if calls[0]==1:
                with open(self.response_file,'ab') as fd:
                    fd.write(b' ')
            return result
        with patch.object(hold,'_visible_roles_and_challenges',side_effect=mutate):
            with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self.verify()

    def test_standalone_cli_parse_and_denial_schema(self):
        output=StringIO()
        with redirect_stdout(output):
            self.assertEqual(operator.main(self._argv()),2)
        obj=json.loads(output.getvalue())
        self.assertEqual(obj['schema'],d.RESULT_SCHEMA)
        self.assertFalse(obj['external_atomic_cas_or_worm_write_performed'])
        output=StringIO()
        with redirect_stdout(output):
            self.assertEqual(operator.main(self._argv(**{
                'expected_receipt_sha256':'fb'*32})),3)
        obj=json.loads(output.getvalue())
        self.assertEqual(obj['schema'],d.DENIAL_SCHEMA)
        self.assertFalse(obj['ninth_signature_eighth_signature_and_histories_accepted'])

    def test_unified_console_uses_fixed_isolated_read_only_verifier(self):
        verified=self.verify()
        command_log=[]
        def stub(cmd, **kwargs):
            command_log.append(cmd)
            return 2,{'schema':d.RESULT_SCHEMA,'command':'verify-nonexecution',**verified}
        args={**self.args,
              'expected_receipt_sha256':case.sha(Path(self.response_file).read_bytes())}
        with patch.object(console,'_command',side_effect=stub):
            output=StringIO()
            with redirect_stdout(output):
                rc=console.audit_hold_disposition(
                    'DeliveryAudit','VerifyOfflineNoExecutionHoldDisposition',
                    pretty=False,**args)
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(output.getvalue())['exit_code'],2)
        self.assertEqual(command_log[0][1:3],['-I','-B'])
        self.assertIn('verify-nonexecution',command_log[0])
        self.assertNotIn('--out',command_log[0])
        self.assertNotIn('--private-key-file',command_log[0])
        with self.assertRaisesRegex(console.ConsoleError,'EC327_ONLY_DELIVERYAUDIT'):
            console.audit_hold_disposition('DeliveryAudit','SignDisposition',**args)

    def test_console_refuses_forged_child_claim_of_cas_success(self):
        true_result=self.verify()
        forged={**true_result,'external_atomic_cas_or_worm_write_performed':True}
        args={**self.args,
              'expected_receipt_sha256':case.sha(Path(self.response_file).read_bytes())}
        with patch.object(console,'_command',return_value=(2,{
            'schema':d.RESULT_SCHEMA,'command':'verify-nonexecution',**forged})):
            with self.assertRaisesRegex(console.ConsoleError,'MUST_NEVER_CLAIM_REMOTE_SUCCESS'):
                console.audit_hold_disposition(
                    'DeliveryAudit','VerifyOfflineNoExecutionHoldDisposition',**args)

    def test_fresh_isolated_cli_and_console_fail_closed_on_mocked_old_history(self):
        args=self._argv()[1:]
        root=Path(__file__).resolve().parents[2]
        script=root/'scripts'/'ces_cas_hold_disposition.py'
        result=subprocess.run([sys.executable,'-I','-B',str(script),
                               'verify-nonexecution',*args],capture_output=True,
                              text=True,timeout=60)
        self.assertEqual(result.returncode,4,result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['schema'],d.DENIAL_SCHEMA)
        script=root/'scripts'/'ces_next.py'
        result=subprocess.run([sys.executable,'-I','-B',str(script),
                               'audit-hold-disposition','DeliveryAudit',
                               'VerifyOfflineNoExecutionHoldDisposition',*args],
                              capture_output=True,text=True,timeout=60)
        self.assertEqual(result.returncode,4,result.stdout+result.stderr)
        doc=json.loads(result.stdout)
        self.assertEqual(doc['schema'],d.DENIAL_SCHEMA)
        self.assertFalse(doc['remote_global_latest_or_child_winner_proven'])


if __name__=='__main__':
    unittest.main()
