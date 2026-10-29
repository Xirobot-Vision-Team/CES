#!/usr/bin/env python3
"""EC328 targeted functional tests: genuine 8th+9th signatures, mocked EC317/318.

Imported EC327 fixtures intentionally mock the deep EC317/318 legacy replay.
The production isolated CLI must reject that deliberately simulated history.
Do not count a mocked legacy signature as a real EC294->328 acceptance pass.
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

from delivery_anchor import anchor
from fork_case_transport import case
from dual_channel_receipt import receipt as r
from conditional_conflict_hold import hold
from offline_hold_disposition import disposition as ninth
from offline_hold_disposition import test_disposition as parent_fixture
from scripts import ces_next as console
from . import ledger, operator


class IndependentOfflineMultiReviewLedgerTests(unittest.TestCase):
    def setUp(self):
        self.f = parent_fixture.IndependentNinthNoExecutionDispositionTests(
            methodName='test_valid_ninth_signature_verifies_after_eighth_and_two_histories')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.folder = Path(self.f.response_file).parent
        self.rows = [self._row_from_original()]
        self.rows.append(self.add_review(2, 'declined_without_submission',
                                         'declined_by_local_reviewer'))
        request = json.loads(Path(self.f.f.out).read_bytes())['claim']
        self.meta = {
            'signed_request_original_raw_sha256': self.f.args['expected_request_sha256'],
            'dispute_case_original_raw_sha256': self.f.args['expected_case_sha256'],
            'registry_id': request['registry_id'],
            'sequence': request['sequence'],
            'expected_remote_parent_original_raw_sha256':
                request['expected_remote_parent_original_raw_sha256'],
            'two_competing_heads_original_raw_sha256':
                request['proposed_competing_child_raw_sha256'],
            'target_store_namespace_id': request['target_store_namespace_id'],
            'previous_ledger_original_raw_sha256': ledger.ZERO,
        }
        self.ledger_file = str(self.folder/'ec328-pinned-multi-review-ledger.json')
        self.write_draft_and_prepare()

    def _row_from_original(self):
        return {
            'position': 1,
            'receipt_file': self.f.response_file,
            'receipt_original_raw_sha256': case.sha(Path(self.f.response_file).read_bytes()),
            'decision_id': self.f.args['decision_id'],
            'ninth_responder_id': self.f.args['ninth_responder_id'],
            'ninth_responder_public_hex': self.f.args['ninth_responder_public_hex'],
            'response_challenge_sha256': self.f.args['response_challenge_sha256'],
            'disposition': self.f.args['expected_disposition'],
            'reason_code': self.f.args['expected_reason_code'],
        }

    def add_review(self, number, disposition, reason, *, key=None, changes=None):
        key = key or Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()
        params = {
            'position': number,
            'receipt_file': str(self.folder/f'ec328-ninth-review-{number}.json'),
            'receipt_original_raw_sha256': None,
            'decision_id': f'ec328_decision_{number}',
            'ninth_responder_id': f'ec328_reviewer_{number}',
            'ninth_responder_public_hex': pub,
            'response_challenge_sha256': case.sha(
                f'ec328-independent-ninth-{number}'.encode('ascii')),
            'disposition': disposition, 'reason_code': reason,
        }
        if changes:
            params.update(changes)
        eighth = json.loads(Path(self.f.f.out).read_bytes())['claim']
        claim = {
            'schema': ninth.CLAIM_SCHEMA,
            **ninth._binding_from_request(eighth,self.f.args['expected_request_sha256']),
            **{key: params[key] for key in (
                'decision_id','ninth_responder_id','ninth_responder_public_hex',
                'response_challenge_sha256','disposition','reason_code')},
            'offline_review_only': True,
            'external_store_contacted_or_atomic_cas_attempted': False,
            'actual_remote_hold_or_nonexecution_independently_proven': False,
            'remote_head_or_global_latest_verified': False,
            'any_child_winner_or_business_commit_proven': False,
            'organization_authority_or_cross_device_uniqueness_proven': False,
        }
        signed = {'schema': ninth.SCHEMA, 'claim': claim,
                  'signature_ed25519': key.sign(ninth.DOMAIN+hold.reg.canonical(claim)).hex()}
        Path(params['receipt_file']).write_bytes(r._raw(signed))
        Path(params['receipt_file']).chmod(0o600)
        params['receipt_original_raw_sha256'] = case.sha(Path(params['receipt_file']).read_bytes())
        return params

    def write_draft_and_prepare(self):
        draft_path = str(self.folder/'ec328-review-ledger-draft.json')
        doc = {'schema': ledger.DRAFT_SCHEMA, **self.meta, 'entries': self.rows}
        Path(draft_path).write_bytes(r._raw(doc))
        Path(draft_path).chmod(0o600)
        # Rebuild only in the fixture. A real operator should never overwrite
        # previously pinned outputs (prepare itself is O_EXCL).
        result = ledger.prepare_unsigned_ledger(
            draft_file=draft_path, out=self.ledger_file)
        self.assertEqual(result['exit_code'], 2)
        self.assertFalse(result['all_signatures_or_original_histories_verified'])
        return result

    def verify(self, **changes):
        params = {key: value for key, value in self.f.args.items()
                  if key not in ('receipt_file','decision_id','ninth_responder_id',
                                 'ninth_responder_public_hex',
                                 'response_challenge_sha256',
                                 'expected_disposition','expected_reason_code')}
        params.update({
            'ledger_file': self.ledger_file,
            'expected_ledger_sha256': case.sha(Path(self.ledger_file).read_bytes()),
            'expected_prior_ledger_sha256': ledger.ZERO,
        })
        params.update(changes)
        return ledger.verify_ledger(**params)

    def _argv(self, **changes):
        params = {key: value for key, value in self.f.args.items()
                  if key not in ('receipt_file','decision_id','ninth_responder_id',
                                 'ninth_responder_public_hex',
                                 'response_challenge_sha256',
                                 'expected_disposition','expected_reason_code')}
        params.update({'ledger_file':self.ledger_file,
                      'expected_ledger_sha256':case.sha(Path(self.ledger_file).read_bytes())})
        params.update(changes)
        argv=['verify-ledger']
        for key, value in params.items():
            if key in ('left','right','prior_registry_file','prior_ledger_file'):
                continue
            argv.extend(('--'+key.replace('_','-'),str(value)))
        for key in ('prior_registry_file','prior_ledger_file'):
            if params.get(key) is not None:
                argv.extend(('--'+key.replace('_','-'),params[key]))
        for side in ('left','right'):
            for key,value in params[side].items():
                argv.extend(('--'+side+'-'+key.replace('_','-'),str(value)))
        return argv

    def test_two_genuine_independent_offline_dispositions_are_detected_as_divergent(self):
        result = self.verify()
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['offline_disposition_disagreement_detected'])
        self.assertEqual(result['disposition_counts'],{
            'declined_without_submission':1,'deferred_without_submission':1})
        self.assertEqual(result['review_count'],2)
        self.assertTrue(result['all_ninth_signatures_eighth_signature_and_two_complete_original_histories_verified'])
        for field in (*ledger.EXPLICIT_FALSE_FIELDS,
                      'business_or_external_store_writes_performed'):
            self.assertIs(result[field],False)

    def test_two_matching_signed_opinions_remain_unresolved(self):
        self.rows[1] = self.add_review(2, 'deferred_without_submission',
                                       'awaiting_authorized_external_executor')
        self.ledger_file = str(self.folder/'ec328-two-consistent.json')
        self.write_draft_and_prepare()
        result = self.verify()
        self.assertFalse(result['offline_disposition_disagreement_detected'])
        self.assertEqual(result['status'],
                         'offline_review_dispositions_consistent_unresolved')

    def test_single_entry_ledger_has_no_fake_history_claim(self):
        self.rows=self.rows[:1]
        self.ledger_file=str(self.folder/'ec328-first-review-only.json')
        self.write_draft_and_prepare()
        self.assertEqual(self.verify()['review_count'],1)

    def test_immutable_previous_snapshot_one_append_recognized(self):
        initial_rows=self.rows
        self.rows=self.rows[:1]
        self.ledger_file=str(self.folder/'ec328-first-receipt-ledger.json')
        self.write_draft_and_prepare()
        old=self.ledger_file
        old_sha=case.sha(Path(old).read_bytes())
        self.meta['previous_ledger_original_raw_sha256']=old_sha
        self.rows=initial_rows
        self.ledger_file=str(self.folder/'ec328-one-new-receipt-ledger.json')
        self.write_draft_and_prepare()
        result=self.verify(prior_ledger_file=old,
                           expected_prior_ledger_sha256=old_sha)
        self.assertEqual(result['previous_ledger_original_raw_sha256'],old_sha)
        with self.assertRaisesRegex(anchor.AnchorError,'PRIOR_LEDGER_WHOLE_ORIGINAL'):
            self.verify(expected_prior_ledger_sha256=old_sha)
        with self.assertRaisesRegex(anchor.AnchorError,'INDEPENDENT_PRIOR_LEDGER'):
            self.verify(prior_ledger_file=old,
                        expected_prior_ledger_sha256='af'*32)

    def test_previous_snapshot_cannot_be_rewritten_to_alter_first_decision(self):
        self.rows=self.rows[:1]
        self.ledger_file=str(self.folder/'ec328-real-previous.json')
        self.write_draft_and_prepare()
        old=self.ledger_file
        old_sha=case.sha(Path(old).read_bytes())
        self.meta['previous_ledger_original_raw_sha256']=old_sha
        self.rows[0]=self.add_review(1,'deferred_without_submission',
                    'awaiting_authorized_external_executor')
        self.rows.append(self.add_review(2,'declined_without_submission',
                                        'declined_by_local_reviewer'))
        self.ledger_file=str(self.folder/'ec328-manipulated-append.json')
        self.write_draft_and_prepare()
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_AN_EXACT_SINGLE_ENTRY_APPEND'):
            self.verify(prior_ledger_file=old,
                        expected_prior_ledger_sha256=old_sha)

    def test_manifest_wrong_original_request_or_child_has_no_authority(self):
        for change in ({'signed_request_original_raw_sha256':'ae'*32},
                       {'two_competing_heads_original_raw_sha256':['bb'*32,'cc'*32]}):
            with self.subTest(change=change):
                changed={**json.loads(Path(self.ledger_file).read_bytes()),**change}
                tmp=str(self.folder/'ec328-wrong-scope.json')
                Path(tmp).write_bytes(r._raw(changed));Path(tmp).chmod(0o600)
                with self.assertRaisesRegex(anchor.AnchorError,'LEDGER_NOT_EQUAL'):
                    self.verify(ledger_file=tmp,
                         expected_ledger_sha256=case.sha(Path(tmp).read_bytes()))

    def test_duplicate_ninth_keys_and_decisions_do_not_count_twice(self):
        for field in ('ninth_responder_id','ninth_responder_public_hex',
                      'response_challenge_sha256','decision_id',
                      'receipt_original_raw_sha256','receipt_file'):
            with self.subTest(field=field):
                changed=json.loads(Path(self.ledger_file).read_bytes())
                changed['entries'][1][field]=changed['entries'][0][field]
                changed['entries'][1]['entry_commitment_sha256']=ledger._entry_hash(changed['entries'][1])
                changed['ledger_head_entry_commitment_sha256']=changed['entries'][1]['entry_commitment_sha256']
                tmp=str(self.folder/'ec328-duplicate-row.json')
                Path(tmp).write_bytes(r._raw(changed));Path(tmp).chmod(0o600)
                with self.assertRaisesRegex(anchor.AnchorError,'DUPLICATE_RECEIPT'):
                    self.verify(ledger_file=tmp,
                        expected_ledger_sha256=case.sha(Path(tmp).read_bytes()))

    def test_wrong_ledger_sha_and_broken_chain_or_reordered_positions_deny(self):
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.verify(expected_ledger_sha256='aa'*32)
        for change in ('link','head','position'):
            with self.subTest(change=change):
                altered=json.loads(Path(self.ledger_file).read_bytes())
                if change=='link':
                    altered['entries'][1]['previous_entry_commitment_sha256']='ab'*32
                    altered['entries'][1]['entry_commitment_sha256']=ledger._entry_hash(altered['entries'][1])
                    altered['ledger_head_entry_commitment_sha256']=altered['entries'][1]['entry_commitment_sha256']
                elif change=='head':
                    altered['ledger_head_entry_commitment_sha256']='ac'*32
                else:
                    altered['entries'][1]['position']=1
                    altered['entries'][1]['entry_commitment_sha256']=ledger._entry_hash(altered['entries'][1])
                    altered['ledger_head_entry_commitment_sha256']=altered['entries'][1]['entry_commitment_sha256']
                tmp=str(self.folder/'ec328-bad-local-chain.json')
                Path(tmp).write_bytes(r._raw(altered));Path(tmp).chmod(0o600)
                with self.assertRaises(anchor.AnchorError):
                    self.verify(ledger_file=tmp,
                        expected_ledger_sha256=case.sha(Path(tmp).read_bytes()))

    def test_second_signed_reply_rebound_to_another_request_denies_even_if_resigned(self):
        forged=json.loads(Path(self.rows[1]['receipt_file']).read_bytes())
        forged['claim']['signed_request_original_raw_sha256']='ba'*32
        # A valid ninth signer can sign an incorrect binding; still rejected.
        fake=Ed25519PrivateKey.generate()
        self.rows[1]=self.add_review(2,'declined_without_submission',
                                    'declined_by_local_reviewer',key=fake)
        forged=json.loads(Path(self.rows[1]['receipt_file']).read_bytes())
        forged['claim']['signed_request_original_raw_sha256']='ba'*32
        forged['signature_ed25519']=fake.sign(
            ninth.DOMAIN+hold.reg.canonical(forged['claim'])).hex()
        Path(self.rows[1]['receipt_file']).write_bytes(r._raw(forged))
        self.rows[1]['receipt_original_raw_sha256']=case.sha(r._raw(forged))
        self.ledger_file=str(self.folder/'ec328-bad-request-bind.json')
        self.write_draft_and_prepare()
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_BOUND_TO_PINNED'):
            self.verify()

    def test_repin_all_old_receipts_after_deep_replay_prevents_mutation(self):
        original=ninth.verify_nonexecution
        def mutate(*args,**kwargs):
            observed=original(*args,**kwargs)
            with open(self.rows[0]['receipt_file'],'ab') as stream:
                stream.write(b' ')
            return observed
        with patch.object(ninth,'verify_nonexecution',side_effect=mutate):
            with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self.verify()

    def test_signed_reply_cannot_claim_success_or_independent_nonexecution(self):
        doc=json.loads(Path(self.rows[1]['receipt_file']).read_bytes())
        doc['claim']['actual_remote_hold_or_nonexecution_independently_proven']=True
        Path(self.rows[1]['receipt_file']).write_bytes(r._raw(doc))
        self.rows[1]['receipt_original_raw_sha256']=case.sha(r._raw(doc))
        self.ledger_file=str(self.folder/'ec328-forged-remote-proof.json')
        self.write_draft_and_prepare()
        with self.assertRaisesRegex(anchor.AnchorError,'NO_FAKE_EXTERNAL_EXECUTION'):
            self.verify()

    def test_missing_real_old_case_rejected_even_with_two_valid_new_signatures(self):
        Path(self.f.f.f.case_file).unlink()
        with self.assertRaises((anchor.AnchorError,hold.io.HostError)):
            self.verify()

    def test_resigned_old_seventh_identity_or_challenge_not_a_new_ninth_role(self):
        old = self.f.f.f.f.trust
        for change in (
                {'ninth_responder_id': old['seventh_receiver_id']},
                {'response_challenge_sha256': old['seventh_receiver_challenge_sha256']}):
            with self.subTest(change=change):
                self.rows[1]=self.add_review(2,'declined_without_submission',
                       'declined_by_local_reviewer',changes=change)
                self.ledger_file=str(self.folder/'ec328-historical-role-replay.json')
                # Reuse a fresh O_EXCL name for each subcase.
                self.ledger_file=self.ledger_file.replace('.json',
                    '-id.json' if 'ninth_responder_id' in change else '-nonce.json')
                self.write_draft_and_prepare()
                with self.assertRaises(anchor.AnchorError) as denial:
                    self.verify()
                self.assertTrue('REUSES' in denial.exception.code)

    def test_try_to_append_two_new_rows_to_a_pinned_old_snapshot_is_denied(self):
        self.rows=self.rows[:1]
        self.ledger_file=str(self.folder/'ec328-append-parent.json')
        self.write_draft_and_prepare()
        prev=self.ledger_file
        prev_sha=case.sha(Path(prev).read_bytes())
        self.meta['previous_ledger_original_raw_sha256']=prev_sha
        self.rows.append(self.add_review(2,'declined_without_submission',
                                         'declined_by_local_reviewer'))
        self.rows.append(self.add_review(3,'deferred_without_submission',
                                         'external_transaction_evidence_unavailable'))
        self.ledger_file=str(self.folder/'ec328-append-two-instead-of-one.json')
        self.write_draft_and_prepare()
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_AN_EXACT_SINGLE_ENTRY_APPEND'):
            self.verify(prior_ledger_file=prev,
                        expected_prior_ledger_sha256=prev_sha)

    def test_final_whole_source_repin_detects_change_after_additional_role_traversal(self):
        deep=ninth.verify_nonexecution
        roles=hold._visible_roles_and_challenges
        flag={'after_deep':False,'changed':False}
        def after_deep(**kwargs):
            value=deep(**kwargs)
            flag['after_deep']=True
            return value
        def mutate_after_roles(**kwargs):
            value=roles(**kwargs)
            if flag['after_deep'] and not flag['changed']:
                flag['changed']=True
                with open(self.f.f.f.left['origin_file'],'ab') as stream:
                    stream.write(b' ')
            return value
        with patch.object(ninth,'verify_nonexecution',side_effect=after_deep), \
             patch.object(hold,'_visible_roles_and_challenges',
                          side_effect=mutate_after_roles):
            with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self.verify()
        self.assertTrue(flag['changed'])

    def test_draft_is_only_private_canonical_proposal_not_trust(self):
        draft_file=str(self.folder/'ec328-review-ledger-draft.json')
        raw=Path(draft_file).read_bytes()
        Path(draft_file).write_bytes(raw+b' ')
        with self.assertRaisesRegex(anchor.AnchorError,'DRAFT_MUST_BE_CANONICAL'):
            ledger.prepare_unsigned_ledger(
                draft_file=draft_file,
                out=str(self.folder/'ec328-invalid-draft-output.json'))
        self.assertFalse(Path(self.folder/'ec328-invalid-draft-output.json').exists())

    def test_candidate_writer_is_exclusive_private_and_never_proclaims_authenticity(self):
        original=self.ledger_file
        self.assertEqual(Path(original).stat().st_mode & 0o777,0o600)
        with self.assertRaisesRegex(anchor.AnchorError,'OUTPUT_ALREADY_EXISTS'):
            ledger.prepare_unsigned_ledger(
                draft_file=str(self.folder/'ec328-review-ledger-draft.json'),
                out=original)
        self.assertEqual(self.verify()['exit_code'],2)

    def test_standalone_cli_and_console_wrapper_both_return_unresolved_two(self):
        output=StringIO()
        with redirect_stdout(output):
            self.assertEqual(operator.main(self._argv()),2)
        doc=json.loads(output.getvalue())
        self.assertEqual(doc['schema'],ledger.RESULT_SCHEMA)
        self.assertTrue(doc['offline_disposition_disagreement_detected'])
        data=self.verify()
        argv=self._argv()[1:]
        args={key:value for key,value in self.f.args.items()
             if key not in ('receipt_file','decision_id','ninth_responder_id',
                            'ninth_responder_public_hex',
                            'response_challenge_sha256',
                            'expected_disposition','expected_reason_code')}
        args.update({'ledger_file':self.ledger_file,
                     'expected_ledger_sha256':case.sha(Path(self.ledger_file).read_bytes()),
                     'prior_ledger_file':None,
                     'expected_prior_ledger_sha256':ledger.ZERO})
        calls=[]
        def stub(cmd,**kwargs):
            calls.append(cmd)
            return 2,{'schema':ledger.RESULT_SCHEMA,'command':'verify-ledger',**data}
        with patch.object(console,'_command',side_effect=stub):
            output=StringIO()
            with redirect_stdout(output):
                rc=console.audit_hold_review_ledger('DeliveryAudit',
                    'VerifyOfflineNonExecutionReviewLedger',pretty=False,**args)
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(output.getvalue())['exit_code'],2)
        self.assertEqual(calls[0][1:3],['-I','-B'])
        self.assertIn('verify-ledger',calls[0])
        self.assertNotIn('prepare-unsigned-ledger',calls[0])
        self.assertNotIn('--out',calls[0])
        self.assertNotIn('--private-key-file',calls[0])
        self.assertNotIn('--endpoint',calls[0])
        with self.assertRaisesRegex(console.ConsoleError,'EC328_ONLY_DELIVERYAUDIT'):
            console.audit_hold_review_ledger('DeliveryAudit','PrepareUnsigned',**args)
        forged={**data,'external_store_write_or_actual_nonexecution_proven':True}
        with patch.object(console,'_command',return_value=(2,{
            'schema':ledger.RESULT_SCHEMA,'command':'verify-ledger',**forged})):
            with self.assertRaisesRegex(console.ConsoleError,'MUST_NOT_CLAIM_REMOTE_SUCCESS'):
                console.audit_hold_review_ledger('DeliveryAudit',
                    'VerifyOfflineNonExecutionReviewLedger',**args)

    def test_fresh_isolated_real_process_fails_closed_on_mocked_old_history(self):
        argv=self._argv()
        root=Path(__file__).resolve().parents[2]
        for script,cmd in (
            (root/'scripts'/'ces_cas_review_ledger.py',argv),
            (root/'scripts'/'ces_next.py',[
                'audit-hold-ledger','DeliveryAudit',
                'VerifyOfflineNonExecutionReviewLedger',*argv[1:]])):
            with self.subTest(script=script.name):
                p=subprocess.run([sys.executable,'-I','-B',str(script),*cmd],
                                 text=True,capture_output=True,timeout=60)
                self.assertEqual(p.returncode,4,p.stderr+p.stdout)
                data=json.loads(p.stdout)
                self.assertEqual(data['schema'],ledger.DENIAL_SCHEMA)
                self.assertFalse(data['external_store_write_or_actual_nonexecution_proven'])


if __name__ == '__main__':
    unittest.main()
