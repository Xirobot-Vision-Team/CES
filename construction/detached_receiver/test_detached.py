#!/usr/bin/env python3
"""EC369 real Ed25519 receiver-only copies tests, MOCKED EC366 deep parent.

The test fixture originates in EC367/EC368 and mocks only EC366..EC337 to
create the previously signed parent hash. All signatures EC366 source/attest,
EC367 witness, EC368 handoff, EC369 map/challenge/answer are real Ed25519.
After setup every ORIGINAL sender file is actually deleted before audit.
"""
from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from root_provenance import provenance as src
from portable_receiver import test_portable as test368
from witness_distribution import test_distribution as test367
from . import detached as core

UTC,EV,EXP=test367.UTC,test367.EV,test367.EXP


class FocusedDetachedTests(unittest.TestCase):
    def setUp(self):
        self.f=test368.FocusedPortableReceiverTests('test_01_two_real_signatures_and_full_byte_copies')
        self.f.setUp()
        self.addCleanup(self.f.fx.tmp.cleanup)
        self.fx=self.f.fx
        # Add real institution signed provenance attestations to the EC367
        # synthetic root. Their *directory checkpoint truth* remains untested.
        root=json.loads(Path(self.fx.root['path']).read_bytes())
        for i,inst in enumerate(self.fx.institutions):
            role=test367.core.SOURCES[i]
            body={'schema':src.ATTEST_SCHEMA,
              'claimed_institution_id':inst['name'],
              'claimed_institution_role':role,
              'institution_public_key_original_sha256':inst['public']['sha256'],
              'parent_ec365_canonical_result_sha256':self.fx.parent365,
              'institution_status_original_sha256':self.fx.statuses[i][-1]['sha256'],
              'sequence':1,'previous_attestation_original_sha256':None,
              'directory_lineage_id':'ExampleDirectory',
              'attestation_kind':'corroborate','directory_root_generation':0,
              'epoch_signed_directory_observations':[{
                'epoch_index':0,'directory_root_public_key_original_sha256':'f'*64,
                'directory_checkpoint_original_sha256':'e'*64,
                'signed_tree_size':1,'signed_merkle_root_sha256':'d'*64,
                'parent_ec361_canonical_result_sha256':'c'*64,
                'source_a_manifest_original_sha256':'a'*64,
                'source_b_manifest_original_sha256':'b'*64}],
              'signed_directory_handoff_original_shas':[],
              'observed_checkpoint_original_sha256':'e'*64,
              'observed_tree_size':1,'observed_merkle_root_sha256':'d'*64,
              'issued_utc':UTC,'expires_utc':EXP}
            signed={**body,'signature_institution_ed25519_hex':inst['private'].sign(
                src.ATTEST_DOMAIN+canonical.canonical(body)).hex()}
            att=self.fx.write('synthetic-signed-institution-attestation',signed)
            self.fx.att_shas[i]=att['sha256']
            root['institutions'][i]['signed_provenance_attestations']=[att]
        self.fx.root=self.fx.write('root-with-real-signed-attestations',root)
        self.fx.parent_result()
        for wt in self.fx.witnesses:wt['records']=[]
        self.fx.make_witness(0);self.fx.make_witness(1)
        self.fx.distribution_bundle()
        self.f.args=self.fx.args367()
        self.f.parent=self.fx.run_audit()
        self.f.rebuild()
        self.messages=[]
        self.make_map()
        self.make_challenge()
        self.make_bundle()
        # Actual source originals are *gone*. No parent.audit mock can run
        # or supply the EC369 auditor with missing sender source paths.
        for x in self.f.originals:Path(x['path']).unlink()

    def signed(self,name,body,private,domain,field):
        record={**body,field:private.sign(domain+canonical.canonical(body)).hex()}
        return self.fx.write(name,record)

    def make_map(self,changes=None,signer=None):
        items=[{'kind':old['kind'],
                 'source_original':{'path':old['path'],'sha256':old['sha256']},
                 'byte_length':old['length'],
                 'receiver_copy':copy['receiver_copy']}
               for old,copy in zip(self.f.originals,self.f.copies)]
        self.mapbody={'schema':core.MAP_SCHEMA,
           'claimed_sender_id':self.f.sender_id,
           'sender_public_key_original_sha256':self.f.sender_key['sha256'],
           'claimed_receiver_id':self.f.receiver_id,
           'receiver_public_key_original_sha256':self.f.receiver_key['sha256'],
           'parent_ec367_canonical_result_sha256':self.f.parent_sha,
           'parent_ec366_canonical_result_sha256':self.fx.parent_sha,
           'parent_ec365_canonical_result_sha256':self.fx.parent365,
           'portable_inventory_canonical_sha256':self.f.inv_sha,
           'witness_head_original_shas':self.f.heads,
           'institution_root_public_key_original_shas':[
              i['public']['sha256'] for i in self.fx.institutions],
           'witness_public_key_original_shas':[
              i['public']['sha256'] for i in self.fx.witnesses],
           'institution_claimed_ids':[x['name'] for x in self.fx.institutions],
           'witness_claimed_ids':[x['name'] for x in self.fx.witnesses],
           'originals':items,'issued_utc':UTC,'expires_utc':EXP}
        if changes:self.mapbody.update(changes)
        self.mapref=self.signed('detached-signed-map',self.mapbody,
             signer or self.f.sender_private,core.MAP_DOMAIN,
             'signature_sender_ed25519_hex')

    def make_challenge(self,*,seq=0,prior_req=None,prior_ans=None,
                       nonce=None,request_changes=None,response_changes=None,
                       response_signer=None):
        if seq>0 and prior_req is None and self.messages:
            prior_req=self.messages[-1]['receiver_challenge_original']['sha256']
        if seq>0 and prior_ans is None and self.messages:
            prior_ans=self.messages[-1]['sender_disclosure_original']['sha256']
        common={'claimed_sender_id':self.f.sender_id,
          'sender_public_key_original_sha256':self.f.sender_key['sha256'],
          'claimed_receiver_id':self.f.receiver_id,
          'receiver_public_key_original_sha256':self.f.receiver_key['sha256'],
          'sequence':seq,'previous_challenge_original_sha256':prior_req,
          'previous_answer_original_sha256':prior_ans,
          'signed_copy_map_original_sha256':self.mapref['sha256'],
          'portable_inventory_canonical_sha256':self.f.inv_sha,
          'parent_ec367_canonical_result_sha256':self.f.parent_sha,
          'receiver_nonce_sha256':nonce or (format(seq+1,'064x'))}
        all_shas=[x['source_original']['sha256'] for x in self.mapbody['originals']]
        req={'schema':core.CHALLENGE_SCHEMA,**common,
             'challenged_source_original_shas':all_shas,
             'issued_utc':UTC,'expires_utc':EXP}
        if request_changes:req.update(request_changes)
        rref=self.signed('receiver-challenge',req,self.f.receiver_private,
                        core.CHALLENGE_DOMAIN,'signature_receiver_ed25519_hex')
        ans={'schema':core.ANSWER_SCHEMA,**common,
             'receiver_challenge_original_sha256':rref['sha256'],
             'disclosure_state':'provided',
             'disclosed_source_original_shas':all_shas,
             'answered_utc':EV,'expires_utc':EXP}
        if response_changes:ans.update(response_changes)
        aref=self.signed('sender-disclosure-answer',ans,
             response_signer or self.f.sender_private,core.ANSWER_DOMAIN,
             'signature_sender_ed25519_hex')
        self.messages.append({'receiver_challenge_original':rref,
                              'sender_disclosure_original':aref})

    def make_bundle(self):
        self.bundle=self.fx.write('detached-bundle',{
          'schema':core.BUNDLE_SCHEMA,'signed_copy_map_original':self.mapref,
          'handoffs':self.f.pairs,'disclosure_challenges':self.messages})

    def opts(self,**changes):
        p={'detached_evaluation_utc':EV,
           'detached_bundle_file':self.bundle['path'],
           'expected_detached_bundle_sha256':self.bundle['sha256'],
           'expected_signed_copy_map_sha256':self.mapref['sha256'],
           'expected_portable_inventory_sha256':self.f.inv_sha,
           'expected_parent_ec367_canonical_result_sha256':self.f.parent_sha,
           'expected_parent_ec366_canonical_result_sha256':self.fx.parent_sha,
           'expected_parent_ec365_canonical_result_sha256':self.fx.parent365,
           'sender_public_key_file':self.f.sender_key['path'],
           'expected_sender_public_key_sha256':self.f.sender_key['sha256'],
           'claimed_sender_id':self.f.sender_id,
           'receiver_public_key_file':self.f.receiver_key['path'],
           'expected_receiver_public_key_sha256':self.f.receiver_key['sha256'],
           'claimed_receiver_id':self.f.receiver_id,
           'expected_retained_sender_dispatch_head_sha256':self.f.pairs[-1][
               'sender_dispatch_original']['sha256'],
           'expected_retained_receiver_ack_head_sha256':self.f.pairs[-1][
               'receiver_ack_original']['sha256'],
           'minimum_retained_sender_dispatch_sequence':0,
           'minimum_retained_receiver_ack_sequence':0,
           'expected_retained_challenge_head_sha256':self.messages[-1][
               'receiver_challenge_original']['sha256'],
           'expected_retained_answer_head_sha256':self.messages[-1][
               'sender_disclosure_original']['sha256'],
           'expected_retained_challenge_nonce_sha256':format(len(self.messages),'064x'),
           'minimum_retained_challenge_sequence':0,
           'institution_root_public_key_shas':[
               x['public']['sha256'] for x in self.fx.institutions],
           'witness_public_key_shas':[x['public']['sha256'] for x in self.fx.witnesses],
           'institution_claimed_ids':[x['name'] for x in self.fx.institutions],
           'witness_claimed_ids':[x['name'] for x in self.fx.witnesses],
           'expected_source_status_head_shas':[
               x[-1]['sha256'] for x in self.fx.statuses],
           'expected_source_attestation_head_shas':list(self.fx.att_shas),
           'expected_witness_head_shas':self.f.heads,
           'signed_sender_dispatch_shas':[x['sender_dispatch_original']['sha256']
                                          for x in self.f.pairs],
           'signed_receiver_ack_shas':[x['receiver_ack_original']['sha256']
                                       for x in self.f.pairs],
           'signed_challenge_shas':[x['receiver_challenge_original']['sha256']
                                    for x in self.messages],
           'signed_answer_shas':[x['sender_disclosure_original']['sha256']
                                 for x in self.messages]}
        return {**p,**changes}

    def run_audit(self,**changes):
        return core.audit(**self.opts(**changes))

    def test_01_actual_sender_origins_deleted_detached_signatures_verify(self):
        self.assertFalse(any(Path(x['path']).exists() for x in self.f.originals))
        result=self.run_audit()
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['locally_detached_signed_copy_inventory_and_dual_receipt_consistent'],result)
        self.assertFalse(result['original_sender_source_paths_required_or_read'])
        self.assertFalse(result['ec365_through_ec337_historical_parent_or_directory_checkpoint_replay_performed'])
        self.assertEqual(result['true_copied_institution_provenance_ed25519_signature_count'],2)
        self.assertEqual(result['true_copied_witness_ed25519_signature_count'],2)
        self.assertTrue(all(result[x] is False for x in core.NEGATIVES))

    def test_02_bad_copy_hash_fails_closed(self):
        p=Path(self.mapbody['originals'][2]['receiver_copy']['path'])
        p.write_bytes(b'not a complete original')
        with self.assertRaises(errors.AnchorError):self.run_audit()

    def test_03_missing_source_origin_is_not_restored_or_read(self):
        result=self.run_audit()
        self.assertEqual(result['actual_copied_source_original_count'],len(self.f.originals))
        self.assertTrue(all(not Path(x['path']).exists() for x in self.f.originals))

    def test_04_wrong_independently_retained_parent_pin_is_visible(self):
        result=self.run_audit(expected_parent_ec367_canonical_result_sha256='a'*64)
        self.assertTrue(result[core.FLAGS[0]])
        self.assertFalse(result['locally_detached_signed_copy_inventory_and_dual_receipt_consistent'])

    def test_05_wrong_standalone_signed_map_original_pin_denied(self):
        with self.assertRaises(errors.AnchorError):
            self.run_audit(expected_signed_copy_map_sha256='e'*64)

    def test_06_non_sender_signed_map_denied(self):
        self.make_map(signer=self.f.receiver_private)
        self.make_bundle()
        with self.assertRaises(errors.AnchorError) as x:self.run_audit()
        self.assertEqual(x.exception.status,'permission_denied')

    def test_07_mismatched_signed_receiver_ack_head_does_not_upgrade(self):
        result=self.run_audit(expected_retained_receiver_ack_head_sha256='f'*64)
        self.assertTrue(result[core.FLAGS[8]])

    def test_08_challenge_missing_disclosed_source_original_flagged(self):
        self.messages=[]
        self.make_challenge(response_changes={'disclosed_source_original_shas':[
            x['source_original']['sha256'] for x in self.mapbody['originals'][:-1]]})
        self.make_bundle()
        result=self.run_audit()
        self.assertTrue(result[core.FLAGS[9]])
        self.assertFalse(result['locally_detached_signed_copy_inventory_and_dual_receipt_consistent'])

    def test_09_genuine_sender_signed_withholding_flagged(self):
        self.messages=[]
        self.make_challenge(response_changes={'disclosure_state':'withheld'})
        self.make_bundle()
        self.assertTrue(self.run_audit()[core.FLAGS[9]])

    def test_10_fake_sender_signed_disclosure_signature_denied(self):
        self.messages=[]
        self.make_challenge(response_signer=self.f.receiver_private)
        self.make_bundle()
        with self.assertRaises(errors.AnchorError) as x:self.run_audit()
        self.assertEqual(x.exception.status,'permission_denied')

    def test_11_two_linked_dual_signed_disclosure_challenges(self):
        self.make_challenge(seq=1,nonce='2'*64)
        self.make_bundle()
        result=self.run_audit(expected_retained_challenge_nonce_sha256='2'*64,
                              minimum_retained_challenge_sequence=1)
        self.assertTrue(result['locally_detached_signed_copy_inventory_and_dual_receipt_consistent'])
        self.assertEqual(result['true_disclosure_challenge_ed25519_signature_count'],2)

    def test_12_true_signed_challenge_previous_answer_gap_visible(self):
        self.make_challenge(seq=1,response_changes={
            'previous_answer_original_sha256':'c'*64})
        self.make_bundle()
        self.assertTrue(self.run_audit()[core.FLAGS[9]])

    def test_13_external_nonce_pin_prevents_replayed_disclosure(self):
        self.assertTrue(self.run_audit(expected_retained_challenge_nonce_sha256='f'*64)[core.FLAGS[10]])

    def test_14_missing_copied_original_denied(self):
        self.mapbody['originals']=self.mapbody['originals'][:-1]
        self.mapref=self.signed('short-map',self.mapbody,self.f.sender_private,
                       core.MAP_DOMAIN,'signature_sender_ed25519_hex')
        self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.run_audit()

    def test_15_handoff_status_withheld_signed_but_not_locally_complete(self):
        # Signed withdrawal at EC368 layer remains visible; the prior signed
        # accepted receipt cannot be silently replaced by a source path.
        ack=self.f.pairs[0]['receiver_ack_original']
        orig=json.loads(Path(ack['path']).read_bytes())
        raw={k:v for k,v in orig.items() if k!='signature_receiver_ed25519_hex'}
        raw['receipt_state']='withheld'
        new=self.signed('withheld-ec368-ack',raw,self.f.receiver_private,
                 test368.core.ACK_DOMAIN,'signature_receiver_ed25519_hex')
        self.f.pairs[0]['receiver_ack_original']=new
        self.make_bundle()
        result=self.run_audit()
        self.assertTrue(result[core.FLAGS[7]])
        self.assertFalse(result['locally_detached_signed_copy_inventory_and_dual_receipt_consistent'])

    def test_16_pinned_signed_stream_mismatch_visible(self):
        self.assertTrue(self.run_audit(signed_challenge_shas=['e'*64])[core.FLAGS[10]])

    def test_17_file_hardlink_alias_copy_to_map_denied(self):
        # A copied original cannot reuse the same physical inode as the signed
        # map or as a different role. A changed signature isn't a shortcut.
        self.mapbody['originals'][2]['receiver_copy']={
          'path':self.mapref['path'],
          'sha256':self.mapbody['originals'][2]['source_original']['sha256']}
        self.mapref=self.signed('alias-map',self.mapbody,self.f.sender_private,
                   core.MAP_DOMAIN,'signature_sender_ed25519_hex')
        self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.run_audit()

    def test_18_wrong_claimed_sender_or_receiver_pin_denied(self):
        with self.assertRaises(errors.AnchorError):
            self.run_audit(claimed_sender_id=self.f.receiver_id)


    def test_19_real_fixed_isolated_unified_child_with_sender_origins_missing(self):
        # The *actual* python -I -B child runs here, not a mocked reply.
        from scripts import ces_next as router
        opts=self.opts()
        with patch.object(router,'_emit') as out:
            code=router.audit_detached_receiver(
                'DeliveryAudit','AuditDetachedReceiver',**opts)
        self.assertEqual(code,2)
        self.assertTrue(out.call_args.args[0][
            'locally_detached_signed_copy_inventory_and_dual_receipt_consistent'])
        self.assertFalse(out.call_args.args[0]['original_sender_source_paths_required_or_read'])

    def test_20_real_fixed_isolated_child_denies_bad_copy(self):
        from scripts import ces_next as router
        Path(self.mapbody['originals'][4]['receiver_copy']['path']).write_bytes(b'bad-copy')
        with patch.object(router,'_emit') as out:
            code=router.audit_detached_receiver(
                'DeliveryAudit','AuditDetachedReceiver',**self.opts())
        self.assertIn(code,(3,4,5))
        self.assertFalse(out.call_args.args[0]['original_sender_source_paths_required_or_read'])

    def test_21_fixed_child_must_not_overclaim_old_history(self):
        from scripts import ces_next as router
        real=self.run_audit()
        fake={**real,
          'ec365_through_ec337_historical_parent_or_directory_checkpoint_replay_performed':True}
        with patch.object(router,'_command',return_value=(2,fake)),patch.object(router,'_emit'):
            with self.assertRaises(Exception):router.audit_detached_receiver(
                'DeliveryAudit','AuditDetachedReceiver',**self.opts())

    def test_22_two_linked_ec368_sender_receiver_epochs_offline(self):
        # Before the sources disappeared, EC368 constructed two independently
        # real signed linked epochs; the detached auditor checks both originals.
        self.f.make_pair(seq=1)
        self.make_bundle()
        result=self.run_audit(minimum_retained_sender_dispatch_sequence=1,
                              minimum_retained_receiver_ack_sequence=1)
        self.assertTrue(result['locally_detached_signed_copy_inventory_and_dual_receipt_consistent'])
        self.assertEqual(result['true_copied_receiver_ack_ed25519_signature_count'],2)


    def test_23_true_extra_signed_source_revocation_survives_deleted_origins(self):
        # Recreate inputs ONLY in synthetic fixture setup; the actual EC369
        # audit will again have zero accessible original sender-side sources.
        for old,copy in zip(self.f.originals,self.f.copies):
            Path(old['path']).write_bytes(Path(copy['receiver_copy']['path']).read_bytes())
        rev=self.fx.source_status(0,1,'revoke')
        self.fx.distribution_bundle(extra=[{
            'source_role':test367.core.SOURCES[0],'original':rev}])
        self.f.args=self.fx.args367()
        self.f.parent=self.fx.run_audit()  # EC366 deeper ancestry MOCK only
        self.f.rebuild()                   # True fresh EC368 Ed25519 receipts
        self.messages=[]
        self.make_map()
        self.make_challenge()
        self.make_bundle()
        for old in self.f.originals:Path(old['path']).unlink()
        self.assertFalse(any(Path(x['path']).exists() for x in self.f.originals))
        result=self.run_audit()
        self.assertTrue(result[core.FLAGS[2]])
        self.assertIn(rev['sha256'],result['verified_copy_source_terminal_status_original_shas'])
        self.assertEqual(result['actual_source_status_head_shas'][0],rev['sha256'])
        self.assertFalse(result['locally_detached_signed_copy_inventory_and_dual_receipt_consistent'])
        self.assertFalse(result['original_sender_source_paths_required_or_read'])


if __name__=='__main__':unittest.main()
