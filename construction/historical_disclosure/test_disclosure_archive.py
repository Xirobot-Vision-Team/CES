#!/usr/bin/env python3
"""EC376 real old EC354/355 Ed25519 + receiver original bytes + EC356 joins.

Native old EC374..EC369 production parent replay occurs in isolated child
checks. The deeper old EC366..337 fixture stays explicitly MOCKED: these
cases do not claim that a complete EC353 signed checkpoint is authenticated.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from gossip import gossip as ec354
from disclosure import disclosure as ec355
from witness_distribution import test_distribution as util
from historical_custody import test_custody_archive as previous_tests
from . import disclosure_archive as core

ROOT=Path(__file__).resolve().parents[2]


class HistoricTrueSignedDisclosureOriginalsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        previous_tests.ReceiverHistoricalTrueCustodyOriginalsTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        previous_tests.ReceiverHistoricalTrueCustodyOriginalsTests.tearDownClass()

    def setUp(self):
        self.fx=previous_tests.ReceiverHistoricalTrueCustodyOriginalsTests(
                'test_01_actual_old_ec356_sig_originals_ec357_inventory_link')
        original=self.fx.construct_ec356_receiver_originals

        def with_true_ec354_ec355_signed_originals():
            self.prepare_signed_originals()
            prev=self.fx.signed
            def signed(name,body,key,domain):
                if name.startswith('ec375_real_signed_original_ack_'):
                    slot=name[-1]
                    body=copy.deepcopy(body)
                    body.update({
                        'parent_disclosure_bundle_original_sha256':self.disclosure['sha256'],
                        'gossip_reply_original_sha256':self.reply['sha256'],
                        'ec355_request_original_sha256':self.req[slot]['sha256'],
                        'ec355_receipt_original_sha256':self.receipt[slot]['sha256'],
                    })
                return prev(name,body,key,domain)
            self.fx.signed=signed
            try:
                original()
                # EC375 constructs source-review inventories from its local
                # pre-signature ACK body. Keep that audit declaration tied to
                # the EC376-replaced *actual* signed receipt SHA, otherwise
                # inherited EC375 would correctly flag stale source reviews.
                for row in self.fx.signed_inventory_records:
                    row['ec355_receipt_original_sha256']=(
                        self.receipt[row['slot']]['sha256'])
                for slot in ('a','b'):
                    self.fx.sources[slot]['ackbody'].update({
                        'parent_disclosure_bundle_original_sha256':
                            self.disclosure['sha256'],
                        'gossip_reply_original_sha256':self.reply['sha256'],
                        'ec355_request_original_sha256':self.req[slot]['sha256'],
                        'ec355_receipt_original_sha256':self.receipt[slot]['sha256'],
                    })
            finally:self.fx.signed=prev
        self.fx.construct_ec356_receiver_originals=with_true_ec354_ec355_signed_originals
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.parent=self.fx.audit()  # real EC375 source signatures; deep parent mock noted
        self.make_bundle()

    def store(self,name,body):return self.fx.store(name,body)

    def sign(self,name,body,key,domain):
        return self.store(name,{**body,'signature_ed25519_hex':
                 key.sign(domain+canonical.canonical(body)).hex()})

    def old_label(self,ref):return self.fx.old_label(ref)

    def prepare_signed_originals(self):
        self.private={};self.auditors=[];self.receiver_actors=[]
        for i,actorid in enumerate(('AuditorChallenger','AuditorPeer','AuditorResponder')):
            key=ed25519.Ed25519PrivateKey.generate()
            pub=self.store('ec376_real_old_ec354_auditor_key_'+actorid,util.pub(key))
            ref=self.sign('ec376_real_old_ec354_signed_auditor_ref_'+actorid,{
                'schema':ec354.AUDITOR_SCHEMA,
                'auditor_id':actorid,
                'auditor_public_key_original_sha256':pub['sha256'],
                'claimed_auditor_organization':'Auditor Organisation '+str(i),
                'claimed_auditor_directory_uri':'https://auditor'+str(i)+'.example.invalid/',
                'valid_from_utc':util.UTC,'valid_until_utc':util.EXP},
                key,ec354.AUDITOR_DOMAIN)
            self.private[actorid]=key
            self.auditors.append({'auditor_id':actorid,
                'auditor_public_key':self.old_label(pub),
                'auditor_reference':self.old_label(ref)})
            self.receiver_actors.append({'auditor_id':actorid,
                'public_key_original':pub,'signed_reference_original':ref})
        self.challenge=self.sign('ec376_real_old_ec354_challenge',{
            'schema':ec354.CHALLENGE_SCHEMA,
            'challenge_id':'HistoricChallenge',
            'challenger_auditor_id':'AuditorChallenger',
            'responder_auditor_id':'AuditorResponder',
            'challenger_reference_original_sha256':self.receiver_actors[0][
                'signed_reference_original']['sha256'],
            'responder_reference_original_sha256':self.receiver_actors[2][
                'signed_reference_original']['sha256'],
            'parent_publication_bundle_original_sha256':'1'*64,
            'log_id':'HistoricLog',
            'log_reference_original_sha256':'2'*64,
            'checkpoint_original_sha256':'3'*64,
            'tree_size':1,'root_hash_sha256':'4'*64,
            'previous_challenge_original_sha256':ec354.GENESIS,
            'nonce_hex':'a'*32,'issued_utc':util.UTC},
            self.private['AuditorChallenger'],ec354.CHALLENGE_DOMAIN)
        cpbytes=b'original-checkpoint-shared-historic-byte-copy'
        witbytes=b'original-witness-shared-historic-byte-copy'
        self.cp={};self.wit={}
        for slot in ('a','b'):
            self.cp[slot]=self.store('ec376_true_old_ec355_cp_copy_'+slot,cpbytes)
            self.wit[slot]=self.store('ec376_true_old_ec355_witness_copy_'+slot,witbytes)
        self.reply=self.sign('ec376_real_old_ec354_gossip_reply',{
            'schema':ec354.REPLY_SCHEMA,
            'challenge_original_sha256':self.challenge['sha256'],
            'responder_auditor_id':'AuditorResponder',
            'responder_reference_original_sha256':self.receiver_actors[2][
                'signed_reference_original']['sha256'],
            'log_id':'HistoricLog','response_kind':'checkpoint_view',
            'checkpoint_original_sha256':self.cp['a']['sha256'],
            'tree_size':2,'root_hash_sha256':'5'*64,
            'responded_utc':util.UTC},
            self.private['AuditorResponder'],ec354.REPLY_DOMAIN)
        self.gossip=self.store('ec376_original_unsigned_old_ec354_gossip_manifest',{
            'schema':ec354.BUNDLE_SCHEMA,
            'auditors':self.auditors,
            'exchanges':[{'challenge':self.old_label(self.challenge),
                          'replies':[self.old_label(self.reply)]}]})
        self.req={};self.receipt={};oldrequests=[];newrequests=[]
        for slot,kind,target,idx in (
            ('a','original_responder','AuditorResponder',2),
            ('b','independent_peer','AuditorPeer',1)):
            self.req[slot]=self.sign('ec376_old_signed_ec355_request_'+slot,{
                'schema':ec355.REQUEST_SCHEMA,
                'request_id':'HistoricDisclosureRequest'+slot.upper(),
                'parent_gossip_bundle_original_sha256':self.gossip['sha256'],
                'gossip_challenge_original_sha256':self.challenge['sha256'],
                'gossip_reply_original_sha256':self.reply['sha256'],
                'log_id':'HistoricLog',
                'claimed_checkpoint_original_sha256':self.cp[slot]['sha256'],
                'claimed_tree_size':2,'claimed_root_hash_sha256':'5'*64,
                'requester_auditor_id':'AuditorChallenger',
                'requester_reference_original_sha256':self.receiver_actors[0][
                    'signed_reference_original']['sha256'],
                'requested_auditor_id':target,
                'requested_reference_original_sha256':self.receiver_actors[idx][
                    'signed_reference_original']['sha256'],
                'requested_role':kind,
                'previous_request_original_sha256':ec355.GENESIS,
                'nonce_hex':('b' if slot=='a' else 'c')*32,
                'issued_utc':util.UTC},
                self.private['AuditorChallenger'],ec355.REQUEST_DOMAIN)
            self.receipt[slot]=self.sign('ec376_old_signed_ec355_receipt_'+slot,{
                'schema':ec355.RECEIPT_SCHEMA,
                'request_original_sha256':self.req[slot]['sha256'],
                'gossip_reply_original_sha256':self.reply['sha256'],
                'respondent_auditor_id':target,
                'respondent_reference_original_sha256':self.receiver_actors[idx][
                    'signed_reference_original']['sha256'],
                'log_id':'HistoricLog',
                'response_kind':'furnished_originals',
                'checkpoint_original_sha256':self.cp[slot]['sha256'],
                'witness_original_sha256':self.wit[slot]['sha256'],
                'claimed_checkpoint_length':len(cpbytes),
                'claimed_witness_length':len(witbytes),
                'responded_utc':util.UTC},
                self.private[target],ec355.RECEIPT_DOMAIN)
            oldrequests.append({'request':self.old_label(self.req[slot]),
                'responses':[{'receipt':self.old_label(self.receipt[slot]),
                    'checkpoint':self.old_label(self.cp[slot]),
                    'witness_statement':self.old_label(self.wit[slot]),
                    'consistency_proof':None}]})
            newrequests.append({'signed_request_original':self.req[slot],
                'responses':[{'signed_receipt_original':self.receipt[slot],
                    'checkpoint_original':self.cp[slot],
                    'witness_original':self.wit[slot],
                    'consistency_original':None}]})
        self.disclosure=self.store('ec376_old_unsigned_ec355_manifest',{
            'schema':ec355.BUNDLE_SCHEMA,'requests':oldrequests})
        self.receiver_requests=newrequests

    def make_bundle(self):
        self.epochs=[{'epoch_index':i,'ec354_gossip_bundle_original':self.gossip,
           'ec355_disclosure_bundle_original':self.disclosure,
           'auditors':copy.deepcopy(self.receiver_actors),
           'exchanges':[{'signed_challenge_original':self.challenge,
                         'signed_reply_originals':[self.reply]}],
           'disclosure_requests':copy.deepcopy(self.receiver_requests)}
           for i in range(2)]
        self.rebuild()

    def rebuild(self):
        self.archive=self.store('ec376_true_old_receiver_archive',{
            'schema':core.BUNDLE_SCHEMA,
            'parent_ec375_canonical_result_sha256':core.sha(
                 canonical.canonical(self.parent)),
            'ec375_historical_custody_archive_original_sha256':self.fx.archive['sha256'],
            'claimed_directory_lineage_id':self.fx.old.ec373.old.lineage,
            'epochs':self.epochs})

    def keydigest(self):
        return core.sha(canonical.canonical([{'auditor_id':row['auditor_id'],
            'public_key_original_sha256':row['public_key_original']['sha256']}
            for row in self.receiver_actors]))

    def options(self,**overrides):
        opts=self.fx.options(expected_retained_historical_custody_inventory_sha256=
             self.fx.derive()['receiver_verified_historical_custody_inventory_sha256'])
        opts.update(historical_disclosure_archive_bundle_file=self.archive['path'],
            expected_historical_disclosure_archive_bundle_sha256=self.archive['sha256'],
            historical_disclosure_gossip_bundle_shas=[self.gossip['sha256']]*2,
            historical_disclosure_request_bundle_shas=[self.disclosure['sha256']]*2,
            historical_disclosure_auditor_key_inventory_shas=[self.keydigest()]*2,
            minimum_historical_disclosure_request_counts=[2]*2,
            minimum_historical_disclosure_receipt_counts=[2]*2)
        opts.update(overrides)
        return opts

    def derive(self,**overrides):
        with patch.object(core.prior,'audit',return_value=self.parent):
            return core.derive_inventory(**self.options(**overrides))

    def audit(self,**overrides):
        opts=self.options(expected_retained_historical_disclosure_inventory_sha256=
             self.derive()['receiver_verified_historical_disclosure_inventory_sha256'])
        opts.update(overrides)
        with patch.object(core.prior,'audit',return_value=self.parent):
            return core.audit(**opts)

    def test_01_real_three_auditor_gossip_and_two_receipts_verified(self):
        doc=self.audit()
        self.assertTrue(doc['local_pinned_historical_disclosure_signatures_and_ack_links_consistent'])
        self.assertEqual(doc['verified_real_ec354_self_signed_auditor_count'],6)
        self.assertEqual(doc['verified_real_ec354_signed_gossip_challenge_count'],2)
        self.assertEqual(doc['verified_real_ec354_signed_gossip_reply_count'],2)
        self.assertEqual(doc['verified_real_ec355_signed_request_count'],4)
        self.assertEqual(doc['verified_real_ec355_signed_receipt_count'],4)
        self.assertEqual(doc['verified_real_ec356_ack_to_ec355_signed_receipt_join_count'],4)
        self.assertEqual(doc['exit_code'],2)
        self.assertFalse(doc['old_ec353_log_checkpoint_or_witness_signatures_reverified'])

    def test_02_old_ec354_gossip_unsigned_manifest_byte_mutation_denied(self):
        Path(self.gossip['path']).write_bytes(b'CHANGED-OLD-GOSSIP')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_03_old_ec355_unsigned_manifest_byte_mutation_denied(self):
        Path(self.disclosure['path']).write_bytes(b'CHANGED-OLD-DISCLOSURE')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_04_real_auditor_self_signature_bad_original_denied(self):
        Path(self.receiver_actors[0]['signed_reference_original']['path']).write_bytes(b'UNSIGNED')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_05_real_gossip_challenge_signature_bytes_wrong_denied(self):
        Path(self.challenge['path']).write_bytes(b'NOT-OLD-CHALLENGE')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_06_real_gossip_reply_signature_bytes_wrong_denied(self):
        Path(self.reply['path']).write_bytes(b'NOT-OLD-REPLY')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_07_real_signed_request_original_bytes_mutated_denied(self):
        Path(self.req['a']['path']).write_bytes(b'NOT-OLD-REQUEST')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_08_real_signed_receipt_original_bytes_mutated_denied(self):
        Path(self.receipt['b']['path']).write_bytes(b'NOT-OLD-RECEIPT')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_09_real_checkpoint_second_receiver_copy_corruption_denied(self):
        Path(self.cp['b']['path']).write_bytes(b'NEW-COPY-NOT-EQUAL')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_10_real_witness_second_receiver_copy_corruption_denied(self):
        Path(self.wit['a']['path']).write_bytes(b'NEW-WITNESS-COPY-NOT-EQUAL')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_11_signature_forgery_sha_consistent_still_denied(self):
        # The exact new receiver SHA matches the forged file bytes. Isolate
        # the *cryptographic* rejection to prevent an easy outer SHA mismatch
        # from masquerading as an Ed25519 negative test.
        fake=json.loads(Path(self.receipt['a']['path']).read_text())
        fake['signature_ed25519_hex']='f'*128
        new=self.store('ec376_forged_original_receipt_with_SHA',fake)
        self.assertEqual(new['sha256'],core.sha(Path(new['path']).read_bytes()))
        request=json.loads(Path(self.req['a']['path']).read_text())
        request['_sha']=self.req['a']['sha256']
        actors={actor['auditor_id']:{
            'id':actor['auditor_id'],
            'reference_sha':actor['signed_reference_original']['sha256'],
            'key':util.pub(self.private[actor['auditor_id']]),
            'from':core.tr._utc(util.UTC),'until':core.tr._utc(util.EXP),
        } for actor in self.receiver_actors}
        claim={'gossip_reply_original_sha256':self.reply['sha256'],
               'claimed_checkpoint_original_sha256':self.cp['a']['sha256'],
               'log_id':'HistoricLog'}
        with self.assertRaises(errors.AnchorError) as failure:
            ec355._receipt(Path(new['path']).read_bytes(),request,claim,
                           actors,core.tr._utc(util.EV))
        self.assertIn('SIGNATURE',failure.exception.code.upper())
        # A forged new receipt reference is also rejected by the complete
        # old-manifest/receiver pin path, not promoted into its historic ACK.
        self.epochs[0]['disclosure_requests'][0]['responses'][0][
            'signed_receipt_original']=new
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_12_invalid_old_unsigned_manifest_reference_sha_denied(self):
        self.epochs[1]['disclosure_requests'][0]['signed_request_original']={
            **self.req['a'],'sha256':'f'*64}
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_13_broken_ack_signed_parent_receipt_link_denied(self):
        # The previous EC375 signed ACK is really checked; merely changing
        # a new unsigned receiver mapping cannot redirect its original SHA.
        self.epochs[0]['disclosure_requests'][0]['responses'][0][
            'signed_receipt_original']=self.receipt['b']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_14_gossip_nonexistent_sender_path_labels_never_opened(self):
        self.assertFalse(Path(self.old_label(self.challenge)['path']).exists())
        self.assertFalse(Path(self.old_label(self.req['a'])['path']).exists())
        doc=self.derive()
        self.assertFalse(doc['sender_origin_path_required_or_read'])
        self.assertFalse(doc['prior_ec355_ec354_sender_paths_opened_as_authority'])

    def test_15_receiver_copy_cannot_use_historic_origin_path_label(self):
        self.epochs[0]['exchanges'][0]['signed_challenge_original']=self.old_label(
            self.challenge)
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_16_independent_gossip_SHA_pin_drift_is_adverse(self):
        d=self.audit(historical_disclosure_gossip_bundle_shas=['f'*64]*2)
        self.assertTrue(d[core.FLAGS[1]])
        self.assertFalse(d['local_pinned_historical_disclosure_signatures_and_ack_links_consistent'])

    def test_17_independent_signed_auditor_inventory_pin_drift_adverse(self):
        d=self.audit(historical_disclosure_auditor_key_inventory_shas=['e'*64]*2)
        self.assertTrue(d[core.FLAGS[1]])

    def test_18_independent_retained_canonical_inventory_drift_adverse(self):
        d=self.audit(expected_retained_historical_disclosure_inventory_sha256='e'*64)
        self.assertTrue(d[core.FLAGS[1]])

    def test_19_request_or_receipt_count_floor_cannot_manufacture_coverage(self):
        d=self.audit(minimum_historical_disclosure_receipt_counts=[3,3])
        self.assertTrue(d[core.FLAGS[1]])

    def test_20_unsigned_derive_is_canonical_and_never_certifies_retention(self):
        doc=self.derive()
        self.assertFalse(doc['caller_external_inventory_pin_created_or_certified'])
        self.assertEqual(doc['receiver_verified_historical_disclosure_inventory_sha256'],
            core.sha(canonical.canonical(doc['unsigned_verified_historical_disclosure_inventory'])))

    def test_21_forged_new_wrapper_parent_canonical_digest_denied(self):
        self.epochs[0]['epoch_index']=0
        d=json.loads(Path(self.archive['path']).read_text())
        d['parent_ec375_canonical_result_sha256']='e'*64
        self.archive=self.store('ec376_forged_parent_hash',d)
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_22_new_wrapper_extra_untrusted_key_denied(self):
        self.epochs[0]['download_url']='https://untrusted.example/'
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_23_wrong_ec354_auditor_key_sha_fails_before_signature_trust(self):
        self.epochs[0]['auditors'][0]['public_key_original']=self.receiver_actors[1][
            'public_key_original']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_24_old_ec355_signed_reply_earliest_nonce_claim_not_fabricated(self):
        d=self.derive()
        self.assertEqual(d['verified_real_ec354_signed_gossip_reply_count'],2)
        self.assertFalse(d['complete_old_ec354_through_ec337_canonical_parent_replay_performed'])

    def argv(self,unified=False,derive=False):
        from publication_accountability import accountability as p370
        from historical_archive import archive as p371
        from historical_authority import authority_archive as p372
        from historical_inclusion import inclusion_archive as p373
        from historical_owner import owner_archive as p374
        from historical_custody import custody_archive as p375
        opts=self.options(expected_retained_historical_disclosure_inventory_sha256=
               self.derive()['receiver_verified_historical_disclosure_inventory_sha256'])
        command='derive-historical-disclosure-inventory' if derive else \
                'audit-historical-disclosure-archive'
        argv=[sys.executable,'-I','-B',str(ROOT/'scripts'/(
            'ces_next.py' if unified else 'ces_cas_historical_disclosure_archive.py')),
            command]
        if unified:argv+=['DeliveryAudit','AuditHistoricalDisclosureArchive']
        scalars=(*p370.prior.SCALARS,*p370.NEW_SCALARS,
                 *p371.NEW_SCALARS,*p371.AUDIT_ONLY,
                 *p372.NEW_SCALARS,*p372.AUDIT_ONLY,
                 *p373.NEW_SCALARS,*p373.AUDIT_ONLY,
                 *p374.NEW_SCALARS,*p374.AUDIT_ONLY,
                 *p375.NEW_SCALARS,*p375.AUDIT_ONLY,*core.NEW_SCALARS)
        if not derive:scalars+=core.AUDIT_ONLY
        for key in scalars:argv.extend(['--'+key.replace('_','-'),str(opts[key])])
        for key,flag in (*p370.prior.REPEATS,*p370.NEW_REPEATS,
                         *p371.NEW_REPEATS,*p372.NEW_REPEATS,*p373.NEW_REPEATS,
                         *p374.NEW_REPEATS,*p375.NEW_REPEATS,*core.NEW_REPEATS):
            for val in opts[key]:argv.extend([flag,'none' if val is None else str(val)])
        return argv

    def test_25_fixed_isolated_unified_live_ec375_to_ec369_replay(self):
        proc=subprocess.run(self.argv(unified=True),capture_output=True,
                            text=True,timeout=180)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[:1800])
        doc=json.loads(proc.stdout)
        self.assertEqual(doc['schema'],core.RESULT_SCHEMA)
        self.assertTrue(doc['local_pinned_historical_disclosure_signatures_and_ack_links_consistent'])

    def test_26_fixed_isolated_standalone_true_original_unsigned_derive(self):
        proc=subprocess.run(self.argv(derive=True),capture_output=True,
                            text=True,timeout=180)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[:1800])
        self.assertEqual(json.loads(proc.stdout)['schema'],core.DERIVE_SCHEMA)

    def test_27_fixed_unified_isolated_signature_corruption_denied(self):
        argv=self.argv(unified=True)
        Path(self.req['b']['path']).write_bytes(b'BROKEN-EARLIER-SIGNED-REQUEST')
        proc=subprocess.run(argv,capture_output=True,text=True,timeout=180)
        self.assertIn(proc.returncode,(3,4,5),proc.stderr+' '+proc.stdout[:1400])
        doc=json.loads(proc.stdout)
        self.assertEqual(doc['schema'],core.DENIAL_SCHEMA)
        self.assertFalse(doc['sender_origin_path_required_or_read'])

if __name__=='__main__':unittest.main()
