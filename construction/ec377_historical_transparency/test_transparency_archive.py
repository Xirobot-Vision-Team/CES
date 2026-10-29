#!/usr/bin/env python3
"""EC377 genuine old EC353 Ed25519 + RFC6962 leaf and signed ancestry tests.

Uses EC376's deliberately MOCKED EC366->EC337 historical fixture. The
isolated child tests use the real EC376->EC369 production receiver chain;
this suite never claims complete genuine old EC352->EC337 parent results.
"""
from __future__ import annotations

import copy
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import unittest
from types import MethodType
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import transparency as tr
from ec354_gossip import gossip as ec354
from ec355_disclosure import disclosure as ec355
from ec367_witness_distribution import test_distribution as util
from ec376_historical_disclosure import test_disclosure_archive as previous_tests
from . import transparency_archive as core

ROOT=Path(__file__).resolve().parents[2]


def upgrade_previous_fixture(fx):
    """Before EC375 signs its ACKs, replace EC376's placeholder bytes with
    real *original-domain signed* EC353 log checkpoints + witness statements.
    """
    previous_tests.HistoricTrueSignedDisclosureOriginalsTests.prepare_signed_originals(fx)
    fx.new_log_private={};fx.logs=[];fx.pub_receiver_logs=[]
    for i,logid in enumerate(('HistoricLog','HistoricSecondLog')):
        log_priv=ed25519.Ed25519PrivateKey.generate()
        wit_priv=ed25519.Ed25519PrivateKey.generate()
        logkey=fx.store('ec377_log_pub_'+str(i),util.pub(log_priv))
        witkey=fx.store('ec377_witness_pub_'+str(i),util.pub(wit_priv))
        logref=fx.sign('ec377_old_signed_log_reference_'+str(i),{
            'schema':tr.LOG_REF_SCHEMA,'log_id':logid,
            'log_public_key_original_sha256':logkey['sha256'],
            'claimed_log_organization':'Historic Merkle Log Organisation '+str(i),
            'claimed_log_publication_uri':'https://merklelog'+str(i)+'.example.invalid/',
            'valid_from_utc':util.UTC,'valid_until_utc':util.EXP},
            log_priv,tr.LOG_REF_DOMAIN)
        witref=fx.sign('ec377_old_signed_witness_reference_'+str(i),{
            'schema':tr.WITNESS_REF_SCHEMA,'log_id':logid,
            'witness_public_key_original_sha256':witkey['sha256'],
            'claimed_witness_organization':'Historic Merkle Witness Organisation '+str(i),
            'claimed_witness_document_uri':'https://merklewitness'+str(i)+'.example.invalid/',
            'valid_from_utc':util.UTC,'valid_until_utc':util.EXP},
            wit_priv,tr.WITNESS_REF_DOMAIN)
        artifact=fx.store('ec377_receiver_old_ec352_leaf_'+str(i),
                          ('genuine-received-legacy-ec352-slice-'+str(i)).encode())
        leaf=Path(artifact['path']).read_bytes()
        cpbody={'schema':tr.CHECKPOINT_SCHEMA,'log_id':logid,
                'log_reference_original_sha256':logref['sha256'],
                'previous_checkpoint_original_sha256':tr.GENESIS,
                'tree_size':1,'root_hash_sha256':tr.leaf_hash(leaf).hex(),
                'issued_utc':util.UTC}
        cp=fx.store('ec377_real_old_ec353_signed_checkpoint_'+str(i),{
            **cpbody,'log_signature_ed25519_hex':log_priv.sign(
                tr.CHECKPOINT_DOMAIN+canonical.canonical(cpbody)).hex()})
        witbody={'schema':tr.WITNESS_SCHEMA,'log_id':logid,
                 'checkpoint_original_sha256':cp['sha256'],
                 'witness_reference_original_sha256':witref['sha256'],
                 'tree_size':1,'root_hash_sha256':cpbody['root_hash_sha256'],
                 'witnessed_utc':util.UTC}
        wit=fx.store('ec377_real_old_ec353_signed_witness_'+str(i),{
            **witbody,'witness_signature_ed25519_hex':wit_priv.sign(
                tr.WITNESS_DOMAIN+canonical.canonical(witbody)).hex()})
        proof=fx.store('ec377_real_old_ec353_rfc6962_inclusion_'+str(i),{
            'schema':tr.INCLUSION_SCHEMA,'log_id':logid,
            'checkpoint_original_sha256':cp['sha256'],
            'artifact_kind':'registry_root_reference',
            'artifact_original_sha256':artifact['sha256'],
            'leaf_index':0,'audit_path_sha256_hex':[]})
        old_log={'log_id':logid,'log_reference':fx.old_label(logref),
            'log_public_key':fx.old_label(logkey),
            'witness_reference':fx.old_label(witref),
            'witness_public_key':fx.old_label(witkey),
            'checkpoints':[{'checkpoint':fx.old_label(cp),
                            'witness_statement':fx.old_label(wit),
                            'consistency_proof':None}],
            'inclusions':[fx.old_label(proof)]}
        new_log={'log_id':logid,'log_public_key_original':logkey,
            'log_reference_original':logref,'witness_public_key_original':witkey,
            'witness_reference_original':witref,
            'checkpoints':[{'signed_checkpoint_original':cp,
                'signed_witness_original':wit,'consistency_original':None}],
            'inclusions':[{'proof_original':proof,'artifact_original':artifact}]}
        fx.logs.append(old_log);fx.pub_receiver_logs.append(new_log)
        fx.new_log_private[logid]=(log_priv,wit_priv)
    fx.publication=fx.store('ec377_original_old_ec353_unsigned_publication_bundle',{
        'schema':tr.BUNDLE_SCHEMA,'logs':fx.logs})
    # Replace ALL old signed EC354/355 evidence before EC375 genuinely signs
    # EC356 custody ACKs, and regenerate the original old unsigned manifests.
    signed_cp=fx.pub_receiver_logs[0]['checkpoints'][0]['signed_checkpoint_original']
    signed_wit=fx.pub_receiver_logs[0]['checkpoints'][0]['signed_witness_original']
    challenged=json.loads(Path(fx.challenge['path']).read_text())
    challenged.pop('signature_ed25519_hex')
    challenged.update(parent_publication_bundle_original_sha256=fx.publication['sha256'],
        log_reference_original_sha256=fx.pub_receiver_logs[0][
            'log_reference_original']['sha256'],
        checkpoint_original_sha256=signed_cp['sha256'],
        tree_size=1,
        root_hash_sha256=json.loads(Path(signed_cp['path']).read_text())['root_hash_sha256'])
    fx.challenge=fx.sign('ec377_true_gossip_challenge',challenged,
                         fx.private['AuditorChallenger'],ec354.CHALLENGE_DOMAIN)
    fx.cp={};fx.wit={}
    cpbytes=Path(signed_cp['path']).read_bytes()
    witbytes=Path(signed_wit['path']).read_bytes()
    for slot in ('a','b'):
        fx.cp[slot]=fx.store('ec377_real_signed_ec353_checkpoint_received_copy_'+slot,cpbytes)
        fx.wit[slot]=fx.store('ec377_real_signed_ec353_witness_received_copy_'+slot,witbytes)
    reply=json.loads(Path(fx.reply['path']).read_text())
    reply.pop('signature_ed25519_hex')
    reply.update(challenge_original_sha256=fx.challenge['sha256'],
                 checkpoint_original_sha256=signed_cp['sha256'],
                 tree_size=1,root_hash_sha256=challenged['root_hash_sha256'])
    fx.reply=fx.sign('ec377_true_gossip_reply',reply,fx.private['AuditorResponder'],
                     ec354.REPLY_DOMAIN)
    fx.gossip=fx.store('ec377_old_unsigned_real_ec354_gossip_manifest',{
        'schema':ec354.BUNDLE_SCHEMA,'auditors':fx.auditors,
        'exchanges':[{'challenge':fx.old_label(fx.challenge),
                      'replies':[fx.old_label(fx.reply)]}]})
    oldreqs=[];newreqs=[]
    for slot in ('a','b'):
        req=json.loads(Path(fx.req[slot]['path']).read_text())
        req.pop('signature_ed25519_hex')
        req.update(parent_gossip_bundle_original_sha256=fx.gossip['sha256'],
                   gossip_challenge_original_sha256=fx.challenge['sha256'],
                   gossip_reply_original_sha256=fx.reply['sha256'],
                   claimed_checkpoint_original_sha256=signed_cp['sha256'],
                   claimed_tree_size=1,claimed_root_hash_sha256=challenged['root_hash_sha256'])
        fx.req[slot]=fx.sign('ec377_reissued_true_ec355_request_'+slot,req,
                              fx.private['AuditorChallenger'],ec355.REQUEST_DOMAIN)
        receipt=json.loads(Path(fx.receipt[slot]['path']).read_text())
        receipt.pop('signature_ed25519_hex')
        target='AuditorResponder' if slot=='a' else 'AuditorPeer'
        receipt.update(request_original_sha256=fx.req[slot]['sha256'],
            gossip_reply_original_sha256=fx.reply['sha256'],
            checkpoint_original_sha256=signed_cp['sha256'],
            witness_original_sha256=signed_wit['sha256'],
            claimed_checkpoint_length=len(cpbytes),claimed_witness_length=len(witbytes))
        fx.receipt[slot]=fx.sign('ec377_reissued_true_ec355_receipt_'+slot,receipt,
                                fx.private[target],ec355.RECEIPT_DOMAIN)
        oldreqs.append({'request':fx.old_label(fx.req[slot]),
            'responses':[{'receipt':fx.old_label(fx.receipt[slot]),
                          'checkpoint':fx.old_label(fx.cp[slot]),
                          'witness_statement':fx.old_label(fx.wit[slot]),
                          'consistency_proof':None}]})
        newreqs.append({'signed_request_original':fx.req[slot],
            'responses':[{'signed_receipt_original':fx.receipt[slot],
                          'checkpoint_original':fx.cp[slot],
                          'witness_original':fx.wit[slot],
                          'consistency_original':None}]})
    fx.disclosure=fx.store('ec377_old_unsigned_real_ec355_disclosure_manifest',{
        'schema':ec355.BUNDLE_SCHEMA,'requests':oldreqs})
    fx.receiver_requests=newreqs
    # EC375 uses literal placeholders to make its old ACK checkpoint copies.
    # Replace those two original byte *copies* before ACK Ed25519 signing.
    original_store=fx.fx.store
    def custody_cp_bytes(name,data):
        if name.startswith('ec375_actual_signed_custody_cp_copy_'):data=cpbytes
        if name.startswith('ec375_actual_signed_custody_witness_copy_'):data=witbytes
        return original_store(name,data)
    fx.fx.store=custody_cp_bytes


class GenuineOldEc353MerkleReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        previous_tests.HistoricTrueSignedDisclosureOriginalsTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        previous_tests.HistoricTrueSignedDisclosureOriginalsTests.tearDownClass()

    def setUp(self):
        self.prev=previous_tests.HistoricTrueSignedDisclosureOriginalsTests(
            'test_01_real_three_auditor_gossip_and_two_receipts_verified')
        self.prev.prepare_signed_originals=MethodType(upgrade_previous_fixture,self.prev)
        self.prev.setUp()
        self.addCleanup(self.prev.doCleanups)
        # Parent ordinary setup already invoked true EC375 audit. EC376's
        # focused unit fixture has intentionally MOCKED deep EC366..EC337.
        self.parent=self.prev.audit()
        self.rows=[]
        self.make_bundle()

    def store(self,name,obj):return self.prev.store(name,obj)

    def make_bundle(self):
        self.rows=[{'epoch_index':i,
            'ec353_publication_bundle_original':self.prev.publication,
            'logs':copy.deepcopy(self.prev.pub_receiver_logs)}
            for i in range(2)]
        self.rebuild()

    def rebuild(self):
        self.archive=self.store('ec377_receiver_real_ec353_archive',{
            'schema':core.BUNDLE_SCHEMA,
            'parent_ec376_canonical_result_sha256':core.sha(canonical.canonical(self.parent)),
            'ec376_historical_disclosure_archive_original_sha256':self.prev.archive['sha256'],
            'claimed_directory_lineage_id':self.prev.fx.old.ec373.old.lineage,
            'epochs':self.rows})

    def keydigest(self):
        return core.sha(canonical.canonical([{'log_id':r['log_id'],
            'log_public_key_original_sha256':r['log_public_key_original']['sha256'],
            'witness_public_key_original_sha256':r['witness_public_key_original']['sha256']}
            for r in self.prev.pub_receiver_logs]))

    def headdigest(self):
        return core.sha(canonical.canonical([{'log_id':r['log_id'],
            'signed_head_original_shas':[r['checkpoints'][-1][
                'signed_checkpoint_original']['sha256']]}
            for r in self.prev.pub_receiver_logs]))

    def options(self,**overrides):
        opts=self.prev.options(expected_retained_historical_disclosure_inventory_sha256=
           self.prev.derive()['receiver_verified_historical_disclosure_inventory_sha256'])
        opts.update(historical_transparency_archive_bundle_file=self.archive['path'],
            expected_historical_transparency_archive_bundle_sha256=self.archive['sha256'],
            historical_transparency_publication_bundle_shas=[self.prev.publication['sha256']]*2,
            historical_transparency_log_key_inventory_shas=[self.keydigest()]*2,
            historical_transparency_signed_head_inventory_shas=[self.headdigest()]*2,
            minimum_historical_transparency_tree_sizes=[1]*2,
            minimum_historical_transparency_inclusion_counts=[2]*2)
        opts.update(overrides)
        return opts

    def derive(self,**overrides):
        with patch.object(core.previous,'audit',return_value=self.parent):
            return core.derive_inventory(**self.options(**overrides))

    def audit(self,**overrides):
        opts=self.options(expected_retained_historical_transparency_inventory_sha256=
                self.derive()['receiver_verified_historical_transparency_inventory_sha256'])
        opts.update(overrides)
        with patch.object(core.previous,'audit',return_value=self.parent):
            return core.audit(**opts)

    def argv(self,unified=False,derive=False):
        from ec370_publication_accountability import accountability as p370
        from ec371_historical_archive import archive as p371
        from ec372_historical_authority import authority_archive as p372
        from ec373_historical_inclusion import inclusion_archive as p373
        from ec374_historical_owner import owner_archive as p374
        from ec375_historical_custody import custody_archive as p375
        from ec376_historical_disclosure import disclosure_archive as p376
        opts=self.options()
        if not derive:
            opts['expected_retained_historical_transparency_inventory_sha256']=self.derive()[
                'receiver_verified_historical_transparency_inventory_sha256']
        cmd='derive-historical-transparency-inventory' if derive else \
            'audit-historical-transparency-archive'
        argv=[sys.executable,'-I','-B',str(ROOT/'scripts'/(
            'ces_next.py' if unified else 'ces_cas_historical_transparency_archive.py')),
            cmd]
        if unified:argv+=['DeliveryAudit','AuditHistoricalTransparencyArchive']
        scalars=(*p370.prior.SCALARS,*p370.NEW_SCALARS,*p371.NEW_SCALARS,
                 *p371.AUDIT_ONLY,*p372.NEW_SCALARS,*p372.AUDIT_ONLY,
                 *p373.NEW_SCALARS,*p373.AUDIT_ONLY,*p374.NEW_SCALARS,
                 *p374.AUDIT_ONLY,*p375.NEW_SCALARS,*p375.AUDIT_ONLY,
                 *p376.NEW_SCALARS,*p376.AUDIT_ONLY,*core.NEW_SCALARS)
        if not derive:scalars+=core.AUDIT_ONLY
        for k in scalars:argv.extend(['--'+k.replace('_','-'),str(opts[k])])
        for k,flag in (*p370.prior.REPEATS,*p370.NEW_REPEATS,
                       *p371.NEW_REPEATS,*p372.NEW_REPEATS,*p373.NEW_REPEATS,
                       *p374.NEW_REPEATS,*p375.NEW_REPEATS,*p376.NEW_REPEATS,
                       *core.NEW_REPEATS):
            for value in opts[k]:argv.extend([flag,'none' if value is None else str(value)])
        return argv

    def append_second_signed_checkpoint(self,*,fork=False,bad_consistency=False):
        from ec353_transparency import test_transparency as merkle_util
        idx=1
        old=copy.deepcopy(self.prev.logs[idx])
        receiver=copy.deepcopy(self.prev.pub_receiver_logs[idx])
        oldcp=receiver['checkpoints'][0]['signed_checkpoint_original']
        oldbody=json.loads(Path(oldcp['path']).read_text())
        pub=receiver['witness_reference_original']
        logpriv,witpriv=self.prev.new_log_private[old['log_id']]
        new_art=self.store('ec377_second_merkle_leaf',b'received-true-second-signed-leaf')
        old_art=receiver['inclusions'][0]['artifact_original']
        raw_a=Path(old_art['path']).read_bytes()
        raw_b=Path(new_art['path']).read_bytes()
        cpbody={'schema':tr.CHECKPOINT_SCHEMA,'log_id':old['log_id'],
            'log_reference_original_sha256':receiver['log_reference_original']['sha256'],
            'previous_checkpoint_original_sha256':tr.GENESIS if fork else oldcp['sha256'],
            'tree_size':1 if fork else 2,
            'root_hash_sha256':tr.leaf_hash(raw_b).hex() if fork else
                 merkle_util.root([raw_a,raw_b]).hex(),
            'issued_utc':util.UTC}
        cp=self.store('ec377_second_actual_signed_log_checkpoint',{
            **cpbody,'log_signature_ed25519_hex':logpriv.sign(
                tr.CHECKPOINT_DOMAIN+canonical.canonical(cpbody)).hex()})
        witbody={'schema':tr.WITNESS_SCHEMA,'log_id':old['log_id'],
            'checkpoint_original_sha256':cp['sha256'],
            'witness_reference_original_sha256':pub['sha256'],
            'tree_size':cpbody['tree_size'],
            'root_hash_sha256':cpbody['root_hash_sha256'],
            'witnessed_utc':util.UTC}
        wit=self.store('ec377_second_actual_signed_witness',{
            **witbody,'witness_signature_ed25519_hex':witpriv.sign(
                tr.WITNESS_DOMAIN+canonical.canonical(witbody)).hex()})
        cons=None
        if not fork:
            consistency={'schema':tr.CONSISTENCY_SCHEMA,'log_id':old['log_id'],
                'previous_checkpoint_original_sha256':oldcp['sha256'],
                'next_checkpoint_original_sha256':cp['sha256'],
                'previous_tree_size':1,'next_tree_size':2,
                'audit_path_sha256_hex':['f'*64 if bad_consistency else
                    tr.leaf_hash(raw_b).hex()]}
            cons=self.store('ec377_second_real_rfc6962_consistency',consistency)
        old['checkpoints'].append({'checkpoint':self.prev.old_label(cp),
            'witness_statement':self.prev.old_label(wit),
            'consistency_proof':self.prev.old_label(cons) if cons else None})
        receiver['checkpoints'].append({'signed_checkpoint_original':cp,
            'signed_witness_original':wit,'consistency_original':cons})
        if not fork:
            incl=self.store('ec377_second_real_merkle_inclusion',{
                'schema':tr.INCLUSION_SCHEMA,'log_id':old['log_id'],
                'checkpoint_original_sha256':cp['sha256'],
                'artifact_kind':'registry_root_reference',
                'artifact_original_sha256':new_art['sha256'],
                'leaf_index':1,'audit_path_sha256_hex':[tr.leaf_hash(raw_a).hex()]})
            old['inclusions'].append(self.prev.old_label(incl))
            receiver['inclusions'].append({'proof_original':incl,
                                         'artifact_original':new_art})
        return old,receiver,cp

    def audit_log_slice(self,old,receiver):
        def pinned_read(ref,role,cap):
            raw=Path(ref['path']).read_bytes()
            self.assertEqual(core.sha(raw),ref['sha256'])
            self.assertLessEqual(len(raw),cap)
            return raw
        return core._log(old,receiver,pinned_read,set(),tr._utc(util.EV),
                         set(),Counter(),set())

    def test_01_true_old_log_witness_merkle_and_ec354_ec355_join(self):
        doc=self.audit()
        self.assertEqual(doc['exit_code'],2)
        self.assertEqual(doc['verified_real_ec353_signed_log_reference_count'],4)
        self.assertEqual(doc['verified_real_ec353_signed_checkpoint_count'],4)
        self.assertEqual(doc['verified_real_ec353_signed_witness_count'],4)
        self.assertEqual(doc['verified_original_rfc6962_merkle_inclusion_count'],4)
        self.assertEqual(doc['verified_bound_old_ec354_signed_challenge_count'],2)
        self.assertEqual(doc['verified_bound_old_ec355_furnished_original_pair_count'],4)
        self.assertTrue(doc['local_pinned_ec353_signatures_merkle_and_old_claims_consistent'])
        self.assertFalse(doc['complete_old_ec353_through_ec337_canonical_parent_results_rebuilt'])

    def test_02_true_original_signed_log_bad_bytes_denied(self):
        p=self.prev.pub_receiver_logs[0]['checkpoints'][0]['signed_checkpoint_original']['path']
        Path(p).write_bytes(b'OLD-EC353-CHECKPOINT-CORRUPT')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_03_true_original_signed_witness_bad_bytes_denied(self):
        p=self.prev.pub_receiver_logs[0]['checkpoints'][0]['signed_witness_original']['path']
        Path(p).write_bytes(b'OLD-EC353-WITNESS-CORRUPT')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_04_recovered_log_public_key_byte_corruption_denied(self):
        p=self.prev.pub_receiver_logs[1]['log_public_key_original']['path']
        Path(p).write_bytes(b'BROKEN-LOG-KEY')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_05_recovered_witness_reference_signature_corruption_denied(self):
        p=self.prev.pub_receiver_logs[0]['witness_reference_original']['path']
        Path(p).write_bytes(b'BROKEN-SELF-SIGNATURE')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_06_merkle_leaf_sha_consistent_wrong_proof_denied(self):
        newproof=copy.deepcopy(json.loads(Path(self.prev.pub_receiver_logs[1][
            'inclusions'][0]['proof_original']['path']).read_text()))
        newproof['audit_path_sha256_hex']=['f'*64]
        newref=self.store('ec377_sha_consistent_invalid_merkle_path',newproof)
        self.assertEqual(newref['sha256'],core.sha(Path(newref['path']).read_bytes()))
        receiver=copy.deepcopy(self.prev.pub_receiver_logs[1])
        receiver['inclusions'][0]['proof_original']=newref
        old=copy.deepcopy(self.prev.logs[1]);old['inclusions'][0]=self.prev.old_label(newref)
        with self.assertRaises(errors.AnchorError) as failed:
            self.audit_log_slice(old,receiver)
        self.assertIn('INCLUSION_NOT_VERIFIED',failed.exception.code)

    def test_07_original_ec353_bundle_byte_mutation_denied(self):
        Path(self.prev.publication['path']).write_bytes(b'REPLACED')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_08_original_signed_ec354_challenge_ec353_parent_binding_denied(self):
        self.rows[0]['ec353_publication_bundle_original']={**self.prev.publication,
                                                            'sha256':'f'*64}
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_09_wrong_original_receiver_checkpoint_mapping_denied(self):
        self.rows[0]['logs'][0]['checkpoints'][0]['signed_checkpoint_original']=self.rows[0][
            'logs'][1]['checkpoints'][0]['signed_checkpoint_original']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_10_old_sender_labels_never_opened(self):
        self.assertFalse(Path(self.prev.logs[0]['log_reference']['path']).exists())
        self.assertFalse(Path(self.prev.logs[0]['checkpoints'][0]['checkpoint']['path']).exists())
        doc=self.derive()
        self.assertFalse(doc['sender_origin_path_required_or_read'])

    def test_11_receiver_path_cannot_be_old_sender_label(self):
        self.rows[0]['logs'][0]['log_public_key_original']=self.prev.logs[0]['log_public_key']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_12_unretained_head_pin_reports_adversity_not_success(self):
        doc=self.audit(historical_transparency_signed_head_inventory_shas=['f'*64]*2)
        self.assertTrue(doc[core.FLAGS[1]])
        self.assertFalse(doc['local_pinned_ec353_signatures_merkle_and_old_claims_consistent'])

    def test_13_unretained_inclusion_floor_reports_adversity(self):
        doc=self.audit(minimum_historical_transparency_inclusion_counts=[3,3])
        self.assertTrue(doc[core.FLAGS[1]])

    def test_14_genuinely_signed_competing_genesis_fork_is_adverse(self):
        old,receiver,_=self.append_second_signed_checkpoint(fork=True)
        evidence=self.audit_log_slice(old,receiver)
        self.assertTrue(evidence['fork'])
        self.assertEqual(len(evidence['heads']),2)
        self.assertEqual(len(evidence['checkpoints']),2)

    def test_19_real_two_leaf_signed_checkpoint_append_only_and_inclusion(self):
        old,receiver,newcp=self.append_second_signed_checkpoint()
        evidence=self.audit_log_slice(old,receiver)
        self.assertFalse(evidence['fork'])
        self.assertFalse(evidence['consistency_dispute'])
        self.assertEqual(evidence['heads'],[newcp['sha256']])
        self.assertEqual(evidence['inclusion_count'],2)
        self.assertEqual(len(evidence['ancestry'][newcp['sha256']]),2)

    def test_20_sha_consistent_false_consistency_path_is_visible_not_success(self):
        old,receiver,_=self.append_second_signed_checkpoint(bad_consistency=True)
        evidence=self.audit_log_slice(old,receiver)
        self.assertTrue(evidence['consistency_dispute'])
        self.assertFalse(evidence['fork'])

    def test_21_forged_sha_consistent_checkpoint_signature_denied(self):
        old=copy.deepcopy(self.prev.logs[1])
        receiver=copy.deepcopy(self.prev.pub_receiver_logs[1])
        forged=json.loads(Path(receiver['checkpoints'][0][
            'signed_checkpoint_original']['path']).read_text())
        forged['log_signature_ed25519_hex']='f'*128
        forgedref=self.store('ec377_sha_consistent_wrong_old_ec353_log_signature',forged)
        self.assertEqual(forgedref['sha256'],core.sha(Path(forgedref['path']).read_bytes()))
        receiver['checkpoints'][0]['signed_checkpoint_original']=forgedref
        old['checkpoints'][0]['checkpoint']=self.prev.old_label(forgedref)
        with self.assertRaises(errors.AnchorError) as failure:
            self.audit_log_slice(old,receiver)
        self.assertIn('SIGNATURE_INVALID',failure.exception.code)

    def test_22_parent_substitute_success_report_rejected_before_merkle(self):
        opts=self.options()
        with patch.object(core.previous,'audit',return_value={'schema':core.previous.RESULT_SCHEMA,
                          'exit_code':0,'sender_origin_path_required_or_read':False}):
            with self.assertRaises(errors.AnchorError) as failure:
                core.derive_inventory(**opts)
        self.assertIn('PRODUCTION_EC376',failure.exception.code)

    def test_15_actual_parent_unresolved_not_upgraded(self):
        d=self.audit()
        self.assertEqual(d['status'],core.OUTCOMES[-1]+'_unresolved')
        self.assertTrue(d[core.FLAGS[-1]])
        self.assertFalse(d['ec353_through_ec337_full_historical_parent_replay_performed'])

    def test_16_standalone_isolated_true_parent_evidence_derive(self):
        p=subprocess.run(self.argv(derive=True),capture_output=True,text=True,timeout=180)
        self.assertEqual(p.returncode,2,p.stderr+' '+p.stdout[:1600])
        self.assertEqual(json.loads(p.stdout)['schema'],core.DERIVE_SCHEMA)

    def test_17_unified_isolated_true_production_ec376_to_ec369_audit(self):
        p=subprocess.run(self.argv(unified=True),capture_output=True,text=True,timeout=180)
        self.assertEqual(p.returncode,2,p.stderr+' '+p.stdout[:1600])
        self.assertEqual(json.loads(p.stdout)['schema'],core.RESULT_SCHEMA)

    def test_18_unified_isolated_signed_original_corruption_denied(self):
        argv=self.argv(unified=True)
        Path(self.prev.pub_receiver_logs[1]['checkpoints'][0][
             'signed_witness_original']['path']).write_bytes(b'BAD-WITNESS-ORIGINAL')
        p=subprocess.run(argv,capture_output=True,text=True,timeout=180)
        self.assertIn(p.returncode,(3,4,5),p.stderr+' '+p.stdout[:1600])
        self.assertEqual(json.loads(p.stdout)['schema'],core.DENIAL_SCHEMA)

if __name__=='__main__':unittest.main()
