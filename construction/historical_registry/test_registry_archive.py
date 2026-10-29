#!/usr/bin/env python3
"""EC378: real historical EC352 Ed25519 domains under genuine EC353 signed logs.

Old EC377->EC369 production is genuinely run for isolated child cases; only
its inherited EC366->EC337 deep fixture remains deliberately mocked. No test
pretends to supply historic actual EC351 original issuer authority.
"""
from __future__ import annotations

import copy
import json
import io
import os
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from key_registry import registry as old352
from transparency import transparency as old353
from transparency import test_transparency as merkle
from witness_distribution import test_distribution as util
from historical_transparency import test_transparency_archive as old_fixture
from . import registry_archive as core

ROOT=Path(__file__).resolve().parents[2]
ORIGINAL_EC377_UPGRADE=old_fixture.upgrade_previous_fixture


def genuine_registry_origins(fx):
    """Inject unchanged genuine EC352 Ed25519 originals *before* old EC353
    checkpoint/gossip/receipt/EC356 ACK signing, never after. This preserves
    actual signed parent SHA/copy causality through all newer parent layers.
    """
    save=fx.store
    def intercept(name,obj):
        if name=='ec377_original_old_ec353_unsigned_publication_bundle':
            keys=[];origins=[];registries=[]
            for i,ch in enumerate(('HistoricRegistryA','HistoricRegistryB')):
                rootpriv=ed25519.Ed25519PrivateKey.generate()
                signerpriv=ed25519.Ed25519PrivateKey.generate()
                rootkey=save('ec378_real_old_ec352_root_key_'+ch,util.pub(rootpriv))
                signerkey=save('ec378_real_old_ec352_operator_key_'+ch,util.pub(signerpriv))
                body={'schema':old352.ROOT_SCHEMA,'registry_channel_id':ch,
                  'root_public_key_original_sha256':rootkey['sha256'],
                  'claimed_issuer_organization':'Historical Issuer '+str(i),
                  'claimed_issuer_document_uri':'https://issuer'+str(i)+'.example.invalid/',
                  'valid_from_utc':util.UTC,'valid_until_utc':util.EXP}
                rootref=save('ec378_original_old_ec352_signed_root_ref_'+ch,{
                    **body,'self_signature_ed25519_hex':rootpriv.sign(
                        old352.ROOT_DOMAIN+canonical.canonical(body)).hex()})
                eventbody={'schema':old352.EVENT_SCHEMA,
                    'registry_channel_id':ch,'sequence':1,
                    'previous_event_sha256':old352.GENESIS,
                    'event_kind':'activate',
                    'root_reference_original_sha256':rootref['sha256'],
                    'root_public_key_original_sha256':rootkey['sha256'],
                    'signer_public_key_original_sha256':signerkey['sha256'],
                    'issued_utc':util.UTC,'valid_until_utc':util.EXP,
                    'entries':[]}
                event=save('ec378_original_old_ec352_signed_event_'+ch,{
                    **eventbody,'root_signature_ed25519_hex':rootpriv.sign(
                        old352.EVENT_DOMAIN+canonical.canonical(eventbody)).hex(),
                    'previous_signer_signature_ed25519_hex':old352.NONE,
                    'current_signer_signature_ed25519_hex':signerpriv.sign(
                        old352.OPERATOR_DOMAIN+canonical.canonical(eventbody)).hex()})
                keys.append((rootpriv,signerpriv))
                registries.append({'registry_channel_id':ch,
                    'root_public_key_original':rootkey,
                    'root_reference_original':rootref,
                    'events':[{'signed_event_original':event,
                               'signer_public_key_original':signerkey}]})
                origins.extend([('registry_root_reference',rootref),
                                ('registry_event',event)])
            fx.ec378_registries=registries
            fx.ec378_private=keys
            leaves=[Path(ref['path']).read_bytes() for _,ref in origins]
            for index,(oldlog,received) in enumerate(zip(fx.logs,fx.pub_receiver_logs)):
                logid=oldlog['log_id'];logpriv,witpriv=fx.new_log_private[logid]
                logref=received['log_reference_original']
                witref=received['witness_reference_original']
                body={'schema':old353.CHECKPOINT_SCHEMA,'log_id':logid,
                    'log_reference_original_sha256':logref['sha256'],
                    'previous_checkpoint_original_sha256':old353.GENESIS,
                    'tree_size':len(origins),
                    'root_hash_sha256':merkle.root(leaves).hex(),
                    'issued_utc':util.UTC}
                cp=save('ec378_ec353_real_signed_checkpoint_'+str(index),{
                   **body,'log_signature_ed25519_hex':logpriv.sign(
                         old353.CHECKPOINT_DOMAIN+canonical.canonical(body)).hex()})
                witbody={'schema':old353.WITNESS_SCHEMA,'log_id':logid,
                    'checkpoint_original_sha256':cp['sha256'],
                    'witness_reference_original_sha256':witref['sha256'],
                    'tree_size':len(origins),'root_hash_sha256':body['root_hash_sha256'],
                    'witnessed_utc':util.UTC}
                wit=save('ec378_ec353_real_signed_witness_'+str(index),{
                    **witbody,'witness_signature_ed25519_hex':witpriv.sign(
                        old353.WITNESS_DOMAIN+canonical.canonical(witbody)).hex()})
                oldlog['checkpoints']=[{'checkpoint':fx.old_label(cp),
                       'witness_statement':fx.old_label(wit),'consistency_proof':None}]
                received['checkpoints']=[{'signed_checkpoint_original':cp,
                       'signed_witness_original':wit,'consistency_original':None}]
                oldlog['inclusions']=[];received['inclusions']=[]
                for j,(kind,ref) in enumerate(origins):
                    proof=save('ec378_ec353_real_inclusion_'+str(index)+'_'+str(j),{
                      'schema':old353.INCLUSION_SCHEMA,'log_id':logid,
                      'checkpoint_original_sha256':cp['sha256'],
                      'artifact_kind':kind,'artifact_original_sha256':ref['sha256'],
                      'leaf_index':j,'audit_path_sha256_hex':[
                          h.hex() for h in merkle.inclusion(leaves,j)]})
                    oldlog['inclusions'].append(fx.old_label(proof))
                    received['inclusions'].append({'proof_original':proof,
                         'artifact_original':ref})
            obj={'schema':old353.BUNDLE_SCHEMA,'logs':fx.logs}
        return save(name,obj)
    sign=fx.sign
    def resized_sign(name,body,key,domain):
        if (name=='ec377_true_gossip_challenge' or
            name=='ec377_true_gossip_reply'):
            body={**body,'tree_size':4}
        elif name.startswith('ec377_reissued_true_ec355_request_'):
            body={**body,'claimed_tree_size':4}
        return sign(name,body,key,domain)
    fx.store=intercept
    fx.sign=resized_sign
    try:ORIGINAL_EC377_UPGRADE(fx)
    finally:
        fx.store=save
        fx.sign=sign


class OriginalEc352RegistryUnderEc353Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):old_fixture.GenuineOldEc353MerkleReceiverTests.setUpClass()

    @classmethod
    def tearDownClass(cls):old_fixture.GenuineOldEc353MerkleReceiverTests.tearDownClass()

    def setUp(self):
        self.fx=old_fixture.GenuineOldEc353MerkleReceiverTests(
            'test_01_true_old_log_witness_merkle_and_ec354_ec355_join')
        with patch.object(old_fixture,'upgrade_previous_fixture',genuine_registry_origins):
            self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.parent=self.fx.audit()
        self.registries=copy.deepcopy(self.fx.prev.ec378_registries)
        self.epochs=[]
        self.make_archive()

    def store(self,name,obj):return self.fx.store(name,obj)

    def make_archive(self):
        self.epochs=[{'epoch_index':i,'claimed_tsa_channel_ids':
                     ['HistoricTsaChannelA','HistoricTsaChannelB'],
                     'registries':copy.deepcopy(self.registries)}
                     for i in range(2)]
        self.rebuild()

    def rebuild(self):
        self.archive=self.store('ec378_real_signed_ec352_receiver_archive',{
            'schema':core.BUNDLE_SCHEMA,
            'parent_ec377_canonical_result_sha256':core.sha(canonical.canonical(self.parent)),
            'ec377_historical_transparency_archive_original_sha256':self.fx.archive['sha256'],
            'claimed_directory_lineage_id':self.fx.prev.fx.old.ec373.old.lineage,
            'epochs':self.epochs})

    def root_hash(self):
        return core.sha(canonical.canonical([{
           'registry_channel_id':r['registry_channel_id'],
           'root_public_key_original_sha256':r['root_public_key_original']['sha256'],
           'root_reference_original_sha256':r['root_reference_original']['sha256']}
           for r in self.registries]))

    def head_hash(self):
        return core.sha(canonical.canonical([{
           'registry_channel_id':r['registry_channel_id'],
           'signed_terminal_head_original_shas':[
               r['events'][-1]['signed_event_original']['sha256']]}
           for r in self.registries]))

    def opts(self,**overrides):
        opts=self.fx.options(expected_retained_historical_transparency_inventory_sha256=
            self.fx.derive()['receiver_verified_historical_transparency_inventory_sha256'])
        opts.update(historical_registry_archive_bundle_file=self.archive['path'],
            expected_historical_registry_archive_bundle_sha256=self.archive['sha256'],
            historical_registry_root_key_inventory_shas=[self.root_hash()]*2,
            historical_registry_signed_head_inventory_shas=[self.head_hash()]*2,
            minimum_historical_registry_signed_event_counts=[2]*2,
            minimum_historical_registry_dual_log_inclusion_counts=[8]*2)
        opts.update(overrides)
        return opts

    def derive(self,**overrides):
        with patch.object(core.previous,'audit',return_value=self.parent):
            return core.derive_inventory(**self.opts(**overrides))

    def audit(self,**overrides):
        opts=self.opts(expected_retained_historical_registry_inventory_sha256=
              self.derive()['receiver_verified_historical_registry_inventory_sha256'])
        opts.update(overrides)
        with patch.object(core.previous,'audit',return_value=self.parent):
            return core.audit(**opts)

    def argv(self,unified=False):
        from publication_accountability import accountability as p370
        from historical_archive import archive as p371
        from historical_authority import authority_archive as p372
        from historical_inclusion import inclusion_archive as p373
        from historical_owner import owner_archive as p374
        from historical_custody import custody_archive as p375
        from historical_disclosure import disclosure_archive as p376
        from historical_transparency import transparency_archive as p377
        opts=self.opts(expected_retained_historical_registry_inventory_sha256=
                      self.derive()['receiver_verified_historical_registry_inventory_sha256'])
        scalars=(*p370.prior.SCALARS,*p370.NEW_SCALARS,*p371.NEW_SCALARS,
            *p371.AUDIT_ONLY,*p372.NEW_SCALARS,*p372.AUDIT_ONLY,
            *p373.NEW_SCALARS,*p373.AUDIT_ONLY,*p374.NEW_SCALARS,*p374.AUDIT_ONLY,
            *p375.NEW_SCALARS,*p375.AUDIT_ONLY,*p376.NEW_SCALARS,*p376.AUDIT_ONLY,
            *p377.NEW_SCALARS,*p377.AUDIT_ONLY,*core.NEW_SCALARS,*core.AUDIT_ONLY)
        repeats=(*p370.prior.REPEATS,*p370.NEW_REPEATS,*p371.NEW_REPEATS,
            *p372.NEW_REPEATS,*p373.NEW_REPEATS,*p374.NEW_REPEATS,
            *p375.NEW_REPEATS,*p376.NEW_REPEATS,*p377.NEW_REPEATS,*core.NEW_REPEATS)
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts'/(
             'ces_next.py' if unified else 'ces_cas_historical_registry_archive.py')),
             'audit-historical-registry-archive']
        if unified:cmd+=['DeliveryAudit','AuditHistoricalRegistryArchive']
        for k in scalars:cmd+=['--'+k.replace('_','-'),str(opts[k])]
        for k,flag in repeats:
            for v in opts[k]:cmd.extend((flag,'none' if v is None else str(v)))
        return cmd

    def test_01_true_signed_ec352_roots_and_event_originals_in_both_logs(self):
        doc=self.audit()
        self.assertEqual(doc['exit_code'],2)
        self.assertEqual(doc['verified_original_ec352_self_signed_root_reference_count'],4)
        self.assertEqual(doc['verified_original_ec352_root_and_operator_signed_event_count'],4)
        self.assertEqual(doc['verified_original_ec352_signed_merkle_log_membership_count'],16)
        self.assertEqual(doc['missing_signed_head_ancestry_registry_log_memberships'],0)
        self.assertTrue(doc['local_signed_ec352_registry_signatures_and_dual_log_links_consistent'])
        self.assertFalse(doc['old_ec351_source_attestation_issuer_authority_originals_replayed'])
        self.assertTrue(doc[core.FLAGS[-1]])

    def test_02_original_root_sha_consistent_forged_signature_denied(self):
        d=json.loads(Path(self.registries[0]['root_reference_original']['path']).read_text())
        d['self_signature_ed25519_hex']='f'*128
        self.epochs[0]['registries'][0]['root_reference_original']=self.store('forged-root',d)
        self.rebuild()
        with self.assertRaises(errors.AnchorError) as ctx:self.derive()
        self.assertIn('SIGNATURE_INVALID',ctx.exception.code)

    def test_03_original_event_sha_consistent_forged_root_signature_denied(self):
        d=json.loads(Path(self.registries[0]['events'][0]['signed_event_original']['path']).read_text())
        d['root_signature_ed25519_hex']='f'*128
        self.epochs[0]['registries'][0]['events'][0]['signed_event_original']=self.store('forged-event-root',d)
        self.rebuild()
        with self.assertRaises(errors.AnchorError) as ctx:self.derive()
        self.assertIn('SIGNATURE_INVALID',ctx.exception.code)

    def test_04_original_event_sha_consistent_forged_operator_signature_denied(self):
        d=json.loads(Path(self.registries[0]['events'][0]['signed_event_original']['path']).read_text())
        d['current_signer_signature_ed25519_hex']='f'*128
        self.epochs[0]['registries'][0]['events'][0]['signed_event_original']=self.store('forged-event-operator',d)
        self.rebuild()
        with self.assertRaises(errors.AnchorError) as ctx:self.derive()
        self.assertIn('SIGNATURE_INVALID',ctx.exception.code)

    def test_05_root_key_byte_mutation_denied(self):
        Path(self.registries[0]['root_public_key_original']['path']).write_bytes(b'NO_LONGER_32_BYTES')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_06_wrong_parent_canonical_sha_denied(self):
        b=json.loads(Path(self.archive['path']).read_text())
        b['parent_ec377_canonical_result_sha256']='f'*64
        self.archive=self.store('bad-live-parent-binding',b)
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_07_original_event_without_merkle_proof_is_unresolved(self):
        # EC352 event signed by the original root/operator and valid itself,
        # but no original EC353 log contains this new signed event's bytes.
        new=self.signed_event(0,2,'renew')
        for e in self.epochs:e['registries'][0]['events'].append(copy.deepcopy(new))
        self.rebuild()
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[4]])
        self.assertGreater(doc['missing_signed_head_ancestry_registry_log_memberships'],0)
        self.assertFalse(doc['local_signed_ec352_registry_signatures_and_dual_log_links_consistent'])

    def signed_event(self,i,sequence,kind,new_priv=None,bad_previous=False):
        r=self.registries[i]
        old=json.loads(Path(r['events'][0]['signed_event_original']['path']).read_text())
        signerpriv=self.fx.prev.ec378_private[i][1]
        rootpriv=self.fx.prev.ec378_private[i][0]
        signerkey=r['events'][0]['signer_public_key_original']
        if new_priv is not None:
            signerkey=self.store('rotated-signer',util.pub(new_priv))
        body={k:v for k,v in old.items() if k not in (
            'root_signature_ed25519_hex','current_signer_signature_ed25519_hex',
            'previous_signer_signature_ed25519_hex')}
        body.update(sequence=sequence,event_kind=kind,
            signer_public_key_original_sha256=signerkey['sha256'],
            previous_event_sha256=r['events'][0]['signed_event_original']['sha256'])
        original_signer=signerpriv
        current= new_priv or signerpriv
        signed={**body,
          'root_signature_ed25519_hex':rootpriv.sign(
              old352.EVENT_DOMAIN+canonical.canonical(body)).hex(),
          'previous_signer_signature_ed25519_hex':(
              signerpriv.sign(old352.PRIOR_DOMAIN+canonical.canonical(body)).hex()
              if kind=='rotate' and not bad_previous else old352.NONE),
          'current_signer_signature_ed25519_hex':(
              current.sign(old352.OPERATOR_DOMAIN+canonical.canonical(body)).hex()
              if kind!='revoke' else old352.NONE)}
        return {'signed_event_original':self.store('ec378_test_signed_'+kind+str(i),signed),
                'signer_public_key_original':signerkey}

    def test_08_real_ed25519_prior_signer_rotation_verified(self):
        rotated=ed25519.Ed25519PrivateKey.generate()
        newer=self.signed_event(0,2,'rotate',rotated)
        original=self.registries[0]
        def read(ref,role,cap):
            raw=Path(ref['path']).read_bytes()
            self.assertEqual(ref['sha256'],core.sha(raw))
            self.assertLessEqual(len(raw),cap)
            return raw
        seen=set()
        result=core._registry({**original,'events':[original['events'][0],newer]},
                              read,old353._utc(util.EV),set(),set(),seen)
        self.assertEqual(len(result['heads']),1)
        self.assertFalse(result['revoked'])

    def test_09_missing_prior_signer_rotation_signature_denied(self):
        newer=self.signed_event(0,2,'rotate',ed25519.Ed25519PrivateKey.generate(),True)
        def read(ref,role,cap):return Path(ref['path']).read_bytes()
        with self.assertRaises(errors.AnchorError) as ctx:
            core._registry({**self.registries[0],
               'events':[self.registries[0]['events'][0],newer]},read,
               old353._utc(util.EV),set(),set(),set())
        self.assertIn('SIGNATURE',ctx.exception.code)

    def test_10_real_signed_terminal_revocation_is_adverse(self):
        newer=self.signed_event(0,2,'revoke')
        for e in self.epochs:e['registries'][0]['events'].append(copy.deepcopy(newer))
        self.rebuild()
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[2]])

    def test_11_true_signed_event_fork_is_adverse(self):
        one=self.signed_event(0,2,'renew')
        two=self.signed_event(0,2,'revoke')
        for e in self.epochs:e['registries'][0]['events']+=[copy.deepcopy(one),copy.deepcopy(two)]
        self.rebuild()
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[2]])

    def test_12_independent_root_inventory_pin_mismatch_is_adverse(self):
        doc=self.audit(historical_registry_root_key_inventory_shas=['f'*64]*2)
        self.assertTrue(doc[core.FLAGS[1]])

    def test_13_independent_head_inventory_pin_mismatch_is_adverse(self):
        doc=self.audit(historical_registry_signed_head_inventory_shas=['f'*64]*2)
        self.assertTrue(doc[core.FLAGS[1]])

    def test_14_retained_count_floor_mismatch_is_adverse(self):
        doc=self.audit(minimum_historical_registry_signed_event_counts=[4]*2)
        self.assertTrue(doc[core.FLAGS[1]])

    def test_15_historic_log_sender_paths_not_opened(self):
        p=self.fx.prev.logs[0]['log_reference']['path']
        self.assertFalse(Path(p).exists())
        self.assertFalse(self.derive()['sender_origin_path_required_or_read'])

    def test_16_receiver_path_must_not_alias_old_sender_path(self):
        self.epochs[0]['registries'][0]['root_reference_original']=self.fx.prev.logs[0][
              'log_reference']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_17_duplicate_root_operator_key_roles_denied(self):
        self.epochs[0]['registries'][1]['root_public_key_original']=self.registries[0][
               'root_public_key_original']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_18_structurally_invalid_extra_event_fields_denied(self):
        d=json.loads(Path(self.registries[0]['events'][0]['signed_event_original']['path']).read_text())
        d['injected_sender_path']='/tmp/historic'
        self.epochs[0]['registries'][0]['events'][0]['signed_event_original']=self.store('extra-key',d)
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_19_never_treat_merkle_membership_as_official_ec351_auth(self):
        doc=self.audit()
        self.assertFalse(doc['old_ec351_source_attestation_issuer_authority_originals_replayed'])
        self.assertFalse(doc['self_signed_old_registry_root_proves_official_issuer_identity'])
        self.assertFalse(doc['old_ec353_merkle_leaf_alone_proves_root_issuer_authorization'])

    def test_20_fake_parent_success_cannot_substitute(self):
        with patch.object(core.previous,'audit',return_value={'exit_code':0,'status':'pass'}):
            with self.assertRaises(errors.AnchorError):core.audit(**self.opts(
              expected_retained_historical_registry_inventory_sha256='a'*64))

    @unittest.skipUnless(os.getenv("CES_EC378_REAL_DEEP")=="1",
        "Deferred: real EC377->EC369 isolated replay; EC366->EC337 remains mocked")
    def test_21_real_isolated_standalone_and_router_live_parent_replay(self):
        for unified in (False,True):
            proc=subprocess.run(self.argv(unified),capture_output=True,text=True,
                                cwd=ROOT,timeout=180)
            self.assertEqual(proc.returncode,2,proc.stderr+'\n'+proc.stdout[-500:])
            doc=json.loads(proc.stdout)
            self.assertEqual(doc['exit_code'],2)
            self.assertTrue(doc['local_signed_ec352_registry_signatures_and_dual_log_links_consistent'])

    @unittest.skipUnless(os.getenv("CES_EC378_REAL_DEEP")=="1",
        "Deferred: real deep isolated child and independently mutated receiver")
    def test_22_real_isolated_mutated_receiver_denied(self):
        p=self.registries[0]['events'][0]['signed_event_original']['path']
        Path(p).write_bytes(b'WRONG_UNPINNED_BYTES')
        proc=subprocess.run(self.argv(),capture_output=True,text=True,cwd=ROOT,timeout=180)
        self.assertIn(proc.returncode,(3,4,5),proc.stderr+proc.stdout[-300:])
        doc=json.loads(proc.stdout)
        self.assertNotEqual(doc['exit_code'],2)


    def test_23_fixed_router_accepts_strict_unresolved_real_result_contract(self):
        from scripts import ces_next
        good=self.audit()
        opts=self.opts(expected_retained_historical_registry_inventory_sha256=
             self.derive()['receiver_verified_historical_registry_inventory_sha256'])
        with patch.object(ces_next,'_command',return_value=(2,good)),redirect_stdout(io.StringIO()) as out:
            rc=ces_next.audit_historical_registry_archive(
                'DeliveryAudit','AuditHistoricalRegistryArchive',**opts)
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(out.getvalue())['schema'],core.RESULT_SCHEMA)

    def test_24_router_rejects_fake_success_exit_zero(self):
        from scripts import ces_next
        opts=self.opts(expected_retained_historical_registry_inventory_sha256='a'*64)
        with patch.object(ces_next,'_command',return_value=(0,{'exit_code':0})):
            with self.assertRaises(Exception):
                ces_next.audit_historical_registry_archive(
                    'DeliveryAudit','AuditHistoricalRegistryArchive',**opts)

    def test_25_router_rejects_mutated_unresolved_counter(self):
        from scripts import ces_next
        opts=self.opts(expected_retained_historical_registry_inventory_sha256=
             self.derive()['receiver_verified_historical_registry_inventory_sha256'])
        bad={**self.audit(),
             'verified_original_ec352_root_and_operator_signed_event_count':999}
        with patch.object(ces_next,'_command',return_value=(2,bad)):
            with self.assertRaises(Exception):
                ces_next.audit_historical_registry_archive(
                    'DeliveryAudit','AuditHistoricalRegistryArchive',**opts)

    def test_26_fixed_router_cannot_expand_to_other_actions(self):
        from scripts import ces_next
        opts=self.opts(expected_retained_historical_registry_inventory_sha256='a'*64)
        with self.assertRaises(Exception):
            ces_next.audit_historical_registry_archive(
                'DeliverySend','Send',**opts)

    def test_27_old_ec352_event_signed_expiry_outside_root_denied(self):
        # Old EC352 helper must enforce event validity contained in its root
        # reference rather than accepting a self-signed authority extension.
        root=self.registries[0];priv=self.fx.prev.ec378_private[0][0]
        oper=self.fx.prev.ec378_private[0][1]
        d=json.loads(Path(root['events'][0]['signed_event_original']['path']).read_text())
        body={k:v for k,v in d.items() if not k.endswith('_signature_ed25519_hex')}
        body['valid_until_utc']='2026-10-30T12:00:00Z'
        new=self.store('event-extends-root-window',{
           **body,
           'root_signature_ed25519_hex':priv.sign(
               old352.EVENT_DOMAIN+canonical.canonical(body)).hex(),
           'current_signer_signature_ed25519_hex':oper.sign(
               old352.OPERATOR_DOMAIN+canonical.canonical(body)).hex(),
           'previous_signer_signature_ed25519_hex':old352.NONE})
        def read(ref,role,cap):return Path(ref['path']).read_bytes()
        with self.assertRaises(errors.AnchorError) as ctx:
            core._registry({**root,'events':[{'signed_event_original':new,
                'signer_public_key_original':root['events'][0]['signer_public_key_original']}]},
                read,old353._utc(util.EV),set(),set(),set())
        self.assertIn('OUTSIDE_OWN_ROOT',ctx.exception.code)


if __name__=='__main__':unittest.main()
