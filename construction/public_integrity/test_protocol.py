#!/usr/bin/env python3
"""EC396 genuine local Ed25519, Merkle and byte-exact copy tests.

Synthetic outer parent and genuine RFC3161 issuance are deliberately mocked:
these tests DO NOT prove legal registration, qualified TSA or actual WORM.
"""
from __future__ import annotations

from datetime import datetime,timedelta,timezone
from pathlib import Path
from unittest.mock import patch
import hashlib
import tempfile
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from offline_transfer_registry import registry as canonical
from delivery_anchor import anchor as errors
from transparency import transparency as tr
from . import protocol as core


class PublicHistoryLocalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ces_ec396_')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.serial=0
        self.keys={k:Ed25519PrivateKey.generate() for k in (
            'ia','ib','ar1','ar2','registrar','log','worma','wormb')}
        self.roles={k:self.role(k) for k in self.keys}
        self.lineage='OriginalLineage396'
        self.cutoff='2026-10-25T15:00:00Z'
        self.evaluation='2026-10-26T11:00:00Z'
        self.oldconfirm=self.archive({'genuine_original':'EC395 offer ack confirm signed'},'confirm')
        self.oldreceipts=[self.archive({'genuine_original':f'EC395 signed archivist {k}'},'archive')
                          for k in range(2)]
        self.ec395_roster={'schema':core.parent.ROSTER_SCHEMA,
          'claimed_directory_lineage_id':self.lineage,
          'credential_issuers':[self.roles['ia'],self.roles['ib']],
          'offsite_archivists':[self.roles['ar1'],self.roles['ar2']]}
        self.parentroles=self.archive(self.ec395_roster,'parent-roster')
        self.parentbundle={k:None for k in core.parent.BUNDLE_FIELDS}
        self.parentbundle.update({'schema':core.parent.BUNDLE_SCHEMA,
          'claimed_directory_lineage_id':self.lineage,
          'external_role_roster_original':self.parentroles,
          'external_credential_attestations':[],
          'epochs':[{'epoch_index':0,'gossip':{'confirm':{'signed_original':self.oldconfirm}},
             'archives':[{'signed_receipt_original':self.oldreceipts[0]},
                         {'signed_receipt_original':self.oldreceipts[1]}]}]})
        self.parentref=self.archive(self.parentbundle,'parent-ec395')
        self.public_roster={'schema':core.ROSTER_SCHEMA,
          'claimed_directory_lineage_id':self.lineage,
          'registry_signer':self.roles['registrar'],
          'transparency_log_signer':self.roles['log'],
          'device_operators':[self.roles['worma'],self.roles['wormb']]}
        self.rostref=self.archive(self.public_roster,'new-roster')
        self.catref=self.archive(b'PURPORTED THIRD PARTY REGISTER: NOT AUTHENTICATED','catalog')
        self.parent_digest='d'*64
        self.flags={k:False for k in core.FLAGS}
        self.parent_report=self.make_parent_report()
        self.subjects=core._subjects(self.ec395_roster)
        self.opts={
         'historical_directory_root_shas':['a'*64],
         'claimed_historical_directory_lineage_id':self.lineage,
         'ec391_tsa_evaluation_utc':self.evaluation,
         'expected_outside_retained_ec393_dispute_cutoff_utc':self.cutoff,
         core.parent.NEW_SCALARS[0]:self.parentref['path'],
         core.parent.NEW_SCALARS[1]:self.parentref['sha256'],
         core.parent.NEW_SCALARS[2]:self.parentroles['sha256'],
         core.parent.NEW_SCALARS[6]:self.roles['ia']['public_hex'],
         core.parent.NEW_SCALARS[7]:self.roles['ib']['public_hex'],
         core.parent.AUDIT_ONLY[0]:self.parent_digest,
         core.NEW_SCALARS[2]:self.rostref['sha256'],
         core.NEW_SCALARS[3]:self.catref['sha256'],
         core.NEW_SCALARS[4]:self.roles['registrar']['public_hex'],
         core.NEW_SCALARS[5]:self.roles['log']['public_hex'],
        }

    def archive(self,doc,name):
        self.serial+=1
        b=doc if isinstance(doc,bytes) else canonical.canonical(doc)
        p=self.root/f'{name}-{self.serial}.original'
        p.write_bytes(b)
        return {'path':str(p),'sha256':hashlib.sha256(b).hexdigest()}

    def role(self,name):
        pub=self.keys[name].public_key().public_bytes(
           encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
        return {'role_id':'Role'+name,'site_id':'Site'+name,
                'public_hex':pub.hex(),'public_key_original':self.archive(pub,'raw-key-'+name)}

    def signed(self,name,domain,claim,schema):
        return self.archive({'schema':schema,'claim':claim,'signature_ed25519':
             self.keys[name].sign(domain+canonical.canonical(claim)).hex()},'signed-'+name)

    def read(self,ref,role,cap):
        data=Path(ref['path']).read_bytes()
        self.assertLessEqual(len(data),cap)
        self.assertEqual(hashlib.sha256(data).hexdigest(),ref['sha256'])
        return data

    def timestamp(self,raw,ref,trust,authority,read,evaluation,cutoff,claimed,flags):
        return {'gen':claimed+timedelta(seconds=1), 'clean':True,'sha256':ref['sha256']}

    def make_parent_report(self):
        flags={k:i>=7 for i,k in enumerate(core.parent.FLAGS)}
        row={'epoch_index':0,'cryptographically_bounded_reciprocal_gossip_count':1,
             'verified_two_source_original_recovery_count':2,
             'genuine_parent_observation_originals_readback':2,
             'required_archived_unique_original_count':9,
             'reciprocal_signed_gossip_inventory_sha256':'c'*64,
             'offsite_signed_recovery_inventory_sha256':'b'*64,
             'signed_disclosed_gossip_divergences':0}
        return {'schema':core.parent.RESULT_SCHEMA,
          'command':'audit-historical-ec339-credential-gossip-archive',
          'status':core.parent.OUTCOMES[7]+'_unresolved','exit_code':2,
          'offline_unresolved_exit_code':2,
          'verified_live_ec394_report_sha256':'a'*64,
          'verified_live_ec394_inventory_sha256':'b'*64,
          'original_credential_gossip_archive_sha256':self.parentref['sha256'],
          'receiver_verified_credential_gossip_archive_inventory_sha256':self.parent_digest,
          'original_independently_signed_credential_count':2,
          'cryptographically_bounded_reciprocal_gossip_count':1,
          'cryptographically_bounded_two_site_archive_replica_count':2,
          'genuine_signed_reciprocal_gossip_disclosure_conflict_count':0,
          'inherited_genuinely_operator_signed_log_fork_count':0,
          'credential_gossip_archive_epoch_reviews':[row],
          'visible_genuinely_signed_reciprocal_witness_view_conflicts':[],
          'local_credential_gossip_and_readback_consistency':True,
          'sender_origin_path_required_or_read':False,
          'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
          **flags,**{k:False for k in core.parent.NEGATIVES}}

    def signed_registry(self,status='active'):
        claim={'schema':core.REGISTRY_CLAIM,'directory_lineage_id':self.lineage,
          'parent_ec395_bundle_sha256':self.parentref['sha256'],
          'parent_ec395_verified_inventory_sha256':self.parent_digest,
          'public_catalog_original_sha256':self.catref['sha256'],
          'epoch_index':0,'registry_sequence':1,
          'previous_registry_snapshot_sha256':core.ZERO,
          'registry_signer_id':self.roles['registrar']['role_id'],
          'subjects':[{'role_id':s['role_id'],'public_hex':s['public_hex'],
             'status':status if s==self.subjects[0] else 'active',
             'effective_utc':'2026-10-25T13:00:00Z'} for s in self.subjects],
          'claimed_snapshot_utc':'2026-10-25T14:00:00Z'}
        original=self.signed('registrar',core.REGISTRY_DOMAIN,claim,core.REGISTRY_SCHEMA)
        return {'signed_original':original,
          'rfc3161_token_original':self.archive(b'FAKE TOKEN FOR UNIT TEST ONLY','tsa-reg')}

    @staticmethod
    def merkle4(raw):
        leaves=[tr.leaf_hash(x) for x in raw]
        a=tr.node_hash(leaves[0],leaves[1]);b=tr.node_hash(leaves[2],leaves[3])
        return tr.node_hash(a,b).hex(),[
         [leaves[1].hex(),b.hex()],[leaves[0].hex(),b.hex()],
         [leaves[3].hex(),a.hex()],[leaves[2].hex(),a.hex()]]

    def signed_log(self,reg):
        source=[reg['signed_original'],self.oldconfirm,*self.oldreceipts]
        root,proofs=self.merkle4([self.read(r,'leaf',70_000) for r in source])
        claim={'schema':core.LOG_CLAIM,'directory_lineage_id':self.lineage,
          'parent_ec395_bundle_sha256':self.parentref['sha256'],
          'parent_ec395_verified_inventory_sha256':self.parent_digest,
          'epoch_index':0,'log_signer_id':self.roles['log']['role_id'],
          'log_sequence':1,'previous_signed_log_head_sha256':core.ZERO,
          'tree_size':4,'merkle_root_sha256':root,
          'registry_snapshot_original_sha256':source[0]['sha256'],
          'claimed_published_utc':'2026-10-25T14:10:00Z'}
        h=self.signed('log',core.LOG_DOMAIN,claim,core.LOG_SCHEMA)
        return {'signed_head_original':h,
          'rfc3161_token_original':self.archive(b'NOT REAL DER','tsa-log'),
          'leaves':[{'kind':kind,'signed_original':ref,'index':i,
                'path_sha256':proofs[i]} for i,(kind,ref) in enumerate(zip(core.LEAF_KINDS,source))],
          'consistency_path_sha256':[]}

    def signed_device(self,name,log):
        inventory=self.archive(b'OPAQUE DEVICE ATTESTATION DATA NOT HARDWARE PROOF '+name.encode(),
              'device-inventory')
        pairs=[{'source_original':src,'device_copy_original':
           self.archive(self.read(src,'old',70_000),'copy-'+name)} for src in self.oldreceipts]
        rows=sorted([{'source_original_sha256':x['source_original']['sha256'],
              'device_copy_original_sha256':x['device_copy_original']['sha256'],
              'source_path':x['source_original']['path'],
              'copy_path':x['device_copy_original']['path']} for x in pairs],
              key=lambda r:r['source_path'])
        claim={'schema':core.WORM_CLAIM,'directory_lineage_id':self.lineage,
           'parent_ec395_bundle_sha256':self.parentref['sha256'],
           'parent_ec395_verified_inventory_sha256':self.parent_digest,
           'epoch_index':0,'device_operator_id':self.roles[name]['role_id'],
           'device_site_id':self.roles[name]['site_id'],
           'device_serial_id':'Device'+name,
           'claimed_storage_mode':'worm_append_only_claimed',
           'device_inventory_sha256':inventory['sha256'],
           'public_log_head_original_sha256':log['signed_head_original']['sha256'],
           'previous_epoch_attestation_sha256':core.ZERO,
           'original_to_device_copy_inventory_sha256':core.cdigest(rows),
           'claimed_sealed_utc':'2026-10-25T14:30:00Z',
           'claimed_retention_until_utc':'2027-10-26T00:00:00Z'}
        signed=self.signed(name,core.WORM_DOMAIN,claim,core.WORM_SCHEMA)
        return {'operator_id':self.roles[name]['role_id'],
          'device_inventory_original':inventory,
          'signed_attestation_original':signed,
          'rfc3161_token_original':self.archive(b'NOT REAL DER','tsa-worm'),
          'copies':pairs}

    def setup_bundle(self,reg_status='active'):
        reg=self.signed_registry(reg_status)
        log=self.signed_log(reg)
        devices=[self.signed_device('worma',log),self.signed_device('wormb',log)]
        body={'schema':core.BUNDLE_SCHEMA,'claimed_directory_lineage_id':self.lineage,
          'parent_ec395_credential_gossip_bundle_original':self.parentref,
          'outside_authority_roster_original':self.rostref,
          'purported_public_catalog_original':self.catref,
          'epochs':[{'epoch_index':0,'registry':reg,'log':log,'devices':devices}]}
        file=self.archive(body,'new-ec396-bundle')
        self.opts.update({core.NEW_SCALARS[0]:file['path'],
          core.NEW_SCALARS[1]:file['sha256'],
          core.NEW_SCALARS[6]:reg['signed_original']['sha256'],
          core.NEW_SCALARS[7]:devices[0]['signed_attestation_original']['sha256']})
        for k,_ in core.NEW_REPEATS:
            self.opts[k]=[0] if k.startswith('minimum_') else ['a'*64]
        return body

    def evaluate(self,derive=True):
        anchor={'known_keys':[],'known_sites':[],'known_ids':[],
           'trust':{},'authority':'MOCK_TSA'}
        with patch.object(core,'_inputs',return_value={}),\
             patch.object(core.parent,'audit',return_value=self.parent_report),\
             patch.object(core.parent,'_actual_parent_source',return_value=anchor),\
             patch.object(core,'_stamp',side_effect=self.timestamp):
            return core.derive_inventory(**self.opts) if derive else core.audit(**self.opts)

    def test_01_ed25519_registry_four_real_roles_and_time_bounded(self):
        reg=self.signed_registry()
        with patch.object(core,'_stamp',side_effect=self.timestamp):
            out=core._registry(reg,0,self.roles['registrar'],self.subjects,
              core.ZERO,None,self.parentref,self.parent_digest,self.catref,self.lineage,
              self.read,{},'MOCK',datetime.fromisoformat(self.evaluation.replace('Z','+00:00')),
              datetime.fromisoformat(self.cutoff.replace('Z','+00:00')),self.flags,{})
        self.assertTrue(out['pre_cutoff']);self.assertEqual(4,out['current_verified_roles'])

    def test_02_real_merkle4_all_four_originals_included(self):
        reg=self.signed_registry();log=self.signed_log(reg)
        out,ok=core._inclusions(log['leaves'],
            dict(zip(core.LEAF_KINDS,[reg['signed_original'],self.oldconfirm,*self.oldreceipts])),
            self.read,core.tr.strict_json(self.read(log['signed_head_original'],'log',70_000),'LOG')['claim']['merkle_root_sha256'],
            4,self.flags)
        self.assertTrue(ok);self.assertEqual(4,len(out))

    def test_03_false_merkle_path_does_not_get_credit(self):
        reg=self.signed_registry();log=self.signed_log(reg)
        log['leaves'][0]['path_sha256'][0]='f'*64
        out,ok=core._inclusions(log['leaves'],
            dict(zip(core.LEAF_KINDS,[reg['signed_original'],self.oldconfirm,*self.oldreceipts])),
            self.read,core.tr.strict_json(self.read(log['signed_head_original'],'log',70_000),'LOG')['claim']['merkle_root_sha256'],
            4,self.flags)
        self.assertFalse(ok);self.assertTrue(self.flags[core.FLAGS[3]])

    def test_04_signed_parent_report_proof_contract_refuses_invented_pass(self):
        core._parent_report(self.parent_report,self.opts)
        self.parent_report['status']='passed'
        with self.assertRaises(errors.AnchorError):core._parent_report(self.parent_report,self.opts)

    def test_05_actual_signed_child_derive_and_audit_no_legal_pass(self):
        self.setup_bundle();a=self.evaluate()
        self.assertEqual(2,a['exit_code']);self.assertEqual(4,a['signed_pre_cutoff_registry_active_role_count'])
        self.assertEqual(1,a['verified_public_log_original_inclusion_set_count'])
        self.assertEqual(2,a['independent_signed_device_original_readback_count'])
        for i,k in enumerate(core.NEW_REPEATS[:3]):
            field=('registry_inventory_sha256','log_inclusion_inventory_sha256','device_recovery_inventory_sha256')[i]
            self.opts[k[0]]=[a['public_integrity_epoch_reviews'][0][field]]
        self.opts[core.AUDIT_ONLY[0]]=a['receiver_verified_public_integrity_inventory_sha256']
        self.opts[core.NEW_REPEATS[3][0]]=[4]
        self.opts[core.NEW_REPEATS[4][0]]=[1]
        self.opts[core.NEW_REPEATS[5][0]]=[2]
        report=self.evaluate(False)
        self.assertEqual(report['status'],core.OUTCOMES[6]+'_unresolved')
        self.assertTrue(report['local_original_public_history_and_device_copy_consistency'])
        self.assertTrue(all(report[k] is False for k in core.NEGATIVES))

    def test_06_true_signed_revocation_denies_four_role_floor(self):
        self.setup_bundle('revoked');a=self.evaluate()
        self.assertEqual(0,a['signed_pre_cutoff_registry_active_role_count'])
        self.assertEqual(1,a['signed_revocation_or_suspension_observation_count'])
        self.assertTrue(a[core.FLAGS[2]])

    def test_07_tampered_independent_source_copy_rejected(self):
        body=self.setup_bundle()
        target=body['epochs'][0]['devices'][0]['copies'][0]['device_copy_original']['path']
        Path(target).write_bytes(b'BAD')
        report=self.run_denial()
        self.assertIn(report.status,('permission_denied','invalid_input'))

    def test_08_untrusted_log_key_reuse_denied(self):
        self.setup_bundle()
        document=dict(self.public_roster)
        document['transparency_log_signer']=self.roles['registrar']
        with self.assertRaises(errors.AnchorError):core._roster(document,self.rostref,
             self.opts,self.lineage,{'known_keys':[],'known_ids':[],'known_sites':[]},
             self.ec395_roster,self.read)

    def test_09_forged_registry_ed25519_denied(self):
        r=self.signed_registry()
        raw=core.tr.strict_json(self.read(r['signed_original'],'registry',70_000),'REG')
        with self.assertRaises(errors.AnchorError):core._signed_verify(
           self.roles['log'],raw['signature_ed25519'],core.REGISTRY_DOMAIN,
           raw['claim'],'FORGED_AUTHORITY')

    def test_10_wrong_external_whole_inventory_sha_keeps_adverse(self):
        self.setup_bundle();a=self.evaluate()
        self.opts[core.AUDIT_ONLY[0]]='f'*64
        report=self.evaluate(False)
        self.assertTrue(report[core.FLAGS[1]])
        self.assertEqual(2,report['exit_code'])

    def test_11_missing_merkle_leaf_cannot_claim_log_count(self):
        body=self.setup_bundle()
        body['epochs'][0]['log']['leaves'].pop()
        ref=self.archive(body,'revised-leaf-bundle')
        self.opts[core.NEW_SCALARS[0]]=ref['path'];self.opts[core.NEW_SCALARS[1]]=ref['sha256']
        a=self.evaluate()
        self.assertEqual(0,a['verified_public_log_original_inclusion_set_count'])
        self.assertEqual(0,a['independent_signed_device_original_readback_count'])

    def test_12_cross_site_device_inventory_alias_rejected(self):
        body=self.setup_bundle()
        body['epochs'][0]['devices'][1]['device_inventory_original']=body['epochs'][0]['devices'][0]['device_inventory_original']
        ref=self.archive(body,'dup-device-inventory-bundle')
        self.opts[core.NEW_SCALARS[0]]=ref['path'];self.opts[core.NEW_SCALARS[1]]=ref['sha256']
        err=self.run_denial()
        self.assertEqual(err.status,'permission_denied')

    def test_13_registry_revoked_then_signed_active_rollback_stays_adverse(self):
        reg=self.signed_registry('active')
        history={self.subjects[0]['role_id']:(
            'revoked',datetime(2026,10,25,13,0,tzinfo=timezone.utc))}
        with patch.object(core,'_stamp',side_effect=self.timestamp):
            r=core._registry(reg,0,self.roles['registrar'],self.subjects,
              core.ZERO,None,self.parentref,self.parent_digest,self.catref,self.lineage,
              self.read,{},'MOCK',datetime.fromisoformat(self.evaluation.replace('Z','+00:00')),
              datetime.fromisoformat(self.cutoff.replace('Z','+00:00')),self.flags,history)
        self.assertEqual(r['current_verified_roles'],0)
        self.assertTrue(self.flags[core.FLAGS[2]])

    def test_14_genuine_signed_forked_log_root_is_adverse(self):
        reg=self.signed_registry();current=self.signed_log(reg)
        raw=core.tr.strict_json(self.read(current['signed_head_original'],'head',70_000),'HEAD')
        prevroot='a'*64
        claim={**raw['claim'],'epoch_index':1,'log_sequence':2,
          'previous_signed_log_head_sha256':'b'*64}
        current['signed_head_original']=self.signed('log',core.LOG_DOMAIN,claim,core.LOG_SCHEMA)
        expect=dict(zip(core.LEAF_KINDS,[reg['signed_original'],self.oldconfirm,*self.oldreceipts]))
        with patch.object(core,'_stamp',side_effect=self.timestamp):
            result=core._log(current,1,self.roles['log'],reg['signed_original'],
              'b'*64,4,prevroot,datetime(2026,10,25,14,0,tzinfo=timezone.utc),
              self.parentref,self.parent_digest,self.lineage,expect,self.read,{},'MOCK',
              datetime.fromisoformat(self.evaluation.replace('Z','+00:00')),
              datetime.fromisoformat(self.cutoff.replace('Z','+00:00')),self.flags)
        self.assertFalse(result['prefix_consistent'])
        self.assertFalse(result['complete'])
        self.assertTrue(self.flags[core.FLAGS[3]])

    def test_15_real_signed_registry_future_effective_time_not_current(self):
        reg=self.signed_registry()
        obj=core.tr.strict_json(self.read(reg['signed_original'],'reg',70_000),'REG')
        claim=obj['claim']
        claim['subjects'][0]['effective_utc']='2030-01-01T00:00:00Z'
        reg['signed_original']=self.signed('registrar',core.REGISTRY_DOMAIN,claim,core.REGISTRY_SCHEMA)
        with patch.object(core,'_stamp',side_effect=self.timestamp):
            result=core._registry(reg,0,self.roles['registrar'],self.subjects,
              core.ZERO,None,self.parentref,self.parent_digest,self.catref,self.lineage,
              self.read,{},'MOCK',datetime.fromisoformat(self.evaluation.replace('Z','+00:00')),
              datetime.fromisoformat(self.cutoff.replace('Z','+00:00')),self.flags,{})
        self.assertEqual(0,result['current_verified_roles'])
        self.assertTrue(self.flags[core.FLAGS[2]])

    def run_denial(self):
        with self.assertRaises(errors.AnchorError) as cm:self.evaluate()
        return cm.exception


if __name__=='__main__':unittest.main()
