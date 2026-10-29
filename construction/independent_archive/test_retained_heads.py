#!/usr/bin/env python3
"""EC390 local real-Ed25519 head/receipt cases; deep historic parent MOCKED.

The signatures are genuinely locally generated. EC389->EC369 outer parent,
EC387 preparation and inherited EC317/318 ancestry are NOT independently
executed here; neither signer keys nor timestamps are third-party credentials.
"""
from __future__ import annotations
import copy
import json
import subprocess
import sys
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from external_revocation import test_witness_custody as ptest
from external_revocation import witness_custody as prior
from . import retained_heads as core


class ArchivedHistoryTests(ptest.LocallySignedExternalRevocationWitnessTests):
    # unittest inherits EC389 cases intentionally: old signed source checks
    # remain an implicit fixture. Test runner selects only test_ec390_* names.
    def setUp(self):
        super().setUp()
        self.archivist_priv=Ed25519PrivateKey.generate()
        self.receipt_priv=Ed25519PrivateKey.generate()
        pub_a=self.archivist_priv.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        pub_r=self.receipt_priv.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        keya=self.root/('ec390-archive-'+self._testMethodName+'.raw')
        keyr=self.root/('ec390-receipt-'+self._testMethodName+'.raw')
        keya.write_bytes(pub_a);keyr.write_bytes(pub_r)
        self.new_roster={'schema':core.ROSTER_SCHEMA,'claimed_directory_lineage_id':'Lineage388',
            'archivists':[{'signer_id':'Archivist1','public_hex':pub_a.hex(),
                          'public_key_original':ptest.ref(keya)}],
            'receipt_attestors':[{'signer_id':'ReceiptAttestor1','public_hex':pub_r.hex(),
                                  'public_key_original':ptest.ref(keyr)}]}
        self.new_roster_ref=self._archive('ec390-roster-'+self._testMethodName+'.json',
                                         self.new_roster)
        self.signed_source=[{'ec339_revoked_status_original_sha256':self.revoked['sha256'],
            'ec389_signed_witness_original_sha256':self.pair['signed_witness_original']['sha256'],
            'ec389_signed_custody_original_sha256':self.pair['signed_custody_original']['sha256']}]
        self.parent_hash='ab'*32;self.old_archive_sha='bc'*32;self.parent_inventory='cd'*32
        self.head_claim={'schema':core.HEAD_CLAIM_SCHEMA,
            'directory_lineage_id':'Lineage388',
            'tsa_channel_id':self.channel['tsa_channel_id'],
            'epoch_index':0,'parent_ec389_canonical_result_sha256':self.parent_hash,
            'ec389_external_witness_archive_original_sha256':self.old_archive_sha,
            'ec389_parent_derived_inventory_sha256':self.parent_inventory,
            'archivist_id':'Archivist1','checkpoint_sequence':1,
            'previous_signed_archive_head_original_sha256':core.ZERO,
            'ec389_signed_source_pairs':copy.deepcopy(self.signed_source),
            'claimed_archived_utc':'2026-10-25T11:30:00Z'}
        self.receipt_claim={'schema':core.RECEIPT_CLAIM_SCHEMA,
            'directory_lineage_id':'Lineage388','tsa_channel_id':self.channel['tsa_channel_id'],
            'epoch_index':0,'signed_archive_head_original_sha256':'ff'*32,
            'ec389_signed_source_pairs_sha256':core.sha(canonical.canonical(self.signed_source)),
            'receipt_attestor_id':'ReceiptAttestor1','receipt_sequence':1,
            'previous_signed_receipt_original_sha256':core.ZERO,
            'claimed_received_utc':'2026-10-25T11:35:00Z'}
        self.entry=self.sign_pair()
        self.signed_flags={k:False for k in core.FLAGS}

    def sign_pair(self,h=None,r=None,tag=None,a_key=None,r_key=None,include_receipt=True):
        h=copy.deepcopy(self.head_claim if h is None else h)
        r=copy.deepcopy(self.receipt_claim if r is None else r)
        tag=tag or self._testMethodName
        head={'schema':core.HEAD_SCHEMA,'claim':h,
              'signature_ed25519':(a_key or self.archivist_priv).sign(
                  core.HEAD_DOMAIN+canonical.canonical(h)).hex()}
        href=self._archive('ec390-head-'+tag+'.json',head)
        r['signed_archive_head_original_sha256']=href['sha256'] if (
            r['signed_archive_head_original_sha256']=='ff'*32) else r['signed_archive_head_original_sha256']
        r['ec389_signed_source_pairs_sha256']=core.sha(canonical.canonical(h['ec389_signed_source_pairs']))
        receipt={'schema':core.RECEIPT_SCHEMA,'claim':r,
              'signature_ed25519':(r_key or self.receipt_priv).sign(
                  core.RECEIPT_DOMAIN+canonical.canonical(r)).hex()}
        rref=self._archive('ec390-receipt-'+tag+'.json',receipt) if include_receipt else None
        return {'tsa_channel_id':self.channel['tsa_channel_id'],
                'signed_archive_head_original':href,
                'signed_head_receipt_original':rref}

    def _channel(self,entry=None,prev=None,idx=0,source=None):
        signers=core._roster(self.new_roster,self.new_roster_ref,self.new_roster_ref['sha256'],
                             self.read,{'ExternalWitness1','ExternalCustodian1'},
                             {self.pub_w.hex(),self.pub_c.hex()})
        s=source or {self.channel['tsa_channel_id']:{'pairs':self.signed_source,
           'last_deposit':core.old339._time('2026-10-25T11:25:00Z'),
           'witness_head_sha256':self.pair['signed_witness_original']['sha256'],
           'custody_head_sha256':self.pair['signed_custody_original']['sha256']}}
        flags={k:False for k in core.FLAGS}
        result,nextprev=core._channel(entry if entry is not None else self.entry,s,
                signers,self.read,idx,'Lineage388',self.parent_hash,
                self.old_archive_sha,self.parent_inventory,prev,flags)
        return result,nextprev,flags

    def _reject(self,entry=None,prev=None,idx=0):
        with self.assertRaises(errors.AnchorError):self._channel(entry,prev,idx)

    def test_ec390_01_real_separate_head_and_receipt_signatures(self):
        r,prev,f=self._channel()
        self.assertTrue(r['signed_snapshot_matches_live_ec389_source'])
        self.assertEqual(r['signed_archive_head_sha256'],self.entry['signed_archive_head_original']['sha256'])
        self.assertTrue(r['signed_head_receipt_sha256'])
        self.assertFalse(any(f.values()))

    def test_ec390_02_independent_receipt_missing_remains_gap(self):
        e=copy.deepcopy(self.entry);e['signed_head_receipt_original']=None
        r,prev,f=self._channel(e)
        self.assertTrue(f[core.FLAGS[3]])
        self.assertIsNone(r['signed_head_receipt_sha256'])

    def test_ec390_03_no_head_or_receipt_is_incomplete(self):
        e={'tsa_channel_id':self.channel['tsa_channel_id'],
           'signed_archive_head_original':None,'signed_head_receipt_original':None}
        r,_,f=self._channel(e)
        self.assertTrue(f[core.FLAGS[3]])
        self.assertIsNone(r['signed_archive_head_sha256'])

    def test_ec390_04_receipt_without_head_denied(self):
        e=copy.deepcopy(self.entry);e['signed_archive_head_original']=None
        self._reject(e)

    def test_ec390_05_head_signature_tamper_denied(self):
        h=json.loads(self.root.joinpath('ec390-head-'+self._testMethodName+'.json').read_bytes())
        h['signature_ed25519']='ba'*64
        e=copy.deepcopy(self.entry);e['signed_archive_head_original']=self._archive(
            'ec390-malicious-head-'+self._testMethodName+'.json',h)
        self._reject(e)

    def test_ec390_06_receipt_signature_tamper_denied(self):
        r=json.loads(self.root.joinpath('ec390-receipt-'+self._testMethodName+'.json').read_bytes())
        r['signature_ed25519']='da'*64
        e=copy.deepcopy(self.entry);e['signed_head_receipt_original']=self._archive(
            'ec390-malicious-receipt-'+self._testMethodName+'.json',r)
        self._reject(e)

    def test_ec390_07_valid_signed_conflicting_old_status_is_adverse(self):
        h=copy.deepcopy(self.head_claim)
        h['ec389_signed_source_pairs'][0]['ec339_revoked_status_original_sha256']='12'*32
        r,_,flags=self._channel(self.sign_pair(h,tag=self._testMethodName+'-fork'))
        self.assertTrue(flags[core.FLAGS[4]])
        self.assertFalse(r['signed_snapshot_matches_live_ec389_source'])

    def test_ec390_08_valid_signed_reordered_source_is_adverse(self):
        h=copy.deepcopy(self.head_claim);h['ec389_signed_source_pairs']=[]
        _,_,flags=self._channel(self.sign_pair(h,tag=self._testMethodName+'-missing'))
        self.assertTrue(flags[core.FLAGS[4]])

    def test_ec390_09_head_parent_canonical_sha_not_substitutable(self):
        h=copy.deepcopy(self.head_claim);h['parent_ec389_canonical_result_sha256']='a1'*32
        self._reject(self.sign_pair(h,tag=self._testMethodName+'-badparent'))

    def test_ec390_10_head_parent_original_sha_not_substitutable(self):
        h=copy.deepcopy(self.head_claim);h['ec389_external_witness_archive_original_sha256']='a1'*32
        self._reject(self.sign_pair(h,tag=self._testMethodName+'-badparent'))

    def test_ec390_11_head_lineage_must_match_original(self):
        h=copy.deepcopy(self.head_claim);h['directory_lineage_id']='DifferentLineage'
        self._reject(self.sign_pair(h,tag=self._testMethodName+'-lineage'))

    def test_ec390_12_head_channel_must_match_original(self):
        h=copy.deepcopy(self.head_claim);h['tsa_channel_id']='WrongChannel'
        self._reject(self.sign_pair(h,tag=self._testMethodName+'-channel'))

    def test_ec390_13_receipt_references_exact_head_sha(self):
        r=copy.deepcopy(self.receipt_claim)
        r['signed_archive_head_original_sha256']='ba'*32
        self._reject(self.sign_pair(r=r,tag=self._testMethodName+'-headsha'))

    def test_ec390_14_receipt_claim_role_prevents_cross_key_substitution(self):
        r=copy.deepcopy(self.receipt_claim);r['receipt_attestor_id']='Archivist1'
        self._reject(self.sign_pair(r=r,tag=self._testMethodName+'-role'))

    def test_ec390_15_independent_roster_must_be_sha_retained(self):
        with self.assertRaises(errors.AnchorError):core._roster(
            self.new_roster,self.new_roster_ref,'a8'*32,self.read,set(),set())

    def test_ec390_16_new_signer_cannot_reuse_old_public_key_or_id(self):
        with self.assertRaises(errors.AnchorError):core._roster(
            self.new_roster,self.new_roster_ref,self.new_roster_ref['sha256'],
            self.read,set(),{self.new_roster['archivists'][0]['public_hex']})
        with self.assertRaises(errors.AnchorError):core._roster(
            self.new_roster,self.new_roster_ref,self.new_roster_ref['sha256'],
            self.read,{'Archivist1'},set())

    def test_ec390_17_archive_clock_earlier_than_signed_custody_is_adverse(self):
        h=copy.deepcopy(self.head_claim);h['claimed_archived_utc']='2026-10-25T11:24:00Z'
        _,_,f=self._channel(self.sign_pair(h,tag=self._testMethodName+'-early'))
        self.assertTrue(f[core.FLAGS[5]])

    def test_ec390_18_receipt_clock_earlier_than_signed_archive_is_adverse(self):
        r=copy.deepcopy(self.receipt_claim);r['claimed_received_utc']='2026-10-25T11:29:00Z'
        _,_,f=self._channel(self.sign_pair(r=r,tag=self._testMethodName+'-early'))
        self.assertTrue(f[core.FLAGS[5]])

    def test_ec390_19_epoch2_binds_true_previous_checkpoint_sha(self):
        _,prev,_=self._channel()
        h=copy.deepcopy(self.head_claim);h.update({'epoch_index':1,'checkpoint_sequence':2,
          'previous_signed_archive_head_original_sha256':prev['head']})
        r=copy.deepcopy(self.receipt_claim);r.update({'epoch_index':1,'receipt_sequence':2,
          'previous_signed_receipt_original_sha256':prev['receipt']})
        _,_,f=self._channel(self.sign_pair(h,r,tag=self._testMethodName+'-append'),prev,1)
        self.assertFalse(f[core.FLAGS[6]])

    def test_ec390_20_epoch2_rollback_signed_head_is_adverse(self):
        _,prev,_=self._channel()
        h=copy.deepcopy(self.head_claim);h.update({'epoch_index':1,'checkpoint_sequence':2,
          'previous_signed_archive_head_original_sha256':prev['head'],
          'ec389_signed_source_pairs':[]})
        r=copy.deepcopy(self.receipt_claim);r.update({'epoch_index':1,'receipt_sequence':2,
          'previous_signed_receipt_original_sha256':prev['receipt']})
        _,_,f=self._channel(self.sign_pair(h,r,tag=self._testMethodName+'-rollback'),prev,1)
        self.assertTrue(f[core.FLAGS[6]])

    def test_ec390_21_epoch2_breaks_predecessor_is_adverse(self):
        _,prev,_=self._channel()
        h=copy.deepcopy(self.head_claim);h.update({'epoch_index':1,'checkpoint_sequence':2,
          'previous_signed_archive_head_original_sha256':'ca'*32})
        r=copy.deepcopy(self.receipt_claim);r.update({'epoch_index':1,'receipt_sequence':2,
          'previous_signed_receipt_original_sha256':prev['receipt']})
        _,_,f=self._channel(self.sign_pair(h,r,tag=self._testMethodName+'-fork'),prev,1)
        self.assertTrue(f[core.FLAGS[6]])

    def test_ec390_22_epoch2_claimed_clock_regression_is_adverse(self):
        _,prev,_=self._channel()
        h=copy.deepcopy(self.head_claim);h.update({'epoch_index':1,'checkpoint_sequence':2,
          'previous_signed_archive_head_original_sha256':prev['head'],
          'claimed_archived_utc':'2026-10-25T11:25:00Z'})
        r=copy.deepcopy(self.receipt_claim);r.update({'epoch_index':1,'receipt_sequence':2,
          'previous_signed_receipt_original_sha256':prev['receipt']})
        _,_,f=self._channel(self.sign_pair(h,r,tag=self._testMethodName+'-clock'),prev,1)
        self.assertTrue(f[core.FLAGS[5]])

    def test_ec390_23_receipt_epoch_must_match_head_epoch(self):
        r=copy.deepcopy(self.receipt_claim);r['epoch_index']=2
        self._reject(self.sign_pair(r=r,tag=self._testMethodName+'-epoch'))

    def test_ec390_24_head_noncanonical_original_is_denied(self):
        p=self.root/('ec390-head-'+self._testMethodName+'.json')
        tampered=self.root/('ec390-space-'+self._testMethodName+'.json')
        tampered.write_bytes(p.read_bytes()+b'\n')
        e=copy.deepcopy(self.entry);e['signed_archive_head_original']=ptest.ref(tampered)
        self._reject(e)

    def test_ec390_25_signed_snapshot_list_cannot_have_extra_fields(self):
        h=copy.deepcopy(self.head_claim);h['ec389_signed_source_pairs'][0]['extra']='bar'
        self._reject(self.sign_pair(h,tag=self._testMethodName+'-fields'))

    def test_ec390_26_parent_contract_rejects_fabricated_pass(self):
        with self.assertRaises(errors.AnchorError):core._parent(
            {'schema':prior.RESULT_SCHEMA,'status':'passed','exit_code':2},1)

    def _outer_ec390(self):
        # Create a valid EC389 parent by running its own source replay while
        # explicitly mocking only the older EC388 audit and its source index.
        actual388,opts=self._outer()
        a,b,c=self._patch_outer(actual388)
        with a,b,c:
            derived=prior.derive_inventory(**opts)
            review=derived['historical_ec339_external_witness_epoch_reviews'][0]
            opts['historical_ec339_external_publication_inventory_shas']=[review[
                'external_publication_inventory_sha256']]
            opts['historical_ec339_external_custody_inventory_shas']=[review[
                'external_custody_inventory_sha256']]
            opts['expected_retained_historical_ec339_external_witness_custody_inventory_sha256']=(
                derived['receiver_verified_external_revocation_witness_custody_inventory_sha256'])
            actual389=prior.audit(**opts)
        self.parent_hash=core.sha(canonical.canonical(actual389))
        self.parent_inventory=actual389['receiver_verified_external_revocation_witness_custody_inventory_sha256']
        self.old_archive_sha=opts['expected_historical_ec339_external_witness_custody_archive_bundle_sha256']
        self.head_claim['parent_ec389_canonical_result_sha256']=self.parent_hash
        self.head_claim['ec389_external_witness_archive_original_sha256']=self.old_archive_sha
        self.head_claim['ec389_parent_derived_inventory_sha256']=self.parent_inventory
        self.entry=self.sign_pair(tag=self._testMethodName+'-outer')
        record=self._archive('ec390-archive-'+self._testMethodName+'.json',{
            'schema':core.BUNDLE_SCHEMA,'parent_ec389_canonical_result_sha256':self.parent_hash,
            'ec389_external_witness_archive_original_sha256':self.old_archive_sha,
            'claimed_directory_lineage_id':'Lineage388',
            'independent_archive_roster_original':self.new_roster_ref,
            'epochs':[{'epoch_index':0,'channels':[self.entry]}]})
        opts.update({'historical_ec339_independent_archive_heads_bundle_file':record['path'],
           'expected_historical_ec339_independent_archive_heads_bundle_sha256':record['sha256'],
           'expected_outside_retained_ec390_independent_archive_roster_sha256':self.new_roster_ref['sha256'],
           'historical_ec339_independent_signed_head_inventory_shas':['a7'*32],
           'historical_ec339_independent_signed_receipt_inventory_shas':['a8'*32],
           'minimum_historical_ec339_independent_signed_checkpoint_counts':[1]})
        return actual389,opts

    def _outer_ctx(self,actual):
        return (patch.object(core,'_inputs',return_value={}),
                patch.object(core.parent,'audit',return_value=actual),
                patch.object(core.oldsource,'_old_sender_labels'))

    def test_ec390_27_outer_live_ec389_parent_mocked_real_head_receipt(self):
        actual,opts=self._outer_ec390();a,b,c=self._outer_ctx(actual)
        with a,b,c:
            result=core.derive_inventory(**opts)
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['genuine_independent_signed_checkpoint_receipt_count'],1)
        self.assertTrue(result[core.FLAGS[1]])
        self.assertFalse(result[core.FLAGS[2]])
        self.assertFalse(result[core.FLAGS[4]])
        self.assertFalse(result[core.FLAGS[3]])

    def test_ec390_28_outer_exact_retained_shas_still_unresolved(self):
        actual,opts=self._outer_ec390();a,b,c=self._outer_ctx(actual)
        with a,b,c:
            derived=core.derive_inventory(**opts)
            ep=derived['historical_independent_archive_epoch_reviews'][0]
            opts['historical_ec339_independent_signed_head_inventory_shas']=[ep[
                'independent_signed_head_inventory_sha256']]
            opts['historical_ec339_independent_signed_receipt_inventory_shas']=[ep[
                'independent_signed_receipt_inventory_sha256']]
            opts['expected_retained_historical_ec339_independent_archive_inventory_sha256']=(
                derived['receiver_verified_independent_archive_inventory_sha256'])
            result=core.audit(**opts)
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['local_independent_signed_archive_heads_and_receipts_consistent'])
        self.assertTrue(result[core.FLAGS[7]] and result[core.FLAGS[8]])
        self.assertNotIn('unsigned_independent_archive_heads_receipts_inventory',result)

    def test_ec390_29_outer_missing_checkpoint_is_visible_gap(self):
        actual,opts=self._outer_ec390()
        p=opts['historical_ec339_independent_archive_heads_bundle_file']
        bundle=json.loads(self.root.joinpath('ec390-archive-'+self._testMethodName+'.json').read_bytes())
        bundle['epochs'][0]['channels'][0]['signed_archive_head_original']=None
        bundle['epochs'][0]['channels'][0]['signed_head_receipt_original']=None
        update=self._archive('ec390-no-checkpoint-'+self._testMethodName+'.json',bundle)
        opts[core.NEW_SCALARS[0]]=update['path'];opts[core.NEW_SCALARS[1]]=update['sha256']
        a,b,c=self._outer_ctx(actual)
        with a,b,c:res=core.derive_inventory(**opts)
        self.assertTrue(res[core.FLAGS[3]])
        self.assertEqual(res['genuine_independent_signed_checkpoint_receipt_count'],0)

    def test_ec390_30_outer_signed_head_valid_but_source_conflict(self):
        actual,opts=self._outer_ec390()
        conflict=copy.deepcopy(self.head_claim)
        conflict['ec389_signed_source_pairs'][0]['ec339_revoked_status_original_sha256']='de'*32
        new=self.sign_pair(conflict,tag=self._testMethodName+'-conflict')
        bundle=json.loads(self.root.joinpath('ec390-archive-'+self._testMethodName+'.json').read_bytes())
        bundle['epochs'][0]['channels'][0]=new
        update=self._archive('ec390-source-dispute-'+self._testMethodName+'.json',bundle)
        opts[core.NEW_SCALARS[0]]=update['path'];opts[core.NEW_SCALARS[1]]=update['sha256']
        a,b,c=self._outer_ctx(actual)
        with a,b,c:res=core.derive_inventory(**opts)
        self.assertTrue(res[core.FLAGS[4]])
        self.assertEqual(res['exit_code'],2)

    def test_ec390_31_outside_roster_hash_cannot_be_silently_replaced(self):
        actual,opts=self._outer_ec390()
        opts[core.NEW_SCALARS[2]]='f7'*32
        a,b,c=self._outer_ctx(actual)
        with a,b,c:
            with self.assertRaises(errors.AnchorError):core.derive_inventory(**opts)

    def test_ec390_32_help_advertises_no_key_creation(self):
        top=__import__('pathlib').Path(__file__).resolve().parents[2]
        for script,command in (
            ('ces_cas_historical_independent_archive_heads.py',
             'audit-historical-ec339-independent-archive-heads'),
            ('ces_next.py','audit-historical-ec339-independent-archive-heads')):
            p=subprocess.run([sys.executable,'-I','-B',str(top/'scripts'/script),
                command,'--help'],capture_output=True,text=True,timeout=40)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('--historical-ec339-independent-signed-head-inventory-sha256',p.stdout)
            self.assertNotIn('--private-key',p.stdout)


def load_tests(loader,tests,pattern):
    import unittest
    names=sorted(name for name in dir(ArchivedHistoryTests)
                 if name.startswith('test_ec390_'))
    return unittest.TestSuite(ArchivedHistoryTests(name) for name in names)


if __name__=='__main__':
    import unittest
    unittest.TextTestRunner(verbosity=2).run(load_tests(None,None,None))
