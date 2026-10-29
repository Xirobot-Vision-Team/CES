#!/usr/bin/env python3
"""EC397 genuinely signed local originals; parent and TSA deliberately MOCKED.

No test here asserts real public internet publication, issuer qualification, or
independently administered hardware. These are offline byte-and-signature tests.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
from datetime import timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import copy
import json
import unittest

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from public_integrity.test_protocol import PublicHistoryLocalTests
from . import protocol as core


class PublicationTwoChannelTests(unittest.TestCase):
    def setUp(self):
        self.old=PublicHistoryLocalTests('test_01_ed25519_registry_four_real_roles_and_time_bounded')
        self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        b=self.old
        b.setup_bundle()
        # Parent EC396 locally signs true RFC6962 EC395-source inclusions, device
        # and registry originals. The ancestral EC395 audit and TSA are mocked.
        pre=b.evaluate()
        for key,rowkey in zip((x[0] for x in core.parent.NEW_REPEATS[:3]),
               ('registry_inventory_sha256','log_inclusion_inventory_sha256',
                'device_recovery_inventory_sha256')):
            b.opts[key]=[pre['public_integrity_epoch_reviews'][0][rowkey]]
        complete=b.evaluate()
        b.opts[core.parent.AUDIT_ONLY[0]]=complete[
             'receiver_verified_public_integrity_inventory_sha256']
        self.actual=b.evaluate(derive=False)
        self.assertEqual(self.actual['local_original_public_history_and_device_copy_consistency'],True)
        self.lineage=b.lineage
        self.parentref={'path':b.opts[core.parent.NEW_SCALARS[0]],
                        'sha256':b.opts[core.parent.NEW_SCALARS[1]]}
        self.pbundle=json.loads(Path(self.parentref['path']).read_bytes())
        self.headep=self.pbundle['epochs'][0]['log']
        self.headref=self.headep['signed_head_original']
        self.headclaim=json.loads(Path(self.headref['path']).read_bytes())['claim']
        self.parentdigest=self.actual['receiver_verified_public_integrity_inventory_sha256']
        for name in ('channel_a','channel_b'):
            b.keys[name]=Ed25519PrivateKey.generate()
            b.roles[name]=b.role(name)
            b.roles[name]['channel_id']='channel-'+name[-1]
        self.roster={'schema':core.ROSTER_SCHEMA,'claimed_directory_lineage_id':self.lineage,
               'channels':[b.roles['channel_a'],b.roles['channel_b']]}
        self.rosterref=b.archive(self.roster,'ec397-witness-roster')
        self.opts=dict(b.opts)
        self.opts[core.NEW_SCALARS[2]]=self.rosterref['sha256']
        for i,name in enumerate(('channel_a','channel_b')):
            self.opts[core.NEW_SCALARS[3+i]]=b.roles[name]['public_hex']
        self.anchor={'known_keys':[],'known_sites':[],'known_ids':[],
                     'trust':{},'authority':'MOCK_TSA'}
        self._build()

    def _dispatch(self):
        c={'schema':core.DISPATCH_CLAIM,'directory_lineage_id':self.lineage,
           'parent_ec396_bundle_sha256':self.parentref['sha256'],
           'parent_ec396_verified_inventory_sha256':self.parentdigest,
           'epoch_index':0,'dispatch_sequence':1,
           'log_signer_id':self.old.roles['log']['role_id'],
           'public_log_signed_head_original_sha256':self.headref['sha256'],
           'public_log_merkle_size':self.headclaim['tree_size'],
           'public_log_merkle_root_sha256':self.headclaim['merkle_root_sha256'],
           'previous_dispatch_original_sha256':core.ZERO,
           'claimed_dispatched_utc':'2026-10-25T14:15:00Z'}
        s=self.old.signed('log',core.DISPATCH_DOMAIN,c,core.DISPATCH_SCHEMA)
        return {'signed_original':s,
                'rfc3161_token_original':self.old.archive(b'MOCK_DER_DISPATCH','token-dispatch')}

    def _channel(self,name,dispatch):
        b=self.old
        dc=b.archive(Path(dispatch['signed_original']['path']).read_bytes(),'channel-dispatch-copy')
        hc=b.archive(Path(self.headref['path']).read_bytes(),'channel-head-copy')
        rows=[{'kind':'dispatch','original_sha256':dispatch['signed_original']['sha256'],
              'original_copy_path':dc['path'],'copy_sha256':dc['sha256']},
              {'kind':'public_head','original_sha256':self.headref['sha256'],
               'original_copy_path':hc['path'],'copy_sha256':hc['sha256']}]
        role=b.roles[name]
        c={'schema':core.RECEIPT_CLAIM,
           'directory_lineage_id':self.lineage,
           'parent_ec396_bundle_sha256':self.parentref['sha256'],
           'parent_ec396_verified_inventory_sha256':self.parentdigest,
           'epoch_index':0,'channel_id':role['channel_id'],
           'observer_id':role['role_id'],'observer_site_id':role['site_id'],
           'public_log_head_original_sha256':self.headref['sha256'],
           'public_log_merkle_size':self.headclaim['tree_size'],
           'public_log_merkle_root_sha256':self.headclaim['merkle_root_sha256'],
           'dispatch_signed_original_sha256':dispatch['signed_original']['sha256'],
           'previous_channel_receipt_original_sha256':core.ZERO,
           'recovered_original_copies_inventory_sha256':core.cdigest(rows),
           'claimed_observed_utc':'2026-10-25T14:20:00Z'}
        sig=b.signed(name,core.RECEIPT_DOMAIN,c,core.RECEIPT_SCHEMA)
        return {'channel_id':role['channel_id'],'signed_receipt_original':sig,
             'rfc3161_token_original':b.archive(b'MOCK_DER_CHANNEL','token-channel'),
             'copied_dispatch_original':dc,'copied_public_log_head_original':hc}

    def _build(self):
        dispatch=self._dispatch()
        channels=[self._channel(name,dispatch) for name in ('channel_a','channel_b')]
        self.body={'schema':core.BUNDLE_SCHEMA,
          'claimed_directory_lineage_id':self.lineage,
          'parent_ec396_public_integrity_bundle_original':self.parentref,
          'outside_observer_roster_original':self.rosterref,
          'epochs':[{'epoch_index':0,'dispatch':dispatch,
                     'channels':channels,'conflicting_heads':[]}]}
        self._save()
        self.opts[core.NEW_SCALARS[5]]=dispatch['signed_original']['sha256']
        self.opts[core.NEW_SCALARS[6]]=channels[0]['signed_receipt_original']['sha256']
        self.opts[core.NEW_SCALARS[7]]=channels[1]['signed_receipt_original']['sha256']
        for k,_ in core.NEW_REPEATS:
            self.opts[k]=[0] if k.startswith('minimum_') else ['a'*64]

    def _save(self):
        ref=self.old.archive(self.body,'bundle-ec397')
        self.opts[core.NEW_SCALARS[0]]=ref['path']
        self.opts[core.NEW_SCALARS[1]]=ref['sha256']

    def _timestamps(self,raw,ref,trust,aid,read,evaluation,cutoff,claimed,flags):
        return {'gen':claimed+timedelta(seconds=1),'clean':True,'sha256':ref['sha256']} if ref else None

    def evaluate(self,derive=True):
        with patch.object(core,'_inputs',return_value={}),\
             patch.object(core.parent,'audit',return_value=self.actual),\
             patch.object(core.parent.parent,'_actual_parent_source',return_value=self.anchor),\
             patch.object(core,'_stamp',side_effect=self._timestamps):
            return core.derive_inventory(**self.opts) if derive else core.audit(**self.opts)

    def _denied(self):
        with self.assertRaises(errors.AnchorError):self.evaluate()

    def test_01_genuine_two_new_keys_and_two_original_copies(self):
        doc=self.evaluate()
        self.assertEqual(doc['verified_independent_signed_channel_delivery_count'],2)
        self.assertEqual(doc['verified_two_channel_observation_pair_count'],1)
        self.assertFalse(doc['bounded_local_two_channel_original_integrity']) # wrong outside floors
        self.assertFalse(doc['two_signatures_on_furnished_documents_prove_independent_internet_publication'])
        self.assertEqual(doc['exit_code'],2)

    def test_02_derive_audit_whole_external_inventory_sha_and_floors(self):
        doc=self.evaluate()
        review=doc['publication_epoch_reviews'][0]
        self.opts[core.NEW_REPEATS[0][0]]=[review['channel_delivery_inventory_sha256']]
        self.opts[core.NEW_REPEATS[1][0]]=[review['signed_fork_originals_inventory_sha256']]
        self.opts[core.NEW_REPEATS[2][0]]=[2]
        self.opts[core.NEW_REPEATS[3][0]]=[1]
        good=self.evaluate()
        self.assertTrue(good['bounded_local_two_channel_original_integrity'])
        self.opts[core.AUDIT_ONLY[0]]=good[
            'receiver_verified_two_channel_publication_inventory_sha256']
        audited=self.evaluate(False)
        self.assertEqual(audited['schema'],core.RESULT_SCHEMA)
        self.assertEqual(audited['verified_two_channel_observation_pair_count'],1)
        self.assertNotIn('unsigned_two_channel_publication_inventory',audited)
        self.assertEqual(audited['exit_code'],2)
        self.opts[core.AUDIT_ONLY[0]]='b'*64
        self.assertTrue(self.evaluate(False)[core.FLAGS[1]])

    def test_03_wrong_parent_real_inventory_sha_fails_closed(self):
        self.actual=copy.deepcopy(self.actual)
        self.actual['receiver_verified_public_integrity_inventory_sha256']='c'*64
        self._denied()

    def test_04_parent_with_signed_history_adversity_cannot_get_channel_credit(self):
        self.actual=copy.deepcopy(self.actual)
        self.actual[core.parent.FLAGS[0]]=True
        self.actual['local_original_public_history_and_device_copy_consistency']=False
        self.actual['status']=core.parent.OUTCOMES[0]+'_unresolved'
        r=self.evaluate()
        self.assertEqual(r['verified_independent_signed_channel_delivery_count'],0)
        self.assertTrue(r[core.FLAGS[0]])

    def test_05_forged_receipt_signature_is_rejected(self):
        d=self.body['epochs'][0]['channels'][0]
        obj=json.loads(Path(d['signed_receipt_original']['path']).read_bytes())
        obj['signature_ed25519']='00'*64
        d['signed_receipt_original']=self.old.archive(obj,'forged-receipt')
        self._save();self._denied()

    def test_06_replayed_witness_role_key_is_not_independent(self):
        self.roster['channels'][0]['public_hex']=self.old.roles['registrar']['public_hex']
        self.roster['channels'][0]['public_key_original']=self.old.roles['registrar']['public_key_original']
        self.rosterref=self.old.archive(self.roster,'bad-roster')
        self.body['outside_observer_roster_original']=self.rosterref
        self.opts[core.NEW_SCALARS[2]]=self.rosterref['sha256']
        self.opts[core.NEW_SCALARS[3]]=self.old.roles['registrar']['public_hex']
        self._save();self._denied()

    def test_07_copy_byte_mutation_even_under_genuine_hash_detected(self):
        d=self.body['epochs'][0]['channels'][0]
        ref=d['copied_public_log_head_original']
        Path(ref['path']).write_bytes(b'BIT ROT')
        self._denied()

    def test_08_duplicate_channel_copy_alias_across_independent_roles_denied(self):
        chans=self.body['epochs'][0]['channels']
        chans[1]['copied_public_log_head_original']=chans[0]['copied_public_log_head_original']
        self._save();self._denied()

    def test_09_real_signed_conflicting_head_recorded_without_public_consensus(self):
        alt=dict(self.headclaim)
        alt['merkle_root_sha256']='f'*64
        genuine=self.old.signed('log',core.parent.LOG_DOMAIN,alt,core.parent.LOG_SCHEMA)
        self.body['epochs'][0]['conflicting_heads']=[{'signed_head_original':genuine,
         'rfc3161_token_original':self.old.archive(b'MOCK_DER_FORK','fork-token')}]
        self._save()
        doc=self.evaluate()
        self.assertEqual(doc['visible_authentic_signed_public_log_fork_count'],1)
        self.assertEqual(doc['verified_independent_signed_channel_delivery_count'],0)
        self.assertTrue(doc[core.FLAGS[4]])
        self.assertEqual(doc['unsigned_two_channel_publication_inventory'][
           'observed_genuine_signed_forks'][0]['signed_conflicting_head_sha256'],genuine['sha256'])

    def test_10_unsigned_alternative_is_not_accepted_as_fork(self):
        alt=dict(self.headclaim)
        alt['merkle_root_sha256']='e'*64
        genuine=self.old.signed('log',core.parent.LOG_DOMAIN,alt,core.parent.LOG_SCHEMA)
        obj=json.loads(Path(genuine['path']).read_bytes());obj['signature_ed25519']='00'*64
        forged=self.old.archive(obj,'fake-fork')
        self.body['epochs'][0]['conflicting_heads']=[{
          'signed_head_original':forged,'rfc3161_token_original':None}]
        self._save();self._denied()

    def test_11_missing_receipt_is_unresolved_and_cannot_recredit(self):
        d=self.body['epochs'][0]['channels'][1]
        for name in ('signed_receipt_original','rfc3161_token_original',
                     'copied_dispatch_original','copied_public_log_head_original'):
            d[name]=None
        self._save()
        doc=self.evaluate()
        self.assertEqual(doc['verified_independent_signed_channel_delivery_count'],1)
        self.assertEqual(doc['verified_two_channel_observation_pair_count'],0)
        self.assertTrue(doc[core.FLAGS[3]])

    def test_12_wrong_claimed_signed_dispatch_head_sha_rejected(self):
        d=self.body['epochs'][0]['dispatch']
        c=json.loads(Path(d['signed_original']['path']).read_bytes())['claim']
        c['public_log_signed_head_original_sha256']='e'*64
        d['signed_original']=self.old.signed('log',core.DISPATCH_DOMAIN,c,core.DISPATCH_SCHEMA)
        self._save();self._denied()

    def test_13_wrong_signed_observation_copy_inventory_rejected(self):
        d=self.body['epochs'][0]['channels'][0]
        c=json.loads(Path(d['signed_receipt_original']['path']).read_bytes())['claim']
        c['recovered_original_copies_inventory_sha256']='e'*64
        d['signed_receipt_original']=self.old.signed('channel_a',core.RECEIPT_DOMAIN,c,
                                                     core.RECEIPT_SCHEMA)
        self._save();self._denied()

    def test_14_prior_token_order_after_cutoff_cannot_grant_count(self):
        def bad_timestamp(raw,ref,trust,aid,read,evaluation,cutoff,claimed,flags):
            return {'gen':claimed+timedelta(days=2),'clean':True,'sha256':ref['sha256']}
        with patch.object(core,'_inputs',return_value={}),\
             patch.object(core.parent,'audit',return_value=self.actual),\
             patch.object(core.parent.parent,'_actual_parent_source',return_value=self.anchor),\
             patch.object(core,'_stamp',side_effect=bad_timestamp):
            doc=core.derive_inventory(**self.opts)
        self.assertEqual(doc['verified_two_channel_observation_pair_count'],0)
        self.assertTrue(doc[core.FLAGS[2]])

    def test_15_unbounded_signer_role_status_is_unavailable(self):
        self.actual=copy.deepcopy(self.actual)
        self.actual['status']='PASS'
        self._denied()

    def test_16_duplicate_fork_original_bytes_cannot_inflate_signed_conflict_count(self):
        alt=dict(self.headclaim);alt['merkle_root_sha256']='f'*64
        first=self.old.signed('log',core.parent.LOG_DOMAIN,alt,core.parent.LOG_SCHEMA)
        second=self.old.archive(Path(first['path']).read_bytes(),'copied-duplicate-fork')
        self.body['epochs'][0]['conflicting_heads']=[
          {'signed_head_original':first,'rfc3161_token_original':None},
          {'signed_head_original':second,'rfc3161_token_original':None}]
        self._save();self._denied()

    def test_17_copy_alias_to_real_parent_signed_head_is_forbidden(self):
        self.body['epochs'][0]['channels'][0]['copied_public_log_head_original']=self.headref
        self._save();self._denied()

    def test_18_receipt_claim_earlier_than_signed_dispatch_loses_credit(self):
        d=self.body['epochs'][0]['channels'][0]
        c=json.loads(Path(d['signed_receipt_original']['path']).read_bytes())['claim']
        c['claimed_observed_utc']='2026-10-25T14:00:00Z'
        d['signed_receipt_original']=self.old.signed('channel_a',core.RECEIPT_DOMAIN,c,
                                                     core.RECEIPT_SCHEMA)
        self._save()
        report=self.evaluate()
        self.assertEqual(report['verified_independent_signed_channel_delivery_count'],1)
        self.assertTrue(report[core.FLAGS[3]])

    def test_19_signed_wrong_previous_receipt_original_sha_is_rejected(self):
        d=self.body['epochs'][0]['channels'][0]
        c=json.loads(Path(d['signed_receipt_original']['path']).read_bytes())['claim']
        c['previous_channel_receipt_original_sha256']='a'*64
        d['signed_receipt_original']=self.old.signed('channel_a',core.RECEIPT_DOMAIN,c,
                                                     core.RECEIPT_SCHEMA)
        self._save();self._denied()

    def test_20_outside_first_receipt_pin_mismatch_sets_adverse_not_pass(self):
        self.opts[core.NEW_SCALARS[6]]='b'*64
        doc=self.evaluate()
        self.assertEqual(doc['verified_independent_signed_channel_delivery_count'],2)
        self.assertTrue(doc[core.FLAGS[1]])
        self.assertEqual(doc['exit_code'],2)

if __name__=='__main__':unittest.main()
