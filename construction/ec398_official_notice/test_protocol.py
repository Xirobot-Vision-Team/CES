#!/usr/bin/env python3
"""EC398 true local Ed25519+bytes, synthetic EC397 parent and TSA MOCKED.

These fixtures DO NOT supply a real official government publication, legal
registrar certificate, prior internet availability, hardware WORM or real DER.
"""
from __future__ import annotations

import copy
import json
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec295_delivery_anchor import anchor as errors
from ec397_publication_witness import test_protocol as ec397_test
from . import protocol as core


class ExternalNoticeLocalTests(unittest.TestCase):
    def setUp(self):
        old=ec397_test.PublicationTwoChannelTests(
          'test_02_derive_audit_whole_external_inventory_sha_and_floors')
        old.setUp()
        self.addCleanup(old.doCleanups)
        self.old=old;self.fixture=old.old
        # EC397 focused child audit still invokes no genuine EC396 ancestors.
        baseline=old.evaluate()
        old.opts[core.parent.NEW_REPEATS[0][0]]=[
              baseline['publication_epoch_reviews'][0]['channel_delivery_inventory_sha256']]
        old.opts[core.parent.NEW_REPEATS[1][0]]=[
              baseline['publication_epoch_reviews'][0]['signed_fork_originals_inventory_sha256']]
        old.opts[core.parent.NEW_REPEATS[2][0]]=[2]
        old.opts[core.parent.NEW_REPEATS[3][0]]=[1]
        complete=old.evaluate()
        self.assertTrue(complete['bounded_local_two_channel_original_integrity'])
        old.opts[core.parent.AUDIT_ONLY[0]]=complete[
            'receiver_verified_two_channel_publication_inventory_sha256']
        self.real_parent=old.evaluate(False)
        self.parentref={'path':old.opts[core.parent.NEW_SCALARS[0]],
                        'sha256':old.opts[core.parent.NEW_SCALARS[1]]}
        self.parent_sha=self.real_parent['receiver_verified_two_channel_publication_inventory_sha256']
        self.lineage=old.lineage
        self.pregref=old.pbundle['epochs'][0]['registry']['signed_original']
        self.pregclaim=json.loads(Path(self.pregref['path']).read_bytes())['claim']
        for name in ('official_registrar','notice_a','notice_b'):
            self.fixture.keys[name]=Ed25519PrivateKey.generate()
            self.fixture.roles[name]=self.fixture.role(name)
        for name,parentname in (('notice_a','channel_a'),('notice_b','channel_b')):
            self.fixture.roles[name]['channel_id']=self.fixture.roles[parentname]['channel_id']
        self.roster={'schema':core.ROSTER_SCHEMA,
           'claimed_directory_lineage_id':self.lineage,
           'registrar':self.fixture.roles['official_registrar'],
           'custodians':[self.fixture.roles['notice_a'],self.fixture.roles['notice_b']]}
        self.rosterref=self.fixture.archive(self.roster,'ec398-external-roster')
        self.source=self.fixture.archive(
            b'OPAQUE historical gazette excerpt; NOT independently authenticated',
            'external-source-notice')
        self.opts=dict(old.opts)
        self.opts[core.NEW_SCALARS[2]]=self.rosterref['sha256']
        for i,name in enumerate(('official_registrar','notice_a','notice_b')):
            self.opts[core.NEW_SCALARS[3+i]]=self.fixture.roles[name]['public_hex']
        self.anchor=old.anchor
        self._build()

    def _bulletin(self):
        c={'schema':core.NOTICE_CLAIM,'directory_lineage_id':self.lineage,
           'parent_ec397_bundle_sha256':self.parentref['sha256'],
           'parent_ec397_verified_inventory_sha256':self.parent_sha,
           'parent_ec396_signed_registry_snapshot_sha256':self.pregref['sha256'],
           'epoch_index':0,'notice_sequence':1,
           'registrar_id':self.fixture.roles['official_registrar']['role_id'],
           'source_notice_original_sha256':self.source['sha256'],
           'previous_signed_notice_original_sha256':core.ZERO,
           'subjects':copy.deepcopy(self.pregclaim['subjects']),
           'claimed_published_utc':'2026-10-25T14:35:00Z'}
        return {'signed_original':self.fixture.signed('official_registrar',
             core.NOTICE_DOMAIN,c,core.NOTICE_SCHEMA),
             'rfc3161_token_original':self.fixture.archive(b'NOT_DER_NOTICE','token')}

    def _receipt(self,name,notice):
        role=self.fixture.roles[name]
        channel=role['channel_id']
        original=next(x['signed_receipt_original'] for x in self.old.body['epochs'][0]['channels']
                      if x['channel_id']==channel)
        copied_source=self.fixture.archive(Path(self.source['path']).read_bytes(),'copy-source')
        copied_notice=self.fixture.archive(Path(notice['signed_original']['path']).read_bytes(),
                                           'copy-signed-notice')
        copied_parent=self.fixture.archive(Path(original['path']).read_bytes(),
                                           'copy-parent-channel-receipt')
        refs=(('source_notice',copied_source,self.source),
              ('signed_notice',copied_notice,notice['signed_original']),
              ('parent_receipt',copied_parent,original))
        rows=[{'kind':kind,'source_sha256':src['sha256'],
               'copy_sha256':ref['sha256'],'copy_path':ref['path']}
              for kind,ref,src in refs]
        c={'schema':core.CUSTODY_CLAIM,'directory_lineage_id':self.lineage,
           'parent_ec397_bundle_sha256':self.parentref['sha256'],
           'parent_ec397_verified_inventory_sha256':self.parent_sha,
           'epoch_index':0,'channel_id':channel,
           'custodian_id':role['role_id'],'custodian_site_id':role['site_id'],
           'signed_notice_original_sha256':notice['signed_original']['sha256'],
           'source_notice_original_sha256':self.source['sha256'],
           'parent_signed_channel_receipt_original_sha256':original['sha256'],
           'previous_custodian_receipt_original_sha256':core.ZERO,
           'three_original_copy_inventory_sha256':core.cdigest(rows),
           'claimed_archived_utc':'2026-10-25T14:45:00Z'}
        s=self.fixture.signed(name,core.CUSTODY_DOMAIN,c,core.CUSTODY_SCHEMA)
        return {'channel_id':channel,'signed_receipt_original':s,
           'rfc3161_token_original':self.fixture.archive(b'NOT_DER_CUSTODY','token'),
           'copied_source_notice_original':copied_source,
           'copied_signed_notice_original':copied_notice,
           'copied_parent_channel_receipt_original':copied_parent}

    def _build(self):
        notice=self._bulletin()
        custody=[self._receipt(name,notice) for name in ('notice_a','notice_b')]
        self.body={'schema':core.BUNDLE_SCHEMA,
          'claimed_directory_lineage_id':self.lineage,
          'parent_ec397_publication_bundle_original':self.parentref,
          'outside_notice_roster_original':self.rosterref,
          'epochs':[{'epoch_index':0,'source_notice_original':self.source,
                    'notice':notice,'custodians':custody}]}
        self._save()
        self.opts[core.NEW_SCALARS[6]]=self.source['sha256']
        self.opts[core.NEW_SCALARS[7]]=notice['signed_original']['sha256']
        self.opts[core.NEW_SCALARS[8]]=custody[0]['signed_receipt_original']['sha256']
        self.opts[core.NEW_SCALARS[9]]=custody[1]['signed_receipt_original']['sha256']
        for k in core.REPEAT_NAMES:
            self.opts[k]=[0] if k.startswith('minimum_') else ['a'*64]

    def _save(self):
        r=self.fixture.archive(self.body,'ec398-bundle')
        self.opts[core.NEW_SCALARS[0]]=r['path']
        self.opts[core.NEW_SCALARS[1]]=r['sha256']

    def _stamp(self,raw,ref,trust,aid,read,evaluation,cutoff,claimed,flags,flag):
        return ({'gen':claimed+timedelta(seconds=1),'sha256':ref['sha256'],'clean':True}
                if ref else None)

    def evaluate(self,derive=True):
        with patch.object(core,'_inputs',return_value={}),\
             patch.object(core.parent,'audit',return_value=self.real_parent),\
             patch.object(core.parent.parent.parent,'_actual_parent_source',
                          return_value=self.anchor),\
             patch.object(core,'_stamp',side_effect=self._stamp):
            return core.derive_inventory(**self.opts) if derive else core.audit(**self.opts)

    def denied(self):
        with self.assertRaises(errors.AnchorError):self.evaluate()

    def test_01_valid_local_ed25519_and_all_six_exact_original_copies(self):
        r=self.evaluate()
        self.assertEqual(r['verified_corroborated_active_notice_role_count'],4)
        self.assertEqual(r['verified_two_channel_three_original_custody_count'],2)
        self.assertEqual(r['visible_genuine_signed_registry_conflict_count'],0)
        self.assertEqual(r['exit_code'],2)
        self.assertFalse(r['bounded_local_external_notice_and_custody_consistency'])
        self.assertFalse(r['opaque_gazette_original_proves_legally_effective_official_announcement'])

    def test_02_two_phase_derive_and_audit_not_self_authorizing(self):
        r=self.evaluate()
        row=r['external_notice_epoch_reviews'][0]
        self.opts[core.REPEAT_NAMES[0]]=[row['notice_originals_inventory_sha256']]
        self.opts[core.REPEAT_NAMES[1]]=[row['custody_original_readback_inventory_sha256']]
        self.opts[core.REPEAT_NAMES[2]]=[4]
        self.opts[core.REPEAT_NAMES[3]]=[2]
        good=self.evaluate()
        self.assertTrue(good['bounded_local_external_notice_and_custody_consistency'])
        self.opts[core.AUDIT_ONLY[0]]=good['receiver_verified_external_notice_inventory_sha256']
        accepted=self.evaluate(False)
        self.assertEqual(accepted['schema'],core.RESULT_SCHEMA)
        self.assertNotIn('unsigned_external_notice_inventory',accepted)
        self.assertEqual(accepted['verified_two_channel_three_original_custody_count'],2)
        self.assertEqual(accepted['exit_code'],2)  # never regulatory PASS
        self.opts[core.AUDIT_ONLY[0]]='f'*64
        self.assertTrue(self.evaluate(False)[core.FLAGS[1]])

    def test_03_real_parent_report_forged_sha_rejected(self):
        self.real_parent=copy.deepcopy(self.real_parent)
        self.real_parent['receiver_verified_two_channel_publication_inventory_sha256']='f'*64
        self.denied()

    def test_04_parent_signed_fork_or_bad_channels_cannot_gain_notice_credit(self):
        self.real_parent=copy.deepcopy(self.real_parent)
        self.real_parent[core.parent.FLAGS[4]]=True
        self.real_parent['bounded_local_two_channel_original_integrity']=False
        self.real_parent['status']=core.parent.OUTCOMES[4]+'_unresolved'
        r=self.evaluate()
        self.assertEqual(r['verified_corroborated_active_notice_role_count'],0)
        self.assertEqual(r['verified_two_channel_three_original_custody_count'],0)
        self.assertTrue(r[core.FLAGS[0]])

    def test_05_forged_notice_ed25519_signature_denied(self):
        d=self.body['epochs'][0]['notice']
        s=json.loads(Path(d['signed_original']['path']).read_bytes())
        s['signature_ed25519']='00'*64
        d['signed_original']=self.fixture.archive(s,'fake-notice')
        self._save();self.denied()

    def test_06_forged_custodian_signature_denied(self):
        d=self.body['epochs'][0]['custodians'][0]
        s=json.loads(Path(d['signed_receipt_original']['path']).read_bytes())
        s['signature_ed25519']='00'*64
        d['signed_receipt_original']=self.fixture.archive(s,'fake-keeper')
        self._save();self.denied()

    def test_07_source_bytes_changed_denied(self):
        Path(self.source['path']).write_bytes(b'REPLACED OFFICIAL NOTICE')
        self.denied()

    def test_08_copied_parent_receipt_bytes_changed_denied(self):
        ref=self.body['epochs'][0]['custodians'][1]['copied_parent_channel_receipt_original']
        Path(ref['path']).write_bytes(b'WRONG REPLICA')
        self.denied()

    def test_09_copy_path_cross_role_alias_denied(self):
        c=self.body['epochs'][0]['custodians']
        c[1]['copied_source_notice_original']=c[0]['copied_source_notice_original']
        self._save();self.denied()

    def test_10_reused_existing_signer_key_denied(self):
        bad=self.fixture.roles['registrar']
        self.roster['registrar']=bad
        self.rosterref=self.fixture.archive(self.roster,'reused-ec396-signer')
        self.body['outside_notice_roster_original']=self.rosterref
        self.opts[core.NEW_SCALARS[2]]=self.rosterref['sha256']
        self.opts[core.NEW_SCALARS[3]]=bad['public_hex']
        self._save();self.denied()

    def test_11_reused_site_by_new_signer_denied(self):
        self.roster['custodians'][0]['site_id']=self.roster['registrar']['site_id']
        self.rosterref=self.fixture.archive(self.roster,'reused-site')
        self.body['outside_notice_roster_original']=self.rosterref
        self.opts[core.NEW_SCALARS[2]]=self.rosterref['sha256']
        self._save();self.denied()

    def test_12_parent_signed_status_disagreement_cannot_authenticate_roles(self):
        n=self.body['epochs'][0]['notice']
        signed=json.loads(Path(n['signed_original']['path']).read_bytes())
        signed['claim']['subjects'][0]['status']='revoked'
        n['signed_original']=self.fixture.signed('official_registrar',
           core.NOTICE_DOMAIN,signed['claim'],core.NOTICE_SCHEMA)
        self.body['epochs'][0]['custodians']=[self._receipt(name,n) for name in
                                               ('notice_a','notice_b')]
        self._save()
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[3]])
        self.assertEqual(r['verified_corroborated_active_notice_role_count'],0)
        self.assertEqual(r['visible_genuine_signed_registry_conflict_count'],1)

    def test_13_parent_actual_role_identity_substitution_denied(self):
        n=self.body['epochs'][0]['notice']
        signed=json.loads(Path(n['signed_original']['path']).read_bytes())
        signed['claim']['subjects'][0]['public_hex']='f'*64
        n['signed_original']=self.fixture.signed('official_registrar',
          core.NOTICE_DOMAIN,signed['claim'],core.NOTICE_SCHEMA)
        self._save();self.denied()

    def test_14_signed_earlier_notice_than_real_parent_registry_loses_credit(self):
        n=self.body['epochs'][0]['notice']
        signed=json.loads(Path(n['signed_original']['path']).read_bytes())
        signed['claim']['claimed_published_utc']='2026-10-25T13:00:00Z'
        n['signed_original']=self.fixture.signed('official_registrar',
          core.NOTICE_DOMAIN,signed['claim'],core.NOTICE_SCHEMA)
        self.body['epochs'][0]['custodians']=[self._receipt(name,n) for name in
                                               ('notice_a','notice_b')]
        self._save()
        r=self.evaluate()
        self.assertEqual(r['verified_corroborated_active_notice_role_count'],0)
        self.assertTrue(r[core.FLAGS[2]])

    def test_15_too_late_custody_claim_loses_credit(self):
        c=self.body['epochs'][0]['custodians'][0]
        signed=json.loads(Path(c['signed_receipt_original']['path']).read_bytes())
        signed['claim']['claimed_archived_utc']='2026-10-25T15:30:00Z'
        c['signed_receipt_original']=self.fixture.signed('notice_a',
           core.CUSTODY_DOMAIN,signed['claim'],core.CUSTODY_SCHEMA)
        self._save()
        r=self.evaluate()
        self.assertEqual(r['verified_two_channel_three_original_custody_count'],1)
        self.assertTrue(r[core.FLAGS[4]])

    def test_16_wrong_actual_parent_observer_sha_denied(self):
        c=self.body['epochs'][0]['custodians'][0]
        signed=json.loads(Path(c['signed_receipt_original']['path']).read_bytes())
        signed['claim']['parent_signed_channel_receipt_original_sha256']='e'*64
        c['signed_receipt_original']=self.fixture.signed('notice_a',
          core.CUSTODY_DOMAIN,signed['claim'],core.CUSTODY_SCHEMA)
        self._save();self.denied()

    def test_17_wrong_signed_previous_original_denied(self):
        c=self.body['epochs'][0]['custodians'][1]
        signed=json.loads(Path(c['signed_receipt_original']['path']).read_bytes())
        signed['claim']['previous_custodian_receipt_original_sha256']='a'*64
        c['signed_receipt_original']=self.fixture.signed('notice_b',
          core.CUSTODY_DOMAIN,signed['claim'],core.CUSTODY_SCHEMA)
        self._save();self.denied()

    def test_18_missing_second_signer_only_one_custody_credit(self):
        c=self.body['epochs'][0]['custodians'][1]
        for k in core.CUSTODY_FIELDS-{'channel_id'}:c[k]=None
        self._save()
        r=self.evaluate()
        self.assertEqual(r['verified_two_channel_three_original_custody_count'],1)
        self.assertTrue(r[core.FLAGS[4]])

    def test_19_external_source_signature_pin_mismatch_unresolved(self):
        self.opts[core.NEW_SCALARS[6]]='f'*64
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[1]])
        self.assertEqual(r['exit_code'],2)

    def test_20_externally_pinned_whole_parent_status_cannot_be_PASS(self):
        self.real_parent=copy.deepcopy(self.real_parent)
        self.real_parent['status']='PASS'
        self.denied()

    def test_21_real_parent_pair_one_requires_two_deliveries(self):
        self.real_parent=copy.deepcopy(self.real_parent)
        self.real_parent['publication_epoch_reviews'][0]['verified_signed_channel_deliveries']=1
        self.real_parent['verified_independent_signed_channel_delivery_count']=1
        self.denied()

    def test_22_new_opaque_notice_source_cannot_alias_parent_original(self):
        self.body['epochs'][0]['source_notice_original']=self.pregref
        self._save();self.denied()

    def test_23_new_signed_notice_original_cannot_alias_parent_original(self):
        self.body['epochs'][0]['notice']['signed_original']=self.pregref
        self._save();self.denied()

    def test_24_missing_new_tsa_token_must_lose_credit(self):
        self.body['epochs'][0]['notice']['rfc3161_token_original']=None
        self._save()
        r=self.evaluate()
        self.assertEqual(r['verified_corroborated_active_notice_role_count'],0)
        self.assertEqual(r['verified_two_channel_three_original_custody_count'],0)
        self.assertTrue(r[core.FLAGS[2]])

    def test_25_signed_notice_wrong_parent_source_sha_is_not_corroboration(self):
        notice=self.body['epochs'][0]['notice']
        signed=json.loads(Path(notice['signed_original']['path']).read_bytes())
        signed['claim']['parent_ec396_signed_registry_snapshot_sha256']='e'*64
        notice['signed_original']=self.fixture.signed('official_registrar',
              core.NOTICE_DOMAIN,signed['claim'],core.NOTICE_SCHEMA)
        self._save();self.denied()

    def test_26_custodian_copy_cannot_reuse_its_parent_original_path(self):
        c=self.body['epochs'][0]['custodians'][0]
        real=next(x['signed_receipt_original'] for x in
             self.old.body['epochs'][0]['channels']
             if x['channel_id']==c['channel_id'])
        c['copied_parent_channel_receipt_original']=real
        self._save();self.denied()

if __name__=='__main__':unittest.main()
