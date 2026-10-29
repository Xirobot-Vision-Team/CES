#!/usr/bin/env python3
"""EC384 original-byte test fixtures; old EC347->EC337 ancestor remains MOCKED.

First focused test replays the actual locally signed EC348->EC345 input; other
scoped tests re-use that *already replayed* ancestor but verify actual EC344 /
EC345 Ed25519 signed original bytes, roles and original SHA references.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from receiver_visibility import visibility as old344
from disclosure_challenge import challenge as old345
from historical_readback import test_readback_archive as site_fixture
from . import offer_archive as core


def digest(raw):return core.sha(raw)
def ref(path,sha):return {'path':str(path),'sha256':sha}


class OriginalDisclosureOfferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        site_fixture.OriginalChallengerReceiverSiteTests.setUpClass()
        cls.orig=site_fixture.OriginalChallengerReceiverSiteTests
        cls.h=cls.orig.fixture
        cls.src=cls.h.source
        cls.roster=cls.orig.replayed[0]
        cls.base_383=cls.orig.base_row
        cls.base_382=cls.orig.base_oldrow
        oldsites={s['receiver_id']:s for s in cls.base_383['ec346_receiver_copy_site_originals']}
        cls.base_row={
            'tsa_channel_id':cls.base_383['tsa_channel_id'],
            'ec345_disclosure_issuer_public_key_original':copy.deepcopy(
                cls.base_383['ec347_challenger_public_key_original']),
            'ec344_ec345_registered_receiver_keys_originals':[
                {'receiver_id':a['signer_id'],
                 'receiver_public_key_original':copy.deepcopy(oldsites[a['signer_id']][
                     'receiver_public_key_original'])} for a in cls.roster['receivers']],
            'ec344_signed_visibility_originals':[ref(p,s) for p,s in zip(
                cls.src['view_files'],cls.src['view_shas'],strict=True)],
            'ec345_signed_challenge_originals':[ref(p,s) for p,s in zip(
                cls.src['challenge_files'],cls.src['challenge_shas'],strict=True)],
            'ec345_signed_response_originals':[ref(p,s) for p,s in zip(
                cls.src['response_files'],cls.src['response_shas'],strict=True)],
        }

    @classmethod
    def tearDownClass(cls):
        site_fixture.OriginalChallengerReceiverSiteTests.tearDownClass()

    def setUp(self):
        self.row=copy.deepcopy(type(self).base_row)
        self.old383=copy.deepcopy(type(self).base_383)
        self.old382=copy.deepcopy(type(self).base_382)
        self.h.role_paths={}

    def tearDown(self):self.h.role_paths={}

    def run_origins(self,full=False):
        self.h.role_paths={}
        if full:return core._channel(self.row,self.old383,self.old382,
                                      self.h.read_original,set())
        with patch.object(core.parent.previous.previous,'_ec348_original',
                          return_value=self.h.ctx):
            return core._channel(self.row,self.old383,self.old382,
                                 self.h.read_original,set())

    def denied(self):
        with self.assertRaises(errors.AnchorError):self.run_origins()

    def test_01_genuine_legacy_signed_ec344_views_ec345_request_and_offer(self):
        r=self.run_origins(full=True)
        self.assertTrue(r['full_original_ec344_ec345_source_replay'])
        self.assertEqual(r['signed_ec344_registered_view_count'],2)
        self.assertEqual(r['signed_ec345_authorized_challenge_count'],1)
        self.assertEqual(r['signed_ec345_registered_receiver_offer_count'],2)
        self.assertTrue(r['verified_disclosed_target_has_signed_offer'])
        self.assertFalse(r['signed_ec345_predecessor_incomplete'])

    def test_02_source_parent_original_sha_mismatch_denied(self):
        self.old382['ec348_full_replay_inputs_original']['sha256']='aa'*32
        with self.assertRaises(errors.AnchorError):self.run_origins(full=True)

    def test_03_unsigned_checkpoint_sha_substitution_denied(self):
        self.old383['ec344_source_checkpoint_original']['sha256']='bb'*32;self.denied()

    def test_04_unsigned_directory_original_substitution_denied(self):
        self.old383['ec344_receiver_directory_original']['sha256']='cc'*32;self.denied()

    def test_05_authoritative_ec343_roster_original_pin_denied(self):
        self.old383['ec343_authority_roster_original']['sha256']='dd'*32;self.denied()

    def test_06_ec345_proposer_key_is_reused_from_real_ec383(self):
        self.row['ec345_disclosure_issuer_public_key_original']['sha256']='aa'*32;self.denied()

    def test_07_registered_receiver_key_swap_denied(self):
        rows=self.row['ec344_ec345_registered_receiver_keys_originals']
        rows[0]['receiver_public_key_original']=copy.deepcopy(rows[1]['receiver_public_key_original'])
        self.denied()

    def test_08_registered_receiver_id_census_enforced(self):
        self.row['ec344_ec345_registered_receiver_keys_originals'].pop();self.denied()

    def test_09_signed_view_original_census_cannot_be_truncated(self):
        self.row['ec344_signed_visibility_originals'].pop();self.denied()

    def test_10_signed_view_sha_pinned_to_actual_original_source(self):
        self.row['ec344_signed_visibility_originals'][0]['sha256']='cb'*32;self.denied()

    def test_11_signed_challenge_original_cannot_be_replaced(self):
        self.row['ec345_signed_challenge_originals'][0]['sha256']='ca'*32;self.denied()

    def test_12_signed_response_originals_cannot_be_truncated(self):
        self.row['ec345_signed_response_originals'].pop();self.denied()

    def test_13_signed_offer_response_order_is_authoritative(self):
        self.row['ec345_signed_response_originals'].reverse();self.denied()

    def test_14_signed_offer_original_sha_substitution_denied(self):
        self.row['ec345_signed_response_originals'][0]['sha256']='ac'*32;self.denied()

    def test_15_extra_signed_response_field_not_accepted(self):
        original=json.loads(Path(self.src['response_files'][0]).read_text())
        original['claim']['injected_new_authority']=True
        with self.assertRaises(errors.AnchorError):
            core._signed(original,old345.RESPONSE_FIELDS,old345.RESPONSE_SCHEMA,
                old345.RESPONSE_DOMAIN,self.roster['receivers'][0]['public_hex'],
                'TEST_SIGNED_EC345_EXTRA_FIELD')

    def test_16_actual_original_signature_tamper_denied(self):
        doc=json.loads(Path(self.src['challenge_files'][0]).read_bytes())
        doc['signature_ed25519']='00'*64
        with self.assertRaises(errors.AnchorError):
            core._signed(doc,old345.CHALLENGE_FIELDS,old345.CHALLENGE_SCHEMA,
                         old345.CHALLENGE_DOMAIN,self.roster['change_proposer']['public_hex'],
                         'TEST_SIGNED_OLD_EC345_SIGNATURE')

    def test_17_signed_view_bad_signature_denied(self):
        doc=json.loads(Path(self.src['view_files'][0]).read_bytes())
        doc['signature_ed25519']='00'*64
        r=next(a for a in self.roster['receivers'] if a['signer_id']==doc['claim']['receiver_id'])
        with self.assertRaises(errors.AnchorError):
            core._signed(doc,old344.VIEW_CLAIM_FIELDS,old344.VIEW_SCHEMA,
                         old344.DOMAIN,r['public_hex'],'TEST_SIGNED_EC344_VIEW')

    def test_18_signed_view_receiver_key_separation_is_strict(self):
        doc=json.loads(Path(self.src['view_files'][0]).read_bytes())
        with self.assertRaises(errors.AnchorError):
            core._signed(doc,old344.VIEW_CLAIM_FIELDS,old344.VIEW_SCHEMA,
                old344.DOMAIN,self.roster['change_proposer']['public_hex'],
                'TEST_SIGNER_ROLE_FORGERY')

    def test_19_signed_challenge_cannot_be_verified_by_receiver_key(self):
        doc=json.loads(Path(self.src['challenge_files'][0]).read_bytes())
        with self.assertRaises(errors.AnchorError):
            core._signed(doc,old345.CHALLENGE_FIELDS,old345.CHALLENGE_SCHEMA,
                old345.CHALLENGE_DOMAIN,self.roster['receivers'][0]['public_hex'],
                'TEST_EC345_PROPOSER_ROLE_FORGERY')

    def test_20_signed_response_cannot_be_verified_by_proposer_key(self):
        doc=json.loads(Path(self.src['response_files'][0]).read_bytes())
        with self.assertRaises(errors.AnchorError):
            core._signed(doc,old345.RESPONSE_FIELDS,old345.RESPONSE_SCHEMA,
                old345.RESPONSE_DOMAIN,self.roster['change_proposer']['public_hex'],
                'TEST_EC345_RECEIVER_ROLE_FORGERY')

    def test_21_signed_source_snapshot_and_ack_pair_must_match_ec383(self):
        self.old383['ec345_verified_source_ack_set_original']['sha256']='ab'*32;self.denied()

    def test_22_missing_old_ec348_originals_stay_unresolved(self):
        self.old382['ec348_full_replay_inputs_original']=None
        self.row={k:(self.base_row['tsa_channel_id'] if k=='tsa_channel_id' else None
                     if k=='ec345_disclosure_issuer_public_key_original' else [])
                  for k in core.CHANNEL_FIELDS}
        r=self.run_origins();self.assertFalse(r['full_original_ec344_ec345_source_replay'])
        self.assertEqual(r['signed_ec345_registered_receiver_offer_count'],0)

    def test_23_missing_source_cannot_insert_fake_signed_claims(self):
        self.old382['ec348_full_replay_inputs_original']=None;self.denied()

    def test_24_signed_challenge_original_bytes_tampered_denied(self):
        path=Path(self.src['challenge_files'][0]);original=path.read_bytes()
        try:
            path.write_bytes(original+b' ')
            self.denied()
        finally:path.write_bytes(original)

    def test_25_signed_view_original_bytes_tampered_denied(self):
        path=Path(self.src['view_files'][0]);original=path.read_bytes()
        try:
            path.write_bytes(original+b' ')
            self.denied()
        finally:path.write_bytes(original)

    def test_26_source_item_id_swap_does_not_become_signed_offer(self):
        with patch.object(core.parent.previous.previous,'_ec348_original',
                          return_value={'inputs':{**self.src,'item_id':'missing_target'}}):
            with self.assertRaises(errors.AnchorError):
                core._channel(self.row,self.old383,self.old382,self.h.read_original,set())

    def test_27_signed_view_not_same_as_unsigned_checkpoint(self):
        self.assertEqual(self.run_origins()['signed_ec344_registered_view_count'],2)
        checkpoint=json.loads(Path(self.src['checkpoint_file']).read_bytes())
        self.assertNotIn('signature_ed25519',checkpoint)

    def _outer(self):
        """Outer EC383..369 parent MOCKED; new signed originals are real."""
        fake_parent={'schema':core.parent.RESULT_SCHEMA,'exit_code':2,
          'sender_origin_path_required_or_read':False,
          'ec346_through_ec337_full_independent_original_historical_acceptance_performed':False,
          'historical_ec347_site_epoch_reviews':[{'epoch_index':0}],
          'local_ec347_challenger_receiver_ec346_signed_source_originals_consistent':True}
        parent_sha=digest(canonical.canonical(fake_parent))
        def archive(name,doc):
            raw=canonical.canonical(doc);p=self.h.w/name;p.write_bytes(raw)
            return ref(p,digest(raw))
        old382=archive('ec384-fake-old-ec382.json',{
            'schema':core.parent.previous.BUNDLE_SCHEMA,
            'claimed_directory_lineage_id':'Lineage384',
            'epochs':[{'epoch_index':0,'channels':[self.old382]}],
            **{k:'33'*32 for k in core.parent.previous.BUNDLE_FIELDS if k not in (
                'schema','claimed_directory_lineage_id','epochs')}})
        old383=archive('ec384-fake-old-ec383.json',{
            'schema':core.parent.BUNDLE_SCHEMA,
            'claimed_directory_lineage_id':'Lineage384',
            'epochs':[{'epoch_index':0,'channels':[self.old383]}],
            **{k:'44'*32 for k in core.parent.BUNDLE_FIELDS if k not in (
                'schema','claimed_directory_lineage_id','epochs')}})
        original=archive('ec384-new-archive.json',{
            'schema':core.BUNDLE_SCHEMA,
            'claimed_directory_lineage_id':'Lineage384',
            'epochs':[{'epoch_index':0,'channels':[self.row]}],
            'parent_ec383_canonical_result_sha256':parent_sha,
            'ec383_historical_site_archive_original_sha256':old383['sha256']})
        labels=archive('ec384-old-sender-labels.json',{'schema':'fixture'})
        old377=archive('ec384-old-ec377.json',{
            'schema':core.parent.previous.previous.p379.p377.BUNDLE_SCHEMA,
            'epochs':[{'ec353_publication_bundle_original':labels}],
            **{k:'55'*32 for k in core.parent.previous.previous.p379.p377.BUNDLE_FIELDS
               if k not in ('schema','epochs')}})
        opts={'historical_directory_root_shas':['77'*32],
            'claimed_historical_directory_lineage_id':'Lineage384',
            'historical_ec348_keeper_archive_bundle_file':old382['path'],
            'expected_historical_ec348_keeper_archive_bundle_sha256':old382['sha256'],
            'historical_ec347_site_provenance_archive_bundle_file':old383['path'],
            'expected_historical_ec347_site_provenance_archive_bundle_sha256':old383['sha256'],
            'historical_ec345_disclosure_archive_bundle_file':original['path'],
            'expected_historical_ec345_disclosure_archive_bundle_sha256':original['sha256'],
            'historical_transparency_archive_bundle_file':old377['path'],
            'expected_historical_transparency_archive_bundle_sha256':old377['sha256'],
            'historical_ec344_signed_visibility_inventory_shas':['ba'*32],
            'historical_ec345_authorized_offer_inventory_shas':['bc'*32],
            'minimum_historical_ec344_signed_visibility_counts':[2],
            'minimum_historical_ec345_signed_challenge_counts':[1],
            'minimum_historical_ec345_signed_offer_counts':[2]}
        return fake_parent,opts

    def _with_outer(self):
        return (patch.object(core,'_inputs',return_value={}),
            patch.object(core.parent,'audit',return_value=self._fake_parent),
            patch.object(core.parent.previous.previous,'_ec348_original',return_value=self.h.ctx),
            patch.object(core.parent.previous.previous.p379,'_old_sender_labels'))

    def test_28_unsigned_inventory_derived_on_verified_legacy_signatures(self):
        self._fake_parent,opts=self._outer();a,b,c,d=self._with_outer()
        with a,b,c,d:report=core.derive_inventory(**opts)
        self.assertEqual(report['exit_code'],2)
        self.assertEqual(report['genuine_old_ec344_receiver_signed_view_original_count'],2)
        self.assertEqual(report['genuine_old_ec345_authorized_challenge_original_count'],1)
        self.assertEqual(report['genuine_old_ec345_receiver_signed_offer_original_count'],2)
        self.assertTrue(report[core.FLAGS[1]])
        self.assertFalse(report['caller_external_inventory_pin_created_or_certified'])
        self.assertFalse(report['sender_origin_path_required_or_read'])

    def test_29_fully_matched_local_provenance_still_exit_two(self):
        self._fake_parent,opts=self._outer();a,b,c,d=self._with_outer()
        with a,b,c,d:
            derived=core.derive_inventory(**opts)
            ep=derived['historical_ec345_disclosure_epoch_reviews'][0]
            opts['historical_ec344_signed_visibility_inventory_shas']=[
                ep['ec344_signed_visibility_inventory_sha256']]
            opts['historical_ec345_authorized_offer_inventory_shas']=[
                ep['ec345_authorized_disclosure_offer_inventory_sha256']]
            opts['expected_retained_historical_ec345_disclosure_inventory_sha256']=derived[
                'receiver_verified_historical_ec345_disclosure_inventory_sha256']
            audited=core.audit(**opts)
        self.assertEqual(audited['exit_code'],2)
        self.assertTrue(audited['local_ec344_signed_views_ec345_authorized_offer_originals_consistent'])
        self.assertTrue(audited[core.FLAGS[7]])
        self.assertTrue(audited[core.FLAGS[8]])
        self.assertNotIn('unsigned_verified_historical_ec345_disclosure_inventory',audited)

    def test_30_external_retention_comparator_mismatch_is_visible(self):
        self._fake_parent,opts=self._outer();a,b,c,d=self._with_outer()
        with a,b,c,d:
            derived=core.derive_inventory(**opts)
            ep=derived['historical_ec345_disclosure_epoch_reviews'][0]
            opts['historical_ec344_signed_visibility_inventory_shas']=[
                ep['ec344_signed_visibility_inventory_sha256']]
            opts['historical_ec345_authorized_offer_inventory_shas']=[
                ep['ec345_authorized_disclosure_offer_inventory_sha256']]
            opts['expected_retained_historical_ec345_disclosure_inventory_sha256']='ca'*32
            audited=core.audit(**opts)
        self.assertTrue(audited[core.FLAGS[1]])
        self.assertEqual(audited['exit_code'],2)

    def test_31_standalone_and_unified_help_readonly(self):
        root=Path(__file__).resolve().parents[2]
        for script in ('ces_cas_historical_disclosure_challenge_archive.py','ces_next.py'):
            command=('audit-historical-ec345-disclosure-archive',)
            p=subprocess.run([sys.executable,'-I','-B',str(root/'scripts'/script),
                              *command,'--help'],text=True,capture_output=True,timeout=30)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('--expected-retained-historical-ec345-disclosure-inventory-sha256',p.stdout)
            self.assertIn('--historical-ec345-authorized-offer-inventory-sha256',p.stdout)
            self.assertNotIn('--private-key',p.stdout)


    def test_32_genuine_signed_unavailable_is_unresolved_not_invalid_authority(self):
        # Sign two actual legacy Ed25519 unavailable claims (not mutated bytes).
        # EC384's historical read-only audit preserves those signed negative
        # assertions without inventing a positive offer or permission denial.
        challenge=(self.src['challenge_files'][0],self.src['challenge_shas'][0])
        replies=[self.h.response(challenge,receiver=i,kind=old345.UNAVAILABLE)
                 for i in range(2)]
        replacement=copy.deepcopy(self.src)
        replacement['response_files']=[row[0] for row in replies]
        replacement['response_shas']=[row[1] for row in replies]
        self.row['ec345_signed_response_originals']=[ref(p,s) for p,s in replies]
        with patch.object(core.parent.previous.previous,'_ec348_original',
                          return_value={'inputs':replacement}):
            verified=core._channel(self.row,self.old383,self.old382,
                                   self.h.read_original,set())
        self.assertTrue(verified['full_original_ec344_ec345_source_replay'])
        self.assertEqual(verified['signed_ec345_registered_receiver_offer_count'],0)
        self.assertFalse(verified['verified_disclosed_target_has_signed_offer'])
        self.assertTrue(verified['signed_offer_claim_conflict_or_missing'])



if __name__=='__main__':unittest.main()
