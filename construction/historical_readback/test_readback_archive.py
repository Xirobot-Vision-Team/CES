#!/usr/bin/env python3
"""EC383 bounded original Ed25519 signer-site tests.

Locally produced authentic legacy signed EC346/347/348 originals are used.
The older inherited EC347->337 fixture contains MOCKED deep ancestor tests;
no remote production originals or independent real physical custody are claimed.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from readback_challenge import readback as old347
from historical_keeper import test_keeper_archive as keeper_fixture
from . import readback_archive as core


def digest(raw):return hashlib.sha256(raw).hexdigest()
def ref(path,hashvalue):return {'path':str(path),'sha256':hashvalue}


class OriginalChallengerReceiverSiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        keeper_fixture.GenuineOldKeeperOriginals.setUpClass()
        # The genuine locally signed EC346/347/348 history is built once.
        # Focused adversarial tests re-open REAL original bytes and signatures,
        # but reuse the already-replayed historic ancestor to avoid 30x deep
        # EC337 fixture replay cost (which is anyway MOCKED in this fixture).
        cls.fixture=keeper_fixture.GenuineOldKeeperOriginals()
        cls.fixture.setUp();cls.fixture.build()
        src=cls.fixture.source
        cls.replayed=(old347._parent({k:src[k] for k in old347.PARENT_KEYS}))
        helper=cls('test_01_actual_old_challenger_receiver_ed25519_authority_and_local_bytes')
        helper.h=cls.fixture;helper.src=src
        helper.roster,helper.item,_,helper.latest=cls.replayed
        cls.base_row=helper.make_row()
        original=canonical.canonical(src)
        sourcepath=cls.fixture.w/'ec383-actual-ec348-replay-input.json'
        sourcepath.write_bytes(original)
        cls.base_oldrow={'tsa_channel_id':'old_signed_channel_alpha',
            'ec348_full_replay_inputs_original':ref(sourcepath,digest(original))}
        cls.base_row['tsa_channel_id']=cls.base_oldrow['tsa_channel_id']

    @classmethod
    def tearDownClass(cls):
        cls.fixture.tearDown()
        keeper_fixture.GenuineOldKeeperOriginals.tearDownClass()

    def setUp(self):
        self.h=type(self).fixture
        self.src=self.h.source
        self.roster,self.item,_,self.latest=type(self).replayed
        self.row=copy.deepcopy(type(self).base_row)
        self.oldrow=copy.deepcopy(type(self).base_oldrow)
        self.h.role_paths={}

    def tearDown(self):self.h.role_paths={}

    def write_key(self,actor,kind):
        raw=bytes.fromhex(actor['public_hex'])
        p=self.h.w/f'ec383-{kind}-{actor["signer_id"]}.pub'
        p.write_bytes(raw)
        return ref(p,digest(raw))

    def make_row(self):
        src=self.src
        response={}
        for path in src['readback_response_files']:
            claim=json.loads(Path(path).read_bytes())['claim']
            response[claim['receiver_id']]=claim
        sites=[]
        for a in self.roster['receivers']:
            rid=a['signer_id']
            if rid not in self.latest:continue
            path,digest_old,obs=self.latest[rid]
            reply=response.get(rid)
            measured=(reply is not None and reply['response_kind']==old347.MEASURED)
            sites.append({'receiver_id':rid,'receiver_public_key_original':self.write_key(a,'receiver'),
                'ec346_latest_signed_observation_original':ref(path,digest_old),
                'claimed_storage_id':obs['claimed_storage_id'],'copy_id':obs['copy_id'],
                'explicit_copy_snapshot_original':ref(reply['copy_snapshot_file'],
                    reply['copy_snapshot_original_raw_sha256']) if measured else None,
                'explicit_copy_ack_set_original':ref(reply['copy_ack_set_file'],
                    reply['copy_ack_set_original_raw_sha256']) if measured else None})
        return {'ec343_authority_roster_original':ref(src['roster_file'],src['expected_roster_sha256']),
            'ec344_receiver_directory_original':ref(src['directory_file'],src['expected_directory_sha256']),
            'ec344_source_checkpoint_original':ref(src['checkpoint_file'],src['expected_checkpoint_sha256']),
            'ec347_challenger_public_key_original':self.write_key(self.roster['change_proposer'],'challenger'),
            'ec347_signed_challenge_originals':[ref(p,s) for p,s in zip(
                src['readback_challenge_files'],src['readback_challenge_shas'],strict=True)],
            'ec347_signed_response_originals':[ref(p,s) for p,s in zip(
                src['readback_response_files'],src['readback_response_shas'],strict=True)],
            'ec346_signed_observation_originals':[ref(p,s) for p,s in zip(
                src['observation_files'],src['observation_shas'],strict=True)],
            'ec345_verified_source_snapshot_original':ref(self.item['snapshot_file'],
                self.item['expected_snapshot_sha256']),
            'ec345_verified_source_ack_set_original':ref(self.item['ack_set_file'],
                self.item['expected_ack_set_sha256']),
            'ec346_receiver_copy_site_originals':sites}

    def run_originals(self,*,genuine_full_replay=False):
        self.h.role_paths={}
        if genuine_full_replay:
            return core._channel(self.row,self.oldrow,self.h.read_original,set())
        with patch.object(core.previous.previous,'_ec348_original',return_value=self.h.ctx), \
             patch.object(core.old347,'_parent',return_value=type(self).replayed):
            return core._channel(self.row,self.oldrow,self.h.read_original,set())

    def denied(self):
        with self.assertRaises(errors.AnchorError):self.run_originals()

    def test_01_actual_old_challenger_receiver_ed25519_authority_and_local_bytes(self):
        result=self.run_originals(genuine_full_replay=True)
        self.assertTrue(result['full_original_signed_ec347_challenger_receiver_replay'])
        self.assertEqual(result['original_ec346_authorized_signed_observation_count'],2)
        self.assertEqual(result['genuine_ec347_registered_receiver_count'],2)
        self.assertEqual(result['actual_original_copy_byte_retest_count'],2)
        self.assertTrue(result['all_presented_signed_copy_bytes_match'])
        self.assertFalse(result['incomplete_explicit_copy_retest'])
        self.assertFalse(result['signed_site_or_readback_adverse'])
        self.assertEqual(len(result['ec347_response_original_shas']),2)

    def test_02_original_ec343_roster_sha_swap_denied(self):
        self.row['ec343_authority_roster_original']['sha256']='aa'*32;self.denied()

    def test_03_real_ec344_receiver_directory_original_sha_swap_denied(self):
        self.row['ec344_receiver_directory_original']['sha256']='aa'*32;self.denied()

    def test_04_real_ec344_checkpoint_sha_swap_denied(self):
        self.row['ec344_source_checkpoint_original']['sha256']='aa'*32;self.denied()

    def test_05_challenger_public_key_sha_unpinned_denied(self):
        self.row['ec347_challenger_public_key_original']['sha256']='aa'*32;self.denied()

    def test_06_challenger_key_substituted_from_receiver_denied(self):
        self.row['ec347_challenger_public_key_original']=copy.deepcopy(
            self.row['ec346_receiver_copy_site_originals'][0]['receiver_public_key_original'])
        self.denied()

    def test_07_challenger_original_public_key_wrong_raw_bytes_denied(self):
        p=self.h.w/'ec383-wrong-proposer.pub';p.write_bytes(b'Z'*32)
        self.row['ec347_challenger_public_key_original']=ref(p,digest(b'Z'*32))
        self.denied()

    def test_08_exact_challenge_round_count_cannot_be_truncated(self):
        self.row['ec347_signed_challenge_originals']=[];self.denied()

    def test_09_challenge_original_sha_substituted_denied(self):
        self.row['ec347_signed_challenge_originals'][0]['sha256']='ba'*32;self.denied()

    def test_10_signed_receiver_response_census_cannot_be_truncated(self):
        self.row['ec347_signed_response_originals'].pop();self.denied()

    def test_11_signed_receiver_response_original_cannot_be_substituted(self):
        self.row['ec347_signed_response_originals'][0]['sha256']='bb'*32;self.denied()

    def test_12_signed_ec346_observation_original_missing_denied(self):
        self.row['ec346_signed_observation_originals'].pop();self.denied()

    def test_13_latest_ec346_signed_site_head_sha_substitution_denied(self):
        self.row['ec346_receiver_copy_site_originals'][0][
            'ec346_latest_signed_observation_original']['sha256']='cc'*32
        self.denied()

    def test_14_signed_storage_label_forgery_denied(self):
        self.row['ec346_receiver_copy_site_originals'][0]['claimed_storage_id']='new_fake_site'
        self.denied()

    def test_15_signed_copy_id_forgery_denied(self):
        self.row['ec346_receiver_copy_site_originals'][0]['copy_id']='new_fake_copy'
        self.denied()

    def test_16_receiver_key_swapped_denied(self):
        s=self.row['ec346_receiver_copy_site_originals']
        s[0]['receiver_public_key_original']=copy.deepcopy(s[1]['receiver_public_key_original'])
        self.denied()

    def test_17_missing_local_explicit_copy_is_properly_unresolved(self):
        site=self.row['ec346_receiver_copy_site_originals'][0]
        site['explicit_copy_snapshot_original']=None
        site['explicit_copy_ack_set_original']=None
        result=self.run_originals()
        self.assertTrue(result['incomplete_explicit_copy_retest'])
        self.assertEqual(result['actual_original_copy_byte_retest_count'],1)
        self.assertTrue(result['all_presented_signed_copy_bytes_match'])

    def test_18_half_presented_copy_pair_denied(self):
        self.row['ec346_receiver_copy_site_originals'][0]['explicit_copy_ack_set_original']=None
        self.denied()

    def test_19_cannot_open_undeclared_extra_path(self):
        site=self.row['ec346_receiver_copy_site_originals'][0]
        site['explicit_copy_snapshot_original']['path']=str(self.h.w/'rogue.json')
        self.denied()

    def test_20_copy_sha_independent_ref_mutation_denied(self):
        site=self.row['ec346_receiver_copy_site_originals'][0]
        site['explicit_copy_snapshot_original']['sha256']='dd'*32
        self.denied()

    def test_21_changed_local_copy_detected_even_with_recomputed_new_sha(self):
        site=self.row['ec346_receiver_copy_site_originals'][0]
        p=Path(site['explicit_copy_snapshot_original']['path'])
        original=p.read_bytes()
        try:
            p.write_bytes(b'actual copy changed since old signed observation')
            site['explicit_copy_snapshot_original']['sha256']=digest(p.read_bytes())
            result=self.run_originals()
            self.assertTrue(result['signed_site_or_readback_adverse'])
            self.assertFalse(result['all_presented_signed_copy_bytes_match'])
        finally:p.write_bytes(original)

    def test_22_source_snapshot_sha_replaced_denied(self):
        self.row['ec345_verified_source_snapshot_original']['sha256']='ee'*32;self.denied()

    def test_23_site_receiver_order_is_authenticated(self):
        self.row['ec346_receiver_copy_site_originals'].reverse();self.denied()

    def test_24_site_duplicate_receiver_identity_denied(self):
        self.row['ec346_receiver_copy_site_originals'][1]['receiver_id']=self.row[
            'ec346_receiver_copy_site_originals'][0]['receiver_id']
        self.denied()

    def test_25_cross_evidence_role_alias_denied(self):
        self.row['ec346_receiver_copy_site_originals'][0][
            'explicit_copy_snapshot_original']=copy.deepcopy(
                 self.row['ec343_authority_roster_original'])
        self.denied()

    def test_26_missing_real_old_ec348_source_does_not_forge_authenticity(self):
        self.oldrow['ec348_full_replay_inputs_original']=None
        self.row={k:(self.oldrow['tsa_channel_id'] if k=='tsa_channel_id' else []
                     if k in ('ec347_signed_challenge_originals','ec347_signed_response_originals',
                        'ec346_signed_observation_originals','ec346_receiver_copy_site_originals') else None)
                  for k in core.CHANNEL_FIELDS}
        result=self.run_originals()
        self.assertFalse(result['full_original_signed_ec347_challenger_receiver_replay'])
        self.assertEqual(result['original_ec346_authorized_signed_observation_count'],0)

    def test_27_missing_source_must_not_insert_self_claimed_key(self):
        self.oldrow['ec348_full_replay_inputs_original']=None
        self.row['ec343_authority_roster_original']=None
        self.denied()

    def test_28_nonce_and_signed_claim_duplicate_key_rejected_as_old_original(self):
        p=Path(self.row['ec347_signed_response_originals'][0]['path'])
        raw=p.read_bytes()
        try:
            p.write_bytes(raw[:-1]+b',"claim":{}}')
            self.row['ec347_signed_response_originals'][0]['sha256']=digest(p.read_bytes())
            self.denied()
        finally:p.write_bytes(raw)

    def test_29_signed_ec346_observation_body_mutation_denied(self):
        p=Path(self.row['ec346_signed_observation_originals'][0]['path'])
        original=p.read_bytes()
        try:
            p.write_bytes(original+b' ')
            self.denied()
        finally:p.write_bytes(original)

    def test_30_original_source_ref_wrong_path_with_same_sha_denied(self):
        self.oldrow['ec348_full_replay_inputs_original']['path']=str(self.h.w/'decoy.json')
        with self.assertRaises((errors.AnchorError,OSError)):
            core.previous.previous._ec348_original(
                self.oldrow['ec348_full_replay_inputs_original'],
                self.h.read_original,set())


    def synthetic_epoch_receiver(self):
        """Synthetic *outer* parent for testing the new engine, not proof of
        real EC382->EC369 production historical parent or a provider site.
        The actual old signed EC346/347 original byte verification stays live.
        """
        oldparent={'schema':core.previous.RESULT_SCHEMA,'exit_code':2,
          'sender_origin_path_required_or_read':False,
          'ec348_through_ec337_full_independent_historical_parent_acceptance_performed':False,
          'historical_ec348_keeper_epoch_reviews':[{'epoch_index':0}],
          'local_recovered_keeper_readback_original_binding_consistent':True}
        parent_sha=digest(canonical.canonical(oldparent))
        def archive(name,obj):
            raw=canonical.canonical(obj);p=self.h.w/name;p.write_bytes(raw)
            return ref(p,digest(raw))
        real_old382=archive('ec383-synthetic-parent-ec382.json',{
          'schema':core.previous.BUNDLE_SCHEMA,
          'parent_ec381_canonical_result_sha256':'56'*32,
          'ec381_historical_channel_archive_original_sha256':'57'*32,
          'claimed_directory_lineage_id':'Lineage383',
          'epochs':[{'epoch_index':0,'channels':[self.oldrow]}]})
        new=archive('ec383-synthetic-new-bundle.json',{
          'schema':core.BUNDLE_SCHEMA,
          'parent_ec382_canonical_result_sha256':parent_sha,
          'ec382_historical_keeper_archive_original_sha256':real_old382['sha256'],
          'claimed_directory_lineage_id':'Lineage383',
          'epochs':[{'epoch_index':0,'channels':[self.row]}]})
        old353=archive('ec383-synthetic-ec353-labels.json',{'schema':'stub'})
        old377=archive('ec383-synthetic-ec377-original.json',{
           **{k:'placeholder' for k in core.previous.previous.p379.p377.BUNDLE_FIELDS
              if k not in ('schema','epochs')},
           'schema':core.previous.previous.p379.p377.BUNDLE_SCHEMA,
           'epochs':[{'ec353_publication_bundle_original':old353}]})
        opts={'historical_directory_root_shas':['55'*32],
           'claimed_historical_directory_lineage_id':'Lineage383',
           'historical_ec348_keeper_archive_bundle_file':real_old382['path'],
           'expected_historical_ec348_keeper_archive_bundle_sha256':real_old382['sha256'],
           'historical_ec347_site_provenance_archive_bundle_file':new['path'],
           'expected_historical_ec347_site_provenance_archive_bundle_sha256':new['sha256'],
           'historical_transparency_archive_bundle_file':old377['path'],
           'expected_historical_transparency_archive_bundle_sha256':old377['sha256'],
           'historical_ec347_actor_authorization_inventory_shas':['fa'*32],
           'historical_ec346_copy_site_inventory_shas':['fb'*32],
           'minimum_historical_ec347_authorized_receiver_counts':[2],
           'minimum_historical_ec346_signed_observation_counts':[2],
           'minimum_historical_ec346_byte_retested_copy_counts':[2]}
        return oldparent,opts

    def test_31_engine_unsigned_derive_retained_root_and_real_old_signatures(self):
        oldparent,opts=self.synthetic_epoch_receiver()
        with patch.object(core,'_inputs',return_value={}), \
             patch.object(core.previous,'audit',return_value=oldparent), \
             patch.object(core.previous.previous,'_ec348_original',return_value=self.h.ctx), \
             patch.object(core.old347,'_parent',return_value=type(self).replayed), \
             patch.object(core.previous.previous.p379,'_old_sender_labels'):
            report=core.derive_inventory(**opts)
        self.assertEqual(report['exit_code'],2)
        self.assertEqual(report['genuine_old_ec347_authorized_receiver_count'],2)
        self.assertEqual(report['genuine_old_ec346_signed_observation_original_count'],2)
        self.assertEqual(report['genuine_old_ec346_current_copy_local_retest_count'],2)
        self.assertTrue(report['outside_retained_ec347_authority_or_ec346_site_inventory_floor_disagrees'])
        self.assertFalse(report['local_ec347_challenger_receiver_ec346_signed_source_originals_consistent'])
        self.assertFalse(report['caller_external_inventory_pin_created_or_certified'])
        self.assertTrue(report['full_unmocked_old_ec346_through_ec337_external_source_unavailable'])
        self.assertTrue(report['offsite_physical_identity_independent_custody_and_calibrated_utc_unproven'])
        self.assertTrue(report['sender_origin_path_required_or_read'] is False)

    def test_32_genuine_signed_site_consistent_but_all_lawful_exit_two(self):
        oldparent,opts=self.synthetic_epoch_receiver()
        context=(patch.object(core,'_inputs',return_value={}),
                 patch.object(core.previous,'audit',return_value=oldparent),
                 patch.object(core.previous.previous,'_ec348_original',return_value=self.h.ctx),
                 patch.object(core.old347,'_parent',return_value=type(self).replayed),
                 patch.object(core.previous.previous.p379,'_old_sender_labels'))
        with context[0],context[1],context[2],context[3],context[4]:
            derived=core.derive_inventory(**opts)
            epoch=derived['historical_ec347_site_epoch_reviews'][0]
            opts['historical_ec347_actor_authorization_inventory_shas']=[
                epoch['ec347_challenger_actor_original_inventory_sha256']]
            opts['historical_ec346_copy_site_inventory_shas']=[
                epoch['ec346_signed_site_and_retested_byte_inventory_sha256']]
            opts['expected_retained_historical_ec347_site_provenance_inventory_sha256']=                derived['receiver_verified_historical_ec347_site_inventory_sha256']
            audited=core.audit(**opts)
        self.assertTrue(audited['local_ec347_challenger_receiver_ec346_signed_source_originals_consistent'])
        self.assertEqual(audited['exit_code'],2)
        self.assertEqual(audited['status'],
            'ec383_old_ec346_through_ec337_independent_external_history_incomplete_unresolved')
        self.assertEqual(audited['schema'],core.RESULT_SCHEMA)
        self.assertNotIn('unsigned_verified_historical_ec347_site_provenance_inventory',audited)

    def test_33_standalone_and_unified_help_are_fixed_read_only_commands(self):
        import subprocess
        import sys
        root=Path(__file__).resolve().parents[2]
        for script,cmd in (
             ('ces_cas_historical_site_provenance.py',
                  'audit-historical-ec347-site-provenance-archive'),
             ('ces_next.py','audit-historical-ec347-site-provenance-archive')):
            cp=subprocess.run([sys.executable,'-I','-B',str(root/'scripts'/script),
                cmd,'--help'],text=True,capture_output=True,timeout=25)
            self.assertEqual(cp.returncode,0,cp.stderr)
            self.assertIn('--expected-retained-historical-ec347-site-provenance-inventory-sha256',cp.stdout)
            self.assertIn('--historical-ec346-copy-site-inventory-sha256',cp.stdout)
            self.assertNotIn('--private-key',cp.stdout)


if __name__=='__main__':unittest.main()
