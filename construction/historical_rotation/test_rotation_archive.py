#!/usr/bin/env python3
"""EC387 old authentic EC340 signed first hop and EC339 actor original tests.

Genuine locally issued Ed25519 evidence. The deeply inherited old EC317/318
source fixture is MOCKED; only outer EC386->EC369 parent envelope is MOCKED
in explicitly named inventory tests. Never call either external acceptance.
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
from historical_root import test_root_archive as ancestor
from issuer_root_rotation import rotation as old340
from . import rotation_archive as core


def ref(path):
    p=Path(path)
    return {'path':str(p),'sha256':core.sha(p.read_bytes())}


class AuthenticOldEpochRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ancestor.AuthenticOldRootConflictTests.setUpClass()
        cls.f=ancestor.AuthenticOldRootConflictTests
        cls.h=cls.f.h
        cls.root=cls.f.root
        cls.source=copy.deepcopy(cls.f.base_row)
        cls.manifest=copy.deepcopy(cls.f.manifest)
        cls.context=cls.manifest['context']
        cls.history=cls.manifest['history']
        cls.first=cls.manifest['hops'][0]
        cls.policy=json.loads(Path(cls.context['policy_file']).read_bytes())
        cls.legacy=json.loads(Path(cls.context['authority_roster_file']).read_bytes())
        cls.successor=json.loads(Path(cls.first['successor_roster_file']).read_bytes())
        cls.observer=json.loads(Path(cls.first['observer_roster_file']).read_bytes())
        prior_sources={k['public_hex']:k['public_key_original'] for k in cls.source['ec341_signer_public_key_copies']}
        cls.key_sources=[]
        for kind,role in core.KEY_ORDER:
            idx=old340.ROLES.index(role) if role in old340.ROLES else None
            pub=(cls.legacy['issuers'][idx]['issuer_public_hex'] if kind=='old_issuer' else
                 cls.successor['issuers'][idx]['issuer_public_hex'] if kind=='new_issuer' else
                 cls.observer['observer_public_hex'] if kind=='observer' else
                 cls.policy['actors'][idx]['public_hex'])
            if kind!='historical_actor':
                original=prior_sources[pub]
            else:
                fn=cls.root/('ec387-supplied-actor-'+role+'.raw')
                fn.write_bytes(bytes.fromhex(pub))
                original=ref(fn)
            cls.key_sources.append({'kind':kind,'role':role,'public_hex':pub,
                                    'public_key_original':original})
        cls.base_row={
          'tsa_channel_id':cls.source['tsa_channel_id'],
          'ec340_legacy_policy_original':ref(cls.context['policy_file']),
          'ec339_predecessor_authority_roster_original':ref(cls.context['authority_roster_file']),
          'ec340_epoch2_successor_roster_original':ref(cls.first['successor_roster_file']),
          'ec340_observer_roster_original':ref(cls.first['observer_roster_file']),
          'ec340_signed_retirement_observation_original':ref(cls.first['root_observation_file']),
          'ec340_signed_role_edges':[
              {'side':e['side'],'role':e['role'],'edge_original':ref(e['file'])}
              for e in cls.first['edge_signatures']],
          'ec339_original_signed_role_history':[
              {'role':role,**{kind+'_original':ref(cls.history[role+'_'+kind+'_file'])
                  for kind in ('receipt','grant','status')}}
              for role in old340.ROLES],
          'ec340_original_public_key_sources':cls.key_sources}

    @classmethod
    def tearDownClass(cls):
        ancestor.AuthenticOldRootConflictTests.tearDownClass()

    def setUp(self):
        self.row=copy.deepcopy(self.base_row)
        self.authentic=copy.deepcopy(self.source)
        self.h.role_paths={}

    def tearDown(self):self.h.role_paths={}

    def call(self):
        self.h.role_paths={}
        return core._channel(self.row,self.authentic,self.h.read_original)

    def denied(self):
        with self.assertRaises(errors.AnchorError):self.call()

    def test_01_real_eight_old_new_ed25519_edges_signed_observer_and_legacy_roles(self):
        r=self.call()
        self.assertTrue(r['full_original_ec340_signed_rotation_replay'])
        self.assertEqual(r['ec340_signed_role_edge_count'],8)
        self.assertEqual(r['ec340_signed_observation_count'],1)
        self.assertEqual(r['ec339_signed_grant_status_count'],8)
        self.assertEqual(len(r['ec339_receipt_grant_status_sha256s']),4)
        self.assertEqual(len(r['ec340_original_public_key_copy_sha256s']),13)
        self.assertEqual(r['ec340_epoch2_successor_sha256'],self.first['expected_successor_roster_sha256'])

    def test_02_authentic_manifest_not_replaced_by_an_epoch2_source(self):
        self.authentic['ec341_lineage_manifest_original']=ref(self.first['successor_roster_file'])
        self.denied()

    def test_03_old_epoch1_policy_original_pin_cannot_be_replaced(self):
        self.row['ec340_legacy_policy_original']['sha256']='ac'*32
        self.denied()

    def test_04_old_epoch1_predecessor_original_pin_cannot_be_replaced(self):
        self.row['ec339_predecessor_authority_roster_original']['sha256']='ad'*32
        self.denied()

    def test_05_epoch2_successor_is_manifest_first_not_a_fork(self):
        self.row['ec340_epoch2_successor_roster_original']=ref(
            self.manifest['forks'][0]['hop']['successor_roster_file'])
        self.denied()

    def test_06_exact_old_new_role_order_enforced(self):
        edges=self.row['ec340_signed_role_edges']
        edges[0],edges[1]=edges[1],edges[0]
        self.denied()

    def test_07_signature_original_digest_not_swappable(self):
        self.row['ec340_signed_role_edges'][2]['edge_original']['sha256']='ba'*32
        self.denied()

    def test_08_real_signed_observer_original_required(self):
        self.row['ec340_signed_retirement_observation_original']=None
        self.denied()

    def test_09_exact_four_old_actor_receipts_grants_status_originals(self):
        self.row['ec339_original_signed_role_history'].pop()
        self.denied()

    def test_10_historical_grant_and_status_cannot_be_cross_role(self):
        a=self.row['ec339_original_signed_role_history']
        a[0]['grant_original'],a[1]['grant_original']=a[1]['grant_original'],a[0]['grant_original']
        self.denied()

    def test_11_new_epoch_root_copy_must_be_parent_ec386_original(self):
        p=self.row['ec340_original_public_key_sources'][4]
        raw=bytes.fromhex(p['public_hex'])
        other=self.root/'ec387-nonauthoritative-reissued-raw-copy.bin'
        other.write_bytes(raw)
        p['public_key_original']=ref(other)
        self.denied()

    def test_12_historical_actor_public_key_raw_bytes_matched(self):
        self.row['ec340_original_public_key_sources'][-1]['public_hex']='aa'*32
        self.denied()

    def test_13_raw_actor_source_content_tamper_refused(self):
        entry=self.row['ec340_original_public_key_sources'][-1]
        path=Path(entry['public_key_original']['path']);before=path.read_bytes()
        try:
            path.write_bytes(b'\x00'*32)
            self.denied()
        finally:
            path.write_bytes(before)

    def test_14_signed_historical_ec339_grant_original_tamper_refused(self):
        path=Path(self.history['sender_grant_file']);before=path.read_bytes()
        try:
            path.write_bytes(before+b' ')
            self.denied()
        finally:
            path.write_bytes(before)

    def test_15_approved_ec342_hold_parent_conflict_is_required(self):
        original=core.old342._governance
        with patch.object(core.old342,'_governance',side_effect=lambda *a: {
                    **original(*a),'parent_root_original_raw_sha256':'ab'*32}):
            self.denied()

    def test_16_absent_parent_source_is_unresolved_no_fresh_root_injection(self):
        self.authentic={k:(self.source['tsa_channel_id'] if k=='tsa_channel_id' else
                 [] if k in ('ec341_manifest_dependency_originals','ec341_signer_public_key_copies')
                 else None) for k in core.parent.CHANNEL_FIELDS}
        self.row={k:(self.source['tsa_channel_id'] if k=='tsa_channel_id' else
                   [] if k in ('ec340_signed_role_edges','ec339_original_signed_role_history',
                               'ec340_original_public_key_sources') else None)
                  for k in core.CHANNEL_FIELDS}
        r=self.call()
        self.assertFalse(r['full_original_ec340_signed_rotation_replay'])
        self.assertEqual(r['ec340_signed_role_edge_count'],0)

    def test_17_missing_parent_must_not_be_renewed_by_synthetic_keys(self):
        self.authentic['ec341_lineage_manifest_original']=None
        self.denied()

    def _archive(self,name,doc):
        path=self.root/name
        path.write_bytes(canonical.canonical(doc))
        return ref(path)

    def _outer(self):
        mock_parent={'schema':core.parent.RESULT_SCHEMA,'exit_code':2,
            'sender_origin_path_required_or_read':False,
            'ec341_through_ec337_full_independent_original_historical_acceptance_performed':False,
            'historical_ec341_root_conflict_epoch_reviews':[{'epoch_index':0}],
            'local_old_ec341_signed_root_conflict_ec342_hold_originals_consistent':True,
            'status':core.parent.OUTCOMES[5]+'_unresolved',
            **{k:(i in (5,7,8)) for i,k in enumerate(core.parent.FLAGS)},
            **{k:False for k in core.parent.NEGATIVES}}
        psha=core.sha(canonical.canonical(mock_parent))
        earlier=self._archive('ec387-old-ec386-archive.json',{
            'schema':core.parent.BUNDLE_SCHEMA,
            'parent_ec385_canonical_result_sha256':'ab'*32,
            'ec385_historical_change_archive_original_sha256':'bc'*32,
            'claimed_directory_lineage_id':'Lineage387',
            'epochs':[{'epoch_index':0,'channels':[self.authentic]}]})
        current=self._archive('ec387-new-rotation-archive.json',{
            'schema':core.BUNDLE_SCHEMA,
            'parent_ec386_canonical_result_sha256':psha,
            'ec386_historical_root_archive_original_sha256':earlier['sha256'],
            'claimed_directory_lineage_id':'Lineage387',
            'epochs':[{'epoch_index':0,'channels':[self.row]}]})
        sender=self._archive('ec387-sender-label.json',{'schema':'dummy'})
        index=self._archive('ec387-old-ec377-sender-index.json',{
            'schema':core.p377.BUNDLE_SCHEMA,
            'epochs':[{'ec353_publication_bundle_original':sender}],
            **{k:'ab'*32 for k in core.p377.BUNDLE_FIELDS if k not in ('schema','epochs')}})
        opts={'historical_directory_root_shas':['cd'*32],
            'claimed_historical_directory_lineage_id':'Lineage387',
            'historical_ec341_signed_root_conflict_archive_bundle_file':earlier['path'],
            'expected_historical_ec341_signed_root_conflict_archive_bundle_sha256':earlier['sha256'],
            'historical_ec340_signed_rotation_archive_bundle_file':current['path'],
            'expected_historical_ec340_signed_rotation_archive_bundle_sha256':current['sha256'],
            'historical_transparency_archive_bundle_file':index['path'],
            'expected_historical_transparency_archive_bundle_sha256':index['sha256'],
            'historical_ec340_role_rotation_inventory_shas':['ba'*32],
            'historical_ec339_actor_grant_inventory_shas':['ca'*32],
            'minimum_historical_ec340_signed_edge_counts':[8],
            'minimum_historical_ec340_signed_observation_counts':[1],
            'minimum_historical_ec339_signed_grant_status_counts':[8]}
        return mock_parent,opts

    def _patched(self,parent):
        return (patch.object(core,'_inputs',return_value={}),
                patch.object(core.parent,'audit',return_value=parent),
                patch.object(core.p379,'_old_sender_labels'))

    def test_18_derived_inventory_from_real_old_signatures_mocked_outer_parent(self):
        mock,opts=self._outer();a,b,c=self._patched(mock)
        with a,b,c:res=core.derive_inventory(**opts)
        self.assertEqual(res['exit_code'],2)
        self.assertEqual(res['genuine_old_ec340_signed_edge_count'],8)
        self.assertEqual(res['genuine_old_ec340_signed_observation_count'],1)
        self.assertEqual(res['genuine_old_ec339_signed_grant_status_count'],8)
        self.assertTrue(res[core.FLAGS[1]])
        self.assertFalse(res['caller_retained_inventory_sha_independently_certified'])

    def test_19_correct_floor_never_claims_actual_external_acceptance(self):
        mock,opts=self._outer();a,b,c=self._patched(mock)
        with a,b,c:
            derived=core.derive_inventory(**opts)
            ep=derived['historical_ec340_rotation_epoch_reviews'][0]
            opts['historical_ec340_role_rotation_inventory_shas']=[ep['old_ec340_rotation_inventory_sha256']]
            opts['historical_ec339_actor_grant_inventory_shas']=[ep['old_ec339_actor_history_inventory_sha256']]
            opts['expected_retained_historical_ec340_signed_rotation_inventory_sha256']=(
                derived['receiver_verified_old_ec340_signed_rotation_inventory_sha256'])
            audited=core.audit(**opts)
        self.assertEqual(audited['exit_code'],2)
        self.assertTrue(audited['local_old_ec340_signed_rotation_ec341_conflict_parent_originals_consistent'])
        self.assertTrue(audited[core.FLAGS[7]] and audited[core.FLAGS[8]])
        self.assertNotIn('unsigned_verified_old_ec340_rotation_inventory',audited)

    def test_20_wrong_externally_retained_inventory_sha_adverse_unresolved(self):
        mock,opts=self._outer();a,b,c=self._patched(mock)
        with a,b,c:
            derived=core.derive_inventory(**opts)
            ep=derived['historical_ec340_rotation_epoch_reviews'][0]
            opts['historical_ec340_role_rotation_inventory_shas']=[ep['old_ec340_rotation_inventory_sha256']]
            opts['historical_ec339_actor_grant_inventory_shas']=[ep['old_ec339_actor_history_inventory_sha256']]
            opts['expected_retained_historical_ec340_signed_rotation_inventory_sha256']='dd'*32
            audited=core.audit(**opts)
        self.assertEqual(audited['exit_code'],2)
        self.assertTrue(audited[core.FLAGS[1]])

    def test_21_no_private_signing_or_write_subcommand(self):
        root=Path(__file__).resolve().parents[2]
        for name,cmd in (('ces_cas_historical_rotation_archive.py',
                          'audit-historical-ec340-rotation-archive'),
                         ('ces_next.py','audit-historical-ec340-rotation-archive')):
            p=subprocess.run([sys.executable,'-I','-B',str(root/'scripts'/name),
                cmd,'--help'],capture_output=True,text=True,timeout=30)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('--expected-retained-historical-ec340-signed-rotation-inventory-sha256',p.stdout)
            self.assertNotIn('--private-key',p.stdout)

if __name__=='__main__':unittest.main()
