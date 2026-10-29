#!/usr/bin/env python3
"""EC386 genuine locally signed old EC341/EC342 conflict originals.

Outer receiver parent tests explicitly MOCK EC385->EC369; inherited old
EC317/318 fixtures also MOCK prior ancestry. No global/offsite proof claimed.
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
from historical_change import test_change_archive as fixture
from root_lineage import lineage as old341
from . import root_archive as core


def ref(path):
    raw=Path(path).read_bytes()
    return {'path':str(path),'sha256':core.sha(raw)}


class AuthenticOldRootConflictTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.OriginalSignedChangeTests.setUpClass()
        cls.f=fixture.OriginalSignedChangeTests
        cls.h=cls.f.h
        cls.parent_row=copy.deepcopy(cls.f.base_row)
        cls.legacy=cls.f.legacy.p
        cls.gov=json.loads(Path(cls.legacy.gov_file).read_bytes())
        cls.manifest=json.loads(Path(cls.legacy.manifest_file).read_bytes())
        cls.paths,cls.pins=old341._check_manifest(cls.manifest)
        cls.root=cls.h.w
        keys={}
        legacy_root=json.loads(Path(cls.manifest['context']['authority_roster_file']).read_bytes())
        for issuer in legacy_root['issuers']:
            keys[issuer['issuer_public_hex']]=True
        for hop in [*cls.manifest['hops'],*(f['hop'] for f in cls.manifest['forks'])]:
            child=json.loads(Path(hop['successor_roster_file']).read_bytes())
            witness=json.loads(Path(hop['observer_roster_file']).read_bytes())
            for issuer in child['issuers']:keys[issuer['issuer_public_hex']]=True
            keys[witness['observer_public_hex']]=True
        cls.copies=[]
        for index,pub in enumerate(sorted(keys)):
            keyfile=cls.root/f'ec386-supplied-public-key-copy-{index}.raw'
            keyfile.write_bytes(bytes.fromhex(pub))
            cls.copies.append({'public_hex':pub,'public_key_original':ref(keyfile)})
        cls.base_row={
          'tsa_channel_id':cls.parent_row['tsa_channel_id'],
          'ec342_governance_roster_original':copy.deepcopy(
              cls.parent_row['ec342_governance_roster_original']),
          'ec342_signed_hold_request_original':copy.deepcopy(
              cls.parent_row['ec342_hold_request_original']),
          'ec341_lineage_manifest_original':ref(cls.legacy.manifest_file),
          'ec341_manifest_dependency_originals':[ref(p) for p in cls.paths],
          'ec341_signer_public_key_copies':cls.copies}

    @classmethod
    def tearDownClass(cls):
        fixture.OriginalSignedChangeTests.tearDownClass()

    def setUp(self):
        self.row=copy.deepcopy(self.base_row)
        self.parent=copy.deepcopy(self.parent_row)
        self.h.role_paths={}

    def tearDown(self):self.h.role_paths={}

    def run_channel(self):
        self.h.role_paths={}
        return core._channel(self.row,self.parent,self.h.read_original)

    def denied(self):
        with self.assertRaises(errors.AnchorError):self.run_channel()

    def test_01_true_old_signed_root_siblings_link_approved_hold(self):
        r=self.run_channel()
        self.assertTrue(r['full_original_ec341_signed_root_replay'])
        self.assertEqual(r['ec341_original_signed_edge_count'],32)
        self.assertEqual(r['ec341_original_signed_observation_count'],4)
        self.assertEqual(r['ec341_observed_signed_sibling_count'],1)
        self.assertEqual(r['ec341_competing_root_sha256'],
                         self.gov['alternative_successor_original_raw_sha256'])
        self.assertEqual(r['ec342_hold_sha256'],self.parent['ec342_hold_request_original']['sha256'])

    def test_02_no_selected_root_can_be_substituted(self):
        self.row['ec341_lineage_manifest_original']['sha256']='ab'*32
        self.denied()

    def test_03_governance_parent_original_sha_cannot_be_replaced(self):
        self.row['ec342_governance_roster_original']['sha256']='ab'*32
        self.denied()

    def test_04_hold_parent_original_sha_cannot_be_replaced(self):
        self.row['ec342_signed_hold_request_original']['sha256']='ac'*32
        self.denied()

    def test_05_dependency_census_cannot_omit_one_signed_edge(self):
        self.row['ec341_manifest_dependency_originals'].pop()
        self.denied()

    def test_06_dependency_reference_cannot_change_signed_observation_sha(self):
        path=self.manifest['forks'][0]['hop']['root_observation_file']
        idx=self.paths.index(path)
        self.row['ec341_manifest_dependency_originals'][idx]['sha256']='cd'*32
        self.denied()

    def test_07_dependency_cannot_reorder_issuer_root_or_signatures(self):
        refs=self.row['ec341_manifest_dependency_originals']
        refs[-2],refs[-1]=refs[-1],refs[-2]
        self.denied()

    def test_08_raw_public_key_copy_must_match_original_roster(self):
        self.row['ec341_signer_public_key_copies'][0]['public_hex']='dd'*32
        self.denied()

    def test_09_all_public_key_copies_required(self):
        self.row['ec341_signer_public_key_copies'].pop()
        self.denied()

    def test_10_key_copy_sha_does_not_auto_authenticate_identity(self):
        r=self.run_channel()
        self.assertEqual(len(r['ec341_verifiable_public_key_copy_sha256s']),
                         len(self.copies))
        self.assertNotIn('institution_identity_verified',r)

    def test_11_corrupted_old_signed_observation_rejected_after_original_pin(self):
        # The truly signed legacy edge's original SHA is fixed inside the
        # old EC341 manifest, independently of the EC386 wrapper.
        path=Path(self.manifest['forks'][0]['hop']['edge_signatures'][0]['file'])
        before=path.read_bytes()
        try:
            path.write_bytes(before+b' ')
            self.denied()
        finally:
            path.write_bytes(before)

    def test_12_no_parent_source_remains_missing_not_freshly_signed(self):
        self.parent['ec342_governance_roster_original']=None
        self.parent['ec342_hold_request_original']=None
        self.row={k:(self.parent['tsa_channel_id'] if k=='tsa_channel_id' else
            [] if k in ('ec341_manifest_dependency_originals',
                        'ec341_signer_public_key_copies') else None)
            for k in core.CHANNEL_FIELDS}
        r=self.run_channel()
        self.assertFalse(r['full_original_ec341_signed_root_replay'])
        self.assertEqual(r['ec341_original_signed_edge_count'],0)

    def test_13_missing_source_rejects_injected_signed_lineage(self):
        self.parent['ec342_governance_roster_original']=None
        self.parent['ec342_hold_request_original']=None
        self.denied()

    def test_14_past_root_epoch_cannot_be_used_as_new_current(self):
        # Preserve parent EC342 SHA; forged manifest/pinned current root cannot
        # override its exact signed root and epoch.
        self.row['ec341_lineage_manifest_original']=copy.deepcopy(
          self.row['ec341_manifest_dependency_originals'][0])
        self.denied()

    def _archive(self,name,doc):
        path=self.root/name
        path.write_bytes(canonical.canonical(doc))
        return ref(path)

    def _outer(self):
        fake_parent={'schema':core.parent.RESULT_SCHEMA,'exit_code':2,
           'sender_origin_path_required_or_read':False,
           'ec343_through_ec337_full_independent_original_historical_acceptance_performed':False,
           'historical_ec343_change_epoch_reviews':[{'epoch_index':0}],
           'local_ec342_approved_hold_ec343_signed_change_originals_consistent':True}
        psha=core.sha(canonical.canonical(fake_parent))
        old=self._archive('ec386-old-ec385-archive.json',{
            'schema':core.parent.BUNDLE_SCHEMA,'parent_ec384_canonical_result_sha256':'ad'*32,
            'ec384_historical_offer_archive_original_sha256':'bc'*32,
            'claimed_directory_lineage_id':'Lineage386',
            'epochs':[{'epoch_index':0,'channels':[self.parent]}]})
        new=self._archive('ec386-new-root-archive.json',{
            'schema':core.BUNDLE_SCHEMA,'parent_ec385_canonical_result_sha256':psha,
            'ec385_historical_change_archive_original_sha256':old['sha256'],
            'claimed_directory_lineage_id':'Lineage386',
            'epochs':[{'epoch_index':0,'channels':[self.row]}]})
        sender=self._archive('ec386-sender-label-index.json',{'schema':'dummy'})
        old377=self._archive('ec386-old-ec377-index.json',{
            'schema':core.p377.BUNDLE_SCHEMA,
            'epochs':[{'ec353_publication_bundle_original':sender}],
            **{k:'be'*32 for k in core.p377.BUNDLE_FIELDS if k not in ('schema','epochs')}})
        opts={'historical_directory_root_shas':['de'*32],
            'claimed_historical_directory_lineage_id':'Lineage386',
            'historical_ec343_change_approval_archive_bundle_file':old['path'],
            'expected_historical_ec343_change_approval_archive_bundle_sha256':old['sha256'],
            'historical_ec341_signed_root_conflict_archive_bundle_file':new['path'],
            'expected_historical_ec341_signed_root_conflict_archive_bundle_sha256':new['sha256'],
            'historical_transparency_archive_bundle_file':old377['path'],
            'expected_historical_transparency_archive_bundle_sha256':old377['sha256'],
            'historical_ec341_signed_root_inventory_shas':['ad'*32],
            'historical_ec342_root_conflict_binding_inventory_shas':['ae'*32],
            'minimum_historical_ec341_signed_edge_counts':[32],
            'minimum_historical_ec341_signed_observation_counts':[4],
            'minimum_historical_ec341_verified_sibling_counts':[1]}
        return fake_parent,opts

    def _outer_patches(self,parent_report):
        return (patch.object(core,'_inputs',return_value={}),
                patch.object(core.parent,'audit',return_value=parent_report),
                patch.object(core.p379,'_old_sender_labels'))

    def test_15_unsigned_inventory_derived_from_real_signatures_under_mocked_parent(self):
        report,opts=self._outer();a,b,c=self._outer_patches(report)
        with a,b,c:actual=core.derive_inventory(**opts)
        self.assertEqual(actual['exit_code'],2)
        self.assertEqual(actual['genuine_old_ec341_signed_edge_count'],32)
        self.assertEqual(actual['genuine_old_ec341_signed_observation_count'],4)
        self.assertEqual(actual['genuine_old_ec341_visible_signed_sibling_count'],1)
        self.assertTrue(actual[core.FLAGS[1]])
        self.assertTrue(actual[core.FLAGS[5]])
        self.assertFalse(actual['caller_retained_inventory_sha_independently_certified'])

    def test_16_exact_outside_floors_do_not_grant_success_status(self):
        report,opts=self._outer();a,b,c=self._outer_patches(report)
        with a,b,c:
            derived=core.derive_inventory(**opts)
            ep=derived['historical_ec341_root_conflict_epoch_reviews'][0]
            opts['historical_ec341_signed_root_inventory_shas']=[
                ep['ec341_signed_root_inventory_sha256']]
            opts['historical_ec342_root_conflict_binding_inventory_shas']=[
                ep['ec342_signed_hold_conflict_binding_inventory_sha256']]
            opts['expected_retained_historical_ec341_signed_root_conflict_inventory_sha256']=(
                derived['receiver_verified_old_ec341_signed_root_inventory_sha256'])
            audited=core.audit(**opts)
        self.assertEqual(audited['exit_code'],2)
        self.assertTrue(audited['local_old_ec341_signed_root_conflict_ec342_hold_originals_consistent'])
        self.assertTrue(audited[core.FLAGS[5]])
        self.assertTrue(audited[core.FLAGS[7]] and audited[core.FLAGS[8]])
        self.assertNotIn('unsigned_verified_old_ec341_root_conflict_inventory',audited)

    def test_17_audit_retained_sha_mismatch_adverse(self):
        report,opts=self._outer();a,b,c=self._outer_patches(report)
        with a,b,c:
            deriv=core.derive_inventory(**opts)
            e=deriv['historical_ec341_root_conflict_epoch_reviews'][0]
            opts['historical_ec341_signed_root_inventory_shas']=[e['ec341_signed_root_inventory_sha256']]
            opts['historical_ec342_root_conflict_binding_inventory_shas']=[e['ec342_signed_hold_conflict_binding_inventory_sha256']]
            opts['expected_retained_historical_ec341_signed_root_conflict_inventory_sha256']='cb'*32
            audited=core.audit(**opts)
        self.assertTrue(audited[core.FLAGS[1]])
        self.assertEqual(audited['exit_code'],2)

    def test_18_fixed_help_contains_no_private_signing_interface(self):
        root=Path(__file__).resolve().parents[2]
        for script in ('ces_cas_historical_root_conflict_archive.py','ces_next.py'):
            p=subprocess.run([sys.executable,'-I','-B',str(root/'scripts'/script),
               'audit-historical-ec341-root-conflict-archive','--help'],
               capture_output=True,text=True,timeout=30)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('--expected-retained-historical-ec341-signed-root-conflict-inventory-sha256',p.stdout)
            self.assertNotIn('--private-key',p.stdout)

if __name__=='__main__':unittest.main()
