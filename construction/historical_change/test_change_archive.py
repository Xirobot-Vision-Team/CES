#!/usr/bin/env python3
"""Real legacy-format Ed25519 EC342/343 originals; inherited EC347->337 mock disclosed."""
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
from hold_receipts import test_timeline as timeline_fixture
from historical_offer import test_offer_archive as offer_fixture
from . import change_archive as core


def ref(path,sha):return {'path':str(path),'sha256':sha}


class OriginalSignedChangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        offer_fixture.OriginalDisclosureOfferTests.setUpClass()
        cls.outer=offer_fixture.OriginalDisclosureOfferTests
        cls.h=cls.outer.h
        cls.src=cls.outer.src
        cls.roster=cls.outer.roster
        cls.old384=copy.deepcopy(cls.outer.base_row)
        cls.old383=copy.deepcopy(cls.outer.base_383)
        cls.old382=copy.deepcopy(cls.outer.base_382)
        cls.legacy=timeline_fixture.HoldReceiptTimelineTests
        cls.target=cls.legacy.rev
        cls.sibling=cls.legacy.withdraw
        cls.chk=json.loads(Path(cls.src['checkpoint_file']).read_bytes())
        cls.keyfile=cls.h.w/'ec385-authorized-independent-change-approver-public-key.raw'
        raw=bytes.fromhex(cls.roster['change_approver']['public_hex'])
        cls.keyfile.write_bytes(raw)
        cls.keyref=ref(cls.keyfile,core.sha(raw))
        cls.ancestor=cls.outer.h.ctx
        # All file refs are genuine unchanged old locally Ed25519 signed bytes.
        def original(path):return ref(path,core.sha(Path(path).read_bytes()))
        cls.original=staticmethod(original)
        target=cls.old383['ec345_verified_source_snapshot_original']
        doc=json.loads(Path(target['path']).read_bytes())
        cls.base_row={
          'tsa_channel_id':cls.old384['tsa_channel_id'],
          'ec342_governance_roster_original':original(cls.src['governance_roster_file']),
          'ec342_hold_request_original':original(cls.legacy.p.hold_file),
          'ec342_review_manifest_original':original(cls.src['review_manifest_file']),
          'ec342_external_approval_original':original(cls.src['approval_file']),
          'ec342_signed_review_originals':[original(x['file']) for x in
                json.loads(Path(cls.src['review_manifest_file']).read_bytes())['attestations']],
          'ec343_source_head_snapshot_original':original(cls.src['head_snapshot_file']),
          'ec343_source_head_ack_set_original':original(cls.src['head_ack_set_file']),
          'ec343_original_source_head_receiver_receipts':[original(x['file']) for x in
             json.loads(Path(cls.src['head_ack_set_file']).read_bytes())['receipts']],
          'ec343_signed_target_snapshot_original':copy.deepcopy(target),
          'ec343_signed_target_ack_set_original':copy.deepcopy(
             cls.old383['ec345_verified_source_ack_set_original']),
          'ec343_original_signed_change_request':original(doc['change_file']),
          'ec343_original_signed_change_approval':original(doc['change_approval_file']),
          'ec343_original_target_receiver_receipts':[original(x['file']) for x in
             json.loads(Path(cls.old383['ec345_verified_source_ack_set_original']['path']).read_bytes())['receipts']],
          'ec343_change_proposer_public_key_original':copy.deepcopy(
             cls.old384['ec345_disclosure_issuer_public_key_original']),
          'ec343_change_approver_public_key_original':copy.deepcopy(cls.keyref),
          'ec343_competing_signed_successors':[]}

    @classmethod
    def tearDownClass(cls):offer_fixture.OriginalDisclosureOfferTests.tearDownClass()

    def setUp(self):
        self.row=copy.deepcopy(type(self).base_row)
        self.p384=copy.deepcopy(type(self).old384)
        self.p383=copy.deepcopy(type(self).old383)
        self.p382=copy.deepcopy(type(self).old382)
        self.h.role_paths={}

    def tearDown(self):self.h.role_paths={}

    def signed_sibling(self):
        s=self.sibling
        return {'snapshot_original':self.original(s['snapshot_file']),
          'ack_set_original':self.original(s['ack_set_file']),
          'signed_change_original':self.original(s['change_file']),
          'signed_approval_original':self.original(s['approval_file']),
          'receiver_receipt_originals':[self.original(x['file']) for x in
            json.loads(Path(s['ack_set_file']).read_bytes())['receipts']]}

    def run_channel(self,full=False):
        self.h.role_paths={}
        if full:
            return core._channel(self.row,self.p384,self.p383,self.p382,
                                self.h.read_original,set())
        with patch.object(core.parent.parent.previous.previous,'_ec348_original',
                          return_value=self.ancestor):
            return core._channel(self.row,self.p384,self.p383,self.p382,
                                 self.h.read_original,set())

    def denied(self):
        with self.assertRaises(errors.AnchorError):self.run_channel()

    def test_01_real_ec342_reviews_hold_approval_ec343_change_signatures_and_acks(self):
        report=self.run_channel(full=True)
        self.assertTrue(report['full_original_ec342_ec343_source_replay'])
        self.assertEqual(report['ec342_signed_review_count'],len(self.row['ec342_signed_review_originals']))
        self.assertEqual(report['ec343_signed_change_count'],1)
        self.assertEqual(report['ec343_verified_signed_receiver_ack_count'],4)
        self.assertFalse(report['ec343_same_parent_signed_fork_observed'])
        self.assertEqual(report['ec343_change_request_kind'],'request_revision')

    def test_02_genuine_signed_sibling_is_adverse_not_a_winner(self):
        self.row['ec343_competing_signed_successors']=[self.signed_sibling()]
        report=self.run_channel()
        self.assertTrue(report['ec343_same_parent_signed_fork_observed'])
        self.assertEqual(report['ec343_signed_change_count'],2)
        self.assertEqual(report['ec343_verified_signed_receiver_ack_count'],6)

    def test_03_signer_keys_must_reuse_original_ec384_proposer(self):
        self.row['ec343_change_proposer_public_key_original']['sha256']='aa'*32
        self.denied()

    def test_04_change_approver_has_separate_real_raw_public_key(self):
        self.row['ec343_change_approver_public_key_original']=copy.deepcopy(
            self.row['ec343_change_proposer_public_key_original'])
        self.denied()

    def test_05_governance_original_exact_sha(self):
        self.row['ec342_governance_roster_original']['sha256']='bb'*32;self.denied()

    def test_06_approved_hold_raw_original_sha(self):
        self.row['ec342_hold_request_original']['sha256']='ac'*32;self.denied()

    def test_07_review_manifest_exact_and_unchanged(self):
        self.row['ec342_review_manifest_original']['sha256']='ee'*32;self.denied()

    def test_08_real_signed_review_census_cannot_drop(self):
        self.row['ec342_signed_review_originals'].pop();self.denied()

    def test_09_independent_ec342_external_approval_cannot_swap(self):
        self.row['ec342_external_approval_original']['sha256']='ee'*32;self.denied()

    def test_10_ec342_previous_snapshot_pinned_to_real_source(self):
        self.row['ec343_source_head_snapshot_original']['sha256']='aa'*32;self.denied()

    def test_11_signed_previous_receiver_ack_set_sha_pinned(self):
        self.row['ec343_source_head_ack_set_original']['sha256']='aa'*32;self.denied()

    def test_12_receiver_ack_census_not_truncated(self):
        self.row['ec343_original_source_head_receiver_receipts'].pop();self.denied()

    def test_13_verified_original_target_reused_from_ec383(self):
        self.row['ec343_signed_target_snapshot_original']['sha256']='ff'*32;self.denied()

    def test_14_ec345_original_target_ack_sha_exact(self):
        self.row['ec343_signed_target_ack_set_original']['sha256']='dc'*32;self.denied()

    def test_15_independent_signed_change_request_sha_exact(self):
        self.row['ec343_original_signed_change_request']['sha256']='ac'*32;self.denied()

    def test_16_independent_signed_review_approval_sha_exact(self):
        self.row['ec343_original_signed_change_approval']['sha256']='be'*32;self.denied()

    def test_17_target_receiver_receipt_sha_pinned(self):
        self.row['ec343_original_target_receiver_receipts'][0]['sha256']='ab'*32;self.denied()

    def test_18_signed_approval_or_request_byte_change_detected(self):
        path=Path(self.row['ec343_original_signed_change_approval']['path'])
        original=path.read_bytes()
        try:
            path.write_bytes(original+b' ');self.denied()
        finally:path.write_bytes(original)

    def test_19_unsigned_ec344_checkpoint_is_never_receipt_signer(self):
        checkpoint=json.loads(Path(self.src['checkpoint_file']).read_bytes())
        self.assertNotIn('signature_ed25519',checkpoint)
        self.assertEqual(self.run_channel()['ec343_signed_change_count'],1)

    def test_20_off_checkpoint_supplied_sibling_cannot_elevate(self):
        s=self.signed_sibling()
        s['snapshot_original']=copy.deepcopy(self.row['ec343_source_head_snapshot_original'])
        self.row['ec343_competing_signed_successors']=[s]
        self.denied()

    def test_21_fork_change_and_approval_cannot_be_mixed(self):
        s=self.signed_sibling()
        s['signed_approval_original']=copy.deepcopy(
              self.row['ec343_original_signed_change_approval'])
        self.row['ec343_competing_signed_successors']=[s]
        self.denied()

    def test_22_signed_sibling_receipts_required(self):
        s=self.signed_sibling();s['receiver_receipt_originals'].pop()
        self.row['ec343_competing_signed_successors']=[s];self.denied()

    def test_23_missing_old_348_source_stays_unresolved(self):
        self.p382['ec348_full_replay_inputs_original']=None
        self.p384['ec345_disclosure_issuer_public_key_original']=None
        self.row={k:(self.old384['tsa_channel_id'] if k=='tsa_channel_id' else
              [] if k in ('ec342_signed_review_originals',
               'ec343_original_source_head_receiver_receipts',
               'ec343_original_target_receiver_receipts',
               'ec343_competing_signed_successors') else None)
                 for k in core.CHANNEL_FIELDS}
        report=self.run_channel()
        self.assertFalse(report['full_original_ec342_ec343_source_replay'])
        self.assertEqual(report['ec343_signed_change_count'],0)

    def test_24_missing_old_source_rejects_signed_provenance_injection(self):
        self.p382['ec348_full_replay_inputs_original']=None;self.denied()

    def test_25_original_source_context_item_id_swapped_denied(self):
        with patch.object(core.parent.parent.previous.previous,'_ec348_original',
              return_value={'inputs':{**self.src,'item_id':'different'}}):
            with self.assertRaises(errors.AnchorError):
                core._channel(self.row,self.p384,self.p383,self.p382,
                              self.h.read_original,set())

    def _outer(self):
        # Outer EC384->369 parent mocked, but EC342/343 signatures genuine.
        fake_parent={'schema':core.parent.RESULT_SCHEMA,'exit_code':2,
          'sender_origin_path_required_or_read':False,
          'ec345_through_ec337_full_independent_original_historical_acceptance_performed':False,
          'historical_ec345_disclosure_epoch_reviews':[{'epoch_index':0}],
          'local_ec344_signed_views_ec345_authorized_offer_originals_consistent':True}
        psha=core.sha(canonical.canonical(fake_parent))
        def archive(name,doc):
            raw=canonical.canonical(doc);path=self.h.w/name
            path.write_bytes(raw);return ref(path,core.sha(raw))
        def fake(name,schema,fields,channel,**authentic_links):
            return archive(name,{'schema':schema,'epochs':[{'epoch_index':0,
                 'channels':[channel]}],'claimed_directory_lineage_id':'Lineage385',
                 **{k:'a3'*32 for k in fields if k not in (
                    'schema','epochs','claimed_directory_lineage_id')},**authentic_links})
        old382=fake('ec385-fake-old-382.json',core.parent.parent.previous.BUNDLE_SCHEMA,
                    core.parent.parent.previous.BUNDLE_FIELDS,self.p382)
        old383=fake('ec385-fake-old-383.json',core.parent.parent.BUNDLE_SCHEMA,
                    core.parent.parent.BUNDLE_FIELDS,self.p383,
                    ec382_historical_keeper_archive_original_sha256=old382['sha256'])
        old384=fake('ec385-fake-old-384.json',core.parent.BUNDLE_SCHEMA,
                    core.parent.BUNDLE_FIELDS,self.p384,
                    ec383_historical_site_archive_original_sha256=old383['sha256'])
        new=archive('ec385-new-archive.json',{
          'schema':core.BUNDLE_SCHEMA,'parent_ec384_canonical_result_sha256':psha,
          'ec384_historical_offer_archive_original_sha256':old384['sha256'],
          'claimed_directory_lineage_id':'Lineage385',
          'epochs':[{'epoch_index':0,'channels':[self.row]}]})
        sender=archive('ec385-old-sender.json',{'schema':'dummy'})
        ref377=archive('ec385-old-377.json',{
          'schema':core.parent.parent.previous.previous.p379.p377.BUNDLE_SCHEMA,
          'epochs':[{'ec353_publication_bundle_original':sender}],
          **{k:'aa'*32 for k in core.parent.parent.previous.previous.p379.p377.BUNDLE_FIELDS
             if k not in ('schema','epochs')}})
        return fake_parent,{'historical_directory_root_shas':['cc'*32],
          'claimed_historical_directory_lineage_id':'Lineage385',
          'historical_ec348_keeper_archive_bundle_file':old382['path'],
          'expected_historical_ec348_keeper_archive_bundle_sha256':old382['sha256'],
          'historical_ec347_site_provenance_archive_bundle_file':old383['path'],
          'expected_historical_ec347_site_provenance_archive_bundle_sha256':old383['sha256'],
          'historical_ec345_disclosure_archive_bundle_file':old384['path'],
          'expected_historical_ec345_disclosure_archive_bundle_sha256':old384['sha256'],
          'historical_ec343_change_approval_archive_bundle_file':new['path'],
          'expected_historical_ec343_change_approval_archive_bundle_sha256':new['sha256'],
          'historical_transparency_archive_bundle_file':ref377['path'],
          'expected_historical_transparency_archive_bundle_sha256':ref377['sha256'],
          'historical_ec342_approved_hold_inventory_shas':['ca'*32],
          'historical_ec343_signed_change_inventory_shas':['ce'*32],
          'minimum_historical_ec342_signed_review_counts':[3],
          'minimum_historical_ec343_signed_change_counts':[1],
          'minimum_historical_ec343_signed_ack_counts':[4]}

    def _patches(self):return (
         patch.object(core,'_inputs',return_value={}),
         patch.object(core.parent,'audit',return_value=self._fake_parent),
         patch.object(core.parent.parent.previous.previous,'_ec348_original',
                      return_value=self.ancestor),
         patch.object(core.parent.parent.previous.previous.p379,'_old_sender_labels'))

    def test_26_real_original_inventory_derived_under_mocked_outer_parent(self):
        self._fake_parent,opts=self._outer();a,b,c,d=self._patches()
        with a,b,c,d:report=core.derive_inventory(**opts)
        self.assertEqual(report['exit_code'],2)
        self.assertEqual(report['genuine_old_ec343_signed_change_original_count'],1)
        self.assertEqual(report['genuine_old_ec343_signed_receiver_ack_original_count'],4)
        self.assertTrue(report[core.FLAGS[1]])
        self.assertFalse(report['caller_external_inventory_pin_created_or_certified'])

    def test_27_exact_outside_inventory_floors_still_exit_2(self):
        self._fake_parent,opts=self._outer();a,b,c,d=self._patches()
        with a,b,c,d:
            derived=core.derive_inventory(**opts)
            ep=derived['historical_ec343_change_epoch_reviews'][0]
            opts['historical_ec342_approved_hold_inventory_shas']=[
                   ep['ec342_approved_hold_inventory_sha256']]
            opts['historical_ec343_signed_change_inventory_shas']=[
                   ep['ec343_signed_change_inventory_sha256']]
            opts['expected_retained_historical_ec343_change_approval_inventory_sha256']=(
                   derived['receiver_verified_historical_ec343_change_inventory_sha256'])
            audited=core.audit(**opts)
        self.assertEqual(audited['exit_code'],2)
        self.assertTrue(audited['local_ec342_approved_hold_ec343_signed_change_originals_consistent'])
        self.assertTrue(audited[core.FLAGS[7]] and audited[core.FLAGS[8]])
        self.assertNotIn('unsigned_verified_historical_ec343_change_inventory',audited)

    def test_28_retained_inventory_mismatch_stays_unresolved(self):
        self._fake_parent,opts=self._outer();a,b,c,d=self._patches()
        with a,b,c,d:
            derived=core.derive_inventory(**opts)
            ep=derived['historical_ec343_change_epoch_reviews'][0]
            opts['historical_ec342_approved_hold_inventory_shas']=[ep['ec342_approved_hold_inventory_sha256']]
            opts['historical_ec343_signed_change_inventory_shas']=[ep['ec343_signed_change_inventory_sha256']]
            opts['expected_retained_historical_ec343_change_approval_inventory_sha256']='ee'*32
            audited=core.audit(**opts)
        self.assertTrue(audited[core.FLAGS[1]])
        self.assertEqual(audited['exit_code'],2)

    def test_29_help_has_no_private_signer(self):
        root=Path(__file__).resolve().parents[2]
        for script in ('ces_cas_historical_change_archive.py','ces_next.py'):
            p=subprocess.run([sys.executable,'-I','-B',str(root/'scripts'/script),
               'audit-historical-ec343-change-archive','--help'],capture_output=True,
               text=True,timeout=30)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('--expected-retained-historical-ec343-change-approval-inventory-sha256',p.stdout)
            self.assertNotIn('--private-key',p.stdout)


if __name__=='__main__':unittest.main()
