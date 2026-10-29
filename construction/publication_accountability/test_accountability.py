#!/usr/bin/env python3
"""Focused *genuine* EC366..EC370 Ed25519 tests with mocked EC366 deep parent.

Only the EC366->EC337 parent hash in the inherited synthetic fixture is
mocked; no production EC370 parent audit is mocked. Sender originals are
physically deleted before each EC370 audit. New keys are test-only signers.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from cryptography.hazmat.primitives.asymmetric import ed25519
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from witness_distribution import test_distribution as fixture
from detached_receiver import test_detached as test369
from . import accountability as core

UTC,EV,EXP=fixture.UTC,fixture.EV,fixture.EXP
ROOT=Path(__file__).resolve().parents[2]


class FocusedPublicationAccountabilityTests(unittest.TestCase):
    def setUp(self):
        # True source, witness, handoff and EC369 signatures are constructed
        # with ephemeral keys. EC366's old directory-parent is MOCKED only
        # inside the earlier EC367 setup, never by production EC370 code.
        self.base=test369.FocusedDetachedTests(
            'test_01_actual_sender_origins_deleted_detached_signatures_verify')
        self.base.setUp()
        self.addCleanup(self.base.fx.tmp.cleanup)
        self.fx=self.base.fx
        self.sender=self.base.opts()
        self.parent=self.base.run_audit()
        self.publisher=ed25519.Ed25519PrivateKey.generate()
        self.observer=ed25519.Ed25519PrivateKey.generate()
        self.pkey=self.fx.write('ec370-publisher-key',fixture.pub(self.publisher))
        self.okey=self.fx.write('ec370-observer-key',fixture.pub(self.observer))
        self.hand=[{'sender_dispatch_original_sha256':p['sender_dispatch_original']['sha256'],
                    'receiver_ack_original_sha256':p['receiver_ack_original']['sha256']}
                   for p in self.base.f.pairs]
        self.disc=[{'receiver_challenge_original_sha256':p['receiver_challenge_original']['sha256'],
                    'sender_disclosure_original_sha256':p['sender_disclosure_original']['sha256']}
                   for p in self.base.messages]
        self.epochs=[];self.competing_p=[];self.competing_o=[]
        self.make_epoch()
        self.make_bundle()

    def sign(self,name,body,priv,domain,field):
        return self.fx.write(name,{**body,field:priv.sign(domain+canonical.canonical(body)).hex()})

    def options(self,**change):
        attrs={**self.sender,
           'publication_bundle_file':self.bundle['path'],
           'expected_publication_bundle_sha256':self.bundle['sha256'],
           'publisher_public_key_file':self.pkey['path'],
           'expected_publisher_public_key_sha256':self.pkey['sha256'],
           'claimed_publisher_id':'ExamplePublisher',
           'publication_observer_public_key_file':self.okey['path'],
           'expected_publication_observer_public_key_sha256':self.okey['sha256'],
           'claimed_publication_observer_id':'ExampleObserver',
           'expected_retained_publisher_notice_head_sha256':self.epochs[-1][
               'publisher_notice_original']['sha256'],
           'expected_retained_publication_observer_head_sha256':self.epochs[-1][
               'publication_observation_original']['sha256'],
           'expected_latest_publication_inventory_sha256':core._inventory_hash(
               self.sender,self.parent,self.hand,self.disc),
           'minimum_retained_publication_sequence':0,
           'minimum_retained_published_challenge_count':1,
           'signed_publisher_notice_shas':[e['publisher_notice_original']['sha256']
                                           for e in self.epochs],
           'signed_publication_observer_shas':[e['publication_observation_original']['sha256']
                                               for e in self.epochs]}
        return {**attrs,**change}

    def make_epoch(self,*,nhand=None,ndisc=None,notice_change=None,observation_change=None,
                   publisher_signer=None,observer_signer=None,append=True,fork_at=None):
        seq=len(self.epochs) if fork_at is None else fork_at
        hand=copy.deepcopy(self.hand[:nhand]);disc=copy.deepcopy(self.disc[:ndisc])
        common={'claimed_publisher_id':'ExamplePublisher',
         'publisher_public_key_original_sha256':self.pkey['sha256'],
         'claimed_publication_observer_id':'ExampleObserver',
         'publication_observer_public_key_original_sha256':self.okey['sha256'],
         'claimed_sender_id':self.base.f.sender_id,
         'claimed_receiver_id':self.base.f.receiver_id,
         'sequence':seq,
         'previous_publisher_notice_original_sha256':(
             self.epochs[seq-1]['publisher_notice_original']['sha256'] if seq else None),
         'previous_publication_observation_original_sha256':(
             self.epochs[seq-1]['publication_observation_original']['sha256'] if seq else None),
         'detached_bundle_original_sha256':self.base.bundle['sha256'],
         'signed_copy_map_original_sha256':self.base.mapref['sha256'],
         'parent_ec367_canonical_result_sha256':self.base.f.parent_sha,
         'portable_inventory_canonical_sha256':self.base.f.inv_sha,
         'publication_inventory_canonical_sha256':core._inventory_hash(
             self.sender,self.parent,hand,disc),
         'published_handoff_sha_pairs':hand,
         'published_disclosure_sha_pairs':disc,
         'issued_utc':UTC,'expires_utc':EXP}
        notice={'schema':core.NOTICE_SCHEMA,**common,'publication_state':'published'}
        if notice_change:notice.update(notice_change)
        nref=self.sign('publisher-notice',notice,publisher_signer or self.publisher,
                       core.NOTICE_DOMAIN,'signature_publisher_ed25519_hex')
        observation={'schema':core.OBSERVATION_SCHEMA,**common,
                     'publisher_notice_original_sha256':nref['sha256'],
                     'observation_state':'confirmed'}
        if observation_change:observation.update(observation_change)
        oref=self.sign('observer-inclusion',observation,observer_signer or self.observer,
                       core.OBSERVATION_DOMAIN,'signature_observer_ed25519_hex')
        pair={'publisher_notice_original':nref,'publication_observation_original':oref}
        if append:self.epochs.append(pair)
        return pair

    def make_bundle(self):
        self.bundle=self.fx.write('ec370-publication-bundle',{
           'schema':core.BUNDLE_SCHEMA,'publication_epochs':self.epochs,
           'competing_publisher_notice_originals':self.competing_p,
           'competing_publication_observation_originals':self.competing_o})

    def audit(self,**change):
        return core.audit(**self.options(**change))

    def test_01_genuine_dual_signed_complete_history_while_sender_origins_gone(self):
        doc=self.audit()
        self.assertEqual(doc['exit_code'],2)
        self.assertTrue(doc['locally_two_party_publication_and_full_inventory_consistent'],doc)
        self.assertEqual(doc['true_verified_publisher_notice_ed25519_count'],1)
        self.assertEqual(doc['true_verified_publication_observer_ed25519_count'],1)
        self.assertFalse(doc['original_sender_source_paths_required_or_read'])
        self.assertTrue(all(not Path(e['path']).exists() for e in self.base.f.originals))
        self.assertTrue(all(doc[k] is False for k in core.NEGATIVES))

    def test_02_actual_publisher_notice_signature_forgery_denied(self):
        self.epochs=[self.make_epoch(publisher_signer=self.observer,append=False)]
        self.make_bundle()
        with self.assertRaises(errors.AnchorError) as caught:self.audit()
        self.assertEqual(caught.exception.status,'permission_denied')

    def test_03_real_observer_signature_forgery_denied(self):
        self.epochs=[self.make_epoch(observer_signer=self.publisher,append=False)]
        self.make_bundle()
        with self.assertRaises(errors.AnchorError) as caught:self.audit()
        self.assertEqual(caught.exception.status,'permission_denied')

    def test_04_tampered_publisher_original_bytes_denied(self):
        Path(self.epochs[0]['publisher_notice_original']['path']).write_bytes(b'tamper')
        with self.assertRaises(errors.AnchorError):self.audit()

    def test_05_external_old_publisher_head_detects_rollback(self):
        doc=self.audit(expected_retained_publisher_notice_head_sha256='f'*64)
        self.assertTrue(doc[core.FLAGS[5]])
        self.assertFalse(doc['locally_two_party_publication_and_full_inventory_consistent'])

    def test_06_external_notices_stream_mismatch_detected(self):
        doc=self.audit(signed_publisher_notice_shas=['a'*64])
        self.assertTrue(doc[core.FLAGS[5]])

    def test_07_genuine_publisher_signed_withheld_not_upgraded(self):
        self.epochs=[self.make_epoch(notice_change={
            'publication_state':'withheld'},append=False)]
        self.make_bundle()
        self.assertTrue(self.audit()[core.FLAGS[1]])

    def test_08_true_observer_signed_disputed_not_upgraded(self):
        self.epochs=[self.make_epoch(observation_change={
            'observation_state':'disputed'},append=False)]
        self.make_bundle()
        self.assertTrue(self.audit()[core.FLAGS[1]])

    def test_09_genuine_publisher_signed_missing_original_not_complete(self):
        # Add a second genuine EC369 challenge before rebuilding EC370 state.
        self.base.make_challenge(seq=1,nonce='2'*64)
        self.base.make_bundle()
        self.sender=self.base.opts(expected_retained_challenge_nonce_sha256='2'*64)
        self.parent=self.base.run_audit(**{'expected_retained_challenge_nonce_sha256':'2'*64})
        self.disc=[{'receiver_challenge_original_sha256':p['receiver_challenge_original']['sha256'],
                    'sender_disclosure_original_sha256':p['sender_disclosure_original']['sha256']}
                   for p in self.base.messages]
        self.epochs=[];self.make_epoch(ndisc=1);self.make_bundle()
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[2]])

    def test_10_true_two_epoch_monotonic_signed_challenges_and_publications(self):
        self.base.make_challenge(seq=1,nonce='2'*64)
        self.base.make_bundle()
        self.sender=self.base.opts(expected_retained_challenge_nonce_sha256='2'*64)
        self.parent=self.base.run_audit(**{'expected_retained_challenge_nonce_sha256':'2'*64})
        self.disc=[{'receiver_challenge_original_sha256':p['receiver_challenge_original']['sha256'],
                    'sender_disclosure_original_sha256':p['sender_disclosure_original']['sha256']}
                   for p in self.base.messages]
        self.epochs=[];self.make_epoch(ndisc=1);self.make_epoch(ndisc=2)
        self.make_bundle()
        doc=self.audit(minimum_retained_publication_sequence=1,
                       minimum_retained_published_challenge_count=2)
        self.assertTrue(doc['locally_two_party_publication_and_full_inventory_consistent'],doc)
        self.assertEqual(doc['true_verified_publication_observer_ed25519_count'],2)

    def test_11_true_signed_broken_previous_observer_sha_visible(self):
        self.make_epoch(notice_change={
            'previous_publication_observation_original_sha256':'1'*64})
        self.make_bundle()
        self.assertTrue(self.audit()[core.FLAGS[3]])

    def test_12_genuine_observer_signed_inconsistent_source_notice_visible(self):
        self.epochs=[self.make_epoch(observation_change={
            'parent_ec367_canonical_result_sha256':'f'*64},append=False)]
        self.make_bundle()
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[4]])
        self.assertTrue(doc[core.FLAGS[2]])

    def test_13_genuine_signed_inventory_hash_mismatch_not_accepted(self):
        self.epochs=[self.make_epoch(notice_change={
            'publication_inventory_canonical_sha256':'f'*64},append=False)]
        self.make_bundle()
        self.assertTrue(self.audit()[core.FLAGS[2]])

    def test_14_external_minimum_challenge_floor_blocks_truncation(self):
        doc=self.audit(minimum_retained_published_challenge_count=2)
        self.assertTrue(doc[core.FLAGS[5]])

    def test_15_signed_competing_publisher_fork_included_not_ignored(self):
        conflicting=self.make_epoch(notice_change={'publication_state':'disputed'},
                                    append=False,fork_at=0)
        self.competing_p.append(conflicting['publisher_notice_original'])
        self.make_bundle()
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[6]])
        self.assertEqual(doc['true_verified_competing_publisher_ed25519_count'],1)

    def test_16_forged_competing_observation_is_denied_not_reported(self):
        bad=self.make_epoch(observation_change={'observation_state':'withheld'},
                            observer_signer=self.publisher,append=False)
        self.competing_o.append(bad['publication_observation_original'])
        self.make_bundle()
        with self.assertRaises(errors.AnchorError) as caught:self.audit()
        self.assertEqual(caught.exception.status,'permission_denied')

    def test_17_parent_external_source_head_conflict_inherited(self):
        bad=self.audit(expected_source_status_head_shas=['f'*64,
                 self.sender['expected_source_status_head_shas'][1]])
        self.assertTrue(bad[core.FLAGS[0]])
        self.assertFalse(bad['locally_two_party_publication_and_full_inventory_consistent'])

    def test_18_actual_fixed_python_I_B_unified_child(self):
        inputs=self.options()
        args=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_next.py'),
              'audit-publication-accountability','DeliveryAudit','AuditPublicationAccountability']
        for k in (*test369.core.SCALARS,*core.NEW_SCALARS):
            args.extend(['--'+k.replace('_','-'),str(inputs[k])])
        for k,flag in (*test369.core.REPEATS,*core.NEW_REPEATS):
            for value in inputs[k]:args.extend([flag,'none' if value is None else str(value)])
        result=subprocess.run(args,capture_output=True,text=True,timeout=180)
        self.assertEqual(result.returncode,2,(result.stdout,result.stderr))
        doc=json.loads(result.stdout)
        self.assertEqual(doc['schema'],core.RESULT_SCHEMA)
        self.assertTrue(doc['locally_two_party_publication_and_full_inventory_consistent'],doc)

    def test_19_true_signed_observer_competing_fork_visible(self):
        conflicting=self.make_epoch(observation_change={'observation_state':'disputed'},
                                    append=False,fork_at=0)
        self.competing_o.append(conflicting['publication_observation_original'])
        self.make_bundle()
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[6]])
        self.assertEqual(doc['true_verified_competing_observer_ed25519_count'],1)

    def test_20_publisher_and_observer_must_be_independent_roles(self):
        with self.assertRaises(errors.AnchorError) as caught:
            self.audit(expected_publication_observer_public_key_sha256=self.pkey['sha256'])
        self.assertEqual(caught.exception.status,'permission_denied')

    def test_21_unsigned_inventory_export_is_exact_and_not_a_signature(self):
        doc=core.derive_inventory(**self.sender)
        self.assertEqual(doc['exit_code'],2)
        self.assertEqual(doc['schema'],core.DERIVE_SCHEMA)
        self.assertEqual(doc['current_unsigned_canonical_inventory_sha256'],
                         core._inventory_hash(self.sender,self.parent,self.hand,self.disc))
        self.assertFalse(doc['new_private_signing_or_publication_record_generated'])
        self.assertTrue(doc['inherited_ec369_detached_locally_consistent'])

    def test_22_unsigned_prefix_is_exact_but_not_misreported_as_all(self):
        self.base.make_challenge(seq=1,nonce='2'*64)
        self.base.make_bundle()
        opts=self.base.opts(expected_retained_challenge_nonce_sha256='2'*64)
        result=core.derive_inventory(published_disclosure_prefix_count=1,**opts)
        self.assertEqual(result['actual_full_disclosure_pair_count'],2)
        self.assertEqual(result['selected_disclosure_pair_count'],1)
        self.assertNotEqual(result['current_unsigned_canonical_inventory_sha256'],
                            core.derive_inventory(**opts)[
                                'current_unsigned_canonical_inventory_sha256'])

    def test_23_true_standalone_isolated_unsigned_export(self):
        args=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_cas_publication_accountability.py'),
              'derive-publication-inventory']
        for k in test369.core.SCALARS:
            args.extend(['--'+k.replace('_','-'),str(self.sender[k])])
        for k,flag in test369.core.REPEATS:
            for value in self.sender[k]:
                args.extend([flag,'none' if value is None else str(value)])
        result=subprocess.run(args,capture_output=True,text=True,timeout=180)
        self.assertEqual(result.returncode,2,(result.stdout,result.stderr))
        doc=json.loads(result.stdout)
        self.assertEqual(doc['schema'],core.DERIVE_SCHEMA)
        self.assertFalse(doc['new_private_signing_or_publication_record_generated'])

    def test_24_distinct_sane_signer_claimed_times_do_not_require_same_timestamp(self):
        self.epochs=[]
        self.epochs=[self.make_epoch(observation_change={
            'issued_utc':EV},append=False)]
        self.make_bundle()
        doc=self.audit()
        self.assertTrue(doc['locally_two_party_publication_and_full_inventory_consistent'],doc)

    def test_25_fixed_unified_child_denies_tampered_signed_record(self):
        inputs=self.options()
        args=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_next.py'),
              'audit-publication-accountability','DeliveryAudit','AuditPublicationAccountability']
        for k in (*test369.core.SCALARS,*core.NEW_SCALARS):
            args.extend(['--'+k.replace('_','-'),str(inputs[k])])
        for k,flag in (*test369.core.REPEATS,*core.NEW_REPEATS):
            for value in inputs[k]:args.extend([flag,'none' if value is None else str(value)])
        Path(self.epochs[0]['publication_observation_original']['path']).write_bytes(b'broken')
        result=subprocess.run(args,capture_output=True,text=True,timeout=180)
        self.assertIn(result.returncode,(3,4,5),(result.stdout,result.stderr))
        doc=json.loads(result.stdout)
        self.assertEqual(doc['schema'],core.DENIAL_SCHEMA)
        self.assertFalse(doc['original_sender_source_paths_required_or_read'])

if __name__=='__main__':unittest.main()
