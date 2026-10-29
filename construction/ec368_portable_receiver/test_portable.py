#!/usr/bin/env python3
"""EC368 focused real Ed25519 and real copy-byte scenarios, MOCK EC366 parent.

We explicitly mock ONLY the immense inherited EC366..EC337 verifier when
constructing a local EC367 result; EC367's witness and source signature checks
and EC368's new sender/receiver signatures and whole copy inventory are real.
This suite is NOT evidence of an EC366..EC337 end-to-end replay.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec367_witness_distribution import distribution as upstream
from ec367_witness_distribution import test_distribution as test367
UTC,EV,EXP=test367.UTC,test367.EV,test367.EXP
from . import portable as core


def pub(private):
    return private.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)


class FocusedPortableReceiverTests(unittest.TestCase):
    def setUp(self):
        # Test-only signer keys are never loaded by the production verifier.
        self.fx=test367.FocusedWitnessCryptoTests('test_01_valid_real_ed25519_witnesses_correlate_mock_parent_only')
        self.fx.setUp()
        self.addCleanup(self.fx.tmp.cleanup)
        self.args=self.fx.args367()
        self.parent=self.fx.run_audit()
        self.sender_private=ed25519.Ed25519PrivateKey.generate()
        self.receiver_private=ed25519.Ed25519PrivateKey.generate()
        self.sender_key=self.fx.write('sender-key',pub(self.sender_private))
        self.receiver_key=self.fx.write('receiver-key',pub(self.receiver_private))
        self.sender_id='SenderClaimOnly'
        self.receiver_id='ReceiverClaimOnly'
        self.index=0
        self.rebuild()

    def rebuild(self):
        self.parent_sha=core.sha(canonical.canonical(self.parent))
        originals,_=core._origins(self.args)
        inv=core._inventory(originals,self.parent_sha)
        self.inv_sha=core.sha(canonical.canonical(inv))
        self.originals=originals
        self.copies=[{'kind':x['kind'],'source_original_sha256':x['sha256'],
             'byte_length':x['length'],
             'receiver_copy':self.fx.write('receiver-copy-'+x['kind'],x['raw'])}
             for x in originals]
        self.heads=[x['actual_witness_head_sha256'] for x in
                    self.parent['two_witness_distribution_reviews']]
        self.pairs=[]
        self.make_pair()
        self.bundle()

    def make_pair(self,*,seq=0,previous_sender=None,previous_ack=None,
                  receiver_state='accepted',sender_changes=None,
                  receiver_changes=None,sender_key=None,receiver_key=None):
        if seq>0 and previous_sender is None and self.pairs:
            previous_sender=self.pairs[-1]['sender_dispatch_original']['sha256']
        if seq>0 and previous_ack is None and self.pairs:
            previous_ack=self.pairs[-1]['receiver_ack_original']['sha256']
        common={'claimed_sender_id':self.sender_id,
          'sender_public_key_original_sha256':self.sender_key['sha256'],
          'claimed_receiver_id':self.receiver_id,
          'receiver_public_key_original_sha256':self.receiver_key['sha256'],
          'parent_ec367_canonical_result_sha256':self.parent_sha,
          'portable_inventory_canonical_sha256':self.inv_sha,
          'sequence':seq,
          'previous_sender_dispatch_original_sha256':previous_sender,
          'previous_receiver_ack_original_sha256':previous_ack,
          'witness_head_original_shas':self.heads,
          'expires_utc':EXP}
        body={'schema':core.DISPATCH_SCHEMA,**common,'issued_utc':UTC}
        if sender_changes:body.update(sender_changes)
        signer=sender_key or self.sender_private
        signed={**body,'signature_sender_ed25519_hex':signer.sign(
            core.DISPATCH_DOMAIN+canonical.canonical(body)).hex()}
        dispatched=self.fx.write('sender-dispatch',signed)
        rec={'schema':core.ACK_SCHEMA,**common,
             'sender_dispatch_original_sha256':dispatched['sha256'],
             'receipt_state':receiver_state,'received_utc':EV}
        if receiver_changes:rec.update(receiver_changes)
        signer=receiver_key or self.receiver_private
        acknowledged={**rec,'signature_receiver_ed25519_hex':signer.sign(
            core.ACK_DOMAIN+canonical.canonical(rec)).hex()}
        ack=self.fx.write('receiver-ack',acknowledged)
        self.pairs.append({'sender_dispatch_original':dispatched,
                           'receiver_ack_original':ack})
        return self.pairs[-1]

    def bundle(self):
        raw={'schema':core.BUNDLE_SCHEMA,
              'parent_ec367_canonical_result_sha256':self.parent_sha,
              'portable_inventory':self.copies,'handoffs':self.pairs}
        self.bundleref=self.fx.write('portable-bundle',raw)

    def opts(self,**changes):
        args={**self.args,
          'portable_receiver_evaluation_utc':EV,
          'portable_receiver_bundle_file':self.bundleref['path'],
          'expected_portable_receiver_bundle_sha256':self.bundleref['sha256'],
          'expected_portable_inventory_sha256':self.inv_sha,
          'sender_public_key_file':self.sender_key['path'],
          'expected_sender_public_key_sha256':self.sender_key['sha256'],
          'claimed_sender_id':self.sender_id,
          'receiver_public_key_file':self.receiver_key['path'],
          'expected_receiver_public_key_sha256':self.receiver_key['sha256'],
          'claimed_receiver_id':self.receiver_id,
          'expected_retained_sender_dispatch_head_sha256':self.pairs[-1][
               'sender_dispatch_original']['sha256'],
          'expected_retained_receiver_ack_head_sha256':self.pairs[-1][
               'receiver_ack_original']['sha256'],
          'minimum_retained_sender_dispatch_sequence':0,
          'minimum_retained_receiver_ack_sequence':0,
          'signed_sender_dispatch_shas':[p['sender_dispatch_original']['sha256']
                                         for p in self.pairs],
          'signed_receiver_ack_shas':[p['receiver_ack_original']['sha256']
                                      for p in self.pairs]}
        return {**args,**changes}

    def audit(self,**changes):
        with patch.object(core.parent,'audit',return_value=self.parent):
            return core.audit(**self.opts(**changes))

    def test_01_two_real_signatures_and_full_byte_copies(self):
        result=self.audit()
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['locally_receiver_held_complete_portable_inventory_acknowledged'])
        self.assertEqual(result['byte_identical_original_copy_count'],len(self.originals))
        self.assertEqual(result['actual_receiver_ed25519_ack_signature_count'],1)
        self.assertTrue(all(result[k] is False for k in core.NEGATIVES))

    def test_02_derive_inventory_from_reopened_true_originals(self):
        with patch.object(core.parent,'audit',return_value=self.parent):
            report=core.checklist(**self.args)
        self.assertEqual(report['expected_portable_inventory_sha256'],self.inv_sha)
        self.assertEqual(len(report['required_exact_original_inventory']),len(self.originals))

    def test_03_selective_omission_must_deny(self):
        self.copies=self.copies[:-1]
        self.bundle()
        with self.assertRaises(errors.AnchorError):self.audit()

    def test_04_copy_bytes_tamper_must_deny(self):
        Path(self.copies[3]['receiver_copy']['path']).write_bytes(b'malicious bytes')
        with self.assertRaises(errors.AnchorError) as got:self.audit()
        self.assertIn(got.exception.status,('permission_denied','invalid_input'))

    def test_05_receiver_copy_same_inode_as_original_denied(self):
        self.copies[2]['receiver_copy']={'path':self.originals[2]['path'],
                                        'sha256':self.originals[2]['sha256']}
        self.bundle()
        with self.assertRaises(errors.AnchorError) as got:self.audit()
        self.assertEqual(got.exception.status,'permission_denied')

    def test_06_wrong_real_receiver_signature_denied(self):
        self.pairs=[]
        self.make_pair(receiver_key=self.sender_private)
        self.bundle()
        with self.assertRaises(errors.AnchorError) as got:self.audit()
        self.assertEqual(got.exception.status,'permission_denied')

    def test_07_wrong_real_sender_signature_denied(self):
        self.pairs=[]
        self.make_pair(sender_key=self.receiver_private)
        self.bundle()
        with self.assertRaises(errors.AnchorError) as got:self.audit()
        self.assertEqual(got.exception.status,'permission_denied')

    def test_08_signed_withholding_does_not_upgrade(self):
        self.pairs=[]
        self.make_pair(receiver_state='withheld')
        self.bundle()
        r=self.audit()
        self.assertTrue(r['authentic_receiver_ack_withheld_or_disputed_visible'])
        self.assertFalse(r['locally_receiver_held_complete_portable_inventory_acknowledged'])

    def test_09_real_two_step_sender_receiver_chain(self):
        self.make_pair(seq=1)
        self.bundle()
        r=self.audit(minimum_retained_sender_dispatch_sequence=1,
                     minimum_retained_receiver_ack_sequence=1)
        self.assertTrue(r['locally_receiver_held_complete_portable_inventory_acknowledged'])
        self.assertEqual(r['actual_latest_handoff_sequence'],1)

    def test_10_receiver_cross_link_conflict_visible(self):
        self.make_pair(seq=1,receiver_changes={
           'previous_receiver_ack_original_sha256':'e'*64})
        self.bundle()
        r=self.audit()
        self.assertTrue(r['authentic_sender_or_receiver_handoff_fork_gap_or_cross_link_visible'])
        self.assertFalse(r['locally_receiver_held_complete_portable_inventory_acknowledged'])

    def test_11_genesis_fork_visible(self):
        self.make_pair(seq=0,sender_changes={'issued_utc':'2026-10-26T12:01:00Z'})
        self.bundle()
        r=self.audit()
        self.assertTrue(r['authentic_sender_or_receiver_handoff_fork_gap_or_cross_link_visible'])
        self.assertIsNone(r['actual_receiver_ack_head_sha256'])

    def test_12_separate_retained_sender_head_prevents_rollback(self):
        r=self.audit(expected_retained_sender_dispatch_head_sha256='f'*64)
        self.assertTrue(r['retained_sender_or_receiver_head_or_sequence_rollback_visible'])

    def test_13_independent_inventory_sha_mismatch_visible(self):
        r=self.audit(expected_portable_inventory_sha256='a'*64)
        self.assertTrue(r['independently_retained_portable_inventory_or_handoff_sha_stream_mismatch'])

    def test_14_signed_different_actual_inventory_detected(self):
        self.pairs=[]
        self.make_pair(sender_changes={'portable_inventory_canonical_sha256':'a'*64})
        self.bundle()
        r=self.audit()
        self.assertTrue(r['sender_receiver_signed_parent_inventory_or_witness_head_disagreement'])

    def test_15_actual_signed_source_revocation_survives_acknowledgment(self):
        revoke=self.fx.source_status(0,1,'revoke')
        self.fx.distribution_bundle([{'source_role':upstream.SOURCES[0],
                                      'original':revoke}])
        self.args=self.fx.args367()
        self.parent=self.fx.run_audit()
        self.rebuild()
        r=self.audit()
        self.assertTrue(r['source_signed_revocation_or_rotation_survives_portable_ack'])
        self.assertFalse(r['locally_receiver_held_complete_portable_inventory_acknowledged'])
        self.assertIn(revoke['sha256'],r['verified_source_terminal_original_shas_preserved'][0])

    def test_16_receiver_key_reused_as_witness_blocks_local_claim(self):
        self.receiver_key=self.fx.write('receiver-key-reuses-witness',
            pub(self.fx.witnesses[0]['private']))
        self.receiver_private=self.fx.witnesses[0]['private']
        self.pairs=[]
        self.make_pair()
        self.bundle()
        r=self.audit()
        self.assertTrue(r['sender_or_receiver_signer_reuses_witness_source_or_historical_role'])
        self.assertFalse(r['locally_receiver_held_complete_portable_inventory_acknowledged'])

    def test_17_signed_utc_future_or_receive_before_dispatch(self):
        self.pairs=[]
        self.make_pair(sender_changes={'issued_utc':'2026-10-28T11:00:00Z'})
        self.bundle()
        r=self.audit()
        self.assertTrue(r['self_reported_dispatch_or_receipt_clock_untrusted_or_out_of_order'])

    def test_19_unified_fixed_router_accepts_only_bounded_exit2_shape(self):
        # This is a mocked isolated child *reply*, NOT a full historical
        # child-process or EC366 original replay.
        from scripts import ces_next as router
        opts=self.opts()
        def fill(k):
            if k in opts:return opts[k]
            if k.endswith('_file'):return str(self.fx.base/'placeholder')
            if k.endswith('_sha256'):return 'a'*64
            if k.endswith('_evaluation_utc'):return UTC
            if k in ('expected_current_root_epoch','minimum_acceptable_epoch'):return 1
            return 'placeholder'
        forwarded={k:fill(k) for k in router.EC368_REQUIRED}
        forwarded.update({k:opts.get(k) for k in router.EC368_OPTIONAL})
        forwarded.update({k:opts.get(k,[]) for k,_ in router.EC368_REPEATS})
        output=self.audit()
        with patch.object(router,'_command',return_value=(2,output)) as child, \
             patch.object(router,'_emit'):
            self.assertEqual(router.audit_portable_receiver(
                 'DeliveryAudit','AuditPortableReceiver',**forwarded),2)
        self.assertEqual(child.call_args.args[0][1:3],['-I','-B'])
        output_bad={**output,
          'locally_receiver_held_complete_portable_inventory_acknowledged':True,
          'official_receiver_identity_actual_physical_custody_trusted_utc_global_completeness_unproven':False}
        with patch.object(router,'_command',return_value=(2,output_bad)), \
             patch.object(router,'_emit'):
            with self.assertRaises(Exception):
                router.audit_portable_receiver('DeliveryAudit','AuditPortableReceiver',
                                               **forwarded)

    def test_18_externally_pinned_signed_sha_order_no_self_authorization(self):
        r=self.audit(signed_receiver_ack_shas=['e'*64])
        self.assertTrue(r['independently_retained_portable_inventory_or_handoff_sha_stream_mismatch'])
        self.assertFalse(r['locally_receiver_held_complete_portable_inventory_acknowledged'])

if __name__=='__main__':unittest.main()
