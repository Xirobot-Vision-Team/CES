#!/usr/bin/env python3
"""EC375 genuine EC356 signers, real receiver original bytes and EC357 bridge.

Production EC374→EC369 is really replayed in isolated child checks. The older
EC366→EC337 fixture is inherited and DELIBERATELY MOCKED. No old EC356 or
EC357 result is reconstructed; negative tests cannot prove global custody.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from custody import custody as ec356
from gossip import gossip
from witness_distribution import test_distribution as util
from historical_owner import test_owner_archive as old_tests
from . import custody_archive as core

ROOT=Path(__file__).resolve().parents[2]


class ReceiverHistoricalTrueCustodyOriginalsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        old_tests.ReceiverHistoricalRealOwnerAndReviewerTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        old_tests.ReceiverHistoricalRealOwnerAndReviewerTests.tearDownClass()

    def setUp(self):
        self.old=old_tests.ReceiverHistoricalRealOwnerAndReviewerTests(
              'test_01_original_ec357_and_ec358_signatures_and_parent_link')
        original=self.old.prepare_genuine_ec357_and_ec358_originals
        def with_true_old_custody_before_signing_ec357():
            self.construct_ec356_receiver_originals()
            saved=self.old.ec373.signed
            def signed(name,body,private,domain,field):
                if name.startswith('ec374_real_source_review_'):
                    body=copy.deepcopy(body)
                    body['ec356_custody_bundle_original_sha256']=self.custody_bundle['sha256']
                    body['root_records']=copy.deepcopy(self.signed_root_records)
                    body['inventory_records']=copy.deepcopy(self.signed_inventory_records)
                    if self._testMethodName.startswith('test_28_'):
                        body['root_records'][0]['root_state']='revoked'
                        body['root_records'][0]['root_state_effective_utc']=util.UTC
                    if self._testMethodName.startswith('test_29_') and name.endswith('_a'):
                        body['inventory_records']=[]
                    if self._testMethodName.startswith('test_30_'):
                        body['inventory_records'][0]['declared_site_id']='ConflictingHistoricalSite'
                    if self._testMethodName.startswith('test_34_') and name.endswith('_a'):
                        # Signed A report describes B's bytes falsely, while
                        # B's own signed report correctly describes its bytes.
                        body['inventory_records'][1]['checkpoint_original_sha256']='e'*64
                    if self._testMethodName.startswith('test_35_') and name.endswith('_a'):
                        # Both reviews are genuine, but A identifies the
                        # opposite channel B under another root signing key.
                        body['root_records'][1]['root_public_key_original_sha256']='e'*64
                return saved(name,body,private,domain,field)
            with patch.object(self.old.ec373,'signed',side_effect=signed):
                original()
        self.old.prepare_genuine_ec357_and_ec358_originals=(
            with_true_old_custody_before_signing_ec357)
        self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        # EC374 inherited fixture originally used an intentionally absent
        # EC356 SHA claim. Replace its (unsigned) new wrapper with the newly
        # generated exact EC357-signed EC356 original SHA, without changing
        # any already-signed EC357/358/359/360 original.
        for epoch in self.old.rows:
            for slot in ('a','b'):
                epoch['source_'+slot]['signed_ec356_custody_bundle_original_sha256']=self.custody_bundle['sha256']
        self.old.rebuild()
        self.parent=self.old.audit() # EC374 real original checks; EC373 parent patched
        self.rows=[]
        self.make_bundle()

    def store(self,name,obj):return self.old.ec373.stored(name,obj)

    def signed(self,name,body,priv,domain):
        doc={**body,'signature_ed25519_hex':priv.sign(
             domain+canonical.canonical(body)).hex()}
        return self.store(name,doc)

    @staticmethod
    def old_label(ref):
        # Deliberately absent sender-origin label, neither an authority nor a
        # path to open. This is distinct from every receiver-held original.
        return {'path':str(Path(ref['path']).parent/('UNOPENED_EC356_'
                          +Path(ref['path']).stem[-42:]+'_'+ref['sha256'][:12])),
                'sha256':ref['sha256']}

    def construct_ec356_receiver_originals(self):
        self.sources={};self.signed_root_records=[];self.signed_inventory_records=[]
        channels=[]
        for slot in ('a','b'):
            big=slot.upper()
            root=ed25519.Ed25519PrivateKey.generate()
            channel=ed25519.Ed25519PrivateKey.generate()
            root_ref=self.store('ec375_actual_old_root_key_'+slot,util.pub(root))
            channel_ref=self.store('ec375_actual_old_channel_key_'+slot,util.pub(channel))
            self_root=self.signed('ec375_old_signed_root_reference_'+slot,{
                'schema':ec356.ROOT_SCHEMA,
                'institution_id':'HistoricCustodyInstitute'+big,
                'claimed_organization':'Historic Custody Org '+big,
                'root_public_key_original_sha256':root_ref['sha256'],
                'valid_from_utc':util.UTC,'valid_until_utc':util.EXP},
                root,ec356.ROOT_DOMAIN)
            auth=self.signed('ec375_old_signed_channel_authority_'+slot,{
                'schema':ec356.AUTH_SCHEMA,
                'institution_id':'HistoricCustodyInstitute'+big,
                'channel_id':'HistoricCustodyChannel'+big,
                'root_reference_original_sha256':self_root['sha256'],
                'channel_public_key_original_sha256':channel_ref['sha256'],
                'claimed_physical_site_id':'HistoricCustodySite'+big,
                'valid_from_utc':util.UTC,'valid_until_utc':util.EXP},
                root,ec356.AUTH_DOMAIN)
            cp_bytes=b'original-checkpoint-shared-historic-byte-copy'
            if slot=='b' and self._testMethodName.startswith('test_36_'):
                cp_bytes=b'other-source-signed-but-not-paired-checkpoint-bytes'
            cp=self.store('ec375_actual_signed_custody_cp_copy_'+slot,
                          cp_bytes)
            witness=self.store('ec375_actual_signed_custody_witness_copy_'+slot,
                          b'original-witness-shared-historic-byte-copy')
            body={'schema':ec356.ACK_SCHEMA,
                  'acknowledgement_id':'HistoricalAck'+big,
                  'parent_disclosure_bundle_original_sha256':'5'*64,
                  'gossip_reply_original_sha256':'6'*64,
                  'ec355_request_original_sha256':'7'*64,
                  'ec355_receipt_original_sha256':('8' if slot=='a' else '9')*64,
                  'ec355_requested_role':('original_responder' if slot=='a'
                                          else 'independent_peer'),
                  'log_id':'HistoricLog',
                  'checkpoint_original_sha256':cp['sha256'],
                  'witness_original_sha256':witness['sha256'],
                  'checkpoint_length':len(Path(cp['path']).read_bytes()),
                  'witness_length':len(Path(witness['path']).read_bytes()),
                  'custody_status':'custodied_originals',
                  'institution_id':'HistoricCustodyInstitute'+big,
                  'channel_id':'HistoricCustodyChannel'+big,
                  'channel_authorization_original_sha256':auth['sha256'],
                  'previous_ack_original_sha256':ec356.GENESIS,
                  'nonce_hex':('a' if slot=='a' else 'b')*32,
                  'acknowledged_utc':util.UTC}
            if slot=='b' and self._testMethodName.startswith('test_32_'):
                body['nonce_hex']='a'*32 # A and B independently signed same nonce
            if slot=='b' and self._testMethodName.startswith('test_33_'):
                body['acknowledgement_id']='HistoricalAckA'
            ack=self.signed('ec375_real_signed_original_ack_'+slot,body,channel,
                            ec356.ACK_DOMAIN)
            receiver={'root_public_key_original':root_ref,
                      'root_reference_signed_original':self_root,
                      'channel_public_key_original':channel_ref,
                      'channel_authorization_signed_original':auth,
                      'acknowledgements':[{'acknowledgement_signed_original':ack,
                       'checkpoint_original':cp,'witness_original':witness}],
                      'selected_ack_head_sha256':ack['sha256']}
            oldentry={'slot':slot,'institution_id':body['institution_id'],
                   'channel_id':body['channel_id'],
                   'claimed_organization':'Historic Custody Org '+big,
                   'root_public_key':self.old_label(root_ref),
                   'root_reference':self.old_label(self_root),
                   'channel_public_key':self.old_label(channel_ref),
                   'channel_authorization':self.old_label(auth),
                   'acknowledgements':[{
                    'acknowledgement':self.old_label(ack),
                    'checkpoint_original':self.old_label(cp),
                    'witness_original':self.old_label(witness)}]}
            channels.append(oldentry)
            self.signed_root_records.append({
                 'slot':slot,'institution_id':body['institution_id'],
                 'claimed_legal_entity_id':'HistoricLegal'+big,
                 'root_public_key_original_sha256':root_ref['sha256'],
                 'root_state':'active','replacement_root_public_key_sha256':None,
                 'root_state_effective_utc':None,
                 'declared_physical_site_id':'HistoricCustodySite'+big})
            self.signed_inventory_records.append({
                 'slot':slot,'ec355_receipt_original_sha256':body[
                       'ec355_receipt_original_sha256'],
                 'checkpoint_original_sha256':cp['sha256'],
                 'checkpoint_length':body['checkpoint_length'],
                 'witness_original_sha256':witness['sha256'],
                 'witness_length':body['witness_length'],
                 'declared_site_id':'HistoricCustodySite'+big,
                 'availability':'present'})
            self.sources[slot]={'root':root,'channel':channel,
                   'receiver':receiver,'old':oldentry,
                   'ackbody':body,'ack':ack,'rootref':self_root,
                   'rootkey':root_ref,'auth':auth,'cp':cp,'witness':witness}
        self.custody_bundle=self.store('ec375_original_unsigned_old_ec356_bundle',{
            'schema':ec356.BUNDLE_SCHEMA,'channels':channels})

    def make_bundle(self):
        self.rows=[{'epoch_index':i,
           'ec356_custody_bundle_original':self.custody_bundle,
           'source_a':copy.deepcopy(self.sources['a']['receiver']),
           'source_b':copy.deepcopy(self.sources['b']['receiver'])}
           for i in range(2)]
        self.rebuild()

    def rebuild(self):
        self.archive=self.store('ec375_receiver_signed_original_archive',{
          'schema':core.BUNDLE_SCHEMA,
          'parent_ec374_canonical_result_sha256':core.sha(
                      canonical.canonical(self.parent)),
          'ec374_historical_owner_epoch_bundle_original_sha256':self.old.bundle['sha256'],
          'claimed_directory_lineage_id':self.old.ec373.old.lineage,
          'epochs':self.rows})

    def options(self,**extra):
        old=self.old.options()
        old['expected_retained_historical_owner_inventory_sha256']=self.old.derive()[
                      'receiver_verified_historical_owner_inventory_sha256']
        old.update(historical_custody_archive_bundle_file=self.archive['path'],
             expected_historical_custody_archive_bundle_sha256=self.archive['sha256'],
             historical_custody_a_root_key_shas=[self.sources['a']['rootkey']['sha256']]*2,
             historical_custody_b_root_key_shas=[self.sources['b']['rootkey']['sha256']]*2,
             historical_custody_a_ack_head_shas=[self.sources['a']['ack']['sha256']]*2,
             historical_custody_b_ack_head_shas=[self.sources['b']['ack']['sha256']]*2,
             minimum_historical_custody_a_ack_counts=[1]*2,
             minimum_historical_custody_b_ack_counts=[1]*2)
        return {**old,**extra}

    def derive(self,**overrides):
        with patch.object(core.prior,'audit',return_value=self.parent):
            return core.derive_inventory(**self.options(**overrides))

    def audit(self,**overrides):
        opts=self.options(expected_retained_historical_custody_inventory_sha256=
             self.derive()['receiver_verified_historical_custody_inventory_sha256'])
        opts.update(overrides)
        with patch.object(core.prior,'audit',return_value=self.parent):
            return core.audit(**opts)

    def test_01_actual_old_ec356_sig_originals_ec357_inventory_link(self):
        doc=self.audit()
        self.assertTrue(doc['local_pinned_historical_custody_signatures_and_source_inventory_consistent'])
        self.assertEqual(doc['verified_real_ec356_root_signed_reference_count'],4)
        self.assertEqual(doc['verified_real_ec356_root_signed_channel_authorization_count'],4)
        self.assertEqual(doc['verified_real_ec356_channel_signed_acknowledgement_count'],4)
        self.assertEqual(doc['verified_real_old_ec356_original_copy_pair_count'],4)
        self.assertEqual(doc['exit_code'],2)
        self.assertTrue(doc[core.FLAGS[-1]])
        self.assertFalse(doc['old_ec356_canonical_result_recomputed_from_complete_ec355_original_inputs'])

    def test_02_true_old_root_signed_bytes_tampered_denied(self):
        Path(self.sources['a']['rootref']['path']).write_bytes(b'FORGED-ROOT')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_03_true_old_root_signature_forgery_denied(self):
        bad=json.loads(Path(self.sources['a']['rootref']['path']).read_text())
        bad['signature_ed25519_hex']='f'*128
        self.rows[0]['source_a']['root_reference_signed_original']=self.store('forged_root',bad)
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_04_true_old_channel_authorization_tamper_denied(self):
        Path(self.sources['b']['auth']['path']).write_bytes(b'TAMPERED-AUTH')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_05_true_old_ack_signed_bytes_tampered_denied(self):
        Path(self.sources['b']['ack']['path']).write_bytes(b'UNSIGNED-BYTES')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_06_true_old_checkpoint_receiver_copy_tamper_denied(self):
        Path(self.sources['a']['cp']['path']).write_bytes(b'ALTERED-ORIGINAL')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_07_true_old_witness_receiver_copy_tamper_denied(self):
        Path(self.sources['a']['witness']['path']).write_bytes(b'ALTERED-WITNESS')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_08_old_unsigned_ec356_original_manifest_tamper_denied(self):
        Path(self.custody_bundle['path']).write_bytes(b'ALTERED-BUNDLE')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_09_invented_receiver_root_bytes_denied(self):
        self.rows[0]['source_a']['root_public_key_original']=self.sources['b']['rootkey']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_10_external_root_key_sha_mismatch_visible(self):
        self.assertTrue(self.audit(historical_custody_a_root_key_shas=['f'*64]*2)[core.FLAGS[1]])

    def test_11_external_ack_head_rollback_visible(self):
        self.assertTrue(self.audit(historical_custody_b_ack_head_shas=['f'*64]*2)[core.FLAGS[1]])

    def test_12_external_ack_count_floor_visible(self):
        self.assertTrue(self.audit(minimum_historical_custody_a_ack_counts=[2,2])[core.FLAGS[1]])

    def test_13_independent_inventory_sha_mismatch_visible(self):
        self.assertTrue(self.audit(expected_retained_historical_custody_inventory_sha256=
                                    'f'*64)[core.FLAGS[1]])

    def test_14_ec356_channel_signer_role_collision_denied(self):
        old=self.sources['a'];actor=core._root_channel
        with self.assertRaises(errors.AnchorError):actor(
            0,'a',old['old'],old['receiver'],lambda ref,role,cap:Path(ref['path']).read_bytes(),
            {old['rootkey']['sha256']},core.tr._utc(util.EV))

    def test_15_old_unsigned_ec356_sender_path_labels_never_opened(self):
        for oldentry in (self.sources['a']['old'],self.sources['b']['old']):
            for name in ('root_public_key','root_reference','channel_public_key',
                         'channel_authorization'):
                self.assertFalse(Path(oldentry[name]['path']).exists())
            for ref in oldentry['acknowledgements'][0].values():
                self.assertFalse(Path(ref['path']).exists())
        self.assertFalse(self.audit()['sender_origin_path_required_or_read'])

    def test_16_historical_ec362_old_copy_labels_never_opened(self):
        for epoch in self.old.ec373.old.rows:
            for slot in ('a','b'):
                m=json.loads(Path(epoch['source_'+slot+'_manifest_original']['path']).read_text())
                for ref in m['copies'].values():self.assertFalse(Path(ref['path']).exists())
        self.assertFalse(self.audit()['old_ec362_signed_source_copy_labels_or_ec369_sender_paths_read'])

    def test_17_receiver_archive_omits_one_old_manifest_ack_denied(self):
        self.rows[1]['source_b']['acknowledgements']=[]
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_18_receiver_ack_copy_must_match_old_manifest_sha(self):
        self.rows[1]['source_a']['acknowledgements'][0]['checkpoint_original']=self.sources['b']['witness']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_19_duplicate_receiver_signed_ack_rejected(self):
        self.rows[0]['source_a']['acknowledgements'].append(copy.deepcopy(
            self.rows[0]['source_a']['acknowledgements'][0]))
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_20_true_signed_custody_fork_detected_lower_level(self):
        old=copy.deepcopy(self.sources['a']['old']);fresh=copy.deepcopy(
                                  self.sources['a']['receiver'])
        body=copy.deepcopy(self.sources['a']['ackbody'])
        body['acknowledgement_id']='HistoricalForkA';body['nonce_hex']='c'*32
        fork=self.signed('ec375_genuine_signed_custody_fork',body,
                          self.sources['a']['channel'],ec356.ACK_DOMAIN)
        fresh['acknowledgements'].append({'acknowledgement_signed_original':fork,
           'checkpoint_original':self.sources['a']['cp'],
           'witness_original':self.sources['a']['witness']})
        old['acknowledgements'].append({'acknowledgement':self.old_label(fork),
           'checkpoint_original':self.old_label(self.sources['a']['cp']),
           'witness_original':self.old_label(self.sources['a']['witness'])})
        actor=core._root_channel(0,'a',old,fresh,
               lambda ref,role,cap:Path(ref['path']).read_bytes(),set(),
               core.tr._utc(util.EV))
        rows,head,forked=core._acks(0,'a',old,fresh,actor,
               lambda ref,role,cap:Path(ref['path']).read_bytes(),
               core.tr._utc(util.EV))
        self.assertTrue(forked)
        self.assertEqual(len(rows),2)
        self.assertEqual(head,self.sources['a']['ack']['sha256'])

    def test_21_ec357_signed_review_bundle_sha_is_immutable(self):
        self.rows[0]['ec356_custody_bundle_original']=self.old.bundle
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_22_unsigned_sha_inventory_deterministic_and_not_certified(self):
        d=self.derive()
        self.assertFalse(d['caller_external_inventory_pin_created_or_certified'])
        self.assertEqual(d['receiver_verified_historical_custody_inventory_sha256'],
            core.sha(canonical.canonical(d['unsigned_verified_historical_custody_inventory'])))

    def test_23_false_live_ec374_parent_digest_denied(self):
        data=json.loads(Path(self.archive['path']).read_text())
        data['parent_ec374_canonical_result_sha256']='f'*64
        self.archive=self.store('false_live_parent_custody',data)
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_24_bare_unexpected_field_rejected(self):
        self.rows[1]['source_a']['untrusted_download_url']='https://bad.invalid'
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_28_genuine_source_signed_root_revocation_stays_adverse(self):
        d=self.audit()
        self.assertTrue(d[core.FLAGS[0]])
        self.assertTrue(d[core.FLAGS[4]])
        self.assertFalse(d['local_pinned_historical_custody_signatures_and_source_inventory_consistent'])
        self.assertEqual(d['exit_code'],2)

    def test_29_genuine_source_signed_inventory_omission_stays_visible(self):
        d=self.audit()
        self.assertTrue(d[core.FLAGS[3]])
        self.assertFalse(d['local_pinned_historical_custody_signatures_and_source_inventory_consistent'])

    def test_30_genuine_source_signed_wrong_custody_site_stays_visible(self):
        d=self.audit()
        self.assertTrue(d[core.FLAGS[4]])
        self.assertFalse(d['local_pinned_historical_custody_signatures_and_source_inventory_consistent'])

    def test_31_independent_old_gossip_claims_not_false_ack_forks(self):
        old=copy.deepcopy(self.sources['a']['old'])
        receiver=copy.deepcopy(self.sources['a']['receiver'])
        body=copy.deepcopy(self.sources['a']['ackbody'])
        body['acknowledgement_id']='IndependentGossipClaim'
        body['nonce_hex']='c'*32
        body['gossip_reply_original_sha256']='3'*64
        body['ec355_receipt_original_sha256']='4'*64
        ack=self.signed('ec375_second_independent_gossip_ack',body,
                         self.sources['a']['channel'],ec356.ACK_DOMAIN)
        old['acknowledgements'].append({'acknowledgement':self.old_label(ack),
           'checkpoint_original':self.old_label(self.sources['a']['cp']),
           'witness_original':self.old_label(self.sources['a']['witness'])})
        receiver['acknowledgements'].append({'acknowledgement_signed_original':ack,
           'checkpoint_original':self.sources['a']['cp'],
           'witness_original':self.sources['a']['witness']})
        read=lambda ref,role,cap:Path(ref['path']).read_bytes()
        actor=core._root_channel(0,'a',old,receiver,read,set(),core.tr._utc(util.EV))
        _,_,fork=core._acks(0,'a',old,receiver,actor,read,core.tr._utc(util.EV))
        self.assertFalse(fork)

    def test_32_two_genuinely_signed_channel_ack_nonce_collision_denied(self):
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_33_two_genuinely_signed_channel_ack_identifier_collision_denied(self):
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_34_source_a_signed_report_cannot_misdescribe_source_b_originals(self):
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[4]])
        self.assertFalse(doc['local_pinned_historical_custody_signatures_and_source_inventory_consistent'])

    def test_35_source_a_signed_report_cannot_misidentify_source_b_root(self):
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[4]])
        self.assertFalse(doc['local_pinned_historical_custody_signatures_and_source_inventory_consistent'])

    def test_36_two_real_signed_channels_without_same_originals_not_quorum(self):
        doc=self.audit()
        self.assertEqual(doc['verified_real_old_ec356_original_copy_pair_count'],4)
        self.assertTrue(doc[core.FLAGS[3]])
        self.assertFalse(doc['local_pinned_historical_custody_signatures_and_source_inventory_consistent'])

    def test_37_real_old_root_ed25519_bad_signature_denied_with_matching_sha(self):
        old=copy.deepcopy(self.sources['a']['old'])
        receiver=copy.deepcopy(self.sources['a']['receiver'])
        doc=json.loads(Path(self.sources['a']['rootref']['path']).read_text())
        doc['signature_ed25519_hex']='f'*128
        forged=self.store('ec375_forged_but_consistent_sha_root_original',doc)
        receiver['root_reference_signed_original']=forged
        old['root_reference']=self.old_label(forged)
        with self.assertRaises(errors.AnchorError):
            core._root_channel(0,'a',old,receiver,
                lambda ref,role,cap:Path(ref['path']).read_bytes(),set(),
                core.tr._utc(util.EV))

    def test_38_real_old_channel_ed25519_bad_signature_denied_with_matching_sha(self):
        old=copy.deepcopy(self.sources['a']['old'])
        receiver=copy.deepcopy(self.sources['a']['receiver'])
        doc=json.loads(Path(self.sources['a']['auth']['path']).read_text())
        doc['signature_ed25519_hex']='f'*128
        forged=self.store('ec375_forged_but_consistent_sha_authorization',doc)
        receiver['channel_authorization_signed_original']=forged
        old['channel_authorization']=self.old_label(forged)
        with self.assertRaises(errors.AnchorError):
            core._root_channel(0,'a',old,receiver,
                lambda ref,role,cap:Path(ref['path']).read_bytes(),set(),
                core.tr._utc(util.EV))

    def test_39_real_old_ack_ed25519_bad_signature_denied_with_matching_sha(self):
        old=copy.deepcopy(self.sources['a']['old'])
        receiver=copy.deepcopy(self.sources['a']['receiver'])
        doc=json.loads(Path(self.sources['a']['ack']['path']).read_text())
        doc['signature_ed25519_hex']='f'*128
        forged=self.store('ec375_forged_but_consistent_sha_signed_ack',doc)
        receiver['acknowledgements'][0]['acknowledgement_signed_original']=forged
        receiver['selected_ack_head_sha256']=forged['sha256']
        old['acknowledgements'][0]['acknowledgement']=self.old_label(forged)
        read=lambda ref,role,cap:Path(ref['path']).read_bytes()
        actor=core._root_channel(0,'a',old,receiver,read,set(),core.tr._utc(util.EV))
        with self.assertRaises(errors.AnchorError):
            core._acks(0,'a',old,receiver,actor,read,core.tr._utc(util.EV))

    def argv(self,unified=False,derive=False):
        from publication_accountability import accountability as p370
        from historical_archive import archive as p371
        from historical_authority import authority_archive as p372
        from historical_inclusion import inclusion_archive as p373
        from historical_owner import owner_archive as p374
        opts=self.options(expected_retained_historical_custody_inventory_sha256=
             self.derive()['receiver_verified_historical_custody_inventory_sha256'])
        command='derive-historical-custody-inventory' if derive else 'audit-historical-custody-archive'
        argv=[sys.executable,'-I','-B',str(ROOT/'scripts'/(
              'ces_next.py' if unified else 'ces_cas_historical_custody_archive.py')),
              command]
        if unified:argv+=['DeliveryAudit','AuditHistoricalCustodyArchive']
        scalars=(*p370.prior.SCALARS,*p370.NEW_SCALARS,
                 *p371.NEW_SCALARS,*p371.AUDIT_ONLY,
                 *p372.NEW_SCALARS,*p372.AUDIT_ONLY,
                 *p373.NEW_SCALARS,*p373.AUDIT_ONLY,
                 *p374.NEW_SCALARS,*p374.AUDIT_ONLY,*core.NEW_SCALARS)
        if not derive:scalars+=core.AUDIT_ONLY
        for key in scalars:argv.extend(['--'+key.replace('_','-'),str(opts[key])])
        for key,flag in (*p370.prior.REPEATS,*p370.NEW_REPEATS,
                         *p371.NEW_REPEATS,*p372.NEW_REPEATS,
                         *p373.NEW_REPEATS,*p374.NEW_REPEATS,*core.NEW_REPEATS):
            for value in opts[key]:argv.extend([flag,'none' if value is None else str(value)])
        return argv

    def test_25_genuine_isolated_unified_ec374_through_ec369(self):
        proc=subprocess.run(self.argv(unified=True),capture_output=True,text=True,timeout=180)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[:1500])
        d=json.loads(proc.stdout)
        self.assertTrue(d['local_pinned_historical_custody_signatures_and_source_inventory_consistent'])
        self.assertTrue(d[core.FLAGS[-1]])

    def test_26_genuine_isolated_standalone_unsigned_derive(self):
        proc=subprocess.run(self.argv(derive=True),capture_output=True,text=True,timeout=180)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[:1500])
        self.assertEqual(json.loads(proc.stdout)['schema'],core.DERIVE_SCHEMA)

    def test_27_unified_original_tamper_isolated_child_denied(self):
        argv=self.argv(unified=True)
        Path(self.sources['a']['ack']['path']).write_bytes(b'BAD_OLD_ACK')
        proc=subprocess.run(argv,capture_output=True,text=True,timeout=180)
        self.assertIn(proc.returncode,(3,4,5),proc.stderr+' '+proc.stdout[:1300])
        doc=json.loads(proc.stdout)
        self.assertEqual(doc['schema'],core.DENIAL_SCHEMA)
        self.assertFalse(doc['sender_origin_path_required_or_read'])

if __name__=='__main__':unittest.main()
