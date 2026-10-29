#!/usr/bin/env python3
"""EC322 real fifth/sixth/seventh Ed25519 structural cases.

The inherited EC321 fixture intentionally mocks its costly EC317 and EC318
original verification. This suite must NOT be reported as a full inherited
EC294->EC318 authentic chain integration run; production code never mocks it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from scripts import ces_next as console

from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport.test_case_structure import PortableCaseGenuineSignerStructureCases
from . import ack


def pub(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


class SeventhIndependentReceiverAckCases(unittest.TestCase):
    def setUp(self):
        # Reuse exactly the genuine fifth/sixth signed fixture from EC321.
        self.f=PortableCaseGenuineSignerStructureCases(methodName=
            'test_full_portable_case_export_import_with_real_fifth_and_sixth_signatures')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        exported=self.f.export_case()
        self.case_sha=exported['case_bundle_original_raw_sha256']
        self.key=Ed25519PrivateKey.generate()
        self.receiver_pub=pub(self.key)
        self.key_path=self.f.write('seventh-private.bin',self.key.private_bytes_raw())
        self.ack_file=str(self.f.dir/'seventh-signed-receipt.json')
        self.inputs=dict(self.f.pins,ack_id='received_case_322',
            seventh_receiver_id='seventh_external_receiver',
            seventh_receiver_public_hex=self.receiver_pub,
            seventh_receiver_challenge_sha256='ea'*32,
            bundle_file=self.f.case_file,
            expected_bundle_sha256=self.case_sha)

    def issue(self,**changes):
        return ack.attest(private_key_file=self.key_path,out=self.ack_file,
            **dict(self.inputs,**changes))

    def check(self,receipt_sha,**changes):
        return ack.verify(ack_file=self.ack_file,
            expected_ack_sha256=receipt_sha,**dict(self.inputs,**changes))

    def rewrite(self,fn):
        original=json.loads(Path(self.ack_file).read_bytes())
        fn(original)
        raw=reg.raw_doc(original)
        self.f.write('tampered-seventh-ack.json',raw)
        return str(self.f.dir/'tampered-seventh-ack.json'),ack.case.sha(raw)

    def test_true_seventh_signed_ack_and_independent_original_case_replay(self):
        signed=self.issue()
        self.assertEqual(signed['exit_code'],2)
        self.assertTrue(signed['seventh_receiver_ed25519_signature_verified'])
        self.assertFalse(signed['external_cas_latest_or_fork_winner_proven'])
        verified=self.check(signed['signed_receiver_ack_original_raw_sha256'])
        self.assertEqual(verified['status'],
            'independent_seventh_signature_and_entire_original_fork_case_reverified')
        self.assertEqual(verified['fork_sequence'],1)
        self.assertEqual(os.stat(self.ack_file).st_mode & 0o777,0o600)
        doc=json.loads(Path(self.ack_file).read_bytes())
        self.assertFalse(doc['claim']['winner_selected'])
        self.assertEqual(doc['claim']['replayed_signed_fork_evidence']['left_registration_count'],1)

    def test_receipt_replay_after_original_exporter_files_and_key_deleted(self):
        signed=self.issue()
        for name in (self.f.witness_file,self.f.left_snapshot,
                     self.f.right_snapshot,self.f.left_map,self.f.right_map,
                     self.f.bundle,self.key_path):
            Path(name).unlink()
        self.assertEqual(self.check(signed['signed_receiver_ack_original_raw_sha256'])['exit_code'],2)

    def test_seventh_signer_must_not_reuse_sixth_or_existing_sender_identity(self):
        for changes in (
            dict(seventh_receiver_id=self.f.pins['witness_id']),
            dict(seventh_receiver_public_hex=self.f.pins['witness_public_hex']),
            dict(seventh_receiver_id=self.f.left_claim['sender_id']),
            dict(seventh_receiver_public_hex=self.f.pub['receiver']),
            dict(seventh_receiver_id=self.f.registrar_id),
            dict(seventh_receiver_public_hex=self.f.pub['custodian_a'])):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(anchor.AnchorError,'SEVENTH_SIGNER_ID_AND_PUBLIC_KEY'):
                    self.issue(**changes)
        self.assertFalse(Path(self.ack_file).exists())

    def test_challenge_must_not_reuse_any_visible_historical_or_sixth(self):
        for nonce in (self.f.pins['witness_challenge_sha256'],
                      self.f.left_claim['receiver_exchange_challenge_sha256'],
                      self.f.right_claim['registrar_entry_challenge_sha256'],
                      '7'*64,'4'*64,self.case_sha):
            with self.subTest(nonce=nonce):
                with self.assertRaisesRegex(anchor.AnchorError,'CHALLENGE_REUSES'):
                    self.issue(seventh_receiver_challenge_sha256=nonce)
        self.assertFalse(Path(self.ack_file).exists())

    def test_a_bad_original_crypto_replay_denies_signing_before_private_key_read(self):
        with patch.object(reg.receipt,'verify',side_effect=anchor.AnchorError(
                'OLD_EC318_REPLAY_REJECTED', 'permission_denied')):
            with patch('ec322_receiver_fork_ack.ack.io.private_from_file',
                       side_effect=AssertionError('PRIVATE_KEY_READ_BEFORE_HISTORY_VERIFIED')):
                with self.assertRaisesRegex(anchor.AnchorError,'OLD_EC318_REPLAY_REJECTED'):
                    self.issue()
        self.assertFalse(Path(self.ack_file).exists())

    def test_wrong_signer_private_key_is_not_accepted_and_no_output(self):
        bad=Ed25519PrivateKey.generate()
        self.f.write('wrong-private.bin',bad.private_bytes_raw())
        with self.assertRaisesRegex(anchor.AnchorError,'PRIVATE_KEY_NOT_MATCH'):
            ack.attest(private_key_file=str(self.f.dir/'wrong-private.bin'),
                out=self.ack_file,**self.inputs)
        self.assertFalse(Path(self.ack_file).exists())

    def test_prior_output_is_not_overwritten_even_on_correct_case(self):
        self.f.write('seventh-signed-receipt.json',b'original unrelated bytes')
        with self.assertRaisesRegex(anchor.AnchorError,'OUTPUT_MUST_NOT_ALREADY_EXIST'):
            self.issue()
        self.assertEqual(Path(self.ack_file).read_bytes(),b'original unrelated bytes')

    def test_verify_requires_independent_whole_original_ack_sha(self):
        signed=self.issue()
        with self.assertRaisesRegex(anchor.AnchorError,'RAW_BYTES_DIFFER_FROM_EXTERNAL_PIN'):
            self.check('f0'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'ACK_NOT_EQUAL_EXTERNALLY_SELECTED'):
            self.check(signed['signed_receiver_ack_original_raw_sha256'],
                seventh_receiver_challenge_sha256='fb'*32)

    def test_tampered_signature_with_whole_ack_repin_is_rejected(self):
        self.issue()
        file,sha=self.rewrite(lambda d:d.__setitem__('signature_ed25519','0'*128))
        with self.assertRaisesRegex(anchor.AnchorError,'SIGNATURE_NOT_AUTHENTIC'):
            ack.verify(ack_file=file,expected_ack_sha256=sha,**self.inputs)

    def test_rewritten_signed_claim_with_whole_ack_repin_is_rejected(self):
        self.issue()
        def manipulate(d):d['claim']['winner_selected']=True
        file,sha=self.rewrite(manipulate)
        with self.assertRaisesRegex(anchor.AnchorError,'CLAIM_SCOPE_MUST_NOT_PRETEND'):
            ack.verify(ack_file=file,expected_ack_sha256=sha,**self.inputs)

    def test_different_original_case_or_wrong_independent_pin_rejected(self):
        signed=self.issue()
        with self.assertRaisesRegex(anchor.AnchorError,'ACK_NOT_EQUAL_EXTERNALLY_SELECTED'):
            self.check(signed['signed_receiver_ack_original_raw_sha256'],
                case_id='different_case_322')
        with self.assertRaisesRegex(anchor.AnchorError,'ACK_NOT_EQUAL_EXTERNALLY_SELECTED'):
            self.check(signed['signed_receiver_ack_original_raw_sha256'],
                expected_bundle_sha256='ff'*32)

    def test_replay_failure_denies_even_authentic_ack_signature(self):
        signed=self.issue()
        with patch.object(reg.receipt,'verify',side_effect=anchor.AnchorError(
                'ORIGINAL_RECEIPT_AUTHENTICITY_FAILED','permission_denied')):
            with self.assertRaisesRegex(anchor.AnchorError,'ORIGINAL_RECEIPT_AUTHENTICITY_FAILED'):
                self.check(signed['signed_receiver_ack_original_raw_sha256'])

    def test_requires_canonical_and_private_original_ack_file(self):
        signed=self.issue()
        Path(self.ack_file).chmod(0o644)
        with self.assertRaisesRegex(anchor.AnchorError,'OWNER_0600_ONE_REGULAR_LINK_REQUIRED'):
            self.check(signed['signed_receiver_ack_original_raw_sha256'])

    def test_console_denies_any_mode_other_than_the_single_read_only_verify(self):
        params=dict(self.inputs,ack_file=self.ack_file,
                    expected_ack_sha256='d9'*32)
        with patch.object(console,'_command',side_effect=AssertionError(
                'UNAUTHORIZED_VERIFICATION_PROCESS_LAUNCHED')):
            with self.assertRaisesRegex(console.ConsoleError,
                                        'ONLY_DELIVERYAUDIT_VERIFY_SEVENTH'):
                console.audit_seventh_fork_ack('DeliveryAudit','Attest',**params)
            with self.assertRaisesRegex(console.ConsoleError,
                                        'ONLY_DELIVERYAUDIT_VERIFY_SEVENTH'):
                console.audit_seventh_fork_ack('CodeSave',
                    'VerifySeventhReceiverForkAck',**params)

    def test_console_fixed_child_uses_verify_only_and_rejects_unknown_reply(self):
        params=dict(self.inputs,ack_file=self.ack_file,
                    expected_ack_sha256='d9'*32)
        calls=[]
        def child(argv,*,timeout,max_output):
            calls.append((argv,timeout,max_output))
            return 2,{'schema':ack.RESULT_SCHEMA,'command':'attest',
                      'exit_code':2,'status':'fake_untrusted_output'}
        with patch.object(console,'_command',side_effect=child):
            with self.assertRaisesRegex(console.ConsoleError,
                                        'ACK_VERIFY_REPLY_INCONSISTENT'):
                console.audit_seventh_fork_ack('DeliveryAudit',
                    'VerifySeventhReceiverForkAck',**params)
        args,timeout,limit=calls[0]
        self.assertEqual(args[:4],[
            console.sys.executable,'-I','-B',str(console.SEVENTH_FORK_ACK)])
        self.assertEqual(args[4],'verify')
        self.assertNotIn('attest',args)
        self.assertNotIn('--private-key-file',args)
        self.assertNotIn('--out',args)
        self.assertEqual(timeout,3600)
        self.assertLessEqual(limit,30000)

    def test_renamed_seventh_identity_with_same_ack_rejected(self):
        signed=self.issue()
        with self.assertRaisesRegex(anchor.AnchorError,'ACK_NOT_EQUAL_EXTERNALLY_SELECTED'):
            self.check(signed['signed_receiver_ack_original_raw_sha256'],
                seventh_receiver_id='other_seventh_receiver')


if __name__=='__main__':
    unittest.main()
