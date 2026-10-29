#!/usr/bin/env python3
"""EC303 focused genuine original EC294..302 proof replay, without fake live sites."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from delivery_anchor import anchor as a
from portable_bundle import bundle as b
from offline_handoff.test_handoff import EC301HandoffCases as Parent
from . import ack as r

ROOT=Path(__file__).resolve().parents[2]


class EC303ReceiverAckCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Parent.setUpClass()
        try:
            cls.parent=Parent
            cls.tmp=tempfile.TemporaryDirectory(prefix='ec303-receipt-')
            cls.home=Path(cls.tmp.name)
            cls.pins={'a_id':Parent.keys.id_a,'a_public_hex':Parent.keys.pub_a,
                      'a_tip':Parent.keys.a2['sha'],
                      'b_id':Parent.keys.id_b,'b_public_hex':Parent.keys.pub_b,
                      'b_tip':Parent.keys.b1['sha'],
                      'session_tip':Parent.parent.s2,'receipt_tip':Parent.sr2}
            cls.archive=cls.home/'bundle.zip'
            cls.export=b.build_bundle(Parent.journal2,cls.pins,str(cls.archive))
            assert cls.export['exit_code']==0
            cls.imported=cls.home/'received-proof'
            b.verify_bundle(str(cls.archive),cls.export['bundle_sha256'],cls.pins,
                            destination=str(cls.imported))
            cls.key=Ed25519PrivateKey.generate()
            cls.pub=cls.key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw).hex()
            cls.private=cls.home/'independent-receiver.key'
            cls.private.write_bytes(cls.key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()))
            cls.private.chmod(0o600)
            cls.context={'bundle_file':str(cls.archive),
                         'expected_bundle_sha256':cls.export['bundle_sha256'],
                         'pins':cls.pins,
                         'sender_id':'source-01','receiver_id':'destination-02',
                         'receiver_public_hex':cls.pub,'challenge_sha256':'5'*64}
            cls.out=cls.home/'receiver-ack.json'
            cls.sent=r.issue_ack(**cls.context,imported_dir=str(cls.imported),
                                 receiver_private_key_file=str(cls.private),out=str(cls.out))
        except BaseException:
            if hasattr(cls,'tmp'):cls.tmp.cleanup()
            Parent.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        Parent.tearDownClass()

    def verification(self, **kwargs):
        params={**self.context, 'acknowledgement_file':str(self.out),
                'expected_acknowledgement_sha256':self.sent['acknowledgement_sha256']}
        return r.verify_ack(**{**params,**kwargs})

    def _key(self, filename):
        key=Ed25519PrivateKey.generate()
        p=self.home/filename
        p.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()))
        p.chmod(0o600)
        return p

    def _issue(self, filename, **kwargs):
        return r.issue_ack(**{**self.context,**kwargs},
                           imported_dir=str(self.imported),
                           receiver_private_key_file=str(self.private),
                           out=str(self.home/filename))

    def _cli_flags(self):
        flags=[]
        for k,val in self.pins.items():
            flags += ['--expected-'+k.replace('_','-'),val]
        for k,val in (('bundle-file',str(self.archive)),
                      ('expected-bundle-sha256',self.export['bundle_sha256']),
                      ('expected-sender-id','source-01'),
                      ('expected-receiver-id','destination-02'),
                      ('expected-receiver-public-hex',self.pub),
                      ('expected-exchange-challenge-sha256','5'*64)):
            flags += ['--'+k,val]
        return flags

    def test_01_real_import_byte_identity_and_domain_separated_signed_receipt(self):
        response=self.verification()
        self.assertEqual(response['exit_code'],0)
        self.assertEqual(response['report_sha256'],self.export['report_sha256'])
        self.assertEqual(self.sent['evidence_document_count'],28)
        self.assertEqual(os.stat(self.out).st_mode & 0o777,0o600)
        self.assertNotIn(b'private_key',self.out.read_bytes())
        self.assertNotIn(str(self.imported).encode(),self.out.read_bytes())
        self.assertTrue(json.loads(self.out.read_bytes())['claim']['private_import_byte_identity_reverified'])

    def test_02_wrong_independent_bundle_pin_or_witness_tip_denied_before_signing(self):
        with self.assertRaisesRegex(a.AnchorError,'EXTERNAL_BUNDLE_SHA_MISMATCH'):
            self._issue('forged-bundle.json',expected_bundle_sha256='1'*64)
        with self.assertRaisesRegex(a.AnchorError,'MANIFEST_IDENTITY_PINS'):
            self._issue('forged-ec301.json',pins=self.pins|{'receipt_tip':'6'*64})
        self.assertFalse((self.home/'forged-bundle.json').exists())
        self.assertFalse((self.home/'forged-ec301.json').exists())

    def test_03_tampered_imported_leaf_or_extra_file_blocks_ack(self):
        leaf=self.imported/'docs'/'0002.json'
        raw=leaf.read_bytes()
        leaf.write_bytes(raw+b' ')
        try:
            with self.assertRaisesRegex(a.AnchorError,'IMPORTED_MATERIAL_DIFFERS'):
                self._issue('changed-data.json')
        finally:
            leaf.write_bytes(raw)
        junk=self.imported/'docs'/'secret-key.txt'
        junk.write_text('nothing',encoding='utf8')
        try:
            with self.assertRaisesRegex(a.AnchorError,'EXTRA_OR_MISSING'):
                self._issue('extra-data.json')
        finally:
            junk.unlink()
        self.assertFalse((self.home/'changed-data.json').exists())

    def test_04_reject_symlink_file_permissions_and_nonprivate_import(self):
        leaf=self.imported/'docs'/'0002.json'
        leaf.chmod(0o644)
        try:
            with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OWNER_0600'):
                self._issue('unsafe-file.json')
        finally:
            leaf.chmod(0o600)
        original=leaf.read_bytes()
        leaf.unlink()
        target=self.home/'same-bytes-elsewhere.json'
        target.write_bytes(original);target.chmod(0o600)
        leaf.symlink_to(target)
        try:
            with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OWNER_0600'):
                self._issue('unsafe-symlink.json')
        finally:
            leaf.unlink();leaf.write_bytes(original);leaf.chmod(0o600)
        self.assertFalse((self.home/'unsafe-file.json').exists())
        self.assertFalse((self.home/'unsafe-symlink.json').exists())

    def test_05_original_signer_keys_forbidden_and_private_key_mismatch(self):
        with self.assertRaisesRegex(a.AnchorError,'SEPARATE_INDEPENDENT_RECEIVER'):
            self._issue('same-witness-key.json',receiver_public_hex=self.pins['a_public_hex'])
        wrong=self._key('another-receiver.key')
        with self.assertRaisesRegex(a.AnchorError,'RECEIVER_PRIVATE_KEY_NOT_EQUAL'):
            r.issue_ack(**self.context,imported_dir=str(self.imported),
                        receiver_private_key_file=str(wrong),out=str(self.home/'wrong-key.json'))
        self.assertFalse((self.home/'wrong-key.json').exists())

    def test_06_receipt_signing_is_outside_import_and_exclusive(self):
        with self.assertRaisesRegex(a.AnchorError,'ACK_DESTINATION_MUST_BE_NEW'):
            self._issue('receiver-ack.json')
        with self.assertRaisesRegex(a.AnchorError,'ACK_DESTINATION_MUST_BE_NEW'):
            r.issue_ack(**self.context,imported_dir=str(self.imported),
                        receiver_private_key_file=str(self.private),
                        out=str(self.imported/'other.json'))
        self.assertFalse((self.imported/'other.json').exists())

    def test_07_unsigned_changes_denied_even_with_new_raw_sha_pin(self):
        doc=json.loads(self.out.read_bytes())
        doc['claim']['receiver_id']='someone-else'
        changed=self.home/'changed-receipt.json'
        changed.write_bytes(b.canonical(doc));changed.chmod(0o600)
        with self.assertRaisesRegex(a.AnchorError,'RECEIVER_ED25519_SIGNATURE_INVALID'):
            self.verification(acknowledgement_file=str(changed),
                              expected_acknowledgement_sha256=b.digest(changed.read_bytes()))
        with self.assertRaisesRegex(a.AnchorError,'ACKNOWLEDGEMENT_NOT_EQUAL_EXTERNAL_RAW'):
            self.verification(expected_acknowledgement_sha256='7'*64)

    def test_08_correct_signature_cannot_authenticate_wrong_out_of_band_challenge_or_receiver(self):
        with self.assertRaisesRegex(a.AnchorError,'SIGNED_ACK_NOT_EQUAL'):
            self.verification(challenge_sha256='7'*64)
        with self.assertRaisesRegex(a.AnchorError,'SIGNED_ACK_NOT_EQUAL'):
            self.verification(sender_id='other-origin')
        with self.assertRaisesRegex(a.AnchorError,'RECEIVER_ED25519_SIGNATURE_INVALID'):
            self.verification(receiver_public_hex=Ed25519PrivateKey.generate().public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw).hex())

    def test_09_standalone_cli_verify_and_issue_flow(self):
        cli=ROOT/'scripts'/'ces_bundle_ack.py'
        flags=self._cli_flags()
        ver=[sys.executable,'-I','-B',str(cli),'verify',*flags,
             '--acknowledgement-file',str(self.out),
             '--expected-acknowledgement-sha256',self.sent['acknowledgement_sha256']]
        run=subprocess.run(ver,text=True,capture_output=True,timeout=180)
        self.assertEqual(run.returncode,0,run.stdout+'\n'+run.stderr)
        reply=json.loads(run.stdout)
        self.assertTrue(reply['original_ec301_to_ec294_signatures_reverified'])
        self.assertFalse(reply['cross_site_transport_or_human_independence_proven'])
        issue=[sys.executable,'-I','-B',str(cli),'issue',*flags,
               '--imported-dir',str(self.imported),
               '--receiver-private-key-file',str(self.private),
               '--out',str(self.home/'issued-with-cli.json')]
        run=subprocess.run(issue,text=True,capture_output=True,timeout=180)
        self.assertEqual(run.returncode,0,run.stdout+'\n'+run.stderr)
        self.assertEqual(json.loads(run.stdout)['acknowledgement_sha256'],self.sent['acknowledgement_sha256'])

    def test_10_read_only_unified_console_and_original_router_74_11_preserved(self):
        cli=ROOT/'scripts'/'ces_next.py'
        flags=self._cli_flags()+[
            '--acknowledgement-file',str(self.out),
            '--expected-acknowledgement-sha256',self.sent['acknowledgement_sha256']]
        ver=[sys.executable,'-I','-B',str(cli),'audit-ack',
             'DeliveryAudit','VerifyBundleAcknowledgement',*flags]
        run=subprocess.run(ver,text=True,capture_output=True,timeout=180)
        self.assertEqual(run.returncode,0,run.stdout+'\n'+run.stderr)
        self.assertEqual(json.loads(run.stdout)['exit_code'],0)
        denied=ver.copy()
        denied[denied.index('VerifyBundleAcknowledgement')]='SignAcknowledgement'
        run=subprocess.run(denied,text=True,capture_output=True,timeout=45)
        self.assertEqual(run.returncode,3)
        self.assertEqual(json.loads(run.stdout)['status'],'permission_denied')
        run=subprocess.run([sys.executable,'-I','-B',str(cli),'doctor'],
                           text=True,capture_output=True,timeout=45)
        self.assertEqual(run.returncode,0,run.stderr)
        doc=json.loads(run.stdout)
        self.assertEqual(doc['router_registered_routes'],74)
        self.assertTrue(doc['ec303_offline_independent_receiver_ack_client_present'])
        self.assertFalse(doc['ec303_real_human_receipt_external_challenge_or_immutable_custody_verified'])


if __name__=='__main__':unittest.main()
