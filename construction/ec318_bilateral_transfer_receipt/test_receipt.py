#!/usr/bin/env python3
"""EC318 focused real-Ed25519 signed transfer fixture, no mocked historical PASS."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from ec295_delivery_anchor import anchor as a
from ec302_portable_bundle import bundle as b
from ec317_original_rebinding import test_rebinding as original_fixture
from . import receipt as r

ROOT = Path(__file__).resolve().parents[2]


class EC318BilateralOriginalTransferCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original_fixture.EC317OriginalSHARebindingCases.setUpClass()
        try:
            cls.base = original_fixture.EC317OriginalSHARebindingCases
            cls.site = tempfile.TemporaryDirectory(prefix='ces-ec318-receiver-')
            cls.received = str(Path(cls.site.name) / 'independent-transfer.zip')
            shutil.copyfile(cls.base.bundle,cls.received)
            os.chmod(cls.received,0o600)
            cls.keys = {role:Ed25519PrivateKey.generate()
                        for role in ('sender','receiver')}
            cls.context = dict(cls.base.context)
            cls.context.update(bundle_file=cls.received,
                expected_bundle_sha256=cls.base.exported['bundle_original_raw_sha256'],
                sender_id='ec318_offline_sender',
                receiver_id='ec318_offline_receiver',
                sender_exchange_challenge_sha256='93'*32,
                receiver_exchange_challenge_sha256='94'*32)
            for role in cls.keys:
                cls.context[role+'_public_hex']=cls.keys[role].public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw).hex()
                raw=cls.keys[role].private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption())
                path=Path(cls.site.name) / (role+'-private.bin')
                path.write_bytes(raw)
                path.chmod(0o600)
                setattr(cls,role+'_private',str(path))
            cls.offer=str(Path(cls.site.name)/'sender-offer.json')
            cls.ack=str(Path(cls.site.name)/'receiver-ack.json')
            cls.closure=str(Path(cls.site.name)/'sender-closure.json')
            cls.confirm_challenge='95'*32
            cls.offered=r.sender_offer(private_key_file=cls.sender_private,
                                       out=cls.offer,**cls.context)
            cls.offer_pin=b.digest(Path(cls.offer).read_bytes())
            cls.accepted=r.receiver_ack(offer_file=cls.offer,
                expected_offer_sha256=cls.offer_pin,
                private_key_file=cls.receiver_private,out=cls.ack,**cls.context)
            cls.ack_pin=b.digest(Path(cls.ack).read_bytes())
            cls.confirmed=r.sender_confirm(offer_file=cls.offer,
                expected_offer_sha256=cls.offer_pin,
                ack_file=cls.ack,expected_ack_sha256=cls.ack_pin,
                sender_confirmation_challenge_sha256=cls.confirm_challenge,
                private_key_file=cls.sender_private,out=cls.closure,**cls.context)
            cls.close_pin=b.digest(Path(cls.closure).read_bytes())
        except BaseException:
            if hasattr(cls,'site'):
                cls.site.cleanup()
            original_fixture.EC317OriginalSHARebindingCases.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.site.cleanup()
        original_fixture.EC317OriginalSHARebindingCases.tearDownClass()

    def _verify(self, **change):
        args=dict(self.context,offer_file=self.offer,
            expected_offer_sha256=self.offer_pin,ack_file=self.ack,
            expected_ack_sha256=self.ack_pin,closure_file=self.closure,
            expected_closure_sha256=self.close_pin,
            sender_confirmation_challenge_sha256=self.confirm_challenge)
        args.update(change)
        return r.verify(**args)

    def _cli_args(self):
        c=self.context
        fields=['--bundle-file',c['bundle_file'],
            '--expected-bundle-sha256',c['expected_bundle_sha256'],
            '--chain-file',c['chain_file'],
            '--expected-chain-sha256',c['expected_chain_sha256'],
            '--ledger-manifest-file',c['ledger_manifest_file'],
            '--expected-ledger-manifest-sha256',c['expected_ledger_manifest_sha256'],
            '--expected-latest-certificate-sha256',c['expected_latest_certificate_sha256'],
            '--expected-latest-challenge-sha256',c['expected_latest_challenge_sha256']]
        for role in ('a','b'):
            fields+=['--custodian-'+role+'-id',c['trust']['custodian_'+role+'_id'],
                     '--custodian-'+role+'-public-hex',
                     c['trust']['custodian_'+role+'_public_hex']]
        for name in ('sender_id','sender_public_hex','receiver_id',
                     'receiver_public_hex','sender_exchange_challenge_sha256',
                     'receiver_exchange_challenge_sha256'):
            fields+=['--'+name.replace('_','-'),c[name]]
        fields+=['--sender-confirmation-challenge-sha256',self.confirm_challenge,
                 '--offer-file',self.offer,'--expected-offer-sha256',self.offer_pin,
                 '--ack-file',self.ack,'--expected-ack-sha256',self.ack_pin,
                 '--closure-file',self.closure,'--expected-closure-sha256',self.close_pin]
        return fields

    def test_01_real_distinct_sender_and_receiver_ed25519_handshake(self):
        self.assertEqual(self.offered['exit_code'],0)
        self.assertEqual(self.accepted['exit_code'],0)
        self.assertEqual(self.confirmed['exit_code'],0)
        self.assertEqual(self.offered['offer_original_raw_sha256'],self.offer_pin)
        self.assertEqual(self.accepted['ack_original_raw_sha256'],self.ack_pin)
        self.assertEqual(self.confirmed['closure_original_raw_sha256'],self.close_pin)
        self.assertGreater(self.offered['source_reference_count'],10)
        # The old absolute path tree can be physically absent on receiver site.
        source=self.base.parent.owner
        offline=source.with_name(source.name+'-ec318-isolated')
        os.rename(source,offline)
        try:
            done=self._verify()
        finally:
            os.rename(offline,source)
        self.assertEqual(done['status'],
            'three_authentic_bilateral_signatures_and_every_original_replay_valid')
        self.assertTrue(done['original_ec316_to_ec294_signatures_fully_replayed'])
        self.assertFalse(done['physical_transfer_or_external_durable_receipt_proven'])
        self.assertFalse(done['global_latest_or_business_write_proven'])

    def test_02_sender_or_receiver_forged_signature_fails_even_if_repinned(self):
        for name,path,pin,bad_role in (
            ('offer',self.offer,self.offer_pin,'sender_signature_ed25519'),
            ('ack',self.ack,self.ack_pin,'receiver_signature_ed25519'),
            ('closure',self.closure,self.close_pin,'sender_signature_ed25519')):
            doc=json.loads(Path(path).read_bytes())
            doc[bad_role]='0'*128
            forged=Path(self.site.name) / ('forged-'+name+'.json')
            forged.write_bytes(r.canonical(doc)+b'\n')
            forged.chmod(0o600)
            forged_pin=b.digest(forged.read_bytes())
            if name=='offer':
                with self.assertRaisesRegex(a.AnchorError,'OFFER_SIGNATURE_NOT_AUTHENTIC'):
                    r._verify_offer(str(forged),forged_pin,json.loads(
                        Path(self.offer).read_bytes())['binding'])
            elif name=='ack':
                with self.assertRaisesRegex(a.AnchorError,'ACK_SIGNATURE_NOT_AUTHENTIC'):
                    r._verify_ack(str(forged),forged_pin,json.loads(
                        Path(self.offer).read_bytes())['binding'],self.offer_pin)
            else:
                with self.assertRaisesRegex(a.AnchorError,'CLOSE_SIGNATURE_NOT_AUTHENTIC'):
                    r._verify_close(str(forged),forged_pin,json.loads(
                        Path(self.offer).read_bytes())['binding'],self.offer_pin,
                        self.ack_pin,self.confirm_challenge)

    def test_03_replaced_ack_anchored_to_other_offer_rejected(self):
        forged=json.loads(Path(self.ack).read_bytes())
        forged['claim']['offer_original_raw_sha256']='8'*64
        path=Path(self.site.name)/'swapped-ack.json'
        path.write_bytes(r.canonical(forged)+b'\n')
        path.chmod(0o600)
        with self.assertRaisesRegex(a.AnchorError,'ACK_DOES_NOT_REFERENCE'):
            r._verify_ack(str(path),b.digest(path.read_bytes()),
                json.loads(Path(self.offer).read_bytes())['binding'],self.offer_pin)

    def test_04_output_key_and_challenge_denied_before_signing(self):
        target=str(Path(self.site.name)/'not-created.json')
        with self.assertRaisesRegex(a.AnchorError,'OUTPUT_MUST_BE_NEW'):
            r.sender_offer(private_key_file=self.sender_private,
                           out=self.offer,**self.context)
        self.assertFalse(Path(target).exists())
        context=dict(self.context,receiver_public_hex=self.context['sender_public_hex'])
        with self.assertRaisesRegex(a.AnchorError,'FOUR_DISTINCT_VALID'):
            r.sender_offer(private_key_file=self.sender_private,out=target,**context)
        self.assertFalse(Path(target).exists())
        context=dict(self.context,receiver_exchange_challenge_sha256=
                     self.context['sender_exchange_challenge_sha256'])
        with self.assertRaisesRegex(a.AnchorError,'THREE_DISTINCT'):
            r.sender_offer(private_key_file=self.sender_private,out=target,**context)
        self.assertFalse(Path(target).exists())
        with self.assertRaisesRegex(a.AnchorError,'FOURTH_DISTINCT'):
            r._close_claim(json.loads(Path(self.offer).read_bytes())['binding'],
                self.offer_pin,self.ack_pin,self.context['sender_exchange_challenge_sha256'])

    def test_05_unified_console_only_verify_no_sign_or_out(self):
        cli=ROOT/'scripts'/'ces_next.py'
        args=['audit-transfer','DeliveryAudit','VerifyBilateralTransferReceipt',
              *self._cli_args()]
        good=subprocess.run([sys.executable,'-B',str(cli),*args],
                            capture_output=True,text=True,timeout=220)
        self.assertEqual(good.returncode,0,good.stdout+good.stderr)
        answer=json.loads(good.stdout)
        self.assertEqual(answer['closure_original_raw_sha256'],self.close_pin)
        forbidden=str(Path(self.site.name)/'console-unauthorized.json')
        denied=subprocess.run([sys.executable,'-B',str(cli),*args,'--out',forbidden],
                              capture_output=True,text=True)
        self.assertNotEqual(denied.returncode,0)
        self.assertFalse(Path(forbidden).exists())
        wrong=subprocess.run([sys.executable,'-B',str(cli),
            'audit-transfer','DeliveryAudit','Sign',*self._cli_args()],
            capture_output=True,text=True)
        self.assertEqual(wrong.returncode,3)
        self.assertFalse(json.loads(wrong.stdout)['permissions_granted'])

    def test_06_wrong_external_ledger_and_signature_sha_do_not_pass(self):
        with self.assertRaises((a.AnchorError,)):
            self._verify(expected_offer_sha256='9'*64)
        with self.assertRaises((a.AnchorError,)):
            self._verify(expected_latest_certificate_sha256='8'*64)
