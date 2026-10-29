#!/usr/bin/env python3
"""EC319 tests use the *actual* EC318->EC294 original signed fixture, not PASS mocks."""
from __future__ import annotations

import copy
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
from bilateral_transfer_receipt import test_receipt as prior_fixture
from bilateral_transfer_receipt import receipt as r
from . import registry as reg

ROOT = Path(__file__).resolve().parents[2]


class EC319SignedOfflineRegistryCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prior_fixture.EC318BilateralOriginalTransferCases.setUpClass()
        cls.parent = prior_fixture.EC318BilateralOriginalTransferCases
        try:
            cls.private = tempfile.TemporaryDirectory(prefix='ces-ec319-registry-')
            cls.site = Path(cls.private.name)
            cls.private_key = Ed25519PrivateKey.generate()
            cls.public_hex = cls.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw).hex()
            private = cls.private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption())
            cls.private_file = cls._write('registrar-secret-key', private)
            cls.registrar_id = 'ec319_offline_registrar'
            cls.epoch_challenge = 'aa'*32
            old = cls.parent.context
            cls.genesis_file = str(cls.site/'signed-genesis.json')
            cls.genesis = reg.bootstrap(registry_id='ec319_test_handoff_registry',
                registrar_id=cls.registrar_id,registrar_public_hex=cls.public_hex,
                registrar_epoch_challenge_sha256=cls.epoch_challenge,
                bundle_file=old['bundle_file'],
                expected_bundle_sha256=old['expected_bundle_sha256'],
                chain_file=old['chain_file'],
                expected_chain_sha256=old['expected_chain_sha256'],
                ledger_manifest_file=old['ledger_manifest_file'],
                expected_ledger_manifest_sha256=old['expected_ledger_manifest_sha256'],
                expected_latest_certificate_sha256=old['expected_latest_certificate_sha256'],
                expected_latest_challenge_sha256=old['expected_latest_challenge_sha256'],
                trust=old['trust'],private_key_file=cls.private_file,
                out=cls.genesis_file)
            cls.r1 = dict(sender_id=old['sender_id'],
                sender_public_hex=old['sender_public_hex'],
                receiver_id=old['receiver_id'],
                receiver_public_hex=old['receiver_public_hex'],
                sender_exchange_challenge_sha256=old['sender_exchange_challenge_sha256'],
                receiver_exchange_challenge_sha256=old['receiver_exchange_challenge_sha256'],
                sender_confirmation_challenge_sha256=cls.parent.confirm_challenge,
                registrar_entry_challenge_sha256='ab'*32,
                offer_original_raw_sha256=cls.parent.offer_pin,
                ack_original_raw_sha256=cls.parent.ack_pin,
                closure_original_raw_sha256=cls.parent.close_pin)
            cls.m1 = dict(sequence=1,bundle_file=old['bundle_file'],
                offer_file=cls.parent.offer,ack_file=cls.parent.ack,
                closure_file=cls.parent.closure)
            cls.material_1 = cls._make_materials('map-one.json',[cls.m1])
            cls.snapshot_1_file = str(cls.site/'registered-one.json')
            cls.snapshot_1 = reg.append(registry_file=cls.genesis_file,
                expected_registry_sha256=cls.genesis['snapshot_original_raw_sha256'],
                materials_file=cls.material_1,
                expected_genesis_raw_sha256=cls.genesis['genesis_signed_original_raw_sha256'],
                expected_head_raw_sha256=cls.genesis['head_signed_original_raw_sha256'],
                registrar_id=cls.registrar_id,registrar_public_hex=cls.public_hex,
                new_claim_fields=cls.r1,private_key_file=cls.private_file,
                out=cls.snapshot_1_file)
            # A second independently signed real EC318 handshake for the SAME
            # byte-identical transported originals, with all fresh challenges.
            cls.context2 = dict(old,sender_exchange_challenge_sha256='b1'*32,
                receiver_exchange_challenge_sha256='b2'*32)
            cls.confirm2 = 'b3'*32
            cls.offer2=str(cls.site/'transfer-two-offer.json')
            cls.ack2=str(cls.site/'transfer-two-ack.json')
            cls.close2=str(cls.site/'transfer-two-closure.json')
            result = r.sender_offer(out=cls.offer2,
                private_key_file=cls.parent.sender_private,**cls.context2)
            offer2_sha = result['offer_original_raw_sha256']
            result = r.receiver_ack(offer_file=cls.offer2,
                expected_offer_sha256=offer2_sha,
                private_key_file=cls.parent.receiver_private,out=cls.ack2,
                **cls.context2)
            ack2_sha = result['ack_original_raw_sha256']
            result = r.sender_confirm(offer_file=cls.offer2,
                expected_offer_sha256=offer2_sha,
                ack_file=cls.ack2,expected_ack_sha256=ack2_sha,
                sender_confirmation_challenge_sha256=cls.confirm2,
                private_key_file=cls.parent.sender_private,out=cls.close2,
                **cls.context2)
            cls.r2 = dict(cls.r1,
                sender_exchange_challenge_sha256='b1'*32,
                receiver_exchange_challenge_sha256='b2'*32,
                sender_confirmation_challenge_sha256=cls.confirm2,
                registrar_entry_challenge_sha256='b4'*32,
                offer_original_raw_sha256=offer2_sha,
                ack_original_raw_sha256=ack2_sha,
                closure_original_raw_sha256=result['closure_original_raw_sha256'])
            cls.m2 = dict(sequence=2,bundle_file=old['bundle_file'],
                offer_file=cls.offer2,ack_file=cls.ack2,closure_file=cls.close2)
            cls.material_2 = cls._make_materials('map-two.json',[cls.m1,cls.m2])
            cls.snapshot_2_file = str(cls.site/'registered-two.json')
            cls.snapshot_2 = reg.append(registry_file=cls.snapshot_1_file,
                expected_registry_sha256=cls.snapshot_1['snapshot_original_raw_sha256'],
                materials_file=cls.material_2,
                expected_genesis_raw_sha256=cls.genesis['genesis_signed_original_raw_sha256'],
                expected_head_raw_sha256=cls.snapshot_1['head_signed_original_raw_sha256'],
                registrar_id=cls.registrar_id,registrar_public_hex=cls.public_hex,
                new_claim_fields=cls.r2,private_key_file=cls.private_file,
                out=cls.snapshot_2_file)
        except BaseException:
            if hasattr(cls, 'private'):
                cls.private.cleanup()
            prior_fixture.EC318BilateralOriginalTransferCases.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.private.cleanup()
        prior_fixture.EC318BilateralOriginalTransferCases.tearDownClass()

    @classmethod
    def _write(cls, name, data):
        path=cls.site/name
        path.write_bytes(data)
        path.chmod(0o600)
        return str(path)

    @classmethod
    def _make_materials(cls, name, receipts):
        return cls._write(name,reg.raw_doc({'schema':reg.MATERIALS_SCHEMA,
            'genesis_bundle_file':cls.parent.context['bundle_file'],
            'receipts':receipts}))

    def _verify(self, snapshot_file=None, snapshot=None, materials=None, **changes):
        snap=snapshot or self.snapshot_2
        kwargs=dict(registry_file=snapshot_file or self.snapshot_2_file,
            expected_registry_sha256=snap['snapshot_original_raw_sha256'],
            materials_file=materials or self.material_2,
            expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
            expected_head_raw_sha256=snap['head_signed_original_raw_sha256'],
            registrar_id=self.registrar_id, registrar_public_hex=self.public_hex)
        kwargs.update(changes)
        return reg.verify(**kwargs)

    def test_01_immutable_snapshots_chain_and_older_source_absent(self):
        self.assertEqual(self.snapshot_1['registration_count'],1)
        self.assertEqual(self.snapshot_2['registration_count'],2)
        self.assertTrue(Path(self.genesis_file).exists())
        self.assertTrue(Path(self.snapshot_1_file).exists())
        self.assertNotEqual(self.genesis['snapshot_original_raw_sha256'],
                            self.snapshot_1['snapshot_original_raw_sha256'])
        source=self.parent.base.parent.owner
        offline=source.with_name(source.name+'-ec319-source-inaccessible')
        os.rename(source,offline)
        try:
            done=self._verify()
        finally:
            os.rename(offline,source)
        self.assertEqual(done['registration_count'],2)
        self.assertTrue(done['genuine_ec318_to_ec294_historical_signatures_replayed'])
        self.assertFalse(done['physical_worm_or_global_latest_proven'])

    def test_02_previous_receipt_and_challenge_reuse_denied_before_key_read(self):
        filename=str(self.site/'no-replay-output.json')
        reused=dict(self.r1,registrar_entry_challenge_sha256='e1'*32)
        m=self._make_materials('map-duplicate.json',[self.m1,self.m1|{'sequence':2}])
        with self.assertRaisesRegex(a.AnchorError,'DUPLICATE_TRANSFER_OR_RECEIPT'):
            reg.append(registry_file=self.snapshot_1_file,
                expected_registry_sha256=self.snapshot_1['snapshot_original_raw_sha256'],
                expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
                expected_head_raw_sha256=self.snapshot_1['head_signed_original_raw_sha256'],
                registrar_id=self.registrar_id,registrar_public_hex=self.public_hex,
                new_claim_fields=reused,materials_file=m,
                private_key_file=self.private_file,out=filename)
        recycled=dict(self.r2,registrar_entry_challenge_sha256='ab'*32)
        with self.assertRaisesRegex(a.AnchorError,'REPLAYED_HISTORICAL_OR_CURRENT'):
            reg.append(registry_file=self.snapshot_1_file,
                expected_registry_sha256=self.snapshot_1['snapshot_original_raw_sha256'],
                expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
                expected_head_raw_sha256=self.snapshot_1['head_signed_original_raw_sha256'],
                registrar_id=self.registrar_id,registrar_public_hex=self.public_hex,
                new_claim_fields=recycled,materials_file=self.material_2,
                private_key_file=self.private_file,out=filename)
        self.assertFalse(Path(filename).exists())

    def test_03_edited_signer_or_signed_entry_repin_does_not_pass(self):
        forged=json.loads(Path(self.snapshot_2_file).read_bytes())
        forged['records'][1]['signature_ed25519']='0'*128
        path=self._write('repinned-forged-entry.json',reg.raw_doc(forged))
        with self.assertRaisesRegex(a.AnchorError,'REGISTRAR_ED25519_SIGNATURE_NOT_AUTHENTIC'):
            self._verify(snapshot_file=path,
                expected_registry_sha256=reg.digest(Path(path).read_bytes()))
        with self.assertRaisesRegex(a.AnchorError,'GENESIS_OR_HEAD_SIGNED_RECORD'):
            self._verify(expected_head_raw_sha256='1'*64)
        with self.assertRaisesRegex(a.AnchorError,'SNAPSHOT_RAW_BYTES_DIFFERS'):
            self._verify(expected_registry_sha256='2'*64)

    def test_04_two_authentic_same_parent_registrar_forks_detected(self):
        branch_material=self._make_materials('map-branch.json',[
            self.m2 | {'sequence':1}])
        path=str(self.site/'forked-first-transfer.json')
        fork=reg.append(registry_file=self.genesis_file,
            expected_registry_sha256=self.genesis['snapshot_original_raw_sha256'],
            materials_file=branch_material,
            expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
            expected_head_raw_sha256=self.genesis['head_signed_original_raw_sha256'],
            registrar_id=self.registrar_id,registrar_public_hex=self.public_hex,
            new_claim_fields=self.r2,private_key_file=self.private_file,out=path)
        result=reg.compare(left_file=self.snapshot_1_file,
            expected_left_sha256=self.snapshot_1['snapshot_original_raw_sha256'],
            left_materials_file=self.material_1,
            expected_left_head_raw_sha256=self.snapshot_1['head_signed_original_raw_sha256'],
            right_file=path,
            expected_right_sha256=fork['snapshot_original_raw_sha256'],
            right_materials_file=branch_material,
            expected_right_head_raw_sha256=fork['head_signed_original_raw_sha256'],
            expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
            registrar_id=self.registrar_id,registrar_public_hex=self.public_hex)
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['divergent_sequence'],1)
        self.assertNotEqual(result['left_divergent_signed_record_raw_sha256'],
                            result['right_divergent_signed_record_raw_sha256'])
        self.assertTrue(result['both_forks_full_ec318_to_ec294_replayed'])

    def test_05_console_verify_only_and_old_ec304_name_preserved(self):
        args=['--registry-file',self.snapshot_2_file,
            '--expected-registry-sha256',self.snapshot_2['snapshot_original_raw_sha256'],
            '--materials-file',self.material_2,
            '--expected-genesis-raw-sha256',self.genesis['genesis_signed_original_raw_sha256'],
            '--expected-head-raw-sha256',self.snapshot_2['head_signed_original_raw_sha256'],
            '--registrar-id',self.registrar_id,
            '--registrar-public-hex',self.public_hex]
        cli=str(ROOT/'scripts'/'ces_next.py')
        base=[sys.executable,'-B',cli,'audit-transfer-registry',
              'DeliveryAudit','VerifyOfflineTransferRegistry',*args]
        process=subprocess.run(base,capture_output=True,text=True,timeout=200)
        self.assertEqual(process.returncode,0,process.stdout+process.stderr)
        self.assertEqual(json.loads(process.stdout)['registration_count'],2)
        denied=subprocess.run(base+['--private-key-file',self.private_file],
            capture_output=True,text=True)
        self.assertNotEqual(denied.returncode,0)
        denied=subprocess.run([sys.executable,'-B',cli,'audit-transfer-registry',
            'DeliveryAudit','Append',*args],capture_output=True,text=True)
        self.assertEqual(denied.returncode,3)
        self.assertFalse(json.loads(denied.stdout)['permissions_granted'])
        help_doc=subprocess.run([sys.executable,'-B',cli,'--help'],
            capture_output=True,text=True)
        self.assertIn('audit-registry',help_doc.stdout)
        self.assertIn('audit-transfer-registry',help_doc.stdout)

    def test_06_no_old_original_or_wrong_fifth_role_key_shortcuts(self):
        with self.assertRaisesRegex(a.AnchorError,'RAW_BYTES_DIFFER_FROM_EXTERNAL_PIN'):
            self._verify(expected_registry_sha256='f'*64)
        with self.assertRaisesRegex(a.AnchorError,'GENESIS_SCHEMA_REGISTRAR_OR_TRUST'):
            self._verify(registrar_id='false_registrar')
        # The fifth signing key must be different from the first four keys.
        denied=str(self.site/'deny-wrong-registrar-private.json')
        with self.assertRaisesRegex(a.AnchorError,'REGISTRAR_PRIVATE_KEY_NOT'):
            reg.append(registry_file=self.snapshot_1_file,
                expected_registry_sha256=self.snapshot_1['snapshot_original_raw_sha256'],
                expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
                expected_head_raw_sha256=self.snapshot_1['head_signed_original_raw_sha256'],
                registrar_id=self.registrar_id,registrar_public_hex=self.public_hex,
                new_claim_fields=self.r2,materials_file=self.material_2,
                private_key_file=self.parent.sender_private,out=denied)
        self.assertFalse(Path(denied).exists())
