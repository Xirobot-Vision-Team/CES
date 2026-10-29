#!/usr/bin/env python3
"""Fast registrar-only structure tests; EC317/318 replay is stubbed HERE ONLY.

These tests DO NOT demonstrate EC318->294 cryptographic replay. The separate
EC319SignedOfflineRegistryCases genuine fixture tests are required for that.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from delivery_anchor import anchor as a
from . import registry as reg


def public(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex()


class OfflineRegistryOnlyStructureCases(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='ces-ec319-structure-')
        self.addCleanup(self.directory.cleanup)
        self.site=Path(self.directory.name)
        self.keys={x:Ed25519PrivateKey.generate() for x in ('a','b','sender','receiver','registrar')}
        self.pub={x:public(k) for x,k in self.keys.items()}
        self.registrar='fifth_offline_registrar'
        private=self.keys['registrar'].private_bytes_raw()
        self.key=self.write('registrar-private',private)
        self.root = dict(chain_file='/old-site/immutable-chain.json',
            expected_chain_sha256='1'*64,
            ledger_manifest_file='/old-site/immutable-ledger.json',
            expected_ledger_manifest_sha256='2'*64,
            expected_latest_certificate_sha256='3'*64,
            expected_latest_challenge_sha256='4'*64,
            trust={'custodian_a_id':'independent_a','custodian_b_id':'independent_b',
                   'custodian_a_public_hex':self.pub['a'],
                   'custodian_b_public_hex':self.pub['b']})
        self.original_report=dict(exit_code=0,
            status='relocated_original_bytes_fully_reverified_without_original_paths',
            every_original_ec316_to_ec294_signature_replayed=True,
            old_signed_original_bytes_rewritten=False,
            external_business_writes_performed=False,
            replayed_result_original_sha256='5'*64,
            source_reference_count=22)
        self.original_patch=patch.object(reg.original,'verify',
            return_value=self.original_report)
        self.original_patch.start()
        self.addCleanup(self.original_patch.stop)
        self.receipt_patch=patch.object(reg.receipt,'verify',
            side_effect=lambda **kw: dict(
                exit_code=0,
                status='three_authentic_bilateral_signatures_and_every_original_replay_valid',
                original_ec316_to_ec294_signatures_fully_replayed=True,
                original_full_replay_result_sha256='5'*64,
                binding_canonical_sha256='6'*64,
                source_reference_count=22,
                independent_sender_and_receiver_human_custody_proven=False,
                physical_transfer_or_external_durable_receipt_proven=False,
                global_latest_or_business_write_proven=False))
        self.receipt_patch.start()
        self.addCleanup(self.receipt_patch.stop)
        self.genesis_path=str(self.site/'genesis.json')
        self.genesis=reg.bootstrap(registry_id='signed_local_epoch',
            registrar_id=self.registrar,registrar_public_hex=self.pub['registrar'],
            registrar_epoch_challenge_sha256='7'*64,
            bundle_file=str(self.site/'nonexistent_original_bundle.zip'),
            expected_bundle_sha256='8'*64,
            private_key_file=self.key,out=self.genesis_path,**self.root)
        self.one=self.claim('a')
        self.two=self.claim('b')
        self.material_1=self.material('map1.json',1)
        self.material_2=self.material('map2.json',2)
        self.first_path=str(self.site/'registered1.json')
        self.first=self.append(self.genesis_path,self.genesis,self.one,
                               self.material_1,self.first_path)

    def write(self,name,raw):
        path=self.site/name
        path.write_bytes(raw)
        path.chmod(0o600)
        return str(path)

    def material(self,name,count):
        return self.write(name,reg.raw_doc({'schema':reg.MATERIALS_SCHEMA,
            'genesis_bundle_file':str(self.site/'nonexistent_original_bundle.zip'),
            'receipts':[dict(sequence=i,bundle_file=str(self.site/'bundle.zip'),
                offer_file=str(self.site/f'offer{i}.json'),
                ack_file=str(self.site/f'ack{i}.json'),
                closure_file=str(self.site/f'close{i}.json')) for i in range(1,count+1)]}))

    def claim(self,c):
        v=20 if c=='a' else 80
        return dict(offer_original_raw_sha256=f'{v:02x}'*32,
            ack_original_raw_sha256=f'{v+1:02x}'*32,
            closure_original_raw_sha256=f'{v+2:02x}'*32,
            sender_id='registrar_sender',sender_public_hex=self.pub['sender'],
            receiver_id='registrar_receiver',receiver_public_hex=self.pub['receiver'],
            sender_exchange_challenge_sha256=f'{v+3:02x}'*32,
            receiver_exchange_challenge_sha256=f'{v+4:02x}'*32,
            sender_confirmation_challenge_sha256=f'{v+5:02x}'*32,
            registrar_entry_challenge_sha256=f'{v+6:02x}'*32)

    def append(self,previous_path,previous,new,materials,out):
        return reg.append(registry_file=previous_path,
            expected_registry_sha256=previous['snapshot_original_raw_sha256'],
            materials_file=materials,
            expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
            expected_head_raw_sha256=previous['head_signed_original_raw_sha256'],
            registrar_id=self.registrar,registrar_public_hex=self.pub['registrar'],
            new_claim_fields=new,private_key_file=self.key,out=out)

    def verify(self,path,snap,materials):
        return reg.verify(registry_file=path,
            expected_registry_sha256=snap['snapshot_original_raw_sha256'],
            materials_file=materials,
            expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
            expected_head_raw_sha256=snap['head_signed_original_raw_sha256'],
            registrar_id=self.registrar,registrar_public_hex=self.pub['registrar'])

    def test_real_fifth_key_signatures_and_causal_prefix(self):
        nextpath=str(self.site/'second.json')
        second=self.append(self.first_path,self.first,self.two,self.material_2,nextpath)
        self.assertEqual(second['registration_count'],2)
        self.assertEqual(self.verify(nextpath,second,self.material_2)['registration_count'],2)
        self.assertTrue(Path(self.first_path).exists())

    def test_reused_receipt_and_challenge_denied(self):
        copy=dict(self.one,registrar_entry_challenge_sha256='c8'*32)
        with self.assertRaisesRegex(a.AnchorError,'DUPLICATE_TRANSFER'):
            self.append(self.first_path,self.first,copy,self.material_2,
                        str(self.site/'bad1.json'))
        copy=dict(self.two,registrar_entry_challenge_sha256=self.one['registrar_entry_challenge_sha256'])
        with self.assertRaisesRegex(a.AnchorError,'CHALLENGE_REJECTED'):
            self.append(self.first_path,self.first,copy,self.material_2,
                        str(self.site/'bad2.json'))
        self.assertFalse((self.site/'bad1.json').exists())
        self.assertFalse((self.site/'bad2.json').exists())

    def test_rehashed_forged_fifth_signature_fails(self):
        item=json.loads(Path(self.first_path).read_bytes())
        item['records'][1]['signature_ed25519']='0'*128
        path=self.write('forged.json',reg.raw_doc(item))
        fake=dict(self.first,snapshot_original_raw_sha256=reg.digest(Path(path).read_bytes()))
        with self.assertRaisesRegex(a.AnchorError,'REGISTRAR_ED25519_SIGNATURE_NOT_AUTHENTIC'):
            reg.verify(registry_file=path,
                expected_registry_sha256=fake['snapshot_original_raw_sha256'],
                materials_file=self.material_1,
                expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
                expected_head_raw_sha256=reg.digest(reg.raw_doc(item['records'][-1])),
                registrar_id=self.registrar,registrar_public_hex=self.pub['registrar'])

    def test_valid_branch_fork_proof_and_prefix_comparison(self):
        p=str(self.site/'another-first.json')
        fork=self.append(self.genesis_path,self.genesis,self.two,self.material_1,p)
        def compare(right_path,right,rm):
            return reg.compare(left_file=self.first_path,
                expected_left_sha256=self.first['snapshot_original_raw_sha256'],
                left_materials_file=self.material_1,
                expected_left_head_raw_sha256=self.first['head_signed_original_raw_sha256'],
                right_file=right_path,expected_right_sha256=right['snapshot_original_raw_sha256'],
                right_materials_file=rm,
                expected_right_head_raw_sha256=right['head_signed_original_raw_sha256'],
                expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
                registrar_id=self.registrar,registrar_public_hex=self.pub['registrar'])
        self.assertEqual(compare(p,fork,self.material_1)['divergent_sequence'],1)
        p2=str(self.site/'second.json')
        second=self.append(self.first_path,self.first,self.two,self.material_2,p2)
        self.assertEqual(compare(p2,second,self.material_2)['status'],
                         'one_valid_signed_registry_prefix_of_the_other')

    def test_prior_snapshot_and_role_pins_must_be_external(self):
        with self.assertRaisesRegex(a.AnchorError,'RAW_BYTES_DIFFER'):
            reg.verify(registry_file=self.first_path,
                expected_registry_sha256='9'*64,
                materials_file=self.material_1,
                expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
                expected_head_raw_sha256=self.first['head_signed_original_raw_sha256'],
                registrar_id=self.registrar,registrar_public_hex=self.pub['registrar'])
        with self.assertRaisesRegex(a.AnchorError,'GENESIS_SCHEMA_REGISTRAR_OR_TRUST'):
            reg.verify(registry_file=self.first_path,
                expected_registry_sha256=self.first['snapshot_original_raw_sha256'],
                materials_file=self.material_1,
                expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
                expected_head_raw_sha256=self.first['head_signed_original_raw_sha256'],
                registrar_id='false_registrar',registrar_public_hex=self.pub['registrar'])
