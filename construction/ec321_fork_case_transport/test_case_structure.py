#!/usr/bin/env python3
"""EC321 real fifth/sixth Ed25519 + ZIP rebind tests.

IMPORTANT: EC317 original verified-history and EC318 three signatures are
mocked in this quick structure suite, exactly as in EC319/EC320 structure
fixtures. Nothing here asserts a full EC294->EC318 signed replay passed.
"""
from __future__ import annotations

import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec320_fork_witness import witness as w
from . import case as c


def pub(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex()


class PortableCaseGenuineSignerStructureCases(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ces-ec321-structure-')
        self.addCleanup(self.temp.cleanup)
        self.dir=Path(self.temp.name)
        self.keys={kind:Ed25519PrivateKey.generate() for kind in (
            'custodian_a','custodian_b','sender','receiver','registrar','witness')}
        self.pub={role:pub(private) for role,private in self.keys.items()}
        self.registrar_id='fifth_offline_registrar'
        self.bundle=self.write('original-zip.zip',self.zip_fixture_bytes())
        bundle_sha=c.sha(Path(self.bundle).read_bytes())
        root={'chain_file':'/original-only/chain.json',
            'expected_chain_sha256':'1'*64,
            'ledger_manifest_file':'/original-only/ledger.json',
            'expected_ledger_manifest_sha256':'2'*64,
            'expected_latest_certificate_sha256':'3'*64,
            'expected_latest_challenge_sha256':'4'*64,
            'trust':{'custodian_a_id':'custodian_a_identity',
                     'custodian_b_id':'custodian_b_identity',
                     'custodian_a_public_hex':self.pub['custodian_a'],
                     'custodian_b_public_hex':self.pub['custodian_b']}}
        self.original_patch=patch.object(reg.original,'verify',return_value={
            'exit_code':0,
            'status':'relocated_original_bytes_fully_reverified_without_original_paths',
            'every_original_ec316_to_ec294_signature_replayed':True,
            'old_signed_original_bytes_rewritten':False,
            'external_business_writes_performed':False,
            'replayed_result_original_sha256':'5'*64,
            'source_reference_count':11})
        self.original_patch.start();self.addCleanup(self.original_patch.stop)
        self.receipt_patch=patch.object(reg.receipt,'verify',return_value={
            'exit_code':0,
            'status':'three_authentic_bilateral_signatures_and_every_original_replay_valid',
            'original_ec316_to_ec294_signatures_fully_replayed':True,
            'original_full_replay_result_sha256':'5'*64,
            'binding_canonical_sha256':'6'*64,
            'source_reference_count':11,
            'independent_sender_and_receiver_human_custody_proven':False,
            'physical_transfer_or_external_durable_receipt_proven':False,
            'global_latest_or_business_write_proven':False})
        self.receipt_patch.start();self.addCleanup(self.receipt_patch.stop)
        self.genesis_path=str(self.dir/'genesis.json')
        self.genesis=reg.bootstrap(registry_id='one_fork_epoch',
            registrar_id=self.registrar_id,
            registrar_public_hex=self.pub['registrar'],
            registrar_epoch_challenge_sha256='7'*64,
            bundle_file=self.bundle,expected_bundle_sha256=bundle_sha,
            private_key_file=self.key('registrar'),out=self.genesis_path,**root)
        self.left_receipts,self.left_claim=self.receipts('left',10)
        self.right_receipts,self.right_claim=self.receipts('right',20)
        self.left_map=self.materials('left',self.left_receipts)
        self.right_map=self.materials('right',self.right_receipts)
        self.left_snapshot=str(self.dir/'left-snapshot.json')
        self.right_snapshot=str(self.dir/'right-snapshot.json')
        self.left=reg.append(registry_file=self.genesis_path,
            expected_registry_sha256=self.genesis['snapshot_original_raw_sha256'],
            materials_file=self.left_map,
            expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
            expected_head_raw_sha256=self.genesis['head_signed_original_raw_sha256'],
            registrar_id=self.registrar_id,registrar_public_hex=self.pub['registrar'],
            new_claim_fields=self.left_claim,private_key_file=self.key('registrar'),
            out=self.left_snapshot)
        self.right=reg.append(registry_file=self.genesis_path,
            expected_registry_sha256=self.genesis['snapshot_original_raw_sha256'],
            materials_file=self.right_map,
            expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
            expected_head_raw_sha256=self.genesis['head_signed_original_raw_sha256'],
            registrar_id=self.registrar_id,registrar_public_hex=self.pub['registrar'],
            new_claim_fields=self.right_claim,private_key_file=self.key('registrar'),
            out=self.right_snapshot)
        self.witness_file=str(self.dir/'sixth-witness.json')
        self.pins=dict(case_id='portable_fork_case_321',
            witness_id='sixth_independent_witness',
            witness_public_hex=self.pub['witness'],
            witness_challenge_sha256='d0'*32,
            expected_left_sha256=self.left['snapshot_original_raw_sha256'],
            expected_right_sha256=self.right['snapshot_original_raw_sha256'],
            expected_left_head_raw_sha256=self.left['head_signed_original_raw_sha256'],
            expected_right_head_raw_sha256=self.right['head_signed_original_raw_sha256'],
            expected_genesis_raw_sha256=self.genesis['genesis_signed_original_raw_sha256'],
            registrar_id=self.registrar_id,
            registrar_public_hex=self.pub['registrar'])
        result=w.attest(
            private_key_file=self.key('witness'),out=self.witness_file,
            witness_id=self.pins['witness_id'],
            witness_public_hex=self.pins['witness_public_hex'],
            witness_challenge_sha256=self.pins['witness_challenge_sha256'],
            case_id=self.pins['case_id'],
            left_file=self.left_snapshot,
            expected_left_sha256=self.pins['expected_left_sha256'],
            left_materials_file=self.left_map,
            expected_left_head_raw_sha256=self.pins['expected_left_head_raw_sha256'],
            right_file=self.right_snapshot,
            expected_right_sha256=self.pins['expected_right_sha256'],
            right_materials_file=self.right_map,
            expected_right_head_raw_sha256=self.pins['expected_right_head_raw_sha256'],
            expected_genesis_raw_sha256=self.pins['expected_genesis_raw_sha256'],
            registrar_id=self.registrar_id,
            registrar_public_hex=self.pub['registrar'])
        self.assertEqual(result['exit_code'],2)
        self.pins['expected_witness_sha256']=result['attestation_original_raw_sha256']
        self.case_file=str(self.dir/'transport-case.zip')
        self.sources=dict(witness_file=self.witness_file,
            left_file=self.left_snapshot,left_materials_file=self.left_map,
            right_file=self.right_snapshot,right_materials_file=self.right_map)

    @staticmethod
    def zip_fixture_bytes():
        content=BytesIO()
        with zipfile.ZipFile(content,'w',compression=zipfile.ZIP_STORED) as z:
            z.writestr('arbitrary-original.bin',b'Original fixture only; old replay mocked')
        return content.getvalue()

    def write(self,name,raw):
        target=self.dir/name
        target.write_bytes(raw)
        target.chmod(0o600)
        return str(target)

    def key(self,name):
        path=self.dir/(name+'-private.bin')
        if not path.exists():self.write(path.name,self.keys[name].private_bytes_raw())
        return str(path)

    def receipts(self,label,start):
        docs={}
        for i,name in enumerate(('offer','ack','closure')):
            doc={'schema':'ces.ec318.mock_structural_receipt_'+name+'.v1',
                 'branch':label,'nonce':start+i}
            raw=c.raw_json(doc)
            path=self.write(label+'-'+name+'.json',raw)
            docs[name]=(path,c.sha(raw))
        fields=dict(offer_original_raw_sha256=docs['offer'][1],
            ack_original_raw_sha256=docs['ack'][1],
            closure_original_raw_sha256=docs['closure'][1],
            sender_id='transfer_sender',sender_public_hex=self.pub['sender'],
            receiver_id='transfer_receiver',receiver_public_hex=self.pub['receiver'],
            sender_exchange_challenge_sha256=f'{start:02x}'*32,
            receiver_exchange_challenge_sha256=f'{start+1:02x}'*32,
            sender_confirmation_challenge_sha256=f'{start+2:02x}'*32,
            registrar_entry_challenge_sha256=f'{start+3:02x}'*32)
        return docs, fields

    def materials(self,label,docs):
        record={'sequence':1,'bundle_file':self.bundle,
                'offer_file':docs['offer'][0],
                'ack_file':docs['ack'][0],
                'closure_file':docs['closure'][0]}
        return self.write(label+'-map.json',c.raw_json({
            'schema':reg.MATERIALS_SCHEMA,
            'genesis_bundle_file':self.bundle,'receipts':[record]}))

    def export_case(self,**replace):
        return c.export(out=self.case_file,
            **dict(dict(self.pins,**self.sources),**replace))

    def verify_case(self,sha256,**replace):
        return c.verify(bundle_file=self.case_file,
            expected_bundle_sha256=sha256,**dict(self.pins,**replace))

    def _repack(self,mutate):
        with zipfile.ZipFile(self.case_file,'r') as z:
            entries={k:z.read(k) for k in z.namelist()}
        mutate(entries)
        raw=BytesIO()
        with zipfile.ZipFile(raw,'w',allowZip64=False) as z:
            for name,content in entries.items():
                z.writestr(c._zip_info(name),content)
        path=self.write('tampered-case.zip',raw.getvalue())
        return path,c.sha(Path(path).read_bytes())

    def test_full_portable_case_export_import_with_real_fifth_and_sixth_signatures(self):
        sent=self.export_case()
        self.assertEqual(sent['exit_code'],2)
        self.assertEqual(sent['source_object_count'],10)
        self.assertEqual(sent['left_transfer_count'],1)
        self.assertEqual(sent['right_transfer_count'],1)
        verified=self.verify_case(sent['case_bundle_original_raw_sha256'])
        self.assertEqual(verified['exit_code'],2)
        self.assertEqual(verified['fork_sequence'],1)
        self.assertTrue(verified['lossless_exact_original_bytes_rebound_without_source_paths'])
        self.assertFalse(verified['external_latest_winner_or_atomic_cas_proven'])
        self.assertEqual(os.stat(self.case_file).st_mode&0o777,0o600)

    def test_receive_without_source_machine_snapshots_keys_or_materials(self):
        sent=self.export_case()
        for path in (self.left_snapshot,self.right_snapshot,self.witness_file,
                     self.left_map,self.right_map,self.bundle,
                     self.left_receipts['offer'][0],self.right_receipts['closure'][0]):
            Path(path).unlink()
        self.assertEqual(self.verify_case(sent['case_bundle_original_raw_sha256'])['exit_code'],2)

    def test_whole_zip_pin_is_required_and_tamper_or_rehash_requires_all_original_pins(self):
        sent=self.export_case()
        with self.assertRaisesRegex(anchor.AnchorError,'CASE_ZIP_WHOLE_RAW_SHA'):
            self.verify_case('f0'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'CASE_MANIFEST_NOT_EQUAL_ALL_INDEPENDENT'):
            self.verify_case(sent['case_bundle_original_raw_sha256'],case_id='different_case_321')
        src=bytearray(Path(self.case_file).read_bytes());src[-30]^=1
        bad=self.write('changed.zip',bytes(src))
        with self.assertRaisesRegex(anchor.AnchorError,'CASE_ZIP_WHOLE_RAW_SHA'):
            c.verify(bundle_file=bad,
                expected_bundle_sha256=sent['case_bundle_original_raw_sha256'],**self.pins)

    def test_full_original_fork_must_pass_before_export_create(self):
        with patch.object(reg.receipt,'verify',side_effect=anchor.AnchorError(
                'EC318_OLD_HISTORY_CRYPTO_FALSE','permission_denied')):
            with self.assertRaisesRegex(anchor.AnchorError,'OLD_HISTORY_CRYPTO_FALSE'):
                self.export_case()
        self.assertFalse(Path(self.case_file).exists())

    def test_existing_output_is_preserved_even_on_valid_sources(self):
        self.write('transport-case.zip',b'prior untouched')
        with self.assertRaisesRegex(anchor.AnchorError,'EXISTS_NO_OVERWRITE'):
            self.export_case()
        self.assertEqual(Path(self.case_file).read_bytes(),b'prior untouched')

    def test_export_detects_unsigned_path_map_redirects_to_wrong_receipt(self):
        misdirect=self.materials('malicious',self.right_receipts)
        with self.assertRaises(anchor.AnchorError):
            self.export_case(left_materials_file=misdirect)
        self.assertFalse(Path(self.case_file).exists())

    def test_import_denies_extra_paths_and_unsupported_zip_compression(self):
        self.export_case()
        path,sha256=self._repack(lambda x:x.update({'../../evil.json':b'hello'}))
        with self.assertRaisesRegex(anchor.AnchorError,'UNSAFE_NONCANONICAL'):
            c.verify(bundle_file=path,expected_bundle_sha256=sha256,**self.pins)
        original_entries={}
        with zipfile.ZipFile(self.case_file) as z:
            for name in z.namelist(): original_entries[name]=z.read(name)
        raw=BytesIO()
        with zipfile.ZipFile(raw,'w') as z:
            for name,content in original_entries.items():
                if name=='case-manifest.json':
                    z.writestr(name,content,compress_type=zipfile.ZIP_DEFLATED)
                else: z.writestr(c._zip_info(name),content)
        path=self.write('compressed.zip',raw.getvalue())
        with self.assertRaisesRegex(anchor.AnchorError,'UNSAFE_NONCANONICAL'):
            c.verify(bundle_file=path,expected_bundle_sha256=c.sha(raw.getvalue()),**self.pins)

    def test_signed_registrar_receipt_order_is_rechecked_even_with_whole_zip_repin(self):
        self.export_case()
        def mutate(entries):
            doc=json.loads(entries['case-manifest.json'])
            doc['left_receipts'][0]['offer_sha256']=doc['right_receipts'][0]['offer_sha256']
            entries['case-manifest.json']=c.raw_json(doc)
        path,sha256=self._repack(mutate)
        with self.assertRaisesRegex(anchor.AnchorError,'MISSING_EXTRA_OR_CROSS_TYPED|IMPORT_RECEIPT_SHA_NOT_EQUAL_SIGNED'):
            c.verify(bundle_file=path,expected_bundle_sha256=sha256,**self.pins)

    def test_forged_sixth_signature_even_rehashed_is_rejected(self):
        self.export_case()
        def mutate(entries):
            old=self.pins['expected_witness_sha256']
            doc=json.loads(entries['objects/'+old+'.json'])
            doc['signature_ed25519']='0'*128
            raw=c.raw_json(doc);new=c.sha(raw)
            del entries['objects/'+old+'.json']
            entries['objects/'+new+'.json']=raw
            manifest=json.loads(entries['case-manifest.json'])
            manifest['external_pins']['expected_witness_sha256']=new
            for obj in manifest['objects']:
                if obj['raw_sha256']==old:obj['raw_sha256']=new
            manifest['objects'].sort(key=lambda item:item['raw_sha256'])
            entries['case-manifest.json']=c.raw_json(manifest)
            self.new_witness_sha=new
        path,sha256=self._repack(mutate)
        with self.assertRaisesRegex(anchor.AnchorError,'SIXTH_ED25519_SIGNATURE_NOT_AUTHENTIC'):
            c.verify(bundle_file=path,expected_bundle_sha256=sha256,
                     **dict(self.pins,expected_witness_sha256=self.new_witness_sha))

    def test_import_lost_source_object_fails_before_any_replay(self):
        self.export_case()
        def mutate(entries):
            delete=next(name for name in entries if name.startswith('objects/')
                        and name.endswith('.zip'))
            del entries[delete]
        path,sha256=self._repack(mutate)
        with self.assertRaisesRegex(anchor.AnchorError,'ARCHIVE_MEMBERSHIP'):
            c.verify(bundle_file=path,expected_bundle_sha256=sha256,**self.pins)


if __name__=='__main__': unittest.main()
