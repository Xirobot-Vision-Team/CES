#!/usr/bin/env python3
"""EC302 compact functional integration: actual EC294-301 local signed fixture.

Provider/Inbox and multi-human custody remain simulated; no production claim.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

from ec295_delivery_anchor import anchor as a
from ec301_offline_handoff.test_handoff import EC301HandoffCases as Parent
from . import bundle as b

ROOT=Path(__file__).resolve().parents[2]


class EC302PortableBundleCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Parent.setUpClass()
        cls.fixture=Parent
        cls.work=tempfile.TemporaryDirectory(prefix='ec302-')
        cls.home=Path(cls.work.name)
        cls.pins={'a_id':Parent.keys.id_a,'a_public_hex':Parent.keys.pub_a,
                  'a_tip':Parent.keys.a2['sha'],
                  'b_id':Parent.keys.id_b,'b_public_hex':Parent.keys.pub_b,
                  'b_tip':Parent.keys.b1['sha'],
                  'session_tip':Parent.parent.s2,'receipt_tip':Parent.sr2}
        cls.archive=cls.home/'real-proof.zip'
        cls.export=b.build_bundle(Parent.journal2,cls.pins,str(cls.archive))

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()
        Parent.tearDownClass()

    def _zip_edit(self, replace, filename):
        archive=self.home/filename
        with zipfile.ZipFile(self.archive) as f:
            members={name:f.read(name) for name in f.namelist()}
        replace(members)
        with zipfile.ZipFile(archive,'w') as out:
            for name,payload in members.items():
                info=zipfile.ZipInfo(name, date_time=(1980,1,1,0,0,0))
                info.compress_type=zipfile.ZIP_STORED
                info.create_system=3
                info.external_attr=(stat.S_IFREG|0o600)<<16
                out.writestr(info,payload)
        archive.chmod(0o600)
        return str(archive),hashlib.sha256(archive.read_bytes()).hexdigest()

    def _cli_pins(self):
        flags=[]
        for k,v in self.pins.items():
            flags.extend(['--expected-'+k.replace('_','-'),v])
        return flags

    def test_01_genuine_full_signed_source_export_verification_and_cross_directory_import(self):
        original=self.export
        self.assertEqual(original['exit_code'],0)
        self.assertEqual(original['evidence_document_count'],28)
        received=b.verify_bundle(str(self.archive),original['bundle_sha256'],self.pins)
        self.assertEqual(received['report_sha256'],original['report_sha256'])
        self.assertIsNone(received['rebound_journal_file'])
        dest=self.home/'receiver-different-absolute-root'
        imported=b.verify_bundle(str(self.archive),original['bundle_sha256'],self.pins,
                                 destination=str(dest))
        self.assertEqual(imported['report_sha256'],original['report_sha256'])
        self.assertTrue(Path(imported['rebound_journal_file']).is_file())
        self.assertEqual(os.stat(dest).st_mode & 0o777,0o700)
        self.assertEqual(os.stat(dest/'docs'/'0001.json').st_mode & 0o777,0o600)
        self.assertNotIn(str(self.fixture.root).encode(),self.archive.read_bytes())
        self.assertNotIn(b'PRIVATE KEY-----',self.archive.read_bytes())
        # EC295 policy SHA is defined over RAW file bytes. Must still match.
        rebuilt=json.loads((dest/'docs'/'0001.json').read_text())
        self.assertTrue(rebuilt['entries'][0]['ec300_history_file'].startswith(str(dest)))
        new_archive=self.home/'portable-reexport.zip'
        rerelease=b.build_bundle(imported['rebound_journal_file'],self.pins,str(new_archive))
        self.assertEqual(rerelease['bundle_sha256'],original['bundle_sha256'])

    def test_02_no_silent_creation_or_overwrite(self):
        with self.assertRaisesRegex(a.AnchorError,'EXISTS_NO_OVERWRITE'):
            b.build_bundle(self.fixture.journal2,self.pins,str(self.archive))
        exists=self.home/'present'
        exists.mkdir(mode=0o700)
        with self.assertRaisesRegex(a.AnchorError,'EXISTS_NO_OVERWRITE'):
            b.verify_bundle(str(self.archive),self.export['bundle_sha256'],self.pins,
                            destination=str(exists))

    def test_03_wrong_external_zip_sha_never_accepted_or_imported(self):
        dest=self.home/'must-not-create'
        with self.assertRaisesRegex(a.AnchorError,'EXTERNAL_BUNDLE_SHA_MISMATCH'):
            b.verify_bundle(str(self.archive),'1'*64,self.pins,destination=str(dest))
        self.assertFalse(dest.exists())

    def test_04_forged_latest_receipt_pin_is_denied(self):
        bad=self.pins|{'receipt_tip':'1'*64}
        with self.assertRaisesRegex(a.AnchorError,'MANIFEST_IDENTITY_PINS'):
            b.verify_bundle(str(self.archive),self.export['bundle_sha256'],bad)

    def test_05_corrupt_evidence_entry_rejected_even_when_attacker_recomputes_zip_sha(self):
        def corrupt(members):
            m=json.loads(members['manifest.json'])
            name=next(row['id'] for row in m['documents']
                      if row['schema']==b.RECEIPT)
            item=json.loads(members[name])
            item['recipient_signature_ed25519']='a'*128
            raw=b.canonical(item)
            members[name]=raw
            row=next(row for row in m['documents'] if row['id']==name)
            row['sha256']=b.digest(raw);row['size']=len(raw)
            members['manifest.json']=b.canonical(m)
        path,hash_=self._zip_edit(corrupt,'corrupt-valid-new-zip-hash.zip')
        with self.assertRaisesRegex(a.AnchorError,'RECEIPT_NOT_EQUAL_EXTERNALLY_PINN|ED25519_SENDER_OR_RECIPIENT'):
            b.verify_bundle(path,hash_,self.pins)

    def test_06_reference_escape_and_schema_splicing_fail(self):
        def bad_ref(members):
            m=json.loads(members['manifest.json'])
            name=b.ROOT_ID
            journal=json.loads(members[name])
            journal['entries'][0]['signed_receipt_file']=b.REF_PREFIX+'../private.key'
            raw=b.canonical(journal)
            members[name]=raw
            row=next(row for row in m['documents'] if row['id']==name)
            row['sha256']=b.digest(raw);row['size']=len(raw)
            members['manifest.json']=b.canonical(m)
        path,d=self._zip_edit(bad_ref,'invalid-ref.zip')
        with self.assertRaisesRegex(a.AnchorError,'DOCUMENT_REFERENCE_NOT_A_CLOSED'):
            b.verify_bundle(path,d,self.pins)

    def test_07_unexpected_extra_file_denied(self):
        path,d=self._zip_edit(lambda members:members.update({'docs/9999.json':b'{}'}),
                              'extraneous.zip')
        with self.assertRaisesRegex(a.AnchorError,'MISSING_EXTRA_OR_NONCONSECUTIVE'):
            b.verify_bundle(path,d,self.pins)

    def test_08_sensitive_or_credential_field_fail_closed(self):
        with self.assertRaisesRegex(a.AnchorError,'PRIVATE_OR_CREDENTIAL'):
            b._safe_public_data({'private_key_file':'/tmp/a.key'})
        with self.assertRaisesRegex(a.AnchorError,'PRIVATE_OR_CREDENTIAL'):
            b._safe_public_data({'hmac_secret_or_private_payload_returned':True})
        b._safe_public_data({'raw_hmac_secret_or_private_payload_returned':False,
                             'read_credential_sha256':'1'*64})

    def test_09_cli_export_verify_import_and_fixed_console_route(self):
        cli=ROOT/'scripts'/'ces_evidence_bundle.py'
        opts=self._cli_pins()
        command=[sys.executable,'-I','-B',str(cli),'verify',
                 '--bundle-file',str(self.archive),
                 '--expected-bundle-sha256',self.export['bundle_sha256'],*opts]
        proc=subprocess.run(command,capture_output=True,text=True,timeout=90)
        self.assertEqual(proc.returncode,0,proc.stdout+' '+proc.stderr)
        data=json.loads(proc.stdout)
        self.assertTrue(data['bundle_verification_and_complete_original_signature_replay'])
        self.assertFalse(data['external_latest_pins_proven_immutable'])
        cli=ROOT/'scripts'/'ces_next.py'
        command=[sys.executable,'-I','-B',str(cli),'audit-bundle',
                 'DeliveryAudit','VerifyPortableBundle',
                 '--bundle-file',str(self.archive),
                 '--expected-bundle-sha256',self.export['bundle_sha256'],*opts]
        proc=subprocess.run(command,capture_output=True,text=True,timeout=90)
        self.assertEqual(proc.returncode,0,proc.stdout+' '+proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['exit_code'],0)
        command[command.index('VerifyPortableBundle')]='WrongMode'
        proc=subprocess.run(command,capture_output=True,text=True,timeout=90)
        self.assertEqual(proc.returncode,3)
        self.assertEqual(json.loads(proc.stdout)['status'],'permission_denied')

    def test_10_original_router_count_and_default_denial_unchanged(self):
        import subprocess
        cli=ROOT/'scripts'/'ces_next.py'
        command=[sys.executable,'-I','-B',str(cli),'doctor']
        proc=subprocess.run(command,capture_output=True,text=True,timeout=45)
        self.assertEqual(proc.returncode,0,proc.stderr)
        doc=json.loads(proc.stdout)
        self.assertEqual(doc['router_registered_routes'],74)
        self.assertTrue(doc['ec302_offline_complete_evidence_bundle_client_present'])
        self.assertFalse(doc['ec302_real_cross_site_transfer_or_external_custody_verified'])
