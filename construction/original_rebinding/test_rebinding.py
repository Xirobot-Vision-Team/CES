#!/usr/bin/env python3
"""EC317 real EC316/315->294 Ed25519 fixture, byte-preserving device handoff.

Tests share one genuine source-signed fixture; no historical PASS is mocked.
Physical cross-device custody and original native PowerShell smoke are deferred.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from portable_bundle import bundle as b
from dual_custodian_checkpoint import test_checkpoint as fixture
from . import rebinding as r


class EC317OriginalSHARebindingCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.EC316DualSignedOriginalCheckpointCases.setUpClass()
        try:
            cls.parent = fixture.EC316DualSignedOriginalCheckpointCases
            cls.chain, cls.cert = cls.parent._seal('ec317-full-rebind', cls.parent.one)
            cls.context = dict(chain_file=cls.chain[0],
                expected_chain_sha256=cls.chain[1],
                ledger_manifest_file=cls.parent.root1[0],
                expected_ledger_manifest_sha256=cls.parent.root1[1],
                expected_latest_certificate_sha256=cls.cert[1],
                expected_latest_challenge_sha256=cls.parent.challenge1,
                trust=cls.parent.trust)
            cls.bundle = cls.parent._out('ec317-original-rebind-bundle.zip')
            cls.exported = r.export(out=cls.bundle, **cls.context)
            cls.receiver = tempfile.TemporaryDirectory(prefix='ces-ec317-receiver-')
            cls.received = str(Path(cls.receiver.name) / 'moved-evidence.zip')
            shutil.copyfile(cls.bundle, cls.received)
            Path(cls.received).chmod(0o600)
        except BaseException:
            fixture.EC316DualSignedOriginalCheckpointCases.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            cls.receiver.cleanup()
        finally:
            fixture.EC316DualSignedOriginalCheckpointCases.tearDownClass()

    def test_01_real_original_signed_receipt_and_receiver_without_source_tree(self):
        self.assertEqual(self.exported['exit_code'], 0)
        self.assertGreater(self.exported['source_reference_count'], 10)
        self.assertTrue(self.exported['every_original_ec316_to_ec294_signature_replayed'])
        self.assertFalse(self.exported['old_signed_original_bytes_rewritten'])
        # The recipient copy is physically elsewhere. Make EVERY original
        # ledger/certificate/source absolute path unreadable for this replay.
        source = self.parent.owner
        offline = source.with_name(source.name + '-temporarily-offline')
        os.rename(source, offline)
        try:
            result = r.verify(bundle_file=self.received,
                expected_bundle_sha256=self.exported['bundle_original_raw_sha256'],
                **self.context)
        finally:
            os.rename(offline, source)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['source_reference_count'],
                         self.exported['source_reference_count'])
        self.assertEqual(result['replayed_result_original_sha256'],
                         self.exported['replayed_result_original_sha256'])
        self.assertEqual(result['latest_certificate_original_raw_sha256'],
                         self.cert[1])
        self.assertFalse(result['external_global_latest_or_physical_cas_proven'])

    def test_02_external_bundle_pin_key_and_original_path_mismatch_fail_closed(self):
        with self.assertRaisesRegex(a.AnchorError, 'ARCHIVE_DIFFERS_FROM_INDEPENDENT'):
            r.verify(bundle_file=self.received,
                expected_bundle_sha256='9'*64, **self.context)
        bad = dict(self.context,expected_latest_certificate_sha256='8'*64)
        with self.assertRaisesRegex(a.AnchorError, 'ARCHIVE_ROOT_DOES_NOT_MATCH'):
            r.verify(bundle_file=self.received,
                expected_bundle_sha256=self.exported['bundle_original_raw_sha256'],
                **bad)
        altered = dict(self.context, chain_file='/unknown/no-source.json')
        with self.assertRaisesRegex(a.AnchorError, 'ARCHIVE_ROOT_DOES_NOT_MATCH'):
            r.verify(bundle_file=self.received,
                expected_bundle_sha256=self.exported['bundle_original_raw_sha256'],
                **altered)

    def test_03_no_implicit_live_source_fallback_and_scoped_cleanup(self):
        with io._scoped_original_source_reads(bindings={}):
            with self.assertRaisesRegex(io.HostError, 'UNMAPPED_ORIGINAL_SOURCE'):
                io._open_regular(self.chain[0], 25000, private=True)
            with self.assertRaisesRegex(io.HostError, 'UNMAPPED_ORIGINAL_SOURCE'):
                b._private_parent(self.chain[0])
        # Prior EC316 semantics are unchanged after the scoped adapter exits.
        self.assertEqual(b.digest(io._open_regular(self.chain[0],25000,private=True)),
                         self.chain[1])
        with self.assertRaisesRegex(a.AnchorError, 'ARCHIVE_EXISTS_NO_OVERWRITE'):
            r.export(out=self.bundle, **self.context)

    def _rewrite_zip(self, operation, name: str) -> tuple[str,str]:
        with zipfile.ZipFile(self.bundle) as z:
            payload={item.filename:z.read(item) for item in z.infolist()}
        operation(payload)
        destination=str(Path(self.receiver.name) / name)
        with zipfile.ZipFile(destination,'w') as z:
            for path, raw in sorted(payload.items()):
                z.writestr(r._archive_info(path),raw)
        os.chmod(destination,0o600)
        return destination,b.digest(Path(destination).read_bytes())

    def test_04_extra_object_and_missing_document_fail_even_if_zip_rehashed(self):
        def extraneous(payload):
            bogus=b.canonical({'schema':'ces.ec317.unused.evidence.v1'})
            payload['objects/'+b.digest(bogus)+'.json']=bogus
        path, sha=self._rewrite_zip(extraneous,'extra-repinned.zip')
        with self.assertRaisesRegex(a.AnchorError,'MISSING_OR_UNREFERENCED'):
            r.verify(bundle_file=path,expected_bundle_sha256=sha,**self.context)
        def missing(payload):
            name=next(n for n in payload if n.startswith('objects/'))
            del payload[name]
        path, sha=self._rewrite_zip(missing,'missing-repinned.zip')
        with self.assertRaisesRegex(a.AnchorError,'MISSING_OR_UNREFERENCED'):
            r.verify(bundle_file=path,expected_bundle_sha256=sha,**self.context)

    def test_05_one_old_source_tampered_with_new_matching_sha_fails_signature_replay(self):
        # This changes an *original custodian certificate* inside the ZIP,
        # then recomputes all transport SHA values; the old signed certificate
        # in the chain MUST still reject it rather than trusting transfer SHAs.
        def tamper(payload):
            manifest=json.loads(payload['manifest.json'])
            row=next(x for x in manifest['sources']
                     if x['original_absolute_path'] == self.cert[0])
            old='objects/'+row['original_raw_sha256']+'.'+row['source_format']
            doc=json.loads(payload[old])
            doc['votes']['a']['signature_ed25519']='0'*128
            raw=b.canonical(doc)
            new_sha=b.digest(raw)
            row['original_raw_sha256']=new_sha
            row['raw_size']=len(raw)
            payload['objects/'+new_sha+'.json']=raw
            if not any(x['original_raw_sha256']==self.cert[1] for x in manifest['sources']):
                del payload[old]
            payload['manifest.json']=b.canonical(manifest)
        path,sha=self._rewrite_zip(tamper,'forged-signed-source.zip')
        with self.assertRaises((a.AnchorError, io.HostError)):
            r.verify(bundle_file=path, expected_bundle_sha256=sha,**self.context)

    def test_06_unified_console_cannot_export_or_sign(self):
        import subprocess
        import sys
        cli=Path(__file__).resolve().parents[2]/'scripts'/'ces_next.py'
        args=['audit-rebind','DeliveryAudit','VerifyPortableSignedCheckpoint',
            '--bundle-file',self.received,
            '--expected-bundle-sha256',self.exported['bundle_original_raw_sha256'],
            '--chain-file',self.chain[0],
            '--expected-chain-sha256',self.chain[1],
            '--ledger-manifest-file',self.parent.root1[0],
            '--expected-ledger-manifest-sha256',self.parent.root1[1],
            '--expected-latest-certificate-sha256',self.cert[1],
            '--expected-latest-challenge-sha256',self.parent.challenge1]
        for role in ('a','b'):
            args.extend(['--custodian-'+role+'-id',
                         self.parent.trust['custodian_'+role+'_id'],
                         '--custodian-'+role+'-public-hex',
                         self.parent.trust['custodian_'+role+'_public_hex']])
        cmd=[sys.executable,'-B',str(cli),*args]
        run=subprocess.run([*cmd,'--out',self.parent._out('unauthorized')],
                           text=True,capture_output=True)
        self.assertNotEqual(run.returncode,0)
        self.assertFalse(Path(self.parent._out('unauthorized')).exists())
        run=subprocess.run([sys.executable,'-B',str(cli),
                            *[x if x!='VerifyPortableSignedCheckpoint' else 'Sign'
                              for x in args]],text=True,capture_output=True)
        self.assertEqual(run.returncode,3)
        self.assertEqual(json.loads(run.stdout)['permissions_granted'],False)
