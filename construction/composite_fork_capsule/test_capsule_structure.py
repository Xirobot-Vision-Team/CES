#!/usr/bin/env python3
"""EC323 focused genuine fifth/sixth/seventh crypto + exact bytes capsule.

EC321's inherited structural fixture mocks ONLY deep EC317/318 legacy replay.
The production EC323 code never mocks EC322/EC321 or earlier validators.
Do not report this as a true production unmocked EC294->EC323 integration.
"""
from __future__ import annotations

from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import warnings
import unittest
from unittest.mock import patch
import zipfile

from scripts import ces_next as console
from delivery_anchor import anchor
from offline_transfer_registry import registry as reg
from receiver_fork_ack import test_ack_structure as original_fixture
from . import capsule as c


class CompositeOriginalCaseAndAckCases(unittest.TestCase):
    def setUp(self):
        self.f = original_fixture.SeventhIndependentReceiverAckCases(
            methodName='test_true_seventh_signed_ack_and_independent_original_case_replay')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        signed=self.f.issue()
        self.ack_sha=signed['signed_receiver_ack_original_raw_sha256']
        self.outer=str(self.f.f.dir/'complete-originals-capsule.zip')
        self.trust={k:v for k,v in self.f.inputs.items()
                    if k not in ('bundle_file','expected_bundle_sha256')}
        self.trust['expected_bundle_sha256']=self.f.case_sha
        self.trust['expected_ack_sha256']=self.ack_sha

    def seal(self,**changes):
        params=dict(self.trust,bundle_file=self.f.f.case_file,
                    ack_file=self.f.ack_file,out=self.outer)
        params.update(changes)
        return c.seal(**params)

    def check(self,whole_sha,**changes):
        params=dict(self.trust,capsule_file=self.outer,
                    expected_capsule_sha256=whole_sha)
        params.update(changes)
        return c.verify(**params)

    def edit_zip(self, transform):
        raw=Path(self.outer).read_bytes()
        with zipfile.ZipFile(BytesIO(raw),'r') as archive:
            docs=[(info.filename,archive.read(info)) for info in archive.infolist()]
        docs=transform(docs)
        out=BytesIO()
        with zipfile.ZipFile(out,'w',allowZip64=False) as archive:
            for name,data in docs:
                archive.writestr(c._zip_info(name),data)
        file=self.f.f.write('tampered-archive.zip',out.getvalue())
        return file,c.case.sha(out.getvalue())

    def test_seal_preserves_both_exact_original_bytes_and_successful_replay(self):
        sealed=self.seal()
        self.assertEqual(sealed['exit_code'],2)
        self.assertFalse(sealed['portable_capsule_itself_is_a_new_signature'])
        self.assertEqual(os.stat(self.outer).st_mode&0o777,0o600)
        with zipfile.ZipFile(self.outer) as archive:
            self.assertEqual(archive.namelist(),list(c.MEMBERS))
            self.assertEqual(archive.read(c.CASE_MEMBER),
                             Path(self.f.f.case_file).read_bytes())
            self.assertEqual(archive.read(c.ACK_MEMBER),
                             Path(self.f.ack_file).read_bytes())
            manifest=json.loads(archive.read(c.MANIFEST_FILE))
            self.assertEqual(manifest['ec321_external_pins'],self.f.f.pins)
            self.assertEqual(manifest['seventh_receiver_external_trust']['seventh_receiver_id'],
                             'seventh_external_receiver')
            self.assertFalse(manifest['global_latest_fork_winner_or_external_cas_proven'])
        verified=self.check(sealed['capsule_original_raw_sha256'])
        self.assertEqual(verified['status'],
            'independent_portable_original_case_seventh_ack_and_all_histories_reverified')
        self.assertTrue(verified['seventh_ed25519_and_entire_original_signed_history_reverified'])
        self.assertEqual(verified['fork_sequence'],1)

    def test_import_when_only_capsule_and_external_trust_remain(self):
        sealed=self.seal()
        relocated=self.f.f.dir/'relocated-capsule.zip'
        shutil.copyfile(self.outer,relocated)
        relocated.chmod(0o600)
        for path in (self.f.ack_file,self.f.f.case_file,self.f.key_path,
                     self.f.f.witness_file,self.f.f.left_snapshot,self.f.f.right_snapshot,
                     self.f.f.left_map,self.f.f.right_map,self.f.f.bundle):
            Path(path).unlink(missing_ok=True)
        verified=self.check(sealed['capsule_original_raw_sha256'],
                            capsule_file=str(relocated))
        self.assertEqual(verified['exit_code'],2)
        self.assertEqual(verified['capsule_original_raw_sha256'],
                         sealed['capsule_original_raw_sha256'])

    def test_same_exact_input_produces_identical_deterministic_archive(self):
        sealed=self.seal()
        other=str(self.f.f.dir/'same-originals-again.zip')
        repeated=self.seal(out=other)
        self.assertEqual(sealed['capsule_original_raw_sha256'],
                         repeated['capsule_original_raw_sha256'])
        self.assertEqual(Path(self.outer).read_bytes(),Path(other).read_bytes())

    def test_tampered_ack_with_recomputed_ack_sha_cannot_be_sealed(self):
        ack_doc=json.loads(Path(self.f.ack_file).read_bytes())
        ack_doc['signature_ed25519']='0'*128
        changed=self.f.f.write('bad-original-seventh-ack.json',reg.raw_doc(ack_doc))
        with self.assertRaisesRegex(anchor.AnchorError,'SIGNATURE_NOT_AUTHENTIC'):
            self.seal(ack_file=changed,
                      expected_ack_sha256=c.case.sha(Path(changed).read_bytes()))
        self.assertFalse(Path(self.outer).exists())

    def test_source_history_must_pass_before_sealing_anything(self):
        with patch.object(reg.receipt,'verify',side_effect=anchor.AnchorError(
                'BROKEN_ORIGINAL_EC318_SIGNATURE','permission_denied')):
            with self.assertRaisesRegex(anchor.AnchorError,'BROKEN_ORIGINAL_EC318_SIGNATURE'):
                self.seal()
        self.assertFalse(Path(self.outer).exists())

    def test_seal_detects_concurrent_source_change_after_full_replay(self):
        original=c._replay
        def changed_after_replay(**kwargs):
            result=original(**kwargs)
            Path(self.f.ack_file).write_bytes(b'CHANGED WITHOUT NEW VALID SIGNATURE')
            return result
        with patch.object(c,'_replay',side_effect=changed_after_replay):
            with self.assertRaisesRegex(anchor.AnchorError,
                                        'RECHECKED_EC322_ACK_ORIGINAL_WHOLE_SHA_MISMATCH'):
                self.seal()
        self.assertFalse(Path(self.outer).exists())

    def test_existing_destination_or_source_filename_never_overwritten(self):
        self.f.f.write('complete-originals-capsule.zip',b'do not overwrite')
        with self.assertRaisesRegex(anchor.AnchorError,'OUTPUT_EXISTS'):
            self.seal()
        self.assertEqual(Path(self.outer).read_bytes(),b'do not overwrite')
        with self.assertRaisesRegex(anchor.AnchorError,'THREE_DISTINCT'):
            self.seal(out=self.f.ack_file)
        with self.assertRaisesRegex(anchor.AnchorError,'THREE_DISTINCT'):
            self.seal(out=self.f.f.case_file)

    def test_outer_and_both_inner_whole_sha_are_required_outside(self):
        sealed=self.seal()
        for change in ({'expected_capsule_sha256':'aa'*32},
                       {'expected_bundle_sha256':'bb'*32},
                       {'expected_ack_sha256':'cc'*32},
                       {'ack_id':'wrong_ack'},
                       {'case_id':'wrong_case'},
                       {'seventh_receiver_challenge_sha256':'ee'*32},
                       {'registrar_public_hex':self.f.receiver_pub}):
            with self.subTest(change=change):
                with self.assertRaises((anchor.AnchorError,reg.io.HostError)):
                    self.check(sealed['capsule_original_raw_sha256'],**change)

    def test_manifest_repin_cannot_replace_independent_trust(self):
        sealed=self.seal()
        def tamper(docs):
            entries=[]
            for name,raw in docs:
                if name==c.MANIFEST_FILE:
                    obj=json.loads(raw)
                    obj['ec321_external_pins']['case_id']='unsigned_new_identity'
                    raw=reg.raw_doc(obj)
                entries.append((name,raw))
            return entries
        tampered,sha=self.edit_zip(tamper)
        with self.assertRaisesRegex(anchor.AnchorError,'MANIFEST_NOT_EQUAL_ALL_OUTSIDE'):
            self.check(sha,capsule_file=tampered)
        self.assertEqual(sealed['exit_code'],2)

    def test_inner_member_mutated_even_with_new_outer_sha_fails(self):
        self.seal()
        bad,sha=self.edit_zip(lambda docs:[
            (name,data+b'X' if name==c.ACK_MEMBER else data) for name,data in docs])
        with self.assertRaisesRegex(anchor.AnchorError,'MANIFEST_NOT_EQUAL_ALL_OUTSIDE'):
            self.check(sha,capsule_file=bad)

    def test_extra_member_and_traversal_are_rejected_without_extraction(self):
        self.seal()
        for suffix in ('extra.json','../injected.json'):
            with self.subTest(suffix=suffix):
                path,sha=self.edit_zip(lambda docs:docs+[(suffix,b'bad')])
                with self.assertRaisesRegex(anchor.AnchorError,'EXACT_THREE_ORDERED'):
                    self.check(sha,capsule_file=path)
        self.assertFalse((self.f.f.dir/'injected.json').exists())

    def test_duplicate_member_and_compression_rejected_even_with_outer_pin(self):
        self.seal()
        with zipfile.ZipFile(self.outer) as archive:
            docs=[(n,archive.read(n)) for n in archive.namelist()]
        for variant in ('duplicate','compressed'):
            out=BytesIO()
            with zipfile.ZipFile(out,'w') as zipout:
                for name,data in docs:
                    info=c._zip_info(name)
                    if variant=='compressed' and name==c.CASE_MEMBER:
                        info.compress_type=zipfile.ZIP_DEFLATED
                    zipout.writestr(info,data)
                if variant=='duplicate':
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore',UserWarning)
                        zipout.writestr(c._zip_info(c.ACK_MEMBER),docs[-1][1])
            path=self.f.f.write(variant+'.zip',out.getvalue())
            with self.subTest(variant=variant):
                with self.assertRaisesRegex(anchor.AnchorError,
                                            'EXACT_THREE_ORDERED|UNSAFE_NONCANONICAL'):
                    self.check(c.case.sha(out.getvalue()),capsule_file=path)

    def test_noncanonical_trailing_bytes_or_foreign_zip_metadata_rejected(self):
        self.seal()
        raw=Path(self.outer).read_bytes()+b'GARBAGE'
        bad=self.f.f.write('trailing.zip',raw)
        with self.assertRaises(anchor.AnchorError):
            self.check(c.case.sha(raw),capsule_file=bad)
        with zipfile.ZipFile(self.outer) as original:
            docs=[(n,original.read(n)) for n in original.namelist()]
        out=BytesIO()
        with zipfile.ZipFile(out,'w') as archive:
            for name,data in docs:
                info=c._zip_info(name)
                if name==c.CASE_MEMBER:
                    info.extra=b'\x01\x00\x00\x00'
                archive.writestr(info,data)
        bad=self.f.f.write('foreign-metadata.zip',out.getvalue())
        with self.assertRaisesRegex(anchor.AnchorError,'UNSAFE_NONCANONICAL'):
            self.check(c.case.sha(out.getvalue()),capsule_file=bad)

    def test_invalid_archive_owner_mode_or_symlink_rejected(self):
        sealed=self.seal()
        os.chmod(self.outer,0o644)
        with self.assertRaisesRegex(anchor.AnchorError,'OWNER_0600_ONE_REGULAR_LINK'):
            self.check(sealed['capsule_original_raw_sha256'])
        os.chmod(self.outer,0o600)
        link=str(self.f.f.dir/'capsule-symlink.zip')
        os.symlink(self.outer,link)
        with self.assertRaises(anchor.AnchorError):
            self.check(sealed['capsule_original_raw_sha256'],capsule_file=link)

    def test_even_unchanged_authentic_capsule_replays_old_crypto_every_time(self):
        sealed=self.seal()
        with patch.object(reg.receipt,'verify',side_effect=anchor.AnchorError(
            'OLD_HISTORY_REVERIFICATION_REJECTED','permission_denied')):
            with self.assertRaisesRegex(anchor.AnchorError,'OLD_HISTORY_REVERIFICATION_REJECTED'):
                self.check(sealed['capsule_original_raw_sha256'])

    def test_console_only_one_read_only_mode_and_fixed_subprocess(self):
        values=dict(self.trust,capsule_file=self.outer,
                    expected_capsule_sha256='dd'*32)
        with patch.object(console,'_command',side_effect=AssertionError(
                'WRONG_ACTION_MUST_FAIL_BEFORE_CHILD_LAUNCH')):
            with self.assertRaisesRegex(console.ConsoleError,'ONLY_DELIVERYAUDIT'):
                console.audit_fork_capsule('DeliveryAudit','Seal',**values)
            with self.assertRaisesRegex(console.ConsoleError,'ONLY_DELIVERYAUDIT'):
                console.audit_fork_capsule('CodeSave','VerifyPortableOriginalForkCapsule',
                                           **values)
        calls=[]
        def child(argv,*,timeout,max_output):
            calls.append((argv,timeout,max_output))
            return 2,dict(schema=c.RESULT_SCHEMA,command='seal',exit_code=2)
        with patch.object(console,'_command',side_effect=child):
            with self.assertRaisesRegex(console.ConsoleError,'CAPSULE_VERIFY_REPLY_INCONSISTENT'):
                console.audit_fork_capsule('DeliveryAudit',
                    'VerifyPortableOriginalForkCapsule',**values)
        args,timeout,max_output=calls[0]
        self.assertEqual(args[:4],[console.sys.executable,'-I','-B',str(console.FORK_CAPSULE)])
        self.assertEqual(args[4],'verify')
        self.assertNotIn('seal',args)
        self.assertNotIn('--out',args)
        self.assertNotIn('--private-key-file',args)
        self.assertEqual(timeout,3600)
        self.assertLessEqual(max_output,30000)

    def test_cli_parser_only_exposes_seal_verify_and_verify_has_no_write_args(self):
        from . import operator
        root=operator.parser()
        commands=next(action for action in root._actions
                      if getattr(action,'choices',None) is not None).choices
        self.assertEqual(set(commands),{'seal','verify'})
        verify=commands['verify']
        accepted={option for act in verify._actions for option in act.option_strings}
        self.assertNotIn('--out',accepted)
        self.assertNotIn('--private-key-file',accepted)
        self.assertNotIn('--bundle-file',accepted)
        self.assertNotIn('--ack-file',accepted)


if __name__=='__main__':
    unittest.main()
