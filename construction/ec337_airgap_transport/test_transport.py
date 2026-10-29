#!/usr/bin/env python3
"""EC337 focused functionality. Genuine local 8th/9th Ed25519; EC317/318 MOCK.

A positive offline bytes-inspection/installation result is not an institution's
independent SHA custody nor a complete unmocked production EC294->333 proof.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile

from ec295_delivery_anchor import anchor
from ec321_fork_case_transport import case
from ec335_nested_source_closure import test_closure as previous
from ec336_portable_signed_replay import replay
from scripts import ces_next
from . import transport


class OfflineOriginalTransportTests(unittest.TestCase):
    def setUp(self):
        self.old=previous.NestedOriginalClosureTests(
            methodName='test_complete_receiver_copy_audit_and_embedded_member_recheck')
        self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        self.base=self.old.root
        self.arch=str(self.base/'ec337-originals-transport.zip')
        self.control_root=str(self.base/'received-controls')
        self.dest_root=self.old.destination_root
        self.bundle_sha=None

    def pins(self):
        return dict(expected_first_hop_plan_sha256=self.old.old.plan_sha,
                    expected_closure_sha256=self.old.closure_sha,
                    expected_map_sha256=self.old.map_sha,
                    expected_handoff_sha256=self.old.handoff_sha,
                    left_expected_manifest_sha256=self.old.old.old.options()[
                        'left_expected_manifest_sha256'],
                    right_expected_manifest_sha256=self.old.old.old.options()[
                        'right_expected_manifest_sha256'])

    def create(self):
        self.old.create()
        self.old.prepare()
        args=dict(out=self.arch,first_hop_plan_file=self.old.old.plan,
                  closure_file=self.old.closure,map_file=self.old.mapping,
                  **self.pins())
        result=transport.create_bundle(**args)
        self.bundle_sha=result['bundle_original_raw_sha256']
        return result

    def inspect(self,**changes):
        args=dict(bundle_file=self.arch,expected_bundle_sha256=self.bundle_sha,
                  **self.pins())
        args.update(changes)
        return transport.inspect_bundle(**args)

    def receiver(self):
        os.mkdir(self.dest_root,0o700)
        os.mkdir(self.control_root,0o700)

    def install(self,**changes):
        args=dict(bundle_file=self.arch,expected_bundle_sha256=self.bundle_sha,
                  control_root=self.control_root,destination_root=self.dest_root,
                  **self.pins())
        args.update(changes)
        return transport.install_bundle(**args)

    def source_rows(self):
        return json.loads(Path(self.old.closure).read_bytes())['sources']

    def test_deterministic_real_byte_export_and_canonical_bounded_zip(self):
        created=self.create()
        inspect=self.inspect()
        self.assertEqual(created['exit_code'],2)
        self.assertEqual(inspect['exit_code'],2)
        self.assertEqual(inspect['persistent_original_source_count'],22)
        self.assertEqual(inspect['nested_zip_member_identity_declared_count'],15)
        self.assertTrue(inspect['all_archive_members_whole_sha_verified'])
        self.assertTrue(all(inspect[k] is False for k in transport.FALSE_FIELDS))
        with zipfile.ZipFile(self.arch) as z:
            self.assertEqual(len(z.namelist()),27)
            self.assertEqual(z.namelist()[:5],['manifest.json',transport.CUSTODY_SLOTS_NAME,*transport.CONTROL_NAMES])
            worksheet=json.loads(z.read(transport.CUSTODY_SLOTS_NAME))
            self.assertIsNone(worksheet['outside_bundle_bundle_whole_sha256'])
            self.assertFalse(worksheet['custody_verified_by_this_bundle'])
            originals=self.source_rows()
            for i,row in enumerate(originals,1):
                self.assertEqual(z.read(transport._name(i)),
                                 Path(row['source_path']).read_bytes())
        duplicate=str(self.base/'ec337-second.zip')
        a=transport.create_bundle(out=duplicate,first_hop_plan_file=self.old.old.plan,
                closure_file=self.old.closure,map_file=self.old.mapping,**self.pins())
        self.assertEqual(a['bundle_original_raw_sha256'],self.bundle_sha)
        self.assertEqual(Path(self.arch).read_bytes(),Path(duplicate).read_bytes())

    def test_install_performs_actual_ec335_byte_and_nested_verify(self):
        self.create();self.receiver()
        result=self.install()
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['receiver_installed_sources_and_controls_byte_rechecked'])
        mapping=json.loads(Path(self.old.mapping).read_bytes())['locations']
        for row in mapping:
            self.assertEqual(Path(row['source_path']).read_bytes(),
                             Path(row['destination_path']).read_bytes())
            self.assertEqual(os.stat(row['destination_path']).st_mode&0o777,0o600)
        for name in transport.LOCAL_CONTROL_FILES:
            self.assertEqual(os.stat(Path(self.control_root)/name).st_mode&0o777,
                             0o600)
        self.assertFalse(result['installed_bytes_alone_prove_full_ec294_to_ec333_signature_replay'])

    def test_install_then_guarded_old_absolute_path_history_with_sources_physically_absent(self):
        self.create();self.receiver();self.install()
        sources=self.source_rows()
        for row in sources:
            orig=Path(row['source_path'])
            orig.rename(orig.with_name(orig.name+'.ec337-old-not-present'))
        self.assertFalse(any(os.path.lexists(row['source_path']) for row in sources))
        result=replay.verify_relocated_history(
            first_hop_plan_file=str(Path(self.control_root)/'ec334-plan.json'),
            closure_file=str(Path(self.control_root)/'ec335-closure.json'),
            map_file=str(Path(self.control_root)/'ec335-map.json'),**self.pins())
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['ec333_to_ec294_inherited_original_signatures_replayed_locally'])
        self.assertEqual(result['receiver_observed_persistent_guarded_source_count'],
                         len(sources))

    def test_wrong_bundle_sha_and_any_one_of_six_outside_roots_fail_closed(self):
        self.create()
        for key in ['expected_bundle_sha256',*self.pins()]:
            with self.subTest(key=key):
                with self.assertRaises(anchor.AnchorError):
                    self.inspect(**{key:'ab'*32})

    def test_payload_mutation_refused_even_if_bundle_sha_recomputed_locally(self):
        self.create()
        # Flip content byte in a stored source entry, not the central directory.
        with zipfile.ZipFile(self.arch) as z:
            entry=z.getinfo(transport._name(1))
            off=entry.header_offset+30+len(entry.filename)
        with open(self.arch,'r+b') as fp:
            fp.seek(off);x=fp.read(1);fp.seek(off);fp.write(bytes([x[0]^0x01]))
        new_sha=case.sha(Path(self.arch).read_bytes())
        with self.assertRaises(Exception):
            self.inspect(expected_bundle_sha256=new_sha)

    def test_zip_comment_hidden_bytes_symlink_and_mode_not_accepted(self):
        self.create()
        with zipfile.ZipFile(self.arch,'a') as z:
            z.comment=b'unsigned extra trailer'
        self.bundle_sha=case.sha(Path(self.arch).read_bytes())
        with self.assertRaisesRegex(anchor.AnchorError,'ARCHIVE_'):
            self.inspect()
        os.chmod(self.arch,0o644)
        with self.assertRaisesRegex(anchor.AnchorError,'PRIVATE_BUNDLE'):
            self.inspect()

    def test_receiver_no_overwrite_or_partial_write_when_target_preexists(self):
        self.create();self.receiver()
        original=str(Path(self.control_root)/'ec334-plan.json')
        Path(original).write_bytes(b'previous user bytes')
        with self.assertRaisesRegex(anchor.AnchorError,'OVERWRITE'):
            self.install()
        self.assertEqual(Path(original).read_bytes(),b'previous user bytes')
        self.assertFalse(any(Path(self.dest_root).iterdir()))

    def test_receiver_rollback_owns_only_its_inodes_when_nested_verify_fails(self):
        self.create();self.receiver()
        with patch.object(transport.closure,'verify_copies',side_effect=
                          anchor.AnchorError('SIMULATED_NESTED_COPY_FAILURE')):
            with self.assertRaisesRegex(anchor.AnchorError,'SIMULATED'):
                self.install()
        self.assertEqual(list(Path(self.control_root).iterdir()),[])
        self.assertEqual(list(Path(self.dest_root).iterdir()),[])

    def test_receiver_partial_write_failure_removes_only_created_files_and_dirs(self):
        self.create();self.receiver()
        original=transport._exclusive_bytes
        count=[0]
        def fail_later(*args):
            count[0]+=1
            if count[0]==6:
                raise anchor.AnchorError('EC337_SIMULATED_COPY_INTERRUPTION')
            return original(*args)
        with patch.object(transport,'_exclusive_bytes',side_effect=fail_later):
            with self.assertRaisesRegex(anchor.AnchorError,'SIMULATED_COPY'):
                self.install()
        self.assertEqual(list(Path(self.control_root).iterdir()),[])
        self.assertEqual(list(Path(self.dest_root).iterdir()),[])

    def test_destination_root_not_caller_pinned_map_root_is_denied(self):
        self.create();self.receiver()
        other=str(self.base/'wrong-receiver-root')
        os.mkdir(other,0o700)
        with self.assertRaisesRegex(anchor.AnchorError,'MAP_DESTINATIONS'):
            self.install(destination_root=other)
        self.assertEqual(list(Path(other).iterdir()),[])

    def test_unified_route_never_exposes_writers_or_false_exit0(self):
        self.create()
        opts=dict(bundle_file=self.arch,expected_bundle_sha256=self.bundle_sha,
                  **self.pins())
        with self.assertRaisesRegex(ces_next.ConsoleError,'ONLY_DELIVERYAUDIT'):
            ces_next.audit_airgap_transport('DeliveryAudit','InstallBundle',**opts)
        with patch.object(ces_next,'_command',return_value=(0,{
            'schema':transport.RESULT_SCHEMA,'exit_code':0})):
            with self.assertRaisesRegex(ces_next.ConsoleError,'PROCESS_EXIT_INVALID'):
                ces_next.audit_airgap_transport('DeliveryAudit',
                    'VerifyPinnedAirgapOriginalTransport',**opts)
        with patch.object(ces_next,'_command',return_value=(2,{
            'schema':transport.RESULT_SCHEMA,'exit_code':2})):
            with self.assertRaisesRegex(ces_next.ConsoleError,'UNGROUNDED'):
                ces_next.audit_airgap_transport('DeliveryAudit',
                    'VerifyPinnedAirgapOriginalTransport',**opts)

    def test_real_isolated_standalone_create_and_receiver_install(self):
        self.old.create();self.old.prepare()
        command=[sys.executable,'-I','-B','scripts/ces_cas_airgap_transport.py']
        args=[]
        for key,value in self.pins().items():
            args+=['--'+key.replace('_','-'),value]
        new_archive=str(self.base/'isolated-transport.zip')
        r=subprocess.run(command+['create-bundle','--out',new_archive,
            '--first-hop-plan-file',self.old.old.plan,
            '--closure-file',self.old.closure,
            '--map-file',self.old.mapping]+args,capture_output=True,text=True,
            timeout=150)
        self.assertEqual(r.returncode,2,r.stdout[:700]+r.stderr[:350])
        produced=json.loads(r.stdout)
        self.assertEqual(produced['bundle_original_raw_sha256'],
                         case.sha(Path(new_archive).read_bytes()))
        self.receiver()
        r=subprocess.run(command+['install-bundle','--bundle-file',new_archive,
            '--expected-bundle-sha256',produced['bundle_original_raw_sha256'],
            '--control-root',self.control_root,
            '--destination-root',self.dest_root]+args,
            capture_output=True,text=True,timeout=150)
        self.assertEqual(r.returncode,2,r.stdout[:700]+r.stderr[:350])
        self.assertTrue(json.loads(r.stdout)[
            'receiver_installed_sources_and_controls_byte_rechecked'])
        self.assertEqual(len(json.loads(Path(self.old.mapping).read_bytes())[
            'locations']),22)

    def test_symlink_receiver_root_denied_no_external_write(self):
        self.create();self.receiver()
        outside=self.base/'forbidden-outside'
        outside.mkdir(mode=0o700)
        os.rmdir(self.dest_root)
        Path(self.dest_root).symlink_to(outside,target_is_directory=True)
        with self.assertRaises(Exception):
            self.install()
        self.assertEqual(list(outside.iterdir()),[])
        self.assertEqual(list(Path(self.control_root).iterdir()),[])

    def test_isolated_standalone_and_unified_read_only_really_inspect(self):
        self.create()
        args=['--bundle-file',self.arch,'--expected-bundle-sha256',self.bundle_sha]
        for key,value in self.pins().items():
            args+=['--'+key.replace('_','-'),value]
        prefixes=(
            [sys.executable,'-I','-B','scripts/ces_cas_airgap_transport.py',
             'inspect-bundle'],
            [sys.executable,'-I','-B','scripts/ces_next.py',
             'audit-airgap-transport','DeliveryAudit',
             'VerifyPinnedAirgapOriginalTransport'],
        )
        for cmd in prefixes:
            r=subprocess.run(cmd+args,capture_output=True,text=True,timeout=90)
            self.assertEqual(r.returncode,2,r.stdout[:1000]+r.stderr[:400])
            result=json.loads(r.stdout)
            self.assertEqual(result['exit_code'],2)
            self.assertEqual(result['bundle_original_raw_sha256'],self.bundle_sha)
        denied=subprocess.run(prefixes[1][:4]+['audit-airgap-transport',
                'DeliveryAudit','InstallBundle']+args,capture_output=True,text=True,
                timeout=60)
        self.assertEqual(denied.returncode,3)


if __name__=='__main__':
    unittest.main()
