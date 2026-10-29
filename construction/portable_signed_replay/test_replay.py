#!/usr/bin/env python3
"""EC336 focused behavior. Local eighth/ninth signatures genuine; deep EC317/318 MOCK.

Positive local tests patch inherited old structural fixtures. True -I -B isolated
production must refuse the mocked old history: NOT a production-chain PASS.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from finding_query_host import protocol as io
from delivery_anchor import anchor
from fork_case_transport import case
from nested_source_closure import test_closure as inherited
from scripts import ces_next
from . import replay


class ReceiverOriginalSignedReplayTests(unittest.TestCase):
    def setUp(self):
        self.fixture = inherited.NestedOriginalClosureTests(
            methodName='test_complete_receiver_copy_audit_and_embedded_member_recheck')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def ready(self) -> dict:
        self.fixture.ready()
        return dict(self.fixture.options(),
            expected_handoff_sha256=self.fixture.handoff_sha,
            left_expected_manifest_sha256=self.fixture.old.old.options()[
                'left_expected_manifest_sha256'],
            right_expected_manifest_sha256=self.fixture.old.old.options()[
                'right_expected_manifest_sha256'])

    def original_rows(self) -> list[dict]:
        return json.loads(Path(self.fixture.closure).read_bytes())['sources']

    def test_receiver_real_replay_path_with_original_files_physically_absent(self):
        kw = self.ready()
        rows = self.original_rows()
        original = {row['source_path']: Path(row['source_path']).read_bytes()
                    for row in rows}
        for row in rows:
            path = Path(row['source_path'])
            path.rename(path.with_name(path.name + '.ec336-held-out'))
        self.assertTrue(all(not os.path.lexists(row['source_path']) for row in rows))
        result = replay.verify_relocated_history(**kw)
        self.assertEqual(result['exit_code'], 2)
        self.assertTrue(result['ec333_complete_handoff_canonical_bytes_reconstructed'])
        self.assertTrue(result['ec333_to_ec294_inherited_original_signatures_replayed_locally'])
        self.assertEqual(result['persistent_original_source_count'], len(rows))
        self.assertEqual(result['receiver_observed_persistent_guarded_source_count'], len(rows))
        self.assertGreater(result['receiver_verified_temporary_import_read_event_count'], 0)
        mapping = json.loads(Path(self.fixture.mapping).read_bytes())['locations']
        for item in mapping:
            self.assertEqual(Path(item['destination_path']).read_bytes(),
                             original[item['source_path']])
        self.assertTrue(all(result[flag] is False for flag in replay.FALSE_FIELDS))
        self.assertTrue(all(not os.path.lexists(p) for p in original))

    def test_tampered_copy_fails_even_if_old_source_still_exists(self):
        kw = self.ready()
        mapping = json.loads(Path(self.fixture.mapping).read_bytes())['locations']
        path = Path(mapping[0]['destination_path'])
        path.write_bytes(path.read_bytes() + b'\nUNSIGNED-CHANGED')
        with self.assertRaisesRegex(anchor.AnchorError,
                                    'ORIGINAL_COPY_BYTES_OR_LENGTH_MISMATCH'):
            replay.verify_relocated_history(**kw)

    def test_missing_copy_never_falls_back_to_present_old_path(self):
        kw = self.ready()
        mapping = json.loads(Path(self.fixture.mapping).read_bytes())['locations']
        path = Path(mapping[0]['destination_path'])
        path.unlink()
        with self.assertRaises((anchor.AnchorError, OSError, io.HostError)):
            replay.verify_relocated_history(**kw)

    def test_all_external_sha_roots_and_control_pins_are_not_self_authenticating(self):
        kw = self.ready()
        for field in ('expected_first_hop_plan_sha256', 'expected_closure_sha256',
                      'expected_map_sha256', 'expected_handoff_sha256',
                      'left_expected_manifest_sha256',
                      'right_expected_manifest_sha256'):
            wrong = dict(kw, **{field: 'a1'*32})
            with self.subTest(field=field):
                with self.assertRaises(anchor.AnchorError):
                    replay.verify_relocated_history(**wrong)

    def test_fake_positive_replay_reply_without_reading_all_sources_is_denied(self):
        kw = self.ready()
        forged = {
            'command': 'verify-handoff', 'exit_code': 2,
            'status': 'unsigned_offline_delta_handoff_exactly_reconstructed_unresolved',
            'handoff_original_exactly_reconstructed_from_both_original_signed_histories': True,
            'both_ec331_manifests_and_all_inherited_old_signed_histories_replayed': True,
            'handoff_and_both_manifest_all_inherited_original_pins_late_rechecked': True,
            **{flag: False for flag in replay.handoff.FALSE_FIELDS},
        }
        with patch.object(replay.handoff, 'verify_handoff', return_value=forged):
            with self.assertRaisesRegex(anchor.AnchorError,
                                        'DID_NOT_OBSERVE_EXACT_EXPECTED'):
                replay.verify_relocated_history(**kw)

    def test_unmapped_new_source_read_is_denied_before_forged_success(self):
        kw = self.ready()
        forbidden = str(self.fixture.root / 'never-in-source-closure.json')
        Path(forbidden).write_text('a fake source')
        os.chmod(forbidden, 0o600)
        def extra_read(**_kw):
            io._open_regular(forbidden, 400, private=True)
            self.fail('unmapped file must not have been read')
        with patch.object(replay.handoff, 'verify_handoff', side_effect=extra_read):
            with self.assertRaisesRegex(io.HostError, 'UNMAPPED_ORIGINAL_SOURCE_READ'):
                replay.verify_relocated_history(**kw)

    def test_exact_temporary_import_grants_have_no_generic_prefix_or_leak(self):
        with io._scoped_original_source_reads(bindings={}):
            with self.assertRaisesRegex(io.HostError, 'UNMAPPED'):
                io._original_source_read_path('/tmp/ces-ec321-fork-receive-mock/a.json')
            with io._scoped_verified_local_import_reads(frozenset((
                '/tmp/ces-ec321-fork-receive-mock/a.json',))):
                self.assertEqual(io._original_source_read_path(
                    '/tmp/ces-ec321-fork-receive-mock/a.json'),
                    '/tmp/ces-ec321-fork-receive-mock/a.json')
                with self.assertRaisesRegex(io.HostError, 'UNMAPPED'):
                    io._original_source_read_path(
                        '/tmp/ces-ec321-fork-receive-mock/b.json')
            with self.assertRaisesRegex(io.HostError, 'UNMAPPED'):
                io._original_source_read_path('/tmp/ces-ec321-fork-receive-mock/a.json')

    def test_old_registry_metadata_checks_follow_same_bound_inode(self):
        kw = self.ready()
        path = self.original_rows()[0]['source_path']
        locations = json.loads(Path(self.fixture.mapping).read_bytes())['locations']
        dest = next(item['destination_path'] for item in locations
                    if item['source_path'] == path)
        real = Path(path)
        real.rename(real.with_name(real.name + '.held'))
        from offline_transfer_registry import registry as reg
        with io._scoped_original_source_reads(bindings={path: dest}):
            result = reg._private_read(path, 110_000_000, 'EC336_EXACT_MAPPED_FILE')
            self.assertEqual(result, Path(dest).read_bytes())
            os.chmod(dest, 0o644)
            with self.assertRaisesRegex(anchor.AnchorError, 'OWNER_0600'):
                reg._private_read(path, 110_000_000, 'EC336_MODE_FAILURE')

    def test_real_isolated_production_refuses_deeper_mock_signatures(self):
        kw = self.ready()
        argv = [i for key, value in kw.items()
                for i in ('--' + key.replace('_', '-'), value)]
        for prefix in (
            [sys.executable, '-I', '-B', 'scripts/ces_cas_relocated_signed_replay.py',
             'verify-signed-replay'],
            [sys.executable, '-I', '-B', 'scripts/ces_next.py',
             'audit-relocated-signed-replay', 'DeliveryAudit',
             'VerifyRelocatedOriginalSignedHistory'],
        ):
            proc = subprocess.run(prefix + argv, capture_output=True, text=True,
                                  timeout=100)
            self.assertIn(proc.returncode, (3, 4, 5), proc.stdout + proc.stderr)
            denial = json.loads(proc.stdout)
            self.assertFalse(denial.get('ec333_to_ec294_inherited_original_signatures_replayed_locally'))
            self.assertNotEqual(denial.get('status'), replay.RESULT_STATUS)

    def test_unified_readonly_entry_refuses_forged_success_and_writer_mode(self):
        kw = self.ready()
        with self.assertRaisesRegex(ces_next.ConsoleError, 'EC336_ONLY'):
            ces_next.audit_relocated_signed_replay(
                'DeliveryAudit', 'SignAndRelocateOriginals', **kw)
        with patch.object(ces_next, '_command', return_value=(0, {'status': 'success'})):
            with self.assertRaisesRegex(ces_next.ConsoleError, 'PROCESS_EXIT_INVALID'):
                ces_next.audit_relocated_signed_replay(
                    'DeliveryAudit', 'VerifyRelocatedOriginalSignedHistory', **kw)
        self.assertNotIn('create-closure', ces_next.build_parser().format_help())
        self.assertNotIn('sign-request', ces_next.build_parser().format_help())


if __name__ == '__main__':
    unittest.main()
