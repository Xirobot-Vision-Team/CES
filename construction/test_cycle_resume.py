#!/usr/bin/env python3
"""EC236 local behaviour tests: actual EC231 record + EC235 pause, no action execution."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

try:
    from . import cycle_run_metadata as md
    from . import cycle_permission_pause as pp
    from . import cycle_resume as rs
except ImportError:
    import cycle_run_metadata as md
    import cycle_permission_pause as pp
    import cycle_resume as rs

SNAP = b'carefully-captured-CES-code-snapshot\n'
SOURCE = 'local:test-source'


def action(name='CodeSave', mode='Snapshot', step='step_save', deps=()):
    return {'step_id': step, 'action': name, 'mode': mode, 'depends_on': list(deps)}


@unittest.skipUnless(os.name == 'posix', 'POSIX owner-private EC231/EC235 records required')
class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ec236-local-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.meta = md.CycleMetadataStore(self.tmp.name)
        self.pauses = pp.CyclePermissionPauseStore(self.tmp.name)
        self.service = rs.CycleResumeHandler(self.tmp.name)
        self.record = self.meta.create(snapshot_bytes=SNAP, source_ref=SOURCE,
                                       actor_origin='human', actor_subject='test-operator',
                                       actions=[action(), action('Inspect', 'Snapshot', 'step_inspect', ['step_save'])])
        self.checkpoint = self.pauses.pause(self.record['run_id'])
        self.run_id = self.record['run_id']
        self.original_file = self.root / (self.run_id + '.cycle.json')
        self.pause_file = self.root / (self.run_id + pp.PAUSE_SUFFIX)
        self.original_raw = self.original_file.read_bytes()
        self.pause_raw = self.pause_file.read_bytes()

    def restore(self, snapshot=SNAP, source=SOURCE, **opts):
        return self.service.restore(self.run_id, snapshot_bytes=snapshot, source_ref=source, **opts)

    def assert_read_only(self, result):
        self.assertEqual(result['schema'], rs.SCHEMA)
        self.assertEqual(result['effects'], {x: False for x in rs.EFFECT_KEYS})
        self.assertFalse(result['permission_check']['independent_approval_verified'])
        self.assertFalse(result['permission_check']['native_gate_rechecked'])
        self.assertFalse(result['trust']['permission_authenticated'])
        self.assertFalse(result['trust']['step_execution_proven'])
        self.assertEqual(self.original_file.read_bytes(), self.original_raw)
        self.assertEqual(self.pause_file.read_bytes(), self.pause_raw)
        self.assertEqual(rs.validate_result(result), result)

    def test_restart_real_unmodified_run_restores_only_saved_denial(self):
        service = rs.CycleResumeHandler(str(self.root))
        out = service.restore(self.run_id, snapshot_bytes=SNAP, source_ref=SOURCE)
        self.assertEqual(out['status'], 'PAUSED_PERMISSION_REQUIRED')
        self.assertEqual(out['next_action'], 'REVALIDATE_INDEPENDENT_PERMISSION_OUTSIDE_RESUME')
        self.assertEqual(out['reason_code'], rs.REASONS['unchanged_wait'])
        self.assertEqual(out['permission_check']['saved_gate'], 'DENY')
        self.assertEqual(out['restored_checkpoint']['run_state'], 'NOT_STARTED')
        self.assertEqual(out['restored_checkpoint']['remaining_step_ids'], ['step_save', 'step_inspect'])
        self.assertEqual(out['restored_checkpoint']['step_states'], [
            {'step_id': 'step_save', 'state': 'NOT_STARTED'},
            {'step_id': 'step_inspect', 'state': 'NOT_STARTED'}])
        self.assertEqual(out['record_binding']['pause_sha256'], self.checkpoint['pause_sha256'])
        self.assertFalse(out['trust']['input_source_authenticated'])
        self.assert_read_only(out)

    def test_equal_length_modified_bytes_must_reprepare(self):
        stale = b'X' + SNAP[1:]
        self.assertEqual(len(stale), len(SNAP))
        out = self.restore(stale)
        self.assertEqual(out['status'], 'REPREPARE_REQUIRED')
        self.assertEqual(out['reason_code'], rs.REASONS['input_drift'])
        self.assertFalse(out['fresh_input']['bytes_match'])
        self.assertTrue(out['fresh_input']['source_ref_match'])
        self.assertEqual(out['next_action'], 'CREATE_FRESH_RUN_AND_REPREPARE')
        self.assert_read_only(out)

    def test_byte_length_change_must_reprepare(self):
        out = self.restore(SNAP + b'edited')
        self.assertEqual(out['status'], 'REPREPARE_REQUIRED')
        self.assertFalse(out['fresh_input']['bytes_match'])
        self.assert_read_only(out)

    def test_empty_snapshot_is_detected_as_change_not_reused(self):
        out = self.restore(b'')
        self.assertEqual(out['status'], 'REPREPARE_REQUIRED')
        self.assertEqual(out['fresh_input']['byte_length'], 0)
        self.assert_read_only(out)

    def test_source_ref_change_even_identical_bytes_requires_reprepare(self):
        out = self.restore(SNAP, 'local:other-source')
        self.assertEqual(out['status'], 'REPREPARE_REQUIRED')
        self.assertEqual(out['reason_code'], rs.REASONS['source_drift'])
        self.assertFalse(out['fresh_input']['source_ref_match'])
        self.assertTrue(out['fresh_input']['bytes_match'])
        self.assert_read_only(out)

    def test_simultaneous_source_and_bytes_drift(self):
        out = self.restore(b'new!', 'local:other-source')
        self.assertEqual(out['status'], 'REPREPARE_REQUIRED')
        self.assertEqual(out['reason_code'], rs.REASONS['both_drift'])
        self.assert_read_only(out)

    def test_declined_checkpoint_remains_declined_never_override(self):
        other = self.meta.create(snapshot_bytes=SNAP, source_ref=SOURCE,
                                 actor_origin='service', actor_subject='service-actor',
                                 actions=[action()])
        decl = self.pauses.pause(other['run_id'], operator_response='DECLINED')
        out = self.service.restore(other['run_id'], snapshot_bytes=SNAP, source_ref=SOURCE)
        self.assertEqual(out['status'], 'PAUSED_PERMISSION_REQUIRED')
        self.assertEqual(out['reason_code'], rs.REASONS['unchanged_declined'])
        self.assertEqual(out['restored_checkpoint']['operator_response'], 'DECLINED')
        self.assertEqual(out['record_binding']['pause_sha256'], decl['pause_sha256'])
        self.assertFalse(out['effects']['can_resume'])

    def test_independently_saved_pins_must_all_match(self):
        good = self.restore(expected_record_sha256=self.record['record_sha256'],
                            expected_action_set_sha256=self.record['action_set_sha256'],
                            expected_input_sha256=self.record['input']['sha256'],
                            expected_pause_sha256=self.checkpoint['pause_sha256'])
        self.assertEqual(good['status'], 'PAUSED_PERMISSION_REQUIRED')
        for field in ('record', 'action_set', 'input', 'pause'):
            with self.subTest(pin=field):
                bad = self.restore(**{'expected_' + field + '_sha256': '0' * 64})
                self.assertEqual(bad['status'], 'UNKNOWN_BLOCKED')
                self.assertEqual(bad['next_action'], 'MANUAL_REVIEW_NO_RECOVERY')
                self.assertFalse(bad['checkpoint_verified'])
                self.assert_read_only(bad)

    def test_missing_paused_checkpoint_never_interpreted_as_unpaused(self):
        other = self.meta.create(snapshot_bytes=SNAP, source_ref=SOURCE,
                                 actor_origin='human', actor_subject='abc', actions=[action()])
        out = self.service.restore(other['run_id'], snapshot_bytes=SNAP, source_ref=SOURCE)
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(out['reason_code'], 'CYCLE_PAUSE_NOT_FOUND')
        self.assertEqual(out['restored_checkpoint']['remaining_step_ids'], [])

    def test_unknown_run_never_revived_as_new_run(self):
        run = 'run_v1_' + 'a'*48
        out = self.service.restore(run, snapshot_bytes=SNAP, source_ref=SOURCE)
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(out['reason_code'], 'CYCLE_RUN_NOT_FOUND')
        self.assertFalse(out['effects']['new_run_created'])

    def test_corrupted_pause_even_when_fresh_changed_remains_unknown(self):
        self.pause_file.write_bytes(b'{"fake":"authorized"}\n')
        out = self.restore(b'modified')
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertFalse(out['checkpoint_verified'])
        self.assertNotEqual(out['next_action'], 'CREATE_FRESH_RUN_AND_REPREPARE')
        self.assertFalse(out['permission_check']['independent_approval_verified'])
        self.assertEqual(self.original_file.read_bytes(), self.original_raw)

    def test_corrupted_original_metadata_denies_recovery(self):
        self.original_file.write_bytes(b'not JSON')
        out = self.restore()
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertIsNone(out['record_binding']['record_sha256'])
        self.assertEqual(self.pause_file.read_bytes(), self.pause_raw)

    def test_symlink_pause_denies_restore(self):
        other = self.root / 'other.json'
        other.write_bytes(self.pause_raw)
        self.pause_file.unlink()
        self.pause_file.symlink_to(other)
        out = self.restore()
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(other.read_bytes(), self.pause_raw)

    def test_hardlink_pause_denies_restore(self):
        dup = self.root / 'linked.json'
        os.link(self.pause_file, dup)
        out = self.restore()
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(self.pause_file.read_bytes(), self.pause_raw)

    def test_handler_source_change_is_unknown_not_permission(self):
        with patch.object(self.service.pauses.next_handler, 'next',
                          side_effect=pp.CyclePauseError('CYCLE_PAUSE_HANDLER_SOURCE_CHANGED', 'source changed')):
            out = self.restore()
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertFalse(out['checkpoint_verified'])
        self.assert_read_only(out)

    def test_re_read_failure_or_mid_restore_swap_blocks(self):
        original = self.service.pauses.load
        values = [self.checkpoint, {**self.checkpoint, 'pause_sha256': '0' * 64}]
        def change(_run):
            return values.pop(0)
        with patch.object(self.service.pauses, 'load', side_effect=change):
            out = self.restore()
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(out['reason_code'], 'CYCLE_RESUME_PERSISTED_CHECKPOINT_CHANGED')
        self.assert_read_only(out)

    def test_missing_bytes_or_digest_only_not_a_fresh_input(self):
        for value in (None, 'digest', 'a'*64, bytearray(SNAP), memoryview(SNAP), True):
            with self.subTest(value=type(value).__name__):
                with self.assertRaisesRegex(rs.CycleResumeError, 'CYCLE_RESUME_FRESH_BYTES_REQUIRED'):
                    self.service.restore(self.run_id, snapshot_bytes=value, source_ref=SOURCE)
        with self.assertRaisesRegex(rs.CycleResumeError, 'CYCLE_RESUME_FRESH_BYTES_REQUIRED'):
            self.restore(b'A' * (md.MAX_SNAPSHOT_BYTES + 1))

    def test_invalid_source_run_and_pin_rejected_before_read(self):
        with self.assertRaises(md.CycleMetadataError):
            self.service.restore('run_bad', snapshot_bytes=SNAP, source_ref=SOURCE)
        for value in ('', '../escape', True, None, 'a'*129):
            with self.subTest(ref=value):
                with self.assertRaises(md.CycleMetadataError):
                    self.service.restore(self.run_id, snapshot_bytes=SNAP, source_ref=value)
        for val in ('ABC', True, '0'*63):
            with self.subTest(pin=val):
                with self.assertRaises(md.CycleMetadataError):
                    self.restore(expected_pause_sha256=val)

    def test_result_validator_rejects_synthetic_grants_or_false_status(self):
        valid = self.restore()
        for key, value in [('can_resume', True), ('handler_invoked', True), ('write_authorized', True)]:
            with self.subTest(effect=key):
                fake = json.loads(json.dumps(valid))
                fake['effects'][key] = value
                with self.assertRaises(rs.CycleResumeError):
                    rs.validate_result(fake)
        for mutate in (
            lambda x: x['permission_check'].update(independent_approval_verified=True),
            lambda x: x['trust'].update(input_source_authenticated=True),
            lambda x: x.update(status='REPREPARE_REQUIRED'),
            lambda x: x['restored_checkpoint'].update(run_state='SUCCEEDED'),
            lambda x: x.update(unrecognized=True),
        ):
            fake = json.loads(json.dumps(valid))
            mutate(fake)
            with self.assertRaises(rs.CycleResumeError):
                rs.validate_result(fake)

    def test_input_file_read_is_real_no_symlink_or_truncation(self):
        file = self.root / 'fresh.bin'
        file.write_bytes(SNAP)
        self.assertEqual(rs.read_fresh_snapshot(file), SNAP)
        file.write_bytes(b'')
        self.assertEqual(rs.read_fresh_snapshot(file), b'')
        file.write_bytes(b'z'*(md.MAX_SNAPSHOT_BYTES+1))
        with self.assertRaises(rs.CycleResumeError):
            rs.read_fresh_snapshot(file)
        file.write_bytes(SNAP)
        link = self.root / 'snapshot-symlink'
        link.symlink_to(file)
        with self.assertRaises(rs.CycleResumeError):
            rs.read_fresh_snapshot(link)
        with self.assertRaises(rs.CycleResumeError):
            rs.read_fresh_snapshot(Path('not-absolute'))
        with self.assertRaises(rs.CycleResumeError):
            rs.read_fresh_snapshot(self.root / 'missing.bin')

    def test_cli_exit_2_for_safe_paused_checkpoint(self):
        file = self.root / 'snapshot.bin'
        file.write_bytes(SNAP)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = rs.main(['restore', '--store', self.tmp.name, '--run-id', self.run_id,
                            '--source-ref', SOURCE, '--snapshot-file', str(file)])
        out = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(out['status'], 'PAUSED_PERMISSION_REQUIRED')
        self.assert_read_only(out)

    def test_cli_exit_3_on_input_drift(self):
        file = self.root / 'snapshot.bin'
        file.write_bytes(b'changed!')
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = rs.main(['restore', '--store', self.tmp.name, '--run-id', self.run_id,
                            '--source-ref', SOURCE, '--snapshot-file', str(file)])
        out = json.loads(output.getvalue())
        self.assertEqual(code, 3)
        self.assertEqual(out['status'], 'REPREPARE_REQUIRED')
        self.assert_read_only(out)

    def test_cli_exit_5_on_file_missing(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = rs.main(['restore', '--store', self.tmp.name, '--run-id', self.run_id,
                            '--source-ref', SOURCE, '--snapshot-file', str(self.root/'missing')])
        self.assertEqual(code, 5)
        self.assertEqual(json.loads(output.getvalue())['status'], 'UNKNOWN_BLOCKED')

    def test_cli_observable_snapshot_swap_blocks(self):
        f = self.root / 'existing'; f.write_bytes(SNAP)
        original = rs.read_fresh_snapshot
        seen = [SNAP, b'surprise']
        with patch.object(rs, 'read_fresh_snapshot', side_effect=lambda _: seen.pop(0)):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                exit_code = rs.main(['restore', '--store', self.tmp.name, '--run-id', self.run_id,
                                     '--source-ref', SOURCE, '--snapshot-file', str(f)])
        self.assertEqual(exit_code, 5)
        self.assertEqual(json.loads(output.getvalue())['reason_code'],
                         'CYCLE_RESUME_FILE_CHANGED_DURING_RESTORE')

    def test_cli_permissions_and_record_files_unchanged(self):
        path = self.root / 'fresh.bin'; path.write_bytes(SNAP)
        self.restore()
        self.assertEqual(stat.S_IMODE(self.original_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.pause_file.stat().st_mode), 0o600)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(list(self.root.glob('*.json'))), 2)


if __name__ == '__main__':
    unittest.main()
