#!/usr/bin/env python3
"""EC262 real nonroot file/fsync/HMAC-chain journal cases; no OCI."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec262_signed_audit_host.audit import AuditLog, AuditError


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0,
                     'operator-private Linux journal requires nonroot user')
class AuditJournalTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='ces262-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.directory = self.root/'audit'
        self.directory.mkdir(mode=0o700)
        self.key = self.root/'hmac.key'
        self.key.write_bytes(os.urandom(32))
        self.key.chmod(0o600)
        self.log = self.directory/'events.jsonl'
        self.head = self.directory/'head.json'

    def record_some(self):
        with AuditLog(str(self.directory), str(self.key)) as journal:
            journal.record('service_start')
            journal.record('session_open', 'a' * 24)
            journal.record('begin_authorized', 'a' * 24)
            return journal.summary()

    def verify(self):
        with AuditLog(str(self.directory), str(self.key), create=False) as journal:
            return journal.summary()

    def test_01_durable_append_reopen_and_partial_verification(self):
        summary = self.record_some()
        self.assertEqual(summary['event_count'], 3)
        self.assertEqual(summary, self.verify())
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.head.stat().st_mode & 0o777, 0o600)
        records = [json.loads(line) for line in self.log.read_bytes().splitlines()]
        self.assertEqual([obj['seq'] for obj in records], [1, 2, 3])
        self.assertEqual(records[-1]['prev_mac'], records[-2]['mac'])
        self.assertEqual(len(records[-1]['mac']), 64)
        with AuditLog(str(self.directory), str(self.key)) as journal:
            journal.record('service_closed')
            self.assertEqual(journal.count, 4)
        self.assertEqual(self.verify()['event_count'], 4)

    def test_02_modified_record_fails_mac_or_head(self):
        self.record_some()
        raw = self.log.read_bytes().replace(b'begin_authorized', b'session_denied')
        self.log.write_bytes(raw)
        with self.assertRaises(AuditError):
            self.verify()

    def test_03_complete_suffix_removal_denied_by_head_seal(self):
        self.record_some()
        raw = self.log.read_bytes()
        self.log.write_bytes(raw[:raw.rfind(b'\n', 0, len(raw)-1)+1])
        with self.assertRaisesRegex(AuditError, 'EC262_AUDIT_HEAD_MISMATCH'):
            self.verify()

    def test_04_partial_line_and_head_corruption_are_denied(self):
        self.record_some()
        self.log.write_bytes(self.log.read_bytes()[:-3])
        with self.assertRaisesRegex(AuditError, 'EC262_AUDIT_PARTIAL_RECORD'):
            self.verify()
        self.log.write_bytes(b'')
        with self.assertRaisesRegex(AuditError, 'EC262_AUDIT_HEAD_MISMATCH'):
            self.verify()

    def test_05_wrong_key_and_symlink_deny_reopen(self):
        self.record_some()
        other = self.root/'wrong.key'
        other.write_bytes(os.urandom(32))
        other.chmod(0o600)
        with self.assertRaises(AuditError):
            with AuditLog(str(self.directory), str(other), create=False):
                pass
        self.log.rename(self.directory/'moved.jsonl')
        self.log.symlink_to(self.directory/'moved.jsonl')
        with self.assertRaises(AuditError):
            self.verify()

    def test_06_second_writer_lock_and_changed_log_are_blocked(self):
        with AuditLog(str(self.directory), str(self.key)) as first:
            first.record('service_start')
            with self.assertRaises(AuditError):
                with AuditLog(str(self.directory), str(self.key)):
                    pass
            self.log.write_bytes(self.log.read_bytes() + b'x')
            with self.assertRaisesRegex(AuditError, 'EC262_AUDIT_REPLACED_OR_CHANGED'):
                first.record('service_closed')
            self.assertTrue(first.poisoned)

    def test_07_broken_append_poisoned_instead_of_restarting(self):
        with AuditLog(str(self.directory), str(self.key)) as first:
            first.record('service_start')
            with mock.patch('ec262_signed_audit_host.audit.os.fsync',
                            side_effect=OSError('disk full')):
                with self.assertRaisesRegex(AuditError, 'EC262_AUDIT_WRITE_UNAVAILABLE'):
                    first.record('service_closed')
            self.assertTrue(first.poisoned)
            with self.assertRaisesRegex(AuditError, 'EC262_AUDIT_POISONED'):
                first.record('service_closed')
        with self.assertRaises(AuditError):
            self.verify()  # Journal was written but the head was not committed.

    def test_08_untrusted_reason_and_payload_never_logged(self):
        with AuditLog(str(self.directory), str(self.key)) as journal:
            journal.record('session_denied', 'b' * 24, 'private/path/secret')
            self.assertEqual(journal.count, 1)
            with self.assertRaises(AuditError):
                journal.record('unknown_user_event', 'b' * 24)
        self.assertIn(b'UNCLASSIFIED', self.log.read_bytes())
        self.assertNotIn(b'private/path/secret', self.log.read_bytes())

    def test_09_existing_audit_head_cannot_be_silently_reset(self):
        self.record_some()
        self.log.unlink()
        with self.assertRaisesRegex(AuditError, 'EC262_AUDIT_HEAD_PREEXISTS_NEW_JOURNAL'):
            with AuditLog(str(self.directory), str(self.key)):
                pass

    def test_10_read_only_inspection_never_creates_a_journal(self):
        with self.assertRaises(AuditError):
            self.verify()
        self.assertFalse(self.log.exists())
        self.assertFalse(self.head.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
