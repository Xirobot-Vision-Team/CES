#!/usr/bin/env python3
"""EC262 real Git+HMAC+AF_UNIX+fork+ledger+audit, MOCK OCI/cgroup only."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec254_session_host import broker as session
from ec260_active_recall_host.test_host import ActiveRecallStrictSessionTests as previous
from ec256_cgroup_reaper import supervisor as cg
from ec257_cgroup_metrics import test_session as strict
from ec262_signed_audit_host.audit import AuditLog
from ec262_signed_audit_host import serve as audited_service
import quality_run_budget as budget


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').is_file(),
                     'nonroot Linux and Git required')
class AuditedSignedSessionTests(unittest.TestCase):
    setUp = previous.setUp
    engine = previous.engine
    remote = previous.remote
    begin_request = previous.begin_request
    join_host = previous.join_host
    kill_host = previous.kill_host

    def _prepare(self):
        self.audit_root = self.fix.root / 'audit'
        self.audit_root.mkdir(mode=0o700)
        self.audit_key = self.fix.private / 'audit.key'
        self.audit_key.write_bytes(os.urandom(32))
        self.audit_key.chmod(0o600)

    def start(self, *, fail_audit_at=None):
        self._prepare()
        child = os.fork()
        if child == 0:
            try:
                def reap(_pol, _label, _name, container_id, *, recorded, on_bound):
                    if (container_id != strict.ID or
                            recorded != self.proof.journal_event()):
                        raise cg.CgroupError('EC262_TEST_REAP_DRIFT')
                with mock.patch.object(session.runner, '_runtime_ready', return_value=None), \
                     mock.patch.object(session.runner, '_runtime_binary', return_value=None), \
                     mock.patch.object(session.runner, '_run_command', side_effect=self.engine), \
                     mock.patch.object(cg, 'CGROUP_MOUNT', str(self.root)), \
                     mock.patch.object(cg, '_mount_root', lambda: None), \
                     mock.patch.object(cg, '_boot_id', lambda: strict.BOOT), \
                     mock.patch.object(cg, '_path_for_pid',
                                       lambda pid: '/user.slice/ces-meter.service'), \
                     mock.patch.object(cg, 'bind_live',
                                       lambda pol, identity, label: self.proof), \
                     mock.patch.object(cg, 'reap_before_remove', side_effect=reap):
                    if fail_audit_at is None:
                        # Exercise the REAL new operator entrypoint, including
                        # placement, distinct keys, recovery and Git startup.
                        audited_service.run_serve(argparse.Namespace(
                            policy=str(self.fix.policy_path), socket=self.socket,
                            repo=str(self.gitfx.repo),
                            allowlist=str(self.gitfx.allowpath),
                            receipt=str(self.gitfx.output / 'source.custody.json'),
                            profile_id='python.pytest', max_sessions=1,
                            accept_timeout=3,
                            audit_root=str(self.audit_root),
                            audit_key=str(self.audit_key)))
                    else:
                        # Only the injected developer failure tests patch the
                        # host callback; no testing switch exists in the CLI.
                        with AuditLog(str(self.audit_root), str(self.audit_key)) as audit:
                            audit.record('service_start')
                            def write(event, token, reason):
                                if event == fail_audit_at:
                                    raise OSError('TEST_INJECTED_AUDIT_WRITE_FAILURE')
                                audit.record(event, token, reason)
                            session.serve(
                                str(self.fix.policy_path), self.socket,
                                max_sessions=1, accept_timeout=3,
                                require_cgroup=True, require_kernel_metrics=True,
                                startup_guard=self.gate.startup,
                                before_begin_guard=self.gate.before_begin,
                                during_session_guard=self.gate.before_begin,
                                audit_event=write)
                            audit.record('service_closed')
                os._exit(0)
            except BaseException:
                os._exit(5)
        self.child = child
        for _ in range(300):
            if os.path.exists(self.socket):
                return
            pid, status = os.waitpid(self.child, os.WNOHANG)
            if pid == self.child:
                self.child = None
                self.fail('EC262 audited host failed before binding: ' +
                          str(os.waitstatus_to_exitcode(status)))
            time.sleep(.01)
        self.fail('EC262 audited host failed to bind socket')

    def read_events(self):
        with AuditLog(str(self.audit_root), str(self.audit_key),
                      create=False) as journal:
            count = journal.count
        records = [json.loads(row) for row in
                   (self.audit_root/'events.jsonl').read_bytes().splitlines()]
        self.assertEqual(len(records), count)
        return records

    def assert_ledger_closed(self):
        journals = list(Path(self.policy['ledger_root']).glob('lease-*'))
        self.assertEqual(len(journals), 1)
        self.assertIn(b'"event":"closed"', journals[0].read_bytes())
        self.assertFalse(list(Path(self.policy['scratch_root']).iterdir()))

    def test_01_signed_git_session_journals_send_and_cleanup(self):
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            events = []
            for _ in range(50):
                entry = client.poll(80, budget.MAX_CHUNK)
                events.append(entry)
                if entry['kind'] == 'exit':
                    break
        self.assertEqual(events[-1]['kind'], 'exit')
        self.join_host()
        self.assert_ledger_closed()
        rows = self.read_events()
        labels = [row['event'] for row in rows]
        for expected in ('begin_authorized', 'begin_egress_attempt',
                         'begin_egress_enqueued', 'poll_egress_attempt',
                         'poll_egress_enqueued', 'session_cleanup_state',
                         'service_closed'):
            self.assertIn(expected, labels)
        self.assertEqual(next(row for row in rows
                              if row['event'] == 'session_cleanup_state')['reason_code'],
                         'LEDGER_SAFE')
        self.assertFalse(any('chunk_b64' in str(row) for row in rows))

    def test_02_revocation_is_recorded_and_durable_ledger_closed(self):
        self.engine_wait = 4.0
        self.start()
        client = self.remote().begin(self.begin_request())
        receipt = self.gitfx.output/'source.custody.json'
        obj = json.loads(receipt.read_text())
        obj['tampered_audit_revocation'] = True
        receipt.write_text(json.dumps(obj, sort_keys=True, separators=(',', ':')))
        client.conn.settimeout(7)
        try:
            denial = session._receive(client.conn)
            self.assertEqual(denial['status'], 'unavailable')
        finally:
            client.conn.close()
        self.join_host()
        self.assert_ledger_closed()
        rows = self.read_events()
        revoked = [row for row in rows if row['event'] == 'session_denied']
        self.assertTrue(revoked)
        self.assertEqual(revoked[-1]['reason_code'],
                         'EC259_CUSTODY_RECEIPT_NOT_GIT_CONTENT')
        self.assertIn('session_cleanup_state', [row['event'] for row in rows])

    def test_03_mandatory_audit_failure_denies_before_lease_and_halts_host(self):
        self.start(fail_audit_at='begin_authorized')
        with self.assertRaisesRegex(session.SessionHostError,
                                    'SESSION_WIRE_INCOMPLETE'):
            self.remote().begin(self.begin_request())
        pid, status = os.waitpid(self.child, 0)
        self.child = None
        self.assertEqual(os.waitstatus_to_exitcode(status), 5)
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')), [])
        self.assertFalse(list(Path(self.policy['scratch_root']).iterdir()))
        self.assertEqual(self.read_events()[-1]['event'], 'session_open')

    def test_04_audit_failure_after_begin_triggers_lease_recovery_and_exit(self):
        self.engine_wait = 4.0
        self.start(fail_audit_at='begin_egress_enqueued')
        # The begin response may already reach the client before its
        # post-send audit fails: it must NOT prove session survival.
        try:
            client = self.remote().begin(self.begin_request())
        except session.SessionHostError:
            pass
        else:
            client.conn.settimeout(3)
            self.assertEqual(client.conn.recv(1), b'')
            client.conn.close()
        pid, status = os.waitpid(self.child, 0)
        self.child = None
        self.assertEqual(os.waitstatus_to_exitcode(status), 5)
        self.assert_ledger_closed()
        rows = self.read_events()
        self.assertIn('begin_egress_attempt', [row['event'] for row in rows])
        self.assertNotIn('begin_egress_enqueued', [row['event'] for row in rows])


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AuditedSignedSessionTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
