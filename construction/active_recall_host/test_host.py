#!/usr/bin/env python3
"""EC260 real nonroot Git/AF_UNIX/HMAC/ledger/fork, mock OCI/cgroup only."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from session_host import broker as session
from custody_gated_host.test_host import GatedStrictSessionTests
from cgroup_reaper import supervisor as cg
from cgroup_metrics import test_session as strict
import quality_run_budget as budget


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     os.path.isfile('/usr/bin/git'), 'requires nonroot Linux + Git')
class ActiveRecallStrictSessionTests(GatedStrictSessionTests):
    """Inherits signed start/deny cases; adds active recall over same fixture."""

    def start(self, *, no_socket=False):
        child = os.fork()
        if child == 0:
            try:
                def reap(_pol, _label, _name, container_id, *, recorded, on_bound):
                    if (container_id != strict.ID or
                            recorded != self.proof.journal_event()):
                        raise cg.CgroupError('CGROUP256_TEST_REAP_DRIFT')
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
                    session.serve(
                        str(self.fix.policy_path), self.socket,
                        max_sessions=1, accept_timeout=3,
                        require_cgroup=True, require_kernel_metrics=True,
                        startup_guard=self.gate.startup,
                        before_begin_guard=self.gate.before_begin,
                        during_session_guard=self.gate.before_begin,
                    )
                os._exit(0)
            except BaseException:
                os._exit(5)
        self.child = child
        for _ in range(300):
            if os.path.exists(self.socket):
                break
            pid, status = os.waitpid(self.child, os.WNOHANG)
            if pid == self.child:
                self.child = None
                if no_socket:
                    self.assertEqual(os.waitstatus_to_exitcode(status), 5)
                    self.assertFalse(os.path.exists(self.socket))
                    return
                self.fail('EC260 host stopped before socket bind')
            time.sleep(.01)
        if no_socket:
            self.fail('EC260 unexpectedly bound socket after denied startup')
        self.assertTrue(os.path.exists(self.socket), 'EC260 host did not bind')

    def _read_revocation(self, client, expected_code):
        # The client did NOT poll: receive the unsolicited host failure frame.
        client.conn.settimeout(7)
        message = session._receive(client.conn)
        self.assertEqual(message['status'], 'unavailable')
        permitted = (expected_code if isinstance(expected_code, tuple)
                     else (expected_code,))
        self.assertIn(message['reason_code'], permitted)
        self.assertFalse(message['overall_quality_pass_verified'])
        client.finished = True
        client.conn.close()
        self.join_host()
        journals = list(Path(self.policy['ledger_root']).glob('lease-*'))
        self.assertEqual(len(journals), 1)
        self.assertIn(b'"event":"closed"', journals[0].read_bytes())
        self.assertFalse(list(Path(self.policy['scratch_root']).iterdir()))

    def test_05_receipt_revoke_while_idle_forces_host_cleanup(self):
        self.engine_wait = 4.0
        self.start()
        client = self.remote().begin(self.begin_request())
        receipt = self.gitfx.output/'source.custody.json'
        content = json.loads(receipt.read_text())
        content['overall_quality_pass_verified'] = True
        receipt.write_text(json.dumps(content, sort_keys=True, separators=(',', ':')))
        self._read_revocation(client, 'EC259_CUSTODY_RECEIPT_NOT_GIT_CONTENT')

    def test_06_grant_policy_revoke_while_idle_forces_cleanup(self):
        self.engine_wait = 4.0
        self.start()
        client = self.remote().begin(self.begin_request())
        self.fix.policy['grants'][0]['allow_output_text'] = False
        self.fix.write_policy()
        self._read_revocation(client, ('LEASE_HOST_POLICY_CHANGED_OR_REVOKED',
                                       'EC259_POLICY_RACED', 'EC259_POLICY_PIN_CHANGED'))

    def test_07_active_monitor_fails_on_partial_client_frame(self):
        self.engine_wait = 4.0
        self.start()
        client = self.remote().begin(self.begin_request())
        client.conn.sendall(b'{"schema":"ces.ec254.')
        receipt = self.gitfx.output/'source.custody.json'
        content = json.loads(receipt.read_text())
        content['forbidden_changed_during_partial_request'] = True
        receipt.write_text(json.dumps(content, sort_keys=True, separators=(',', ':')))
        self._read_revocation(client, 'EC259_CUSTODY_RECEIPT_NOT_GIT_CONTENT')

    def test_08_normal_idle_then_poll_does_not_revoke_unmodified_source(self):
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            time.sleep(1.3)   # Actually traverses periodic live recheck.
            events = []
            for _ in range(60):
                report = client.poll(80, budget.MAX_CHUNK)
                events.append(report)
                if report['kind'] == 'exit':
                    break
        self.assertEqual(events[-1]['kind'], 'exit')
        self.join_host()
        journal = next(Path(self.policy['ledger_root']).glob('lease-*'))
        self.assertIn(b'"event":"closed"', journal.read_bytes())

    def test_09_stop_is_still_available_for_valid_active_sessions(self):
        self.engine_wait = 4.0
        self.start()
        client = self.remote().begin(self.begin_request())
        outcome = client.stop_and_reap('operator stop')
        self.assertTrue(outcome['stop_acknowledged'])
        self.join_host()
        self.assertFalse(list(Path(self.policy['scratch_root']).iterdir()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
