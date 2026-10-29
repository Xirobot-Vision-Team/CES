#!/usr/bin/env python3
"""EC261 signed real-Git session/ledger integration; OCI + cgroup MOCK ONLY.

Testing hook runs only in the forked test host: a real custody receipt is
revoked exactly after a poll has generated an event but BEFORE any reply byte.
The default EC260 host sees the revocation and reaps the reserved lease.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from session_host import broker as session
from active_recall_host import test_host as previous
import quality_run_budget as budget


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').is_file(),
                     'requires nonroot Linux with real Git')
class GuardedEgressSignedTests(unittest.TestCase):
    # Reuse the real Git/HMAC + nonroot AF_UNIX + durable ledger fixture but do
    # not inherit its tests or execute EC260's cases twice in this module.
    setUp = previous.ActiveRecallStrictSessionTests.setUp
    engine = previous.ActiveRecallStrictSessionTests.engine
    start = previous.ActiveRecallStrictSessionTests.start
    remote = previous.ActiveRecallStrictSessionTests.remote
    begin_request = previous.ActiveRecallStrictSessionTests.begin_request
    join_host = previous.ActiveRecallStrictSessionTests.join_host
    kill_host = previous.ActiveRecallStrictSessionTests.kill_host

    def revoke_receipt(self):
        receipt = self.gitfx.output / 'source.custody.json'
        content = json.loads(receipt.read_text())
        content['tampered_after_poll_before_egress'] = True
        receipt.write_text(json.dumps(content, sort_keys=True, separators=(',', ':')))

    def assert_durable_cleanup(self):
        self.join_host()
        journals = list(Path(self.policy['ledger_root']).glob('lease-*'))
        self.assertEqual(len(journals), 1)
        self.assertIn(b'"event":"closed"', journals[0].read_bytes())
        self.assertFalse(list(Path(self.policy['scratch_root']).iterdir()))

    def test_01_revocation_after_poll_before_egress_reaps_without_disclosure(self):
        self.engine_wait = 4.0
        original = session._send_monitored
        def revoke_at_poll(conn, body, deadline, check):
            if body.get('reason_code') == 'SESSION_POLL_HOST_REPORT_ONLY':
                self.revoke_receipt()
            return original(conn, body, deadline, check)
        with mock.patch.object(session, '_send_monitored', new=revoke_at_poll):
            self.start()
        client = self.remote().begin(self.begin_request())
        client.conn.settimeout(7)
        try:
            with self.assertRaisesRegex(session.SessionHostError, 'POLL_UNAVAILABLE'):
                client.poll(80, budget.MAX_CHUNK)
        finally:
            client.conn.close()
        self.assert_durable_cleanup()

    def test_02_stalled_nonreader_revocation_does_not_postpone_ledger_reap(self):
        self.engine_wait = 4.0
        original = session._send_monitored
        def blocked_at_poll(conn, body, deadline, check):
            if body.get('reason_code') == 'SESSION_POLL_HOST_REPORT_ONLY':
                # Artificial test harness backpressure on the ACTUAL host
                # socket: before writing a poll frame, fill its send buffer.
                # No fake OCI cgroup or user client input can bypass the guard.
                old = conn.gettimeout()
                try:
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                    conn.setblocking(False)
                    while True:
                        try:
                            conn.send(b'F' * 4096)
                        except BlockingIOError:
                            break
                finally:
                    conn.settimeout(old)
            return original(conn, body, deadline, check)
        with mock.patch.object(session, '_send_monitored', new=blocked_at_poll), \
             mock.patch.object(session, 'ACTIVE_RECHECK_SECONDS', .09):
            self.start()
        client = self.remote().begin(self.begin_request())
        session._send(client.conn, {'schema': session.REQUEST_SCHEMA,
                                    'operation': 'poll', 'wait_ms': 60,
                                    'max_chunk_bytes': budget.MAX_CHUNK})
        # Do not read the client's socket. Host must keep actively checking.
        time.sleep(.35)
        self.revoke_receipt()
        self.assert_durable_cleanup()
        client.conn.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
