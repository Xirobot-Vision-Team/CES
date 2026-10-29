#!/usr/bin/env python3
"""EC260 bounded client timeout adapter; no new wire or authorization."""
from __future__ import annotations

import socket
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec260_active_recall_host.client import ActiveRecallBroker
from ec254_session_host import broker as prior
from ec252_quality_run_host import broker as runner


class ActiveRecallClientTests(unittest.TestCase):
    def test_01_preserves_super_begin_and_receipt_but_waits_for_git_guard(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        orig = prior.Session(a, {'schema':'test'})
        with mock.patch.object(prior.TrustedBroker, 'begin', return_value=orig) as call:
            client = ActiveRecallBroker('/trusted/session.sock', 1000, 'test-scope')
            deadline = time.monotonic_ns() + 55_000_000_000
            req = {'deadline_monotonic_ns':deadline}
            observed = client.begin(req)
            call.assert_called_once_with(req)
            self.assertIs(observed, orig)
            self.assertEqual(observed.receipt, {'schema':'test'})
            self.assertGreater(observed.conn.gettimeout(), 2)
            self.assertLessEqual(observed.conn.gettimeout(),
                                 runner.WALL_SECONDS + runner.MAX_CLEANUP_SECONDS + 3)

    def test_02_invalid_deadline_rejected_before_any_host_connection(self):
        client = ActiveRecallBroker('/trusted/session.sock', 1000, 'test-scope')
        with mock.patch.object(prior.TrustedBroker, 'begin') as start:
            for req in ({}, {'deadline_monotonic_ns':True},
                        {'deadline_monotonic_ns':'now'},
                        {'deadline_monotonic_ns':time.monotonic_ns()-1}):
                with self.assertRaisesRegex(prior.SessionHostError,
                                            'EC260_CLIENT_DEADLINE_INVALID'):
                    client.begin(req)
            start.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
