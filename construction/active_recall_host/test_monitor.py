#!/usr/bin/env python3
"""EC260 bounded active-read receiver tests; no OCI/kernel attestation."""
from __future__ import annotations

import json
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from session_host import broker as session


class Revoked(Exception):
    pass


class MonitoredWireTests(unittest.TestCase):
    def setUp(self):
        self.local, self.peer = socket.socketpair()
        self.addCleanup(self.local.close)
        self.addCleanup(self.peer.close)
        self.ticks = 0

    def receive_in_thread(self, callback, *, timeout=2.0):
        result = {}
        def target():
            try:
                result['value'] = session._receive_monitored(
                    self.local, time.monotonic() + timeout, callback)
            except Exception as exc:
                result['error'] = exc
        thread = threading.Thread(target=target)
        thread.start()
        return thread, result

    def test_01_idle_revocation_without_client_poll(self):
        def check():
            self.ticks += 1
            if self.ticks == 3:
                raise Revoked()
        with mock.patch.object(session, 'ACTIVE_RECHECK_SECONDS', .04):
            thread, result = self.receive_in_thread(check)
            thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(result.get('error'), Revoked)
        self.assertNotIn('value', result)
        self.assertEqual(self.ticks, 3)

    def test_02_trickled_frame_does_not_bypass_idle_check(self):
        def check():
            self.ticks += 1
            if self.ticks >= 3:
                raise Revoked()
        with mock.patch.object(session, 'ACTIVE_RECHECK_SECONDS', .04):
            thread, result = self.receive_in_thread(check)
            self.peer.sendall(b'{"schema":')
            thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(result.get('error'), Revoked)
        self.assertNotIn('value', result)

    def test_03_complete_frame_checked_before_parse_and_release(self):
        def check():
            self.ticks += 1
        packet = {'schema': 'ces.ec254.quality_session_request.v1',
                  'operation': 'poll', 'wait_ms': 20, 'max_chunk_bytes': 200}
        thread, result = self.receive_in_thread(check)
        self.peer.sendall(json.dumps(packet).encode('ascii') + b'\n')
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result.get('value'), packet)
        self.assertGreaterEqual(self.ticks, 2)

    def test_04_second_frame_in_same_write_is_rejected(self):
        thread, result = self.receive_in_thread(lambda: None)
        self.peer.sendall(b'{"a":1}\n{"b":2}\n')
        thread.join(timeout=1)
        self.assertIsInstance(result.get('error'), session.SessionHostError)
        self.assertEqual(result['error'].code, 'SESSION_WIRE_TRAILING_BYTES')

    def test_05_oversize_and_missing_newline_fail_closed(self):
        thread, result = self.receive_in_thread(lambda: None)
        self.peer.sendall(b'x' * (session.MAX_WIRE + 2))
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result['error'].code, 'SESSION_WIRE_TOO_LARGE')

    def test_06_idle_peer_disconnect_is_not_deadline_wait(self):
        thread, result = self.receive_in_thread(lambda: None)
        self.peer.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result['error'].code, 'SESSION_CLIENT_DISCONNECTED')

    def test_07_wall_deadline_applies_without_poll(self):
        with mock.patch.object(session, 'ACTIVE_RECHECK_SECONDS', .05):
            thread, result = self.receive_in_thread(lambda: None, timeout=.12)
            thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result['error'].code, 'SESSION_WALL_DEADLINE')


if __name__ == '__main__':
    unittest.main(verbosity=2)
