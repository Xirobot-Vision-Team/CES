#!/usr/bin/env python3
"""EC261 real AF_UNIX backpressure and bounded monitored egress; no OCI."""
from __future__ import annotations

import json
import socket
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec254_session_host import broker as host


class Revoked(Exception):
    pass


class MonitoredEgressTests(unittest.TestCase):
    def setUp(self):
        self.local, self.peer = socket.socketpair()
        self.addCleanup(self.local.close)
        self.addCleanup(self.peer.close)
        self.local.settimeout(1.75)
        self.ticks = 0

    def check(self):
        self.ticks += 1

    def fill_nonreading_peer(self):
        self.local.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        prior = self.local.gettimeout()
        self.local.setblocking(False)
        total = 0
        try:
            while total < 1_000_000:
                try:
                    total += self.local.send(b'F' * 4096)
                except BlockingIOError:
                    break
        finally:
            self.local.settimeout(prior)
        self.assertGreater(total, 0)
        self.assertLess(total, 1_000_000)

    def test_01_exact_single_line_wire_with_fresh_guard(self):
        payload = host._reply('partial', 'SESSION_POLL_HOST_REPORT_ONLY',
                              event={'kind': 'heartbeat', 'resources': {'cpu_ms': 1}})
        host._send_monitored(self.local, payload,
                             time.monotonic() + 1, self.check)
        self.peer.settimeout(.5)
        self.assertEqual(json.loads(host.fio._receive(self.peer, host.MAX_WIRE)), payload)
        self.assertEqual(self.ticks, 1)
        self.assertEqual(self.local.gettimeout(), 1.75)

    def test_02_revocation_before_first_byte_never_discloses(self):
        def deny():
            self.ticks += 1
            raise Revoked('lost original signed authorization')
        with self.assertRaises(Revoked):
            host._send_monitored(self.local, {'event': 'sensitive'},
                                 time.monotonic() + 1, deny)
        self.peer.settimeout(.06)
        with self.assertRaises(socket.timeout):
            self.peer.recv(1)
        self.assertEqual(self.local.gettimeout(), 1.75)
        self.assertEqual(self.ticks, 1)

    def test_03_stalled_receiver_does_not_suspend_revocation(self):
        self.fill_nonreading_peer()
        def check():
            self.ticks += 1
            if self.ticks >= 3:
                raise Revoked()
        started = time.monotonic()
        with mock.patch.object(host, 'ACTIVE_RECHECK_SECONDS', .035):
            with self.assertRaises(Revoked):
                host._send_monitored(self.local, {'status': 'partial'},
                                     time.monotonic() + 1.3, check)
        self.assertGreaterEqual(self.ticks, 3)
        self.assertLess(time.monotonic() - started, .65)
        self.assertEqual(self.local.gettimeout(), 1.75)

    def test_04_nonreading_receiver_hits_absolute_wall_deadline(self):
        self.fill_nonreading_peer()
        started = time.monotonic()
        with mock.patch.object(host, 'ACTIVE_RECHECK_SECONDS', .03):
            with self.assertRaises(host.SessionHostError) as cm:
                host._send_monitored(self.local, {'status': 'partial'},
                                     time.monotonic() + .16, self.check)
        self.assertEqual(cm.exception.code, 'SESSION_WALL_DEADLINE')
        self.assertGreaterEqual(self.ticks, 2)
        self.assertLess(time.monotonic() - started, .7)
        self.assertEqual(self.local.gettimeout(), 1.75)

    def test_05_partial_reply_aborts_without_appending_false_error(self):
        def revoke_second_chunk():
            self.ticks += 1
            if self.ticks == 2:
                raise Revoked()
        with mock.patch.object(host, 'ACTIVE_RECHECK_SECONDS', 0), \
             mock.patch.object(host, 'ACTIVE_EGRESS_CHUNK', 48):
            with self.assertRaises(host.SessionEgressInterrupted) as cm:
                host._send_monitored(self.local, {'data': 'x' * 700},
                                     time.monotonic() + 1, revoke_second_chunk)
        self.assertIsInstance(cm.exception.__cause__, Revoked)
        self.peer.settimeout(.05)
        self.assertEqual(self.peer.recv(4096), b'{"data":"' + b'x' * 39)
        with self.assertRaises(socket.timeout):
            self.peer.recv(1)  # No JSON status was appended to the fragment.
        self.assertEqual(self.local.gettimeout(), 1.75)

    def test_06_disconnected_peer_cannot_stall_service(self):
        self.peer.close()
        with self.assertRaises(host.SessionHostError) as cm:
            host._send_monitored(self.local, {'status': 'partial'},
                                 time.monotonic() + .2, self.check)
        self.assertEqual(cm.exception.code, 'SESSION_SEND_UNAVAILABLE')
        self.assertEqual(self.local.gettimeout(), 1.75)

    def test_07_failure_response_under_nonreader_has_short_cleanup_budget(self):
        self.fill_nonreading_peer()
        start = time.monotonic()
        with self.assertRaises(host.SessionHostError) as cm:
            host._send_monitored(self.local, host._reply('unavailable', 'SCOPE_REVOKED'),
                                 time.monotonic() + host.ACTIVE_DENIAL_WRITE_SECONDS,
                                 None)
        self.assertEqual(cm.exception.code, 'SESSION_WALL_DEADLINE')
        self.assertLess(time.monotonic() - start, .65)

    def test_08_oversized_response_never_writes_or_changes_timeout(self):
        with self.assertRaises(host.fio.HostError):
            host._send_monitored(self.local, {'data': 'x' * (host.MAX_WIRE + 1)},
                                 time.monotonic() + 1, self.check)
        self.assertEqual(self.ticks, 0)
        self.assertEqual(self.local.gettimeout(), 1.75)
        self.peer.settimeout(.06)
        with self.assertRaises(socket.timeout):
            self.peer.recv(1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
