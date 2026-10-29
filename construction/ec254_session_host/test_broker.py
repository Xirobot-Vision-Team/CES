#!/usr/bin/env python3
"""EC254 nonroot Linux focused tests. Real socket/fork/fsync; OCI mocked.

Do NOT interpret these as live rootless Podman, cgroup, CI or source attestation.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'ec253_lease_host'))
spec = importlib.util.spec_from_file_location('ec253_fixture_for_ec254',
                    ROOT / 'ec253_lease_host' / 'test_broker.py')
fixture = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(fixture)
ec254_spec = importlib.util.spec_from_file_location('ec254_module_for_tests', HERE / 'broker.py')
b = importlib.util.module_from_spec(ec254_spec)
assert ec254_spec and ec254_spec.loader
ec254_spec.loader.exec_module(b)


def packet(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii') + b'\n'


class SessionTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest('Run local system tests as a nonroot Linux account')
        self.fix = fixture.LeaseHostTests('test_private_policy_and_original_catalog_valid')
        self.fix.setUp()
        self.addCleanup(self.fix.doCleanups)
        self.policy = self.fix.policy
        self.socket = str(self.fix.root / 'socket' / 'session.sock')
        self.child = None
        self.addCleanup(self.kill_host)
        self.stats_fail = False
        self.engine_wait = 0.28
        self.engine_code = 0

    def begin_request(self, **changes):
        auth = b.lease._tickets(self.policy, self.fix.profile)
        req = {'schema': b.REQUEST_SCHEMA, 'operation': 'begin',
               'scope_id': 'test-scope', 'profile_id': self.fix.profile,
               'source_pin_sha256': self.fix.pin,
               'profile_sha256': b.guard.catalog_entry(self.fix.profile)['profile_sha256'],
               'approval_receipt_sha256': auth['approval_receipt_sha256'],
               'lease_receipt_sha256': auth['lease_receipt_sha256'],
               'image_sha256': self.policy['image_id'][7:],
               'lease_id': auth['lease']['ticket_id'],
               'deadline_monotonic_ns': time.monotonic_ns() + 55_000_000_000,
               'limits': dict(b.FIXED_LIMITS)}
        req.update(changes)
        return req

    def engine(self, _pol, args, **kw):
        def result(code=0, raw=b''):
            return b.runner.CommandResult(code, raw, b'',
                    hashlib.sha256(raw).hexdigest(), hashlib.sha256(b'').hexdigest(),
                    len(raw))
        identity = 'a' * 64
        if not hasattr(self, '_oci_state'):
            self._oci_state = {'created': False, 'removed': False, 'name': '', 'label': ''}
        state = self._oci_state
        if args[0] == 'stats':
            if self.stats_fail:
                return result(1)
            return result(raw=(identity + '|10000000|4096B|2|0B / 0B\n').encode())
        if args[0] == 'create':
            state['created'] = True
            state['name'] = args[args.index('--name') + 1]
            state['label'] = next((x.split('=', 2)[2] for x in args
                                   if x.startswith('--label=io.ces.lease.sha256=')), '')
            return result(raw=(identity + '\n').encode())
        if args[0] == 'ps':
            return result(raw=(identity + '\n').encode()
                          if state['created'] and not state['removed'] else b'')
        if args[:2] == ['container', 'inspect']:
            return result(raw=('|'.join((identity, state['name'], state['label'],
                                         self.policy['image_id'][7:])) + '\n').encode())
        if args[0] == 'start':
            if kw.get('on_spawn'):
                kw['on_spawn'](123456)
            if kw.get('on_output'):
                kw['on_output']('stdout', b'hello from OCI\n')
            time.sleep(self.engine_wait)
            return result(self.engine_code, b'hello from OCI\n')
        if args[0] == 'inspect':
            return result(raw=packet({'Running': False, 'StartedAt':
                   '2026-10-24T08:00:00Z', 'ExitCode': self.engine_code,
                   'OOMKilled': False}))
        if args[0] == 'rm':
            state['removed'] = True
            return result()
        if args[:2] == ['container', 'exists']:
            return result(1 if state['removed'] or not state['created'] else 0)
        raise AssertionError(args)

    def start(self, **options):
        self.stats_fail = options.get('stats_fail', self.stats_fail)
        self.engine_wait = options.get('engine_wait', self.engine_wait)
        self.engine_code = options.get('engine_code', self.engine_code)
        child = os.fork()
        if child == 0:
            try:
                with mock.patch.object(b.runner, '_runtime_ready', return_value=None), \
                     mock.patch.object(b.runner, '_runtime_binary', return_value=None), \
                     mock.patch.object(b.runner, '_run_command', side_effect=self.engine):
                    b.serve(str(self.fix.policy_path), self.socket,
                            max_sessions=options.get('max_sessions', 1),
                            accept_timeout=3)
                os._exit(0)
            except BaseException:
                os._exit(1)
        self.child = child
        for _ in range(200):
            if os.path.exists(self.socket):
                break
            time.sleep(0.01)
        self.assertTrue(os.path.exists(self.socket), 'Host failed to bind')

    def join_host(self):
        pid = self.child
        self.assertIsNotNone(pid)
        for _ in range(200):
            found, status = os.waitpid(pid, os.WNOHANG)
            if found == pid:
                self.child = None
                self.assertEqual(os.waitstatus_to_exitcode(status), 0,
                                 'Host rejected durable cleanup')
                return
            time.sleep(0.025)
        self.fail('Host has not exited after session')

    def kill_host(self):
        if self.child is not None:
            try:
                os.kill(self.child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(self.child, 0)
            except ChildProcessError:
                pass
            self.child = None

    def remote(self):
        return b.TrustedBroker(self.socket, os.geteuid(), 'test-scope')

    def test_01_exact_receipt_bindings_and_no_quality_pass(self):
        req = self.begin_request()
        policy, auth, grant = b._begin(req, self.policy, os.geteuid())
        self.assertEqual(auth['lease']['ticket_id'], req['lease_id'])
        self.assertEqual(grant['uid'], os.geteuid())
        self.assertEqual(policy['schema'], b.runner.REQUEST_SCHEMA)
        rcpt = b._receipt(req, self.policy, 'ec254-' + 'a'*32)
        self.assertEqual(rcpt['sealed_source_sha256'],
                         self.policy['expected_source_tar_sha256'])
        b.budget._read_session(rcpt, selected=req, limits=req['limits'])

    def test_02_reject_tighter_limits_before_lease(self):
        req = self.begin_request(limits=dict(b.FIXED_LIMITS, memory_peak_bytes=2*1024*1024))
        with self.assertRaisesRegex(b.SessionHostError, 'LOWER_LIMITS'):
            b._begin(req, self.policy, os.geteuid())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')), [])

    def test_03_wrong_uid_scope_denied(self):
        with self.assertRaisesRegex(b.runner.HostRunError, 'SCOPE_PROFILE_DENIED'):
            b._begin(self.begin_request(), self.policy, os.geteuid() + 1)

    def test_04_change_approval_receipt_denied(self):
        with self.assertRaisesRegex(b.SessionHostError, 'SIGNED_SCOPE_MISMATCH'):
            b._begin(self.begin_request(approval_receipt_sha256='f'*64),
                     self.policy, os.geteuid())

    def test_05_bad_deadline_denied(self):
        with self.assertRaisesRegex(b.SessionHostError, 'DEADLINE'):
            b._begin(self.begin_request(deadline_monotonic_ns=time.monotonic_ns()+100000),
                     self.policy, os.geteuid())

    def test_06_incorrect_ticket_mac_denied(self):
        request = self.begin_request()
        self.fix.lease['mac_sha256'] = '1'*64
        fixture.store(self.fix.lease_path, fixture.encode(self.fix.lease))
        with self.assertRaisesRegex(b.lease.LeaseHostError, 'EC186'):
            b._begin(request, self.policy, os.geteuid())

    def test_07_metrics_strict_and_no_fabricated_fallback(self):
        identity = 'a' * 64
        sample = b.runner.CommandResult(0,
                 (identity + '|123000000|10MiB|2|3kB / 4kB\n').encode(),
                 b'', '', '', 100)
        with mock.patch.object(b.runner, '_run_command', return_value=sample):
            metrics = b._metrics(self.policy, identity, 100,
                                 {k: 0 for k in b.budget.RESOURCE_KEYS})
        self.assertEqual(metrics, {'cpu_ms': 123, 'memory_peak_bytes': 10*1024*1024,
                                   'io_bytes': 7000, 'processes': 2})
        spoof = b.runner.CommandResult(0,
                (('b'*64) + '|123000000|10MiB|2|3kB / 4kB\n').encode(),
                b'', '', '', 100)
        with mock.patch.object(b.runner, '_run_command', return_value=spoof):
            with self.assertRaisesRegex(b.SessionHostError, 'TELEMETRY_ID_OR_FORMAT'):
                b._metrics(self.policy, identity, 100, metrics)
        with mock.patch.object(b.runner, '_run_command',
                               return_value=b.runner.CommandResult(1,b'',b'','','',0)):
            with self.assertRaisesRegex(b.SessionHostError, 'TELEMETRY_UNAVAILABLE'):
                b._metrics(self.policy, identity, 0, metrics)

    def test_08_full_session_real_uid_fork_journal_mock_oci(self):
        self.fix.policy['grants'][0]['allow_output_text'] = True
        self.fix.write_policy()
        self.policy = self.fix.policy
        self.start(engine_wait=0.65)
        req = self.begin_request()
        session = self.remote().begin(req)
        self.assertEqual(session.receipt['lease_receipt_sha256'],
                         req['lease_receipt_sha256'])
        seen = []
        for _ in range(25):
            event = session.poll(80, b.budget.MAX_CHUNK)
            seen.append(event['kind'])
            if event['kind'] == 'output':
                self.assertEqual(event['chunk'], b'hello from OCI\n')
            if event['kind'] == 'exit':
                self.assertEqual(event['exit_code'], 0)
                self.assertTrue(event['resources']['cpu_ms'] >= 10)
                break
        self.assertIn('output', seen)
        self.assertIn('exit', seen)
        self.join_host()
        journals = list(Path(self.policy['ledger_root']).glob('lease-*'))
        self.assertEqual(len(journals), 1)
        self.assertFalse(list(Path(self.policy['scratch_root']).iterdir()))
        self.assertIn(b'"event":"closed"', journals[0].read_bytes())

    def test_09_explicit_stop_reaps_and_burns_lease(self):
        self.start(engine_wait=4)
        session = self.remote().begin(self.begin_request())
        receipt = session.stop_and_reap('stop requested')
        self.assertTrue(receipt['stop_acknowledged'])
        self.assertTrue(receipt['reaped'])
        self.join_host()
        journals = list(Path(self.policy['ledger_root']).glob('lease-*'))
        self.assertEqual(len(journals), 1)
        self.assertEqual(list(Path(self.policy['scratch_root']).iterdir()), [])

    def test_10_no_stats_fails_closed_and_reclaims(self):
        self.start(stats_fail=True, engine_wait=3)
        # First real stats sample is mandatory BEFORE begin can return.
        with self.assertRaisesRegex(b.SessionHostError, 'REMOTE_BEGIN_DENIED'):
            self.remote().begin(self.begin_request())
        self.join_host()
        self.assertEqual(len(list(Path(self.policy['ledger_root']).glob('lease-*'))), 1)

    def test_11_duplicate_lease_declined_after_one_session(self):
        self.start(engine_wait=3, max_sessions=2)
        session = self.remote().begin(self.begin_request())
        self.assertTrue(session.stop_and_reap('done')['reaped'])
        with self.assertRaisesRegex(b.SessionHostError, 'REMOTE_BEGIN_DENIED'):
            self.remote().begin(self.begin_request())
        self.join_host()

    def test_12_permission_revoked_before_poll_no_output_disclosure(self):
        self.fix.policy['grants'][0]['allow_output_text'] = True
        self.fix.write_policy()
        self.policy = self.fix.policy
        self.start(engine_wait=4)
        session = self.remote().begin(self.begin_request())
        self.fix.policy['grants'][0]['profile_ids'] = ['python.ruff']
        self.fix.write_policy()
        with self.assertRaisesRegex(b.SessionHostError, 'POLL_UNAVAILABLE'):
            session.poll(80, b.budget.MAX_CHUNK)
        session.stop_and_reap('revoked')
        self.join_host()
        self.assertEqual(len(list(Path(self.policy['ledger_root']).glob('lease-*'))), 1)

    def test_13_suppressed_content_still_counts_io(self):
        self.start(engine_wait=0.65)
        with self.remote().begin(self.begin_request()) as session:
            frames = []
            for _ in range(30):
                event = session.poll(80, b.budget.MAX_CHUNK)
                frames.append(event)
                if event['kind'] == 'exit':
                    break
        self.join_host()
        self.assertTrue(frames)
        self.assertFalse(any(frame['kind'] == 'output' for frame in frames))
        self.assertTrue(any(frame['resources']['io_bytes'] >= len(b'hello from OCI\n')
                            for frame in frames), repr(frames))

    def test_14_wrong_expected_server_uid_rejects_without_consumption(self):
        self.start()
        with self.assertRaisesRegex(b.SessionHostError, 'WRONG_HOST_UID'):
            b.TrustedBroker(self.socket, os.geteuid()+1, 'test-scope').begin(
                self.begin_request())
        self.join_host()
        self.assertFalse(list(Path(self.policy['ledger_root']).glob('lease-*')))

    def test_15_mock_stream_renders_binary_frame_strictly(self):
        a,bside = socket.socketpair()
        try:
            payload = b'\x00\xff\n'
            b._inner_send(a, {'type':'output','stream':'stderr',
                              'bytes':len(payload),
                              'chunk_b64':b.base64.b64encode(payload).decode('ascii')})
            self.assertEqual(b._inner_read(bside)['bytes'], 3)
            with self.assertRaisesRegex(b.SessionHostError, 'INNER_FRAME_TOO_LARGE'):
                b._inner_send(a, {'type':'output', 'stream':'stdout',
                                  'chunk_b64': 'a'*3000})
        finally:
            a.close();bside.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
