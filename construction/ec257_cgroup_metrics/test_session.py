#!/usr/bin/env python3
"""EC257 end-to-end local signed-session tests; mocked OCI + fake cgroupfs.

These cover actual nonroot fork/AF_UNIX, signed EC186 tickets, fsynced ledger,
worker pre-reap final samples and conservative cleanup. They DO NOT execute
Podman or a real cgroup.kill.
"""
from __future__ import annotations

import os
from pathlib import Path
import signal
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec254_session_host import broker as session
from ec254_session_host import test_broker as older
from ec256_cgroup_reaper import supervisor as cg
from ec257_cgroup_metrics.test_metrics import ID, BOOT, SCOPE
import quality_run_budget as budget


class StrictKernelSessionTests(unittest.TestCase):
    engine = older.SessionTests.engine
    begin_request = older.SessionTests.begin_request
    join_host = older.SessionTests.join_host
    kill_host = older.SessionTests.kill_host
    def remote(self):
        return session.TrustedBroker(self.socket, os.geteuid(), 'test-scope')

    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest('Actual fixture requires unprivileged Linux UID')
        self.fix = older.fixture.LeaseHostTests('test_private_policy_and_original_catalog_valid')
        self.fix.setUp()
        self.addCleanup(self.fix.doCleanups)
        self.policy = self.fix.policy
        self.socket = str(self.fix.root/'socket'/'ec257.sock')
        self.child = None
        self.addCleanup(self.kill_host)
        self.stats_fail = True  # Prove NO Podman stats fallback in strict mode.
        self.engine_wait = 0.75
        self.engine_code = 0
        self.root = self.fix.root/'cgroups'
        self.group = self.root/SCOPE.lstrip('/')
        self.group.mkdir(parents=True)
        (self.group/'cpu.stat').write_text('usage_usec 12345000\n')
        (self.group/'memory.peak').write_text('10485760\n')
        (self.group/'pids.peak').write_text('4\n')
        (self.group/'io.stat').write_text('8:0 rbytes=140 wbytes=300\n')
        stat = self.group.stat()
        self.proof = cg.Binding(cg.BIND_SCHEMA, ID, BOOT, SCOPE,
                                stat.st_dev, stat.st_ino, 7123)
        self.fix.policy['grants'][0]['allow_output_text'] = True
        self.fix.write_policy()
        self.policy = self.fix.policy

    def start(self, *, engine_wait=None):
        if engine_wait is not None:
            self.engine_wait = engine_wait
        child = os.fork()
        if child == 0:
            try:
                def reap(_pol, _label, _name, container_id, *, recorded, on_bound):
                    if container_id != ID or recorded != self.proof.journal_event():
                        raise cg.CgroupError('CGROUP256_TEST_REAP_DRIFT')
                with mock.patch.object(session.runner, '_runtime_ready', return_value=None), \
                     mock.patch.object(session.runner, '_runtime_binary', return_value=None), \
                     mock.patch.object(session.runner, '_run_command', side_effect=self.engine), \
                     mock.patch.object(cg, 'CGROUP_MOUNT', str(self.root)), \
                     mock.patch.object(cg, '_mount_root', lambda: None), \
                     mock.patch.object(cg, '_boot_id', lambda: BOOT), \
                     mock.patch.object(cg, '_path_for_pid', lambda pid: '/user.slice/ces-meter.service'), \
                     mock.patch.object(cg, 'bind_live', lambda pol, identity, label: self.proof), \
                     mock.patch.object(cg, 'reap_before_remove', side_effect=reap):
                    session.serve(str(self.fix.policy_path), self.socket,
                                  max_sessions=1, accept_timeout=3,
                                  require_cgroup=True, require_kernel_metrics=True)
                os._exit(0)
            except BaseException as exc:
                import traceback
                traceback.print_exc()
                os._exit(1)
        self.child = child
        for _ in range(200):
            if os.path.exists(self.socket):
                break
            time.sleep(0.01)
        self.assertTrue(os.path.exists(self.socket), 'Strict host failed to bind')

    def assert_cleanup(self):
        self.join_host()
        journals = list(Path(self.policy['ledger_root']).glob('lease-*'))
        self.assertEqual(len(journals), 1)
        self.assertIn(b'"event":"closed"', journals[0].read_bytes())
        self.assertIn(b'"event":"cgroup_bound"', journals[0].read_bytes())
        self.assertFalse(list(Path(self.policy['scratch_root']).iterdir()))

    def test_01_kernel_meter_survives_podman_stats_unavailable(self):
        self.start()
        with self.remote().begin(self.begin_request()) as host:
            events = []
            for _ in range(50):
                report = host.poll(80, budget.MAX_CHUNK)
                events.append(report)
                if report['kind'] == 'exit':
                    break
        self.assertEqual(events[-1]['kind'], 'exit')
        self.assertTrue(any(e['kind'] == 'output' for e in events))
        self.assertEqual(events[-1]['resources']['cpu_ms'], 12345)
        self.assertEqual(events[-1]['resources']['memory_peak_bytes'], 10485760)
        self.assertGreaterEqual(events[-1]['resources']['io_bytes'], 440+len(b'hello from OCI\n'))
        self.assert_cleanup()

    def test_02_kernel_peak_budget_violation_denies_session_but_still_cleans(self):
        self.start(engine_wait=1.5)
        host = self.remote().begin(self.begin_request())
        (self.group/'memory.peak').write_text(
            str(budget.HARD_CEILINGS['memory_peak_bytes'] + 100) + '\n')
        with self.assertRaisesRegex(session.SessionHostError, 'SESSION_REMOTE_POLL_UNAVAILABLE'):
            for _ in range(25):
                host.poll(80, budget.MAX_CHUNK)
        host.stop_and_reap('resource violation')
        self.assert_cleanup()

    def test_03_final_counter_missing_must_never_return_exit(self):
        self.start(engine_wait=0.8)
        host = self.remote().begin(self.begin_request())
        # The same binding remains durable but its mandatory peak file goes
        # missing before the final worker pre-reap snapshot.
        (self.group/'pids.peak').unlink()
        time.sleep(1.05)  # allow natural worker completion/pre-reap failure
        with self.assertRaisesRegex(session.SessionHostError, 'SESSION_REMOTE_POLL_UNAVAILABLE'):
            for _ in range(25):
                host.poll(80, budget.MAX_CHUNK)
        host.stop_and_reap('no counter')
        self.assert_cleanup()

    def test_04_missing_first_kernel_counter_denies_begin_and_reaps(self):
        (self.group/'pids.peak').unlink()
        self.start(engine_wait=1.2)
        with self.assertRaisesRegex(session.SessionHostError, 'SESSION_REMOTE_BEGIN_DENIED'):
            self.remote().begin(self.begin_request())
        self.assert_cleanup()


if __name__ == '__main__':
    unittest.main(verbosity=2)
