#!/usr/bin/env python3
"""EC259 integrated strict socket/fork/HMAC/ledger gate (OCI/cgroup MOCK ONLY).

Real Git SHA objects and EC253 tickets are validated. The OCI engine, live
cgroup2 kernel resource files and Podman are simulated. Not an E2E host PASS.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from session_host import broker as session
from cgroup_metrics import test_session as strict
from cgroup_reaper import supervisor as cg
from git_tar_custody import custody
from git_tar_custody import test_custody as git_fixture
from custody_gated_host.gate import OperatorCustodyGate
import quality_run_budget as budget


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     os.path.isfile('/usr/bin/git'), 'requires nonroot Linux + Git')
class GatedStrictSessionTests(unittest.TestCase):
    engine = strict.StrictKernelSessionTests.engine
    begin_request = strict.StrictKernelSessionTests.begin_request
    join_host = strict.StrictKernelSessionTests.join_host
    kill_host = strict.StrictKernelSessionTests.kill_host
    remote = strict.StrictKernelSessionTests.remote

    def setUp(self):
        old_umask = os.umask(0o077)
        self.addCleanup(os.umask, old_umask)
        strict.StrictKernelSessionTests.setUp(self)
        self.gitfx = git_fixture.RealGitTests('test_git_object_reader_is_offline_and_bounded')
        self.gitfx.setUp()
        self.addCleanup(self.gitfx.doCleanups)
        self.gitfx.prepare()
        self.policy['source_tar_path'] = str(self.gitfx.output / 'source.tar')
        self.policy['expected_source_tar_sha256'] = custody._sha(
            (self.gitfx.output / 'source.tar').read_bytes())
        self.fix.write_policy()
        self.gate = OperatorCustodyGate(
            str(self.fix.policy_path), str(self.gitfx.repo),
            str(self.gitfx.allowpath), str(self.gitfx.output / 'source.custody.json'),
            'python.pytest')

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
                     mock.patch.object(cg, '_path_for_pid', lambda pid: '/user.slice/ces-meter.service'), \
                     mock.patch.object(cg, 'bind_live', lambda pol, identity, label: self.proof), \
                     mock.patch.object(cg, 'reap_before_remove', side_effect=reap):
                    session.serve(str(self.fix.policy_path), self.socket,
                                  max_sessions=1, accept_timeout=3,
                                  require_cgroup=True, require_kernel_metrics=True,
                                  startup_guard=self.gate.startup,
                                  before_begin_guard=self.gate.before_begin)
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
                self.fail('EC259 host stopped before socket bind')
            time.sleep(.01)
        if no_socket:
            self.fail('EC259 host unexpectedly bound socket on failed startup')
        self.assertTrue(os.path.exists(self.socket), 'EC259 host did not bind socket')

    def test_01_real_git_custody_then_signed_strict_session_mock_oci(self):
        self.start()
        events = []
        with self.remote().begin(self.begin_request()) as host:
            for _ in range(50):
                event = host.poll(80, budget.MAX_CHUNK)
                events.append(event)
                if event['kind'] == 'exit':
                    break
        self.assertTrue(events)
        self.assertEqual(events[-1]['kind'], 'exit')
        self.assertGreaterEqual(events[-1]['resources']['cpu_ms'], 12345)
        self.assertTrue(any(e['kind'] == 'output' for e in events))
        self.join_host()
        journals = list(Path(self.policy['ledger_root']).glob('lease-*'))
        self.assertEqual(len(journals), 1)
        self.assertIn(b'"event":"closed"', journals[0].read_bytes())
        self.assertFalse(list(Path(self.policy['scratch_root']).iterdir()))

    def test_02_changed_receipt_denies_begin_before_consuming_lease(self):
        self.start()
        rec = self.gitfx.output / 'source.custody.json'
        obj = json.loads(rec.read_text())
        obj['overall_quality_pass_verified'] = True
        rec.write_bytes(custody._canonical(obj))
        with self.assertRaisesRegex(session.SessionHostError, 'SESSION_REMOTE_BEGIN_DENIED'):
            self.remote().begin(self.begin_request())
        self.join_host()
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')), [])
        self.assertFalse(list(Path(self.policy['scratch_root']).iterdir()))

    def test_03_changed_allowlist_denies_begin_before_consuming_lease(self):
        self.start()
        self.gitfx.allow['source_paths'] = ['pytest.ini']
        self.gitfx.write_approval()
        with self.assertRaisesRegex(session.SessionHostError, 'SESSION_REMOTE_BEGIN_DENIED'):
            self.remote().begin(self.begin_request())
        self.join_host()
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')), [])
        self.assertFalse(list(Path(self.policy['scratch_root']).iterdir()))

    def test_04_bad_source_custody_prevents_socket_startup(self):
        (self.gitfx.output / 'source.tar').write_bytes(b'not an approved TAR')
        self.start(no_socket=True)
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')), [])
        self.assertFalse(list(Path(self.policy['scratch_root']).iterdir()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
