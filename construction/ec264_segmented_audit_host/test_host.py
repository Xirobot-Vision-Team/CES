#!/usr/bin/env python3
"""EC264 signed Git + AF_UNIX/fork/ledger host; OCI and cgroup MOCK ONLY."""
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
from ec256_cgroup_reaper import supervisor as cg
from ec257_cgroup_metrics import test_session as strict
from ec263_offline_anchor_host import checkpoint as cp
from ec263_offline_anchor_host.test_host import AnchoredRealGitSessionTests as previous
from ec262_signed_audit_host.audit import AuditLog
from ec264_segmented_audit_host import segment as seg
from ec264_segmented_audit_host import serve as segmented_service
import quality_run_budget as budget


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux, Git and Ed25519 required')
class SegmentedRealGitSessionTests(unittest.TestCase):
    setUp = previous.setUp
    engine = previous.engine
    remote = previous.remote
    begin_request = previous.begin_request
    join_host = previous.join_host
    kill_host = previous.kill_host
    assert_ledger_closed = previous.assert_ledger_closed
    _prepare = previous._prepare

    def prepare(self):
        self._prepare()
        with AuditLog(str(self.audit_root), str(self.audit_key)) as audit:
            audit.record('service_start')
            audit.record('service_closed')
        self.signing = self.fix.private/'ec264-signer.key'
        self.public = self.fix.private/'ec264-signer.pub'
        self.proposal = self.fix.private/'ec264-proposal.json'
        self.checkpoint = self.fix.private/'ec264-checkpoint.json'
        self.pub_pin = cp.generate_offline_keypair(str(self.signing),
                                                   str(self.public))['signer_public_sha256']
        cp.propose(str(self.audit_root), str(self.audit_key), self.pub_pin,
                   str(self.proposal))
        self.cp_pin = cp.sign_offline(str(self.proposal), str(self.signing),
                                      str(self.checkpoint))['checkpoint_sha256']
        self.next_root = self.fix.root/'next-audit'
        self.next_root.mkdir(mode=0o700)
        self.next_key = self.fix.private/'next-audit.key'
        self.next_key.write_bytes(os.urandom(32))
        self.next_key.chmod(0o600)
        self.cont_proposal = self.fix.private/'ec264-transition-proposal.json'
        self.continuation = self.fix.private/'ec264-transition.json'
        proposed = seg.propose_transition(str(self.audit_root), str(self.audit_key),
            str(self.checkpoint), self.cp_pin, str(self.public), self.pub_pin,
            str(self.next_key), seg.ZERO, str(self.cont_proposal))
        self.cont_pin = seg.sign_transition_offline(str(self.cont_proposal),
            str(self.signing), str(self.continuation))['continuation_sha256']
        self.config = self.fix.private/'ec264-chain.json'
        self.config.write_bytes(seg._canonical({
            'schema': seg.CONFIG_SCHEMA,
            'signer_public_key': str(self.public),
            'signer_public_sha256': self.pub_pin,
            'archives': [{'audit_root': str(self.audit_root),
                          'audit_key': str(self.audit_key),
                          'checkpoint': str(self.checkpoint),
                          'checkpoint_sha256': self.cp_pin,
                          'continuation': str(self.continuation),
                          'continuation_sha256': self.cont_pin}],
            'active': {'audit_root': str(self.next_root),
                       'audit_key': str(self.next_key),
                       'segment_id': proposed['next_segment_id']},
        }) + b'\n')
        self.config.chmod(0o600)
        self.chain_pin = cp._digest(self.config.read_bytes())
        with seg.SegmentAudit(str(self.config), self.chain_pin,
                              initialize=True):
            pass
        self.args = argparse.Namespace(
            policy=str(self.fix.policy_path), socket=self.socket,
            repo=str(self.gitfx.repo), allowlist=str(self.gitfx.allowpath),
            receipt=str(self.gitfx.output/'source.custody.json'),
            profile_id='python.pytest', max_sessions=1, accept_timeout=3,
            chain=str(self.config), chain_sha256=self.chain_pin,
        )

    def start(self):
        child = os.fork()
        if child == 0:
            try:
                def reap(_pol, _label, _name, container_id, *, recorded, on_bound):
                    if (container_id != strict.ID or
                            recorded != self.proof.journal_event()):
                        raise cg.CgroupError('EC264_TEST_REAP_DRIFT')
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
                    segmented_service.run_serve(self.args)
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
                self.fail('EC264 segmented host failed before socket: ' +
                          str(os.waitstatus_to_exitcode(status)))
            time.sleep(.01)
        self.fail('EC264 segmented host failed to bind socket')

    def test_01_signed_git_session_after_archive_roundtrip_and_cleanup(self):
        self.prepare()
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            events = []
            for _ in range(50):
                result = client.poll(80, budget.MAX_CHUNK)
                events.append(result)
                if result['kind'] == 'exit':
                    break
        self.assertEqual(events[-1]['kind'], 'exit')
        self.join_host()
        self.assert_ledger_closed()
        with seg.SegmentAudit(str(self.config), self.chain_pin,
                              writable=False) as audit:
            report = audit.summary()
            self.assertEqual(report['sealed_archive_count'], 1)
            self.assertEqual(report['sealed_archive_event_count'], 2)
            self.assertGreater(report['active_local_event_count'], 4)
            self.assertFalse(report['overall_quality_pass_verified'])
        labels = [json.loads(row)['event'] for row in
                  (self.next_root/'events.jsonl').read_bytes().splitlines()]
        self.assertIn('begin_authorized', labels)
        self.assertIn('session_cleanup_state', labels)
        self.assertIn('service_closed', labels)
        self.assertEqual(len((self.audit_root/'events.jsonl').read_bytes().splitlines()), 2)

    def test_02_replaced_archived_checkpoint_denied_pre_socket_pre_lease(self):
        self.prepare()
        self.checkpoint.write_bytes(self.checkpoint.read_bytes().replace(
            b'"nonce":', b'"nonceX":', 1))
        with self.assertRaises(cp.AnchorError):
            segmented_service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')), [])
        with AuditLog(str(self.next_root), str(self.next_key), create=False) as audit:
            self.assertEqual(audit.count, 0)

    def test_03_previous_archive_tamper_during_live_session_forces_cleanup(self):
        self.prepare()
        self.engine_wait = 4.0
        self.start()
        client = self.remote().begin(self.begin_request())
        p = self.audit_root/'events.jsonl'
        raw = p.read_bytes()
        p.write_bytes(raw.replace(b'service_start', b'service_stArT', 1))
        client.conn.settimeout(6)
        try:
            try:
                client.poll(80, budget.MAX_CHUNK)
            except (session.SessionHostError, socket.error):
                pass
        finally:
            client.conn.close()
        pid, status = os.waitpid(self.child, 0)
        self.child = None
        self.assertEqual(os.waitstatus_to_exitcode(status), 5)
        self.assert_ledger_closed()


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SegmentedRealGitSessionTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
