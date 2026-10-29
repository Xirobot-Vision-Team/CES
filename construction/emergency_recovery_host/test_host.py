#!/usr/bin/env python3
"""EC269 real AF_UNIX/Git/lease/signed audit tests; OCI/cgroup mocked.

All root/council signers are local simulated identities, not actual physical
council members or a remote issuer. No production Podman result is asserted.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from session_host import broker as session
from offline_anchor_host import checkpoint as cp
from segmented_audit_host import test_host as host
from custody_receipt_host.custody import CustodyAudit
from emergency_recovery_host import recovery as rec
from emergency_recovery_host import serve as service
from emergency_recovery_host.test_recovery import EmergencyRecoveryTests as original
import quality_run_budget as budget


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux Git and cryptography required')
class RealRecoveryHostTests(unittest.TestCase):
    setUp = original.setUp
    prepare = original.prepare
    prepare_base = original.prepare_base
    prepare_ec266 = original.prepare_ec266
    new_gov = original.new_gov
    make_handover = original.make_handover
    renew_policy = original.renew_policy
    create_chain = original.create_chain
    issue = original.issue
    write_gate = original.write_gate
    _kwargs = original._kwargs
    material = original.material
    sign_recovery = original.sign_recovery
    engine = host.SegmentedRealGitSessionTests.engine
    remote = host.SegmentedRealGitSessionTests.remote
    begin_request = host.SegmentedRealGitSessionTests.begin_request
    join_host = host.SegmentedRealGitSessionTests.join_host
    kill_host = host.SegmentedRealGitSessionTests.kill_host
    assert_ledger_closed = host.SegmentedRealGitSessionTests.assert_ledger_closed
    _prepare = host.SegmentedRealGitSessionTests._prepare

    def start(self):
        with mock.patch.object(host.segmented_service,'run_serve',new=service.run_serve):
            host.SegmentedRealGitSessionTests.start(self)

    def _events(self):
        return [json.loads(row)['event'] for row in
                (self.next_root/'events.jsonl').read_bytes().splitlines()]

    def test_01_quorum_recovery_enables_real_audited_git_session(self):
        self.prepare()
        self.prev_root_secret.unlink()
        assert service.verify_gate(self.args)['independent_council_votes_verified'] == 2
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            output=[]
            for _ in range(45):
                reply=client.poll(80,budget.MAX_CHUNK)
                output.append(reply)
                if reply['kind']=='exit':
                    break
        self.assertEqual(output[-1]['kind'],'exit')
        self.join_host()
        self.assert_ledger_closed()
        with CustodyAudit(str(self.config),self.chain_pin,str(self.custody_gate),
                          self.args.custody_gate_sha256,writable=False) as audit:
            self.assertEqual(audit.summary()['custody_receipts_verified'],1)
        events=self._events()
        self.assertIn('service_closed',events)
        self.assertIn('begin_authorized',events)
        self.assertIn('session_cleanup_state',events)

    def test_02_missing_charter_denied_before_socket_new_lease_or_audit(self):
        self.prepare()
        self.charter.unlink()
        with self.assertRaises(rec.RecoveryError):
            service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')),[])
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(),b'')

    def test_03_lost_council_public_key_actively_recalls_running_session(self):
        self.prepare()
        self.engine_wait = 4.0
        self.start()
        client=self.remote().begin(self.begin_request())
        self.council[0][1].unlink()
        client.conn.settimeout(8)
        output=[]
        try:
            try:
                for _ in range(45):
                    reply=client.poll(80,budget.MAX_CHUNK)
                    output.append(reply)
                    if reply['kind']=='exit':
                        break
            except (socket.error,session.SessionHostError):
                pass
        finally:
            client.conn.close()
        _,status=os.waitpid(self.child,0)
        self.child=None
        self.assertEqual(os.waitstatus_to_exitcode(status),0)
        self.assertFalse(any(x.get('kind')=='exit' for x in output))
        self.assert_ledger_closed()
        events=self._events()
        self.assertIn('session_denied',events)
        self.assertIn('session_cleanup_state',events)

    def test_04_recovery_new_root_independent_renewal_uses_same_host(self):
        self.prepare()
        next_gov,next_pin=self.renew_policy(3,self.new_pin)
        chain,chain_pin=self.create_chain(next_gov,next_pin)
        self.args.governance_policy=str(next_gov)
        self.args.governance_policy_sha256=next_pin
        self.args.minimum_governance_epoch=3
        self.args.expected_previous_governance_sha256=self.new_pin
        self.args.continuation_chain=str(chain)
        self.args.continuation_chain_sha256=chain_pin
        self.prev_root_secret.unlink()
        self.assertEqual(service.verify_gate(self.args)['new_root_continuation_epochs'],1)
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            events=[]
            for _ in range(45):
                reply=client.poll(80,budget.MAX_CHUNK)
                events.append(reply)
                if reply['kind']=='exit':break
        self.assertEqual(events[-1]['kind'],'exit')
        self.join_host()
        self.assert_ledger_closed()

    def test_05_certificate_tamper_rejected_before_socket_or_start_audit(self):
        self.prepare()
        self.recovery_cert.write_bytes(self.recovery_cert.read_bytes()+b'\x20')
        with self.assertRaises(rec.RecoveryError):
            service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(),b'')


if __name__ == '__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(RealRecoveryHostTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
