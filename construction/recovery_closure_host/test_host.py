#!/usr/bin/env python3
"""EC270 real Git/AF_UNIX/fork/lease/audit host; OCI/cgroup are mocks.

Uses real locally signed offline credentials, not independent people or
remote WORM/forge/CI/Podman certification.
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
from governed_source_host import governance as gov
from segmented_audit_host import test_host as host
from custody_receipt_host.custody import CustodyAudit
from recovery_closure_host import closure as rat
from recovery_closure_host import serve as service
from recovery_closure_host.test_closure import RatifiedRecoveryTests as original
import quality_run_budget as budget


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux Git Ed25519 required')
class RatifiedRecoveryHostTests(unittest.TestCase):
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
    sign_recovery = original.sign_recovery
    sign_closure = original.sign_closure
    closure_material = original.closure_material
    material = original.material
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

    def events(self):
        return [json.loads(line)['event'] for line in
                (self.next_root/'events.jsonl').read_bytes().splitlines()]

    def test_01_ratified_recovery_allows_real_git_and_audit_session(self):
        self.prepare()
        self.prev_root_secret.unlink()
        self.witness_secret.unlink()
        self.assertTrue(service.verify_gate(self.args)['closure_independent_witness_signature_verified'])
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
        self.assertIn('service_closed',self.events())
        self.assertIn('begin_authorized',self.events())
        self.assertIn('session_cleanup_state',self.events())

    def test_02_missing_witness_denied_before_socket_lease_or_event(self):
        self.prepare()
        self.witness_public.unlink()
        with self.assertRaises(Exception):
            service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')),[])
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(),b'')

    def test_03_witness_loss_during_session_revokes_and_reaps(self):
        self.prepare()
        self.engine_wait=4.0
        self.start()
        client=self.remote().begin(self.begin_request())
        self.witness_public.unlink()
        client.conn.settimeout(8)
        responses=[]
        try:
            try:
                for _ in range(45):
                    reply=client.poll(80,budget.MAX_CHUNK)
                    responses.append(reply)
                    if reply['kind']=='exit':
                        break
            except (socket.error,session.SessionHostError):
                pass
        finally:
            client.conn.close()
        _,status=os.waitpid(self.child,0)
        self.child=None
        self.assertEqual(os.waitstatus_to_exitcode(status),0)
        self.assertFalse(any(r.get('kind')=='exit' for r in responses))
        self.assert_ledger_closed()
        self.assertIn('session_denied',self.events())
        self.assertIn('session_cleanup_state',self.events())

    def test_04_later_new_root_governance_and_inherited_lease_contract(self):
        self.prepare()
        next_policy,next_sha=self.renew_policy(3,self.new_pin)
        chain,chain_sha=self.create_chain(next_policy,next_sha)
        self.args.governance_policy=str(next_policy)
        self.args.governance_policy_sha256=next_sha
        self.args.minimum_governance_epoch=3
        self.args.expected_previous_governance_sha256=self.new_pin
        self.args.continuation_chain=str(chain)
        self.args.continuation_chain_sha256=chain_sha
        self.assertEqual(service.verify_gate(self.args)['new_root_continuation_epochs'],1)
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            events=[]
            for _ in range(45):
                reply=client.poll(80,budget.MAX_CHUNK)
                events.append(reply)
                if reply['kind']=='exit':
                    break
        self.assertEqual(events[-1]['kind'],'exit')
        self.join_host()
        self.assert_ledger_closed()

    def test_05_closure_certificate_tamper_blocks_start(self):
        self.prepare()
        self.closure_cert.write_bytes(self.closure_cert.read_bytes()+b' ')
        with self.assertRaises(Exception):
            service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(),b'')

    def test_06_expired_historic_charter_does_not_block_new_strict_host(self):
        self.prepare()
        charter_expiry=json.loads(self.charter.read_bytes())['expires_at_unix']
        self.assertLess(charter_expiry,self.valid_until)
        # The process and its active guarded responses see a single continuous
        # synthetic wall/monotonic clock after charter expiry but before the
        # current separately signed EC267 governance expires.
        with mock.patch.object(gov,'_now',return_value=(charter_expiry+3.0,500.0)):
            self.assertTrue(service.verify_gate(self.args)['closure_independent_witness_signature_verified'])
            self.start()
            with self.remote().begin(self.begin_request()) as client:
                responses=[]
                for _ in range(45):
                    response=client.poll(80,budget.MAX_CHUNK)
                    responses.append(response)
                    if response['kind']=='exit':
                        break
            self.assertEqual(responses[-1]['kind'],'exit')
            self.join_host()
            self.assert_ledger_closed()



if __name__ == '__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(RatifiedRecoveryHostTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
