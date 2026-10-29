#!/usr/bin/env python3
"""EC268 actual Git/socket/lease/signed audit/recall; OCI + cgroup mock only."""
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
from root_handover_host import handover as rot
from root_handover_host import serve as service
from root_handover_host.test_handover import RootHandoverTests as original
import quality_run_budget as budget


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'real local nonroot Git and Ed25519 required')
class RealRootHandoverGitHostTests(unittest.TestCase):
    setUp = original.setUp
    prepare = original.prepare
    prepare_base = original.prepare_base
    prepare_ec266 = original.prepare_ec266
    new_gov = original.new_gov
    renew_policy = original.renew_policy
    create_chain = original.create_chain
    make_handover = original.make_handover
    _kwargs = original._kwargs
    issue = original.issue
    write_gate = original.write_gate
    engine = host.SegmentedRealGitSessionTests.engine
    remote = host.SegmentedRealGitSessionTests.remote
    begin_request = host.SegmentedRealGitSessionTests.begin_request
    join_host = host.SegmentedRealGitSessionTests.join_host
    kill_host = host.SegmentedRealGitSessionTests.kill_host
    assert_ledger_closed = host.SegmentedRealGitSessionTests.assert_ledger_closed
    _prepare = host.SegmentedRealGitSessionTests._prepare

    def start(self):
        with mock.patch.object(host.segmented_service, 'run_serve', new=service.run_serve):
            host.SegmentedRealGitSessionTests.start(self)

    def test_01_valid_three_party_handover_enables_audited_session(self):
        self.prepare()
        verified = service.verify_gate(self.args)
        self.assertEqual(verified['handover_signatures_verified'], ['old','new','witness'])
        self.assertEqual(verified['custody_receipts_verified'], 1)
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            events = []
            for _ in range(45):
                response = client.poll(80, budget.MAX_CHUNK)
                events.append(response)
                if response['kind'] == 'exit':
                    break
        self.assertEqual(events[-1]['kind'],'exit')
        self.join_host()
        self.assert_ledger_closed()
        with CustodyAudit(str(self.config),self.chain_pin,str(self.custody_gate),
                          self.args.custody_gate_sha256,writable=False) as audit:
            self.assertEqual(audit.summary()['custody_receipts_verified'],1)
            names = [json.loads(row)['event'] for row in
                     (self.next_root/'events.jsonl').read_bytes().splitlines()]
            self.assertIn('service_closed',names)
            self.assertIn('begin_authorized',names)
            self.assertIn('session_cleanup_state',names)

    def test_02_missing_witness_denied_before_socket_lease_or_service_audit(self):
        self.prepare()
        self.witness_public.unlink()
        with self.assertRaisesRegex(rot.HandoverError,'EC268_PUBLIC_KEY_FILE_UNAVAILABLE'):
            service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')),[])
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(),b'')

    def test_03_live_witness_recall_denies_response_and_closes_lease(self):
        self.prepare()
        self.engine_wait = 4.0
        self.start()
        client = self.remote().begin(self.begin_request())
        self.witness_public.unlink()
        client.conn.settimeout(8)
        replies = []
        try:
            try:
                for _ in range(45):
                    replies.append(client.poll(80,budget.MAX_CHUNK))
                    if replies[-1]['kind']=='exit':
                        break
            except (socket.error,session.SessionHostError):
                pass
        finally:
            client.conn.close()
        _, status = os.waitpid(self.child,0)
        self.child = None
        self.assertEqual(os.waitstatus_to_exitcode(status),0)
        self.assertFalse(any(r.get('kind')=='exit' for r in replies))
        self.assert_ledger_closed()
        names = [json.loads(row)['event'] for row in
                 (self.next_root/'events.jsonl').read_bytes().splitlines()]
        self.assertIn('session_denied',names)
        self.assertIn('session_cleanup_state',names)

    def test_04_modified_immutable_handover_denied_pre_socket(self):
        self.prepare()
        self.handover_cert.write_bytes(self.handover_cert.read_bytes() + b' ')
        with self.assertRaises(rot.HandoverError):
            service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(),b'')


    def test_05_renewed_new_root_epoch_operates_without_old_signing_secret(self):
        self.prepare()
        next_governance, next_pin = self.renew_policy(3,self.new_pin)
        chain, chain_pin = self.create_chain(next_governance,next_pin)
        self.args.governance_policy = str(next_governance)
        self.args.governance_policy_sha256 = next_pin
        self.args.minimum_governance_epoch = 3
        self.args.expected_previous_governance_sha256 = self.new_pin
        self.args.continuation_chain = str(chain)
        self.args.continuation_chain_sha256 = chain_pin
        self.prev_root_secret.unlink()
        self.witness_secret.unlink()
        verified = service.verify_gate(self.args)
        self.assertEqual(verified['governance_continuations'],1)
        self.assertEqual(verified['governance_epoch'],3)
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            events=[]
            for _ in range(45):
                response=client.poll(80,budget.MAX_CHUNK)
                events.append(response)
                if response['kind']=='exit':
                    break
        self.assertEqual(events[-1]['kind'],'exit')
        self.join_host()
        self.assert_ledger_closed()


if __name__ == '__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(RealRootHandoverGitHostTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
