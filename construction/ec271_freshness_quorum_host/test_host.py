#!/usr/bin/env python3
"""EC271 strict host functional tests using Git/AF_UNIX/fork/Lease/audit.

OCI execution and cgroup kernel accounting are inherited mocks. These tests
never establish remote forge, timestamp, human separation or WORM acceptance.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from ec254_session_host import broker as session
from ec263_offline_anchor_host import checkpoint as cp
from ec264_segmented_audit_host import test_host as host
from ec265_custody_receipt_host.custody import CustodyAudit
from ec271_freshness_quorum_host import serve as service
from ec271_freshness_quorum_host.test_freshness import FreshnessTests as original
import quality_run_budget as budget


@unittest.skipUnless(os.name=='posix' and os.geteuid()!=0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux Git Ed25519 required')
class QuorumFreshnessHostTests(unittest.TestCase):
    setUp = original.setUp
    prepare = original.prepare
    historic = original.historic
    freshness_options = original.freshness_options
    sign_seal = original.sign_seal
    new_gate = original.new_gate
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
        return [json.loads(x)['event'] for x in
                (self.next_root/'events.jsonl').read_bytes().splitlines()]

    def test_01_two_signatures_authorize_real_git_lease_audit(self):
        self.prepare()
        self.prev_root_secret.unlink()
        self.witness_secret.unlink()
        self.assertEqual(service.verify_gate(self.args)['freshness_signed_witnesses'],2)
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            rows=[]
            for _ in range(45):
                r=client.poll(80,budget.MAX_CHUNK)
                rows.append(r)
                if r['kind']=='exit':
                    break
        self.assertEqual(rows[-1]['kind'],'exit')
        self.join_host()
        self.assert_ledger_closed()
        with CustodyAudit(str(self.config),self.chain_pin,str(self.custody_gate),
                          self.args.custody_gate_sha256,writable=False) as audit:
            self.assertEqual(audit.summary()['custody_receipts_verified'],1)
        self.assertIn('begin_authorized',self.events())
        self.assertIn('service_closed',self.events())

    def test_02_missing_quorum_receipt_denies_before_service_start(self):
        self.prepare()
        self.receipt.unlink()
        with self.assertRaises(Exception):
            service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')),[])
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(),b'')

    def test_03_witness_key_removed_mid_session_revokes_and_reaps(self):
        self.prepare()
        self.engine_wait=4.0
        self.start()
        client=self.remote().begin(self.begin_request())
        self.witnesses[1][1].unlink()
        client.conn.settimeout(8)
        replies=[]
        try:
            try:
                for _ in range(45):
                    r=client.poll(80,budget.MAX_CHUNK)
                    replies.append(r)
                    if r['kind']=='exit':
                        break
            except (socket.error,session.SessionHostError):
                pass
        finally:
            client.conn.close()
        _,status=os.waitpid(self.child,0)
        self.child=None
        self.assertEqual(os.waitstatus_to_exitcode(status),0)
        self.assertFalse(any(r.get('kind')=='exit' for r in replies))
        self.assert_ledger_closed()
        self.assertIn('session_denied',self.events())
        self.assertIn('session_cleanup_state',self.events())

    def test_04_old_parent_host_still_succeeds_without_new_credential(self):
        self.prepare()
        from ec270_recovery_closure_host import serve as parent
        self.assertTrue(parent.verify_gate(self.args)['closure_independent_witness_signature_verified'])
        self.receipt.unlink()
        self.assertTrue(parent.verify_gate(self.args)['closure_independent_witness_signature_verified'])
        with self.assertRaises(Exception):
            service.verify_gate(self.args)

    def test_05_changing_pinned_witness_roster_denies_before_socket(self):
        self.prepare()
        self.args.freshness_witness_public[1]=str(self.new_root_public)
        self.args.freshness_witness_public_sha256[1]=self.new_root_pin
        with self.assertRaises(Exception):
            service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(),b'')


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(QuorumFreshnessHostTests)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
