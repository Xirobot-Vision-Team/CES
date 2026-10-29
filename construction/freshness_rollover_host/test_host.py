#!/usr/bin/env python3
"""EC272 nonroot Git + AF_UNIX/fork + signed custody host checks.

Podman OCI and cgroup remain mocks, not production isolation evidence.
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
from session_host import broker as session
from offline_anchor_host import checkpoint as cp
from segmented_audit_host import test_host as host
from custody_receipt_host.custody import CustodyAudit
from freshness_rollover_host import serve as service
from freshness_rollover_host.test_rollover import RolloverTests as original
import quality_run_budget as budget


@unittest.skipUnless(os.name=='posix' and os.geteuid()!=0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux Git/Ed25519 required')
class SignedRolloverHostTests(unittest.TestCase):
    setUp=original.setUp
    prepare=original.prepare
    _context=original._context
    _signed_checkpoint=original._signed_checkpoint
    sign_seal=original.sign_seal
    historic=original.historic
    freshness_options=original.freshness_options
    prepare_base=original.prepare_base
    prepare_ec266=original.prepare_ec266
    new_gov=original.new_gov
    make_handover=original.make_handover
    renew_policy=original.renew_policy
    create_chain=original.create_chain
    issue=original.issue
    write_gate=original.write_gate
    _kwargs=original._kwargs
    sign_recovery=original.sign_recovery
    sign_closure=original.sign_closure
    closure_material=original.closure_material
    material=original.material
    _prepare=host.SegmentedRealGitSessionTests._prepare
    engine=host.SegmentedRealGitSessionTests.engine
    remote=host.SegmentedRealGitSessionTests.remote
    begin_request=host.SegmentedRealGitSessionTests.begin_request
    join_host=host.SegmentedRealGitSessionTests.join_host
    kill_host=host.SegmentedRealGitSessionTests.kill_host
    assert_ledger_closed=host.SegmentedRealGitSessionTests.assert_ledger_closed

    def start(self):
        with mock.patch.object(host.segmented_service,'run_serve',new=service.run_serve):
            host.SegmentedRealGitSessionTests.start(self)

    def events(self):
        return [json.loads(x)['event'] for x in
                (self.next_root/'events.jsonl').read_bytes().splitlines()]

    def test_01_strict_host_accepts_signed_checkpoint_and_reaps_session(self):
        self.prepare()
        self.prev_root_secret.unlink()
        self.witness_secret.unlink()
        report=service.verify_gate(self.args)
        self.assertEqual(report['sealed_checkpoint_number'],1)
        self.assertEqual(report['freshness_sequence'],2)
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            rows=[]
            for _ in range(50):
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
        self.assertIn('service_closed',self.events())
        self.assertIn('begin_authorized',self.events())

    def test_02_missing_historic_checkpoint_fails_before_socket_and_lease(self):
        self.prepare()
        self.cp_file.unlink()
        with self.assertRaises(Exception):
            service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')),[])
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(),b'')

    def test_03_active_session_revoked_when_current_tail_disappears(self):
        self.prepare()
        self.engine_wait=4.0
        self.start()
        client=self.remote().begin(self.begin_request())
        self.next_receipt.unlink()
        client.conn.settimeout(8)
        rows=[]
        try:
            try:
                for _ in range(45):
                    r=client.poll(80,budget.MAX_CHUNK)
                    rows.append(r)
                    if r['kind']=='exit':
                        break
            except (socket.error,session.SessionHostError):
                pass
        finally:
            client.conn.close()
        _,status=os.waitpid(self.child,0)
        self.child=None
        self.assertEqual(os.waitstatus_to_exitcode(status),0)
        self.assertFalse(any(r.get('kind')=='exit' for r in rows))
        self.assert_ledger_closed()
        self.assertIn('session_denied',self.events())
        self.assertIn('session_cleanup_state',self.events())

    def test_04_old_parent_ec270_remains_independent_of_rollover(self):
        self.prepare()
        from recovery_closure_host import serve as old
        self.assertTrue(old.verify_gate(self.args)['closure_independent_witness_signature_verified'])
        self.cp_file.unlink()
        self.assertTrue(old.verify_gate(self.args)['closure_independent_witness_signature_verified'])
        with self.assertRaises(Exception):
            service.verify_gate(self.args)


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(SignedRolloverHostTests)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
