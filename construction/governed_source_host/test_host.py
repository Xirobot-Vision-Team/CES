#!/usr/bin/env python3
"""EC267 opt-in Git/AF_UNIX/signed-lease/in-session issuer recall integration.

The Podman/cgroup runtime is mocked; real external identity and clock are not.
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
from governed_source_host import governance as gov
from governed_source_host import serve as governed_serve
from governed_source_host.test_governance import GovernanceTests as old
import quality_run_budget as budget


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'real nonroot Git + cryptography required')
class GovernedGitHostTests(unittest.TestCase):
    setUp = old.setUp
    prepare = old.prepare
    prepare_ec266 = old.prepare_ec266
    issue = old.issue
    write_gate = old.write_gate
    engine = host.SegmentedRealGitSessionTests.engine
    remote = host.SegmentedRealGitSessionTests.remote
    begin_request = host.SegmentedRealGitSessionTests.begin_request
    join_host = host.SegmentedRealGitSessionTests.join_host
    kill_host = host.SegmentedRealGitSessionTests.kill_host
    assert_ledger_closed = host.SegmentedRealGitSessionTests.assert_ledger_closed
    _prepare = host.SegmentedRealGitSessionTests._prepare
    prepare_base = old.prepare_base

    def start(self):
        with mock.patch.object(host.segmented_service, 'run_serve',
                               new=governed_serve.run_serve):
            host.SegmentedRealGitSessionTests.start(self)

    def test_01_current_governance_allows_fully_audited_session(self):
        self.prepare()
        preflight = governed_serve.verify_gate(self.args)
        self.assertTrue(preflight['independent_governance_signature_verified'])
        self.assertEqual(preflight['custody_receipts_verified'], 1)
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            events = []
            for _ in range(45):
                event = client.poll(80, budget.MAX_CHUNK)
                events.append(event)
                if event['kind'] == 'exit':
                    break
        self.assertEqual(events[-1]['kind'], 'exit')
        self.join_host()
        self.assert_ledger_closed()
        with CustodyAudit(str(self.config), self.chain_pin, str(self.custody_gate),
                          self.args.custody_gate_sha256, writable=False) as audit:
            events = [json.loads(row)['event'] for row in
                      (self.next_root/'events.jsonl').read_bytes().splitlines()]
            self.assertIn('begin_authorized', events)
            self.assertIn('service_closed', events)
            self.assertEqual(audit.summary()['custody_receipts_verified'], 1)

    def test_02_revoked_ci_authority_denied_before_socket_audit_or_new_lease(self):
        self.prepare()
        self.issue(revoked=(self.signers['ci']['pin'],))
        with self.assertRaisesRegex(gov.GovernanceError, 'EC267_ACTIVE_ISSUER_REVOKED'):
            governed_serve.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')), [])
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(), b'')

    def test_03_live_revocation_by_snapshot_removal_denies_and_cleans_lease(self):
        self.prepare()
        self.engine_wait = 4.0
        self.start()
        client = self.remote().begin(self.begin_request())
        self.gov_policy.unlink()
        client.conn.settimeout(8)
        replies = []
        try:
            try:
                for _ in range(40):
                    replies.append(client.poll(80, budget.MAX_CHUNK))
                    if replies[-1]['kind'] == 'exit':
                        break
            except (socket.error, session.SessionHostError):
                pass
        finally:
            client.conn.close()
        _, status = os.waitpid(self.child, 0)
        self.child = None
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertFalse(any(x.get('kind') == 'exit' for x in replies))
        self.assert_ledger_closed()
        rows = [json.loads(x) for x in
                (self.next_root/'events.jsonl').read_bytes().splitlines()]
        self.assertTrue(any(x['event'] == 'session_denied' for x in rows))
        self.assertTrue(any(x['event'] == 'session_cleanup_state' for x in rows))


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(GovernedGitHostTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
