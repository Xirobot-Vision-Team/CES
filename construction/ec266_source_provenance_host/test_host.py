#!/usr/bin/env python3
"""EC266 real Git/socket/fork/signed-lease integration; OCI/cgroup mocked.

This deliberately does NOT claim an independently deployed Git/CI service,
external evidence issuer, real Podman or delegated kernel cgroup-v2.
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
from ec254_session_host import broker as session
from ec263_offline_anchor_host import checkpoint as cp
from ec264_segmented_audit_host import test_host as source_host
from ec266_source_provenance_host import provenance as prov
from ec266_source_provenance_host import serve as source_serve
from ec266_source_provenance_host.test_provenance import ProvenanceTests as base
from ec265_custody_receipt_host import custody as trust_audit
import quality_run_budget as budget


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').exists() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux real Git/Ed25519 required')
class RealGitSignedSourceHostTests(unittest.TestCase):
    setUp = base.setUp
    prepare = base.prepare
    prepare_base = base.prepare_base
    write_gate = base.write_gate
    new_gate = base.new_gate
    engine = source_host.SegmentedRealGitSessionTests.engine
    remote = source_host.SegmentedRealGitSessionTests.remote
    begin_request = source_host.SegmentedRealGitSessionTests.begin_request
    join_host = source_host.SegmentedRealGitSessionTests.join_host
    kill_host = source_host.SegmentedRealGitSessionTests.kill_host
    assert_ledger_closed = source_host.SegmentedRealGitSessionTests.assert_ledger_closed
    _prepare = source_host.SegmentedRealGitSessionTests._prepare

    def start(self):
        with mock.patch.object(source_host.segmented_service, 'run_serve',
                               new=source_serve.run_serve):
            source_host.SegmentedRealGitSessionTests.start(self)

    def test_01_git_session_requires_three_signatures_and_custody(self):
        self.prepare()
        preflight = source_serve.verify_gate(self.args)
        self.assertEqual(preflight['role_signatures_valid'], ['origin', 'review', 'ci'])
        self.assertEqual(preflight['custody_receipts_verified'], 1)
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            events = []
            for _ in range(50):
                event = client.poll(80, budget.MAX_CHUNK)
                events.append(event)
                if event['kind'] == 'exit':
                    break
        self.assertEqual(events[-1]['kind'], 'exit')
        self.join_host()
        self.assert_ledger_closed()
        with trust_audit.CustodyAudit(str(self.config), self.chain_pin,
                str(self.custody_gate), self.args.custody_gate_sha256,
                writable=False) as audit:
            labels = [json.loads(row)['event'] for row in
                      (self.next_root/'events.jsonl').read_bytes().splitlines()]
            self.assertIn('begin_authorized', labels)
            self.assertIn('service_closed', labels)
            self.assertEqual(audit.summary()['custody_receipts_verified'], 1)

    def test_02_invalid_remote_review_signature_denied_pre_socket_lease_audit(self):
        self.prepare()
        doc = self.signers['review']['signed']
        raw = doc.read_bytes()
        doc.write_bytes(raw.replace(b'"approved"', b'"rejected"'))
        with self.assertRaises(prov.ProvenanceError):
            source_serve.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')), [])
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(), b'')

    def test_03_ci_evidence_removed_during_live_session_causes_cleanup(self):
        self.prepare()
        self.engine_wait = 4.0
        self.start()
        client = self.remote().begin(self.begin_request())
        self.signers['ci']['evidence'].unlink()
        client.conn.settimeout(8)
        responses = []
        try:
            try:
                for _ in range(40):
                    responses.append(client.poll(80, budget.MAX_CHUNK))
                    if responses[-1]['kind'] == 'exit':
                        break
            except (socket.error, session.SessionHostError):
                # A revoked source authority may cause a refused poll or a
                # disconnected transport; neither can count as success.
                pass
        finally:
            client.conn.close()
        pid, status = os.waitpid(self.child, 0)
        self.child = None
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertFalse(any(x.get('kind') == 'exit' for x in responses))
        self.assert_ledger_closed()
        rows = [json.loads(x) for x in
                (self.next_root/'events.jsonl').read_bytes().splitlines()]
        self.assertTrue(any(x['event'] == 'session_denied' and
            x['reason_code'] == 'EC266_PRIVATE_FILE_UNAVAILABLE' for x in rows))
        self.assertTrue(any(x['event'] == 'session_cleanup_state' for x in rows))


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RealGitSignedSourceHostTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
