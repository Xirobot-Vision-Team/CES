#!/usr/bin/env python3
"""EC265 strict signed Git + AF_UNIX host, true receipts; OCI/cgroup mocked."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from offline_anchor_host import checkpoint as cp
from segmented_audit_host import segment as seg
from segmented_audit_host import test_host as source_host
from custody_receipt_host import custody
from custody_receipt_host import serve as custody_serve
import quality_run_budget as budget


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').exists() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux Git and Ed25519 required')
class RealGitCustodyGateTests(unittest.TestCase):
    setUp = source_host.SegmentedRealGitSessionTests.setUp
    engine = source_host.SegmentedRealGitSessionTests.engine
    remote = source_host.SegmentedRealGitSessionTests.remote
    begin_request = source_host.SegmentedRealGitSessionTests.begin_request
    join_host = source_host.SegmentedRealGitSessionTests.join_host
    kill_host = source_host.SegmentedRealGitSessionTests.kill_host
    assert_ledger_closed = source_host.SegmentedRealGitSessionTests.assert_ledger_closed
    _prepare = source_host.SegmentedRealGitSessionTests._prepare

    def prepare(self):
        source_host.SegmentedRealGitSessionTests.prepare(self)
        transport = self.fix.root/'transport'
        custody.export_archive(str(self.config), self.chain_pin, 0, str(transport))
        self.custody_secret = self.fix.private/'custodian-ed25519.key'
        self.custody_public = self.fix.private/'custodian-ed25519.pub'
        self.custody_pin = cp.generate_offline_keypair(str(self.custody_secret),
                                                       str(self.custody_public))['signer_public_sha256']
        vault = self.fix.root/'vault'
        vault.mkdir(mode=0o700)
        receipt = custody.receive_archive(str(transport), str(vault),
            str(self.custody_secret), self.custody_pin, expected_index=0,
            expected_checkpoint_pin=self.cp_pin,
            expected_continuation_pin=self.cont_pin,
            expected_parent_pin=seg.ZERO, expected_signer_pin=self.pub_pin)
        self.receiver_receipt = self.fix.private/'custody-receipt.json'
        shutil.copyfile(receipt['receipt_path'], self.receiver_receipt)
        self.receiver_receipt.chmod(0o600)
        gate = {'schema': custody.GATE_SCHEMA,
                'custody_public_key': str(self.custody_public),
                'custody_public_sha256': self.custody_pin,
                'receipts': [{'archive_index': 0, 'receipt': str(self.receiver_receipt),
                              'receipt_sha256': cp._digest(self.receiver_receipt.read_bytes())}]}
        self.custody_gate = self.fix.private/'custody-gate.json'
        self.custody_gate.write_bytes(seg._canonical(gate) + b'\n')
        self.custody_gate.chmod(0o600)
        self.args.custody_gate = str(self.custody_gate)
        self.args.custody_gate_sha256 = cp._digest(self.custody_gate.read_bytes())

    def start(self):
        # Reuse EC264 real Git/Socket/HMAC/fork cleanup fixture, but invoke the
        # NEW service under its existing mocked OCI/cgroup execution harness.
        with mock.patch.object(source_host.segmented_service, 'run_serve',
                               new=custody_serve.run_serve):
            source_host.SegmentedRealGitSessionTests.start(self)

    def test_01_signed_git_session_requires_receipt_and_reaps_ledger(self):
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
        rows = [json.loads(line) for line in
                (self.next_root/'events.jsonl').read_bytes().splitlines()]
        labels = [row['event'] for row in rows]
        self.assertIn('begin_authorized', labels)
        self.assertIn('service_closed', labels)
        with custody.CustodyAudit(str(self.config), self.chain_pin,
                str(self.custody_gate), self.args.custody_gate_sha256,
                writable=False) as audit:
            self.assertEqual(audit.summary()['custody_receipts_verified'], 1)
            self.assertFalse(audit.summary()['overall_quality_pass_verified'])

    def test_02_receipt_tamper_refused_pre_socket_and_pre_lease(self):
        self.prepare()
        self.receiver_receipt.write_bytes(self.receiver_receipt.read_bytes().replace(
            b'"nonce":', b'"other":', 1))
        with self.assertRaises(custody.CustodyError):
            custody_serve.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')), [])
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(), b'')


if __name__ == '__main__':
    unittest.main(verbosity=2)
