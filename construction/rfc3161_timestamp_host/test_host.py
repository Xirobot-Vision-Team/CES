#!/usr/bin/env python3
"""EC273 optional strict service: real Git/socket/lease/recall, synthetic TSA.

OCI and cgroup are still mocked by inherited EC257 development fixtures.
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
from freshness_rollover_host import serve as old_host
from freshness_rollover_host.test_host import SignedRolloverHostTests as original
from rfc3161_timestamp_host import serve as service
from rfc3161_timestamp_host.test_timeproof import LocalTSA
import quality_run_budget as budget


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and
                     os.geteuid()!=0 and Path('/usr/bin/git').exists() and
                     Path('/usr/bin/openssl').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux Git/OpenSSL/Ed25519 required')
class TrustedTimestampHostTests(unittest.TestCase,LocalTSA):
    setUp=original.setUp
    _prepare=original._prepare
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
    engine=original.engine
    remote=original.remote
    begin_request=original.begin_request
    join_host=original.join_host
    kill_host=original.kill_host
    assert_ledger_closed=original.assert_ledger_closed

    def prepare_tsa(self):
        self.prepare()
        self.issue_tsa()
        self.args.tsa_request=str(self.tsa_request)
        self.args.tsa_request_sha256=self.tsa_request_pin
        self.args.tsa_response=str(self.tsa_response)
        self.args.tsa_response_sha256=self.response_pin
        self.args.tsa_ca_bundle=str(self.ca)
        self.args.tsa_ca_bundle_sha256=__import__('hashlib').sha256(self.ca.read_bytes()).hexdigest()
        self.args.tsa_leaf_cert_sha256=self.leaf_pin
        self.args.tsa_policy_oid=self.tsa_policy
        self.args.tsa_openssl_binary=self.openssl
        self.args.tsa_openssl_binary_sha256=self.binary_pin
        self.args.tsa_max_age_seconds=600
        self.args.tsa_minimum_time_unix=self.issued-30
        self.args.tsa_intermediates=None
        self.args.tsa_intermediates_sha256=None

    def start(self):
        with mock.patch.object(host.segmented_service,'run_serve',new=service.run_serve):
            host.SegmentedRealGitSessionTests.start(self)

    def events(self):
        return [json.loads(x)['event'] for x in
                (self.next_root/'events.jsonl').read_bytes().splitlines()]

    def test_01_timestamp_gate_allows_real_git_session(self):
        self.prepare_tsa()
        self.prev_root_secret.unlink()
        self.witness_secret.unlink()
        report=service.verify_gate(self.args)
        self.assertTrue(report['trusted_external_timestamp_signature_verified'])
        self.assertEqual(report['sealed_checkpoint_number'],1)
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            replies=[]
            for _ in range(50):
                response=client.poll(80,budget.MAX_CHUNK)
                replies.append(response)
                if response['kind']=='exit':
                    break
        self.assertEqual(replies[-1]['kind'],'exit')
        self.join_host()
        self.assert_ledger_closed()
        self.assertIn('begin_authorized',self.events())
        self.assertIn('service_closed',self.events())

    def test_02_missing_tsa_denies_before_socket_and_lease(self):
        self.prepare_tsa()
        self.tsa_response.unlink()
        with self.assertRaises(Exception):
            service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')),[])
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(),b'')

    def test_03_session_live_revoked_if_tsa_token_disappears(self):
        self.prepare_tsa()
        self.engine_wait=4.0
        self.start()
        client=self.remote().begin(self.begin_request())
        self.tsa_response.unlink()
        client.conn.settimeout(8)
        messages=[]
        try:
            try:
                for _ in range(50):
                    response=client.poll(80,budget.MAX_CHUNK)
                    messages.append(response)
                    if response.get('kind')=='exit':
                        break
            except (socket.error,session.SessionHostError):
                pass
        finally:
            client.conn.close()
        _,status=os.waitpid(self.child,0)
        self.child=None
        self.assertEqual(os.waitstatus_to_exitcode(status),0)
        self.assertFalse(any(msg.get('kind')=='exit' for msg in messages))
        self.assert_ledger_closed()
        self.assertIn('session_denied',self.events())

    def test_04_old_ec272_host_remains_opt_in_and_unchanged(self):
        self.prepare_tsa()
        self.assertEqual(old_host.verify_gate(self.args)['freshness_sequence'],2)
        self.tsa_request.unlink()
        self.assertEqual(old_host.verify_gate(self.args)['freshness_sequence'],2)
        with self.assertRaises(Exception):
            service.verify_gate(self.args)


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(TrustedTimestampHostTests)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
