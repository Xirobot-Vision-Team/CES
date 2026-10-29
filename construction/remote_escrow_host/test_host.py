#!/usr/bin/env python3
"""EC274 host integration: actual signed Git/TSA/TLS/AF_UNIX/lease/audit.

Independence of the escrow machine and rootless OCI/cgroup are not exercised:
localhost escrow is synthetic, OCI and cgroup are inherited mocks.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import ssl
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from session_host import broker as session
from offline_anchor_host import checkpoint as cp
from segmented_audit_host import test_host as host
from rfc3161_timestamp_host import serve as parent_service
from rfc3161_timestamp_host.test_host import TrustedTimestampHostTests as base
from rfc3161_timestamp_host.test_timeproof import LocalTSA
from remote_escrow_host import escrow as esc
from remote_escrow_host import operator as ops
from remote_escrow_host import serve as service
from remote_escrow_host.daemon import Handler, BoundedTLSServer
from remote_escrow_host.test_escrow import EscrowProtocolTests
import quality_run_budget as budget


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and
                     os.geteuid()!=0 and Path('/usr/bin/git').exists() and
                     Path('/usr/bin/openssl').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot real Git/OpenSSL/Ed25519 required')
class RemoteEscrowHostTests(unittest.TestCase,LocalTSA):
    setUp=base.setUp
    _prepare=base._prepare
    prepare=base.prepare
    prepare_tsa=base.prepare_tsa
    _context=base._context
    _signed_checkpoint=base._signed_checkpoint
    sign_seal=base.sign_seal
    historic=base.historic
    freshness_options=base.freshness_options
    prepare_base=base.prepare_base
    prepare_ec266=base.prepare_ec266
    new_gov=base.new_gov
    make_handover=base.make_handover
    renew_policy=base.renew_policy
    create_chain=base.create_chain
    issue=base.issue
    write_gate=base.write_gate
    _kwargs=base._kwargs
    sign_recovery=base.sign_recovery
    sign_closure=base.sign_closure
    closure_material=base.closure_material
    material=base.material
    engine=base.engine
    remote=base.remote
    begin_request=base.begin_request
    join_host=base.join_host
    kill_host=base.kill_host
    assert_ledger_closed=base.assert_ledger_closed
    events=base.events

    def prepare_remote(self):
        self.prepare_tsa()  # authentic localhost synthetic RFC3161 CA/token
        t=EscrowProtocolTests('test_04_quorum_wrong_signer_duplicate_and_signature_tamper')
        t.setUp()
        self.addCleanup(t.temp.cleanup)
        self.addCleanup(t.stop_server)
        t.namespace='ces-project-alpha'
        t.root=self.new_root_pin
        t.closure=self.closure_pin
        t.witnesses=list(self.witness_keys)
        t.keys=esc.witness_keys(t.witnesses,t.escrow_pin)
        t.witness_pins=sorted(t.keys)
        self.args.escrow_public_sha256=t.escrow_pin
        self.args.escrow_namespace=t.namespace
        self.args.escrow_expected_previous_sha256=esc.ZERO
        self.args.escrow_minimum_previous_index=0
        subject,real_keys=ops._get_verified_subject(self.args)
        self.assertEqual(real_keys,t.keys)
        proposal=self.fix.private/'ec274-genesis-proposal.json'
        proposal_doc=esc.prepare_proposal(subject,None,output=str(proposal))
        signed=[]
        for i,(pubpin,public_path,secret_path) in enumerate(self.witnesses[:2]):
            path=self.fix.private/f'ec274-vote-{i}.json'
            doc=esc.sign_proposal(str(proposal),proposal_doc['proposal_sha256'],
                str(secret_path),pubpin,str(path))
            signed.append((str(path),doc['vote_sha256']))
        target=self.fix.private/'ec274-assembled.json'
        esc.assemble(str(proposal),proposal_doc['proposal_sha256'],signed,
            t.keys,t.namespace,t.root,t.closure,str(target))
        record=esc._parse(target.read_bytes(),esc.MAX_RECORD,'TEST_RECORD_INVALID')
        t.issue_tls()
        t.ledger=esc.EscrowLedger(str(t.journal),namespace=t.namespace,
            keys=t.keys,root=t.root,closure=t.closure,
            escrow_secret_path=str(t.secrets[3]),escrow_pin=t.escrow_pin,
            minimum_bootstrap_sequence=subject['freshness_sequence'],
            minimum_bootstrap_epoch=subject['governance_epoch'])
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(t.cert),str(t.tls_key))
        t.http=BoundedTLSServer(('127.0.0.1',0),Handler,ctx)
        t.http.ledger=t.ledger
        t.thread=threading.Thread(target=t.http.serve_forever,daemon=True)
        t.thread.start()
        self.args.escrow_host='localhost'
        self.args.escrow_port=t.http.server_port
        self.args.escrow_namespace=t.namespace
        self.args.escrow_tls_ca=str(t.ca)
        self.args.escrow_tls_ca_sha256=esc.sha(t.ca.read_bytes())
        self.args.escrow_tls_leaf_sha256=t.tls_pin
        self.args.escrow_public=str(t.publics[3])
        self.args.escrow_public_sha256=t.escrow_pin
        self.args.escrow_minimum_index=1
        self.client=esc.RemoteClient(host='localhost',port=t.http.server_port,
            namespace=t.namespace,ca_path=str(t.ca),
            ca_pin=self.args.escrow_tls_ca_sha256,leaf_pin=t.tls_pin,
            escrow_public_path=str(t.publics[3]),escrow_public_pin=t.escrow_pin,
            witness_keys_map=t.keys,root=t.root,closure=t.closure)
        received,head=self.client.advance(record)
        self.assertEqual(received,record)
        self.args.escrow_record_sha256=head
        self.t=t

    def start(self):
        with mock.patch.object(host.segmented_service,'run_serve',new=service.run_serve):
            host.SegmentedRealGitSessionTests.start(self)

    def test_01_valid_remote_escrow_allows_full_host_and_signed_session(self):
        self.prepare_remote()
        # Parent offline keys are purposely absent from server and host runtime.
        self.prev_root_secret.unlink();self.witness_secret.unlink()
        result=service.verify_gate(self.args)
        self.assertTrue(result['ec274_independent_remote_escrow_opt_in'])
        self.assertTrue(result['escrow_nonce_bound_signed_remote_reply_verified'])
        self.assertEqual(result['escrow_record_index'],1)
        self.start()
        with self.remote().begin(self.begin_request()) as client:
            replies=[]
            for _ in range(50):
                response=client.poll(80,budget.MAX_CHUNK)
                replies.append(response)
                if response.get('kind')=='exit':break
        self.assertEqual(replies[-1]['kind'],'exit')
        self.join_host()
        self.assert_ledger_closed()
        self.assertIn('service_closed',self.events())

    def test_02_remote_head_pin_mismatch_denied_before_socket_lease(self):
        self.prepare_remote()
        self.args.escrow_record_sha256='0'*64
        with self.assertRaises(Exception):
            service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')),[])
        self.assertEqual((self.next_root/'events.jsonl').read_bytes(),b'')
        # Deliberately unchanged EC273 still works without the new escrow.
        self.assertTrue(parent_service.verify_gate(self.args)[
            'trusted_external_timestamp_signature_verified'])

    def test_03_escrow_network_loss_revokes_active_session(self):
        self.prepare_remote()
        self.engine_wait=4.0
        self.start()
        client=self.remote().begin(self.begin_request())
        self.t.stop_server()
        client.conn.settimeout(8)
        messages=[]
        try:
            try:
                for _ in range(50):
                    response=client.poll(80,budget.MAX_CHUNK)
                    messages.append(response)
                    if response.get('kind')=='exit': break
            except (socket.error,session.SessionHostError): pass
        finally:
            client.conn.close()
        _,status=os.waitpid(self.child,0)
        self.child=None
        self.assertEqual(os.waitstatus_to_exitcode(status),0)
        self.assertFalse(any(msg.get('kind')=='exit' for msg in messages))
        self.assert_ledger_closed()
        self.assertIn('session_denied',self.events())


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(RemoteEscrowHostTests)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
