#!/usr/bin/env python3
"""EC275 strict host: real Git/TSA/two TLS escrows/socket/Lease/signed audit.

Remote sites are co-located localhost simulations; OCI/cgroup remain inherited
mocks. This is a focused development test, not physical disaster-recovery proof.
"""
from __future__ import annotations

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
from remote_escrow_host import escrow as esc
from remote_escrow_host import serve as parent_service
from remote_escrow_host.test_host import RemoteEscrowHostTests
from dual_escrow_host import serve as service
from dual_escrow_host.test_quorum import SecondaryEscrowSite
import quality_run_budget as budget


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and
                     os.geteuid()!=0 and Path('/usr/bin/git').exists() and
                     Path('/usr/bin/openssl').is_file() and
                     cp.Ed25519PrivateKey is not None,
                     'nonroot real Git/OpenSSL/Ed25519 required')
class DualEscrowHostTests(RemoteEscrowHostTests):
    def prepare_remote(self):
        super().prepare_remote()  # full signed EC272/273 + one live EC274
        record,head=self.client.read(minimum_index=1)
        subject=record['proposal']
        second=SecondaryEscrowSite(self.t.private/'ec275-secondary',
            namespace=self.t.namespace,keys=self.t.keys,
            root=self.t.root,closure=self.t.closure,
            bootstrap_sequence=subject['freshness_sequence'],
            bootstrap_epoch=subject['governance_epoch']).start()
        self.addCleanup(second.stop)
        self.site=second
        _,mirror_head=second.client().advance(record)
        self.assertEqual(mirror_head,head)
        self.args.secondary_escrow_host='localhost'
        self.args.secondary_escrow_port=second.http.server_port
        self.args.secondary_escrow_tls_ca=str(second.ca)
        self.args.secondary_escrow_tls_ca_sha256=second.ca_pin
        self.args.secondary_escrow_tls_leaf_sha256=second.leaf_pin
        self.args.secondary_escrow_public=str(second.pub)
        self.args.secondary_escrow_public_sha256=second.signer_pin
        self.args.secondary_escrow_minimum_index=1

    def start(self):
        with mock.patch.object(host.segmented_service,'run_serve',new=service.run_serve):
            host.SegmentedRealGitSessionTests.start(self)

    def test_04_secondary_bad_pin_and_identity_refused_before_socket(self):
        self.prepare_remote()
        initial=self.args.secondary_escrow_tls_leaf_sha256
        self.args.secondary_escrow_tls_leaf_sha256='f'*64
        with self.assertRaises(Exception): service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')),[])
        self.args.secondary_escrow_tls_leaf_sha256=initial
        self.args.secondary_escrow_public_sha256=self.args.escrow_public_sha256
        with self.assertRaises(Exception): service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertTrue(parent_service.verify_gate(self.args)[
            'ec274_independent_remote_escrow_opt_in'])

    def test_05_secondary_network_loss_revokes_in_flight_session(self):
        self.prepare_remote()
        self.engine_wait=4.0
        self.start()
        client=self.remote().begin(self.begin_request())
        self.site.stop()
        client.conn.settimeout(8)
        messages=[]
        try:
            try:
                for _ in range(50):
                    response=client.poll(80,budget.MAX_CHUNK)
                    messages.append(response)
                    if response.get('kind')=='exit': break
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


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(DualEscrowHostTests)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
