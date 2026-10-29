#!/usr/bin/env python3
"""EC276 strict Host tests: real Git/TSA/two TLS authorities/lease/AF_UNIX.

Inherited rootless OCI/cgroup calls are mocked. Three offline approvers and
both TLS sites run on one localhost development machine, not independent HSMs.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from ec254_session_host import broker as session
from ec263_offline_anchor_host import checkpoint as cp
from ec264_segmented_audit_host import test_host as host
from ec274_remote_escrow_host import escrow as esc
from ec275_dual_escrow_host.quorum import DualEscrow
from ec275_dual_escrow_host.test_host import DualEscrowHostTests
from ec276_dual_approval_host import approval as auth
from ec276_dual_approval_host import serve as service
import quality_run_budget as budget


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and
                     os.geteuid()!=0 and Path('/usr/bin/git').exists() and
                     Path('/usr/bin/openssl').is_file() and
                     cp.Ed25519PrivateKey is not None,
                     'nonroot Git/OpenSSL/Ed25519 required')
class ApprovedDualEscrowHostTests(DualEscrowHostTests):
    def prepare_remote(self):
        super().prepare_remote()
        self.duo=DualEscrow(self.client,self.site.client())
        keys=[]
        signer=[]
        for i in range(3):
            secret=self.t.private/f'ec276-host-approver-{i}-secret.raw'
            public=self.t.private/f'ec276-host-approver-{i}-public.raw'
            cp.generate_offline_keypair(str(secret),str(public))
            pin=esc.sha(public.read_bytes())
            keys.append((str(public),pin))
            signer.append((pin,secret))
        self.signer=signer
        self.approver_pairs=keys
        self.keys=auth.approver_keys(keys,self.duo)
        record,head=self.client.read(minimum_index=1)
        self.assertEqual(head,self.args.escrow_record_sha256)
        self.intent_file=self.t.private/'ec276-host-intent.json'
        self.approval_file=self.t.private/'ec276-host-approval.json'
        self.create_approval(record,now=int(time.time()))
        self.args.approver_public=[x for x,_ in keys]
        self.args.approver_public_sha256=[p for _,p in keys]
        self.args.approval=str(self.approval_file)
        self.args.approval_sha256=esc.sha(self.approval_file.read_bytes())

    def create_approval(self,record,*,now):
        proposal=auth.prepare_intent(self.duo,self.keys,record,
            previous_sha256=record['proposal']['previous_record_sha256'],
            not_before_unix=now-20,expires_at_unix=now+300,
            output=str(self.intent_file))
        votes=[]
        for i,(pin,secret) in enumerate(sorted(self.signer)[:2]):
            vote_path=self.t.private/f'ec276-host-vote-{i}.json'
            result=auth.sign_intent(intent_path=str(self.intent_file),
                intent_sha256=proposal['intent_sha256'],secret_path=str(secret),
                signer_sha256=pin,output=str(vote_path))
            votes.append((str(vote_path),result['approval_vote_sha256']))
        auth.assemble_approval(intent_path=str(self.intent_file),
            intent_sha256=proposal['intent_sha256'],vote_paths=votes,
            duo=self.duo,keys=self.keys,output=str(self.approval_file))

    def start(self):
        with mock.patch.object(host.segmented_service,'run_serve',new=service.run_serve):
            host.SegmentedRealGitSessionTests.start(self)

    def test_06_all_signing_private_keys_absent_from_host_and_two_authorities(self):
        self.prepare_remote()
        for _,key in self.signer:
            key.unlink()
        result=service.verify_gate(self.args)
        self.assertTrue(result['ec276_offline_two_person_approval_required'])
        self.assertEqual(result['ec276_offline_approver_signatures_verified'],2)
        self.assertTrue(result['ec275_primary_secondary_signed_live_read_verified'])
        self.assertTrue(result['ec274_independent_remote_escrow_opt_in'])
        self.assertFalse(result['ec276_physical_approver_independence_verified'])

    def test_07_signed_approval_bad_pin_or_host_head_deny_before_socket(self):
        self.prepare_remote()
        self.args.approval_sha256='e'*64
        with self.assertRaises(Exception): service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())
        self.assertEqual(list(Path(self.policy['ledger_root']).glob('lease-*')),[])
        self.args.approval_sha256=esc.sha(self.approval_file.read_bytes())
        self.args.escrow_record_sha256='f'*64
        with self.assertRaises(Exception): service.run_serve(self.args)
        self.assertFalse(Path(self.socket).exists())

    def test_08_approval_public_key_reuse_and_placement_refused(self):
        self.prepare_remote()
        original=self.args.approver_public_sha256[:]
        self.args.approver_public_sha256[0]=self.args.escrow_public_sha256
        with self.assertRaises(Exception): service.verify_gate(self.args)
        self.args.approver_public_sha256=original
        self.args.approval=self.args.provenance_gate
        with self.assertRaises(Exception): service.verify_gate(self.args)

    def test_09_offline_approval_file_deleted_during_session_revokes(self):
        self.prepare_remote()
        self.engine_wait=4.0
        self.start()
        client=self.remote().begin(self.begin_request())
        self.approval_file.unlink()
        client.conn.settimeout(8)
        messages=[]
        try:
            try:
                for _ in range(50):
                    response=client.poll(80,budget.MAX_CHUNK)
                    messages.append(response)
                    if response.get('kind')=='exit':break
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

    def test_10_monotonic_clock_anchor_denies_expired_approval_without_network(self):
        self.prepare_remote()
        # Construct a parent with the full original preflight, then deny via
        # EC276's active-time recheck without sleeping in a live OCI session.
        from ec266_source_provenance_host.serve import _open_preflight
        with _open_preflight(self.args,writable=False) as audit:
            gate=service._preflight(self.args,audit)
            policy,pin=service.lease._policy(self.args.policy)
            gate.startup(policy,pin)
            gate._clock_wall-=500  # an older monotonic reference cannot ease expiry
            gate._highest_now=gate._receipt['ec276_approval_expires_at_unix']+1
            with self.assertRaisesRegex(esc.EscrowError,
                                        'EC276_APPROVAL_NOT_YET_VALID_OR_EXPIRED'):
                gate._authorize()


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(ApprovedDualEscrowHostTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
