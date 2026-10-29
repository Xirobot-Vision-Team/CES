#!/usr/bin/env python3
"""EC277 real local two-TLS/site signature and server-side authorization tests.

All identities are synthetic and co-located. Tests prove API behavior, not
physical separation, trusted wall-clock, WORM or production PKI.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from ec263_offline_anchor_host import checkpoint as cp
from ec266_source_provenance_host import provenance as prov
from ec274_remote_escrow_host import escrow as esc
from ec274_remote_escrow_host.test_escrow import EscrowProtocolTests
from ec274_remote_escrow_host.daemon import BoundedTLSServer
from ec275_dual_escrow_host.quorum import DualEscrow
from ec275_dual_escrow_host.test_quorum import SecondaryEscrowSite
from ec276_dual_approval_host import approval as auth
from ec277_approval_enforced_escrow import daemon,operator
from ec277_approval_enforced_escrow.client import ApprovedDualEscrow,EnforcedEscrowError
from ec277_approval_enforced_escrow.policy import TrustPolicy,PolicyError,SCHEMA


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and
    os.geteuid()!=0 and cp.Ed25519PrivateKey is not None and
    Path('/usr/bin/openssl').is_file(),'nonroot OpenSSL + Ed25519 required')
class ServerEnforcedTests(unittest.TestCase):
    def setUp(self):
        fixture=EscrowProtocolTests('test_04_quorum_wrong_signer_duplicate_and_signature_tamper')
        fixture.setUp()
        self.t=fixture
        self.addCleanup(fixture.temp.cleanup)
        fixture.issue_tls()
        peer=SecondaryEscrowSite(fixture.private/'ec277-secondary',namespace=fixture.namespace,
            keys=fixture.keys,root=fixture.root,closure=fixture.closure,
            bootstrap_sequence=2,bootstrap_epoch=3)
        self.peer=peer
        port_a=free_port()
        port_b=free_port()
        while port_b==port_a: port_b=free_port()
        self.a=esc.RemoteClient(host='localhost',port=port_a,
            namespace=fixture.namespace,ca_path=str(fixture.ca),
            ca_pin=prov._digest(fixture.ca.read_bytes()),leaf_pin=fixture.tls_pin,
            escrow_public_path=str(fixture.publics[3]),escrow_public_pin=fixture.escrow_pin,
            witness_keys_map=fixture.keys,root=fixture.root,closure=fixture.closure)
        self.b=esc.RemoteClient(host='localhost',port=port_b,
            namespace=fixture.namespace,ca_path=str(peer.ca),ca_pin=peer.ca_pin,
            leaf_pin=peer.leaf_pin,escrow_public_path=str(peer.pub),
            escrow_public_pin=peer.signer_pin,witness_keys_map=fixture.keys,
            root=fixture.root,closure=fixture.closure)
        self.approvers=[]
        self.secrets=[]
        for i in range(3):
            secret=fixture.private/f'ec277-approver-secret-{i}.raw'
            public=fixture.private/f'ec277-approver-public-{i}.raw'
            cp.generate_offline_keypair(str(secret),str(public))
            pin=esc.sha(public.read_bytes())
            self.approvers.append({'path':str(public),'sha256':pin})
            self.secrets.append((pin,str(secret)))
        self.policy_doc={'schema':SCHEMA,'namespace':fixture.namespace,
            'recovered_root_public_sha256':fixture.root,
            'closure_sha256':fixture.closure,
            'primary':self.site(self.a), 'secondary':self.site(self.b),
            'witnesses':[{'path':path,'sha256':pin} for path,pin in fixture.witnesses],
            'approvers':self.approvers}
        self.policy_path=str(fixture.private/'approved-site-policy.json')
        prov._new(self.policy_path,esc.canonical(self.policy_doc))
        self.policy_pin=esc.sha(esc.canonical(self.policy_doc))
        self.policy=TrustPolicy(self.policy_path,self.policy_pin)
        self.dual=ApprovedDualEscrow(self.policy)
        self.now=int(time.time())
        self.num=0
        self.servers={}
        self.addCleanup(self.stop_servers)
        self.ledgers={}
        self.start_server('primary')
        self.start_server('secondary')
        self.first=fixture.signed(fixture.subject())
        self.first_pin=esc.sha(esc.canonical(self.first))

    def site(self,client):
        return {'host':client.host,'port':client.port,
            'tls_ca':client.ca_path,'tls_ca_sha256':client.ca_pin,
            'tls_leaf_sha256':client.leaf_pin,
            'escrow_public':client.escrow_public_path,
            'escrow_public_sha256':client.escrow_pin}

    def name(self,stem):
        self.num+=1
        return str(self.t.private/f'{stem}-{self.num}.json')

    def start_server(self,role):
        if role=='primary':
            site=self.a
            crt=self.t.cert
            tls_key=self.t.tls_key
            journal=self.t.journal
            secret=self.t.secrets[3]
        else:
            site=self.b
            crt=self.peer.cert
            tls_key=self.peer.tls_key
            journal=self.peer.dir/'secondary-journal.jsonl'
            secret=self.peer.sec
        self.policy.validate_server_files(role,port=site.port,journal=str(journal),
            escrow_secret=str(secret),tls_cert=str(crt),tls_key=str(tls_key))
        if role not in self.ledgers:
            ledger=esc.EscrowLedger(str(journal),namespace=self.t.namespace,
                keys=self.t.keys,root=self.t.root,closure=self.t.closure,
                escrow_secret_path=str(secret),escrow_pin=site.escrow_pin,
                minimum_bootstrap_sequence=2,minimum_bootstrap_epoch=3)
            self.ledgers[role]=ledger
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(crt),str(tls_key))
        http=BoundedTLSServer(('127.0.0.1',site.port),daemon.ApprovedHandler,ctx)
        http.policy=self.policy
        http.ledger=self.ledgers[role]
        http.role=role
        http.clock=daemon.AnchoredClock()
        th=threading.Thread(target=http.serve_forever,daemon=True)
        th.start()
        self.servers[role]=(http,th)

    def stop_server(self,role):
        if role in self.servers:
            http,th=self.servers.pop(role)
            http.shutdown();http.server_close();th.join(timeout=5)

    def stop_servers(self):
        for role in list(self.servers):
            self.stop_server(role)
        for ledger in self.ledgers.values():
            ledger.close()
        self.ledgers={}

    def approved(self,record=None, previous=None,*,start=None,end=None,
                 assembled=True):
        record=self.first if record is None else record
        previous=esc.ZERO if previous is None else previous
        start=self.now-30 if start is None else start
        end=self.now+1800 if end is None else end
        intent_file=self.name('intent')
        prepared=auth.prepare_intent(self.policy.dual,self.policy.approvers,record,
            previous_sha256=previous,not_before_unix=start,
            expires_at_unix=end,output=intent_file)
        votes=[]
        for pin,secret in sorted(self.secrets)[:2]:
            vote_file=self.name('vote')
            out=auth.sign_intent(intent_path=intent_file,
                intent_sha256=prepared['intent_sha256'],secret_path=secret,
                signer_sha256=pin,output=vote_file)
            votes.append((vote_file,out['approval_vote_sha256']))
        file=self.name('approval')
        if assembled:
            result=auth.assemble_approval(intent_path=intent_file,
                intent_sha256=prepared['intent_sha256'],vote_paths=votes,
                duo=self.policy.dual,keys=self.policy.approvers,output=file)
            sha=result['approval_sha256']
        else:
            data={'schema':auth.APPROVAL_SCHEMA,
                'intent':auth._read_intent(intent_file,prepared['intent_sha256']),
                'approvals':[auth._document(path,pin,auth.MAX_VOTE,'TEST_INVALID')
                             for path,pin in votes]}
            prov._new(file,esc.canonical(data))
            sha=esc.sha(esc.canonical(data))
        return auth.read_approval(file,sha),file,sha

    def test_01_unsigned_legacy_advance_disabled_on_both_sites(self):
        for client in (self.a,self.b):
            with self.subTest(site=client.port),self.assertRaises(esc.EscrowError):
                client.advance(self.first)
        self.assertEqual(self.dual.read_pair()[1],esc.ZERO)
        self.assertEqual((self.ledgers['primary'].count,
                          self.ledgers['secondary'].count),(0,0))

    def test_02_two_independent_remote_approval_admissions_and_signed_receipts(self):
        approval,file,pin=self.approved()
        pre=self.dual.inspect_advance_approved(approval)
        self.assertEqual((pre['primary'],pre['secondary']),('pending','pending'))
        out=self.dual.advance_approved(approval)
        self.assertEqual(out['record_sha256'],self.first_pin)
        self.assertEqual(self.dual.read_pair(minimum_index=1)[1],self.first_pin)
        for role in ('primary','secondary'):
            reply=out['new_server_signed_commit_receipts'][role]
            self.assertIsNotNone(reply)
            self.assertEqual(reply['site_role'],role)
            self.assertEqual(reply['approval_sha256'],pin)
            self.assertEqual(reply['signed_head']['head_sha256'],self.first_pin)
            self.assertEqual(reply['record_index'],1)
        self.assertEqual(self.dual.inspect_approved(approval)['record_index'],1)
        out2=self.dual.advance_approved(approval)
        self.assertTrue(out2['primary_was_previously_advanced'])
        self.assertTrue(out2['secondary_was_previously_advanced'])
        self.assertEqual(out2['new_server_signed_commit_receipts'],
                         {'primary':None,'secondary':None})
        self.assertFalse(out2['both_server_enforcements_attested_in_this_operation'])
        self.assertEqual(out2['reason_code'],
                         'EC277_BOTH_APPROVED_HEADS_READBACK_NO_NEW_WRITE')

    def test_03_server_denies_forged_signature_duplicate_or_different_site(self):
        approved,_,_=self.approved()
        negatives=[]
        forged=json.loads(json.dumps(approved))
        forged['approvals'][0]['signature_ed25519']='f'*128
        negatives.append(forged)
        duplicate=json.loads(json.dumps(approved))
        duplicate['approvals'][1]=duplicate['approvals'][0]
        negatives.append(duplicate)
        wrong_site=json.loads(json.dumps(approved))
        wrong_site['intent']['secondary']['port']+=1
        negatives.append(wrong_site)
        modified=json.loads(json.dumps(approved))
        modified['intent']['record']['proposal']['nonce']='0'*32
        negatives.append(modified)
        for client in (self.dual.primary,self.dual.secondary):
            for i,bad in enumerate(negatives):
                with self.subTest(site=client.role,variation=i),self.assertRaises(esc.EscrowError):
                    client.advance_approved(bad,intent=approved['intent'])
        self.assertEqual(self.dual.read_pair()[1],esc.ZERO)

    def test_04_both_sites_enforce_time_even_when_votes_valid(self):
        expired,_,_=self.approved(start=self.now-800,end=self.now-700,assembled=False)
        future,_,_=self.approved(start=self.now+800,end=self.now+900,assembled=False)
        for client in (self.dual.primary,self.dual.secondary):
            for doc in (expired,future):
                with self.subTest(site=client.role),self.assertRaises(esc.EscrowError):
                    client.advance_approved(doc,intent=doc['intent'])
        self.assertEqual(self.dual.read_pair()[1],esc.ZERO)

    def test_05_one_sided_commit_detected_and_same_authorization_recovers(self):
        doc,_,_=self.approved()
        with mock.patch.object(self.dual.secondary,'advance_approved',
            side_effect=esc.EscrowError('SIMULATED_SECONDARY_NETWORK_FAILURE')):
            with self.assertRaisesRegex(EnforcedEscrowError,'EC277_PARTIAL'):
                self.dual.advance_approved(doc)
        self.assertEqual(self.a.read(minimum_index=1)[1],self.first_pin)
        self.assertEqual(self.b.read()[1],esc.ZERO)
        state=self.dual.inspect_advance_approved(doc)
        self.assertEqual((state['primary'],state['secondary']),('advanced','pending'))
        final=self.dual.advance_approved(doc)
        self.assertTrue(final['primary_was_previously_advanced'])
        self.assertIsNone(final['new_server_signed_commit_receipts']['primary'])
        self.assertIsNotNone(final['new_server_signed_commit_receipts']['secondary'])
        self.assertEqual(self.dual.read_pair(minimum_index=1)[1],self.first_pin)

    def test_06_pinned_policy_file_tamper_or_wrong_local_cert_rejected(self):
        with self.assertRaises(PolicyError):
            self.policy.validate_server_files('secondary',port=self.a.port,
                journal=str(self.name('journal')),escrow_secret=str(self.t.secrets[3]),
                tls_cert=str(self.t.cert),tls_key=str(self.t.tls_key))
        with self.assertRaises(PolicyError):
            self.policy.validate_server_files('primary',port=self.a.port,
                journal=str(self.name('journal')),escrow_secret=str(self.t.secrets[3]),
                tls_cert=str(self.peer.cert),tls_key=str(self.t.tls_key))
        doc,_,_=self.approved()
        old=Path(self.policy_path).read_bytes()
        Path(self.policy_path).write_bytes(old[:-1]+b' ')
        with self.assertRaises(esc.EscrowError):
            self.dual.primary.advance_approved(doc,intent=doc['intent'])
        Path(self.policy_path).write_bytes(old)
        self.assertEqual(self.dual.read_pair()[1],esc.ZERO)

    def test_07_actual_cli_full_two_site_signed_cas_and_legacy_bypass(self):
        approved,file,pin=self.approved()
        args=['--policy',self.policy_path,'--policy-sha256',self.policy_pin,
              '--approval',file,'--approval-sha256',pin]
        def call(action):
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                code=operator.main([action,*args])
            return code,json.loads(out.getvalue())
        self.assertEqual(call('inspect-advance-approved')[0],2)
        code,signed=call('advance-approved')
        self.assertEqual(code,2)
        self.assertEqual(signed['record_sha256'],self.first_pin)
        self.assertEqual(call('inspect-approved')[0],2)
        old=DualEscrow(self.a,self.b)
        next_record=self.t.signed(self.t.subject(seq=3,previous=self.first),self.first)
        next_head=esc.sha(esc.canonical(next_record))
        with self.assertRaises(esc.EscrowError):
            old.advance(next_record,record_sha256=next_head,
                        previous_sha256=self.first_pin)
        self.assertEqual(self.dual.read_pair(minimum_index=1)[1],self.first_pin)

    def test_08_second_signed_successor_cas_and_no_fork_via_old_route(self):
        initial,_,_=self.approved()
        self.dual.advance_approved(initial)
        second=self.t.signed(self.t.subject(seq=3,previous=self.first),self.first)
        following,_,_=self.approved(second,self.first_pin)
        result=self.dual.advance_approved(following)
        self.assertEqual(result['record_index'],2)
        self.assertEqual(result['new_server_signed_commit_receipt_count'],2)
        self.assertEqual(self.dual.read_pair(minimum_index=2)[1],
                         esc.sha(esc.canonical(second)))
        self.assertEqual((self.ledgers['primary'].count,
                          self.ledgers['secondary'].count),(2,2))


if __name__=='__main__':
    cases=unittest.defaultTestLoader.loadTestsFromTestCase(ServerEnforcedTests)
    result=unittest.TextTestRunner(verbosity=2).run(cases)
    raise SystemExit(0 if result.wasSuccessful() else 1)
