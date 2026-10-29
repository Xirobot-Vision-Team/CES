#!/usr/bin/env python3
"""EC276: real localhost two-TLS sites, 3 new Ed25519 offline keys, 2 votes.

No real independence of personnel, WORM, external clock or distributed atomicity
is inferred from these isolated development cases.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from offline_anchor_host import checkpoint as cp
from source_provenance_host import provenance as prov
from remote_escrow_host import escrow as esc
from remote_escrow_host.test_escrow import EscrowProtocolTests
from dual_escrow_host.quorum import DualEscrow
from dual_escrow_host.test_quorum import SecondaryEscrowSite
from dual_approval_host import approval as auth
from dual_approval_host import operator as ops


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and
    os.geteuid()!=0 and cp.Ed25519PrivateKey is not None and
    Path('/usr/bin/openssl').is_file(),'nonroot OpenSSL/Ed25519 required')
class SignedApprovalTests(unittest.TestCase):
    def setUp(self):
        t=EscrowProtocolTests('test_04_quorum_wrong_signer_duplicate_and_signature_tamper')
        t.setUp()
        self.t=t
        self.addCleanup(t.temp.cleanup)
        self.addCleanup(t.stop_server)
        t.start_server()
        second=SecondaryEscrowSite(t.private/'ec276-site-b',namespace=t.namespace,
            keys=t.keys,root=t.root,closure=t.closure,
            bootstrap_sequence=2,bootstrap_epoch=3).start()
        self.addCleanup(second.stop)
        self.second=second
        self.duo=DualEscrow(t.client,second.client())
        self.signers=[]
        pairs=[]
        for i in range(3):
            secret=t.private/f'approver-{i}-private.raw'
            public=t.private/f'approver-{i}-public.raw'
            cp.generate_offline_keypair(str(secret),str(public))
            pin=esc.sha(public.read_bytes())
            self.signers.append((pin,secret,public))
            pairs.append((str(public),pin))
        self.keys=auth.approver_keys(pairs,self.duo)
        self.pairs=pairs
        self.first=t.signed(t.subject())
        self.first_pin=esc.sha(esc.canonical(self.first))
        self.now=int(time.time())
        self.seq=0

    def unique(self,name):
        self.seq+=1
        return str(self.t.private/f'{name}-{self.seq}.json')

    def approved(self,record=None,previous=esc.ZERO,start=None,end=None):
        record=self.first if record is None else record
        start=self.now-60 if start is None else start
        end=self.now+3600 if end is None else end
        intent_file=self.unique('intent')
        res=auth.prepare_intent(self.duo,self.keys,record,
            previous_sha256=previous,not_before_unix=start,
            expires_at_unix=end,output=intent_file)
        votes=[]
        for pin,secret,_ in sorted(self.signers)[:2]:
            vote_file=self.unique('vote')
            vote=auth.sign_intent(intent_path=intent_file,
                intent_sha256=res['intent_sha256'],secret_path=str(secret),
                signer_sha256=pin,output=vote_file)
            votes.append((vote_file,vote['approval_vote_sha256']))
        approval_file=self.unique('approval')
        result=auth.assemble_approval(intent_path=intent_file,
            intent_sha256=res['intent_sha256'],vote_paths=votes,
            duo=self.duo,keys=self.keys,output=approval_file)
        doc=auth.read_approval(approval_file,result['approval_sha256'])
        return approval_file,result['approval_sha256'],doc,res

    def test_01_two_distinct_offline_votes_pin_record_and_both_sites(self):
        file,pin,doc,res=self.approved()
        intent=auth.verified_file(file,pin,self.duo,self.keys,now=self.now)
        self.assertEqual(intent['record_sha256'],self.first_pin)
        self.assertEqual(intent['record'],self.first)
        self.assertEqual(set(x['public_sha256'] for x in doc['approvals']),
                         set(sorted(self.keys)[:2]))
        self.assertEqual(intent['primary'],auth.site_identity(self.duo.primary))
        self.assertEqual(intent['secondary'],auth.site_identity(self.duo.secondary))
        self.assertEqual(self.duo.advance(self.first,record_sha256=self.first_pin,
                                         previous_sha256=esc.ZERO)['record_index'],1)
        self.assertEqual(self.duo.read_pair(minimum_index=1)[0],intent['record'])

    def test_02_duplicate_missing_reordered_and_invalid_approvers_refused(self):
        _,_,doc,_=self.approved()
        valid=list(doc['approvals'])
        for votes in ([valid[0]], [valid[0],valid[0]],list(reversed(valid)),
                      [{**valid[0],'signature_ed25519':'f'*128},valid[1]]):
            with self.subTest(votes=votes),self.assertRaises(esc.EscrowError):
                auth.verify_approval({**doc,'approvals':votes},self.duo,self.keys,now=self.now)
        with self.assertRaises(esc.EscrowError):
            auth.approver_keys([(str(self.t.publics[0]),self.t.witnesses[0][1]),
                self.pairs[1],self.pairs[2]],self.duo)

    def test_03_site_pins_predecessor_record_and_witness_tamper_refused(self):
        _,_,doc,_=self.approved()
        for change in (
            {'primary':{**doc['intent']['primary'],'port':1}},
            {'secondary':{**doc['intent']['secondary'],'tls_leaf_sha256':'f'*64}},
            {'record_sha256':'a'*64},
            {'previous_record_sha256':'b'*64},
            {'record_index':15},
            {'witness_public_sha256':[]},
        ):
            modified={**doc,'intent':{**doc['intent'],**change}}
            with self.subTest(change=change),self.assertRaises(esc.EscrowError):
                auth.verify_approval(modified,self.duo,self.keys,now=self.now)
        changed=dict(self.first)
        changed['approvals']=[dict(v) for v in self.first['approvals']]
        changed['approvals'][0]['signature_ed25519']='0'*128
        with self.assertRaises(esc.EscrowError):
            auth.prepare_intent(self.duo,self.keys,changed,previous_sha256=esc.ZERO,
                not_before_unix=self.now-1,expires_at_unix=self.now+1,
                output=self.unique('unwitnessed'))

    def test_04_expiration_future_not_before_and_oversized_duration_refused(self):
        file,pin,doc,_=self.approved(start=self.now-1,end=self.now+1)
        auth.verified_file(file,pin,self.duo,self.keys,now=self.now)
        with self.assertRaisesRegex(esc.EscrowError,'EC276_APPROVAL_NOT_YET_VALID_OR_EXPIRED'):
            auth.verified_file(file,pin,self.duo,self.keys,now=self.now+2)
        with self.assertRaisesRegex(esc.EscrowError,'EC276_APPROVAL_NOT_YET_VALID_OR_EXPIRED'):
            auth.verified_file(file,pin,self.duo,self.keys,now=self.now-2)
        with self.assertRaises(esc.EscrowError):
            auth.prepare_intent(self.duo,self.keys,self.first,previous_sha256=esc.ZERO,
                not_before_unix=self.now,expires_at_unix=self.now+auth.MAX_LIFETIME+1,
                output=self.unique('too-long'))

    def test_05_partial_commit_same_exact_two_person_approved_record_resumed(self):
        file,pin,doc,_=self.approved()
        intent=auth.verified_file(file,pin,self.duo,self.keys,now=self.now)
        self.t.client.advance(self.first)
        state=self.duo.inspect_advance(intent['record'],
            record_sha256=intent['record_sha256'],
            previous_sha256=intent['previous_record_sha256'])
        self.assertEqual((state['primary'],state['secondary']),('advanced','pending'))
        self.assertEqual(self.duo.advance(intent['record'],
            record_sha256=intent['record_sha256'],
            previous_sha256=intent['previous_record_sha256'])['record_index'],1)
        self.assertEqual(self.duo.read_pair(minimum_index=1)[1],self.first_pin)
        alternate=self.t.signed(self.t.subject())
        with self.assertRaises(esc.EscrowError):
            self.duo.advance(alternate,record_sha256=esc.sha(esc.canonical(alternate)),
                             previous_sha256=esc.ZERO)

    def test_06_cli_offline_signing_and_live_approved_cas(self):
        record_path=self.unique('full-record')
        prov._new(record_path,esc.canonical(self.first))
        args=[]
        for client,prefix in ((self.duo.primary,'escrow'),(self.duo.secondary,'secondary-escrow')):
            args.extend(['--'+prefix+'-host',client.host,
                '--'+prefix+'-port',str(client.port),
                '--'+prefix+'-tls-ca',client.ca_path,
                '--'+prefix+'-tls-ca-sha256',client.ca_pin,
                '--'+prefix+'-tls-leaf-sha256',client.leaf_pin,
                '--'+prefix+'-public',client.escrow_public_path,
                '--'+prefix+'-public-sha256',client.escrow_pin])
        args.extend(['--escrow-namespace',self.duo.namespace,
                     '--root-sha256',self.duo.root,'--closure-sha256',self.duo.closure])
        for path,pin in self.t.witnesses:
            args+=['--freshness-witness-public',path,
                   '--freshness-witness-public-sha256',pin]
        for path,pin in self.pairs:
            args+=['--approver-public',path,'--approver-public-sha256',pin]
        def cli(action,opts,base=None):
            stdout=io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code=ops.main([action,*(args if base is None else base),*opts])
            return code,json.loads(stdout.getvalue())
        intent_path=self.unique('cli-intent')
        code,proposed=cli('prepare-intent',['--record',record_path,
            '--record-sha256',self.first_pin,
            '--expected-previous-sha256',esc.ZERO,
            '--not-before-unix',str(self.now-20),
            '--expires-at-unix',str(self.now+1800),'--output',intent_path])
        self.assertEqual(code,2)
        vote_paths=[]
        for pin,secret,_ in sorted(self.signers)[:2]:
            vote_file=self.unique('cli-vote')
            code,signed=cli('sign-intent',['--intent',intent_path,
                '--intent-sha256',proposed['intent_sha256'],
                '--approver-secret',str(secret),'--approver-public-sha256',pin,
                '--output',vote_file],base=[])
            self.assertEqual(code,2)
            vote_paths.extend(['--approval-vote',vote_file,
                               '--approval-vote-sha256',signed['approval_vote_sha256']])
        signed_path=self.unique('cli-approval')
        code,result=cli('assemble-approval',['--intent',intent_path,
            '--intent-sha256',proposed['intent_sha256'],'--output',signed_path,*vote_paths])
        self.assertEqual(code,2)
        approved=['--approval',signed_path,'--approval-sha256',result['approval_sha256']]
        code,rehearsal=cli('inspect-advance-approved',approved)
        self.assertEqual((code,rehearsal['primary'],rehearsal['secondary']),
                         (2,'pending','pending'))
        code,committed=cli('advance-approved',approved)
        self.assertEqual(code,2)
        self.assertTrue(committed['ec276_two_offline_approvals_verified'])
        code,checked=cli('inspect-approved',approved)
        self.assertEqual(code,2)
        self.assertTrue(checked['two_fresh_remote_signatures_verified'])
        code,denied=cli('inspect-approved',['--approval',signed_path,
            '--approval-sha256','f'*64])
        self.assertEqual((code,denied['status']),(5,'unavailable'))

    def test_07_other_head_even_if_signed_by_witnesses_is_not_operator_approved(self):
        file,pin,doc,_=self.approved()
        other=self.t.signed(self.t.subject())
        other_pin=esc.sha(esc.canonical(other))
        self.t.client.advance(other)
        self.second.client().advance(other)
        auth.verified_file(file,pin,self.duo,self.keys,now=self.now)
        with self.assertRaises(esc.EscrowError):
            self.duo.inspect_advance(doc['intent']['record'],
                record_sha256=doc['intent']['record_sha256'],
                previous_sha256=doc['intent']['previous_record_sha256'])
        self.assertNotEqual(other_pin,self.first_pin)


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(SignedApprovalTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
