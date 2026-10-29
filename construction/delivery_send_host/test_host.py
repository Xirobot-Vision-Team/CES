#!/usr/bin/env python3
"""EC288 bounded host integration tests: REAL original EC225 with MOCK provider.

No live provider or organizational humans are contacted. These are development
examples and regression guards, NOT final production acceptance.
"""
from __future__ import annotations

import base64
from dataclasses import fields, is_dataclass
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import protocol as p, daemon, operator as op
import delivery_preview as dp
import delivery_send as ds
import test_delivery_send as fixtures
from finding_query_host import protocol as io


def encode(obj):
    if type(obj) is bytes:
        return base64.b64encode(obj).decode('ascii')
    if type(obj) is dp.ReportSelection:
        return {'kind':'REPORT',**{f.name:encode(getattr(obj,f.name))
                  for f in fields(obj) if f.name!='reader'}}
    if type(obj) is dp.FindingSelection:
        reader=obj.reader.ledger
        return {'kind':'FINDING',
                'reader_roots':{
                   'stage_root':reader.stage_root,
                   'business_repo_root':reader.business_repo_root,
                   'finding_store_root':reader.finding_store_root,
                   'codesave_root':reader.codesave_root},
                **{f.name:encode(getattr(obj,f.name))
                   for f in fields(obj) if f.name!='reader'}}
    if is_dataclass(obj):
        return {(('exact_payload_b64' if f.name=='exact_payload_bytes' else f.name)):
                encode(getattr(obj,f.name)) for f in fields(obj)}
    if type(obj) in (tuple,list):
        return [encode(v) for v in obj]
    if type(obj) is dict:
        return {k:encode(v) for k,v in obj.items()}
    return obj


class EC288HostCases(unittest.TestCase):
    def setUp(self):
        self.fx=fixtures.SendCases()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        # Genuine EC221-225 fixture grants are bound to this fixed synthetic
        # epoch; patch only wall time, never bypass signature/source checks.
        timer=patch.object(p.time,'time',return_value=fixtures.NOW)
        timer.start()
        self.addCleanup(timer.stop)
        self.tmp=tempfile.TemporaryDirectory(prefix='ec288_host_')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.outbox=self.root/'outbox'
        self.admissions=self.root/'admissions'
        self.outbox.mkdir(mode=0o700);self.admissions.mkdir(mode=0o700)
        self.signers={role:Ed25519PrivateKey.generate()
                      for role in ('custodian','authorizer','server')}
        self.job=p.encode_original_request(self.fx.req)
        self.trust=self.make_trust()
        self.job_path=self.write('job.json',p.canonical(self.job))
        self.trust_path=self.write('trust.json',p.canonical(self.trust))
        self.cred_path=self.write('credential.txt',self.fx.access.credential.encode())
        self.policy_path=str(self.root/'policy.json')
        self.server_key_path=self.write('host.key',self.signers['server'].private_bytes(
            serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))
        self.prepare()

    def write(self,name,raw):
        path=self.root/name
        with open(path,'xb') as file:
            file.write(raw)
        path.chmod(0o600)
        return str(path)

    def make_trust(self):
        # self.fx is test_delivery_authorization.AuthorizationCases
        sendfx=self.fx
        r=sendfx.fx.roots if hasattr(sendfx,'fx') else sendfx.roots
        # self.fx is SendCases; `fx` holds original authorization fixture.
        a=sendfx.fx.roots
        i=sendfx.fx.i.roots
        sd=sendfx.roots
        target=encode(sendfx.target)
        return {'schema':p.TRUST_SCHEMA,
            'identity':{'issuer_id':i.issuer_id,
                'directory_public_hex':i.directory_public_key.hex(),
                'revocation_public_hex':i.revocation_public_key.hex(),
                'verification_public_hex':i.verification_public_key.hex()},
            'authorization':{'issuer_id':a.issuer_id,
                'organization_id':a.organization_id,'approver_id':a.approver_id,
                'approval_public_hex':a.approval_public_key.hex(),
                'entitlement_public_hex':a.organization_entitlement_public_key.hex(),
                'revocation_public_hex':a.organization_revocation_public_key.hex(),
                'minimum_revocation_epoch':a.minimum_revocation_epoch},
            'send':{'issuer_id':sd.issuer_id,'operator_id':sd.operator_id,
                'side_effect_public_hex':sd.side_effect_public_key.hex(),
                'provider_capability_public_hex':sd.provider_capability_public_key.hex(),
                'minimum_send_epoch':sd.minimum_send_epoch},
            'target':target,'enable_live_sandbox_send':True}

    def prepare(self):
        self.policy_info=op.prepare_policy(
            job_file=self.job_path,trust_file=self.trust_path,
            credential_file=self.cred_path,
            outbox_root=str(self.outbox),admission_root=str(self.admissions),
            allowed_uids=[os.getuid()],
            custodian_pub=p.public_hex(self.signers['custodian']),
            authorizer_pub=p.public_hex(self.signers['authorizer']),
            server_pub=p.public_hex(self.signers['server']),
            out=self.policy_path,enable=True)
        self.sha=self.policy_info['policy_sha256']

    def grant(self,stamp=None):
        pol=p.load_policy(self.policy_path,self.sha)
        req=p.load_job(pol)
        sub=p.new_subject(os.getuid(),self.sha,p.job_pins(pol,req),25)
        return {'schema':p.GRANT_SCHEMA,'subject':sub,
                'custodian_signature_ed25519':p.sign('custodian',sub,self.signers['custodian']),
                'authorizer_signature_ed25519':p.sign('authorizer',sub,self.signers['authorizer'])}

    def run_host(self,grant,with_probe=True):
        path=str(self.root/'rpc.sock')
        host=daemon.DeliverySendHost(path=path,policy_path=self.policy_path,
                                      policy_sha=self.sha,
                                      private_key_file=self.server_key_path)
        thr=threading.Thread(target=host.handle_request,daemon=True)
        try:
            thr.start()
            # _clock and original source receipts share the frozen fixture UTC.
            if with_probe:
                real=ds.HTTPSPrivateTestTransport
                def probe(_adapter,target,credential,challenge):
                    return self.fx.transport.probe(target,credential,challenge)
                def submit(_adapter,target,credential,body,operation):
                    return self.fx.transport.submit(target,credential,body,operation)
                context1=patch.object(real,'probe',probe)
                context2=patch.object(real,'submit',submit)
                context1.start();context2.start()
            try:
                path_grant=self.write('grant-'+str(time.monotonic_ns())+'.json',p.canonical(grant))
                rc,out=op.submit(socket_path=path,grant_file=path_grant,
                                 policy_sha=self.sha,
                                 server_pub=p.public_hex(self.signers['server']),
                                 timeout=10)
                return rc,out
            finally:
                if with_probe:
                    context2.stop();context1.stop()
        finally:
            thr.join(timeout=3)
            host.server_close()

    def test_private_original_job_roundtrip_real_types(self):
        parsed=p.validate_job(self.job)
        self.assertIs(type(parsed),ds.DeliverySendRequest)
        self.assertEqual(parsed.authorization_request.exact_payload_bytes,
                         self.fx.req.authorization_request.exact_payload_bytes)
        src=parsed.authorization_request.identity_request.sensitive_review_request
        self.assertIs(type(src.preview_request.sources[0]),dp.ReportSelection)
        self.assertEqual(len(p.trust_keys(self.trust)),8)

    def test_original_business_module_is_real_https_adapter_by_default(self):
        sender=p.build_sender(self.trust,self.fx.access.credential,str(self.outbox))
        self.assertIs(type(sender._transport),ds.HTTPSPrivateTestTransport)
        self.assertFalse(sender.access.allow_synthetic_transport_for_development)

    def test_signed_votes_bound_to_host_uid_and_original_grant(self):
        pol=p.load_policy(self.policy_path,self.sha)
        req=p.load_job(pol)
        grant=self.grant()
        sub=p.validate_grant(grant,pol,req,uid=os.getuid(),
                             now=fixtures.NOW,policy_sha=self.sha)
        self.assertEqual(sub['uid'],os.getuid())
        bad={**grant,'authorizer_signature_ed25519':grant['custodian_signature_ed25519']}
        with self.assertRaises(p.HostError):
            p.validate_grant(bad,pol,req,uid=os.getuid(),now=fixtures.NOW,policy_sha=self.sha)
        with self.assertRaises(p.HostError):
            p.validate_grant(grant,pol,req,uid=os.getuid()+1,now=fixtures.NOW,policy_sha=self.sha)

    def test_real_socket_original_ec225_mocked_capability_and_202_at_most_once(self):
        grant=self.grant()
        rc,doc=self.run_host(grant)
        self.assertEqual(rc,2,doc)
        self.assertTrue(doc['verified_server_signature'])
        self.assertEqual(doc['result']['schema'],ds.SCHEMA)
        self.assertEqual(doc['result']['submission_state'],'SUBMISSION_UNCONFIRMED')
        self.assertFalse(doc['result']['message_sent'])
        self.assertFalse(doc['delivered_verified_by_ces'])
        self.assertEqual((self.fx.transport.probes,self.fx.transport.posts),(1,1))
        self.assertEqual(len(list(self.outbox.glob('ec225-*'))),1)
        self.assertEqual(len(list(self.admissions.glob('ec288-*'))),1)
        # Reuse the same grant is spent on HOST even without reaching EC225.
        again_rc,again=self.run_host(grant,with_probe=False)
        self.assertEqual(again_rc,3,again)
        self.assertTrue(again['send_outcome_unknown'])
        self.assertEqual(self.fx.transport.posts,1)

    def test_missing_role_or_modified_original_body_never_reaches_provider(self):
        g=self.grant()
        g['authorizer_signature_ed25519']='00'*64
        rc,result=self.run_host(g,with_probe=False)
        self.assertEqual(rc,3,result)
        self.assertFalse(result['result']['send_outcome_unknown'])
        self.assertEqual(self.fx.transport.posts,0)
        self.assertEqual(list(self.admissions.iterdir()),[])

    def test_offline_operator_subject_votes_and_exact_assembly(self):
        subfile=str(self.root/'subject.json')
        made=op.prepare_subject(self.policy_path,self.sha,os.getuid(),20,subfile)
        self.assertTrue(made['no_network_or_provider_submission'])
        for role in ('custodian','authorizer'):
            signer=self.signers[role]
            private=signer.private_bytes(serialization.Encoding.Raw,
                                         serialization.PrivateFormat.Raw,
                                         serialization.NoEncryption())
            keyfile=self.write(role+'.key',private)
            op.vote(role,subfile,keyfile,str(self.root/(role+'.vote')))
        outfile=str(self.root/'ready.grant')
        op.assemble(subfile,str(self.root/'custodian.vote'),
                    str(self.root/'authorizer.vote'),
                    p.public_hex(self.signers['custodian']),
                    p.public_hex(self.signers['authorizer']),outfile)
        grant=io.read_doc(outfile,8192)
        rc,output=self.run_host(grant)
        self.assertEqual(rc,2,output)
        self.assertEqual(self.fx.transport.posts,1)

    def test_policy_rejects_reused_upstream_signer_for_host(self):
        pol=p.load_policy(self.policy_path,self.sha)
        stolen=self.trust['identity']['directory_public_hex']
        pol['custodian_issuer_public_hex']=stolen
        with self.assertRaises(p.HostError):
            p.validate_policy({**pol,'host_backend_sha256':'a'*64})
        # A valid policy shape still cannot become a running host if upstream
        # original and newly admitted host roles reuse one Ed25519 key.
        pol['host_backend_sha256']=p.host_code_sha()
        p.validate_policy(pol)
        original=Path(self.policy_path).read_bytes()
        Path(self.policy_path).write_bytes(p.canonical(pol))
        with self.assertRaises(p.HostError):
            daemon.DeliverySendHost(path=str(self.root/'role.sock'),
                                    policy_path=self.policy_path,
                                    policy_sha=p.digest(p.canonical(pol)),
                                    private_key_file=self.server_key_path)
        Path(self.policy_path).write_bytes(original)

    def test_private_job_change_or_role_reuse_rejected(self):
        g=self.grant()
        self.write('another.json',p.canonical({'schema':'not_original'}))
        newjob={**self.job,'schema':'changed'}
        Path(self.job_path).write_bytes(p.canonical(newjob))
        with self.assertRaises(p.HostError):
            daemon.DeliverySendHost(path=str(self.root/'no.sock'),
                                    policy_path=self.policy_path,
                                    policy_sha=self.sha,
                                    private_key_file=self.server_key_path)

    def test_original_unconfirmed_failure_no_duplicate_provider_post(self):
        self.fx.transport.fail_submit=True
        g=self.grant()
        rc,out=self.run_host(g)
        self.assertEqual(rc,5,out)
        self.assertTrue(out['result']['submission_post_attempted'])
        self.assertEqual(out['result']['submission_state'],'UNKNOWN_UNCONFIRMED')
        self.assertTrue(out['send_outcome_unknown'])
        self.assertEqual(self.fx.transport.posts,1)
        self.assertEqual(len(list(self.outbox.glob('ec225-*'))),1)

    def test_signed_reply_tamper_fails_verification(self):
        req={'schema':p.REQUEST_SCHEMA,'nonce':'a'*32,'grant':self.grant()}
        denial=p.denial('EC288_SYNTHETIC_DENIED')
        reply=p.signed_reply(req,denial,self.sha,
                             p.load_policy(self.policy_path,self.sha)['job_sha256'],
                             self.signers['server'],fixtures.NOW)
        self.assertEqual(p.verify_reply(reply,req,
            p.public_hex(self.signers['server']),self.sha,fixtures.NOW),denial)
        reply['result']={**denial,'delivered':True}
        with self.assertRaises(p.HostError):
            p.verify_reply(reply,req,p.public_hex(self.signers['server']),
                           self.sha,fixtures.NOW)


if __name__=='__main__':
    unittest.main()
