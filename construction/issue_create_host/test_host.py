#!/usr/bin/env python3
"""EC287 local synthetic source/identity/authorization tests; NO live remote POST.

Original EC217/218 are actually invoked. The provider is explicitly mocked at
its original transport constructor, so a claimed 201 in these tests MUST NOT
be reported as live provider creation or production acceptance.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime,timedelta,timezone
import copy
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from finding_query_host import protocol as io
from issue_create_host import protocol as p, daemon as d, operator as o
import issue_create_grant as cg
import issue_create_write as cw
from test_issue_create_write import FakeCreateTransport,TEST_TOKEN
import test_issue_match as tm
import test_issue_eligibility as te
import test_issue_plan as tp
import test_issue_create_grant as tg


def save(path: Path, value: dict) -> str:
    raw=p.canonical(value)+b'\n'
    path.write_bytes(raw)
    path.chmod(0o600)
    return p.sha(raw)


def secret_key(path: Path) -> Ed25519PrivateKey:
    key=Ed25519PrivateKey.generate()
    raw=key.private_bytes(serialization.Encoding.Raw,
                          serialization.PrivateFormat.Raw,
                          serialization.NoEncryption())
    path.write_bytes(raw)
    path.chmod(0o600)
    return key


class EC287Host(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ec287_')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        os.chmod(self.root,0o700)
        self.now=datetime.now(timezone.utc).replace(microsecond=0)
        prior={}
        for module,name,value in ((tm,'NOW',self.now-timedelta(seconds=30)),
                (te,'NOW',self.now-timedelta(seconds=30)),
                (te,'CURRENT',self.now),(te,'CLOCK',lambda:self.now),
                (tp,'CURRENT',self.now),(tp,'CLOCK',lambda:self.now),
                (tg,'CURRENT',self.now),(tg,'CLOCK',lambda:self.now)):
            prior[(module,name)]=getattr(module,name)
            setattr(module,name,value)
        self.addCleanup(lambda:[setattr(m,n,v) for (m,n),v in prior.items()])
        self.kw=tg.fixture()
        self.approval=tg.sign(self.kw)
        self.intent=self.kw['intent']
        self.job={'schema':p.JOB_SCHEMA,
                  'evidence':asdict(self.kw['evidence']),
                  'intent':asdict(self.intent),
                  'content':asdict(self.kw['content']),
                  'approval':asdict(self.approval)}
        self.jobfile=self.root/'job.json'
        self.trustfile=self.root/'trust.json'
        self.accessfile=self.root/'access.json'
        self.tokenfile=self.root/'provider.token'
        self.reservation=self.root/'ec217.db'
        self.attempt=self.root/'ec218.db'
        self.admission=self.root/'ec287.db'
        self.policyfile=self.root/'policy.json'
        self.serverkeyfile=self.root/'host.key'
        self.sock=str(self.root/'host.sock')
        self.keys={role:secret_key(self.root/(role+'.key'))
                   for role in ('custodian','authorizer','server')}
        self.pub={role:p.public_hex(key) for role,key in self.keys.items()}
        trust={}
        for name,authority in self.kw['trusted_issuers'].items():
            entry=asdict(authority)
            entry['public_key_hex']=entry.pop('public_key').hex()
            trust[name]=entry
        self.trust={'schema':p.TRUST_SCHEMA,
            'eligibility_review_keys_hex':{
                k:v.hex() for k,v in self.kw['trusted_eligibility_review_keys'].items()},
            'issuers':trust}
        self.access={'schema':p.ACCESS_SCHEMA,**asdict(cw.HostCreateAccess(
                self.intent.provider,self.intent.api_host,
                self.intent.account_ref,self.intent.repository,
                self.intent.expected_repository_id,self.intent.visibility,
                self.intent.policy_revision_sha256,self.intent.audience,
                te.stamp(self.now+timedelta(seconds=100)),True,True,True))}
        save(self.jobfile,self.job)
        save(self.trustfile,self.trust)
        save(self.accessfile,self.access)
        self.tokenfile.write_text(TEST_TOKEN+'\n',encoding='ascii')
        self.tokenfile.chmod(0o600)
        self.keys['server'].private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        # owner policy is generated independently of client-supplied task.
        self.policy_details=o.prepare_policy(
            job_file=str(self.jobfile),trust_file=str(self.trustfile),
            access_file=str(self.accessfile),token_file=str(self.tokenfile),
            reservation_db=str(self.reservation),attempt_db=str(self.attempt),
            host_grant_db=str(self.admission),allowed_uids=[os.getuid()],
            custodian_pub=self.pub['custodian'],
            authorizer_pub=self.pub['authorizer'],server_pub=self.pub['server'],
            out=str(self.policyfile),explicit_enable=True)
        self.policy_sha=self.policy_details['policy_sha256']
        self.serverkeyfile.write_bytes(self.keys['server'].private_bytes(
            serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))
        self.serverkeyfile.chmod(0o600)
        self.fake=FakeCreateTransport(self.kw)
        self.host=None

    def tearDown(self):
        if self.host:
            self.host.shutdown()
            self.host.server_close()
            self.thread.join(timeout=5)

    def reserve(self):
        result=cg.reserve_issue_create_grant(
            self.kw['evidence'],self.intent,self.kw['content'],self.approval,
            trusted_eligibility_review_keys=self.kw['trusted_eligibility_review_keys'],
            trusted_issuers=self.kw['trusted_issuers'],
            ledger=cg.SQLiteOneUseLedger(self.reservation,self.intent.audience),
            clock=lambda:self.now)
        self.assertEqual(result['grant_state'],'RESERVED_ONE_ATTEMPT',result)
        return result

    def signed_grant(self,*,uid=None,ttl=30,signer_override=None):
        policy=p.load_policy(str(self.policyfile),self.policy_sha)
        job=p.load_job(policy)
        subject=p.new_subject(os.getuid() if uid is None else uid,
            self.policy_sha,p.job_pins(policy,job),ttl)
        grant={'schema':p.GRANT_SCHEMA,'subject':subject}
        for role in ('custodian','authorizer'):
            signer=signer_override if role=='authorizer' and signer_override else self.keys[role]
            grant[f'{role}_signature_ed25519']=p.sign(role,subject,signer)
        return grant

    def write_grant(self,grant):
        path=self.root/(secrets.token_hex(8)+'.grant')
        save(path,grant)
        return str(path)

    def start_host(self):
        self.host=d.IssueCreateHostServer(path=self.sock,
            policy_path=str(self.policyfile),policy_sha=self.policy_sha,
            private_key_file=str(self.serverkeyfile))
        self.thread=threading.Thread(target=self.host.serve_forever,
                                     kwargs={'poll_interval':.03},daemon=True)
        self.thread.start()

    def create(self,grant):
        file=self.write_grant(grant)
        return o.create(socket_path=self.sock,grant_file=file,
                policy_sha=self.policy_sha,server_pub=self.pub['server'])

    def test_01_private_job_roundtrip_includes_all_original_ec215_to_ec218_types(self):
        reconstructed=p.load_job(p.load_policy(str(self.policyfile),self.policy_sha))
        self.assertEqual(reconstructed['evidence'],self.kw['evidence'])
        self.assertEqual(reconstructed['intent'],self.intent)
        self.assertEqual(reconstructed['content'],self.kw['content'])
        self.assertEqual(reconstructed['approval'],self.approval)
        self.assertNotIn(TEST_TOKEN,str(reconstructed))

    def test_02_original_ec217_reserved_and_ec218_mocked_post_exactly_once(self):
        self.reserve()
        grant=self.signed_grant()
        self.start_host()
        with mock.patch.object(cw,'StrictHTTPSIssueCreateTransport',
                               side_effect=lambda:self.fake):
            rc,output=self.create(grant)
        self.assertEqual(rc,2,output)
        self.assertTrue(output['verified_server_signature'])
        self.assertEqual(output['result']['create_state'],'PROVIDER_REPORTED_CREATED')
        self.assertEqual(self.fake.post_count,1)
        self.assertEqual(self.fake.get_count,1)
        self.assertEqual(self.fake.payload['title'],self.kw['content'].title)
        self.assertEqual(self.fake.payload['body'],self.kw['content'].body)
        self.assertTrue(self.attempt.exists())
        self.assertTrue(self.admission.exists())
        exposed=json.dumps(output)
        for secret in (self.kw['content'].title,self.kw['content'].body,
                       TEST_TOKEN,self.intent.repository):
            self.assertNotIn(secret,exposed)
        # This is a MOCKED 201. It is NOT a real provider issue, regardless
        # of the original production result's 'provider_reported_created'.

    def test_03_same_signed_host_grant_is_single_use_even_after_mocked_create(self):
        self.reserve();grant=self.signed_grant();self.start_host()
        with mock.patch.object(cw,'StrictHTTPSIssueCreateTransport',
                               side_effect=lambda:self.fake):
            first=self.create(grant)
            second=self.create(grant)
        self.assertEqual(first[0],2)
        self.assertEqual(second[0],3)
        self.assertIn('ALREADY_SPENT',second[1]['result']['reason_code'])
        self.assertTrue(second[1]['remote_effect_outcome_unknown'])
        self.assertEqual(self.fake.post_count,1)

    def test_04_distinct_host_vote_cannot_repeat_same_original_ec218_operation(self):
        self.reserve();grant1=self.signed_grant();grant2=self.signed_grant()
        self.start_host()
        with mock.patch.object(cw,'StrictHTTPSIssueCreateTransport',
                               side_effect=lambda:self.fake):
            first=self.create(grant1)
            second=self.create(grant2)
        self.assertEqual(first[0],2)
        self.assertEqual(second[1]['result']['create_state'],'BLOCKED')
        self.assertTrue(second[1]['result']['same_request_replay_blocked'])
        self.assertTrue(second[1]['remote_effect_outcome_unknown'])
        self.assertEqual(self.fake.post_count,1)

    def test_05_missing_original_ec217_durable_reservation_denies_before_remote(self):
        grant=self.signed_grant();self.start_host()
        with mock.patch.object(cw,'StrictHTTPSIssueCreateTransport',
                               side_effect=lambda:self.fake):
            rc,out=self.create(grant)
        self.assertEqual(rc,3)
        self.assertIn('EC217',out['result']['reason_code'])
        self.assertEqual(self.fake.get_count,0)
        self.assertFalse(self.admission.exists())

    def test_06_forged_authorizer_vote_denied_by_real_ed25519(self):
        self.reserve();bad=self.signed_grant(signer_override=Ed25519PrivateKey.generate())
        self.start_host()
        rc,out=self.create(bad)
        self.assertEqual(rc,3)
        self.assertEqual(out['result']['reason_code'],'EC287_SIGNATURE_INVALID')
        self.assertFalse(self.admission.exists())

    def test_07_wrong_kernel_uid_scope_denied(self):
        self.reserve();bad=self.signed_grant(uid=os.getuid()+1)
        self.start_host()
        rc,out=self.create(bad)
        self.assertEqual(rc,3)
        self.assertIn('PEER_SCOPE',out['result']['reason_code'])
        self.assertFalse(self.admission.exists())

    def test_08_private_job_mutated_after_vote_rejected_before_original_backend(self):
        self.reserve();grant=self.signed_grant()
        self.start_host()
        self.jobfile.write_bytes(self.jobfile.read_bytes()+b' ')
        rc,out=self.create(grant)
        self.assertEqual(rc,5)
        self.assertIn('RAW_BYTES_CHANGED',out['result']['reason_code'])
        self.assertEqual(self.fake.get_count,0)

    def test_09_private_trust_issuer_mutated_after_vote_rejected(self):
        self.reserve();grant=self.signed_grant();self.start_host()
        self.trustfile.write_bytes(self.trustfile.read_bytes()+b' ')
        rc,out=self.create(grant)
        self.assertEqual(rc,5)
        self.assertIn('RAW_BYTES_CHANGED',out['result']['reason_code'])
        self.assertFalse(self.admission.exists())

    def test_10_private_host_access_mutated_after_vote_rejected(self):
        self.reserve();grant=self.signed_grant();self.start_host()
        self.accessfile.write_bytes(self.accessfile.read_bytes()+b' ')
        rc,out=self.create(grant)
        self.assertEqual(rc,5)
        self.assertFalse(self.admission.exists())

    def test_11_nonce_reply_tamper_or_wrong_signer_is_never_trusted(self):
        subject=self.signed_grant()['subject']
        req={'schema':p.REQUEST_SCHEMA,'nonce':secrets.token_hex(16),
             'grant':self.signed_grant()}
        receipt=p.signed_reply(req,p.denial('EC287_NEGATIVE_TEST'),
                               self.policy_sha,subject['job_sha256'],
                               self.keys['server'],int(time.time()))
        self.assertEqual(p.verify_reply(receipt,req,self.pub['server'],
                                        self.policy_sha,int(time.time()))['exit_code'],5)
        altered=copy.deepcopy(receipt);altered['result']['reason_code']='EC287_FORGED'
        with self.assertRaises(p.HostError):
            p.verify_reply(altered,req,self.pub['server'],
                           self.policy_sha,int(time.time()))
        with self.assertRaises(p.HostError):
            p.verify_reply(receipt,{**req,'nonce':secrets.token_hex(16)},
                           self.pub['server'],self.policy_sha,int(time.time()))
        with self.assertRaises(p.HostError):
            p.verify_reply(receipt,req,p.public_hex(Ed25519PrivateKey.generate()),
                           self.policy_sha,int(time.time()))

    def test_12_client_wrong_server_public_key_reports_unknown_no_retry(self):
        self.reserve();grant=self.signed_grant();self.start_host()
        with mock.patch.object(cw,'StrictHTTPSIssueCreateTransport',
                               side_effect=lambda:self.fake):
            with self.assertRaisesRegex(p.HostError,'EFFECT_UNKNOWN'):
                o.create(socket_path=self.sock,grant_file=self.write_grant(grant),
                    policy_sha=self.policy_sha,
                    server_pub=p.public_hex(Ed25519PrivateKey.generate()))
        self.assertEqual(self.fake.post_count,1)

    def test_13_original_post_failure_creates_unknown_no_second_attempt(self):
        self.reserve();grant=self.signed_grant();self.start_host()
        self.fake.post_error=TimeoutError('secret remote timeout')
        with mock.patch.object(cw,'StrictHTTPSIssueCreateTransport',
                               side_effect=lambda:self.fake):
            rc,out=self.create(grant)
            rc2,_=self.create(self.signed_grant())
        self.assertEqual(rc,5)
        self.assertEqual(out['result']['create_state'],'UNKNOWN')
        self.assertTrue(out['remote_effect_outcome_unknown'])
        self.assertEqual(self.fake.post_count,1)
        self.assertEqual(rc2,2)
        # Second subject is accepted by host but original EC218 says BLOCKED;
        # its exit is partial (2), not permission to POST.

    def test_14_invalid_original_result_shape_cannot_escape_as_signed_success(self):
        self.reserve();grant=self.signed_grant();self.start_host()
        with mock.patch.object(cw,'create_new_issue_once',return_value={
            'schema':cw.SCHEMA,'status':'partial','exit_code':2,'issue_created':True}):
            rc,out=self.create(grant)
        self.assertEqual(rc,5)
        self.assertIn('UNRECOGNIZED_ORIGINAL_RESULT',out['result']['reason_code'])
        self.assertTrue(out['remote_effect_outcome_unknown'])

    def test_15_grant_admission_commit_persists_across_database_instances(self):
        g=secrets.token_hex(16)
        self.assertTrue(d.admission_claim(str(self.admission),g))
        self.assertFalse(d.admission_claim(str(self.admission),g))
        self.assertTrue(d.admission_claim(str(self.admission),secrets.token_hex(16)))

    def test_16_expired_offline_subject_denied_even_with_valid_dual_signatures(self):
        self.reserve();grant=self.signed_grant()
        subject=grant['subject'];subject['issued_at_unix']-=130
        subject['expires_at_unix']-=130
        for role in ('custodian','authorizer'):
            grant[role+'_signature_ed25519']=p.sign(role,subject,self.keys[role])
        self.start_host()
        rc,out=self.create(grant)
        self.assertEqual(rc,3)
        self.assertEqual(self.fake.post_count,0)

    def test_17_access_token_and_server_private_files_require_owner_acl(self):
        self.tokenfile.chmod(0o644)
        with self.assertRaises(p.HostError):
            self.start_host()

    def test_18_client_invalid_no_request_does_not_claim_provider_success(self):
        self.reserve();grant=self.signed_grant();self.start_host()
        with self.assertRaises(p.HostError):
            o.create(socket_path=self.sock,grant_file=self.write_grant(grant),
                    policy_sha='0'*64,server_pub=self.pub['server'])
        self.assertFalse(self.admission.exists())

    def test_19_console_literal_and_original_router_host_denial_unchanged(self):
        from importlib.util import spec_from_file_location, module_from_spec
        path=Path(__file__).resolve().parents[2]/'scripts'/'ces_next.py'
        spec=spec_from_file_location('ec287_console_test',path)
        module=module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual((module.VERSION,module.ROUND),('V5.97','R287'))
        self.assertEqual(module._select(module._inventory(),
            'IssueCreate','Create')['route_kind'],'HOST_REQUIRED')
        with self.assertRaises(module.ConsoleError):
            module.run('IssueCreate','Create',str(self.jobfile))
        with self.assertRaises(module.ConsoleError):
            module.host_issue('QualityRun','Execute',socket_path=self.sock,
                grant_file=str(self.jobfile),policy_sha=self.policy_sha,
                server_public_hex=self.pub['server'])


    def test_20_real_console_subprocess_to_live_signed_denial(self):
        # Do not reserve original EC217: this exercises the complete REAL
        # console -> isolated CLI -> AF_UNIX -> signed host denial stack.
        grant=self.signed_grant();self.start_host()
        script=Path(__file__).resolve().parents[2]/'scripts'/'ces_next.py'
        cmd=[sys.executable,'-I','-B',str(script),'host-issue',
             'IssueCreate','Create','--socket',self.sock,
             '--grant-file',self.write_grant(grant),
             '--policy-sha256',self.policy_sha,
             '--server-public-hex',self.pub['server']]
        res=subprocess.run(cmd,capture_output=True,text=True,timeout=12)
        self.assertEqual(res.returncode,3,res.stderr+' '+res.stdout)
        doc=json.loads(res.stdout)
        self.assertEqual(doc['schema'],p.RESULT_SCHEMA)
        self.assertTrue(doc['verified_server_signature'])
        self.assertEqual(doc['result']['reason_code'],
                         'EC287_ORIGINAL_EC217_APPROVAL_OR_RESERVATION_DENIED')
        self.assertIs(doc['automatic_post_retry_allowed'],False)
        self.assertFalse(self.admission.exists())

    def test_21_host_authority_must_not_reuse_original_ec217_or_reviewer_key(self):
        prior=p.load_policy(str(self.policyfile),self.policy_sha)
        prior['custodian_issuer_public_hex']=next(iter(
            self.trust['eligibility_review_keys_hex'].values()))
        newfile=self.root/'bad-policy.json'
        new_sha=save(newfile,prior)
        with self.assertRaisesRegex(p.HostError,'KEYS_MUST_BE_DISTINCT'):
            d.IssueCreateHostServer(path=self.sock,policy_path=str(newfile),
                policy_sha=new_sha,private_key_file=str(self.serverkeyfile))
        self.assertFalse(Path(self.sock).exists())

    def test_22_real_offline_subject_and_votes_assemble_one_exact_grant(self):
        subjectfile=str(self.root/'offline-subject.json')
        cfile=str(self.root/'c-vote.json')
        afile=str(self.root/'a-vote.json')
        grantfile=str(self.root/'offline-grant.json')
        output=o.prepare_subject(str(self.policyfile),self.policy_sha,
                                 os.getuid(),30,subjectfile)
        self.assertFalse(output['network_requested'])
        self.assertEqual(o.vote('custodian',subjectfile,
                                str(self.root/'custodian.key'),cfile)['role'],
                         'custodian')
        self.assertEqual(o.vote('authorizer',subjectfile,
                                str(self.root/'authorizer.key'),afile)['role'],
                         'authorizer')
        o.assemble(subjectfile,cfile,afile,self.pub['custodian'],
                   self.pub['authorizer'],grantfile)
        granted=io.read_doc(grantfile,p.MAX_RPC)
        policy=p.load_policy(str(self.policyfile),self.policy_sha)
        job=p.load_job(policy)
        actual=p.validate_grant(granted,policy,job,uid=os.getuid(),
                                now=int(time.time()),policy_sha=self.policy_sha)
        self.assertEqual(actual['operation_sha256'],
                         cw.operation_sha256(self.intent))
        # Assembling alone has no provider effects, durable claims, or POST.
        self.assertFalse(self.attempt.exists())
        self.assertFalse(self.admission.exists())


if __name__=='__main__':
    unittest.main()
