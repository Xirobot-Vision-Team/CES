#!/usr/bin/env python3
"""EC285 focused real Git, original EC229 signatures, dual offline votes and AF_UNIX.

All signers here are intentionally synthetic on a disposable local machine.
This is NOT proof of distinct actual people or a production trust deployment.
"""
from __future__ import annotations

from dataclasses import replace
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from finding_query_host import protocol as io
import docs_only_publish as docs
from test_docs_only_publish import DocsOnlyGitCases, cmd
from . import protocol as p, daemon, operator as op


class DocsHostTests(unittest.TestCase):
    def setUp(self):
        self.fx=DocsOnlyGitCases(methodName='runTest')
        self.fx.setUp()
        # Native EC229 grants stay strictly bounded; refresh synthetic fixture
        # expiries within EC229's 30s revocation / 45s side-effect age limits.
        self.fx.request=self.fx.make_request(
            revoke_changes={'expires_at':self.fx.now+28},
            grant_changes={'expires_at':self.fx.now+38})
        self.addCleanup(self.fx.doCleanups)
        self.private=Path(self.fx.temp.name)/'host_private'
        self.private.mkdir(mode=0o700)
        a=self.fx.access
        self.job={'schema':p.JOB_SCHEMA,'access':{
            'issuer_id':a.roots.issuer_id,
            'operator_id':a.roots.operator_id,
            'project_id':a.roots.project_id,
            'repository_id':a.roots.repository_id,
            'policy_public_hex':a.roots.policy_public_key.hex(),
            'reviewer_public_hex':a.roots.reviewer_public_key.hex(),
            'revocation_public_hex':a.roots.revocation_public_key.hex(),
            'side_effect_public_hex':a.roots.side_effect_public_key.hex(),
            'minimum_policy_epoch':a.roots.minimum_policy_epoch,
            'repository_root':a.repository_root,
            'approved_base_commit':a.approved_base_commit,
            'allowed_exact_paths':list(a.allowed_exact_paths),
            'worktree_root':a.worktree_root,'journal_root':a.journal_root,
            'sandbox_bare_root':a.sandbox_bare_root,
            'git_executable':a.git_executable,
            'enable_private_local_sandbox_publish':True},
            'request':{
                'documents':[vars(d) for d in self.fx.request.documents],
                'repository_policy':vars(self.fx.request.repository_policy),
                'content_review':vars(self.fx.request.content_review),
                'current_revocation':vars(self.fx.request.current_revocation),
                'one_use_grant':vars(self.fx.request.one_use_grant),
                'explicitly_approve_exact_docs_only_local_publish':True}}
        p.validate_job(self.job)
        self.keys=[Ed25519PrivateKey.generate() for _ in range(3)]
        for name,key in zip(('custodian','authorizer','server'),self.keys):
            self._write(name+'.key',key.private_bytes(
                serialization.Encoding.Raw,serialization.PrivateFormat.Raw,
                serialization.NoEncryption()))
        self.job_path=self._write('job.json',p.canonical(self.job)+b'\n')
        self.policy={'schema':p.POLICY_SCHEMA,
            'job_file':str(self.job_path),
            'job_sha256':p.sha(self.job_path.read_bytes()),
            'allowed_uids':[os.getuid()],
            'custodian_issuer_public_hex':p.public_hex(self.keys[0]),
            'authorizer_issuer_public_hex':p.public_hex(self.keys[1]),
            'server_public_hex':p.public_hex(self.keys[2])}
        self.policy_path=self._write('policy.json',p.canonical(self.policy)+b'\n')
        self.policy_sha=p.sha(self.policy_path.read_bytes())
        self.socket_path=str(Path(self.fx.temp.name)/'docs.sock')
        self.subject=p.new_subject(uid=os.getuid(),policy_sha=self.policy_sha,
            job_sha=self.policy['job_sha256'],ttl=40,**{
            'project_id':p.job_pins(self.job)['project_id'],
            'repository_id':p.job_pins(self.job)['repository_id'],
            'base_commit':p.job_pins(self.job)['base_commit'],
            'manifest_sha':p.job_pins(self.job)['manifest_sha256'],
            'allowlist_sha':p.job_pins(self.job)['allowlist_sha256'],
            'target_sha':p.job_pins(self.job)['target_binding_sha256'],
            'backend_sha':p.job_pins(self.job)['docs_backend_sha256']})
        self.grant={'schema':p.GRANT_SCHEMA,'subject':self.subject,
            'custodian_signature_ed25519':p.sign('custodian',self.subject,self.keys[0]),
            'authorizer_signature_ed25519':p.sign('authorizer',self.subject,self.keys[1])}
        self.grant_path=self._write('grant.json',p.canonical(self.grant)+b'\n')

    def _write(self,name,raw: bytes):
        path=self.private/name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def _server(self):
        srv=daemon.DocsHostServer(path=self.socket_path,
                policy_path=str(self.policy_path),policy_sha=self.policy_sha,
                private_key_file=str(self.private/'server.key'))
        thread=threading.Thread(target=srv.serve_forever,kwargs={'poll_interval':.01},
                                daemon=True)
        thread.start()
        self.addCleanup(thread.join,2)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv

    def _call(self,*,console=False):
        if console:
            command=[sys.executable,'-I','-B',
                str(Path(__file__).resolve().parents[2]/'scripts/ces_next.py'),
                'host-docs','DocsOnlyPublish','LocalSandbox','--socket',self.socket_path,
                '--grant-file',str(self.grant_path),'--policy-sha256',self.policy_sha,
                '--server-public-hex',p.public_hex(self.keys[2])]
            done=subprocess.run(command,capture_output=True,text=True,timeout=110)
            return done.returncode,json.loads(done.stdout.strip())
        return op.publish(socket_path=self.socket_path,
            grant_file=str(self.grant_path),policy_sha=self.policy_sha,
            server_pub=p.public_hex(self.keys[2]))

    def _assert_no_side_effect(self):
        self.assertEqual(list(self.fx.journal.iterdir()),[])
        self.assertEqual(list(self.fx.work.iterdir()),[])
        self.assertEqual(list((self.fx.bare/'refs/heads').iterdir()),[])

    def test_real_original_ec229_create_new_private_ref(self):
        self._server()
        rc,doc=self._call()
        self.assertEqual(rc,2,doc)
        res=doc['result']
        self.assertTrue(doc['verified_server_signature'])
        self.assertTrue(p.safe_success(res,self.subject))
        self.assertFalse(res['published'])
        self.assertEqual(cmd('git','rev-parse','HEAD',cwd=self.fx.repo),self.fx.head)
        self.assertEqual(cmd('git','status','--porcelain',cwd=self.fx.repo),'')
        self.assertFalse((self.fx.repo/self.fx.doc.relative_path).exists())
        self.assertEqual(cmd('git','rev-parse',res['private_sandbox_ref'],cwd=self.fx.bare),
                         res['local_candidate_commit_sha'])
        self.assertEqual(cmd('git','show',res['local_candidate_commit_sha']+':'+
                             self.fx.doc.relative_path,cwd=self.fx.bare),
                         self.fx.raw.decode().strip())

    def test_exact_replay_cannot_create_second_ref_or_write(self):
        self._server()
        self.assertEqual(self._call()[0],2)
        rc,receipt=self._call()
        self.assertEqual(rc,4,receipt)
        self.assertTrue(receipt['verified_server_signature'])
        self.assertIn('SANDBOX_REF_ALREADY_EXISTS',receipt['result']['reason_code'])
        self.assertEqual(len(list(self.fx.work.iterdir())),1)

    def test_console_literal_host_docs_uses_real_original_ec229(self):
        self._server()
        rc,receipt=self._call(console=True)
        self.assertEqual(rc,2,receipt)
        self.assertTrue(receipt['verified_server_signature'])
        self.assertTrue(receipt['result']['private_sandbox_ref_observed'])

    def test_original_router_run_still_denies_host_required(self):
        base=Path(__file__).resolve().parents[2]
        command=[sys.executable,'-I','-B',str(base/'scripts/ces_next.py'),
                 'run','DocsOnlyPublish','LocalSandbox','--request-file',
                 str(self.grant_path)]
        result=subprocess.run(command,capture_output=True,text=True,timeout=35)
        self.assertNotEqual(result.returncode,0)
        self.assertNotEqual(json.loads(result.stdout)['status'],'partial')

    def test_missing_or_wrong_host_signature_never_calls_git(self):
        self._server()
        forged=copy.deepcopy(self.grant)
        forged['authorizer_signature_ed25519']='0'*128
        self._write('forged.json',p.canonical(forged)+b'\n')
        original=self.grant_path
        self.grant_path=self.private/'forged.json'
        rc,doc=self._call()
        self.assertEqual(rc,3,doc)
        self.assertFalse(doc['result']['local_effect_outcome_unknown'])
        self._assert_no_side_effect()
        self.grant_path=original

    def test_wrong_kernel_uid_never_calls_git(self):
        self.policy['allowed_uids']=[os.getuid()+1]
        self._write('wrong-policy.json',p.canonical(self.policy)+b'\n')
        self.policy_path=self.private/'wrong-policy.json'
        self.policy_sha=p.sha(self.policy_path.read_bytes())
        self.subject['policy_sha256']=self.policy_sha
        self.grant['subject']=self.subject
        for role,index in (('custodian',0),('authorizer',1)):
            self.grant[f'{role}_signature_ed25519']=p.sign(role,self.subject,self.keys[index])
        self.grant_path.write_bytes(p.canonical(self.grant)+b'\n')
        self._server()
        rc,doc=self._call()
        self.assertEqual(rc,3,doc)
        self.assertIn('UID_SCOPE_PIN',doc['result']['reason_code'])
        self.assertFalse(doc['result']['local_effect_outcome_unknown'])
        self._assert_no_side_effect()

    def test_original_reviewer_signature_forged_is_not_host_override(self):
        forged=copy.deepcopy(self.job)
        forged['request']['content_review']['signature_hex']='0'*128
        self.job_path.write_bytes(p.canonical(forged)+b'\n')
        self.policy['job_sha256']=p.sha(self.job_path.read_bytes())
        self.policy_path.write_bytes(p.canonical(self.policy)+b'\n')
        self.policy_sha=p.sha(self.policy_path.read_bytes())
        self.subject['job_sha256']=self.policy['job_sha256']
        self.subject['policy_sha256']=self.policy_sha
        self.grant['subject']=self.subject
        for role,index in (('custodian',0),('authorizer',1)):
            self.grant[f'{role}_signature_ed25519']=p.sign(role,self.subject,self.keys[index])
        self.grant_path.write_bytes(p.canonical(self.grant)+b'\n')
        self._server()
        rc,doc=self._call()
        self.assertEqual(rc,5,doc)
        self.assertFalse(doc['result']['local_effect_outcome_unknown'])
        self._assert_no_side_effect()

    def test_raw_job_bytes_drift_blocks_effect(self):
        self._server()
        self.job_path.write_bytes(self.job_path.read_bytes()+b' ')
        rc,doc=self._call()
        self.assertEqual(rc,5,doc)
        self.assertFalse(doc['result']['local_effect_outcome_unknown'])
        self._assert_no_side_effect()

    def test_raw_policy_bytes_drift_blocks_effect(self):
        self._server()
        self.policy_path.write_bytes(self.policy_path.read_bytes()+b' ')
        rc,doc=self._call()
        self.assertEqual(rc,5,doc)
        self.assertFalse(doc['result']['local_effect_outcome_unknown'])
        self._assert_no_side_effect()

    def test_source_git_dirty_original_denies_before_claim(self):
        self._server()
        (self.fx.repo/'source/service.py').write_text('unsafe source drift\n')
        rc,doc=self._call()
        self.assertEqual(rc,5,doc)
        self.assertFalse(doc['result']['local_effect_outcome_unknown'])
        self._assert_no_side_effect()

    def test_seven_signers_cannot_overlap(self):
        self.policy['server_public_hex']=self.job['access']['reviewer_public_hex']
        other=self._write('collision.json',p.canonical(self.policy)+b'\n')
        with self.assertRaises(p.HostError):
            daemon.DocsHostServer(path=self.socket_path,
                policy_path=str(other),policy_sha=p.sha(other.read_bytes()),
                private_key_file=str(self.private/'server.key'))

    def test_offline_votes_assemble_and_verified_result(self):
        self._server()
        subject_file=self._write('subject.json',p.canonical(self.subject)+b'\n')
        a=self.private/'custodian.vote.json'
        b=self.private/'authorizer.vote.json'
        op.vote('custodian',str(subject_file),str(self.private/'custodian.key'),str(a))
        op.vote('authorizer',str(subject_file),str(self.private/'authorizer.key'),str(b))
        new_grant=self.private/'assembled.json'
        op.assemble(str(subject_file),str(a),str(b),
            p.public_hex(self.keys[0]),p.public_hex(self.keys[1]),str(new_grant))
        self.grant_path=new_grant
        rc,doc=self._call()
        self.assertEqual(rc,2,doc)

    def test_host_policy_revocation_before_push_guard_blocks_ref(self):
        from unittest.mock import patch
        original=docs.RestrictedGit.run
        checks=[0]
        def change_policy_before_final_review(git,cwd,*args,**kw):
            # The second exact absence check is after a private commit, but
            # before EC229's final review and EC285's guarded push edge.
            if args and args[0]=='show-ref' and '--verify' in args:
                checks[0]+=1
                if checks[0]==2:
                    self.policy_path.write_bytes(self.policy_path.read_bytes()+b' ')
            return original(git,cwd,*args,**kw)
        self._server()
        with patch.object(docs.RestrictedGit,'run',change_policy_before_final_review):
            rc,doc=self._call()
        self.assertGreaterEqual(checks[0],2)
        self.assertEqual(rc,5,doc)
        self.assertTrue(doc['result']['local_effect_outcome_unknown'])
        exact_ref=docs.REF_NAMESPACE+p.operation_id(self.subject)
        observed=subprocess.run(['git','show-ref','--verify','--quiet',exact_ref],
                                 cwd=self.fx.bare,capture_output=True)
        self.assertEqual(observed.returncode,1)
        self.assertEqual(cmd('git','status','--porcelain',cwd=self.fx.repo),'')

    def test_tiny_post_check_revocation_race_never_claims_no_write(self):
        # A policy change AFTER the last gate but BEFORE the Git syscall is
        # not atomic with file I/O. This must report UNKNOWN, not false denial.
        from unittest.mock import patch
        original=docs.RestrictedGit.run
        triggered=[False]
        def change_immediately_before_git_call(git,cwd,*args,**kw):
            if args and args[0]=='push' and not triggered[0]:
                triggered[0]=True
                self.policy_path.write_bytes(self.policy_path.read_bytes()+b' ')
            return original(git,cwd,*args,**kw)
        self._server()
        with patch.object(docs.RestrictedGit,'run',change_immediately_before_git_call):
            rc,doc=self._call()
        self.assertTrue(triggered[0])
        self.assertEqual(rc,5,doc)
        self.assertTrue(doc['result']['local_effect_outcome_unknown'])
        exact_ref=docs.REF_NAMESPACE+p.operation_id(self.subject)
        observed=subprocess.run(['git','show-ref','--verify','--quiet',exact_ref],
                                 cwd=self.fx.bare,capture_output=True)
        self.assertEqual(observed.returncode,0)
        self.assertEqual(cmd('git','status','--porcelain',cwd=self.fx.repo),'')

    def test_original_push_io_unknown_no_retry(self):
        from unittest.mock import patch
        original=docs.RestrictedGit.run
        def synthetic_push_fail(git,cwd,*args,**kw):
            if args and args[0]=='push':
                raise docs.DocsDenied('SYNTHETIC_PUSH_IO_OUTCOME_UNKNOWN','unavailable')
            return original(git,cwd,*args,**kw)
        self._server()
        with patch.object(docs.RestrictedGit,'run',synthetic_push_fail):
            rc,doc=self._call()
        self.assertEqual(rc,5,doc)
        self.assertTrue(doc['result']['local_effect_outcome_unknown'])
        self.assertEqual(len(list(self.fx.journal.iterdir())),1)
        rc,doc=self._call()
        self.assertNotEqual(rc,2,doc)
        self.assertEqual(len(list(self.fx.work.iterdir())),1)

    def test_private_job_and_policy_creation_helpers(self):
        # First-party CLI prep consumes private original EC229 records only.
        source=self._write('source.json',p.canonical(self.job)+b'\n')
        jobpath=self.private/'created-job.json'
        observed=op.prepare_job(str(source),str(jobpath))
        self.assertEqual(observed['job_sha256'],p.sha(jobpath.read_bytes()))
        self.assertFalse(observed['private_document_text_returned'])
        generated=op.prepare_policy(job_file=str(jobpath),allowed_uids=[os.getuid()],
            custodian_pub=p.public_hex(self.keys[0]),
            authorizer_pub=p.public_hex(self.keys[1]),
            server_pub=p.public_hex(self.keys[2]),out=str(self.private/'created-policy.json'))
        self.assertEqual(generated['job_sha256'],observed['job_sha256'])
        self.assertFalse(generated['private_documents_returned'])

    def test_signed_reply_forgery_detected(self):
        req={'schema':p.REQUEST_SCHEMA,'nonce':'a'*32,'grant':self.grant}
        forged=p.signed_reply(req,p.denial('TEST'),self.policy_sha,
                              self.policy['job_sha256'],self.keys[2],int(time.time()))
        forged['result']['status']='partial'
        with self.assertRaises(p.HostError):
            p.verify_reply(forged,req,p.public_hex(self.keys[2]),
                           self.policy_sha,int(time.time()))

    def test_client_absent_socket_reports_unknown_no_automatic_retry(self):
        with self.assertRaises(p.HostError) as cm:
            self._call()
        self.assertIn('TRANSPORT_UNKNOWN',cm.exception.code)
        self._assert_no_side_effect()


if __name__=='__main__':
    unittest.main()
