#!/usr/bin/env python3
"""EC284 focused real original EC208+EC207+EC206 and AF_UNIX signed append.

All signer roles share one machine in these development tests, NOT a real
organization or production independent Unix service account.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

CONSTRUCTION = Path(__file__).resolve().parents[1]
ROOT = CONSTRUCTION.parent
sys.path.insert(0, str(CONSTRUCTION))
from ec284_knowledge_save_host import daemon, operator, protocol as p
from ec279_finding_query_host import protocol as io
from test_knowledge_version_save import VersionSaveTests


def private(path: Path, raw: bytes) -> Path:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    return path


def doc(path: Path, value: dict) -> Path:
    return private(path, p.canonical(value) + b'\n')


@unittest.skipUnless(hasattr(socket, 'SO_PEERCRED') and hasattr(os,'getuid'),
                     'Linux kernel AF_UNIX peer credentials required')
class KnowledgeSaveHostTests(unittest.TestCase):
    def setUp(self):
        self.fx = VersionSaveTests('test_initialized_only_explicitly_and_no_source_modification')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        api = self.fx.api
        source = api.store
        self.tmp = Path(self.fx.hfx.fx.tmp.name)
        signed = self.fx._sign(self.fx.req)
        self.job = {'schema': p.JOB_SCHEMA,
            'repository_root': source.repository_root,
            'knowledge_root': source.knowledge_root,
            'candidate_root': source.root,
            'version_root': api.root,
            'candidate_store_id': source.store_id,
            'version_store_id': api.store_id,
            'repository_ref': source.repository_ref,
            'knowledge_space_key': source.knowledge_space_key,
            'period_id': source.period_id,
            'source_policy_revision': source.source_policy_revision,
            'chapter_path': api.chapter_path,
            'trusted_approvers': {key: {'role': row['role'],
                          'public_hex': row['public_key'].hex()}
                          for key,row in api.trusted_approvers.items()},
            'revoked_approvers': [],
            'save_request': json.loads(signed['request_json']),
            'handoff_request': json.loads(signed['handoff_request_json']),
            'handoff_policy': json.loads(signed['handoff_policy_json']),
            'candidate_read_policies': json.loads(signed['candidate_read_policies_json']),
            'save_policy': json.loads(signed['save_policy_json']),
            'approvals': json.loads(signed['approvals_json'])}
        self.signers = {r: Ed25519PrivateKey.generate()
                        for r in ('custodian','authorizer','server')}
        self.pub = {r:p.public_hex(key) for r,key in self.signers.items()}
        self.keyfiles = {r: private(self.tmp / f'ec284-{r}.key', key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())) for r,key in self.signers.items()}
        self.server = None
        self.thread = None

    def files(self):
        self.job_file = doc(self.tmp / 'ec284-job.json', self.job)
        self.policy = {'schema':p.POLICY_SCHEMA, 'job_file':str(self.job_file),
            'job_sha256':p.sha(self.job_file.read_bytes()),
            'allowed_uids':[os.getuid()],
            'custodian_issuer_public_hex':self.pub['custodian'],
            'authorizer_issuer_public_hex':self.pub['authorizer'],
            'server_public_hex':self.pub['server']}
        self.policy_file = doc(self.tmp / 'ec284-policy.json', self.policy)
        self.policy_sha = p.sha(self.policy_file.read_bytes())
        self.sock = str(self.tmp / 'ec284.sock')
        self.subject = p.new_subject(uid=os.getuid(),
            policy_sha=self.policy_sha, job_sha=self.policy['job_sha256'],
            repository_ref=self.job['repository_ref'],
            save_key=self.job['save_request']['save_key'],
            request_sha=p.sha(p.canonical(self.job['save_request'])),
            authorization_scope_sha=self.job['save_policy']['authorization_scope_sha256'],
            chapter_sha=self.job['save_request']['expected_new_chapter_sha256'],
            ttl=180)
        self.grant = self.make_grant(self.subject)
        self.grant_file = doc(self.tmp / 'ec284-grant.json', self.grant)

    def make_grant(self, subject=None):
        subject = subject or self.subject
        return {'schema':p.GRANT_SCHEMA, 'subject':subject,
            'custodian_signature_ed25519':p.sign('custodian',subject,
                                                  self.signers['custodian']),
            'authorizer_signature_ed25519':p.sign('authorizer',subject,
                                                   self.signers['authorizer'])}

    def start(self):
        self.files()
        self.server = daemon.SaveServer(path=self.sock,
            policy_path=str(self.policy_file), policy_sha=self.policy_sha,
            private_key_file=str(self.keyfiles['server']))
        self.thread = threading.Thread(target=self.server.serve_forever,
            kwargs={'poll_interval':.025},daemon=True)
        self.thread.start()
        def close():
            self.server.shutdown()
            self.thread.join(3)
            self.server.server_close()
        self.addCleanup(close)
        return self.server

    def save(self, grant=None, pub=None):
        file = self.grant_file if grant is None else doc(
            self.tmp / ('grant-'+str(time.time_ns())+'.json'), grant)
        return operator.save(socket_path=self.sock, grant_file=str(file),
            policy_sha=self.policy_sha, server_public_hex=pub or self.pub['server'])

    def count(self):
        return self.fx.api.inspect()['subject']['version_count']

    def test_01_original_ec208_append_and_source_untouched(self):
        self.start()
        original = self.fx.src.read_bytes()
        before = self.count()
        rc, answer = self.save()
        self.assertEqual(rc,2,answer)
        res = answer['result']
        self.assertTrue(answer['verified_server_signature'])
        self.assertTrue(res['local_version_metadata_written'])
        self.assertEqual(res['reason_code'],'KNOWLEDGE_SAVE_NEW_IMMUTABLE_LOCAL_VERSION_APPENDED')
        self.assertEqual(res['subject']['save_key'],'version_one')
        self.assertEqual(res['subject']['chapter_content_sha256'],
                         self.job['save_request']['expected_new_chapter_sha256'])
        self.assertEqual(self.count(), before+1)
        self.assertEqual(self.fx.src.read_bytes(), original)
        self.assertEqual(self.fx.api.inspect()['subject']['head_version_id'],
                         res['subject']['version_id'])
        self.assertNotIn('replacement_section_base64',json.dumps(answer))

    def test_02_repeat_identical_grant_is_original_ec208_idempotent(self):
        self.start()
        self.assertEqual(self.save()[0],2)
        rc,out=self.save()
        self.assertEqual(rc,2,out)
        self.assertEqual(out['result']['reason_code'],
                         'KNOWLEDGE_SAVE_ALREADY_SAVED_IDEMPOTENT_NO_WRITE')
        self.assertFalse(out['result']['local_version_metadata_written'])
        self.assertEqual(self.count(),1)

    def test_03_mutated_and_missing_offline_votes_refused(self):
        self.start()
        fake=copy.deepcopy(self.grant)
        fake['custodian_signature_ed25519']='0'*128
        rc,out=self.save(fake)
        self.assertEqual(rc,3,out)
        self.assertFalse(out['result']['local_version_metadata_written'])
        fake=copy.deepcopy(self.grant)
        fake.pop('authorizer_signature_ed25519')
        self.assertEqual(self.save(fake)[0],3)
        self.assertEqual(self.count(),0)

    def test_04_bad_uid_job_savekey_or_request_grant_refused(self):
        self.start()
        for updates in ({'uid':os.getuid()+12345},{'save_key':'another_key'},
                        {'job_sha256':'a'*64},{'new_chapter_sha256':'a'*64},
                        {'save_request_sha256':'a'*64}):
            forged={**self.subject,**updates}
            rc,out=self.save(self.make_grant(forged))
            self.assertEqual(rc,3,(updates,out))
        self.assertEqual(self.count(),0)

    def test_05_job_tamper_after_server_start_refused_without_append(self):
        self.start()
        self.job_file.write_bytes(self.job_file.read_bytes()+b' ')
        rc,out=self.save()
        self.assertEqual(rc,5,out)
        self.assertFalse(out['result']['local_write_outcome_unknown'])
        self.assertEqual(self.count(),0)

    def test_06_policy_replacement_revokes_old_grant(self):
        self.start()
        self.policy_file.write_bytes(self.policy_file.read_bytes()+b' ')
        rc,out=self.save()
        self.assertEqual(rc,5,out)
        self.assertEqual(self.count(),0)

    def test_07_forbidden_business_write_flag_rejected_on_start(self):
        self.job['save_policy']['permit_business_repository_write']=True
        self.files()
        with self.assertRaises(p.HostError) as ctx:
            daemon.SaveServer(path=self.sock, policy_path=str(self.policy_file),
                policy_sha=self.policy_sha,
                private_key_file=str(self.keyfiles['server']))
        self.assertEqual(ctx.exception.code,'EC284_LOCAL_METADATA_ONLY_POLICY_REQUIRED')
        self.assertEqual(self.count(),0)

    def test_08_reused_ec208_approver_key_for_host_rejected(self):
        self.pub['custodian']=next(iter(self.job['trusted_approvers'].values()))['public_hex']
        self.files()
        with self.assertRaises(p.HostError) as ctx:
            daemon.SaveServer(path=self.sock, policy_path=str(self.policy_file),
                policy_sha=self.policy_sha,
                private_key_file=str(self.keyfiles['server']))
        self.assertEqual(ctx.exception.code,'EC284_HOST_AND_EC208_APPROVER_SIGNER_COLLISION')

    def test_09_source_drift_refused_by_real_original_ec208_preview(self):
        self.start()
        self.fx.src.write_bytes(self.fx.src.read_bytes()+b'\n# unexpected drift\n')
        rc,out=self.save()
        self.assertEqual(rc,5,out)
        self.assertIn('PREVIEW_SCOPE_NOT_READY',out['result']['reason_code'])
        self.assertEqual(list((Path(self.fx.root) / 'versions').iterdir()),[])

    def test_10_expired_approval_refused(self):
        self.start()
        expired={**self.subject,'issued_at_unix':int(time.time())-400,
                 'expires_at_unix':int(time.time())-100}
        rc,out=self.save(self.make_grant(expired))
        self.assertEqual(rc,3,out)
        self.assertEqual(self.count(),0)

    def test_11_forged_signed_reply_is_rejected_by_client(self):
        self.start()
        with self.assertRaises(p.HostError):
            self.save(pub=p.public_hex(Ed25519PrivateKey.generate()))
        # Note the *real host* still executed exactly one successful write.
        self.assertEqual(self.count(),1)

    def test_12_prepare_and_inspect_job_public_pins_only(self):
        from types import SimpleNamespace
        def save_arg(key, doc_value):
            path=doc(self.tmp / (key+'.json'),doc_value)
            return str(path)
        args=dict(repository_root=self.job['repository_root'],
            knowledge_root=self.job['knowledge_root'],
            candidate_root=self.job['candidate_root'],
            version_root=self.job['version_root'],
            candidate_store_id=self.job['candidate_store_id'],
            version_store_id=self.job['version_store_id'],
            repository_ref=self.job['repository_ref'],
            knowledge_space_key=self.job['knowledge_space_key'],
            period_id=self.job['period_id'],
            source_policy_revision=self.job['source_policy_revision'],
            chapter_path=self.job['chapter_path'], revoked_approvers_file=None,
            out=str(self.tmp/'created-job.json'))
        for k in ('trusted_approvers','save_request','handoff_request',
                  'handoff_policy','candidate_read_policies','save_policy','approvals'):
            args[k+'_file']=save_arg(k,self.job[k])
        receipt=operator.prepare_job(SimpleNamespace(**args))
        self.assertEqual(receipt['status'],
                         'private_save_job_created_pending_two_independent_host_votes')
        self.assertFalse(receipt['chapter_text_returned'])
        self.assertNotIn('Improved behavior',json.dumps(receipt))
        self.assertEqual(p.sha(Path(args['out']).read_bytes()),receipt['job_sha256'])
        self.assertEqual(os.stat(args['out']).st_mode & 0o777,0o600)

    def test_13_exact_original_router_host_denied_and_console_opt_in(self):
        self.start()
        command=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_next.py')]
        blocked=subprocess.run([*command,'run','KnowledgeSave','SaveLocal',
                         '--request-file',str(self.grant_file)],
                         capture_output=True,text=True,timeout=40)
        self.assertEqual(blocked.returncode,3,blocked.stdout)
        out=subprocess.run([*command,'host-save','KnowledgeSave','SaveLocal',
                '--socket',self.sock,'--grant-file',str(self.grant_file),
                '--policy-sha256',self.policy_sha,
                '--server-public-hex',self.pub['server']],
                capture_output=True,text=True,timeout=90)
        self.assertEqual(out.returncode,2,out.stdout+out.stderr)
        data=json.loads(out.stdout)
        self.assertTrue(data['verified_server_signature'])
        self.assertEqual(self.count(),1)

    def test_15_real_offline_cli_sign_assemble_and_use_grant(self):
        self.start()
        script=str(ROOT / 'scripts' / 'ces_knowledge_save_host.py')
        pub=operator.inspect_public(self.job,self.policy['job_sha256'])
        signed=self.tmp / 'ec284-offline-subject.json'
        args=[sys.executable,'-I','-B',script,'prepare-offline',
              '--uid',str(os.getuid()), '--policy-sha256',self.policy_sha,
              '--job-sha256',pub['job_sha256'],
              '--repository-ref',pub['repository_ref'],
              '--save-key',pub['save_key'],
              '--save-request-sha256',pub['save_request_sha256'],
              '--authorization-scope-sha256',pub['authorization_scope_sha256'],
              '--new-chapter-sha256',pub['new_chapter_sha256'],
              '--ttl-seconds','180','--out',str(signed)]
        run=subprocess.run(args,capture_output=True,text=True,timeout=40)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        votes={}
        for role in ('custodian','authorizer'):
            votes[role]=self.tmp / (role+'-vote.json')
            run=subprocess.run([sys.executable,'-I','-B',script,
                'sign-'+role+'-offline','--subject-file',str(signed),
                '--private-key-file',str(self.keyfiles[role]),
                '--out',str(votes[role])],capture_output=True,text=True,timeout=40)
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        grant=self.tmp / 'ec284-from-offline-cli.json'
        run=subprocess.run([sys.executable,'-I','-B',script,'assemble-offline',
            '--subject-file',str(signed),
            '--custodian-vote',str(votes['custodian']),
            '--authorizer-vote',str(votes['authorizer']),
            '--custodian-public-hex',self.pub['custodian'],
            '--authorizer-public-hex',self.pub['authorizer'],
            '--out',str(grant)],capture_output=True,text=True,timeout=40)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        rc,res=operator.save(socket_path=self.sock,grant_file=str(grant),
            policy_sha=self.policy_sha,server_public_hex=self.pub['server'])
        self.assertEqual(rc,2,res)
        self.assertEqual(self.count(),1)

    def test_16_policy_revocation_after_real_write_reports_unknown(self):
        from unittest.mock import patch
        self.start()
        real=daemon.vs.KnowledgeVersionSave.save
        def append_then_revoke(api, **kw):
            result=real(api,**kw)
            self.policy_file.write_bytes(self.policy_file.read_bytes()+b' ')
            return result
        with patch.object(daemon.vs.KnowledgeVersionSave,'save',append_then_revoke):
            rc,out=self.save()
        self.assertEqual(rc,5,out)
        self.assertTrue(out['result']['local_write_outcome_unknown'])
        self.assertIsNone(out['result']['local_version_metadata_written'])
        self.assertEqual(self.count(),1)

    def test_14_wrong_host_route_cannot_exercise_write_client(self):
        self.start()
        args=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_next.py'),
             'host-save','QualityRun','Execute','--socket',self.sock,
             '--grant-file',str(self.grant_file),
             '--policy-sha256',self.policy_sha,
             '--server-public-hex',self.pub['server']]
        out=subprocess.run(args,capture_output=True,text=True,timeout=40)
        self.assertEqual(out.returncode,3,out.stdout)
        self.assertEqual(self.count(),0)


if __name__ == '__main__':
    unittest.main()
