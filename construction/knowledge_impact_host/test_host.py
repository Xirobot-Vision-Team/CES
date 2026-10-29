#!/usr/bin/env python3
"""EC282 focused real Git, original EC204 backend, Unix UID and signatures.

Signer keys and target/baseline Git statements here are LOCAL SYNTHETIC test
identities. Neither this suite nor passing results establish organizational
issuer custody, provider attestation, independent hosts or final acceptance.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

CONSTRUCTION = Path(__file__).resolve().parents[1]
ROOT = CONSTRUCTION.parent
sys.path.insert(0, str(CONSTRUCTION))

from knowledge_impact_host import protocol as p, daemon, operator
from finding_query_host import protocol as io
import test_knowledge_impact as original_fixture
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def doc(path: Path, obj: dict) -> Path:
    path.write_bytes(p.canonical(obj) + b'\n')
    os.chmod(path, 0o600)
    return path


def raw_key(path: Path, key: Ed25519PrivateKey) -> Path:
    path.write_bytes(key.private_bytes(serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    os.chmod(path, 0o600)
    return path


@unittest.skipUnless(shutil.which('git') and hasattr(os, 'getuid'),
                     'POSIX Git and peer UID required')
class KnowledgeImpactHostCases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ces-ec282-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fx = original_fixture.ImpactTests(
            'test_real_git_modified_selected_file_and_no_section_claim')
        self.fx.setUp()  # real detached temp Git commits + fresh signed fixtures
        self.addCleanup(self.fx.doCleanups)
        self.keys = {role: Ed25519PrivateKey.generate()
                     for role in ('source', 'reader', 'server')}
        self.pubs = {r: p.public_hex(k) for r, k in self.keys.items()}
        self.keyfiles = {r: raw_key(self.root / (r + '.ed25519'), k)
                         for r, k in self.keys.items()}
        pub_target = self.fx.fx.pub.hex()
        pub_baseline = self.fx.baseline_public.hex()
        self.job = {
            'schema': p.JOB_SCHEMA,
            'repository_root': str(self.fx.fx.repo),
            'knowledge_root': str(self.fx.fx.knowledge),
            'repository_ref': 'cesrepo1:' + '1'*64,
            'target_ref': 'refs/heads/main',
            'git_executable': shutil.which('git'),
            'trusted_target_public_hex_by_id': {'production': pub_target},
            'trusted_baseline_public_hex_by_id': {'baseline-authority': pub_baseline},
            'request': copy.deepcopy(self.fx.r),
            'bootstrap_read_policy': copy.deepcopy(self.fx.bp),
            'target_read_policy': copy.deepcopy(self.fx.tp),
            'impact_read_policy': copy.deepcopy(self.fx.ip),
            'target_statement': copy.deepcopy(self.fx.target_doc),
            'target_signature_base64': self.fx.fx.sign(self.fx.target_doc),
            'baseline_statement': copy.deepcopy(self.fx.baseline_doc),
            'baseline_signature_base64': self.fx.sign_base(),
        }
        self.job_path = doc(self.root/'job.json', self.job)
        self.policy = {'schema': p.POLICY_SCHEMA,
                       'job_file': str(self.job_path),
                       'job_sha256': p.sha(self.job_path.read_bytes()),
                       'allowed_uids': [os.getuid()],
                       'source_issuer_public_hex': self.pubs['source'],
                       'reader_issuer_public_hex': self.pubs['reader'],
                       'server_public_hex': self.pubs['server']}
        self.policy_path = doc(self.root/'policy.json', self.policy)
        self.policy_sha = p.sha(self.policy_path.read_bytes())
        self.socket_path = str(self.root/'impact.sock')
        self.subject = p.new_subject(
            uid=os.getuid(), policy_sha=self.policy_sha,
            job_sha=self.policy['job_sha256'],
            repository_ref=self.job['repository_ref'],
            target_ref=self.job['target_ref'], ttl=250)
        self.grant = self.sign_grant(self.subject)
        self.grant_path = doc(self.root/'grant.json', self.grant)
        self.server = None

    def sign_grant(self, s, keys=None):
        keys = keys or self.keys
        return {'schema': p.GRANT_SCHEMA, 'subject': s,
                'source_signature_ed25519': p.sign('source', s, keys['source']),
                'reader_signature_ed25519': p.sign('reader', s, keys['reader'])}

    def start_host(self):
        self.server = daemon.ImpactServer(
            path=self.socket_path, policy_path=str(self.policy_path),
            policy_sha=self.policy_sha,
            private_key_file=str(self.keyfiles['server']))
        thread = threading.Thread(target=self.server.serve_forever,
            kwargs={'poll_interval': .025}, daemon=True)
        thread.start()
        def shutdown():
            self.server.shutdown()
            thread.join(2)
            self.server.server_close()
        self.addCleanup(shutdown)
        return self.server

    def client(self, grant=None, *, trusted_pub=None, policy_pin=None):
        filepath = self.grant_path
        if grant is not None:
            filepath = doc(self.root/(f'ticket-{time.time_ns()}.json'), grant)
        return operator.analyze(
            socket_path=self.socket_path, grant_file=str(filepath),
            policy_sha=self.policy_sha if policy_pin is None else policy_pin,
            server_public_hex=self.pubs['server'] if trusted_pub is None else trusted_pub)

    def test_01_real_git_original_ec204_signed_partial(self):
        self.start_host()
        before = self.fx.fx.cmd('status', '--porcelain')
        rc, docu = self.client()
        self.assertEqual(rc, 2, docu)
        self.assertTrue(docu['verified_server_signature'])
        result = docu['result']
        self.assertEqual(result['reason_code'],
                         'KNOWLEDGE_IMPACT_SELECTED_GIT_CHANGES_PARTIAL')
        subject = result['subject']
        self.assertEqual(subject['source_changes'][0]['change_kind'], 'MODIFIED')
        self.assertEqual(subject['source_changes'][0]['comparison_state'],
                         'GIT_SELECTED_PATH_BYTES_VERIFIED')
        self.assertTrue(subject['summary']['selected_source_comparison_complete'])
        self.assertFalse(subject['summary']['whole_repository_change_set_complete'])
        self.assertEqual(subject['knowledge_sections_to_update'], [])
        self.assertFalse(docu['knowledge_semantic_impact_verified'])
        self.assertEqual(self.fx.fx.cmd('status','--porcelain'), before)

    def test_02_no_unsigned_grants_wrong_uid_or_roles(self):
        self.start_host()
        bad = copy.deepcopy(self.grant)
        bad['source_signature_ed25519'] = bad['reader_signature_ed25519']
        rc, output = self.client(bad)
        self.assertEqual(rc, 3)
        self.assertFalse(output['result']['handler_invoked'])
        bad = copy.deepcopy(self.grant)
        bad['subject']['uid'] = os.getuid() + 1
        rc, output = self.client(bad)
        self.assertEqual(rc, 3)
        bad = copy.deepcopy(self.grant)
        bad['subject']['expires_at_unix'] -= 100
        rc, output = self.client(bad)
        self.assertEqual(rc, 3)

    def test_03_expired_or_future_grant_even_with_real_signatures(self):
        self.start_host()
        s = p.new_subject(uid=os.getuid(), policy_sha=self.policy_sha,
            job_sha=self.policy['job_sha256'],
            repository_ref=self.job['repository_ref'],
            target_ref=self.job['target_ref'], ttl=15, now=int(time.time())-100)
        self.assertEqual(self.client(self.sign_grant(s))[0], 3)
        s = p.new_subject(uid=os.getuid(), policy_sha=self.policy_sha,
            job_sha=self.policy['job_sha256'],
            repository_ref=self.job['repository_ref'],
            target_ref=self.job['target_ref'], ttl=15, now=int(time.time())+200)
        self.assertEqual(self.client(self.sign_grant(s))[0], 3)

    def test_04_private_job_tamper_detected_after_server_start(self):
        self.start_host()
        self.job['request']['sources'].clear()
        doc(self.job_path, self.job)
        rc, output = self.client()
        self.assertEqual(rc, 5)
        self.assertEqual(output['result']['reason_code'],
                         'EC282_PINNED_JOB_BYTES_CHANGED')
        self.assertFalse(output['result']['data_disclosed'])

    def test_05_private_policy_hot_tamper_denies(self):
        self.start_host()
        self.policy['allowed_uids'] = []
        doc(self.policy_path, self.policy)
        rc, output = self.client()
        self.assertEqual(rc, 5)
        self.assertEqual(output['result']['reason_code'],
                         'EC282_HOST_POLICY_PIN_CHANGED')

    def test_06_git_target_moved_original_backend_fails_closed(self):
        self.start_host()
        self.fx.fx.put(self.fx.fx.repo, 'unselected-after.md', b'# change\n')
        self.fx.fx.commit('new target (after signed scope)')
        rc, output = self.client()
        # Original EC203 may return a signed partial unknown if data permits;
        # selected path comparisons may not be promoted to verified.
        self.assertEqual(rc, 5, output)
        self.assertEqual(output['result']['reason_code'],
                         'EC282_ORIGINAL_EC204_BACKEND_DID_NOT_AUTHORIZE_RESULT')

    def test_07_client_rejects_wrong_host_public_and_reply_forgery(self):
        self.start_host()
        with self.assertRaises(p.HostError):
            self.client(trusted_pub=p.public_hex(Ed25519PrivateKey.generate()))
        rc, out = self.client()
        self.assertEqual(rc, 2)
        req = {'schema': p.REQUEST_SCHEMA, 'nonce': out['signed_reply']['nonce'],
               'grant': self.grant}
        forged = copy.deepcopy(out['signed_reply'])
        forged['result']['subject']['knowledge_sections_to_update'] = ['made-up']
        with self.assertRaises(p.HostError):
            p.verify_reply(forged, req, server_public_hex=self.pubs['server'],
                policy_sha=self.policy_sha, now=int(time.time()))

    def test_08_bad_original_target_signature_not_returned_as_analysis(self):
        self.job['target_signature_base64'] = 'A' * 88
        self.job_path = doc(self.job_path, self.job)
        self.policy['job_sha256'] = p.sha(self.job_path.read_bytes())
        doc(self.policy_path, self.policy)
        self.policy_sha = p.sha(self.policy_path.read_bytes())
        self.subject = p.new_subject(uid=os.getuid(), policy_sha=self.policy_sha,
            job_sha=self.policy['job_sha256'],
            repository_ref=self.job['repository_ref'],
            target_ref=self.job['target_ref'], ttl=100)
        self.grant = self.sign_grant(self.subject)
        self.grant_path = doc(self.grant_path, self.grant)
        self.start_host()
        rc, out = self.client()
        self.assertEqual(rc, 5)
        self.assertFalse(out['result']['data_disclosed'])

    def test_09_offline_votes_exact_scope_nonoverwriting(self):
        subfile = doc(self.root/'subject.json', self.subject)
        role_files = []
        for role in ('source', 'reader'):
            path = self.root/(role+'.vote')
            operator.vote(role, str(subfile), str(self.keyfiles[role]), str(path))
            role_files.append(path)
            with self.assertRaises(io.HostError):
                operator.vote(role, str(subfile), str(self.keyfiles[role]), str(path))
        grant_path = self.root/'grant.offline.json'
        operator.assemble(str(subfile), str(role_files[0]), str(role_files[1]),
                          self.pubs['source'], self.pubs['reader'], str(grant_path))
        self.assertEqual(io.read_doc(str(grant_path)), self.grant)
        self.start_host()
        rc, result = operator.analyze(
            socket_path=self.socket_path, grant_file=str(grant_path),
            policy_sha=self.policy_sha, server_public_hex=self.pubs['server'])
        self.assertEqual(rc, 2, result)

    def test_10_console_real_host_and_exact_other_modes_denied(self):
        self.start_host()
        base = [sys.executable, '-I', '-B', str(ROOT/'scripts/ces_next.py')]
        args = ['host-impact', 'KnowledgeImpact', 'Analyze',
                '--socket', self.socket_path,
                '--grant-file', str(self.grant_path),
                '--policy-sha256', self.policy_sha,
                '--server-public-hex', self.pubs['server']]
        proc = subprocess.run([*base, *args], cwd=ROOT,
                              capture_output=True, text=True, timeout=45)
        self.assertEqual(proc.returncode, 2, proc.stdout+proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['result']['status'], 'partial')
        args[1:3] = ['QualityRun', 'Execute']
        blocked = subprocess.run([*base, *args], cwd=ROOT,
                                 capture_output=True, text=True, timeout=15)
        self.assertEqual(blocked.returncode, 3, blocked.stdout+blocked.stderr)
        blocked = subprocess.run([*base, 'run', 'KnowledgeImpact','Analyze',
                                  '--request-file', str(self.grant_path)], cwd=ROOT,
                                 capture_output=True, text=True, timeout=15)
        self.assertNotEqual(blocked.returncode, 0)

    def test_11_reject_symlink_or_public_private_job_and_uid_before_backend(self):
        self.start_host()
        with patch.object(daemon, 'perform_analysis', side_effect=AssertionError('called')):
            bad = copy.deepcopy(self.grant)
            bad['subject']['uid'] = os.getuid() + 1
            self.assertEqual(self.client(bad)[0], 3)
        os.chmod(self.job_path, 0o644)
        self.assertEqual(self.client()[0], 5)
        os.chmod(self.job_path, 0o600)

    def test_12_reject_signer_collision_or_untrusted_git(self):
        wrong = copy.deepcopy(self.job)
        wrong['git_executable'] = str(self.root/'not-installed-git')
        with self.assertRaises(p.HostError):
            p.validate_job(wrong)
        self.policy['source_issuer_public_hex'] = self.policy['server_public_hex']
        with self.assertRaises(p.HostError):
            p.validate_policy(self.policy)
        self.policy['source_issuer_public_hex'] = self.pubs['source']
        self.job['trusted_baseline_public_hex_by_id'] = {
            'baseline-authority': self.fx.fx.pub.hex()}
        with self.assertRaises(p.HostError):
            p.validate_job(self.job)


    def test_13_prepare_job_from_original_ec202_ec203_ec204_inputs(self):
        files = {}
        for name, value in (
            ('target-keys', self.job['trusted_target_public_hex_by_id']),
            ('baseline-keys', self.job['trusted_baseline_public_hex_by_id']),
            ('request', self.job['request']),
            ('bootstrap-policy', self.job['bootstrap_read_policy']),
            ('target-policy', self.job['target_read_policy']),
            ('impact-policy', self.job['impact_read_policy']),
            ('target-statement', self.job['target_statement']),
            ('baseline-statement', self.job['baseline_statement'])):
            files[name] = doc(self.root/(name+'.input.json'), value)
        for name, sig in (
            ('target-signature', self.job['target_signature_base64']),
            ('baseline-signature', self.job['baseline_signature_base64'])):
            fp = self.root/(name+'.b64')
            fp.write_bytes(sig.encode('ascii')+b'\n')
            os.chmod(fp, 0o600)
            files[name] = fp
        args = ['prepare-job', '--repository-root', str(self.fx.fx.repo),
                '--knowledge-root', str(self.fx.fx.knowledge),
                '--repository-ref', self.job['repository_ref'],
                '--target-ref', self.job['target_ref'],
                '--git-executable', self.job['git_executable']]
        for key, fpath in files.items():
            args += ['--'+key+'-file', str(fpath)]
        output = self.root/'constructed-job.json'
        ns = operator.parser().parse_args(args+['--out',str(output)])
        record = operator.prepare_job(ns)
        self.assertEqual(record['status'],
                         'private_exact_job_created_pending_offline_approval')
        self.assertEqual(record['job_sha256'],self.policy['job_sha256'])
        self.assertEqual(io.read_doc(str(output), p.MAX_JOB, private=True),self.job)
        with self.assertRaises(p.HostError):
            operator.prepare_job(ns)



if __name__ == '__main__':
    unittest.main(verbosity=2)
