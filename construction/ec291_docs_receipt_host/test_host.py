#!/usr/bin/env python3
"""EC291 local development fixtures: REAL original EC229 Git + EC230 readback.

All repositories are disposable local Git; offline signing keys generated on
one test machine are NOT real organizational separation or final acceptance.
No provider HTTP, public Git push or publication/cleanup occurs in the Host.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec279_finding_query_host import protocol as io
from ec285_docs_sandbox_host import protocol as old
from . import protocol as p, daemon, operator as op
import docs_only_publish as docs
import publication_receipts as rec
import test_docs_only_publish as docsfx


class EC291DocsReadbackCases(unittest.TestCase):
    def setUp(self):
        self.fx = docsfx.DocsOnlyGitCases()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        # Genuine original EC229 publisher performs one local Git ref creation.
        self.written = self.fx.result()
        self.assertEqual(self.written['status'], 'partial', self.written)
        self.temp = tempfile.TemporaryDirectory(prefix='ces-ec291-docs-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for dirname in ('owner', 'audit', 'admission', 'socket'):
            (self.root / dirname).mkdir(mode=0o700)
        self.private = self.root / 'owner'
        self.keys = [Ed25519PrivateKey.generate() for _ in range(5)]
        self.public = [old.public_hex(k) for k in self.keys]
        self.private_keys = {}
        for role, key in zip(('read', 'cleanup', 'custodian', 'inspector', 'server'),
                             self.keys):
            self.private_keys[role] = str(self._write(role + '.key',
                                                     key.private_bytes_raw()))
        access, request = self.fx.access, self.fx.request
        job = {'schema': old.JOB_SCHEMA, 'access': {
            'issuer_id': access.roots.issuer_id,
            'operator_id': access.roots.operator_id,
            'project_id': access.roots.project_id,
            'repository_id': access.roots.repository_id,
            'policy_public_hex': access.roots.policy_public_key.hex(),
            'reviewer_public_hex': access.roots.reviewer_public_key.hex(),
            'revocation_public_hex': access.roots.revocation_public_key.hex(),
            'side_effect_public_hex': access.roots.side_effect_public_key.hex(),
            'minimum_policy_epoch': access.roots.minimum_policy_epoch,
            'repository_root': access.repository_root,
            'approved_base_commit': access.approved_base_commit,
            'allowed_exact_paths': list(access.allowed_exact_paths),
            'worktree_root': access.worktree_root,
            'journal_root': access.journal_root,
            'sandbox_bare_root': access.sandbox_bare_root,
            'git_executable': access.git_executable,
            'enable_private_local_sandbox_publish': True},
            'request': {
                'documents': [vars(d) for d in request.documents],
                'repository_policy': vars(request.repository_policy),
                'content_review': vars(request.content_review),
                'current_revocation': vars(request.current_revocation),
                'one_use_grant': vars(request.one_use_grant),
                'explicitly_approve_exact_docs_only_local_publish': True}}
        old.validate_job(job)
        self.jobpath = str(self._write('job.json', p.canonical(job) + b'\n'))
        self.polpath = str(self.private / 'policy.json')
        self.polsha = self.make_policy()
        self.socket = str(self.root / 'socket' / 'docs-read.sock')
        self.host = self.thread = None

    def _write(self, name: str, data: bytes) -> Path:
        file = self.private / name
        file.write_bytes(data)
        file.chmod(0o600)
        return file

    def make_policy(self, uids=None) -> str:
        out = op.prepare_policy(job_file=self.jobpath,
            audit_root=str(self.root / 'audit'),
            admission_root=str(self.root / 'admission'),
            allowed_uids=[os.getuid()] if uids is None else uids,
            read_public_hex=self.public[0], cleanup_public_hex=self.public[1],
            receipt_epoch=7, custodian_public_hex=self.public[2],
            inspector_public_hex=self.public[3],
            server_public_hex=self.public[4], out=self.polpath, enable=True)
        return out['policy_sha256']

    def grant(self, read_path: str | None = None) -> tuple[str, str]:
        folder = self.root / ('grant-' + os.urandom(5).hex())
        folder.mkdir(mode=0o700)
        template, read, subject = (str(folder / n) for n in (
            'template.json', 'read.json', 'subject.json'))
        a, b, grant = (str(folder / n) for n in (
            'custodian.vote', 'inspector.vote', 'grant.json'))
        if read_path is None:
            op.prepare_read_template(self.polpath, self.polsha, 34, template)
            op.sign_read_template(template, self.private_keys['read'], read)
        else:
            read = read_path
        op.prepare_subject(self.polpath, self.polsha, read, os.getuid(), 24, subject)
        op.vote('custodian', subject, self.private_keys['custodian'], a)
        op.vote('inspector', subject, self.private_keys['inspector'], b)
        op.assemble(subject, a, b, self.public[2], self.public[3], grant)
        return grant, read

    def start(self):
        self.host = daemon.DocsReceiptHost(
            path=self.socket, policy_path=self.polpath,
            policy_sha=self.polsha,
            private_key_file=self.private_keys['server'])
        self.thread = threading.Thread(target=self.host.serve_forever,
                    kwargs={'poll_interval': .015}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        if self.host is not None and self.thread is not None and self.thread.is_alive():
            self.host.shutdown()
            self.thread.join(2)
        if self.host is not None:
            self.host.server_close()
            self.host = None

    def call(self, grant: str, read: str, *, console: bool = False):
        if console:
            command = [sys.executable, '-I', '-B',
                str(Path(__file__).resolve().parents[2] / 'scripts/ces_next.py'),
                'host-docs-receipt', 'DocsOnlyPublish', 'Readback',
                '--socket', self.socket, '--grant-file', grant,
                '--read-grant-file', read, '--policy-sha256', self.polsha,
                '--server-public-hex', self.public[4]]
            proc = subprocess.run(command, capture_output=True, text=True, timeout=100)
            return proc.returncode, json.loads(proc.stdout)
        return op.submit(socket_path=self.socket, grant_file=grant,
            read_grant_file=read, policy_sha=self.polsha, server_pub=self.public[4])

    def count(self):
        return (len(list((self.root / 'admission').iterdir())),
                len(list((self.root / 'audit').iterdir())))

    def test_01_genuine_ec229_commit_and_ec230_independent_private_ref_observed(self):
        original_journal = sorted((self.fx.journal / ('ec229-' + self.written['operation_id'])).iterdir())
        ref = docsfx.cmd('git', 'rev-parse', self.written['private_sandbox_ref'], cwd=self.fx.bare)
        self.start()
        grant, read = self.grant()
        with patch.object(rec.HTTPSPrivateReceiptReader, 'read', side_effect=AssertionError('no provider GET')):
            rc, response = self.call(grant, read)
        self.assertEqual(rc, 2, response)
        self.assertTrue(response['verified_server_signature'])
        self.assertTrue(response['verified_private_local_git_ref_observed'])
        result = response['result']
        self.assertEqual(result['receipt_state'], 'VERIFIED_PRIVATE_LOCAL_REF_ONLY')
        self.assertEqual(result['mode'], rec.MODE_DOCS)
        self.assertEqual(self.count(), (1, 1))
        self.assertTrue((next((self.root / 'audit').iterdir()) / '02_OBSERVATION').is_file())
        self.assertTrue((next((self.root / 'admission').iterdir()) / '00_ADMISSION.json').is_file())
        self.assertFalse(result['external_publication_confirmed'])
        self.assertFalse(result['local_worktree_cleanup_confirmed'])
        self.assertFalse(result['provider_receipt_read_attempted'])
        self.assertEqual(docsfx.cmd('git', 'rev-parse', self.written['private_sandbox_ref'], cwd=self.fx.bare), ref)
        self.assertEqual(docsfx.cmd('git', 'rev-parse', 'HEAD', cwd=self.fx.repo), self.fx.head)
        self.assertEqual(sorted((self.fx.journal / ('ec229-' + self.written['operation_id'])).iterdir()), original_journal)

    def test_02_identical_host_grant_is_durable_one_use(self):
        self.start()
        a, b = self.grant()
        self.assertEqual(self.call(a, b)[0], 2)
        rc, result = self.call(a, b)
        self.assertEqual(rc, 3, result)
        self.assertIn('ALREADY_SPENT', result['result']['reason_code'])
        self.assertEqual(self.count(), (1, 1))

    def test_03_new_host_votes_cannot_reuse_same_ec230_read_nonce(self):
        self.start()
        grant1, read = self.grant()
        self.assertEqual(self.call(grant1, read)[0], 2)
        grant2, _ = self.grant(read_path=read)
        rc, result = self.call(grant2, read)
        self.assertNotEqual(rc, 2, result)
        self.assertTrue(result['verified_server_signature'])
        self.assertEqual(self.count(), (2, 1))
        self.assertFalse(result['verified_private_local_git_ref_observed'])

    def test_04_original_ec229_durable_push_attempt_is_required_before_admission(self):
        marker = self.fx.journal / ('ec229-' + self.written['operation_id']) / '06_PUSH_ATTEMPTED'
        marker.unlink()  # corrupted disposable fixture, not production modification
        # Host can initialize from signed original request; it cannot consume a
        # new Host admission when the old stage chain has been corrupted.
        self.start()
        grant, read = self.grant()
        rc, response = self.call(grant, read)
        self.assertNotEqual(rc, 2, response)
        self.assertEqual(self.count(), (0, 0))

    def test_05_forged_ec291_inspector_vote_rejected_before_read(self):
        self.start()
        grant, read = self.grant()
        forged = json.loads(Path(grant).read_text())
        forged['inspector_signature_ed25519'] = '0' * 128
        file = self._write('forged-host-grant.json', p.canonical(forged) + b'\n')
        rc, result = self.call(str(file), read)
        self.assertEqual(rc, 3, result)
        self.assertEqual(self.count(), (0, 0))

    def test_06_forged_original_ec230_read_signer_denied_before_read(self):
        self.start()
        grant, read = self.grant()
        forged = json.loads(Path(read).read_text())
        forged['signature_hex'] = '0' * 128
        file = self._write('forged-read.json', p.canonical(forged) + b'\n')
        # Both synthetic Host voters deliberately sign the *forged* read hash.
        # A structurally valid dual-Host admission still cannot impersonate
        # the independent original EC230 READ signer on the actual socket.
        changed = json.loads(Path(grant).read_text())
        subject = changed['subject']
        subject['read_grant_sha256'] = p.sha(p.canonical(forged))
        changed['custodian_signature_ed25519'] = p.sign('custodian', subject, self.keys[2])
        changed['inspector_signature_ed25519'] = p.sign('inspector', subject, self.keys[3])
        newgrant = self._write('forged-read-bound-host.json', p.canonical(changed) + b'\n')
        rc, result = self.call(str(newgrant), str(file))
        self.assertEqual(rc, 3, result)
        self.assertIn('READ_GRANT_INVALID', result['result']['reason_code'])
        self.assertEqual(self.count(), (0, 0))

    def test_07_incorrect_kernel_peer_uid_denied_even_with_valid_offline_votes(self):
        self.start()
        grant, read = self.grant()
        with patch.object(daemon, 'kernel_uid', return_value=os.getuid() + 1):
            rc, result = self.call(grant, read)
        self.assertEqual(rc, 3, result)
        self.assertEqual(self.count(), (0, 0))

    def test_08_exact_owner_job_bytes_cannot_drift(self):
        self.start()
        grant, read = self.grant()
        with open(self.jobpath, 'ab') as fp:
            fp.write(b' ')
        rc, result = self.call(grant, read)
        self.assertNotEqual(rc, 2)
        self.assertEqual(self.count(), (0, 0))

    def test_09_missing_private_ref_is_unknown_not_absence_proof(self):
        docsfx.cmd('git', 'update-ref', '-d', self.written['private_sandbox_ref'], cwd=self.fx.bare)
        self.start()
        grant, read = self.grant()
        rc, response = self.call(grant, read)
        self.assertEqual(rc, 2, response)
        self.assertEqual(response['result']['receipt_state'], 'UNKNOWN_PRIVATE_REF_ABSENT')
        self.assertFalse(response['verified_private_local_git_ref_observed'])
        self.assertFalse(response['result']['external_publication_confirmed'])
        self.assertEqual(self.count(), (1, 1))

    def test_10_untrusted_private_git_ref_pointing_to_base_rejected(self):
        docsfx.cmd('git', 'update-ref', self.written['private_sandbox_ref'], self.fx.head,
            cwd=self.fx.bare)
        self.start()
        grant, read = self.grant()
        rc, response = self.call(grant, read)
        self.assertNotEqual(rc, 2, response)
        self.assertFalse(response['verified_private_local_git_ref_observed'])
        self.assertEqual(self.count(), (1, 1))

    def test_11_unified_console_exact_entry_and_original_run_denied(self):
        self.start()
        grant, read = self.grant()
        rc, result = self.call(grant, read, console=True)
        self.assertEqual(rc, 2, result)
        self.assertTrue(result['verified_private_local_git_ref_observed'])
        base = Path(__file__).resolve().parents[2] / 'scripts/ces_next.py'
        denied = subprocess.run([sys.executable, '-I', '-B', str(base), 'run',
            'DocsOnlyPublish', 'LocalSandbox', '--request-file', grant],
            text=True, capture_output=True, timeout=30)
        self.assertEqual(denied.returncode, 3)
        self.assertEqual(json.loads(denied.stdout)['reason_code'],
                         'EC278_INDEPENDENT_HOST_BRIDGE_REQUIRED')

    def test_12_role_keys_cannot_share_with_original_ec229_reviewers(self):
        pol = p.load_policy(self.polpath, self.polsha)
        pol['custodian_public_hex'] = p.load_job(pol)['access']['reviewer_public_hex']
        with self.assertRaises(p.HostError):
            p.service(pol)

    def test_13_exact_original_read_permission_rejects_report_mode(self):
        pol = p.load_policy(self.polpath, self.polsha)
        grant, read = self.grant()
        changed = json.loads(Path(read).read_text())
        body = changed['statement']
        body['mode'] = rec.MODE_REPORT
        changed['signature_hex'] = self.keys[0].sign(rec.READ_DOMAIN +
                                                   p.dp.canonical(body)).hex()
        with self.assertRaises(p.HostError):
            p.read_statement(changed, pol['read_public_hex'])

    def test_14_original_ec230_scope_disables_cleanup_and_provider_get(self):
        svc, scope, original = p.service(p.load_policy(self.polpath, self.polsha))
        self.assertIsInstance(scope, docs.HostDocsScope)
        self.assertIsInstance(original, docs.DocsOnlyPublishRequest)
        self.assertFalse(svc.host.enable_clean_linked_worktree)
        self.assertEqual(svc.host.provider_read_credential, '')
        self.assertFalse(svc.host.allow_synthetic_receipt_reader_for_development)


if __name__ == '__main__':
    unittest.main()
