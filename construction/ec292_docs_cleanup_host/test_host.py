#!/usr/bin/env python3
"""EC292: real disposable EC229 Git -> EC291 read -> EC230 worktree removal.

Synthetic one-machine signing keys are for code-level tests, not independent
human custody, enterprise governance, multi-node durability or remote Git.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec285_docs_sandbox_host import protocol as old
from ec291_docs_receipt_host.test_host import EC291DocsReadbackCases
from ec291_docs_receipt_host import protocol as prior
import docs_only_publish as docs
import publication_receipts as rec
import test_docs_only_publish as gitfx
from . import protocol as p, daemon, operator as op


class EC292CleanupCases(unittest.TestCase):
    def setUp(self):
        self.previous = EC291DocsReadbackCases('test_01_genuine_ec229_commit_and_ec230_independent_private_ref_observed')
        self.previous.setUp()
        self.addCleanup(self.previous.doCleanups)
        self.root = self.previous.root
        self.private = self.previous.private
        self.keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.public = [old.public_hex(k) for k in self.keys]
        self.secret = [str(self.previous._write('ec292-' + name + '.key',
                                    key.private_bytes_raw())) for name, key in
                       zip(('custodian', 'reviewer', 'server'), self.keys)]
        (self.root / 'cleanup-admission').mkdir(mode=0o700)
        self.proofpath = str(self.private / 'ec291-signed-readback-result.json')
        self.polpath = str(self.private / 'ec292-policy.json')
        self.polsha = op.prepare_policy(
            ec291_policy_file=self.previous.polpath,
            ec291_policy_sha256=self.previous.polsha,
            readback_result_file=self.proofpath,
            admission_root=str(self.root / 'cleanup-admission'),
            allowed_uids=[os.getuid()],
            cleanup_custodian_public_hex=self.public[0],
            independent_reviewer_public_hex=self.public[1],
            server_public_hex=self.public[2], out=self.polpath,
            enable=True)['policy_sha256']
        self.socket = str(self.root / 'socket' / 'ec292-clean.sock')
        self.host = self.thread = None

    def readback(self):
        self.previous.start()
        grant, read = self.previous.grant()
        rc, response = self.previous.call(grant, read)
        self.assertEqual(rc, 2, response)
        self.assertTrue(response['verified_private_local_git_ref_observed'])
        self.previous._write('ec291-signed-readback-result.json',
                             p.canonical(response) + b'\n')
        self.previous.stop()
        return response

    def approval(self):
        folder = self.root / ('cleanup-grant-' + os.urandom(5).hex())
        folder.mkdir(mode=0o700)
        template, signed, subject, a, b, grant = (str(folder / n) for n in (
            'original.template', 'original.grant', 'host.subject',
            'custodian.vote', 'reviewer.vote', 'host.grant'))
        op.prepare_cleanup_template(self.polpath, self.polsha, 34, template)
        op.sign_cleanup_template(template, self.previous.private_keys['cleanup'], signed)
        op.prepare_subject(self.polpath, self.polsha, signed,
                           os.getuid(), 24, subject)
        op.vote('custodian', subject, self.secret[0], a)
        op.vote('reviewer', subject, self.secret[1], b)
        op.assemble(subject, a, b, self.public[0], self.public[1], grant)
        return grant, signed

    def start(self):
        self.host = daemon.CleanupHost(path=self.socket,
            policy_path=self.polpath, policy_sha=self.polsha,
            private_key_file=self.secret[2])
        self.thread = threading.Thread(target=self.host.serve_forever,
                    kwargs={'poll_interval': 0.015}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        if self.host is not None and self.thread is not None and self.thread.is_alive():
            self.host.shutdown()
            self.thread.join(2)
        if self.host is not None:
            self.host.server_close()
            self.host = None

    def call(self, grant: str, cleanup: str, *, console=False):
        if console:
            path = Path(__file__).resolve().parents[2] / 'scripts' / 'ces_next.py'
            cmd = [sys.executable, '-I', '-B', str(path), 'host-docs-cleanup',
                   'DocsOnlyPublish', 'Cleanup', '--socket', self.socket,
                   '--grant-file', grant, '--cleanup-grant-file', cleanup,
                   '--policy-sha256', self.polsha,
                   '--server-public-hex', self.public[2]]
            child = subprocess.run(cmd, text=True, capture_output=True, timeout=95)
            return child.returncode, json.loads(child.stdout)
        return op.submit(socket_path=self.socket, grant_file=grant,
            cleanup_grant_file=cleanup, policy_sha=self.polsha,
            server_pub=self.public[2])

    def worktree(self):
        return self.previous.fx.work / ('ec229-' + self.previous.written['operation_id'])

    def admission_count(self):
        return len(list((self.root / 'cleanup-admission').iterdir()))

    def grant_for_changed_cleanup(self, original_grant: str, changed_cleanup: dict):
        # Both *new* host voters approve the altered original CLEAN grant.
        # Therefore only the original EC230 grant / exact Git pin gate can
        # reject it; a client-side digest mismatch is not the reason.
        grant = json.loads(Path(original_grant).read_text())
        subject = grant['subject']
        subject['cleanup_grant_sha256'] = p.sha(p.canonical(changed_cleanup))
        grant['custodian_signature_ed25519'] = p.sign('custodian', subject, self.keys[0])
        grant['reviewer_signature_ed25519'] = p.sign('reviewer', subject, self.keys[1])
        return str(self.previous._write('ec292-rebound-' + os.urandom(3).hex() + '.json',
                                        p.canonical(grant) + b'\n'))

    def test_01_real_git_worktree_cleanup_exact_original_unchanged_ec230(self):
        before_journal = sorted((self.previous.fx.journal / (
                    'ec229-' + self.previous.written['operation_id'])).iterdir())
        ref = self.previous.written['private_sandbox_ref']
        candidate = self.previous.written['local_candidate_commit_sha']
        original_head = self.previous.fx.head
        self.assertTrue(self.worktree().is_dir())
        self.readback()
        grant, clean = self.approval()
        self.start()
        with patch.object(rec.HTTPSPrivateReceiptReader, 'read', side_effect=AssertionError('provider GET forbidden')):
            rc, response = self.call(grant, clean)
        self.assertEqual(rc, 2, response)
        self.assertTrue(response['verified_exact_linked_worktree_removed'])
        result = response['result']
        self.assertTrue(result['local_worktree_cleanup_confirmed'])
        self.assertTrue(result['cleanup_attempted'])
        self.assertFalse(self.worktree().exists())
        self.assertEqual(gitfx.cmd('git', 'rev-parse', ref, cwd=self.previous.fx.bare), candidate)
        self.assertEqual(gitfx.cmd('git', 'rev-parse', 'HEAD', cwd=self.previous.fx.repo), original_head)
        self.assertEqual(gitfx.cmd('git', 'status', '--porcelain', cwd=self.previous.fx.repo), '')
        self.assertEqual(sorted((self.previous.fx.journal / (
                    'ec229-' + self.previous.written['operation_id'])).iterdir()), before_journal)
        self.assertEqual(self.admission_count(), 1)
        self.assertEqual(len(list((self.root / 'audit').iterdir())), 2)
        audit = self.root / 'audit' / ('ec230-clean-' + self.previous.written['operation_id'])
        self.assertTrue((audit / '03_REMOVE_COMPLETED').is_file())
        self.assertTrue((self.root / 'cleanup-admission' / (
            'ec292-clean-' + self.previous.written['operation_id']) /
            '00_ADMISSION.json').is_file())

    def test_02_original_cleanup_ticket_and_host_vote_not_replayable(self):
        self.readback()
        grant, clean = self.approval()
        self.start()
        self.assertEqual(self.call(grant, clean)[0], 2)
        again, result = self.call(grant, clean)
        self.assertNotEqual(again, 2, result)
        self.assertTrue(result['verified_server_signature'])
        self.assertFalse(result['verified_exact_linked_worktree_removed'])
        self.assertEqual(self.admission_count(), 1)

    def test_03_unsigned_or_forged_ec291_proof_denied_before_admission(self):
        proof = self.readback()
        forged = json.loads(Path(self.proofpath).read_text())
        forged['signed_reply']['signature_ed25519'] = '0' * 128
        self.previous._write('ec291-signed-readback-result.json', p.canonical(forged)+b'\n')
        with self.assertRaises((p.HostError, prior.HostError)):
            self.approval()
        self.assertEqual(self.admission_count(), 0)

    def test_04_no_ec291_positive_readback_denied(self):
        self.start()
        with self.assertRaises((OSError, p.HostError, old.HostError)):
            self.approval()
        self.assertEqual(self.admission_count(), 0)
        self.assertTrue(self.worktree().is_dir())

    def test_05_original_ec230_cleanup_approval_forgery_denied(self):
        self.readback()
        grant, clean = self.approval()
        forged = json.loads(Path(clean).read_text())
        forged['signature_hex'] = '0' * 128
        false_clean = self.previous._write('ec292-forged-clean.json',
                                           p.canonical(forged)+b'\n')
        rebound = self.grant_for_changed_cleanup(grant, forged)
        self.start()
        rc, response = self.call(rebound, str(false_clean))
        self.assertEqual(rc, 3, response)
        self.assertEqual(self.admission_count(), 0)
        self.assertTrue(self.worktree().is_dir())

    def test_06_second_host_vote_forgery_denied(self):
        self.readback()
        grant, clean = self.approval()
        forged = json.loads(Path(grant).read_text())
        forged['reviewer_signature_ed25519'] = '0' * 128
        path = self.previous._write('ec292-forged-reviewer.json',
                                    p.canonical(forged)+b'\n')
        self.start()
        rc, out = self.call(str(path), clean)
        self.assertEqual(rc, 3, out)
        self.assertEqual(self.admission_count(), 0)

    def test_07_kernel_peer_uid_not_equivalent_to_claimed_uid(self):
        self.readback()
        grant, clean = self.approval()
        self.start()
        with patch.object(daemon, 'kernel_uid', return_value=os.getuid()+1):
            rc, out = self.call(grant, clean)
        self.assertEqual(rc, 3, out)
        self.assertEqual(self.admission_count(), 0)

    def test_08_original_worktree_dirty_denied_before_admission(self):
        self.readback()
        (self.worktree() / 'untracked-content').write_text('do not erase me')
        with self.assertRaises((rec.ReceiptDenied, p.HostError)):
            self.approval()
        self.assertTrue((self.worktree() / 'untracked-content').is_file())
        self.assertEqual(self.admission_count(), 0)

    def test_09_code_policy_original_job_changed_denied(self):
        self.readback()
        grant, clean = self.approval()
        with open(self.previous.jobpath, 'ab') as f:
            f.write(b' ')
        with self.assertRaises((p.HostError, prior.HostError, rec.ReceiptDenied)):
            p.load_policy(self.polpath, self.polsha)
        self.assertEqual(self.admission_count(), 0)
        self.assertTrue(self.worktree().is_dir())

    def test_10_unified_console_and_old_run_still_denied(self):
        self.readback()
        grant, clean = self.approval()
        self.start()
        rc, out = self.call(grant, clean, console=True)
        self.assertEqual(rc, 2, out)
        self.assertTrue(out['verified_exact_linked_worktree_removed'])
        cli = Path(__file__).resolve().parents[2] / 'scripts' / 'ces_next.py'
        child = subprocess.run([sys.executable, '-I', '-B', str(cli), 'run',
            'DocsOnlyPublish', 'LocalSandbox', '--request-file', grant],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(child.returncode, 3)
        self.assertEqual(json.loads(child.stdout)['reason_code'],
                         'EC278_INDEPENDENT_HOST_BRIDGE_REQUIRED')

    def test_11_clean_operation_admission_already_exists_no_retry(self):
        self.readback()
        grant, clean = self.approval()
        slot = self.root / 'cleanup-admission' / (
            'ec292-clean-' + self.previous.written['operation_id'])
        slot.mkdir(mode=0o700)
        self.start()
        rc, out = self.call(grant, clean)
        self.assertNotEqual(rc, 2, out)
        self.assertEqual(self.admission_count(), 1)
        self.assertTrue(self.worktree().is_dir())

    def test_12_positive_proof_bound_to_original_audit_observation(self):
        proof = self.readback()
        audit = self.root / 'audit' / ('ec230-read-' +
                                      proof['result']['inspection_id'])
        (audit / '02_OBSERVATION').unlink()
        with self.assertRaises((rec.ReceiptDenied, p.HostError)):
            self.approval()
        self.assertEqual(self.admission_count(), 0)

    def test_13_tampered_clean_grant_worktree_inode_not_accepted(self):
        self.readback()
        grant, clean = self.approval()
        forged = json.loads(Path(clean).read_text())
        forged['statement']['worktree_inode'][1] += 1
        forged['signature_hex'] = self.previous.keys[1].sign(
            rec.CLEAN_DOMAIN + p.canonical(forged['statement'])).hex()
        altered = self.previous._write('ec292-inode-change.json',
                                        p.canonical(forged)+b'\n')
        rebound = self.grant_for_changed_cleanup(grant, forged)
        self.start()
        rc, response = self.call(rebound, str(altered))
        self.assertEqual(rc, 3, response)
        self.assertEqual(self.admission_count(), 0)
        self.assertTrue(self.worktree().is_dir())

    def test_14_new_role_keys_cannot_reuse_prior_host_keys(self):
        pol = p.load_policy(self.polpath, self.polsha)
        pol['independent_reviewer_public_hex'] = self.previous.public[3]
        with self.assertRaises(p.HostError):
            p.validate_policy(pol)


    def test_15_original_ec291_unknown_ref_is_not_cleanup_authorization(self):
        gitfx.cmd('git', 'update-ref', '-d',
                  self.previous.written['private_sandbox_ref'],
                  cwd=self.previous.fx.bare)
        self.previous.start()
        grant, read = self.previous.grant()
        rc, result = self.previous.call(grant, read)
        self.assertEqual(rc, 2, result)
        self.assertFalse(result['verified_private_local_git_ref_observed'])
        self.previous._write('ec291-signed-readback-result.json',
                             p.canonical(result) + b'\n')
        self.previous.stop()
        with self.assertRaises((p.HostError, rec.ReceiptDenied)):
            self.approval()
        self.assertEqual(self.admission_count(), 0)
        self.assertTrue(self.worktree().is_dir())

    def test_16_stale_original_ec230_observation_not_reused(self):
        self.readback()
        with patch.object(rec, '_time', return_value=int(time.time()) + 70):
            with self.assertRaises((p.HostError, rec.ReceiptDenied)):
                self.approval()
        self.assertEqual(self.admission_count(), 0)
        self.assertTrue(self.worktree().is_dir())


if __name__ == '__main__':
    unittest.main()
