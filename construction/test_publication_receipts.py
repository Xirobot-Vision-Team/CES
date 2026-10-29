#!/usr/bin/env python3
"""EC230 dev fixtures only: real disposable Git and EC200 store; fake GET.

No live enterprise identity, provider authority, filesystem crash, network or
production publication has been verified. Cases focus on *feature semantics*.
"""
from __future__ import annotations

from dataclasses import replace
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

import delivery_authorization as da
import delivery_preview as dp
import publication_receipts as rec
import report_publish as rp
import docs_only_publish as gitp
import test_docs_only_publish as docsfx
import test_report_publish as reportfx

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / 'references' / 'publication-receipt-result.v1.schema.json').read_text())
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)


def signed(key, domain, body):
    return da.SignedAuthorizationStatement(
        copy.deepcopy(body), key.sign(domain + dp.canonical(body)).hex())


class FakeGET:
    def __init__(self, key):
        self.key = key
        self.calls = 0
        self.created = True
        self.mutations = {}
        self.failure = False
        self.last_challenge = None
        self.last_credential = None

    def read(self, target, credential, challenge):
        self.calls += 1
        self.last_challenge = challenge
        self.last_credential = credential
        if self.failure:
            raise OSError('Synthetic provider timeout')
        now = reportfx.NOW
        body = {
            'schema': rec.PROVIDER_SCHEMA, 'provider_id': target.provider_id,
            'account_id': target.account_id, 'project_id': target.project_id,
            'destination_id': target.destination_id,
            'operation_id': challenge['operation_id'],
            'target_sha256': challenge['target_sha256'],
            'report_ref': challenge['report_ref'],
            'rendered_sha256': challenge['rendered_sha256'],
            'challenge_nonce': challenge['challenge_nonce'],
            'record_state': 'CREATED_PRIVATE_TEST' if self.created else 'NOT_FOUND',
            'record_id_sha256': 'b' * 64 if self.created else None,
            'private_sandbox': True, 'create_only': True,
            'issued_at': now - 2, 'expires_at': now + 12,
        }
        body.update(self.mutations)
        return signed(self.key, rec.PROVIDER_DOMAIN, body)


class ReceiptTestBase(unittest.TestCase):
    def make_service(self, reader=None, *, read_enabled=True, cleanup_enabled=True):
        self.read_key, self.clean_key = (Ed25519PrivateKey.generate(),
                                         Ed25519PrivateKey.generate())
        self.audit_tmp = tempfile.TemporaryDirectory(prefix='ces-ec230-audit-')
        self.addCleanup(self.audit_tmp.cleanup)
        host = rec.HostReceiptScope(
            rec.ReceiptRoots(docsfx.public_key(self.read_key),
                             docsfx.public_key(self.clean_key), 3),
            self.audit_tmp.name, read_enabled, cleanup_enabled, bool(reader),
            'readonly_synthetic_ec230_receipt_token')
        return rec.PublicationReceiptService(host, reader=reader)

    def read_permission(self, mode, op, target, original_grant, *, nonce='c' * 32,
                        epoch=3, changes=None):
        now = self.now
        body = {
            'schema': rec.READ_SCHEMA, 'mode': mode, 'operation_id': op,
            'target_sha256': target, 'original_grant_sha256': original_grant,
            'inspection_nonce': nonce, 'receipt_epoch': epoch,
            'code_revision_sha256': rec.ACTIVE_CODE_SHA256,
            'permission': rec.READ_PERMISSION, 'issued_at': now - 2,
            'expires_at': now + 20,
        }
        body.update(changes or {})
        return signed(self.read_key, rec.READ_DOMAIN, body)

    def cleanup_permission(self, op, target, grant_sha, inspect_result,
                           commit, inode, *, changes=None):
        body = {
            'schema': rec.CLEAN_SCHEMA, 'mode': rec.MODE_DOCS,
            'operation_id': op, 'target_sha256': target,
            'original_grant_sha256': grant_sha,
            'inspection_id': inspect_result['inspection_id'],
            'observation_sha256': inspect_result['observation_sha256'],
            'candidate_commit_sha': commit, 'worktree_inode': list(inode),
            'cleanup_epoch': 3, 'permission': rec.CLEAN_PERMISSION,
            'code_revision_sha256': rec.ACTIVE_CODE_SHA256,
            'issued_at': self.now - 2, 'expires_at': self.now + 20,
        }
        body.update(changes or {})
        return signed(self.clean_key, rec.CLEAN_DOMAIN, body)

    def valid_result(self, result, status=None):
        errors = list(VALIDATOR.iter_errors(result))
        self.assertEqual(errors, [], [(list(e.path), e.message) for e in errors])
        if status:
            self.assertEqual(result['status'], status, result)
        self.assertFalse(result['external_publication_confirmed'])
        self.assertFalse(result['public_or_production_published'])
        self.assertFalse(result['original_post_or_push_retried'])
        self.assertFalse(result['remote_ref_or_provider_content_deleted'])
        self.assertFalse(result['original_journal_deleted'])
        self.assertFalse(result['original_source_or_index_modified'])
        return result


class DocsReceipts(ReceiptTestBase):
    def setUp(self):
        self.fixture = docsfx.DocsOnlyGitCases()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.now = self.fixture.now
        self.service = self.make_service()
        self.pub_result = self.fixture.result()
        self.assertEqual(self.pub_result['status'], 'partial')
        self.op = self.pub_result['operation_id']
        self.target = self.fixture.publisher._target_binding
        self.orig_grant = rec._hash(dp.canonical(self.fixture.request.one_use_grant.statement))
        self.read = self.read_permission(rec.MODE_DOCS, self.op, self.target,
                                         self.orig_grant)

    def inspect(self, permit=None):
        with patch.object(rec.time, 'time', return_value=self.now):
            return self.valid_result(self.service.inspect_docs(
                self.fixture.request, self.fixture.access, permit or self.read))

    def cleanup(self, result, grant):
        with patch.object(rec.time, 'time', return_value=self.now):
            return self.valid_result(self.service.cleanup_docs(
                self.fixture.request, self.fixture.access, result['inspection_id'], grant))

    def permit_cleanup(self, result, changes=None):
        p = self.fixture.work / ('ec229-' + self.op)
        return self.cleanup_permission(self.op, self.target, self.orig_grant,
                         result, self.pub_result['local_candidate_commit_sha'],
                         (os.lstat(p).st_dev, os.lstat(p).st_ino), changes=changes)

    def test_real_git_positive_read_and_exact_clean_worktree(self):
        seen = self.inspect()
        self.valid_result(seen, 'partial')
        self.assertEqual(seen['receipt_state'], 'VERIFIED_PRIVATE_LOCAL_REF_ONLY')
        self.assertFalse(seen['local_worktree_cleanup_confirmed'])
        ref = self.pub_result['private_sandbox_ref']
        commit = self.pub_result['local_candidate_commit_sha']
        permission = self.permit_cleanup(seen)
        clean = self.cleanup(seen, permission)
        self.valid_result(clean, 'partial')
        self.assertTrue(clean['local_worktree_cleanup_confirmed'])
        self.assertFalse((self.fixture.work / ('ec229-' + self.op)).exists())
        self.assertEqual(docsfx.cmd('git', 'rev-parse', ref, cwd=self.fixture.bare), commit)
        self.assertEqual(docsfx.cmd('git', 'rev-parse', 'HEAD', cwd=self.fixture.repo),
                         self.fixture.head)
        self.assertEqual(docsfx.cmd('git', 'status', '--porcelain', cwd=self.fixture.repo), '')
        self.assertTrue((self.fixture.journal / ('ec229-' + self.op)).is_dir())
        self.assertEqual(len(list(Path(self.audit_tmp.name).iterdir())), 2)
        again = self.cleanup(seen, permission)
        self.assertNotEqual(again['status'], 'partial')
        self.assertFalse(again['local_worktree_cleanup_confirmed'])

    def test_inspection_grant_replay_denied(self):
        self.valid_result(self.inspect(), 'partial')
        self.assertIn('CLAIM_SPENT', self.inspect()['reason_code'])

    def test_read_signer_forgery_denied(self):
        forged = signed(self.clean_key, rec.READ_DOMAIN, self.read.statement)
        result = self.inspect(forged)
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(list(Path(self.audit_tmp.name).iterdir()), [])

    def test_original_independent_grant_drift_denied(self):
        req = replace(self.fixture.request, one_use_grant=signed(
            self.fixture.keys[0], gitp.GRANT_DOMAIN,
            self.fixture.request.one_use_grant.statement))
        with patch.object(rec.time, 'time', return_value=self.now):
            out = self.service.inspect_docs(req, self.fixture.access, self.read)
        self.assertNotEqual(out['status'], 'partial')

    def test_missing_private_ref_is_unknown_not_retryable(self):
        docsfx.cmd('git', 'update-ref', '-d', self.pub_result['private_sandbox_ref'],
                   cwd=self.fixture.bare)
        result = self.inspect()
        self.assertEqual(result['receipt_state'], 'UNKNOWN_PRIVATE_REF_ABSENT')
        self.assertFalse(result['original_post_or_push_retried'])
        self.assertFalse(result['external_publication_confirmed'])

    def test_commit_or_ref_conflict_denied(self):
        marker = self.fixture.journal / ('ec229-' + self.op) / '05_COMMIT_CREATED'
        marker.chmod(0o600)
        marker.write_bytes(b'0' * 40)
        result = self.inspect()
        self.assertNotEqual(result['status'], 'partial')

    def test_unrecognized_original_marker_denied(self):
        slot = self.fixture.journal / ('ec229-' + self.op)
        (slot / 'FAKE_COMPLETED').write_text('bad')
        self.assertNotEqual(self.inspect()['status'], 'partial')

    def test_rejected_cleanup_when_unknown_provider_ref(self):
        docsfx.cmd('git', 'update-ref', '-d', self.pub_result['private_sandbox_ref'],
                   cwd=self.fixture.bare)
        observation = self.inspect()
        grant = self.permit_cleanup(observation)
        blocked = self.cleanup(observation, grant)
        self.assertNotEqual(blocked['status'], 'partial')
        self.assertTrue((self.fixture.work / ('ec229-' + self.op)).is_dir())

    def test_cleanup_rejects_extra_ignored_file(self):
        obs = self.inspect()
        worktree = self.fixture.work / ('ec229-' + self.op)
        (worktree / '.gitignore').write_text('ignored.bin\n')
        (worktree / 'ignored.bin').write_text('important')
        rejected = self.cleanup(obs, self.permit_cleanup(obs))
        self.assertNotEqual(rejected['status'], 'partial')
        self.assertTrue((worktree / 'ignored.bin').exists())

    def test_cleanup_rejects_fake_inode_or_stale_ref(self):
        obs = self.inspect()
        bad = self.permit_cleanup(obs, {'worktree_inode': [1, 2]})
        self.assertNotEqual(self.cleanup(obs, bad)['status'], 'partial')
        self.assertTrue((self.fixture.work / ('ec229-' + self.op)).exists())

    def test_reconcile_after_past_revocation_window_with_fresh_read(self):
        # Historic signers' expiry is not a reason to lose readback; it is
        # also not a retroactive assertion they were active at the POST edge.
        future = self.now + 250
        grant = self.read_permission(rec.MODE_DOCS, self.op, self.target,
                    self.orig_grant, nonce='e' * 32,
                    changes={'issued_at': future - 1, 'expires_at': future + 20})
        with patch.object(rec.time, 'time', return_value=future):
            out = self.service.inspect_docs(self.fixture.request, self.fixture.access, grant)
        self.valid_result(out, 'partial')
        self.assertEqual(out['receipt_state'], 'VERIFIED_PRIVATE_LOCAL_REF_ONLY')

    def test_original_publisher_disabled_does_not_disable_independent_receipt(self):
        disabled = replace(self.fixture.access, enable_private_local_sandbox_publish=False)
        with patch.object(rec.time, 'time', return_value=self.now):
            result = self.service.inspect_docs(self.fixture.request, disabled, self.read)
        self.valid_result(result, 'partial')

    def test_after_ambiguous_git_stage_no_forged_positive_receipt(self):
        slot = self.fixture.journal / ('ec229-' + self.op)
        (slot / '06_PUSH_ATTEMPTED').unlink()
        self.assertNotEqual(self.inspect()['status'], 'partial')

    def test_cleanup_untrusted_symlink_file_preserves_local_worktree(self):
        obs = self.inspect()
        worktree = self.fixture.work / ('ec229-' + self.op)
        (worktree / 'hidden_link').symlink_to('/tmp')
        denial = self.cleanup(obs, self.permit_cleanup(obs))
        self.assertNotEqual(denial['status'], 'partial')
        self.assertTrue((worktree / 'hidden_link').is_symlink())

    def test_cleanup_fresh_observation_required(self):
        obs = self.inspect()
        grant = self.permit_cleanup(obs)
        with patch.object(rec.time, 'time', return_value=self.now + 65):
            result = self.service.cleanup_docs(
                self.fixture.request, self.fixture.access, obs['inspection_id'], grant)
        self.valid_result(result)
        self.assertNotEqual(result['status'], 'partial')

    def test_cleanup_rejects_missing_inspection(self):
        fake = {'inspection_id': 'a' * 64, 'observation_sha256': 'b' * 64}
        fake_grant = self.permit_cleanup(fake)
        self.assertNotEqual(self.cleanup(fake, fake_grant)['status'], 'partial')


class ReportReceipts(ReceiptTestBase):
    def setUp(self):
        self.fixture = reportfx.ReportPublishCases()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.now = reportfx.NOW
        self.fake = FakeGET(self.fixture.keys[5])
        self.service = self.make_service(self.fake)
        self.attempt = self.fixture.call()
        self.assertEqual(self.attempt['status'], 'partial')
        self.op = self.attempt['operation_id']
        self.target = self.fixture.publisher._target
        self.orig_grant = rp._digest(self.fixture.req.side_effect_grant)
        self.read = self.read_permission(rec.MODE_REPORT, self.op, self.target,
                                         self.orig_grant)

    def inspect(self, permit=None):
        with patch.object(rec.time, 'time', return_value=self.now):
            return self.valid_result(self.service.inspect_report(
                self.fixture.req, self.fixture.access, permit or self.read))

    def test_provider_signed_created_private_receipt_not_publication(self):
        result = self.inspect()
        self.valid_result(result, 'partial')
        self.assertEqual(result['receipt_state'],
                         'SIGNED_PROVIDER_PRIVATE_TEST_RECORD_OBSERVED')
        self.assertTrue(result['provider_receipt_read_attempted'])
        self.assertEqual(self.fake.calls, 1)
        self.assertEqual(self.fake.last_credential, 'readonly_synthetic_ec230_receipt_token')
        self.assertNotEqual(self.fake.last_credential, self.fixture.access.credential)
        self.assertEqual(self.fixture.port.posts, 1)
        self.assertFalse(result['public_or_production_published'])
        self.assertEqual(len(list(Path(self.fixture.ledger.name).iterdir())), 1)
        self.assertEqual(len(list(Path(self.audit_tmp.name).iterdir())), 1)

    def test_provider_not_found_is_unknown(self):
        self.fake.created = False
        result = self.inspect()
        self.valid_result(result, 'partial')
        self.assertEqual(result['receipt_state'], 'UNKNOWN_PROVIDER_REPORTS_NOT_FOUND')
        self.assertFalse(result['external_publication_confirmed'])

    def test_provider_timeout_fails_closed_and_read_nonce_is_spent(self):
        self.fake.failure = True
        result = self.inspect()
        self.assertEqual(result['status'], 'unavailable')
        self.assertTrue(result['provider_receipt_read_attempted'])
        self.assertEqual(self.fake.calls, 1)
        self.fake.failure = False
        self.assertNotEqual(self.inspect()['status'], 'partial')
        self.assertEqual(self.fake.calls, 1)

    def test_original_send_disabled_still_allows_new_read_permission(self):
        disabled = replace(self.fixture.access, enable_private_test_publish=False)
        with patch.object(rec.time, 'time', return_value=self.now):
            result = self.service.inspect_report(self.fixture.req, disabled, self.read)
        self.valid_result(result, 'partial')
        self.assertEqual(self.fake.calls, 1)

    def test_historically_expired_report_permission_still_signed(self):
        future = self.now + 240
        late = self.read_permission(rec.MODE_REPORT, self.op, self.target,
                    self.orig_grant, nonce='e' * 32,
                    changes={'issued_at': future - 2, 'expires_at': future + 20})
        # Signed Provider observation must itself remain current at future.
        old_read = self.fake.read
        def fresh_read(t, cred, challenge):
            signed_old = old_read(t, cred, challenge)
            body = dict(signed_old.statement)
            body['issued_at'] = future - 1
            body['expires_at'] = future + 12
            return signed(self.fixture.keys[5], rec.PROVIDER_DOMAIN, body)
        self.fake.read = fresh_read
        with patch.object(rec.time, 'time', return_value=future):
            result = self.service.inspect_report(self.fixture.req, self.fixture.access, late)
        self.valid_result(result, 'partial')

    def test_report_untrusted_read_credential_rejected_before_get(self):
        newhost = replace(self.service.host,
                          provider_read_credential=self.fixture.access.credential)
        other = rec.PublicationReceiptService(newhost, reader=self.fake)
        with patch.object(rec.time, 'time', return_value=self.now):
            out = other.inspect_report(self.fixture.req, self.fixture.access, self.read)
        self.assertNotEqual(out['status'], 'partial')
        self.assertEqual(self.fake.calls, 0)

    def test_provider_record_id_hash_invalid(self):
        self.fake.mutations = {'record_id_sha256': None}
        self.assertNotEqual(self.inspect()['status'], 'partial')

    def test_untrusted_private_claim_denied(self):
        self.fake.mutations = {'private_sandbox': False}
        self.assertNotEqual(self.inspect()['status'], 'partial')

    def test_challenge_mismatch_denied(self):
        self.fake.mutations = {'challenge_nonce': 'a' * 32}
        self.assertNotEqual(self.inspect()['status'], 'partial')

    def test_no_original_post_marker_denies_external_request(self):
        marker = Path(self.fixture.ledger.name) / ('ec228-' + self.op) / '03_POST_ATTEMPTED'
        marker.unlink()
        result = self.inspect()
        self.assertNotEqual(result['status'], 'partial')
        self.assertEqual(self.fake.calls, 0)

    def test_mismatched_report_origin_denies_provider_get(self):
        forged = replace(self.fixture.req, rendered_sha256='0' * 64)
        with patch.object(rec.time, 'time', return_value=self.now):
            result = self.service.inspect_report(forged, self.fixture.access, self.read)
        self.assertNotEqual(result['status'], 'partial')
        self.assertEqual(self.fake.calls, 0)

    def test_expired_read_grant_denies_provider_get(self):
        expired = self.read_permission(rec.MODE_REPORT, self.op, self.target,
                    self.orig_grant, changes={'issued_at': self.now - 100,
                                              'expires_at': self.now - 70})
        self.assertNotEqual(self.inspect(expired)['status'], 'partial')
        self.assertEqual(self.fake.calls, 0)


if __name__ == '__main__':
    unittest.main()
