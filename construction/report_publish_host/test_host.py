#!/usr/bin/env python3
"""EC289 focused LOCAL ONLY: genuine original EC228 with simulated provider HTTPS.

Actual immutable EC199/200 report, original five signatures, real Ed25519
host votes, AF_UNIX kernel peer UID and durable two-level ledgers are used.
Provider /capability and /publish are stubs; NO network side effect occurs.
"""
from __future__ import annotations

from dataclasses import replace
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from finding_query_host import protocol as io
from . import protocol as p, operator as op, daemon
import report_publish as rp
import test_report_publish as test_orig


class EC289HostCases(unittest.TestCase):
    def setUp(self):
        self.old_now = test_orig.NOW
        test_orig.NOW = int(time.time())
        self.addCleanup(lambda: setattr(test_orig, 'NOW', self.old_now))
        self.fx = test_orig.ReportPublishCases()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.tmp = tempfile.TemporaryDirectory(prefix='ces-ec289-host-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.pub = [p.public_hex(x) for x in self.keys]
        self.job = p.encode_original_request(self.fx.req)
        self.trust = {
            'schema': p.TRUST_SCHEMA,
            'enable_live_private_publication': True,
            'roots': {
                'issuer_id': self.fx.roots.issuer_id,
                'operator_id': self.fx.roots.operator_id,
                'minimum_policy_epoch': self.fx.roots.minimum_policy_epoch,
                **{field: pub.hex() for field, pub in zip(
                    p.original_key_fields(), (
                        self.fx.roots.organization_public_key,
                        self.fx.roots.route_public_key,
                        self.fx.roots.revocation_public_key,
                        self.fx.roots.content_reviewer_public_key,
                        self.fx.roots.side_effect_public_key,
                        self.fx.roots.provider_public_key))}},
            'target': {k: getattr(self.fx.target, k) for k in (
                'provider_id', 'account_id', 'project_id',
                'destination_id', 'endpoint', 'sandbox_private',
                'single_destination')},
        }
        op.write_private(str(self.root / 'job.json'), self.job, p.MAX_JOB)
        op.write_private(str(self.root / 'trust.json'), self.trust, p.MAX_TRUST)
        (self.root / 'token.txt').write_bytes(b'local_fake_token_provisioned_not_real')
        os.chmod(self.root / 'token.txt', 0o600)
        for folder in ('original-outbox', 'admissions', 'sockets'):
            (self.root / folder).mkdir(mode=0o700)
        for role, key in zip(('custodian', 'publisher', 'server'), self.keys):
            path = self.root / (role + '.key')
            path.write_bytes(key.private_bytes_raw())
            os.chmod(path, 0o600)
        pol = op.prepare_policy(
            job_file=str(self.root / 'job.json'),
            trust_file=str(self.root / 'trust.json'),
            credential_file=str(self.root / 'token.txt'),
            outbox_root=str(self.root / 'original-outbox'),
            admission_root=str(self.root / 'admissions'),
            allowed_uids=[os.getuid()], custodian_pub=self.pub[0],
            publisher_pub=self.pub[1], server_pub=self.pub[2],
            out=str(self.root / 'policy.json'), enable=True)
        self.policy_sha = pol['policy_sha256']
        self.host = None
        self.thread = None
        self.fake = test_orig.FakePrivateProvider(self.fx.keys[5])

    def build_grant(self):
        base = self.root / ('grants-' + os.urandom(5).hex())
        base.mkdir(mode=0o700)
        subject = base / 'subject.json'
        op.prepare_subject(str(self.root / 'policy.json'), self.policy_sha,
                           os.getuid(), 20, str(subject))
        votes = []
        for role in ('custodian', 'publisher'):
            vote_path = base / (role + '.vote')
            op.vote(role, str(subject), str(self.root / (role + '.key')),
                    str(vote_path))
            votes.append(str(vote_path))
        grant = base / 'grant.json'
        op.assemble(str(subject), votes[0], votes[1], self.pub[0], self.pub[1],
                    str(grant))
        return str(grant)

    def start(self):
        self.host = daemon.ReportPublishHost(
            path=str(self.root / 'sockets' / 'host.sock'),
            policy_path=str(self.root / 'policy.json'),
            policy_sha=self.policy_sha,
            private_key_file=str(self.root / 'server.key'))
        self.addCleanup(self.host.server_close)
        self.thread = threading.Thread(target=self.host.serve_forever,
                                       kwargs={'poll_interval': .02}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        if self.host is not None and self.thread is not None and self.thread.is_alive():
            self.host.shutdown()
            self.thread.join(timeout=3)

    def invoke(self, grant: str):
        return op.submit(socket_path=str(self.root / 'sockets' / 'host.sock'),
                         grant_file=grant, policy_sha=self.policy_sha,
                         server_pub=self.pub[2], timeout=10)

    def mocked_provider(self):
        fake = self.fake
        def capability(_port, target, cred, challenge):
            return fake.capability(target, cred, challenge)
        def publish(_port, target, cred, body, operation):
            return fake.publish(target, cred, body, operation)
        class ProviderContext:
            def __enter__(nested):
                nested.a = patch.object(rp.HTTPSPrivatePublishTransport,
                                        'capability', capability)
                nested.b = patch.object(rp.HTTPSPrivatePublishTransport,
                                        'publish', publish)
                nested.a.start(); nested.b.start()
                return nested
            def __exit__(nested, *args):
                nested.b.stop(); nested.a.stop()
        return ProviderContext()

    def assert_receipt(self, rc, out, state='partial'):
        self.assertEqual(out['schema'], p.RESULT_SCHEMA)
        self.assertTrue(out['verified_server_signature'])
        self.assertEqual(out['result']['status'], state, out)
        self.assertEqual(rc, out['result']['exit_code'])
        self.assertFalse(out['published_or_remote_visibility_verified'])
        self.assertFalse(out['automatic_publish_retry_allowed'])
        self.assertFalse(out['private_markdown_endpoint_or_credential_returned'])

    def test_01_roundtrip_actual_saved_report_and_original_ec228(self):
        self.start()
        with self.mocked_provider():
            rc, out = self.invoke(self.build_grant())
        self.assert_receipt(rc, out)
        self.assertEqual(self.fake.probes, 1)
        self.assertEqual(self.fake.posts, 1)
        self.assertEqual(out['result']['publication_state'], 'SUBMISSION_UNCONFIRMED')
        self.assertTrue(out['provider_http_only_not_publication'])
        self.assertEqual(self.fake.last_body['report_ref'], self.fx.req.report_ref)
        self.assertEqual(self.fake.last_body['rendered_sha256'], self.fx.req.rendered_sha256)
        self.assertEqual(len(list((self.root / 'admissions').glob('ec289-*'))), 1)
        entries = list((self.root / 'original-outbox').glob('ec228-*'))
        self.assertEqual(len(entries), 1)
        self.assertTrue((entries[0] / '03_POST_ATTEMPTED').is_file())
        self.assertTrue((entries[0] / '04_POST_RETURNED').is_file())
        self.assertFalse(out['result']['published'])

    def test_02_same_host_grant_replay_never_posts_twice(self):
        self.start()
        grant = self.build_grant()
        with self.mocked_provider():
            self.assertEqual(self.invoke(grant)[0], 2)
            rc, out = self.invoke(grant)
        self.assert_receipt(rc, out, 'permission_denied')
        self.assertTrue(out['publication_outcome_unknown'])
        self.assertIn('ALREADY_SPENT', out['result']['reason_code'])
        self.assertEqual(self.fake.posts, 1)

    def test_03_fresh_host_grant_cannot_republish_original_operation(self):
        self.start()
        with self.mocked_provider():
            self.assertEqual(self.invoke(self.build_grant())[0], 2)
            rc, out = self.invoke(self.build_grant())
        self.assert_receipt(rc, out, 'blocked')
        self.assertIn('ALREADY_CLAIMED', out['result']['reason_code'])
        self.assertEqual((self.fake.probes, self.fake.posts), (1, 1))
        self.assertEqual(len(list((self.root / 'admissions').glob('ec289-*'))), 2)
        self.assertEqual(len(list((self.root / 'original-outbox').glob('ec228-*'))), 1)

    def test_04_wrong_host_vote_no_provider_egress(self):
        self.start()
        grant = self.build_grant()
        data = io.read_doc(grant, 8192)
        data['publisher_signature_ed25519'] = '0' * 128
        swapped = self.root / 'tampered.vote'
        io.write_exclusive(str(swapped), data)
        with self.mocked_provider():
            rc, out = self.invoke(str(swapped))
        self.assert_receipt(rc, out, 'permission_denied')
        self.assertEqual((self.fake.probes, self.fake.posts), (0, 0))
        self.assertEqual(list((self.root / 'admissions').iterdir()), [])

    def test_05_wrong_uid_denied_before_host_grant_spent(self):
        self.start()
        grant = self.build_grant()
        data = io.read_doc(grant, 8192)
        data['subject']['uid'] = min(os.getuid() + 1, 2**31 - 1)
        changed = self.root / 'bad-uid.json'
        io.write_exclusive(str(changed), data)
        rc, out = self.invoke(str(changed))
        self.assert_receipt(rc, out, 'permission_denied')
        self.assertFalse(out['publication_outcome_unknown'])

    def test_06_changed_private_credential_detected_without_send(self):
        grant = self.build_grant()
        self.start()
        (self.root / 'token.txt').write_bytes(b'different_new_token_not_approved')
        with self.mocked_provider():
            rc, out = self.invoke(grant)
        self.assert_receipt(rc, out, 'unavailable')
        self.assertEqual(self.fake.posts, 0)
        self.assertEqual(list((self.root / 'admissions').iterdir()), [])

    def test_07_wrong_target_or_duplicate_orig_root_denied(self):
        trust = copy.deepcopy(self.trust)
        trust['target']['sandbox_private'] = False
        with self.assertRaises(p.HostError):
            p.validate_trust(trust)
        trust = copy.deepcopy(self.trust)
        trust['roots']['provider_public_hex'] = trust['roots']['side_effect_public_hex']
        with self.assertRaises(ValueError):
            p.build_publisher(trust, 'test_token_with_length_12345',
                              str(self.root / 'original-outbox'))

    def test_08_provider_capability_denied_and_no_second_attempt(self):
        self.start()
        self.fake.mutations = {'create_only': False}
        with self.mocked_provider():
            rc, out = self.invoke(self.build_grant())
            self.assert_receipt(rc, out, 'blocked')
            self.assertEqual(self.fake.posts, 0)
            rc2, other = self.invoke(self.build_grant())
        self.assert_receipt(rc2, other, 'blocked')
        self.assertEqual(self.fake.probes, 1)
        self.assertTrue(out['result']['claim_committed'])

    def test_09_provider_timeout_post_unknown_and_no_retry(self):
        self.start()
        self.fake.fail_post = True
        with self.mocked_provider():
            rc, out = self.invoke(self.build_grant())
            rc2, dup = self.invoke(self.build_grant())
        self.assert_receipt(rc, out, 'unavailable')
        self.assertEqual(out['result']['publication_state'], 'UNKNOWN_UNCONFIRMED')
        self.assertTrue(out['publication_outcome_unknown'])
        self.assertEqual(self.fake.posts, 1)
        self.assert_receipt(rc2, dup, 'blocked')
        entries = list((self.root / 'original-outbox').glob('ec228-*'))
        self.assertTrue((entries[0] / '05_POST_UNKNOWN').is_file())

    def test_10_changed_original_signed_review_denied_without_host_admission(self):
        grant = self.build_grant()
        self.start()
        # Change report-store immutable Markdown bytes; original EC228 checks
        # exact private source and never contacts provider.
        saved = (Path(self.fx.tmp.name) / '.ces-report-render-v1' /
                 ('report-' + self.fx.req.report_ref[len('cesrr1:'):] + '.md'))
        saved.write_bytes(b'rewritten without authenticated review')
        with self.mocked_provider():
            rc, out = self.invoke(grant)
        self.assert_receipt(rc, out, 'unavailable')
        self.assertEqual((self.fake.probes, self.fake.posts), (0, 0))
        self.assertEqual(list((self.root / 'admissions').iterdir()), [])

    def test_11_synthetic_result_cannot_claim_publication(self):
        good = rp._refused('TEST_DENIAL', 'blocked')
        forged = {**good, 'published': True}
        with self.assertRaises(p.HostError):
            p.validate_backend(forged)
        forged = {**good, 'attempt_receipt_id': 'cesrp1:' + '1' * 64}
        with self.assertRaises(p.HostError):
            p.validate_backend(forged)

    def test_12_original_console_remains_default_denied(self):
        root = Path(__file__).resolve().parents[2]
        script = root / 'scripts' / 'ces_next.py'
        def run(*args):
            cp = subprocess.run([sys.executable, '-I', '-B', str(script), *args],
                                capture_output=True, text=True, timeout=18)
            return cp.returncode, json.loads(cp.stdout)
        rc, output = run('run', 'ReportPublish', 'PrivateTest',
                         '--request-file', str(self.root / 'nothing.json'))
        self.assertEqual(rc, 3)
        self.assertEqual(output['reason_code'],
                         'EC278_INDEPENDENT_HOST_BRIDGE_REQUIRED')
        rc, output = run('host-publish', 'DeliverySend', 'Send',
                         '--socket', str(self.root / 'sockets' / 'host.sock'),
                         '--grant-file', str(self.root / 'nothing.json'),
                         '--policy-sha256', self.policy_sha,
                         '--server-public-hex', self.pub[2])
        self.assertEqual(rc, 3)
        self.assertIn('ONLY_REPORTPUBLISH', output['reason_code'])
        rc, output = run('routes', '--kind', 'host')
        self.assertEqual(rc, 0)
        self.assertEqual(len(output['routes']), 11)

    def test_13_real_console_subprocess_verifies_host_reply(self):
        self.start()
        grant = self.build_grant()
        with self.mocked_provider():
            cp = subprocess.run(
                [sys.executable, '-I', '-B',
                 str(Path(__file__).resolve().parents[2] / 'scripts' / 'ces_next.py'),
                 'host-publish', 'ReportPublish', 'PrivateTest',
                 '--socket', str(self.root / 'sockets' / 'host.sock'),
                 '--grant-file', grant, '--policy-sha256', self.policy_sha,
                 '--server-public-hex', self.pub[2]],
                capture_output=True, text=True, timeout=20)
        self.assertEqual(cp.returncode, 2, cp.stdout + cp.stderr)
        data = json.loads(cp.stdout)
        self.assert_receipt(cp.returncode, data)
        self.assertEqual(self.fake.posts, 1)

    def test_14_host_keys_are_independent_of_six_original_signers(self):
        broken = copy.deepcopy(self.trust)
        overlap = broken['roots']['provider_public_hex']
        with self.assertRaises(p.HostError):
            op.prepare_policy(
                job_file=str(self.root / 'job.json'),
                trust_file=str(self.root / 'trust.json'),
                credential_file=str(self.root / 'token.txt'),
                outbox_root=str(self.root / 'original-outbox'),
                admission_root=str(self.root / 'admissions'),
                allowed_uids=[os.getuid()], custodian_pub=overlap,
                publisher_pub=self.pub[1], server_pub=self.pub[2],
                out=str(self.root / 'should-not-write-policy.json'), enable=True)


if __name__ == '__main__':
    unittest.main()
