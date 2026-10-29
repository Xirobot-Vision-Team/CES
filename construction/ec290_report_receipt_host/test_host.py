#!/usr/bin/env python3
"""EC290 LOCAL tests; original EC228/230 are real, provider wire is MOCK ONLY.

Never performs real TLS/network publication or receipt GET. These tests do not
certify real corporate key separation, operator trust, OS portability, remote
receipt availability or original PowerShell smoke suites.
"""
from __future__ import annotations

import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec279_finding_query_host import protocol as io
from ec289_report_publish_host import protocol as prev
from . import protocol as p, daemon, operator as op
import publication_receipts as rec
import report_publish as rp
import test_publication_receipts as original_rec
import test_report_publish as original_pub


class EC290ReadbackCases(unittest.TestCase):
    def setUp(self):
        old = original_pub.NOW
        original_pub.NOW = int(time.time())
        self.addCleanup(lambda: setattr(original_pub, 'NOW', old))
        self.fixture = original_pub.ReportPublishCases()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.tmp = tempfile.TemporaryDirectory(prefix='ces-ec290-readback-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pubkey = [Ed25519PrivateKey.generate() for _ in range(5)]
        self.public = [prev.public_hex(x) for x in self.pubkey]
        self.files = {}
        for role, key in zip(('read', 'cleanup', 'custodian', 'inspector', 'server'),
                             self.pubkey):
            fp = self.root / (role + '.key')
            fp.write_bytes(key.private_bytes_raw())
            os.chmod(fp, 0o600)
            self.files[role] = str(fp)
        job = prev.encode_original_request(self.fixture.req)
        trust = {
            'schema': prev.TRUST_SCHEMA, 'enable_live_private_publication': True,
            'roots': {'issuer_id': self.fixture.roots.issuer_id,
                      'operator_id': self.fixture.roots.operator_id,
                      'minimum_policy_epoch': self.fixture.roots.minimum_policy_epoch,
                      **{name: value.hex() for name, value in zip(
                          prev.original_key_fields(), (
                              self.fixture.roots.organization_public_key,
                              self.fixture.roots.route_public_key,
                              self.fixture.roots.revocation_public_key,
                              self.fixture.roots.content_reviewer_public_key,
                              self.fixture.roots.side_effect_public_key,
                              self.fixture.roots.provider_public_key))}},
            'target': {k: getattr(self.fixture.target, k) for k in (
                'provider_id', 'account_id', 'project_id', 'destination_id',
                'endpoint', 'sandbox_private', 'single_destination')},
        }
        for name, data, limit in (('job.json', job, prev.MAX_JOB),
                                   ('trust.json', trust, prev.MAX_TRUST)):
            op.write_private(str(self.root / name), data, limit)
        (self.root / 'read.token').write_bytes(b'local_read_only_provider_token_for_mock')
        for name in ('read.token',):
            os.chmod(self.root / name, 0o600)
        for folder in ('audit', 'admission', 'socket', 'original-outbox'):
            (self.root / folder).mkdir(mode=0o700)
        # EC289/290 require the original outbox parent to be owner-private;
        # the standalone EC228 fixture defaults to a direct /tmp directory.
        self.fixture.access = replace(self.fixture.access,
            outbox_root=str(self.root / 'original-outbox'))
        self.fixture.publisher = rp.ReportPublisher(
            self.fixture.access, self.fixture.port)
        self.polpath = str(self.root / 'policy.json')
        result = op.prepare_policy(
            job_file=str(self.root / 'job.json'),
            trust_file=str(self.root / 'trust.json'),
            read_credential_file=str(self.root / 'read.token'),
            outbox_root=str(self.root / 'original-outbox'),
            audit_root=str(self.root / 'audit'),
            admission_root=str(self.root / 'admission'),
            allowed_uids=[os.getuid()], read_public_hex=self.public[0],
            cleanup_public_hex=self.public[1], receipt_epoch=4,
            custodian_public_hex=self.public[2],
            inspector_public_hex=self.public[3],
            server_public_hex=self.public[4], out=self.polpath, enable=True)
        self.polsha = result['policy_sha256']
        self.assertFalse(result['original_ec228_write_credential_loaded'])
        self.socket = str(self.root / 'socket' / 'host.sock')
        self.host = None
        self.thread = None
        self.mock = original_rec.FakeGET(self.fixture.keys[5])
        self.published = False

    def original_publish(self):
        if not self.published:
            out = self.fixture.publisher.publish_once(self.fixture.req)
            self.assertEqual(out['status'], 'partial', out)
            self.assertEqual(self.fixture.port.posts, 1)
            self.published = True

    def grant(self) -> tuple[str, str]:
        folder = self.root / ('vote-' + os.urandom(5).hex())
        folder.mkdir(mode=0o700)
        template = str(folder / 'template.json')
        read = str(folder / 'read.json')
        subject = str(folder / 'subject.json')
        a, b = str(folder / 'a.json'), str(folder / 'b.json')
        allvotes = str(folder / 'grant.json')
        op.prepare_read_template(self.polpath, self.polsha, 34, template)
        op.sign_read_template(template, self.files['read'], read)
        op.prepare_subject(self.polpath, self.polsha, read, os.getuid(), 24, subject)
        op.vote('custodian', subject, self.files['custodian'], a)
        op.vote('inspector', subject, self.files['inspector'], b)
        op.assemble(subject, a, b, self.public[2], self.public[3], allvotes)
        return allvotes, read

    def start(self):
        self.host = daemon.ReceiptHost(
            path=self.socket, policy_path=self.polpath,
            policy_sha=self.polsha, private_key_file=self.files['server'])
        self.addCleanup(self.host.server_close)
        self.thread = threading.Thread(target=self.host.serve_forever,
                kwargs={'poll_interval': .02}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        if self.host and self.thread and self.thread.is_alive():
            self.host.shutdown()
            self.thread.join(timeout=3)

    def invoke(self, grant, read):
        return op.submit(socket_path=self.socket, grant_file=grant,
                         read_grant_file=read, policy_sha=self.polsha,
                         server_pub=self.public[4], timeout=12)

    def simulated_get(self):
        fake = self.mock
        def read(_reader, target, credential, challenge):
            return fake.read(target, credential, challenge)
        return patch.object(rec.HTTPSPrivateReceiptReader, 'read', read)

    def test_01_original_publish_and_signed_private_record_observed(self):
        self.original_publish()
        self.start()
        with self.simulated_get():
            rc, out = self.invoke(*self.grant())
        self.assertEqual(rc, 2, out)
        self.assertTrue(out['verified_server_signature'])
        self.assertTrue(out['independent_private_provider_record_observed'])
        self.assertEqual(out['result']['receipt_state'],
                         'SIGNED_PROVIDER_PRIVATE_TEST_RECORD_OBSERVED')
        self.assertEqual(self.mock.calls, 1)
        self.assertEqual(self.fixture.port.posts, 1)
        self.assertFalse(out['public_or_production_published'])
        self.assertFalse(out['publish_retry_allowed'])
        self.assertEqual(len(list((self.root / 'admission').glob('ec290-*'))), 1)
        observations = list((self.root / 'audit').glob('ec230-read-*'))
        self.assertEqual(len(observations), 1)
        self.assertTrue((observations[0] / '02_OBSERVATION').is_file())
        self.assertTrue((observations[0] / '01_ATTEMPT').is_file())

    def test_02_provider_says_missing_is_unknown_not_absence_proof(self):
        self.original_publish()
        self.start()
        self.mock.created = False
        with self.simulated_get():
            rc, out = self.invoke(*self.grant())
        self.assertEqual(rc, 2, out)
        self.assertEqual(out['result']['receipt_state'],
                         'UNKNOWN_PROVIDER_REPORTS_NOT_FOUND')
        self.assertFalse(out['independent_private_provider_record_observed'])
        self.assertFalse(out['automatic_provider_read_retry_allowed'])

    def test_03_same_exact_grant_replay_spent_only_one_get(self):
        self.original_publish()
        self.start()
        files = self.grant()
        with self.simulated_get():
            self.assertEqual(self.invoke(*files)[0], 2)
            rc, out = self.invoke(*files)
        self.assertEqual(rc, 3)
        self.assertIn('ALREADY_SPENT', out['result']['reason_code'])
        self.assertEqual(self.mock.calls, 1)
        self.assertTrue(out['result']['provider_readback_may_have_been_attempted'])

    def test_04_different_host_voter_with_same_ec230_read_grant_cannot_reget(self):
        self.original_publish()
        self.start()
        grant, read = self.grant()
        with self.simulated_get():
            self.assertEqual(self.invoke(grant, read)[0], 2)
            # New *independent* host votes, same independent EC230 nonce.
            newsub = str(self.root / 'newsubject.json')
            op.prepare_subject(self.polpath, self.polsha, read, os.getuid(), 24,
                               newsub)
            a, b, out = (str(self.root / x) for x in ('avote.json',
                                                      'bvote.json', 'grant2.json'))
            op.vote('custodian', newsub, self.files['custodian'], a)
            op.vote('inspector', newsub, self.files['inspector'], b)
            op.assemble(newsub, a, b, self.public[2], self.public[3], out)
            rc, data = self.invoke(out, read)
        self.assertEqual(rc, 4)
        self.assertIn('CLAIM_SPENT', data['result']['reason_code'])
        self.assertEqual(self.mock.calls, 1)
        self.assertEqual(len(list((self.root / 'admission').iterdir())), 2)

    def test_05_no_original_post_attempt_never_consumes_admission_or_get(self):
        self.start()
        with self.simulated_get():
            rc, result = self.invoke(*self.grant())
        self.assertNotEqual(rc, 2)
        self.assertEqual(self.mock.calls, 0)
        self.assertEqual(list((self.root / 'admission').iterdir()), [])

    def test_06_tampered_ec230_read_signature_refused_before_claim(self):
        self.original_publish()
        self.start()
        grant, read = self.grant()
        body = io.read_doc(read, 4000, private=True)
        body['signature_hex'] = '0' * 128
        changed = str(self.root / 'changed_read.json')
        op.write_private(changed, body, 4000)
        with self.simulated_get():
            with self.assertRaisesRegex(p.HostError,
                                        'EC290_CLIENT_SIGNED_READ_SUBJECT_CHANGED'):
                self.invoke(grant, changed)
        self.assertEqual(self.mock.calls, 0)
        self.assertEqual(list((self.root / 'admission').iterdir()), [])

    def test_07_tampered_host_inspector_vote_refused(self):
        self.original_publish()
        self.start()
        grant, read = self.grant()
        body = io.read_doc(grant, p.MAX_RPC, private=True)
        body['inspector_signature_ed25519'] = '0' * 128
        altered = str(self.root / 'altered_vote.json')
        op.write_private(altered, body, p.MAX_RPC)
        with self.simulated_get():
            rc, out = self.invoke(altered, read)
        self.assertEqual(rc, 3)
        self.assertEqual(self.mock.calls, 0)
        self.assertEqual(list((self.root / 'admission').iterdir()), [])

    def test_08_original_job_or_read_token_raw_bytes_drift_fail_closed(self):
        self.original_publish()
        self.start()
        grant, read = self.grant()
        path = self.root / 'read.token'
        path.write_bytes(b'changed_read_token_does_not_match_hash')
        with self.simulated_get():
            rc, out = self.invoke(grant, read)
        self.assertEqual(rc, 3)
        self.assertEqual(self.mock.calls, 0)
        self.assertEqual(list((self.root / 'admission').iterdir()), [])

    def test_09_provider_timeout_unknown_ledger_not_retried(self):
        self.original_publish()
        self.start()
        self.mock.failure = True
        with self.simulated_get():
            rc, out = self.invoke(*self.grant())
        self.assertEqual(rc, 5)
        self.assertEqual(self.mock.calls, 1)
        self.assertFalse(out['independent_private_provider_record_observed'])
        self.assertTrue(out['result']['provider_receipt_read_attempted'])
        self.assertEqual(len(list((self.root / 'audit').iterdir())), 1)
        self.assertEqual(len(list((self.root / 'admission').iterdir())), 1)

    def test_10_console_exact_route_and_original_router_denial(self):
        root = Path(__file__).resolve().parents[2]
        cli = root / 'scripts' / 'ces_next.py'
        self.original_publish()
        self.start()
        grant, read = self.grant()
        base = [sys.executable, str(cli), 'host-receipt', 'ReportPublish',
                'Readback', '--socket', self.socket, '--grant-file', grant,
                '--read-grant-file', read, '--policy-sha256', self.polsha,
                '--server-public-hex', self.public[4]]
        with self.simulated_get():
            proc = subprocess.run(base, cwd=root, capture_output=True, text=True)
        # In subprocess the mock is not in the server process; server is in the
        # current process on a background thread, so the mock is still active.
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out['result']['schema'], rec.SCHEMA)
        self.assertTrue(out['verified_server_signature'])
        bad = subprocess.run(base[:3] + ['PrivateTest'] + base[4:],
                             cwd=root, capture_output=True, text=True)
        self.assertEqual(bad.returncode, 3, bad.stdout)
        self.assertEqual(json.loads(bad.stdout)['status'], 'permission_denied')
        desc = subprocess.run([sys.executable, str(cli), 'describe',
                               'ReportPublish', 'PrivateTest'], cwd=root,
                              capture_output=True, text=True)
        self.assertEqual(desc.returncode, 0)
        self.assertTrue(json.loads(desc.stdout)['requires_independent_host'])


    def test_11_valid_two_host_signatures_but_wrong_kernel_uid_rejected(self):
        self.original_publish()
        self.start()
        grant, read = self.grant()
        doc = io.read_doc(grant, p.MAX_RPC, private=True)
        doc['subject']['uid'] = os.getuid() + 1
        doc['custodian_signature_ed25519'] = p.sign(
            'custodian', doc['subject'], self.pubkey[2])
        doc['inspector_signature_ed25519'] = p.sign(
            'inspector', doc['subject'], self.pubkey[3])
        wrong = str(self.root / 'wrong_uid.json')
        op.write_private(wrong, doc, p.MAX_RPC)
        with self.simulated_get():
            rc, result = self.invoke(wrong, read)
        self.assertEqual(rc, 3, result)
        self.assertIn('UID_GRANT_OR_PIN_DRIFT', result['result']['reason_code'])
        self.assertEqual(self.mock.calls, 0)
        self.assertEqual(list((self.root / 'admission').iterdir()), [])

    def test_12_provider_sends_signed_but_wrong_target_never_becomes_proof(self):
        self.original_publish()
        self.start()
        self.mock.mutations = {'target_sha256': 'f' * 64}
        with self.simulated_get():
            rc, result = self.invoke(*self.grant())
        self.assertEqual(rc, 4, result)
        self.assertEqual(self.mock.calls, 1)
        self.assertIn('UNTRUSTED_OR_CONFLICTING_PROVIDER_RECEIPT',
                      result['result']['reason_code'])
        self.assertFalse(result['independent_private_provider_record_observed'])
        audit = list((self.root / 'audit').iterdir())
        self.assertEqual(len(audit), 1)
        self.assertTrue((audit[0] / '01_ATTEMPT').is_file())
        self.assertFalse((audit[0] / '02_OBSERVATION').exists())

    def test_13_valid_host_votes_cannot_authorize_forged_read_signer(self):
        self.original_publish()
        self.start()
        grant, read = self.grant()
        forged = io.read_doc(read, 4000, private=True)
        forged_key = Ed25519PrivateKey.generate()
        forged['signature_hex'] = forged_key.sign(
            rec.READ_DOMAIN + p.canonical(forged['statement'])).hex()
        doc = io.read_doc(grant, p.MAX_RPC, private=True)
        doc['subject']['read_grant_sha256'] = p.sha(p.canonical(forged))
        doc['custodian_signature_ed25519'] = p.sign(
            'custodian', doc['subject'], self.pubkey[2])
        doc['inspector_signature_ed25519'] = p.sign(
            'inspector', doc['subject'], self.pubkey[3])
        # Bypass the honest client locally: issue a complete unauthorized
        # RPC directly to prove the server does its own EC230 key validation.
        import socket
        request = {'schema': p.REQUEST_SCHEMA, 'nonce': os.urandom(16).hex(),
                   'grant': doc, 'read_grant': forged}
        with self.simulated_get():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect(self.socket)
                sock.sendall(p.canonical(request) + b'\n')
                wire = sock.recv(17000)
        reply = io.parse(wire.strip(), p.MAX_REPLY)
        res = p.verify_reply(reply, request, self.public[4], self.polsha,
                             int(time.time()))
        self.assertEqual(res['status'], 'permission_denied', res)
        self.assertIn('READ_GRANT_DENIED', res['reason_code'])
        self.assertEqual(self.mock.calls, 0)
        self.assertEqual(list((self.root / 'admission').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
