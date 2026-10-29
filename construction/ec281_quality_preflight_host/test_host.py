#!/usr/bin/env python3
"""Focused EC281 real AF_UNIX / real EC186 local development scenarios.

SYNTHETIC HMAC issuers and 3 co-located Ed25519 keys. These tests do not prove
production authority, trusted broker OCI isolation, lease custody or CI PASS.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
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

HERE = Path(__file__).resolve()
CONSTRUCTION = HERE.parents[1]
ROOT = CONSTRUCTION.parent
sys.path.insert(0, str(CONSTRUCTION))

from ec279_finding_query_host import protocol as io
from ec280_quality_query_host import protocol as quality_io
from ec281_quality_preflight_host import daemon, operator, protocol as p
import quality_detect as detect
import quality_run_guard as guard


def secret_file(path: Path, raw: bytes) -> Path:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw)
    return path

def doc_file(path: Path, obj: dict) -> Path:
    return secret_file(path, p.canonical(obj) + b'\n')

def mac(key: bytes, domain: bytes, obj: dict) -> str:
    return hmac.new(key, domain + guard._canonical(obj), hashlib.sha256).hexdigest()

def stamp(t: datetime) -> str:
    return t.isoformat(timespec='seconds').replace('+00:00', 'Z')


class PreflightFixture(unittest.TestCase):
    def setUp(self):
        if not hasattr(__import__('socket'), 'SO_PEERCRED'):
            self.skipTest('Linux kernel peer UID not available')
        self.temp = tempfile.TemporaryDirectory(prefix='ec281_host_')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / 'repo'
        self.repo.mkdir(mode=0o700)
        self.profile_id = 'python.pytest'
        self.profile_sha = guard.catalog_entry(self.profile_id)['profile_sha256']
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.pin = detect.QualityDetector.observe_root(
            str(self.repo), authorize_observation=lambda _: True)
        pin_sha = detect._sha(detect.DOMAIN_PIN, self.pin)
        self.policy_key = os.urandom(48)
        self.broker_key = os.urandom(48)
        self.approval = {
            'schema': guard.APPROVAL_SCHEMA,
            'ticket_id': 'approval_ec281_local_AA',
            'profile_id': self.profile_id,
            'profile_sha256': self.profile_sha,
            'source_pin_sha256': pin_sha,
            'issued_at_utc': stamp(now),
            'expires_at_utc': stamp(now + timedelta(seconds=100)),
            'approved_purpose': guard.BUILTIN_PROFILES[self.profile_id]['purpose'],
        }
        self.approval['mac_sha256'] = mac(
            self.policy_key, guard.DOMAIN_APPROVAL, self.approval)
        self.lease = {
            'schema': guard.LEASE_SCHEMA,
            'ticket_id': 'lease_ec281_local_AA',
            'source_pin_sha256': pin_sha,
            'profile_sha256': self.profile_sha,
            'approval_receipt_sha256':
                guard._digest(guard.DOMAIN_RECEIPT, self.approval),
            'image_sha256': '8' * 64,
            'controls': dict(guard.REQUIRED_CONTROLS),
            'issued_at_utc': stamp(now),
            'expires_at_utc': stamp(now + timedelta(seconds=90)),
        }
        self.lease['mac_sha256'] = mac(
            self.broker_key, guard.DOMAIN_LEASE, self.lease)
        files = {
            'source_pin': doc_file(self.base/'pin.json', self.pin),
            'approval_ticket': doc_file(self.base/'approval.json', self.approval),
            'lease_ticket': doc_file(self.base/'lease.json', self.lease),
            'policy_key': secret_file(self.base/'policy.hmac', self.policy_key),
            'broker_key': secret_file(self.base/'broker.hmac', self.broker_key),
        }
        self.signer_files = {}
        self.signer_pubs = {}
        for role in ('policy', 'isolation', 'server'):
            priv = self.base / (role + '.ed25519')
            self.signer_pubs[role] = operator.keygen(str(priv))['public_hex']
            self.signer_files[role] = priv
        self.policy = {
            'schema': p.POLICY_SCHEMA,
            'repo_root': str(self.repo),
            'allowed_profiles': ['python.pytest'],
            'allowed_uids': [os.getuid()],
            'policy_issuer_public_hex': self.signer_pubs['policy'],
            'isolation_issuer_public_hex': self.signer_pubs['isolation'],
            'server_public_hex': self.signer_pubs['server'],
        }
        for name, path in files.items():
            self.policy[f'{name}_file'] = str(path)
            self.policy[f'{name}_sha256'] = p.sha(path.read_bytes())
        self.policy_file = doc_file(self.base/'policy.json', self.policy)
        self.policy_sha = p.sha(self.policy_file.read_bytes())
        self.socket_path = str(self.base/'preflight.sock')
        self.subject = p.new_subject(
            profile_id=self.profile_id, uid=os.getuid(),
            policy_sha=self.policy_sha,
            source_pin_sha=self.policy['source_pin_sha256'],
            approval_sha=self.policy['approval_ticket_sha256'],
            lease_sha=self.policy['lease_ticket_sha256'], ttl=110)
        self.grant = self.sign_grant(self.subject)
        self.grant_file = doc_file(self.base/'grant.json', self.grant)

    def sign_grant(self, subject):
        def sign_as(role):
            key = io.private_from_file(str(self.signer_files[role]))
            return p.sign(role, subject, key)
        return {
            'schema': p.GRANT_SCHEMA, 'subject': subject,
            'policy_signature_ed25519': sign_as('policy'),
            'isolation_signature_ed25519': sign_as('isolation')
        }

    def host(self):
        srv = daemon.PreflightServer(
            path=self.socket_path, policy_path=str(self.policy_file),
            policy_sha=self.policy_sha,
            private_key_file=str(self.signer_files['server']))
        thread = threading.Thread(target=srv.serve_forever,
                                  kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        self.addCleanup(lambda: (srv.shutdown(), thread.join(2), srv.server_close()))
        return srv

    def call(self, grant=None):
        chosen = self.grant_file if grant is None else (
            doc_file(self.base/('grant%d.json' % time.time_ns()), grant))
        return operator.preflight(
            socket_path=self.socket_path, grant_file=str(chosen),
            policy_sha=self.policy_sha,
            server_public_hex=self.signer_pubs['server'])

    def test_01_real_ec186_preflight_signatures_socket_no_execution(self):
        self.host()
        rc, envelope = self.call()
        self.assertEqual(rc, 2)
        self.assertTrue(envelope['verified_server_signature'])
        result = envelope['result']
        self.assertEqual(result['schema'], guard.SCHEMA)
        self.assertEqual(result['plan']['state'], 'PREPARED_ONLY_NOT_EXECUTABLE')
        self.assertEqual(result['effects']['root_observations'], 2)
        self.assertEqual(result['effects']['authorization_calls'], 4)
        self.assertFalse(result['effects']['tests_executed'])
        self.assertFalse(result['effects']['lease_consumed'])
        self.assertFalse(result['proof']['overall_quality_pass_verified'])

    def test_02_unsigned_and_tampered_expiry_and_uid_refused(self):
        self.host()
        bad = json.loads(p.canonical(self.grant))
        bad['subject']['uid'] = os.getuid() + 1
        rc, env = self.call(bad)
        self.assertEqual(rc, 3)
        self.assertFalse(env['result']['handler_invoked'])
        expired = dict(self.subject)
        expired['issued_at_unix'] -= 400
        expired['expires_at_unix'] -= 400
        rc, env = self.call(self.sign_grant(expired))
        self.assertEqual(rc, 3)
        invalid = dict(self.grant)
        invalid['policy_signature_ed25519'] = invalid['isolation_signature_ed25519']
        rc, env = self.call(invalid)
        self.assertEqual(rc, 3)

    def test_03_server_pinned_ticket_tamper_refused(self):
        self.host()
        ticket_file = Path(self.policy['lease_ticket_file'])
        ticket_file.write_bytes(b'{"corrupted":true}\\n')
        rc, env = self.call()
        self.assertEqual(rc, 5)
        self.assertNotIn('image_sha256', json.dumps(env['result']))
        self.assertFalse(env['result']['tests_executed'])

    def test_04_host_policy_tamper_refused(self):
        self.host()
        self.policy_file.write_bytes(b'{"changed":true}\\n')
        rc, env = self.call()
        self.assertEqual(rc, 5)
        self.assertEqual(env['result']['reason_code'], 'EC281_POLICY_PIN_CHANGED')

    def test_05_pin_wrong_directory_or_new_profile_refused(self):
        self.host()
        self.repo.rename(self.base/'repo_moved')
        rc, env = self.call()
        self.assertEqual(rc, 5)
        self.assertFalse(env['result']['quality_pass_verified'])
        (self.base/'repo_moved').rename(self.repo)
        bad = dict(self.subject, profile_id='python.ruff')
        rc, env = self.call(self.sign_grant(bad))
        self.assertEqual(rc, 3)

    def test_06_response_signature_nonce_and_fake_quality_pass(self):
        self.host()
        rc, env = self.call()
        self.assertEqual(rc, 2)
        reply = json.loads(p.canonical(env['signed_reply']))
        reply['result']['proof']['overall_quality_pass_verified'] = True
        request = {
            'schema': p.REQUEST_SCHEMA,
            'nonce': reply['nonce'],
            'grant': self.grant,
        }
        key = io.private_from_file(str(self.signer_files['server']))
        # Even a synthetic compromised host signing a success-shaped forged
        # preflight does not make the plan an accepted QUALITY_PASS result.
        reply['request_sha256'] = p.sha(p.canonical(request))
        reply['signature_ed25519'] = p.sign(
            'server', {k:v for k,v in reply.items()
                       if k != 'signature_ed25519'}, key)
        with self.assertRaises(p.HostError):
            p.verify_reply(reply, request, server_public_hex=self.signer_pubs['server'],
                           policy_sha=self.policy_sha, now=int(time.time()))
        reply['nonce'] = '0'*32
        with self.assertRaises(p.HostError):
            p.verify_reply(reply, request, server_public_hex=self.signer_pubs['server'],
                           policy_sha=self.policy_sha, now=int(time.time()))

    def test_07_cli_offline_votes_real_signature_and_no_overwrite(self):
        subject_path = doc_file(self.base/'subject.json', self.subject)
        a_path = self.base/'vote-policy.json'
        b_path = self.base/'vote-isolation.json'
        operator.vote('policy', str(subject_path), str(self.signer_files['policy']),
                      str(a_path))
        operator.vote('isolation', str(subject_path),
                      str(self.signer_files['isolation']), str(b_path))
        out = self.base/'assembled.json'
        operator.assemble(str(subject_path), str(a_path), str(b_path),
                          self.signer_pubs['policy'], self.signer_pubs['isolation'],
                          str(out))
        self.assertEqual(io.read_doc(str(out)), self.grant)
        with self.assertRaises(io.HostError):
            operator.assemble(str(subject_path), str(a_path), str(b_path),
                              self.signer_pubs['policy'],
                              self.signer_pubs['isolation'], str(out))
        self.host()
        rc, env = operator.preflight(
            socket_path=self.socket_path, grant_file=str(out),
            policy_sha=self.policy_sha,
            server_public_hex=self.signer_pubs['server'])
        self.assertEqual(rc, 2)

    def test_08_unified_console_host_only_and_router_denial(self):
        self.host()
        args = [sys.executable, '-I', '-B', str(ROOT/'scripts/ces_next.py'),
                'host-preflight', 'QualityRun', 'Preflight',
                '--socket', self.socket_path, '--grant-file',
                str(self.grant_file), '--policy-sha256', self.policy_sha,
                '--server-public-hex', self.signer_pubs['server']]
        res = subprocess.run(args, cwd=ROOT, capture_output=True,
                             text=True, timeout=25)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        doc = json.loads(res.stdout)
        self.assertTrue(doc['verified_server_signature'])
        self.assertEqual(doc['result']['plan']['state'],
                         'PREPARED_ONLY_NOT_EXECUTABLE')
        args[6] = 'Execute'
        res = subprocess.run(args, cwd=ROOT, capture_output=True,
                             text=True, timeout=15)
        self.assertEqual(res.returncode, 3)
        routes = subprocess.run(
            [sys.executable, '-I', '-B', str(ROOT/'scripts/ces_next.py'),
             'routes', '--kind', 'host'], cwd=ROOT, capture_output=True,
            text=True, timeout=20)
        self.assertEqual(routes.returncode, 0)
        self.assertEqual(json.loads(routes.stdout)['route_count'], 11)

    def test_09_host_denies_unpinned_server_key(self):
        wrong = self.base/'wrong.ed25519'
        operator.keygen(str(wrong))
        with self.assertRaises(p.HostError):
            daemon.PreflightServer(
                path=self.socket_path, policy_path=str(self.policy_file),
                policy_sha=self.policy_sha, private_key_file=str(wrong))

if __name__ == '__main__':
    unittest.main(verbosity=2)
