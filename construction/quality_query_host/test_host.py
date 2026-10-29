#!/usr/bin/env python3
"""EC280 targeted real Unix socket + QualityShow integration (synthetic receipts).

Does not claim independent issuer humans/OS principals, real provider evidence
or native PowerShell validation. Only a focused, local functionality gate.
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
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from quality_query_host import protocol as p, daemon as d, operator as op
from finding_query_host import protocol as io
import test_quality_show as fixture


def keyfile(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_bytes(key.private_bytes(serialization.Encoding.Raw,
                     serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    os.chmod(path, 0o600)


class QualityHostCases(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='ces-ec280-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.scope = copy.deepcopy(fixture.LOCAL)
        self.keys = {r: Ed25519PrivateKey.generate()
                     for r in ('evidence', 'query', 'server')}
        self.keypath = self.root / 'server.key'
        keyfile(self.keypath, self.keys['server'])
        self.cursor_path = self.root / 'cursor.key'
        self.cursor_path.write_bytes(os.urandom(32))
        os.chmod(self.cursor_path, 0o600)
        self.socket_path = self.root / 'quality.sock'
        self.batch_path = self.root / 'evidence.json'
        self.policy_path = self.root / 'policy.json'
        self.grant_path = self.root / 'grant.json'
        self.records = [fixture.sample('config', offset=i * 2) for i in range(3)]
        self.query = {'source_scope': copy.deepcopy(self.scope), 'filters': {},
                      'page_size': 1, 'include_numeric_metrics': False,
                      'acknowledge_historical_proposal': False}
        self.server = None

    def setup_policy(self, *, records=None, scope=None):
        self.scope = copy.deepcopy(scope or self.scope)
        if records is not None:
            self.records = records
        batch = {'schema': p.BATCH_SCHEMA, 'source_scope': self.scope,
                 'evidence': self.records}
        self.batch_path.write_bytes(p.canonical(batch) + b'\n')
        os.chmod(self.batch_path, 0o600)
        self.policy = {
            'schema': p.POLICY_SCHEMA, 'evidence_file': str(self.batch_path),
            'evidence_sha256': p.sha(self.batch_path.read_bytes()),
            'cursor_key_file': str(self.cursor_path),
            'cursor_key_sha256': p.sha(self.cursor_path.read_bytes()),
            'source_scope': copy.deepcopy(self.scope),
            'evidence_issuer_public_hex': p.public_hex(self.keys['evidence']),
            'query_issuer_public_hex': p.public_hex(self.keys['query']),
            'server_public_hex': p.public_hex(self.keys['server']),
            'allowed_uids': [os.getuid()]}
        self.policy_path.write_bytes(p.canonical(self.policy) + b'\n')
        os.chmod(self.policy_path, 0o600)
        self.policy_sha = p.sha(self.policy_path.read_bytes())
        self.query['source_scope'] = copy.deepcopy(self.scope)

    def sign_grant(self, *, q=None, subject=None):
        if subject is None:
            subject = p.make_subject(copy.deepcopy(self.query if q is None else q),
                                     os.getuid(), self.policy_sha,
                                     self.policy['evidence_sha256'], 300)
        grant = {'schema': p.GRANT_SCHEMA, 'subject': subject,
                 'evidence_signature_ed25519': p.sign(
                     'evidence', subject, self.keys['evidence']),
                 'query_signature_ed25519': p.sign(
                     'query', subject, self.keys['query'])}
        self.grant_path.write_bytes(p.canonical(grant) + b'\n')
        os.chmod(self.grant_path, 0o600)
        return grant

    def start_server(self):
        self.server = d.QualityServer(
            path=str(self.socket_path), policy_path=str(self.policy_path),
            policy_sha=self.policy_sha, private_key_file=str(self.keypath))
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': 0.03}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
            self.server = None

    def live(self, *, records=None, scope=None):
        self.setup_policy(records=records, scope=scope)
        self.sign_grant()
        self.start_server()

    def query_host(self, *, cursor=None, server_key=None, pin=None):
        return op.request_query(
            socket_path=str(self.socket_path), grant_path=str(self.grant_path),
            policy_sha=self.policy_sha if pin is None else pin,
            server_public_hex=(p.public_hex(self.keys['server']) if server_key is None
                               else server_key), cursor=cursor)

    def assert_readonly(self, res):
        self.assertEqual(res['status'], 'partial')
        self.assertEqual(res['exit_code'], 2)
        self.assertTrue(res['effects']['read_only'])
        self.assertFalse(res['proof']['verified_quality_pass'])
        self.assertFalse(res['coverage']['source_currentness_proven'])
        self.assertFalse(res['effects']['provider_requests'])

    def test_01_real_quality_backend_signed_pinned_batch_page_1(self):
        self.live()
        rc, doc = self.query_host()
        self.assertEqual(rc, 2)
        self.assertTrue(doc['verified_server_signature'])
        self.assertEqual(doc['signed_reply']['result'], doc['result'])
        self.assert_readonly(doc['result'])
        self.assertEqual(doc['result']['counts']['supplied'], 3)
        self.assertEqual(doc['result']['counts']['returned'], 1)
        self.assertIsNotNone(doc['result']['next_cursor'])

    def test_02_real_pagination_under_same_offline_votes(self):
        self.live()
        first = self.query_host()[1]['result']
        second = self.query_host(cursor=first['next_cursor'])[1]['result']
        third = self.query_host(cursor=second['next_cursor'])[1]['result']
        self.assertEqual(len({x['entries'][0]['evidence_id']
                              for x in (first, second, third)}), 3)
        self.assertIsNone(third['next_cursor'])
        self.assertEqual(second['revision_sha256'], first['revision_sha256'])

    def test_03_missing_wrong_vote_and_changed_query_rejected_before_read(self):
        self.live()
        grant = p.read_doc(str(self.grant_path))
        for change in ('missing', 'wrong', 'query'):
            edited = copy.deepcopy(grant)
            if change == 'missing':
                edited['query_signature_ed25519'] = ''
            elif change == 'wrong':
                edited['evidence_signature_ed25519'] = p.sign(
                    'query', edited['subject'], self.keys['query'])
            else:
                edited['subject']['query']['page_size'] = 2
            self.grant_path.write_bytes(p.canonical(edited) + b'\n')
            rc, doc = self.query_host()
            self.assertEqual(rc, 3, (change, doc))
            self.assertFalse(doc['result']['handler_invoked'])
        self.grant_path.write_bytes(p.canonical(grant) + b'\n')
        self.assertEqual(self.query_host()[0], 2)

    def test_04_kernel_peer_uid_policy_and_expiration(self):
        self.live()
        grant = p.read_doc(str(self.grant_path))
        self.policy['allowed_uids'] = [os.getuid() + 1]
        self.policy_path.write_bytes(p.canonical(self.policy) + b'\n')
        rc, doc = self.query_host()
        self.assertEqual(rc, 5)  # policy SHA check denies before UID
        self.assertIn('POLICY_SHA_CHANGED', doc['result']['reason_code'])
        self.setup_policy()
        self.sign_grant(subject=p.make_subject(self.query, os.getuid(),
                                              self.policy_sha,
                                              self.policy['evidence_sha256'],
                                              10, now=int(time.time()) - 20))
        self.assertEqual(self.query_host()[0], 3)

    def test_05_pinned_batch_and_cursor_secret_tamper_are_fail_closed(self):
        self.live()
        original = self.batch_path.read_bytes()
        self.batch_path.write_bytes(original + b' ')
        rc, doc = self.query_host()
        self.assertEqual(rc, 5)
        self.assertEqual(doc['result']['reason_code'], 'EC280_PINNED_BATCH_CHANGED')
        self.batch_path.write_bytes(original)
        original_key = self.cursor_path.read_bytes()
        self.cursor_path.write_bytes(os.urandom(32))
        self.assertEqual(self.query_host()[0], 5)
        self.cursor_path.write_bytes(original_key)
        self.assertEqual(self.query_host()[0], 2)

    def test_06_private_receipts_invalid_or_cross_scope_cannot_be_projected(self):
        bad = [fixture.sample('config', scope=self.scope)]
        bad[0]['result']['inventory_sha256'] = 'f' * 64
        self.live(records=bad)
        rc, doc = self.query_host()
        self.assertEqual(rc, 5)
        self.assertEqual(doc['result']['reason_code'], 'EC280_BACKEND_QUALITYSHOW_REFUSED')
        self.assertFalse(doc['result']['handler_invoked'])

    def test_07_verify_signature_reply_pin_and_nonce_tamper(self):
        self.live()
        rc, doc = self.query_host()
        self.assertEqual(rc, 2)
        fake = Ed25519PrivateKey.generate()
        with self.assertRaises(p.HostError):
            self.query_host(server_key=p.public_hex(fake))
        # Reconstruct a legitimately signed response to a known request, then
        # verify the unmodified baseline succeeds before testing modifications.
        req = {'schema': p.REQUEST_SCHEMA, 'nonce': '1' * 32,
               'grant': p.read_doc(str(self.grant_path)), 'cursor': None}
        valid = p.signed_reply(req, doc['result'], self.policy_sha,
                               self.policy['evidence_sha256'],
                               self.keys['server'], int(time.time()))
        result = p.verify_reply(copy.deepcopy(valid), req,
                                server_public_hex=p.public_hex(self.keys['server']),
                                policy_sha=self.policy_sha, now=int(time.time()))
        self.assertEqual(result['status'], 'partial')
        for field, changed in (('nonce', 'f' * 32),
                               ('evidence_sha256', '0' * 64),
                               ('request_sha256', '0' * 64)):
            reply = copy.deepcopy(valid)
            reply[field] = changed
            with self.assertRaises(p.HostError):
                p.verify_reply(reply, req,
                               server_public_hex=p.public_hex(self.keys['server']),
                               policy_sha=self.policy_sha, now=int(time.time()))
        reply = copy.deepcopy(valid)
        reply['result']['proof']['verified_quality_pass'] = True
        with self.assertRaises(p.HostError):
            p.verify_reply(reply, req,
                           server_public_hex=p.public_hex(self.keys['server']),
                           policy_sha=self.policy_sha, now=int(time.time()))

    def test_08_metrics_separately_signed_flags_never_claim_quality_pass(self):
        remote = copy.deepcopy(fixture.REMOTE)
        receipts = [fixture.sample('ci_evidence', scope=remote)]
        self.query['source_scope'] = remote
        self.live(records=receipts, scope=remote)
        default = self.query_host()[1]['result']
        self.assert_readonly(default)
        metric_query = copy.deepcopy(self.query)
        metric_query['include_numeric_metrics'] = True
        self.sign_grant(q=metric_query)
        with_metrics = self.query_host()[1]['result']
        self.assert_readonly(with_metrics)
        self.assertNotEqual(default['entries'][0]['summary'],
                            with_metrics['entries'][0]['summary'])
        # Changing a metric flag on the original signed grant cannot promote it.
        self.sign_grant(q=self.query)
        changed = p.read_doc(str(self.grant_path))
        changed['subject']['query']['include_numeric_metrics'] = True
        self.grant_path.write_bytes(p.canonical(changed) + b'\n')
        self.assertEqual(self.query_host()[0], 3)

    def test_09_independent_cli_offline_prepare_votes_assembly_and_query(self):
        self.live()
        cli = Path(__file__).resolve().parents[2] / 'scripts' / 'ces_quality_host.py'
        cmd = [sys.executable, '-I', '-B', str(cli)]
        def call(*args):
            proc = subprocess.run(cmd + list(args), capture_output=True,
                                  text=True, timeout=30)
            return proc, json.loads(proc.stdout)
        unsigned = self.root / 'query.json'
        unsigned.write_bytes(p.canonical(self.query) + b'\n')
        subject_path = self.root / 'subject.json'
        proc, _ = call('prepare-offline', '--query-file', str(unsigned),
                       '--uid', str(os.getuid()), '--policy-sha256', self.policy_sha,
                       '--evidence-sha256', self.policy['evidence_sha256'],
                       '--ttl-seconds', '300', '--out', str(subject_path))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        vote_paths = {}
        for role in ('evidence', 'query'):
            key_path = self.root / (role + '.key')
            keyfile(key_path, self.keys[role])
            vote_path = self.root / (role + '.vote.json')
            proc, _ = call('sign-' + role + '-offline',
                           '--subject-file', str(subject_path),
                           '--private-key-file', str(key_path),
                           '--out', str(vote_path))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            vote_paths[role] = vote_path
        assembled = self.root / 'assembled.json'
        proc, _ = call('assemble-offline', '--subject-file', str(subject_path),
                       '--evidence-vote', str(vote_paths['evidence']),
                       '--query-vote', str(vote_paths['query']),
                       '--evidence-public-hex', p.public_hex(self.keys['evidence']),
                       '--query-public-hex', p.public_hex(self.keys['query']),
                       '--out', str(assembled))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc, result = call('query', '--socket', str(self.socket_path),
                            '--grant-file', str(assembled),
                            '--policy-sha256', self.policy_sha,
                            '--server-public-hex', p.public_hex(self.keys['server']))
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assert_readonly(result['result'])

    def test_10_console_quality_route_real_and_router_host_denial_unchanged(self):
        self.live()
        cli = Path(__file__).resolve().parents[2] / 'scripts' / 'ces_next.py'
        cmd = [sys.executable, '-I', '-B', str(cli)]
        def run(*args):
            process = subprocess.run(cmd + list(args), capture_output=True,
                                     text=True, timeout=40)
            return process, json.loads(process.stdout)
        proc, doc = run('host-query', 'QualityShow', 'Query',
                        '--socket', str(self.socket_path),
                        '--grant-file', str(self.grant_path),
                        '--policy-sha256', self.policy_sha,
                        '--server-public-hex', p.public_hex(self.keys['server']))
        self.assertEqual(proc.returncode, 2, (proc.stdout, proc.stderr))
        self.assertEqual(doc['result']['counts']['supplied'], 3)
        proc, doc = run('run', 'QualityShow', 'Query', '--request-file',
                        str(self.grant_path))
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(doc['reason_code'], 'EC278_INDEPENDENT_HOST_BRIDGE_REQUIRED')
        proc, doc = run('host-query', 'IssueCreate', 'Create',
                        '--socket', str(self.socket_path),
                        '--grant-file', str(self.grant_path),
                        '--policy-sha256', self.policy_sha,
                        '--server-public-hex', p.public_hex(self.keys['server']))
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(doc['reason_code'],
                         'EC279_ONLY_FINDINGSHOW_QUERY_HAS_OPT_IN_HOST')

    def test_11_reply_denies_if_os_peer_credentials_unavailable(self):
        self.live()
        with patch.object(d, 'peer_uid', side_effect=p.HostError(
                'EC280_TEST_NO_KERNEL_ID', 'unavailable')):
            rc, doc = self.query_host()
        self.assertEqual(rc, 5)
        self.assertEqual(doc['result']['reason_code'], 'EC280_TEST_NO_KERNEL_ID')
        with patch.object(d, 'peer_uid', return_value=os.getuid() + 1):
            rc, doc = self.query_host()
        self.assertEqual(rc, 3)
        self.assertEqual(doc['result']['reason_code'],
                         'EC280_UID_SOURCE_OR_BATCH_NOT_AUTHORIZED')

    def test_12_offline_vote_roles_and_private_path_ownership(self):
        self.setup_policy()
        subject = p.make_subject(self.query, os.getuid(), self.policy_sha,
                                 self.policy['evidence_sha256'], 300)
        self.assertNotEqual(p.sign('evidence', subject, self.keys['query']),
                            p.sign('query', subject, self.keys['query']))
        self.assertEqual(p.load_batch(p.load_policy(str(self.policy_path),
                                                   self.policy_sha))[1],
                         self.records)
        os.chmod(self.batch_path, 0o644)
        with self.assertRaises(io.HostError):
            p.load_batch(self.policy)
        os.chmod(self.batch_path, 0o600)


if __name__ == '__main__':
    unittest.main(verbosity=2)
