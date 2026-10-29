#!/usr/bin/env python3
"""EC279 focused end-to-end actual EC178 private store + AF_UNIX two-vote host.

Fixtures use local synthetic keys and a same-uid demo host; this is NOT a proof
of physically separate authorities, real delegated OS principal or production.
"""
from __future__ import annotations

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
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ec279_finding_query_host import daemon as d, operator as op, protocol as p
import test_finding_show as fixture


def public(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


def keyfile(path, key):
    path.write_bytes(key.private_bytes(serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    os.chmod(path, 0o600)


class EC279HostCases(unittest.TestCase):
    # Reuse synthetic real EC172..179 producers without inheriting old test cases.
    setUp = fixture.FindingShowCases.setUp
    setup_projection = fixture.FindingShowCases.setup_projection
    setup_input = fixture.FindingShowCases.setup_input
    act = fixture.FindingShowCases.act
    callback = fixture.FindingShowCases.callback
    setup_save_store = fixture.FindingShowCases.setup_save_store
    project = fixture.FindingShowCases.project
    prepare = fixture.FindingShowCases.prepare
    validate = fixture.FindingShowCases.validate
    review = fixture.FindingShowCases.review
    with_review = fixture.FindingShowCases.with_review
    candidate = fixture.FindingShowCases.candidate
    dispatch = fixture.FindingShowCases.dispatch
    review_key = staticmethod(fixture.FindingShowCases.review_key)
    start = fixture.FindingShowCases.start
    save = fixture.FindingShowCases.save
    setup_historical = fixture.FindingShowCases.setup_historical
    start_finding = fixture.FindingShowCases.start_finding
    commit = fixture.FindingShowCases.commit
    files = fixture.FindingShowCases.files
    begin = fixture.FindingShowCases.begin
    second_batch = fixture.FindingShowCases.second_batch

    def init_host(self, *, create_records=True, page_size=10):
        if create_records:
            self.begin(ttl_seconds=600)
        else:
            self.start_finding()
        self.keys = {r: Ed25519PrivateKey.generate() for r in ('store', 'query', 'server')}
        base = self.root.parent / 'ec279-host'
        base.mkdir(mode=0o700)
        self.host_base = base
        self.key_path = base / 'host.key'
        keyfile(self.key_path, self.keys['server'])
        self.socket_path = base / 'service.sock'
        policy = {'schema': p.POLICY_SCHEMA, 'stage_root': str(self.root),
                  'business_repo_root': str(self.repo),
                  'finding_store_root': str(self.ledger_root), 'codesave_root': None,
                  'store_pin': self.ledger_pin,
                  'store_issuer_public_hex': public(self.keys['store']),
                  'query_issuer_public_hex': public(self.keys['query']),
                  'server_public_hex': public(self.keys['server']),
                  'allowed_uids': [os.getuid()]}
        self.policy_path = base / 'policy.json'
        self.policy_path.write_bytes(p.canonical(policy) + b'\n')
        os.chmod(self.policy_path, 0o600)
        self.policy_sha = p.sha(self.policy_path.read_bytes())
        scope = self.preview['source_binding']
        self.query = {'source_binding': dict(scope),
                      'query_content_for': self.prepared['source_mode'],
                      'filters': {}, 'page_size': page_size,
                      'include_expired': False, 'include_digest_details': False,
                      'authorize_expired_audit': False,
                      'authorize_path_digest_query': False,
                      'authorize_digest_details': False,
                      'acknowledge_historical_proposal_metadata': False}
        self.grant_path = base / 'grant.json'
        self.sign_grant()
        self.srv = d.FindingServer(path=str(self.socket_path),
                                   policy_path=str(self.policy_path),
                                   policy_sha=self.policy_sha,
                                   private_key_file=str(self.key_path))
        self.thread = threading.Thread(target=self.srv.serve_forever,
                                       kwargs={'poll_interval': 0.05}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_host)

    def stop_host(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(3)

    def sign_grant(self, *, uid=None, now=None):
        now = int(time.time()) if now is None else now
        self.subject = p.new_subject(q=copy.deepcopy(self.query),
                                     uid=os.getuid() if uid is None else uid,
                                     store_pin=self.ledger_pin, ttl=300, now=now)
        self.grant = {'schema': p.GRANT_SCHEMA, 'subject': self.subject,
                      'store_signature_ed25519': p.sign('store', self.subject, self.keys['store']),
                      'query_signature_ed25519': p.sign('query', self.subject, self.keys['query'])}
        self.grant_path.write_bytes(p.canonical(self.grant) + b'\n')
        os.chmod(self.grant_path, 0o600)

    def query_host(self, *, cursor=None, server_public=None, policy_sha=None):
        return op.request_query(socket_path=str(self.socket_path),
                                grant_path=str(self.grant_path),
                                server_public_hex=server_public or public(self.keys['server']),
                                policy_sha=policy_sha or self.policy_sha, cursor=cursor)

    def test_real_hmac_private_store_read_and_signed_result_without_business_write(self):
        self.init_host()
        original = (self.repo / 'read-only.py').read_bytes()
        rc, out = self.query_host()
        self.assertEqual(rc, 2, out)
        result = out['result']
        self.assertTrue(out['verified_server_signature'])
        self.assertEqual(result['matched_count'], 1)
        self.assertEqual(result['findings'][0]['finding_id'],
                         self.preview['findings'][0]['finding_id'])
        self.assertFalse(result['findings'][0]['semantic_defect_verified'])
        self.assertFalse(result['effects']['external_transfer'])
        self.assertEqual((self.repo / 'read-only.py').read_bytes(), original)
        self.assertNotIn('read-only.py', json.dumps(out))
        self.assertNotIn('Synthetic patch line', json.dumps(out))

    def test_unsigned_or_wrong_signer_query_grant_rejected_before_private_read(self):
        self.init_host()
        self.grant.pop('query_signature_ed25519')
        self.grant_path.write_bytes(p.canonical(self.grant) + b'\n')
        with patch('finding_show.FindingShower.query') as q:
            rc, out = self.query_host()
            self.assertEqual(rc, 3, out)
            self.assertEqual(out['result']['reason_code'], 'EC279_GRANT_SCHEMA_INVALID')
            q.assert_not_called()
        self.sign_grant()
        self.grant['query_signature_ed25519'] = p.sign('query', self.subject,
                                                        Ed25519PrivateKey.generate())
        self.grant_path.write_bytes(p.canonical(self.grant) + b'\n')
        rc, out = self.query_host()
        self.assertEqual(rc, 3, out)
        self.assertEqual(out['result']['reason_code'], 'EC279_SIGNED_GRANT_SIGNATURE_FAILED')

    def test_peer_uid_and_time_bound_enforced(self):
        self.init_host()
        self.sign_grant(uid=os.getuid() + 1)
        rc, out = self.query_host()
        self.assertEqual((rc, out['result']['reason_code']),
                         (3, 'EC279_UID_OR_STORE_PIN_NOT_AUTHORIZED'))
        self.sign_grant(now=int(time.time()) - 1000)
        rc, out = self.query_host()
        self.assertEqual((rc, out['result']['reason_code']),
                         (3, 'EC279_SIGNED_GRANT_EXPIRED_OR_NOT_YET_VALID'))
        self.sign_grant(now=int(time.time()) + 1000)
        rc, _ = self.query_host()
        self.assertEqual(rc, 3)

    def test_exact_query_flags_and_source_cannot_be_escalated(self):
        self.init_host()
        q2 = copy.deepcopy(self.grant)
        q2['subject']['query']['include_digest_details'] = True
        q2['subject']['query']['authorize_digest_details'] = True
        self.grant_path.write_bytes(p.canonical(q2) + b'\n')
        rc, out = self.query_host()
        self.assertEqual(rc, 3, out)
        self.sign_grant()
        self.query['include_digest_details'] = True
        self.query['authorize_digest_details'] = True
        self.sign_grant()
        rc, out = self.query_host()
        self.assertEqual(rc, 2, out)
        self.assertIn('digest_details', out['result']['findings'][0])
        self.query['source_binding']['source_context_sha256'] = 'f' * 64
        self.sign_grant()
        rc, out = self.query_host()
        self.assertEqual((rc, out['result']['matched_count']), (2, 0))

    def test_policy_pin_mutation_denies_even_existing_signed_grant(self):
        self.init_host()
        self.policy_path.write_bytes(self.policy_path.read_bytes().replace(b'"allowed_uids"',
                                                         b'"allowed_uids" '))
        rc, out = self.query_host()
        self.assertEqual(rc, 5, out)
        self.assertEqual(out['result']['reason_code'],
                         'EC279_HOST_POLICY_CHANGED_OR_WRONG_PIN')

    def test_host_client_pinning_cannot_accept_another_server_or_policy(self):
        self.init_host()
        with self.assertRaises(p.HostError):
            self.query_host(server_public=public(Ed25519PrivateKey.generate()))
        with self.assertRaises(p.HostError):
            self.query_host(policy_sha='f' * 64)
        rc, valid = self.query_host()
        self.assertEqual(rc, 2)
        req = {'schema': p.REQUEST_SCHEMA, 'nonce': valid['signed_reply']['nonce'],
               'grant': self.grant, 'cursor': None}
        forged = copy.deepcopy(valid['signed_reply'])
        forged['result']['matched_count'] = 100000
        with self.assertRaises(p.HostError):
            p.verify_reply(forged, req, public_hex=public(self.keys['server']),
                           policy_sha=self.policy_sha, now=int(time.time()))

    def test_real_pagination_replays_only_under_same_dual_signed_scope(self):
        self.init_host(create_records=False, page_size=1)
        # New synthetic sealed batch after starting host; same store pin remains.
        # Two findings in one source need > 1 genuine local metadata finding.
        self.second_batch(count=2, commits=2)
        # Re-authorize the exact new binding/query after fixture's store update.
        self.query['source_binding'] = dict(self.preview['source_binding'])
        self.sign_grant()
        rc, first = self.query_host()
        self.assertEqual(rc, 2, first)
        self.assertEqual(first['result']['matched_count'], 2)
        self.assertIsNotNone(first['result']['next_cursor'])
        rc, second = self.query_host(cursor=first['result']['next_cursor'])
        self.assertEqual(rc, 2, second)
        self.assertNotEqual(first['result']['findings'][0]['finding_id'],
                            second['result']['findings'][0]['finding_id'])

    def test_unified_console_explicit_host_query_works_without_opening_router(self):
        self.init_host()
        cli = Path(__file__).resolve().parents[2] / 'scripts' / 'ces_next.py'
        argv = ['host-query', 'FindingShow', 'Query', '--socket', str(self.socket_path),
                '--grant-file', str(self.grant_path),
                '--policy-sha256', self.policy_sha,
                '--server-public-hex', public(self.keys['server'])]
        proc = subprocess.run([sys.executable, '-I', '-B', str(cli), *argv],
                              text=True, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 2, (proc.stdout, proc.stderr))
        obj = json.loads(proc.stdout)
        self.assertTrue(obj['verified_server_signature'])
        self.assertEqual(obj['result']['matched_count'], 1)
        # This is a single, literal host Action; it does not turn the 11 router
        # HOST_REQUIRED entries into unprivileged generic RequestPath calls.
        cmd = [sys.executable, '-I', '-B', str(cli)]
        denied = subprocess.run(cmd + ['host-query', 'IssueCreate', 'Create',
                        '--socket', str(self.socket_path), '--grant-file', str(self.grant_path),
                        '--policy-sha256', self.policy_sha,
                        '--server-public-hex', public(self.keys['server'])],
                        text=True, capture_output=True, timeout=30)
        self.assertEqual(denied.returncode, 3)
        self.assertEqual(json.loads(denied.stdout)['reason_code'],
                         'EC279_ONLY_FINDINGSHOW_QUERY_HAS_OPT_IN_HOST')
        normal = subprocess.run(cmd + ['run', 'FindingShow', 'Query',
                                       '--request-file', str(self.grant_path)],
                                text=True, capture_output=True, timeout=30)
        self.assertEqual(normal.returncode, 3)
        self.assertEqual(json.loads(normal.stdout)['reason_code'],
                         'EC278_INDEPENDENT_HOST_BRIDGE_REQUIRED')

    def test_offline_keygen_persists_unique_private_file_and_public_only_output(self):
        private = self.root.parent / 'ec279-test-key.key'
        first = op._keygen(str(private))
        self.assertEqual(first['public_hex'], public(p.private_from_file(str(private))))
        self.assertEqual(os.stat(private).st_mode & 0o777, 0o600)
        self.assertFalse(first['private_key_material_returned'])
        with self.assertRaises(p.HostError):
            op._keygen(str(private))  # Never overwrite offline secret.

    def test_offline_prepare_vote_assemble_real_entrypoint(self):
        self.init_host()
        root = Path(__file__).resolve().parents[2]
        cli = root / 'scripts' / 'ces_finding_host.py'
        qpath = self.host_base / 'query.json'
        qpath.write_bytes(p.canonical(self.query) + b'\n')
        subject = self.host_base / 'subject.json'
        out_store = self.host_base / 'store-vote.json'
        out_query = self.host_base / 'query-vote.json'
        keys = {}
        for role in ('store', 'query'):
            keypath = self.host_base / (role + '.key')
            keyfile(keypath, self.keys[role])
            keys[role] = keypath
        args = [["prepare-offline", '--query-file', str(qpath), '--uid', str(os.getuid()),
                 '--store-pin', self.ledger_pin, '--ttl-seconds', '300', '--out', str(subject)],
                ['sign-store-offline', '--subject-file', str(subject),
                 '--private-key-file', str(keys['store']), '--out', str(out_store)],
                ['sign-query-offline', '--subject-file', str(subject),
                 '--private-key-file', str(keys['query']), '--out', str(out_query)],
                ['assemble-offline', '--subject-file', str(subject),
                 '--store-vote', str(out_store), '--query-vote', str(out_query),
                 '--store-public-hex', public(self.keys['store']),
                 '--query-public-hex', public(self.keys['query']), '--out', str(self.host_base/'assembled.json')],
                ['query', '--socket', str(self.socket_path),
                 '--grant-file', str(self.host_base/'assembled.json'),
                 '--policy-sha256', self.policy_sha,
                 '--server-public-hex', public(self.keys['server'])]]
        for i, argv in enumerate(args):
            proc = subprocess.run([sys.executable, '-I', '-B', str(cli), *argv],
                                  cwd=root, capture_output=True, timeout=30, text=True)
            self.assertEqual(proc.returncode, 2 if i == 4 else 0, (argv, proc.stdout, proc.stderr))
            self.assertIn('status', proc.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
