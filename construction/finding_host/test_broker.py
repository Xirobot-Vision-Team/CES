#!/usr/bin/env python3
"""EC250 bounded local functional tests; Linux UID is NOT enterprise identity."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import broker
import test_finding_show as real_fixture


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(socket, 'SO_PEERCRED'),
                     'requires kernel SO_PEERCRED, non-Linux must deny')
class BrokerCases(unittest.TestCase):
    def setUp(self):
        self.harness = real_fixture.FindingShowCases(
            'test_real_sealed_store_query_has_semantic_boundaries_and_no_plaintext')
        self.harness.setUp()
        self.addCleanup(self.harness.doCleanups)
        self.harness.begin()
        self.temp = tempfile.TemporaryDirectory(prefix='ces-ec250-host-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy_path = self.root / 'policy.json'
        self.socket_path = self.root / 'owner.sock'
        self.request_path = self.root / 'query.json'
        self.grant = {
            'uid': os.geteuid(), 'scope_id': 'synthetic_scope_a',
            'source_binding': dict(self.harness.preview['source_binding']),
            'source_mode': 'WorkingTree',
            'allow_expired_audit': False, 'allow_path_digest_query': False,
            'allow_digest_details': False, 'acknowledge_historical_proposal': False,
        }
        self.policy = {
            'schema': broker.POLICY_SCHEMA,
            'store': {
                'stage_root': str(self.harness.root),
                'business_repo_root': str(self.harness.repo),
                'finding_store_root': str(self.harness.ledger_root),
                'codesave_root': None,
                'expected_finding_store_pin': self.harness.ledger_pin,
            },
            'grants': [self.grant],
        }
        self.request = {
            'schema': broker.REQUEST_SCHEMA, 'scope_id': 'synthetic_scope_a',
            'filters': {}, 'page_size': 10, 'cursor': None,
            'include_expired': False, 'include_digest_details': False,
        }
        self.write_policy()
        self.write_request()

    def write_policy(self):
        self.policy_path.write_text(json.dumps(self.policy), encoding='utf-8')
        self.policy_path.chmod(0o600)

    def write_request(self):
        self.request_path.write_text(json.dumps(self.request), encoding='utf-8')

    def run_server(self, count=1):
        failures = []
        def worker():
            try:
                broker.serve(str(self.policy_path), str(self.socket_path),
                             max_requests=count, accept_timeout=8)
            except BaseException as exc:
                failures.append(exc)
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        for _ in range(500):
            if self.socket_path.exists():
                break
            if failures or not thread.is_alive():
                break
            time.sleep(0.002)
        self.assertEqual(failures, [])
        self.assertTrue(self.socket_path.exists(), failures)
        self.addCleanup(thread.join, 9)
        return thread, failures

    def client(self):
        return broker.query(str(self.socket_path), str(self.request_path), os.geteuid())

    def test_real_sealed_ec178_finding_store_over_unix_socket(self):
        original = (self.harness.repo / 'read-only.py').read_bytes()
        thread, failures = self.run_server()
        response = self.client()
        thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(response['status'], 'partial')
        self.assertEqual(response['exit_code'], 2)
        self.assertTrue(response['host_os_peer_uid_verified'])
        self.assertTrue(response['host_scope_policy_checked'])
        self.assertFalse(response['enterprise_actor_authenticated'])
        self.assertFalse(response['business_effect_verified'])
        self.assertEqual(response['result']['matched_count'], 1)
        self.assertEqual(response['result']['findings'][0]['finding_id'],
                         self.harness.preview['findings'][0]['finding_id'])
        self.assertNotIn('digest_details', response['result']['findings'][0])
        self.assertEqual(original, (self.harness.repo / 'read-only.py').read_bytes())
        self.assertFalse(self.socket_path.exists())

    def test_kernel_peer_uid_scope_grant_rechecked_at_next_query(self):
        thread, failures = self.run_server(2)
        first = self.client()
        self.assertEqual(first['status'], 'partial')
        self.policy['grants'][0]['uid'] = os.geteuid() + 1
        self.write_policy()
        second = self.client()
        thread.join(4)
        self.assertEqual(failures, [])
        self.assertEqual(second['status'], 'permission_denied')
        self.assertEqual(second['reason_code'], 'HOST_PEER_UID_SCOPE_NOT_GRANTED')
        self.assertIsNone(second['result'])

    def test_request_cannot_inject_permissions_roots_or_symbols(self):
        for bad in (
            {'authorize_store_read': True},
            {'finding_store_root': str(self.harness.ledger_root)},
            {'handler': 'python:evil'},
            {'uid': os.geteuid()},
        ):
            with self.subTest(bad=bad):
                req = dict(self.request, **bad)
                r = broker.execute(json.dumps(req).encode(), str(self.policy_path), os.geteuid())
                self.assertEqual(r['status'], 'invalid_input')
                self.assertIsNone(r['result'])

    def test_disclosure_grants_default_denied_and_pinned_store(self):
        for override in ({'include_expired': True}, {'include_digest_details': True},
                         {'filters': {'path_identity_sha256': '0' * 64}}):
            with self.subTest(override=override):
                req = dict(self.request, **override)
                r = broker.execute(json.dumps(req).encode(), str(self.policy_path), os.geteuid())
                self.assertEqual(r['reason_code'], 'HOST_QUERY_DISCLOSURE_NOT_GRANTED')
                self.assertIsNone(r['result'])
        self.policy['store']['expected_finding_store_pin'] = '0' * 64
        self.write_policy()
        response = broker.execute(json.dumps(self.request).encode(),
                                  str(self.policy_path), os.geteuid())
        self.assertEqual(response['status'], 'unavailable')
        self.assertIsNone(response['result']['next_cursor'])
        self.assertEqual(response['result']['matched_count'], 0)

    def test_operator_granted_digest_details_can_be_read_but_no_source_text(self):
        self.policy['grants'][0]['allow_digest_details'] = True
        self.write_policy()
        self.request['include_digest_details'] = True
        response = broker.execute(json.dumps(self.request).encode(),
                                  str(self.policy_path), os.geteuid())
        self.assertEqual(response['status'], 'partial')
        self.assertIn('digest_details', response['result']['findings'][0])
        literal = json.dumps(response)
        self.assertNotIn('read-only.py', literal)
        self.assertNotIn('diff --git', literal)
        self.assertFalse(response['business_repository_written'])

    def test_socket_and_policy_paths_must_be_operator_private(self):
        outside = str(Path(__file__).resolve().parent / 'unsafe.sock')
        with self.assertRaises(broker.HostError):
            broker._private_parent(outside, policy=False)
        self.root.chmod(0o777)
        try:
            with self.assertRaisesRegex(broker.HostError, 'HOST_PARENT_NOT_OWNER_PRIVATE'):
                broker._private_parent(str(self.socket_path), policy=False)
        finally:
            self.root.chmod(0o700)

    def test_wrong_exact_source_scope_is_not_fuzzy_look_up(self):
        self.policy['grants'][0]['source_binding']['source_identity_sha256'] = '0' * 64
        self.write_policy()
        response = broker.execute(json.dumps(self.request).encode(),
                                  str(self.policy_path), os.geteuid())
        self.assertEqual(response['status'], 'partial')
        self.assertEqual(response['result']['matched_count'], 0)
        self.assertFalse(response['business_effect_verified'])

    def test_malformed_policy_must_not_bypass_and_no_symlink(self):
        self.policy_path.chmod(0o644)
        with self.assertRaisesRegex(broker.HostError, 'HOST_POLICY_NOT_OWNER_PRIVATE_REGULAR'):
            broker._read_policy_file(str(self.policy_path))
        self.policy_path.chmod(0o600)
        alias = self.root / 'alias.json'
        alias.symlink_to(self.policy_path)
        with self.assertRaises(broker.HostError):
            broker._read_policy_file(str(alias))
        self.policy['grants'].append(dict(self.grant))
        self.write_policy()
        with self.assertRaisesRegex(broker.HostError, 'HOST_POLICY_DUPLICATE_GRANT'):
            broker._read_policy_file(str(self.policy_path))

    def test_mid_query_policy_change_discards_result(self):
        real_read = broker._read_policy_file
        calls = 0
        def fake_read(path):
            nonlocal calls
            calls += 1
            policy, sha = real_read(path)
            return policy, ('0' * 64 if calls > 1 else sha)
        with patch.object(broker, '_read_policy_file', side_effect=fake_read):
            response = broker.execute(json.dumps(self.request).encode(),
                                      str(self.policy_path), os.geteuid())
        self.assertEqual(response['status'], 'unavailable')
        self.assertEqual(response['reason_code'], 'HOST_POLICY_REVISED_DURING_QUERY')
        self.assertIsNone(response['result'])

    def test_transport_rejects_malformed_and_oversized_requests(self):
        with self.assertRaises(broker.HostError):
            broker._json(b'{"a":1,"a":2}', broker.MAX_REQUEST)
        with self.assertRaises(broker.HostError):
            broker._json(b'x' * (broker.MAX_REQUEST + 1), broker.MAX_REQUEST)
        self.assertNotEqual(broker._reply('permission_denied', 'x')['exit_code'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
