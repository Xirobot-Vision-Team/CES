#!/usr/bin/env python3
"""EC251 focused local tests: real EC188 projection through actual Linux AF_UNIX.

All EC181-187 receipts here are synthetic. No provider/test/run attestation.
"""
from __future__ import annotations

import copy
import hashlib
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

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import broker
import test_quality_show as fixture


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(socket, 'SO_PEERCRED'),
                     'actual Linux SO_PEERCRED required')
class HostQueryCases(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='ces-ec251-quality-')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.root.chmod(0o700)
        self.policy_path = self.root / 'policy.json'
        self.snapshot_path = self.root / 'snapshot.json'
        self.key_path = self.root / 'cursor.key'
        self.socket_path = self.root / 'quality.sock'
        self.request_file = self.root / 'client.json'
        self.key = bytes(range(32))
        self.scope = copy.deepcopy(fixture.LOCAL)
        self.evidence = [fixture.sample('config'), fixture.sample('run_preflight', offset=1)]
        self.grant = {
            'uid': os.geteuid(), 'scope_id': 'quality_scope_1',
            'allowed_kinds': ['config', 'run_preflight'],
            'allow_numeric_metrics': False, 'acknowledge_historical_proposal': False,
        }
        self.policy = {
            'schema': broker.POLICY_SCHEMA, 'source_scope': self.scope,
            'snapshot_path': str(self.snapshot_path),
            'expected_snapshot_sha256': '0' * 64,
            'cursor_key_path': str(self.key_path),
            'expected_cursor_key_sha256': hashlib.sha256(self.key).hexdigest(),
            'grants': [self.grant],
        }
        self.request = {
            'schema': broker.REQUEST_SCHEMA, 'scope_id': 'quality_scope_1',
            'filters': {}, 'page_size': 1, 'cursor': None,
            'include_numeric_metrics': False,
        }
        self.key_path.write_bytes(self.key)
        self.key_path.chmod(0o600)
        self.save_snapshot()
        self.save_policy()
        self.save_request()

    def save_policy(self):
        self.policy_path.write_text(json.dumps(self.policy), encoding='utf-8')
        self.policy_path.chmod(0o600)

    def save_snapshot(self, *, update_policy_pin=True):
        snapshot = {'schema': broker.SNAPSHOT_SCHEMA,
                    'source_scope': self.scope, 'evidence': self.evidence}
        raw = json.dumps(snapshot, separators=(',', ':'), sort_keys=True).encode()
        self.snapshot_path.write_bytes(raw)
        self.snapshot_path.chmod(0o600)
        if update_policy_pin:
            self.policy['expected_snapshot_sha256'] = hashlib.sha256(raw).hexdigest()

    def save_request(self):
        self.request_file.write_text(json.dumps(self.request), encoding='utf-8')

    def direct(self):
        return broker.execute(json.dumps(self.request).encode(),
                              str(self.policy_path), os.geteuid())

    def run_server(self, count=1):
        failures = []
        def worker():
            try:
                broker.serve(str(self.policy_path), str(self.socket_path),
                             max_requests=count, accept_timeout=8)
            except BaseException as exc:
                failures.append(exc)
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        for _ in range(500):
            if self.socket_path.exists() or failures or not t.is_alive():
                break
            time.sleep(0.004)
        self.assertEqual(failures, [])
        self.assertTrue(self.socket_path.exists(), failures)
        self.addCleanup(t.join, 9)
        return t, failures

    def client(self):
        self.save_request()
        return broker.query(str(self.socket_path), str(self.request_file), os.geteuid())

    def test_real_two_page_query_using_kernel_uid_and_pinned_private_snapshot(self):
        old_snapshot = self.snapshot_path.read_bytes()
        t, errors = self.run_server(2)
        first = self.client()
        self.assertEqual((first['status'], first['exit_code']), ('partial', 2), first)
        self.assertTrue(first['host_os_peer_uid_verified'])
        self.assertTrue(first['host_scope_policy_checked'])
        self.assertTrue(first['host_private_snapshot_pin_verified'])
        self.assertEqual(first['result']['counts']['supplied'], 2)
        self.assertEqual(first['result']['counts']['returned'], 1)
        self.assertFalse(first['result']['proof']['verified_quality_pass'])
        self.assertIsNotNone(first['result']['next_cursor'])
        self.request['cursor'] = first['result']['next_cursor']
        second = self.client()
        t.join(3)
        self.assertFalse(t.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(second['status'], 'partial')
        self.assertIsNone(second['result']['next_cursor'])
        self.assertNotEqual(first['result']['entries'][0]['kind'],
                            second['result']['entries'][0]['kind'])
        self.assertEqual(self.snapshot_path.read_bytes(), old_snapshot)
        self.assertFalse(self.socket_path.exists())
        self.assertFalse(second['external_provider_called'])
        self.assertFalse(second['business_repository_written'])

    def test_policy_uid_scope_revocation_is_rechecked_per_page(self):
        t, errors = self.run_server(2)
        first = self.client()
        self.assertEqual(first['status'], 'partial')
        self.request['cursor'] = first['result']['next_cursor']
        self.grant['uid'] = os.geteuid() + 1
        self.save_policy()
        second = self.client()
        t.join(3)
        self.assertEqual(errors, [])
        self.assertEqual(second['status'], 'permission_denied')
        self.assertEqual(second['reason_code'], 'QUALITY_HOST_PEER_SCOPE_NOT_GRANTED')
        self.assertIsNone(second['result'])

    def test_unauthorized_uid_or_scope_and_request_supplied_authority(self):
        self.request['scope_id'] = 'ungranted_scope'
        self.assertEqual(self.direct()['status'], 'permission_denied')
        self.request['scope_id'] = 'quality_scope_1'
        for injected in ({'uid': os.geteuid()}, {'source_scope': self.scope},
                         {'snapshot_path': str(self.snapshot_path)},
                         {'allow_query': True}, {'cursor_key_path': str(self.key_path)},
                         {'evidence': self.evidence}, {'action': 'QualityRun'}):
            with self.subTest(injected=injected):
                raw = json.dumps({**self.request, **injected}).encode()
                answer = broker.execute(raw, str(self.policy_path), os.geteuid())
                self.assertEqual(answer['status'], 'invalid_input')
                self.assertIsNone(answer['result'])
        self.assertEqual(broker.execute(json.dumps(self.request).encode(),
                                        str(self.policy_path), os.geteuid() + 1)['status'],
                         'permission_denied')

    def test_tamper_snapshot_without_operator_pin_update_blocks_result(self):
        self.evidence.append(fixture.sample('config', offset=2))
        self.save_snapshot(update_policy_pin=False)
        out = self.direct()
        self.assertEqual((out['status'], out['reason_code']),
                         ('unavailable', 'QUALITY_HOST_SNAPSHOT_PIN_MISMATCH'))
        self.assertIsNone(out['result'])

    def test_operator_new_snapshot_pin_invalidates_earlier_hmac_cursor(self):
        first = self.direct()
        self.assertEqual(first['status'], 'partial')
        self.request['cursor'] = first['result']['next_cursor']
        self.evidence.append(fixture.sample('config', offset=2))
        self.save_snapshot()
        self.save_policy()
        second = self.direct()
        self.assertEqual(second['status'], 'unavailable')
        self.assertIn('QUALITYSHOW_CURSOR_SCOPE_FILTER_OR_SNAPSHOT_CHANGED',
                      second['reason_code'])
        self.assertEqual(second['result']['entries'], [])

    def test_kind_whitelist_per_grant_filters_all_unauthorized_receipts(self):
        self.grant['allowed_kinds'] = ['config']
        self.save_policy()
        partial = self.direct()
        self.assertEqual(partial['status'], 'partial')
        self.assertEqual(partial['result']['counts']['supplied'], 1)
        self.assertEqual(partial['result']['counts']['matched_by_kind']['run_preflight'], 0)
        self.request['filters'] = {'kinds': ['run_preflight']}
        denied = self.direct()
        self.assertEqual((denied['status'], denied['reason_code']),
                         ('permission_denied', 'QUALITY_HOST_KIND_NOT_GRANTED'))

    def test_numeric_provider_metrics_require_separate_host_grant(self):
        self.scope = copy.deepcopy(fixture.REMOTE)
        self.evidence = [fixture.sample('ci_evidence', scope=self.scope)]
        self.grant['allowed_kinds'] = ['ci_evidence']
        self.save_snapshot()
        self.policy['source_scope'] = self.scope
        self.save_policy()
        self.request['include_numeric_metrics'] = True
        denied = self.direct()
        self.assertEqual(denied['status'], 'permission_denied')
        self.grant['allow_numeric_metrics'] = True
        self.save_policy()
        out = self.direct()
        self.assertEqual(out['status'], 'partial', out)
        self.assertEqual(out['result']['entries'][0]['summary']['provider_test_counts']['total'], 7)
        self.assertFalse(out['result']['proof']['verified_quality_pass'])

    def test_missing_or_mismatched_cursor_key_blocks_output(self):
        self.key_path.write_bytes(os.urandom(32))
        self.key_path.chmod(0o600)
        out = self.direct()
        self.assertEqual((out['status'], out['reason_code']),
                         ('unavailable', 'QUALITY_HOST_CURSOR_KEY_PIN_MISMATCH'))

    def test_reject_snapshot_mixed_sources_even_when_client_filters_kind(self):
        self.evidence.append(fixture.sample('ci_metadata', scope=fixture.REMOTE))
        self.save_snapshot()
        self.save_policy()
        out = self.direct()
        self.assertEqual((out['status'], out['reason_code']),
                         ('unavailable', 'QUALITY_HOST_SNAPSHOT_RECORD_SCOPE_INVALID'))

    def test_private_permissions_and_links_rejected(self):
        self.snapshot_path.chmod(0o644)
        self.assertEqual(self.direct()['status'], 'unavailable')
        self.snapshot_path.chmod(0o600)
        self.root.chmod(0o755)
        self.assertEqual(self.direct()['status'], 'unavailable')
        self.root.chmod(0o700)
        symlink = self.root / 'linked.json'
        symlink.symlink_to(self.snapshot_path)
        self.policy['snapshot_path'] = str(symlink)
        self.save_policy()
        self.assertEqual(self.direct()['status'], 'unavailable')
        self.policy['snapshot_path'] = str(self.snapshot_path)
        self.save_policy()
        link = self.root / 'extra.json'
        os.link(self.snapshot_path, link)
        self.assertEqual(self.direct()['status'], 'unavailable')

    def test_duplicate_json_keys_and_boolean_page_rejected(self):
        raw = (b'{"schema":"' + broker.REQUEST_SCHEMA.encode() +
               b'","schema":"' + broker.REQUEST_SCHEMA.encode() + b'"}')
        self.assertEqual(broker.execute(raw, str(self.policy_path), os.geteuid())['status'],
                         'invalid_input')
        self.request['page_size'] = True
        self.assertEqual(self.direct()['status'], 'invalid_input')
        self.request['page_size'] = 1
        self.request['filters'] = {'kinds': ['config', 'config']}
        self.assertEqual(self.direct()['status'], 'invalid_input')

    def test_midquery_policy_revoke_discards_projected_entries(self):
        original = broker.quality.QualityShow.query
        def revoke(instance, **kwargs):
            projection = original(instance, **kwargs)
            self.grant['uid'] = os.geteuid() + 3
            self.save_policy()
            return projection
        with patch.object(broker.quality.QualityShow, 'query', revoke):
            result = self.direct()
        self.assertEqual((result['status'], result['reason_code']),
                         ('unavailable', 'QUALITY_HOST_AUTHORIZATION_OR_SNAPSHOT_CHANGED'))
        self.assertIsNone(result['result'])

    def test_midquery_snapshot_swap_without_matching_policy_pin_discards_entries(self):
        original = broker.quality.QualityShow.query
        def swap(instance, **kwargs):
            projection = original(instance, **kwargs)
            self.evidence.append(fixture.sample('config', offset=2))
            self.save_snapshot(update_policy_pin=False)
            return projection
        with patch.object(broker.quality.QualityShow, 'query', swap):
            result = self.direct()
        self.assertEqual((result['status'], result['reason_code']),
                         ('unavailable', 'QUALITY_HOST_SNAPSHOT_PIN_MISMATCH'))
        self.assertIsNone(result['result'])

    def test_proposed_pr_scope_requires_operator_ack(self):
        self.scope = copy.deepcopy(fixture.PROPOSAL)
        self.evidence = []
        self.policy['source_scope'] = self.scope
        self.save_snapshot()
        self.save_policy()
        self.assertEqual(self.direct()['status'], 'unavailable')
        self.grant['acknowledge_historical_proposal'] = True
        self.save_policy()
        out = self.direct()
        self.assertEqual(out['status'], 'partial', out)
        self.assertTrue(out['result']['scope']['proposed_pr_historical_only'])

    def test_separate_cli_processes_execute_true_quality_projection(self):
        script = str(HERE / 'broker.py')
        server = subprocess.Popen(
            [sys.executable, '-I', '-B', script, 'serve', '--policy', str(self.policy_path),
             '--socket', str(self.socket_path), '--max-requests', '1',
             '--accept-timeout', '5'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            for _ in range(500):
                if self.socket_path.exists() or server.poll() is not None:
                    break
                time.sleep(0.005)
            self.assertTrue(self.socket_path.exists())
            client = subprocess.run(
                [sys.executable, '-I', '-B', script, 'query', '--socket', str(self.socket_path),
                 '--request-file', str(self.request_file),
                 '--expect-host-uid', str(os.geteuid())],
                capture_output=True, text=True, timeout=8, check=False)
            self.assertEqual(client.returncode, 2, client.stderr)
            output = json.loads(client.stdout)
            self.assertEqual(output['result']['schema'], broker.quality.SCHEMA)
            self.assertEqual(output['result']['counts']['returned'], 1)
            self.assertFalse(output['quality_pass_verified'])
            stdout, stderr = server.communicate(timeout=8)
            self.assertEqual(server.returncode, 0, (stdout, stderr))
            self.assertFalse(self.socket_path.exists())
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate(timeout=3)

    def test_socket_peer_uid_client_checks_before_sending(self):
        t, errors = self.run_server()
        self.save_request()
        with self.assertRaisesRegex(broker.QualityHostError, 'QUALITY_HOST_SERVER_UID_MISMATCH'):
            broker.query(str(self.socket_path), str(self.request_file),
                         os.geteuid() + 1)
        t.join(4)
        self.assertEqual(errors, [])
        self.assertFalse(self.socket_path.exists())

    def test_source_text_and_untrusted_stdout_not_in_wire(self):
        self.scope = copy.deepcopy(fixture.LOCAL)
        self.evidence = [fixture.sample('run_session', scope=self.scope)]
        self.grant['allowed_kinds'] = ['run_session']
        self.save_snapshot()
        self.save_policy()
        out = self.direct()
        self.assertEqual(out['status'], 'partial', out)
        raw = json.dumps(out)
        self.assertNotIn('SENSITIVE_STDOUT', raw)
        self.assertNotIn('SECRET=abc123', raw)
        self.assertNotIn('private source', raw)
        self.assertFalse(out['quality_pass_verified'])

    def test_policy_cannot_lie_about_immutable_source_or_reference_key(self):
        self.policy['source_scope'] = copy.deepcopy(fixture.REMOTE)
        self.save_policy()
        self.assertEqual(self.direct()['status'], 'unavailable')
        self.policy['source_scope'] = self.scope
        self.policy['cursor_key_path'] = self.policy['snapshot_path']
        self.save_policy()
        self.assertEqual(self.direct()['status'], 'unavailable')


if __name__ == '__main__':
    unittest.main(verbosity=2)
