#!/usr/bin/env python3
"""EC245 focused local-only negative scenario tests (not external acceptance)."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import run as fixtures


class NegativeFixtureContractTests(unittest.TestCase):
    def test_complete_case_catalog_and_explicit_deferred_evidence(self) -> None:
        cases = fixtures.load_cases()
        self.assertEqual(len(cases), 26)
        self.assertEqual({x['id'] for x in cases}, set(fixtures.SCENARIOS))
        self.assertEqual({x['family'] for x in cases},
                         {'offline', 'resource', 'privacy', 'consistency'})
        self.assertTrue(all(x['needs_external'] is True for x in cases))
        self.assertFalse(any(x['expected']['status'] == 'success' for x in cases))

    def test_actual_module_boundaries_all_refuse_or_downgrade(self) -> None:
        result = fixtures.execute()
        self.assertEqual((result['cases_run'], result['cases_passed'],
                          result['cases_failed']), (26, 26, 0))
        self.assertEqual(result['status'],
                         'LOCAL_SIMULATION_PASSED_NOT_ONLINE_ACCEPTANCE')
        self.assertFalse(result['business_effect_verified'])
        self.assertEqual(result['final_user_assisted_acceptance'], 'NOT_RUN')
        self.assertTrue(all(x['real_provider_or_host_verified'] is False
                            for x in result['scenario_results']))
        self.assertNotIn(fixtures.CANARY, json.dumps(result))

    def test_timeout_overbudget_and_private_exceptions_discard_payload(self) -> None:
        for cid in ('RES-02', 'RES-03', 'PRV-04', 'PRV-05'):
            with self.subTest(case=cid):
                result = fixtures.inspect(cid)
                self.assertEqual(result['status'], 'unavailable')
                self.assertEqual((result['handler_attempted'],
                                  result['handler_invoked']), (True, False))
                self.assertFalse(result['payload_retained'])
                self.assertTrue(result['_canary_absent'])

    def test_complete_synthetic_ci_observation_is_not_live_ci(self) -> None:
        obj, calls = fixtures._ci('CON-02')
        self.assertEqual(calls, 3)
        self.assertEqual(obj['status'], 'partial')
        self.assertEqual(obj['permission']['transport'], 'SYNTHETIC')
        self.assertEqual(obj['permission']['provider_read'], 'NOT_PROVEN_SYNTHETIC')
        self.assertEqual(obj['effects']['live_network_get_requests'], 0)
        self.assertFalse(obj['coverage']['test_execution_by_ces'])
        self.assertFalse(obj['coverage']['git_sha_binding_verified'])
        self.assertNotIn(fixtures.CANARY, json.dumps(obj))

    def test_no_external_process_or_socket_in_scenario_scope(self) -> None:
        with fixtures._no_external_side_effects():
            with self.assertRaises(fixtures.CaseError):
                subprocess.run(['false'], check=False)
            with self.assertRaises(fixtures.CaseError):
                socket.create_connection(('127.0.0.1', 9))
        self.assertTrue(fixtures.inspect('NET-02')['_safe'])

    def test_unknown_case_never_dispatches_any_handler(self) -> None:
        with self.assertRaises(fixtures.CaseError):
            fixtures.execute({'PRV-99'})
        with self.assertRaises(fixtures.CaseError):
            fixtures.execute(set())

    def test_truncated_corrupt_duplicate_and_oversized_manifest_refused(self) -> None:
        original = fixtures.FIXTURES.read_bytes()
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / 'manifest.json'
            payloads = (b'{', b'{"schema":1,"schema":2}',
                        b'x' * (fixtures.MAX_FIXTURE_BYTES + 1))
            for payload in payloads:
                with self.subTest(size=len(payload)):
                    bad.write_bytes(payload)
                    with mock.patch.object(fixtures, 'FIXTURES', bad):
                        with self.assertRaises(fixtures.CaseError):
                            fixtures.load_cases()
            # A forged fixture trying to call the existing function and label
            # its output `success` must be refused before anything runs.
            payload = json.loads(original)
            payload['cases'][0]['expected']['status'] = 'success'
            bad.write_text(json.dumps(payload), encoding='utf-8')
            with mock.patch.object(fixtures, 'FIXTURES', bad):
                with self.assertRaises(fixtures.CaseError):
                    fixtures.load_cases()

    def test_symlink_manifest_refused_when_platform_supports_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            real, link = Path(td) / 'data.json', Path(td) / 'link.json'
            real.write_bytes(fixtures.FIXTURES.read_bytes())
            try:
                link.symlink_to(real)
            except (OSError, NotImplementedError):
                self.skipTest('symlinks not supported on this runner')
            with mock.patch.object(fixtures, 'FIXTURES', link):
                with self.assertRaises(fixtures.CaseError):
                    fixtures.load_cases()

    def test_cli_emits_only_bounded_json_and_correct_exit(self) -> None:
        cmd = [sys.executable, '-I', '-B', str(HERE / 'run.py'),
               '--case', 'NET-01', '--case', 'PRV-05']
        output = subprocess.run(cmd, capture_output=True, check=False,
                                timeout=12)
        self.assertEqual(output.returncode, 0)
        self.assertEqual(output.stderr, b'')
        self.assertLess(len(output.stdout), fixtures.MAX_PRINT_BYTES)
        self.assertEqual(len(output.stdout.splitlines()), 1)
        parsed = json.loads(output.stdout)
        self.assertEqual((parsed['cases_run'], parsed['cases_passed']), (2, 2))
        self.assertFalse(parsed['real_network_outage_tested'])
        self.assertNotIn(fixtures.CANARY.encode('ascii'), output.stdout)
        unknown = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'run.py'),
                                  '--case', 'PRV-99'], capture_output=True,
                                 check=False, timeout=12)
        self.assertEqual(unknown.returncode, 4)
        self.assertEqual(json.loads(unknown.stdout)['reason_code'],
                         'EC245_LOCAL_SUITE_REFUSED')
        self.assertEqual(unknown.stderr, b'')

    def test_reviewed_current_source_lock_keeps_exact_router_binding(self) -> None:
        import hashlib
        root = HERE.parent.parent
        pin = json.loads((root / 'construction/SECURITY_SOURCE_LOCK.json').read_text())
        import security_permission_audit as security
        self.assertEqual(pin['direct_entrypoints'],security._direct_entrypoints(root))
        self.assertEqual(set(pin['source_sha256']),set(security._lock_paths(root,security.extract_routes(root))))
        self.assertEqual(hashlib.sha256((root / 'construction/unified_action_router.py')
                         .read_bytes()).hexdigest(),
                         pin['source_sha256']['construction/unified_action_router.py'])
        self.assertNotIn('construction/negative_scenarios/run.py', pin['source_sha256'])


if __name__ == '__main__':
    unittest.main()
