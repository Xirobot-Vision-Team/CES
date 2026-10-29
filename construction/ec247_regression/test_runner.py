#!/usr/bin/env python3
"""EC247 focused tests for fixed synthetic inputs and real local module chains.

No native PowerShell/15 Smoke/real provider/enterprise/OS/final acceptance.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runner as r


class EC247RegressionTests(unittest.TestCase):
    def test_01_existing_15_smoke_bytes_and_coverage_bind(self):
        plan, reqs = r.load_plan()
        self.assertEqual(len(plan['native_smokes']), 15)
        self.assertEqual(tuple(Path(x['file']).name for x in plan['native_smokes']),
                         r.SMOKE_NAMES)
        for entry in plan['native_smokes']:
            self.assertEqual(hashlib.sha256((r.ROOT / entry['file']).read_bytes()).hexdigest(),
                             entry['sha256'])
            self.assertEqual(entry['execution'], 'NOT_RUN_NATIVE_PWSH7_GIT')
        self.assertEqual(set(reqs), set(r.REQUEST_KEYS))
        self.assertEqual(set(r.FLOW_EXECUTORS), set(r.FLOW_IDS))

    def test_02_real_local_seven_cross_module_chains(self):
        before = {x: hashlib.sha256((r.ROOT / 'tests' / x).read_bytes()).hexdigest()
                  for x in r.SMOKE_NAMES}
        report = r.execute()
        self.assertEqual(report['flow_count'], 7)
        self.assertEqual(report['flow_passed'], 7, report['flows'])
        self.assertEqual(report['result'], 'LOCAL_DEVELOPMENT_PASSED_NOT_FINAL_ACCEPTANCE')
        self.assertTrue(all(f['status'] == 'LOCAL_DEVELOPMENT_PASSED' for f in report['flows']))
        for key in ('native_smokes_executed', 'real_network_tested',
                    'business_permissions_granted', 'enterprise_or_os_accepted',
                    'final_acceptance_started'):
            self.assertIs(report[key], False)
        after = {x: hashlib.sha256((r.ROOT / 'tests' / x).read_bytes()).hexdigest()
                 for x in r.SMOKE_NAMES}
        self.assertEqual(after, before)
        self.assertIn('Cycle:BusinessWriteAttempt', [x['route'] for x in
            next(f for f in report['flows'] if f['id'] == 'cycle_source_chain')['steps']])

    def test_03_isolated_cycle_writes_are_only_disposable(self):
        result = r.execute('cycle_source_chain')
        self.assertEqual(result['flow_count'], 1)
        self.assertEqual(result['flow_passed'], 1, result)
        statuses = [(x['route'], x['normalized_status']) for x in result['flows'][0]['steps']]
        self.assertEqual(statuses[0], ('Cycle:Create', 'denied'))
        self.assertEqual(statuses[-1], ('Cycle:BusinessWriteAttempt', 'denied'))
        self.assertIn(('Cycle:Summary', 'partial'), statuses)
        self.assertFalse(result['final_acceptance_started'])

    def test_04_fixed_exports_are_ready_to_use_request_v1_files(self):
        with tempfile.TemporaryDirectory(prefix='ec247-export-parent-') as folder:
            dest = Path(folder) / 'export'
            receipt = r.prepare(str(dest))
            self.assertEqual(receipt['file_count'], len(r.FIXTURE_NAMES) +
                             len(r.REQUEST_KEYS) + 2)
            self.assertFalse(receipt['native_smokes_executed'])
            for name in r.FIXTURE_NAMES:
                self.assertEqual((dest / name).read_bytes(), (r.FIX / name).read_bytes())
            for action, mode in r.REQUEST_KEYS:
                file = dest / 'requests' / ((action + '-' + mode).lower() + '.json')
                doc = json.loads(file.read_bytes())
                self.assertEqual((doc['schema'], doc['action'], doc['mode']),
                                 ('ces.unified_action_router.request.v1', action, mode))
            plan = (dest / 'native-smoke-commands.txt').read_text()
            self.assertEqual(plan.count('pwsh -NoProfile -File'), 15)
            commands = (dest / 'router-request-commands.txt').read_text()
            self.assertEqual(commands.count('python3 -I scripts/ces_router.py'),
                             len(r.REQUEST_KEYS))
            self.assertFalse((dest / 'native-smoke-results.json').exists())

    def test_05_existing_export_directory_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix='ec247-already-exists-') as folder:
            output = Path(folder) / 'data'
            output.mkdir()
            sentinel = output / 'existing.txt'
            sentinel.write_text('KEEP', encoding='utf-8')
            with self.assertRaisesRegex(r.RegressionError,
                                        'EXPORT_DESTINATION_ALREADY_EXISTS'):
                r.prepare(str(output))
            self.assertEqual(sentinel.read_text(encoding='utf-8'), 'KEEP')

    def test_06_own_project_tree_is_not_export_destination(self):
        with self.assertRaisesRegex(r.RegressionError,
                                    'EXPORT_DESTINATION_UNSAFE_OR_INSIDE_PACKAGE'):
            r.prepare(str(r.ROOT / 'never-create-ec247-export'))

    def test_07_modified_fixture_bytes_are_refused_before_execution(self):
        with tempfile.TemporaryDirectory(prefix='ec247-tamper-') as folder:
            alternate = Path(folder) / 'copied'
            alternate.mkdir()
            for name in (*r.FIXTURE_NAMES, 'manifest.json'):
                (alternate / name).write_bytes((r.FIX / name).read_bytes())
            with (alternate / 'cycle-input.txt').open('ab') as handle:
                handle.write(b'TAMPERED')
            with mock.patch.object(r, 'FIX', alternate), mock.patch.object(
                    r, 'MANIFEST', alternate / 'manifest.json'):
                with self.assertRaisesRegex(r.RegressionError,
                                            'REGRESSION_FIXTURE_PIN_DRIFT'):
                    r.load_plan()

    def test_08_stale_native_smoke_sha_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='ec247-stale-smoke-') as folder:
            manifest = json.loads(r.MANIFEST.read_text(encoding='utf-8'))
            manifest['native_smokes'][0]['sha256'] = '0' * 64
            other = Path(folder) / 'manifest.json'
            other.write_text(json.dumps(manifest), encoding='utf-8')
            with mock.patch.object(r, 'MANIFEST', other):
                with self.assertRaisesRegex(r.RegressionError,
                                            'REGRESSION_ORIGINAL_SMOKE_CHANGED'):
                    r.load_plan()

    def test_09_duplicate_json_keys_refused(self):
        with self.assertRaisesRegex(r.RegressionError, 'FIXTURE_DUPLICATE_JSON_KEY'):
            r.strict_json(b'{"schema":"first","schema":"second"}')

    def test_10_synthetic_cli_is_single_json_and_no_native_acceptance(self):
        script = r.ROOT / 'construction/ec247_regression/runner.py'
        for args in (['--plan'], ['--run', '--only', 'provider_network_boundary']):
            proc = subprocess.run([sys.executable, '-I', '-B', str(script), *args],
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertEqual(len(proc.stdout.splitlines()), 1)
            self.assertFalse(proc.stderr)
            doc = json.loads(proc.stdout)
            if '--run' in args:
                self.assertIs(doc['final_acceptance_started'], False)
            else:
                self.assertEqual(doc['final_acceptance'], 'NOT_STARTED')


if __name__ == '__main__':
    unittest.main(verbosity=2)
