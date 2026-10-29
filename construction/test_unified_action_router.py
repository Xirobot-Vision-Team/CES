#!/usr/bin/env python3
"""EC241 focused real route/permission checks; not native PS7 or enterprise acceptance."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

# Allow `python -m unittest construction.test_unified_action_router` from the skill root.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_action_router import (ROUTES, LEGACY, SCHEMA, REQUEST_SCHEMA,
                                   dispatch, inventory)

ROOT = Path(__file__).resolve().parent.parent
ENTRY = ROOT / 'scripts' / 'ces_router.py'


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ec241-real-router-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.request_path = self.root / 'invocation.json'

    def run_entry(self, action, mode, *, extra=None, raw=None):
        value = {'schema': REQUEST_SCHEMA, 'action': action, 'mode': mode}
        if extra is not None:
            value.update(extra)
        self.request_path.write_bytes(raw if raw is not None else
                                      json.dumps(value, ensure_ascii=True).encode())
        proc = subprocess.run([sys.executable, '-I', str(ENTRY), '-Action', action,
                               '-Mode', mode, '-RequestPath', str(self.request_path)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=30, check=False)
        self.assertEqual(proc.stderr, '', proc.stderr)
        self.assertEqual(len(proc.stdout.splitlines()), 1, proc.stdout)
        output = json.loads(proc.stdout)
        self.assertEqual(output['schema'], SCHEMA)
        self.assertFalse(output['business_effect_verified'])
        self.assertFalse(output['permissions_granted_by_router'])
        return proc.returncode, output

    def test_inventory_is_explicit_fixed_handlers(self):
        result = inventory()
        self.assertEqual(result['route_count'], len(ROUTES) + sum(len(x) for x in LEGACY.values()))
        self.assertGreaterEqual(result['route_count'], 65)
        self.assertEqual(len({(x['action'].casefold(), str(x['mode']).casefold())
                              for x in result['routes']}), result['route_count'])
        self.assertTrue(all(x['handler'] and x['effect'] for x in result['routes']))
        self.assertFalse(result['host_only_routes_execute_without_host_bridge'])
        self.assertTrue(any(x['action'] == 'IssueCreate' and x['mode'] == 'Create' and
                            not x['invokable_by_new_router'] for x in result['routes']))

    def test_dedicated_python_cli_lists_inventory(self):
        proc = subprocess.run([sys.executable, '-I', str(ENTRY), '--list-routes'],
                              capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)['route_count'], inventory()['route_count'])

    def test_real_due_calendar_api_partial_without_business_claim(self):
        rc, out = self.run_entry('Due', 'Evaluate', extra={'parameters': {
            'project_timezone': 'UTC', 'cadence': 'day',
            'observed_at': '2026-10-24T12:00:00Z', 'never_processed': True}})
        self.assertEqual(rc, 2)
        self.assertTrue(out['handler_invoked'])
        self.assertEqual(out['handler_status'], 'partial')
        self.assertEqual(out['handler_result']['decision']['state'], 'DUE')
        self.assertEqual(out['handler_result']['limitations']['scheduler_or_report_executed'], False)

    def test_real_api_invalid_calendar_is_propagated(self):
        rc, out = self.run_entry('Due', 'Evaluate', extra={'parameters': {
            'project_timezone': 'UTC', 'cadence': 'invalid'}})
        self.assertEqual(rc, 4)
        self.assertEqual(out['handler_status'], 'invalid_input')
        self.assertTrue(out['handler_invoked'])

    def test_real_multisource_cli_offline_denial_not_fake_success(self):
        rc, out = self.run_entry('CodePrepare', 'MultiSource', extra={'argv': [
            '--source-mode', 'WorkingTree']})
        self.assertEqual(rc, 4)
        self.assertTrue(out['handler_invoked'])
        self.assertEqual(out['handler_exit_code'], 4)
        self.assertIsNone(out['handler_result']['context'])

    def test_real_cycle_create_requires_explicit_private_write_gate(self):
        store = self.root / 'private'
        store.mkdir(mode=0o700)
        os.chmod(store, 0o700)
        snap = self.root / 'snapshot.bytes'
        snap.write_bytes(b'EC241 local synthetic snapshot\n')
        action_set = self.root / 'actions.json'
        action_set.write_text(json.dumps([{
            'step_id': 'step_first', 'action': 'Inspect',
            'mode': 'Snapshot', 'depends_on': []}]))
        args = ['--store', str(store), '--snapshot-file', str(snap),
                '--source-ref', 'local:ec241-synthetic', '--actor-origin', 'human',
                '--actor-subject', 'local-ec241-operator', '--actions-json', str(action_set)]
        rc, blocked = self.run_entry('Cycle', 'Create', extra={'argv': args})
        self.assertEqual(rc, 3)
        self.assertFalse(blocked['handler_invoked'])
        self.assertEqual(blocked['reason_code'], 'ROUTER_PRIVATE_WRITE_EXPLICIT_OPT_IN_REQUIRED')
        self.assertEqual(list(store.iterdir()), [])
        if os.name != 'posix':
            return
        rc, written = self.run_entry('Cycle', 'Create', extra={
            'argv': args, 'acknowledge_private_ces_write': True})
        self.assertEqual(rc, 2, written)
        self.assertEqual(written['handler_result']['status'], 'metadata_created_not_started')
        self.assertFalse(written['handler_result']['execution_proven'])
        run_id = written['handler_result']['run_id']
        self.assertTrue((store / (run_id + '.cycle.json')).exists())
        rc, inspected = self.run_entry('Cycle', 'Inspect', extra={
            'argv': ['--store', str(store), '--run-id', run_id]})
        self.assertEqual(rc, 2)
        self.assertTrue(inspected['handler_result']['metadata_valid'])
        self.assertFalse(inspected['handler_result']['execution_proven'])
        record = inspected['handler_result']['record']
        rc, summary = self.run_entry('Cycle', 'Summary', extra={
            'argv': ['--store', str(store), '--run-id', run_id,
                     '--expected-record-sha256', record['record_sha256'],
                     '--expected-action-set-sha256', record['action_set_sha256'],
                     '--expected-input-sha256', record['input']['sha256']]})
        self.assertEqual(rc, 2)
        self.assertEqual(summary['handler_result']['status'], 'NOT_STARTED')
        self.assertTrue(summary['handler_result']['checks']['independent_pins_provided'])
        self.assertFalse(summary['handler_result']['overall_success_proven'])
        self.assertEqual(summary['handler_result']['counts']['verified_success'], 0)

    def test_cycle_missing_run_reports_unknown_not_success(self):
        rc, out = self.run_entry('Cycle', 'Summary', extra={'argv': [
            '--store', str(self.root), '--run-id', 'run_v1_' + 'a' * 48]})
        self.assertEqual(rc, 5)
        self.assertTrue(out['handler_invoked'])
        self.assertEqual(out['handler_status'], 'UNKNOWN_BLOCKED')
        self.assertIsNone(out['handler_result']['record_binding']['record_sha256'])

    def test_unknown_action_and_mode_are_not_reinterpreted(self):
        for action, mode in [('NoSuchAction', 'Run'), ('Cycle', 'PretendSucceeded'),
                             ('IssueCreate', 'EditExisting')]:
            with self.subTest(action=action, mode=mode):
                rc, out = self.run_entry(action, mode)
                self.assertEqual(rc, 3)
                self.assertEqual(out['reason_code'], 'ROUTER_ACTION_OR_MODE_UNREGISTERED')
                self.assertFalse(out['handler_invoked'])

    def test_legacy_native_routes_cannot_skip_original_code_save_gate(self):
        for action, mode in [('CodeSave', 'Snapshot'), ('CodeShow', 'List'), ('Inspect', 'Other')]:
            with self.subTest(action=action, mode=mode):
                rc, out = self.run_entry(action, mode)
                self.assertEqual(rc, 3)
                self.assertEqual(out['reason_code'], 'ROUTER_LEGACY_POWERSHELL_REQUIRED')
                self.assertFalse(out['handler_invoked'])

    def test_host_authority_cannot_be_self_declared_in_json(self):
        for a, m in [('IssueCreate', 'Create'), ('QualityRun', 'Execute'),
                     ('DeliverySend', 'Send'), ('DocsOnlyPublish', 'LocalSandbox'),
                     ('ReportPublish', 'PrivateTest')]:
            with self.subTest(route=(a, m)):
                rc, out = self.run_entry(a, m)
                self.assertEqual(rc, 3)
                self.assertEqual(out['effect_class'], 'INDEPENDENT_HOST_BRIDGE_REQUIRED')
                self.assertEqual(out['reason_code'], 'ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED')
                self.assertFalse(out['handler_invoked'])

    def test_host_json_cannot_pass_untrusted_transport_or_secrets(self):
        rc, out = self.run_entry('DeliverySend', 'Send', extra={
            'parameters': {'host_access': {'enable_live_sandbox_send': True}}})
        self.assertEqual(rc, 4)
        self.assertEqual(out['reason_code'], 'ROUTER_HOST_ONLY_CANNOT_ACCEPT_FAKE_CREDENTIAL_INPUT')
        self.assertFalse(out['handler_invoked'])

    def test_network_read_requires_separate_opt_in(self):
        rc, out = self.run_entry('IssueSync', 'Read', extra={
            'argv': ['--allow-network']})
        self.assertEqual(rc, 3)
        self.assertEqual(out['reason_code'], 'ROUTER_NETWORK_OPT_IN_REQUIRED')
        self.assertFalse(out['handler_invoked'])

    def test_network_read_opt_in_does_not_grant_provider_access(self):
        rc, out = self.run_entry('IssueSync', 'Read', extra={
            'argv': ['--allow-network'], 'allow_network_read': True})
        self.assertNotEqual(rc, 2)
        self.assertTrue(out['handler_invoked'] or out['status'] == 'unavailable')
        self.assertFalse(out['business_effect_verified'])

    def test_issue_eligibility_stdin_input_reaches_real_handler_offline(self):
        rc, out = self.run_entry('IssueCreate', 'Eligibility', extra={
            'argv': [], 'stdin_json': {}})
        self.assertEqual(rc, 4)
        self.assertTrue(out['handler_invoked'])
        self.assertEqual(out['handler_result']['reason_code'], 'ISSUE_ELIGIBILITY_CLI_REQUEST_INVALID')
        self.assertEqual(out['handler_result']['authorization'], 'NOT_GRANTED')

    def test_issue_eligibility_cannot_write_via_stdin_command_switch(self):
        rc, out = self.run_entry('IssueCreate', 'Eligibility', extra={
            'argv': ['--some-other-command'], 'stdin_json': {}})
        self.assertEqual(rc, 4)
        self.assertFalse(out['handler_invoked'])

    def test_malformed_and_duplicate_json_cannot_enter_backend(self):
        for raw in (b'bad json', b'{"schema":"a","schema":"b"}',
                    b'{"schema":"a","Schema":"b"}', b'\xef\xbb\xbf{}', b'{}'):
            with self.subTest(raw=raw):
                rc, out = self.run_entry('Due', 'Evaluate', raw=raw)
                self.assertEqual(rc, 4)
                self.assertFalse(out['handler_invoked'])

    def test_request_action_mode_exact_binding(self):
        rc, out = self.run_entry('Cycle', 'Next', extra={'action': 'Due', 'argv': []})
        self.assertEqual(rc, 4)
        self.assertEqual(out['reason_code'], 'ROUTER_ACTION_MODE_BINDING_MISMATCH')

    @unittest.skipUnless(os.name == 'posix', 'O_NOFOLLOW request no-symlink test requires POSIX')
    def test_symlink_request_refused_without_opening_target(self):
        f = self.root / 'external.json'
        f.write_text('{}')
        self.request_path.symlink_to(f)
        proc = subprocess.run([sys.executable, '-I', str(ENTRY), '-Action', 'Due',
                               '-Mode', 'Evaluate', '-RequestPath', str(self.request_path)],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(json.loads(proc.stdout)['reason_code'], 'ROUTER_REQUEST_UNAVAILABLE')

    def test_private_write_ack_is_not_cross_route_permission(self):
        rc, out = self.run_entry('Due', 'Evaluate', extra={
            'acknowledge_private_ces_write': True, 'parameters': {}})
        self.assertEqual(rc, 4)
        self.assertFalse(out['handler_invoked'])

    def test_python_result_stays_single_json_not_native_success(self):
        rc, out = self.run_entry('Collect', 'ProposedPR', extra={'argv': []})
        self.assertEqual(rc, 4)
        self.assertTrue(out['handler_invoked'])
        self.assertEqual(out['handler_result']['exit_code'], 4)
        self.assertFalse(out['business_effect_verified'])

    def test_api_initializer_blocks_unknown_keys(self):
        rc, out = self.run_entry('ReportPrepare', 'Prepare', extra={
            'init': {'untrusted_callback': 'execute arbitrary source'}, 'parameters': {}})
        self.assertEqual(rc, 4)
        self.assertEqual(out['reason_code'], 'ROUTER_API_INITIALIZER_FIELD_UNEXPECTED')

    def test_cli_prevents_transmitting_nonjson_backend_debug_as_success(self):
        # argparse's usage text is stderr, not a returned JSON business result.
        rc, out = self.run_entry('Cycle', 'Next', extra={'argv': ['--invalid-flag']})
        self.assertEqual(rc, 5)
        self.assertEqual(out['reason_code'], 'ROUTER_HANDLER_NONJSON_OUTPUT')
        self.assertFalse(out['handler_invoked'])


if __name__ == '__main__':
    unittest.main()
