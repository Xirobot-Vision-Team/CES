#!/usr/bin/env python3
"""Small EC246 functional checks; no host or external provider access."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import sys
from unittest import TestCase, main, mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import route_help
from unified_action_router import dispatch


class RouteHelpTests(TestCase):
    def test_live_routes_exact_74_and_kinds(self):
        _, rows = route_help._load()
        self.assertEqual(len(rows), 74)
        kinds = {k: sum(r['route_kind'] == k for r in rows) for k in
                 ('LEGACY_NATIVE_R150', 'CLI', 'API', 'PREVIEW', 'HOST_REQUIRED')}
        self.assertEqual(kinds, {'LEGACY_NATIVE_R150': 16, 'CLI': 39, 'API': 7,
                                 'PREVIEW': 1, 'HOST_REQUIRED': 11})

    def test_cycle_help_not_confused_with_old_actions_family(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = route_help.main(['--action', 'Cycle', '--json'])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result['count'], 15)
        self.assertIn('BusinessWriteAttempt', [r['mode'] for r in result['routes']])

    def test_vetted_due_example_has_true_request_shape(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = route_help.main(['--action', 'Due', '--mode', 'Evaluate', '--example'])
        self.assertEqual(code, 0)
        example = json.loads(output.getvalue())['request']
        self.assertEqual(example['schema'], 'ces.unified_action_router.request.v1')
        self.assertEqual(set(example), {'schema', 'action', 'mode', 'parameters'})
        result, exit_code = dispatch('Due', 'Evaluate', example)
        self.assertEqual((result['schema'], result['status'], exit_code),
                         ('ces.unified_action_router.v2', 'partial', 2))
        self.assertFalse(result['business_effect_verified'])

    def test_two_documented_host_examples_refuse_before_handler(self):
        cat, _ = route_help._load()
        for e in cat['examples']:
            if e['action'] not in ('IssueCreate', 'DocsOnlyPublish'):
                continue
            res, code = dispatch(e['action'], e['mode'], e['request'])
            self.assertEqual((res['status'], code), ('denied', 3))
            self.assertFalse(res['handler_attempted'])
            self.assertFalse(res['handler_invoked'])
            self.assertEqual(res['reason_code'],
                             'ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED')

    def test_schema_review_examples_are_genuine_local_handlers(self):
        cat, _ = route_help._load()
        for e in cat['examples']:
            if e['action'] != 'SchemaReview':
                continue
            res, code = dispatch(e['action'], e['mode'], e['request'])
            self.assertEqual((res['status'], code), ('partial', 2))
            self.assertTrue(res['handler_invoked'])
            self.assertFalse(res['permissions_granted_by_router'])

    def test_unvetted_template_is_not_fabricated(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = route_help.main(['--action', 'DeliveryPreview', '--mode',
                                    'Preview', '--example'])
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(output.getvalue())['reason_code'],
                         'NO_VETTED_EXAMPLE_FOR_THIS_ROUTE')

    def test_product_matrix_drift_causes_safe_refusal(self):
        original = route_help._read_json
        def tamper(path: Path):
            result = original(path)
            if path == route_help.MATRIX:
                result = copy.deepcopy(result)
                result['unified_v5_routes'][0]['handler'] = 'unsafe:wrong'
            return result
        with mock.patch.object(route_help, '_read_json', side_effect=tamper):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = route_help.main(['--action', 'Due'])
        self.assertEqual(code, 4)
        self.assertIn(json.loads(output.getvalue())['reason_code'],
                      ('PACKAGED_HELP_PRODUCT_MATRIX_DRIFT', 'PACKAGED_HELP_ROUTE_DRIFT'))


if __name__ == '__main__':
    main()
