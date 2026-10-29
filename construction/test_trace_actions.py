#!/usr/bin/env python3
"""Small offline EC-152 fixtures for trace query correctness; not CES runtime tests."""
from __future__ import annotations

import copy
import unittest

from trace_actions import EXPECTED, check_trace, find_route, read_trace, safe_source


class TraceQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = read_trace()

    def test_all_authored_modes_have_exactly_one_route(self):
        ids = [(r['action'], r['mode']) for r in self.receipt['routes']]
        expected = {(action, mode) for action, modes in EXPECTED.items() for mode in modes}
        self.assertEqual(set(ids), expected)
        self.assertEqual(len(ids), len(set(ids)))

    def test_case_insensitive_lookup_and_default_routing(self):
        self.assertEqual(find_route(self.receipt, 'inspect', None)['id'], 'Inspect')
        self.assertEqual(find_route(self.receipt, 'COLLECT', None)['id'], 'Collect:WorkingTree')
        self.assertEqual(find_route(self.receipt, 'collect', 'deliveredtarget')['id'], 'Collect:DeliveredTarget')
        self.assertEqual(find_route(self.receipt, 'codesave', None)['id'], 'CodeSave:Snapshot')
        self.assertEqual(find_route(self.receipt, 'codeshow', 'sequence')['id'], 'CodeShow:Sequence')

    def test_unimplemented_and_invalid_mode_fail_closed(self):
        for action, mode in [('QualityRun', None), ('CodeShow', None), ('Collect', 'ProposedPR'),
                             ('Inspect', 'Snapshot'), ('CodeShow', 'Delete')]:
            with self.subTest(action=action, mode=mode), self.assertRaises(ValueError):
                find_route(self.receipt, action, mode)

    def test_relative_path_gate_does_not_allow_escape(self):
        for path in ['scripts/../../anything.ps1','/tmp/anything.ps1',
                     'scripts/ces.ps1/..', 'scripts/ces.pwsh', 'tests\\Inspect.Smoke.ps1']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                safe_source(path)

    def test_static_source_trace_matches_frozen_receipt(self):
        result = check_trace(self.receipt)
        self.assertEqual(result['problems'], [], result)
        # Future authorized edits may move source without destroying the archived R150 receipt.
        self.assertIsInstance(result['warnings'], list)
        self.assertEqual(result['primary_smoke_suites'], 15)
        self.assertEqual(result['native_runtime_validation'], 'NOT_RUN')

    def test_missing_handler_is_not_treated_as_functional(self):
        altered = copy.deepcopy(self.receipt)
        altered['routes'][0]['handler']['symbol'] = 'Unimplemented-Handler'
        result = check_trace(altered)
        self.assertEqual(result['verdict'], 'STATIC_TRACE_FAIL')
        self.assertTrue(any('handler not found' in problem for problem in result['problems']))


if __name__ == '__main__':
    unittest.main()
