#!/usr/bin/env python3
"""EC-155 focused offline contract fixtures. Not CES PowerShell/Smoke testing."""
from __future__ import annotations

import copy
import unittest

from action_registry import (
    RegistryError,
    ROUTABLE,
    check_registry,
    describe,
    read_registry,
    resolve,
    validate_registry,
)


class ActionModeRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = read_registry()

    def test_authored_routes_and_planned_capabilities_are_disjoint(self):
        data = self.registry
        self.assertEqual(len(data['supported_actions']), 7)
        self.assertEqual(len(data['routes']), 16)
        self.assertEqual(len(data['planned_capabilities']), 29)
        self.assertEqual(len({r['id'].casefold() for r in data['routes']}), 16)
        self.assertTrue(all(not p['cli_handler_registered'] for p in data['planned_capabilities']))
        self.assertTrue(all(r['implementation_state'] == 'SOURCE_AUTHORED_RUNTIME_UNVERIFIED' for r in data['routes']))

    def test_default_action_and_collect_modes(self):
        implicit = resolve(self.registry)
        self.assertEqual((implicit['canonical_action'], implicit['effective_mode']), ('Inspect', None))
        self.assertFalse(implicit['action_was_explicit'])
        self.assertEqual(implicit['decision'], ROUTABLE)
        default_collect = resolve(self.registry, action='cOlLeCt')
        self.assertEqual(default_collect['route']['id'], 'Collect:WorkingTree')
        self.assertEqual(resolve(self.registry, action='COLLECT', mode='dELIVEREDtARGET')['route']['id'],
                         'Collect:DeliveredTarget')

    def test_inspect_mode_ignored_including_unknown_mode(self):
        for mode in (None, 'Snapshot', 'RandomOtherMode', '', 'Sequence'):
            with self.subTest(mode=mode):
                result = resolve(self.registry, action='INSPECT', mode=mode)
                self.assertEqual(result['route']['id'], 'Inspect')
                self.assertIsNone(result['effective_mode'])
        self.assertTrue(resolve(self.registry, action='Inspect', mode='other')['mode_was_explicit'])

    def test_omitted_snapshot_routes_despite_workingtree_parameter_default(self):
        for action in ('Reconcile', 'CodePrepare', 'CodeValidate', 'CodeSave'):
            with self.subTest(action=action):
                implicit = resolve(self.registry, action=action)
                explicit = resolve(self.registry, action=action.lower(), mode='sNaPsHoT')
                self.assertEqual(implicit['route']['id'], action + ':Snapshot')
                self.assertEqual(explicit['route']['id'], action + ':Snapshot')
                self.assertEqual(implicit['effective_mode'], 'Snapshot')
                self.assertFalse(implicit['mode_was_explicit'])
        save = resolve(self.registry, action='CodeSave')
        self.assertTrue(save['requires_explicit_persist_authorization'])
        self.assertFalse(save['read_only'])
        self.assertTrue(save['no_execution_or_permission_grant'])
        self.assertIsNone(save['cli_rejection_exit_code'])
        self.assertEqual(save['runtime_exit_code'], 'UNKNOWN_UNTIL_NATIVE_EXECUTION')

    def test_codeshow_requires_explicit_mode(self):
        implicit = resolve(self.registry, action='CodeShow')
        self.assertEqual((implicit['decision'], implicit['reason_code'], implicit['cli_rejection_exit_code']),
                         ('invalid_input', 'CODE_SHOW_MODE_REQUIRED', 4))
        for mode in self.registry['action_modes']['CodeShow']['modes']:
            with self.subTest(mode=mode):
                result = resolve(self.registry, action='CODEshow', mode=mode.swapcase())
                self.assertEqual(result['route']['id'], 'CodeShow:' + mode)
                self.assertTrue(result['read_only'])
        self.assertEqual(resolve(self.registry, action='CodeShow', mode='WorkingTree')['cli_rejection_exit_code'], 4)

    def test_unimplemented_modes_do_not_fake_a_handler(self):
        cases = [
            ('Collect', 'ProposedPR', 'not_implemented', 'NOT_IMPLEMENTED', 3),
            ('Collect', '', 'not_implemented', 'NOT_IMPLEMENTED', 3),
            ('Reconcile', 'WorkingTree', 'invalid_input', 'SNAPSHOT_MODE_REQUIRED', 4),
            ('CodePrepare', 'MultiSource', 'invalid_input', 'SNAPSHOT_MODE_REQUIRED', 4),
            ('CodeSave', 'Staged', 'invalid_input', 'SNAPSHOT_MODE_REQUIRED', 4),
            ('CodeShow', 'Delete', 'invalid_input', 'CODE_SHOW_MODE_REQUIRED', 4),
            ('CodeShow', '', 'invalid_input', 'CODE_SHOW_MODE_REQUIRED', 4),
            ('QualityRun', None, 'not_implemented', 'NOT_IMPLEMENTED', 3),
            ('', None, 'not_implemented', 'NOT_IMPLEMENTED', 3),
            ('  Inspect', None, 'not_implemented', 'NOT_IMPLEMENTED', 3),
        ]
        for action, mode, status, reason, code in cases:
            with self.subTest(action=action, mode=mode):
                result = resolve(self.registry, action=action, mode=mode)
                self.assertEqual((result['decision'], result['reason_code'], result['cli_rejection_exit_code']),
                                 (status, reason, code))
                self.assertIsNone(result['route'])
                self.assertFalse(result['handler_invoked'])
        self.assertEqual(resolve(self.registry, action='Collect', mode='ProposedPR')['planned_capability']['name'],
                         'Collect:ProposedPR')
        self.assertEqual(resolve(self.registry, action='QualityRun')['planned_capability']['name'], 'QualityRun')

    def test_planned_query_not_confused_with_runtime_action(self):
        show = describe(self.registry, 'codeshow')
        self.assertEqual(len(show['routes']), 9)
        self.assertEqual(show['kind'], 'source_authored_action')
        plan = describe(self.registry, 'QualityRun')
        self.assertEqual(plan['kind'], 'planned_capability')
        self.assertFalse(plan['registered_handler'])
        self.assertEqual(describe(self.registry, 'NoSuchAction')['runtime_state'], 'NOT_IMPLEMENTED')

    def test_registry_cannot_upgrade_planned_action_or_remove_authorization(self):
        data = copy.deepcopy(self.registry)
        data['planned_capabilities'][0]['cli_handler_registered'] = True
        with self.assertRaises(RegistryError):
            validate_registry(data)
        data = copy.deepcopy(self.registry)
        data['routes'][6]['effect'] = 'READ_ONLY'  # CodeSave
        with self.assertRaises(RegistryError):
            validate_registry(data)
        data = copy.deepcopy(self.registry)
        data['action_modes']['Collect']['reject']['exit_code'] = 0
        with self.assertRaises(RegistryError):
            validate_registry(data)

    def test_trace_and_source_preflight_are_unchanged(self):
        result = check_registry(self.registry)
        self.assertEqual(result['verdict'], 'STATIC_CONTRACT_MATCH', result)
        self.assertEqual(result['problems'], [])
        self.assertEqual(result['details']['authored_route_count'], 16)
        self.assertEqual(result['details']['planned_capability_count'], 29)
        self.assertEqual(result['details']['native_powershell'], 'NOT_RUN')

    def test_mode_entry_reordering_is_rejected(self):
        data = copy.deepcopy(self.registry)
        data['routes'][1], data['routes'][2] = data['routes'][2], data['routes'][1]
        with self.assertRaises(RegistryError):
            validate_registry(data)
        data = copy.deepcopy(self.registry)
        data['routes'].append(copy.deepcopy(data['routes'][0]))
        with self.assertRaises(RegistryError):
            validate_registry(data)


if __name__ == '__main__':
    unittest.main()
