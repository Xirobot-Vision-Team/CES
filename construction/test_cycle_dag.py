#!/usr/bin/env python3
"""EC232 focused tests: actual EC231 store + deterministic graph-only outcomes."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import cycle_dag as dag
import cycle_run_metadata as md

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / 'references/cycle-dag-result.v1.schema.json'


def task(step_id: str, *depends_on: str) -> dict:
    return {"step_id": "step_" + step_id, "action": "CodePrepare", "mode": "Snapshot",
            "depends_on": ["step_" + name for name in depends_on]}


@unittest.skipUnless(os.name == 'posix', 'EC231 private record storage is POSIX-only')
class CycleDagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix='ec232-cycle-')
        self.addCleanup(self.tmp.cleanup)
        self.private_dir = Path(self.tmp.name) / 'runs'
        self.store = md.CycleMetadataStore(self.private_dir)
        self.inspector = dag.CycleDagInspector(self.private_dir)
        self.input_bytes = b'ec232 actual caller snapshot bytes\x00\n'
        self.actions = [task('code'),
                        {**task('quality', 'code'), 'action': 'QualityRun', 'mode': None},
                        {**task('report', 'quality'), 'action': 'ReportPrepare', 'mode': None}]

    def create(self, actions=None, **options) -> dict:
        return self.store.create(
            snapshot_bytes=self.input_bytes, source_ref='git:local/snapshot',
            actor_origin='service', actor_subject='declared-caller',
            actions=self.actions if actions is None else actions, **options)

    def check(self, record: dict, **kwargs) -> dict:
        return self.inspector.check(record['run_id'], **kwargs)

    def file(self, rec: dict) -> Path:
        return self.private_dir / (rec['run_id'] + '.cycle.json')

    def write_record(self, rec: dict) -> None:
        rec['record_sha256'] = md.digest(md.DOMAIN_RECORD, md._without_digest(rec))
        self.file(rec).write_bytes(md.canonical(rec))

    def assert_no_effects(self, result: dict) -> None:
        self.assertEqual(set(result['effects'].values()), {False})
        self.assertFalse(result['trust']['input_authenticated'])
        self.assertFalse(result['trust']['actor_verified'])
        self.assertFalse(result['trust']['permissions_granted'])
        self.assertEqual(result['trust']['metadata_integrity'], 'UNSIGNED_LOCAL_SELF_HASH_ONLY')

    def test_real_code_quality_report_chain_with_layers(self) -> None:
        rec = self.create()
        original = self.file(rec).read_bytes()
        res = self.check(rec)
        self.assertEqual(res['status'], dag.VALID)
        self.assertEqual(res['reason_code'], 'CYCLE_DAG_ACYCLIC')
        self.assertEqual(res['topological_order'], ['step_code', 'step_quality', 'step_report'])
        self.assertEqual(res['topological_layers'], [['step_code'], ['step_quality'], ['step_report']])
        self.assertEqual(res['step_count'], 3)
        self.assertEqual(res['dependency_edge_count'], 2)
        self.assertEqual(res['cycle_components'], [])
        self.assertEqual(res['cycle_witness'], [])
        self.assertEqual(self.file(rec).read_bytes(), original, 'Read-only DAG check must not mutate EC231 record')
        self.assertEqual(self.store.load(rec['run_id'])['dependency_resolution'], 'NOT_EVALUATED_EC232')
        self.assert_no_effects(res)

    def test_actual_digests_and_declared_provenance_are_bound(self) -> None:
        rec = self.create(input_completeness='DECLARED_PARTIAL')
        res = self.check(rec, expected_record_sha256=rec['record_sha256'],
                         expected_action_set_sha256=rec['action_set_sha256'],
                         expected_input_sha256=hashlib.sha256(self.input_bytes).hexdigest())
        self.assertEqual(res['record_sha256'], rec['record_sha256'])
        self.assertEqual(res['action_set_sha256'], rec['action_set_sha256'])
        self.assertEqual(res['input_sha256'], rec['input']['sha256'])
        self.assertEqual(res['source_ref'], 'git:local/snapshot')
        self.assertEqual(res['actor_origin'], 'service')
        self.assertEqual(res['actor_subject'], 'declared-caller')
        self.assertEqual(res['input_completeness'], 'DECLARED_PARTIAL')
        self.assertEqual(res['metadata_dependency_resolution'], 'NOT_EVALUATED_EC232')
        self.assertRegex(res['graph_sha256'], r'^[0-9a-f]{64}$')
        self.assert_no_effects(res)

    def test_stable_topological_layers_use_declaration_order_not_dict_order(self) -> None:
        actions = [task('report', 'quality'), task('side'), task('quality', 'code'),
                   task('code'), task('end', 'report', 'side')]
        rec = self.create(actions)
        a, b = self.check(rec), self.check(rec)
        self.assertEqual(a, b)
        self.assertEqual(a['topological_layers'], [
            ['step_side', 'step_code'], ['step_quality'], ['step_report'], ['step_end']])
        self.assertEqual(a['topological_order'], ['step_side', 'step_code', 'step_quality', 'step_report', 'step_end'])

    def test_disconnected_graph_single_layer_for_all_roots(self) -> None:
        rec = self.create([task('z'), task('a'), task('x')])
        res = self.check(rec)
        self.assertEqual(res['topological_layers'], [['step_z', 'step_a', 'step_x']])
        self.assertEqual(res['dependency_edge_count'], 0)

    def test_two_node_cycle_explicitly_blocked_without_order(self) -> None:
        rec = self.create([task('a', 'b'), task('b', 'a')])
        res = self.check(rec)
        self.assertEqual(res['status'], dag.CYCLIC)
        self.assertEqual(res['reason_code'], 'CYCLE_DAG_CYCLE_DETECTED')
        self.assertEqual(res['cycle_components'], [['step_a', 'step_b']])
        self.assertEqual(res['cycle_witness'], ['step_a', 'step_b', 'step_a'])
        self.assertEqual(res['blocked_step_ids'], ['step_a', 'step_b'])
        self.assertEqual(res['topological_order'], [])
        self.assertEqual(res['topological_layers'], [])
        self.assert_no_effects(res)

    def test_three_node_cycle_and_downstream_not_misclassified_as_cyclic(self) -> None:
        rec = self.create([task('downstream', 'a'), task('root'), task('a', 'b'),
                           task('b', 'c'), task('c', 'a'), task('other', 'root')])
        res = self.check(rec)
        self.assertEqual(res['status'], dag.CYCLIC)
        self.assertEqual(res['cycle_components'], [['step_a', 'step_b', 'step_c']])
        self.assertEqual(res['cycle_witness'], ['step_a', 'step_b', 'step_c', 'step_a'])
        self.assertEqual(res['blocked_step_ids'], ['step_downstream', 'step_a', 'step_b', 'step_c'])
        self.assertNotIn('step_root', res['blocked_step_ids'])
        self.assertNotIn('step_other', res['blocked_step_ids'])
        self.assertEqual(res['topological_order'], [], 'No actionable partial order on a cyclic graph')

    def test_multiple_disjoint_cycles_all_reported_in_stable_order(self) -> None:
        rec = self.create([task('b', 'c'), task('a', 'b'), task('c', 'a'),
                           task('e', 'f'), task('f', 'e'), task('standalone')])
        result = self.check(rec)
        self.assertEqual(result['cycle_components'], [['step_b', 'step_a', 'step_c'],
                                                     ['step_e', 'step_f']])
        self.assertEqual(result['cycle_witness'], ['step_b', 'step_c', 'step_a', 'step_b'])
        self.assertNotIn('step_standalone', result['blocked_step_ids'])

    def test_32_step_dense_dag_with_bounded_edges(self) -> None:
        nodes = [task(f'n{i:02d}', *(f'n{j:02d}' for j in range(i))) for i in range(32)]
        rec = self.create(nodes)
        res = self.check(rec)
        self.assertEqual(res['status'], dag.VALID)
        self.assertEqual(res['step_count'], 32)
        self.assertEqual(res['dependency_edge_count'], 496)
        self.assertEqual(res['topological_order'], [f'step_n{i:02d}' for i in range(32)])
        self.assertEqual(len(res['topological_layers']), 32)

    def test_permuting_dependency_input_changes_record_but_not_dag_order(self) -> None:
        a = self.create([task('a'), task('b'), task('c', 'b', 'a')])
        b = self.create([task('a'), task('b'), task('c', 'a', 'b')])
        pa, pb = self.check(a), self.check(b)
        self.assertEqual(pa['topological_layers'], pb['topological_layers'])
        self.assertNotEqual(pa['action_set_sha256'], pb['action_set_sha256'])
        self.assertNotEqual(pa['graph_sha256'], pb['graph_sha256'])

    def test_ec231_preflight_rejects_missing_duplicate_self_invalid_id(self) -> None:
        invalid = [[task('a', 'missing')], [task('a'), task('a')],
                   [task('a', 'a')], [task('a', 'b', 'b'), task('b')],
                   [dict(task('a'), extra=True)]]
        for a in invalid:
            with self.subTest(a=a), self.assertRaises(md.CycleMetadataError):
                self.create(a)
        self.assertFalse(self.private_dir.exists(), 'Invalid EC231 declarations must not mint a RunId')

    def test_resealed_malformed_missing_or_duplicate_edges_block_unknown(self) -> None:
        original = self.create()
        for change, expected in [
            (lambda r: r['action_set'][1]['depends_on'].append('step_gone'), 'CYCLE_DEPENDENCY_REF_MISSING'),
            (lambda r: r['action_set'][1]['depends_on'].append('step_code'), 'CYCLE_DEPENDENCY_DUPLICATE_OR_SELF'),
            (lambda r: r['action_set'][0]['depends_on'].append('step_code'), 'CYCLE_DEPENDENCY_DUPLICATE_OR_SELF'),
        ]:
            with self.subTest(expected=expected):
                rec = copy.deepcopy(original)
                change(rec)
                rec['action_set_sha256'] = md.digest(md.DOMAIN_ACTIONS, rec['action_set'])
                self.write_record(rec)
                result = self.check(original)
                self.assertEqual(result['status'], dag.UNKNOWN)
                self.assertEqual(result['reason_code'], expected)
                self.assertEqual(result['topological_order'], [])
                self.assertIsNone(result['record_sha256'])

    def test_record_and_action_and_input_out_of_band_pins_fail_closed(self) -> None:
        rec = self.create()
        for field in ('expected_record_sha256', 'expected_action_set_sha256', 'expected_input_sha256'):
            for bad in ('a'*64, 'not-sha', True):
                with self.subTest(field=field, bad=bad):
                    outcome = self.check(rec, **{field:bad})
                    self.assertEqual(outcome['status'], dag.UNKNOWN)
                    self.assertEqual(outcome['topological_order'], [])
                    self.assertIsNone(outcome['actor_subject'])
                    self.assertIsNone(outcome['action_set_sha256'])
                    self.assert_no_effects(outcome)

    def test_out_of_band_pin_detects_resigned_same_uid_action_change(self) -> None:
        rec = self.create()
        anchored_digest = rec['record_sha256']
        changed = copy.deepcopy(rec)
        changed['action_set'][2]['depends_on'] = ['step_code']
        changed['action_set_sha256'] = md.digest(md.DOMAIN_ACTIONS, changed['action_set'])
        self.write_record(changed)
        self.assertEqual(self.check(rec, expected_record_sha256=anchored_digest)['reason_code'],
                         'CYCLE_DAG_RECORD_PIN_MISMATCH')
        self.assertEqual(self.check(rec)['status'], dag.VALID,
                         'Unpinned unsigned record cannot detect same-UID edit+rehash')

    def test_missing_private_root_and_missing_run_never_create_or_claim_valid(self) -> None:
        other = dag.CycleDagInspector(self.private_dir)
        missing = 'run_v1_' + '0'*48
        first = other.check(missing)
        self.assertEqual(first['status'], dag.UNKNOWN)
        self.assertEqual(first['reason_code'], 'CYCLE_STORE_UNAVAILABLE')
        self.assertFalse(self.private_dir.exists())
        self.create()
        self.assertEqual(other.check(missing)['reason_code'], 'CYCLE_RUN_NOT_FOUND')

    def test_invalid_run_id_never_opens_path(self) -> None:
        for bad in ('../../../../etc/passwd', 'run_v1_'+'0'*47, None, 1):
            with self.subTest(bad=bad):
                result = self.inspector.check(bad)
                self.assertEqual(result['status'], dag.UNKNOWN)
                self.assertIsNone(result['run_id'])
                self.assertEqual(result['reason_code'], 'CYCLE_RUN_ID_INVALID')
        self.assertFalse(self.private_dir.exists())

    def test_saved_corruption_and_permission_boundary_fail_closed(self) -> None:
        rec = self.create()
        self.file(rec).write_bytes(b'{invalid json')
        outcome = self.check(rec)
        self.assertEqual(outcome['status'], dag.UNKNOWN)
        self.assertEqual(outcome['reason_code'], 'CYCLE_JSON_MALFORMED')
        self.assertEqual(outcome['cycle_components'], [])
        self.assert_no_effects(outcome)
        self.file(rec).chmod(0o644)
        self.assertEqual(self.check(rec)['reason_code'], 'CYCLE_RECORD_NOT_PRIVATE')

    def test_symlink_and_hardlink_not_read_as_valid_saved_cycle(self) -> None:
        rec = self.create()
        path = self.file(rec)
        other = path.parent / 'other'
        os.link(path, other)
        self.assertEqual(self.check(rec)['status'], dag.UNKNOWN)
        other.unlink()
        path.rename(other)
        os.symlink(other, path)
        self.assertEqual(self.check(rec)['status'], dag.UNKNOWN)
        self.assert_no_effects(self.check(rec))

    def test_unverified_historical_partial_or_unknown_does_not_escalate(self) -> None:
        rec = self.create()
        changed = copy.deepcopy(rec)
        changed['steps'][1].update(state='DECLARED_PARTIAL', reason_code='CALLER_DECLARED_PARTIAL',
                                   evidence_sha256='a'*64, observed_at_utc=rec['created_at_utc'])
        changed['run_state'] = 'PARTIAL'
        changed['budget']['usage']['steps'] = 1
        self.write_record(changed)
        part = self.check(rec)
        self.assertEqual(part['status'], dag.VALID)
        self.assertEqual(part['metadata_run_state'], 'PARTIAL')
        self.assert_no_effects(part)
        changed['steps'][1].update(state='UNKNOWN', reason_code='SOURCE_UNCERTAIN',
                                   evidence_sha256=None, observed_at_utc=None)
        changed['run_state'] = 'UNKNOWN'
        self.write_record(changed)
        unknown_step = self.check(rec)
        self.assertEqual(unknown_step['status'], dag.VALID)
        self.assertEqual(unknown_step['metadata_run_state'], 'UNKNOWN')
        self.assert_no_effects(unknown_step)

    def test_forged_actor_authority_rejected_even_after_rehash(self) -> None:
        rec = self.create()
        changed = copy.deepcopy(rec)
        changed['actor']['verified'] = True
        self.write_record(changed)
        result = self.check(rec)
        self.assertEqual(result['status'], dag.UNKNOWN)
        self.assertEqual(result['reason_code'], 'CYCLE_ACTOR_AUTHORITY_FORBIDDEN')

    def test_cli_success_cycle_and_unknown_have_distinct_exit_codes(self) -> None:
        scenarios = [(self.create(), dag.VALID, 0),
                     (self.create([task('a', 'b'), task('b', 'a')]), dag.CYCLIC, 3)]
        for record, status, exit_code in scenarios:
            with self.subTest(status=status):
                p = subprocess.run([sys.executable, str(ROOT/'construction/cycle_dag.py'), 'check',
                                   '--store', str(self.private_dir), '--run-id', record['run_id'],
                                   '--expected-record-sha256', record['record_sha256']],
                                   capture_output=True, text=True)
                self.assertEqual(p.returncode, exit_code, p.stderr)
                result = json.loads(p.stdout)
                self.assertEqual(result['status'], status)
                self.assert_no_effects(result)
        p = subprocess.run([sys.executable, str(ROOT/'construction/cycle_dag.py'), 'check',
                           '--store', str(self.private_dir), '--run-id', 'run_v1_' + 'f'*48],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 5)
        self.assertEqual(json.loads(p.stdout)['status'], dag.UNKNOWN)

    @unittest.skipIf(Draft202012Validator is None, 'optional jsonschema package not installed')
    def test_schema_accepts_all_three_outcomes_and_rejects_success_escalation(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding='utf-8'))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        a = self.check(self.create())
        b = self.check(self.create([task('a', 'b'), task('b', 'a')]))
        c = self.inspector.check('run_v1_'+'f'*48)
        for result in (a, b, c):
            with self.subTest(status=result['status']):
                self.assertEqual(list(validator.iter_errors(result)), [])
        for edited in (
            dict(a, effects={**a['effects'], 'can_dispatch': True}),
            dict(a, outcome='SUCCESS'),
            dict(b, topological_order=['step_a']),
            dict(c, graph_sha256='a'*64),
        ):
            self.assertTrue(list(validator.iter_errors(edited)), 'Forged/invalid output must fail contract')


if __name__ == '__main__':
    unittest.main()
