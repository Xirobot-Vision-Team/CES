#!/usr/bin/env python3
"""EC237 focused *real local files* tests; no native/enterprise acceptance implied."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

try:
    from . import cycle_run_metadata as md
    from . import cycle_permission_pause as pause
    from . import cycle_next as nxt
    from . import cycle_summary as sm
except ImportError:
    import cycle_run_metadata as md
    import cycle_permission_pause as pause
    import cycle_next as nxt
    import cycle_summary as sm

SNAP = b'EC237 synthetic-local-snapshot-bytes\n'
SOURCE = 'local:ec237-source'


def action(step='step_one', action='Inspect', mode='Snapshot', deps=()):
    return {'step_id': step, 'action': action, 'mode': mode, 'depends_on': list(deps)}


@unittest.skipUnless(os.name == 'posix', 'requires real EC231 POSIX-private stored records')
class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ec237-real-local-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.store = md.CycleMetadataStore(self.path)
        self.reporter = sm.CycleSummaryReporter(self.path)
        self.record = self.create([action(), action('step_two', 'Inspect', 'Snapshot', ['step_one'])])
        self.run_id = self.record['run_id']
        self.record_file = self.path / (self.run_id + '.cycle.json')
        self.original_bytes = self.record_file.read_bytes()

    def create(self, actions):
        return self.store.create(snapshot_bytes=SNAP, source_ref=SOURCE,
                                 actor_origin='human', actor_subject='ec237-operator',
                                 actions=actions)

    def check(self, run_id=None, **kwargs):
        out = self.reporter.summary(run_id or self.run_id, **kwargs)
        self.assertEqual(sm.validate_result(out), out)
        self.assertEqual(out['schema'], sm.SCHEMA)
        self.assertFalse(out['overall_success_proven'])
        self.assertTrue(all(v is False for v in out['trust'].values()))
        self.assertTrue(all(v is False for v in out['effects'].values()))
        self.assertEqual(out['counts']['verified_success'], 0)
        self.assertEqual(out['counts']['verified_failure'], 0)
        self.assertIsNone(out['cost']['external_cost_usd'])
        return out

    def test_original_immutable_run_source_bound_summary(self):
        out = self.check()
        self.assertEqual(out['status'], 'NOT_STARTED')
        self.assertEqual(out['counts']['total_steps'], 2)
        self.assertEqual(out['counts']['not_started'], 2)
        self.assertEqual(out['counts']['dependency_blocked'], 1)
        self.assertEqual(out['steps'][0]['report_state'], 'NOT_STARTED_UNEXECUTED')
        self.assertEqual(out['steps'][1]['report_state'], 'DEPENDENCY_UNPROVEN')
        self.assertEqual(out['steps'][1]['blocked_by_unproven_dependencies'], ['step_one'])
        self.assertTrue(out['checks']['route_source_checked'])
        self.assertEqual(out['record_binding']['record_sha256'], self.record['record_sha256'])
        self.assertIsNotNone(out['record_binding']['proposal_sha256'])
        self.assertEqual(self.record_file.read_bytes(), self.original_bytes)

    def test_cost_capture_not_invented_cpu_or_billing(self):
        out = self.check()
        self.assertEqual(out['cost']['capture_input_bytes'], len(SNAP))
        self.assertEqual(out['cost']['capture_declared_usage']['input_bytes'], len(SNAP))
        self.assertEqual(out['cost']['capture_declared_usage']['steps'], 0)
        self.assertEqual(out['cost']['accounting_scope'], 'EC231_DECLARATIONS_ONLY_NO_EXECUTION_METER')
        self.assertIsNone(out['cost']['execution_wall_ms'])
        self.assertIsNone(out['cost']['execution_cpu_ms'])
        self.assertIsNone(out['cost']['execution_evidence_bytes'])

    def test_optional_independent_three_pins(self):
        out = self.check(expected_record_sha256=self.record['record_sha256'],
                         expected_action_set_sha256=self.record['action_set_sha256'],
                         expected_input_sha256=self.record['input']['sha256'])
        self.assertTrue(out['checks']['independent_pins_provided'])
        self.assertFalse(out['trust']['record_authenticated'])

    def test_bad_external_record_pin_blocks_and_discards_data(self):
        self.unknown(expected_record_sha256='f'*64)

    def test_bad_external_input_pin_blocks_and_discards_data(self):
        self.unknown(expected_input_sha256='f'*64)

    def test_bad_external_action_pin_blocks_and_discards_data(self):
        self.unknown(expected_action_set_sha256='f'*64)

    def test_invalid_pin_format_blocks(self):
        self.unknown(expected_record_sha256='not-a-hash')

    def test_absent_pause_pin_prevents_silent_unpaused_report(self):
        self.unknown(expected_pause_sha256='0'*64)

    def test_current_run_id_missing_must_not_fabricate_steps(self):
        self.unknown('run_v1_'+'a'*48)

    def test_malformed_run_id(self):
        self.unknown('../outside')

    def test_corrupt_json_file(self):
        self.record_file.write_bytes(b'{broken-json')
        self.unknown()

    def test_saved_record_self_hash_swapped(self):
        modified = json.loads(self.original_bytes)
        modified['input']['sha256'] = 'a'*64
        self.record_file.write_text(json.dumps(modified))
        self.unknown()

    def test_record_file_symlink_refused(self):
        self.record_file.unlink()
        self.record_file.symlink_to('/etc/passwd')
        self.unknown()

    def test_record_file_world_readable_refused(self):
        os.chmod(self.record_file, 0o644)
        self.unknown()

    def test_saved_real_persisted_permission_pause_wait(self):
        entry = self.create([action('step_save', 'CodeSave', 'Snapshot'),
                             action('step_after', deps=['step_save'])])
        checkpoint = pause.CyclePermissionPauseStore(self.path).pause(entry['run_id'])
        before = (self.path / (entry['run_id'] + pause.PAUSE_SUFFIX)).read_bytes()
        out = self.check(entry['run_id'])
        self.assertEqual(out['status'], 'PAUSED_PERMISSION_REQUIRED')
        self.assertEqual(out['record_binding']['pause_sha256'], checkpoint['pause_sha256'])
        self.assertEqual(out['steps'][0]['report_state'], 'PAUSED_DENY_UNEXECUTED')
        self.assertEqual(out['steps'][1]['report_state'], 'DEPENDENCY_UNPROVEN')
        self.assertEqual(out['counts']['permission_blocked'], 1)
        self.assertTrue(out['checks']['pause_valid'])
        self.assertFalse(out['trust']['permission_granted'])
        self.assertEqual(out['cost']['persisted_pause_budget_observation']['admitted_inspections'],
                         checkpoint['budget_observation']['admitted_inspections'])
        self.assertFalse(out['cost']['persisted_pause_budget_observation']['independently_attested'])
        self.assertEqual((self.path / (entry['run_id'] + pause.PAUSE_SUFFIX)).read_bytes(), before)

    def test_saved_declined_permission_stays_denied(self):
        entry = self.create([action('step_save', 'CodeSave', 'Snapshot')])
        pause.CyclePermissionPauseStore(self.path).pause(entry['run_id'], operator_response='DECLINED')
        out = self.check(entry['run_id'])
        self.assertEqual(out['status'], 'PAUSED_PERMISSION_REQUIRED')
        self.assertEqual(out['counts']['permission_blocked'], 1)
        self.assertFalse(out['effects']['can_dispatch'])

    def test_absent_pause_on_code_save_not_mistaken_for_approval(self):
        entry = self.create([action('step_save', 'CodeSave', 'Snapshot')])
        out = self.check(entry['run_id'])
        self.assertEqual(out['status'], 'AWAIT_PERMISSION_NO_CHECKPOINT')
        self.assertFalse(out['checks']['pause_present'])
        self.assertEqual(out['steps'][0]['report_state'], 'AWAITING_PERMISSION_UNEXECUTED')
        self.assertFalse(out['trust']['permission_granted'])

    def test_pause_digest_external_pin_equal_is_not_authorization(self):
        entry = self.create([action('step_save', 'CodeSave', 'Snapshot')])
        saved = pause.CyclePermissionPauseStore(self.path).pause(entry['run_id'])
        out = self.check(entry['run_id'], expected_pause_sha256=saved['pause_sha256'])
        self.assertEqual(out['status'], 'PAUSED_PERMISSION_REQUIRED')
        self.assertFalse(out['trust']['permission_granted'])

    def test_pause_digest_external_pin_mismatch_blocks(self):
        entry = self.create([action('step_save', 'CodeSave', 'Snapshot')])
        pause.CyclePermissionPauseStore(self.path).pause(entry['run_id'])
        self.unknown(entry['run_id'], expected_pause_sha256='d'*64)

    def test_corrupt_existing_pause_is_not_treated_as_absent(self):
        entry = self.create([action('step_save', 'CodeSave', 'Snapshot')])
        pause.CyclePermissionPauseStore(self.path).pause(entry['run_id'])
        (self.path / (entry['run_id'] + pause.PAUSE_SUFFIX)).write_bytes(b'{}')
        self.unknown(entry['run_id'])

    def test_symlink_pause_is_not_treated_as_absent(self):
        entry = self.create([action('step_save', 'CodeSave', 'Snapshot')])
        saved = self.path / (entry['run_id'] + pause.PAUSE_SUFFIX)
        saved.symlink_to('/etc/passwd')
        self.unknown(entry['run_id'])

    def test_pause_appearing_during_read_blocks(self):
        original = sm._sidecar_exists
        calls = []
        def appears(path, run_id):
            calls.append(run_id)
            return len(calls) > 1
        with patch.object(sm, '_sidecar_exists', side_effect=appears):
            self.unknown()
        self.assertEqual(len(calls), 2)

    def test_original_record_changes_between_reads(self):
        original_load = self.reporter.store.load
        count = [0]
        def switched(run_id):
            count[0] += 1
            obj = original_load(run_id)
            if count[0] == 2:
                return dict(obj) | {'record_sha256': '0'*64}
            return obj
        with patch.object(self.reporter.store, 'load', side_effect=switched):
            self.unknown()
        self.assertGreaterEqual(count[0], 2)

    def test_live_source_route_changes_between_two_checks(self):
        original_next = self.reporter.next.next
        count = [0]
        def altered(*args, **kwargs):
            count[0] += 1
            result = original_next(*args, **kwargs)
            if count[0] == 2:
                result['proposal_sha256'] = '8'*64
            return result
        with patch.object(self.reporter.next, 'next', side_effect=altered):
            self.unknown()
        self.assertEqual(count[0], 2)

    def test_full_32_step_dense_dependency_report_not_truncated(self):
        actions = [action('step_'+str(i).zfill(2)+'z'*43, deps=[
            'step_'+str(j).zfill(2)+'z'*43 for j in range(i)]) for i in range(32)]
        entry = self.create(actions)
        out = self.check(entry['run_id'])
        self.assertEqual(out['status'], 'NOT_STARTED')
        self.assertEqual(out['counts']['total_steps'], 32)
        self.assertEqual(out['counts']['dependency_blocked'], 31)
        self.assertLessEqual(len(md.canonical(out)), sm.MAX_SUMMARY_BYTES)

    def test_ai_handoff_is_operator_handoff_not_execution(self):
        entry = self.create([action('step_ai', 'AIHandoff', 'CodeAnalysis')])
        out = self.check(entry['run_id'])
        self.assertEqual(out['status'], 'OPERATOR_HANDOFF_REQUIRED')
        self.assertEqual(out['steps'][0]['report_state'], 'OPERATOR_HANDOFF_UNEXECUTED')
        self.assertFalse(out['trust']['handler_runtime_verified'])

    def test_source_route_unavailable_is_unknown_no_steps(self):
        old = self.reporter.next.next
        def broken(*a, **kw):
            item = old(*a, **kw)
            item['status'] = nxt.UNKNOWN
            item['reason_code'] = 'CYCLE_NEXT_HANDLER_SOURCE_UNAVAILABLE'
            return item
        with patch.object(self.reporter.next, 'next', side_effect=broken):
            self.unknown()

    def test_unimplemented_first_root_blocks_no_success(self):
        entry = self.create([action('step_unsupported', 'ImaginaryAction', 'Snapshot')])
        out = self.check(entry['run_id'])
        self.assertEqual(out['status'], 'BLOCKED_NO_HANDLER')
        self.assertEqual(out['counts']['not_started'], 1)
        self.assertEqual(out['counts']['verified_failure'], 0)

    def test_dependency_cycle_reported_as_block_not_progress(self):
        entry = self.create([action('step_a', deps=['step_b']),
                             action('step_b', deps=['step_a'])])
        out = self.check(entry['run_id'])
        self.assertEqual(out['status'], 'BLOCKED_DAG_CYCLE')
        self.assertFalse(out['checks']['dag_valid'])
        self.assertEqual(out['counts']['dependency_blocked'], 2)
        self.assertEqual(out['counts']['verified_failure'], 0)

    def _rewrite_state(self, entry, state):
        """Make valid but UNATTESTED caller-declaration metadata, not progress."""
        p = self.path / (entry['run_id']+'.cycle.json')
        obj = json.loads(p.read_text())
        obj['steps'][0]['state'] = state
        if state == 'DECLARED_PARTIAL':
            obj['steps'][0].update({
                'observed_at_utc': obj['created_at_utc'],
                'evidence_sha256': 'e'*64,
                'reason_code': 'DECLARED_PROGRESS_UNVERIFIED',
                'handoff_id': 'handoff_v1_'+'9'*48,
            })
            obj['run_state'] = 'PARTIAL'
        else:
            obj['steps'][0]['reason_code'] = 'UNKNOWN_HISTORY'
            obj['run_state'] = 'UNKNOWN'
        obj['record_sha256'] = md.digest(md.DOMAIN_RECORD, md._without_digest(obj))
        md.validate_record(obj)
        p.write_text(json.dumps(obj, sort_keys=True, indent=2)+'\n')
        os.chmod(p, 0o600)
        return obj

    def test_declared_partial_evidence_sha_never_becomes_verified_success(self):
        original = self._rewrite_state(self.record, 'DECLARED_PARTIAL')
        out = self.check()
        self.assertEqual(out['status'], 'UNVERIFIED_PROGRESS_BLOCKED')
        self.assertEqual(out['counts']['declared_partial'], 1)
        self.assertEqual(out['steps'][0]['report_state'], 'DECLARED_PARTIAL_UNVERIFIED')
        self.assertEqual(out['steps'][0]['declared_evidence_sha256'], 'e'*64)
        self.assertEqual(out['steps'][0]['declared_handoff_id'], 'handoff_v1_'+'9'*48)
        self.assertFalse(out['steps'][0]['success_verified'])
        self.assertEqual(out['record_binding']['record_sha256'], original['record_sha256'])
        self.assertEqual(out['counts']['dependency_blocked'], 1)

    def test_unknown_metadata_does_not_become_failed_business_step(self):
        self._rewrite_state(self.record, 'UNKNOWN')
        out = self.check()
        self.assertEqual(out['status'], 'UNVERIFIED_PROGRESS_BLOCKED')
        self.assertEqual(out['counts']['unknown'], 1)
        self.assertEqual(out['steps'][0]['report_state'], 'UNKNOWN_UNVERIFIED')
        self.assertFalse(out['steps'][0]['failure_verified'])

    def test_validator_rejects_fake_verified_success(self):
        fake = self.check()
        fake['counts']['verified_success'] = 1
        with self.assertRaises(sm.CycleSummaryError):sm.validate_result(fake)

    def test_validator_rejects_fake_approval_or_can_resume(self):
        fake = self.check()
        fake['effects']['can_resume'] = True
        with self.assertRaises(sm.CycleSummaryError):sm.validate_result(fake)

    def test_validator_rejects_fake_external_billed_cost(self):
        fake = self.check()
        fake['cost']['external_cost_usd'] = 10
        with self.assertRaises(sm.CycleSummaryError):sm.validate_result(fake)

    def test_validator_rejects_fake_dependency_success(self):
        fake = self.check()
        fake['steps'][1]['blocked_by_unproven_dependencies'] = []
        with self.assertRaises(sm.CycleSummaryError):sm.validate_result(fake)

    def test_validator_rejects_undeclared_partial_proof(self):
        fake = self.check()
        fake['steps'][0]['declared_evidence_sha256'] = 'f'*64
        with self.assertRaises(sm.CycleSummaryError):sm.validate_result(fake)

    def test_cli_json_and_non_success_exit(self):
        args = ['summary','--store',str(self.path),'--run-id',self.run_id]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = sm.main(args)
        result = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'NOT_STARTED')
        self.assertFalse(result['overall_success_proven'])
        self.assertEqual(len(output.getvalue().splitlines()), 1)

    def test_cli_unknown_exit_five_and_no_steps(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = sm.main(['summary','--store',str(self.path),'--run-id','bad-id'])
        self.assertEqual(code, 5)
        self.assertEqual(json.loads(output.getvalue())['steps'], [])

    def test_cli_blocked_no_handler_exit_three(self):
        entry = self.create([action('step_unsupported', 'ImaginaryAction', 'Snapshot')])
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = sm.main(['summary','--store',str(self.path),'--run-id',entry['run_id']])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())['status'], 'BLOCKED_NO_HANDLER')

    def test_strict_draft202012_contract_positive_negative(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest('jsonschema optional; schema validation deferred to final environment')
        contract = json.loads((Path(__file__).resolve().parent.parent /
                               'references/cycle-summary.v1.schema.json').read_text())
        Draft202012Validator.check_schema(contract)
        validator = Draft202012Validator(contract)
        valid = [self.check(), self.unknown('run_v1_'+'b'*48)]
        save = self.create([action('step_save', 'CodeSave', 'Snapshot')])
        valid.append(self.check(save['run_id']))
        pause.CyclePermissionPauseStore(self.path).pause(save['run_id'])
        valid.append(self.check(save['run_id']))
        partial = self.create([action('step_declared')])
        self._rewrite_state(partial, 'DECLARED_PARTIAL')
        valid.append(self.check(partial['run_id']))
        for report in valid:
            self.assertEqual(list(validator.iter_errors(report)), [], report['status'])
        examples = []
        bad = copy.deepcopy(valid[0]); bad['effects']['can_dispatch'] = True; examples.append(bad)
        bad = copy.deepcopy(valid[0]); bad['overall_success_proven'] = True; examples.append(bad)
        bad = copy.deepcopy(valid[0]); bad['counts']['verified_success'] = 1; examples.append(bad)
        bad = copy.deepcopy(valid[0]); bad['cost']['execution_wall_ms'] = 40; examples.append(bad)
        bad = copy.deepcopy(valid[0]); bad['unrecognized'] = 0; examples.append(bad)
        bad = copy.deepcopy(valid[3]); bad['checks']['pause_valid'] = False; examples.append(bad)
        bad = copy.deepcopy(valid[4]); bad['steps'][0]['report_state'] = 'NOT_STARTED_UNEXECUTED'; examples.append(bad)
        for report in examples:
            self.assertTrue(list(validator.iter_errors(report)), report)

    def test_serialized_output_bounded_by_schema(self):
        out = self.check()
        self.assertLessEqual(len(md.canonical(out)), sm.MAX_SUMMARY_BYTES)
        self.assertNotIn(SNAP.decode(), json.dumps(out))

    def test_empty_external_source_is_not_fabricated(self):
        out = self.check()
        self.assertNotIn('source_ref', out['record_binding'])
        self.assertFalse(out['trust']['input_source_authenticated'])

    def unknown(self, run_id=None, **kwargs):
        out = self.check(run_id, **kwargs)
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(out['steps'], [])
        self.assertEqual(out['counts']['total_steps'], 0)
        self.assertFalse(out['checks']['record_valid'])
        self.assertIsNone(out['cost']['capture_input_bytes'])
        return out


if __name__ == '__main__':
    unittest.main()
