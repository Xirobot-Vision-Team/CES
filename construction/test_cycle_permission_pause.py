#!/usr/bin/env python3
"""EC235 targeted local functional scenarios (NOT host/native acceptance)."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

try:
    from . import cycle_run_metadata as md
    from . import cycle_budget as budget
    from . import cycle_next as nxt
    from . import cycle_permission_pause as pp
except ImportError:
    import cycle_run_metadata as md
    import cycle_budget as budget
    import cycle_next as nxt
    import cycle_permission_pause as pp


def action(n, name='CodeSave', mode='Snapshot', deps=()):
    return {'step_id': 'step_' + n, 'action': name, 'mode': mode, 'depends_on': list(deps)}


@unittest.skipUnless(os.name == 'posix', 'POSIX private-durable storage only')
class PauseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ec235-check-')
        self.addCleanup(self.temp.cleanup)
        self.store = md.CycleMetadataStore(self.temp.name)
        self.subject = pp.CyclePermissionPauseStore(self.temp.name)

    def create(self, actions=None, snapshot=b'private-source-contents'):
        return self.store.create(snapshot_bytes=snapshot, source_ref='test:synthetic',
                                 actor_origin='human', actor_subject='test-actor',
                                 actions=actions or [action('one')])

    def file(self, record):
        return Path(self.temp.name) / (record['run_id'] + pp.PAUSE_SUFFIX)

    def denial(self, r):
        self.assertIn(r['status'], pp.STATUS_FOR.values())
        self.assertEqual(r['permission_gate']['gate_result'], 'DENY')
        self.assertFalse(r['permission_gate']['approval_token_issued'])
        self.assertFalse(r['permission_gate']['independent_approval_verified'])
        self.assertEqual(r['effects']['pause_persisted'], True)
        self.assertTrue(all(v is False for k, v in r['effects'].items() if k != 'pause_persisted'))
        self.assertTrue(all(v is False for v in r['trust'].values()))
        self.assertEqual(r['remaining_step_ids'][0], 'step_one')

    def test_real_unapproved_code_save_commits_durable_checkpoint(self):
        original = self.create()
        original_bytes = (Path(self.temp.name) / (original['run_id'] + '.cycle.json')).read_bytes()
        out = self.subject.pause(original['run_id'])
        self.denial(out)
        self.assertEqual(out['reason_code'], pp.REASON_FOR['NOT_PROVIDED'])
        self.assertEqual(out['step_id'], 'step_one')
        self.assertEqual(out['route_binding']['handler_file'], 'scripts/codesave.ps1')
        self.assertEqual(out['route_binding']['required_switch'], 'ApprovePersist')
        self.assertEqual(out['budget_observation']['admitted_inspections'], 1)
        self.assertNotIn(b'private-source-contents', self.file(original).read_bytes())
        self.assertEqual(stat.S_IMODE(self.file(original).stat().st_mode), 0o600)
        self.assertEqual((Path(self.temp.name) / (original['run_id'] + '.cycle.json')).read_bytes(), original_bytes)
        self.assertEqual(self.store.load(original['run_id'])['run_state'], 'NOT_STARTED')

    def test_restart_load_rechecks_live_source_and_original(self):
        record = self.create()
        saved = self.subject.pause(record['run_id'])
        restarted = pp.CyclePermissionPauseStore(self.temp.name)
        self.assertEqual(restarted.inspect(record['run_id']), saved)

    def test_case_insensitive_declared_native_mode_preserves_exact_request(self):
        r = self.create([action('one', 'CodeSave', 'SNAPSHOT')])
        saved = self.subject.pause(r['run_id'])
        self.assertEqual(saved['route_binding']['declared_mode'], 'SNAPSHOT')
        self.assertEqual(saved['route_binding']['effective_mode'], 'Snapshot')
        self.denial(saved)

    def test_declined_response_stays_denied_and_durable(self):
        record = self.create()
        out = self.subject.pause(record['run_id'], operator_response='DECLINED')
        self.denial(out)
        self.assertEqual(out['status'], 'PAUSED_PERMISSION_DECLINED')
        self.assertEqual(self.subject.inspect(record['run_id'])['permission_gate']['operator_response'],
                         'DECLINED')

    def test_approval_is_not_a_legal_api_input(self):
        record = self.create()
        with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_APPROVAL_NOT_SUPPORTED'):
            self.subject.pause(record['run_id'], operator_response='APPROVED')
        self.assertFalse(self.file(record).exists())

    def test_truthy_boolean_and_unknown_response_refused(self):
        record = self.create()
        for value in (True, False, None, 1, 'GRANTED', '', 'NOT_PROVIDED '):
            with self.subTest(response=value):
                with self.assertRaises(pp.CyclePauseError):
                    self.subject.pause(record['run_id'], operator_response=value)
        self.assertFalse(self.file(record).exists())

    def test_only_first_actual_root_may_pause(self):
        record = self.create([action('inspect', 'Inspect', None), action('one')])
        with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_NO_BUDGETED_PERMISSION_STEP'):
            self.subject.pause(record['run_id'])
        self.assertFalse(self.file(record).exists())

    def test_dependent_code_save_cannot_pause_as_ready(self):
        record = self.create([action('inspect', 'Inspect', None),
                              action('one', deps=('step_inspect',))])
        with self.assertRaises(pp.CyclePauseError):
            self.subject.pause(record['run_id'])
        self.assertFalse(self.file(record).exists())

    def test_unimplemented_handler_blocked(self):
        record = self.create([action('one', 'ReportPublish', 'Snapshot')])
        with self.assertRaises(pp.CyclePauseError):
            self.subject.pause(record['run_id'])
        self.assertFalse(self.file(record).exists())

    def test_ai_handoff_does_not_get_code_save_permission_checkpoint(self):
        record = self.create([action('one', 'AIHandoff', 'CodeAnalysis')])
        with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_NOT_A_PERMISSION_STEP'):
            self.subject.pause(record['run_id'])
        self.assertFalse(self.file(record).exists())

    def test_dag_cycle_is_not_a_permission_checkpoint(self):
        record = self.create([action('one', deps=('step_two',)),
                              action('two', deps=('step_one',))])
        with self.assertRaises(pp.CyclePauseError):
            self.subject.pause(record['run_id'])
        self.assertFalse(self.file(record).exists())

    def test_existing_checkpoint_never_overwritten_or_silently_retried(self):
        record = self.create()
        self.subject.pause(record['run_id'])
        first = self.file(record).read_bytes()
        with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_ALREADY_EXISTS'):
            self.subject.pause(record['run_id'], operator_response='DECLINED')
        self.assertEqual(first, self.file(record).read_bytes())

    def test_exclusive_create_allows_only_one_concurrent_checkpoint(self):
        record = self.create()
        success, errors = [], []
        barrier = threading.Barrier(2)
        def submit():
            barrier.wait()
            try:
                success.append(self.subject.pause(record['run_id'])['pause_sha256'])
            except Exception as ex:
                errors.append(getattr(ex, 'code', type(ex).__name__))
        workers = [threading.Thread(target=submit) for _ in range(2)]
        for worker in workers: worker.start()
        for worker in workers: worker.join(timeout=30)
        self.assertEqual(len(success), 1)
        self.assertEqual(errors, ['CYCLE_PAUSE_ALREADY_EXISTS'])

    def test_missing_checkpoint_never_looks_like_not_started_or_success(self):
        record = self.create()
        with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_NOT_FOUND'):
            self.subject.inspect(record['run_id'])

    def test_nonexistent_run_never_mints_a_pause(self):
        with self.assertRaises(md.CycleMetadataError):
            self.subject.pause('run_v1_' + '0' * 48)
        self.assertEqual(list(Path(self.temp.name).glob('*.permission-pause.v1.json')), [])

    def test_wrong_external_pin_refused_before_sidecar(self):
        record = self.create()
        with self.assertRaises(pp.CyclePauseError):
            self.subject.pause(record['run_id'], expected_input_sha256='0' * 64)
        self.assertFalse(self.file(record).exists())

    def test_correct_all_three_pins_accepted(self):
        r = self.create()
        out = self.subject.pause(r['run_id'], expected_record_sha256=r['record_sha256'],
                                 expected_action_set_sha256=r['action_set_sha256'],
                                 expected_input_sha256=r['input']['sha256'])
        self.denial(out)

    def test_tight_budget_not_misrepresented_as_persisted(self):
        record = self.create()
        with self.assertRaises(pp.CyclePauseError):
            self.subject.pause(record['run_id'], overrides={'output_bytes': 1})
        self.assertFalse(self.file(record).exists())

    def test_budget_enforcement_rejects_invalid_override(self):
        record = self.create()
        with self.assertRaises(pp.CyclePauseError):
            self.subject.pause(record['run_id'], overrides={'max_step_inspections': 999})
        self.assertFalse(self.file(record).exists())

    def test_all_steps_remain_unperformed_in_pause(self):
        record = self.create([action('one'), action('two', 'Inspect', None),
                              action('three', 'CodeShow', 'Findings', ('step_two',))])
        out = self.subject.pause(record['run_id'])
        self.denial(out)
        self.assertEqual(out['remaining_step_ids'], ['step_one', 'step_two', 'step_three'])
        self.assertEqual(self.store.load(record['run_id'])['budget']['usage']['steps'], 0)

    def test_self_hash_without_grant_cannot_claim_authority(self):
        record = self.create()
        out = self.subject.pause(record['run_id'])
        out['effects']['write_authorized'] = True
        out['pause_sha256'] = md.digest(pp.DOMAIN_PAUSE, pp._without_hash(out))
        self.file(record).write_bytes(md.canonical(out) + b'\n')
        with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_EFFECTS_ESCALATION'):
            self.subject.inspect(record['run_id'])

    def test_unsigned_self_hash_recomputed_with_permission_grant_is_rejected(self):
        record = self.create()
        out = self.subject.pause(record['run_id'])
        out['permission_gate']['independent_approval_verified'] = True
        out['pause_sha256'] = md.digest(pp.DOMAIN_PAUSE, pp._without_hash(out))
        self.file(record).write_bytes(md.canonical(out) + b'\n')
        with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_GATE_AUTHORITY_FORBIDDEN'):
            self.subject.inspect(record['run_id'])

    def test_tamper_actor_binding_and_rehash_does_not_pass_live_match(self):
        record = self.create()
        out = self.subject.pause(record['run_id'])
        out['metadata_binding']['actor_subject'] = 'substitute-actor'
        out['pause_sha256'] = md.digest(pp.DOMAIN_PAUSE, pp._without_hash(out))
        self.file(record).write_bytes(md.canonical(out) + b'\n')
        with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_CYCLE_BINDING_DRIFT'):
            self.subject.inspect(record['run_id'])

    def test_corrupt_digest_never_yields_a_pause(self):
        record = self.create()
        self.subject.pause(record['run_id'])
        out = self.file(record).read_bytes()
        self.file(record).write_bytes(out.replace(b'PAUSED_AWAITING_PERMISSION', b'PAUSED_PERMISSION_DECLINED'))
        with self.assertRaises(md.CycleMetadataError):
            self.subject.inspect(record['run_id'])

    def test_symlink_or_hardlink_denied(self):
        record = self.create()
        self.subject.pause(record['run_id'])
        sidecar = self.file(record)
        relocated = sidecar.with_suffix('.old')
        sidecar.rename(relocated)
        sidecar.symlink_to(relocated)
        with self.assertRaises(md.CycleMetadataError):
            self.subject.inspect(record['run_id'])
        sidecar.unlink()
        os.link(relocated, sidecar)
        with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_NOT_PRIVATE'):
            self.subject.inspect(record['run_id'])

    def test_changed_source_backed_proposal_blocks_restart(self):
        r = self.create()
        self.subject.pause(r['run_id'])
        real = self.subject.next_handler.next
        def change(*a, **kw):
            import copy
            result = copy.deepcopy(real(*a, **kw))
            result['next_step']['handler']['handler_sha256'] = '0' * 64
            return result
        with patch.object(self.subject.next_handler, 'next', side_effect=change):
            with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_HANDLER_SOURCE_CHANGED'):
                self.subject.inspect(r['run_id'])

    def test_readonly_inspect_does_not_touch_saved_bytes(self):
        r = self.create()
        self.subject.pause(r['run_id'])
        before = self.file(r).read_bytes()
        self.subject.inspect(r['run_id'])
        self.assertEqual(before, self.file(r).read_bytes())

    def test_partial_write_uncertainty_blocks_overwrite(self):
        r = self.create()
        def partial(fd, data):
            os.write(fd, data[:13])
            raise OSError('simulated short write/OS error')
        with patch.object(md, '_write_all', side_effect=partial):
            with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_WRITE_UNCERTAIN'):
                self.subject.pause(r['run_id'])
        self.assertTrue(self.file(r).exists())
        with self.assertRaisesRegex(pp.CyclePauseError, 'CYCLE_PAUSE_ALREADY_EXISTS'):
            self.subject.pause(r['run_id'])

    def test_cli_pause_then_inspect_exit_two_and_no_mutations(self):
        r = self.create()
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            exit_code = pp.main(['pause', '--store', self.temp.name, '--run-id', r['run_id']])
        self.assertEqual(exit_code, 2)
        first = json.loads(buf.getvalue())
        self.denial(first)
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            exit_code = pp.main(['inspect', '--store', self.temp.name, '--run-id', r['run_id']])
        self.assertEqual(exit_code, 2)
        self.assertEqual(json.loads(buf.getvalue()), first)

    def test_cli_approved_input_exits_blocked(self):
        r = self.create()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                pp.main(['pause', '--store', self.temp.name, '--run-id', r['run_id'],
                         '--operator-response', 'APPROVED'])
        self.assertFalse(self.file(r).exists())

    def test_cli_missing_checkpoint_reports_bounded_denial(self):
        r = self.create()
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            code = pp.main(['inspect', '--store', self.temp.name, '--run-id', r['run_id']])
        self.assertEqual(code, 5)
        result = json.loads(buf.getvalue())
        self.assertEqual(result['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(result['reason_code'], 'CYCLE_PAUSE_NOT_FOUND')
        self.assertFalse(result['effects']['write_authorized'])

    def test_strict_json_schema_accepts_real_and_rejects_forged_grant(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest('jsonschema not installed: defer external schema check')
        schema = json.loads((Path(__file__).resolve().parent.parent / 'references' /
                             'cycle-permission-pause.v1.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        r = self.create()
        record = self.subject.pause(r['run_id'])
        validator = Draft202012Validator(schema)
        self.assertEqual(list(validator.iter_errors(record)), [])
        import copy
        unauthorized = copy.deepcopy(record)
        unauthorized['effects']['write_authorized'] = True
        self.assertTrue(list(validator.iter_errors(unauthorized)))
        extra = copy.deepcopy(record)
        extra['authorization_token'] = 'fake'
        self.assertTrue(list(validator.iter_errors(extra)))


if __name__ == '__main__':
    unittest.main()
