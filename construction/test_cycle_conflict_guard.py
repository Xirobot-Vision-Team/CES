#!/usr/bin/env python3
"""EC240 focused real POSIX Cycle store tests; event and producer bytes are synthetic."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import cycle_conflict_guard as cg
import cycle_run_metadata as md
import cycle_cross_action as cc
import handoff_lifecycle as lc
import task_staging as st
from test_handoff_lifecycle import context


@unittest.skipUnless(os.name == 'posix', 'EC231 real private store requires POSIX')
class ConflictGuardCases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ec240-guard-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.path = self.base / 'cycles'
        self.saved = md.CycleMetadataStore(self.path).create(
            snapshot_bytes=b'EC240 original synthetic local snapshot',
            source_ref='host:ec240-input', actor_origin='human',
            actor_subject='ec240-local-declaration',
            actions=[{'step_id': 'step_1', 'action': 'Inspect',
                      'mode': 'Snapshot', 'depends_on': []}])
        self.run_id = self.saved['run_id']
        self.original_path = self.path / (self.run_id + '.cycle.json')
        self.original_bytes = self.original_path.read_bytes()
        self.pins = dict(expected_record_sha256=self.saved['record_sha256'],
                         expected_action_set_sha256=self.saved['action_set_sha256'],
                         expected_input_sha256=self.saved['input']['sha256'])
        self.guard = cg.CycleConflictGuard(self.path)
        self.schedule = dict(scheduler_kind='cron', schedule_id='ec240.hourly',
                             cadence='hourly', host_state='claimed_configured',
                             trigger_id='evt_event_240_aabbcc0123',
                             scheduled_for_utc='2026-10-24T15:00:00.000000Z')

    def summary(self, **changes):
        return self.guard.scheduled_summary(self.run_id, **self.pins,
                                            **{**self.schedule, **changes})

    def inspect(self, request_id=None):
        return self.guard.inspect(self.run_id, **self.pins,
                                  request_id=request_id or self.schedule['trigger_id'])

    def assert_nobody_wrote_business(self, out):
        for key in ('business_code_executed', 'business_write_performed',
                    'native_action_dispatched', 'permission_granted',
                    'external_scheduler_installed'):
            self.assertFalse(out['effects'][key], key)
        self.assertEqual(self.original_path.read_bytes(), self.original_bytes)

    def test_real_summary_single_durable_receipt_and_replay_no_second_call(self):
        first = self.summary()
        self.assertEqual(first['status'], 'RECORDED_OBSERVATION')
        self.assertEqual(first['source_observation']['status'], 'CHECK_OBSERVED_ONLY')
        self.assertTrue(first['effects']['ec239_summary_called'])
        self.assertTrue(first['effects']['new_guard_final_receipt_persisted'])
        self.assertEqual(first['receipt']['phase'], 'FINAL')
        with patch.object(self.guard.scheduler, 'invoke', side_effect=AssertionError('duplicate call')):
            again = self.summary()
        self.assertEqual(again['status'], 'REPLAY_SUPPRESSED')
        self.assertTrue(again['effects']['repeat_operation_suppressed'])
        self.assertEqual(again['source_observation']['result_sha256'],
                         first['source_observation']['result_sha256'])
        self.assertFalse(again['source_observation']['called_now'])
        self.assertFalse(again['effects']['ec239_summary_called'])
        self.assertEqual(self.inspect()['status'], 'RECEIPT_OBSERVED')
        self.assert_nobody_wrote_business(again)

    def test_different_id_same_tick_is_conflict_not_second_check(self):
        self.summary()
        with patch.object(self.guard.scheduler, 'invoke', side_effect=AssertionError('must block')):
            result = self.summary(trigger_id='evt_event_240_new_unique')
        self.assertEqual(result['status'], 'CONFLICT_BLOCKED')
        self.assertEqual(result['reason_code'], 'CONFLICT_SLOT_ALREADY_OWNED_BY_DIFFERENT_INTENT')

    def test_same_id_different_tick_is_conflict(self):
        self.summary()
        self.assertEqual(self.summary(scheduled_for_utc='2026-10-24T16:00:00.000000Z')['status'],
                         'CONFLICT_BLOCKED')

    def test_second_valid_tick_sequentially_writes_new_receipt(self):
        self.summary()
        result = self.summary(trigger_id='evt_event_240_different_tick',
                              scheduled_for_utc='2026-10-24T16:00:00.000000Z')
        self.assertEqual(result['status'], 'RECORDED_OBSERVATION')
        self.assertEqual(len(self.ledger()['entries']), 2)

    def ledger(self):
        return json.loads((self.path / (self.run_id + '.ec240.ledger.json')).read_bytes())

    def test_preflight_invalid_no_event_reservation(self):
        no = self.summary(host_state='absent')
        self.assertEqual(no['status'], 'REJECTED')
        self.assertEqual(self.inspect()['status'], 'NO_RECEIPT')
        self.assertEqual(self.summary(trigger_id='evt_bad;input')['status'], 'REJECTED')
        self.assertEqual(self.summary(scheduled_for_utc='2026-10-24T15:20:00.000000Z')['status'],
                         'REJECTED')
        self.assertEqual(self.inspect()['status'], 'NO_RECEIPT')

    def test_bad_external_pin_is_fail_closed_without_receipt(self):
        bad = {**self.pins, 'expected_record_sha256': 'f' * 64}
        out = self.guard.scheduled_summary(self.run_id, **bad, **self.schedule)
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertIsNone(out['receipt'])
        self.assertEqual(self.inspect()['status'], 'NO_RECEIPT')

    def test_interrupted_source_call_blocks_all_future_ticks_and_inspection(self):
        with patch.object(self.guard.scheduler, 'invoke', side_effect=RuntimeError('abrupt stop')):
            first = self.summary()
        self.assertEqual(first['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(self.ledger()['entries'][0]['phase'], 'RESERVED')
        self.assertEqual(self.inspect()['status'], 'UNKNOWN_BLOCKED')
        with patch.object(self.guard.scheduler, 'invoke', side_effect=AssertionError('must never retry')):
            new_tick = self.summary(trigger_id='evt_event_240_after_interruption',
                                    scheduled_for_utc='2026-10-24T16:00:00.000000Z')
        self.assertEqual(new_tick['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(new_tick['reason_code'],
                         'CONFLICT_INTERRUPTED_RESERVATION_REQUIRES_RECONCILIATION')
        self.assert_nobody_wrote_business(new_tick)

    def test_known_ec239_check_block_has_final_receipt_not_permission(self):
        # EC237 finds an unsupported Action/Handler, not a business failure.
        bad = md.CycleMetadataStore(self.base / 'unsupported').create(
            snapshot_bytes=b'unsupported', source_ref='host:ec240-synthetic',
            actor_origin='human', actor_subject='declared-user',
            actions=[{'step_id': 'step_unknown', 'action': 'NoSuchAction',
                      'mode': None, 'depends_on': []}])
        guard = cg.CycleConflictGuard(self.base / 'unsupported')
        pins = dict(expected_record_sha256=bad['record_sha256'],
                    expected_action_set_sha256=bad['action_set_sha256'],
                    expected_input_sha256=bad['input']['sha256'])
        out = guard.scheduled_summary(bad['run_id'], **pins, **self.schedule)
        self.assertEqual(out['status'], 'RECORDED_CHECK_BLOCK')
        self.assertEqual(out['source_observation']['status'], 'CHECK_BLOCKED')
        self.assert_nobody_wrote_business(self.summary())

    def test_local_advisory_lock_nonblocking_parallel_other_tick(self):
        entered = threading.Event()
        release = threading.Event()
        original = self.guard.scheduler.invoke

        def slow(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(timeout=10))
            return original(*args, **kwargs)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with patch.object(self.guard.scheduler, 'invoke', side_effect=slow):
                future = pool.submit(self.summary)
                self.assertTrue(entered.wait(timeout=10))
                other = cg.CycleConflictGuard(self.path)
                out = other.scheduled_summary(
                    self.run_id, **self.pins,
                    **{**self.schedule, 'trigger_id': 'evt_event_240_other_process',
                       'scheduled_for_utc': '2026-10-24T16:00:00.000000Z'})
                self.assertEqual(out['status'], 'OVERLAP_BLOCKED')
                self.assertFalse(out['effects']['ec239_summary_called'])
                release.set()
                self.assertEqual(future.result(timeout=15)['status'], 'RECORDED_OBSERVATION')

    def test_damaged_receipt_or_orphan_swap_is_unknown(self):
        self.summary()
        name = self.path / (self.run_id + '.ec240.ledger.json')
        old = name.read_bytes()
        name.write_bytes(old.replace(b'FINAL', b'OTHER'))
        self.assertEqual(self.summary()['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(self.inspect()['status'], 'UNKNOWN_BLOCKED')
        name.write_bytes(old)
        orphan = self.path / (self.run_id + '.ec240.swap')
        orphan.write_bytes(b'interrupted temp')
        self.assertEqual(self.summary()['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(self.inspect()['status'], 'UNKNOWN_BLOCKED')

    def test_non_private_ledger_is_unknown(self):
        self.summary()
        name = self.path / (self.run_id + '.ec240.ledger.json')
        name.chmod(0o644)
        self.assertEqual(self.summary()['status'], 'UNKNOWN_BLOCKED')

    def test_explicit_business_write_permission_deny_is_not_a_fake_grant(self):
        out = self.guard.business_write_attempt(self.run_id, **self.pins)
        self.assertEqual(out['status'], 'PERMISSION_DENIED')
        self.assertFalse(out['effects']['new_guard_reservation_persisted'])
        self.assertFalse(out['effects']['permission_granted'])
        self.assertEqual(self.inspect()['status'], 'NO_RECEIPT')
        self.assert_nobody_wrote_business(out)

    def test_fabricated_positive_source_response_is_quarantined(self):
        original = self.guard.scheduler.invoke
        def corrupted(*args, **kwargs):
            out = original(*args, **kwargs)
            out['effects']['business_writes_performed'] = True
            return out
        with patch.object(self.guard.scheduler, 'invoke', side_effect=corrupted):
            first = self.summary()
        self.assertEqual(first['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(self.ledger()['entries'][0]['phase'], 'RESERVED')
        self.assertEqual(self.summary(trigger_id='evt_event_240_second_unsafe',
                                      scheduled_for_utc='2026-10-24T16:00:00.000000Z')['status'],
                         'UNKNOWN_BLOCKED')
        self.assertEqual(self.inspect(request_id='evt_event_240_other_no_receipt')['status'],
                         'UNKNOWN_BLOCKED')

    def test_result_and_ledger_draft2020_12_contract(self):
        import jsonschema
        root = Path(__file__).resolve().parent.parent / 'references'
        result_schema = json.loads((root / 'cycle-conflict-result.v1.schema.json').read_text())
        ledger_schema = json.loads((root / 'cycle-conflict-ledger.v1.schema.json').read_text())
        jsonschema.Draft202012Validator.check_schema(result_schema)
        jsonschema.Draft202012Validator.check_schema(ledger_schema)
        validate_result = jsonschema.Draft202012Validator(result_schema).validate
        for out in (self.inspect(), self.guard.business_write_attempt(self.run_id, **self.pins),
                    self.summary(), self.summary(), self.inspect(),
                    self.summary(trigger_id='evt_event_240_other')):
            validate_result(out)
        jsonschema.Draft202012Validator(ledger_schema).validate(self.ledger())
        self.assertEqual(cg.validate_ledger(self.ledger(), self.run_id,
                         {'record_sha256': self.pins['expected_record_sha256'],
                          'action_set_sha256': self.pins['expected_action_set_sha256'],
                          'input_sha256': self.pins['expected_input_sha256']}), self.ledger())

    def test_lock_symlink_cannot_authorize_operation(self):
        name = self.path / (self.run_id + '.ec240.lock')
        name.symlink_to(self.original_path)
        out = self.summary()
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(self.original_bytes, self.original_path.read_bytes())

    def test_cli_json_and_status_codes(self):
        script = Path(cg.__file__).resolve()
        common = ['--store', str(self.path), '--run-id', self.run_id,
                  '--expected-record-sha256', self.pins['expected_record_sha256'],
                  '--expected-action-set-sha256', self.pins['expected_action_set_sha256'],
                  '--expected-input-sha256', self.pins['expected_input_sha256']]
        cmd = [sys.executable, str(script), 'business_write_attempt', *common]
        r = subprocess.run(cmd, capture_output=True, check=False)
        self.assertEqual(r.returncode, 3)
        self.assertEqual(json.loads(r.stdout)['status'], 'PERMISSION_DENIED')
        invoke = [sys.executable, str(script), 'scheduled_summary', *common,
                  '--scheduler-kind', self.schedule['scheduler_kind'],
                  '--schedule-id', self.schedule['schedule_id'],
                  '--cadence', self.schedule['cadence'],
                  '--trigger-id', self.schedule['trigger_id'],
                  '--scheduled-for-utc', self.schedule['scheduled_for_utc']]
        r = subprocess.run(invoke, capture_output=True, check=False)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(json.loads(r.stdout)['status'], 'RECORDED_OBSERVATION')
        self.assertEqual(subprocess.run(invoke, capture_output=True).returncode, 2)
        inspect = [sys.executable, str(script), 'inspect', *common,
                   '--request-id', self.schedule['trigger_id']]
        r = subprocess.run(inspect, capture_output=True)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(json.loads(r.stdout)['status'], 'RECEIPT_OBSERVED')
        self.assert_nobody_wrote_business(json.loads(r.stdout))


@unittest.skipUnless(os.name == 'posix', 'EC238 genuine staged owner requires POSIX')
class ConflictGuardArtifactCases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ec240-cross-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.path = self.base / 'cycles'
        self.stage = self.base / 'stage'
        self.repo = self.base / 'repo'
        self.stage.mkdir(mode=0o700)
        self.repo.mkdir(mode=0o700)
        (self.repo / 'business.txt').write_bytes(b'PROTECTED_BIZ_NOT_CHANGED')
        stager = st.TaskStaging(str(self.stage), str(self.repo))
        self.pin = stager.initialize(approve_init=True)['parent_pin']
        session = lc.Lifecycle.create(context(), 'ec240-created-0001')
        snap = session.snapshot()
        for target, key in [('READY', 'ec240-ready-0001'), ('ACTIVE', 'ec240-active-0001')]:
            snap = session.advance_run(target, expected_revision=snap['revision'],
                                       context_sha256=snap['source']['context_sha256'],
                                       operation_key=key)
        snap = session.create_handoff(expected_revision=snap['revision'],
                                      context_sha256=snap['source']['context_sha256'],
                                      operation_key='ec240-handoff-0001')
        self.handoff = snap['handoffs'][0]['handoff_id']
        staged = stager.stage_live(session, expected_parent_pin=self.pin,
                                   expected_revision=snap['revision'],
                                   context_sha256=snap['source']['context_sha256'],
                                   operation_key='ec240-created-0001', authorize_stage=True)
        self.staged = staged
        snapshot = md.canonical({'schema': cc.CONTEXT_SNAPSHOT_SCHEMA,
                                 'stage_run_id': staged['run_id'],
                                 'handoff_id': self.handoff,
                                 'source_context_sha256': staged['source_context_sha256'],
                                 'source_identity_sha256': staged['source_identity_sha256']})
        self.source_ref = 'host:ec240-original-source'
        actions = [{'step_id': 'step_code', 'action': 'CodeShow',
                    'mode': None, 'depends_on': []},
                   {'step_id': 'step_finding', 'action': 'FindingShow',
                    'mode': None, 'depends_on': []}]
        record = md.CycleMetadataStore(self.path).create(
            snapshot_bytes=snapshot, source_ref=self.source_ref,
            actor_origin='human', actor_subject='declared-local', actions=actions)
        self.run_id = record['run_id']
        self.pins = dict(expected_record_sha256=record['record_sha256'],
                         expected_action_set_sha256=record['action_set_sha256'],
                         expected_input_sha256=record['input']['sha256'])
        self.original = (self.path / (self.run_id + '.cycle.json')).read_bytes()
        self.cross = cc.CycleCrossActionLedger(self.path, self.stage, self.repo)
        self.cross.link(self.run_id, self.handoff, snapshot_bytes=snapshot,
                        source_ref=self.source_ref, expected_stage_parent_pin=self.pin)
        self.guard = cg.CycleConflictGuard(self.path)
        self.raw = md.canonical({'schema': 'ces.code_prepare_multisource.v1',
                                 'status': 'partial',
                                 'reason_code': 'SYNTHETIC_UNVERIFIED',
                                 'metadata': {
                                     'handoff_id': self.handoff,
                                     'run_id': staged['run_id'],
                                     'source_context_sha256': staged['source_context_sha256'],
                                     'source_identity_sha256': staged['source_identity_sha256']}})
        self.params = dict(upload_id='upl_local_240_artifact_1234',
                           stage_store=self.stage, business_repo_root=self.repo,
                           handoff_id=self.handoff, expected_stage_parent_pin=self.pin,
                           family='Code', step_id='step_code', artifact_bytes=self.raw)

    def attach(self, **kw):
        return self.guard.artifact_attach(self.run_id, **self.pins, **{**self.params, **kw})

    def test_real_ec238_attach_then_duplicate_and_other_id_are_suppressed(self):
        out = self.attach()
        self.assertEqual(out['status'], 'RECORDED_LOCAL_ATTACHMENT')
        self.assertEqual(out['source_observation']['status'], 'ATTACHED_LOCAL_ONLY')
        self.assertTrue(out['effects']['ec238_local_artifact_attach_called'])
        artifact = self.path / ('artifact_' + hashlib.sha256(self.raw).hexdigest() + cc.ARTIFACT_FILE)
        initial = artifact.read_bytes()
        with patch.object(cc.CycleCrossActionLedger, 'attach', side_effect=AssertionError('repeat')):
            repeat = self.attach()
            new_alias = self.attach(upload_id='upl_local_240_different_id')
        self.assertEqual(repeat['status'], 'REPLAY_SUPPRESSED')
        self.assertEqual(new_alias['status'], 'REPLAY_SUPPRESSED')
        self.assertEqual(artifact.read_bytes(), initial)
        self.assertEqual((self.path / (self.run_id + '.cycle.json')).read_bytes(), self.original)
        self.assertEqual((self.repo / 'business.txt').read_bytes(), b'PROTECTED_BIZ_NOT_CHANGED')

    def test_same_step_different_bytes_and_same_request_id_other_step_block(self):
        self.assertEqual(self.attach()['status'], 'RECORDED_LOCAL_ATTACHMENT')
        changed = md.canonical({'schema': 'ces.code_prepare_multisource.v1',
                                'status': 'partial', 'reason_code': 'OTHER'})
        self.assertEqual(self.attach(artifact_bytes=changed)['status'], 'CONFLICT_BLOCKED')
        self.assertEqual(self.attach(family='Finding', step_id='step_finding')['status'],
                         'CONFLICT_BLOCKED')

    def test_attachment_preflight_wrong_parent_pin_does_not_poison_ledger(self):
        wrong = self.attach(expected_stage_parent_pin='f' * 64)
        self.assertIn(wrong['status'], ('REJECTED', 'UNKNOWN_BLOCKED'))
        ledger = self.path / (self.run_id + '.ec240.ledger.json')
        self.assertFalse(ledger.exists())
        self.assertEqual(self.attach()['status'], 'RECORDED_LOCAL_ATTACHMENT')

    def test_interrupted_after_local_artifact_receipt_never_uploads_twice(self):
        real = cc.CycleCrossActionLedger.attach
        def attach_then_crash(bound, *args, **kwargs):
            real(bound, *args, **kwargs)
            raise RuntimeError('simulated process death after EC238 local commit')
        with patch.object(cc.CycleCrossActionLedger, 'attach', new=attach_then_crash):
            first = self.attach()
        self.assertEqual(first['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(json.loads((self.path / (self.run_id + '.ec240.ledger.json')).read_bytes())
                         ['entries'][0]['phase'], 'RESERVED')
        with patch.object(cc.CycleCrossActionLedger, 'attach', side_effect=AssertionError('retry forbidden')):
            self.assertEqual(self.attach()['status'], 'UNKNOWN_BLOCKED')
            self.assertEqual(self.attach(upload_id='upl_local_240_new_attempt')['status'],
                             'UNKNOWN_BLOCKED')
        self.assertEqual((self.repo / 'business.txt').read_bytes(), b'PROTECTED_BIZ_NOT_CHANGED')

    def test_real_cli_artifact_attach_replay_and_bounded_output(self):
        art = self.base / 'artifact-input.json'
        art.write_bytes(self.raw)
        program = Path(cg.__file__).resolve()
        common = [sys.executable, str(program), 'artifact_attach',
                  '--store', str(self.path), '--run-id', self.run_id,
                  '--expected-record-sha256', self.pins['expected_record_sha256'],
                  '--expected-action-set-sha256', self.pins['expected_action_set_sha256'],
                  '--expected-input-sha256', self.pins['expected_input_sha256'],
                  '--upload-id', self.params['upload_id'],
                  '--stage-store', str(self.stage), '--business-root', str(self.repo),
                  '--handoff-id', self.handoff, '--stage-parent-pin', self.pin,
                  '--family', 'Code', '--step-id', 'step_code',
                  '--artifact-file', str(art)]
        first = subprocess.run(common, capture_output=True, check=False)
        self.assertEqual(first.returncode, 2, first.stderr)
        self.assertEqual(json.loads(first.stdout)['status'], 'RECORDED_LOCAL_ATTACHMENT')
        repeat = subprocess.run(common, capture_output=True, check=False)
        self.assertEqual(repeat.returncode, 2)
        self.assertEqual(json.loads(repeat.stdout)['status'], 'REPLAY_SUPPRESSED')

    def test_bad_declared_family_and_malformed_artifact_preflight_no_reservation(self):
        self.assertEqual(self.attach(family='NotAFamily')['status'], 'REJECTED')
        self.assertIn(self.attach(artifact_bytes=b'not json')['status'], ('REJECTED', 'UNKNOWN_BLOCKED'))
        self.assertFalse((self.path / (self.run_id + '.ec240.ledger.json')).exists())


if __name__ == '__main__':
    unittest.main()
