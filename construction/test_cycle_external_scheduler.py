#!/usr/bin/env python3
"""EC239 focused functional local scenarios; NO installed scheduler or business E2E."""
from __future__ import annotations

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
    from . import cycle_summary as sm
    from . import cycle_external_scheduler as ex
except ImportError:
    import cycle_run_metadata as md
    import cycle_summary as sm
    import cycle_external_scheduler as ex


@unittest.skipUnless(os.name == 'posix', 'requires genuine EC231 owner-private store')
class ExternalSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ec239-schedule-boundary-')
        self.addCleanup(self.tmp.cleanup)
        self.store_path = Path(self.tmp.name) / 'cycle-store'
        self.record = md.CycleMetadataStore(self.store_path).create(
            snapshot_bytes=b'EC239 real new local snapshot; not business execution',
            source_ref='local:ec239-fixture', actor_origin='human',
            actor_subject='ec239-declared-operator',
            actions=[{'step_id': 'step_one', 'action': 'Inspect',
                      'mode': 'Snapshot', 'depends_on': []}])
        self.path = self.store_path / (self.record['run_id'] + '.cycle.json')
        self.before = self.path.read_bytes()
        self.boundary = ex.CycleExternalSchedulerBoundary(self.store_path)
        self.args = dict(cadence='hourly', scheduler_kind='cron',
                         host_state='absent', schedule_id='ces-pipeline.hourly',
                         expected_record_sha256=self.record['record_sha256'],
                         expected_action_set_sha256=self.record['action_set_sha256'],
                         expected_input_sha256=self.record['input']['sha256'])
        self.trigger = dict(trigger_id='evt_local_event_239_a1',
                            scheduled_for_utc='2026-10-24T15:00:00.000000Z')

    def plan(self, **kwargs):
        return self.boundary.plan(self.record['run_id'], **{**self.args, **kwargs})

    def invoke(self, **kwargs):
        return self.boundary.invoke(self.record['run_id'],
                                    **{**self.args, 'host_state': 'claimed_configured',
                                       **self.trigger, **kwargs})

    def asserts_unprivileged(self, result):
        self.assertEqual(result['schema'], ex.SCHEMA)
        self.assertFalse(result['scheduler']['external_installation_verified'])
        self.assertFalse(result['scheduler']['external_cadence_verified'])
        self.assertFalse(result['scheduler']['external_trigger_authenticated'])
        self.assertFalse(result['scheduler']['scheduled_job_created'])
        self.assertFalse(result['trigger']['execution_on_schedule_proven'])
        self.assertFalse(result['trigger']['deduplication_checked'])
        self.assertTrue(all(not val for key, val in result['effects'].items()
                            if key != 'local_read_only_summary_observed'))
        self.assertFalse(result['preconditions']['external_scheduler_authority_verified'])
        self.assertFalse(result['preconditions']['actor_authenticated'])
        self.assertFalse(result['preconditions']['business_input_source_authenticated'])
        self.assertFalse(result['preconditions']['independent_permission_granted'])
        self.assertEqual(result['outstanding']['duplicate_concurrent_delivery'],
                         'NOT_IMPLEMENTED_EC240')
        self.assertEqual(self.before, self.path.read_bytes())

    def test_absent_host_yields_only_instructions_not_checks(self):
        with patch.object(self.boundary.reporter, 'summary', side_effect=AssertionError('not allowed')):
            result = self.plan()
        self.assertEqual(result['status'], 'INSTRUCTIONS_ONLY')
        self.assertEqual(result['check']['summary'], None)
        self.assertFalse(result['check']['called'])
        self.assertFalse(result['effects']['local_read_only_summary_observed'])
        argv = result['invocation']['command_argv_template']
        self.assertEqual(argv[2], 'invoke')
        self.assertIn('--trigger-id', argv)
        self.assertIn('--scheduled-for-utc', argv)
        self.assertEqual(argv[argv.index('--host-state')+1], 'claimed_configured')
        self.assertEqual(result['cadence']['cron_utc_reference'], '0 * * * *')
        self.assertEqual(result['preconditions']['three_caller_sha_pins_match_local_record'], True)
        self.asserts_unprivileged(result)

    def test_plan_caller_config_claim_remains_unverified(self):
        result = self.plan(host_state='claimed_configured', scheduler_kind='windows_task')
        self.assertEqual(result['status'], 'CONFIG_CLAIM_ONLY')
        self.assertFalse(result['scheduler']['external_installation_verified'])
        self.assertFalse(result['check']['called'])
        self.asserts_unprivileged(result)

    def test_external_invocation_returns_real_read_only_summary_only(self):
        result = self.invoke()
        self.assertEqual(result['status'], 'CHECK_OBSERVED_ONLY')
        self.assertEqual(result['check']['summary_status'], 'NOT_STARTED')
        self.assertEqual(result['check']['summary']['counts']['verified_success'], 0)
        self.assertTrue(result['check']['called'])
        self.assertTrue(result['effects']['local_read_only_summary_observed'])
        self.assertTrue(result['cadence']['tick_alignment_checked'])
        self.assertEqual(result['trigger']['event_id_claim'], self.trigger['trigger_id'])
        self.asserts_unprivileged(result)

    def test_absent_declared_scheduler_never_invokes_check(self):
        with patch.object(self.boundary.reporter, 'summary', side_effect=AssertionError('not allowed')):
            result = self.invoke(host_state='absent')
        self.assertEqual(result['status'], 'TRIGGER_REJECTED')
        self.assertEqual(result['reason_code'], 'EXTERNAL_SCHEDULE_HOST_DECLARED_ABSENT')
        self.assertIsNone(result['check']['summary'])
        self.asserts_unprivileged(result)

    def test_invalid_event_token_cannot_call_summary(self):
        with patch.object(self.boundary.reporter, 'summary', side_effect=AssertionError('not allowed')):
            result = self.invoke(trigger_id='evt_bad;rm -rf /')
        self.assertEqual(result['status'], 'TRIGGER_REJECTED')
        self.assertEqual(result['reason_code'], 'EXTERNAL_SCHEDULE_EVENT_ID_INVALID')
        self.asserts_unprivileged(result)

    def test_missing_trigger_fields_rejected(self):
        result = self.boundary._run('invoke', self.record['run_id'], **self.args)
        self.assertEqual(result['status'], 'TRIGGER_REJECTED')
        self.asserts_unprivileged(result)

    def test_daily_weekly_utc_tick_contract(self):
        for cadence, good in [('daily', '2026-10-25T00:00:00.000000Z'),
                              ('weekly', '2026-10-26T00:00:00.000000Z')]:
            with self.subTest(cadence=cadence):
                result = self.invoke(cadence=cadence, scheduled_for_utc=good)
                self.assertEqual(result['status'], 'CHECK_OBSERVED_ONLY')
                self.asserts_unprivileged(result)
        for cadence, tick in [('hourly', '2026-10-24T15:01:00.000000Z'),
                              ('hourly', '2026-10-24T15:00:01.000000Z'),
                              ('daily', '2026-10-24T15:00:00.000000Z'),
                              ('weekly', '2026-10-25T00:00:00.000000Z'),
                              ('weekly', '2026-10-26T00:00:00.000001Z')]:
            with self.subTest(bad=(cadence,tick)):
                result = self.invoke(cadence=cadence, scheduled_for_utc=tick)
                self.assertEqual(result['status'], 'TRIGGER_REJECTED')
                self.assertEqual(result['reason_code'], 'EXTERNAL_SCHEDULE_TICK_NOT_ON_CADENCE')
                self.asserts_unprivileged(result)

    def test_unknown_or_ambiguous_trigger_calendar_is_rejected(self):
        for tick in ('2026-02-30T00:00:00.000000Z',
                     '2026-10-24T15:00:00Z',
                     '2026-10-24T15:00:00.000000+00:00',
                     '2026-10-24T15:00:00.000000Z\n--hack'):
            with self.subTest(tick=tick):
                result = self.invoke(scheduled_for_utc=tick)
                self.assertEqual(result['status'], 'TRIGGER_REJECTED')
                self.asserts_unprivileged(result)

    def test_unknown_cadence_or_kind_or_host_or_id(self):
        for overrides in ({'cadence':'every_5_seconds'},
                          {'scheduler_kind':'shell;cmd'},
                          {'host_state':'verified_installed'},
                          {'schedule_id':'../unknown'},
                          {'schedule_id':'a'},
                          {'expected_input_sha256':'not-hash'}):
            with self.subTest(overrides=overrides):
                result = self.plan(**overrides)
                self.assertEqual(result['status'], 'PLAN_REJECTED')
                self.asserts_unprivileged(result)

    def test_wrong_independent_pins_must_not_show_local_record(self):
        for name in ('expected_record_sha256',
                     'expected_action_set_sha256', 'expected_input_sha256'):
            with self.subTest(pin=name):
                result = self.plan(**{name: 'a'*64 if self.args[name] != 'a'*64 else 'b'*64})
                self.assertEqual(result['status'], 'UNKNOWN_BLOCKED')
                self.assertEqual(result['reason_code'], 'EXTERNAL_SCHEDULE_PIN_MISMATCH')
                self.assertIsNone(result['record_binding'])
                self.assertIsNone(result['run_id'])
                self.assertFalse(result['preconditions']['three_caller_sha_pins_match_local_record'])
                self.asserts_unprivileged(result)

    def test_missing_run_unknown_without_creating_run(self):
        rid = 'run_v1_' + 'f'*48
        result = self.boundary.plan(rid, **self.args)
        self.assertEqual(result['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(result['reason_code'], 'CYCLE_RUN_NOT_FOUND')
        self.assertFalse((self.store_path / (rid+'.cycle.json')).exists())
        self.asserts_unprivileged(result)

    def test_nonprivate_or_corrupt_run_unknown(self):
        self.path.chmod(0o644)
        result = self.plan()
        self.assertEqual(result['status'], 'UNKNOWN_BLOCKED')
        self.assertIsNone(result['check']['summary'])
        self.path.chmod(0o600)
        self.path.write_text('corrupted')
        result = self.invoke()
        self.assertEqual(result['status'], 'UNKNOWN_BLOCKED')
        self.assertIsNone(result['check']['summary'])

    def test_corrupt_summary_cannot_escalate_success(self):
        forged = {'status': 'NOT_STARTED', 'overall_success_proven': True}
        with patch.object(self.boundary.reporter, 'summary', return_value=forged):
            out = self.invoke()
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertIsNone(out['check']['summary'])
        self.asserts_unprivileged(out)

    def test_ec237_unknown_summary_is_redacted(self):
        unknown = sm.CycleSummaryReporter(self.store_path).summary(
            'run_v1_' + 'f'*48)
        self.assertEqual(unknown['status'], 'UNKNOWN_BLOCKED')
        with patch.object(self.boundary.reporter, 'summary', return_value=unknown):
            out = self.invoke()
        self.assertEqual(out['status'], 'UNKNOWN_BLOCKED')
        self.assertIsNone(out['check']['summary'])
        self.asserts_unprivileged(out)

    def test_ec237_known_block_is_not_success(self):
        # Real source-backed first root only: invalid action fails safe.
        other = md.CycleMetadataStore(self.store_path).create(
            snapshot_bytes=b'ec239 unsupported action', source_ref='local:unsupported',
            actor_origin='external', actor_subject='unverified-job',
            actions=[{'step_id':'step_unavailable', 'action':'NotAvailable',
                      'mode':None, 'depends_on':[]}])
        args = dict(self.args, host_state='claimed_configured',
                    expected_record_sha256=other['record_sha256'],
                    expected_action_set_sha256=other['action_set_sha256'],
                    expected_input_sha256=other['input']['sha256'])
        out = self.boundary.invoke(other['run_id'], **args, **self.trigger)
        self.assertEqual(out['status'], 'CHECK_BLOCKED')
        self.assertEqual(out['check']['summary_status'], 'BLOCKED_NO_HANDLER')
        self.assertEqual(out['check']['summary']['counts']['verified_success'], 0)
        self.assertFalse(out['effects']['business_success_proven'])

    def test_repeated_same_trigger_is_not_deduplicated_or_represented_as_unique(self):
        first = self.invoke()
        second = self.invoke()
        self.assertEqual(first['status'], 'CHECK_OBSERVED_ONLY')
        self.assertEqual(second['status'], 'CHECK_OBSERVED_ONLY')
        self.assertEqual(first['trigger']['event_id_claim'], second['trigger']['event_id_claim'])
        self.assertFalse(second['effects']['duplicate_or_overlap_prevented'])
        self.asserts_unprivileged(second)

    def test_plan_does_not_create_scheduler_artifacts(self):
        self.plan()
        self.invoke()
        self.assertEqual({p.name for p in self.store_path.iterdir()},
                         {self.path.name})
        self.assertEqual(self.path.read_bytes(), self.before)

    def test_cli_plan_and_invoke_codes_and_json_line(self):
        base = [sys.executable, str(Path(ex.__file__).resolve()),
                '--store', str(self.store_path), '--run-id', self.record['run_id'],
                '--cadence', 'hourly', '--scheduler-kind','cron',
                '--schedule-id', self.args['schedule_id'],
                '--expected-record-sha256', self.args['expected_record_sha256'],
                '--expected-action-set-sha256', self.args['expected_action_set_sha256'],
                '--expected-input-sha256', self.args['expected_input_sha256']]
        cases = [('plan', 'absent', [], 2, 'INSTRUCTIONS_ONLY'),
                 ('plan', 'claimed_configured', [], 2, 'CONFIG_CLAIM_ONLY'),
                 ('invoke', 'claimed_configured', ['--trigger-id', self.trigger['trigger_id'],
                      '--scheduled-for-utc', self.trigger['scheduled_for_utc']],
                  2, 'CHECK_OBSERVED_ONLY'),
                 ('invoke', 'absent', ['--trigger-id', self.trigger['trigger_id'],
                      '--scheduled-for-utc', self.trigger['scheduled_for_utc']],
                  3, 'TRIGGER_REJECTED'),
                 ('invoke', 'claimed_configured', [], 3, 'TRIGGER_REJECTED')]
        for operation,host,extras,exit_code,status in cases:
            with self.subTest(operation=operation,host=host,extra=extras):
                command = base[:2] + [operation] + base[2:] + ['--host-state',host] + extras
                got = subprocess.run(command, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=25)
                self.assertEqual(got.returncode, exit_code, got.stderr)
                self.assertEqual(got.stdout.count(b'\n'), 1)
                self.assertEqual(json.loads(got.stdout)['status'], status)
                self.assertFalse(got.stderr)

    def test_full_json_schema_and_semantic_non_escalation(self):
        import jsonschema
        base = Path(__file__).resolve().parent.parent
        schema = json.loads((base / 'references/cycle-external-scheduler.v1.schema.json')
                            .read_text(encoding='utf-8'))
        jsonschema.Draft202012Validator.check_schema(schema)
        validate = jsonschema.Draft202012Validator(schema).validate
        for item in (self.plan(), self.plan(host_state='claimed_configured'),
                     self.invoke(), self.invoke(host_state='absent'),
                     self.invoke(trigger_id='evt_injection_not_good!'),
                     self.plan(expected_input_sha256='a'*64)):
            with self.subTest(status=item['status']):
                validate(item)
                self.asserts_unprivileged(item)
                self.assertLessEqual(len(ex._serialize(item)), ex.MAX_JSON_OUTPUT)
        self.assertFalse(schema['properties']['scheduler']['properties']
                         ['external_installation_verified']['const'])


if __name__ == '__main__':
    unittest.main()
