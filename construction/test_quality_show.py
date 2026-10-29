#!/usr/bin/env python3
"""EC188 strictly local synthetic QualityShow contract/behavior tests.

These receipts are constructed as synthetic fixtures and use the real upstream
checksum algorithms. They are NOT provider calls, host runs or final acceptance.
"""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest

import jsonschema

import quality_detect as detect
import quality_read_ci as ci
import quality_sha_bind as sha
import quality_ci_evidence as cie
import quality_observation as obs
import quality_run_guard as run_guard
import quality_run_budget as run_budget
from quality_show import QualityShow, SCHEMA, KINDS, canonical

NOW = datetime(2026, 10, 23, 5, 0, 0, tzinfo=timezone.utc)
KEY = bytes(range(32))
PIN = 'a' * 64
PIN2 = 'b' * 64
SHA = 'c' * 40
SHA2 = 'd' * 40
LOCAL = {'source_mode': 'WorkingTree', 'root_pin_sha256': PIN}
REMOTE = {'source_mode': 'DeliveredTarget', 'provider': 'github',
          'repository': 'test-org/example', 'project_id': 1234,
          'commit_sha': SHA, 'proposal_number': None}
PROPOSAL = {**REMOTE, 'source_mode': 'ProposedPR', 'proposal_number': 9}


def at(seconds=0):
    return (NOW + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')


def sample(kind, *, scope=LOCAL, offset=0):
    result = SYNTHETIC_RESULTS[kind](scope)
    return {'kind': kind, 'result': result, 'source_scope': copy.deepcopy(scope),
            'recorded_at_utc': at(offset)}


def _base(schema, fields):
    return {'schema': schema, 'status': 'partial', 'exit_code': 2,
            'reason_code': 'SYNTHETIC_DEV_RECEIPT', **fields,
            'trust_boundary': 'SYNTHETIC_CLAIMS_NOT_INDEPENDENTLY_VERIFIED'}


def config(scope):
    source = {'source_mode': 'WorkingTree',
              'local_root_pin_sha256': scope['root_pin_sha256']}
    coverage = {'repository_wide_inventory_complete': False, 'tests_executed': False,
                'selected_paths': 1, 'unparsed_or_malformed_configs': 0}
    fields = {'source': source, 'files': [], 'languages': [], 'tools': [],
              'profile_hints': [], 'coverage': coverage}
    return _base(detect.SCHEMA, {**fields, 'inventory_sha256':
                  detect._sha(detect.DOMAIN_INVENTORY, fields)})


def ci_metadata(scope):
    source = {key: scope[key] for key in ('provider', 'repository', 'project_id', 'commit_sha')}
    fields = {'source': source, 'observation': {'run': {}, 'job': {}},
              'permission': {'transport': 'SYNTHETIC'},
              'coverage': {'git_sha_binding_verified': False,
                           'test_execution_by_ces': False}}
    return _base(ci.SCHEMA, {**fields, 'observation_sha256': ci._hash(fields)})


def sha_binding(scope):
    source = copy.deepcopy(scope)
    fields = {'source': source, 'ci_observation': {},
              'binding': {'sha_equal': True, 'source_commit_sha': scope['commit_sha'],
                          'ci_commit_sha': scope['commit_sha'],
                          'git_object_bytes_hashed': False,
                          'tests_executed_by_ces': False},
              'permission': {'transport': 'SYNTHETIC'}, 'coverage': {}}
    return _base(sha.SCHEMA, {**fields, 'association_sha256': sha.checksum(fields)})


def ci_evidence_sample(scope):
    s = {**scope, 'source_proposal_object_id': None}
    fields = {'scope': s, 'test_evidence': {
        'state': 'pass', 'availability': 'present',
        'counts': {'total': 7, 'passed': 7, 'failed': 0, 'skipped': 0},
        'preview': 'SHOULD_NOT_APPEAR'},
        'report_evidence': {'state': 'measured',
                            'coverage_metrics': {'lines_total': 100,
                                                 'lines_covered': 75, 'percent': 75.0}},
        'classification': 'pass',
        'coverage': {'actual_tests_executed_by_ces': False,
                     'runner_integrity_verified': False,
                     'github_report_run_only': True},
        'permission': {'transport': 'SYNTHETIC'}}
    return _base(cie.SCHEMA,
                 {**fields, 'evidence_sha256': cie.digest(fields)})


def observation(scope):
    is_local = scope['source_mode'] == 'WorkingTree'
    local = {'pin_digest': scope['root_pin_sha256']} if is_local else None
    remote = None if is_local else dict(scope)
    proof = {'overall_quality_pass_verified': False,
             'performance_measured': False,
             'ci_test_execution_independently_verified': False,
             'git_object_bytes_verified': False}
    tests = (None if is_local else {'classification': 'pass',
             'is_provider_content_claim': True, 'ces_tests_executed': False,
             'counts': {'total': 3, 'passed': 3, 'failed': 0, 'skipped': 0}})
    coverage = None if is_local else {'state': 'provider_reported',
                'independently_measured_by_ces': False,
                'metrics': {'lines_total': 11, 'lines_covered': 9, 'percent': 81.82}}
    fields = {'observed_at_utc': at(),
              'source': {'local': local, 'remote': remote,
                         'same_revision_proven': False},
              'observations': {'local_config': {'pin_digest': scope['root_pin_sha256'],
                               'candidate_paths': 2} if is_local else None,
                               'tests': tests, 'coverage': coverage,
                               'performance': {'state': 'not_measured',
                                               'benchmark_samples': 0, 'metrics': []}},
              'evidence_refs': [], 'execution_environment': {}, 'grants': {},
              'proof': proof}
    return _base(obs.SCHEMA, {**fields, 'observation_sha256': obs._hash(fields)})


def run_preflight(scope):
    fields = {'prepared_at_utc': at(), 'profile': {'id': 'python.pytest'},
              'source': {'mode': 'WorkingTree', 'source_pin_sha256': scope['root_pin_sha256']},
              'authorization': {}, 'isolation': {}, 'context': {},
              'plan': {'state': 'PREPARED_ONLY_NOT_EXECUTABLE',
                       'source_pin_sha256': scope['root_pin_sha256']},
              'proof': {'overall_quality_pass_verified': False,
                        'actual_isolation_verified_by_ces': False}}
    return _base(run_guard.SCHEMA, {**fields, 'plan_sha256':
                  run_guard._digest(run_guard.DOMAIN_PLAN, fields)})


def run_session(_scope):
    fields = {'profile_id': 'python.pytest', 'limits': {},
              'execution': {'state': 'exited_host_reported', 'overall_pass_verified': False,
                            'actual_process_exit_independently_verified': False,
                            'host_reported_exit_code': 0},
              'resources': {},
              'output': {'stdout_preview': 'SENSITIVE_STDOUT\nSECRET=abc123',
                         'stderr_preview': 'private source',
                         'truncated': False, 'complete': True,
                         'captured_bytes': 34, 'discarded_bytes': 0},
              'proof': {'quality_pass_verified': False,
                        'kernel_isolation_independently_verified': False,
                        'broker_identity_independently_authenticated': False,
                        'test_execution_verified_by_ces': False,
                        'host_claims_only': True},
              'effects': {'stop_requested': False, 'reaped_reported_by_host': False}}
    return _base(run_budget.SCHEMA, fields)


SYNTHETIC_RESULTS = {
    'config': config, 'ci_metadata': ci_metadata,
    'sha_binding': sha_binding, 'ci_evidence': ci_evidence_sample,
    'observation': observation, 'run_preflight': run_preflight,
    'run_session': run_session,
}


class QualityShowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        contract_file = (Path(__file__).resolve().parent.parent / 'references' /
                         'quality-show-result.v1.schema.json')
        contract = json.loads(contract_file.read_text(encoding='utf8'))
        jsonschema.Draft202012Validator.check_schema(contract)
        cls.validator = jsonschema.Draft202012Validator(contract)

    def setUp(self):
        self.clock = lambda: NOW
        self.svc = QualityShow(cursor_key=KEY, clock=self.clock)
        self.calls = []

    def scope_grant(self, facts):
        self.calls.append(('scope', facts['phase']))
        return True

    def item_grant(self, facts):
        self.calls.append(('evidence', facts['kind']))
        return True

    def metric_grant(self, facts):
        self.calls.append(('metrics', facts['phase']))
        return True

    def query(self, records=None, scope=LOCAL, **kwargs):
        return self.svc.query(
            source_scope=copy.deepcopy(scope),
            evidence=copy.deepcopy(records if records is not None else [sample('config')]),
            allow_query=True, allow_evidence_read=True,
            authorize_scope=self.scope_grant,
            authorize_evidence=self.item_grant, **kwargs)

    def assertPartial(self, output):
        self.validator.validate(output)
        self.assertEqual((output['status'], output['exit_code']), ('partial', 2), output)
        self.assertFalse(output['coverage']['quality_pass_independently_verified'])
        self.assertFalse(output['proof']['verified_quality_pass'])

    def assertDenied(self, output, reason=None):
        self.validator.validate(output)
        self.assertIn(output['status'], ('invalid_input', 'unavailable'), output)
        self.assertEqual(output['exit_code'], 4 if output['status'] == 'invalid_input' else 5)
        self.assertEqual(output['entries'], [])
        self.assertIsNone(output['counts'])
        if reason:
            self.assertEqual(output['reason_code'], reason)

    def test_local_exact_config_and_coverage(self):
        o = self.query()
        self.assertPartial(o)
        self.assertEqual(o['entries'][0]['kind'], 'config')
        self.assertIn('NOT_REPOSITORY_WIDE', o['entries'][0]['incompleteness'])
        self.assertEqual(o['coverage']['not_supplied_classes'], sorted(set(KINDS) - {'config'}))
        self.assertEqual(self.calls, [('scope','BEFORE_READ'),
                                      ('evidence','config'), ('scope','FINALIZE')])

    def test_ci_read_claim_not_sha_bind(self):
        o = self.query([sample('ci_metadata', scope=REMOTE)], scope=REMOTE)
        self.assertPartial(o)
        self.assertEqual(o['entries'][0]['binding_strength'],
                         'REMOTE_METADATA_SHA_MATCH_MODE_CALLER_SELECTED')
        self.assertIn('SOURCE_MODE_NOT_IN_EC182_RECEIPT', o['entries'][0]['incompleteness'])
        self.assertEqual(o['entries'][0]['summary']['provider_run_state'], 'unknown')
        self.assertEqual(o['entries'][0]['summary']['provider_job_conclusion'], 'unknown')

    def test_sha_binding_exact_provider_field_only(self):
        o = self.query([sample('sha_binding', scope=REMOTE)], scope=REMOTE)
        self.assertPartial(o)
        self.assertEqual(o['entries'][0]['summary']['association'],
                         'PROVIDER_FIELD_CLAIM_SHA_EQUAL')

    def test_ci_pass_never_global_verified(self):
        o = self.query([sample('ci_evidence', scope=REMOTE)], scope=REMOTE)
        self.assertPartial(o)
        self.assertEqual(o['entries'][0]['classification'], 'pass')
        self.assertEqual(o['coverage']['ci_pass_claim_count_not_verified'], 1)
        self.assertNotIn('provider_test_counts', o['entries'][0]['summary'])
        self.assertNotIn('SENSITIVE_STDOUT', json.dumps(o))

    def test_remote_observation_no_benchmark(self):
        o = self.query([sample('observation', scope=REMOTE)], scope=REMOTE)
        self.assertPartial(o)
        self.assertEqual(o['entries'][0]['summary']['test_classification'], 'pass')
        self.assertFalse(o['coverage']['performance_benchmark_measured'])

    def test_local_observation_separate_track(self):
        o = self.query([sample('observation')])
        self.assertPartial(o)
        self.assertEqual(o['entries'][0]['summary']['observation_track'],
                         'LOCAL_ONLY_EXTRACTED')
        self.assertNotIn('test_classification', o['entries'][0]['summary'])

    def test_local_run_preflight_not_execution(self):
        o = self.query([sample('run_preflight')])
        self.assertPartial(o)
        self.assertEqual(o['entries'][0]['summary']['execution_state'],
                         'NOT_EXECUTED_PREFLIGHT_ONLY')

    def test_ec187_exit_zero_is_host_claim_no_pass_or_stdout(self):
        o = self.query([sample('run_session')])
        self.assertPartial(o)
        row = o['entries'][0]
        self.assertEqual(row['binding_strength'], 'CALLER_LINKED_NO_SOURCE_PIN_IN_EC187_RESULT')
        self.assertTrue(row['summary']['host_reported_exit_zero_is_not_pass'])
        self.assertEqual(row['summary']['host_reported_exit_code'], 0)
        self.assertEqual(o['coverage']['caller_linked_ec187_count'], 1)
        self.assertNotIn('SENSITIVE_STDOUT', json.dumps(o))
        self.assertNotIn('SECRET=', json.dumps(o))
        self.assertNotIn('private source', json.dumps(o))

    def test_ec187_interrupt_truncation_reap_uncertainty(self):
        rec = sample('run_session')
        rec['result']['execution']['state'] = 'interrupted_or_unverified'
        rec['result']['execution']['host_reported_exit_code'] = None
        rec['result']['output']['truncated'] = True
        rec['result']['output']['complete'] = False
        rec['result']['output']['discarded_bytes'] = 44
        rec['result']['effects']['stop_requested'] = True
        o = self.query([rec])
        self.assertPartial(o)
        self.assertEqual(o['coverage']['interrupted_ec187_count'], 1)
        self.assertEqual(o['coverage']['output_truncated_ec187_count'], 1)
        self.assertIn('INTERRUPTED_OR_UNCONFIRMED_TERMINATION',
                      o['entries'][0]['incompleteness'])
        self.assertFalse(o['entries'][0]['summary']['termination_reaped_host_reported'])

    def test_ec187_inconsistent_complete_and_truncated_denied(self):
        rec = sample('run_session')
        rec['result']['output']['truncated'] = True
        self.assertDenied(self.query([rec]), 'QUALITYSHOW_RUN_OUTPUT_STATE_INVALID')

    def test_ec187_unverified_true_is_denied(self):
        rec = sample('run_session')
        rec['result']['proof']['quality_pass_verified'] = True
        self.assertDenied(self.query([rec]), 'QUALITYSHOW_UNSUPPORTED_VERIFIED_PROOF_FLAG')

    def test_ec187_remote_cannot_be_attached(self):
        self.assertDenied(self.query([sample('run_session', scope=REMOTE)], scope=REMOTE),
                          'QUALITYSHOW_RUN_SESSION_REMOTE_SCOPE_NOT_SUPPORTED')

    def test_metric_optin_and_independent_grant(self):
        data = [sample('ci_evidence', scope=REMOTE)]
        denied = self.query(data, scope=REMOTE, include_numeric_metrics=True)
        self.assertDenied(denied, 'QUALITYSHOW_NUMERIC_METRICS_NOT_AUTHORIZED')
        o = self.query(data, scope=REMOTE, include_numeric_metrics=True,
                       authorize_numeric_metrics=self.metric_grant)
        self.assertPartial(o)
        self.assertEqual(o['entries'][0]['summary']['provider_test_counts']['total'], 7)
        self.assertEqual(o['entries'][0]['summary']['provider_coverage_metrics']['percent'], 75)
        self.assertIn(('metrics','FINALIZE'), self.calls)

    def test_provider_transport_redaction(self):
        rec = sample('ci_metadata', scope=REMOTE)
        rec['result']['permission']['transport'] = 'Authorization: super-secret-token'
        rec['result']['observation_sha256'] = ci._hash({
            k: rec['result'][k] for k in ('source', 'observation','permission','coverage')})
        o = self.query([rec], scope=REMOTE)
        self.assertPartial(o)
        self.assertNotIn('super-secret', json.dumps(o))

    def test_sensitive_caller_source_repository_not_echoed(self):
        scope = dict(REMOTE, repository='organization/private-repository')
        o = self.query([sample('ci_evidence', scope=scope)], scope=scope)
        self.assertPartial(o)
        self.assertNotIn('organization/private-repository', json.dumps(o))

    def test_no_match_cannot_assert_absence(self):
        o = self.query([sample('config')], filters={'kinds':['ci_evidence']})
        self.assertPartial(o)
        self.assertEqual(o['entries'], [])
        self.assertEqual(o['reason_code'], 'QUALITYSHOW_NO_MATCH_IS_NOT_NO_EVIDENCE')
        self.assertTrue(o['coverage']['missing_evidence_not_absence_proof'])

    def test_empty_evidence_partial_no_absence_proof(self):
        o = self.query([])
        self.assertPartial(o)
        self.assertEqual(o['counts']['supplied'], 0)
        self.assertEqual(o['coverage']['not_supplied_classes'], sorted(KINDS))

    def test_remote_proposal_requires_historical_ack(self):
        records = [sample('ci_evidence', scope=PROPOSAL)]
        self.assertDenied(self.query(records, scope=PROPOSAL),
                          'QUALITYSHOW_PROPOSED_PR_HISTORICAL_ACK_REQUIRED')
        o = self.query(records, scope=PROPOSAL, acknowledge_historical_proposal=True)
        self.assertPartial(o)
        self.assertTrue(o['scope']['proposed_pr_historical_only'])
        self.assertTrue(o['coverage']['source_mode_historical_proposal_only'])

    def test_filter_by_class_and_time(self):
        rows = [sample('ci_evidence', scope=REMOTE, offset=-10),
                sample('sha_binding', scope=REMOTE, offset=-5)]
        out = self.query(rows, scope=REMOTE,
                         filters={'classification':'pass','from_utc':at(-12),'until_utc':at(0)})
        self.assertPartial(out)
        self.assertEqual(out['counts']['matched'], 1)
        self.assertEqual(out['entries'][0]['kind'], 'ci_evidence')

    def test_untrusted_new_unsupported_kind_denied(self):
        row = sample('config')
        row['kind'] = 'report'
        self.assertDenied(self.query([row]))

    def test_remote_scope_sha_forged_denied(self):
        row = sample('ci_evidence', scope=REMOTE)
        row['result']['scope']['commit_sha'] = SHA2
        row['result']['evidence_sha256'] = cie.digest({
            k:row['result'][k] for k in ('scope','test_evidence','report_evidence',
                                         'classification','coverage','permission')})
        self.assertDenied(self.query([row], scope=REMOTE),
                          'QUALITYSHOW_EVIDENCE_REMOTE_SCOPE_MISMATCH')

    def test_digest_mutation_denied(self):
        row = sample('config')
        row['result']['coverage']['selected_paths'] += 1
        self.assertDenied(self.query([row]), 'QUALITYSHOW_PRODUCER_DIGEST_MISMATCH')

    def test_forged_ci_verified_flag_denied_even_valid_checksum(self):
        row = sample('ci_metadata', scope=REMOTE)
        row['result']['coverage']['git_sha_binding_verified'] = True
        row['result']['observation_sha256'] = ci._hash({
            k:row['result'][k] for k in ('source','observation','permission','coverage')})
        self.assertDenied(self.query([row], scope=REMOTE),
                          'QUALITYSHOW_UNSUPPORTED_VERIFIED_PROOF_FLAG')

    def test_cross_scope_batch_fails_closed_all_entries(self):
        records = [sample('config'), sample('config', scope={**LOCAL,'root_pin_sha256':PIN2})]
        o = self.query(records)
        self.assertDenied(o, 'QUALITYSHOW_CROSS_SCOPE_EVIDENCE_FORBIDDEN')

    def test_exact_evidence_grant_denied_no_partial_rows(self):
        records = [sample('config'), sample('run_session')]
        def deny_session(facts): return facts['kind'] != 'run_session'
        o = self.svc.query(source_scope=LOCAL, evidence=records, allow_query=True,
                           allow_evidence_read=True, authorize_scope=self.scope_grant,
                           authorize_evidence=deny_session)
        self.assertDenied(o, 'QUALITYSHOW_EVIDENCE_ITEM_NOT_AUTHORIZED')

    def test_missing_source_grants_denied(self):
        o = self.svc.query(source_scope=LOCAL, evidence=[sample('config')],
                           allow_query=True, allow_evidence_read=True,
                           authorize_evidence=self.item_grant)
        self.assertDenied(o, 'QUALITYSHOW_SCOPE_READ_NOT_AUTHORIZED')

    def test_explicit_optins_required(self):
        o = self.svc.query(source_scope=LOCAL, evidence=[sample('config')],
                           authorize_scope=self.scope_grant, authorize_evidence=self.item_grant)
        self.assertDenied(o, 'QUALITYSHOW_QUERY_AND_EVIDENCE_GRANTS_REQUIRED')

    def test_final_scope_revocation_fails_closed(self):
        o = self.svc.query(source_scope=LOCAL, evidence=[sample('config')],
                           allow_query=True, allow_evidence_read=True,
                           authorize_scope=lambda f: f['phase'] != 'FINALIZE',
                           authorize_evidence=self.item_grant)
        self.assertDenied(o, 'QUALITYSHOW_FINAL_SCOPE_PERMISSION_REVOKED')

    def test_callback_mutates_receipt_denied(self):
        rows = [sample('config')]
        def mutate(_facts):
            rows[0]['result']['files'].append({'path':'injected'})
            return True
        o = self.svc.query(source_scope=LOCAL, evidence=rows,
                           allow_query=True, allow_evidence_read=True,
                           authorize_scope=self.scope_grant, authorize_evidence=mutate)
        self.assertDenied(o, 'QUALITYSHOW_SOURCE_OR_RECEIPT_MUTATED_DURING_AUTHORIZATION')

    def test_callback_mutates_scope_denied(self):
        scope = dict(LOCAL)
        def change(f):
            if f['phase'] == 'FINALIZE':
                scope['root_pin_sha256'] = PIN2
            return True
        o = self.svc.query(source_scope=scope, evidence=[sample('config')],
                           allow_query=True, allow_evidence_read=True,
                           authorize_scope=change, authorize_evidence=self.item_grant)
        self.assertDenied(o, 'QUALITYSHOW_SOURCE_OR_RECEIPT_MUTATED_DURING_AUTHORIZATION')

    def test_query_sort_stable_and_cursor_second_page(self):
        records = [sample('config', offset=-20), sample('run_preflight', offset=-10),
                   sample('run_session', offset=-30)]
        first = self.query(records, page_size=1)
        self.assertPartial(first)
        self.assertEqual(first['entries'][0]['kind'], 'run_preflight')
        self.assertTrue(first['next_cursor'])
        second = self.query(records, page_size=1, cursor=first['next_cursor'])
        self.assertPartial(second)
        self.assertEqual(second['entries'][0]['kind'], 'config')
        third = self.query(records, page_size=1, cursor=second['next_cursor'])
        self.assertPartial(third)
        self.assertEqual(third['entries'][0]['kind'], 'run_session')
        self.assertIsNone(third['next_cursor'])
        self.assertEqual(len({x['evidence_id'] for x in
                              first['entries']+second['entries']+third['entries']}), 3)

    def test_cursor_tamper_denied(self):
        records = [sample('config'), sample('run_preflight')]
        first = self.query(records, page_size=1)
        token = first['next_cursor']
        last = '0' if token[-1] != '0' else '1'
        self.assertDenied(self.query(records, page_size=1,cursor=token[:-1]+last),
                          'QUALITYSHOW_CURSOR_MAC_INVALID')

    def test_cursor_replay_other_scope_denied(self):
        records = [sample('config'), sample('run_preflight')]
        cursor = self.query(records, page_size=1)['next_cursor']
        changed = [sample('config',scope={**LOCAL,'root_pin_sha256':PIN2}),
                   sample('run_preflight',scope={**LOCAL,'root_pin_sha256':PIN2})]
        self.assertDenied(self.query(changed, scope={**LOCAL,'root_pin_sha256':PIN2},
                                     page_size=1,cursor=cursor),
                          'QUALITYSHOW_CURSOR_SCOPE_FILTER_OR_SNAPSHOT_CHANGED')

    def test_cursor_changed_filters_denied(self):
        records = [sample('config'), sample('run_preflight')]
        cursor = self.query(records,page_size=1)['next_cursor']
        self.assertDenied(self.query(records,page_size=1,cursor=cursor,
                                     filters={'kinds':['config']}),
                          'QUALITYSHOW_CURSOR_SCOPE_FILTER_OR_SNAPSHOT_CHANGED')

    def test_cursor_record_added_invalidates_revision(self):
        records = [sample('config'), sample('run_preflight')]
        cursor = self.query(records,page_size=1)['next_cursor']
        extended = records+[sample('run_session')]
        self.assertDenied(self.query(extended,page_size=1,cursor=cursor),
                          'QUALITYSHOW_CURSOR_SCOPE_FILTER_OR_SNAPSHOT_CHANGED')

    def test_cursor_evidence_modified_invalidates_revision(self):
        records = [sample('config'), sample('run_preflight')]
        cursor = self.query(records,page_size=1)['next_cursor']
        changed = copy.deepcopy(records)
        changed[0]['recorded_at_utc']=at(-3)
        self.assertDenied(self.query(changed,page_size=1,cursor=cursor),
                          'QUALITYSHOW_CURSOR_SCOPE_FILTER_OR_SNAPSHOT_CHANGED')

    def test_cursor_expiry_denied(self):
        records = [sample('config'),sample('run_preflight')]
        token = self.query(records,page_size=1)['next_cursor']
        svc = QualityShow(cursor_key=KEY,
                          clock=lambda: NOW+timedelta(seconds=301))
        o = svc.query(source_scope=LOCAL, evidence=records, allow_query=True,
                      allow_evidence_read=True, authorize_scope=self.scope_grant,
                      authorize_evidence=self.item_grant, page_size=1,cursor=token)
        self.assertDenied(o, 'QUALITYSHOW_CURSOR_EXPIRED_OR_CLOCK_REGRESSED')

    def test_cursor_key_rotation_denied(self):
        records = [sample('config'),sample('run_preflight')]
        token = self.query(records,page_size=1)['next_cursor']
        svc = QualityShow(cursor_key=b'y'*32, clock=self.clock)
        o = svc.query(source_scope=LOCAL, evidence=records, allow_query=True,
                      allow_evidence_read=True, authorize_scope=self.scope_grant,
                      authorize_evidence=self.item_grant, page_size=1,cursor=token)
        self.assertDenied(o, 'QUALITYSHOW_CURSOR_MAC_INVALID')

    def test_cursor_changed_page_size_denied(self):
        records = [sample('config'),sample('run_preflight'),sample('run_session')]
        token = self.query(records,page_size=1)['next_cursor']
        self.assertDenied(self.query(records,page_size=2,cursor=token),
                          'QUALITYSHOW_CURSOR_SCOPE_FILTER_OR_SNAPSHOT_CHANGED')

    def test_cursor_does_not_bypass_reauthorization(self):
        records = [sample('config'), sample('run_preflight')]
        token = self.query(records,page_size=1)['next_cursor']
        o = self.svc.query(source_scope=LOCAL, evidence=records,
                           allow_query=True, allow_evidence_read=True,
                           authorize_scope=lambda _: False,
                           authorize_evidence=self.item_grant,
                           page_size=1, cursor=token)
        self.assertDenied(o, 'QUALITYSHOW_SCOPE_READ_NOT_AUTHORIZED')

    def test_class_count_coverage_without_unsupported_pass(self):
        local_records = [sample('config'), sample('observation'),
                         sample('run_preflight'), sample('run_session')]
        out = self.query(local_records)
        self.assertPartial(out)
        self.assertEqual(out['counts']['supplied'], 4)
        self.assertEqual(out['coverage']['ci_pass_claim_count_not_verified'], 0)
        self.assertEqual(out['scope']['commit_sha_claim'], None)

    def test_duplicate_receipt_rejected(self):
        row = sample('config')
        self.assertDenied(self.query([row,copy.deepcopy(row)]),
                          'QUALITYSHOW_DUPLICATED_EVIDENCE_RECORD')

    def test_large_source_item_and_limits(self):
        records = [sample('config')]*97
        self.assertDenied(self.query(records), 'QUALITYSHOW_EVIDENCE_LIST_LIMIT_INVALID')
        self.assertDenied(self.query([],page_size=0), 'QUALITYSHOW_PAGE_SIZE_INVALID')
        self.assertDenied(self.query([],page_size=True), 'QUALITYSHOW_PAGE_SIZE_INVALID')

    def test_noncanonical_time_denied(self):
        row = sample('config')
        row['recorded_at_utc'] = '2026-10-23T05:00:00+00:00'
        self.assertDenied(self.query([row]), 'QUALITYSHOW_UTC_SECOND_TIMESTAMP_REQUIRED')

    def test_capture_in_future_denied(self):
        row = sample('config', offset=11)
        self.assertDenied(self.query([row]), 'QUALITYSHOW_FUTURE_CAPTURE_TIMESTAMP')

    def test_malformed_nested_data_fails_no_leak(self):
        row = sample('ci_evidence',scope=REMOTE)
        row['result']['test_evidence']['counts'] = object()
        self.assertDenied(self.query([row],scope=REMOTE))

    def test_snapshot_cannot_be_claimed_complete(self):
        o = self.query([sample('config')])
        self.assertPartial(o)
        self.assertFalse(o['coverage']['supplied_evidence_exhaustive'])
        self.assertFalse(o['coverage']['source_currentness_proven'])
        self.assertFalse(o['coverage']['cross_source_mode_quality_equivalence_proven'])

    def test_actual_ec184_ec185_mock_adapters_both_project_as_claims(self):
        # These are the producers' real implementations, with their OWN offline
        # synthetic GH transport; not hand-written EC188 mock receipt shapes.
        from test_quality_ci_evidence import harness, GH
        from test_quality_observation import Context
        source = {'source_mode': 'DeliveredTarget', 'provider': GH.provider,
                  'repository': GH.repository, 'project_id': GH.project_id,
                  'commit_sha': GH.commit_sha, 'proposal_number': None}
        ctx = Context()
        self.addCleanup(ctx.close)
        observed = ctx.collect()
        parsed, *_ = harness()
        self.assertEqual(observed['status'], 'partial')
        self.assertEqual(parsed['status'], 'partial')
        items = [dict(kind=k, result=v, source_scope=copy.deepcopy(source),
                      recorded_at_utc=at(-i))
                 for i, (k, v) in enumerate((('observation', observed),
                                              ('ci_evidence', parsed)))]
        displayed = self.query(items, scope=source)
        self.assertPartial(displayed)
        self.assertEqual({x['kind'] for x in displayed['entries']},
                         {'observation', 'ci_evidence'})
        self.assertTrue(all(x['classification'] == 'pass' for x in displayed['entries']))
        self.assertEqual(displayed['coverage']['ci_pass_claim_count_not_verified'], 2)
        self.assertNotIn('ci-secret', json.dumps(displayed))
        self.assertNotIn('source-secret', json.dumps(displayed))
        self.assertFalse(displayed['proof']['tested_execution_confirmed'])

    def test_actual_ec182_provider_run_success_kept_as_claim(self):
        from test_quality_read_ci import scenario, GH
        receipt, *_ = scenario(GH)
        self.assertEqual(receipt['status'], 'partial')
        scope = {'source_mode': 'DeliveredTarget', 'provider': GH.provider,
                 'repository': GH.repository, 'project_id': GH.project_id,
                 'commit_sha': GH.commit_sha, 'proposal_number': None}
        record = dict(kind='ci_metadata', result=receipt, source_scope=scope,
                      recorded_at_utc=at(-1))
        displayed = self.query([record], scope=scope)
        self.assertPartial(displayed)
        ci = displayed['entries'][0]
        self.assertEqual(ci['summary']['provider_run_conclusion'], 'success')
        self.assertEqual(ci['summary']['provider_job_conclusion'], 'success')
        self.assertEqual(ci['classification'], 'not_applicable')
        self.assertFalse(ci['summary']['quality_pass_verified'])
        self.assertFalse(displayed['proof']['tested_execution_confirmed'])

    def test_actual_ec181_ec185_local_producer_source_and_microseconds(self):
        # EC181 obtains a real *local temporary-directory* pin; EC185 consumes
        # that source, preserving microsecond timestamps for actual producers.
        from test_quality_observation import Context
        ctx = Context(local=True, remote=False)
        self.addCleanup(ctx.close)
        r = ctx.collect()
        self.assertEqual(r['status'], 'partial')
        real_pin = r['source']['local']['pin_digest']
        source = {'source_mode': 'WorkingTree', 'root_pin_sha256': real_pin}
        record = {'kind': 'observation', 'result': r,
                  'source_scope': source, 'recorded_at_utc': at(-1)}
        displayed = self.query([record], scope=source)
        self.assertPartial(displayed)
        self.assertEqual(displayed['entries'][0]['summary']['observation_track'],
                         'LOCAL_ONLY_EXTRACTED')

    def test_actual_ec183_github_sha_binding_stays_provider_claim(self):
        from test_quality_sha_bind import run, GH
        receipt, *_ = run(GH)
        self.assertEqual(receipt['status'], 'partial')
        scope = {'source_mode': 'DeliveredTarget', 'provider': GH.provider,
                 'repository': GH.repository, 'project_id': GH.project_id,
                 'commit_sha': GH.commit_sha, 'proposal_number': None}
        displayed = self.query([dict(kind='sha_binding', result=receipt,
                                     source_scope=scope, recorded_at_utc=at(-1))],
                               scope=scope)
        self.assertPartial(displayed)
        self.assertEqual(displayed['entries'][0]['summary']['association'],
                         'PROVIDER_FIELD_CLAIM_SHA_EQUAL')
        self.assertFalse(displayed['proof']['authenticated_source_snapshot'])

    def test_actual_ec186_preflight_is_still_nonexecutable(self):
        from test_quality_run_guard import SafetyGateTests
        SafetyGateTests.setUpClass()
        upstream = SafetyGateTests('test_01_valid_gated_plan_remains_partial_not_executable')
        upstream.setUp()
        self.addCleanup(upstream.doCleanups)
        original = upstream.run_gate()
        self.assertEqual(original['status'], 'partial')
        scope = {'source_mode': 'WorkingTree',
                 'root_pin_sha256': upstream.sdigest}
        result = self.query([dict(kind='run_preflight', result=original,
                                  source_scope=scope, recorded_at_utc=at(-1))],
                            scope=scope)
        self.assertPartial(result)
        self.assertEqual(result['entries'][0]['summary']['execution_state'],
                         'NOT_EXECUTED_PREFLIGHT_ONLY')
        self.assertFalse(result['proof']['tested_execution_confirmed'])

    def test_actual_ec187_host_exit_zero_still_not_quality_pass(self):
        from test_quality_run_budget import BudgetTests
        BudgetTests.setUpClass()
        upstream = BudgetTests('test_01_zero_exit_remains_partial_unverified')
        upstream.setUp()
        self.addCleanup(upstream.doCleanups)
        original = upstream.do()
        self.assertEqual(original['status'], 'partial')
        scope = {'source_mode': 'WorkingTree',
                 'root_pin_sha256': upstream.sdigest}
        result = self.query([dict(kind='run_session', result=original,
                                  source_scope=scope, recorded_at_utc=at(-1))],
                            scope=scope)
        self.assertPartial(result)
        row = result['entries'][0]
        self.assertEqual(row['binding_strength'],
                         'CALLER_LINKED_NO_SOURCE_PIN_IN_EC187_RESULT')
        self.assertEqual(row['summary']['host_reported_exit_code'], 0)
        self.assertTrue(row['summary']['host_reported_exit_zero_is_not_pass'])
        self.assertFalse(result['proof']['verified_quality_pass'])

    def test_actual_ec187_cancel_before_begin_has_no_session(self):
        from test_quality_run_budget import BudgetTests
        BudgetTests.setUpClass()
        upstream = BudgetTests('test_04_pre_cancel_no_broker_begin')
        upstream.setUp()
        self.addCleanup(upstream.doCleanups)
        upstream.cancel_callback = lambda: True
        original = upstream.do()
        self.assertEqual(original['reason_code'],
                         'QUALITYRUNBUDGET_CANCELLED_BEFORE_START')
        scope = {'source_mode': 'WorkingTree',
                 'root_pin_sha256': upstream.sdigest}
        record = dict(kind='run_session', result=original,
                      source_scope=scope, recorded_at_utc=at(-1))
        result = self.query([record], scope=scope)
        self.assertPartial(result)
        self.assertEqual(result['entries'][0]['classification'], 'not_run')
        self.assertEqual(result['entries'][0]['summary']['execution_state'],
                         'NOT_STARTED_CANCELLED_BEFORE_BROKER')
        self.assertIn('NO_EC187_EXTERNAL_SESSION_STARTED',
                      result['entries'][0]['incompleteness'])
        self.assertFalse(result['proof']['tested_execution_confirmed'])
        forged = copy.deepcopy(record)
        forged['result']['effects']['external_broker_begin_called'] = True
        self.assertDenied(self.query([forged], scope=scope),
                          'QUALITYSHOW_NO_RUN_SESSION_EVIDENCE')

    def test_full_schema_accepts_all_seven_evidence_classes(self):
        local = self.query([sample(k) for k in
                            ('config', 'observation', 'run_preflight', 'run_session')])
        remote = self.query([sample(k, scope=REMOTE) for k in
                            ('ci_metadata', 'sha_binding', 'ci_evidence', 'observation')],
                            scope=REMOTE)
        self.assertPartial(local)
        self.assertPartial(remote)
        for output in (local, remote):
            self.validator.validate(output)
        self.assertEqual(local['counts']['supplied'], 4)
        self.assertEqual(remote['counts']['supplied'], 4)


if __name__ == '__main__':
    unittest.main()
