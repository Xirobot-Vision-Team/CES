#!/usr/bin/env python3
"""EC182 focused synthetic development scenarios, NEVER live CI evidence."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import unittest

import quality_read_ci as qc

NOW = datetime(2026, 10, 22, 20, 0, tzinfo=timezone.utc)
SHA = 'a' * 40
GH = qc.CISelection('github', 'acme/widget', 731, 991, 2300, 2,
                     350, 'main', SHA, 3600)
GL = qc.CISelection('gitlab', 'acme/widget', 731, None, 2300, None,
                     350, 'main', SHA, 3600)


def gh_run():
    return {'id': 2300, 'workflow_id': 991, 'run_attempt': 2,
            'repository': {'id': 731, 'full_name': 'acme/widget'},
            'head_branch': 'main', 'head_sha': SHA,
            'status': 'completed', 'conclusion': 'success',
            'created_at': '2026-10-22T19:45:00Z',
            'updated_at': '2026-10-22T19:58:00Z'}


def gh_job(id=350):
    return {'id': id, 'run_id': 2300, 'head_sha': SHA, 'head_branch': 'main',
            'status': 'completed', 'conclusion': 'success',
            'started_at': '2026-10-22T19:48:00Z',
            'completed_at': '2026-10-22T19:55:00Z'}


def gl_project():
    return {'id': 731, 'path_with_namespace': 'acme/widget'}


def gl_run():
    return {'id': 2300, 'project_id': 731, 'ref': 'main', 'sha': SHA,
            'status': 'success', 'created_at': '2026-10-22T19:45:00.000Z',
            'updated_at': '2026-10-22T19:58:00.000Z'}


def gl_job():
    return {'id': 350, 'pipeline': {'id': 2300, 'project_id': 731},
            'ref': 'main', 'commit': {'id': SHA},
            'status': 'success', 'allow_failure': False,
            'started_at': '2026-10-22T19:48:00.000Z',
            'finished_at': '2026-10-22T19:55:00.000Z',
            'archived': False, 'erased_at': None}


class FakeTransport:
    """Tests only: successful mocks can NEVER become LIVE_HTTPS source."""
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, headers, timeout):
        self.calls.append((url, headers, timeout))
        if not self.responses:
            raise AssertionError('unexpected extra request')
        v = self.responses.pop(0)
        if isinstance(v, Exception):
            raise v
        return deepcopy(v)


def scenario(key=GH, responses=None, grant=None, token='test-opaque',
             network=True, metadata=True):
    if responses is None:
        responses = ([gh_run(), {'total_count': 1, 'jobs': [gh_job()]}, gh_run()]
                     if key.provider == 'github' else
                     [gl_project(), gl_run(), gl_job(), gl_run()])
    fake = FakeTransport(responses)
    reader = qc.QualityCIReader(fake, clock=lambda: NOW)
    log = []

    def allowed(facts):
        log.append(facts.copy())
        return True if grant is None else grant(facts)

    result = reader.read(key, credential=token, allow_network=network,
                         allow_ci_metadata=metadata, authorize=allowed)
    return result, fake, log


class QualityReadCITests(unittest.TestCase):
    def ok(self, result):
        self.assertEqual((result['status'], result['exit_code'],
                          result['reason_code']),
                         ('partial', 2, 'QUALITYREADCI_CI_METADATA_OBSERVED'))
        self.assertFalse(result['effects']['writes_performed'])
        self.assertFalse(result['coverage']['git_sha_binding_verified'])
        self.assertFalse(result['coverage']['test_execution_by_ces'])
        self.assertEqual(result['permission']['transport'], 'SYNTHETIC')
        self.assertEqual(result['permission']['provider_read'], 'NOT_PROVEN_SYNTHETIC')
        self.assertRegex(result['observation_sha256'], r'^[0-9a-f]{64}$')
        self.assertNotIn('test-opaque', json.dumps(result))

    def denied(self, result, code, status='unavailable'):
        self.assertEqual((result['status'], result['exit_code'], result['reason_code']),
                         (status, qc.EXIT[status], 'QUALITYREADCI_' + code))
        self.assertIsNone(result['source'])
        self.assertIsNone(result['observation'])
        self.assertIsNone(result['coverage'])
        self.assertIsNone(result['observation_sha256'])

    def test_github_observed_without_completeness_promotion(self):
        r, fake, grants = scenario()
        self.ok(r)
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual([g['read_kind'] for g in grants],
                         ['RUN', 'ATTEMPT_JOBS', 'RUN_RECHECK', 'FINALIZE_OBSERVATION'])
        self.assertTrue(fake.calls[1][0].endswith('/attempts/2/jobs?per_page=100&page=1'))
        self.assertEqual(r['source']['workflow_id'], 991)
        self.assertEqual(r['source']['run_id'], 2300)
        self.assertEqual(r['source']['job_id'], 350)
        self.assertEqual(r['observation']['job']['conclusion'], 'success')
        self.assertFalse(r['coverage']['cross_request_atomic_snapshot'])

    def test_gitlab_complete_single_job_read(self):
        r, fake, grants = scenario(GL)
        self.ok(r)
        self.assertEqual(len(fake.calls), 4)
        self.assertEqual([g['read_kind'] for g in grants],
                         ['PROJECT', 'PIPELINE', 'JOB', 'PIPELINE_RECHECK', 'FINALIZE_OBSERVATION'])
        self.assertEqual(r['observation']['run']['state'], 'success')
        self.assertIsNone(r['source']['attempt'])
        self.assertFalse(r['coverage']['attempt_bound'])
        self.assertTrue(fake.calls[0][0].endswith('/projects/731'))

    def test_read_optins_are_independently_required(self):
        for network, metadata in [(False, False), (False, True), (True, False)]:
            r, fake, _ = scenario(network=network, metadata=metadata)
            self.denied(r, 'EXPLICIT_READ_OPTIN_REQUIRED', 'invalid_input')
            self.assertEqual(fake.calls, [])

    def test_credential_required_before_callback_or_network(self):
        for token in (None, '', 'x\ncredential', ' '*30, 'x'*4097):
            r, fake, grants = scenario(token=token)
            self.denied(r, 'CREDENTIAL_MISSING_OR_INVALID', 'invalid_input')
            self.assertFalse(fake.calls or grants)

    def test_callback_missing(self):
        fake = FakeTransport([])
        r = qc.QualityCIReader(fake, clock=lambda: NOW).read(
            GH, credential='token', allow_network=True,
            allow_ci_metadata=True, authorize=None)
        self.denied(r, 'INDEPENDENT_SCOPE_GRANT_MISSING', 'invalid_input')
        self.assertFalse(fake.calls)

    def test_permission_refused_at_any_endpoint_discards_all(self):
        for deny_kind in ('RUN', 'ATTEMPT_JOBS', 'RUN_RECHECK', 'FINALIZE_OBSERVATION'):
            r, fake, logs = scenario(grant=lambda x: x['read_kind'] != deny_kind)
            self.denied(r, 'SCOPE_PERMISSION_DENIED')
            self.assertLessEqual(len(fake.calls), 3)
            self.assertEqual(logs[-1]['read_kind'], deny_kind)

    def test_permission_callback_exception_fails_closed(self):
        def denied(_):
            raise RuntimeError('secret failure: never leak')
        r, _, _ = scenario(grant=denied)
        self.denied(r, 'SCOPE_PERMISSION_DENIED')
        self.assertNotIn('secret', json.dumps(r))

    def test_github_project_id_is_mandatory_identity(self):
        run = gh_run()
        run['repository']['id'] = 999
        r, _, _ = scenario(responses=[run])
        self.denied(r, 'REPOSITORY_IDENTITY_MISMATCH')

    def test_github_project_name_is_mandatory_identity(self):
        run = gh_run()
        run['repository']['full_name'] = 'acme/other'
        r, _, _ = scenario(responses=[run])
        self.denied(r, 'REPOSITORY_IDENTITY_MISMATCH')

    def test_github_workflow_id_is_mandatory(self):
        run = gh_run()
        run['workflow_id'] = 993
        r, _, _ = scenario(responses=[run])
        self.denied(r, 'RUN_IDENTITY_MISMATCH')

    def test_github_attempt_pinned_no_fallback(self):
        run = gh_run()
        run['run_attempt'] = 3
        r, _, _ = scenario(responses=[run])
        self.denied(r, 'RUN_IDENTITY_MISMATCH')

    def test_github_sha_branch_mismatch(self):
        for field, code in [('head_sha', 'COMMIT_FIELD_MISMATCH'),
                            ('head_branch', 'BRANCH_FIELD_MISMATCH')]:
            run = gh_run()
            run[field] = 'b'*40 if field == 'head_sha' else 'release'
            r, _, _ = scenario(responses=[run])
            self.denied(r, code)

    def test_github_selected_job_must_be_in_exact_attempt(self):
        r, _, _ = scenario(responses=[gh_run(), {'total_count': 1, 'jobs': [gh_job(351)]}])
        self.denied(r, 'JOB_NOT_IN_SELECTED_ATTEMPT')

    def test_github_job_sha_mismatch(self):
        job = gh_job()
        job['head_sha'] = 'b'*40
        r, _, _ = scenario(responses=[gh_run(), {'total_count': 1, 'jobs': [job]}])
        self.denied(r, 'JOB_RUN_OR_COMMIT_MISMATCH')

    def test_github_job_skipped_is_not_a_pass(self):
        job = gh_job()
        job['conclusion'] = 'skipped'
        r, _, _ = scenario(responses=[gh_run(), {'total_count': 1, 'jobs': [job]}])
        self.denied(r, 'JOB_NOT_FINAL')

    def test_github_run_cancelled_is_unavailable(self):
        run = gh_run()
        run['conclusion'] = 'cancelled'
        r, _, _ = scenario(responses=[run])
        self.denied(r, 'RUN_NOT_FINAL')

    def test_observed_failure_is_not_ces_failure_or_success(self):
        run, job = gh_run(), gh_job()
        run['conclusion'] = 'failure'
        job['conclusion'] = 'failure'
        r, _, _ = scenario(responses=[run, {'total_count': 1, 'jobs': [job]}, run])
        self.ok(r)
        self.assertEqual(r['observation']['run']['conclusion'], 'failure')
        self.assertEqual(r['status'], 'partial')

    def test_recheck_refuses_changed_upstream_run(self):
        newer = gh_run()
        newer['updated_at'] = '2026-10-22T19:59:00Z'
        r, _, _ = scenario(responses=[gh_run(), {'total_count': 1, 'jobs': [gh_job()]}, newer])
        self.denied(r, 'RUN_CHANGED_DURING_READ')

    def test_pages_101_jobs_exact_selection(self):
        first = [gh_job(x) for x in range(1000,1100)]
        r, fake, _ = scenario(responses=[gh_run(), {'total_count': 101, 'jobs': first},
                                         {'total_count': 101, 'jobs': [gh_job()]}, gh_run()])
        self.ok(r)
        self.assertEqual(len(fake.calls), 4)
        self.assertTrue(fake.calls[2][0].endswith('&page=2'))

    def test_pages_truncation_rejected(self):
        r, _, _ = scenario(responses=[gh_run(), {'total_count': 2, 'jobs': [gh_job()] }])
        self.denied(r, 'JOBS_PAGE_INCOMPLETE_OR_AMBIGUOUS')

    def test_pages_over_300_rejected_without_second_page(self):
        r, fake, _ = scenario(responses=[gh_run(), {'total_count': 301, 'jobs': [gh_job()] }])
        self.denied(r, 'JOBS_PAGE_INCOMPLETE_OR_AMBIGUOUS')
        self.assertEqual(len(fake.calls), 2)

    def test_duplicate_jobs_rejected(self):
        r, _, _ = scenario(responses=[gh_run(), {'total_count': 2, 'jobs': [gh_job(), gh_job()]}])
        self.denied(r, 'JOBS_PAGE_INCOMPLETE_OR_AMBIGUOUS')

    def test_gl_project_mismatch(self):
        p = gl_project()
        p['path_with_namespace'] = 'other/widget'
        r, _, _ = scenario(GL, [p])
        self.denied(r, 'REPOSITORY_IDENTITY_MISMATCH')

    def test_gl_pipeline_project_sha_branch_and_id(self):
        for field, altered, code in [('id', 2301, 'RUN_IDENTITY_MISMATCH'),
                                     ('project_id', 732, 'RUN_IDENTITY_MISMATCH'),
                                     ('ref', 'other', 'BRANCH_FIELD_MISMATCH'),
                                     ('sha', 'b'*40, 'COMMIT_FIELD_MISMATCH')]:
            run = gl_run()
            run[field] = altered
            r, _, _ = scenario(GL, [gl_project(), run])
            self.denied(r, code)

    def test_gl_job_pipeline_identity_and_commit(self):
        for name, v, reason in [('id', 99, 'JOB_RUN_OR_PROJECT_MISMATCH'),
                                ('project_id', 99, 'JOB_RUN_OR_PROJECT_MISMATCH')]:
            job = gl_job()
            job['pipeline'][name] = v
            r, _, _ = scenario(GL, [gl_project(), gl_run(), job])
            self.denied(r, reason)
        job = gl_job()
        job['commit']['id'] = 'b'*40
        r, _, _ = scenario(GL, [gl_project(), gl_run(), job])
        self.denied(r, 'JOB_RUN_OR_COMMIT_MISMATCH')

    def test_gl_job_allow_failure_not_used_as_verdict(self):
        job = gl_job()
        job['status'] = 'failed'
        job['allow_failure'] = True
        r, _, _ = scenario(GL, [gl_project(), gl_run(), job, gl_run()])
        self.ok(r)
        self.assertTrue(r['observation']['job']['allow_failure'])
        self.assertEqual(r['observation']['job']['conclusion'], 'failure')
        self.assertEqual(r['observation']['run']['conclusion'], 'success')

    def test_gl_cancelled_pipeline_refusal(self):
        run = gl_run()
        run['status'] = 'canceled'
        r, _, _ = scenario(GL, [gl_project(), run])
        self.denied(r, 'RUN_NOT_FINAL')

    def test_gl_erased_job_refusal(self):
        job = gl_job()
        job['erased_at'] = '2026-10-22T19:58:00.000Z'
        r, _, _ = scenario(GL, [gl_project(), gl_run(), job])
        self.denied(r, 'JOB_ARCHIVED_OR_ERASED')

    def test_old_result_refused_without_normalizing_success(self):
        older = gh_run()
        older['created_at'] = '2026-10-20T19:45:00Z'
        older['updated_at'] = '2026-10-20T19:58:00Z'
        r, _, _ = scenario(responses=[older])
        self.denied(r, 'STALE_CI_RESULT')

    def test_future_timestamp_refused(self):
        run = gh_run()
        run['updated_at'] = '2026-10-23T19:58:00Z'
        r, _, _ = scenario(responses=[run])
        self.denied(r, 'FUTURE_PROVIDER_TIMESTAMP')

    def test_timestamp_corruption_refused(self):
        run = gh_run()
        run['updated_at'] = 'today'
        r, _, _ = scenario(responses=[run])
        self.denied(r, 'PROVIDER_TIMESTAMP_INVALID')

    def test_unknown_field_types_refused(self):
        run = gh_run()
        run['id'] = True
        r, _, _ = scenario(responses=[run])
        self.denied(r, 'RUN_IDENTITY_MISMATCH')

    def test_transport_exception_never_leaks(self):
        r, _, _ = scenario(responses=[RuntimeError('INTERNAL SECRET TOKEN')])
        self.denied(r, 'TRANSPORT_FAILED')
        self.assertNotIn('SECRET', json.dumps(r))

    def test_selection_rejects_malformed_and_unsupported(self):
        bad = [qc.CISelection('github', '../widget', 731, 991, 2300, 2, 350,
                              'main', SHA, 3600),
               qc.CISelection('gitlab', 'acme/widget', 731, 991, 2300, None, 350,
                              'main', SHA, 3600),
               qc.CISelection('github', 'acme/widget', 731, None, 2300, 2, 350,
                              'main', SHA, 3600),
               qc.CISelection('github', 'acme/widget', 731, 991, 2300, 2, 350,
                              '../main', SHA, 3600),
               qc.CISelection('github', 'acme/widget', 731, 991, 2300, 2, 350,
                              'main', '0'*40, 3600),
               qc.CISelection('github', 'acme/widget', 731, 991, 2300, 2, 350,
                              'main', SHA, 20)]
        for b in bad:
            r, fake, log = scenario(b)
            self.assertEqual(r['status'], 'invalid_input')
            self.assertFalse(fake.calls or log)

    def test_strict_json_duplicate_nonfinite_and_array_rejected(self):
        for raw in [b'{"a":1,"a":2}', b'{"x":NaN}', b'[]', b'\xff']:
            with self.assertRaises(qc.CIError):
                qc._json_object(raw)

    def test_transport_forbids_external_hosts_mutating_routes_and_redirects(self):
        transport = qc.StrictHTTPSCITransport()
        for url in ['https://evil.example/repos/o/r',
                    'http://api.github.com/repos/o/r/actions/runs/1',
                    'https://api.github.com.evil.net/repos/o/r',
                    'https://api.github.com/repos/o/r/actions/jobs/1/logs#fragment',
                    'https://api.github.com/repos/o/r/actions/runs/1?per_page=200&page=1']:
            with self.assertRaises(qc.CIError):
                transport.get(url, {}, 8.0)

    def test_mocked_transport_cannot_claim_live_authenticated_ci(self):
        r, _, _ = scenario()
        self.ok(r)
        self.assertNotEqual(r['permission']['provider_read'], 'HTTPS_200_TOKEN_PRESENT')

    def test_cli_denies_network_by_default_and_prints_single_json(self):
        script = Path(__file__).with_name('quality_read_ci.py')
        p = subprocess.run([sys.executable, str(script), '--provider', 'github',
                            '--repository', 'acme/widget', '--project-id', '731',
                            '--workflow-id', '991', '--run-id', '2300', '--attempt', '2',
                            '--job-id', '350', '--branch', 'main', '--commit-sha', SHA,
                            '--max-result-age-seconds', '3600'],
                           capture_output=True, text=True, timeout=5)
        self.assertEqual(p.returncode, 4)
        result = json.loads(p.stdout)
        self.denied(result, 'EXPLICIT_READ_OPTIN_REQUIRED', 'invalid_input')
        self.assertEqual(result['effects']['live_network_get_requests'], 0)

    def test_draft202012_response_schema_real_shape_and_negative_claims(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest('jsonschema optional developer tool unavailable')
        schema = json.loads((Path(__file__).parent.parent /
                             'references/quality-read-ci-result.v1.schema.json').read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        for r in (scenario()[0], scenario(GL)[0], scenario(network=False)[0]):
            self.assertFalse(list(validator.iter_errors(r)))
        fake_positive = scenario()[0]
        for key, value in [('status','success'),('exit_code',0)]:
            cloned = deepcopy(fake_positive)
            cloned[key] = value
            self.assertTrue(list(validator.iter_errors(cloned)))
        cloned = deepcopy(fake_positive)
        cloned['coverage']['test_execution_by_ces'] = True
        self.assertTrue(list(validator.iter_errors(cloned)))

    def test_synthetic_live_provenance_spoof_rejected_by_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest('jsonschema optional developer tool unavailable')
        schema = json.loads((Path(__file__).parent.parent /
                             'references/quality-read-ci-result.v1.schema.json').read_text())
        validator = jsonschema.Draft202012Validator(schema)
        value = scenario()[0]
        value['permission']['provider_read'] = 'HTTPS_200_TOKEN_PRESENT'
        self.assertTrue(list(validator.iter_errors(value)))
        value['permission']['transport'] = 'LIVE_HTTPS'
        value['effects']['live_network_get_requests'] = 0
        self.assertTrue(list(validator.iter_errors(value)))


if __name__ == '__main__':
    unittest.main()
