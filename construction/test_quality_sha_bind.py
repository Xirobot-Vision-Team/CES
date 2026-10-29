#!/usr/bin/env python3
"""EC183 synthetic GH/GL source + CI scenarios; never live evidence."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys
import unittest

import quality_read_ci as qc
import quality_sha_bind as qb
import test_quality_read_ci as ci_test

NOW = ci_test.NOW
SHA = ci_test.SHA
GH, GL = ci_test.GH, ci_test.GL
SENTINEL = object()


class Transport:
    def __init__(self, replies):
        self.replies = deepcopy(replies)
        self.calls = []

    def get(self, url, headers, timeout):
        self.calls.append(url)
        if not self.replies:
            raise AssertionError('exceeded planned requests')
        result = self.replies.pop(0)
        if isinstance(result, Exception):
            raise result
        return deepcopy(result)


def replies(provider, pr=False):
    if provider == 'github':
        repo = {'id': 731, 'full_name': 'acme/widget', 'archived': False, 'disabled': False}
        branch = {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': SHA}}
        commit = {'sha': SHA, 'tree': {'sha': 'b'*40}}
        proposal = {'id': 23, 'number': 7, 'state': 'open', 'merged_at': None,
                    'head': {'ref': 'main', 'sha': SHA,
                             'repo': {'id': 731, 'full_name': 'acme/widget'}},
                    'base': {'repo': {'id': 731, 'full_name': 'acme/widget'}}}
    else:
        repo = {'id': 731, 'path_with_namespace': 'acme/widget', 'archived': False,
                'empty_repo': False}
        branch = {'name': 'main', 'commit': {'id': SHA}}
        commit = {'id': SHA}
        proposal = {'id': 23, 'iid': 7, 'state': 'opened', 'project_id': 731,
                    'target_project_id': 731, 'source_project_id': 731,
                    'source_branch': 'main', 'sha': SHA, 'diff_refs': {'head_sha': SHA}}
    if pr:
        return [deepcopy(repo), deepcopy(proposal), deepcopy(branch), deepcopy(commit),
                deepcopy(proposal), deepcopy(branch), deepcopy(repo)]
    return [deepcopy(repo), deepcopy(branch), deepcopy(commit),
            deepcopy(branch), deepcopy(repo)]


def ci_replies(provider):
    return ([ci_test.gh_run(), {'total_count': 1, 'jobs': [ci_test.gh_job()]},
             ci_test.gh_run()] if provider == 'github' else
            [ci_test.gl_project(), ci_test.gl_run(), ci_test.gl_job(), ci_test.gl_run()])


def run(key=GH, *, mode='DeliveredTarget', proposal=SENTINEL, source=SENTINEL,
        new_ci=SENTINEL, receipt=SENTINEL, grant_source=None, grant_ci=None,
        network=True, ci_read=True, source_read=True, receipt_reuse=True,
        token_source='source-key', token_ci='ci-key', dev=True, clock=None):
    if proposal is SENTINEL:
        proposal = 7 if mode == 'ProposedPR' else None
    src = Transport(replies(key.provider, mode == 'ProposedPR') if source is SENTINEL else source)
    fresh = Transport(ci_replies(key.provider) if new_ci is SENTINEL else new_ci)
    if receipt is SENTINEL:
        receipt, _, _ = ci_test.scenario(key)
    sg, cg = [], []

    def source_gate(info):
        sg.append(info)
        return True if grant_source is None else grant_source(info)

    def ci_gate(info):
        cg.append(info)
        return True if grant_ci is None else grant_ci(info)

    reader = qc.QualityCIReader(fresh, clock=clock or (lambda: NOW))
    binder = qb.QualitySHABinder(src, reader, clock=clock or (lambda: NOW))
    result = binder.bind(qb.SourceSelection(key, mode, proposal), ci_receipt=receipt,
                         source_credential=token_source, ci_credential=token_ci,
                         allow_network=network, allow_ci_read=ci_read,
                         allow_receipt_reuse=receipt_reuse, allow_source_read=source_read,
                         authorize_source=source_gate, authorize_ci=ci_gate,
                         allow_synthetic_development=dev)
    return result, src, fresh, sg, cg


class FocusedE183(unittest.TestCase):
    def good(self, output, source, ci):
        self.assertEqual((output['status'], output['exit_code']), ('partial', 2))
        self.assertEqual(output['source']['commit_sha'], SHA)
        self.assertEqual(output['permission']['transport'], 'SYNTHETIC')
        self.assertFalse(output['coverage']['ci_source_sha_associated'])
        self.assertFalse(output['binding']['git_object_bytes_hashed'])
        self.assertFalse(output['effects']['executed_commands'])
        self.assertFalse(output['effects']['writes_performed'])
        self.assertEqual(output['effects']['live_source_get_requests'], 0)
        self.assertEqual(output['effects']['live_ci_get_requests'], 0)
        self.assertEqual(len(source.calls), output['effects']['source_get_calls'])
        self.assertEqual(len(ci.calls), output['effects']['ci_get_calls'])
        self.assertNotIn('source-key', json.dumps(output))

    def bad(self, output, code, status='unavailable'):
        self.assertEqual(output['reason_code'], 'QUALITYSHABIND_' + code)
        self.assertEqual((output['status'], output['exit_code']), (status, qb.EXIT[status]))
        for k in ('source', 'ci_observation', 'binding', 'coverage', 'association_sha256'):
            self.assertIsNone(output[k])

    def test_gh_delivered(self):
        output, source, ci, source_grants, ci_grants = run()
        self.good(output, source, ci)
        self.assertEqual((len(source.calls), len(ci.calls)), (5, 3))
        self.assertEqual(output['source']['source_mode'], 'DeliveredTarget')
        self.assertTrue(source.calls[2].endswith('/git/commits/' + SHA))
        self.assertEqual(source_grants[-1]['read_kind'], 'FINALIZE_SOURCE_BINDING')
        self.assertEqual(ci_grants[-1]['read_kind'], 'FINALIZE_CI_BINDING')

    def test_gl_delivered(self):
        output, source, ci, *_ = run(GL)
        self.good(output, source, ci)
        self.assertEqual((len(source.calls), len(ci.calls)), (5, 4))
        self.assertIn('/projects/731/repository/branches/', source.calls[1])

    def test_gh_open_proposal(self):
        output, source, ci, *_ = run(mode='ProposedPR')
        self.good(output, source, ci)
        self.assertEqual((len(source.calls), len(ci.calls)), (7, 3))
        self.assertEqual(output['source']['proposal_object_id'], 23)
        self.assertTrue(output['coverage']['proposal_rechecked'])

    def test_gl_open_proposal(self):
        output, source, ci, *_ = run(GL, mode='ProposedPR')
        self.good(output, source, ci)
        self.assertEqual((len(source.calls), len(ci.calls)), (7, 4))
        self.assertIn('/merge_requests/7', source.calls[1])

    def test_unimplemented_working_tree_is_not_approximated(self):
        result, s, c, *_ = run(mode='WorkingTree')
        self.bad(result, 'SOURCE_MODE_UNSUPPORTED', 'invalid_input')
        self.assertFalse(s.calls or c.calls)

    def test_all_optins_independent_before_io(self):
        for field in ('network', 'ci_read', 'source_read', 'receipt_reuse'):
            result, s, c, *_ = run(**{field: False})
            self.bad(result, 'INDEPENDENT_OPTINS_REQUIRED', 'invalid_input')
            self.assertFalse(s.calls or c.calls)

    def test_credentials_independent(self):
        for which in ('token_source', 'token_ci'):
            for value in (None, '', 'abc\nsecret', 'x'*4097):
                result, s, c, *_ = run(**{which: value})
                self.bad(result, 'TWO_CREDENTIALS_REQUIRED', 'invalid_input')
                self.assertFalse(s.calls or c.calls)

    def test_proposal_mode_number_contract(self):
        for mode, num, code in [('DeliveredTarget', 7, 'PROPOSAL_FORBIDDEN_FOR_DELIVERED'),
                                ('ProposedPR', 0, 'PROPOSAL_NUMBER_REQUIRED'),
                                ('ProposedPR', True, 'PROPOSAL_NUMBER_REQUIRED')]:
            result, s, c, *_ = run(mode=mode, proposal=num)
            self.bad(result, code, 'invalid_input')
            self.assertFalse(s.calls or c.calls)

    def test_synthetic_cannot_be_misrepresented_as_live(self):
        result, s, c, *_ = run(dev=False)
        self.bad(result, 'SYNTHETIC_DEVELOPMENT_NOT_PERMITTED', 'invalid_input')
        self.assertFalse(s.calls or c.calls)

    def test_unauthorized_or_tampered_receipt(self):
        for receipt in ({}, None, {'schema': qc.SCHEMA}):
            result, s, c, *_ = run(receipt=receipt)
            self.bad(result, 'CI_RECEIPT_INVALID', 'invalid_input')
            self.assertFalse(s.calls or c.calls)

    def test_modified_receipt_digest(self):
        receipt, _, _ = ci_test.scenario(GH)
        receipt['source']['commit_sha'] = 'e'*40
        result, s, c, *_ = run(receipt=receipt)
        self.bad(result, 'CI_RECEIPT_DIGEST_MISMATCH', 'invalid_input')
        self.assertFalse(s.calls or c.calls)

    def test_recomputed_hash_does_not_transfer_authority(self):
        receipt, _, _ = ci_test.scenario(GH)
        receipt['source']['project_id'] = 700
        receipt['observation_sha256'] = qc._hash({k: receipt[k] for k in
            ('source', 'observation', 'permission', 'coverage')})
        result, *_ = run(receipt=receipt)
        self.bad(result, 'CI_RECEIPT_SCOPE_MISMATCH')

    def test_receipt_expiry_prevents_remote_calls(self):
        result, s, c, *_ = run(clock=lambda: NOW + timedelta(minutes=6))
        self.bad(result, 'CI_RECEIPT_STALE')
        self.assertFalse(s.calls or c.calls)

    def test_source_callbacks_gate_each_read_and_finalize(self):
        for kind in ('REPOSITORY_BEFORE', 'BRANCH_BEFORE', 'COMMIT_OBJECT',
                     'BRANCH_AFTER', 'REPOSITORY_AFTER', 'FINALIZE_SOURCE_BINDING'):
            result, s, c, sg, *_ = run(grant_source=lambda x: x['read_kind'] != kind)
            self.bad(result, 'SOURCE_SCOPE_DENIED')
            self.assertEqual(sg[-1]['read_kind'], kind)

    def test_ci_callbacks_gate_each_read_and_finalization(self):
        result, s, c, *_ = run(grant_ci=lambda x: x['read_kind'] != 'RUN')
        self.bad(result, 'FRESH_CI_RECHECK_FAILED')
        self.assertEqual(len(s.calls), 3)
        self.assertFalse(c.calls)
        result, s, c, *rest = run(grant_ci=lambda x: x['read_kind'] != 'FINALIZE_CI_BINDING')
        self.bad(result, 'CI_SCOPE_REVOKED')
        self.assertEqual(len(s.calls), 5)

    def test_repository_numeric_identity_not_name_only(self):
        source = replies('github')
        source[0]['id'] = 999
        result, s, c, *_ = run(source=source)
        self.bad(result, 'SOURCE_REPOSITORY_ID_MISMATCH')
        self.assertEqual(len(s.calls), 1)
        self.assertFalse(c.calls)

    def test_gitlab_project_path_must_match(self):
        source = replies('gitlab')
        source[0]['path_with_namespace'] = 'acme/other'
        result, s, c, *_ = run(GL, source=source)
        self.bad(result, 'SOURCE_REPOSITORY_NAME_MISMATCH')
        self.assertEqual(len(s.calls), 1)

    def test_branch_sha_mismatch_denied_before_ci(self):
        for key in (GH, GL):
            source = replies(key.provider)
            if key.provider == 'github':
                source[1]['object']['sha'] = 'e'*40
            else:
                source[1]['commit']['id'] = 'e'*40
            result, s, c, *_ = run(key, source=source)
            self.bad(result, 'SOURCE_CI_SHA_MISMATCH')
            self.assertEqual(len(s.calls), 2)
            self.assertFalse(c.calls)

    def test_commit_oid_mismatch_denied(self):
        for key in (GH, GL):
            source = replies(key.provider)
            source[2]['sha' if key.provider == 'github' else 'id'] = 'e'*40
            result, s, c, *_ = run(key, source=source)
            self.bad(result, 'COMMIT_OBJECT_SHA_MISMATCH')
            self.assertEqual(len(s.calls), 3)
            self.assertFalse(c.calls)

    def test_second_branch_read_detects_changed_source(self):
        source = replies('github')
        source[3]['object']['sha'] = 'e'*40
        result, s, c, *_ = run(source=source)
        self.bad(result, 'SOURCE_CI_SHA_MISMATCH')
        self.assertEqual(len(s.calls), 4)
        self.assertTrue(c.calls)

    def test_repo_recheck_drift(self):
        source = replies('gitlab')
        source[4]['id'] = 999
        result, s, c, *_ = run(GL, source=source)
        self.bad(result, 'SOURCE_REPOSITORY_ID_MISMATCH')
        self.assertEqual(len(s.calls), 5)
        self.assertTrue(c.calls)

    def test_fork_pr_and_mr_denied(self):
        for key in (GH, GL):
            source = replies(key.provider, pr=True)
            if key.provider == 'github':
                source[1]['head']['repo']['id'] = 444
            else:
                source[1]['source_project_id'] = 444
            result, s, c, *_ = run(key, mode='ProposedPR', source=source)
            self.bad(result, 'CROSS_FORK_NOT_BOUND')
            self.assertFalse(c.calls)

    def test_pr_merge_sha_cannot_pass_as_head(self):
        source = replies('github', pr=True)
        source[1]['head']['sha'] = 'e'*40
        result, *_ = run(mode='ProposedPR', source=source)
        self.bad(result, 'PROPOSAL_CI_SHA_MISMATCH')

    def test_mr_diff_version_requires_same_head(self):
        source = replies('gitlab', pr=True)
        source[1]['diff_refs']['head_sha'] = 'e'*40
        result, *_ = run(GL, mode='ProposedPR', source=source)
        self.bad(result, 'PROPOSAL_DIFF_HEAD_DRIFT')

    def test_changed_pr_object_during_recheck(self):
        source = replies('github', pr=True)
        source[4]['id'] = 999
        result, s, c, *_ = run(mode='ProposedPR', source=source)
        self.bad(result, 'SOURCE_DRIFT_DURING_ASSOCIATION')
        self.assertEqual(len(s.calls), 7)
        self.assertTrue(c.calls)

    def test_ci_attempt_not_interchangeable(self):
        changed = ci_test.gh_run()
        changed['run_attempt'] = 3
        result, s, c, *_ = run(new_ci=[changed])
        self.bad(result, 'FRESH_CI_RECHECK_FAILED')
        self.assertEqual(len(s.calls), 3)
        self.assertEqual(len(c.calls), 1)

    def test_ci_changed_result_cannot_reuse_old_receipt(self):
        changed = ci_test.gh_run()
        changed['updated_at'] = '2026-10-22T19:59:00Z'
        result, s, c, *_ = run(new_ci=[changed, {'total_count': 1, 'jobs': [ci_test.gh_job()]}, changed])
        self.bad(result, 'FRESH_CI_OBSERVATION_DRIFT')
        self.assertEqual(len(c.calls), 3)

    def test_source_transport_exception_opaque(self):
        result, s, c, *_ = run(source=[RuntimeError('secret provider response')])
        self.bad(result, 'SOURCE_TRANSPORT_FAILED')
        self.assertNotIn('secret', json.dumps(result))
        self.assertEqual(len(s.calls), 1)
        self.assertFalse(c.calls)

    def test_branch_path_escapes_gitlab_slash(self):
        changed = qc.CISelection('gitlab', 'acme/widget', 731, None, 2300, None,
                                  350, 'feature/x', SHA, 3600)
        self.assertIn('/branches/feature%2Fx', qb._endpoint(
            qb.SourceSelection(changed, 'DeliveredTarget'), 'REF'))

    def test_transport_refuses_untrusted_urls(self):
        t = qb.StrictSourceHTTPS()
        for u in ('http://api.github.com/repos/a/b',
                  'https://api.github.com.evil/repos/a/b',
                  'https://gitlab.com:443/api/v4/projects/1',
                  'https://gitlab.com/api/v4/projects/1?private_token=abc',
                  'https://api.github.com/repos/a/../b'):
            with self.assertRaises(qb.BindError):
                t.get(u, {}, 1.0)

    def test_cli_optin_refusal_stays_offline(self):
        f = Path(__file__).with_name('quality_sha_bind.py')
        argv = ['--receipt', '/does/not/exist', '--provider', 'github',
                '--repository', 'acme/widget', '--project-id', '731',
                '--workflow-id', '991', '--run-id', '2300', '--attempt', '2',
                '--job-id', '350', '--branch', 'main', '--commit-sha', SHA,
                '--ci-max-age', '3600', '--source-mode', 'DeliveredTarget']
        p = subprocess.run([sys.executable, str(f), *argv], text=True,
                           capture_output=True, timeout=6)
        self.assertEqual(p.returncode, 4)
        self.assertEqual(json.loads(p.stdout)['reason_code'],
                         'QUALITYSHABIND_INDEPENDENT_OPTINS_REQUIRED')


if __name__ == '__main__':
    unittest.main()
