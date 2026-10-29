#!/usr/bin/env python3
"""EC212 focused offline integration: actual EC211 reader + fake GET transport.

All credentials, issues, organization grants and clock readings are synthetic.
No network, repository writes, provider writes, permanent snapshot cache, or
native PowerShell execution is performed.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import unittest
from urllib.error import HTTPError

import issue_provider as ip
import issue_sync as sync

FIX = Path(__file__).resolve().parent / 'fixtures' / 'ec211'
NOW = datetime(2026, 10, 24, 9, 0, 0, tzinfo=timezone.utc)
TOKEN = 'DO-NOT-PRINT-FAKE-ISSUE-SYNC-TOKEN'


def fixture(file):
    return json.loads((FIX / (file + '.json')).read_text(encoding='utf-8'))


def make_context(provider='github', account='synthetic-account-slot'):
    return ip.ProviderContext(provider, ip.API_HOST[provider], account)


def make_scope(provider='github', numbers=(17, 18), repository=None, repo_id=None):
    return sync.IssueSyncScope(
        repository or ('example/repo' if provider == 'github' else 'team/subteam/service'),
        repo_id if repo_id is not None else (73142 if provider == 'github' else 903210),
        tuple(numbers))


def expiry(delta=120):
    return (NOW + timedelta(seconds=delta)).isoformat().replace('+00:00', 'Z')


def grants(ctx, scope, **override):
    data = dict(method=sync.METHOD, provider=ctx.provider, api_host=ctx.api_host,
                account_ref=ctx.account_ref, repository=scope.repository,
                expected_repository_id=scope.expected_repository_id, numbers=scope.numbers,
                expires_at_utc=expiry(), authorized=True, allow_write=False)
    data.update(override)
    return sync.IssueSyncGrant(**data)


def read_grants(ctx, scope):
    return {
        n: ip.IssueReadGrant(ip.METHOD, ctx.provider, ctx.api_host, ctx.account_ref,
                             scope.repository, n, expiry(), True)
        for n in scope.numbers
    }


def issue_of(provider, number, *, issue_id=None, repo_name=None, repo_id=None, title=None):
    obj = fixture(provider + '_issue')
    if provider == 'github':
        obj['number'] = number
        obj['id'] = issue_id if issue_id is not None else 500404 + number
        obj['node_id'] = 'synthetic-node-' + str(number)
        if repo_name:
            obj['repository_url'] = 'https://api.github.com/repos/' + repo_name
    else:
        obj['iid'] = number
        obj['id'] = issue_id if issue_id is not None else 812048 + number
        obj['project_id'] = repo_id if repo_id is not None else 903210
        obj['references']['full'] = (repo_name or 'team/subteam/service') + '#' + str(number)
    if title is not None:
        obj['title'] = title
    return obj


def repo_of(provider, *, name=None, repo_id=None):
    obj = fixture('github_repository' if provider == 'github' else 'gitlab_project')
    if name is not None:
        obj['full_name' if provider == 'github' else 'path_with_namespace'] = name
    if repo_id is not None:
        obj['id'] = repo_id
    return obj


class BatchTransport:
    def __init__(self, triples):
        self.values = [copy.deepcopy(v) for three in triples for v in three]
        self.calls = []

    def get_object(self, url, headers, timeout):
        self.calls.append((url, copy.deepcopy(headers), timeout))
        if not self.values:
            raise AssertionError('unexpected GET after bounded selection')
        value = self.values.pop(0)
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


def triplets(provider='github', numbers=(17, 18), *, titles=None):
    return [(repo_of(provider),
             issue_of(provider, number, title=(titles or {}).get(number)),
             repo_of(provider)) for number in numbers]


def run(provider='github', *, numbers=(17, 18), ctx=None, scope=None, transport=None,
        sync_grant=None, per_grants=None, baseline=(), allowed=True,
        token_supplier=lambda: TOKEN, clock=lambda: NOW, timeout=8):
    c = ctx or make_context(provider)
    selection = scope or make_scope(provider, numbers)
    tr = transport or BatchTransport(triplets(provider, selection.numbers))
    result = sync.sync_issues(c, selection, sync_grant=sync_grant or grants(c, selection),
                              issue_read_grants=per_grants or read_grants(c, selection),
                              baseline=baseline, allow_network=allowed,
                              token_supplier=token_supplier, transport=tr, clock=clock,
                              timeout=timeout)
    return result, tr


class IssueSyncTests(unittest.TestCase):
    def assert_refused(self, out, reason, status='unavailable'):
        self.assertEqual(out['status'], status, out)
        self.assertEqual(out['reason_code'], 'ISSUE_SYNC_' + reason, out)
        self.assertEqual(out['exit_code'], 4 if status == 'invalid_input' else 5)
        self.assertEqual(out['read_state'], 'UNKNOWN')
        self.assertIsNone(out['scope'])
        self.assertEqual(out['entries'], [])
        self.assertIsNone(out['aggregate_snapshot_sha256'])
        self.assertFalse(out['snapshot_collection_performed'])
        self.assertFalse(out['issue_or_provider_written'])

    def assert_complete(self, out, count):
        self.assertEqual((out['status'], out['exit_code']), ('partial', 2), out)
        self.assertTrue(out['complete_selection'])
        self.assertEqual(out['coverage'], 'COMPLETE_EXPLICIT_SELECTION_NONATOMIC')
        self.assertEqual(out['observed_count'], count)
        self.assertEqual(out['unknown_count'], 0)
        self.assertTrue(out['snapshot_collection_performed'])
        self.assertRegex(out['aggregate_snapshot_sha256'], r'^[0-9a-f]{64}$')
        for key in ('issue_created', 'issue_or_provider_written',
                    'business_repository_written', 'knowledge_source_written',
                    'persisted', 'external_cache_mutated', 'native_issue_action_registered',
                    'organizational_grant_authenticated', 'baseline_authenticated',
                    'snapshot_atomic', 'full_repository_inventory'):
            self.assertIs(out[key], False, (key, out[key]))
        self.assertTrue(out['selected_metadata_projection_only'])
        self.assertEqual(out['read_state'], 'SYNTHETIC_OBSERVED')

    def test_github_selected_whitelist_and_only_six_get(self):
        out, tr = run()
        self.assert_complete(out, 2)
        self.assertEqual(out['scope']['numbers'], [17, 18])
        self.assertEqual(out['provider_read_invocations'], 2)
        self.assertEqual(out['maximum_possible_provider_gets'], 6)
        self.assertEqual([u for u, _, _ in tr.calls], [
            'https://api.github.com/repos/example/repo',
            'https://api.github.com/repos/example/repo/issues/17',
            'https://api.github.com/repos/example/repo',
            'https://api.github.com/repos/example/repo',
            'https://api.github.com/repos/example/repo/issues/18',
            'https://api.github.com/repos/example/repo'])
        self.assertTrue(all(t <= 8 for _, _, t in tr.calls))
        payload = json.dumps(out, ensure_ascii=False)
        for private in (TOKEN, 'SYNTHETIC private title', 'NOT-A-REAL-SECRET',
                        'SYNTHETIC private description'):
            self.assertNotIn(private, payload)
        self.assertEqual(out['entries'][0]['snapshot']['identity']['provider_issue_id'], '500421')

    def test_gitlab_selected_project_id_and_confidential(self):
        out, tr = run('gitlab')
        self.assert_complete(out, 2)
        self.assertEqual(out['entries'][0]['snapshot']['provider_confidentiality'],
                         'CONFIDENTIAL')
        self.assertEqual(tr.calls[1][0],
                         'https://gitlab.com/api/v4/projects/903210/issues/17')
        self.assertEqual(tr.calls[4][0],
                         'https://gitlab.com/api/v4/projects/903210/issues/18')
        self.assertNotIn('SYNTHETIC restricted description', json.dumps(out))
        self.assertNotIn(TOKEN, json.dumps(out))

    def test_stable_projection_and_change_hint_not_trusted(self):
        first = run()[0]
        baseline = tuple(sync.BaselineFingerprint(
            number=e['number'], provider_issue_id=e['snapshot']['identity']['provider_issue_id'],
            identity_sha256=e['snapshot']['identity_sha256'],
            snapshot_sha256=e['snapshot']['snapshot_sha256']
        ) for e in first['entries'])
        same = run(baseline=baseline)[0]
        self.assert_complete(same, 2)
        self.assertEqual([x['comparison'] for x in same['entries']],
                         ['SAME_SELECTED_PROJECTION_AS_CALLER_HINT'] * 2)
        self.assertEqual(same['aggregate_snapshot_sha256'],
                         first['aggregate_snapshot_sha256'])
        updated = run(baseline=baseline,
                      transport=BatchTransport(triplets(titles={18: 'CHANGED PRIVATE TITLE'})))[0]
        self.assert_complete(updated, 2)
        self.assertEqual(updated['entries'][1]['comparison'],
                         'DIFFERENT_SELECTED_PROJECTION_FROM_CALLER_HINT')
        self.assertNotEqual(updated['aggregate_snapshot_sha256'],
                            first['aggregate_snapshot_sha256'])
        self.assertNotIn('CHANGED PRIVATE TITLE', json.dumps(updated))
        self.assertFalse(updated['baseline_authenticated'])

    def test_same_issue_id_reused_different_local_number_is_hard_failure(self):
        cases = triplets()
        cases[1] = (repo_of('github'), issue_of('github', 18, issue_id=500421),
                    repo_of('github'))
        out, tr = run(transport=BatchTransport(cases))
        self.assert_refused(out, 'ISSUE_ID_COLLISION_ACROSS_BATCH')
        self.assertEqual(len(tr.calls), 6)

    def test_repository_canonical_path_changes_across_issue_reads(self):
        cases = triplets()
        cases[1] = (repo_of('github', name='EXAMPLE/repo'),
                    issue_of('github', 18, repo_name='EXAMPLE/repo'),
                    repo_of('github', name='EXAMPLE/repo'))
        out, _ = run(transport=BatchTransport(cases))
        self.assert_refused(out, 'REPOSITORY_LOCATOR_CHANGED_ACROSS_BATCH')

    def test_404_and_normal_result_partial_unknown(self):
        response = [repo_of('github'), HTTPError('https://secret.invalid', 404,
                    'SENSITIVE-404-MESSAGE', {}, None),
                    repo_of('github'), issue_of('github', 18), repo_of('github')]
        class QueueTransport:
            calls = 0
            def get_object(self, *args):
                self.calls += 1
                obj = response.pop(0)
                if isinstance(obj, Exception): raise obj
                return obj
        tr = QueueTransport()
        out, _ = run(transport=tr)
        self.assertEqual(out['status'], 'partial')
        self.assertEqual(out['coverage'], 'PARTIAL_SELECTION_UNKNOWN')
        self.assertEqual(out['observed_count'], 1)
        self.assertEqual(out['unknown_count'], 1)
        self.assertEqual(out['entries'][0]['state'], 'UNKNOWN')
        self.assertEqual(out['entries'][0]['reason_code'],
                         'ISSUE_PROVIDER_READ_FAILED')
        self.assertIsNone(out['entries'][0]['snapshot'])
        self.assertIsNone(out['aggregate_snapshot_sha256'])
        self.assertEqual(tr.calls, 5)
        self.assertNotIn('SENSITIVE-404-MESSAGE', json.dumps(out))

    def test_all_unknown_never_complete_or_absent(self):
        responses = [HTTPError('https://secret.invalid', 403, 'PRIVATE', {}, None)] * 2
        class ErrorTransport:
            calls = 0
            def get_object(self, *args):
                self.calls += 1
                raise responses.pop(0)
        tr = ErrorTransport()
        out, _ = run(transport=tr)
        self.assertEqual(out['status'], 'unavailable')
        self.assertEqual(out['coverage'], 'UNKNOWN')
        self.assertEqual(out['observed_count'], 0)
        self.assertEqual(out['unknown_count'], 2)
        self.assertEqual(len(out['entries']), 2)
        self.assertFalse(out['snapshot_collection_performed'])
        self.assertEqual(tr.calls, 2)

    def test_provider_repository_id_mismatch_is_unknown_per_issue(self):
        cases = [repo_of('github', repo_id=111)]
        # After first rejected GET, the next issue starts at index 1.
        cases += [repo_of('github'), issue_of('github', 18), repo_of('github')]
        tr = BatchTransport([])
        tr.values = cases
        out, _ = run(transport=tr)
        self.assertEqual(out['status'], 'partial', out)
        self.assertEqual(out['entries'][0]['reason_code'], 'ISSUE_REPOSITORY_ID_MISMATCH')
        self.assertEqual(out['entries'][1]['state'], 'OBSERVED_SELECTED_METADATA')
        self.assertIsNone(out['aggregate_snapshot_sha256'])
        self.assertEqual(len(tr.calls), 4)

    def test_identity_conflict_caller_hint_quarantines_entry(self):
        prior = sync.BaselineFingerprint(17, '9999', 'a'*64, 'b'*64)
        out, _ = run(baseline=(prior,))
        self.assertEqual(out['status'], 'partial')
        self.assertEqual(out['observed_count'], 1)
        self.assertEqual(out['entries'][0]['comparison'], 'UNKNOWN')
        self.assertIsNone(out['entries'][0]['snapshot'])
        self.assertEqual(out['entries'][0]['reason_code'],
                         'ISSUE_SYNC_IDENTITY_CONFLICT_UNKNOWN')

    def test_invalid_baseline_rejected_before_any_get(self):
        tr = BatchTransport(triplets())
        out, tr = run(baseline=(sync.BaselineFingerprint(17, '1', 'A'*64, 'b'*64),),
                      transport=tr)
        self.assert_refused(out, 'BASELINE_INVALID', status='invalid_input')
        self.assertEqual(tr.calls, [])

    def test_offline_network_not_requested_does_not_read_credentials(self):
        c, s = make_context(), make_scope()
        out = sync.sync_issues(c, s, sync_grant=grants(c, s),
                    issue_read_grants=read_grants(c, s),
                    token_supplier=lambda: self.fail('accessed credential'))
        self.assert_refused(out, 'NETWORK_NOT_AUTHORIZED')

    def test_missing_batch_grant_is_refused_before_credential(self):
        c, s = make_context(), make_scope()
        out = sync.sync_issues(c, s, allow_network=True,
                    issue_read_grants=read_grants(c, s),
                    token_supplier=lambda: self.fail('accessed credential'),
                    clock=lambda: NOW)
        self.assert_refused(out, 'GRANT_REQUIRED')

    def test_missing_per_issue_grant_is_refused_without_reads(self):
        c, s = make_context(), make_scope()
        fake = BatchTransport(triplets())
        rs = read_grants(c, s)
        del rs[18]
        out = sync.sync_issues(c, s, allow_network=True, transport=fake,
                    sync_grant=grants(c, s), issue_read_grants=rs,
                    token_supplier=lambda: self.fail('accessed credential'),
                    clock=lambda: NOW)
        self.assert_refused(out, 'PER_ISSUE_GRANTS_REQUIRED')
        self.assertFalse(fake.calls)

    def test_extra_per_issue_grant_is_rejected(self):
        c, s = make_context(), make_scope()
        rs = read_grants(c, s)
        rs[19] = ip.IssueReadGrant(ip.METHOD, c.provider, c.api_host, c.account_ref,
                                    s.repository, 19, expiry(), True)
        out, _ = run(per_grants=rs)
        self.assert_refused(out, 'PER_ISSUE_GRANTS_REQUIRED')

    def test_per_issue_grant_wrong_repository_or_allowwrite(self):
        c, s = make_context(), make_scope()
        for mode in ('path', 'write', 'expired'):
            with self.subTest(mode=mode):
                rs = read_grants(c, s)
                old = rs[18]
                values = dict(old.__dict__)
                if mode == 'path': values['repository'] = 'other/repo'
                if mode == 'write': values['allow_write'] = True
                if mode == 'expired': values['expires_at_utc'] = expiry(-1)
                rs[18] = ip.IssueReadGrant(**values)
                out, tr = run(per_grants=rs)
                self.assert_refused(out, 'PER_ISSUE_GRANT_INVALID')
                self.assertEqual(tr.calls, [])

    def test_wrong_batch_grant_scope_expiry_and_write(self):
        c, s = make_context(), make_scope()
        for values, expected in [
            ({'repository': 'other/repo'}, 'GRANT_SCOPE_MISMATCH'),
            ({'account_ref': 'other-account'}, 'GRANT_SCOPE_MISMATCH'),
            ({'allow_write': True}, 'GRANT_REQUIRED'),
            ({'numbers': (17,)}, 'GRANT_SCOPE_MISMATCH'),
            ({'expires_at_utc': expiry(-1)}, 'GRANT_EXPIRED_OR_TOO_BROAD'),
            ({'expires_at_utc': expiry(301)}, 'GRANT_EXPIRED_OR_TOO_BROAD')
        ]:
            with self.subTest(values=values):
                out, tr = run(sync_grant=grants(c, s, **values))
                self.assert_refused(out, expected)
                self.assertFalse(tr.calls)

    def test_scope_rejects_invalid_allowlists_without_network(self):
        c = make_context()
        for values in ((), (18, 17), (17, 17), (17, 0), (True,),
                       tuple(range(1, 10)), (2147483648,)):
            with self.subTest(values=values):
                scope = make_scope(numbers=values)
                out, tr = run(scope=scope)
                self.assert_refused(out, 'ALLOWLIST_INVALID', 'invalid_input')
                self.assertFalse(tr.calls)

    def test_scope_rejects_wrong_repo_id_host_or_account(self):
        for ctx, scope, code, status in [
            (make_context(), make_scope(repo_id=True), 'REPOSITORY_ID_INVALID', 'invalid_input'),
            (make_context(), make_scope(repository='../repo'), 'SCOPE_INVALID', 'invalid_input'),
            (ip.ProviderContext('github', 'evil.invalid', 'synthetic-slot'),
             make_scope(), 'PROVIDER_CONTEXT_INVALID', 'invalid_input'),
            (ip.ProviderContext('github', 'api.github.com', ''),
             make_scope(), 'PROVIDER_CONTEXT_INVALID', 'unavailable'),
        ]:
            with self.subTest(code=code):
                result, tr = run(ctx=ctx, scope=scope)
                self.assert_refused(result, code, status)
                self.assertFalse(tr.calls)

    def test_missing_token_or_token_exception_is_redacted(self):
        out, tr = run(token_supplier=lambda: None)
        self.assert_refused(out, 'CREDENTIALS_UNAVAILABLE')
        self.assertFalse(tr.calls)
        def fail():
            raise Exception('SECRET-TOKEN-TEXT')
        out, tr = run(token_supplier=fail)
        self.assert_refused(out, 'CREDENTIALS_UNAVAILABLE')
        self.assertNotIn('SECRET-TOKEN-TEXT', json.dumps(out))
        self.assertFalse(tr.calls)

    def test_global_permission_expiration_after_read_drops_all_snapshots(self):
        c, s = make_context(), make_scope(numbers=(17,))
        cursor = {'calls': 0}
        def advancing_clock():
            cursor['calls'] += 1
            if cursor['calls'] >= 7:
                return NOW + timedelta(seconds=121)
            return NOW
        out, tr = run(ctx=c, scope=s,
                      clock=advancing_clock,
                      transport=BatchTransport(triplets(numbers=(17,))))
        self.assert_refused(out, 'GRANT_EXPIRED_OR_TOO_BROAD')
        self.assertEqual(len(tr.calls), 3)
        self.assertIsNone(out['aggregate_snapshot_sha256'])
        self.assertEqual(out['entries'], [])

    def test_local_source_staleness_downgrades_to_unknown(self):
        c, s = make_context(), make_scope(numbers=(17,))
        cursor = {'n': 0}
        def clock():
            cursor['n'] += 1
            # EC211 observes at NOW; EC212 finishes 130 seconds later while
            # both batch grant and EC211 per-Issue grant remain valid.
            return NOW + timedelta(seconds=130) if cursor['n'] >= 7 else NOW
        sg = grants(c, s, expires_at_utc=expiry(260))
        rg = read_grants(c, s)
        rg[17] = ip.IssueReadGrant(ip.METHOD, c.provider, c.api_host, c.account_ref,
                                   s.repository, 17, expiry(260), True)
        out, tr = run(ctx=c, scope=s, sync_grant=sg, per_grants=rg,
                      clock=clock, transport=BatchTransport(triplets(numbers=(17,))))
        self.assertEqual(out['status'], 'unavailable', out)
        self.assertEqual(out['entries'][0]['reason_code'], 'ISSUE_SYNC_OBSERVATION_STALE')
        self.assertIsNone(out['entries'][0]['snapshot'])
        self.assertEqual(len(tr.calls), 3)

    def test_real_provider_does_not_get_fake_provider_observed_status(self):
        c, s = make_context(), make_scope()
        out = sync.sync_issues(c, s, allow_network=False)
        self.assertEqual(out['read_state'], 'UNKNOWN')
        self.assertFalse(out['snapshot_collection_performed'])

    def test_cli_is_offline_by_default_and_has_no_writes(self):
        script = Path(__file__).resolve().parent / 'issue_sync.py'
        completed = subprocess.run(
            [sys.executable, str(script), '--provider', 'github',
             '--repository', 'example/repo', '--expected-repository-id', '73142',
             '--numbers', '17,18', '--account-ref', 'synthetic-slot', '--json'], capture_output=True, text=True,
            check=False, timeout=6)
        self.assertEqual(completed.returncode, 5, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload['reason_code'], 'ISSUE_SYNC_NETWORK_NOT_AUTHORIZED')
        self.assertFalse(payload['issue_or_provider_written'])


    def test_eight_issues_bound_is_twenty_four_gets(self):
        numbers = tuple(range(17, 25))
        out, tr = run(numbers=numbers)
        self.assert_complete(out, 8)
        self.assertEqual(out['maximum_possible_provider_gets'], 24)
        self.assertEqual(len(tr.calls), 24)

    def test_github_pull_request_is_not_relabelled_issue(self):
        items = triplets()
        pr = issue_of('github', 17)
        pr['pull_request'] = {'url': 'https://example.invalid'}
        class QueueTransport:
            def __init__(self):
                self.items = [repo_of('github'), pr,
                              repo_of('github'), issue_of('github', 18),
                              repo_of('github')]
            def get_object(self, *args): return self.items.pop(0)
        out, _ = run(transport=QueueTransport())
        self.assertEqual(out['coverage'], 'PARTIAL_SELECTION_UNKNOWN')
        self.assertEqual(out['entries'][0]['reason_code'],
                         'ISSUE_GITHUB_PULL_REQUEST_NOT_ISSUE')
        self.assertEqual(out['entries'][1]['state'], 'OBSERVED_SELECTED_METADATA')

    def test_result_contract_rejects_sensitive_extra_property(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest('jsonschema optional developer dependency unavailable')
        base = Path(__file__).resolve().parent.parent / 'references'
        grant_schema = json.loads((base / 'issue-sync-grant.v1.schema.json').read_text())
        result_schema = json.loads((base / 'issue-sync-result.v1.schema.json').read_text())
        jsonschema.Draft202012Validator.check_schema(grant_schema)
        jsonschema.Draft202012Validator.check_schema(result_schema)
        val = jsonschema.Draft202012Validator(result_schema)
        selected = run()[0]
        offline = sync.sync_issues(make_context(), make_scope())
        self.assertFalse(list(val.iter_errors(selected)))
        self.assertFalse(list(val.iter_errors(offline)))
        mutated = copy.deepcopy(selected)
        mutated['entries'][0]['snapshot']['title'] = 'PRIVATE'
        self.assertTrue(list(val.iter_errors(mutated)))
        check = grants(make_context(), make_scope())
        self.assertFalse(list(jsonschema.Draft202012Validator(
            grant_schema).iter_errors(check.__dict__ | {'numbers':list(check.numbers)})))

    def test_invalid_timeout_is_input_error_before_get(self):
        for value in (0, -1, True, 9, float('nan')):
            with self.subTest(value=value):
                out, tr = run(timeout=value)
                self.assert_refused(out, 'TIMEOUT_INVALID', 'invalid_input')
                self.assertEqual(tr.calls, [])


if __name__ == '__main__':
    unittest.main()
