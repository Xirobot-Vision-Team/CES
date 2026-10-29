#!/usr/bin/env python3
"""EC213 offline focused functionality: real EC211 read with fake GET only.

No real account, secret, remote Issue, network, PowerShell, write, or user
final acceptance is exercised by these synthetic local development checks.
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
from unittest.mock import patch

import issue_provider as ip
import issue_show as show

FIX = Path(__file__).parent / 'fixtures' / 'ec211'
NOW = datetime(2026, 10, 24, 9, 0, tzinfo=timezone.utc)
TOKEN = 'NOT-A-REAL-EC213-SECRET-TOKEN'


def fixture(name):
    return json.loads((FIX / (name + '.json')).read_text('utf-8'))


def context(provider='github'):
    return ip.ProviderContext(provider, ip.API_HOST[provider], 'synthetic-account-slot')


def selection(provider='github', **kw):
    defaults = dict(repository='example/repo' if provider == 'github' else 'team/subteam/service',
                    expected_repository_id=73142 if provider == 'github' else 903210,
                    number=17, expected_provider_issue_id=500421 if provider == 'github' else 812065)
    defaults.update(kw)
    return show.IssueShowSelection(**defaults)


def expiry(delta=120):
    return (NOW + timedelta(seconds=delta)).isoformat(timespec='seconds').replace('+00:00', 'Z')


def grant(ctx, chosen, **kw):
    opts = dict(method=show.METHOD, provider=ctx.provider, api_host=ctx.api_host,
                account_ref=ctx.account_ref, repository=chosen.repository,
                expected_repository_id=chosen.expected_repository_id,
                number=chosen.number, expected_provider_issue_id=chosen.expected_provider_issue_id,
                filters=chosen.filters, max_observation_age_seconds=chosen.max_observation_age_seconds,
                expires_at_utc=expiry(), authorized=True, allow_write=False)
    opts.update(kw)
    return show.IssueShowGrant(**opts)


def read_grant(ctx, chosen, **kw):
    opts = dict(method=ip.METHOD, provider=ctx.provider, api_host=ctx.api_host,
                account_ref=ctx.account_ref, repository=chosen.repository, number=chosen.number,
                expires_at_utc=expiry(), authorized=True, allow_write=False)
    opts.update(kw)
    return ip.IssueReadGrant(**opts)


class FakeTransport:
    def __init__(self, provider='github', *, repo=None, issue=None, second_repo=None):
        rp = fixture('github_repository' if provider == 'github' else 'gitlab_project')
        obj = fixture(provider + '_issue')
        def saved(value):
            return value if isinstance(value, Exception) else copy.deepcopy(value)
        self.steps = [saved(repo if repo is not None else rp),
                      saved(issue if issue is not None else obj),
                      saved(second_repo if second_repo is not None else rp)]
        self.calls = []

    def get_object(self, url, headers, timeout):
        self.calls.append((url, headers, timeout))
        if not self.steps:
            raise AssertionError('Exceeded three-GET bound')
        value = self.steps.pop(0)
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


def execute(provider='github', *, ctx=None, chosen=None, sg=None, rg=None,
            transport=None, allow=True, supplier=lambda: TOKEN,
            clock=lambda: NOW, timeout=8.0):
    ctx = ctx or context(provider)
    chosen = chosen or selection(provider)
    transport = transport if transport is not None else FakeTransport(provider)
    result = show.show_issue(ctx, chosen, show_grant=sg if sg is not None else grant(ctx, chosen),
                             issue_read_grant=rg if rg is not None else read_grant(ctx, chosen),
                             allow_network=allow, token_supplier=supplier,
                             transport=transport, clock=clock, timeout=timeout)
    return result, transport


class IssueShowTests(unittest.TestCase):
    def observed(self, out, matched=True):
        self.assertEqual(out['status'], 'partial', out)
        self.assertEqual(out['exit_code'], 2, out)
        self.assertEqual(out['read_state'], 'SYNTHETIC_OBSERVED', out)
        self.assertEqual(out['issue_existence'], 'SYNTHETIC_FIXTURE_PRESENT')
        self.assertEqual(out['filter_outcome'], 'MATCHED' if matched else 'EXCLUDED_BY_FILTER')
        self.assertEqual(out['source_origin'], 'synthetic_fixture')
        self.assertEqual(out['provider_read_invocations'], 1)
        self.assertEqual(out['maximum_possible_provider_gets'], 3)
        self.assertFalse(out['organizational_grant_authenticated'])
        for key in ('issue_created', 'issue_sync_performed', 'native_issue_action_registered',
                    'issue_or_provider_written', 'business_repository_written',
                    'knowledge_source_written', 'persisted', 'snapshot_atomic',
                    'external_cache_mutated', 'full_issue_contents',
                    'provider_account_ownership_authenticated'):
            self.assertFalse(out[key], (key, out))
        self.assertIsNotNone(out['issue'] if matched else out['scope'])

    def unknown(self, out, reason=None, status='unavailable', invoked=None):
        self.assertEqual(out['status'], status, out)
        self.assertEqual(out['exit_code'], 5 if status == 'unavailable' else 4, out)
        self.assertEqual(out['read_state'], 'UNKNOWN')
        self.assertEqual(out['issue_existence'], 'UNKNOWN')
        self.assertEqual(out['filter_outcome'], 'UNKNOWN')
        self.assertEqual(out['coverage'], 'UNKNOWN')
        self.assertIsNone(out['issue'])
        self.assertIsNone(out['scope'])
        self.assertIsNone(out['observed_at_utc'])
        if reason:
            self.assertEqual(out['reason_code'], 'ISSUE_SHOW_' + reason, out)
        if invoked is not None:
            self.assertEqual(out['provider_read_invocations'], int(invoked))
        self.assertFalse(out['issue_or_provider_written'])

    def test_github_show_exact_global_id_and_three_get_urls(self):
        out, tr = execute()
        self.observed(out)
        self.assertEqual(out['scope']['expected_provider_issue_id'], '500421')
        self.assertEqual(out['issue']['identity']['provider_issue_id'], '500421')
        self.assertEqual(out['issue']['provider_state'], 'OPEN')
        self.assertEqual(len(tr.calls), 3)
        self.assertEqual([c[0] for c in tr.calls], [
            'https://api.github.com/repos/example/repo',
            'https://api.github.com/repos/example/repo/issues/17',
            'https://api.github.com/repos/example/repo'])
        self.assertTrue(all(call[2] <= 8 for call in tr.calls))

    def test_gitlab_uses_project_numeric_id_and_confidential(self):
        out, tr = execute('gitlab')
        self.observed(out)
        self.assertEqual(out['issue']['provider_confidentiality'], 'CONFIDENTIAL')
        self.assertEqual(tr.calls[1][0],
                         'https://gitlab.com/api/v4/projects/903210/issues/17')

    def test_redaction_of_private_content_credentials_and_actor(self):
        out, _ = execute()
        serialized = json.dumps(out)
        for value in (TOKEN, 'SYNTHETIC private title',
                      'SYNTHETIC body', 'NOT-A-REAL-SECRET',
                      'needs-triage', 'I_kwSyntheticOnly01'):
            self.assertNotIn(value, serialized)
        self.assertEqual(set(out['issue'].keys()), {
            'identity', 'identity_sha256', 'snapshot_sha256', 'provider_state',
            'provider_created_at_utc', 'provider_updated_at_utc',
            'provider_closed_at_utc', 'provider_confidentiality',
            'observed_at_utc', 'observation_origin', 'snapshot_semantics',
            'source_limited_to_selected_metadata'})

    def test_state_included(self):
        chosen = selection(filters=show.ShowFilters(state='OPEN'))
        self.observed(execute(chosen=chosen)[0])

    def test_state_excluded_no_snapshot_or_private_info(self):
        chosen = selection(filters=show.ShowFilters(state='CLOSED'))
        out, tr = execute(chosen=chosen)
        self.observed(out, matched=False)
        self.assertIsNone(out['issue'])
        self.assertEqual(out['reason_code'], 'ISSUE_SHOW_FILTER_EXCLUDED')
        self.assertEqual(len(tr.calls), 3)

    def test_gitlab_confidentiality_included(self):
        chosen = selection('gitlab', filters=show.ShowFilters(confidentiality='CONFIDENTIAL'))
        self.observed(execute('gitlab', chosen=chosen)[0])

    def test_gitlab_confidentiality_excluded(self):
        chosen = selection('gitlab', filters=show.ShowFilters(confidentiality='STANDARD'))
        self.observed(execute('gitlab', chosen=chosen)[0], matched=False)

    def test_update_lower_inclusive(self):
        chosen = selection(filters=show.ShowFilters(updated_not_before_utc='2026-07-02T11:20:00Z'))
        self.observed(execute(chosen=chosen)[0])

    def test_update_upper_exclusive(self):
        chosen = selection(filters=show.ShowFilters(updated_before_utc='2026-07-02T11:20:00Z'))
        self.observed(execute(chosen=chosen)[0], matched=False)

    def test_update_interval(self):
        chosen = selection(filters=show.ShowFilters(
            updated_not_before_utc='2026-07-01T00:00:00Z',
            updated_before_utc='2026-07-03T00:00:00Z'))
        self.observed(execute(chosen=chosen)[0])

    def test_bad_filter_values_or_reverse_interval_prevent_token(self):
        for f in (show.ShowFilters(state='published'),
                  show.ShowFilters(confidentiality='Private'),
                  show.ShowFilters(updated_before_utc='bad'),
                  show.ShowFilters(updated_not_before_utc='2026-07-04T00:00:00Z',
                                   updated_before_utc='2026-07-03T00:00:00Z')):
            with self.subTest(filter=f):
                tokens = []
                out, tr = execute(chosen=selection(filters=f),
                                  supplier=lambda: tokens.append(1) or TOKEN)
                self.unknown(out, status='invalid_input', invoked=False)
                self.assertEqual(len(tokens), 0)
                self.assertEqual(len(tr.calls), 0)

    def test_offline_default_never_reads_credential_or_get(self):
        called = []
        out, tr = execute(allow=False, supplier=lambda: called.append(1) or TOKEN)
        self.unknown(out, 'NETWORK_NOT_AUTHORIZED', invoked=False)
        self.assertEqual(called, [])
        self.assertEqual(tr.calls, [])

    def test_missing_show_grant_and_missing_provider_grant_fail_before_token(self):
        for kind in ('show', 'read'):
            ctx, chosen = context(), selection()
            called = []
            out, tr = execute(ctx=ctx, chosen=chosen,
                              sg=False if kind == 'show' else grant(ctx, chosen),
                              rg=False if kind == 'read' else read_grant(ctx, chosen),
                              supplier=lambda: called.append(True) or TOKEN)
            self.unknown(out, 'SHOW_GRANT_REQUIRED' if kind == 'show'
                         else 'PROVIDER_READ_GRANT_REQUIRED', invoked=False)
            self.assertEqual(tr.calls, [])
            self.assertEqual(called, [])

    def test_expired_show_grant_before_supplier(self):
        ctx, chosen = context(), selection()
        out, tr = execute(ctx=ctx, chosen=chosen, sg=grant(ctx, chosen, expires_at_utc=expiry(-1)))
        self.unknown(out, 'SHOW_GRANT_EXPIRED_OR_TOO_BROAD', invoked=False)
        self.assertEqual(tr.calls, [])

    def test_grant_too_far_future_refused(self):
        ctx, chosen = context(), selection()
        out, _ = execute(ctx=ctx, chosen=chosen,
                         sg=grant(ctx, chosen, expires_at_utc=expiry(301)))
        self.unknown(out, 'SHOW_GRANT_EXPIRED_OR_TOO_BROAD', invoked=False)

    def test_show_grant_bound_to_exact_filter_id_and_max_age(self):
        ctx, chosen = context(), selection()
        wrongs = ({'expected_provider_issue_id': 500422},
                  {'expected_repository_id': 999},
                  {'number': 18},
                  {'filters': show.ShowFilters(state='CLOSED')},
                  {'max_observation_age_seconds': 30},
                  {'repository': 'other/repo'},
                  {'account_ref': 'another-slot'},
                  {'allow_write': True},
                  {'authorized': False},
                  {'method': ip.METHOD})
        for kw in wrongs:
            with self.subTest(kwargs=kw):
                out, tr = execute(ctx=ctx, chosen=chosen, sg=grant(ctx, chosen, **kw))
                self.unknown(out, invoked=False)
                self.assertEqual(tr.calls, [])

    def test_ec212_batch_grant_is_not_a_show_grant(self):
        import issue_sync as sync
        ctx, chosen = context(), selection()
        batch = sync.IssueSyncGrant(sync.METHOD, ctx.provider, ctx.api_host,
                                    ctx.account_ref, chosen.repository,
                                    chosen.expected_repository_id, (chosen.number,),
                                    expiry(), True)
        out, tr = execute(ctx=ctx, chosen=chosen, sg=batch)
        self.unknown(out, 'SHOW_GRANT_REQUIRED', invoked=False)
        self.assertEqual(tr.calls, [])

    def test_read_grant_cannot_be_show_grant(self):
        ctx, chosen = context(), selection()
        out, tr = execute(ctx=ctx, chosen=chosen, sg=read_grant(ctx, chosen))
        self.unknown(out, 'SHOW_GRANT_REQUIRED', invoked=False)
        self.assertEqual(tr.calls, [])

    def test_missing_token_or_supplier_refused_without_get(self):
        for supplier in (None, lambda: None, lambda: 'contains\nnewline'):
            out, tr = execute(supplier=supplier)
            self.unknown(out, 'CREDENTIALS_UNAVAILABLE', invoked=False)
            self.assertEqual(tr.calls, [])

    def test_wrong_global_issue_id_observed_not_exposed(self):
        chosen = selection(expected_provider_issue_id=500420)
        out, tr = execute(chosen=chosen)
        self.unknown(out, 'STABLE_ISSUE_ID_MISMATCH', invoked=True)
        self.assertEqual(len(tr.calls), 3)

    def test_wrong_numeric_repository_id_fail_closed(self):
        chosen = selection(expected_repository_id=99999)
        out, tr = execute(chosen=chosen)
        self.unknown(out, invoked=True)
        self.assertEqual(len(tr.calls), 1)

    def test_repository_path_case_variation_not_followed(self):
        rp = fixture('github_repository')
        rp['full_name'] = 'Example/Repo'
        issue = fixture('github_issue')
        issue['repository_url'] = 'https://api.github.com/repos/Example/Repo'
        chosen = selection()
        out, tr = execute(transport=FakeTransport('github', repo=rp, issue=issue,
                                                  second_repo=rp))
        self.unknown(out, 'REPOSITORY_LOCATOR_CHANGED', invoked=True)
        self.assertEqual(len(tr.calls), 3)

    def test_provider_404_hidden_issue_is_unknown_not_absent(self):
        denied = HTTPError('https://api.github.com', 404, 'secret', None, None)
        out, tr = execute(transport=FakeTransport(issue=denied))
        self.unknown(out, 'PROVIDER_UNKNOWN_OR_UNAVAILABLE', invoked=True)
        self.assertEqual(len(tr.calls), 2)
        self.assertNotIn('secret', json.dumps(out))

    def test_provider_get_transport_throws_secret_bearing_error(self):
        out, tr = execute(transport=FakeTransport(repo=RuntimeError(TOKEN)))
        self.unknown(out, 'PROVIDER_UNKNOWN_OR_UNAVAILABLE', invoked=True)
        self.assertNotIn(TOKEN, json.dumps(out))

    def test_github_pr_rejected_as_unknown(self):
        issue = fixture('github_issue')
        issue['pull_request'] = {'url': 'https://example.invalid/synthetic'}
        out, _ = execute(transport=FakeTransport(issue=issue))
        self.unknown(out, 'PROVIDER_UNKNOWN_OR_UNAVAILABLE', invoked=True)

    def test_provider_result_injected_source_extra_secrets_never_forwarded(self):
        orig = ip.read_issue
        def extra(*a, **kw):
            response = orig(*a, **kw)
            response['source']['leak'] = 'sensitive value NEVER return'
            response['source']['title'] = 'raw title NEVER return'
            return response
        with patch.object(ip, 'read_issue', side_effect=extra):
            out, _ = execute()
        self.observed(out)
        self.assertNotIn('NEVER return', json.dumps(out))

    def test_invalid_provider_projection_refused_no_original_text(self):
        orig = ip.read_issue
        def tamper(*a, **kw):
            response = orig(*a, **kw)
            response['source']['identity']['provider_repository_id'] = '999'
            response['source']['title'] = TOKEN
            return response
        with patch.object(ip, 'read_issue', side_effect=tamper):
            out, _ = execute()
        self.unknown(out, 'PROVIDER_PROJECTION_REJECTED', invoked=True)
        self.assertNotIn(TOKEN, json.dumps(out))

    def test_grant_expires_during_three_get_discards_observation(self):
        ctx, chosen = context(), selection()
        tick = [NOW]
        class ClockTransport(FakeTransport):
            def get_object(self, url, headers, timeout):
                result = super().get_object(url, headers, timeout)
                if len(self.calls) == 3:
                    tick[0] += timedelta(seconds=200)
                return result
        out, tr = execute(ctx=ctx, chosen=chosen,
                          sg=grant(ctx, chosen, expires_at_utc=expiry(120)),
                          transport=ClockTransport(), clock=lambda: tick[0])
        self.unknown(out, invoked=True)
        self.assertEqual(len(tr.calls), 3)
        self.assertEqual(out['issue'], None)

    def test_provider_read_grant_expires_during_get(self):
        ctx, chosen = context(), selection()
        tick = [NOW]
        class ClockTransport(FakeTransport):
            def get_object(self, url, headers, timeout):
                response = super().get_object(url, headers, timeout)
                if len(self.calls) == 3:
                    tick[0] += timedelta(seconds=200)
                return response
        out, tr = execute(ctx=ctx, chosen=chosen,
                          sg=grant(ctx, chosen, expires_at_utc=expiry(290)),
                          rg=read_grant(ctx, chosen, expires_at_utc=expiry(120)),
                          transport=ClockTransport(), clock=lambda: tick[0])
        self.unknown(out, invoked=True)
        self.assertEqual(len(tr.calls), 3)

    def test_source_stale_at_end_cannot_be_claimed(self):
        tick = [NOW]
        class ClockTransport(FakeTransport):
            def get_object(self, url, headers, timeout):
                return super().get_object(url, headers, timeout)
        calls = [0]
        def clock():
            calls[0] += 1
            # At least nine clock reads in the composed reader; shift only
            # after the source observation has already been constructed.
            return tick[0]
        orig = ip.read_issue
        def lapse(*args, **kwargs):
            response = orig(*args, **kwargs)
            tick[0] += timedelta(seconds=40)
            return response
        chosen = selection(max_observation_age_seconds=30)
        with patch.object(ip, 'read_issue', side_effect=lapse):
            out, _ = execute(chosen=chosen, clock=clock)
        self.unknown(out, 'OBSERVATION_STALE', invoked=True)

    def test_clock_rollback_after_provider_call(self):
        tick = [NOW]
        orig = ip.read_issue
        def rollback(*args, **kwargs):
            result = orig(*args, **kwargs)
            tick[0] -= timedelta(seconds=1)
            return result
        with patch.object(ip, 'read_issue', side_effect=rollback):
            out, _ = execute(clock=lambda: tick[0])
        self.unknown(out, 'CLOCK_ROLLBACK', invoked=True)

    def test_required_pin_and_filter_boundaries(self):
        cases = [selection(expected_provider_issue_id=0),
                 selection(expected_repository_id=0),
                 selection(expected_provider_issue_id=True),
                 selection(max_observation_age_seconds=121),
                 selection(max_observation_age_seconds=0),
                 selection(max_observation_age_seconds=True),
                 selection(number=0)]
        for chosen in cases:
            with self.subTest(selection=chosen):
                out, tr = execute(chosen=chosen)
                self.unknown(out, status='invalid_input', invoked=False)
                self.assertEqual(tr.calls, [])

    def test_bad_timeout_fail_closed_before_get(self):
        for timeout in (0, 9, True, float('nan'), float('inf')):
            with self.subTest(timeout=timeout):
                out, tr = execute(timeout=timeout)
                self.unknown(out, 'TIMEOUT_INVALID', status='invalid_input', invoked=False)
                self.assertEqual(tr.calls, [])

    def test_supplier_only_once(self):
        called = []
        out, _ = execute(supplier=lambda: called.append(1) or TOKEN)
        self.observed(out)
        self.assertEqual(len(called), 1)

    def test_offline_cli_json_no_provider_and_no_token_disclosure(self):
        argv = [sys.executable, str(Path(show.__file__).resolve()),
                '--provider', 'github', '--repository', 'example/repo',
                '--expected-repository-id', '73142', '--number', '17',
                '--expected-issue-id', '500421', '--json']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 5, result.stderr)
        obj = json.loads(result.stdout)
        self.unknown(obj, 'CONTEXT_INVALID', invoked=False)
        self.assertNotIn(TOKEN, result.stdout)


if __name__ == '__main__':
    unittest.main()
