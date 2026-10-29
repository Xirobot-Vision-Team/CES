#!/usr/bin/env python3
"""EC211 isolated fake provider tests: no real credentials, no external GET."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import issue_provider as ip

HERE = Path(__file__).resolve().parent
FIX = HERE / 'fixtures' / 'provider_issues'
FROZEN = datetime(2026, 10, 24, 8, 0, 0, tzinfo=timezone.utc)


def sample(name):
    return json.loads((FIX / (name + '.json')).read_text(encoding='utf-8'))


class FakeTransport:
    def __init__(self, repo=None, issue=None, repo_after=None):
        self.responses = [repo or sample('github_repository'),
                          issue or sample('github_issue'),
                          repo_after or repo or sample('github_repository')]
        self.calls = []

    def get_object(self, url, headers, timeout):
        self.calls.append((url, headers, timeout))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


def selected(provider='github', repository=None, number=17, repo_id=None):
    if repository is None:
        repository = 'example/repo' if provider == 'github' else 'team/subteam/service'
    return ip.IssueSelection(repository, number, repo_id)


def context(provider='github', host=None, account='fixture-slot-1'):
    return ip.ProviderContext(provider, host or ip.API_HOST.get(provider, ''), account)


def grant(ctx, item, *, ttl=120, **changes):
    params = dict(method=ip.METHOD, provider=ctx.provider, api_host=ctx.api_host,
                  account_ref=ctx.account_ref, repository=item.repository,
                  number=item.number,
                  expires_at_utc=(FROZEN + timedelta(seconds=ttl)).isoformat().replace('+00:00', 'Z'),
                  authorized=True, allow_write=False)
    params.update(changes)
    return ip.IssueReadGrant(**params)


def call(provider='github', *, repo=None, issue=None, repo_after=None, selection=None,
         ctx=None, read_grant=None, supplier=lambda: 'SYNTHETIC-TOKEN-NOT-PRINTED',
         allowed=True, clock=lambda: FROZEN):
    c = ctx or context(provider)
    s = selection or selected(provider)
    tr = FakeTransport(repo or sample(provider + ('_repository' if provider == 'github' else '_project')),
                       issue or sample(provider + '_issue'), repo_after)
    out = ip.read_issue(c, s, allow_network=allowed, grant=read_grant or grant(c, s),
                        token_supplier=supplier, transport=tr, clock=clock)
    return out, tr


class IssueProviderTests(unittest.TestCase):
    def accepted(self, out):
        self.assertEqual((out['status'], out['exit_code'], out['reason_code']),
                         ('partial', 2, 'ISSUE_METADATA_OBSERVED'), out)
        self.assertEqual(out['issue_existence'], 'SYNTHETIC_FIXTURE_PRESENT')
        self.assertFalse(out['issue_or_provider_written'])
        self.assertFalse(out['native_issue_action_registered'])
        self.assertFalse(out['issue_sync_performed'])
        self.assertFalse(out['organizational_grant_authenticated'])
        return out['source']

    def denied(self, out, reason, *, invalid=False):
        self.assertEqual(out['status'], 'invalid_input' if invalid else 'unavailable', out)
        self.assertEqual(out['reason_code'], 'ISSUE_' + reason, out)
        self.assertEqual(out['exit_code'], 4 if invalid else 5)
        self.assertEqual(out['read_state'], 'UNKNOWN')
        self.assertEqual(out['issue_existence'], 'UNKNOWN')
        self.assertIsNone(out['source'])

    def test_github_stable_ids_and_bounded_three_get(self):
        out, tr = call()
        result = self.accepted(out)
        self.assertEqual(result['identity']['provider_repository_id'], '73142')
        self.assertEqual(result['identity']['provider_issue_id'], '500421')
        self.assertEqual(result['identity']['issue_number'], 17)
        self.assertEqual(result['provider_state'], 'OPEN')
        self.assertEqual(result['origin'], 'synthetic_fixture')
        self.assertFalse(result['snapshot_atomic'])
        self.assertRegex(result['identity_sha256'], r'^[0-9a-f]{64}$')
        self.assertRegex(result['snapshot_sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual([u for u, _, _ in tr.calls], [
            'https://api.github.com/repos/example/repo',
            'https://api.github.com/repos/example/repo/issues/17',
            'https://api.github.com/repos/example/repo'])
        self.assertTrue(all(h['Authorization'].startswith('Bearer ') and
                            h['Accept-Encoding'] == 'identity' for _, h, _ in tr.calls))
        self.assertNotIn('SYNTHETIC-TOKEN-NOT-PRINTED', json.dumps(out))
        self.assertNotIn('SYNTHETIC private title', json.dumps(out))
        self.assertNotIn('NOT-A-REAL-SECRET', json.dumps(out))

    def test_gitlab_project_id_endpoint_and_confidential_redaction(self):
        out, tr = call('gitlab')
        source = self.accepted(out)
        self.assertEqual(source['identity']['provider_repository_id'], '903210')
        self.assertEqual(source['identity']['provider_issue_id'], '812065')
        self.assertEqual(source['provider_confidentiality'], 'CONFIDENTIAL')
        self.assertEqual([x[0] for x in tr.calls], [
            'https://gitlab.com/api/v4/projects/team%2Fsubteam%2Fservice',
            'https://gitlab.com/api/v4/projects/903210/issues/17',
            'https://gitlab.com/api/v4/projects/team%2Fsubteam%2Fservice'])
        self.assertNotIn('SYNTHETIC private GitLab', json.dumps(out))
        self.assertNotIn('SYNTHETIC restricted description', json.dumps(out))
        self.assertNotIn('SYNTHETIC-TOKEN', json.dumps(out))

    def test_metadata_snapshots_change_only_on_allowlisted_fields(self):
        first = self.accepted(call()[0])
        changed = sample('github_issue')
        changed['title'] += ' edited'
        edited = self.accepted(call(issue=changed)[0])
        self.assertEqual(first['identity_sha256'], edited['identity_sha256'])
        self.assertNotEqual(first['snapshot_sha256'], edited['snapshot_sha256'])
        changed = sample('github_issue')
        changed['body'] = 'another private value'
        self.assertNotEqual(first['snapshot_sha256'], self.accepted(call(issue=changed)[0])['snapshot_sha256'])
        changed = sample('github_issue')
        changed['labels'].reverse()
        self.assertEqual(first['snapshot_sha256'], self.accepted(call(issue=changed)[0])['snapshot_sha256'])
        changed['irrelevant_actor_token'] = 'SENSITIVE-WILL-NOT-PUBLISH'
        x = self.accepted(call(issue=changed)[0])
        self.assertEqual(first['snapshot_sha256'], x['snapshot_sha256'])
        self.assertNotIn('SENSITIVE-WILL-NOT-PUBLISH', json.dumps(x))

    def test_stable_identity_hash_ignores_repository_path_rename(self):
        # Same stable GH numeric repo and Issue ID under a renamed, still
        # explicit locator; metadata fingerprint may change but identity must not.
        first = self.accepted(call()[0])
        repo = sample('github_repository')
        repo['full_name'] = 'new-owner/repo'
        issue = sample('github_issue')
        issue['repository_url'] = 'https://api.github.com/repos/new-owner/repo'
        renamed = self.accepted(call(repo=repo, issue=issue,
                                     selection=selected(repository='new-owner/repo'))[0])
        self.assertEqual(first['identity_sha256'], renamed['identity_sha256'])
        self.assertNotEqual(first['snapshot_sha256'], renamed['snapshot_sha256'])

    def test_grant_expiry_rechecked_after_three_gets(self):
        c, s = context(), selected()
        stamps = iter([FROZEN, FROZEN + timedelta(seconds=121)])
        out = ip.read_issue(c, s, grant=grant(c, s), allow_network=True,
                            transport=FakeTransport(), clock=lambda: next(stamps),
                            token_supplier=lambda: 'synthetic')
        self.denied(out, 'READ_GRANT_EXPIRED_OR_TOO_BROAD')

    def test_github_closed_state_and_timestamps(self):
        issue = sample('github_issue')
        issue.update(state='closed', state_reason='completed',
                     updated_at='2026-07-06T09:00:00Z', closed_at='2026-07-05T09:00:00Z')
        s = self.accepted(call(issue=issue)[0])
        self.assertEqual(s['provider_state'], 'CLOSED')
        self.assertTrue(s['provider_closed_at_utc'].endswith('Z'))

    def test_no_network_default_and_no_credential_touch(self):
        c, s = context(), selected()
        out = ip.read_issue(c, s, grant=grant(c, s), token_supplier=lambda: self.fail('token read'))
        self.denied(out, 'NETWORK_NOT_AUTHORIZED')
        out = ip.read_issue(c, s, allow_network=True,
                            token_supplier=lambda: self.fail('token read'))
        self.denied(out, 'READ_GRANT_REQUIRED')

    def test_context_missing_or_host_untrusted(self):
        for c, reason, invalid in [
            (context(account=''), 'ACCOUNT_CONTEXT_UNAVAILABLE', False),
            (context(host='127.0.0.1'), 'HOST_NOT_ALLOWED', True),
            (context(host='api.github.com.evil.org'), 'HOST_NOT_ALLOWED', True),
            (context(provider='gitea', host='gitea.com'), 'PROVIDER_UNSUPPORTED', True),
        ]:
            with self.subTest(context=c):
                out = ip.read_issue(c, selected(), allow_network=True,
                                    token_supplier=lambda: self.fail('credential read'))
                self.denied(out, reason, invalid=invalid)

    def test_invalid_path_and_selection_rejected_before_credentials(self):
        for repository in ['https://github.com/a/b', 'owner', 'owner/../repo',
                           'owner//repo', 'owner/repo?x=1', '.git/repo',
                           'owner/repo%2Fother', 'owner/repo\nX', 'owner/..']:
            with self.subTest(repo=repository):
                out = ip.read_issue(context(), selected(repository=repository),
                                    allow_network=True,
                                    token_supplier=lambda: self.fail('credentials'))
                self.denied(out, 'REPOSITORY_INVALID', invalid=True)
        for n in (0, -1, True, 2**31, '17'):
            out = ip.read_issue(context(), selected(number=n), allow_network=True)
            self.denied(out, 'ISSUE_NUMBER_INVALID', invalid=True)
        for rid in (True, -1, 0, 2**64):
            out = ip.read_issue(context(), selected(repo_id=rid), allow_network=True)
            self.denied(out, 'REPOSITORY_ID_INVALID', invalid=True)

    def test_grant_must_be_exact_and_short_lived(self):
        c, s = context(), selected()
        for alteration, reason in [
            ({'method': 'CREATE_ISSUE'}, 'READ_GRANT_REQUIRED'),
            ({'authorized': False}, 'READ_GRANT_REQUIRED'),
            ({'allow_write': True}, 'READ_GRANT_REQUIRED'),
            ({'account_ref': 'wrong'}, 'READ_GRANT_SCOPE_MISMATCH'),
            ({'repository': 'different/repo'}, 'READ_GRANT_SCOPE_MISMATCH'),
            ({'number': 18}, 'READ_GRANT_SCOPE_MISMATCH'),
            ({'provider': 'gitlab'}, 'READ_GRANT_SCOPE_MISMATCH'),
            ({'expires_at_utc': (FROZEN-timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')},
             'READ_GRANT_EXPIRED_OR_TOO_BROAD'),
            ({'expires_at_utc': (FROZEN+timedelta(hours=1)).isoformat().replace('+00:00', 'Z')},
             'READ_GRANT_EXPIRED_OR_TOO_BROAD'),
        ]:
            with self.subTest(alteration=alteration):
                out = ip.read_issue(c, s, grant=grant(c, s, **alteration), allow_network=True,
                                    token_supplier=lambda: self.fail('credentials'),
                                    clock=lambda: FROZEN)
                self.denied(out, reason)

    def test_invalid_credentials_supplier_cannot_leak(self):
        c, s = context(), selected()
        for supplier in (lambda: None, lambda: 'abc\r\nAuthorization: leaked',
                         lambda: 123, lambda: (_ for _ in ()).throw(RuntimeError('MY-PRIVATE-TOKEN'))):
            out = ip.read_issue(c, s, grant=grant(c, s), allow_network=True,
                                token_supplier=supplier, clock=lambda: FROZEN)
            self.denied(out, 'CREDENTIALS_UNAVAILABLE')
            self.assertNotIn('MY-PRIVATE-TOKEN', json.dumps(out))

    def test_repository_expected_id_and_identity_mismatch(self):
        out, _ = call(selection=selected(repo_id=73143))
        self.denied(out, 'REPOSITORY_ID_MISMATCH')
        repo = sample('github_repository')
        repo['full_name'] = 'other/repo'
        self.denied(call(repo=repo)[0], 'REPOSITORY_LOCATOR_MISMATCH')
        issue = sample('github_issue')
        issue['repository_url'] = 'https://api.github.com/repos/other/repo'
        self.denied(call(issue=issue)[0], 'ISSUE_REPOSITORY_MISMATCH')
        issue = sample('github_issue')
        issue['number'] = 99
        self.denied(call(issue=issue)[0], 'ISSUE_IDENTITY_MISMATCH')
        issue['number'] = 17
        issue['id'] = True
        self.denied(call(issue=issue)[0], 'PROVIDER_METADATA_INCOMPLETE')

    def test_github_pr_must_not_masquerade_as_issue(self):
        issue = sample('github_issue')
        issue['pull_request'] = {'url':'https://api.github.com/repos/example/repo/pulls/17'}
        self.denied(call(issue=issue)[0], 'GITHUB_PULL_REQUEST_NOT_ISSUE')

    def test_repo_drift_before_after_denied(self):
        later = sample('github_repository')
        later['id'] = 93731
        self.denied(call(repo_after=later)[0], 'REPOSITORY_CHANGED_DURING_READ')
        later = sample('github_repository')
        later['full_name'] = 'renamed/repo'
        self.denied(call(repo_after=later)[0], 'REPOSITORY_LOCATOR_MISMATCH')

    def test_gitlab_issue_must_match_numeric_project_id_and_reference(self):
        issue = sample('gitlab_issue')
        issue['project_id'] = 81213
        self.denied(call('gitlab', issue=issue)[0], 'ISSUE_REPOSITORY_MISMATCH')
        issue = sample('gitlab_issue')
        issue['references']['full'] = 'other/path#17'
        self.denied(call('gitlab', issue=issue)[0], 'ISSUE_REPOSITORY_MISMATCH')

    def test_out_of_bounds_raw_text_no_fake_partial(self):
        for field, val in [('title', ''), ('body', 'x'*131073),
                           ('labels', [{'name': 'a'}]*101)]:
            issue = sample('github_issue')
            issue[field] = val
            out, _ = call(issue=issue)
            self.assertEqual(out['status'], 'unavailable')
            self.assertIsNone(out['source'])

    def test_duplicate_and_nonfinite_json_denied(self):
        for raw in (b'{"id":1,"id":2}', b'{"a":{"b":2,"b":3}}',
                    b'{"x":NaN}', b'[]', b'broken', b'\xff'):
            with self.subTest(raw=raw):
                with self.assertRaises(ip.IssueError):
                    ip._json_object(raw)

    def test_fixture_marker_never_accepts_live_or_fake_payload(self):
        r = sample('github_repository')
        r['_ces_fixture'] = True
        self.denied(call(repo=r)[0], 'PROVIDER_PAYLOAD_INVALID')

    def test_transport_exception_sanitized_unknown(self):
        c, s = context(), selected()
        tr = FakeTransport(RuntimeError('SUPERSECRET-MUST-BE-HIDDEN'))
        result = ip.read_issue(c, s, grant=grant(c, s), allow_network=True,
                               token_supplier=lambda: 'secret', transport=tr,
                               clock=lambda: FROZEN)
        self.denied(result, 'PROVIDER_READ_FAILED')
        self.assertNotIn('SUPERSECRET', json.dumps(result))

    def test_404_does_not_prove_nonexistence(self):
        c, s = context(), selected()
        tr = FakeTransport(HTTPError('https://hidden', 404, 'secret', None, None))
        # FakeTransport surfaces raw HTTPError, but StrictTransport has the
        # deliberate 404 classification. Test classification without network.
        with patch.object(ip, 'build_opener') as op:
            opener = op.return_value
            opener.open.side_effect = HTTPError('https://hidden', 404, 'secret', None, None)
            result = ip.read_issue(c, s, grant=grant(c, s), allow_network=True,
                                   token_supplier=lambda: 'secret', clock=lambda: FROZEN)
            self.denied(result, 'ISSUE_UNKNOWN_OR_INACCESSIBLE')
        self.assertEqual(len(tr.calls), 0)

    def test_strict_endpoint_whitelist(self):
        for url in ['http://api.github.com/repos/a/b', 'https://127.0.0.1/issue',
                    'https://api.github.com.evil.org/repos/a/b',
                    'https://api.github.com/repos/a/b/issues/1?x=1',
                    'https://api.github.com/repos/a/b/issues/1/../../secrets',
                    'https://gitlab.com/api/v4/projects/a%2F..%2Fz',
                    'https://gitlab.com/api/v4/projects/123/hooks/2',
                    'https://api.github.com:443/repos/a/b']:
            with self.subTest(url=url):
                self.assertFalse(ip._valid_endpoint(url))

    def test_strict_real_transport_get_no_proxy_no_redirect_and_size_cap(self):
        outer = self
        class Response:
            status = 200
            headers = {'Content-Type':'application/json'}
            def geturl(self): return 'https://api.github.com/repos/example/repo'
            def read(self, length):
                outer.assertEqual(length, ip.MAX_BODY+1)
                return b'{"id":1}'
            def __enter__(self): return self
            def __exit__(self, *_): return None
        class Opener:
            def open(self, request, timeout):
                outer.assertEqual(request.get_method(), 'GET')
                outer.assertEqual(timeout, 2.0)
                return Response()
        with patch.object(ip, 'build_opener') as op:
            op.return_value = Opener()
            result = ip.StrictHTTPSIssueTransport().get_object(
                'https://api.github.com/repos/example/repo', {}, 2.0)
            self.assertEqual(result, {'id':1})
            args = op.call_args.args
            self.assertTrue(any(type(a) is ip.ProxyHandler and a.proxies == {} for a in args))
            self.assertTrue(any(type(a) is ip._NoRedirect for a in args))

    def test_cli_default_no_remote_access_and_valid_json(self):
        proc = subprocess.run([sys.executable, str(HERE / 'issue_provider.py'),
                               '--provider', 'github', '--repository', 'example/repo',
                               '--number', '17', '--json'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 5)
        result = json.loads(proc.stdout)
        self.assertIn(result['reason_code'], ('ISSUE_ACCOUNT_CONTEXT_UNAVAILABLE', 'ISSUE_NETWORK_NOT_AUTHORIZED'))
        self.assertEqual(proc.stderr, '')
        self.assertIsNone(result['source'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
