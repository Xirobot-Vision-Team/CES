#!/usr/bin/env python3
"""EC220 local synthetic regression: one selected Issue, no external calls."""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from urllib.error import HTTPError

import issue_provider as ip
import issue_create_write as cw
import issue_unknown_recheck as rc
import issue_existing_readonly as er

FIX = Path(__file__).resolve().parent / 'fixtures' / 'ec211'
NOW = datetime(2026, 10, 24, 12, 30, tzinfo=timezone.utc)
TOKEN = 'SYNTHETIC-ONLY-NOT-A-REAL-TOKEN'


def sample(name):
    return json.loads((FIX / (name + '.json')).read_text(encoding='utf-8'))


def stamp(dt):
    return dt.isoformat(timespec='seconds').replace('+00:00', 'Z')


class FakeGET:
    def __init__(self, provider='github'):
        if provider == 'github':
            self.repo = sample('github_repository')
            self.repo['has_issues'] = True
            self.issue = sample('github_issue')
        else:
            self.repo = sample('gitlab_project')
            self.repo['issues_enabled'] = True
            self.issue = sample('gitlab_issue')
        self.repo_after = copy.deepcopy(self.repo)
        self.failure_at = 0
        self.calls = []

    def get_object(self, url, headers, timeout):
        self.calls.append(('GET', url))
        if self.failure_at == len(self.calls):
            raise HTTPError(url, 404, 'hidden or private', {}, None)
        if len(self.calls) == 1:
            return copy.deepcopy(self.repo)
        if len(self.calls) == 2:
            return copy.deepcopy(self.issue)
        return copy.deepcopy(self.repo_after)


def params(provider='github', visibility='PRIVATE'):
    if provider == 'github':
        ctx, repo, rid, iid = ip.ProviderContext('github', 'api.github.com', 'slot-GH'), 'example/repo', 73142, 500421
    else:
        ctx, repo, rid, iid = ip.ProviderContext('gitlab', 'gitlab.com', 'slot-GL'), 'team/subteam/service', 903210, 812065
    sel = ip.IssueSelection(repo, 17, rid)
    fields = dict(method=er.READ_METHOD, provider=ctx.provider, api_host=ctx.api_host,
                  account_ref=ctx.account_ref, repository=repo,
                  expected_repository_id=rid, expected_issue_number=17,
                  expected_provider_issue_id=iid, visibility=visibility,
                  policy_revision_sha256='a'*64, audience='ces-ec220-audience',
                  expires_at_utc=stamp(NOW + timedelta(seconds=50)), authorized=True,
                  network_opt_in=True, read_issue_metadata_opt_in=True,
                  read_full_issue_content_opt_in=True,
                  read_private_or_confidential_opt_in=True,
                  provider_credentials_attested_by_host=True, allow_write=False)
    return ctx, sel, er.HostExistingReadAccess(**fields)


_DEFAULT_ACCESS = object()


def read(provider='github', *, access=_DEFAULT_ACCESS, sel=None, ctx=None, fake=None,
         clock=lambda: NOW, supplier=lambda: TOKEN, timeout=2):
    cc, ss, aa = params(provider)
    return er.read_existing_issue(ctx or cc, sel or ss, access=aa if access is _DEFAULT_ACCESS else access,
                                  token_supplier=supplier, transport=fake or FakeGET(provider),
                                  clock=clock, timeout=timeout)


class RouteTests(unittest.TestCase):
    GH = 'https://api.github.com/repos/example/repo'
    GL = 'https://gitlab.com/api/v4/projects/team%2Fsubteam%2Fservice'
    GLS = 'https://gitlab.com/api/v4/projects/903210/issues'

    def test_original_exact_provider_get_routes_stay_available(self):
        for profile in ('EC211_SELECTED', 'EC219_RECHECK', 'EC220_SELECTED'):
            with self.subTest(profile=profile):
                for url in (self.GH, self.GH+'/issues/17', self.GL, self.GLS+'/17'):
                    self.assertTrue(er.allow_issue_http('GET', url, profile=profile), url)
                self.assertFalse(er.allow_issue_http('GET', self.GH+'/issues', profile=profile))

    def test_recheck_requires_bounded_exact_sorted_paging(self):
        g = self.GH+'/issues?state=all&sort=created&direction=desc&per_page=50&page='
        l = self.GLS+'?scope=all&state=all&order_by=created_at&sort=desc&per_page=50&page='
        for i in range(1, 4):
            for url in (g+str(i), l+str(i)):
                self.assertTrue(er.allow_issue_http('GET', url, profile='EC219_RECHECK'))
                self.assertFalse(er.allow_issue_http('GET', url, profile='EC220_SELECTED'))
                self.assertFalse(er.allow_issue_http('GET', url, profile='EC211_SELECTED'))
        for url in (g+'4', g+'0', g+'01', l+'4', l+'01', g+'1&labels=bug',
                    self.GH+'/issues?page=1', self.GLS+'?scope=all&per_page=100&page=1'):
            self.assertFalse(er.allow_issue_http('GET', url, profile='EC219_RECHECK'), url)

    def test_only_ec218_can_classify_new_collection_post(self):
        for url in (self.GH+'/issues', self.GLS):
            self.assertTrue(er.allow_issue_http('POST', url, profile=er.PROFILE_CREATE))
            for profile in er.READ_PROFILES:
                self.assertFalse(er.allow_issue_http('POST', url, profile=profile))
        for url in (self.GH, self.GL):
            self.assertTrue(er.allow_issue_http('GET', url, profile=er.PROFILE_CREATE))
        self.assertFalse(er.allow_issue_http('GET', self.GH+'/issues/17', profile=er.PROFILE_CREATE))
        self.assertFalse(er.allow_issue_http('GET', self.GLS+'/17', profile=er.PROFILE_CREATE))

    def test_existing_issue_mutation_paths_cannot_become_create(self):
        for u in (self.GH+'/issues/17', self.GH+'/issues/17/comments',
                  self.GH+'/issues/17/labels', self.GH+'/issues/17/assignees',
                  self.GH+'/issues/17/lock', self.GH+'/issues/comments/232',
                  self.GH+'/issues/17/labels/bug', self.GH+'/issues/17/reactions',
                  self.GLS+'/17', self.GLS+'/17/notes', self.GLS+'/17/award_emoji',
                  self.GLS+'/17/participants', self.GLS+'/17/todo'):
            for verb in ('POST', 'PUT', 'PATCH', 'DELETE'):
                for profile in ('EC218_NEW_CREATE', 'EC219_RECHECK', 'EC220_SELECTED'):
                    with self.subTest(u=u, verb=verb, profile=profile):
                        self.assertFalse(er.allow_issue_http(verb, u, profile=profile))

    def test_general_issue_mutation_methods_rejected_even_collection(self):
        for u in (self.GH+'/issues', self.GLS):
            for verb in ('PATCH', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'post', 'PROPFIND'):
                self.assertFalse(er.allow_issue_http(verb, u, profile=er.PROFILE_CREATE))

    def test_label_assignee_search_pr_routes_not_authorized(self):
        for u in (self.GH+'/labels', self.GH+'/labels/security',
                  self.GH+'/assignees', self.GH+'/pulls/17', self.GH+'/issues/17/comments',
                  self.GH+'/issues/17/timeline', self.GH+'/issues/17/events',
                  self.GLS+'/17/notes', self.GLS+'/17/resource_label_events',
                  self.GLS+'/17/related_merge_requests', self.GLS+'/17/discussions',
                  self.GLS+'/17/labels', self.GH+'/issues/17?state=closed'):
            for profile in (*er.READ_PROFILES, er.PROFILE_CREATE):
                self.assertFalse(er.allow_issue_http('GET', u, profile=profile), u)

    def test_reject_url_confusion_encoded_paths_and_hosts(self):
        for u in ('http://api.github.com/repos/example/repo',
                  'https://evil.example/repos/example/repo',
                  'https://api.github.com.evil.org/repos/example/repo',
                  'https://api.github.com:443/repos/example/repo',
                  'https://u:p@api.github.com/repos/example/repo',
                  'https://api.github.com/repos/example/../repo',
                  'https://api.github.com/repos/example/%2Frepo',
                  'https://api.github.com/repos/example/repo/issues/017',
                  'https://api.github.com/repos/example/repo/issues/0',
                  'https://api.github.com/repos/example/repo/issues/999999999999',
                  'https://api.github.com/repos/example/repo#fragment',
                  self.GH+'?x=1', self.GH+'?x=1&method=POST',
                  self.GH+'/issues?state=all&sort=created&direction=desc&per_page=50&page=1%26x=1',
                  self.GL.replace('%2F', '%2f'),
                  'https://gitlab.com/api/v4/projects/903210/issues/17/../18',
                  'https://gitlab.com/api/v4/projects/903210/issues/17?iid=18',
                  self.GH+'\r\nX-METHOD:POST',
                  'https://api.github.com/repos/example\\repo',
                  'https://api.github.com/repos/example/repo/issues/17/labels'):
            for profile in (*er.READ_PROFILES, er.PROFILE_CREATE):
                self.assertFalse(er.allow_issue_http('GET', u, profile=profile), u)

    def test_method_override_and_forwarding_headers_rejected(self):
        for k in er.BANNED_HEADERS:
            with self.subTest(k=k):
                self.assertFalse(er.allow_issue_http('GET', self.GH, profile='EC220_SELECTED',
                                                     headers={k.upper(): 'PATCH'}))
        self.assertFalse(er.allow_issue_http('GET', self.GH, profile='EC220_SELECTED',
                                             headers={'Accept': 'ok', 'accept': 'yes'}))
        self.assertFalse(er.allow_issue_http('GET', self.GH, profile='EC220_SELECTED',
                                             headers={'Accept': 'yes\r\nX-Method:POST'}))
        self.assertTrue(er.allow_issue_http('GET', self.GH, profile='EC220_SELECTED',
                                            headers={'Authorization': 'Bearer '+TOKEN,
                                                     'Accept-Encoding': 'identity'}))

    def test_transport_legacy_ec211_ec218_ec219_use_shared_gate(self):
        self.assertFalse(ip._valid_endpoint(self.GH+'/issues/17/comments'))
        self.assertFalse(cw._allowed_url(self.GH+'/issues/17', 'POST'))
        self.assertFalse(cw._allowed_url(self.GLS+'/17/notes', 'POST'))
        self.assertFalse(rc._allowed_get(self.GH+'/issues/17/comments'))
        self.assertTrue(rc._allowed_get(self.GH+'/issues?state=all&sort=created&direction=desc&per_page=50&page=1'))
        with self.assertRaises(ip.IssueError):
            ip.StrictHTTPSIssueTransport().get_object(self.GH,
                {'X-HTTP-Method-Override': 'DELETE'}, 2)
        with self.assertRaises(cw.WriteError):
            cw.StrictHTTPSIssueCreateTransport().post_create(
                self.GH+'/issues/17/comments', {}, b'{}', 1)
        with self.assertRaises(rc.RecheckError):
            rc.StrictHTTPSIssueReadTransport().get_json(
                self.GH, {'X-Original-URL': 'https://example.com'}, 1)


class ExistingIssueReadTests(unittest.TestCase):
    def test_github_private_pinned_read_three_get_and_redaction(self):
        fake = FakeGET()
        out = read(fake=fake)
        self.assertEqual((out['status'], out['exit_code'], out['read_state']),
                         ('partial', 2, 'SYNTHETIC_PINNED_ISSUE_OBSERVED'), out)
        self.assertEqual(out['provider_get_count'], 3)
        self.assertEqual([x[0] for x in fake.calls], ['GET']*3)
        self.assertEqual(out['source']['privacy'], 'NOT_REPORTED')
        self.assertEqual(out['source']['provider_state'], 'OPEN')
        self.assertNotIn('SYNTHETIC private title', json.dumps(out))
        self.assertNotIn('NOT-A-REAL-SECRET', json.dumps(out))
        self.assertNotIn('example/repo', json.dumps(out))
        self.assertNotIn(TOKEN, json.dumps(out))
        self.assertTrue(out['source']['repository_identity_double_checked'])
        self.assertFalse(out['issue_mutated'])
        self.assertFalse(out['absence_proven'])
        self.assertFalse(out['provider_token_scope_independently_verified'])

    def test_gitlab_confidential_pinned_read(self):
        out = read('gitlab')
        self.assertEqual(out['status'], 'partial', out)
        self.assertEqual(out['source']['privacy'], 'CONFIDENTIAL')
        self.assertNotIn('SYNTHETIC restricted description', json.dumps(out))
        self.assertEqual(out['provider_get_count'], 3)

    def test_public_github_scope_no_private_flag_allowed(self):
        c, s, a = params(visibility='PUBLIC')
        fake = FakeGET()
        fake.repo['private'] = fake.repo_after['private'] = False
        out = read(access=replace(a, read_private_or_confidential_opt_in=False), fake=fake)
        self.assertEqual(out['status'], 'partial', out)

    def test_gitlab_requires_confidential_preconsent_even_in_public_project(self):
        c, s, a = params('gitlab', 'PUBLIC')
        fake = FakeGET('gitlab')
        fake.repo['visibility'] = fake.repo_after['visibility'] = 'public'
        out = read('gitlab', access=replace(a, read_private_or_confidential_opt_in=False), fake=fake)
        self.assertEqual(out['status'], 'unavailable')
        self.assertEqual(out['provider_get_count'], 0)

    def test_private_read_without_privacy_grant_has_zero_get(self):
        c, s, a = params()
        out = read(access=replace(a, read_private_or_confidential_opt_in=False))
        self.assertEqual(out['provider_get_count'], 0)
        self.assertEqual(out['issue_existence'], 'UNKNOWN')

    def test_missing_full_content_permission_never_reaches_provider(self):
        c, s, a = params()
        for field in ('read_full_issue_content_opt_in', 'network_opt_in',
                      'read_issue_metadata_opt_in', 'provider_credentials_attested_by_host'):
            out = read(access=replace(a, **{field: False}))
            self.assertEqual(out['provider_get_count'], 0, field)
            self.assertEqual(out['status'], 'unavailable')

    def test_legacy_create_grant_and_old_metadata_read_cannot_replay(self):
        c, s, a = params()
        old_read = ip.IssueReadGrant(ip.METHOD, c.provider, c.api_host, c.account_ref,
                                     s.repository, s.number, stamp(NOW+timedelta(seconds=30)),
                                     True, False)
        old_create = cw.HostCreateAccess(c.provider, c.api_host, c.account_ref,
                                          s.repository, s.expected_repository_id, 'PRIVATE',
                                          'a'*64, 'ces-ec220-audience',
                                          stamp(NOW+timedelta(seconds=30)), True, True, True)
        for legacy in (old_read, old_create, {'authorized': True}, None):
            out = read(access=legacy)
            self.assertEqual(out['provider_get_count'], 0)
            self.assertEqual(out['read_state'], 'UNKNOWN')

    def test_grant_wrong_method_write_flag_scope_and_account(self):
        c, s, a = params()
        for change in (dict(method='CREATE_NEW_ISSUE'), dict(allow_write=True),
                       dict(authorized=False), dict(provider='gitlab'),
                       dict(api_host='evil.example'), dict(account_ref='other-slot'),
                       dict(repository='Example/Repo'), dict(expected_repository_id=99),
                       dict(expected_issue_number=18), dict(expected_provider_issue_id=1234),
                       dict(policy_revision_sha256='bad'), dict(audience='bad space')):
            out = read(access=replace(a, **change))
            if 'expected_provider_issue_id' in change:
                self.assertEqual(out['provider_get_count'], 2)
            else:
                self.assertEqual(out['provider_get_count'], 0, change)

    def test_expired_overlong_and_future_access(self):
        c, s, a = params()
        for expiry in (NOW - timedelta(seconds=1), NOW, NOW + timedelta(seconds=121)):
            out = read(access=replace(a, expires_at_utc=stamp(expiry)))
            self.assertEqual(out['provider_get_count'], 0)

    def test_credential_supplier_failure_never_gets(self):
        for supply in (None, lambda: None, lambda: 'bad\ncredential',
                       lambda: (_ for _ in ()).throw(RuntimeError('secret info'))):
            out = read(supplier=supply)
            self.assertEqual(out['provider_get_count'], 0)
            self.assertNotIn('secret info', json.dumps(out))

    def test_credential_not_provided_from_environment(self):
        out = er.read_existing_issue(*params()[:2], access=params()[2],
                                     token_supplier=None, transport=FakeGET(), clock=lambda: NOW)
        self.assertEqual(out['provider_get_count'], 0)

    def test_repo_id_name_visibility_and_feature_must_match(self):
        for diff in ({'id': 999}, {'full_name': 'Example/Repo'},
                     {'private': False}, {'has_issues': False},
                     {'has_issues': None}):
            fake = FakeGET();fake.repo.update(diff)
            out = read(fake=fake)
            self.assertEqual(out['provider_get_count'], 1, diff)
            self.assertEqual(out['issue_existence'], 'UNKNOWN', diff)

    def test_repo_after_issue_drift_fails_closed(self):
        for diff in ({'id': 999}, {'private': False},
                     {'full_name': 'example/REPO'}, {'has_issues': None}):
            fake = FakeGET();fake.repo_after.update(diff)
            out = read(fake=fake)
            self.assertEqual(out['provider_get_count'], 3, diff)
            self.assertEqual(out['issue_existence'], 'UNKNOWN')

    def test_gl_confidential_and_repository_changes_unknown(self):
        for diff in ({'visibility': 'public'}, {'issues_enabled': None},
                     {'path_with_namespace': 'team/subteam/Service'}):
            fake = FakeGET('gitlab');fake.repo.update(diff)
            out = read('gitlab', fake=fake)
            self.assertEqual(out['provider_get_count'], 1)
            self.assertEqual(out['read_state'], 'UNKNOWN')

    def test_github_pull_request_must_not_be_counted_as_issue(self):
        fake = FakeGET();fake.issue['pull_request'] = {'url': 'https://api.github.com/...'}
        out = read(fake=fake)
        self.assertEqual(out['provider_get_count'], 2)
        self.assertEqual(out['issue_existence'], 'UNKNOWN')
        self.assertEqual(out['status'], 'unavailable')

    def test_distinguish_global_issue_id_vs_local_number(self):
        fake = FakeGET();fake.issue['id'] = 17
        self.assertEqual(read(fake=fake)['provider_get_count'], 2)
        c, s, a = params()
        fixed = FakeGET(); fixed.issue['id'] = 17
        self.assertEqual(read(access=replace(a, expected_provider_issue_id=17),
                              fake=fixed)['status'], 'partial')

    def test_gitlab_iid_is_not_global_id_or_merge_request_iid(self):
        fake = FakeGET('gitlab')
        fake.issue['iid'] = fake.issue['id']
        out = read('gitlab', fake=fake)
        self.assertEqual(out['issue_existence'], 'UNKNOWN')
        self.assertEqual(out['provider_get_count'], 2)
        fake = FakeGET('gitlab');fake.issue['project_id'] = 10
        self.assertEqual(read('gitlab', fake=fake)['issue_existence'], 'UNKNOWN')

    def test_missing_hidden_private_404_is_unknown_not_absent(self):
        for point in (1, 2, 3):
            fake = FakeGET();fake.failure_at = point
            out = read(fake=fake)
            self.assertEqual(out['provider_get_count'], point)
            self.assertEqual(out['issue_existence'], 'UNKNOWN')
            self.assertFalse(out['absence_proven'])
            self.assertFalse(out['hidden_issues_ruled_out'])

    def test_grant_expiring_during_get_stops_before_next_get(self):
        c, s, a = params()
        steps = [NOW, NOW, NOW + timedelta(seconds=51)]
        def tick(): return steps.pop(0) if steps else NOW + timedelta(seconds=51)
        fake = FakeGET()
        out = read(access=a, fake=fake, clock=tick)
        self.assertEqual(out['provider_get_count'], 1)
        self.assertEqual(out['read_state'], 'UNKNOWN')

    def test_no_live_network_with_injected_clock(self):
        c, s, a = params()
        out = er.read_existing_issue(c, s, access=a, token_supplier=lambda: TOKEN,
                                      transport=None, clock=lambda: NOW)
        self.assertEqual(out['provider_get_count'], 0)
        self.assertEqual(out['issue_existence'], 'UNKNOWN')

    def test_large_body_or_unserializable_response_never_exposes_text(self):
        fake = FakeGET();fake.issue['body'] = 'secret '+ ('Z'* (1024*1024))
        out = read(fake=fake)
        self.assertEqual(out['read_state'], 'UNKNOWN')
        self.assertNotIn('secret ', json.dumps(out))

    def test_result_no_content_and_no_permission_to_change_labels_or_state(self):
        out = read()
        self.assertIsNotNone(out['source'])
        for k in ('issue_mutated','issue_closed','issue_reopened','comment_created',
                  'labels_changed','assignees_changed','existing_issue_edit_authorized',
                  'provider_post_invoked','new_issue_created','absence_proven'):
            self.assertIs(out[k], False, k)
        self.assertEqual(out['source']['title_body_labels_disclosed'], False)


if __name__ == '__main__':
    unittest.main()
