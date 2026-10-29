#!/usr/bin/env python3
"""EC214 local synthetic capability tests; not actual provider/org/native acceptance."""
from __future__ import annotations

import copy
from dataclasses import replace, asdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import unittest

import issue_provider as ip
import issue_match as match

FIXTURES = Path(__file__).parent / 'fixtures' / 'provider_issues'
NOW = datetime(2026, 10, 24, 9, 0, tzinfo=timezone.utc)
TOKEN = 'EC214-SYNTHETIC-SECRET-NOT-REAL'


def fixture(name):
    return json.loads((FIXTURES / (name + '.json')).read_text('utf-8'))


def context(provider='github'):
    return ip.ProviderContext(provider, ip.API_HOST[provider], 'fixture-account')


def anchor(**kw):
    val = dict(commit_sha='a' * 40, path='src/core/logic.py',
               line_start=10, line_end=20, evidence_sha256='b' * 64)
    val.update(kw)
    return match.EvidenceAnchor(**val)


def request(provider='github', *, n=2, title=None, privacy=('STANDARD',),
            title_policy='DISABLED', subject_anchors=(), anchors=None, max_age=120):
    base = 500421 if provider == 'github' else 812065
    c = tuple(match.MatchCandidate(17 + i, base + i,
                                   anchors[i] if anchors else ())
              for i in range(n))
    return match.IssueMatchRequest(
        'example/repo' if provider == 'github' else 'team/subteam/service',
        73142 if provider == 'github' else 903210, c,
        subject_anchors=subject_anchors, subject_title=title,
        title_policy=title_policy, title_privacies=privacy,
        max_observation_age_seconds=max_age)


def expiry(seconds=180):
    return (NOW + timedelta(seconds=seconds)).isoformat(timespec='seconds').replace('+00:00', 'Z')


def grants(ctx, req, *, expires=None):
    digest = match.request_fingerprint(ctx, req)
    kwargs = dict(provider=ctx.provider, api_host=ctx.api_host,
                  account_ref=ctx.account_ref, repository=req.repository,
                  expected_repository_id=req.expected_repository_id,
                  candidate_pins=tuple((c.number, c.expected_provider_issue_id)
                                       for c in req.candidates),
                  request_sha256=digest, expires_at_utc=expires or expiry(),
                  authorized=True)
    mg = match.IssueMatchGrant(method=match.METHOD, **kwargs)
    tg = (match.IssueTitleGrant(method=match.TITLE_METHOD,
                                allowed_privacies=req.title_privacies, **kwargs)
          if req.title_policy == 'AUTHORIZED' else None)
    rg = {c.number: ip.IssueReadGrant(
        ip.METHOD, ctx.provider, ctx.api_host, ctx.account_ref,
        req.repository, c.number, expires or expiry(), True)
        for c in req.candidates}
    return mg, tg, rg


class FakeBatch:
    def __init__(self, provider, req, *, problems=None, privacy=None, titles=None,
                 repo_name=None):
        self.steps = []
        self.calls = []
        self._phase = 0
        problems = problems or {}
        titles = titles or {}
        for c in req.candidates:
            repo = fixture('github_repository' if provider == 'github' else 'gitlab_project')
            issue = fixture(provider + '_issue')
            if repo_name is not None:
                repo['full_name' if provider == 'github' else 'path_with_namespace'] = repo_name
            issue['id'] = c.expected_provider_issue_id
            issue['number' if provider == 'github' else 'iid'] = c.number
            if provider == 'gitlab':
                issue['references']['full'] = f'{req.repository}#{c.number}'
                if privacy is not None:
                    issue['confidential'] = privacy
            if c.number in titles:
                issue['title'] = titles[c.number]
            seq = [repo, issue, repo]
            if c.number in problems:
                seq[problems[c.number][0]] = problems[c.number][1]
            self.steps += [copy.deepcopy(x) if not isinstance(x, Exception) else x for x in seq]

    def get_object(self, url, headers, timeout):
        self.calls.append((url, headers, timeout))
        if not self.steps:
            raise AssertionError('unexpected fourth GET')
        obj = self.steps.pop(0)
        self._phase += 1
        if isinstance(obj, Exception):
            # Each Issue is an independent three-GET attempt. If GET 1 or 2
            # fails, the provider reader will skip the remaining GET(s).
            self.steps = self.steps[3 - self._phase:]
            self._phase = 0
            raise obj
        if self._phase == 3:
            self._phase = 0
        return copy.deepcopy(obj)


def execute(provider='github', *, req=None, mg=None, tg=None, rg=None,
            transport=None, clock=None, allow_network=True,
            supplier=None, timeout=8.0):
    ctx = context(provider)
    req = req or request(provider)
    base_mg, base_tg, base_rg = grants(ctx, req)
    transport = transport if transport is not None else FakeBatch(provider, req)
    out = match.match_issues(
        ctx, req,
        match_grant=base_mg if mg is None else mg,
        title_grant=base_tg if tg is None else tg,
        issue_read_grants=base_rg if rg is None else rg,
        allow_network=allow_network, transport=transport,
        token_supplier=supplier or (lambda: TOKEN),
        clock=clock or (lambda: NOW), timeout=timeout)
    return out, transport


class IssueMatchTests(unittest.TestCase):
    def assert_safe(self, result):
        raw = json.dumps(result, sort_keys=True)
        for secret in (TOKEN, 'SYNTHETIC private title', 'SYNTHETIC private GitLab',
                       'SYNTHETIC body', 'NOT-A-REAL-SECRET', 'type:bug',
                       'redteam private', 'private project detail'):
            self.assertNotIn(secret, raw)
        for name in ('potential_duplicate_confirmed', 'no_duplicate_confirmed',
                     'evidence_anchors_provider_authenticated',
                     'organizational_grant_authenticated', 'title_or_description_disclosed',
                     'full_repository_inventory', 'snapshot_atomic',
                     'raw_issue_content_persisted', 'external_ai_or_embedding_service_used',
                     'native_issue_action_registered', 'issue_or_provider_written',
                     'business_repository_written', 'knowledge_source_written',
                     'external_cache_mutated', 'issue_created'):
            self.assertIs(result[name], False, (name, result))
        self.assertTrue(all(not e['confirmed_duplicate'] for e in result['entries']))

    def test_github_selected_exact_pins_and_six_get_limit(self):
        out, fake = execute()
        self.assertEqual(out['status'], 'partial', out)
        self.assertEqual(out['coverage'], 'COMPLETE_EXPLICIT_SELECTION_NONATOMIC')
        self.assertEqual([e['number'] for e in out['entries']], [17, 18])
        self.assertEqual(len(fake.calls), 6)
        self.assertEqual(out['maximum_possible_provider_gets'], 6)
        self.assertEqual([u[0] for u in fake.calls], [
            'https://api.github.com/repos/example/repo',
            'https://api.github.com/repos/example/repo/issues/17',
            'https://api.github.com/repos/example/repo',
            'https://api.github.com/repos/example/repo',
            'https://api.github.com/repos/example/repo/issues/18',
            'https://api.github.com/repos/example/repo'])
        self.assertTrue(all(call[2] == 8.0 for call in fake.calls))
        self.assertTrue(all(e['review_hint'] == 'NO_POSITIVE_SIGNAL' for e in out['entries']))
        self.assert_safe(out)

    def test_evidence_exact_anchor_is_review_hint_only(self):
        req = request(subject_anchors=(anchor(),), anchors=((anchor(),), ()))
        out, _ = execute(req=req)
        self.assertEqual(out['review_candidate_count'], 1)
        self.assertEqual(out['entries'][0]['anchor_matches'], 1)
        self.assertEqual(out['entries'][0]['review_hint'], 'REVIEW_CANDIDATE')
        self.assertEqual(out['entries'][1]['anchor_matches'], 0)
        self.assert_safe(out)

    def test_changing_commit_line_path_or_digest_no_anchor_hit(self):
        for altered in (dict(commit_sha='c'*40), dict(line_start=11),
                        dict(path='src/other.py'), dict(evidence_sha256='d'*64)):
            with self.subTest(altered=altered):
                changed = anchor(**altered)
                req = request(subject_anchors=(anchor(),), anchors=((changed,), ()))
                out, _ = execute(req=req)
                self.assertEqual(out['review_candidate_count'], 0)

    def test_github_default_private_classification_withholds_title(self):
        req = request(n=1, title_policy='AUTHORIZED',
                      title='SYNTHETIC private title never return to caller')
        out, _ = execute(req=req)
        self.assertEqual(out['entries'][0]['title_similarity_hint'],
                         'WITHHELD_BY_PRIVACY_POLICY')
        self.assertEqual(out['review_candidate_count'], 0)
        self.assert_safe(out)

    def test_github_explicit_not_reported_title_opt_in(self):
        req = request(n=1, title_policy='AUTHORIZED',
                      title='SYNTHETIC private title never return to caller',
                      privacy=('STANDARD', 'NOT_REPORTED'))
        out, fake = execute(req=req)
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(out['entries'][0]['title_similarity_hint'],
                         'HIGH_LEXICAL_OVERLAP')
        self.assertEqual(out['entries'][0]['review_hint'], 'REVIEW_CANDIDATE')
        self.assert_safe(out)

    def test_gitlab_confidential_blocked_without_extra_privacy_permission(self):
        req = request('gitlab', n=1, title_policy='AUTHORIZED',
                      title='SYNTHETIC private GitLab title never return to caller')
        out, _ = execute('gitlab', req=req)
        self.assertEqual(out['entries'][0]['provider_confidentiality'], 'CONFIDENTIAL')
        self.assertEqual(out['entries'][0]['title_similarity_hint'], 'WITHHELD_BY_PRIVACY_POLICY')
        self.assert_safe(out)

    def test_gitlab_confidential_title_explicit_scope(self):
        req = request('gitlab', n=1, title_policy='AUTHORIZED',
                      privacy=('STANDARD', 'NOT_REPORTED', 'CONFIDENTIAL'),
                      title='SYNTHETIC private GitLab title never return to caller')
        out, _ = execute('gitlab', req=req)
        self.assertEqual(out['entries'][0]['title_similarity_hint'], 'HIGH_LEXICAL_OVERLAP')
        self.assert_safe(out)

    def test_gitlab_standard_title_allowed_default(self):
        req = request('gitlab', n=1, title_policy='AUTHORIZED',
                      title='SYNTHETIC private GitLab title never return to caller')
        out, _ = execute('gitlab', req=req, transport=FakeBatch('gitlab', req, privacy=False))
        self.assertEqual(out['entries'][0]['title_similarity_hint'], 'HIGH_LEXICAL_OVERLAP')

    def test_low_lexical_overlap_does_not_prove_absence(self):
        req = request('gitlab', n=1, title_policy='AUTHORIZED',
                      title='Different subsystem regression in storage')
        out, _ = execute('gitlab', req=req, transport=FakeBatch('gitlab', req, privacy=False))
        self.assertEqual(out['entries'][0]['title_similarity_hint'], 'LOW_LEXICAL_OVERLAP')
        self.assertEqual(out['entries'][0]['review_hint'], 'NO_POSITIVE_SIGNAL')
        self.assertFalse(out['no_duplicate_confirmed'])

    def test_cjk_lexical_overlap_and_width_normalization(self):
        self.assertEqual(match._title_hint('无法保存配置 文件', '配置文件无法保存'),
                         'HIGH_LEXICAL_OVERLAP')
        self.assertEqual(match._title_hint('ＡＢＣ configuration', 'abc configuration'),
                         'HIGH_LEXICAL_OVERLAP')

    def test_title_grant_missing_preflight_zero_reads_zero_token(self):
        req = request(n=1, title='redteam private', title_policy='AUTHORIZED')
        mg, tg, rg = grants(context(), req)
        calls = []
        out, tr = execute(req=req, tg=replace(tg, authorized=False), rg=rg,
                          supplier=lambda: calls.append('token') or TOKEN)
        self.assertEqual(out['reason_code'], 'ISSUE_MATCH_TITLE_GRANT_REQUIRED')
        self.assertEqual(len(tr.calls), 0)
        self.assertEqual(calls, [])

    def test_title_grant_cannot_substitute_match_grant(self):
        req = request(n=1, title='redteam private', title_policy='AUTHORIZED')
        out, tr = execute(req=req, mg=replace(grants(context(), req)[0], authorized=False))
        self.assertEqual(out['reason_code'], 'ISSUE_MATCH_MATCH_GRANT_REQUIRED')
        self.assertEqual(len(tr.calls), 0)

    def test_provider_per_issue_grants_required_before_first_read(self):
        req = request(n=2)
        mg, tg, rg = grants(context(), req)
        rg.pop(18)
        out, fake = execute(req=req, rg=rg)
        self.assertEqual(out['reason_code'], 'ISSUE_MATCH_PROVIDER_GRANTS_REQUIRED')
        self.assertEqual(len(fake.calls), 0)

    def test_read_grant_wrong_issue_or_account_rejected(self):
        req = request(n=2)
        mg, tg, rg = grants(context(), req)
        rg[18] = replace(rg[18], number=77)
        out, tr = execute(req=req, rg=rg)
        self.assertEqual(out['reason_code'], 'ISSUE_MATCH_PROVIDER_GRANT_INVALID')
        self.assertEqual(len(tr.calls), 0)

    def test_match_grant_fingerprint_detects_anchor_or_title_changes(self):
        req = request(n=1)
        mg, tg, rg = grants(context(), req)
        updated = replace(req, subject_anchors=(anchor(),))
        out, tr = execute(req=updated, mg=mg)
        self.assertEqual(out['reason_code'], 'ISSUE_MATCH_MATCH_GRANT_SCOPE_MISMATCH')
        self.assertEqual(len(tr.calls), 0)
        req2 = request(n=1, title_policy='AUTHORIZED', title='Secret')
        mg, tg, rg = grants(context(), req2)
        out, _ = execute(req=replace(req2, subject_title='secret-changed'), mg=mg)
        self.assertEqual(out['reason_code'], 'ISSUE_MATCH_MATCH_GRANT_SCOPE_MISMATCH')

    def test_title_grant_privacy_widen_fails_preflight(self):
        req = request(n=1, title_policy='AUTHORIZED', title='Secret')
        mg, tg, rg = grants(context(), req)
        out, tr = execute(req=req, mg=mg, tg=replace(tg, allowed_privacies=('STANDARD','CONFIDENTIAL')))
        self.assertEqual(out['reason_code'], 'ISSUE_MATCH_TITLE_GRANT_SCOPE_MISMATCH')
        self.assertEqual(len(tr.calls), 0)

    def test_too_long_grant_rejected(self):
        req = request(n=1)
        mg, tg, rg = grants(context(), req)
        out, tr = execute(req=req, mg=replace(mg, expires_at_utc=expiry(301)))
        self.assertEqual(out['reason_code'], 'ISSUE_MATCH_MATCH_GRANT_EXPIRED_OR_TOO_BROAD')
        self.assertEqual(len(tr.calls), 0)

    def test_expiry_after_last_read_discards_all(self):
        req = request(n=2, subject_anchors=(anchor(),), anchors=((anchor(),), ()))
        mg, tg, rg = grants(context(), req)
        times = [NOW] * 5 + [NOW + timedelta(seconds=200)] * 40
        def clock():
            return times.pop(0) if times else NOW + timedelta(seconds=200)
        out, _ = execute(req=req, clock=clock)
        self.assertEqual(out['status'], 'unavailable')
        self.assertEqual(out['entries'], [])
        self.assert_safe(out)

    def test_identity_drift_must_be_unknown_not_candidate(self):
        req = request(n=1, subject_anchors=(anchor(),), anchors=((anchor(),),))
        bad = fixture('github_issue')
        bad['id'] = 9000000
        out, _ = execute(req=req, transport=FakeBatch('github', req, problems={17:(1,bad)}))
        self.assertEqual(out['status'], 'unavailable')
        self.assertEqual(out['entries'][0]['state'], 'UNKNOWN')
        self.assertEqual(out['review_candidate_count'], 0)

    def test_case_only_repository_path_drift_unknown(self):
        req = request(n=1)
        out, _ = execute(req=req, transport=FakeBatch('github', req, repo_name='Example/repo'))
        self.assertEqual(out['entries'][0]['state'], 'UNKNOWN')
        self.assertEqual(out['coverage'], 'UNKNOWN')

    def test_service_hidden_404_is_unknown(self):
        req = request(n=1)
        ex = ip.IssueError('ISSUE_UNKNOWN_OR_INACCESSIBLE')
        out, tr = execute(req=req, transport=FakeBatch('github', req, problems={17:(1,ex)}))
        self.assertEqual(out['status'], 'unavailable')
        self.assertEqual(out['entries'][0]['state'], 'UNKNOWN')
        self.assertNotIn('ABSENT', json.dumps(out))
        self.assertEqual(len(tr.calls), 2)

    def test_failure_of_first_issue_does_not_suppress_later_selection(self):
        req = request(n=2, subject_anchors=(anchor(),), anchors=((), (anchor(),)))
        out, fake = execute(req=req, transport=FakeBatch('github', req, problems={
            17: (1, ip.IssueError('ISSUE_UNKNOWN_OR_INACCESSIBLE'))}))
        self.assertEqual(out['status'], 'partial')
        self.assertEqual([e['state'] for e in out['entries']],
                         ['UNKNOWN', 'OBSERVED_SELECTED_METADATA'])
        self.assertEqual(out['unknown_count'], 1)
        self.assertEqual(out['review_candidate_count'], 1)
        self.assertEqual(len(fake.calls), 5)
        self.assertFalse(out['potential_duplicate_confirmed'])

    def test_partial_selection_preserves_unknown_coverage(self):
        req = request(n=2, subject_anchors=(anchor(),), anchors=((anchor(),), (anchor(),)))
        ex = ip.IssueError('ISSUE_UNKNOWN_OR_INACCESSIBLE')
        out, fake = execute(req=req, transport=FakeBatch('github', req, problems={18:(1,ex)}))
        self.assertEqual(out['status'], 'partial')
        self.assertTrue(any(e['state'] == 'OBSERVED_SELECTED_METADATA' for e in out['entries']))
        self.assertGreaterEqual(out['unknown_count'], 1)
        self.assertFalse(out['no_duplicate_confirmed'])

    def test_provider_payload_invalid_unknown_and_redacted(self):
        req = request(n=1, title='redteam private', title_policy='AUTHORIZED',
                      privacy=('STANDARD','NOT_REPORTED'))
        issue = fixture('github_issue')
        issue['title'] = 42
        out, _ = execute(req=req, transport=FakeBatch('github', req, problems={17:(1,issue)}))
        self.assertEqual(out['entries'][0]['state'], 'UNKNOWN')
        self.assert_safe(out)

    def test_unauthorized_network_offline_is_zero_reads(self):
        out, tr = execute(allow_network=False)
        self.assertEqual(out['reason_code'], 'ISSUE_MATCH_NETWORK_NOT_AUTHORIZED')
        self.assertEqual(len(tr.calls), 0)

    def test_no_supplier_fails_safely(self):
        req = request(n=1)
        out, tr = execute(req=req, supplier=lambda: (_ for _ in ()).throw(RuntimeError(TOKEN)))
        self.assertEqual(out['reason_code'], 'ISSUE_MATCH_CREDENTIALS_UNAVAILABLE')
        self.assertEqual(len(tr.calls), 0)
        self.assert_safe(out)

    def test_freshness_rollforward_results_unknown(self):
        req = request(n=1, max_age=1)
        calls = [0]
        def tick_clock():
            calls[0] += 1
            return NOW if calls[0] <= 7 else NOW + timedelta(seconds=5)
        out, _ = execute(req=req, clock=tick_clock)
        self.assertEqual(out['entries'][0]['state'], 'UNKNOWN')
        self.assertEqual(out['entries'][0]['reason_code'],
                         'ISSUE_MATCH_OBSERVATION_STALE')
        self.assertEqual(out['status'], 'unavailable')
        self.assertEqual(out['review_candidate_count'], 0)

    def test_bad_scope_duplicate_candidate_pins_and_bad_anchors_invalid(self):
        req = request(n=1)
        for altered in (
            replace(req, candidates=(req.candidates[0], req.candidates[0])),
            replace(req, subject_anchors=(anchor(path='../escape'),)),
            replace(req, subject_anchors=(anchor(line_start=True),)),
            replace(req, subject_anchors=(anchor(), anchor())),
            replace(req, subject_title='bad\x00title'),
            replace(req, subject_title='title without enabled comparison'),
            replace(req, title_policy='AUTHORIZED'),
            replace(req, title_privacies=('NOT_REPORTED', 'STANDARD')),
        ):
            with self.subTest(altered=altered):
                out = match.match_issues(context(), altered, allow_network=False)
                self.assertEqual(out['status'], 'invalid_input', out)
                self.assertEqual(out['entries'], [])

    def test_weird_timeout_nan_bool_rejected_precredential(self):
        for timeout in (True, float('nan'), float('inf'), 0, 9):
            with self.subTest(timeout=timeout):
                out, tr = execute(timeout=timeout)
                self.assertEqual(out['reason_code'], 'ISSUE_MATCH_TIMEOUT_INVALID')
                self.assertEqual(len(tr.calls), 0)

    def test_issue_title_never_in_scope_even_when_observed(self):
        req = request('gitlab', n=1, title_policy='AUTHORIZED', title='redteam private',
                      privacy=('STANDARD','NOT_REPORTED','CONFIDENTIAL'))
        out, _ = execute('gitlab', req=req)
        self.assertNotIn('redteam private', json.dumps(out))
        self.assertNotIn('SYNTHETIC private GitLab title', json.dumps(out))
        self.assertNotIn('description', str(out.get('entries')))

    def test_draft2020_12_request_grant_and_result_contracts(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest('jsonschema unavailable in this environment')
        refs = Path(__file__).parent.parent / 'references'
        schemas = {}
        for key in ('request', 'grant', 'result'):
            name = 'issue-match-' + key + '.v1.schema.json'
            schemas[key] = json.loads((refs / name).read_text('utf-8'))
            jsonschema.Draft202012Validator.check_schema(schemas[key])
        for provider in ('github', 'gitlab'):
            for title_enabled in (False, True):
                req = request(provider, n=1,
                              title_policy='AUTHORIZED' if title_enabled else 'DISABLED',
                              title='SYNTHETIC private title' if title_enabled else None,
                              privacy=('STANDARD','NOT_REPORTED') if title_enabled else ('STANDARD',))
                ctx = context(provider)
                mg, tg, _ = grants(ctx, req)
                normalized = lambda x: json.loads(json.dumps(asdict(x)))
                jsonschema.validate(normalized(req), schemas['request'])
                jsonschema.validate(normalized(mg), schemas['grant'])
                if tg is not None:
                    jsonschema.validate(normalized(tg), schemas['grant'])
                out, _ = execute(provider, req=req)
                jsonschema.validate(out, schemas['result'])
        offline = match.match_issues(context(), request())
        jsonschema.validate(offline, schemas['result'])
        bad = match.match_issues(context(), replace(request(), candidates=()))
        jsonschema.validate(bad, schemas['result'])

    def test_offline_cli_refusal_json_only(self):
        proc = subprocess.run([
            sys.executable, str(Path(__file__).parent / 'issue_match.py'),
            '--provider', 'github', '--repository', 'example/repo',
            '--expected-repository-id', '73142', '--candidate', '17:500421'],
            capture_output=True, text=True, timeout=12)
        self.assertEqual(proc.returncode, 5, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out['read_state'], 'UNKNOWN')
        self.assertFalse(out['issue_or_provider_written'])
        self.assertNotIn(TOKEN, proc.stdout)


if __name__ == '__main__':
    unittest.main()
