#!/usr/bin/env python3
"""EC219 synthetic-only tests: no live provider, no external credentials, no POST."""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import jsonschema
import issue_create_grant as cg
import issue_create_write as cw
import issue_unknown_recheck as rc
from test_issue_create_grant import fixture, sign
from test_issue_eligibility import CURRENT, CLOCK, stamp
from test_issue_create_write import FakeCreateTransport, TEST_TOKEN


class FakeRead:
    def __init__(self, args):
        self.args = args
        self.get_count = 0
        self.urls = []
        self.events = []
        self.extra_rows = []
        self.no_match = False
        self.list_mismatch = None
        self.detail_mismatch = None
        self.repo_mismatch = None
        self.repo_after_mismatch = None
        self.error_url_fragment = None
        self.page_overflow = False

    def issue(self, *, number=45, id=4567, offset=1):
        intent, content = self.args['intent'], self.args['content']
        raw = {'id': id, 'created_at': stamp(CURRENT+timedelta(seconds=offset)),
               'title': content.title, 'labels': list(content.labels)}
        if intent.provider == 'github':
            raw.update(number=number, repository_url=rc._urls(intent),
                       url=rc._urls(intent, number=number), body=content.body,
                       state='open')
            raw['labels'] = [{'name': s} for s in content.labels]
        else:
            raw.update(iid=number, project_id=intent.expected_repository_id,
                       description=content.body, confidential=intent.visibility == 'PRIVATE',
                       state='opened')
        return raw

    def get_json(self, url, headers, timeout):
        self.get_count += 1
        self.urls.append(url)
        self.events.append(('GET', url))
        assert headers.get('PRIVATE-TOKEN') == TEST_TOKEN or \
            headers.get('Authorization') == 'Bearer ' + TEST_TOKEN
        assert headers.get('Cache-Control') == 'no-store'
        assert rc._allowed_get(url)
        if self.error_url_fragment and self.error_url_fragment in url:
            raise rc.RecheckError('PROVIDER_READ_HTTP_UNCERTAIN')
        intent = self.args['intent']
        if url == rc._urls(intent):
            obj = {'id': intent.expected_repository_id}
            if intent.provider == 'github':
                obj.update(full_name=intent.repository,
                           private=intent.visibility == 'PRIVATE', has_issues=True)
            else:
                obj.update(path_with_namespace=intent.repository,
                           visibility=intent.visibility.lower(), issues_enabled=True)
            if self.repo_mismatch:
                obj.update(self.repo_mismatch)
            if self.repo_after_mismatch and self.get_count > 1:
                obj.update(self.repo_after_mismatch)
            return rc.ReadResponse(obj, {})
        if '?state=' in url or '?scope=' in url:
            page = int(url.rsplit('page=', 1)[1])
            if self.page_overflow:
                return rc.ReadResponse([self.issue()] * 51, {})
            if page > 1:
                return rc.ReadResponse([], {})
            if self.no_match:
                return rc.ReadResponse([{'title': 'other issue'}], {})
            raw = self.issue()
            if self.list_mismatch:
                raw.update(self.list_mismatch)
            return rc.ReadResponse([raw, *self.extra_rows], {})
        raw = self.issue()
        if self.detail_mismatch:
            raw.update(self.detail_mismatch)
        return rc.ReadResponse(raw, {})


class EC219(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.args = fixture()
        self.approval = sign(self.args)
        self.ec217 = cg.SQLiteOneUseLedger(self.root/'ec217.db',
                                           self.args['intent'].audience)
        self.writer = cw.SQLiteCreateAttemptLedger(self.root/'ec218.db',
                                                    self.args['intent'].audience)
        self.reader = rc.SQLiteCreateAttemptReader(self.root/'ec218.db',
                                                   self.args['intent'].audience)
        self.ledger = rc.SQLiteRecheckLedger(self.root/'ec219.db',
                                             self.args['intent'].audience)
        self.remote = FakeRead(self.args)
        self.access = self.access_for(self.args)

    def access_for(self, args):
        i = args['intent']
        return rc.HostRecheckAccess(
            i.provider, i.api_host, i.account_ref, i.repository,
            i.expected_repository_id, i.visibility, i.policy_revision_sha256,
            i.audience, stamp(CURRENT+timedelta(seconds=70)), True, True, True,
            True, True)

    def create_prior(self, outcome='POST_UNKNOWN'):
        a = self.args
        reserved = cg.reserve_issue_create_grant(
            a['evidence'], a['intent'], a['content'], self.approval,
            trusted_eligibility_review_keys=a['trusted_eligibility_review_keys'],
            trusted_issuers=a['trusted_issuers'], ledger=self.ec217, clock=CLOCK)
        self.assertEqual(reserved['grant_state'], 'RESERVED_ONE_ATTEMPT')
        op = cw.operation_sha256(a['intent'])
        self.assertEqual(self.writer.atomic_start(
            op, self.approval.grant_id, self.approval.challenge_sha256, CURRENT), 'CLAIMED')
        if outcome != 'POSSIBLY_SENT':
            self.assertTrue(self.writer.record_outcome(
                op, self.approval.grant_id, outcome, None))
        return op

    def recheck(self, **kwargs):
        a = self.args
        kw = dict(
            trusted_eligibility_review_keys=a['trusted_eligibility_review_keys'],
            trusted_historical_issuers=a['trusted_issuers'],
            original_attempts=self.reader, observation_ledger=self.ledger,
            host_access=self.access, token_supplier=lambda: TEST_TOKEN,
            transport=self.remote, clock=CLOCK)
        kw.update(kwargs)
        return rc.recheck_unknown_issue(
            a['evidence'], a['intent'], a['content'],
            kw.pop('approval', self.approval), **kw)

    def test_old_possibly_sent_exact_candidate_is_synthetic_not_created(self):
        self.create_prior('POSSIBLY_SENT')
        r = self.recheck()
        self.assertEqual(r['recheck_state'], 'SIMULATED_EXACT_CANDIDATE')
        self.assertTrue(r['prior_ec218_attempt_confirmed'])
        self.assertTrue(r['synthetic'])
        self.assertFalse(r['issue_created'])
        self.assertFalse(r['remote_exact_candidate_observed'])
        self.assertFalse(r['remote_candidate_durable_recorded'])
        self.assertFalse((self.root/'ec219.db').exists())
        self.assertEqual(r['provider_get_count'], 5)  # repo, two pages, detail, repo
        self.assertTrue(all(rc._allowed_get(u) for u in self.remote.urls))

    def test_post_unknown_independently_bounded_and_no_post(self):
        self.create_prior()
        r = self.recheck()
        self.assertEqual(r['recheck_state'], 'SIMULATED_EXACT_CANDIDATE')
        self.assertLessEqual(self.remote.get_count, rc.MAX_GETS)
        self.assertTrue(all(x[0] == 'GET' for x in self.remote.events))
        self.assertFalse(r['second_create_attempt_authorized'])
        self.assertFalse(r['all_issues_enumerated'])
        self.assertFalse(r['duplicate_absence_proven'])
        self.assertFalse(r['issue_creation_attributed_to_ec218_attempt'])

    def test_no_record_never_network_or_ledger_create(self):
        r = self.recheck()
        self.assertEqual(r['recheck_state'], 'BLOCKED')
        self.assertEqual(self.remote.get_count, 0)
        self.assertFalse((self.root/'ec218.db').exists())
        self.assertFalse((self.root/'ec219.db').exists())

    def test_wrong_grant_cannot_claim_other_operation(self):
        self.create_prior()
        bad = replace(self.approval, grant_id='2'*32)
        r = self.recheck(approval=bad)
        self.assertEqual(r['recheck_state'], 'BLOCKED')
        self.assertEqual(self.remote.get_count, 0)

    def test_unapproved_or_different_signed_content_fails_historical_replay(self):
        self.create_prior()
        a = self.args
        tampered = replace(a['content'], title='Changed unapproved title')
        r = rc.recheck_unknown_issue(
            a['evidence'], a['intent'], tampered, self.approval,
            trusted_eligibility_review_keys=a['trusted_eligibility_review_keys'],
            trusted_historical_issuers=a['trusted_issuers'],
            original_attempts=self.reader, observation_ledger=self.ledger,
            host_access=self.access, token_supplier=lambda: TEST_TOKEN,
            transport=self.remote, clock=CLOCK)
        self.assertNotEqual(r['recheck_state'], 'SIMULATED_EXACT_CANDIDATE')
        self.assertEqual(self.remote.get_count, 0)

    def test_legacy_outcome_not_unknown_does_not_recheck(self):
        for outcome in ('POST_REJECTED', 'SYNTHETIC_RESPONSE', 'PROVIDER_REPORTED_CREATED'):
            with self.subTest(outcome=outcome):
                self.setUp()
                self.create_prior(outcome)
                self.assertEqual(self.recheck()['recheck_state'], 'BLOCKED')
                self.assertEqual(self.remote.get_count, 0)

    def test_host_needs_separate_current_read_and_private_content_optins(self):
        self.create_prior()
        for access in (
            None, replace(self.access, network_opt_in=False),
            replace(self.access, read_issue_metadata_opt_in=False),
            replace(self.access, read_full_issue_content_opt_in=False),
            replace(self.access, private_content_visibility_attested_by_host=False),
            replace(self.access, current_provider_credentials_attested_by_host=False),
            replace(self.access, account_ref='other-account'),
            replace(self.access, repository='other/repo'),
            replace(self.access, visibility='PRIVATE'),
            replace(self.access, expires_at_utc=stamp(CURRENT-timedelta(seconds=1)))):
            with self.subTest(access=access):
                self.assertEqual(self.recheck(host_access=access)['recheck_state'], 'BLOCKED')
        self.assertEqual(self.remote.get_count, 0)

    def test_unknown_if_exact_candidate_not_in_finite_pages(self):
        self.create_prior()
        self.remote.no_match = True
        result = self.recheck()
        self.assertEqual(result['recheck_state'], 'UNKNOWN')
        self.assertEqual(result['exit_code'], 5)
        self.assertFalse(result['hidden_issues_ruled_out'])
        self.assertFalse(result['duplicate_absence_proven'])
        self.assertFalse((self.root/'ec219.db').exists())

    def test_unrelated_title_never_promoted_as_match(self):
        self.create_prior()
        self.remote.list_mismatch = {'title': 'Another concern entirely'}
        self.assertEqual(self.recheck()['recheck_state'], 'UNKNOWN')

    def test_similar_title_but_different_body_is_source_mismatch(self):
        self.create_prior()
        self.remote.detail_mismatch = {'body': 'different source'}
        r = self.recheck()
        self.assertEqual(r['recheck_state'], 'UNKNOWN')
        self.assertIn('AMBIGUOUS', r['reason_code'])

    def test_edited_remote_labels_are_not_a_match(self):
        self.create_prior()
        self.remote.detail_mismatch = {'labels': [{'name': 'new'}]}
        self.assertEqual(self.recheck()['recheck_state'], 'UNKNOWN')

    def test_multiple_exact_created_issues_must_remain_unknown(self):
        self.create_prior()
        self.remote.extra_rows = [self.remote.issue(number=47, id=9876)]
        r = self.recheck()
        self.assertEqual(r['recheck_state'], 'UNKNOWN')
        self.assertFalse(r['remote_exact_candidate_observed'])
        self.assertFalse((self.root/'ec219.db').exists())

    def test_potential_old_duplicate_same_title_prevents_false_positive(self):
        self.create_prior()
        self.remote.extra_rows = [self.remote.issue(number=50, id=9999, offset=-300)]
        self.assertEqual(self.recheck()['recheck_state'], 'UNKNOWN')

    def test_bad_repo_id_path_privacy_before_get_list(self):
        self.create_prior()
        i = self.args['intent']
        for drift in ({'id': 42}, {'full_name': 'another/repo'},
                      {'private': True}, {'has_issues': False}):
            with self.subTest(drift=drift):
                self.remote.repo_mismatch = drift
                self.assertEqual(self.recheck()['recheck_state'], 'UNKNOWN')
                self.assertEqual(self.remote.urls[-1], rc._urls(i))

    def test_repo_rename_race_after_candidate_keeps_unknown(self):
        self.create_prior()
        self.remote.repo_after_mismatch = {'id': 45}
        self.assertEqual(self.recheck()['recheck_state'], 'UNKNOWN')

    def test_http_404_never_proves_private_issue_absence(self):
        self.create_prior()
        self.remote.error_url_fragment = '/issues/45'
        r = self.recheck()
        self.assertEqual(r['recheck_state'], 'UNKNOWN')
        self.assertFalse(r['duplicate_absence_proven'])

    def test_page_overflow_is_not_treated_as_complete(self):
        self.create_prior()
        self.remote.page_overflow = True
        self.assertEqual(self.recheck()['recheck_state'], 'UNKNOWN')

    def test_invalid_timestamp_is_unknown(self):
        self.create_prior()
        self.remote.list_mismatch = {'created_at': 'not UTC'}
        self.assertEqual(self.recheck()['recheck_state'], 'UNKNOWN')

    def test_issue_before_original_attempt_cannot_be_created_by_attempt(self):
        self.create_prior()
        self.remote.list_mismatch = {'created_at': stamp(CURRENT-timedelta(seconds=100))}
        self.assertEqual(self.recheck()['recheck_state'], 'UNKNOWN')

    def test_private_gitlab_requires_confidential_issue(self):
        self.args = fixture('gitlab', privacy='CONFIDENTIAL', visibility='PRIVATE')
        self.approval = sign(self.args)
        self.ec217 = cg.SQLiteOneUseLedger(self.root/'gitlab217.db', self.args['intent'].audience)
        self.writer = cw.SQLiteCreateAttemptLedger(self.root/'gitlab218.db', self.args['intent'].audience)
        self.reader = rc.SQLiteCreateAttemptReader(self.root/'gitlab218.db', self.args['intent'].audience)
        self.ledger = rc.SQLiteRecheckLedger(self.root/'gitlab219.db', self.args['intent'].audience)
        self.remote, self.access = FakeRead(self.args), self.access_for(self.args)
        self.create_prior()
        result = self.recheck()
        self.assertEqual(result['recheck_state'], 'SIMULATED_EXACT_CANDIDATE')
        self.assertIn('/projects/', self.remote.urls[-2])  # last detail, before last repo GET
        self.remote.detail_mismatch = {'confidential': False}
        self.assertEqual(self.recheck()['recheck_state'], 'UNKNOWN')

    def test_malformed_page_and_fixture_marker_rejected(self):
        self.create_prior()
        self.remote.list_mismatch = {'_ces_fixture': True}
        self.assertEqual(self.recheck()['recheck_state'], 'UNKNOWN')

    def test_endpoint_allowlist_excludes_write_methods_and_external_hosts(self):
        self.assertFalse(rc._allowed_get('http://api.github.com/repos/a/b/issues'))
        self.assertFalse(rc._allowed_get('https://attacker.test/repos/a/b/issues'))
        self.assertFalse(rc._allowed_get('https://api.github.com/repos/a/b/issues?state=open'))
        self.assertFalse(rc._allowed_get('https://api.github.com/repos/a/b/issues/0'))
        self.assertFalse(rc._allowed_get('https://api.github.com/repos/a/b/issues?state=all&sort=created&direction=desc&per_page=50&page=999'))
        self.assertFalse(rc._allowed_get('https://gitlab.com/api/v4/projects/3/issues?state=all'))
        self.assertTrue(rc._allowed_get(rc._urls(self.args['intent'], page=1)))
        with self.assertRaises(rc.RecheckError):
            rc.StrictHTTPSIssueReadTransport().get_json('https://evil.example/', {}, 1)

    def test_custom_clock_without_mock_transport_cannot_use_real_https(self):
        self.create_prior()
        r = self.recheck(transport=None)
        self.assertEqual(r['recheck_state'], 'BLOCKED')
        self.assertEqual(self.remote.get_count, 0)

    def test_read_result_does_not_leak_original_text_repo_or_token(self):
        self.create_prior()
        out = json.dumps(self.recheck())
        for secret in (TEST_TOKEN, self.args['content'].body,
                       self.args['content'].title, self.args['intent'].repository):
            self.assertNotIn(secret, out)

    def test_sqlite_ledger_never_overwrites_conflicting_evidence(self):
        op = 'a'*64
        grant = 'b'*32
        self.assertEqual(self.ledger.record_candidate(op, grant, '1'*64, '2'*64, CURRENT),
                         'COMMITTED')
        self.assertEqual(self.ledger.record_candidate(op, grant, '1'*64, '2'*64, CURRENT),
                         'ALREADY_RECORDED')
        self.assertEqual(self.ledger.record_candidate(op, grant, '3'*64, '2'*64, CURRENT),
                         'CONFLICT')
        con = sqlite3.connect(self.root/'ec219.db')
        with con:
            got = con.execute('SELECT identity_sha256, evidence_sha256 FROM '
                              'issue_recheck_candidate').fetchall()
        con.close()
        self.assertEqual(got, [('1'*64, '2'*64)])
        data = (self.root/'ec219.db').read_bytes()
        for secret in (TEST_TOKEN, self.args['content'].body,
                       self.args['intent'].repository):
            self.assertNotIn(secret.encode(), data)

    def test_sqlite_attempt_reader_is_readonly_and_exact_claim(self):
        op = self.create_prior()
        self.assertEqual(self.reader.read_attempt(op, self.approval.grant_id).outcome,
                         'POST_UNKNOWN')
        self.assertIsNone(self.reader.read_attempt('f'*64, self.approval.grant_id))
        self.assertIsNone(self.reader.read_attempt(op, 'f'*32))
        other = rc.SQLiteCreateAttemptReader(self.root/'absent.db', self.args['intent'].audience)
        self.assertIsNone(other.read_attempt(op, self.approval.grant_id))
        self.assertFalse((self.root/'absent.db').exists())

    def test_stored_attempt_clock_drift_is_unknown(self):
        op = self.create_prior()
        with sqlite3.connect(self.root/'ec218.db') as db:
            db.execute('UPDATE issue_create_attempt SET started_at_utc=? WHERE operation_key=?',
                       ('not-a-stamp', op))
        self.assertEqual(self.recheck()['recheck_state'], 'UNKNOWN')
        self.assertEqual(self.remote.get_count, 0)

    def test_output_schema(self):
        schema = json.loads((Path(__file__).parents[1] / 'references' /
                             'issue-unknown-recheck-result.v1.schema.json').read_text())
        self.create_prior()
        outputs = [self.recheck()]
        self.remote.no_match = True
        outputs.append(self.recheck())
        outputs.append(self.recheck(host_access=None))
        outputs.append(self.recheck(timeout=0))
        for result in outputs:
            jsonschema.Draft202012Validator(schema).validate(result)


if __name__ == '__main__':
    unittest.main()
