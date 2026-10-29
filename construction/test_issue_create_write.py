#!/usr/bin/env python3
"""EC218 focused synthetic code-path tests. NEVER a real provider POST."""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
import threading
import unittest

import jsonschema
import issue_create_grant as cg
import issue_create_write as cw
from test_issue_create_grant import fixture, sign
from test_issue_eligibility import CURRENT, CLOCK, stamp

TEST_TOKEN = 'test-injected-not-a-real-token'


class FakeCreateTransport:
    def __init__(self, kw, *, bad_repo=None, bad_response=None, post_error=None):
        self.kw = kw
        self.bad_repo, self.bad_response, self.post_error = bad_repo, bad_response, post_error
        self.get_count = 0
        self.post_count = 0
        self.payload = None
        self.paths = []
        self.lock = threading.Lock()

    def get_object(self, url, headers, timeout):
        with self.lock:
            self.get_count += 1
            self.paths.append(('GET', url))
        assert headers.get('PRIVATE-TOKEN') == TEST_TOKEN or \
            headers.get('Authorization') == 'Bearer ' + TEST_TOKEN
        intent = self.kw['intent']
        raw = {'id': intent.expected_repository_id, 'archived': False}
        if intent.provider == 'github':
            raw.update(full_name=intent.repository,
                       private=intent.visibility == 'PRIVATE', has_issues=True)
        else:
            raw.update(path_with_namespace=intent.repository,
                       visibility=intent.visibility.lower(), issues_enabled=True)
        if self.bad_repo:
            raw.update(self.bad_repo)
        return raw

    def post_create(self, url, headers, body, timeout):
        with self.lock:
            self.post_count += 1
            self.payload = json.loads(body)
            self.paths.append(('POST', url))
        if self.post_error is not None:
            raise self.post_error
        intent, content = self.kw['intent'], self.kw['content']
        if intent.provider == 'github':
            base, _ = cw._urls(intent)
            raw = {'id': 4567, 'number': 45, 'repository_url': base,
                   'url': base + '/issues/45', 'state': 'open',
                   'title': content.title, 'body': content.body,
                   'labels': [{'name': x} for x in content.labels]}
        else:
            raw = {'id': 4567, 'iid': 45,
                   'project_id': intent.expected_repository_id, 'state': 'opened',
                   'title': content.title, 'description': content.body,
                   'labels': list(content.labels),
                   'confidential': intent.visibility == 'PRIVATE'}
        if self.bad_response:
            raw.update(self.bad_response)
        return raw


class EC218(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.args = fixture()
        self.approval = sign(self.args)
        self.reserver_path = self.root / 'grants.db'
        self.attempt_path = self.root / 'attempts.db'
        self.reserver = cg.SQLiteOneUseLedger(self.reserver_path,
                                              self.args['intent'].audience)
        self.reader = cw.SQLiteGrantReservationReader(self.reserver_path,
                                                       self.args['intent'].audience)
        self.writer = cw.SQLiteCreateAttemptLedger(self.attempt_path,
                                                    self.args['intent'].audience)
        self.access = self.access_for(self.args)
        self.transport = FakeCreateTransport(self.args)

    def access_for(self, args):
        i = args['intent']
        return cw.HostCreateAccess(i.provider, i.api_host, i.account_ref,
                                   i.repository, i.expected_repository_id,
                                   i.visibility, i.policy_revision_sha256, i.audience,
                                   stamp(CURRENT + timedelta(seconds=40)), True, True, True)

    def reserve(self, args=None, approval=None):
        a = args or self.args
        return cg.reserve_issue_create_grant(
            a['evidence'], a['intent'], a['content'], approval or self.approval,
            trusted_eligibility_review_keys=a['trusted_eligibility_review_keys'],
            trusted_issuers=a['trusted_issuers'], ledger=self.reserver, clock=CLOCK)

    def write(self, args=None, **overrides):
        a = args or self.args
        kw = dict(trusted_eligibility_review_keys=a['trusted_eligibility_review_keys'],
                  trusted_issuers=a['trusted_issuers'],
                  reserved_grants=self.reader, attempt_ledger=self.writer,
                  host_access=self.access, token_supplier=lambda: TEST_TOKEN,
                  transport=self.transport, clock=CLOCK)
        kw.update(overrides)
        return cw.create_new_issue_once(a['evidence'], a['intent'], a['content'],
                                        kw.pop('approval', self.approval), **kw)

    def test_post_is_not_available_without_durable_ec217_reservation(self):
        # A caller can forge a JSON 'RESERVED_ONE_ATTEMPT' but cannot forge
        # the host-supplied durable proof via that JSON.
        r = self.write()
        self.assertEqual(r['create_state'], 'BLOCKED')
        self.assertEqual(self.transport.post_count, 0)
        self.assertEqual(self.transport.get_count, 0)
        self.assertFalse(self.reserver_path.exists())

    def test_valid_exact_review_and_claim_can_invoke_one_synthetic_post(self):
        self.assertEqual(self.reserve()['grant_state'], 'RESERVED_ONE_ATTEMPT')
        r = self.write()
        self.assertEqual(r['create_state'], 'SIMULATED_RESPONSE_MATCHED')
        self.assertTrue(r['ec217_original_reservation_confirmed'])
        self.assertTrue(r['durable_attempt_barrier_recorded'])
        self.assertTrue(r['provider_post_invoked'])
        self.assertFalse(r['issue_created'])
        self.assertFalse(r['provider_reported_created'])
        self.assertTrue(r['synthetic'])
        self.assertEqual(self.transport.get_count, 1)
        self.assertEqual(self.transport.post_count, 1)
        self.assertEqual(self.transport.payload['body'], self.args['content'].body)
        self.assertEqual(self.transport.payload['title'], self.args['content'].title)
        self.assertEqual(self.transport.payload['labels'], [])
        self.assertNotIn('idempotency', self.transport.payload)
        self.assertEqual(self.write()['create_state'], 'BLOCKED')
        self.assertEqual(self.transport.post_count, 1)

    def test_gitlab_private_creates_confidential_and_numeric_target(self):
        args = fixture('gitlab', privacy='CONFIDENTIAL', visibility='PRIVATE')
        self.args, self.approval = args, sign(args)
        self.access, self.transport = self.access_for(args), FakeCreateTransport(args)
        self.assertEqual(self.reserve()['grant_state'], 'RESERVED_ONE_ATTEMPT')
        result = self.write()
        self.assertEqual(result['create_state'], 'SIMULATED_RESPONSE_MATCHED')
        self.assertTrue(self.transport.payload['confidential'])
        self.assertEqual(self.transport.payload['description'], args['content'].body)
        self.assertTrue(self.transport.paths[-1][1].endswith(
            f"/projects/{args['intent'].expected_repository_id}/issues"))
        self.assertNotIn(args['intent'].repository, json.dumps(result))

    def test_no_create_without_independent_host_and_credential_network_optins(self):
        self.reserve()
        for modified in (
            None, replace(self.access, network_opt_in=False),
            replace(self.access, create_new_issue_opt_in=False),
            replace(self.access, current_provider_credentials_attested_by_host=False),
            replace(self.access, account_ref='another-slot'),
            replace(self.access, expires_at_utc=stamp(CURRENT - timedelta(seconds=1))),
            replace(self.access, policy_revision_sha256='f'*64),
        ):
            with self.subTest(modified=modified):
                self.assertEqual(self.write(host_access=modified)['create_state'], 'BLOCKED')
        self.assertEqual(self.transport.get_count, 0)
        self.assertEqual(self.transport.post_count, 0)

    def test_custom_clock_cannot_drive_real_transport(self):
        self.reserve()
        r = self.write(transport=None)
        self.assertEqual(r['create_state'], 'BLOCKED')
        self.assertFalse(r['provider_post_invoked'])

    def test_provider_rejection_after_post_is_not_auto_retried(self):
        self.reserve()
        self.transport.post_error = cw.WriteError('PROVIDER_POST_REJECTED',
                                                   'REJECTED_UNVERIFIED')
        r = self.write()
        self.assertEqual(r['create_state'], 'REJECTED_UNVERIFIED')
        self.assertTrue(r['provider_post_invoked'])
        self.transport.post_error = None
        self.assertEqual(self.write()['create_state'], 'BLOCKED')
        self.assertEqual(self.transport.post_count, 1)

    def test_sqlite_does_not_persist_title_body_token_or_path(self):
        self.reserve()
        self.write()
        data = self.attempt_path.read_bytes()
        for value in (self.args['content'].title, self.args['content'].body,
                      TEST_TOKEN, self.args['intent'].repository):
            self.assertNotIn(value.encode(), data)

    def test_missing_credential_is_not_a_write_attempt(self):
        self.reserve()
        r = self.write(token_supplier=lambda: None)
        self.assertEqual(r['create_state'], 'BLOCKED')
        self.assertEqual(self.transport.post_count, 0)
        self.assertFalse(self.attempt_path.exists())

    def test_current_repository_visibility_id_path_and_feature_must_match(self):
        self.reserve()
        cases = ({'id': 999}, {'full_name': 'other/repo'}, {'private': True},
                 {'has_issues': False}, {'archived': True}, {'private': None})
        for extra in cases:
            transport = FakeCreateTransport(self.args, bad_repo=extra)
            with self.subTest(extra=extra):
                r = self.write(transport=transport)
                self.assertIn(r['create_state'], ('BLOCKED', 'UNKNOWN'))
                self.assertEqual(transport.post_count, 0)
        self.assertFalse(self.attempt_path.exists())

    def test_tampered_approval_rejected_even_after_original_reservation(self):
        self.reserve()
        modified = replace(self.approval, confirms_create_not_edit=False)
        self.assertEqual(self.write(approval=modified)['create_state'], 'BLOCKED')
        self.assertEqual(self.transport.get_count, 0)

    def test_forged_original_match_receipt_does_not_pass_full_replay(self):
        self.reserve()
        import copy
        altered = copy.deepcopy(self.args['evidence'].plan_result)
        altered['reason_code'] = 'FAKE_ELIGIBLE'
        args = {**self.args, 'evidence': replace(self.args['evidence'], plan_result=altered)}
        r = self.write(args)
        self.assertEqual(r['create_state'], 'UNKNOWN')
        self.assertEqual(self.transport.post_count, 0)

    def test_post_timeout_is_unknown_and_permanently_blocks_repost(self):
        self.reserve()
        self.transport.post_error = TimeoutError('simulated timeout with SECRET')
        first = self.write()
        self.assertEqual(first['create_state'], 'UNKNOWN')
        self.assertEqual(first['exit_code'], 5)
        self.assertTrue(first['provider_post_invoked'])
        self.transport.post_error = None
        second = self.write()
        self.assertEqual(second['create_state'], 'BLOCKED')
        self.assertTrue(second['same_request_replay_blocked'])
        self.assertEqual(self.transport.post_count, 1)
        self.assertNotIn('SECRET', json.dumps(first))

    def test_bad_201_is_unknown_and_never_posts_again(self):
        self.reserve()
        self.transport.bad_response = {'title': 'provider rewrote it'}
        self.assertEqual(self.write()['create_state'], 'UNKNOWN')
        self.transport.bad_response = None
        self.assertEqual(self.write()['create_state'], 'BLOCKED')
        self.assertEqual(self.transport.post_count, 1)

    def test_fresh_signed_grant_cannot_replay_identical_operation(self):
        self.reserve()
        self.assertEqual(self.write()['create_state'], 'SIMULATED_RESPONSE_MATCHED')
        new = sign(self.args, grant_id='2'*32)
        self.assertEqual(self.reserve(approval=new)['grant_state'], 'RESERVED_ONE_ATTEMPT')
        self.assertEqual(self.write(approval=new)['create_state'], 'BLOCKED')
        self.assertEqual(self.transport.post_count, 1)

    def test_two_parallel_threads_share_one_atomic_db_barrier(self):
        self.reserve()
        with ThreadPoolExecutor(max_workers=2) as pool:
            future = [pool.submit(self.write) for _ in range(2)]
            states = [x.result()['create_state'] for x in future]
        self.assertCountEqual(states, ['SIMULATED_RESPONSE_MATCHED', 'BLOCKED'])
        self.assertEqual(self.transport.post_count, 1)

    def test_reader_checks_exact_grant_and_challenge(self):
        self.reserve()
        self.assertIsNone(self.reader.read_claim_time('2'*32, self.approval.challenge_sha256))
        self.assertIsNone(self.reader.read_claim_time('1'*32, 'f'*64))
        self.assertEqual(self.write()['create_state'], 'SIMULATED_RESPONSE_MATCHED')

    def test_reader_not_create_unrelated_sqlite_db(self):
        missing = cw.SQLiteGrantReservationReader(self.root/'does-not-exist.db',
                                                   self.args['intent'].audience)
        self.assertIsNone(missing.read_claim_time('1'*32, 'a'*64))
        self.assertFalse(missing.path.exists())

    def test_ledger_loss_fails_closed_and_does_not_post(self):
        self.reserve()
        class Unavailable:
            audience = 'host:review-station-01'
            def atomic_start(self, *args): return 'UNAVAILABLE'
            def record_outcome(self, *args): return True
        r = self.write(attempt_ledger=Unavailable())
        self.assertEqual(r['create_state'], 'UNKNOWN')
        self.assertEqual(self.transport.post_count, 0)

    def test_crash_after_claim_before_network_is_at_most_once(self):
        self.reserve()
        op = cw.operation_sha256(self.args['intent'])
        self.assertEqual(self.writer.atomic_start(
            op, self.approval.grant_id, self.approval.challenge_sha256, CURRENT), 'CLAIMED')
        self.assertEqual(self.write()['create_state'], 'BLOCKED')
        self.assertEqual(self.transport.post_count, 0)

    def test_no_duplicate_store_uses_grant_id_even_with_different_operation(self):
        self.reserve()
        a = self.args['intent']
        op = cw.operation_sha256(a)
        self.assertEqual(self.writer.atomic_start(
            op, self.approval.grant_id, self.approval.challenge_sha256, CURRENT), 'CLAIMED')
        self.assertEqual(self.writer.atomic_start(
            'f'*64, self.approval.grant_id, self.approval.challenge_sha256, CURRENT),
            'ALREADY_RECORDED')

    def test_no_existing_issue_patch_put_or_delete_urls(self):
        self.assertTrue(cw._allowed_url('https://api.github.com/repos/test/repo/issues', 'POST'))
        self.assertFalse(cw._allowed_url('https://api.github.com/repos/test/repo/issues/3', 'POST'))
        self.assertFalse(cw._allowed_url('https://api.github.com/repos/test/repo/issues/3/comments', 'POST'))
        self.assertFalse(cw._allowed_url('https://gitlab.com/api/v4/projects/3/issues/5', 'POST'))
        self.assertFalse(cw._allowed_url('https://evil.example/api/v4/projects/3/issues', 'POST'))
        self.assertFalse(cw._allowed_url('http://api.github.com/repos/test/repo/issues', 'POST'))

    def test_201_strict_identity_and_labels_disallow_misreporting(self):
        self.reserve()
        for field in ({'id': 0}, {'pull_request': {'url': 'wrong'}},
                      {'repository_url': 'https://evil.example'}, {'labels': [{'name': 'unexpected'}]},
                      {'url': 'https://example.invalid'}):
            with self.subTest(field=field):
                # Each iteration tests verification directly; duplicate barrier
                # deliberately prevents a second POST in the full path.
                raw = FakeCreateTransport(self.args, bad_response=field)
                url, _ = cw._urls(self.args['intent'])
                issue = raw.post_create(url + '/issues', {'Authorization': 'Bearer '+TEST_TOKEN},
                                        cw._payload(self.args['intent'], self.args['content']), 4)
                with self.assertRaises(cw.WriteError):
                    cw._created(issue, self.args['intent'], self.args['content'], url)

    def test_outputs_never_expose_content_or_credentials(self):
        self.reserve()
        r = self.write()
        dumped = json.dumps(r)
        for secret in (self.args['content'].title, self.args['content'].body,
                       self.args['intent'].repository, self.args['intent'].account_ref,
                       TEST_TOKEN, self.approval.issuer_key_id):
            self.assertNotIn(secret, dumped)

    def test_response_contract(self):
        ref = Path(__file__).resolve().parent.parent/'references'/'issue-create-write-result.v1.schema.json'
        schema = json.loads(ref.read_text(encoding='utf-8'))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(self.write(), schema)
        self.reserve()
        jsonschema.validate(self.write(), schema)
        duplicate = self.write()
        jsonschema.validate(duplicate, schema)
        bad = dict(duplicate, issue_created=True)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(bad, schema)


if __name__ == '__main__':
    unittest.main()
