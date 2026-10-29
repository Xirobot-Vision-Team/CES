#!/usr/bin/env python3
"""EC217: local synthetic functional/security tests, no real human consent."""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import timedelta
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import jsonschema

import issue_create_grant as grant
import issue_plan as plan
from test_issue_plan import prepared
from test_issue_eligibility import CURRENT, CLOCK, stamp

# These private bytes are known and synthesized for tests. Not host authority!
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(41, 73)))
ISSUER_PUBLIC = ISSUER.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fixture(provider='github', **options):
    args = prepared(provider, **options)  # fabricated live-shaped EC214 JSON!
    original_plan = plan.draft_issue_plan(**args)
    assert original_plan['plan_state'] == 'DRAFT_READY'
    draft = original_plan['draft']
    ctx, intent = args['context'], args['intent']
    content = grant.FinalIssueContent(
        draft['suggested_title'], draft['suggested_body'].strip(), (),
        tuple(grant.Citation(x['reference_id'], x['anchor_binding_sha256'])
              for x in draft['references']))
    create_intent = grant.IssueCreateIntent(
        grant.ACTION, ctx.provider, ctx.api_host, ctx.account_ref,
        intent.target_repository, intent.expected_repository_id,
        intent.target_visibility, intent.policy_revision_sha256,
        draft['plan_sha256'], grant.plan_result_sha256(original_plan),
        grant.final_content_sha256(content), 'host:review-station-01')
    evidence = grant.PlanEvidence(
        ctx, args['intent'], args['eligibility_request'], args['match_request'],
        args['match_result'], args['eligibility_result'],
        args['review_receipt'], original_plan)
    authority = grant.IssuerAuthority(
        ISSUER_PUBLIC, grant.ROLE, ctx.provider, ctx.api_host, ctx.account_ref,
        draft['target']['repository_identity_sha256'], intent.target_visibility,
        intent.policy_revision_sha256, create_intent.audience, 'a'*64,
        stamp(CURRENT-timedelta(seconds=20)),
        stamp(CURRENT+timedelta(hours=1)), False)
    kw = dict(evidence=evidence, intent=create_intent, content=content,
              trusted_eligibility_review_keys=args['trusted_review_keys'],
              trusted_issuers={'real-host-approved-issuer': authority}, clock=CLOCK)
    return kw


def sign(args, **changes):
    challenge = grant.prepare_issue_create_review(
        args['evidence'], args['intent'], args['content'],
        trusted_eligibility_review_keys=args['trusted_eligibility_review_keys'],
        clock=CLOCK)
    assert challenge['reason_code'] == 'ISSUE_CREATE_GRANT_EXPLICIT_SIGNED_APPROVAL_REQUIRED', challenge
    c = challenge['challenge']
    fields = dict(
        schema=grant.RECEIPT_SCHEMA, method=grant.METHOD,
        action=grant.ACTION, grant_id='1'*32,
        issuer_key_id='real-host-approved-issuer',
        authority_revision_sha256='a'*64, audience=args['intent'].audience,
        challenge_sha256=c['challenge_sha256'],
        plan_result_sha256=c['plan_result_sha256'],
        final_content_sha256=c['final_content_sha256'],
        target_identity_sha256=c['target_identity_sha256'],
        policy_revision_sha256=c['policy_revision_sha256'],
        decision='APPROVE_EXACT_NEW_ISSUE_ONCE',
        confirms_full_final_text_and_citations_reviewed=True,
        confirms_target_visibility_and_privacy_reviewed=True,
        confirms_create_not_edit=True,
        acknowledges_duplicate_absence_not_proven=True,
        issued_at_utc=stamp(CURRENT-timedelta(seconds=1)),
        expires_at_utc=stamp(CURRENT+timedelta(seconds=100)),
        signature_base64='')
    fields.update(changes)
    receipt = grant.HumanCreateApproval(**fields)
    return replace(receipt, signature_base64=base64.b64encode(
        ISSUER.sign(grant.approval_signing_bytes(receipt))).decode('ascii'))


class EC217(unittest.TestCase):
    def setUp(self):
        self.kw = fixture()
        self.receipt = sign(self.kw)

    def inspect(self, **changes):
        kw = {**self.kw, **changes}
        return grant.inspect_issue_create_grant(
            kw['evidence'], kw['intent'], kw['content'], kw.pop('receipt', self.receipt),
            trusted_eligibility_review_keys=kw['trusted_eligibility_review_keys'],
            trusted_issuers=kw['trusted_issuers'], clock=kw['clock'])

    def reserve(self, ledger, **changes):
        kw = {**self.kw, **changes}
        return grant.reserve_issue_create_grant(
            kw['evidence'], kw['intent'], kw['content'], kw.pop('receipt', self.receipt),
            trusted_eligibility_review_keys=kw['trusted_eligibility_review_keys'],
            trusted_issuers=kw['trusted_issuers'], ledger=ledger, clock=kw['clock'])

    def ledger(self, directory):
        return grant.SQLiteOneUseLedger(Path(directory) / 'one-use.db',
                                        self.kw['intent'].audience)

    def test_challenge_requires_review_not_remote_permission(self):
        r = grant.prepare_issue_create_review(
            self.kw['evidence'], self.kw['intent'], self.kw['content'],
            trusted_eligibility_review_keys=self.kw['trusted_eligibility_review_keys'],
            clock=CLOCK)
        self.assertEqual(r['grant_state'], 'NEEDS_REVIEW')
        self.assertEqual(r['status'], 'partial')
        self.assertFalse(r['issue_create_authorized_for_this_one_attempt'])
        self.assertFalse(r['issue_create_network_attempted'])
        self.assertFalse(r['issue_created'])
        self.assertFalse(r['challenge']['provider_write_authorized'])
        self.assertNotIn(self.kw['content'].body, json.dumps(r))

    def test_signed_approval_verified_but_cannot_send_without_claim(self):
        r = self.inspect()
        self.assertEqual(r['grant_state'], 'SIGNED_REVIEW_VALID')
        self.assertEqual(r['exit_code'], 2)
        self.assertFalse(r['issue_create_authorized_for_this_one_attempt'])
        self.assertFalse(r['host_ledger_atomic_claim_recorded'])
        self.assertEqual(r['delivery_state'], 'NOT_ATTEMPTED')
        self.assertFalse(r['organizational_issuer_authenticated_by_ces'])
        self.assertFalse(r['final_prose_safe_by_machine_proof'])

    def test_actual_single_use_durable_ledger_claim_not_issue_write(self):
        with tempfile.TemporaryDirectory() as directory:
            l1 = self.ledger(directory)
            first = self.reserve(l1)
            second = self.reserve(self.ledger(directory))
            self.assertEqual(first['grant_state'], 'RESERVED_ONE_ATTEMPT')
            self.assertTrue(first['host_ledger_atomic_claim_recorded'])
            self.assertTrue(first['issue_create_authorized_for_this_one_attempt'])
            self.assertEqual(first['status'], 'partial')
            self.assertFalse(first['issue_created'])
            self.assertFalse(first['issue_create_network_attempted'])
            self.assertEqual(second['grant_state'], 'BLOCKED')
            self.assertEqual(second['reason_code'], 'ISSUE_CREATE_GRANT_GRANT_ALREADY_CONSUMED')
            with closing(sqlite3.connect(str(l1.path))) as db:
                records = db.execute('SELECT * FROM claim').fetchall()
                self.assertEqual(len(records), 1)
                self.assertNotIn(self.receipt.grant_id, str(records))
                self.assertNotIn(self.kw['content'].title, str(records))

    def test_concurrent_claims_across_connections_exactly_one(self):
        with tempfile.TemporaryDirectory() as directory:
            def work(_):
                return self.reserve(self.ledger(directory))['grant_state']
            with ThreadPoolExecutor(max_workers=8) as pool:
                states = list(pool.map(work, range(8)))
            self.assertEqual(states.count('RESERVED_ONE_ATTEMPT'), 1, states)
            self.assertEqual(states.count('BLOCKED'), 7, states)

    def test_missing_ledger_or_mismatched_audience_fails_closed(self):
        self.assertEqual(self.reserve(None)['grant_state'], 'BLOCKED')
        with tempfile.TemporaryDirectory() as directory:
            other = grant.SQLiteOneUseLedger(Path(directory)/'x.db', 'other:host')
            self.assertEqual(self.reserve(other)['grant_state'], 'BLOCKED')
            self.assertFalse(other.path.exists())

    def test_public_world_writable_ledger_parent_is_not_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o777)
            try:
                self.assertEqual(self.reserve(self.ledger(directory))['grant_state'], 'UNKNOWN')
                self.assertFalse((Path(directory)/'one-use.db').exists())
            finally:
                os.chmod(directory, 0o700)

    def test_symlink_ledger_path_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            dest = Path(directory)/'real.db'
            dest.write_bytes(b'not sqlite')
            (Path(directory)/'one-use.db').symlink_to(dest)
            self.assertEqual(self.reserve(self.ledger(directory))['grant_state'], 'UNKNOWN')

    def test_missing_receipt_and_invalid_signature_not_authorized(self):
        self.assertEqual(self.inspect(receipt=None)['grant_state'], 'NEEDS_REVIEW')
        bad = replace(self.receipt, signature_base64='A'*88)
        self.assertEqual(self.inspect(receipt=bad)['reason_code'],
                         'ISSUE_CREATE_GRANT_APPROVAL_SIGNATURE_INVALID')

    def test_self_signed_untrusted_creation_key_rejected(self):
        self.assertEqual(self.inspect(trusted_issuers={})['grant_state'], 'BLOCKED')
        self.assertEqual(self.inspect(trusted_issuers=None)['grant_state'], 'BLOCKED')

    def test_issuer_role_revocation_and_revision_fail(self):
        old = self.kw['trusted_issuers']['real-host-approved-issuer']
        for authority in (replace(old, revoked=True), replace(old, role='VIEWER'),
                          replace(old, authority_revision_sha256='b'*64)):
            with self.subTest(authority=authority):
                self.assertEqual(self.inspect(trusted_issuers={
                    'real-host-approved-issuer': authority})['grant_state'], 'BLOCKED')

    def test_same_eligibility_review_key_cannot_approve_create(self):
        old = self.kw['trusted_issuers']['real-host-approved-issuer']
        key = self.kw['trusted_eligibility_review_keys']['host-ec215-reviewer']
        self.assertEqual(self.inspect(trusted_issuers={
            'real-host-approved-issuer': replace(old, public_key=key)})['grant_state'], 'BLOCKED')

    def test_wrong_issuer_account_scope_blocked(self):
        old = self.kw['trusted_issuers']['real-host-approved-issuer']
        for changed in (replace(old, account_ref='different'),
                        replace(old, api_host='other.invalid'),
                        replace(old, provider='gitlab'),
                        replace(old, repository_identity_sha256='f'*64),
                        replace(old, audience='different:host'),
                        replace(old, visibility='PRIVATE'),
                        replace(old, policy_revision_sha256='f'*64)):
            self.assertEqual(self.inspect(trusted_issuers={
                'real-host-approved-issuer': changed})['grant_state'], 'BLOCKED')

    def test_grant_expired_or_future_dated_denied(self):
        for receipt in (
            sign(self.kw, issued_at_utc=stamp(CURRENT-timedelta(seconds=181)),
                 expires_at_utc=stamp(CURRENT-timedelta(seconds=1))),
            sign(self.kw, issued_at_utc=stamp(CURRENT+timedelta(seconds=1))),
            sign(self.kw, expires_at_utc=stamp(CURRENT+timedelta(seconds=181))),
        ):
            with self.subTest(receipt=receipt):
                self.assertEqual(self.inspect(receipt=receipt)['grant_state'], 'NEEDS_REVIEW')

    def test_authority_not_yet_valid_or_expired(self):
        authority = self.kw['trusted_issuers']['real-host-approved-issuer']
        for updated in (replace(authority, valid_from_utc=stamp(CURRENT)),
                        replace(authority, valid_until_utc=stamp(CURRENT+timedelta(seconds=30)))):
            self.assertEqual(self.inspect(trusted_issuers={
                'real-host-approved-issuer': updated})['grant_state'], 'NEEDS_REVIEW')

    def test_cannot_swap_title_body_labels_or_citations_after_approval(self):
        content = self.kw['content']
        for modified in (
            replace(content, title='Alternate safe issue title'),
            replace(content, body='Different sanitized body with enough explanatory text.'),
            replace(content, labels=('maintenance',)),
            replace(content, citations=(grant.Citation('E02', content.citations[0].anchor_binding_sha256),)),
        ):
            self.assertEqual(self.inspect(content=modified)['grant_state'], 'BLOCKED')

    def test_new_content_with_fresh_digest_still_needs_new_signature(self):
        content = replace(self.kw['content'], title='Alternate human approved title')
        intent = replace(self.kw['intent'],
                         expected_final_content_sha256=grant.final_content_sha256(content))
        self.assertEqual(self.inspect(content=content, intent=intent)['grant_state'], 'BLOCKED')

    def test_cannot_redirect_target_visibility_provider_repository_id_policy(self):
        intent = self.kw['intent']
        for variant in (
            replace(intent, action='EDIT_EXISTING_ISSUE'),
            replace(intent, visibility='PRIVATE'),
            replace(intent, repository='other/repo'),
            replace(intent, expected_repository_id=999999),
            replace(intent, provider='gitlab'),
            replace(intent, policy_revision_sha256='1'*64),
            replace(intent, api_host='wrong.example'),
            replace(intent, account_ref='attacker'),
            replace(intent, audience='attacker:host'),
        ):
            with self.subTest(variant=variant):
                result = self.inspect(intent=variant)
                self.assertNotEqual(result['grant_state'], 'SIGNED_REVIEW_VALID')

    def test_caller_forged_prior_plan_output_fails_exact_recompute(self):
        bad_plan = copy.deepcopy(self.kw['evidence'].plan_result)
        bad_plan['reason_code'] = 'ISSUE_PLAN_FAKE'
        evidence = replace(self.kw['evidence'], plan_result=bad_plan)
        self.assertEqual(self.inspect(evidence=evidence)['grant_state'], 'UNKNOWN')

    def test_caller_forged_ec215_serialized_result_fails_recompute(self):
        e = self.kw['evidence']
        fake = copy.deepcopy(e.eligibility_result)
        fake['review_signature_cryptographically_valid'] = 1
        self.assertEqual(self.inspect(evidence=replace(e, eligibility_result=fake))['grant_state'], 'UNKNOWN')

    def test_original_ec215_review_expiry_prevents_replay(self):
        future = lambda: CURRENT + timedelta(hours=6)
        self.assertNotEqual(self.inspect(clock=future)['grant_state'], 'SIGNED_REVIEW_VALID')

    def test_changed_original_match_receipt_prevents_grant(self):
        e = self.kw['evidence']
        fake = copy.deepcopy(e.match_result)
        fake['entries'][0]['source']['snapshot_sha256'] = '1'*64
        self.assertNotEqual(self.inspect(evidence=replace(e, match_result=fake))['grant_state'],
                            'SIGNED_REVIEW_VALID')

    def test_valid_gitlab_private_scope(self):
        args = fixture('gitlab', privacy='CONFIDENTIAL', visibility='PRIVATE')
        receipt = sign(args)
        result = grant.inspect_issue_create_grant(
            args['evidence'], args['intent'], args['content'], receipt,
            trusted_eligibility_review_keys=args['trusted_eligibility_review_keys'],
            trusted_issuers=args['trusted_issuers'], clock=CLOCK)
        self.assertEqual(result['grant_state'], 'SIGNED_REVIEW_VALID')
        dumped = json.dumps(result)
        self.assertNotIn('team/subteam/service', dumped)

    def test_cannot_approve_private_classification_to_public(self):
        # The actual EC215 privacy gate blocks PUBLIC target in this scenario.
        from test_issue_eligibility import base, model_live_shaped, signed
        import issue_eligibility as ie
        ctx, req, mr, synthetic = base('github', privacy='CONFIDENTIAL', visibility='PUBLIC')
        observed = model_live_shaped(synthetic)
        review = signed(ctx, req, mr, observed)
        state = ie.evaluate_issue_eligibility(
            ctx, req, mr, observed, review_receipt=review,
            trusted_review_keys=self.kw['trusted_eligibility_review_keys'], clock=CLOCK)
        self.assertEqual(state['eligibility'], 'BLOCKED')

    def test_text_control_bidi_and_not_nfc_denied(self):
        content = self.kw['content']
        for modified in (
            replace(content, title='Review\u202E hidden reversal'),
            replace(content, title='Review\x00 unsafe text'),
            replace(content, title='cafe\u0301 unexpected normalization'),
            replace(content, body='line\rbody that is long enough to be valid'),
            replace(content, body='   body with leading whitespace and at least forty chars'),
        ):
            self.assertEqual(self.inspect(content=modified)['grant_state'], 'INVALID_INPUT')

    def test_label_whitelist_sorted_unique(self):
        content = self.kw['content']
        for labels in (('secret/token',), ('x', 'x'), ('z', 'a'), (123,)):
            self.assertEqual(self.inspect(content=replace(content, labels=labels))['grant_state'],
                             'INVALID_INPUT')

    def test_wrong_ref_sha_denied(self):
        content = self.kw['content']
        new = replace(content, citations=(replace(content.citations[0],
                                                    anchor_binding_sha256='2'*64),))
        intent = replace(self.kw['intent'],
                         expected_final_content_sha256=grant.final_content_sha256(new))
        self.assertEqual(self.inspect(content=new, intent=intent)['grant_state'], 'BLOCKED')

    def test_non_integer_repository_id_and_unknown_action_denied(self):
        intent = self.kw['intent']
        self.assertEqual(self.inspect(intent=replace(intent, expected_repository_id=True))['grant_state'],
                         'INVALID_INPUT')
        self.assertEqual(self.inspect(intent=replace(intent, action='DELETE_ISSUE'))['grant_state'],
                         'BLOCKED')

    def test_no_raw_sensitive_strings_or_reviewer_identity_in_result(self):
        r = self.inspect()
        text = json.dumps(r)
        for bad in ('example/repo', 'src/core/logic.py',
                    'real-host-approved-issuer', 'host-ec215-reviewer',
                    self.kw['content'].body, self.kw['content'].title,
                    'synthetic-token', str(self.kw['intent'].expected_repository_id)):
            self.assertNotIn(bad, text)

    def test_unsigned_mutation_scope_decision_and_acknowledgements(self):
        for changes in (
            {'decision': 'ACKNOWLEDGE_FOR_LOCAL_PROPOSAL_ONLY'},
            {'confirms_create_not_edit': False},
            {'acknowledges_duplicate_absence_not_proven': False},
            {'confirms_target_visibility_and_privacy_reviewed': False},
            {'challenge_sha256': '2'*64},
            {'grant_id': 'non-random'},
            {'action': 'UPDATE_ISSUE'},
        ):
            forged = replace(self.receipt, **changes)
            self.assertEqual(self.inspect(receipt=forged)['grant_state'], 'BLOCKED')

    def test_receipt_replay_in_new_audience_ledger_prevented(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.reserve(self.ledger(directory))
            self.assertEqual(first['grant_state'], 'RESERVED_ONE_ATTEMPT')
            other_audience = replace(self.kw['intent'], audience='other:host')
            self.assertEqual(self.inspect(intent=other_audience)['grant_state'], 'BLOCKED')

    def test_real_grant_id_factory_unique_shape(self):
        ids = {grant.new_grant_id() for _ in range(25)}
        self.assertEqual(len(ids), 25)
        self.assertTrue(all(grant.GRANT_ID.fullmatch(x) for x in ids))

    def test_sqlite_store_unavailable_returns_unknown_without_claim(self):
        class BrokenStore:
            audience = 'host:review-station-01'
            def atomic_claim(self, grant_id, challenge, now):
                return 'UNAVAILABLE'
        self.assertEqual(self.reserve(BrokenStore())['grant_state'], 'UNKNOWN')

    def test_response_contract_schemas(self):
        root = Path(__file__).resolve().parent.parent / 'references'
        for name in ('issue-create-grant-result.v1.schema.json',
                     'issue-create-approval.v1.schema.json',
                     'issue-create-content.v1.schema.json'):
            jsonschema.Draft202012Validator.check_schema(
                json.loads((root/name).read_text(encoding='utf-8')))
        result_schema = json.loads((root/'issue-create-grant-result.v1.schema.json').read_text())
        approval_schema = json.loads((root/'issue-create-approval.v1.schema.json').read_text())
        for result in (self.inspect(), self.inspect(receipt=None)):
            jsonschema.validate(result, result_schema)
        jsonschema.validate(self.receipt.__dict__, approval_schema)
        with tempfile.TemporaryDirectory() as directory:
            jsonschema.validate(self.reserve(self.ledger(directory)), result_schema)
        invalid = copy.deepcopy(self.inspect())
        invalid['issue_created'] = True
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(invalid, result_schema)


if __name__ == '__main__':
    unittest.main()
