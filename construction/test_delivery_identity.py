#!/usr/bin/env python3
"""EC223 directed local checks, using actual disposable EC200/EC222 sources.

Synthetic Ed25519 private keys in this test file have ZERO production trust.
Nothing here simulates an authenticated enterprise directory or real send.
"""
from __future__ import annotations

from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from jsonschema import Draft202012Validator

import delivery_preview as dp
import delivery_redaction as dr
import delivery_identity as di
import test_delivery_redaction as red_fixtures
import test_delivery_preview as preview_fixtures

SCHEMA = json.loads((Path(__file__).resolve().parent.parent / 'references' /
                    'delivery-identity-result.v1.schema.json').read_text('utf-8'))
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)

NOW = 1761300000  # Synthetic fixed clock, NOT enterprise time.
ISSUER = 'example_identity_authority'
PROJECT = 'proj_sampleproject123'
RECIPIENT = 'managed_account_1001'
CHANNEL = 'channel_private_1002'
AUDIENCE = 'audience_private_1003'
OPERATOR = 'verification_operator_1004'


def public_bytes(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def sign(key, domain, statement):
    return di.SignedIdentityStatement(copy.deepcopy(statement),
        key.sign(domain + dp.canonical(statement)).hex())


class IdentityCases(unittest.TestCase):
    def setUp(self):
        self.directory_key = Ed25519PrivateKey.generate()
        self.revocation_key = Ed25519PrivateKey.generate()
        self.permit_key = Ed25519PrivateKey.generate()
        self.roots = di.TrustedIdentityRoots(
            ISSUER, public_bytes(self.directory_key),
            public_bytes(self.revocation_key), public_bytes(self.permit_key))
        self.verifier = di.DeliveryIdentityVerifier(self.roots)
        self.report = red_fixtures.ReportCases()
        self.report.setUp()
        self.addCleanup(self.report.doCleanups)
        self.route = self.make_route()
        dest = self.make_destination(self.route)
        base = replace(self.report.base, destination=dest)
        preview = dp.preview_delivery(base)
        self.assertEqual(preview['status'], 'partial', preview)
        self.review_request = red_fixtures.review_request(base, preview['preview_id'])
        review = dr.review_sensitive_delivery(self.review_request)
        self.assertEqual(review['status'], 'partial', review)
        self.review = review
        self.req = self.make_request()

    def make_route(self, *, role='REPORT_REVIEWER', ceiling='INTERNAL',
                   audience_kind='INTERNAL_REVIEW', channel_kind='CHAT',
                   audience_visibility='PROJECT_PRIVATE',
                   channel_visibility='PROJECT_PRIVATE',
                   issued_at=NOW-20, expires_at=NOW+200):
        return {
            'schema': di.ROUTE_SCHEMA, 'issuer_id': ISSUER,
            'project': {'id': PROJECT, 'status': 'ACTIVE', 'max_privacy': ceiling},
            'recipient': {'id': RECIPIENT, 'kind': 'MANAGED_HUMAN',
                          'project_id': PROJECT, 'role': role,
                          'status': 'ACTIVE', 'privacy_ceiling': ceiling},
            'channel': {'id': CHANNEL, 'kind': channel_kind,
                        'project_id': PROJECT, 'member_recipient_id': RECIPIENT,
                        'membership': 'DIRECT_AUTHORITY_ATTESTED',
                        'visibility': channel_visibility,
                        'privacy_ceiling': ceiling, 'status': 'ACTIVE'},
            'audience': {'id': AUDIENCE, 'kind': audience_kind,
                         'project_id': PROJECT, 'member_recipient_id': RECIPIENT,
                         'selection': 'EXPLICIT_SINGLE_RECIPIENT',
                         'visibility': audience_visibility, 'status': 'ACTIVE'},
            'directory_epoch': 28, 'issued_at': issued_at,
            'expires_at': expires_at,
        }

    def make_destination(self, route):
        return dp.Destination(
            audience_kind=route['audience']['kind'],
            channel_kind=route['channel']['kind'],
            audience_identity_sha256=di.identity_commitment(ISSUER, PROJECT,
                route['audience']['kind'], route['audience']['id']),
            channel_identity_sha256=di.identity_commitment(ISSUER, PROJECT,
                route['channel']['kind'], route['channel']['id']),
            recipient_identity_sha256=di.identity_commitment(ISSUER, PROJECT,
                route['recipient']['kind'], route['recipient']['id']),
        )

    def make_request(self, *, route=None, statuses=None, route_key=None,
                     revocation_key=None, permit_key=None,
                     revocation_override=None, permit_override=None):
        route = copy.deepcopy(self.route if route is None else route)
        rsha = di._sha(di.ROUTE_DOMAIN, route)
        rev = {
            'schema': di.REVOCATION_SCHEMA,
            'issuer_id': ISSUER, 'project_id': PROJECT,
            'route_sha256': rsha, 'directory_epoch': route['directory_epoch'],
            'revocation_epoch': route['directory_epoch'] + 1,
            'states': statuses or dict.fromkeys(
                ('project', 'recipient', 'channel', 'audience'), 'ACTIVE'),
            'issued_at': NOW - 5, 'expires_at': NOW + 45,
        }
        if revocation_override:
            rev.update(revocation_override)
        revsha = di._sha(di.REVOCATION_DOMAIN, rev)
        dest_binding = di._sha(dp.DEST_DOMAIN,
                               dp.destination_shape(self.review_request.preview_request.destination))
        permit = {
            'schema': di.PERMIT_SCHEMA, 'issuer_id': ISSUER,
            'project_id': PROJECT, 'route_sha256': rsha,
            'revocation_checkpoint_sha256': revsha,
            'preview_id': self.review_request.expected_preview_id,
            'review_id': self.review['review_id'],
            'policy_revision_sha256': dr.ACTIVE_POLICY_SHA256,
            'redacted_markdown_sha256': self.review['redacted_markdown_sha256'],
            'destination_binding_sha256': dest_binding,
            'purpose': 'EC223_EXACT_IDENTITY_CHECK_NO_SEND',
            'operator_id': OPERATOR, 'operator_role': 'DIRECTORY_IDENTITY_VERIFIER',
            'issued_at': NOW - 5, 'expires_at': NOW + 90,
        }
        if permit_override:
            permit.update(permit_override)
        return di.DeliveryIdentityRequest(
            sensitive_review_request=self.review_request,
            expected_review_id=self.review['review_id'],
            expected_redacted_markdown_sha256=self.review['redacted_markdown_sha256'],
            project_id=PROJECT,
            directory_route=sign(route_key or self.directory_key, di.ROUTE_DOMAIN, route),
            revocation_checkpoint=sign(revocation_key or self.revocation_key,
                                       di.REVOCATION_DOMAIN, rev),
            verification_permit=sign(permit_key or self.permit_key,
                                     di.PERMIT_DOMAIN, permit),
            permit_independent_identity_verification=True,
        )

    def run_verify(self, req=None, *, clock=NOW):
        with patch.object(di, 'time', types.SimpleNamespace(time=lambda: clock)):
            return self.verifier.verify(self.req if req is None else req)

    def checked(self, result, expected):
        problems = list(VALIDATOR.iter_errors(result))
        self.assertEqual(problems, [], problems)
        self.assertEqual(result['status'], expected, result)
        self.assertEqual(result['delivery_state'], 'NO_DELIVERY_OR_PUBLICATION')
        self.assertFalse(result['effects']['recipient_contacted'])
        self.assertFalse(result['effects']['message_sent'])
        self.assertFalse(result['effects']['delivery_accepted'])
        self.assertFalse(result['effects']['published'])
        self.assertFalse(result['effects']['external_network_requested'])
        self.assertFalse(result['effects']['delivery_authorized'])
        as_text = json.dumps(result, ensure_ascii=False)
        self.assertNotIn(RECIPIENT, as_text)
        self.assertNotIn(CHANNEL, as_text)
        self.assertNotIn(PROJECT, as_text)
        self.assertNotIn(OPERATOR, as_text)
        self.assertNotIn('rendered_markdown', as_text)
        self.assertNotIn(self.report.fixture.saved['subject']['rendered_markdown'], as_text)
        if expected == 'partial':
            self.assertTrue(result['effects']['recipient_identity_verified'])
            self.assertTrue(result['verification']['recipient_verified'])
            self.assertFalse(result['verification']['ready_to_send'])
            self.assertFalse(result['verification']['safe_for_external_send'])
        else:
            self.assertIsNone(result['identity_verification_id'])
            self.assertIsNone(result['verification'])
            self.assertFalse(result['effects']['recipient_identity_verified'])
        return result

    def test_exact_signed_real_local_report_route_verified_but_never_send(self):
        result = self.checked(self.run_verify(), 'partial')
        v = result['verification']
        self.assertEqual(result['exit_code'], 2)
        self.assertEqual(v['review_id'], self.review['review_id'])
        self.assertEqual(v['base_preview_id'], self.review_request.expected_preview_id)
        self.assertEqual(v['redacted_markdown_sha256'],
                         self.review['redacted_markdown_sha256'])
        self.assertTrue(v['explicit_single_recipient'])
        self.assertTrue(v['fresh_signed_revocation_checkpoint_checked'])
        self.assertTrue(v['independent_signed_check_permission_checked'])
        self.assertFalse(v['real_world_person_identity_independently_proven'])
        self.assertFalse(v['organizational_privacy_declassification'])

    def test_wrong_signature_for_each_of_three_independent_authorities(self):
        changes = (
            ('route_key', 'ROUTE_SIGNATURE_INVALID'),
            ('revocation_key', 'REVOCATION_SIGNATURE_INVALID'),
            ('permit_key', 'PERMIT_SIGNATURE_INVALID'),
        )
        for attr, code in changes:
            with self.subTest(authority=attr):
                req = self.make_request(**{attr: Ed25519PrivateKey.generate()})
                with patch.object(self.report.fixture.fx.history, 'show',
                                  side_effect=AssertionError('no source read')):
                    res = self.checked(self.run_verify(req), 'blocked')
                    self.assertIn(code, res['reason_code'])

    def test_untrusted_attached_public_key_cannot_override_host_roots(self):
        forged = copy.deepcopy(self.route)
        forged['directory_public_key'] = public_bytes(self.directory_key).hex()
        req = self.make_request(route=forged)
        self.checked(self.run_verify(req), 'invalid_input')
        unrelated_roots = di.TrustedIdentityRoots(
            ISSUER, public_bytes(Ed25519PrivateKey.generate()),
            self.roots.revocation_public_key, self.roots.verification_public_key)
        with patch.object(di, 'time', types.SimpleNamespace(time=lambda: NOW)):
            self.checked(di.DeliveryIdentityVerifier(unrelated_roots).verify(self.req),
                         'blocked')

    def test_absent_direct_consent_fails_before_source_read(self):
        for x, state in ((False, 'unavailable'), (1, 'invalid_input')):
            with self.subTest(x=x), patch.object(
                    self.report.fixture.fx.history, 'show',
                    side_effect=AssertionError('do not read')):
                self.checked(self.run_verify(replace(
                    self.req, permit_independent_identity_verification=x)), state)

    def test_missing_or_uncommitted_destination_is_not_auto_discovered(self):
        old = self.review_request
        bad = replace(old, preview_request=replace(old.preview_request,
             destination=replace(old.preview_request.destination,
                                 recipient_identity_sha256=None)))
        with patch.object(self.report.fixture.fx.history, 'show',
                          side_effect=AssertionError('no source read')):
            res = self.checked(self.run_verify(replace(
                self.req, sensitive_review_request=bad)), 'invalid_input')
            self.assertIn('ALL_THREE_EXPLICIT_IDENTITIES_REQUIRED', res['reason_code'])

    def test_stale_preview_and_new_recipient_mismatch_are_closed(self):
        broken = replace(self.review_request,
                         expected_preview_id='cesdp1:' + 'a'*64)
        result = self.checked(self.run_verify(replace(
            self.req, sensitive_review_request=broken)), 'blocked')
        self.assertIn('PERMIT_EXACT_SCOPE_OR_OPERATOR_MISMATCH', result['reason_code'])
        different = copy.deepcopy(self.route)
        different['recipient']['id'] = 'managed_account_other123'
        different['channel']['member_recipient_id'] = different['recipient']['id']
        different['audience']['member_recipient_id'] = different['recipient']['id']
        res = self.checked(self.run_verify(self.make_request(route=different)), 'blocked')
        self.assertIn('DESTINATION_IDENTITY_COMMITMENTS_MISMATCH', res['reason_code'])

    def test_project_mismatch_and_wrong_project_scoped_membership(self):
        for change in ('project', 'recipient', 'channel', 'audience'):
            new = copy.deepcopy(self.route)
            if change == 'project':
                new['project']['id'] = 'proj_different_project123'
            else:
                new[change]['project_id'] = 'proj_different_project123'
            with self.subTest(change=change):
                self.checked(self.run_verify(self.make_request(route=new)), 'blocked')

    def test_inactive_account_channel_audience_or_project_block_before_read(self):
        for part in ('recipient', 'channel', 'audience', 'project'):
            mutated = copy.deepcopy(self.route)
            mutated[part]['status'] = 'DISABLED'
            with self.subTest(part=part), patch.object(
                    self.report.fixture.fx.history, 'show',
                    side_effect=AssertionError('no private read')):
                result = self.checked(self.run_verify(self.make_request(route=mutated)),
                                      'blocked')
                self.assertIn('DIRECTORY_ENTITY_INACTIVE_OR_REVOKED', result['reason_code'])

    def test_fresh_signed_revocation_must_cover_every_exact_entity(self):
        for name in ('project', 'recipient', 'channel', 'audience'):
            statuses = dict.fromkeys(('project','recipient','channel','audience'), 'ACTIVE')
            statuses[name] = 'REVOKED'
            with self.subTest(revoked=name), patch.object(
                    self.report.fixture.fx.history, 'show',
                    side_effect=AssertionError('no private read')):
                r = self.checked(self.run_verify(self.make_request(statuses=statuses)),
                                 'blocked')
                self.assertIn('REVOCATION_CHECKPOINT_NOT_ALL_ACTIVE', r['reason_code'])

    def test_revocation_missing_old_or_not_after_directory_epoch(self):
        for kwargs in (
            {'issued_at': NOW - 70, 'expires_at': NOW - 10},
            {'directory_epoch': 29},
            {'revocation_epoch': 0},
        ):
            with self.subTest(kwargs=kwargs):
                self.checked(self.run_verify(self.make_request(
                    revocation_override=kwargs)), 'blocked')

    def test_short_lived_signed_route_and_permit_expire(self):
        old_route = self.make_route(issued_at=NOW - 350, expires_at=NOW - 100)
        self.checked(self.run_verify(self.make_request(route=old_route)), 'blocked')
        self.checked(self.run_verify(self.make_request(permit_override={
            'issued_at': NOW - 180, 'expires_at': NOW - 15})), 'blocked')
        self.checked(self.run_verify(self.req, clock=NOW+80), 'blocked')

    def test_no_preflight_mutation_of_signed_route_or_malleable_extensions(self):
        route = copy.deepcopy(self.route)
        route['channel']['unknown'] = 'ignore me please'
        res = self.checked(self.run_verify(self.make_request(route=route)), 'invalid_input')
        self.assertIn('CHANNEL_SHAPE_INVALID', res['reason_code'])
        route = copy.deepcopy(self.route)
        route['recipient']['role'] = 'COMMIT_AUTHOR'
        self.checked(self.run_verify(self.make_request(route=route)), 'blocked')

    def test_directory_must_prove_direct_membership_not_expand_commit_authors(self):
        for field, value in (('membership', 'INFERRED_FROM_COMMIT_AUTHORS'),
                             ('member_recipient_id', 'another_account_123')):
            route = copy.deepcopy(self.route)
            route['channel'][field] = value
            with self.subTest(field=field):
                self.checked(self.run_verify(self.make_request(route=route)), 'blocked')
        route = copy.deepcopy(self.route)
        route['recipient']['kind'] = 'GIT_COMMIT_AUTHOR'
        self.checked(self.run_verify(self.make_request(route=route)), 'blocked')

    def test_public_or_external_destination_never_eligible_for_current_internal_sources(self):
        for audience, av, cv in (
            ('NAMED_EXTERNAL','EXTERNAL_RESTRICTED', 'EXTERNAL_RESTRICTED'),
            ('PUBLIC_DISTRIBUTION','EXTERNAL_RESTRICTED', 'EXTERNAL_RESTRICTED'),
        ):
            route = self.make_route(audience_kind=audience,
                                    audience_visibility=av, channel_visibility=cv)
            # Make a real EC221+EC222 preview with that explicit external target;
            # even if its local redaction succeeded, it cannot be released.
            req_base = replace(self.review_request.preview_request,
                               destination=self.make_destination(route))
            p = dp.preview_delivery(req_base)
            self.assertEqual(p['status'], 'partial')
            local = replace(self.review_request, preview_request=req_base,
                            expected_preview_id=p['preview_id'])
            r = dr.review_sensitive_delivery(local)
            self.assertEqual(r['status'], 'partial')
            old_req = self.review_request
            old_review = self.review
            self.review_request, self.review = local, r
            try:
                req = self.make_request(route=route)
                outcome = self.checked(self.run_verify(req), 'blocked')
                self.assertIn('EXTERNAL_OR_BROADCAST_TARGET_NOT_ELIGIBLE',
                              outcome['reason_code'])
            finally:
                self.review_request, self.review = old_req, old_review

    def test_untrusted_operator_permission_is_not_a_delivery_grant(self):
        for key, value in (
            ('purpose', 'EC225_SEND'),
            ('operator_role', 'COMMIT_AUTHOR'),
            ('preview_id', 'cesdp1:'+'d'*64),
            ('review_id', 'cesdr1:'+'b'*64),
            ('redacted_markdown_sha256', 'c'*64),
            ('destination_binding_sha256', 'a'*64),
            ('project_id', 'proj_bad_project0001'),
        ):
            with self.subTest(key=key):
                req = self.make_request(permit_override={key: value})
                with patch.object(self.report.fixture.fx.history, 'show',
                                  side_effect=AssertionError('no read')):
                    self.checked(self.run_verify(req), 'blocked')

    def test_tampered_route_signature_or_checkpoint_signature_fails(self):
        for field in ('directory_route', 'revocation_checkpoint',
                      'verification_permit'):
            signed = getattr(self.req, field)
            tampered = replace(signed, signature_hex='0'*128)
            r = self.checked(self.run_verify(replace(self.req, **{field: tampered})),
                             'blocked')
            self.assertIn('SIGNATURE_INVALID', r['reason_code'])

    def test_tampered_private_report_after_identity_permit_returns_no_proof(self):
        changed = replace(self.report.selection, expected_record_sha256='f'*64)
        review = replace(self.review_request, preview_request=replace(
            self.review_request.preview_request, sources=(changed,)))
        bad = replace(self.req, sensitive_review_request=review)
        res = self.checked(self.run_verify(bad), 'unavailable')
        self.assertIn('EXACT_SAFE_LOCAL_EC222_REVIEW_NOT_AVAILABLE', res['reason_code'])

    def test_unsafe_finding_or_blocked_ec222_never_upgrades_identity(self):
        # A verified route alone cannot turn an EC222 blocked result into safe.
        with patch.object(di.dr, 'review_sensitive_delivery', return_value={
                'schema': dr.SCHEMA, 'status': 'blocked', 'exit_code': 5,
                'review_id': self.review['review_id'] } ):
            res = self.checked(self.run_verify(), 'unavailable')
            self.assertIn('EXACT_SAFE_LOCAL_EC222_REVIEW_NOT_AVAILABLE', res['reason_code'])

    def test_privacy_ceiling_and_role_restrictions_are_separate(self):
        # Only for the privacy decision branch. Actual end-to-end tests above
        # ALWAYS call genuine EC222, never use a fake to produce a success.
        mocked = copy.deepcopy(self.review)
        mocked['review']['effective_minimum_privacy_class'] = 'CONFIDENTIAL'
        with patch.object(di.dr, 'review_sensitive_delivery', return_value=mocked):
            result = self.checked(self.run_verify(), 'blocked')
            self.assertIn('CONTENT_EXCEEDS_SIGNED_VISIBILITY_CEILING',
                          result['reason_code'])
        route = self.make_route(ceiling='CONFIDENTIAL')
        with patch.object(di.dr, 'review_sensitive_delivery', return_value=mocked):
            res = self.checked(self.run_verify(self.make_request(route=route)), 'blocked')
            # Destination is still pinned to route's same identity; role is inadequate.
            self.assertIn('RECIPIENT_ROLE_INSUFFICIENT_FOR_CONTENT', res['reason_code'])

    def test_trust_roots_must_be_distinct_out_of_band_values(self):
        for bad in (
            replace(self.roots, verification_public_key=self.roots.directory_public_key),
            replace(self.roots, directory_public_key=b'0'*31),
            replace(self.roots, issuer_id='x'),
        ):
            with self.assertRaises(ValueError):
                di.DeliveryIdentityVerifier(bad)

    def test_source_exception_text_is_never_returned(self):
        with patch.object(self.report.fixture.fx.history, 'show',
                          side_effect=OSError('SECRET=do-not-leak.example')):
            result = self.checked(self.run_verify(), 'unavailable')
            self.assertNotIn('do-not-leak.example', json.dumps(result))

    def test_reread_cannot_succeed_with_stale_revocation_checkpoint(self):
        ticks = iter([NOW, NOW + 51])
        with patch.object(di, 'time', types.SimpleNamespace(time=lambda: next(ticks))):
            res = self.checked(self.verifier.verify(self.req), 'unavailable')
            self.assertIn('IDENTITY_EVIDENCE_EXPIRED_DURING_PRIVATE_RECHECK',
                          res['reason_code'])

    def test_exact_review_identity_and_content_source_digest_are_proof_bound(self):
        a = self.checked(self.run_verify(), 'partial')
        new_revocation = self.make_request(revocation_override={
            'revocation_epoch': self.route['directory_epoch'] + 2})
        b = self.checked(self.run_verify(new_revocation), 'partial')
        self.assertNotEqual(a['identity_verification_id'], b['identity_verification_id'])
        self.assertEqual(a['verification']['source_set_sha256'],
                         b['verification']['source_set_sha256'])
        self.assertEqual(a['verification']['project_binding_sha256'],
                         b['verification']['project_binding_sha256'])

    def test_digest_is_not_automatic_identity_verification_and_limits_input(self):
        self.assertEqual(di.identity_commitment(ISSUER, PROJECT, 'MANAGED_HUMAN',
                                                RECIPIENT),
                         self.req.sensitive_review_request.preview_request.destination.recipient_identity_sha256)
        for args in ((ISSUER, PROJECT, 'GIT_COMMIT_AUTHOR', RECIPIENT),
                     (ISSUER, PROJECT, 'CHAT', 'bad'),
                     (ISSUER, 'bad_project', 'CHAT', CHANNEL)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                di.identity_commitment(*args)
        overlong = copy.deepcopy(self.route)
        overlong['recipient']['id'] = 'person_' + 'x' * 50000
        res = self.checked(self.run_verify(self.make_request(route=overlong)),
                           'invalid_input')
        self.assertIn('ROUTE_BOUNDED_SHAPE_REQUIRED', res['reason_code'])

    def test_request_shape_or_invalid_host_clock_fails_closed(self):
        for clock in (float('nan'), float('inf'), -1, 0):
            with self.subTest(clock=clock):
                self.checked(self.run_verify(clock=clock), 'unavailable')
        self.checked(self.run_verify('not a request'), 'invalid_input')


if __name__ == '__main__':
    unittest.main()
