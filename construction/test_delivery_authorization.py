#!/usr/bin/env python3
"""EC224 local synthetic checks, REAL disposable EC200/221/222/223 reads.

The ephemeral test keys do not represent any real human, organization,
recipient or provider account. No delivery is performed.
"""
from __future__ import annotations

from dataclasses import replace
import copy
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

import delivery_preview as dp
import delivery_redaction as dr
import delivery_identity as di
import delivery_authorization as da
import test_delivery_identity as fixtures

SCHEMA = json.loads((Path(__file__).resolve().parent.parent / 'references' /
                     'delivery-authorization-result.v1.schema.json').read_text('utf-8'))
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)
NOW = fixtures.NOW
ISSUER = 'example_approval_authority'
ORG = 'example_organization_private'
APPROVER = 'authorized_approver_2002'


def sign(key, domain, doc):
    return da.SignedAuthorizationStatement(copy.deepcopy(doc),
        key.sign(domain + dp.canonical(doc)).hex())


class AuthorizationCases(unittest.TestCase):
    def setUp(self):
        self.i = fixtures.IdentityCases()
        self.i.setUp()
        self.addCleanup(self.i.doCleanups)
        self.approval_key = Ed25519PrivateKey.generate()
        self.entitlement_key = Ed25519PrivateKey.generate()
        self.revocation_key = Ed25519PrivateKey.generate()
        self.roots = da.TrustedAuthorizationRoots(
            ISSUER, ORG, APPROVER,
            fixtures.public_bytes(self.approval_key),
            fixtures.public_bytes(self.entitlement_key),
            fixtures.public_bytes(self.revocation_key), 42)
        self.authorizer = da.DeliveryAuthorizer(self.roots, self.i.verifier)
        self.proof = self.i.run_verify()
        self.assertEqual(self.proof['status'], 'partial', self.proof)
        self.verified = self.proof['verification']
        self.content = self.i.review['redacted_markdown'].encode('utf-8')
        self.entitlement = self.make_entitlement()
        self.revocation = self.make_revocation()
        self.grant = self.make_grant()
        self.req = self.make_request()

    def make_entitlement(self):
        return {
            'schema': da.ENTITLEMENT_SCHEMA, 'issuer_id': ISSUER,
            'organization_id': ORG, 'approver_id': APPROVER,
            'approval_public_key_sha256': hashlib.sha256(
                self.roots.approval_public_key).hexdigest(),
            'authorization_trust_anchor_binding_sha256': self.authorizer._root_pin,
            'project_id': fixtures.PROJECT,
            'identity_verification_id': self.proof['identity_verification_id'],
            'route_sha256': self.verified['route_sha256'],
            'destination_binding_sha256': self.verified['destination_binding_sha256'],
            'source_set_sha256': self.verified['source_set_sha256'],
            'payload_sha256': hashlib.sha256(self.content).hexdigest(),
            'privacy_ceiling': 'INTERNAL', 'purpose': da.PURPOSE,
            'approver_role': 'INTERNAL_DELIVERY_APPROVER',
            'approver_status': 'ACTIVE', 'organization_status': 'ACTIVE',
            'may_approve_exact_internal_review': True,
            'authorization_epoch': 42,
            'issued_at': NOW - 15, 'expires_at': NOW + 75,
        }

    def make_grant(self, entitlement=None, revocation=None):
        e = self.entitlement if entitlement is None else entitlement
        rev = self.revocation if revocation is None else revocation
        dest = dp.destination_shape(
            self.i.req.sensitive_review_request.preview_request.destination)
        return {
            'schema': da.GRANT_SCHEMA, 'issuer_id': ISSUER,
            'organization_id': ORG, 'approver_id': APPROVER,
            'approval_nonce': 'a1b2c3d4e5f60123456789abcdef0123',
            'purpose': da.PURPOSE, 'project_id': fixtures.PROJECT,
            'recipient_id': fixtures.RECIPIENT, 'channel_id': fixtures.CHANNEL,
            'audience_id': fixtures.AUDIENCE,
            'recipient_identity_sha256': dest['recipient_identity_sha256'],
            'channel_identity_sha256': dest['channel_identity_sha256'],
            'audience_identity_sha256': dest['audience_identity_sha256'],
            'identity_verification_id': self.proof['identity_verification_id'],
            'identity_trust_anchor_binding_sha256':
                self.verified['trust_anchor_binding_sha256'],
            'authorization_trust_anchor_binding_sha256': self.authorizer._root_pin,
            'project_binding_sha256': self.verified['project_binding_sha256'],
            'route_sha256': self.verified['route_sha256'],
            'identity_revocation_checkpoint_sha256':
                self.verified['revocation_checkpoint_sha256'],
            'destination_binding_sha256': self.verified['destination_binding_sha256'],
            'preview_id': self.verified['base_preview_id'],
            'review_id': self.verified['review_id'],
            'policy_revision_sha256': dr.ACTIVE_POLICY_SHA256,
            'approval_code_revision_sha256': da.ACTIVE_APPROVAL_CODE_SHA256,
            'source_set_sha256': self.verified['source_set_sha256'],
            'payload_sha256': hashlib.sha256(self.content).hexdigest(),
            'payload_size_bytes': len(self.content),
            'payload_media_type': da.MEDIA_TYPE,
            'privacy_floor': 'INTERNAL',
            'entitlement_sha256': dp.sha(da.ENTITLEMENT_DOMAIN, e),
            'organization_revocation_checkpoint_sha256': dp.sha(
                da.REVOCATION_DOMAIN, rev),
            'authorization_epoch': e['authorization_epoch'],
            'issued_at': NOW - 10, 'expires_at': NOW + 60,
        }

    def make_revocation(self, grant=None, entitlement=None):
        # Signed by the organization BEFORE the operator approval. A later
        # checkpoint is a new scope and MUST cause a new signed grant.
        g = grant if grant is not None else getattr(self, 'grant', {})
        e = entitlement if entitlement is not None else self.entitlement
        return {
            'schema': da.REVOCATION_SCHEMA, 'issuer_id': ISSUER,
            'organization_id': ORG, 'project_id': fixtures.PROJECT,
            'identity_verification_id': self.proof['identity_verification_id'],
            'identity_trust_anchor_binding_sha256':
                self.verified['trust_anchor_binding_sha256'],
            'route_sha256': self.verified['route_sha256'],
            'destination_binding_sha256': self.verified['destination_binding_sha256'],
            'entitlement_sha256': dp.sha(da.ENTITLEMENT_DOMAIN, e),
            'approval_nonce': g.get('approval_nonce',
                'a1b2c3d4e5f60123456789abcdef0123'),
            'source_set_sha256': g.get('source_set_sha256',
                                     self.verified['source_set_sha256']),
            'payload_sha256': g.get('payload_sha256',
                                  hashlib.sha256(self.content).hexdigest()),
            'privacy_floor': g.get('privacy_floor', 'INTERNAL'),
            'policy_revision_sha256': dr.ACTIVE_POLICY_SHA256,
            'approval_code_revision_sha256': da.ACTIVE_APPROVAL_CODE_SHA256,
            'authorization_trust_anchor_binding_sha256': self.authorizer._root_pin,
            'authorization_epoch': e['authorization_epoch'], 'revocation_epoch': 42,
            'states': {kind: 'ACTIVE' for kind in
                       ('organization', 'approver', 'approval_key',
                        'entitlement', 'authorization_scope')},
            'issued_at': NOW - 12, 'expires_at': NOW + 25,
        }

    def make_request(self, *, identity=None, entitlement=None, grant=None,
                     revocation=None, entitlement_key=None, grant_key=None,
                     revocation_key=None, payload=None, proof_id=None):
        e = self.entitlement if entitlement is None else entitlement
        g = self.grant if grant is None else grant
        r = self.revocation if revocation is None else revocation
        return da.DeliveryAuthorizationRequest(
            identity_request=self.i.req if identity is None else identity,
            expected_identity_verification_id=(
                self.proof['identity_verification_id'] if proof_id is None else proof_id),
            exact_payload_bytes=self.content if payload is None else payload,
            organization_entitlement=sign(entitlement_key or self.entitlement_key,
                                          da.ENTITLEMENT_DOMAIN, e),
            exact_delivery_grant=sign(grant_key or self.approval_key, da.GRANT_DOMAIN, g),
            organization_revocation_checkpoint=sign(
                revocation_key or self.revocation_key, da.REVOCATION_DOMAIN, r),
            permit_independent_delivery_authorization=True,
        )

    def authorize(self, req=None, *, at=NOW, end=None, inner_end=None):
        da_clock = iter((at, at if end is None else end))
        di_clock = iter((at, at if inner_end is None else inner_end))
        with patch.object(da, 'time', types.SimpleNamespace(time=lambda: next(da_clock))), \
             patch.object(di, 'time', types.SimpleNamespace(time=lambda: next(di_clock))):
            return self.authorizer.authorize(self.req if req is None else req)

    def checked(self, r, status):
        self.assertEqual(list(VALIDATOR.iter_errors(r)), [], r)
        self.assertEqual(r['status'], status, r)
        self.assertEqual(r['delivery_state'], 'NO_DELIVERY_OR_PUBLICATION')
        for label in ('recipient_contacted', 'message_sent', 'delivery_accepted',
                      'delivered', 'published', 'external_network_requested',
                      'git_or_business_files_written', 'ces_records_written',
                      'issue_or_pr_created_or_modified', 'external_ai_invoked'):
            self.assertFalse(r['effects'][label])
        for forbidden in (fixtures.RECIPIENT, fixtures.CHANNEL, fixtures.AUDIENCE,
                          fixtures.PROJECT, ORG, APPROVER, 'rendered_markdown',
                          self.i.report.fixture.saved['subject']['rendered_markdown']):
            self.assertNotIn(forbidden, json.dumps(r, ensure_ascii=False))
        if status == 'partial':
            self.assertTrue(r['effects']['recipient_identity_verified'])
            self.assertTrue(r['effects']['delivery_authorized'])
            self.assertFalse(r['authorization']['ready_to_send'])
            self.assertFalse(r['authorization']['message_sent'])
            self.assertFalse(r['authorization']['published'])
        else:
            self.assertIsNone(r['authorization_receipt_id'])
            self.assertIsNone(r['authorization'])
            self.assertFalse(r['effects']['delivery_authorized'])
            self.assertFalse(r['effects']['recipient_identity_verified'])
        return r

    def test_success_actual_ec200_ec221_ec222_ec223_and_exact_payload(self):
        r = self.checked(self.authorize(), 'partial')
        a = r['authorization']
        self.assertEqual(r['exit_code'], 2)
        self.assertEqual(a['identity_verification_id'], self.proof['identity_verification_id'])
        self.assertEqual(a['payload_bytes_sha256'], hashlib.sha256(self.content).hexdigest())
        self.assertEqual(a['source_set_sha256'], self.verified['source_set_sha256'])
        self.assertEqual(a['effective_minimum_privacy_class'], 'INTERNAL')
        self.assertEqual(a['expires_at'], NOW + 25)
        self.assertFalse(a['durable_single_use_or_replay_prevention'])
        self.assertFalse(a['verified_organization_or_human_in_the_real_world'])

    def test_changed_payload_or_wrong_type_rejected_before_any_private_read(self):
        for payload in (self.content + b'!', self.content[:-1],
                        b'?' + self.content[1:],
                        bytearray(self.content), b'\xff', b'', b'\xef\xbb\xbf' + self.content,
                        b'Z' * (dr.MAX_SUMMARY_BYTES + 1)):
            with self.subTest(payload=str(payload)[:36]), patch.object(
                self.i.report.fixture.fx.history, 'show',
                side_effect=AssertionError('preflight must not read private source')):
                state = 'invalid_input' if not isinstance(payload, bytes) or \
                        payload in (b'', b'\xff') or len(payload) > dr.MAX_SUMMARY_BYTES or \
                        payload.startswith(b'\xef\xbb\xbf') else 'blocked'
                self.checked(self.authorize(self.make_request(payload=payload)), state)

    def test_no_independent_consent_before_private_store_read(self):
        for value, status in ((False, 'unavailable'), (1, 'invalid_input')):
            req = replace(self.req, permit_independent_delivery_authorization=value)
            with patch.object(self.i.report.fixture.fx.history, 'show',
                              side_effect=AssertionError('preflight should fail')):
                self.checked(self.authorize(req), status)

    def test_stale_or_forged_proof_is_not_an_authorization(self):
        self.checked(self.authorize(self.make_request(proof_id='cesdi1:' + 'f'*64)),
                     'blocked')
        # The prior EC223 identity-only result has no authorization effects.
        self.assertFalse(self.proof['effects']['delivery_authorized'])

    def test_each_distinct_authority_rejects_wrong_signature_before_read(self):
        choices = ('entitlement_key', 'grant_key', 'revocation_key')
        for label in choices:
            with self.subTest(label=label), patch.object(
                    self.i.report.fixture.fx.history, 'show',
                    side_effect=AssertionError('signed approval gate before read')):
                result = self.checked(self.authorize(self.make_request(
                    **{label: Ed25519PrivateKey.generate()})), 'blocked')
                self.assertIn('SIGNATURE_INVALID', result['reason_code'])

    def test_host_requires_six_independent_public_keys(self):
        repeated = replace(self.roots, approval_public_key=self.i.roots.directory_public_key)
        with self.assertRaisesRegex(ValueError, 'DISTINCT'):
            da.DeliveryAuthorizer(repeated, self.i.verifier)
        duplicated = replace(self.roots,
            organization_revocation_public_key=self.roots.organization_entitlement_public_key)
        with self.assertRaisesRegex(ValueError, 'DISTINCT'):
            da.DeliveryAuthorizer(duplicated, self.i.verifier)

    def test_mutated_signed_recipient_channel_audience_and_project_denied(self):
        for label in ('recipient_id', 'channel_id', 'audience_id', 'project_id',
                      'recipient_identity_sha256', 'channel_identity_sha256',
                      'audience_identity_sha256', 'destination_binding_sha256'):
            grant = copy.deepcopy(self.grant)
            grant[label] = 'proj_different_123' if label == 'project_id' else 'f' * 64
            r = self.make_revocation(grant=grant)
            with self.subTest(field=label), patch.object(
                    self.i.report.fixture.fx.history, 'show',
                    side_effect=AssertionError('reject before private read')):
                self.checked(self.authorize(self.make_request(grant=grant,
                                                             revocation=r)), 'blocked')

    def test_content_policy_code_source_set_privacy_floor_revision_binding(self):
        changes = {
            'preview_id': 'cesdp1:'+'b'*64,
            'review_id': 'cesdr1:'+'c'*64,
            'policy_revision_sha256': 'd'*64,
            'approval_code_revision_sha256': 'e'*64,
            'source_set_sha256': 'f'*64,
            'payload_sha256': 'a'*64,
            'payload_size_bytes': len(self.content)+1,
            'payload_media_type': 'text/html',
            'privacy_floor': 'PUBLIC',
            'identity_revocation_checkpoint_sha256': 'f'*64,
            'identity_trust_anchor_binding_sha256': 'a'*64,
            'project_binding_sha256': 'f'*64,
            'authorization_trust_anchor_binding_sha256': 'e'*64,
        }
        for field, value in changes.items():
            grant = {**self.grant, field: value}
            guard = (nullcontext() if field == 'privacy_floor' else patch.object(
                    self.i.report.fixture.fx.history, 'show',
                    side_effect=AssertionError('reject early')))
            with self.subTest(field=field), guard:
                revision = self.make_revocation(grant=grant)
                if field == 'privacy_floor':
                    # All three signatures are now coherent; only a FRESH
                    # real EC223 read can discover the actual INTERNAL floor.
                    grant = self.make_grant(revocation=revision)
                    grant['privacy_floor'] = 'PUBLIC'
                self.checked(self.authorize(self.make_request(
                    grant=grant, revocation=revision)),
                    'unavailable' if field == 'privacy_floor' else 'blocked')

    def test_organization_permission_is_independent_of_approver_signature(self):
        for field, value in (
            ('may_approve_exact_internal_review', False),
            ('approver_role', 'REVIEW_ONLY'),
            ('approver_status', 'REVOKED'),
            ('organization_status', 'REVOKED'),
            ('privacy_ceiling', 'PUBLIC'),
            ('approval_public_key_sha256', 'f'*64),
            ('source_set_sha256', 'a'*64),
            ('payload_sha256', 'a'*64),
            ('purpose', 'EC223_EXACT_IDENTITY_CHECK_NO_SEND'),
        ):
            with self.subTest(field=field):
                entitlement = {**self.entitlement, field: value}
                rev = self.make_revocation(entitlement=entitlement)
                grant = self.make_grant(entitlement, rev)
                with patch.object(self.i.report.fixture.fx.history, 'show',
                                  side_effect=AssertionError('reject early')):
                    self.checked(self.authorize(self.make_request(
                        entitlement=entitlement, grant=grant,
                        revocation=rev)), 'blocked')

    def test_org_permission_signer_cannot_replace_approver_signer(self):
        with patch.object(self.i.report.fixture.fx.history, 'show',
                          side_effect=AssertionError('no private read')):
            self.checked(self.authorize(self.make_request(
                grant_key=self.entitlement_key)), 'blocked')

    def test_approval_cannot_reuse_identity_verification_operator(self):
        alternate = replace(self.roots, approver_id=fixtures.OPERATOR)
        other = da.DeliveryAuthorizer(alternate, self.i.verifier)
        with patch.object(self.i.report.fixture.fx.history, 'show',
                          side_effect=AssertionError('deny before read')):
            with patch.object(da, 'time', types.SimpleNamespace(time=lambda: NOW)):
                self.checked(other.authorize(self.req), 'blocked')

    def test_signed_revoked_status_each_entity_blocks(self):
        for label in self.revocation['states']:
            rev = copy.deepcopy(self.revocation)
            rev['states'][label] = 'REVOKED'
            with self.subTest(label=label), patch.object(
                    self.i.report.fixture.fx.history, 'show',
                    side_effect=AssertionError('revocation preflight')):
                self.checked(self.authorize(self.make_request(revocation=rev)), 'blocked')

    def test_revocation_must_be_after_grant_and_monotonic_host_epoch(self):
        for patch_data in (
            {'issued_at': NOW-20},
            {'revocation_epoch': 41},
            {'authorization_epoch': 43},
            {'approval_nonce': 'f'*32},
            {'entitlement_sha256': 'e'*64},
            {'identity_verification_id': 'cesdi1:' + 'f'*64},
            {'route_sha256': 'a'*64},
        ):
            rev = {**self.revocation, **patch_data}
            with self.subTest(patch_data=patch_data):
                self.checked(self.authorize(self.make_request(revocation=rev)), 'blocked')
        newer = da.DeliveryAuthorizer(replace(self.roots,
                                  minimum_revocation_epoch=43), self.i.verifier)
        with patch.object(da, 'time', types.SimpleNamespace(time=lambda: NOW)):
            self.checked(newer.authorize(self.req), 'blocked')

    def test_new_signed_active_revocation_snapshot_requires_NEW_approval(self):
        changed = {**self.revocation, 'revocation_epoch': 43,
                   'issued_at': NOW-11}
        # Even a newer, all-ACTIVE, correctly organization-signed checkpoint
        # may not be attached to the OLD approver-signed grant.
        result = self.checked(self.authorize(self.make_request(
            revocation=changed)), 'blocked')
        self.assertIn('GRANT_EXACT_CONTENT', result['reason_code'])
        replacement = self.make_grant(revocation=changed)
        accepted = self.checked(self.authorize(self.make_request(
            revocation=changed, grant=replacement)), 'partial')
        self.assertNotEqual(accepted['authorization']['approver_exact_grant_sha256'],
                            dp.sha(da.GRANT_DOMAIN, self.grant))

    def test_individual_time_windows_and_old_entitlement(self):
        for kw in (
            {'entitlement': {**self.entitlement, 'issued_at': NOW - 200,
                             'expires_at': NOW - 5}},
            {'grant': {**self.grant, 'issued_at': NOW - 100,
                       'expires_at': NOW - 5}},
            {'revocation': {**self.revocation, 'issued_at': NOW - 60,
                            'expires_at': NOW - 10}},
        ):
            self.checked(self.authorize(self.make_request(**kw)), 'blocked')
        self.checked(self.authorize(at=NOW+40), 'blocked')

    def test_expiration_during_private_recheck_fails_closed(self):
        result = self.authorize(end=NOW+30)
        self.checked(result, 'unavailable')
        self.assertIn('AFTER_PRIVATE_READ', result['reason_code'])

    def test_identity_revocation_change_requires_new_grant(self):
        new_identity = self.i.make_request(revocation_override={
            'issued_at': NOW - 2, 'expires_at': NOW+44, 'revocation_epoch': 30})
        result = self.checked(self.authorize(self.make_request(identity=new_identity)),
                              'blocked')
        self.assertIn('GRANT_EXACT_CONTENT', result['reason_code'])

    def test_identity_actual_private_report_recheck_failure_is_not_approval(self):
        with patch.object(self.i.report.fixture.fx.history, 'show',
                          side_effect=OSError('synthetic private store unavailable')):
            outcome = self.checked(self.authorize(), 'unavailable')
            self.assertIn('FRESH_EXACT_EC223', outcome['reason_code'])

    def test_read_grants_rechecked_ec221_ec222_ec223_not_replaced_by_boolean(self):
        old = self.i.req.sensitive_review_request
        sensitive = replace(old, permit_independent_sensitive_policy_review=False)
        identity = replace(self.i.req, sensitive_review_request=sensitive)
        self.checked(self.authorize(self.make_request(identity=identity)), 'unavailable')

    def test_grant_extension_or_mutable_statement_fails_closed(self):
        modified = {**self.grant, 'public_key_from_request':
                    fixtures.public_bytes(self.approval_key).hex()}
        r = self.make_revocation(grant=modified)
        self.checked(self.authorize(self.make_request(grant=modified, revocation=r)),
                     'invalid_input')
        # Statement dict is untrusted/mutable but the preflight snapshots it.
        mutation = self.make_request()
        mutation.exact_delivery_grant.statement['recipient_id'] = 'attacker_1234'
        self.checked(self.authorize(mutation), 'blocked')

    def test_approval_trust_root_replacement_needs_new_org_grant(self):
        other = da.DeliveryAuthorizer(replace(self.roots,
            approval_public_key=fixtures.public_bytes(Ed25519PrivateKey.generate())),
            self.i.verifier)
        with patch.object(da, 'time', types.SimpleNamespace(time=lambda: NOW)):
            self.checked(other.authorize(self.req), 'blocked')

    def test_two_identical_requests_same_local_receipt_not_false_one_use(self):
        a, b = self.authorize(), self.authorize()
        self.checked(a, 'partial')
        self.checked(b, 'partial')
        self.assertEqual(a['authorization_receipt_id'], b['authorization_receipt_id'])
        self.assertFalse(a['authorization']['durable_single_use_or_replay_prevention'])

    def test_zero_permitted_external_or_provider_effects(self):
        r = self.checked(self.authorize(), 'partial')
        self.assertFalse(r['effects']['external_network_requested'])
        self.assertFalse(r['effects']['message_sent'])
        self.assertFalse(r['effects']['delivered'])
        self.assertFalse(r['effects']['published'])
        self.assertFalse(r['authorization']['live_provider_recipient_permission_verified'])
        self.assertFalse(r['authorization']['organizational_declassification_granted'])


if __name__ == '__main__':
    unittest.main()
