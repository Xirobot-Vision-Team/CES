#!/usr/bin/env python3
"""EC228 local development tests: real persisted EC200 report, six synthetic signers.

Fake provider never sends a network packet. No claimed real identity, publication,
revocation service, HTTPS provider, secure clock or persistent production FS.
"""
from __future__ import annotations

from dataclasses import replace
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

import delivery_authorization as da
import delivery_preview as dp
import report_history as rh
import report_publish as pub
import test_report_history as histfx

BASE = Path(__file__).resolve().parent.parent
RESPONSE_SCHEMA = json.loads((BASE / 'references' / 'report-publish-result.v1.schema.json').read_text())
Draft202012Validator.check_schema(RESPONSE_SCHEMA)
RESULTS = Draft202012Validator(RESPONSE_SCHEMA)
NOW = 1792826820


def key_bytes(key):
    return key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                          format=serialization.PublicFormat.Raw)


def signed(key, domain, doc):
    return da.SignedAuthorizationStatement(copy.deepcopy(doc),
                                           key.sign(domain + dp.canonical(doc)).hex())


class FakePrivateProvider:
    def __init__(self, provider_key):
        self.key = provider_key
        self.probes = 0
        self.posts = 0
        self.status = 202
        self.mutations = {}
        self.fail_probe = False
        self.fail_post = False
        self.after_probe = None
        self.last_body = None

    def capability(self, target, credential, challenge):
        self.probes += 1
        if self.fail_probe:
            raise OSError('synthetic failure')
        doc = {
            'schema': pub.CAPABILITY_SCHEMA, 'provider_id': target.provider_id,
            'account_id': target.account_id,
            'target_sha256': challenge['target_sha256'],
            'operation_id': challenge['operation_id'],
            'challenge_nonce': challenge['challenge_nonce'],
            'report_ref': challenge['report_ref'],
            'rendered_sha256': challenge['rendered_sha256'],
            'permission': 'PUBLISH_EXACT_ONE_PRIVATE_TEST_REPORT',
            'private_sandbox': True, 'single_destination': True,
            'idempotency_supported': True, 'create_only': True,
            'issued_at': NOW - 1, 'expires_at': NOW + 10,
        }
        doc.update(self.mutations)
        if self.after_probe:
            self.after_probe()
        return signed(self.key, pub.CAPABILITY_DOMAIN, doc)

    def publish(self, target, credential, body, operation_id):
        self.posts += 1
        self.last_body = json.loads(body)
        if self.fail_post:
            raise TimeoutError('synthetic timeout')
        return self.status


class ReportPublishCases(unittest.TestCase):
    def setUp(self):
        self.h = histfx.ReportHistoryTests()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.tmp = tempfile.TemporaryDirectory(prefix='ces-ec228-report-')
        self.addCleanup(self.tmp.cleanup)
        self.ledger = tempfile.TemporaryDirectory(prefix='ces-ec228-outbox-')
        self.addCleanup(self.ledger.cleanup)
        self.first = self.h.saved(self.tmp.name)
        self.doc = self.first['subject']
        self.receipt = self.first['storage']
        self.read_policy = self.h.policy(self.tmp.name, self.first, markdown=True)
        self.keys = [Ed25519PrivateKey.generate() for _ in range(6)]
        self.roots = pub.TrustedPublishRoots(
            'publication_issuer_228', 'publication_operator_228',
            *(key_bytes(k) for k in self.keys), minimum_policy_epoch=18)
        self.target = pub.HostPrivatePublishTarget(
            'sandbox_report_provider_228', 'private_publish_account_228',
            'proj_test_publishing_228', 'private_test_board_228',
            'https://sandbox.example.invalid/ces-reports/v1', True, True)
        self.access = pub.HostPublishAccess(
            self.roots, self.target, 'unit_test_provider_token_228',
            self.ledger.name, True, True)
        self.port = FakePrivateProvider(self.keys[5])
        self.publisher = pub.ReportPublisher(self.access, self.port)
        self.req = self.request()

    def request(self):
        d, r, t = self.doc, self.receipt, self.target
        org = {
            'schema': pub.ORG_SCHEMA, 'issuer_id': self.roots.issuer_id,
            'project_id': t.project_id, 'report_slot_ref': d['report_slot_ref'],
            'provider_id': t.provider_id, 'destination_id': t.destination_id,
            'policy_epoch': 18, 'content_class': pub.CONTENT_CLASS,
            'private_sandbox_only': True,
            'issued_at': NOW - 5, 'expires_at': NOW + 70,
        }
        route = {
            'schema': pub.ROUTE_SCHEMA, 'project_id': t.project_id,
            'provider_id': t.provider_id, 'account_id': t.account_id,
            'destination_id': t.destination_id,
            'target_sha256': self.publisher._target,
            'visibility': 'PRIVATE_TEST_ONLY', 'audience': 'INTERNAL_TEST',
            'single_destination': True,
            'issued_at': NOW - 5, 'expires_at': NOW + 70,
        }
        review = {
            'schema': pub.REVIEW_SCHEMA,
            'report_slot_ref': d['report_slot_ref'],
            'report_ref': d['report_ref'], 'version': 1,
            'record_sha256': r['report_record_sha256'],
            'rendered_sha256': r['rendered_sha256'],
            'entry_sha256': r['entry_sha256'],
            'reviewer_id': 'content_reviewer_228',
            'content_class': pub.CONTENT_CLASS,
            'review_state': 'HUMAN_REVIEWED_EXACT_BYTES_FOR_PRIVATE_TEST',
            'issued_at': NOW - 5, 'expires_at': NOW + 70,
        }
        revocation = {
            'schema': pub.REVOCATION_SCHEMA, 'project_id': t.project_id,
            'destination_id': t.destination_id, 'operator_id': self.roots.operator_id,
            'grant_nonce': 'a' * 32, 'policy_epoch': 18,
            'state': 'ACTIVE', 'issued_at': NOW - 5, 'expires_at': NOW + 10,
        }
        signed_org = signed(self.keys[0], pub.ORG_DOMAIN, org)
        signed_route = signed(self.keys[1], pub.ROUTE_DOMAIN, route)
        signed_revoke = signed(self.keys[2], pub.REVOCATION_DOMAIN, revocation)
        signed_review = signed(self.keys[3], pub.REVIEW_DOMAIN, review)
        grant = {
            'schema': pub.GRANT_SCHEMA, 'issuer_id': self.roots.issuer_id,
            'operator_id': self.roots.operator_id, 'project_id': t.project_id,
            'report_slot_ref': d['report_slot_ref'], 'report_ref': d['report_ref'],
            'version': 1, 'record_sha256': r['report_record_sha256'],
            'rendered_sha256': r['rendered_sha256'], 'entry_sha256': r['entry_sha256'],
            'index_binding_sha256': r['index_binding_sha256'],
            'store_binding_sha256': rh.local_store_binding(self.tmp.name),
            'read_policy_sha256': hashlib.sha256(dp.canonical(self.read_policy)).hexdigest(),
            'organization_sha256': pub._digest(signed_org),
            'route_sha256': pub._digest(signed_route),
            'revocation_sha256': pub._digest(signed_revoke),
            'content_review_sha256': pub._digest(signed_review),
            'target_sha256': self.publisher._target,
            'trust_roots_sha256': self.publisher._roots,
            'code_revision_sha256': pub.ACTIVE_PUBLISH_CODE_SHA256,
            'policy_epoch': 18, 'grant_nonce': 'a' * 32,
            'permission': 'PUBLISH_ONCE_IMMUTABLE_PRIVATE_TEST_REPORT',
            'issued_at': NOW - 5, 'expires_at': NOW + 15,
        }
        return pub.ReportPublishRequest(
            self.tmp.name, d['slot_key'], d['period_id'], copy.deepcopy(d['slot_members']),
            copy.deepcopy(self.read_policy), 1, d['report_ref'],
            r['report_record_sha256'], r['rendered_sha256'], r['entry_sha256'],
            r['index_binding_sha256'], signed_org, signed_route, signed_revoke,
            signed_review, signed(self.keys[4], pub.GRANT_DOMAIN, grant), True, True)

    def call(self, req=None, now=NOW):
        with patch.object(pub.time, 'time', return_value=now):
            return self.publisher.publish_once(self.req if req is None else req)

    def check(self, result, state):
        errs = list(RESULTS.iter_errors(result))
        self.assertFalse(errs, [(e.path, e.message) for e in errs])
        self.assertEqual(result['status'], state, result)
        self.assertFalse(result['published'])
        self.assertFalse(result['external_publication_confirmed'])
        self.assertFalse(result['provider_accepted'])
        self.assertFalse(result['effects']['delivery_submit_requested'])
        self.assertFalse(result['effects']['git_or_business_files_written'])
        self.assertFalse(result['effects']['ces_report_store_modified'])

    def denial(self, suffix, req=None, now=NOW, state='blocked'):
        result = self.call(req, now)
        self.check(result, state)
        self.assertEqual(result['reason_code'], 'REPORT_PUBLISH_' + suffix, result)
        return result

    def new_signed(self, req, field, mutate, *, resign=True):
        field_signer = {'organization': (0, pub.ORG_DOMAIN),
                        'route': (1, pub.ROUTE_DOMAIN),
                        'revocation': (2, pub.REVOCATION_DOMAIN),
                        'content_review': (3, pub.REVIEW_DOMAIN),
                        'side_effect_grant': (4, pub.GRANT_DOMAIN)}
        idx, domain = field_signer[field]
        statement = copy.deepcopy(getattr(req, field).statement)
        mutate(statement)
        new = signed(self.keys[idx], domain, statement) if resign else replace(
            getattr(req, field), statement=statement)
        return replace(req, **{field: new})

    def test_real_store_success_never_claims_publication(self):
        result = self.call()
        self.check(result, 'partial')
        self.assertEqual(result['publication_state'], 'SUBMISSION_UNCONFIRMED')
        self.assertTrue(result['claim_committed'])
        self.assertTrue(result['publish_post_attempted'])
        self.assertEqual((self.port.probes, self.port.posts), (1, 1))
        body = self.port.last_body
        self.assertEqual(body['report_ref'], self.doc['report_ref'])
        self.assertEqual(body['record_sha256'], self.receipt['report_record_sha256'])
        self.assertEqual(hashlib.sha256(base64.b64decode(body['markdown_b64'])).hexdigest(),
                         self.receipt['rendered_sha256'])
        self.assertIn('INTERNAL ONLY', base64.b64decode(body['markdown_b64']).decode())
        self.assertNotIn('some-arbitrary-file-path', str(body))

    def test_same_version_same_target_different_grant_is_not_a_second_post(self):
        self.check(self.call(), 'partial')
        # A new valid grant can be signed, but must never free the original
        # report+destination outbox slot. Original grant cannot replay either.
        self.denial('SAME_REPORT_TARGET_ALREADY_CLAIMED_NO_RETRY')
        self.assertEqual(self.port.posts, 1)

    def test_probe_and_post_failure_never_retries(self):
        self.port.fail_post = True
        first = self.call()
        self.check(first, 'unavailable')
        self.assertEqual(first['publication_state'], 'UNKNOWN_UNCONFIRMED')
        self.assertEqual(first['reason_code'], 'REPORT_PUBLISH_PROVIDER_OUTCOME_UNKNOWN_NO_RETRY')
        self.denial('SAME_REPORT_TARGET_ALREADY_CLAIMED_NO_RETRY')
        self.assertEqual(self.port.posts, 1)

    def test_probe_failure_still_spends_operation(self):
        self.port.fail_probe = True
        r = self.call()
        self.check(r, 'unavailable')
        self.assertTrue(r['claim_committed'])
        self.assertFalse(r['publish_post_attempted'])
        self.denial('SAME_REPORT_TARGET_ALREADY_CLAIMED_NO_RETRY')
        self.assertEqual(self.port.posts, 0)

    def test_provider_http_5xx_is_not_publication_proof(self):
        self.port.status = 503
        self.denial('PROVIDER_HTTP_NOT_PUBLICATION_PROOF_NO_RETRY', state='unavailable')
        self.assertEqual(self.port.posts, 1)
        self.denial('SAME_REPORT_TARGET_ALREADY_CLAIMED_NO_RETRY')

    def test_bad_current_revocation_blocks_before_probe(self):
        bad = self.new_signed(self.req, 'revocation', lambda v: v.update(state='REVOKED'))
        self.denial('SIGNED_PUBLISH_GRANT_NOT_EXACT_OR_CODE_CHANGED', bad)
        self.assertEqual(self.port.probes, 0)

    def test_bad_review_bytes_do_not_upgrade_self_asserted_content(self):
        bad = self.new_signed(self.req, 'content_review',
                              lambda v: v.update(rendered_sha256='f' * 64))
        self.denial('SIGNED_PUBLISH_GRANT_NOT_EXACT_OR_CODE_CHANGED', bad)

    def test_forged_content_signature_denied(self):
        bad = self.new_signed(self.req, 'content_review',
                              lambda v: v.update(review_state='FORGED'), resign=False)
        out = self.call(bad)
        self.check(out, 'blocked')
        self.assertIn('SIGNATURE', out['reason_code'])
        self.assertEqual(self.port.probes, 0)

    def test_bad_org_and_route_signatures_denied(self):
        for name in ('organization', 'route', 'revocation', 'side_effect_grant'):
            with self.subTest(name=name):
                bad = self.new_signed(self.req, name,
                                      lambda v: v.update(issued_at=NOW - 4),
                                      resign=False)
                res = self.call(bad)
                self.check(res, 'blocked')
        self.assertEqual(self.port.probes, 0)

    def test_permission_epoch_and_private_only(self):
        with self.assertRaises(ValueError):
            pub.ReportPublisher(replace(self.access,
                                        target=replace(self.target, sandbox_private=False)),
                                self.port)
        with self.assertRaises(ValueError):
            pub.ReportPublisher(replace(self.access, roots=replace(
                self.roots, provider_public_key=key_bytes(self.keys[4]))), self.port)
        bad = self.new_signed(self.req, 'organization',
                              lambda v: v.update(private_sandbox_only=False))
        self.denial('ORG_POLICY_SCOPE_NOT_PERMITTED', bad)

    def test_recipient_route_and_target_must_remain_fixed(self):
        bad = self.new_signed(self.req, 'route',
                              lambda v: v.update(destination_id='other_private_228'))
        self.denial('PUBLISH_TARGET_NOT_AUTHORIZED', bad)
        self.assertEqual(self.port.posts, 0)

    def test_user_must_explicitly_enable_and_allow_network(self):
        for candidate in (replace(self.req, explicitly_approve_exact_private_publication=False),
                          replace(self.req, permit_sandbox_network_egress=False)):
            with self.subTest(candidate=candidate):
                self.denial('EXPLICIT_HOST_SANDBOX_CONSENT_AND_CREDENTIAL_REQUIRED',
                            candidate, state='unavailable')
        self.assertEqual(self.port.probes, 0)

    def test_credentials_without_live_optin_deny(self):
        self.publisher = pub.ReportPublisher(replace(self.access,
            enable_private_test_publish=False), self.port)
        self.denial('EXPLICIT_HOST_SANDBOX_CONSENT_AND_CREDENTIAL_REQUIRED',
                    state='unavailable')

    def test_version_pin_and_nonexistent_report(self):
        bad = replace(self.req, report_ref='cesrr1:' + 'f'*64)
        self.denial('SIGNED_PUBLISH_GRANT_NOT_EXACT_OR_CODE_CHANGED', bad)
        bad = replace(self.req, version=2)
        self.denial('SIGNED_PUBLISH_GRANT_NOT_EXACT_OR_CODE_CHANGED', bad)

    def test_read_policy_not_promoted_to_external_authority(self):
        wrong = copy.deepcopy(self.read_policy)
        wrong['permit_rendered_markdown'] = False
        bad = replace(self.req, read_policy=wrong)
        self.denial('SIGNED_PUBLISH_GRANT_NOT_EXACT_OR_CODE_CHANGED', bad)

    def test_content_provenance_source_bytes_changed(self):
        path = Path(self.tmp.name) / '.ces-report-render-v1' / (
            'report-' + self.req.report_ref[len('cesrr1:'):] + '.md')
        path.write_bytes(b'tampered artifact not allowed')
        self.denial('REPORT_PRIVATE_SOURCE_NOT_VERIFIABLE', state='unavailable')
        self.assertEqual(self.port.posts, 0)

    def test_report_corrupted_index_cannot_escape(self):
        path = Path(self.tmp.name) / '.ces-report-render-v1' / (
            'index-' + self.doc['report_slot_ref'][len('cesrslot1:'):] + '.json')
        path.write_bytes(b'{}')
        self.denial('REPORT_PRIVATE_SOURCE_NOT_VERIFIABLE', state='unavailable')

    def test_probe_only_then_report_mutation_blocks_post(self):
        def alter():
            path = Path(self.tmp.name) / '.ces-report-render-v1' / (
                'report-' + self.req.report_ref[len('cesrr1:'):] + '.md')
            path.write_bytes(b'changed while probing')
        self.port.after_probe = alter
        self.denial('REPORT_PRIVATE_SOURCE_NOT_VERIFIABLE', state='unavailable')
        self.assertEqual((self.port.probes, self.port.posts), (1, 0))
        self.denial('REPORT_PRIVATE_SOURCE_NOT_VERIFIABLE', state='unavailable')

    def test_probe_capability_wrong_scope(self):
        self.port.mutations = {'challenge_nonce': 'f'*32}
        result = self.call()
        self.check(result, 'blocked')
        self.assertEqual(result['reason_code'],
                         'REPORT_PUBLISH_PROVIDER_UNAUTHORIZED_PRIVATE_CAPABILITY')
        self.assertEqual(self.port.posts, 0)
        self.denial('SAME_REPORT_TARGET_ALREADY_CLAIMED_NO_RETRY')

    def test_provider_create_only_rejection_blocks_post(self):
        self.port.mutations = {'create_only': False}
        result = self.call()
        self.check(result, 'blocked')
        self.assertEqual(result['reason_code'],
                         'REPORT_PUBLISH_PROVIDER_UNAUTHORIZED_PRIVATE_CAPABILITY')
        self.assertEqual(self.port.posts, 0)

    def test_provider_narrow_idempotency_rejection_blocks_post(self):
        self.port.mutations = {'idempotency_supported': False}
        result = self.call()
        self.check(result, 'blocked')
        self.assertEqual(self.port.posts, 0)

    def test_provider_old_signature_rejection_blocks_post(self):
        self.port.mutations = {'issued_at': NOW - 100}
        result = self.call()
        self.check(result, 'blocked')
        self.assertEqual(result['reason_code'],
                         'REPORT_PUBLISH_PROVIDER_CAPABILITY_EXPIRED_OR_NOT_CURRENT')
        self.assertEqual(self.port.posts, 0)

    def test_expired_grant_denied_before_store(self):
        bad = self.new_signed(self.req, 'side_effect_grant',
                              lambda v: v.update(expires_at=NOW - 1))
        self.denial('PUBLISH_GRANT_EXPIRED_OR_NOT_CURRENT', bad)
        self.assertEqual(self.port.probes, 0)

    def test_expired_revocation_denied_before_network(self):
        bad = self.new_signed(self.req, 'revocation',
                              lambda v: v.update(expires_at=NOW - 1))
        self.denial('REVOCATION_EXPIRED_OR_NOT_CURRENT', bad)

    def test_signed_read_policy_allowlist_is_enforced_even_with_signed_publish(self):
        # One repository explicitly refuses the Markdown disclosure. Re-signing
        # the independent outer grant does not bypass the genuine EC200 gate.
        policy = copy.deepcopy(self.req.read_policy)
        policy['repository_grants'][0]['permit_rendered_markdown'] = False
        grant = copy.deepcopy(self.req.side_effect_grant.statement)
        grant['read_policy_sha256'] = hashlib.sha256(dp.canonical(policy)).hexdigest()
        bad = replace(self.req, read_policy=policy,
                      side_effect_grant=signed(self.keys[4], pub.GRANT_DOMAIN, grant))
        self.denial('REPOSITORY_MARKDOWN_READ_NOT_AUTHORIZED', bad)
        self.assertEqual(self.port.probes, 0)

    def test_new_correction_at_provider_probe_never_publishes_superseded_version(self):
        def correct():
            c = self.h.correction(self.first, self.read_policy)
            result = self.h.correct(self.tmp.name, self.first, self.read_policy, c)
            self.assertEqual(result['status'], 'partial', result)
        self.port.after_probe = correct
        result = self.call()
        self.check(result, 'blocked')
        self.assertEqual(result['reason_code'], 'REPORT_PUBLISH_REPORT_SUPERSEDED_REQUIRE_NEW_REVIEW')
        self.assertEqual((self.port.probes, self.port.posts), (1, 0))

    def test_wrong_provider_signature_has_no_post(self):
        self.port.key = Ed25519PrivateKey.generate()
        result = self.call()
        self.check(result, 'blocked')
        self.assertEqual(self.port.posts, 0)
        self.assertIn('SIGNATURE', result['reason_code'])

    def test_revocation_can_expire_after_fsynced_attempt_marker_before_post(self):
        clock = {'now': NOW}
        original = pub.PrivatePublishOutbox.mark
        def around(ledger, marker):
            original(ledger, marker)
            if marker == '03_POST_ATTEMPTED':
                clock['now'] = NOW + 11  # after signed CURRENT revocation expiry
        with patch.object(pub.time, 'time', side_effect=lambda: clock['now']):
            with patch.object(pub.PrivatePublishOutbox, 'mark', around):
                result = self.publisher.publish_once(self.req)
        self.check(result, 'unavailable')
        self.assertEqual(result['reason_code'],
                         'REPORT_PUBLISH_DURABLE_PUBLISH_EDGE_EXPIRED_NO_RETRY')
        self.assertTrue(result['claim_committed'])
        self.assertFalse(result['publish_post_attempted'])
        self.assertEqual(self.port.posts, 0)

    def test_request_routed_through_symlinked_store_denied(self):
        # The store is allowed to exist, but the host-selected *root* may not
        # be an attacker redirected symbolic link.
        link = Path(self.ledger.name) / 'report_root'
        link.symlink_to(self.tmp.name, target_is_directory=True)
        bad = replace(self.req, storage_root=str(link))
        result = self.call(bad)
        self.check(result, 'unavailable')
        self.assertEqual(self.port.probes, 0)

    def test_provider_delay_expires_grant_prevents_post(self):
        # Time jumps past permit expiry once the provider probe starts.
        def clock():
            if self.port.probes:
                return NOW + 20
            return NOW
        with patch.object(pub.time, 'time', side_effect=clock):
            result = self.publisher.publish_once(self.req)
        self.check(result, 'blocked')
        self.assertEqual(self.port.posts, 0)
        self.assertTrue(result['claim_committed'])

    def test_duplicate_root_constructor_denial(self):
        broken = replace(self.roots, provider_public_key=self.roots.side_effect_public_key)
        with self.assertRaises(ValueError):
            pub.ReportPublisher(replace(self.access, roots=broken), self.port)

    def test_real_port_required_without_explicit_synthetic_mode(self):
        with self.assertRaises(ValueError):
            pub.ReportPublisher(replace(self.access,
                                        allow_synthetic_transport_for_development=False), self.port)

    def test_outbox_private_mode_required(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            path.chmod(0o755)
            bad = pub.ReportPublisher(replace(self.access, outbox_root=root), self.port)
            self.assertIn('OUTBOX_NOT_OWNER_PRIVATE',
                          self.call_with(bad)['reason_code'])
            self.assertEqual(self.port.posts, 0)

    def call_with(self, publisher):
        with patch.object(pub.time, 'time', return_value=NOW):
            return publisher.publish_once(self.req)

    def test_no_report_input_path_or_arbitrary_payload_in_request(self):
        self.assertNotIn('markdown', pub.ReportPublishRequest.__dataclass_fields__)
        self.assertNotIn('file_path', pub.ReportPublishRequest.__dataclass_fields__)
        self.assertNotIn('remote_url', pub.ReportPublishRequest.__dataclass_fields__)

    def test_signed_grant_binds_current_source_code_sha(self):
        bad = self.new_signed(self.req, 'side_effect_grant',
                              lambda v: v.update(code_revision_sha256='0'*64))
        self.denial('SIGNED_PUBLISH_GRANT_NOT_EXACT_OR_CODE_CHANGED', bad)

    def test_http_status_has_no_published_or_remote_receipt_claim(self):
        result = self.call()
        self.check(result, 'partial')
        self.assertFalse(result['external_visibility_verified'])
        self.assertNotIn('remote_document_id', result)
        self.assertNotIn('external_publication_id', result)

    def test_outbox_operation_scope_report_target_not_nonce(self):
        result = self.call()
        self.check(result, 'partial')
        self.assertEqual(result['operation_id'], dp.sha(pub.OP_DOMAIN, {
            'report_slot_ref': self.doc['report_slot_ref'],
            'report_ref': self.doc['report_ref'],
            'rendered_sha256': self.receipt['rendered_sha256'],
            'target_sha256': self.publisher._target,
            'project_id': self.target.project_id}))

    def test_schema_fails_if_unverified_publication_is_claimed(self):
        result = self.call()
        forged = copy.deepcopy(result)
        forged['published'] = True
        self.assertTrue(list(RESULTS.iter_errors(forged)))

    def test_no_host_provider_and_powershell_side_effect(self):
        self.check(self.call(), 'partial')
        self.assertFalse(self.port.last_body.get('overwrite'))
        self.assertFalse(self.port.last_body.get('update_existing'))
        self.assertNotIn('recipient_list', self.port.last_body)
        self.assertTrue(self.port.last_body['create_only'])
        self.assertFalse(self.port.last_body['overwrite_existing'])


if __name__ == '__main__':
    unittest.main()
