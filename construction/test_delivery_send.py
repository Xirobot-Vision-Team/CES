#!/usr/bin/env python3
"""EC225 focused synthetic one-use provider tests; NO actual network/recipient.

Every success fixture replays a disposable genuine EC200 ReportHistory -> EC221
preview -> EC222 exact sensitive review -> EC223 signed identity -> EC224
signed org/approver entitlement chain, then a separate EC225 test-only permit.
Ephemeral signatures do not prove a real person, organization or provider.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import copy
import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

import delivery_preview as dp
import delivery_authorization as da
import delivery_send as ds
import test_delivery_authorization as fx
import test_delivery_identity as idfx

RESULT_SCHEMA = json.loads((Path(__file__).resolve().parent.parent / 'references' /
                            'delivery-send-result.v1.schema.json').read_text('utf-8'))
Draft202012Validator.check_schema(RESULT_SCHEMA)
VALID = Draft202012Validator(RESULT_SCHEMA)
NOW = fx.NOW


class SandboxFakePort:
    """Signer-backed deterministic fake, never enters real HTTPS stack."""
    def __init__(self, key):
        self.key = key
        self.probes = 0
        self.posts = 0
        self.changes = {}
        self.fail_probe = False
        self.fail_submit = False
        self.code = 202
        self.after_probe = None
        self.last_body = None

    def probe(self, target, credential, challenge):
        self.probes += 1
        if self.fail_probe:
            raise ds.SendDenied('SYNTHETIC_PROBE_UNAVAILABLE', 'unavailable')
        result = {
            'schema': ds.CAPABILITY_SCHEMA,
            'provider_id': target.provider_id,
            'account_id': target.account_id,
            'provider_target_binding_sha256': challenge['provider_target_binding_sha256'],
            'project_id': target.project_id,
            'recipient_id': target.recipient_id,
            'recipient_identity_sha256': target.recipient_identity_sha256,
            'channel_id': target.channel_id,
            'audience_id': target.audience_id,
            'channel_kind': target.channel_kind,
            'operation_id': challenge['operation_id'],
            'challenge_nonce': challenge['challenge_nonce'],
            'payload_sha256': challenge['payload_sha256'],
            'permission': 'SUBMIT_ONE_TEST_DELIVERY', 'state': 'ACTIVE',
            'single_recipient': True, 'user_controlled_test_destination': True,
            'provider_supports_idempotency': True,
            'issued_at': NOW - 1, 'expires_at': NOW + 10,
        }
        result.update(self.changes)
        if self.after_probe:
            self.after_probe()
        return fx.sign(self.key, ds.CAPABILITY_DOMAIN, result)

    def submit(self, target, credential, body, operation_id):
        self.posts += 1
        self.last_body = json.loads(body)
        if self.fail_submit:
            raise TimeoutError('synthetic timeout / do not echo')
        return self.code


class SendCases(unittest.TestCase):
    def setUp(self):
        self.fx = fx.AuthorizationCases()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.tmp = tempfile.TemporaryDirectory(prefix='ces_ec225_sandbox_')
        self.addCleanup(self.tmp.cleanup)
        self.effect_key = Ed25519PrivateKey.generate()
        self.provider_key = Ed25519PrivateKey.generate()
        self.roots = ds.TrustedSideEffectRoots(
            'sandbox_send_authority', 'send_operator_3000',
            idfx.public_bytes(self.effect_key),
            idfx.public_bytes(self.provider_key), 30)
        self.target = ds.HostTestProvider(
            'test_provider_2026', 'sandbox_account_2026',
            'https://sandbox.example.invalid/ces-test/v1', 'test_inbox_9001',
            idfx.PROJECT, idfx.RECIPIENT, idfx.CHANNEL, idfx.AUDIENCE,
            'CHAT', self.fx.grant['recipient_identity_sha256'], True)
        self.access = ds.HostSendAccess(
            self.roots, self.target, 'sandbox_ephemeral_token_for_unit_fixture',
            self.tmp.name, True, True)
        self.transport = SandboxFakePort(self.provider_key)
        self.sender = ds.DeliverySender(self.access, self.fx.authorizer,
                                        self.transport)
        self.permit = self.make_permit()
        self.req = self.request()

    def make_permit(self):
        r = self.fx
        local = r.authorize()
        a = local['authorization']
        self.assertEqual(local['status'], 'partial', local)
        return {
            'schema': ds.SEND_PERMIT_SCHEMA,
            'issuer_id': self.roots.issuer_id,
            'operator_id': self.roots.operator_id,
            'purpose': ds.PURPOSE,
            'authorization_receipt_id': local['authorization_receipt_id'],
            'approver_exact_grant_sha256': a['approver_exact_grant_sha256'],
            'organization_revocation_checkpoint_sha256':
                a['organization_revocation_checkpoint_sha256'],
            'authorization_trust_anchor_binding_sha256':
                a['authorization_trust_anchor_binding_sha256'],
            'send_trust_anchor_binding_sha256': self.sender._roots_pin,
            'provider_target_binding_sha256': self.sender._target_pin,
            'project_id': idfx.PROJECT, 'recipient_id': idfx.RECIPIENT,
            'channel_id': idfx.CHANNEL, 'audience_id': idfx.AUDIENCE,
            'recipient_identity_sha256': self.target.recipient_identity_sha256,
            'route_sha256': a['route_sha256'],
            'destination_binding_sha256': a['destination_binding_sha256'],
            'source_set_sha256': a['source_set_sha256'],
            'payload_sha256': a['payload_bytes_sha256'],
            'send_code_revision_sha256': ds.ACTIVE_SEND_CODE_SHA256,
            'permission_epoch': 30,
            'send_nonce': 'f00df00df00df00df00df00df00df00d',
            'sandbox_only': True,
            'issued_at': NOW - 3, 'expires_at': NOW + 19,
        }

    def request(self, *, permit=None, key=None, approval=None, consent=True,
                network=True):
        statement = self.permit if permit is None else permit
        signed = fx.sign(self.effect_key if key is None else key,
                         ds.PERMIT_DOMAIN, statement)
        return ds.DeliverySendRequest(
            self.fx.req if approval is None else approval,
            signed, consent, network)

    def send(self, req=None, at=NOW):
        # EC224/223 and EC225 all use the very same frozen synthetic clock.
        with patch.object(ds.time, 'time', return_value=at):
            return self.sender.send_once(self.req if req is None else req)

    def checked(self, result, state):
        errs = list(VALID.iter_errors(result))
        self.assertEqual(errs, [], result)
        self.assertEqual(result['status'], state, result)
        self.assertFalse(result['message_sent'])
        self.assertFalse(result['delivery_accepted'])
        self.assertFalse(result['delivered'])
        self.assertFalse(result['published'])
        for key in ('message_sent', 'delivery_accepted', 'delivered', 'published',
                    'recipient_contacted', 'external_ai_invoked',
                    'git_or_business_files_written', 'ces_records_written'):
            self.assertFalse(result['effects'][key], result)
        text = json.dumps(result, ensure_ascii=False)
        for forbidden in (self.access.credential, self.target.endpoint,
                          self.target.recipient_handle, idfx.RECIPIENT,
                          idfx.PROJECT, self.fx.i.report.fixture.saved['subject'][
                              'rendered_markdown']):
            self.assertNotIn(forbidden, text)
        return result

    def test_real_private_source_chain_sandbox_attempt_then_no_false_sent(self):
        r = self.checked(self.send(), 'partial')
        self.assertEqual(r['submission_state'], 'SUBMISSION_UNCONFIRMED')
        self.assertTrue(r['claim_committed'])
        self.assertTrue(r['provider_sandbox_capability_verified'])
        self.assertTrue(r['submission_post_attempted'])
        self.assertTrue(r['effects']['external_network_requested'])
        self.assertTrue(r['effects']['delivery_authorized'])
        self.assertEqual(self.transport.probes, 1)
        self.assertEqual(self.transport.posts, 1)
        content = self.transport.last_body
        self.assertEqual(content['schema'], ds.SUBMIT_SCHEMA)
        self.assertEqual(content['operation_id'], r['operation_id'])
        self.assertEqual(content['payload_sha256'], hashlib.sha256(self.fx.content).hexdigest())
        self.assertEqual(content['payload_media_type'], da.MEDIA_TYPE)
        self.assertEqual(len(list(Path(self.tmp.name).glob('ec225-*'))), 1)
        slot = next(Path(self.tmp.name).glob('ec225-*'))
        self.assertEqual(set(x.name for x in slot.iterdir()), {
            '00_RESERVED_DURABLE', '01_PROBE_REQUESTED', '02_PROBE_VERIFIED',
            '03_SUBMIT_ATTEMPTED', '04_POST_RETURNED'})
        for p in slot.iterdir():
            self.assertEqual(p.read_bytes(), b'')

    def test_same_grant_and_same_permit_no_second_probe_or_post(self):
        first = self.checked(self.send(), 'partial')
        repeat = self.checked(self.send(), 'blocked')
        self.assertEqual(first['operation_id'], repeat['operation_id'])
        self.assertIn('GRANT_ALREADY_USED', repeat['reason_code'])
        self.assertEqual((self.transport.probes, self.transport.posts), (1, 1))

    def test_same_grant_new_signed_side_effect_nonce_still_no_second_send(self):
        self.checked(self.send(), 'partial')
        changed = {**self.permit, 'send_nonce': 'b' * 32}
        self.checked(self.send(self.request(permit=changed)), 'blocked')
        self.assertEqual(self.transport.posts, 1)

    def test_required_credential_and_both_independent_optins_before_private_read(self):
        variants = [
            (replace(self.access, credential=''), self.req),
            (replace(self.access, enable_live_sandbox_send=False), self.req),
            (replace(self.access, target=replace(self.target, user_controlled_sandbox=False)),
             self.req),
            (self.access, self.request(consent=False)),
            (self.access, self.request(network=False)),
        ]
        for access, req in variants:
            with self.subTest(access=str(access.enable_live_sandbox_send),
                              consent=req.permit_single_sandbox_external_side_effect), \
                 patch.object(self.fx.authorizer, 'authorize',
                              side_effect=AssertionError('no private read')):
                sender = ds.DeliverySender(access, self.fx.authorizer, self.transport)
                result = sender.send_once(req)
                self.checked(result, 'unavailable')
                self.assertIsNone(result['operation_id'])
        self.assertEqual(self.transport.probes, 0)

    def test_false_and_nonbool_consent_rejected(self):
        self.checked(self.send(self.request(consent=False)), 'unavailable')
        self.checked(self.send(self.request(consent=1)), 'invalid_input')

    def test_missing_or_forged_independent_signature_never_probes(self):
        self.checked(self.send(self.request(key=Ed25519PrivateKey.generate())),
                     'blocked')
        self.assertEqual(self.transport.probes, 0)
        self.assertEqual(list(Path(self.tmp.name).glob('ec225-*')), [])

    def test_target_account_route_policy_and_content_are_fully_bound(self):
        for label, value in (
            ('project_id', 'proj_diffproject123'),
            ('recipient_id', 'some_other_recipient'),
            ('channel_id', 'some_other_channel'),
            ('audience_id', 'some_other_audience'),
            ('provider_target_binding_sha256', 'a' * 64),
            ('payload_sha256', 'b' * 64),
            ('route_sha256', 'c' * 64),
            ('send_code_revision_sha256', 'd' * 64),
            ('sandbox_only', False),
            ('permission_epoch', 29),
        ):
            with self.subTest(label=label):
                self.checked(self.send(self.request(permit={**self.permit,
                                                             label: value})), 'blocked')
        self.assertEqual(self.transport.probes, 0)

    def test_host_requires_eight_mutually_distinct_keys(self):
        bad = replace(self.roots,
            side_effect_public_key=self.fx.roots.approval_public_key)
        with self.assertRaisesRegex(ValueError, 'EIGHT_ROOTS'):
            ds.DeliverySender(replace(self.access, roots=bad),
                              self.fx.authorizer, self.transport)
        bad2 = replace(self.roots,
            provider_capability_public_key=self.roots.side_effect_public_key)
        with self.assertRaisesRegex(ValueError, 'EIGHT_ROOTS'):
            ds.DeliverySender(replace(self.access, roots=bad2),
                              self.fx.authorizer, self.transport)

    def test_provider_signature_forged_blocks_after_probe(self):
        self.transport.key = Ed25519PrivateKey.generate()
        r = self.checked(self.send(), 'blocked')
        self.assertTrue(r['claim_committed'])
        self.assertTrue(r['provider_probe_requested'])
        self.assertFalse(r['submission_post_attempted'])
        self.assertEqual(self.transport.posts, 0)

    def test_provider_capability_cross_account_recipient_scope_or_nonce_denied(self):
        for label, value in (
            ('account_id', 'wrong_sandbox_account'),
            ('recipient_id', 'wrong_sandbox_recipient'),
            ('channel_id', 'wrong_sandbox_channel'),
            ('recipient_identity_sha256', 'f' * 64),
            ('operation_id', '0' * 64),
            ('challenge_nonce', 'f' * 32),
            ('permission', 'SUBMIT_ANY_DESTINATION'),
            ('state', 'REVOKED'),
            ('single_recipient', False),
            ('user_controlled_test_destination', False),
            ('provider_supports_idempotency', False),
            ('expires_at', NOW - 1),
        ):
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as temp:
                    other = replace(self.access, outbox_root=temp)
                    fake = SandboxFakePort(self.provider_key)
                    fake.changes = {label: value}
                    sender = ds.DeliverySender(other, self.fx.authorizer, fake)
                    with patch.object(ds.time, 'time', return_value=NOW):
                        result = sender.send_once(self.req)
                    self.checked(result, 'blocked')
                    self.assertEqual(fake.posts, 0)
                    self.assertTrue(result['claim_committed'])

    def test_network_probe_unavailable_no_submit_and_no_retry(self):
        self.transport.fail_probe = True
        first = self.checked(self.send(), 'unavailable')
        self.assertTrue(first['claim_committed'])
        self.assertFalse(first['submission_post_attempted'])
        self.checked(self.send(), 'blocked')
        self.assertEqual((self.transport.probes, self.transport.posts), (1, 0))

    def test_post_timeout_or_http_error_stays_unknown_never_retry(self):
        self.transport.fail_submit = True
        self.checked(self.send(), 'unavailable')
        self.checked(self.send(), 'blocked')
        self.assertEqual(self.transport.posts, 1)

    def test_post_http_500_is_unknown_not_accepted_or_delivered(self):
        self.transport.code = 500
        r = self.checked(self.send(), 'unavailable')
        self.assertEqual(r['submission_state'], 'UNKNOWN_UNCONFIRMED')
        self.assertTrue(r['submission_post_attempted'])
        self.assertFalse(r['effects']['delivery_accepted'])

    def test_changed_payload_cannot_be_sent_after_old_authorization(self):
        altered = replace(self.fx.req, exact_payload_bytes=self.fx.content + b'!')
        r = self.checked(self.send(self.request(approval=altered)), 'unavailable')
        self.assertFalse(r['claim_committed'])
        self.assertEqual(self.transport.probes, 0)

    def test_stale_send_permission_or_missing_outbox_fails_closed(self):
        old = {**self.permit, 'expires_at': NOW - 1}
        self.checked(self.send(self.request(permit=old)), 'blocked')
        bad = replace(self.access, outbox_root=self.tmp.name + '/does_not_exist')
        sender = ds.DeliverySender(bad, self.fx.authorizer, self.transport)
        with patch.object(ds.time, 'time', return_value=NOW):
            r = sender.send_once(self.req)
        self.checked(r, 'unavailable')
        self.assertEqual(self.transport.probes, 0)

    def test_second_private_recheck_failure_suppresses_post_but_uses_grant(self):
        original = self.fx.authorizer.authorize
        calls = [0]
        def fail_second(req):
            calls[0] += 1
            return original(req) if calls[0] == 1 else {'status': 'unavailable'}
        with patch.object(self.fx.authorizer, 'authorize', side_effect=fail_second):
            r = self.checked(self.send(), 'unavailable')
        self.assertTrue(r['claim_committed'])
        self.assertTrue(r['provider_sandbox_capability_verified'])
        self.assertFalse(r['submission_post_attempted'])
        self.assertEqual(self.transport.posts, 0)

    def test_outbox_claim_is_atomic_between_separate_instances(self):
        op = 'a' * 64
        with ds.DurableGrantOutbox(self.tmp.name) as a, \
             ds.DurableGrantOutbox(self.tmp.name) as b:
            a.claim(op)
            with self.assertRaisesRegex(ds.SendDenied, 'GRANT_ALREADY_USED'):
                b.claim(op)
        self.assertEqual(len(list(Path(self.tmp.name).glob('ec225-*'))), 1)

    def test_reject_world_writable_or_symlink_private_outbox(self):
        os.chmod(self.tmp.name, 0o777)
        with self.assertRaisesRegex(ds.SendDenied, 'OUTBOX_OWNER_MODE_INVALID'):
            with ds.DurableGrantOutbox(self.tmp.name):
                pass

    def test_http_provider_endpoint_does_not_accept_unsafe_egress_urls(self):
        for endpoint in ('http://example.com/send', 'https://localhost/send',
                         'https://127.0.0.1/a', 'https://example.com/../send',
                         'https://me:pass@example.com/send',
                         'https://example.com/send?recipient=other'):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValueError):
                    ds.DeliverySender(replace(self.access,
                           target=replace(self.target, endpoint=endpoint)),
                           self.fx.authorizer, self.transport)

    def test_synthetic_port_requires_separate_development_optin(self):
        with self.assertRaisesRegex(ValueError, 'HTTPS_ADAPTER'):
            ds.DeliverySender(replace(self.access,
                allow_synthetic_transport_for_development=False),
                self.fx.authorizer, self.transport)


if __name__ == '__main__':
    unittest.main()
