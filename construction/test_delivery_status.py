#!/usr/bin/env python3
"""EC226 offline synthetic acceptance vs inbox delivery development checks.

No real Provider, network, user inbox, enterprise permissions or external send.
The underlying EC225 fixture exercises genuine EC200 -> EC221-225 synthetic
private store reads and an ephemeral fake once before any status observation.
"""
from __future__ import annotations

from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

import delivery_preview as dp
import delivery_authorization as da
import delivery_send as ds
import delivery_status as st
import test_delivery_send as sendfx
import test_delivery_identity as idfx
import test_delivery_authorization as authfx

NOW = authfx.NOW
RESULT_SCHEMA = json.loads((Path(__file__).resolve().parent.parent / 'references' /
                            'delivery-status-result.v1.schema.json').read_text('utf8'))
Draft202012Validator.check_schema(RESULT_SCHEMA)
VALIDATOR = Draft202012Validator(RESULT_SCHEMA)


def seal(key, domain, doc):
    return {'statement': copy.deepcopy(doc),
            'signature_hex': key.sign(domain + dp.canonical(doc)).hex()}


class SignedSyntheticStatusPort:
    def __init__(self, provider_key, inbox_key, observer_id):
        self.provider_key, self.inbox_key = provider_key, inbox_key
        self.observer_id = observer_id
        self.state = 'UNKNOWN'
        self.inbox = False
        self.lookups = 0
        self.last_query = None
        self.provider_patch = {}
        self.ack_patch = {}
        self.fail = False
        self.stale = False
        self.forger = None
        self.on_query = None

    def status(self, target, credential, query):
        self.lookups += 1
        self.last_query = copy.deepcopy(query)
        if self.on_query is not None:
            self.on_query()
        if self.fail:
            raise OSError('synthetic provider status unavailable')
        stamp = NOW - 30 if self.stale else NOW
        state = self.state
        accepted = NOW - 10 if state in ('ACCEPTED', 'DELIVERED') else None
        delivered = NOW - 5 if state == 'DELIVERED' else None
        message = hashlib.sha256(b'ephemeral-private-test-provider-id').hexdigest()
        doc = {
            **query, 'schema': st.STATUS_SCHEMA, 'state': state,
            'provider_message_id_sha256': message if accepted is not None else None,
            'accepted_at': accepted, 'delivered_at': delivered,
            'observed_at': stamp, 'issued_at': stamp - 1, 'expires_at': stamp + 16,
        }
        doc.update(self.provider_patch)
        provider_key = self.provider_key if self.forger is None else self.forger
        provider = seal(provider_key, st.STATUS_DOMAIN, doc)
        ack = None
        if self.inbox:
            a = {
                'schema': st.INBOX_SCHEMA, 'observer_id': self.observer_id,
                'purpose': st.INBOX_PURPOSE, 'provider_id': query['provider_id'],
                'account_id': query['account_id'],
                'provider_target_binding_sha256': query['provider_target_binding_sha256'],
                'operation_id': query['operation_id'],
                'approver_exact_grant_sha256': query['approver_exact_grant_sha256'],
                'recipient_identity_sha256': query['recipient_identity_sha256'],
                'channel_id': query['channel_id'], 'audience_id': query['audience_id'],
                'payload_sha256': query['payload_sha256'],
                'provider_message_id_sha256': doc['provider_message_id_sha256'],
                'provider_status_sha256': dp.sha(st.STATUS_DOMAIN, doc),
                'read_grant_sha256': query['read_grant_sha256'],
                'challenge_nonce': query['challenge_nonce'],
                'test_destination_only': True, 'inbox_observed_at': NOW - 2,
                'issued_at': NOW, 'expires_at': NOW + 10,
            }
            a.update(self.ack_patch)
            ack = seal(self.inbox_key, st.INBOX_DOMAIN, a)
        return {'provider_status': provider, 'inbox_observation': ack}


class StatusCases(unittest.TestCase):
    def setUp(self):
        self.s = sendfx.SendCases()
        self.s.setUp()
        self.addCleanup(self.s.doCleanups)
        self.read_key = Ed25519PrivateKey.generate()
        self.inbox_key = Ed25519PrivateKey.generate()
        self.roots = st.TrustedStatusRoots(
            'status_issuer_226', 'status_reader_226', 'inbox_observer_226',
            idfx.public_bytes(self.read_key), idfx.public_bytes(self.inbox_key), 53)
        self.access = st.HostStatusAccess(
            self.roots, 'independent_status_only_ephemeral_token', True, True)
        self.transport = SignedSyntheticStatusPort(
            self.s.provider_key, self.inbox_key, self.roots.inbox_observer_id)
        self.reader = st.DeliveryStatusReader(self.s.sender, self.access, self.transport)
        self.sent = False
        self.read_nonce = '0123456789abcdef0123456789abcdef'

    def send_once(self):
        with patch.object(ds.time, 'time', return_value=NOW):
            r = self.s.sender.send_once(self.s.req)
        self.assertEqual(r['status'], 'partial', r)
        self.sent = True
        return r

    def grant(self, **updates):
        grant = {
            'schema': st.READ_SCHEMA, 'issuer_id': self.roots.issuer_id,
            'reader_id': self.roots.reader_id, 'purpose': st.READ_PURPOSE,
            'send_trust_anchor_binding_sha256': self.s.sender._roots_pin,
            'status_trust_anchor_binding_sha256': self.reader._root_pin,
            'provider_target_binding_sha256': self.s.sender._target_pin,
            'authorization_receipt_id': self.s.permit['authorization_receipt_id'],
            'approver_exact_grant_sha256': self.s.permit['approver_exact_grant_sha256'],
            'side_effect_permit_sha256': dp.sha(ds.PERMIT_DOMAIN, self.s.permit),
            'provider_id': self.s.target.provider_id,
            'account_id': self.s.target.account_id,
            'project_id': self.s.target.project_id,
            'recipient_id': self.s.target.recipient_id,
            'channel_id': self.s.target.channel_id,
            'audience_id': self.s.target.audience_id,
            'recipient_identity_sha256': self.s.target.recipient_identity_sha256,
            'payload_sha256': hashlib.sha256(self.s.fx.content).hexdigest(),
            'source_set_sha256': self.s.permit['source_set_sha256'],
            'operation_id': dp.sha(ds.OP_DOMAIN, {
                'ec224_approver_grant_sha256': self.s.permit['approver_exact_grant_sha256'],
                'organization_approval_anchor_sha256': self.s.fx.authorizer._root_pin,
                'project_binding_sha256': self.s.fx.grant['project_binding_sha256'],
            }),
            'read_nonce': self.read_nonce, 'permission_epoch': 53,
            'sandbox_only': True,
            'issued_at': NOW - 2, 'expires_at': NOW + 19,
        }
        grant.update(updates)
        return grant

    def req(self, grant=None, *, key=None, permission=True, network=True, original=None):
        statement = self.grant() if grant is None else grant
        return st.DeliveryStatusRequest(
            self.s.req if original is None else original,
            authfx.sign(self.read_key if key is None else key,
                        st.READ_DOMAIN, statement), permission, network)

    def run_status(self, request=None, at=NOW):
        with patch.object(ds.time, 'time', return_value=at):
            return self.reader.observe_once(self.req() if request is None else request)

    def checked(self, value, *, state, status='partial'):
        errors = list(VALIDATOR.iter_errors(value))
        self.assertEqual(errors, [], value)
        self.assertEqual(value['status'], status, value)
        self.assertEqual(value['delivery_state'], state, value)
        self.assertFalse(value['resent'])
        self.assertFalse(value['message_sent_by_status_read'])
        self.assertFalse(value['published'])
        self.assertFalse(value['effects']['provider_submit_requested'])
        self.assertFalse(value['effects']['recipient_contacted_by_status_read'])
        encoded = json.dumps(value, ensure_ascii=False)
        for private in (
            self.s.access.credential, self.access.read_credential,
            self.s.target.endpoint, self.s.target.recipient_handle,
            self.s.fx.i.report.fixture.saved['subject']['rendered_markdown'],
        ):
            self.assertNotIn(private, encoded)
        return value

    def test_no_original_attempt_marker_never_queries_network(self):
        r = self.checked(self.run_status(), status='unavailable',
                         state='UNKNOWN_UNCONFIRMED')
        self.assertFalse(r['submit_attempt_marker_verified'])
        self.assertEqual(self.transport.lookups, 0)

    def test_submitted_http202_does_not_prove_provider_accepted(self):
        original = self.send_once()
        self.assertEqual(original['submission_state'], 'SUBMISSION_UNCONFIRMED')
        r = self.checked(self.run_status(), state='UNKNOWN_UNCONFIRMED')
        self.assertEqual(r['provider_state'], 'UNKNOWN')
        self.assertFalse(r['provider_accepted'])
        self.assertFalse(r['recipient_delivery_observed'])
        self.assertTrue(r['provider_evidence_verified'])
        self.assertEqual(self.transport.lookups, 1)
        self.assertEqual(self.s.transport.posts, 1)

    def test_provider_pending_is_unknown_not_accepted(self):
        self.send_once()
        self.transport.state = 'PENDING'
        self.checked(self.run_status(), state='UNKNOWN_UNCONFIRMED')

    def test_fresh_signed_accepted_only_does_not_claim_delivery(self):
        self.send_once()
        self.transport.state = 'ACCEPTED'
        r = self.checked(self.run_status(), state='ACCEPTED_PROVIDER_ATTESTED')
        self.assertTrue(r['provider_accepted'])
        self.assertFalse(r['recipient_delivery_observed'])
        self.assertFalse(r['inbox_evidence_verified'])

    def test_provider_delivered_without_independent_inbox_is_only_accepted(self):
        self.send_once()
        self.transport.state = 'DELIVERED'
        r = self.checked(self.run_status(), state='ACCEPTED_PROVIDER_ATTESTED')
        self.assertEqual(r['provider_state'], 'DELIVERED')
        self.assertFalse(r['recipient_delivery_observed'])

    def test_real_two_independent_signed_evidence_layers_show_observed_delivery(self):
        self.send_once()
        self.transport.state = 'DELIVERED'
        self.transport.inbox = True
        r = self.checked(self.run_status(), state='DELIVERED_INBOX_OBSERVED')
        self.assertTrue(r['provider_accepted'])
        self.assertTrue(r['recipient_delivery_observed'])
        self.assertTrue(r['inbox_evidence_verified'])
        self.assertTrue(r['provider_evidence_verified'])
        self.assertEqual(self.transport.lookups, 1)
        self.assertEqual(self.s.transport.posts, 1)

    def test_provider_rejected_or_failed_attested_is_not_negative_delivery_proof(self):
        for state, expected in (('REJECTED', 'PROVIDER_REJECTION_ATTESTED'),
                                ('FAILED', 'PROVIDER_FAILURE_ATTESTED')):
            with self.subTest(state=state):
                self.send_once() if not self.sent else None
                self.transport.state = state
                self.read_nonce = '1' * 32 if state == 'FAILED' else '2' * 32
                result = self.checked(self.run_status(), state=expected)
                self.assertFalse(result['provider_accepted'])
                self.assertFalse(result['recipient_delivery_observed'])

    def test_read_grant_exact_replay_blocks_before_second_network(self):
        self.send_once()
        self.checked(self.run_status(), state='UNKNOWN_UNCONFIRMED')
        r = self.checked(self.run_status(), status='blocked',
                         state='UNKNOWN_UNCONFIRMED')
        self.assertIn('REPLAY', r['reason_code'])
        self.assertEqual(self.transport.lookups, 1)

    def test_same_read_nonce_different_fresh_signature_cannot_replay(self):
        self.send_once()
        self.checked(self.run_status(), state='UNKNOWN_UNCONFIRMED')
        changed = self.grant(issued_at=NOW - 1)
        self.checked(self.run_status(self.req(changed)), status='blocked',
                     state='UNKNOWN_UNCONFIRMED')
        self.assertEqual(self.transport.lookups, 1)

    def test_new_independent_read_nonce_can_recheck_status_without_resubmit(self):
        self.send_once()
        self.checked(self.run_status(), state='UNKNOWN_UNCONFIRMED')
        self.transport.state = 'ACCEPTED'
        self.read_nonce = '3' * 32
        self.checked(self.run_status(), state='ACCEPTED_PROVIDER_ATTESTED')
        self.assertEqual(self.s.transport.posts, 1)
        self.assertEqual(self.transport.lookups, 2)

    def test_no_consent_credential_or_egress_refuses_before_network(self):
        self.send_once()
        for request, access in (
            (self.req(permission=False), self.access),
            (self.req(network=False), self.access),
            (self.req(permission=1), self.access),
            (self.req(), replace(self.access, read_credential='')),
            (self.req(), replace(self.access, enable_live_private_status_read=False)),
        ):
            reader = st.DeliveryStatusReader(self.s.sender, access, self.transport)
            with patch.object(ds.time, 'time', return_value=NOW):
                result = reader.observe_once(request)
            self.checked(result, state='UNKNOWN_UNCONFIRMED',
                         status='invalid_input' if type(request.permit_independent_status_read) is int else 'unavailable')
        self.assertEqual(self.transport.lookups, 0)

    def test_read_permission_bad_signature_rejected_before_local_nonce_and_network(self):
        self.send_once()
        bad = self.req(key=Ed25519PrivateKey.generate())
        self.checked(self.run_status(bad), status='blocked',
                     state='UNKNOWN_UNCONFIRMED')
        self.assertEqual(self.transport.lookups, 0)

    def test_read_grant_cross_account_content_recipient_scope_epoch_are_denied(self):
        self.send_once()
        cases = (
            ('provider_id', 'other_provider_888'),
            ('account_id', 'other_account_888'),
            ('recipient_identity_sha256', 'a' * 64),
            ('provider_target_binding_sha256', 'b' * 64),
            ('side_effect_permit_sha256', 'c' * 64),
            ('payload_sha256', 'd' * 64),
            ('approver_exact_grant_sha256', 'e' * 64),
            ('source_set_sha256', 'a' * 64),
            ('status_trust_anchor_binding_sha256', 'a' * 64),
            ('operation_id', '0' * 64),
            ('permission_epoch', 52),
            ('sandbox_only', False),
            ('read_nonce', 'x' * 32),
        )
        for name, value in cases:
            with self.subTest(field=name):
                r = self.run_status(self.req({**self.grant(), name: value}))
                self.checked(r, status='blocked', state='UNKNOWN_UNCONFIRMED')
        self.assertEqual(self.transport.lookups, 0)

    def test_grant_expired_or_noninteger_epochs_denied(self):
        self.send_once()
        for grant in (self.grant(expires_at=NOW),
                      self.grant(issued_at=NOW - 90),
                      self.grant(permission_epoch=True)):
            self.checked(self.run_status(self.req(grant)), status='blocked',
                         state='UNKNOWN_UNCONFIRMED')
        self.assertEqual(self.transport.lookups, 0)

    def test_provider_forged_signature_is_not_trusted(self):
        self.send_once()
        self.transport.state = 'DELIVERED'
        self.transport.inbox = True
        self.transport.forger = Ed25519PrivateKey.generate()
        self.checked(self.run_status(), status='blocked',
                     state='UNKNOWN_UNCONFIRMED')

    def test_provider_wrong_operation_account_recipient_nonce_or_payload_fails_closed(self):
        self.send_once()
        cases = (
            ('operation_id', 'a' * 64),
            ('account_id', 'some_other_account_998'),
            ('recipient_id', 'another_recipient_999'),
            ('payload_sha256', 'b' * 64),
            ('challenge_nonce', 'c' * 32),
            ('read_grant_sha256', 'd' * 64),
            ('provider_target_binding_sha256', 'e' * 64),
        )
        self.transport.state = 'ACCEPTED'
        for index, (field, value) in enumerate(cases):
            with self.subTest(field=field):
                self.read_nonce = f'{index+30:032x}'
                self.transport.provider_patch = {field: value}
                self.checked(self.run_status(), status='blocked',
                             state='UNKNOWN_UNCONFIRMED')

    def test_invalid_timestamp_sequence_or_contradictory_state_fails_closed(self):
        self.send_once()
        cases = (
            ('ACCEPTED', {'delivered_at': NOW - 1}),
            ('ACCEPTED', {'accepted_at': NOW + 90}),
            ('DELIVERED', {'delivered_at': NOW - 20}),
            ('PENDING', {'accepted_at': NOW - 10}),
            ('DELIVERED', {'provider_message_id_sha256': None}),
        )
        for index, (state, patch_doc) in enumerate(cases):
            with self.subTest(state=state, patch=patch_doc):
                self.read_nonce = f'{index+100:032x}'
                self.transport.state = state
                self.transport.provider_patch = patch_doc
                self.checked(self.run_status(), status='blocked',
                             state='UNKNOWN_UNCONFIRMED')

    def test_provider_expired_signed_status_or_timeout_never_accepts(self):
        self.send_once()
        self.transport.stale = True
        self.checked(self.run_status(), status='blocked',
                     state='UNKNOWN_UNCONFIRMED')
        self.read_nonce = 'a' * 32
        self.transport.stale = False
        self.transport.fail = True
        self.checked(self.run_status(), status='unavailable',
                     state='UNKNOWN_UNCONFIRMED')
        self.assertEqual(self.s.transport.posts, 1)

    def test_independent_inbox_observation_wrong_message_or_signature_fails_closed(self):
        self.send_once()
        self.transport.state = 'DELIVERED'
        self.transport.inbox = True
        for index, (field, value) in enumerate((
            ('provider_message_id_sha256', 'a' * 64),
            ('provider_status_sha256', 'b' * 64),
            ('recipient_identity_sha256', 'c' * 64),
            ('operation_id', 'd' * 64),
            ('challenge_nonce', 'e' * 32),
            ('inbox_observed_at', NOW + 100),
            ('test_destination_only', False),
        )):
            with self.subTest(field=field):
                self.read_nonce = f'{index+200:032x}'
                self.transport.ack_patch = {field: value}
                self.checked(self.run_status(), status='blocked',
                             state='UNKNOWN_UNCONFIRMED')

    def test_inbox_claim_without_provider_delivered_does_not_upgrade(self):
        self.send_once()
        self.transport.state = 'ACCEPTED'
        self.transport.inbox = True
        self.checked(self.run_status(), status='blocked',
                     state='UNKNOWN_UNCONFIRMED')

    def test_outbox_marker_missing_tampered_or_not_attempted_no_status(self):
        self.send_once()
        slot = next(Path(self.s.tmp.name).glob('ec225-*'))
        marker = slot / '03_SUBMIT_ATTEMPTED'
        marker.unlink()
        self.checked(self.run_status(), status='unavailable',
                     state='UNKNOWN_UNCONFIRMED')
        self.assertEqual(self.transport.lookups, 0)

    def test_different_send_grant_or_payload_bytes_cannot_borrow_old_outbox(self):
        self.send_once()
        mutated = replace(self.s.fx.req, exact_payload_bytes=b'OTHER PAYLOAD')
        original = replace(self.s.req, authorization_request=mutated)
        self.checked(self.run_status(self.req(original=original)), status='blocked',
                     state='UNKNOWN_UNCONFIRMED')
        self.assertEqual(self.transport.lookups, 0)

    def test_unknown_submit_attempt_can_be_observed_but_not_retried(self):
        self.s.transport.fail_submit = True
        with patch.object(ds.time, 'time', return_value=NOW):
            previous = self.s.sender.send_once(self.s.req)
        self.assertEqual(previous['submission_state'], 'UNKNOWN_UNCONFIRMED')
        self.transport.state = 'ACCEPTED'
        self.checked(self.run_status(), state='ACCEPTED_PROVIDER_ATTESTED')
        self.assertEqual(self.s.transport.posts, 1)

    def test_ten_independent_keys_and_test_only_transport_enforced(self):
        with self.assertRaisesRegex(ValueError, 'TEN_INDEPENDENT'):
            bad_roots = replace(self.roots,
                inbox_observation_public_key=self.s.provider_key.public_key().public_bytes_raw())
            st.DeliveryStatusReader(self.s.sender,
                                    replace(self.access, roots=bad_roots), self.transport)
        with self.assertRaisesRegex(ValueError, 'UNTRUSTED_STATUS_TRANSPORT'):
            st.DeliveryStatusReader(self.s.sender,
                                    replace(self.access,
                                            allow_synthetic_transport_for_development=False),
                                    self.transport)


if __name__ == '__main__':
    unittest.main()
