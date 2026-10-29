#!/usr/bin/env python3
"""EC227 focused LOCAL synthetic auditing; no real network/recipient or send.

Uses EC225/226 genuine Python logic with disposable EC200..EC224 fixture,
private temp outbox, ephemeral keys and a fake signed Provider/inbox observer.
No production authority, identity, live Provider or OS durability is proved.
"""
from __future__ import annotations

from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

import delivery_reconcile as rc
import delivery_send as ds
import delivery_status as st
import test_delivery_status as statusfx

NOW = statusfx.NOW
RESULT_SCHEMA = json.loads((Path(__file__).resolve().parent.parent / 'references' /
                            'delivery-reconcile-result.v1.schema.json').read_text('utf8'))
AUDIT_SCHEMA = json.loads((Path(__file__).resolve().parent.parent / 'references' /
                           'delivery-reconcile-audit.v1.schema.json').read_text('utf8'))
Draft202012Validator.check_schema(RESULT_SCHEMA)
Draft202012Validator.check_schema(AUDIT_SCHEMA)
VALID_RESULT = Draft202012Validator(RESULT_SCHEMA)
VALID_AUDIT = Draft202012Validator(AUDIT_SCHEMA)


class ReconcileCases(unittest.TestCase):
    def setUp(self):
        self.s = statusfx.StatusCases()
        self.s.setUp()
        self.addCleanup(self.s.doCleanups)
        self.audit_key = hashlib.sha256(b'EC227 private ephemeral fixture-only key').digest()
        self.access = rc.HostAuditAccess(self.audit_key, True)
        self.reconciler = rc.DeliveryReconciler(self.s.reader, self.access)

    def sent(self, *, failed=False):
        self.s.transport.state = 'UNKNOWN'
        self.s.s.transport.fail_submit = failed
        return self.s.send_once() if not failed else self._fail_send()

    def _fail_send(self):
        with patch.object(ds.time, 'time', return_value=NOW):
            result = self.s.s.sender.send_once(self.s.s.req)
        self.assertEqual(result['submission_state'], 'UNKNOWN_UNCONFIRMED')
        return result

    def observe(self, request=None):
        with patch.object(ds.time, 'time', return_value=NOW):
            return self.reconciler.observe_and_record(self.s.req() if request is None else request)

    def read(self, *, checkpoint=None):
        with patch.object(ds.time, 'time', return_value=NOW):
            return self.reconciler.readback(self.s.s.req, expected_head_hmac_sha256=checkpoint)

    def guard(self):
        with patch.object(ds.time, 'time', return_value=NOW):
            return self.reconciler.retry_guard(self.s.s.req)

    def checked(self, result, *, status='partial', state='UNKNOWN_UNCONFIRMED'):
        self.assertEqual(list(VALID_RESULT.iter_errors(result)), [], result)
        self.assertEqual(result['status'], status, result)
        self.assertEqual(result['delivery_state'], state, result)
        self.assertFalse(result['original_operation_retry_allowed'])
        self.assertFalse(result['new_delivery_authorized'])
        self.assertFalse(result['effects']['provider_submit_requested'])
        self.assertFalse(result['resent'])
        self.assertFalse(result['published'])
        raw = json.dumps(result)
        for secret in (self.s.s.access.credential, self.s.access.read_credential,
                       self.s.s.target.endpoint, self.s.s.target.recipient_handle,
                       self.s.s.fx.i.report.fixture.saved['subject']['rendered_markdown']):
            self.assertNotIn(secret, raw)
        return result

    def audit_dir(self):
        slots = list(Path(self.s.s.tmp.name).glob('ec227-*'))
        self.assertEqual(len(slots), 1)
        return slots[0]

    def records(self):
        result = []
        for file in sorted(self.audit_dir().glob('*.json')):
            obj = json.loads(file.read_bytes())
            self.assertEqual(list(VALID_AUDIT.iter_errors(obj)), [], obj)
            result.append(obj)
        return result

    def test_no_original_submit_never_allocates_audit_or_queries_status(self):
        r = self.checked(self.observe(), status='unavailable')
        self.assertFalse(r['audit_chain_verified'])
        self.assertEqual(self.s.transport.lookups, 0)
        self.assertFalse(list(Path(self.s.s.tmp.name).glob('ec227-*')))

    def test_readback_before_first_reconciliation_reports_missing_audit(self):
        self.sent()
        r = self.checked(self.read(), status='unavailable')
        self.assertIn('NOT_YET_RECORDED', r['reason_code'])
        self.assertFalse(r['audit_chain_verified'])
        self.assertEqual(self.s.transport.lookups, 0)
        self.checked(self.guard(), status='unavailable')
        self.assertEqual(self.s.s.transport.posts, 1)

    def test_original_http202_outbox_and_unknown_becomes_two_durable_records(self):
        self.sent()
        r = self.checked(self.observe())
        self.assertEqual(r['audit_event_count'], 2)
        self.assertTrue(r['audit_chain_verified'])
        self.assertTrue(r['effects']['local_audit_records_written'])
        self.assertEqual(self.s.transport.lookups, 1)
        self.assertEqual(self.s.s.transport.posts, 1)
        e = self.records()
        self.assertEqual([x['entry']['kind'] for x in e],
                         ['LOOKUP_STARTED', 'LOOKUP_RESULT'])
        self.assertEqual(e[1]['entry']['previous_hmac_sha256'], e[0]['hmac_sha256'])
        self.assertFalse(e[1]['entry']['provider_evidence_verified'] is False)

    def test_local_readback_does_not_recontact_remote_and_is_not_fresh_status(self):
        self.sent()
        self.s.transport.state = 'ACCEPTED'
        live = self.checked(self.observe(), state='ACCEPTED_PROVIDER_ATTESTED')
        before = self.s.transport.lookups
        result = self.checked(self.read(), state='UNKNOWN_UNCONFIRMED')
        self.assertEqual(self.s.transport.lookups, before)
        self.assertEqual(result['last_historical_attested_state'],
                         'ACCEPTED_PROVIDER_ATTESTED')
        self.assertEqual(result['audit_head_hmac_sha256'], live['audit_head_hmac_sha256'])
        self.assertFalse(result['fresh_independent_status_evidence_verified'])
        self.assertFalse(result['effects']['local_audit_records_written'])

    def test_fresh_accepted_then_independent_inbox_observed_is_promoted(self):
        self.sent()
        self.s.transport.state = 'ACCEPTED'
        self.checked(self.observe(), state='ACCEPTED_PROVIDER_ATTESTED')
        self.s.read_nonce = 'a' * 32
        self.s.transport.state = 'DELIVERED'
        self.s.transport.inbox = True
        result = self.checked(self.observe(), state='DELIVERED_INBOX_OBSERVED')
        self.assertEqual(result['audit_event_count'], 4)
        self.assertTrue(result['fresh_independent_status_evidence_verified'])
        self.assertEqual(self.s.s.transport.posts, 1)
        self.assertEqual(self.s.transport.lookups, 2)

    def test_provider_delivered_without_independent_inbox_remains_accepted(self):
        self.sent()
        self.s.transport.state = 'DELIVERED'
        result = self.checked(self.observe(), state='ACCEPTED_PROVIDER_ATTESTED')
        self.assertTrue(result['fresh_independent_status_evidence_verified'])
        self.assertFalse(self.records()[-1]['entry']['inbox_evidence_verified'])

    def test_retry_guard_denies_original_even_when_provider_rejected(self):
        self.sent()
        self.s.transport.state = 'REJECTED'
        self.checked(self.observe(), state='PROVIDER_REJECTION_ATTESTED')
        result = self.checked(self.guard(), status='blocked')
        self.assertIn('SPENT_NO_AUTOMATIC_RESEND', result['reason_code'])
        self.assertEqual(self.s.s.transport.posts, 1)

    def test_submit_timeout_does_not_become_safe_to_retry(self):
        self.sent(failed=True)
        self.s.transport.state = 'UNKNOWN'
        self.checked(self.observe())
        self.checked(self.guard(), status='blocked')
        self.assertEqual(self.s.s.transport.posts, 1)

    def test_provider_status_timeout_persists_unknown_not_delivery(self):
        self.sent()
        self.s.transport.fail = True
        result = self.checked(self.observe())
        self.assertEqual(result['audit_event_count'], 2)
        self.assertFalse(result['fresh_independent_status_evidence_verified'])
        self.assertFalse(self.records()[-1]['entry']['provider_evidence_verified'])
        self.assertTrue(self.records()[0]['entry']['kind'] == 'LOOKUP_STARTED')

    def test_invalid_or_expired_read_grant_before_network_or_audit(self):
        self.sent()
        for request in (self.s.req(key=statusfx.Ed25519PrivateKey.generate()),
                        self.s.req(self.s.grant(expires_at=NOW)),
                        self.s.req(permission=False),
                        self.s.req(network=False)):
            with self.subTest(request=request):
                self.checked(self.observe(request),
                             status='blocked' if request.permit_independent_status_read and
                             request.permit_provider_status_network_egress else 'unavailable')
        self.assertEqual(self.s.transport.lookups, 0)
        self.assertFalse(list(Path(self.s.s.tmp.name).glob('ec227-*')))

    def test_same_status_grant_reentry_denied_before_network_or_second_audit(self):
        self.sent()
        self.checked(self.observe())
        self.checked(self.observe(), status='blocked')
        self.assertEqual(self.s.transport.lookups, 1)
        self.assertEqual(len(self.records()), 2)

    def test_new_independent_read_nonce_may_repeat_status_only_never_submit(self):
        self.sent()
        self.checked(self.observe())
        self.s.read_nonce = 'b' * 32
        self.s.transport.state = 'ACCEPTED'
        self.checked(self.observe(), state='ACCEPTED_PROVIDER_ATTESTED')
        self.assertEqual(len(self.records()), 4)
        self.assertEqual(self.s.s.transport.posts, 1)
        self.assertEqual(self.s.transport.lookups, 2)

    def test_audit_recreated_reader_with_host_key_preserves_record_chain(self):
        self.sent()
        self.s.transport.state = 'ACCEPTED'
        self.checked(self.observe(), state='ACCEPTED_PROVIDER_ATTESTED')
        new_reconciler = rc.DeliveryReconciler(self.s.reader, self.access)
        with patch.object(ds.time, 'time', return_value=NOW):
            result = new_reconciler.readback(self.s.s.req)
        self.checked(result)
        self.assertEqual(result['audit_event_count'], 2)

    def test_wrong_hmac_key_cannot_read_existing_ledger(self):
        self.sent()
        self.checked(self.observe())
        other = rc.DeliveryReconciler(self.s.reader,
                                      rc.HostAuditAccess(b'9' * 32, True))
        with patch.object(ds.time, 'time', return_value=NOW):
            r = other.readback(self.s.s.req)
        self.checked(r, status='unavailable')
        self.assertFalse(r['audit_chain_verified'])

    def test_modified_audit_entry_detected_and_next_read_is_refused(self):
        self.sent()
        self.checked(self.observe())
        path = self.audit_dir() / '000002.json'
        doc = json.loads(path.read_bytes())
        doc['entry']['delivery_state'] = 'DELIVERED_INBOX_OBSERVED'
        path.write_text(json.dumps(doc))
        self.checked(self.read(), status='unavailable')
        self.s.read_nonce = 'c' * 32
        self.checked(self.observe(), status='unavailable')
        self.assertEqual(self.s.transport.lookups, 1)

    def test_missing_middle_audit_file_fails_closed(self):
        self.sent()
        self.checked(self.observe())
        (self.audit_dir() / '000001.json').unlink()
        self.checked(self.read(), status='unavailable')

    def test_unexpected_file_or_symlink_in_audit_is_refused(self):
        self.sent()
        self.checked(self.observe())
        (self.audit_dir() / 'freeform.txt').write_text('untrusted')
        self.checked(self.read(), status='unavailable')

    def test_crash_like_missing_result_remains_explicit_then_new_read_recovers(self):
        self.sent()
        # A simulated unexpected failure AFTER START was fsynced.
        with patch.object(self.s.reader, 'observe_once', side_effect=RuntimeError('crash')):
            self.checked(self.observe(), status='unavailable')
        old = self.checked(self.read())
        self.assertTrue(old['incomplete_prior_observation'])
        self.s.read_nonce = 'd' * 32
        self.s.transport.state = 'ACCEPTED'
        r = self.checked(self.observe(), state='ACCEPTED_PROVIDER_ATTESTED')
        self.assertTrue(r['incomplete_prior_observation'])
        self.assertEqual(r['audit_event_count'], 3)
        self.assertEqual(self.s.s.transport.posts, 1)

    def test_conflicting_provider_state_never_silently_reconciles(self):
        self.sent()
        self.s.transport.state = 'ACCEPTED'
        self.checked(self.observe(), state='ACCEPTED_PROVIDER_ATTESTED')
        self.s.read_nonce = 'e' * 32
        self.s.transport.state = 'REJECTED'
        r = self.checked(self.observe(), state='UNKNOWN_UNCONFIRMED')
        self.assertTrue(r['conflicting_historical_evidence'])
        self.checked(self.guard(), status='blocked')

    def test_provider_message_id_changes_for_same_op_causes_conflict(self):
        self.sent()
        self.s.transport.state = 'ACCEPTED'
        self.checked(self.observe(), state='ACCEPTED_PROVIDER_ATTESTED')
        self.s.read_nonce = 'f' * 32
        self.s.transport.provider_patch = {'provider_message_id_sha256': 'f' * 64}
        result = self.checked(self.observe())
        self.assertTrue(result['conflicting_historical_evidence'])

    def test_new_remote_unknown_overrides_old_attested_current_state(self):
        self.sent()
        self.s.transport.state = 'ACCEPTED'
        self.checked(self.observe(), state='ACCEPTED_PROVIDER_ATTESTED')
        self.s.read_nonce = '1' * 32
        self.s.transport.state = 'UNKNOWN'
        r = self.checked(self.observe(), state='UNKNOWN_UNCONFIRMED')
        self.assertEqual(r['last_historical_attested_state'],
                         'ACCEPTED_PROVIDER_ATTESTED')

    def test_external_checkpoint_detects_valid_tail_rollback(self):
        self.sent()
        self.checked(self.observe())
        actual = self.read()['audit_head_hmac_sha256']
        self.checked(self.read(checkpoint=actual))
        (self.audit_dir() / '000002.json').unlink()
        r = self.checked(self.read(checkpoint=actual), status='blocked')
        self.assertIn('CHECKPOINT', r['reason_code'])

    def test_audit_full_declines_before_consuming_next_read(self):
        self.sent()
        self.checked(self.observe())
        self.s.read_nonce = '2' * 32
        with patch.object(rc, 'MAX_AUDIT_ENTRIES', 2):
            r = self.checked(self.observe(), status='unavailable')
        self.assertIn('CAPACITY', r['reason_code'])
        self.assertEqual(self.s.transport.lookups, 1)
        self.assertEqual(len(self.records()), 2)

    def test_concurrent_operation_lock_blocks_read_without_network(self):
        self.sent()
        history = self.reconciler._history(self.s.s.req)
        with self.reconciler._journal(history, create=True):
            self.checked(self.observe(), status='unavailable')
        self.assertEqual(self.s.transport.lookups, 0)

    def test_host_secret_is_hidden_from_access_repr(self):
        self.assertNotIn(repr(self.audit_key), repr(self.access))

    def test_disabled_host_audit_or_invalid_key_refuses(self):
        with self.assertRaises(ValueError):
            rc.DeliveryReconciler(self.s.reader, rc.HostAuditAccess(b'\0' * 32, True))
        with self.assertRaises(ValueError):
            rc.DeliveryReconciler(self.s.reader, rc.HostAuditAccess(b'9', True))
        self.sent()
        off = rc.DeliveryReconciler(self.s.reader,
                                    replace(self.access, enable_local_private_audit=False))
        with patch.object(ds.time, 'time', return_value=NOW):
            r = off.observe_and_record(self.s.req())
        self.checked(r, status='unavailable')
        self.assertEqual(self.s.transport.lookups, 0)

    def test_original_payload_change_cannot_read_other_operations_audit(self):
        self.sent()
        self.checked(self.observe())
        modified = replace(self.s.s.fx.req, exact_payload_bytes=b'UNKNOWN CONTENT')
        wrong = replace(self.s.s.req, authorization_request=modified)
        with patch.object(ds.time, 'time', return_value=NOW):
            result = self.reconciler.readback(wrong)
        self.checked(result, status='blocked')

    def test_audit_append_failure_does_not_use_status_network(self):
        self.sent()
        with patch.object(rc.PrivateAuditJournal, 'append',
                          side_effect=rc.AuditDenied('SIMULATED_DISK_FAILURE')):
            self.checked(self.observe(), status='unavailable')
        self.assertEqual(self.s.transport.lookups, 0)

    def test_no_new_send_even_after_recorded_failure_and_new_reader(self):
        self.sent(failed=True)
        self.s.transport.state = 'FAILED'
        self.checked(self.observe(), state='PROVIDER_FAILURE_ATTESTED')
        self.s.read_nonce = '3' * 32
        self.s.transport.state = 'PENDING'
        self.checked(self.observe())
        self.checked(self.guard(), status='blocked')
        self.assertEqual(self.s.s.transport.posts, 1)


if __name__ == '__main__':
    unittest.main()
