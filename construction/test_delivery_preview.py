#!/usr/bin/env python3
"""EC221 focused local functional cases using actual EC200/EC179 private stores.

Synthetic upstream content/identities only; no external recipient, email, AI,
provider or real organization authority is exercised. Not final acceptance.
"""
from __future__ import annotations

from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

import delivery_preview as dp
import test_report_history as rh_fixture
import test_finding_show as finding_fixture

SCHEMA_PATH = (Path(__file__).resolve().parent.parent / 'references' /
               'delivery-preview-result.v1.schema.json')
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def dest(**kwargs):
    return replace(dp.Destination('INTERNAL_REVIEW', 'EMAIL', digest('reviewers'),
                                  digest('email-channel'), digest('one-reader')),
                   **kwargs)


def request(sources, **kwargs):
    return replace(dp.DeliveryPreviewRequest(
        sources=tuple(sources), destination=dest(),
        policy_revision_sha256=digest('independent policy snapshot'),
        requested_privacy_floor='PUBLIC',
        permit_local_preview=True,
        permit_private_source_metadata_read=True,
        permit_report_content_read_in_process=True,
        permit_finding_digest_details_read=True,
    ), **kwargs)


class Helpers(unittest.TestCase):
    def ok(self, result):
        self.assertEqual(list(VALIDATOR.iter_errors(result)), [], result)
        self.assertEqual((result['status'], result['exit_code']), ('partial', 2), result)
        self.assertEqual(result['delivery_state'], 'NO_DELIVERY_OR_PUBLICATION')
        self.assertFalse(any(result['effects'].values()))
        self.assertFalse(result['preview']['ready_to_send'])
        self.assertFalse(result['preview']['is_deliverable_payload'])
        self.assertEqual(hashlib.sha256(result['preview_markdown'].encode()).hexdigest(),
                         result['preview_content_sha256'])
        self.assertEqual(result['preview']['preview_id'], result['preview_id'])
        return result['preview']

    def denied(self, result, code, status=None):
        self.assertEqual(list(VALIDATOR.iter_errors(result)), [], result)
        self.assertIsNone(result['preview'], result)
        self.assertIsNone(result['preview_markdown'])
        self.assertFalse(any(result['effects'].values()))
        self.assertEqual(result['reason_code'], 'DELIVERY_PREVIEW_' + code)
        if status:
            self.assertEqual(result['status'], status)


class ReportPreviewCases(Helpers):
    def setUp(self):
        self.fx = rh_fixture.ReportHistoryTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        saved = self.fx.saved(self.tmp.name)
        self.saved = saved
        self.policy = self.fx.policy(self.tmp.name, saved)
        subj = self.fx.ok(self.fx.select(saved, self.tmp.name, policy=self.policy))
        self.selection = dp.ReportSelection(
            reader=self.fx.history, storage_root=self.tmp.name,
            slot_key=saved['subject']['slot_key'],
            period_id=saved['subject']['period_id'],
            slot_members=copy.deepcopy(saved['subject']['slot_members']),
            read_policy=copy.deepcopy(self.policy),
            selected_version=subj['selected_version'],
            expected_report_ref=subj['selected_report_ref'],
            expected_entry_sha256=subj['selected_entry_sha256'],
            expected_record_sha256=subj['record_sha256'],
            expected_rendered_sha256=subj['rendered_sha256'],
            expected_index_binding_sha256=subj['index_binding_sha256'],
        )

    def test_real_saved_version_redacted_and_never_sends(self):
        p = self.ok(dp.preview_delivery(request([self.selection])))
        s = p['sources'][0]
        self.assertEqual(s['source_kind'], 'REPORT')
        self.assertEqual(s['source_content_sha256'], self.saved['subject']['rendered_sha256'])
        self.assertEqual(s['source_record_sha256'], self.selection.expected_record_sha256)
        self.assertEqual(s['latest_observed_version'], 1)
        self.assertEqual(s['content_format'], dp.REPORT_FORMAT)
        self.assertEqual(p['privacy']['effective_minimum_class'], 'INTERNAL')
        self.assertIn('RECIPIENT_IDENTITY_UNVERIFIED_EC223', p['coverage_and_permission_gaps'])
        self.assertIn('REQUESTED_PRIVACY_BELOW_SOURCE_MINIMUM', p['coverage_and_permission_gaps'])

    def test_hash_and_version_pins_fail_closed(self):
        variations = (
            {'expected_entry_sha256': digest('stale entry')},
            {'expected_record_sha256': digest('wrong stored record')},
            {'expected_rendered_sha256': digest('wrong contents')},
            {'expected_index_binding_sha256': digest('previous index')},
            {'selected_version': 2},
            {'expected_report_ref': 'cesrr1:' + digest('other report')},
        )
        for fields in variations:
            with self.subTest(fields=fields):
                outcome = dp.preview_delivery(request([replace(self.selection, **fields)]))
                self.assertEqual(outcome['status'], 'unavailable', outcome)
                self.assertIsNone(outcome['preview'])

    def test_own_local_grants_before_store_read(self):
        for flag in ('permit_local_preview', 'permit_private_source_metadata_read',
                     'permit_report_content_read_in_process'):
            with self.subTest(flag=flag), patch.object(self.fx.history, 'show',
                                                       side_effect=AssertionError('must not read')):
                result = dp.preview_delivery(request([self.selection], **{flag: False}))
                self.assertEqual(result['status'], 'unavailable')
                self.assertIsNone(result['preview'])

    def test_no_automatic_markdown_content_even_when_upstream_permitted(self):
        # Permission in EC200 to read text is not permission to release it.
        policy = self.fx.policy(self.tmp.name, self.saved, markdown=True)
        s = replace(self.selection, read_policy=policy)
        r = dp.preview_delivery(request([s]))
        self.ok(r)
        report_markdown = self.saved['subject']['rendered_markdown']
        self.assertNotIn(report_markdown, json.dumps(r, ensure_ascii=False))
        self.assertNotIn('slot_members', json.dumps(r))
        self.assertNotIn(self.tmp.name, json.dumps(r))

    def test_report_stored_markdown_tamper_or_read_denied(self):
        rpolicy = copy.deepcopy(self.policy)
        rpolicy['permit_history_read'] = False
        result = dp.preview_delivery(request([replace(self.selection, read_policy=rpolicy)]))
        self.denied(result, 'REPORT_SELECTOR_OR_POLICY_INVALID', 'invalid_input')

    def test_exact_destination_fingerprint_changes_with_identities(self):
        a = self.ok(dp.preview_delivery(request([self.selection])))
        b = self.ok(dp.preview_delivery(request([self.selection], destination=dest(
            recipient_identity_sha256=digest('other person')))))
        self.assertNotEqual(a['preview_id'], b['preview_id'])
        self.assertNotEqual(a['destination']['destination_binding_sha256'],
                            b['destination']['destination_binding_sha256'])
        self.assertFalse(b['destination']['recipient_verified'])

    def test_missing_identity_explicit_gaps_and_external_scope(self):
        d = dest(audience_kind='PUBLIC_DISTRIBUTION',
                 audience_identity_sha256=None, recipient_identity_sha256=None,
                 channel_identity_sha256=None)
        result = dp.preview_delivery(request([self.selection], destination=d))
        p = self.ok(result)
        for code in ('AUDIENCE_IDENTITY_NOT_SELECTED', 'RECIPIENT_IDENTITY_NOT_SELECTED',
                     'CHANNEL_IDENTITY_NOT_SELECTED', 'EXTERNAL_AUDIENCE_NOT_CLEARED_FOR_CONTENT'):
            self.assertIn(code, p['coverage_and_permission_gaps'])
        self.assertIn('NO_DELIVERY', result['delivery_state'])

    def test_duplicate_sources_and_invalid_later_source_never_read_first(self):
        with patch.object(self.fx.history, 'show', side_effect=AssertionError('must not read')):
            self.denied(dp.preview_delivery(request([self.selection, self.selection])),
                        'DUPLICATE_SOURCE_SELECTED')
            bad = replace(self.selection, expected_entry_sha256='bad')
            self.denied(dp.preview_delivery(request([self.selection, bad])),
                        'REPORT_VERSION_HASH_PINS_REQUIRED')

    def test_unsupported_caller_report_draft_not_evidence(self):
        self.denied(dp.preview_delivery(request([{'schema': 'ces.report_render.v1'}])),
                    'UNSUPPORTED_SOURCE_KIND')

    def test_sensitive_plaintext_identity_not_accepted(self):
        bad = dest(recipient_identity_sha256='someone@example.org')
        self.denied(dp.preview_delivery(request([self.selection], destination=bad)),
                    'DESTINATION_IDENTITY_MUST_BE_SHA256_OR_NULL')

    def test_permission_bad_type_and_kind_fail_without_read(self):
        for kw, code in (({'permit_report_content_read_in_process': 1},
                          'PREVIEW_READ_PERMISSION_TYPES_INVALID'),
                         ({'requested_privacy_floor': 'maybe-public'}, 'PRIVACY_FLOOR_INVALID')):
            with self.subTest(kw=kw), patch.object(self.fx.history, 'show',
                                                   side_effect=AssertionError('must not read')):
                self.denied(dp.preview_delivery(request([self.selection], **kw)), code)

    def test_cannot_use_arbitrary_renderer_as_reader(self):
        s = replace(self.selection, reader=self.fx.prev.api)
        self.denied(dp.preview_delivery(request([s])), 'REPORT_READER_REQUIRED')


class FindingPreviewCases(Helpers):
    def setUp(self):
        self.fx = finding_fixture.FindingShowCases()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.fx.begin()
        shown = self.fx.lookup()
        self.assertEqual(shown['matched_count'], 1, shown)
        row = shown['findings'][0]
        self.original_row = row
        item = self.fx.lookup(filters={'finding_id': row['finding_id']},
                              page_size=1, include_digest_details=True,
                              authorize_digest_details=True)
        self.assertEqual(item['status'], 'partial', item)
        self.item = item
        d = item['findings'][0]['digest_details']
        self.selection = dp.FindingSelection(
            reader=self.fx.show, expected_finding_store_pin=item['save_store_pin'],
            authorized_source_binding=copy.deepcopy(self.fx.params['authorized_source_binding']),
            query_content_for=self.fx.params['query_content_for'],
            finding_id=row['finding_id'], expected_batch_sequence=row['batch_sequence'],
            expected_record_sha256=d['record_sha256'],
            expected_original_finding_sha256=d['original_finding_sha256'],
            expected_revision_sha256=item['revision_sha256'],
            expected_query_sha256=item['query_sha256'],
            acknowledge_historical_proposal_metadata=
                self.fx.params.get('acknowledge_historical_proposal_metadata', False),
        )

    def test_real_hmac_store_read_is_redacted_and_confidential(self):
        result = dp.preview_delivery(request([self.selection]))
        preview = self.ok(result)
        self.assertEqual(preview['privacy']['effective_minimum_class'], 'CONFIDENTIAL')
        source = preview['sources'][0]
        self.assertEqual(source['source_kind'], 'FINDING')
        self.assertEqual(source['content_format'], dp.FINDING_FORMAT)
        self.assertEqual(source['source_record_sha256'], self.selection.expected_record_sha256)
        self.assertIn('FINDING_SEMANTIC_DEFECT_NOT_VERIFIED', source['gap_codes'])
        self.assertNotIn('synthetic-reviewer', json.dumps(result))
        self.assertFalse(preview['identity_or_source_trust_authenticated'])

    def test_hash_pin_mismatches_are_not_partial_successes(self):
        for fields in ({'expected_record_sha256': digest('bad record')},
                       {'expected_original_finding_sha256': digest('different finding')},
                       {'expected_revision_sha256': digest('stale ledger')},
                       {'expected_query_sha256': digest('other query')},
                       {'expected_finding_store_pin': digest('other store')},
                       {'finding_id': digest('other ID')}):
            with self.subTest(fields=fields):
                out = dp.preview_delivery(request([replace(self.selection, **fields)]))
                self.assertEqual(out['status'], 'unavailable', out)
                self.assertIsNone(out['preview'])

    def test_missing_independent_finding_details_grant_stops_read(self):
        with patch.object(self.fx.show, 'query', side_effect=AssertionError('must not read')):
            self.denied(dp.preview_delivery(request([self.selection],
                    permit_finding_digest_details_read=False)),
                    'FINDING_DIGEST_DETAIL_PERMISSION_REQUIRED', 'unavailable')

    def test_invalid_source_binding_denied_no_guessing(self):
        s = replace(self.selection, authorized_source_binding={'source_mode': 'WorkingTree'})
        self.denied(dp.preview_delivery(request([s])),
                    'FINDING_AUTHORIZED_SOURCE_BINDING_INVALID')

    def test_private_store_not_synthetically_promoted_to_verified(self):
        p = self.ok(dp.preview_delivery(request([self.selection],
                                    requested_privacy_floor='RESTRICTED')))
        self.assertEqual(p['privacy']['effective_minimum_class'], 'RESTRICTED')
        self.assertFalse(p['privacy']['content_policy_reviewed'])
        self.assertFalse(p['delivery_evidence_present'])

    def test_reader_denied_never_falls_back_to_embedded_json(self):
        with patch.object(self.fx.show, 'query', return_value={
            'schema': self.item['schema'], 'status': 'unavailable', 'findings': []}):
            self.denied(dp.preview_delivery(request([self.selection])),
                        'FINDING_READ_NOT_AVAILABLE', 'unavailable')

    def test_stale_second_selection_whole_preview_rejected(self):
        other = replace(self.selection, expected_record_sha256=digest('outdated'))
        result = dp.preview_delivery(request([self.selection, other]))
        self.assertEqual(result['status'], 'unavailable', result)
        self.assertIsNone(result['preview'])


class MixedSourcePreviewCases(Helpers):
    setUp = ReportPreviewCases.setUp
    def test_two_real_private_stores_pin_independent_versions_no_atomic_claim(self):
        finding = finding_fixture.FindingShowCases()
        finding.setUp()
        self.addCleanup(finding.doCleanups)
        finding.begin()
        first = finding.lookup()
        fid = first['findings'][0]['finding_id']
        item = finding.lookup(filters={'finding_id': fid}, page_size=1,
                              include_digest_details=True,
                              authorize_digest_details=True)
        d = item['findings'][0]['digest_details']
        sel = dp.FindingSelection(
            reader=finding.show,
            expected_finding_store_pin=item['save_store_pin'],
            authorized_source_binding=copy.deepcopy(
                finding.params['authorized_source_binding']),
            query_content_for=finding.params['query_content_for'],
            finding_id=fid,
            expected_batch_sequence=item['findings'][0]['batch_sequence'],
            expected_record_sha256=d['record_sha256'],
            expected_original_finding_sha256=d['original_finding_sha256'],
            expected_revision_sha256=item['revision_sha256'],
            expected_query_sha256=item['query_sha256'],
            acknowledge_historical_proposal_metadata=
                finding.params.get('acknowledge_historical_proposal_metadata', False),
        )
        good = dp.preview_delivery(request([self.selection, sel]))
        p = self.ok(good)
        self.assertEqual([x['source_kind'] for x in p['sources']],
                         ['REPORT', 'FINDING'])
        self.assertEqual(p['privacy']['effective_minimum_class'], 'CONFIDENTIAL')
        self.assertFalse(p['cross_source_atomic_snapshot'])
        self.assertEqual(len({x['source_version_sha256'] for x in p['sources']}), 2)
        swapped = dp.preview_delivery(request([sel, self.selection]))
        self.ok(swapped)
        self.assertNotEqual(good['preview_id'], swapped['preview_id'])
        self.assertNotIn(self.tmp.name, json.dumps(good))


if __name__ == '__main__':
    unittest.main()
