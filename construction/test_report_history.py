#!/usr/bin/env python3
"""EC200 offline development cases with genuine EC192..199 replay and local POSIX files."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator
from report_evidence_metrics import canonical, digest
from report_history import (
    ReportHistory, local_store_binding, READ_POLICY_SCHEMA,
    CORRECTION_POLICY_SCHEMA, READ_PURPOSE, CORRECTION_PURPOSE,
    AUDIENCE, HISTORY_LIMITATIONS, _comparison,
)
import test_report_render as preceding

ROOT = Path(__file__).resolve().parent.parent
RESULT_SCHEMA = json.loads((ROOT / 'references' / 'report-history-result.v1.schema.json').read_text())
READ_SCHEMA = json.loads((ROOT / 'references' / 'report-history-read-policy.v1.schema.json').read_text())
CORRECTION_SCHEMA = json.loads((ROOT / 'references' / 'report-history-correction-policy.v1.schema.json').read_text())
for schema in (RESULT_SCHEMA, READ_SCHEMA, CORRECTION_SCHEMA):
    Draft202012Validator.check_schema(schema)
RESPONSE = Draft202012Validator(RESULT_SCHEMA)
READ = Draft202012Validator(READ_SCHEMA)
CORRECTION = Draft202012Validator(CORRECTION_SCHEMA)


class ReportHistoryTests(unittest.TestCase):
    def setUp(self):
        self.prev = preceding.ReportRenderTests()
        self.prev.setUp()
        self.original_inputs = self.prev.arguments()
        self.history = ReportHistory()

    def saved(self, root, **kwargs):
        r = self.prev.api.save(
            **(kwargs.get('args') or self.original_inputs), storage_root=root,
            expected_previous_version=kwargs.get('expected', 0),
            operation_id=kwargs.get('operation_id', 'ec200-first-save-0001'))
        self.assertEqual(r['status'], 'partial', r)
        self.assertEqual(r['storage']['state'], 'SAVED_NEW_VERSION', r)
        return r

    def policy(self, root, first, *, markdown=False):
        doc = first['subject']
        grants = [{
            'repository_ref': r['repository_ref'],
            'report_subject_ref': r['report_subject_ref'],
            'permit_history_read': True,
            'permit_rendered_markdown': markdown,
            'read_receipt_sha256': f'{i + 240:064x}',
        } for i, r in enumerate(doc['slot_members'])]
        return {
            'schema': READ_POLICY_SCHEMA, 'purpose': READ_PURPOSE,
            'audience': AUDIENCE, 'permit_history_read': True,
            'permit_rendered_markdown': markdown,
            'report_slot_ref': doc['report_slot_ref'],
            'slot_key': doc['slot_key'], 'period_id': doc['period_id'],
            'slot_members': copy.deepcopy(doc['slot_members']),
            'store_binding_sha256': local_store_binding(root),
            'policy_receipt_sha256': 'c' * 64,
            'repository_grants': grants,
        }

    def select(self, first, root, policy=None, **kwargs):
        d = first['subject']
        return self.history.show(storage_root=root, slot_key=d['slot_key'],
                                 period_id=d['period_id'],
                                 slot_members=copy.deepcopy(d['slot_members']),
                                 read_policy=copy.deepcopy(policy or self.policy(root, first)),
                                 **kwargs)

    def correction(self, first, read_policy, *, cats=None):
        doc, saved = first['subject'], first['storage']
        return {
            'schema': CORRECTION_POLICY_SCHEMA, 'purpose': CORRECTION_PURPOSE,
            'audience': AUDIENCE, 'permit_append_correction': True,
            'store_binding_sha256': read_policy['store_binding_sha256'],
            'report_slot_ref': doc['report_slot_ref'],
            'slot_key': doc['slot_key'], 'period_id': doc['period_id'],
            'slot_members': copy.deepcopy(doc['slot_members']),
            'expected_previous_version': saved['version'],
            'previous_report_ref': saved['report_ref'],
            'previous_entry_sha256': saved['entry_sha256'],
            'operation_id': 'ec200-correct-op-0002',
            'correction_categories': cats or ['permission'],
            'policy_receipt_sha256': 'b' * 64,
            'repository_grants': [{
                'repository_ref': m['repository_ref'],
                'report_subject_ref': m['report_subject_ref'],
                'permit_append_correction': True,
                'correction_receipt_sha256': f'{i + 270:064x}',
            } for i, m in enumerate(doc['slot_members'])],
        }

    def changed_render(self):
        args = self.prev.arguments()
        args['render_policy']['policy_receipt_sha256'] = 'd' * 64
        return args

    def correct(self, root, first, rpolicy, cpolicy, inputs=None):
        return self.history.correct(
            storage_root=root, read_policy=copy.deepcopy(rpolicy),
            correction_policy=copy.deepcopy(cpolicy),
            **(inputs or self.changed_render()),
        )

    def ok(self, result):
        self.assertEqual(list(RESPONSE.iter_errors(result)), [], result)
        self.assertEqual((result['status'], result['exit_code']), ('partial', 2), result)
        self.assertEqual(result['canonical_json'], canonical(result['subject']))
        self.assertEqual(result['limitations'], HISTORY_LIMITATIONS)
        return result['subject']

    def denied(self, result, code, *, invalid=False):
        self.assertEqual(list(RESPONSE.iter_errors(result)), [], result)
        self.assertEqual((result['status'], result['exit_code']),
                         ('invalid_input', 4) if invalid else ('unavailable', 5), result)
        self.assertEqual(result['reason_code'], 'REPORT_HISTORY_' + code)
        self.assertIsNone(result['subject'])
        self.assertIsNone(result['canonical_json'])

    def test_read_policy_and_correction_policy_have_strict_schemas(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            r = self.policy(tmp, first)
            self.assertEqual(list(READ.iter_errors(r)), [])
            c = self.correction(first, r)
            self.assertEqual(list(CORRECTION.iter_errors(c)), [])
            wrong = copy.deepcopy(c)
            wrong['message'] = 'employee earned a top rating'
            self.assertTrue(list(CORRECTION.iter_errors(wrong)))

    def test_show_actual_index_and_exact_first_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            out = self.ok(self.select(first, tmp))
            self.assertEqual(out['selected_version'], 1)
            self.assertEqual(out['latest_version'], 1)
            self.assertEqual(out['selected_report_ref'], first['subject']['report_ref'])
            self.assertEqual(out['selected_entry_sha256'], first['storage']['entry_sha256'])
            self.assertIsNone(out['comparison'])
            self.assertIsNone(out['rendered_markdown'])
            self.assertEqual(len(out['repositories']), 2)
            self.assertEqual(len(out['history']), 1)
            self.assertEqual(len(out['repositories'][0]['channels']), 4)
            self.assertEqual(out['document_state'], 'UNPUBLISHED_INTERNAL_REVIEW_ARTIFACT')
            self.assertEqual(out['publication_state'], 'NOT_PUBLISHED')
            self.assertFalse(any(out['limitations'].values()))

    def test_explicit_markdown_optin_returns_exact_original_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first, markdown=True)
            viewed = self.ok(self.select(first, tmp, policy=read, include_markdown=True))
            self.assertEqual(viewed['rendered_markdown'], first['subject']['rendered_markdown'])
            self.assertEqual(hashlib.sha256(viewed['rendered_markdown'].encode()).hexdigest(),
                             viewed['rendered_sha256'])

    def test_markdown_denied_without_separate_grant(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            self.denied(self.select(first, tmp, include_markdown=True), 'MARKDOWN_NOT_PERMITTED')
            read = self.policy(tmp, first, markdown=True)
            read['repository_grants'][0]['permit_rendered_markdown'] = False
            self.denied(self.select(first, tmp, policy=read, include_markdown=True),
                        'MARKDOWN_NOT_PERMITTED')
            self.ok(self.select(first, tmp, policy=read))

    def test_missing_store_read_does_not_create_subdirectory(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self.prev.ok(self.prev.api.render(**self.original_inputs))
            read = {'schema': READ_POLICY_SCHEMA}
            out = self.history.show(storage_root=tmp, slot_key=d['slot_key'],
                                    period_id=d['period_id'], slot_members=d['slot_members'],
                                    read_policy=read)
            self.denied(out, 'STORE_OR_RECORD_UNAVAILABLE')
            self.assertEqual(os.listdir(tmp), [])

    def test_malformed_policy_missing_permission_and_broken_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            p = self.policy(tmp, first)
            del p['permit_history_read']
            self.denied(self.select(first, tmp, policy=p), 'POLICY_FIELDS_INVALID', invalid=True)
            p = self.policy(tmp, first)
            p['permit_history_read'] = False
            self.denied(self.select(first, tmp, policy=p), 'READ_NOT_PERMITTED')
            p = self.policy(tmp, first)
            p['repository_grants'][0]['permit_history_read'] = False
            self.denied(self.select(first, tmp, policy=p), 'REPOSITORY_GRANT_DENIED')
            p = self.policy(tmp, first)
            p['repository_grants'][0]['read_receipt_sha256'] = p['policy_receipt_sha256']
            self.denied(self.select(first, tmp, policy=p),
                        'REPOSITORY_RECEIPTS_NOT_INDEPENDENT')

    def test_store_device_inode_binding_rejects_unrelated_private_store(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            first = self.saved(a)
            self.saved(b)
            policy = self.policy(a, first)
            self.denied(self.select(first, b, policy=policy), 'POLICY_STORE_BINDING_MISMATCH')

    def test_different_period_and_report_subject_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            base = first['subject']
            r = self.history.show(storage_root=tmp, slot_key=base['slot_key'],
                                  period_id='2026-period-not-saved',
                                  slot_members=base['slot_members'],
                                  read_policy=self.policy(tmp, first))
            self.denied(r, 'POLICY_SUBJECT_PERIOD_MISMATCH')
            member = copy.deepcopy(base['slot_members'])
            member[0]['report_subject_ref'] = 'cesrs1:' + '0' * 64
            r = self.history.show(storage_root=tmp, slot_key=base['slot_key'],
                                  period_id=base['period_id'], slot_members=member,
                                  read_policy=self.policy(tmp, first))
            self.denied(r, 'POLICY_SUBJECT_PERIOD_MISMATCH')

    def test_deny_invalid_versions_without_read_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            base = set(os.listdir(Path(tmp) / '.ces-report-render-v1'))
            self.denied(self.select(first, tmp, version=True), 'VERSION_INVALID', invalid=True)
            self.denied(self.select(first, tmp, version=2), 'VERSION_NOT_FOUND')
            self.denied(self.select(first, tmp, compare_to_version=1),
                        'COMPARE_VERSION_NOT_FOUND')
            self.assertEqual(set(os.listdir(Path(tmp) / '.ces-report-render-v1')), base)

    def test_correction_creates_second_immutable_version_and_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first)
            correction = self.correction(first, read)
            new = self.correct(tmp, first, read, correction)
            out = self.ok(new)
            self.assertEqual(new['reason_code'], 'REPORT_HISTORY_CORRECTION_APPENDED_NOT_PUBLISHED')
            self.assertEqual(new['correction_storage']['state'], 'SAVED_NEW_VERSION')
            self.assertEqual(out['selected_version'], 2)
            self.assertEqual(out['latest_version'], 2)
            self.assertEqual(out['comparison']['before_version'], 1)
            self.assertEqual(out['comparison']['after_version'], 2)
            self.assertIn('permission', out['comparison']['changed_categories'])
            self.assertEqual(out['comparison']['changes']['citation'], [])
            self.assertEqual(out['correction_declaration']['correction_categories'], ['permission'])
            self.assertEqual(out['correction_declaration']['permanent_index_intent'],
                             'NOT_STORED_IN_EC199_INDEX')
            self.assertNotEqual(out['selected_report_ref'], first['subject']['report_ref'])
            place = Path(tmp) / '.ces-report-render-v1'
            self.assertEqual(len(list(place.glob('report-*.json'))), 2)
            self.assertEqual(len(list(place.glob('report-*.md'))), 2)
            oldbytes = (place / ('report-' + first['subject']['report_ref'][7:] + '.json')).read_bytes()
            self.assertEqual(oldbytes, first['canonical_json'].encode('ascii'))
            original = self.ok(self.select(first, tmp, version=1, compare_to_version=2))
            self.assertEqual(original['selected_report_ref'], first['subject']['report_ref'])
            self.assertEqual(original['comparison']['after_version'], 1)
            self.assertEqual(len(original['history']), 2)

    def test_correction_idempotent_request_against_original_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first)
            policy = self.correction(first, read)
            self.ok(self.correct(tmp, first, read, policy))
            repeat = self.correct(tmp, first, read, policy)
            self.ok(repeat)
            self.assertEqual(repeat['reason_code'], 'REPORT_HISTORY_CORRECTION_REPLAY_EXISTING')
            self.assertEqual(repeat['correction_storage']['state'], 'REPLAY_ALREADY_SAVED')
            self.assertEqual(repeat['subject']['latest_version'], 2)

    def test_correction_new_operation_stale_head_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first)
            policy = self.correction(first, read)
            self.ok(self.correct(tmp, first, read, policy))
            policy['operation_id'] = 'ec200-other-operation-999'
            self.denied(self.correct(tmp, first, read, policy), 'CORRECTION_STALE_HEAD')

    def test_correction_unchanged_content_rejected_without_new_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first)
            policy = self.correction(first, read)
            self.denied(self.correct(tmp, first, read, policy, self.original_inputs),
                        'CORRECTION_NO_DISTINCT_REPORT')
            self.assertEqual(self.ok(self.select(first, tmp))['latest_version'], 1)

    def test_correction_requires_authorized_category_with_real_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first)
            policy = self.correction(first, read, cats=['citation'])
            self.denied(self.correct(tmp, first, read, policy),
                        'CORRECTION_CATEGORY_WITHOUT_DELTA')
            self.assertEqual(self.ok(self.select(first, tmp))['latest_version'], 1)

    def test_correction_requires_distinct_scope_bound_grants(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first)
            policy = self.correction(first, read)
            policy['policy_receipt_sha256'] = read['policy_receipt_sha256']
            self.denied(self.correct(tmp, first, read, policy),
                        'READ_CORRECTION_PERMISSION_NOT_INDEPENDENT')
            policy = self.correction(first, read)
            policy['repository_grants'][0]['permit_append_correction'] = False
            self.denied(self.correct(tmp, first, read, policy), 'REPOSITORY_GRANT_DENIED')
            policy = self.correction(first, read)
            policy['report_slot_ref'] = 'cesrslot1:' + '0' * 64
            self.denied(self.correct(tmp, first, read, policy),
                        'POLICY_SUBJECT_PERIOD_MISMATCH')

    def test_correction_cas_baseline_report_and_entry_must_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first)
            policy = self.correction(first, read)
            policy['previous_report_ref'] = 'cesrr1:' + '0' * 64
            self.denied(self.correct(tmp, first, read, policy), 'CORRECTION_BASE_MISMATCH')
            policy = self.correction(first, read)
            policy['previous_entry_sha256'] = '0' * 64
            self.denied(self.correct(tmp, first, read, policy), 'CORRECTION_BASE_MISMATCH')
            self.assertEqual(self.ok(self.select(first, tmp))['latest_version'], 1)

    def test_correction_requires_ec199_independent_local_save_optin(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first)
            policy = self.correction(first, read)
            inputs = self.changed_render()
            inputs['render_policy']['permit_local_save'] = False
            for grant in inputs['render_policy']['repository_grants']:
                grant['permit_local_save'] = False
            self.denied(self.correct(tmp, first, read, policy, inputs),
                        'CORRECTION_RENDER_SAVE_NOT_PERMITTED')

    def test_correction_forged_upstream_is_not_accepted_as_new_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first)
            policy = self.correction(first, read)
            inp = self.changed_render()
            inp['handoff_json'] = '{"schema":"ces.report_writing_handoff.v1"}'
            self.denied(self.correct(tmp, first, read, policy, inp),
                        'CORRECTION_ORIGINAL_REPLAY_FAILED')

    def test_changed_original_markdown_is_rejected_by_store_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            md = next((Path(tmp) / '.ces-report-render-v1').glob('report-*.md'))
            md.write_bytes(b'# forged\n')
            self.denied(self.select(first, tmp),
                        'STORAGE_REFERENCED_CONTENT_MISSING_OR_CHANGED')

    def test_corrupt_index_and_noncanonical_index_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            idx = next((Path(tmp) / '.ces-report-render-v1').glob('index-*.json'))
            content = idx.read_bytes()
            idx.write_bytes(b' '+content)
            self.denied(self.select(first, tmp), 'STORAGE_INDEX_NONCANONICAL')
            idx.write_bytes(b'{"versions":[]}')
            self.denied(self.select(first, tmp), 'STORAGE_INDEX_FIELDS_INVALID')

    def test_private_store_root_and_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            link = Path(tmp) / 'alias'
            link.symlink_to(Path(tmp), target_is_directory=True)
            policy = self.policy(tmp, first)
            doc = first['subject']
            r = self.history.show(storage_root=str(link), slot_key=doc['slot_key'],
                                  period_id=doc['period_id'], slot_members=doc['slot_members'],
                                  read_policy=policy)
            self.denied(r, 'STORE_OR_RECORD_UNAVAILABLE')
            public = Path(tmp) / 'public'
            public.mkdir(mode=0o755)
            r = self.history.show(storage_root=str(public), slot_key=doc['slot_key'],
                                  period_id=doc['period_id'], slot_members=doc['slot_members'],
                                  read_policy=policy)
            self.denied(r, 'STORAGE_ROOT_NOT_OWNER_PRIVATE')

    def test_real_upstream_redaction_produces_citation_coverage_and_permission_diff(self):
        # This is NOT a fabricated second stored JSON. All EC192..EC198
        # genuine source/review/release replays are used on both versions.
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first)
            prep_api = self.prev.prior.prior
            new_release = prep_api.make_policy(prep_api.scope, prep_api.metrics,
                                               refs=['git-sample'])
            new_prepare = prep_api.call(policy=new_release)
            prep_api.ok(new_prepare)
            new_review = self.prev.prior.review_for(new_prepare)
            new_handoff = self.prev.prior.call(prepare=new_prepare,
                                               release=new_release, review=new_review)
            self.prev.prior.ok(new_handoff)
            new_render = self.prev.policy_for(new_handoff)
            next_inputs = self.prev.arguments(
                handoff=new_handoff, prepare=new_prepare,
                release=new_release, review=new_review, policy=new_render)
            candidate = self.prev.ok(self.prev.api.render(**next_inputs))
            self.assertEqual(candidate['report_slot_ref'], first['subject']['report_slot_ref'])
            # An approval for citations/coverage/permissions cannot silently
            # authorize the *source* hash changes caused by real EC197 replay.
            narrow = self.correction(first, read,
                                     cats=['citation', 'coverage', 'permission'])
            self.denied(self.correct(tmp, first, read, narrow, next_inputs),
                        'CORRECTION_UNDECLARED_CATEGORY_DELTA')
            self.assertEqual(self.ok(self.select(first, tmp))['latest_version'], 1)
            correction = self.correction(first, read,
                                         cats=['citation', 'coverage', 'permission', 'source'])
            appended = self.correct(tmp, first, read, correction, next_inputs)
            projection = self.ok(appended)
            changes = projection['comparison']['changes']
            self.assertTrue(changes['citation'])
            self.assertTrue(changes['coverage'])
            self.assertTrue(changes['permission'])
            self.assertTrue(any(x['removed_count'] > 0 for x in changes['citation']))
            self.assertTrue(any(x['after'] == 'PARTIAL_DECLARED' for x in changes['coverage']
                                if x['field'] == 'coverage_state'))
            self.assertEqual(projection['selected_report_ref'], candidate['report_ref'])
            view = self.ok(self.select(first, tmp, version=2))
            self.assertEqual(view['comparison'], projection['comparison'])
            self.assertEqual(self.ok(self.select(first, tmp, version=1))['selected_report_ref'],
                             first['subject']['report_ref'])

    def test_receipts_cannot_reuse_ec199_or_ec200_read_grant(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            read = self.policy(tmp, first)
            policy = self.correction(first, read)
            policy['repository_grants'][0]['correction_receipt_sha256'] = \
                read['repository_grants'][0]['read_receipt_sha256']
            self.denied(self.correct(tmp, first, read, policy),
                        'CORRECTION_RECEIPTS_NOT_INDEPENDENT')
            policy = self.correction(first, read)
            policy['policy_receipt_sha256'] = self.changed_render()['render_policy']['policy_receipt_sha256']
            self.denied(self.correct(tmp, first, read, policy),
                        'CORRECTION_RECEIPTS_NOT_INDEPENDENT')

    def test_comparison_is_typed_and_preserves_actual_citation_set_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            a = first['subject']
            b = copy.deepcopy(a)
            b['report_ref'] = 'cesrr1:' + 'a' * 64
            b['sections_manifest'][0]['citation_refs'] = ['cesrc1:' + 'f' * 64]
            b['sections_manifest'][0]['coverage_state'] = 'UNKNOWN'
            b['sections_manifest'][0]['coverage_reason_codes'] = ['DATA_NOT_PROVIDED']
            b['sections_manifest'][0]['release_state'] = 'WITHHELD'
            b['sections_manifest'][0]['source_binding_sha256'] = '1' * 64
            b['sections_manifest'][0]['path_scope'] = 'SELECTED_PATHS'
            b['source_pins']['scope_ref'] = 'cesrscope1:changed'
            diff = _comparison(a, b, 1, 2)
            for category in ('source', 'scope', 'permission', 'citation', 'coverage'):
                self.assertTrue(diff['changes'][category], (category, diff))
            c = diff['changes']['citation'][0]
            self.assertEqual(c['repository_ref'], a['sections_manifest'][0]['repository_ref'])
            self.assertEqual(c['added_count'], 1)
            self.assertEqual(c['added_refs'], ['cesrc1:'+'f'*64])
            self.assertEqual(c['removed_count'], len(a['sections_manifest'][0]['citation_refs']))
            self.assertEqual(c['added_omitted_count'], 0)
            self.assertEqual(c['before_set_sha256'],
                             digest('CES-EC200-CITATIONS-v1', sorted(a['sections_manifest'][0]['citation_refs'])))

    def test_comparison_has_32_citation_ref_cap_and_explicit_omitted_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = self.saved(tmp)['subject']
            b = copy.deepcopy(a)
            b['sections_manifest'][0]['citation_refs'] = ['cesrc1:' + f'{i:064x}' for i in range(40)]
            diff = _comparison(a, b, 1, 2)['changes']['citation'][0]
            self.assertEqual(diff['added_count'], 40)
            self.assertEqual(len(diff['added_refs']), 32)
            self.assertEqual(diff['added_omitted_count'], 8)

    def test_show_read_is_no_side_effect_even_on_version_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.saved(tmp)
            store = Path(tmp) / '.ces-report-render-v1'
            original = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in store.iterdir()}
            for _ in range(3):
                self.ok(self.select(first, tmp, version=1))
            after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in store.iterdir()}
            self.assertEqual(original, after)


if __name__ == '__main__':
    unittest.main()
