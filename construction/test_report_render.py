#!/usr/bin/env python3
"""EC199 focused offline ReportRender behavior and opt-in local store tests.

Uses the existing genuine EC192..EC198 replay chain with synthetic declarations.
No real repository identity, grant signature, Git/CI/provider, privacy approval
or user-assisted deployment verification is claimed.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator
from report_evidence_metrics import canonical
from report_render import (
    ReportRender, POLICY_SCHEMA, PURPOSE, AUDIENCE, LIMITATIONS,
)
import test_report_writing_handoff as preceding

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / 'references' /
                     'report-render-result.v1.schema.json').read_text())
Draft202012Validator.check_schema(SCHEMA)
POLICY_CONTRACT = json.loads((ROOT / 'references' /
                              'report-render-policy.v1.schema.json').read_text())
Draft202012Validator.check_schema(POLICY_CONTRACT)
POLICY_VALIDATOR = Draft202012Validator(POLICY_CONTRACT)
VALIDATOR = Draft202012Validator(SCHEMA)


class ReportRenderTests(unittest.TestCase):
    def setUp(self) -> None:
        prior = preceding.ReportWritingHandoffTests()
        prior.setUp()
        self.prior = prior
        self.handoff = prior.call()
        self.assertEqual(self.handoff['status'], 'partial', self.handoff)
        self.policy = self.policy_for(self.handoff)
        self.api = ReportRender()

    @staticmethod
    def policy_for(handoff):
        sub = handoff['subject']
        grants = []
        for i, repo in enumerate(sub['handoff_draft']['outline']['repository_sections']):
            grants.append({
                'repository_ref': repo['repository_ref'],
                'report_subject_ref': repo['report_subject_ref'],
                'source_binding_sha256': repo['source_binding_sha256'],
                'people_binding_sha256': repo['people_binding_sha256'],
                'permit_internal_render': True,
                'permit_local_save': True,
                'render_receipt_sha256': f'{i + 110:064x}',
                'approved_citation_refs': [cite['citation_ref']
                                           for ch in repo['evidence_slots']
                                           for cite in ch['citations']],
            })
        pins = sub['source_pins']
        return {
            'schema': POLICY_SCHEMA,
            'purpose': PURPOSE,
            'audience': AUDIENCE,
            'permit_internal_render': True,
            'permit_local_save': True,
            'slot_key': 'weekly-review',
            'draft_ref': sub['draft_ref'],
            'draft_binding_sha256': sub['binding_sha256'],
            'review_policy_binding_sha256': sub['review_policy_binding_sha256'],
            'prepare_binding_sha256': pins['prepare_binding_sha256'],
            'ai_input_sha256': pins['ai_input_sha256'],
            'scope_binding_sha256': pins['scope_binding_sha256'],
            'metrics_binding_sha256': pins['metrics_binding_sha256'],
            'period_id': pins['period_id'],
            'policy_receipt_sha256': 'e' * 64,
            'repository_grants': grants,
        }

    def arguments(self, policy=None, handoff=None, prepare=None, scope=None,
                  metrics=None, release=None, review=None):
        return {
            'handoff_json': (handoff or self.handoff)['canonical_json'],
            'prepare_json': (prepare or self.prior.prepare)['canonical_json'],
            'scope_json': (scope or self.prior.prior.scope)['canonical_json'],
            'metrics_json': (metrics or self.prior.prior.metrics)['canonical_json'],
            'release_policy': copy.deepcopy(
                self.prior.prior.policy if release is None else release),
            'review_policy': copy.deepcopy(
                self.prior.review if review is None else review),
            'render_policy': copy.deepcopy(
                self.policy if policy is None else policy),
        }

    def ok(self, result):
        self.assertEqual(list(VALIDATOR.iter_errors(result)), [], result)
        self.assertEqual((result['status'], result['exit_code']), ('partial', 2), result)
        self.assertEqual(canonical(result['subject']), result['canonical_json'])
        self.assertEqual(result['limitations'], LIMITATIONS)
        self.assertFalse(any(result['subject']['limitations'].values()))
        return result['subject']

    def refused(self, result, code, *, unavailable=False):
        self.assertEqual(list(VALIDATOR.iter_errors(result)), [], result)
        self.assertEqual((result['status'], result['exit_code']),
                         ('unavailable', 5) if unavailable else ('invalid_input', 4),
                         result)
        self.assertEqual(result['reason_code'], 'REPORT_RENDER_' + code, result)
        self.assertIsNone(result['subject'])
        self.assertIsNone(result['canonical_json'])
        self.assertIsNone(result['storage'])

    def test_render_policy_matches_strict_input_contract(self):
        self.assertEqual(list(POLICY_VALIDATOR.iter_errors(self.policy)), [])
        extra = copy.deepcopy(self.policy)
        extra['purpose'] = 'report_publish'
        self.assertTrue(list(POLICY_VALIDATOR.iter_errors(extra)))
        extra = copy.deepcopy(self.policy)
        extra['repository_grants'][0]['employee_rating'] = 'excellent'
        self.assertTrue(list(POLICY_VALIDATOR.iter_errors(extra)))

    def test_fixed_markdown_is_actually_rendered_and_unpublished(self):
        out = self.api.render(**self.arguments())
        sub = self.ok(out)
        self.assertEqual(out['reason_code'],
                         'REPORT_RENDER_UNPUBLISHED_INTERNAL_DRAFT')
        self.assertIsNone(out['storage'])
        self.assertTrue(sub['report_ref'].startswith('cesrr1:'))
        self.assertTrue(sub['report_slot_ref'].startswith('cesrslot1:'))
        self.assertEqual(sub['document_state'],
                         'UNPUBLISHED_INTERNAL_REVIEW_ARTIFACT')
        doc = sub['rendered_markdown']
        self.assertEqual(hashlib.sha256(doc.encode('utf-8')).hexdigest(),
                         sub['rendered_sha256'])
        self.assertIn('NOT PUBLISHED', doc)
        self.assertIn('NOT an executed, passing CI result', doc)
        self.assertIn('ProposedPR is a proposal', doc)
        self.assertIn('not ReportPublish', doc)
        self.assertEqual(len(sub['sections_manifest']), 8)
        self.assertEqual(len(sub['slot_members']), 2)
        self.assertEqual(sub['source_pins'], self.handoff['subject']['source_pins'])
        self.assertEqual(sub['handoff_draft_ref'], self.handoff['subject']['draft_ref'])

    def test_released_citations_preserved_with_exact_repository_channels(self):
        report = self.ok(self.api.render(**self.arguments()))
        source = self.handoff['subject']['handoff_draft']['outline']['repository_sections']
        for outline in source:
            for slot in outline['evidence_slots']:
                actual = next(m for m in report['sections_manifest']
                              if m['repository_ref'] == outline['repository_ref']
                              and m['channel'] == slot['channel'])
                refs = [c['citation_ref'] for c in slot['citations']]
                self.assertEqual(actual['citation_refs'], refs)
                self.assertEqual(actual['ci_completion_signal'],
                                 slot['ci_completion_signal'])
                self.assertEqual(actual['coverage_state'], slot['coverage_state'])
                for ref in refs:
                    self.assertIn(ref, report['rendered_markdown'])

    def test_raw_sensitive_values_and_free_prose_cannot_be_added(self):
        sub = self.ok(self.api.render(**self.arguments()))
        doc = sub['rendered_markdown']
        for secret in ('alice@example.org', 'index.py', 'source_receipt_sha256',
                       'review_receipt_sha256', 'release_receipt_sha256',
                       'actor_key', 'performance rating', 'PASS verified'):
            self.assertNotIn(secret, doc)
        injected = copy.deepcopy(self.policy)
        injected['narrative'] = 'A person delivered excellent results.'
        self.refused(self.api.render(**self.arguments(policy=injected)),
                     'RENDER_POLICY_FIELDS_INVALID')

    def test_true_empty_is_not_zero_activities(self):
        self.assertIn('NOT proof of no activity',
                      self.ok(self.api.render(**self.arguments()))['rendered_markdown'])

    def test_identical_render_policy_order_is_canonical(self):
        baseline = self.ok(self.api.render(**self.arguments()))
        p = copy.deepcopy(self.policy)
        p['repository_grants'].reverse()
        for r in p['repository_grants']:
            r['approved_citation_refs'].reverse()
        self.assertEqual(baseline, self.ok(self.api.render(**self.arguments(policy=p))))

    def test_from_json_replays_origins_not_local_sha_only(self):
        sub = self.ok(self.api.render(**self.arguments()))
        result = self.api.from_json(serialized=canonical(sub), **self.arguments())
        self.assertEqual(self.ok(result), sub)
        self.assertEqual(result['reason_code'], 'REPORT_RENDER_REPLAYED_ORIGINAL_SOURCES')

    def test_from_json_rejects_even_self_hashed_extra_claim(self):
        sub = self.ok(self.api.render(**self.arguments()))
        sub['individual_performance_score'] = 100
        self.refused(self.api.from_json(serialized=canonical(sub),
                                        **self.arguments()), 'REPLAY_FIELDS_INVALID')

    def test_from_json_rejects_tampered_markdown(self):
        sub = self.ok(self.api.render(**self.arguments()))
        sub['rendered_markdown'] += '\nCI actually passed.'
        self.refused(self.api.from_json(serialized=canonical(sub),
                                        **self.arguments()),
                     'REPLAY_CONTENT_SOURCE_OR_POLICY_MISMATCH')

    def test_from_json_rejects_duplicate_json_keys(self):
        sub = self.ok(self.api.render(**self.arguments()))
        bad = canonical(sub).replace('"schema":', '"schema":"x","schema":', 1)
        self.refused(self.api.from_json(serialized=bad, **self.arguments()),
                     'REPLAY_UPSTREAM_INVALID')

    def test_not_full_original_ec198_handoff_refused(self):
        altered = copy.deepcopy(self.handoff)
        altered['canonical_json'] = '{"schema":"ces.report_writing_handoff.v1"}'
        self.refused(self.api.render(**self.arguments(handoff=altered)),
                     'EC198_OR_UPSTREAM_REPLAY_REFUSED')

    def test_wrong_release_replay_or_source_pins_refused(self):
        release = copy.deepcopy(self.prior.prior.policy)
        release['repository_grants'][0]['release_receipt_sha256'] = 'd' * 64
        self.refused(self.api.render(**self.arguments(release=release)),
                     'EC198_OR_UPSTREAM_REPLAY_REFUSED')
        p = copy.deepcopy(self.policy)
        p['ai_input_sha256'] = '0' * 64
        self.refused(self.api.render(**self.arguments(policy=p)),
                     'RENDER_DRAFT_OR_SOURCE_PINS_STALE', unavailable=True)

    def test_independent_render_policy_and_repository_receipts(self):
        p = copy.deepcopy(self.policy)
        p['policy_receipt_sha256'] = self.prior.review['policy_receipt_sha256']
        self.refused(self.api.render(**self.arguments(policy=p)),
                     'RENDER_RECEIPTS_NOT_INDEPENDENT', unavailable=True)
        p = copy.deepcopy(self.policy)
        p['repository_grants'][1]['render_receipt_sha256'] = \
            p['repository_grants'][0]['render_receipt_sha256']
        self.refused(self.api.render(**self.arguments(policy=p)),
                     'RENDER_RECEIPTS_NOT_INDEPENDENT', unavailable=True)
        p = copy.deepcopy(self.policy)
        p['repository_grants'][0]['render_receipt_sha256'] = \
            self.prior.prior.policy['repository_grants'][0]['release_receipt_sha256']
        self.refused(self.api.render(**self.arguments(policy=p)),
                     'RENDER_RECEIPTS_NOT_INDEPENDENT', unavailable=True)

    def test_render_grants_require_all_exact_repository_citations(self):
        p = copy.deepcopy(self.policy)
        p['repository_grants'].pop()
        self.refused(self.api.render(**self.arguments(policy=p)),
                     'RENDER_REPOSITORY_GRANTS_INCOMPLETE', unavailable=True)
        p = copy.deepcopy(self.policy)
        selected = next(r for r in p['repository_grants']
                        if r['approved_citation_refs'])
        selected['approved_citation_refs'].pop()
        self.refused(self.api.render(**self.arguments(policy=p)),
                     'RENDER_CITATIONS_NOT_EXACT_RELEASED_SET', unavailable=True)
        p = copy.deepcopy(self.policy)
        p['repository_grants'][0]['source_binding_sha256'] = '0' * 64
        self.refused(self.api.render(**self.arguments(policy=p)),
                     'RENDER_REPOSITORY_SOURCE_PEOPLE_STALE', unavailable=True)

    def test_save_permission_not_implicit_in_render_permission(self):
        p = copy.deepcopy(self.policy)
        p['permit_local_save'] = False
        for row in p['repository_grants']:
            row['permit_local_save'] = False
        self.ok(self.api.render(**self.arguments(policy=p)))
        with tempfile.TemporaryDirectory() as tmp:
            res = self.api.save(**self.arguments(policy=p),
                                storage_root=tmp, expected_previous_version=0,
                                operation_id='op-denied-0001')
            self.refused(res, 'LOCAL_SAVE_NOT_PERMITTED', unavailable=True)
            self.assertEqual(os.listdir(tmp), [])

    def test_no_per_repo_save_grant_fails_closed(self):
        p = copy.deepcopy(self.policy)
        p['repository_grants'][0]['permit_local_save'] = False
        with tempfile.TemporaryDirectory() as tmp:
            self.refused(self.api.save(**self.arguments(policy=p),
                                       storage_root=tmp, expected_previous_version=0,
                                       operation_id='op-denied-0002'),
                         'LOCAL_SAVE_NOT_PERMITTED', unavailable=True)

    def test_wrong_purpose_or_mode_refuses_even_if_boolean_true(self):
        p = copy.deepcopy(self.policy)
        p['purpose'] = 'report_publish'
        self.refused(self.api.render(**self.arguments(policy=p)),
                     'RENDER_PURPOSE_OR_OPTIN_INVALID', unavailable=True)
        p = copy.deepcopy(self.policy)
        p['permit_internal_render'] = 1
        self.refused(self.api.render(**self.arguments(policy=p)),
                     'RENDER_PURPOSE_OR_OPTIN_INVALID', unavailable=True)

    def test_local_save_creates_immutable_record_markdown_and_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.api.save(**self.arguments(), storage_root=tmp,
                                   expected_previous_version=0,
                                   operation_id='save-first-001')
            sub = self.ok(result)
            receipt = result['storage']
            self.assertEqual(receipt['state'], 'SAVED_NEW_VERSION')
            self.assertEqual((receipt['version'], receipt['version_count']), (1, 1))
            folder = Path(tmp) / '.ces-report-render-v1'
            files = sorted(x for x in folder.iterdir())
            self.assertEqual(len(files), 3)
            indexpath = next(x for x in files if x.name.startswith('index-'))
            idx = json.loads(indexpath.read_text(encoding='ascii'))
            self.assertEqual(len(idx['versions']), 1)
            self.assertEqual(idx['versions'][0]['version'], 1)
            mdpath = next(x for x in files if x.suffix == '.md')
            self.assertEqual(mdpath.read_text(), sub['rendered_markdown'])
            self.assertFalse(any(x.name.startswith('.pending') for x in files))
            self.assertFalse(result['storage']['publication_state'] == 'PUBLISHED')

    def test_exact_retry_same_token_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            kwargs = dict(storage_root=tmp, expected_previous_version=0,
                          operation_id='save-retry-0001')
            a = self.api.save(**self.arguments(), **kwargs)
            b = self.api.save(**self.arguments(), **kwargs)
            self.ok(a)
            self.ok(b)
            self.assertEqual(a['storage']['state'], 'SAVED_NEW_VERSION')
            self.assertEqual(b['storage']['state'], 'REPLAY_ALREADY_SAVED')
            self.assertEqual(b['storage']['version_count'], 1)
            self.assertEqual(a['storage']['index_binding_sha256'],
                             b['storage']['index_binding_sha256'])

    def test_identical_content_new_operation_reuses_existing_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = self.api.save(**self.arguments(), storage_root=tmp,
                              expected_previous_version=0,operation_id='save-reuse-0001')
            b = self.api.save(**self.arguments(), storage_root=tmp,
                              expected_previous_version=1,operation_id='save-reuse-0002')
            self.ok(a)
            self.ok(b)
            self.assertEqual(b['storage']['state'], 'IDENTICAL_RENDER_EXISTS')
            self.assertEqual(b['storage']['version_count'], 1)

    def test_new_version_is_append_only_and_preserves_old_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = self.api.save(**self.arguments(), storage_root=tmp,
                              expected_previous_version=0,operation_id='save-vers-00001')
            self.ok(a)
            p = copy.deepcopy(self.policy)
            p['policy_receipt_sha256'] = 'd' * 64
            b = self.api.save(**self.arguments(policy=p), storage_root=tmp,
                              expected_previous_version=1,operation_id='save-vers-00002')
            self.ok(b)
            self.assertEqual(b['storage']['state'], 'SAVED_NEW_VERSION')
            self.assertEqual(b['storage']['version'], 2)
            self.assertNotEqual(a['subject']['report_ref'], b['subject']['report_ref'])
            f = Path(tmp) / '.ces-report-render-v1'
            self.assertEqual(len(list(f.glob('report-*.json'))), 2)
            idx = json.loads(next(f.glob('index-*.json')).read_text())
            self.assertEqual(len(idx['versions']), 2)
            self.assertEqual(idx['versions'][1]['previous_entry_sha256'],
                             idx['versions'][0]['entry_sha256'])
            self.assertEqual(idx['versions'][0]['report_ref'], a['subject']['report_ref'])
            self.assertEqual(idx['versions'][1]['report_ref'], b['subject']['report_ref'])

    def test_stale_optimistic_version_rejects_without_updating_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.ok(self.api.save(**self.arguments(), storage_root=tmp,
                                  expected_previous_version=0,operation_id='save-cas-00001'))
            f = Path(tmp) / '.ces-report-render-v1'
            idxfile = next(f.glob('index-*.json'))
            prior_idx = idxfile.read_bytes()
            p = copy.deepcopy(self.policy)
            p['policy_receipt_sha256'] = 'd' * 64
            conflict = self.api.save(**self.arguments(policy=p),storage_root=tmp,
                                     expected_previous_version=0,
                                     operation_id='save-cas-00002')
            self.refused(conflict,'STALE_INDEX_EXPECTED_VERSION_CONFLICT',
                         unavailable=True)
            self.assertEqual(idxfile.read_bytes(),prior_idx)

    def test_same_operation_new_content_conflicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.ok(self.api.save(**self.arguments(), storage_root=tmp,
                                  expected_previous_version=0,operation_id='save-opid-0001'))
            p = copy.deepcopy(self.policy)
            p['policy_receipt_sha256'] = 'd' * 64
            self.refused(self.api.save(**self.arguments(policy=p),storage_root=tmp,
                                       expected_previous_version=1,
                                       operation_id='save-opid-0001'),
                         'SAVE_OPERATION_CONFLICT', unavailable=True)

    def test_corrupt_index_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.ok(self.api.save(**self.arguments(), storage_root=tmp,
                                  expected_previous_version=0,operation_id='save-idx-00001'))
            f = Path(tmp) / '.ces-report-render-v1'
            index = next(f.glob('index-*.json'))
            index.write_bytes(b'{"fake":true}')
            res = self.api.save(**self.arguments(),storage_root=tmp,
                                expected_previous_version=0,operation_id='save-idx-00001')
            self.refused(res,'STORAGE_INDEX_FIELDS_INVALID', unavailable=True)
            self.assertEqual(index.read_bytes(),b'{"fake":true}')

    def test_tampered_existing_report_markdown_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.ok(self.api.save(**self.arguments(), storage_root=tmp,
                                  expected_previous_version=0,operation_id='save-doc-00001'))
            f = Path(tmp) / '.ces-report-render-v1'
            md = next(f.glob('report-*.md'))
            md.write_text('# forged')
            res = self.api.save(**self.arguments(),storage_root=tmp,
                                expected_previous_version=0,operation_id='save-doc-00001')
            self.refused(res,'STORAGE_REFERENCED_CONTENT_MISSING_OR_CHANGED',
                         unavailable=True)

    def test_private_root_only_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)/'alias'
            dest.symlink_to(tmp,target_is_directory=True)
            self.refused(self.api.save(**self.arguments(),
                                       storage_root=str(dest),
                                       expected_previous_version=0,
                                       operation_id='save-symlink-01'),
                         'LOCAL_STORAGE_IO_UNAVAILABLE',unavailable=True)
            public = Path(tmp)/'public'
            public.mkdir(mode=0o755)
            self.refused(self.api.save(**self.arguments(),
                                       storage_root=str(public),
                                       expected_previous_version=0,
                                       operation_id='save-public-001'),
                         'STORAGE_ROOT_NOT_OWNER_PRIVATE',unavailable=True)
            repo = Path(tmp) / 'business-checkout'
            repo.mkdir(mode=0o700)
            (repo / '.git').write_text('gitdir: /another/git-dir\n')
            private = repo / 'private'
            private.mkdir(mode=0o700)
            self.refused(self.api.save(**self.arguments(),
                                       storage_root=str(private),
                                       expected_previous_version=0,
                                       operation_id='save-source-001'),
                         'STORAGE_INSIDE_SOURCE_REPOSITORY',unavailable=True)
            self.assertEqual(os.listdir(private), [])

    def test_storage_root_and_expected_version_require_explicit_valid_input(self):
        self.refused(self.api.save(**self.arguments(),storage_root='relative',
                                   expected_previous_version=0,
                                   operation_id='save-invalid-01'),
                     'STORAGE_ROOT_INVALID')
        with tempfile.TemporaryDirectory() as tmp:
            self.refused(self.api.save(**self.arguments(),storage_root=tmp,
                                       expected_previous_version=True,
                                       operation_id='save-invalid-02'),
                         'EXPECTED_PREVIOUS_VERSION_INVALID')
            self.refused(self.api.save(**self.arguments(),storage_root=tmp,
                                       expected_previous_version=0,
                                       operation_id='../oops'),
                         'SAVE_OPERATION_ID_INVALID')

    def test_render_without_local_storage_does_not_create_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = set(os.listdir(tmp))
            sub = self.ok(self.api.render(**self.arguments()))
            self.assertTrue(sub['rendered_markdown'])
            self.assertEqual(set(os.listdir(tmp)), before)


if __name__ == '__main__':
    unittest.main()
