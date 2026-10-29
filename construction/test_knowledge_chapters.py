#!/usr/bin/env python3
"""EC205 bounded real-Git, actual CES bytes and ephemeral development signatures."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

from knowledge_boundary import canonical, digest
from knowledge_chapters import KnowledgeChapters, POLICY_SCHEMA
from knowledge_bootstrap import MANIFEST_SCHEMA
from test_knowledge_bootstrap import request, source, policy as bootstrap_policy
import test_knowledge_impact as impact_tests

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

SCHEMAS = Path(__file__).resolve().parent.parent/'references'
H = 'a'*64


def sha(data):
    return hashlib.sha256(data).hexdigest()


@unittest.skipIf(impact_tests.Ed25519PrivateKey is None, 'cryptography required')
class ChaptersTests(unittest.TestCase):
    def setUp(self):
        self.upstream = impact_tests.ImpactTests('test_real_git_modified_selected_file_and_no_section_claim')
        self.upstream.setUp()
        self.addCleanup(self.upstream.doCleanups)
        self.doc = (b'# Overview\nUnrelated chapter.\n\n'
                    b'## Component\n<!-- CES-SOURCE source_key=r1 -->\n'
                    b'Actual note for source.\n\n'
                    b'## Appendix\nKeep untouched.\n')
        self.make_snapshot()
        self.rebind()

    def factory(self):
        return KnowledgeChapters(repository_root=str(self.upstream.fx.repo),
            knowledge_root=str(self.upstream.fx.knowledge),
            repository_ref=self.upstream.r['scope']['repository_ref'],
            target_ref='refs/heads/main',
            trusted_target_keys={'production': self.upstream.fx.pub},
            trusted_baseline_keys={'baseline-authority': self.upstream.baseline_public})

    def make_snapshot(self, *, content=None, coverage='complete_declared',
                      stamp='2026-10-11T12:00:00Z'):
        if content is not None:
            self.doc = content
        self.upstream.fx.put(self.upstream.fx.knowledge, 'arch/components.md', self.doc)
        manifest = {'schema': MANIFEST_SCHEMA,
            'repository_ref': 'cesrepo1:'+'1'*64,
            'knowledge_space_key': 'architecture',
            'source_policy_revision': 'policy-v1',
            'snapshot_version': 'checkpoint-v1', 'captured_at_utc': stamp,
            'coverage': coverage,
            'entries': [{'relative_path':'arch/components.md',
                         'sha256':sha(self.doc), 'size_bytes':len(self.doc)}]}
        self.manifest = canonical(manifest).encode('utf-8')
        self.upstream.fx.put(self.upstream.fx.knowledge, 'ces-snapshot.v1.json', self.manifest)

    def rebind(self):
        self.r = request(
            source('k1','ces_knowledge','arch/components.md',self.doc),
            source('r1','repository','src/component.md',self.upstream.fx.content),
            target={'algorithm':'sha1','oid':self.upstream.fx.oid},
            expected_manifest=sha(self.manifest))
        self.bp = bootstrap_policy(self.upstream.api.target.bootstrap,
                                    self.r, provenance=True, content=True)
        _,_,self.tp,self.target_doc = self.upstream.fx.binding(original=self.r)
        self.tp['bootstrap_read_policy_binding_sha256'] = digest(
            'CES-EC202-READ-POLICY-v1', self.bp)
        self.upstream.r = self.r
        self.upstream.bp = self.bp
        self.upstream.tp = self.tp
        self.upstream.target_doc = self.target_doc
        self.upstream.ip = self.upstream.impact_policy()
        self.upstream.baseline_doc = self.upstream.baseline_statement()
        self.ip = self.upstream.ip
        self.baseline_doc = self.upstream.baseline_doc
        self.api = self.factory()
        self.cp = self.chapter_policy()

    def chapter_policy(self):
        preview = self.api.binding_preview(
            request_json=canonical(self.r),
            bootstrap_read_policy_json=canonical(self.bp),
            target_read_policy_json=canonical(self.tp),
            impact_read_policy_json=canonical(self.ip),
            target_statement_json=canonical(self.target_doc),
            baseline_statement_json=canonical(self.baseline_doc))
        self.assertEqual(preview['status'], 'partial',preview)
        pins = preview['subject']
        keys = ('request_binding_sha256','scope_binding_sha256',
            'repository_root_binding_sha256','knowledge_root_binding_sha256',
            'git_root_binding_sha256','target_config_binding_sha256',
            'issuer_registry_binding_sha256','baseline_issuer_registry_binding_sha256',
            'bootstrap_read_policy_binding_sha256','target_read_policy_binding_sha256',
            'impact_read_policy_binding_sha256','target_statement_binding_sha256',
            'baseline_statement_binding_sha256')
        return {'schema': POLICY_SCHEMA,
            'purpose': 'knowledge_existing_chapters_read_only',
            'repository_ref':self.r['scope']['repository_ref'],
            'knowledge_space_key':self.r['scope']['knowledge_space_key'],
            'source_policy_revision':self.r['scope']['source_policy_revision'],
            'period_id':self.r['scope']['period']['period_id'],
            **{k:pins[k] for k in keys},
            'read_receipt_sha256': H,
            'permit_chapter_mapping':True,
            'permit_section_title_projection':True,
            'permit_section_digest_projection':False,
            'permit_reference_digest_comparison':False,
            'permit_repository_write':False,'permit_knowledge_write':False,
            'permit_business_source_write':False,'permit_issue_write':False,
            'permit_publish':False,
            'source_grants': [
                {'source_key': r['source_key'],
                 'source_binding_sha256': pin['source_binding_sha256'],
                 'permit_section_mapping': r['kind']=='ces_knowledge',
                 'permit_repository_association': r['kind']=='repository',
                 'read_receipt_sha256': H}
                for r,pin in zip(self.r['sources'], pins['source_bindings'])]}

    def call(self, *, baseline=True, target_sig='AUTO', base_sig='AUTO'):
        return self.api.map_chapters(
            request_json=canonical(self.r),
            bootstrap_read_policy_json=canonical(self.bp),
            target_read_policy_json=canonical(self.tp),
            impact_read_policy_json=canonical(self.ip),
            chapter_read_policy_json=canonical(self.cp),
            target_statement_json=canonical(self.target_doc),
            target_signature_base64=self.upstream.fx.sign(self.target_doc)
                if target_sig == 'AUTO' else target_sig,
            baseline_statement_json=canonical(self.baseline_doc) if baseline else None,
            baseline_signature_base64=self.upstream.sign_base()
                if base_sig == 'AUTO' and baseline else base_sig)

    def success(self, out=None):
        if out is None: out=self.call()
        self.assertEqual((out['status'],out['exit_code']),('partial',2),out)
        self.assertEqual(out['subject'],json.loads(out['canonical_json']))
        self.assertFalse(any(out['limitations'].values()))
        self.assertTrue(out['subject']['no_write_actions_performed'])
        self.assertEqual(out['subject']['knowledge_sections_to_update'],[])
        self.assertEqual(out['subject']['verified_delivered_facts'],[])
        return out['subject']

    def test_actual_changed_git_bytes_maps_only_selected_chapter(self):
        s=self.success()
        self.assertTrue(s['knowledge_snapshot_stable_across_read'])
        self.assertEqual(s['selected_change_set_state'],'SELECTED_REPOSITORY_PATHS_COMPARED')
        self.assertEqual(s['summary']['visible_selected_sections'],3)
        self.assertEqual(s['summary']['sections_with_explicit_selected_source_links'],1)
        self.assertEqual(s['summary']['unrelated_sections_not_projected'],2)
        record=s['chapter_documents'][0]
        self.assertEqual(len(record['sections']),1)
        sec=record['sections'][0]
        self.assertEqual(sec['heading'],'Component')
        self.assertEqual(sec['ordinal'],1)
        self.assertEqual(sec['associations'][0]['selected_git_change_kind'],'MODIFIED')
        self.assertEqual(sec['associations'][0]['review_state'],'REVIEW_CHANGED_SELECTED_SOURCE')
        self.assertEqual(sec['associations'][0]['staleness_signal'],
                         'POTENTIALLY_STALE_SELECTED_GIT_CONTENT_CHANGED')
        self.assertEqual(s['snapshot_recency_signal'],
                         'DECLARED_SNAPSHOT_PREDATES_SIGNED_TARGET_UNVERIFIED_TIME')
        self.assertTrue(sec['manual_review_candidate'])
        self.assertFalse(sec['semantic_diff_verified'])
        self.assertNotIn('Actual note',canonical(s))
        self.assertNotIn('Keep untouched',canonical(s))
        self.assertEqual(self.upstream.fx.cmd('status','--porcelain'),'')

    def test_markdown_exact_link_maps_without_annotation(self):
        self.make_snapshot(content=b'# Intro\n[architecture](src/component.md)\n')
        self.rebind()
        s=self.success()
        methods=s['chapter_documents'][0]['sections'][0]['associations'][0]['association_methods']
        self.assertEqual(methods,['EXACT_MARKDOWN_LINK'])

    def test_fenced_markers_inline_code_and_lookalikes_never_map(self):
        self.make_snapshot(content=(b'# Main\n'
            b'```markdown\n<!-- CES-SOURCE source_key=r1 -->\n'
            b'[false](src/component.md)\n## Hidden heading\n```\n'
            b'`[inline](src/component.md)`\n'
            b'[other](../src/component.md)\n'
            b'<!-- CES-SOURCE source_key=unknown -->\n'))
        self.rebind()
        s=self.success()
        self.assertEqual(s['summary']['sections_with_explicit_selected_source_links'],0)
        self.assertEqual(s['summary']['visible_selected_sections'],1)
        self.assertEqual(s['summary']['unresolved_explicit_refs'],1)
        self.assertEqual(s['summary']['changed_selected_sources_without_visible_link'],1)

    def test_mode_only_not_interpreted_as_semantic_staleness(self):
        self.upstream.fx.cmd('config','core.filemode','true')
        self.upstream.fx.repo.joinpath('src/component.md').chmod(0o755)
        self.upstream.fx.commit('change mode')
        self.upstream.base_oid = self.upstream.fx.cmd('rev-parse','HEAD^')
        self.rebind()
        s=self.success()
        self.assertEqual(s['chapter_documents'][0]['sections'][0]['associations'][0]
                         ['selected_git_change_kind'],'MODE_ONLY')
        self.assertEqual(s['chapter_documents'][0]['sections'][0]['associations'][0]
                         ['review_state'],'REVIEW_MODE_ONLY_NOT_CONTENT_STALENESS')

    def test_declared_fingerprint_comparison_requires_three_explicit_optins(self):
        self.make_snapshot(content=(b'# Component\n<!-- CES-SOURCE source_key=r1 source_sha256='
            + sha(b'old version').encode() + b' -->\n'))
        self.rebind()
        self.cp['permit_reference_digest_comparison']=True
        self.assertEqual(self.call()['reason_code'],
                         'KNOWLEDGE_CHAPTERS_CHAPTER_FINGERPRINT_COMPARISON_ESCALATION')
        self.tp['permit_source_digest_projection']=True
        self.ip=self.upstream.impact_policy()
        self.ip['permit_change_digest_projection']=True
        self.rebind_from_mutated_upstream()
        self.cp['permit_reference_digest_comparison']=True
        s=self.success()
        assoc=s['chapter_documents'][0]['sections'][0]['associations'][0]
        self.assertEqual(assoc['documented_fingerprint_state'],
                         'DOCUMENTED_FINGERPRINT_DIFFERS_FROM_TARGET')
        self.assertEqual(assoc['review_state'],'REVIEW_DOCUMENTED_FINGERPRINT_DIFFERS')
        self.assertNotIn(sha(b'old version'),canonical(s))

    def rebind_from_mutated_upstream(self):
        self.upstream.tp=self.tp
        projection=self.ip.get('permit_change_digest_projection',False)
        self.upstream.ip=self.upstream.impact_policy()
        self.upstream.ip['permit_change_digest_projection']=projection
        self.ip=self.upstream.ip
        self.api=self.factory()
        self.cp=self.chapter_policy()

    def test_documented_target_fingerprint_match_is_not_semantic_truth(self):
        self.make_snapshot(content=(b'# Component\n<!-- CES-SOURCE source_key=r1 source_sha256='
            + sha(self.upstream.fx.content).encode() + b' -->\n'))
        self.rebind()
        self.tp['permit_source_digest_projection']=True
        self.rebind_from_mutated_upstream()
        self.ip['permit_change_digest_projection']=True
        self.rebind_from_mutated_upstream()
        self.cp['permit_reference_digest_comparison']=True
        s=self.success()
        assoc=s['chapter_documents'][0]['sections'][0]['associations'][0]
        self.assertEqual(assoc['documented_fingerprint_state'],
                         'DOCUMENTED_FINGERPRINT_MATCHES_TARGET')
        self.assertFalse(assoc['semantic_dependency_or_staleness_verified'])
        self.assertFalse(assoc['manual_review_candidate'])

    def test_conflicting_documented_fingerprints_are_explicitly_flagged(self):
        self.make_snapshot(content=(b'# Component\n<!-- CES-SOURCE source_key=r1 source_sha256='
            + b'a'*64 + b' -->\n<!-- CES-SOURCE source_key=r1 source_sha256='
            + b'b'*64 + b' -->\n'))
        self.rebind()
        s=self.success()
        assoc=s['chapter_documents'][0]['sections'][0]['associations'][0]
        self.assertEqual(assoc['review_state'],'REVIEW_CONFLICTING_DOCUMENTED_FINGERPRINTS')

    def test_tampered_local_knowledge_mismatches_manifest_fail_closed(self):
        self.upstream.fx.put(self.upstream.fx.knowledge, 'arch/components.md', b'# Replaced\n')
        s=self.success()
        self.assertEqual(s['summary']['sections_with_explicit_selected_source_links'],0)
        self.assertEqual(s['chapter_documents'][0]['mapping_state'],
                         'UNKNOWN_MANIFEST_OR_KNOWLEDGE_BYTES')

    def test_missing_manifest_not_mapped(self):
        (self.upstream.fx.knowledge/'ces-snapshot.v1.json').unlink()
        s=self.success()
        self.assertEqual(s['summary']['knowledge_documents_unknown'],1)
        self.assertFalse(s['chapter_documents'][0]['sections'])

    def test_invalid_utf8_fails_closed_and_other_sources_not_exposed(self):
        self.make_snapshot(content=b'\xff\xfe bad\n')
        self.rebind()
        s=self.success()
        self.assertEqual(s['chapter_documents'][0]['mapping_state'],
                         'UNKNOWN_UNPARSABLE_OR_UNBOUNDED_MARKDOWN')

    def test_knowledge_doc_without_mapping_permission_not_read(self):
        self.cp['source_grants'][0]['permit_section_mapping']=False
        self.cp['source_grants'][0]['read_receipt_sha256']=None
        s=self.success()
        self.assertEqual(s['chapter_documents'][0]['mapping_state'],'DENIED_NOT_MAPPED')
        self.assertIsNone(s['chapter_documents'][0]['section_count'])

    def test_upstream_content_grant_cannot_be_escalated(self):
        self.bp['source_grants'][0]['permit_content_projection']=False
        self.assertNotEqual(self.call()['status'],'partial')
        self.bp['source_grants'][0]['permit_content_projection']=True
        self.bp['permit_content_projection']=False
        self.assertNotEqual(self.call()['status'],'partial')

    def test_title_and_section_digest_projection_restricted(self):
        self.cp['permit_section_title_projection']=False
        self.cp['permit_section_digest_projection']=False
        s=self.success()
        section=s['chapter_documents'][0]['sections'][0]
        self.assertIsNone(section['heading'])
        self.assertIsNone(section['section_sha256'])
        self.cp['permit_section_digest_projection']=True
        s=self.success()
        self.assertEqual(len(s['chapter_documents'][0]['sections'][0]['section_sha256']),64)
        self.bp['permit_provenance_projection']=False
        self.assertNotEqual(self.call()['status'],'partial')

    def test_chapter_policy_mismatch_and_write_escalation_blocked(self):
        self.cp['permit_knowledge_write']=True
        out=self.call()
        self.assertEqual(out['reason_code'],'KNOWLEDGE_CHAPTERS_CHAPTER_WRITE_INTENT_FORBIDDEN')
        self.cp['permit_knowledge_write']=False
        self.cp['baseline_statement_binding_sha256']='f'*64
        self.assertEqual(self.call()['reason_code'],
                         'KNOWLEDGE_CHAPTERS_CHAPTER_POLICY_BINDING_MISMATCH')

    def test_out_of_scope_repo_marker_cannot_authorize_a_new_source(self):
        self.make_snapshot(content=(b'# Component\n'
            b'<!-- CES-SOURCE source_key=r1 -->\n'
            b'<!-- CES-SOURCE source_key=r2 -->\n'))
        self.rebind()
        s=self.success()
        self.assertEqual(s['summary']['sections_with_explicit_selected_source_links'],1)
        self.assertEqual(s['summary']['unresolved_explicit_refs'],1)

    def test_unsigned_target_changes_all_reviews_to_unknown(self):
        s=self.success(self.call(target_sig=None))
        assoc=s['chapter_documents'][0]['sections'][0]['associations'][0]
        self.assertEqual(assoc['selected_git_change_kind'],'UNKNOWN')
        self.assertEqual(assoc['review_state'],'UNKNOWN_SELECTED_SOURCE_EVIDENCE')

    def test_invalid_baseline_signature_never_claims_a_confirmed_change(self):
        s=self.success(self.call(base_sig=base64.b64encode(b'0'*64).decode()))
        self.assertEqual(s['chapter_documents'][0]['sections'][0]['associations'][0]
                         ['selected_git_change_kind'],'UNKNOWN')

    def test_selected_repo_worktree_drift_prevents_confirmed_source_changes(self):
        self.upstream.fx.put(self.upstream.fx.repo, 'src/component.md', b'uncommitted now')
        s=self.success()
        self.assertEqual(s['chapter_documents'][0]['sections'][0]['associations'][0]
                         ['selected_git_change_kind'],'UNKNOWN')

    def test_snapshot_changes_during_mapping_are_no_longer_mapped(self):
        original=self.api.impact.analyze
        def mutate_after_ec204(**kw):
            ans=original(**kw)
            self.upstream.fx.put(self.upstream.fx.knowledge, 'arch/components.md',
                                 b'# Lost during read\n')
            return ans
        with mock.patch.object(self.api.impact,'analyze',side_effect=mutate_after_ec204):
            s=self.success()
        self.assertFalse(s['knowledge_snapshot_stable_across_read'])
        self.assertEqual(s['chapter_documents'][0]['mapping_state'],
                         'UNKNOWN_SNAPSHOT_CHANGED_DURING_ANALYSIS')
        self.assertEqual(s['summary']['sections_with_explicit_selected_source_links'],0)

    def test_multiline_html_comment_cannot_create_phantom_chapter_link(self):
        self.make_snapshot(content=(b'# Main\n<!--\n'
            b'[phantom](src/component.md)\n## Phantom header\n-->'
            b'\nActual note.\n'))
        self.rebind()
        s=self.success()
        self.assertEqual(s['summary']['sections_with_explicit_selected_source_links'],0)
        self.assertEqual(s['summary']['visible_selected_sections'],1)

    def test_target_ref_change_after_verified_impact_downgrades_mapping(self):
        original=self.api.impact.analyze
        def commit_after_impact(**kw):
            ans=original(**kw)
            self.upstream.fx.put(self.upstream.fx.repo,'separate.md',b'later change')
            self.upstream.fx.commit('move main during chapter read')
            return ans
        with mock.patch.object(self.api.impact,'analyze',side_effect=commit_after_impact):
            s=self.success()
        self.assertEqual(s['target_ref_post_chapter_read_state'],
                         'UNKNOWN_POST_READ_REF_OR_ROOT_DRIFT')
        assoc=s['chapter_documents'][0]['sections'][0]['associations'][0]
        self.assertEqual(assoc['selected_git_change_kind'],'UNKNOWN')
        self.assertIn('UNKNOWN_POST_READ_REF_OR_ROOT_DRIFT',s['uncertainty_reasons'])

    def test_non_markdown_knowledge_file_not_mistaken_for_chapters(self):
        self.upstream.fx.put(self.upstream.fx.knowledge, 'arch/data.json', self.doc)
        manifest = json.loads(self.manifest)
        manifest['entries'] = [{'relative_path':'arch/data.json',
            'sha256':sha(self.doc),'size_bytes':len(self.doc)}]
        self.manifest = canonical(manifest).encode('utf-8')
        self.upstream.fx.put(self.upstream.fx.knowledge,'ces-snapshot.v1.json',self.manifest)
        self.rebind()
        self.r['sources'][0]['relative_path']='arch/data.json'
        self.bp = bootstrap_policy(self.upstream.api.target.bootstrap,
                                    self.r, provenance=True, content=True)
        _,_,self.tp,self.target_doc = self.upstream.fx.binding(original=self.r)
        self.tp['bootstrap_read_policy_binding_sha256']=digest(
            'CES-EC202-READ-POLICY-v1',self.bp)
        self.upstream.r,self.upstream.bp,self.upstream.tp,self.upstream.target_doc = (
            self.r,self.bp,self.tp,self.target_doc)
        self.upstream.ip=self.upstream.impact_policy()
        self.ip=self.upstream.ip
        self.upstream.baseline_doc=self.upstream.baseline_statement()
        self.baseline_doc=self.upstream.baseline_doc
        self.cp=self.chapter_policy()
        s=self.success()
        self.assertEqual(s['chapter_documents'][0]['mapping_state'],
                         'UNKNOWN_UNSUPPORTED_CHAPTER_FORMAT')

    def test_no_heading_document_is_a_bounded_preamble_section(self):
        self.make_snapshot(content=b'<!-- CES-SOURCE source_key=r1 -->\nA note\n')
        self.rebind()
        s=self.success()
        section=s['chapter_documents'][0]['sections'][0]
        self.assertEqual(section['ordinal'],0)
        self.assertEqual(section['heading_level'],0)
        self.assertIsNone(section['heading'])

    def test_too_many_sections_produces_unknown_not_partial_mapping(self):
        self.make_snapshot(content=(b'# Title\n<!-- CES-SOURCE source_key=r1 -->\n' +
                                    b''.join(b'## Part\n' for i in range(65))))
        self.rebind()
        s=self.success()
        self.assertEqual(s['chapter_documents'][0]['mapping_state'],
                         'UNKNOWN_UNPARSABLE_OR_UNBOUNDED_MARKDOWN')
        self.assertEqual(s['summary']['sections_with_explicit_selected_source_links'],0)

    def test_full_read_identity_and_source_binding_protection(self):
        self.r['sources'][1]['relative_path']='secret.md'
        self.assertNotEqual(self.call()['status'],'partial')

    @unittest.skipIf(Draft202012Validator is None,'jsonschema required')
    def test_strict_json_schemas_validate_read_policy_preview_and_results(self):
        for name in ('knowledge-chapter-read-policy.v1.schema.json',
                     'knowledge-chapters-result.v1.schema.json'):
            Draft202012Validator.check_schema(json.loads((SCHEMAS/name).read_text()))
        v=lambda name: Draft202012Validator(json.loads((SCHEMAS/name).read_text()))
        v('knowledge-chapter-read-policy.v1.schema.json').validate(self.cp)
        result=self.call()
        v('knowledge-chapters-result.v1.schema.json').validate(result)
        result=self.call(target_sig=None)
        v('knowledge-chapters-result.v1.schema.json').validate(result)
        result=self.api.binding_preview(request_json=canonical(self.r),
            bootstrap_read_policy_json=canonical(self.bp),
            target_read_policy_json=canonical(self.tp),
            impact_read_policy_json=canonical(self.ip),
            target_statement_json=canonical(self.target_doc),
            baseline_statement_json=canonical(self.baseline_doc))
        v('knowledge-chapters-result.v1.schema.json').validate(result)


if __name__ == '__main__':
    unittest.main()
