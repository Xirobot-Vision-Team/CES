#!/usr/bin/env python3
"""EC210 focused local integration: existing EC202 and EC206-209 real stores."""
from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path

from knowledge_boundary import canonical
from knowledge_bootstrap import KnowledgeBootstrap
from knowledge_chapters import _sections
from knowledge_lifecycle import (KnowledgeLifecycle, QUERY_PURPOSE,
    QUERY_SCHEMA, QUERY_POLICY_SCHEMA, EVIDENCE_SCHEMA, ADMISSION_PURPOSE,
    ADMISSION_SCHEMA)
from test_knowledge_bootstrap import request as bootstrap_req, source, policy as bootstrap_policy
import test_knowledge_version_save as fixture

H = 'a'*64
sha = fixture.digest


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixture.VersionSaveTests(
            'test_initialized_only_explicitly_and_no_source_modification')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.lifecycle = KnowledgeLifecycle(self.fx.api)
        self.bapi = KnowledgeBootstrap(
            repository_root=str(self.fx.hfx.fx.repo),
            knowledge_root=str(self.fx.hfx.fx.knowledge))
        self.req202 = bootstrap_req(
            source('k1', 'ces_knowledge', 'knowledge.md', self.fx.before),
            expected_manifest=sha(self.fx.manifest_file.read_bytes()))
        self.req202['scope']['period']['period_id'] = 'period01'
        self.pol202 = bootstrap_policy(self.bapi, self.req202, content=True, provenance=True)

    def request(self, *, view='source_snapshot', section_indices=None,
                projection='full_sections', search_terms=None, **changes):
        info = self.fx.api.inspect()['subject']
        selected = None if view == 'source_snapshot' else info['head_version_id']
        req = {
            'schema': QUERY_SCHEMA, 'operation': 'knowledge.lifecycle.query',
            'view': view, 'selected_version_id': selected,
            'expected_head_version_id': info['head_version_id'],
            'expected_chapter_sha256':
                sha(self.fx.before) if view == 'source_snapshot' else info['head_content_sha256'],
            'section_indices': [1] if section_indices is None else section_indices,
            'projection': projection, 'search_terms': [] if search_terms is None else search_terms}
        req.update(changes)
        return canonical(req)

    def policy(self, req, **changes):
        pv = self.lifecycle.query_binding_preview(query_request_json=req)
        self.assertEqual(pv['status'], 'partial', pv)
        bind = pv['subject']
        doc = {
            'schema': QUERY_POLICY_SCHEMA, 'purpose': QUERY_PURPOSE,
            'store_instance_id': bind['store_instance_id'],
            'store_scope_binding_sha256': bind['store_scope_binding_sha256'],
            'query_authorization_scope_sha256': bind['query_authorization_scope_sha256'],
            'permission_receipt_sha256': H,
            'permit_query_metadata': True,
            'permit_source_snapshot_text': True,
            'permit_private_version_text': True,
            'permit_restricted_private_version_text': True,
            'permit_term_search': True,
            'permit_full_section_return': True,
            'permit_source_knowledge_write': False,
            'permit_local_metadata_append': False,
            'permit_business_repository_write': False,
            'permit_issue_or_provider_write': False,
            'permit_docs_only_publish': False,
            'permit_publish': False}
        doc.update(changes)
        return canonical(doc)

    def source_read(self, req=None, policy=None, **kw):
        req = req or self.request()
        return self.lifecycle.query(query_request_json=req,
            query_policy_json=policy or self.policy(req),
            bootstrap_request_json=canonical(self.req202),
            bootstrap_read_policy_json=canonical(self.pol202),
            **kw)

    def version_access(self, save_receipt):
        return canonical({
            'schema': EVIDENCE_SCHEMA,
            'versions': [{'version_id': save_receipt['subject']['version_id'], **self.fx.args}]})

    def test_source_full_exact_section_requires_two_separate_grants(self):
        req = self.request()
        out = self.source_read(req)
        self.assertEqual(out['status'], 'partial', out)
        self.assertEqual(base64.b64decode(out['subject']['selected_sections'][0][
            'section_content_base64']), self.fx.before[
                self.fx.original_section['start']:self.fx.original_section['end']])
        self.assertFalse(out['docs_only_publish_invoked'])
        self.assertFalse(out['published'])
        self.assertFalse(out['source_knowledge_file_written'])
        self.assertFalse(out['local_version_metadata_written'])
        self.assertEqual(self.fx.src.read_bytes(), self.fx.before)

    def test_hashes_only_are_not_text_or_search(self):
        req = self.request(projection='hashes_only')
        pv = self.lifecycle.query_binding_preview(query_request_json=req)
        self.assertNotIn('Old API behavior', json.dumps(pv))
        result = self.lifecycle.query(query_request_json=req,
                                      query_policy_json=self.policy(req))
        self.assertEqual(result['status'], 'partial', result)
        self.assertNotIn('section_content_base64', json.dumps(result))
        self.assertNotIn('matching_lines', json.dumps(result))
        self.assertEqual(result['subject']['selected_sections'][0]['section_sha256'],
                         self.fx.original_section['sha256'])

    def test_term_snippets_are_bounded_inside_selected_sections(self):
        req = self.request(projection='match_snippets', search_terms=['behavior'])
        out = self.source_read(req)
        self.assertEqual(out['status'], 'partial', out)
        hit = out['subject']['selected_sections'][0]['matching_lines']
        self.assertEqual(len(hit), 1)
        self.assertIn('Old API behavior', hit[0]['excerpt'])
        self.assertNotIn('Original background', json.dumps(out))

    def test_missing_source_and_ec202_content_permissions_denied(self):
        req = self.request()
        p = self.policy(req)
        out = self.lifecycle.query(query_request_json=req, query_policy_json=p)
        self.assertIn('EC202_CONTENT_PERMISSION_REQUIRED', out['reason_code'])
        p2 = bootstrap_policy(self.bapi, self.req202, content=False)
        out = self.lifecycle.query(query_request_json=req, query_policy_json=p,
            bootstrap_request_json=canonical(self.req202),
            bootstrap_read_policy_json=canonical(p2))
        self.assertNotEqual(out['status'], 'partial', out)
        self.assertIsNone(out['subject'])

    def test_untrusted_query_grant_and_forbidden_publish_fail_closed(self):
        req = self.request()
        for updates in (
            {'permit_query_metadata': False},
            {'permit_source_snapshot_text': False},
            {'permit_docs_only_publish': True},
            {'permit_publish': True},
            {'permit_local_metadata_append': True},
            {'query_authorization_scope_sha256': H},
            {'permission_receipt_sha256': 'not-sha'},
            {'permit_private_version_text': 1},
        ):
            out = self.source_read(req, policy=self.policy(req, **updates))
            self.assertNotEqual(out['status'], 'partial', (updates, out))
            self.assertIsNone(out['subject'])
        self.assertEqual(self.fx.api.inspect()['subject']['version_count'],0)

    def test_invalid_selection_projection_and_version_pins_denied(self):
        cases = [
            {'section_indices':[1,1]}, {'section_indices':[-1]},
            {'section_indices':[99]}, {'view':'local_metadata_version'},
            {'expected_chapter_sha256':H},
            {'expected_head_version_id':H},
            {'search_terms':['x'], 'projection':'full_sections'},
            {'search_terms':[], 'projection':'match_snippets'},
            {'projection':'unbounded'},
        ]
        for updates in cases:
            out = self.lifecycle.query_binding_preview(
                query_request_json=self.request(**updates))
            self.assertNotEqual(out['status'],'partial', (updates,out))

    def test_private_version_full_text_requires_ec207_ec206_replay(self):
        version = self.fx.save()
        req = self.request(view='local_metadata_version')
        denied = self.source_read(req)
        self.assertIn('VERSION_EVIDENCE_BUNDLE_REQUIRED', denied['reason_code'])
        out = self.source_read(req, version_evidence_json=self.version_access(version))
        self.assertEqual(out['status'],'partial',out)
        content = base64.b64decode(out['subject']['selected_sections'][0]['section_content_base64'])
        self.assertEqual(content, self.fx.first_section)
        self.assertTrue(out['subject']['private_versions_not_authoritative_or_published'])
        self.assertEqual(self.fx.src.read_bytes(),self.fx.before)

    def test_private_version_restricted_projection_separate_grant(self):
        version = self.fx.save()
        req = self.request(view='local_metadata_version')
        p = self.policy(req, permit_restricted_private_version_text=False)
        out = self.source_read(req, policy=p,
                               version_evidence_json=self.version_access(version))
        self.assertIn('PRIVATE_METADATA_TEXT_AND_RESTRICTED_GRANTS_REQUIRED',out['reason_code'])

    def test_private_version_corrupt_or_wrong_evidence_bundle_denied(self):
        version = self.fx.save()
        req = self.request(view='local_metadata_version')
        good = json.loads(self.version_access(version))
        for altered in (
            {'versions':[]},
            {'versions':[{**good['versions'][0],'version_id':H}]},
            {'versions':[{
                **good['versions'][0], 'handoff_policy_json':'{}'}]},
        ):
            bad = {**good, **altered}
            out = self.source_read(req, version_evidence_json=canonical(bad))
            self.assertNotEqual(out['status'],'partial',out)
            self.assertIsNone(out['subject'])

    def test_unmodified_section_in_private_head_needs_only_ec202_and_ec210(self):
        self.fx.save()
        req = self.request(view='local_metadata_version',section_indices=[0])
        out = self.source_read(req)
        self.assertEqual(out['status'],'partial',out)
        section=base64.b64decode(out['subject']['selected_sections'][0]['section_content_base64'])
        self.assertIn(b'Original background.',section)
        self.assertEqual(out['subject']['contributing_version_ids'],[])

    def test_head_pinning_detects_concurrent_revision(self):
        req = self.request()
        p = self.policy(req)
        self.fx.save()
        out = self.source_read(req, policy=p)
        self.assertIn('QUERY_HEAD_CHANGED',out['reason_code'])
        self.assertIsNone(out['subject'])

    def test_original_source_drift_denied_even_for_private_metadata_query(self):
        req = self.request(projection='hashes_only')
        self.fx.src.write_bytes(b'# changed\n')
        out = self.lifecycle.query_binding_preview(query_request_json=req)
        self.assertNotEqual(out['status'],'partial')
        self.assertIsNone(out['subject'])

    def test_conflict_delegation_is_read_only_and_no_implicit_retry(self):
        ret = self.lifecycle.assess_conflict(save_request_json=self.fx.req,
                                            handoff_inputs=self.fx.args)
        self.assertEqual(ret['status'],'partial',ret)
        self.assertEqual(ret['subject']['state'],'CURRENT_PARENT_VALID_NO_RETRY_NEEDED')
        denied=self.lifecycle.prepare_retry(save_request_json=self.fx.req,
            handoff_inputs=self.fx.args,ec209_retry_intent_json='{}',
            ec209_retry_policy_json='{}')
        self.assertNotEqual(denied['status'],'partial')
        self.assertEqual(self.fx.api.inspect()['subject']['version_count'],0)

    def test_no_ec205_mapper_means_save_chain_cannot_append(self):
        pre=self.lifecycle.prepare_update(source_inputs={}, handoff_inputs=self.fx.args,
                                          save_request_json=self.fx.req)
        self.assertNotEqual(pre['status'],'partial',pre)
        out=self.lifecycle.save_reviewed(source_inputs={},handoff_inputs=self.fx.args,
            save_request_json=self.fx.req,lifecycle_save_admission_json='{}',
            ec208_save_policy_json='{}',ec208_approvals_json='{}')
        self.assertNotEqual(out['status'],'partial')
        self.assertEqual(self.fx.api.inspect()['subject']['version_count'],0)
        self.assertFalse(out['docs_only_publish_invoked'])


if __name__ == '__main__':
    unittest.main()


# This second fixture exercises the REAL EC205 Git + signed EC203/204 map,
# EC206 private append, EC207 grants and EC208 dual-signed immutable save.
import tempfile
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from knowledge_boundary import digest as scoped_digest
from knowledge_candidate_store import KnowledgeCandidateStore
from knowledge_update_handoff import KnowledgeUpdateHandoff
from knowledge_version_save import KnowledgeVersionSave, ROLES, SIGNED_DOMAIN
import test_knowledge_chapters as map_fixture


@unittest.skipIf(map_fixture.impact_tests.Ed25519PrivateKey is None,
                 'real Git and Ed25519 development environment required')
class LifecycleRealSourceChainTests(unittest.TestCase):
    def setUp(self):
        self.mapfx = map_fixture.ChaptersTests(
            'test_actual_changed_git_bytes_maps_only_selected_chapter')
        self.mapfx.setUp()
        self.addCleanup(self.mapfx.doCleanups)
        self.folder = Path(self.mapfx.upstream.fx.temp.name)
        self.candidate_root = self.folder/'private_candidates'
        self.version_root = self.folder/'private_versions'
        self.candidate_root.mkdir(mode=0o700)
        self.version_root.mkdir(mode=0o700)
        self.candidate = KnowledgeCandidateStore(
            root=str(self.candidate_root), store_id='candidate_suite',
            repository_root=str(self.mapfx.upstream.fx.repo),
            knowledge_root=str(self.mapfx.upstream.fx.knowledge),
            repository_ref=self.mapfx.r['scope']['repository_ref'],
            knowledge_space_key='architecture', period_id='oct-2026',
            source_policy_revision='policy-v1')
        init = self.candidate.initialize(allow_initialize=True)
        self.assertEqual(init['status'],'partial',init)
        self.candidate_init = init['subject']
        self.private_keys={role:Ed25519PrivateKey.generate() for role in ROLES}
        self.trusted={('reviewer01' if role=='independent_reviewer' else 'owner01'):
            {'role':role,'public_key':key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)}
            for role,key in self.private_keys.items()}
        self.version_api=KnowledgeVersionSave(root=str(self.version_root),
            store_id='version_suite', candidate_store=self.candidate,
            chapter_path='arch/components.md',trusted_approvers=self.trusted)
        self.assertEqual(self.version_api.initialize(allow_initialize=True)['status'],'partial')
        self.chain=KnowledgeLifecycle(self.version_api,self.mapfx.api)
        self.source_inputs={
            'request_json':canonical(self.mapfx.r),
            'bootstrap_read_policy_json':canonical(self.mapfx.bp),
            'target_read_policy_json':canonical(self.mapfx.tp),
            'impact_read_policy_json':canonical(self.mapfx.ip),
            'chapter_read_policy_json':canonical(self.mapfx.cp),
            'target_statement_json':canonical(self.mapfx.target_doc),
            'target_signature_base64':self.mapfx.upstream.fx.sign(self.mapfx.target_doc),
            'baseline_statement_json':canonical(self.mapfx.baseline_doc),
            'baseline_signature_base64':self.mapfx.upstream.sign_base(),
        }
        actual=self.mapfx.call()
        self.assertEqual(actual['status'],'partial',actual)
        self.mapped=actual['subject']
        self.section=self.mapped['chapter_documents'][0]['sections'][0]
        self.raw_source=(self.mapfx.upstream.fx.knowledge/'arch/components.md').read_bytes()

    def candidate_proposal(self):
        subject=self.mapped
        return canonical({
            'schema':'ces.knowledge_candidate_proposal.v1',
            'candidate_key':'repo_change_one', 'repository_ref':subject['repository_ref'],
            'knowledge_space_key':subject['knowledge_space_key'],
            'source_policy_revision':'policy-v1','period_id':subject['period_id'],
            'request_binding_sha256':subject['request_binding_sha256'],
            'scope_binding_sha256':subject['scope_binding_sha256'],
            'origin':'ec205_chapter_mapping',
            'source_key':'r1','section_ref':self.section['section_ref'],
            'claim_text':'Source component change may require chapter review',
            'reason_text':'EC204 selected change requires human review',
            'sensitivity':'INTERNAL','proposer_key':'test_author',
            'proposed_at_utc':'2026-10-20T00:00:00Z'})

    def append_and_handoff(self):
        proposal=self.candidate_proposal()
        observed=self.chain.preview_candidate_intake(
            source_inputs=self.source_inputs,proposal_json=proposal)
        self.assertEqual(observed['status'],'partial',observed)
        p=observed['subject']
        append_policy=canonical({
            'schema':'ces.knowledge_candidate_append_policy.v1',
            'purpose':'append_private_candidate_only',
            'store_instance_id':p['store_instance_id'],
            'store_scope_binding_sha256':p['store_scope_binding_sha256'],
            'candidate_binding_sha256':p['candidate_binding_sha256'],
            'authorization_scope_sha256':p['append_authorization_scope_sha256'],
            'permission_receipt_sha256':H,
            'permit_candidate_append':True,'permit_private_claim_store':True,
            'permit_restricted_claim_store':False,
            'permit_upstream_result_intake':True,
            'permit_manual_proposal_intake':False,
            'permit_repository_write':False,
            'permit_authoritative_knowledge_write':False,
            'permit_issue_write':False,'permit_publish':False})
        wrote=self.chain.append_candidate(
            source_inputs=self.source_inputs,proposal_json=proposal,
            append_policy_json=append_policy)
        self.assertEqual(wrote['status'],'partial',wrote)
        self.assertTrue(wrote['candidate_metadata_written'])
        hreq=canonical({
            'schema':'ces.knowledge_update_handoff_request.v1',
            'task_kind':'knowledge_update','handoff_key':'real_git_review',
            'repository_ref':self.mapfx.r['scope']['repository_ref'],
            'knowledge_space_key':'architecture','period_id':'oct-2026',
            'source_policy_revision':'policy-v1',
            'candidate_keys':['repo_change_one']})
        handoff=KnowledgeUpdateHandoff(self.candidate)
        pv=handoff.binding_preview(request_json=hreq)
        self.assertEqual(pv['status'],'partial',pv)
        s=pv['subject']
        hpolicy=canonical({
            'schema':'ces.knowledge_update_handoff_policy.v1',
            'purpose':'prepare_local_knowledge_update_draft_only',
            'store_instance_id':s['store_instance_id'],
            'store_scope_binding_sha256':s['store_scope_binding_sha256'],
            'selection_binding_sha256':s['selection_binding_sha256'],
            'authorization_scope_sha256':s['handoff_authorization_scope_sha256'],
            'permission_receipt_sha256':H,
            'permit_handoff_draft_prepare':True,
            'permit_selected_candidate_provenance_read':True,
            'permit_selected_candidate_text_read':True,
            'permit_restricted_local_draft':False,
            'permit_multi_candidate_draft':False,
            'permit_external_ai_transfer':False,'permit_ai_execution':False,
            'permit_knowledge_save':False,
            'permit_authoritative_knowledge_write':False,
            'permit_repository_or_issue_write':False,'permit_publish':False})
        cp=s['candidate_record_pins'][0]
        read=canonical({
            'schema':'ces.knowledge_update_handoff_candidate_reads.v1',
            'candidate_read_policies':{
                'repo_change_one':{
                    'schema':'ces.knowledge_candidate_read_policy.v1',
                    'purpose':'read_private_candidate_only',
                    'store_instance_id':s['store_instance_id'],
                    'store_scope_binding_sha256':s['store_scope_binding_sha256'],
                    'candidate_key':'repo_change_one',
                    'candidate_binding_sha256':cp['candidate_binding_sha256'],
                    'authorization_scope_sha256':cp['read_authorization_scope_sha256'],
                    'permission_receipt_sha256':H,
                    'permit_candidate_metadata_read':True,
                    'permit_provenance_read':True,
                    'permit_restricted_provenance_read':False,
                    'permit_claim_content_read':True,
                    'permit_restricted_claim_read':False,
                    'permit_repository_write':False,
                    'permit_authoritative_knowledge_write':False,
                    'permit_publish':False}}})
        inputs={'handoff_request_json':hreq,'handoff_policy_json':hpolicy,
                'candidate_read_policies_json':read}
        draft=handoff.prepare(request_json=hreq,handoff_policy_json=hpolicy,
                              candidate_read_policies_json=read)
        self.assertEqual(draft['status'],'partial',draft)
        old=_sections(self.raw_source)[1]
        replacement=(b'## Component\n<!-- CES-SOURCE source_key=r1 -->\n'
                     b'Reviewed explanation based on evidence, pending authority.\n\n')
        after=self.raw_source[:old['start']]+replacement+self.raw_source[old['end']:]
        src_key=next(s for s in self.mapfx.r['sources'] if s['kind']=='ces_knowledge')
        save_request=canonical({
            'schema':'ces.knowledge_save_request.v1',
            'operation':'knowledge.save.metadata_version',
            'save_key':'reviewed_component_update',
            'repository_ref':self.mapfx.r['scope']['repository_ref'],
            'knowledge_space_key':'architecture',
            'period_id':'oct-2026','source_policy_revision':'policy-v1',
            'chapter_path':'arch/components.md',
            'expected_snapshot_version':'checkpoint-v1',
            'expected_manifest_sha256':sha(self.mapfx.manifest),
            'expected_baseline_chapter_sha256':sha(self.raw_source),
            'expected_parent_version_id':None,
            'expected_parent_content_sha256':sha(self.raw_source),
            'section_index':1,'expected_section_sha256':old['sha256'],
            'section_ref':self.section['section_ref'],
            'ec202_knowledge_source_binding_sha256':
                scoped_digest('CES-EC202-SOURCE-v1',src_key),
            'save_permission_receipt_sha256':H,
            'replacement_section_base64':base64.b64encode(replacement).decode('ascii'),
            'replacement_section_sha256':sha(replacement),
            'expected_new_chapter_sha256':sha(after),
            'selection_binding_sha256':draft['subject']['selection_binding_sha256'],
            'ai_input_sha256':draft['subject']['ai_input_sha256'],
            'candidate_keys':['repo_change_one'],
            'candidate_record_ids':[draft['subject']['ai_input']['candidate_evidence'][0]['record_id']],
            'review_summary':'Independent review of exact changed source and chapter update.'})
        return inputs, save_request, wrote

    def approvals(self, scope):
        now=datetime.now(timezone.utc).replace(microsecond=0)
        statements=[]
        for role in ROLES:
            kid='reviewer01' if role=='independent_reviewer' else 'owner01'
            document={'schema':'ces.knowledge_save_approval_statement.v1',
                'purpose':'approve_exact_local_ces_knowledge_metadata_version',
                'signer_key_id':kid,'role':role,'authorization_scope_sha256':scope,
                'review_state':'REVIEWED_APPROVED_FOR_THIS_VERSION_ONLY',
                'issued_at_utc':now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'expires_at_utc':(now+timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ')}
            signed=self.private_keys[role].sign(
                SIGNED_DOMAIN+canonical(document).encode('ascii'))
            statements.append({'statement':document,
                'signature_base64':base64.b64encode(signed).decode('ascii')})
        return canonical({'schema':'ces.knowledge_save_approvals.v1',
                          'statements':statements})

    def save_args(self, handoff_inputs, save_request):
        pv=self.version_api.preview(request_json=save_request,**handoff_inputs)
        self.assertEqual(pv['status'],'partial',pv)
        s=pv['subject']
        return {
            'ec208_save_policy_json':canonical({
                'schema':'ces.knowledge_save_policy.v1',
                'purpose':'append_immutable_local_ces_knowledge_metadata_only',
                'store_instance_id':s['store_instance_id'],
                'store_scope_binding_sha256':s['store_scope_binding_sha256'],
                'authorization_scope_sha256':s['authorization_scope_sha256'],
                'permission_receipt_sha256':H,
                'permit_local_version_append':True,
                'permit_reviewed_text_local_persistence':True,
                'permit_restricted_local_persistence':False,
                'permit_source_knowledge_overwrite':False,
                'permit_business_repository_write':False,
                'permit_issue_or_provider_write':False,
                'permit_publish':False}),
            'ec208_approvals_json':self.approvals(s['authorization_scope_sha256'])}

    def admission(self, pre, **changes):
        pin=pre['subject']
        doc={
            'schema':ADMISSION_SCHEMA,'purpose':ADMISSION_PURPOSE,
            'store_instance_id':pin['ec208_store_instance_id'],
            'store_scope_binding_sha256':pin['ec208_store_scope_binding_sha256'],
            'workflow_authorization_scope_sha256':pin['workflow_authorization_scope_sha256'],
            'permission_receipt_sha256':H,
            'permit_evidence_bound_save_dispatch':True,
            'permit_local_metadata_append_dispatch':True,
            'permit_candidate_store_write':False,
            'permit_source_knowledge_overwrite':False,
            'permit_business_repository_write':False,
            'permit_issue_or_provider_write':False,
            'permit_docs_only_publish':False,'permit_publish':False}
        doc.update(changes)
        return canonical(doc)

    def test_real_git_to_candidate_to_handoff_to_dual_signed_metadata_save(self):
        inputs,req,wrote=self.append_and_handoff()
        pre=self.chain.prepare_update(
            source_inputs=self.source_inputs,handoff_inputs=inputs,
            save_request_json=req)
        self.assertEqual(pre['status'],'partial',pre)
        self.assertFalse(pre['subject']['knowledge_source_write_authorized'])
        result=self.chain.save_reviewed(
            source_inputs=self.source_inputs,handoff_inputs=inputs,
            save_request_json=req,lifecycle_save_admission_json=self.admission(pre),
            **self.save_args(inputs,req))
        self.assertEqual(result['status'],'partial',result)
        self.assertTrue(result['local_version_metadata_written'])
        self.assertEqual(self.version_api.inspect()['subject']['version_count'],1)
        self.assertEqual((self.mapfx.upstream.fx.knowledge/'arch/components.md').read_bytes(),
                         self.raw_source)
        self.assertEqual(self.mapfx.upstream.fx.cmd('status','--porcelain'),'')
        self.assertFalse(result['docs_only_publish_invoked'])
        self.assertFalse(result['published'])
        self.assertFalse(result['organizational_authority_authenticated'])

    def test_independent_ec210_dispatch_denies_publish_or_missing_grant(self):
        inputs,req,wrote=self.append_and_handoff()
        pre=self.chain.prepare_update(source_inputs=self.source_inputs,
            handoff_inputs=inputs,save_request_json=req)
        self.assertEqual(pre['status'],'partial',pre)
        args=self.save_args(inputs,req)
        for changes in ({'permit_docs_only_publish':True},
                        {'permit_publish':True},
                        {'permit_evidence_bound_save_dispatch':False},
                        {'workflow_authorization_scope_sha256':H}):
            denied=self.chain.save_reviewed(source_inputs=self.source_inputs,
                handoff_inputs=inputs,save_request_json=req,
                lifecycle_save_admission_json=self.admission(pre,**changes),**args)
            self.assertNotEqual(denied['status'],'partial',denied)
            self.assertFalse(denied['local_version_metadata_written'])
        self.assertEqual(self.version_api.inspect()['subject']['version_count'],0)


    def test_real_candidate_intake_grant_can_never_publish(self):
        proposal=self.candidate_proposal()
        pv=self.chain.preview_candidate_intake(
            source_inputs=self.source_inputs, proposal_json=proposal)
        self.assertEqual(pv['status'],'partial',pv)
        self.assertFalse(pv['candidate_metadata_written'])
        s=pv['subject']
        denial=canonical({
            'schema':'ces.knowledge_candidate_append_policy.v1',
            'purpose':'append_private_candidate_only',
            'store_instance_id':s['store_instance_id'],
            'store_scope_binding_sha256':s['store_scope_binding_sha256'],
            'candidate_binding_sha256':s['candidate_binding_sha256'],
            'authorization_scope_sha256':s['append_authorization_scope_sha256'],
            'permission_receipt_sha256':H,'permit_candidate_append':True,
            'permit_private_claim_store':True,'permit_restricted_claim_store':False,
            'permit_upstream_result_intake':True,'permit_manual_proposal_intake':False,
            'permit_repository_write':False,
            'permit_authoritative_knowledge_write':False,
            'permit_issue_write':False,'permit_publish':True})
        out=self.chain.append_candidate(source_inputs=self.source_inputs,
                proposal_json=proposal,append_policy_json=denial)
        self.assertNotEqual(out['status'],'partial',out)
        self.assertEqual(list((self.candidate_root/'records').iterdir()),[])
        self.assertFalse(out['published'])

    def test_actual_git_target_move_blocks_candidate_intake(self):
        proposal=self.candidate_proposal()
        self.mapfx.upstream.fx.put(self.mapfx.upstream.fx.repo,
                                  'src/component.md',b'# Unreviewed move\n')
        self.mapfx.upstream.fx.commit('unreviewed branch head changed')
        out=self.chain.preview_candidate_intake(
            source_inputs=self.source_inputs, proposal_json=proposal)
        self.assertNotEqual(out['status'],'partial',out)
        self.assertFalse(out['candidate_metadata_written'])

    def test_mapper_scope_and_external_result_not_accepted_as_authority(self):
        inputs,req,_=self.append_and_handoff()
        malformed={**self.source_inputs,'request_json':'{}'}
        denied=self.chain.prepare_update(source_inputs=malformed,
            handoff_inputs=inputs,save_request_json=req)
        self.assertNotEqual(denied['status'],'partial')
        self.assertEqual(self.version_api.inspect()['subject']['version_count'],0)
