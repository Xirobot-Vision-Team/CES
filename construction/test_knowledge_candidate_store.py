#!/usr/bin/env python3
"""EC206 private candidate storage: focused behavior and fail-closed boundaries.

Synthetic upstream JSON is deliberately *not* treated as authenticated. One
optional test consumes a real EC205 locally recomputed fixture, without claiming
production trust or native CES acceptance.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from knowledge_boundary import canonical
from knowledge_candidate_store import KnowledgeCandidateStore

H = 'a'*64
REPO = 'cesrepo1:'+'1'*64


class CandidateStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.repo, self.knowledge, self.root = (base/x for x in ('repo','knowledge','quarantine'))
        for path in (self.repo,self.knowledge,self.root):
            path.mkdir(mode=0o700)
        (self.repo/'source.txt').write_text('authoritative-code', encoding='utf-8')
        (self.knowledge/'knowledge.md').write_text('original-authoritative-knowledge', encoding='utf-8')
        self.kwargs = dict(root=str(self.root), store_id='knowledge_candidate',
            repository_root=str(self.repo), knowledge_root=str(self.knowledge),
            repository_ref=REPO, knowledge_space_key='architecture', period_id='period01',
            source_policy_revision='policy-v1')
        self.api = KnowledgeCandidateStore(**self.kwargs)
        initial = self.api.initialize(allow_initialize=True)
        self.assertEqual(initial['status'], 'partial', initial)
        self.instance = initial['subject']['store_instance_id']
        self.scope = initial['subject']['store_scope_binding_sha256']

    def proposal(self, **updates):
        doc = {'schema':'ces.knowledge_candidate_proposal.v1',
            'candidate_key':'claim_one', 'repository_ref':REPO,
            'knowledge_space_key':'architecture', 'source_policy_revision':'policy-v1',
            'period_id':'period01','request_binding_sha256':H,'scope_binding_sha256':H,
            'origin':'manual_proposal','source_key':'manual1','section_ref':None,
            'claim_text':'Unverified candidate content','reason_text':'Needs review',
            'sensitivity':'INTERNAL','proposer_key':'reviewer1',
            'proposed_at_utc':'2026-10-24T00:00:00Z'}
        doc.update(updates)
        return canonical(doc)

    def upstream(self, origin, **changes):
        subject={'repository_ref':REPO,'knowledge_space_key':'architecture',
            'period_id':'period01','request_binding_sha256':H,'scope_binding_sha256':H,
            'target_delivery_state':'SIGNED_DELIVERED_TARGET_OBSERVED_AT_REF',
            'verified_delivered_facts':[], 'no_write_actions_performed':True}
        if origin == 'ec205_chapter_mapping':
            subject['model_revision']='EC205_EXPLICIT_EXISTING_CHAPTER_LINKS_ONLY'
            subject['summary']={'knowledge_update_authorized':False}
            subject['chapter_documents']=[{'mapping_state':'SELECTED_SNAPSHOT_CHAPTERS_SCANNED',
               'sections':[{'section_ref':'cesksection1:'+('b'*64),
                 'associations':[{'source_key':'r1', 'manual_review_candidate':True,
                   'semantic_dependency_or_staleness_verified':False,
                   'selected_git_change_kind':'MODIFIED',
                   'selected_git_comparison_state':'GIT_SELECTED_PATH_BYTES_VERIFIED'}]}]}]
            schema='ces.knowledge_chapters.v1'
        else:
            subject['model_revision']='EC204_ATTESTED_SELECTED_GIT_CHANGE_SET_ONLY'
            subject['knowledge_sections_to_update']=[]
            subject['source_changes']=[{'source_key':'r1','kind':'repository',
                'comparison_state':'GIT_SELECTED_PATH_BYTES_VERIFIED',
                'change_kind':'MODIFIED'}]
            schema='ces.knowledge_impact.v1'
        subject.update(changes)
        return canonical({'schema':schema,'status':'partial','exit_code':2,
            'reason_code':'KNOWLEDGE_TEST_SUPPLIED_PARTIAL',
            'subject':subject,'canonical_json':canonical(subject),'limitations':{}})

    def candidate_preview(self, doc, evidence=None):
        preview=self.api.preview(proposal_json=doc, source_result_json=evidence)
        self.assertEqual(preview['status'],'partial', preview)
        return preview['subject']

    def append_policy(self, preview, **updates):
        doc = {'schema':'ces.knowledge_candidate_append_policy.v1',
            'purpose':'append_private_candidate_only',
            'store_instance_id':self.instance,
            'store_scope_binding_sha256':self.scope,
            'candidate_binding_sha256':preview['candidate_binding_sha256'],
            'authorization_scope_sha256':preview['append_authorization_scope_sha256'],
            'permission_receipt_sha256':H,'permit_candidate_append':True,
            'permit_private_claim_store':True,'permit_restricted_claim_store':False,
            'permit_upstream_result_intake':False,'permit_manual_proposal_intake':True,
            'permit_repository_write':False,'permit_authoritative_knowledge_write':False,
            'permit_issue_write':False,'permit_publish':False}
        doc.update(updates)
        return canonical(doc)

    def read_policy(self, preview, **updates):
        doc={'schema':'ces.knowledge_candidate_read_policy.v1',
            'purpose':'read_private_candidate_only',
            'store_instance_id':self.instance,'store_scope_binding_sha256':self.scope,
            'candidate_key':preview['candidate_key'],
            'candidate_binding_sha256':preview['candidate_binding_sha256'],
            'authorization_scope_sha256':preview['read_authorization_scope_sha256'],
            'permission_receipt_sha256':H, 'permit_candidate_metadata_read':True,
            'permit_provenance_read':False,'permit_restricted_provenance_read':False,
            'permit_claim_content_read':False,
            'permit_restricted_claim_read':False,'permit_repository_write':False,
            'permit_authoritative_knowledge_write':False,'permit_publish':False}
        doc.update(updates)
        return canonical(doc)

    def save(self, proposal=None, evidence=None, policy_updates=None):
        p=self.proposal() if proposal is None else proposal
        preview=self.candidate_preview(p,evidence)
        policy=self.append_policy(preview, **(policy_updates or {}))
        return self.api.append(proposal_json=p, append_policy_json=policy,
                               source_result_json=evidence), preview

    def test_initialize_no_auto_create_and_no_overwrite(self):
        self.assertEqual(self.api.initialize(allow_initialize=False)['status'],'unavailable')
        self.assertEqual(self.api.initialize(allow_initialize=True)['status'],'unavailable')
        self.assertFalse((self.root/'source.txt').exists())

    def test_preview_is_read_only_no_text_or_autogrant(self):
        preview = self.api.preview(proposal_json=self.proposal(claim_text='secret-key-material'))
        self.assertEqual(preview['status'],'partial')
        self.assertNotIn('secret-key-material',json.dumps(preview))
        self.assertEqual(len(list((self.root/'records').iterdir())),0)
        self.assertFalse(preview['authoritative_knowledge_write_performed'])

    def test_append_once_idempotent_and_authoritative_unmodified(self):
        before=((self.repo/'source.txt').read_bytes(),(self.knowledge/'knowledge.md').read_bytes())
        first, preview=self.save()
        self.assertEqual(first['status'],'partial',first)
        self.assertTrue(first['local_candidate_write_performed'])
        again=self.api.append(proposal_json=self.proposal(),append_policy_json=self.append_policy(preview))
        self.assertEqual(again['reason_code'],'KNOWLEDGE_CANDIDATE_ALREADY_PERSISTED_IDEMPOTENT_NO_WRITE')
        self.assertFalse(again['local_candidate_write_performed'])
        self.assertEqual(len(list((self.root/'records').iterdir())),1)
        self.assertEqual(before,((self.repo/'source.txt').read_bytes(),(self.knowledge/'knowledge.md').read_bytes()))

    def test_same_key_different_text_conflicts_no_silent_overwrite(self):
        first,_=self.save()
        other=self.proposal(claim_text='changed')
        second,preview=self.save(proposal=other)
        self.assertEqual(preview['state'],'IMMUTABLE_CANDIDATE_KEY_CONFLICT')
        self.assertEqual(second['reason_code'],'KNOWLEDGE_CANDIDATE_IMMUTABLE_CANDIDATE_KEY_CONFLICT')
        self.assertEqual(len(list((self.root/'records').iterdir())),1)

    def test_no_write_without_explicit_policy_and_no_escalation(self):
        doc=self.proposal()
        p=self.candidate_preview(doc)
        policy=self.append_policy(p,permit_candidate_append=False)
        self.assertEqual(self.api.append(proposal_json=doc,append_policy_json=policy)['status'],'unavailable')
        policy=self.append_policy(p,permit_authoritative_knowledge_write=True)
        self.assertEqual(self.api.append(proposal_json=doc,append_policy_json=policy)['status'],'unavailable')
        policy=self.append_policy(p,permit_publish=True)
        self.assertEqual(self.api.append(proposal_json=doc,append_policy_json=policy)['status'],'unavailable')
        policy=self.append_policy(p,permission_receipt_sha256=None)
        self.assertEqual(self.api.append(proposal_json=doc,append_policy_json=policy)['status'],'unavailable')
        self.assertEqual(len(list((self.root/'records').iterdir())),0)

    def test_restricted_intake_and_disclosure_gates(self):
        doc=self.proposal(sensitivity='RESTRICTED')
        preview=self.candidate_preview(doc)
        denied=self.api.append(proposal_json=doc,append_policy_json=self.append_policy(preview))
        self.assertEqual(denied['status'],'unavailable')
        allowed=self.api.append(proposal_json=doc,append_policy_json=self.append_policy(
            preview,permit_restricted_claim_store=True))
        self.assertEqual(allowed['status'],'partial',allowed)
        visible=self.api.read(candidate_key='claim_one',read_policy_json=self.read_policy(preview))
        self.assertEqual(visible['status'],'partial',visible)
        self.assertIsNone(visible['subject']['claim_text'])
        denied=self.api.read(candidate_key='claim_one',read_policy_json=self.read_policy(
            preview,permit_claim_content_read=True))
        self.assertEqual(denied['status'],'unavailable')
        with_body=self.api.read(candidate_key='claim_one',read_policy_json=self.read_policy(
            preview,permit_claim_content_read=True,permit_restricted_claim_read=True))
        self.assertEqual(with_body['subject']['claim_text'],'Unverified candidate content')
        self.assertIsNone(with_body['subject']['provenance'])
        denied_provenance=self.api.read(candidate_key='claim_one',read_policy_json=self.read_policy(
            preview,permit_provenance_read=True))
        self.assertEqual(denied_provenance['status'],'unavailable')
        with_provenance=self.api.read(candidate_key='claim_one',read_policy_json=self.read_policy(
            preview,permit_provenance_read=True,permit_restricted_provenance_read=True))
        self.assertEqual(with_provenance['subject']['provenance']['selection_kind'],
                         'MANUAL_UNVERIFIED_ASSERTION')
        self.assertIsNone(with_provenance['subject']['claim_text'])

    def test_read_policy_scoped_to_exact_candidate_bytes(self):
        first, preview=self.save()
        other=self.api.read(candidate_key='claim_one',read_policy_json=self.read_policy(
            preview,candidate_binding_sha256='b'*64))
        self.assertEqual(other['status'],'unavailable')
        other=self.api.read(candidate_key='claim_one',read_policy_json=self.read_policy(
            preview,permit_repository_write=True))
        self.assertEqual(other['status'],'unavailable')
        self.assertFalse(first['candidate_is_authoritative'])

    def test_list_requires_separate_permission_and_never_discloses_body(self):
        self.save()
        preview=self.api.list_binding_preview()['subject']
        policy={'schema':'ces.knowledge_candidate_list_policy.v1','purpose':'list_private_candidate_keys_only',
            'store_instance_id':self.instance,'store_scope_binding_sha256':self.scope,
            'authorization_scope_sha256':preview['authorization_scope_sha256'],
            'permission_receipt_sha256':H,'permit_candidate_keys_list':True,
            'permit_repository_write':False,'permit_authoritative_knowledge_write':False,
            'permit_publish':False}
        result=self.api.list_keys(list_policy_json=canonical(policy))
        self.assertEqual(result['subject']['candidate_keys'],['claim_one'])
        self.assertNotIn('Unverified candidate content',str(result))
        policy['permit_candidate_keys_list']=False
        self.assertEqual(self.api.list_keys(list_policy_json=canonical(policy))['status'],'unavailable')

    def test_ec205_explicit_section_requires_matching_selected_source(self):
        evidence=self.upstream('ec205_chapter_mapping')
        doc=self.proposal(origin='ec205_chapter_mapping',source_key='r1',
                          section_ref='cesksection1:'+'b'*64)
        stored,preview=self.save(doc,evidence,{'permit_upstream_result_intake':True})
        self.assertEqual(stored['status'],'partial',stored)
        self.assertEqual(stored['subject']['reported_delivery_state'],
                         'SUPPLIED_RESULT_REPORTS_SIGNED_LOCAL_TARGET')
        self.assertFalse(stored['source_result_authenticated_by_store'])
        self.assertEqual(preview['review_state'],'AWAITING_HUMAN_REVIEW')

    def test_real_ec205_local_result_can_be_quarantined_without_knowledge_write(self):
        import test_knowledge_chapters as chapters_tests
        if chapters_tests.impact_tests.Ed25519PrivateKey is None:
            self.skipTest('cryptography unavailable')
        fixture=chapters_tests.ChaptersTests('test_actual_changed_git_bytes_maps_only_selected_chapter')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        real=fixture.call()
        self.assertEqual(real['status'],'partial',real)
        ref=real['subject']['chapter_documents'][0]['sections'][0]['section_ref']
        root=self.root.parent/'real-candidate'
        root.mkdir(mode=0o700)
        scope=fixture.r['scope']
        api=KnowledgeCandidateStore(root=str(root),store_id='real_chapter_review',
            repository_root=str(fixture.upstream.fx.repo),
            knowledge_root=str(fixture.upstream.fx.knowledge),
            repository_ref=scope['repository_ref'],
            knowledge_space_key=scope['knowledge_space_key'],
            period_id=scope['period']['period_id'],
            source_policy_revision=scope['source_policy_revision'])
        init=api.initialize(allow_initialize=True)
        self.assertEqual(init['status'],'partial',init)
        proposal=json.loads(self.proposal(origin='ec205_chapter_mapping',
            source_key='r1',section_ref=ref))
        proposal.update(period_id=scope['period']['period_id'],
            request_binding_sha256=real['subject']['request_binding_sha256'],
            scope_binding_sha256=real['subject']['scope_binding_sha256'])
        before=(fixture.upstream.fx.knowledge/'arch/components.md').read_bytes()
        p=api.preview(proposal_json=canonical(proposal),
                      source_result_json=canonical(real))
        self.assertEqual(p['status'],'partial',p)
        authorization=self.append_policy(p['subject'],
            store_instance_id=init['subject']['store_instance_id'],
            store_scope_binding_sha256=init['subject']['store_scope_binding_sha256'],
            permit_upstream_result_intake=True)
        stored=api.append(proposal_json=canonical(proposal),
            append_policy_json=authorization,source_result_json=canonical(real))
        self.assertEqual(stored['status'],'partial',stored)
        self.assertFalse(stored['candidate_is_authoritative'])
        self.assertEqual((fixture.upstream.fx.knowledge/'arch/components.md').read_bytes(),before)

    def test_ec205_wrong_or_unlinked_section_ref_rejected(self):
        evidence=self.upstream('ec205_chapter_mapping')
        for updates in ({'section_ref':'cesksection1:'+'c'*64},{'source_key':'other'}):
            p=self.proposal(**{'origin':'ec205_chapter_mapping', 'source_key':'r1',
                'section_ref':'cesksection1:'+'b'*64, **updates})
            self.assertEqual(self.api.preview(proposal_json=p,source_result_json=evidence)['status'],
                             'unavailable')

    def test_ec204_selected_git_change_cannot_claim_chapter(self):
        evidence=self.upstream('ec204_selected_change')
        p=self.proposal(origin='ec204_selected_change',source_key='r1')
        stored,_=self.save(p,evidence,{'permit_upstream_result_intake':True})
        self.assertEqual(stored['status'],'partial',stored)
        p=self.proposal(candidate_key='impact2',origin='ec204_selected_change',source_key='r1',
                        section_ref='cesksection1:'+'b'*64)
        self.assertEqual(self.api.preview(proposal_json=p,source_result_json=evidence)['status'],
                         'invalid_input')

    def test_ec204_unknown_stays_unverified(self):
        evidence=self.upstream('ec204_selected_change',target_delivery_state='NOT_VERIFIED',
            source_changes=[{'source_key':'r1','kind':'repository','change_kind':'UNKNOWN',
                             'comparison_state':'UNKNOWN_GIT_RECHECK'}])
        p=self.proposal(origin='ec204_selected_change',source_key='r1')
        stored,_=self.save(p,evidence,{'permit_upstream_result_intake':True})
        self.assertEqual(stored['subject']['reported_delivery_state'],
                         'NO_VERIFIED_DELIVERY_IN_SUPPLIED_RESULT')

    def test_wrong_scope_result_and_fabricated_result_status(self):
        doc=self.proposal(origin='ec204_selected_change',source_key='r1')
        self.assertEqual(self.api.preview(proposal_json=doc,
            source_result_json=self.upstream('ec204_selected_change',period_id='wrong'))['status'],'unavailable')
        evidence=json.loads(self.upstream('ec204_selected_change'))
        evidence['subject']['verified_delivered_facts']=['false_truth']
        evidence['canonical_json']=canonical(evidence['subject'])
        self.assertEqual(self.api.preview(proposal_json=doc,
            source_result_json=canonical(evidence))['status'],'unavailable')

    def test_source_result_not_allowed_for_manual(self):
        self.assertEqual(self.api.preview(proposal_json=self.proposal(),
            source_result_json=self.upstream('ec204_selected_change'))['status'],'invalid_input')

    def test_policy_binding_detects_changed_source_evidence(self):
        evidence=self.upstream('ec204_selected_change')
        doc=self.proposal(origin='ec204_selected_change',source_key='r1')
        preview=self.candidate_preview(doc,evidence)
        changed=self.upstream('ec204_selected_change',target_delivery_state='NOT_VERIFIED')
        attempt=self.api.append(proposal_json=doc,
            append_policy_json=self.append_policy(preview,permit_upstream_result_intake=True),
            source_result_json=changed)
        self.assertEqual(attempt['status'],'unavailable')
        self.assertEqual(len(list((self.root/'records').iterdir())),0)

    def test_record_tamper_fails_closed(self):
        self.save()
        record=next((self.root/'records').iterdir())
        body=json.loads(record.read_text())
        body['body']['candidate']['claim_text']='tampered'
        record.write_text(canonical(body)+'\n')
        self.assertEqual(self.api.preview(proposal_json=self.proposal())['status'],'unavailable')

    def test_record_symlink_or_hardlink_rejected(self):
        self.save()
        record=next((self.root/'records').iterdir())
        companion=self.root.parent/'companion'
        os.link(record,companion)
        self.assertEqual(self.api.list_binding_preview()['status'],'partial')
        self.assertEqual(self.api.preview(proposal_json=self.proposal())['status'],'unavailable')
        companion.unlink()
        real_file=self.root.parent/'shadow'
        record.rename(real_file)
        record.symlink_to(real_file)
        self.assertEqual(self.api.preview(proposal_json=self.proposal())['status'],'unavailable')

    def test_no_candidate_store_inside_or_above_knowledge(self):
        for candidate in (self.knowledge, self.repo, self.knowledge/'child', self.knowledge.parent):
            if not candidate.exists():
                candidate.mkdir(mode=0o700)
            other=KnowledgeCandidateStore(**{**self.kwargs,'root':str(candidate)})
            result=other.initialize(allow_initialize=True)
            self.assertEqual(result['status'],'unavailable',result)

    def test_scope_rebinding_requires_new_store(self):
        other=KnowledgeCandidateStore(**{**self.kwargs,'knowledge_space_key':'another'})
        self.assertEqual(other.list_binding_preview()['status'],'unavailable')
        other=KnowledgeCandidateStore(**{**self.kwargs,'repository_root':str(self.knowledge)})
        self.assertEqual(other.list_binding_preview()['status'],'unavailable')

    def test_replaced_source_root_detected(self):
        moved=self.repo.parent/'old-repo'
        self.repo.rename(moved)
        self.repo.mkdir(mode=0o700)
        self.assertEqual(self.api.list_binding_preview()['status'],'unavailable')

    def test_canonical_json_only_no_duplicate_keys(self):
        raw=self.proposal()
        self.assertEqual(self.api.preview(proposal_json=raw+' ')['status'],'invalid_input')
        duplicate=raw.replace('"claim_text":', '"claim_text":"fake","claim_text":',1)
        self.assertEqual(self.api.preview(proposal_json=duplicate)['status'],'invalid_input')

    def test_concurrent_identical_appends_do_not_duplicate(self):
        doc=self.proposal()
        p=self.candidate_preview(doc)
        policy=self.append_policy(p)
        with ThreadPoolExecutor(max_workers=5) as executor:
            results=list(executor.map(lambda _: self.api.append(proposal_json=doc,
                append_policy_json=policy),range(5)))
        self.assertEqual([x['status'] for x in results],['partial']*5,results)
        self.assertEqual(sum(x['local_candidate_write_performed'] for x in results),1)
        self.assertEqual(len(list((self.root/'records').iterdir())),1)


if __name__ == '__main__':
    unittest.main()
