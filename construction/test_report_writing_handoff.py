#!/usr/bin/env python3
"""EC198 contract/development cases with real EC192..197 synthetic replay.

These are offline in-process functional checks, not authentication, a real AI
request, external authorizer, CI execution, native PowerShell or final acceptance.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from report_evidence_metrics import canonical
from report_writing_handoff import (
    ReportWritingHandoff, AUDIENCE, POLICY_SCHEMA, PURPOSE, ROUTE_ID, TASK_KIND,
    EDITOR_RULES,
)
import test_report_prepare as preceding
from ai_handoff_router import TASK_ROUTES as EC174_TASK_ROUTES

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / 'references' /
                     'report-writing-handoff-result.v1.schema.json').read_text())
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)


class ReportWritingHandoffTests(unittest.TestCase):
    def setUp(self):
        self.prior = preceding.ReportPrepareTests()
        self.prior.setUp()
        self.prepare = self.prior.call()
        self.assertEqual(self.prepare['status'], 'partial', self.prepare)
        self.api = ReportWritingHandoff()
        self.review = self.review_for(self.prepare)

    def review_for(self, prepared, *, release=None):
        prep = prepared['subject']
        grants = []
        for i, row in enumerate(prep['ai_input']['repositories']):
            grants.append({
                'repository_ref': row['repository_ref'],
                'report_subject_ref': row['report_subject_ref'],
                'source_binding_sha256': row['source_binding_sha256'],
                'people_binding_sha256': row['people_binding_sha256'],
                'permit_review_only': True,
                'review_receipt_sha256': f'{i+18:064x}',
                'approved_citation_refs': [c['citation_ref'] for ch in row['channels']
                                           for c in ch['citations']],
            })
        return {
            'schema': POLICY_SCHEMA, 'purpose': PURPOSE, 'audience': AUDIENCE,
            'task_kind': TASK_KIND, 'route_id': ROUTE_ID,
            'permit_review_only': True,
            'prepare_binding_sha256': prep['binding_sha256'],
            'ai_input_sha256': prep['ai_input_sha256'],
            'scope_binding_sha256': prep['scope_binding_sha256'],
            'metrics_binding_sha256': prep['metrics_binding_sha256'],
            'period_id': prep['period_id'],
            'policy_receipt_sha256': 'f'*64,
            'repository_grants': grants,
        }

    def call(self, *, prepare=None, scope=None, metrics=None, release=None,
             review=None, witnesses=None):
        if prepare is None: prepare = self.prepare
        if scope is None: scope = self.prior.scope
        if metrics is None: metrics = self.prior.metrics
        if release is None: release = self.prior.policy
        if review is None: review = self.review
        return self.api.bind(
            prepare_json=prepare['canonical_json'],
            scope_json=scope['canonical_json'], metrics_json=metrics['canonical_json'],
            release_policy=copy.deepcopy(release),
            review_policy=copy.deepcopy(review),
            people_subject_witnesses=witnesses)

    def replay(self, subject, *, prepare=None, scope=None, metrics=None,
               release=None, review=None, witnesses=None):
        return self.api.from_json(
            serialized=canonical(subject),
            prepare_json=(prepare or self.prepare)['canonical_json'],
            scope_json=(scope or self.prior.scope)['canonical_json'],
            metrics_json=(metrics or self.prior.metrics)['canonical_json'],
            release_policy=copy.deepcopy(self.prior.policy if release is None else release),
            review_policy=copy.deepcopy(self.review if review is None else review),
            people_subject_witnesses=witnesses)

    def ok(self, out):
        self.assertEqual(list(VALIDATOR.iter_errors(out)), [], out)
        self.assertEqual((out['status'], out['exit_code']), ('partial',2), out)
        self.assertEqual(out['canonical_json'], canonical(out['subject']))
        self.assertTrue(all(value is False for value in out['limitations'].values()))
        return out['subject']

    def refused(self, out, code, *, unavailable=False):
        self.assertEqual(list(VALIDATOR.iter_errors(out)), [], out)
        self.assertEqual((out['status'],out['exit_code']),
                         ('unavailable',5) if unavailable else ('invalid_input',4), out)
        self.assertEqual(out['reason_code'], 'REPORT_WRITING_HANDOFF_' + code, out)
        self.assertIsNone(out['subject'])
        self.assertIsNone(out['canonical_json'])

    def test_end_to_end_two_repository_draft_and_route_is_offline(self):
        sub = self.ok(self.call())
        handoff=sub['handoff_draft']
        self.assertEqual(handoff['task_kind'],'report_writing')
        self.assertEqual(handoff['route_id'],'ces.route.report_writing.v1')
        self.assertEqual(EC174_TASK_ROUTES['report_writing']['route_id'], ROUTE_ID)
        self.assertFalse(EC174_TASK_ROUTES['report_writing']['ec173_input_supported'])
        self.assertEqual(handoff['route_state'],'STANDALONE_REVIEW_DRAFT_NOT_EC174_DISPATCH')
        self.assertEqual(handoff['external_transfer_state'],'NOT_AUTHORIZED_NOT_DISPATCHED')
        self.assertEqual(handoff['review_state'],'PENDING_HUMAN_SOURCE_AND_PRIVACY_REVIEW')
        self.assertEqual(handoff['ai_input'],self.prepare['subject']['ai_input'])
        self.assertEqual(len(handoff['outline']['repository_sections']),2)
        self.assertTrue(sub['draft_ref'].startswith('cesrhd1:'))
        self.assertEqual(len(sub['binding_sha256']),64)
        self.assertFalse(any(sub['trust_claims'].values()))
        self.assertEqual(handoff['editor_rules'], EDITOR_RULES)

    def test_draft_evidence_slots_are_exact_source_channel_copies(self):
        sub=self.ok(self.call())
        for ai, outline in zip(self.prepare['subject']['ai_input']['repositories'],
                               sub['handoff_draft']['outline']['repository_sections']):
            for k in ['repository_ref','report_subject_ref','source_mode',
                      'source_binding_sha256','people_binding_sha256',
                      'period_window_complete_declared','path_scope',
                      'inventory_state','scope_gap_codes']:
                self.assertEqual(outline[k],ai[k])
            self.assertEqual(len(outline['evidence_slots']),4)
            for src, slot in zip(ai['channels'], outline['evidence_slots']):
                for k in ['channel','coverage_state','coverage_reason_codes',
                          'release_state','ci_completion_signal','citations']:
                    self.assertEqual(slot[k],src[k])
                self.assertTrue(slot['draft_note'])
                self.assertIn(slot['evidence_claim_state'],
                              ('UNVERIFIED_RELEASED_REFERENCES_ONLY',
                               'NO_RELEASED_REFERENCES_NOT_EVIDENCE_OF_NO_ACTIVITY'))

    def test_only_redacted_typed_citation_is_carried(self):
        record=self.ok(self.call())
        flat=canonical(record)
        for raw in ['alice@example.org','divisionA','index.py','source_selector',
                    'identity_scope_sha256','source_receipt_sha256',
                    'release_receipt_sha256','review_receipt_sha256',
                    'actor_key','evidence_id','original_event_id']:
            self.assertNotIn(raw,flat)
        citations=[c['citation_ref'] for r in record['handoff_draft']['outline']['repository_sections']
                   for ch in r['evidence_slots'] for c in ch['citations']]
        self.assertEqual(len(citations),3)
        self.assertTrue(all(ref.startswith('cesrc1:') for ref in citations))
        self.assertEqual(len(set(citations)),len(citations))

    def test_source_pin_is_real_ec197_canonical_sha_not_just_self_hash(self):
        sub=self.ok(self.call())
        pin=sub['source_pins']
        self.assertEqual(pin['prepare_canonical_sha256'],
                         hashlib.sha256(self.prepare['canonical_json'].encode('ascii')).hexdigest())
        self.assertEqual(pin['prepare_binding_sha256'],self.prepare['subject']['binding_sha256'])
        self.assertEqual(pin['scope_binding_sha256'],self.prior.scope['subject']['binding_sha256'])
        self.assertEqual(pin['metrics_binding_sha256'],self.prior.metrics['subject']['binding_sha256'])
        self.assertEqual(pin['release_policy_binding_sha256'],
                         self.prepare['subject']['release_policy_binding_sha256'])
        self.assertEqual(sub['handoff_draft']['source_pins'],pin)

    def test_repeat_and_policy_reordering_are_stable(self):
        a=self.ok(self.call())
        b=copy.deepcopy(self.review)
        b['repository_grants'].reverse()
        for g in b['repository_grants']:g['approved_citation_refs'].reverse()
        self.assertEqual(a,self.ok(self.call(review=b)))
        self.assertEqual(a,self.ok(self.call()))

    def test_replay_from_full_original_inputs_and_policy(self):
        sub=self.ok(self.call())
        result=self.replay(sub)
        self.assertEqual(self.ok(result),sub)
        self.assertEqual(result['reason_code'],
                         'REPORT_WRITING_HANDOFF_REPLAYED_REVIEW_DRAFT')

    def test_empty_ci_and_absent_evidence_remains_not_zero(self):
        mm=self.prior.up.call(); self.prior.up.ok(mm)
        policy=self.prior.make_policy(self.prior.scope,mm)
        prepare=self.prior.call(metrics=mm,policy=policy);self.prior.ok(prepare)
        review=self.review_for(prepare)
        out=self.ok(self.call(prepare=prepare,metrics=mm,release=policy,review=review))
        for r in out['handoff_draft']['outline']['repository_sections']:
            ci=r['evidence_slots'][1]
            self.assertEqual(ci['ci_completion_signal'],'NO_CI_COMPLETION_CLAIM')
            self.assertEqual(ci['evidence_claim_state'],
                             'NO_RELEASED_REFERENCES_NOT_EVIDENCE_OF_NO_ACTIVITY')

    def test_withheld_pass_is_redacted_not_promoted(self):
        release=self.prior.make_policy(self.prior.scope,self.prior.metrics,
                                       refs=['git-sample','ai-sample'])
        prepare=self.prior.call(policy=release);self.prior.ok(prepare)
        review=self.review_for(prepare)
        out=self.ok(self.call(prepare=prepare,release=release,review=review))
        slots=[r['evidence_slots'][1] for r in out['handoff_draft']['outline']['repository_sections']]
        self.assertIn('REDACTED_CI_COMPLETION_UNKNOWN',
                      [ch['ci_completion_signal'] for ch in slots])
        self.assertNotIn('PASS_COMPLETION_CLAIM_UNVERIFIED',
                         canonical(out['handoff_draft']['outline']))
        self.assertIn('CHANNELS_OR_REFERENCES_WITHHELD_BY_RELEASE_POLICY',
                      out['handoff_draft']['outline']['closing']['global_gap_codes'])

    def test_unverified_pass_stays_unverified_even_with_ref(self):
        out=self.ok(self.call())
        slots=[r['evidence_slots'][1] for r in out['handoff_draft']['outline']['repository_sections']]
        self.assertIn('PASS_COMPLETION_CLAIM_UNVERIFIED',
                      [s['ci_completion_signal'] for s in slots])
        self.assertFalse(out['trust_claims']['ci_executed_or_passed_verified'])
        self.assertIn('CI PASS, even if present as a claim',
                      '\n'.join(out['handoff_draft']['editor_rules']))

    def test_proposed_pr_stays_proposal(self):
        row=self.prior.up.pre.create_row('proposed',source_mode='ProposedPR')
        scope=self.prior.up.make_scope(row)
        coverage=[{'repository_id':row['repo_id'],
                   'channels':copy.deepcopy(self.prior.up.coverage[0]['channels'])}]
        mm=self.prior.up.call(scope=scope,coverage=coverage);self.prior.up.ok(mm)
        rel=self.prior.make_policy(scope,mm)
        prepare=self.prior.call(scope=scope,metrics=mm,policy=rel);self.prior.ok(prepare)
        rev=self.review_for(prepare)
        sub=self.ok(self.call(prepare=prepare,scope=scope,metrics=mm,release=rel,review=rev))
        sec=sub['handoff_draft']['outline']['repository_sections'][0]
        self.assertEqual(sec['source_mode'],'ProposedPR')
        self.assertIn('not a merged',sec['source_notice'])
        self.assertIn('PROPOSED_PR_NOT_DELIVERED_TARGET',
                      sub['handoff_draft']['outline']['closing']['global_gap_codes'])

    def test_selected_path_partial_is_preserved(self):
        row=self.prior.up.pre.create_row('small',path_subset=True)
        scope=self.prior.up.make_scope(row)
        coverage=[{'repository_id':row['repo_id'],
                   'channels':copy.deepcopy(self.prior.up.coverage[0]['channels'])}]
        mm=self.prior.up.call(scope=scope,coverage=coverage);self.prior.up.ok(mm)
        rel=self.prior.make_policy(scope,mm)
        prepare=self.prior.call(scope=scope,metrics=mm,policy=rel);self.prior.ok(prepare)
        sec=self.ok(self.call(prepare=prepare,scope=scope,metrics=mm,
                              release=rel,review=self.review_for(prepare)))\
                 ['handoff_draft']['outline']['repository_sections'][0]
        self.assertEqual(sec['path_scope'],'SELECTED_PATHS')
        self.assertIn('SELECTED_PATH_SCOPE',sec['scope_gap_codes'])
        self.assertTrue(any(c['coverage_state']=='PARTIAL_DECLARED'
                            for c in sec['evidence_slots']))

    def test_reject_missing_separate_review_grant(self):
        self.refused(self.api.bind(
            prepare_json=self.prepare['canonical_json'],
            scope_json=self.prior.scope['canonical_json'],
            metrics_json=self.prior.metrics['canonical_json'],
            release_policy=self.prior.policy,review_policy=None),
            'REVIEW_POLICY_REQUIRED',unavailable=True)

    def test_refuse_invalid_intent_route_audience_and_optin(self):
        for k,v in [('schema','wrong'),('purpose','publish_report'),
                    ('audience','PUBLIC'),('task_kind','code_analysis'),
                    ('route_id','ces.route.code_analysis.v1'),
                    ('permit_review_only',False),('permit_review_only',1)]:
            with self.subTest(field=k, value=v):
                pol=copy.deepcopy(self.review);pol[k]=v
                self.refused(self.call(review=pol),'REVIEW_PURPOSE_ROUTE_OR_OPTIN_INVALID',
                             unavailable=True)

    def test_refuse_missing_or_extra_top_level_policy_field(self):
        a=copy.deepcopy(self.review);a.pop('repository_grants')
        self.refused(self.call(review=a),'REVIEW_POLICY_FIELDS_INVALID')
        b=copy.deepcopy(self.review);b['external_provider']='hello'
        self.refused(self.call(review=b),'REVIEW_POLICY_FIELDS_INVALID')

    def test_refuse_stale_prepare_scope_metrics_period_pins(self):
        for k in ['prepare_binding_sha256','ai_input_sha256','scope_binding_sha256',
                  'metrics_binding_sha256','period_id']:
            with self.subTest(field=k):
                pol=copy.deepcopy(self.review);pol[k]='0'*64
                self.refused(self.call(review=pol),
                             'REVIEW_POLICY_PREPARE_SCOPE_OR_PERIOD_STALE', unavailable=True)

    def test_refuse_missing_duplicate_or_unknown_repository_grants(self):
        for mode in ['missing','duplicate','unknown']:
            with self.subTest(mode=mode):
                pol=copy.deepcopy(self.review)
                if mode=='missing':pol['repository_grants'].pop()
                if mode=='duplicate':pol['repository_grants'][1]=copy.deepcopy(pol['repository_grants'][0])
                if mode=='unknown':pol['repository_grants'][0]['repository_ref']='cesrepo1:'+'f'*64
                self.refused(self.call(review=pol),
                             'REVIEW_REPOSITORY_GRANTS_INCOMPLETE' if mode=='missing'
                             else 'REVIEW_REPOSITORY_SET_INVALID',unavailable=True)

    def test_refuse_stale_repository_source_report_or_people(self):
        for key in ['report_subject_ref','source_binding_sha256','people_binding_sha256']:
            with self.subTest(key=key):
                pol=copy.deepcopy(self.review)
                pol['repository_grants'][0][key]='0'*64
                self.refused(self.call(review=pol),
                             'REVIEW_REPOSITORY_SOURCE_OR_PEOPLE_STALE',unavailable=True)

    def test_refuse_repository_individual_optin_false(self):
        for value in [False,0,'true']:
            with self.subTest(v=value):
                pol=copy.deepcopy(self.review)
                pol['repository_grants'][0]['permit_review_only']=value
                self.refused(self.call(review=pol),'REVIEW_REPOSITORY_NOT_PERMITTED',
                             unavailable=True)

    def test_receipts_are_independent_from_policy_release_and_each_other(self):
        cases=[]
        a=copy.deepcopy(self.review);a['policy_receipt_sha256']='a'*64;cases.append(a)
        a=copy.deepcopy(self.review);a['repository_grants'][0]['review_receipt_sha256']='a'*64;cases.append(a)
        a=copy.deepcopy(self.review);a['repository_grants'][1]['review_receipt_sha256']=a['repository_grants'][0]['review_receipt_sha256'];cases.append(a)
        a=copy.deepcopy(self.review);a['repository_grants'][0]['review_receipt_sha256']='f'*64;cases.append(a)
        for a in cases:
            with self.subTest(grant=a):
                self.refused(self.call(review=a),'REVIEW_RECEIPT_NOT_INDEPENDENT',
                             unavailable=True)

    def test_review_policy_receipt_valid_sha_required(self):
        pol=copy.deepcopy(self.review);pol['policy_receipt_sha256']='zzz'
        self.refused(self.call(review=pol),'REVIEW_POLICY_RECEIPT_REQUIRED',unavailable=True)

    def test_citation_exact_allowlist_cannot_drop_or_invent(self):
        for change in ['drop','invent','copy_another_repo','duplicate']:
            pol=copy.deepcopy(self.review)
            target=next(g for g in pol['repository_grants'] if g['approved_citation_refs'])
            items=target['approved_citation_refs']
            if change=='drop': items.pop()
            elif change=='invent': items.append('cesrc1:'+'f'*64)
            elif change=='duplicate': items.append(items[0])
            else:
                # A ref from another repository, or an unrelated fabricated ref,
                # can never be silently accepted into this repository.
                refs=[x for g in pol['repository_grants'] if g is not target for x in g['approved_citation_refs']]
                items.append(refs[0] if refs else 'cesrc1:'+'e'*64)
            with self.subTest(change=change):
                self.refused(self.call(review=pol),
                             'REVIEW_CITATION_ALLOWLIST_INVALID' if change=='duplicate'
                             else 'REVIEW_CITATIONS_NOT_EXACT_RELEASED_SET',
                             unavailable=change!='duplicate')

    def test_citation_malformed_and_extra_grant_fields_rejected(self):
        for malformed in ['alice@example.com','cesrc1:xx',False]:
            pol=copy.deepcopy(self.review)
            target=next(g for g in pol['repository_grants'] if g['approved_citation_refs'])
            target['approved_citation_refs'][0]=malformed
            self.refused(self.call(review=pol),'REVIEW_CITATION_ALLOWLIST_INVALID')
        pol=copy.deepcopy(self.review)
        pol['repository_grants'][0]['instruction']='grade employees'
        self.refused(self.call(review=pol),'REVIEW_REPOSITORY_GRANT_FIELDS_INVALID')

    def test_no_freestyle_or_employee_score_fields_may_be_smuggled(self):
        pol=copy.deepcopy(self.review)
        pol['system_prompt']='Employee ranking, do not reveal'
        self.refused(self.call(review=pol),'REVIEW_POLICY_FIELDS_INVALID')
        result=self.ok(self.call())
        body=canonical(result)
        for field in ['employee_id','employee_score','employee_rank',
                      'performance_grade','display_label','actor_link',
                      'source_text','ci_log','raw_git']:
            self.assertNotIn(field,body)

    def test_reject_original_ec197_tampered_citation_even_with_new_self_hash(self):
        corrupt=copy.deepcopy(self.prepare)
        r=next(r for r in corrupt['subject']['ai_input']['repositories']
               if any(ch['citations'] for ch in r['channels']))
        c=next(ch['citations'][0] for ch in r['channels'] if ch['citations'])
        c['citation_ref']='cesrc1:'+'e'*64
        # Attacker rewrites EC197's own echoed ai_input/hash/binding, but
        # cannot pass the real source+release replay without original bytes.
        p=corrupt['subject']
        p['ai_input_sha256']=hashlib.sha256(canonical(p['ai_input']).encode('ascii')).hexdigest()
        corrupt['canonical_json']=canonical(p)
        self.refused(self.call(prepare=corrupt),'EC197_OR_UPSTREAM_REPLAY_REFUSED')

    def test_refuse_changed_original_release_policy_even_if_review_pin_matches(self):
        rel=copy.deepcopy(self.prior.policy)
        rel['repository_grants'][0]['allowed_channels']=['git_activity']
        self.refused(self.call(release=rel),'EC197_OR_UPSTREAM_REPLAY_REFUSED')

    def test_refuse_original_metrics_replacement(self):
        mm=self.prior.up.call();self.prior.up.ok(mm)
        self.refused(self.call(metrics=mm),'EC197_OR_UPSTREAM_REPLAY_REFUSED', unavailable=True)

    def test_actor_linked_evidence_cannot_be_used_as_report_writing_draft(self):
        # Selected personal references are prohibited by EC197, not merely
        # stripped by EC198; original people witnesses cannot upgrade this.
        # Directly change the EC197 original canonical JSON to simulate a
        # leaked actor field; it must never reach EC198's output.
        modified=copy.deepcopy(self.prepare)
        modified['subject']['ai_input']['repositories'][0]['actor_key']='cesra1:'+'0'*64
        modified['canonical_json']=canonical(modified['subject'])
        self.refused(self.call(prepare=modified),'EC197_OR_UPSTREAM_REPLAY_REFUSED')

    def test_replay_rejects_changed_outline_ref_and_claims(self):
        sub=self.ok(self.call())
        for mutation in ['note','citation','claim','draftref','route']:
            with self.subTest(mutation=mutation):
                cp=copy.deepcopy(sub)
                if mutation=='note':
                    cp['handoff_draft']['outline']['repository_sections'][0]['source_notice']='safe'
                elif mutation=='citation':
                    target=next(ch for repo in cp['handoff_draft']['outline']['repository_sections']
                                for ch in repo['evidence_slots'] if ch['citations'])
                    target['citations'][0]['citation_ref']='cesrc1:'+'d'*64
                elif mutation=='claim':cp['trust_claims']['ci_executed_or_passed_verified']=True
                elif mutation=='draftref':cp['draft_ref']='cesrhd1:'+'d'*64
                else:cp['route_id']='ces.route.code_analysis.v1'
                self.refused(self.replay(cp),'REPLAY_DERIVATION_OR_BINDING_MISMATCH')

    def test_replay_rejects_other_review_policy(self):
        sub=self.ok(self.call())
        rev=copy.deepcopy(self.review)
        rev['policy_receipt_sha256']='e'*64
        self.refused(self.replay(sub,review=rev),
                     'REPLAY_DERIVATION_OR_BINDING_MISMATCH')

    def test_replay_refuses_no_original_scope_or_invalid_source(self):
        sub=self.ok(self.call())
        scope=copy.deepcopy(self.prior.scope)
        scope['canonical_json']='{}'
        self.refused(self.replay(sub,scope=scope), 'REPLAY_OR_UPSTREAM_REFUSED')

    def test_replay_rejects_noncanonical_tampering_duplicates(self):
        sub=self.ok(self.call())
        params=dict(prepare_json=self.prepare['canonical_json'],
                    scope_json=self.prior.scope['canonical_json'],
                    metrics_json=self.prior.metrics['canonical_json'],
                    release_policy=self.prior.policy,review_policy=self.review)
        self.refused(self.api.from_json(serialized=' '+canonical(sub),**params),
                     'JSON_NONCANONICAL')
        self.refused(self.api.from_json(serialized='{"x":1,"x":2}',**params),
                     'JSON_DUPLICATE_KEY')

    def test_replay_rejects_absent_or_additional_record_keys(self):
        sub=self.ok(self.call())
        c=copy.deepcopy(sub);c['ai_execution_verified']=True
        self.refused(self.replay(c),'REPLAY_FIELDS_INVALID')
        c=copy.deepcopy(sub);c.pop('binding_sha256')
        self.refused(self.replay(c),'REPLAY_FIELDS_INVALID')

    def test_bounded_nonserializable_and_too_large_review_policy(self):
        rev=copy.deepcopy(self.review);rev['repository_grants'][0]['approved_citation_refs'].append(object())
        self.refused(self.call(review=rev),'REVIEW_POLICY_SIZE_OR_JSON_INVALID')
        rev=copy.deepcopy(self.review);rev['extra_large']='X'*300000
        self.refused(self.call(review=rev),'REVIEW_POLICY_SIZE_OR_JSON_INVALID')

    def test_prepared_oversize_and_bad_json_fail_closed(self):
        args=dict(scope_json=self.prior.scope['canonical_json'],
                  metrics_json=self.prior.metrics['canonical_json'],
                  release_policy=self.prior.policy,review_policy=self.review)
        self.refused(self.api.bind(prepare_json='X'*1048577,**args),
                     'PREPARED_CANONICAL_JSON_SIZE_INVALID')
        self.refused(self.api.bind(prepare_json='not-json',**args),'JSON_INVALID')
        self.refused(self.api.bind(prepare_json='',**args),
                     'PREPARED_CANONICAL_JSON_SIZE_INVALID')

    def test_reasons_never_echo_untrusted_sensitive_text(self):
        pol=copy.deepcopy(self.review);pol['repository_grants'][0]['repository_ref']='victim@example.org'
        out=self.call(review=pol)
        self.refused(out,'REVIEW_REPOSITORY_SET_INVALID',unavailable=True)
        self.assertNotIn('victim',canonical(out))


if __name__ == '__main__':
    unittest.main()
