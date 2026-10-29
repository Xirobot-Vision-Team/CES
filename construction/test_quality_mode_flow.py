#!/usr/bin/env python3
"""EC190 synthetic-only original-producer/local-saved-record development tests.

All Git lineage, event verifier, host authorizer and provider observations are
controlled fakes, not real provenance or final acceptance.
"""
from __future__ import annotations

import copy
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import unittest

import jsonschema

import quality_show as qs
import test_quality_show as qtest
from quality_mode_flow import CrossModeQualityFlow, EVENT_SCHEMA, REVOKE_SCHEMA, canonical

ROOT = Path(__file__).resolve().parent
SCHEMA_DOC = json.loads((ROOT.parent / 'references' /
                         'cross-mode-quality-flow-result.v1.schema.json').read_text())
CI_BYTES = (ROOT / 'fixtures' / 'ec158' / 'ci-example.json').read_bytes()
CI_SHA = hashlib.sha256(CI_BYTES).hexdigest()
CI_ID = 'ci-' + CI_SHA
CLOCK = qtest.NOW + timedelta(hours=1)


def timestamp(minutes):
    return (qtest.NOW + timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%SZ')


def encode(value):
    return canonical(value)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class FlowCases(unittest.TestCase):
    def setUp(self):
        self.code = {'record_id': CI_ID, 'native_source_mode': 'working_tree_diff',
                     'captured_at_utc': timestamp(30)}
        self.quality_sources = {
            'ProposedPR': {'source_scope': copy.deepcopy(qtest.PROPOSAL),
                           'captured_at_utc': timestamp(2),
                           'evidence': [qtest.sample('ci_evidence', scope=qtest.PROPOSAL)]},
            'DeliveredTarget': {'source_scope': copy.deepcopy(qtest.REMOTE),
                                'captured_at_utc': timestamp(12),
                                'evidence': [qtest.sample('ci_evidence', scope=qtest.REMOTE)]},
            'WorkingTree': {'source_scope': copy.deepcopy(qtest.LOCAL),
                            'captured_at_utc': timestamp(22),
                            'evidence': [qtest.sample('config', scope=qtest.LOCAL)]},
        }
        self.events = {}
        self.revokes = {}
        self.grants = {'quality_scope': [], 'quality_evidence': [],
                       'event': [], 'verify': [], 'code': [], 'revoke': [], 'verify_revoke': []}
        self.view = qs.QualityShow(cursor_key=b'EC190-real-quality-cursor-key-' + b'X' * 4,
                                   clock=lambda: CLOCK)
        self.flow = CrossModeQualityFlow(self.view, clock=lambda: CLOCK)
        self.args = {
            'quality_sources': self.quality_sources,
            'relations': [], 'code_insight': self.code, 'revocations': [],
            'allow_flow': True, 'allow_quality_query': True,
            'allow_quality_evidence_read': True, 'allow_code_insight_read': True,
            'authorize_quality_scope': self.allow('quality_scope'),
            'authorize_quality_evidence': self.allow('quality_evidence'),
            'authorize_code_insight': self.allow('code'),
            'read_code_insight': lambda _facts: CI_BYTES,
            'authorize_source_event': self.allow('event'),
            'read_source_event': lambda facts: self.events.get(facts['event_sha256']),
            'verify_source_event': self.allow('verify'),
            'authorize_revocation': self.allow('revoke'),
            'read_revocation': lambda facts: self.revokes.get(facts['revocation_sha256']),
            'verify_revocation': self.allow('verify_revoke'),
            'acknowledge_historical_proposal': True,
        }
        self.event('ProposedPR', 'DeliveredTarget', 'PROPOSAL_TO_DELIVERED', 6, 8)
        self.event('DeliveredTarget', 'WorkingTree', 'DELIVERED_TO_WORKTREE', 16, 18)
        self.event('CodeInsight', 'WorkingTree', 'CODE_INSIGHT_TO_SOURCE', 25, 26,
                   from_items=[])

    def allow(self, kind):
        def callback(facts):
            self.grants[kind].append(copy.deepcopy(facts))
            return True
        return callback

    def scope(self, mode):
        if mode == 'CodeInsight':
            from quality_mode_flow import digest, SOURCE_DOMAIN
            return digest(SOURCE_DOMAIN, {'source_mode': 'CodeInsight',
                    'record_id': self.code['record_id'], 'native_source_mode': self.code['native_source_mode']})
        return qs.digest(qs.DOMAIN_SCOPE, qs._scope(self.quality_sources[mode]['source_scope']))

    def evidence_id(self, mode):
        return qs.digest(qs.DOMAIN_RECORD, self.quality_sources[mode]['evidence'][0])

    def event(self, a, b, kind, minute, recorded, *, claim='SUPPORTED',
              from_items=None, to_items=None):
        from_items = ([self.evidence_id(a)] if a != 'CodeInsight' else []) if from_items is None else from_items
        to_items = ([self.evidence_id(b)] if b != 'CodeInsight' else []) if to_items is None else to_items
        if kind == 'PROPOSAL_TO_DELIVERED':
            p, d = self.quality_sources[a]['source_scope'], self.quality_sources[b]['source_scope']
            proof = {'provider': p['provider'], 'repository': p['repository'],
                     'project_id': p['project_id'], 'proposal_number': p['proposal_number'],
                     'proposal_head_sha': p['commit_sha'],
                     'delivered_commit_sha': d['commit_sha'],
                     'merge_event_sha256': '1' * 64}
        elif kind == 'DELIVERED_TO_WORKTREE':
            d, w = self.quality_sources[a]['source_scope'], self.quality_sources[b]['source_scope']
            proof = {'provider': d['provider'], 'repository': d['repository'],
                     'project_id': d['project_id'], 'delivered_commit_sha': d['commit_sha'],
                     'worktree_base_commit_sha': d['commit_sha'],
                     'root_pin_sha256': w['root_pin_sha256'],
                     'local_snapshot_event_sha256': '2' * 64}
        elif kind == 'CODE_INSIGHT_TO_SOURCE':
            proof = {'record_id': self.code['record_id'],
                     'record_sha256': self.code['record_id'][3:],
                     'native_source_mode': self.code['native_source_mode'],
                     'target_scope_sha256': self.scope(b),
                     'native_packet_sha256': '0'*64,
                     'native_collect_sha256': '0'*64,
                     'snapshot_map_event_sha256': '3'*64}
        else:
            proof = {'source_capture_ref_sha256': 'a'*64,
                     'target_capture_ref_sha256': 'b'*64}
        obj = {'schema': EVENT_SCHEMA, 'relation_kind': kind, 'claim': claim,
               'from_mode': a, 'to_mode': b,
               'from_scope_sha256': self.scope(a), 'to_scope_sha256': self.scope(b),
               'occurred_at_utc': timestamp(minute),
               'recorded_at_utc': timestamp(recorded), 'proof': proof}
        data = encode(obj)
        event_id = sha(data)
        self.events[event_id] = data
        choice = {'event_sha256': event_id, 'from_item_ids': from_items,
                  'to_item_ids': to_items}
        self.args['relations'].append(choice)
        return choice, obj

    def revoke(self, choice, *, reason='MAPPING_CORRECTED', minute=27):
        original = json.loads(self.events[choice['event_sha256']])
        obj = {'schema': REVOKE_SCHEMA, 'event_sha256': choice['event_sha256'],
               'reason': reason, 'revoked_at_utc': timestamp(minute),
               'recorded_at_utc': timestamp(minute+1),
               'host_revocation_event_sha256': 'f'*64}
        raw = encode(obj)
        self.revokes[sha(raw)] = raw
        row = {'event_sha256': choice['event_sha256'], 'revocation_sha256': sha(raw)}
        self.args['revocations'].append(row)
        return row

    def run_flow(self, **changes):
        args = dict(self.args)
        args.update(changes)
        result = self.flow.relate(**args)
        jsonschema.Draft202012Validator(SCHEMA_DOC).validate(result)
        return result

    def denied(self, result, code=None):
        self.assertIn(result['status'], ('invalid_input', 'unavailable'), result)
        self.assertEqual(result['relations'], [], result)
        self.assertEqual(result['sources'], [], result)
        self.assertIsNone(result['flow_revision_sha256'])
        self.assertFalse(result['effects']['quality_pass_verified'])
        if code:
            self.assertEqual(result['reason_code'], code, result)

    def test_full_four_mode_flow_keeps_source_and_evidence_separate(self):
        response = self.run_flow()
        self.assertEqual((response['status'],response['exit_code']), ('partial',2), response)
        self.assertEqual(response['counts']['source_modes'], 4)
        self.assertEqual(response['counts']['relations'], 3)
        self.assertEqual(response['counts']['context_only_relations'], 3)
        self.assertTrue(all(r['status']=='CONTEXT_ASSOCIATION_ONLY' for r in response['relations']))
        self.assertTrue(all(not r['quality_state_transferred'] for r in response['relations']))
        self.assertTrue(all(not r['source_event_verified_by_ces_git'] for r in response['relations']))
        self.assertEqual([r['relationship'] for r in response['relations']],
                         ['PROPOSAL_TO_DELIVERED','DELIVERED_TO_WORKTREE','CODE_INSIGHT_TO_SOURCE'])
        self.assertGreaterEqual(len(self.grants['quality_scope']), 6)
        self.assertEqual(len(self.grants['code']), 2)
        self.assertEqual([r['phase'] for r in self.grants['event']],
                         ['BEFORE_READ']*3 + ['FINALIZE']*3)
        self.assertEqual([r['phase'] for r in self.grants['verify']],
                         ['BEFORE_READ']*3 + ['FINALIZE']*3)
        self.assertFalse(response['effects']['defect_confirmed'])
        self.assertFalse(response['effects']['test_or_ci_executed_by_flow'])
        self.assertTrue(next(s for s in response['sources']
                             if s['source_mode']=='ProposedPR')['historical_proposal_only'])

    def test_read_only_quality_is_provider_claim_not_actual_executed_test(self):
        result = self.run_flow()
        first = result['relations'][0]
        self.assertEqual(first['from_evidence']['pass_claims'], 1)
        self.assertEqual(first['to_evidence']['pass_claims'], 1)
        self.assertFalse(first['quality_state_transferred'])
        self.assertFalse(result['coverage']['source_or_ci_currentness_independently_verified'])
        self.assertFalse(result['effects']['proposed_pr_declared_delivered'])
        self.assertFalse(result['coverage']['static_code_insight_promoted_to_executed_test'])

    def test_codeinsight_empty_finding_list_not_pass_and_no_model_text_leaked(self):
        result = self.run_flow()
        last = next(r for r in result['relations'] if r['from_mode']=='CodeInsight')
        self.assertEqual(last['from_evidence']['selected_ids'], [])
        self.assertEqual(last['from_evidence']['pass_claims'], 0)
        self.assertTrue(last['from_evidence']['static_findings_are_not_test_results'])
        self.assertEqual(next(s for s in result['sources'] if s['source_mode']=='CodeInsight')
                         ['code_insight_static_finding_count'],0)
        self.assertNotIn('Synthetic empty CodeInsight', json.dumps(result))
        self.assertNotIn('/synthetic/fixture/root', json.dumps(result))

    def test_acknowledgement_required_for_historical_proposal(self):
        self.denied(self.run_flow(acknowledge_historical_proposal=False),
                    'QUALITYFLOW_PROPOSAL_HISTORY_ACK_REQUIRED')

    def test_grant_opt_ins_independently_fail_closed(self):
        for name in ('allow_flow','allow_quality_query','allow_quality_evidence_read'):
            self.denied(self.run_flow(**{name:False}),
                        'QUALITYFLOW_THREE_SEPARATE_QUALITY_OPT_INS_REQUIRED')
        self.denied(self.run_flow(allow_code_insight_read=False),
                    'QUALITYFLOW_CODE_INSIGHT_SEPARATE_OPT_IN_REQUIRED')

    def test_scope_or_receipt_authorization_cannot_be_inherited(self):
        self.denied(self.run_flow(authorize_quality_scope=lambda f: False),
                    'QUALITYFLOW_UPSTREAM_SOURCE_OR_SCOPE_UNAVAILABLE')
        self.denied(self.run_flow(authorize_quality_evidence=lambda f: False),
                    'QUALITYFLOW_UPSTREAM_SOURCE_OR_SCOPE_UNAVAILABLE')

    def test_no_event_read_authorization_is_not_linkable(self):
        self.denied(self.run_flow(authorize_source_event=lambda _f: False),
                    'QUALITYFLOW_SOURCE_EVENT_PERMISSION_DENIED')
        self.denied(self.run_flow(read_source_event=lambda _f: None),
                    'QUALITYFLOW_SOURCE_EVENT_UNAVAILABLE')
        self.denied(self.run_flow(verify_source_event=lambda _f: False),
                    'QUALITYFLOW_HOST_EVENT_REVALIDATION_FAILED')

    def test_source_event_permission_revoked_during_finalize(self):
        self.denied(self.run_flow(authorize_source_event=lambda f: f['phase']=='BEFORE_READ'),
                    'QUALITYFLOW_SOURCE_EVENT_PERMISSION_REVOKED')

    def test_host_source_event_verification_revoked_at_finalize(self):
        self.denied(self.run_flow(verify_source_event=lambda f: f['phase']=='BEFORE_READ'),
                    'QUALITYFLOW_SOURCE_EVENT_VERIFICATION_REVOKED')

    def test_event_bytes_changed_on_finalize(self):
        def read(facts):
            raw = self.events[facts['event_sha256']]
            return raw if facts['phase']=='BEFORE_READ' else raw+b' '
        self.denied(self.run_flow(read_source_event=read),
                    'QUALITYFLOW_SOURCE_EVENT_CHANGED')

    def test_same_commit_string_not_sufficient_for_remote_relation(self):
        choice = self.args['relations'][0]
        obj = json.loads(self.events[choice['event_sha256']])
        obj['proof'].pop('merge_event_sha256')
        raw = encode(obj)
        self.events[sha(raw)] = raw
        relations = [{**choice, 'event_sha256': sha(raw)}]
        self.denied(self.run_flow(relations=relations),
                    'QUALITYFLOW_PROPOSAL_DELIVERY_PROOF_NOT_BOUND')

    def test_proposal_repository_identity_and_event_event_id_must_match(self):
        choice = self.args['relations'][0]
        obj = json.loads(self.events[choice['event_sha256']])
        obj['proof']['repository'] = 'other/project'
        raw = encode(obj)
        self.events[sha(raw)] = raw
        self.denied(self.run_flow(relations=[{**choice,'event_sha256':sha(raw)}]),
                    'QUALITYFLOW_PROPOSAL_DELIVERY_PROOF_NOT_BOUND')

    def test_direct_wrong_scope_or_missing_quality_record_denied(self):
        choice = self.args['relations'][0]
        obj = json.loads(self.events[choice['event_sha256']])
        obj['to_scope_sha256'] = '0'*64
        raw = encode(obj)
        self.events[sha(raw)] = raw
        self.denied(self.run_flow(relations=[{**choice,'event_sha256':sha(raw)}]),
                    'QUALITYFLOW_EVENT_SOURCE_SCOPE_NOT_BOUND')
        bad = {**choice,'from_item_ids':['c'*64]}
        self.denied(self.run_flow(relations=[bad]),
                    'QUALITYFLOW_QUALITY_EVIDENCE_ID_NOT_IN_ORIGINAL_QUERY')

    def test_code_insight_original_record_and_native_map_strict(self):
        self.denied(self.run_flow(read_code_insight=lambda _f: CI_BYTES + b' '),
                    'QUALITYFLOW_CODE_INSIGHT_RECORD_INVALID')
        choice = self.args['relations'][-1]
        self.denied(self.run_flow(relations=[{**choice,'from_item_ids':['F999']}]),
                    'QUALITYFLOW_CODE_FINDING_ID_NOT_IN_ORIGINAL_RECORD')

    def test_code_insight_changed_at_finalize_or_permission_revoked(self):
        self.denied(self.run_flow(authorize_code_insight=lambda f: f['phase']=='BEFORE_READ'),
                    'QUALITYFLOW_CODE_INSIGHT_PERMISSION_REVOKED')
        self.denied(self.run_flow(read_code_insight=lambda f: CI_BYTES if
                    f['phase']=='BEFORE_READ' else CI_BYTES + b' '),
                    'QUALITYFLOW_CODE_INSIGHT_CHANGED')

    def test_codeinsight_record_cannot_masquerade_as_remote_test_receipt(self):
        select = self.args['relations'][-1]
        obj = json.loads(self.events[select['event_sha256']])
        obj['to_mode'] = 'DeliveredTarget'
        obj['to_scope_sha256'] = self.scope('DeliveredTarget')
        obj['proof']['target_scope_sha256'] = self.scope('DeliveredTarget')
        raw = encode(obj)
        self.events[sha(raw)] = raw
        self.denied(self.run_flow(relations=[{**select, 'event_sha256':sha(raw),
                                        'to_item_ids':[self.evidence_id('DeliveredTarget')]}]),
                    'QUALITYFLOW_CODE_INSIGHT_SNAPSHOT_PROOF_NOT_BOUND')

    def test_revocation_preserved_and_prevents_any_quality_transfer(self):
        choice = self.args['relations'][0]
        rev = self.revoke(choice, minute=10)
        result = self.run_flow()
        self.assertEqual(result['counts']['revoked_relations'], 1)
        self.assertEqual(result['counts']['revocation_records'], 1)
        r = next(r for r in result['relations'] if r['event_sha256']==choice['event_sha256'])
        self.assertEqual(r['status'],'REVOKED_NOT_ACTIVE')
        self.assertEqual(r['revoked_by_sha256'],[rev['revocation_sha256']])
        self.assertEqual(len(self.grants['revoke']),2)
        self.assertEqual(len(self.grants['verify_revoke']),2)
        self.assertFalse(r['quality_state_transferred'])

    def test_revocation_permission_recheck_and_original_bytes_recheck(self):
        choice = self.args['relations'][0]
        self.revoke(choice,minute=10)
        self.denied(self.run_flow(authorize_revocation=lambda f:f['phase']=='BEFORE_READ'),
                    'QUALITYFLOW_REVOCATION_PERMISSION_REVOKED')
        self.denied(self.run_flow(verify_revocation=lambda f:f['phase']=='BEFORE_READ'),
                    'QUALITYFLOW_REVOCATION_VERIFICATION_REVOKED')
        self.denied(self.run_flow(read_revocation=lambda f:
                    self.revokes[f['revocation_sha256']] if f['phase']=='BEFORE_READ'
                    else self.revokes[f['revocation_sha256']]+b' '),
                    'QUALITYFLOW_REVOCATION_BYTES_SHA_MISMATCH')

    def test_revocation_cannot_precede_its_related_event(self):
        choice = self.args['relations'][1]
        self.revoke(choice,minute=3)
        self.denied(self.run_flow(), 'QUALITYFLOW_REVOCATION_CHRONOLOGY_INVALID')

    def test_contradictory_host_events_do_not_get_merged_by_majority(self):
        self.event('ProposedPR','DeliveredTarget','PROPOSAL_TO_DELIVERED', 7, 9,
                   claim='DISPUTED')
        result = self.run_flow()
        conflicting = [r for r in result['relations']
                       if r['relationship']=='PROPOSAL_TO_DELIVERED']
        self.assertEqual(len(conflicting),2)
        self.assertTrue(all(r['status']=='CONTRADICTED_NOT_ACTIVE' for r in conflicting))
        self.assertTrue(all(len(r['conflicting_active_evidence_ids'])==1 for r in conflicting))
        self.assertEqual(result['counts']['contradicted_relations'],2)

    def test_disputed_event_is_not_automatically_a_confirmed_retraction(self):
        self.args['relations'] = []
        self.event('ProposedPR','DeliveredTarget','PROPOSAL_TO_DELIVERED', 7, 9,
                   claim='DISPUTED')
        response=self.run_flow()
        self.assertEqual(response['relations'][0]['status'],'DISPUTED_NOT_ACTIVE')
        self.assertEqual(response['counts']['context_only_relations'],0)

    def test_temporal_contradiction_preserved_not_silently_sorted_out(self):
        choice = self.args['relations'][0]
        obj = json.loads(self.events[choice['event_sha256']])
        obj['occurred_at_utc'] = timestamp(20)
        obj['recorded_at_utc'] = timestamp(21)
        raw=encode(obj)
        self.events[sha(raw)] = raw
        result = self.run_flow(relations=[{**choice,'event_sha256':sha(raw)}])
        self.assertEqual(result['relations'][0]['status'],'TEMPORAL_CONTRADICTION_NOT_ACTIVE')
        self.assertEqual(result['counts']['time_inconsistent_relations'],1)
        self.assertEqual(result['relations'][0]['capture_order'],
                         'CALLER_CAPTURE_ORDER_CONTRADICTED')

    def test_future_or_backdated_proof_record_fails_closed(self):
        choice=self.args['relations'][0]
        obj=json.loads(self.events[choice['event_sha256']])
        obj['recorded_at_utc'] = timestamp(1)
        raw=encode(obj); self.events[sha(raw)]=raw
        self.denied(self.run_flow(relations=[{**choice,'event_sha256':sha(raw)}]),
                    'QUALITYFLOW_EVENT_CHRONOLOGY_INVALID')

    def test_exact_selection_no_duplicate_digests_repeated_and_missing_sources(self):
        self.denied(self.run_flow(relations=[self.args['relations'][0]]*2),
                    'QUALITYFLOW_DUPLICATE_OR_INVALID_EVENT_ID')
        self.denied(self.run_flow(quality_sources={'WorkingTree':self.quality_sources['WorkingTree']},
                                  code_insight=None, allow_code_insight_read=False),
                    'QUALITYFLOW_TWO_TO_FOUR_MODES_REQUIRED')
        self.denied(self.run_flow(quality_sources={}),
                    'QUALITYFLOW_QUALITY_SOURCE_SET_INVALID')

    def test_all_4_modes_are_distinct_despite_digest_coincidence(self):
        sources=copy.deepcopy(self.quality_sources)
        sources['ProposedPR']['source_scope']['commit_sha'] = qtest.REMOTE['commit_sha']
        result=self.run_flow(quality_sources=sources)
        self.assertEqual(result['status'], 'partial')
        self.assertNotEqual(result['sources'][1]['source_id'], result['sources'][2]['source_id'])
        self.assertFalse(result['effects']['cross_mode_source_equivalence_proven'])

    def test_only_two_modes_context_comparison_supported(self):
        source = {k:v for k,v in self.quality_sources.items()
                  if k in ('ProposedPR','WorkingTree')}
        self.args['relations'] = []
        self.event('ProposedPR','WorkingTree','CONTEXT_COMPARISON', 4, 5)
        outcome = self.run_flow(quality_sources=source, code_insight=None,
                                allow_code_insight_read=False)
        self.assertEqual(outcome['counts']['source_modes'],2)
        self.assertEqual(outcome['relations'][0]['capture_order'],
                         'NOT_ORDERED_CONTEXT_COMPARISON')

    def test_concurrent_caller_mutation_fails_closed(self):
        done={'yes':False}
        def authorizer(facts):
            if facts['phase']=='FINALIZE' and not done['yes']:
                self.quality_sources['DeliveredTarget']['captured_at_utc'] = timestamp(13)
                done['yes'] = True
            return True
        self.denied(self.run_flow(authorize_source_event=authorizer),
                    'QUALITYFLOW_INPUT_MUTATED_DURING_READ')

    def test_stable_against_caller_selection_order(self):
        first = self.run_flow()
        second = self.run_flow(relations=list(reversed(self.args['relations'])))
        self.assertEqual([r['event_sha256'] for r in first['relations']],
                         [r['event_sha256'] for r in second['relations']])
        # Request ID intentionally commits to exact caller list: the order of
        # intent can differ while observable chronology is deterministic.

    def test_full_qualityshow_multi_page_reauthorization_uses_original_receipts(self):
        sources = copy.deepcopy(self.quality_sources)
        # 31 distinct receipt IDs (capture-label differs); EC188 will truly
        # traverse two pages and re-authorize every producer item.
        sources['WorkingTree']['evidence'] = [
            qtest.sample('config', scope=qtest.LOCAL, offset=n)
            for n in range(31)]
        original = self.args['relations'][1]
        obj = json.loads(self.events[original['event_sha256']])
        raw = encode(obj)
        self.events[sha(raw)] = raw
        result = self.run_flow(quality_sources=sources)
        self.assertEqual(result['status'], 'partial', result)
        summary = next(x for x in result['sources'] if x['source_mode']=='WorkingTree')
        self.assertEqual(summary['quality_evidence_count'], 31)
        self.assertGreaterEqual(len(self.grants['quality_evidence']), 60)

    def test_falsey_revocation_dictionary_is_not_silently_empty_list(self):
        self.denied(self.run_flow(revocations={}),
                    'QUALITYFLOW_REVOCATION_LIMIT_INVALID')
        self.denied(self.run_flow(revocations=''),
                    'QUALITYFLOW_REVOCATION_LIMIT_INVALID')

    def test_host_verifier_receives_exact_identity_and_source_revision(self):
        response = self.run_flow()
        self.assertEqual(response['status'], 'partial')
        event_check = self.grants['verify'][0]
        self.assertEqual(event_check['from_scope'], qtest.PROPOSAL)
        self.assertEqual(event_check['to_scope'], qtest.REMOTE)
        self.assertEqual(event_check['source_scopes']['WorkingTree'], qtest.LOCAL)
        self.assertRegex(event_check['from_quality_revision_sha256'], '^[0-9a-f]{64}$')
        self.assertRegex(event_check['to_quality_revision_sha256'], '^[0-9a-f]{64}$')
        self.assertEqual(self.grants['verify'][0]['request_sha256'],
                         self.grants['verify'][-1]['request_sha256'])

    def test_static_model_finding_id_is_checkable_but_not_a_test(self):
        saved = json.loads(CI_BYTES)
        saved['finding_count'] = 1
        saved['checked_findings'] = [{
            'id': 'F1', 'title': 'Synthetic check of a branch',
            'severity': 'medium', 'confidence': 'low',
            'layer': 'unstaged', 'path': 'src/worker.py',
            'path_endpoint': 'path', 'line_start_claimed': None,
            'line_end_claimed': None, 'line_numbers_verified': False,
            'quote_sha256': 'a'*64,
            'quote_presence': 'pathspec_scoped_tracked_diff_literal',
            'reasoning': 'Local synthetic text only',
            'impact': 'Synthetic impact only',
            'recommendation': 'Synthetic recommendation only',
        }]
        raw = encode(saved)
        self.code['record_id'] = 'ci-' + sha(raw)
        self.args['read_code_insight'] = lambda _f: raw
        self.args['relations'] = []
        self.event('CodeInsight', 'WorkingTree','CODE_INSIGHT_TO_SOURCE',25,26,
                   from_items=['F1'])
        result = self.run_flow()
        self.assertEqual(result['status'],'partial',result)
        relation = result['relations'][0]
        self.assertEqual(relation['from_evidence']['selected_ids'], ['F1'])
        self.assertEqual(relation['from_evidence']['context_only'],1)
        self.assertEqual(relation['from_evidence']['pass_claims'],0)
        self.assertFalse(result['effects']['code_insight_semantics_or_authorship_verified'])

    def test_saved_v1_illegal_provenance_proof_flag_never_accepted(self):
        saved = json.loads(CI_BYTES)
        saved['ci_verified'] = True
        raw = encode(saved)
        self.code['record_id'] = 'ci-' + sha(raw)
        self.args['read_code_insight'] = lambda _f: raw
        self.denied(self.run_flow(), 'QUALITYFLOW_CODE_INSIGHT_RECORD_INVALID')

    def test_no_unsupported_new_power_shell_cli_action_or_native_execution(self):
        result=self.run_flow()
        self.assertFalse(result['effects']['test_or_ci_executed_by_flow'])
        self.assertFalse(result['coverage']['rechecks_are_cross_system_atomic'])
        self.assertFalse(result['effects']['business_repository_or_git_written'])


if __name__ == '__main__':
    unittest.main()
