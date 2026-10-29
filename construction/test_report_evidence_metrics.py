#!/usr/bin/env python3
"""EC196 bounded synthetic developer tests, not provider/PowerShell validation."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from actor_report_subject import ActorReportSubject
from report_evidence_metrics import CHANNELS, ReportEvidenceMetrics
import test_cross_repository_report_scope as previous

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT/'references'/'report-evidence-metrics-result.v1.schema.json').read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


def canonical(v):
    return json.dumps(v, sort_keys=True, ensure_ascii=True, separators=(',', ':'))


class ReportEvidenceMetricsTests(unittest.TestCase):
    def setUp(self):
        self.pre = previous.CrossRepositoryReportScopeTests()
        self.pre.setUp()
        self.api = ReportEvidenceMetrics()
        self.scope = self.make_scope(self.pre.a, self.pre.b)
        self.rows = {r['repository_id']: r for r in self.scope['subject']['repository_set']}
        self.coverage = self.make_coverage()

    def make_scope(self, *rows, operation='report.evidence.read'):
        result = self.pre.run_bind(*rows, operation=operation)
        self.pre.accepted(result)
        return result

    def make_coverage(self, *, state='COMPLETE_DECLARED'):
        def ch(name):
            return {'channel': name, 'state': state,
                    'receipt_sha256': None if state == 'UNKNOWN' else 'f'*64,
                    'reason_codes': ['DATA_NOT_PROVIDED'] if state == 'UNKNOWN'
                    else ['RECORDS_PARTIAL'] if state == 'PARTIAL_DECLARED' else []}
        return [{'repository_id': row['repository_id'],
                 'channels': [ch(ch_name) for ch_name in CHANNELS]}
                for row in self.scope['subject']['repository_set']]

    def event(self, repo_id=None, channel='git_activity', kind='commit_claim',
              eid='event-1', actor_key=None):
        r = self.rows[repo_id or self.pre.a['repo_id']]['report']
        return {'repository_id': repo_id or self.pre.a['repo_id'],
                'report_subject_id': r['report_subject_id'],
                'repository_binding_sha256': r['repository_binding_sha256'],
                'people_binding_sha256': r['people_binding_sha256'],
                'period_id': r['period_id'],
                'evidence_id': eid, 'channel': channel, 'kind': kind,
                'occurred_at_utc': '2026-10-23T12:00:00Z',
                'recorded_at_utc': '2026-10-24T02:00:00Z',
                'evidence_sha256': 'e'*64,
                'source_receipt_sha256': (None if channel == 'unknown_signal'
                                          else 'd'*64),
                'actor_key': actor_key}

    def call(self, evidence=None, coverage=None, *, scope=None, witnesses=None):
        return self.api.bind(
            scope_json=(scope or self.scope)['canonical_json'],
            coverage=copy.deepcopy(self.coverage if coverage is None else coverage),
            evidence=copy.deepcopy([] if evidence is None else evidence),
            people_subject_witnesses=witnesses)

    def ok(self, result):
        self.assertEqual(list(VALIDATOR.iter_errors(result)), [], result)
        self.assertEqual(result['status'], 'partial', result)
        self.assertEqual(result['exit_code'], 2)
        self.assertEqual(result['canonical_json'], canonical(result['subject']))
        self.assertFalse(any(result['limitations'].values()))
        return result['subject']

    def denied(self, result, reason=None):
        self.assertEqual(list(VALIDATOR.iter_errors(result)), [], result)
        self.assertEqual(result['status'], 'invalid_input', result)
        self.assertEqual(result['exit_code'], 4)
        self.assertIsNone(result['subject'])
        self.assertIsNone(result['canonical_json'])
        if reason:
            self.assertEqual(result['reason_code'],
                             'REPORT_EVIDENCE_METRICS_' + reason)

    def test_empty_ci_is_not_pass_and_count_not_performance(self):
        s = self.ok(self.call())
        self.assertEqual(s['repository_metrics'][0]['channels'][1]
                         ['ci_completion_signal'], 'NO_CI_COMPLETION_CLAIM')
        self.assertEqual(s['repository_metrics'][0]['channels'][1]
                         ['empty_observation_meaning'],
                         'ZERO_SUBMITTED_NOT_VERIFIED_ZERO')
        self.assertFalse(s['claims']['individual_productivity_or_performance_assessed'])
        self.assertIn('NO_EVIDENCE_REFERENCES_SUBMITTED', s['global_gaps'])

    def test_all_four_channels_remain_distinct_and_origin_claims(self):
        ev = [self.event(channel='git_activity',kind='commit_claim',eid='git'),
              self.event(channel='ai_conclusion',kind='finding_claim',eid='ai'),
              self.event(channel='ci_execution',kind='completed_pass_claim',eid='ci'),
              self.event(channel='unknown_signal',kind='unavailable',eid='unknown')]
        s=self.ok(self.call(ev))
        items=s['evidence_refs']
        self.assertEqual({e['origin'] for e in items},
                         {'EXTERNAL_GIT_RECORD_CLAIM_UNVERIFIED',
                          'AI_OUTPUT_REFERENCE_CLAIM_UNVERIFIED',
                          'EXTERNAL_CI_RUN_CLAIM_UNVERIFIED',
                          'DECLARED_INFORMATION_GAP_UNVERIFIED'})
        self.assertEqual(sum(c['declaration_count'] for r in s['repository_metrics']
                             for c in r['channels']),4)
        repo = next(r for r in s['repository_metrics'] if r['repository_id']==self.pre.a['repo_id'])
        self.assertEqual(repo['channels'][1]['ci_completion_signal'],
                         'PASS_COMPLETION_CLAIM_UNVERIFIED')
        self.assertFalse(s['claims']['ci_runs_executed_or_completed_verified'])
        self.assertFalse(s['claims']['ai_conclusions_verified_as_facts'])

    def test_cross_repository_events_not_merged(self):
        s=self.ok(self.call([self.event(eid='same'),
                             self.event(repo_id=self.pre.b['repo_id'],eid='same')]))
        self.assertEqual(len(s['evidence_refs']),2)
        self.assertEqual([r['channels'][2]['declaration_count']
                          for r in s['repository_metrics']],[1,1])

    def test_replay_recomputes_exact_scope_and_metrics(self):
        ev=[self.event(channel='ci_execution',kind='completed_fail_claim')]
        response=self.call(ev)
        s=self.ok(response)
        replay=self.api.from_json(serialized=response['canonical_json'],
                                  scope_json=self.scope['canonical_json'])
        self.assertEqual(s,self.ok(replay))

    def test_input_order_does_not_change_binding(self):
        a=self.event(eid='a'); b=self.event(repo_id=self.pre.b['repo_id'],eid='b')
        x=self.ok(self.call([a,b]))
        y=self.ok(self.call([b,a],list(reversed(self.coverage))))
        self.assertEqual(x['binding_sha256'],y['binding_sha256'])
        self.assertEqual(x,y)

    def test_ci_fail_and_pass_conflict_is_not_pass(self):
        s=self.ok(self.call([self.event(channel='ci_execution',kind='completed_fail_claim',eid='a'),
                             self.event(channel='ci_execution',kind='completed_pass_claim',eid='b')]))
        self.assertEqual(s['repository_metrics'][0]['channels'][1]['ci_completion_signal'],
                         'CONFLICTING_COMPLETION_CLAIMS_UNVERIFIED')

    def test_ci_running_is_not_completion(self):
        s=self.ok(self.call([self.event(channel='ci_execution',kind='running_claim')]))
        self.assertEqual(s['repository_metrics'][0]['channels'][1]['ci_completion_signal'],
                         'NO_CI_COMPLETION_CLAIM')

    def test_explicit_unknown_and_partial_are_not_complete(self):
        cv=self.make_coverage(state='UNKNOWN')
        cv[0]['channels'][0]={'channel':'ai_conclusion','state':'PARTIAL_DECLARED',
                              'receipt_sha256':'a'*64,'reason_codes':['RECORDS_PARTIAL']}
        s=self.ok(self.call(coverage=cv))
        self.assertEqual(s['repository_metrics'][0]['channels'][0]
                         ['effective_coverage_state'],'PARTIAL_DECLARED')
        self.assertEqual(s['repository_metrics'][0]['channels'][1]
                         ['effective_coverage_state'],'UNKNOWN')
        self.assertIn('PARTIAL_UNKNOWN_OR_BLOCKED_CHANNEL_COVERAGE',s['global_gaps'])

    def test_upstream_selected_path_downgrades_complete(self):
        row=self.pre.create_row('api',path_subset=True)
        sscope=self.make_scope(row, self.pre.b)
        cv=self.make_coverage();
        s=self.ok(self.call(coverage=cv,scope=sscope))
        sr=next(r for r in s['repository_metrics'] if r['repository_id']==row['repo_id'])
        self.assertEqual(sr['channels'][2]['effective_coverage_state'],
                         'PARTIAL_DECLARED')
        self.assertIn('UPSTREAM_SELECTED_PATHS',sr['channels'][2]['coverage_reason_codes'])

    def test_upstream_inventory_unknown_is_unknown(self):
        row=self.pre.create_row('api',inventory_state='unknown')
        sc=self.make_scope(row,self.pre.b)
        s=self.ok(self.call(scope=sc))
        sr=next(r for r in s['repository_metrics'] if r['repository_id']==row['repo_id'])
        self.assertEqual(sr['channels'][2]['effective_coverage_state'],'UNKNOWN')

    def test_upstream_partial_period_is_partial(self):
        row=self.pre.create_row('api',partial_window=True)
        sc=self.make_scope(row,self.pre.b)
        s=self.ok(self.call(scope=sc))
        sr=next(r for r in s['repository_metrics'] if r['repository_id']==row['repo_id'])
        self.assertEqual(sr['channels'][2]['effective_coverage_state'],'PARTIAL_DECLARED')

    def test_missing_repo_blocks_entire_set_without_dropping_it(self):
        b=copy.deepcopy(self.pre.b['input'])
        b.update(availability='MISSING',people_subject_json=None,authorization=None)
        sc=self.make_scope(self.pre.a,b)
        s=self.ok(self.call(scope=sc,coverage=[]))
        self.assertEqual(s['cross_repository_permission_state'],'BLOCKED')
        self.assertEqual(len(s['repository_metrics']),2)
        self.assertEqual(set(c['effective_coverage_state'] for row in s['repository_metrics']
                             for c in row['channels']), {'BLOCKED'})
        self.assertIn('REPOSITORY_MISSING',s['repository_metrics'][1]['scope_reason_codes'])
        self.assertEqual(s['evidence_refs'],[])

    def test_denied_permission_cannot_read_ready_subset(self):
        b=copy.deepcopy(self.pre.b)
        b['input']['authorization']['granted_operations']=['report.scope.read',
                                                            'report.actors.read']
        sc=self.make_scope(self.pre.a,b,operation='report.scope.read')
        s=self.ok(self.call(scope=sc,coverage=[]))
        self.assertEqual(s['cross_repository_permission_state'],'BLOCKED')

    def test_reading_evidence_requires_requested_operation(self):
        sc=self.make_scope(self.pre.a,self.pre.b,operation='report.scope.read')
        s=self.ok(self.call(scope=sc,coverage=[]))
        self.assertEqual(s['cross_repository_permission_state'],'BLOCKED')
        self.denied(self.call([self.event()],scope=sc),
                    'EVIDENCE_SUPPLIED_WITHOUT_SET_WIDE_PERMISSION')

    def test_blocked_scope_rejects_coverage_or_evidence_payload(self):
        b=copy.deepcopy(self.pre.b['input']); b.update(
            availability='INACCESSIBLE',people_subject_json=None,authorization=None)
        sc=self.make_scope(self.pre.a,b)
        self.denied(self.call(scope=sc), 'EVIDENCE_SUPPLIED_WITHOUT_SET_WIDE_PERMISSION')
        self.denied(self.call([self.event()],coverage=[],scope=sc),
                    'EVIDENCE_SUPPLIED_WITHOUT_SET_WIDE_PERMISSION')

    def test_missing_channel_declaration_rejected(self):
        cv=self.make_coverage();cv[0]['channels'].pop()
        self.denied(self.call(coverage=cv),'COVERAGE_CHANNEL_SET_INVALID')

    def test_duplicate_or_misordered_channel_rejected(self):
        cv=self.make_coverage();cv[0]['channels'][0]['channel']='git_activity'
        self.denied(self.call(coverage=cv),'COVERAGE_CHANNEL_ORDER_OR_DUPLICATE_INVALID')

    def test_missing_repository_declaration_rejected(self):
        self.denied(self.call(coverage=[self.coverage[0]]),
                    'COVERAGE_REPOSITORIES_INCOMPLETE')

    def test_wrong_repository_in_coverage_rejected(self):
        cv=self.make_coverage();cv[0]['repository_id']='cesrepo1:'+'0'*64
        self.denied(self.call(coverage=cv),'COVERAGE_REPOSITORY_SET_INVALID')

    def test_partial_without_reason_and_unknown_with_receipt_rejected(self):
        cv=self.make_coverage();cv[0]['channels'][0].update(
            state='PARTIAL_DECLARED',reason_codes=[])
        self.denied(self.call(coverage=cv),'PARTIAL_DECLARATION_INVALID')
        cv=self.make_coverage();cv[0]['channels'][0].update(
            state='UNKNOWN',reason_codes=['DATA_NOT_PROVIDED'])
        self.denied(self.call(coverage=cv),'UNKNOWN_DECLARATION_INVALID')

    def test_event_wrong_period_rejected(self):
        e=self.event();e['period_id']=self.pre.other_p['period']['period_id']
        self.denied(self.call([e]),'EVIDENCE_SCOPE_OR_PIN_MISMATCH')

    def test_event_wrong_repo_report_and_people_binding_rejected(self):
        for field, invalid in [('repository_id','cesrepo1:'+'0'*64),
                               ('report_subject_id','cesrs1:'+'0'*64),
                               ('repository_binding_sha256','0'*64),
                               ('people_binding_sha256','0'*64)]:
            with self.subTest(field=field):
                e=self.event();e[field]=invalid
                self.denied(self.call([e]),
                            'EVIDENCE_UNKNOWN_REPOSITORY' if field=='repository_id'
                            else 'EVIDENCE_SCOPE_OR_PIN_MISMATCH')

    def test_event_outside_period_rejected(self):
        e=self.event();e['occurred_at_utc']='2026-10-24T00:00:00Z'
        self.denied(self.call([e]),'EVIDENCE_OUTSIDE_PERIOD')

    def test_record_time_before_occurrence_rejected(self):
        e=self.event();e['recorded_at_utc']='2026-10-23T11:59:59Z'
        self.denied(self.call([e]),'RECORD_BEFORE_OCCURRENCE')

    def test_ci_kind_cannot_masquerade_as_git(self):
        self.denied(self.call([self.event(kind='completed_pass_claim')]),
                    'EVIDENCE_CHANNEL_KIND_INVALID')

    def test_unknown_receipt_or_actor_forbidden(self):
        e=self.event(channel='unknown_signal',kind='unavailable')
        e['source_receipt_sha256']='1'*64
        self.denied(self.call([e]),'SOURCE_RECEIPT_INVALID')
        e['source_receipt_sha256']=None;e['actor_key']=self.pre.a['actor_key']
        self.denied(self.call([e]),'ACTOR_REFERENCE_INVALID')

    def test_duplicate_event_ids_even_across_channels_rejected(self):
        a=self.event(eid='same');b=self.event(eid='same',channel='ai_conclusion',kind='finding_claim')
        self.denied(self.call([a,b]),'DUPLICATE_EVIDENCE_ID')

    def test_raw_performance_fields_forbidden(self):
        e=self.event(); e['individual_score']=100
        self.denied(self.call([e]),'EVIDENCE_FIELDS_INVALID')
        cv=self.make_coverage();cv[0]['channels'][0]['LOC']=99999
        self.denied(self.call(coverage=cv),'COVERAGE_CHANNEL_FIELDS_INVALID')

    def test_claims_tamper_and_origin_spoof_rejected_on_replay(self):
        x=self.call([self.event()])
        self.ok(x)
        for change in ('origin','claim','metric'):
            v=copy.deepcopy(x['subject'])
            if change=='origin':v['evidence_refs'][0]['origin']='AUTHENTICATED'
            if change=='claim':v['claims']['employee_scores_or_rankings_generated']=True
            if change=='metric':v['repository_metrics'][0]['channels'][2]['declaration_count']=42
            self.denied(self.api.from_json(serialized=canonical(v),
                         scope_json=self.scope['canonical_json']),
                        'REPLAY_DERIVATION_OR_BINDING_MISMATCH')

    def test_noncanonical_and_duplicate_json_rejected(self):
        x=self.call();self.ok(x)
        self.denied(self.api.from_json(serialized=json.dumps(x['subject']),
                       scope_json=self.scope['canonical_json']),'JSON_NONCANONICAL')
        doubled=x['canonical_json'].replace('"schema":', '"schema":"bad","schema":',1)
        self.denied(self.api.from_json(serialized=doubled,
                       scope_json=self.scope['canonical_json']),'JSON_DUPLICATE_KEY')

    def test_wrong_scope_must_not_replay(self):
        r=self.call([self.event()]);self.ok(r)
        one=self.make_scope(self.pre.a)
        self.denied(self.api.from_json(serialized=r['canonical_json'],
                    scope_json=one['canonical_json']),
                    'COVERAGE_REPOSITORIES_INCOMPLETE')

    def test_actor_requires_original_matching_ec194_evidence(self):
        e=self.event(actor_key=self.pre.a['actor_key'])
        self.denied(self.call([e]),'ACTOR_REFERENCE_REQUIRES_EC194_WITNESS')
        witnesses={self.pre.a['repo_id']:self.pre.a['people']['canonical_json'],
                   self.pre.b['repo_id']:self.pre.b['people']['canonical_json']}
        self.denied(self.call([e],witnesses=witnesses),
                    'ACTOR_EVIDENCE_NOT_LINKED_IN_EC194')

    def with_linked_actor(self):
        """Reissue EC194 source against original EC193 with exact evidence ref."""
        a=copy.deepcopy(self.pre.a)
        ev=self.event()
        person={'identity': {'authority':'github','tenant':'demo',
                             'immutable_subject_id':'10001'},
                'display_label':'same display across repositories',
                'identity_receipt_sha256':'b'*64,
                'authorization':{'purpose':'periodic_repository_report',
                  'receipt_sha256':'a'*64,
                  'valid_from_utc':self.pre.p['period']['start_utc'],
                  'valid_until_exclusive_utc':self.pre.p['period']['end_exclusive_utc']}}
        er={'evidence_id':ev['evidence_id'],'identity':person['identity'],
            'occurred_at_utc':ev['occurred_at_utc'],
            'repository_id':a['repo_id'],
            'report_subject_id':a['report']['subject']['report_subject_id'],
            'source_binding_sha256':a['report']['subject']['binding_sha256'],
            'evidence_sha256':ev['evidence_sha256']}
        new_person=ActorReportSubject().bind(
            repository_subject_json=a['report']['canonical_json'],
            actors=[person],evidence=[er])
        self.assertEqual(new_person['status'],'partial',new_person)
        a['input']['people_subject_json']=new_person['canonical_json']
        a['input']['expected']['people_binding_sha256']=new_person['subject']['binding_sha256']
        sc=self.make_scope(a,self.pre.b)
        r=[r for r in sc['subject']['repository_set'] if r['repository_id']==a['repo_id']][0]
        ev['people_binding_sha256']=r['report']['people_binding_sha256']
        ev['actor_key']=a['actor_key']
        witnesses={a['repo_id']:new_person['canonical_json'],
                   self.pre.b['repo_id']:self.pre.b['people']['canonical_json']}
        return sc, ev, witnesses

    def test_actor_matching_link_only_with_witness_replays(self):
        sc,e,w=self.with_linked_actor()
        result=self.call([e],scope=sc,witnesses=w)
        s=self.ok(result)
        self.assertEqual(s['evidence_refs'][0]['actor_reference_state'],
                         'EC194_DECLARED_EVIDENCE_LINK_UNVERIFIED')
        self.assertFalse(s['claims']['identity_or_evidence_attribution_authenticated'])
        self.assertEqual(self.ok(self.api.from_json(
            serialized=result['canonical_json'],scope_json=sc['canonical_json'],
            people_subject_witnesses=w)),s)
        self.denied(self.api.from_json(serialized=result['canonical_json'],
                    scope_json=sc['canonical_json']),
                    'ACTOR_REFERENCE_REQUIRES_EC194_WITNESS')

    def test_actor_wrong_pseudonym_rejected_even_with_witness(self):
        sc,e,w=self.with_linked_actor()
        e['actor_key']='cesra1:'+'0'*64
        self.denied(self.call([e],scope=sc,witnesses=w),
                    'ACTOR_NOT_ELIGIBLE_IN_EC194')

    def test_actor_wrong_evidence_digest_rejected(self):
        sc,e,w=self.with_linked_actor()
        e['evidence_sha256']='0'*64
        self.denied(self.call([e],scope=sc,witnesses=w),
                    'ACTOR_EVIDENCE_NOT_LINKED_IN_EC194')

    def test_actor_identity_receipt_missing_never_attributed(self):
        a=self.pre.create_row('other',identity_receipt=False)
        s=self.make_scope(a)
        r=s['subject']['repository_set'][0]['report']
        e=self.event();e.update(repository_id=a['repo_id'],
            report_subject_id=r['report_subject_id'],
            repository_binding_sha256=r['repository_binding_sha256'],
            people_binding_sha256=r['people_binding_sha256'],
            actor_key=a['actor_key'])
        cv=[{'repository_id':a['repo_id'],'channels':copy.deepcopy(self.coverage[0]['channels'])}]
        self.denied(self.call([e],coverage=cv,scope=s,
                    witnesses={a['repo_id']:a['people']['canonical_json']}),
                    'ACTOR_NOT_ELIGIBLE_IN_EC194')

    def test_declared_proposed_pr_not_delivered(self):
        a=self.pre.create_row('proposed',source_mode='ProposedPR')
        sc=self.make_scope(a)
        cv=[{'repository_id':a['repo_id'],'channels':copy.deepcopy(self.coverage[0]['channels'])}]
        s=self.ok(self.call(coverage=cv,scope=sc))
        self.assertIn('PROPOSED_PR_NOT_DELIVERED_TARGET',s['global_gaps'])

    def test_event_limit_and_bad_type_fails_closed(self):
        self.denied(self.call(evidence='bad'),'COLLECTION_LIST_INVALID')
        ev=[self.event(eid='evt-'+str(i)) for i in range(513)]
        self.denied(self.call(evidence=ev),'COLLECTION_LIST_INVALID')


if __name__ == '__main__':
    unittest.main()
