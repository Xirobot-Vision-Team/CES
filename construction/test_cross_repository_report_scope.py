#!/usr/bin/env python3
"""EC195 focused synthetic feature checks; NOT live Git/identity/PowerShell tests."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from natural_period import NaturalPeriod
from repository_report_subject import RepositoryReportSubject
from actor_report_subject import ActorReportSubject
from cross_repository_report_scope import CrossRepositoryReportScope

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT/'references'/'cross-repository-report-scope-result.v1.schema.json').read_text())
VALIDATOR = Draft202012Validator(SCHEMA)
ALL = ['report.scope.read', 'report.actors.read', 'report.evidence.read', 'report.actors.link']


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'))


class CrossRepositoryReportScopeTests(unittest.TestCase):
    def setUp(self):
        self.api = CrossRepositoryReportScope()
        self.p = NaturalPeriod().from_id(period_id='cesnp1:day:UTC:2026-10-23')
        self.other_p = NaturalPeriod().from_id(period_id='cesnp1:day:UTC:2026-10-24')
        self.assertEqual(self.p['status'], 'partial')
        self.a = self.create_row('api')
        self.b = self.create_row('web')

    def create_row(self, repository_key, *, person='10001', period=None,
                   report_key='people-activity', source_mode='WorkingTree',
                   identity_receipt=True, path_subset=False, partial_window=False,
                   inventory_state='complete_declared', permissions=None):
        p = period or self.p
        repo = {'namespace_key': 'divisionA', 'project_key': 'demo',
                'repository_key': repository_key}
        source = {'mode': source_mode,
                  'selector': {
                      'kind': {'WorkingTree':'checkout_key',
                               'DeliveredTarget':'delivery_key',
                               'ProposedPR':'proposal_key'}[source_mode],
                      'key': 'report-source'},
                  'git_object': None,
                  'receipt_sha256': None,
                  'observed_at_utc': None}
        cov = {'window': {'start_utc': p['period']['start_utc'],
                          'end_exclusive_utc': ('2026-10-23T12:00:00Z'
                          if partial_window else p['period']['end_exclusive_utc'])},
               'includes': ([{'kind':'file','path':'src/index.py'}] if path_subset
                            else [{'kind':'repository','path':''}]),
               'excludes': [],
               'inventory_state': inventory_state}
        # A local root is valid for WorkingTree and DeliveredTarget only.
        # ProposedPR uses a remote HTTPS repository locator.
        locator = ({'kind':'remote_repository',
                    'value':'https://example.org/divisionA/'+repository_key}
                   if source_mode == 'ProposedPR' else
                   {'kind':'local_root','value':'/work/'+repository_key})
        r = RepositoryReportSubject().bind(
            period_json=p['canonical_json'],
            repository={**repo,'locator':locator}, report_key=report_key,
            source=source, coverage=cov)
        self.assertEqual(r['status'], 'partial', r)
        person_record = {
            'identity': {'authority':'github','tenant':'demo',
                         'immutable_subject_id':person},
            'display_label': 'same display across repositories',
            'identity_receipt_sha256': 'b'*64 if identity_receipt else None,
            'authorization': {
                'purpose': 'periodic_repository_report',
                'receipt_sha256':'a'*64,
                'valid_from_utc':p['period']['start_utc'],
                'valid_until_exclusive_utc':p['period']['end_exclusive_utc']}}
        s = ActorReportSubject().bind(repository_subject_json=r['canonical_json'],
                                      actors=[person_record], evidence=[])
        self.assertEqual(s['status'], 'partial', s)
        request = {
            'repository':repo,
            'expected':{
                'report_subject_id':r['subject']['report_subject_id'],
                'repository_binding_sha256':r['subject']['binding_sha256'],
                'people_binding_sha256':s['subject']['binding_sha256']},
            'availability':'SUBMITTED',
            'people_subject_json':s['canonical_json'],
            'authorization':{
                'purpose':'periodic_cross_repository_report',
                'receipt_sha256':'c'*64,
                'valid_from_utc':self.p['period']['start_utc'],
                'valid_until_exclusive_utc':self.p['period']['end_exclusive_utc'],
                'granted_operations':copy.deepcopy(ALL if permissions is None else permissions)}
        }
        return {'input':request, 'actor_key':s['subject']['actors'][0]['actor_key'],
                'repo_id':r['subject']['repository']['repository_id'],
                'report':r, 'people':s}

    def run_bind(self, *rows, operation='report.scope.read', links=None):
        result=self.api.bind(period_json=self.p['canonical_json'],
            requested_operation=operation,
            repositories=copy.deepcopy([x['input'] if 'input' in x else x for x in rows]),
            actor_links=copy.deepcopy(links))
        self.assertEqual(list(VALIDATOR.iter_errors(result)), [], result)
        return result

    def accepted(self, result):
        self.assertEqual(result['status'],'partial',result)
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['canonical_json'],canonical(result['subject']))
        self.assertFalse(any(result['limitations'].values()))
        return result['subject']

    def rejected(self, result, reason=None, status='invalid_input'):
        self.assertEqual(result['status'],status,result)
        self.assertEqual(result['exit_code'],5 if status=='unavailable' else 4)
        self.assertIsNone(result['subject'])
        self.assertIsNone(result['canonical_json'])
        if reason:
            self.assertEqual(result['reason_code'],'CROSS_REPOSITORY_SCOPE_'+reason)
        self.assertEqual(list(VALIDATOR.iter_errors(result)),[],result)

    def link(self, a=None, b=None, key='team1'):
        a=a or self.a; b=b or self.b
        return {'link_key':key, 'receipt_sha256':'d'*64,
                'members':[{'repository_id':a['repo_id'], 'actor_key':a['actor_key']},
                           {'repository_id':b['repo_id'], 'actor_key':b['actor_key']}]}

    def test_explicit_set_and_permission_intersection(self):
        a=copy.deepcopy(self.a); b=copy.deepcopy(self.b)
        a['input']['authorization']['granted_operations'] = ALL
        b['input']['authorization']['granted_operations'] = ['report.scope.read', 'report.actors.read']
        s=self.accepted(self.run_bind(a,b))
        self.assertEqual(s['effective_operations'],['report.actors.read','report.scope.read'])
        self.assertTrue(s['requested_operation_declared_for_all'])
        self.assertEqual(len(s['repository_set']),2)
        self.assertTrue(all(x['status']=='READY' for x in s['repository_set']))
        self.assertEqual(s['coverage_gaps'],[])
        self.assertFalse(s['claims']['repository_universe_complete_verified'])

    def test_only_explicit_repositories_no_discovery(self):
        s=self.accepted(self.run_bind(self.a))
        self.assertEqual(len(s['repository_set']),1)
        self.assertEqual(s['repository_set'][0]['repository']['repository_key'],'api')
        self.assertIn('REPOSITORY_UNIVERSE_NOT_VERIFIED',s['global_gaps'])

    def test_missing_repository_remains_individually_named_gap(self):
        b=copy.deepcopy(self.b['input'])
        b.update(availability='MISSING',people_subject_json=None,authorization=None)
        s=self.accepted(self.run_bind(self.a,b))
        self.assertEqual(s['effective_operations'],[])
        self.assertFalse(s['requested_operation_declared_for_all'])
        self.assertEqual(s['coverage_gaps'][0]['repository']['repository_key'],'web')
        self.assertEqual(s['coverage_gaps'][0]['reason_codes'],['REPOSITORY_MISSING'])

    def test_inaccessible_repository_remains_named_gap(self):
        b=copy.deepcopy(self.b['input'])
        b.update(availability='INACCESSIBLE',people_subject_json=None,authorization=None)
        s=self.accepted(self.run_bind(b,self.a))
        self.assertEqual(s['coverage_gaps'][0]['reason_codes'],['REPOSITORY_INACCESSIBLE'])
        self.assertEqual(s['coverage_gaps'][0]['repository_id'],self.b['repo_id'])

    def test_missing_and_inaccessible_are_two_separate_gaps(self):
        b=copy.deepcopy(self.b['input']); b.update(availability='MISSING',people_subject_json=None,authorization=None)
        c=self.create_row('mobile')['input']; c.update(availability='INACCESSIBLE',people_subject_json=None,authorization=None)
        s=self.accepted(self.run_bind(self.a,b,c))
        self.assertEqual(len(s['coverage_gaps']),2)
        self.assertEqual({x['repository']['repository_key'] for x in s['coverage_gaps']},{'web','mobile'})

    def test_submitted_but_no_subject_is_gap(self):
        b=copy.deepcopy(self.b['input']); b['people_subject_json']=None
        s=self.accepted(self.run_bind(self.a,b))
        self.assertEqual(s['coverage_gaps'][0]['reason_codes'],['SUBJECT_NOT_SUPPLIED'])

    def test_bad_upstream_subject_is_gap_without_raw_echo(self):
        b=copy.deepcopy(self.b['input']); b['people_subject_json']='not json email=hello@private.org'
        result=self.run_bind(self.a,b)
        s=self.accepted(result)
        self.assertEqual(s['coverage_gaps'][0]['reason_codes'],['SUBJECT_REPLAY_FAILED'])
        self.assertNotIn('hello@private.org',result['canonical_json'])

    def test_period_mismatch_does_not_enter_report(self):
        b=self.create_row('web',period=self.other_p)
        s=self.accepted(self.run_bind(self.a,b))
        self.assertIn('PERIOD_MISMATCH',s['coverage_gaps'][0]['reason_codes'])
        self.assertIsNone([r for r in s['repository_set'] if r['repository_id']==b['repo_id']][0]['report'])

    def test_other_repository_content_cannot_be_impersonated(self):
        b=copy.deepcopy(self.b['input']); b['people_subject_json']=self.a['people']['canonical_json']
        s=self.accepted(self.run_bind(self.a,b))
        self.assertIn('REPOSITORY_IDENTITY_MISMATCH',s['coverage_gaps'][0]['reason_codes'])

    def test_report_slot_pin_mismatch(self):
        b=copy.deepcopy(self.b['input']); b['expected']['report_subject_id']='cesrs1:'+'0'*64
        s=self.accepted(self.run_bind(self.a,b))
        self.assertIn('REPORT_SLOT_MISMATCH',s['coverage_gaps'][0]['reason_codes'])

    def test_missing_pins_do_not_allow_unpinned_admission(self):
        for field,reason in [('report_subject_id','REPORT_SLOT_PIN_MISSING'),
                             ('repository_binding_sha256','REPOSITORY_BINDING_PIN_MISSING'),
                             ('people_binding_sha256','PEOPLE_BINDING_PIN_MISSING')]:
            b=copy.deepcopy(self.b['input']); b['expected'][field]=None
            s=self.accepted(self.run_bind(self.a,b))
            with self.subTest(field=field):self.assertIn(reason,s['coverage_gaps'][0]['reason_codes'])

    def test_stale_repository_binding_is_covered_gap(self):
        b=copy.deepcopy(self.b['input']); b['expected']['repository_binding_sha256']='0'*64
        s=self.accepted(self.run_bind(self.a,b))
        self.assertIn('STALE_REPOSITORY_BINDING',s['coverage_gaps'][0]['reason_codes'])

    def test_stale_people_binding_is_covered_gap(self):
        b=copy.deepcopy(self.b['input']); b['expected']['people_binding_sha256']='0'*64
        s=self.accepted(self.run_bind(self.a,b))
        self.assertIn('STALE_PEOPLE_BINDING',s['coverage_gaps'][0]['reason_codes'])

    def test_changed_source_requires_new_expected_pins(self):
        alternative=self.create_row('web', report_key='people-security',source_mode='DeliveredTarget')
        stale=copy.deepcopy(alternative['input']); stale['expected']=copy.deepcopy(self.b['input']['expected'])
        s=self.accepted(self.run_bind(self.a,stale))
        self.assertIn('REPORT_SLOT_MISMATCH',s['coverage_gaps'][0]['reason_codes'])
        self.assertIn('STALE_REPOSITORY_BINDING',s['coverage_gaps'][0]['reason_codes'])

    def test_no_aggregate_permission_without_each_requested_grant(self):
        b=copy.deepcopy(self.b['input']); b['authorization']['granted_operations']=['report.scope.read']
        s=self.accepted(self.run_bind(self.a,b,operation='report.actors.read'))
        self.assertEqual(s['effective_operations'],[])
        self.assertIn('OPERATION_NOT_GRANTED',s['coverage_gaps'][0]['reason_codes'])
        self.assertFalse(s['requested_operation_declared_for_all'])

    def test_dependency_permissions_do_not_auto_expand(self):
        b=copy.deepcopy(self.b['input']); b['authorization']['granted_operations']=['report.evidence.read']
        s=self.accepted(self.run_bind(self.a,b,operation='report.evidence.read'))
        self.assertEqual(s['effective_operations'],[])
        self.assertIn('OPERATION_NOT_GRANTED',s['coverage_gaps'][0]['reason_codes'])

    def test_authorization_missing_is_explicit_gap(self):
        b=copy.deepcopy(self.b['input']); b['authorization']=None
        s=self.accepted(self.run_bind(self.a,b))
        self.assertEqual(s['coverage_gaps'][0]['reason_codes'],['AUTHORIZATION_MISSING'])

    def test_authorization_invalid_and_short_window_are_gaps(self):
        b=copy.deepcopy(self.b['input']); b['authorization']['purpose']='performance_grading'
        s=self.accepted(self.run_bind(self.a,b))
        self.assertEqual(s['coverage_gaps'][0]['reason_codes'],['AUTHORIZATION_INVALID'])
        b=copy.deepcopy(self.b['input']); b['authorization']['valid_until_exclusive_utc']='2026-10-23T12:00:00Z'
        s=self.accepted(self.run_bind(self.a,b))
        self.assertEqual(s['coverage_gaps'][0]['reason_codes'],['AUTHORIZATION_WINDOW_INSUFFICIENT'])

    def test_authorization_receipts_remain_unverified(self):
        s=self.accepted(self.run_bind(self.a,self.b))
        self.assertTrue(all(x['authorization']['state']=='DECLARED_GRANTED_UNVERIFIED' for x in s['repository_set']))
        self.assertFalse(s['claims']['repository_permissions_authenticated'])
        self.assertIn('REPOSITORY_AUTHORIZATION_NOT_AUTHENTICATED',s['global_gaps'])

    def test_partial_period_and_subset_paths_get_explicit_coverage_gaps(self):
        b=self.create_row('web',partial_window=True,path_subset=True,inventory_state='unknown')
        s=self.accepted(self.run_bind(self.a,b))
        self.assertTrue(s['requested_operation_declared_for_all'])
        self.assertEqual(s['coverage_gaps'][0]['reason_codes'],
                         ['PARTIAL_PERIOD_WINDOW','PATH_INVENTORY_UNVERIFIED','SELECTED_PATH_SCOPE'])
        self.assertIn('EXPLICIT_REPOSITORY_SET_HAS_PARTIAL_COVERAGE',s['global_gaps'])

    def test_full_subjects_actors_evidence_and_raw_ids_not_in_output(self):
        s=self.accepted(self.run_bind(self.a,self.b))
        serialized=canonical(s)
        self.assertNotIn('same display across repositories',serialized)
        self.assertNotIn('immutable_subject_id',serialized)
        self.assertNotIn('evidence_refs',serialized)
        self.assertNotIn('identity_scope_sha256',serialized)
        self.assertNotIn(self.a['actor_key'],serialized)

    def test_order_independence_of_repository_set(self):
        x=self.accepted(self.run_bind(self.a,self.b))
        y=self.accepted(self.run_bind(self.b,self.a))
        self.assertEqual(x,y)

    def test_opt_in_same_scope_link_is_only_unverified_proposal(self):
        s=self.accepted(self.run_bind(self.a,self.b, links=[self.link()]))
        self.assertEqual(len(s['actor_link_proposals']),1)
        proposal=s['actor_link_proposals'][0]
        self.assertEqual(proposal['state'],'DECLARED_SAME_SCOPE_UNVERIFIED')
        self.assertEqual(len(proposal['members']),2)
        self.assertRegex(proposal['link_id'],r'^cesrml1:[0-9a-f]{64}$')
        self.assertFalse(s['claims']['cross_repository_actor_identity_authenticated'])
        self.assertEqual(s['actor_link_gaps'],[])

    def test_same_external_scope_does_not_link_without_opt_in(self):
        s=self.accepted(self.run_bind(self.a,self.b))
        self.assertEqual(s['actor_link_proposals'],[])

    def test_link_needs_permission_intersection(self):
        b=copy.deepcopy(self.b['input'])
        b['authorization']['granted_operations']=['report.scope.read','report.actors.read']
        s=self.accepted(self.run_bind(self.a,b,links=[self.link()]))
        self.assertEqual(s['actor_link_proposals'],[])
        self.assertEqual(s['actor_link_gaps'],[{'link_key':'team1',
                                                'reason_code':'LINK_NOT_PERMITTED_FOR_SET'}])

    def test_link_to_gap_repository_does_not_leak_actor(self):
        b=copy.deepcopy(self.b['input']); b.update(availability='MISSING',people_subject_json=None,authorization=None)
        s=self.accepted(self.run_bind(self.a,b,links=[self.link()]))
        self.assertEqual(s['actor_link_proposals'],[])
        self.assertNotIn(self.b['actor_key'],canonical(s))

    def test_link_with_unknown_actor_stays_rejected(self):
        l=self.link(); l['members'][1]['actor_key']='cesra1:'+'0'*64
        s=self.accepted(self.run_bind(self.a,self.b,links=[l]))
        self.assertEqual(s['actor_link_gaps'][0]['reason_code'],'LINK_ACTOR_NOT_ELIGIBLE')
        self.assertNotIn('cesra1:'+'0'*64,canonical(s))

    def test_equal_display_labels_do_not_link_different_identities(self):
        b=self.create_row('web',person='10002')
        l=self.link(self.a,b)
        s=self.accepted(self.run_bind(self.a,b,links=[l]))
        self.assertEqual(s['actor_link_gaps'][0]['reason_code'],'LINK_IDENTITY_SCOPE_MISMATCH')
        self.assertEqual(s['actor_link_proposals'],[])

    def test_missing_person_receipt_prevents_link(self):
        b=self.create_row('web',identity_receipt=False)
        s=self.accepted(self.run_bind(self.a,b,links=[self.link(self.a,b)]))
        self.assertEqual(s['actor_link_gaps'][0]['reason_code'],'LINK_ACTOR_NOT_ELIGIBLE')

    def test_invalid_link_fields_and_duplicate_keys_are_refused(self):
        x=self.link(); y=self.link(); y['receipt_sha256']='e'*64
        self.rejected(self.run_bind(self.a,self.b,links=[x,y]),'DUPLICATE_LINK_KEY')
        x=self.link(); x['members'][1]['repository_id']=x['members'][0]['repository_id']
        self.rejected(self.run_bind(self.a,self.b,links=[x]),'LINK_MEMBERS_MUST_BE_DIFFERENT_REPOSITORIES')

    def test_empty_and_duplicate_repository_sets_refused(self):
        self.rejected(self.run_bind(),'REPOSITORY_SET_INVALID')
        self.rejected(self.run_bind(self.a,self.a),'DUPLICATE_REPOSITORY')

    def test_replay_without_witnesses_is_explicitly_structural_only(self):
        result=self.run_bind(self.a,self.b)
        replay=self.api.from_json(serialized=result['canonical_json'])
        self.assertEqual(list(VALIDATOR.iter_errors(replay)),[],replay)
        self.assertEqual(self.accepted(result),self.accepted(replay))
        self.assertEqual(replay['reason_code'],'CROSS_REPOSITORY_SCOPE_REPLAYED_STRUCTURAL_ONLY')

    def test_replay_with_exact_witnesses_revalidates_EC194_EC193_EC192(self):
        result=self.run_bind(self.a,self.b,links=[self.link()])
        witnesses={x['repo_id']:x['people']['canonical_json'] for x in (self.a,self.b)}
        replay=self.api.from_json(serialized=result['canonical_json'],
                                  people_subject_witnesses=witnesses)
        self.assertEqual(self.accepted(replay),self.accepted(result))
        self.assertEqual(replay['reason_code'],'CROSS_REPOSITORY_SCOPE_REPLAYED_WITH_WITNESSES')

    def test_missing_or_wrong_witness_is_rejected(self):
        result=self.run_bind(self.a,self.b)
        self.rejected(self.api.from_json(serialized=result['canonical_json'],
                                        people_subject_witnesses={self.a['repo_id']:self.a['people']['canonical_json']}),
                      'WITNESSES_SET_MISMATCH')
        witnesses={x['repo_id']:x['people']['canonical_json'] for x in (self.a,self.b)}
        witnesses[self.b['repo_id']]=self.a['people']['canonical_json']
        self.rejected(self.api.from_json(serialized=result['canonical_json'],people_subject_witnesses=witnesses),
                      'WITNESS_BINDING_MISMATCH')

    def test_replay_witness_cannot_import_different_actor_members(self):
        result=self.run_bind(self.a,self.b,links=[self.link()])
        witnesses={x['repo_id']:x['people']['canonical_json'] for x in (self.a,self.b)}
        # Same repo/report slot, but a different person; recomputed PEOPLE binding.
        b2=self.create_row('web',person='10002')
        witnesses[self.b['repo_id']]=b2['people']['canonical_json']
        self.rejected(self.api.from_json(serialized=result['canonical_json'],people_subject_witnesses=witnesses),
                      'WITNESS_BINDING_MISMATCH')

    def test_replay_rejects_changed_intersection_even_with_recomputed_binding(self):
        result=self.run_bind(self.a,self.b)
        d=copy.deepcopy(result['subject']); d['effective_operations']=['report.scope.read']
        from cross_repository_report_scope import _digest
        d['binding_sha256']=_digest('CES-EC195-SCOPE-BINDING-v1',{k:v for k,v in d.items() if k!='binding_sha256'})
        self.rejected(self.api.from_json(serialized=canonical(d)),'PERMISSION_INTERSECTION_INVALID')

    def test_replay_rejects_tampered_source_or_report_slot_even_with_new_binding(self):
        result=self.run_bind(self.a,self.b)
        d=copy.deepcopy(result['subject'])
        d['repository_set'][0]['report']['source_mode']='ProposedPR'
        from cross_repository_report_scope import _digest
        d['binding_sha256']=_digest('CES-EC195-SCOPE-BINDING-v1',{k:v for k,v in d.items() if k!='binding_sha256'})
        self.rejected(self.api.from_json(serialized=canonical(d)))

    def test_replay_rejects_binding_tamper_and_noncannonical_json(self):
        result=self.run_bind(self.a,self.b)
        d=copy.deepcopy(result['subject']); d['binding_sha256']='0'*64
        self.rejected(self.api.from_json(serialized=canonical(d)),'SCOPE_BINDING_INVALID')
        self.rejected(self.api.from_json(serialized=result['canonical_json']+' '),'JSON_NONCANONICAL')

    def test_replay_rejects_duplicate_casefold_keys_and_float(self):
        self.rejected(self.api.from_json(serialized='{"schema":"x","SCHEMA":"y"}'),'JSON_DUPLICATE_KEY')
        self.rejected(self.api.from_json(serialized='{"v":1.0}'),'JSON_FLOAT_FORBIDDEN')

    def test_schema_rejects_extra_fields_and_invented_performance_claim(self):
        result=self.run_bind(self.a)
        mutated=copy.deepcopy(result)
        mutated['subject']['personnel_grade']='A'
        self.assertTrue(list(VALIDATOR.iter_errors(mutated)))
        mutated=copy.deepcopy(result)
        mutated['subject']['claims']['individual_performance_assessed']=True
        self.assertTrue(list(VALIDATOR.iter_errors(mutated)))

    def test_mutated_input_objects_do_not_mutate_result(self):
        a=copy.deepcopy(self.a['input'])
        result=self.run_bind(a)
        a['expected']['people_binding_sha256']='0'*64
        a['authorization']['granted_operations'].clear()
        self.assertEqual(self.accepted(result)['requested_operation'],'report.scope.read')


if __name__ == '__main__':
    unittest.main()
