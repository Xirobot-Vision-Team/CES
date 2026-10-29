#!/usr/bin/env python3
"""EC194 focused development checks; no live identity/provider/native tests."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from natural_period import NaturalPeriod
from repository_report_subject import RepositoryReportSubject
from actor_report_subject import ActorReportSubject

HERE = Path(__file__).resolve().parent
SCHEMA = json.loads((HERE.parent / 'references' /
                     'actor-report-subject-result.v1.schema.json').read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


class ActorReportSubjectTests(unittest.TestCase):
    def setUp(self):
        period = NaturalPeriod().from_id(period_id='cesnp1:day:UTC:2026-10-23')
        self.assertEqual(period['status'], 'partial')
        repo = RepositoryReportSubject().bind(
            period_json=period['canonical_json'],
            repository={
                'namespace_key': 'divisionA', 'project_key': 'demo',
                'repository_key': 'api',
                'locator': {'kind': 'local_root', 'value': '/work/demo/api'},
            },
            report_key='people-activity',
            source={
                'mode': 'WorkingTree',
                'selector': {'kind': 'checkout_key', 'key': 'working-main'},
                'git_object': {'algorithm': 'sha1', 'oid': 'a' * 40},
                'receipt_sha256': None,
                'observed_at_utc': '2026-10-24T12:00:00Z',
            },
            coverage={
                'window': {'start_utc': period['period']['start_utc'],
                           'end_exclusive_utc': period['period']['end_exclusive_utc']},
                'includes': [{'kind': 'repository', 'path': ''}],
                'excludes': [], 'inventory_state': 'partial_declared',
            },
        )
        self.assertEqual(repo['status'], 'partial')
        self.repo = repo
        self.repo_subject = repo['subject']
        self.api = ActorReportSubject()
        self.alex = {
            'identity': {'authority': 'github', 'tenant': 'acme',
                         'immutable_subject_id': '10001'},
            'display_label': 'Alex',
            'identity_receipt_sha256': '1' * 64,
            'authorization': {
                'purpose': 'periodic_repository_report',
                'receipt_sha256': '2' * 64,
                'valid_from_utc': '2026-10-23T00:00:00Z',
                'valid_until_exclusive_utc': '2026-10-24T00:00:00Z',
            },
        }
        self.sam = copy.deepcopy(self.alex)
        self.sam['identity']['immutable_subject_id'] = '10002'
        self.sam['display_label'] = 'Sam'
        self.sam['identity_receipt_sha256'] = None
        self.sam['authorization']['receipt_sha256'] = '3' * 64
        self.evidence = [{
            'evidence_id': 'evt-001',
            'identity': copy.deepcopy(self.alex['identity']),
            'occurred_at_utc': '2026-10-23T12:00:00Z',
            'repository_id': self.repo_subject['repository']['repository_id'],
            'report_subject_id': self.repo_subject['report_subject_id'],
            'source_binding_sha256': self.repo_subject['binding_sha256'],
            'evidence_sha256': '4' * 64,
        }]

    def run_bind(self, actors=None, evidence=None, repository_subject_json=None):
        result = self.api.bind(
            repository_subject_json=(repository_subject_json if repository_subject_json is not None
                                     else self.repo['canonical_json']),
            actors=copy.deepcopy([self.alex] if actors is None else actors),
            evidence=copy.deepcopy(self.evidence if evidence is None else evidence),
        )
        self.assertEqual(list(VALIDATOR.iter_errors(result)), [], result)
        return result

    def accepted(self, result):
        self.assertEqual(result['status'], 'partial', result)
        self.assertEqual(result['exit_code'], 2)
        self.assertIsNotNone(result['subject'])
        self.assertEqual(json.dumps(result['subject'], sort_keys=True,
                                    ensure_ascii=True, separators=(',', ':')),
                         result['canonical_json'])
        self.assertFalse(any(result['limitations'].values()))
        return result['subject']

    def refused(self, result, reason=None, status='invalid_input'):
        self.assertEqual(result['status'], status, result)
        self.assertEqual(result['exit_code'], 5 if status == 'unavailable' else 4)
        self.assertIsNone(result['subject'])
        self.assertIsNone(result['canonical_json'])
        if reason:
            self.assertEqual(result['reason_code'], 'ACTOR_REPORT_SUBJECT_' + reason)

    def test_known_actor_is_bound_only_by_stable_scoped_identity(self):
        s = self.accepted(self.run_bind())
        self.assertEqual(s['schema'], 'ces.actor_report_subject.v1')
        self.assertRegex(s['actors'][0]['actor_key'], r'^cesra1:[0-9a-f]{64}$')
        self.assertEqual(len(s['actors'][0]['evidence_refs']), 1)
        self.assertEqual(s['unattributed_evidence'], [])
        self.assertEqual(s['actors'][0]['identity_state'],
                         'DECLARED_STABLE_SCOPE_UNVERIFIED_RECEIPT')
        self.assertFalse(s['claims']['actor_identity_authenticated'])
        self.assertFalse(s['claims']['personal_performance_assessed'])
        self.assertEqual(s['repository_subject'], self.repo_subject)

    def test_same_display_name_never_collapses_distinct_identities(self):
        b = copy.deepcopy(self.sam)
        b['display_label'] = 'Alex'
        s = self.accepted(self.run_bind(actors=[self.alex, b], evidence=[]))
        self.assertEqual(len(s['actors']), 2)
        self.assertNotEqual(s['actors'][0]['actor_key'], s['actors'][1]['actor_key'])
        self.assertEqual(s['actors'][0]['display_label_sha256'],
                         s['actors'][1]['display_label_sha256'])

    def test_display_label_change_does_not_change_actor_key(self):
        a = self.accepted(self.run_bind(evidence=[]))['actors'][0]
        x = copy.deepcopy(self.alex)
        x['display_label'] = 'Renamed Person'
        b = self.accepted(self.run_bind(actors=[x], evidence=[]))['actors'][0]
        self.assertEqual(a['actor_key'], b['actor_key'])
        self.assertNotEqual(a['display_label_sha256'], b['display_label_sha256'])

    def test_same_external_identity_is_repository_scoped(self):
        period = NaturalPeriod().from_id(period_id='cesnp1:day:UTC:2026-10-23')
        other = RepositoryReportSubject().bind(
            period_json=period['canonical_json'],
            repository={'namespace_key':'divisionA','project_key':'demo',
                        'repository_key':'web',
                        'locator':{'kind':'local_root','value':'/work/demo/web'}},
            report_key='people-activity',
            source={'mode':'WorkingTree','selector':{'kind':'checkout_key','key':'working-main'},
                    'git_object':None,'receipt_sha256':None,'observed_at_utc':None},
            coverage={'window':{'start_utc':'2026-10-23T00:00:00Z',
                                'end_exclusive_utc':'2026-10-24T00:00:00Z'},
                      'includes':[{'kind':'repository','path':''}],
                      'excludes':[],'inventory_state':'unknown'})
        a = self.accepted(self.run_bind(evidence=[]))['actors'][0]['actor_key']
        b = self.accepted(self.run_bind(repository_subject_json=other['canonical_json'],
                                        evidence=[]))['actors'][0]['actor_key']
        self.assertNotEqual(a, b)

    def test_same_repo_actor_key_is_stable_across_report_periods(self):
        p = NaturalPeriod().from_id(period_id='cesnp1:day:UTC:2026-10-24')
        r = RepositoryReportSubject().bind(
            period_json=p['canonical_json'],
            repository={'namespace_key':'divisionA','project_key':'demo','repository_key':'api',
                        'locator':{'kind':'local_root','value':'/other/clone/api'}},
            report_key='people-activity',
            source={'mode':'WorkingTree','selector':{'kind':'checkout_key','key':'working-main'},
                    'git_object':None,'receipt_sha256':None,'observed_at_utc':None},
            coverage={'window':{'start_utc':'2026-10-24T00:00:00Z',
                                'end_exclusive_utc':'2026-10-25T00:00:00Z'},
                      'includes':[{'kind':'repository','path':''}],
                      'excludes':[],'inventory_state':'unknown'})
        actor = copy.deepcopy(self.alex)
        actor['authorization']['valid_from_utc'] = '2026-10-24T00:00:00Z'
        actor['authorization']['valid_until_exclusive_utc'] = '2026-10-25T00:00:00Z'
        a = self.accepted(self.run_bind(evidence=[]))['actors'][0]['actor_key']
        b = self.accepted(self.run_bind(repository_subject_json=r['canonical_json'],
                                        actors=[actor], evidence=[]))['actors'][0]['actor_key']
        self.assertEqual(a, b)

    def test_unknown_identity_is_not_merged_into_any_actor(self):
        e = copy.deepcopy(self.evidence[0])
        e['identity'] = None
        s = self.accepted(self.run_bind(evidence=[e]))
        self.assertEqual(s['actors'][0]['evidence_refs'], [])
        self.assertEqual(s['unattributed_evidence'][0]['reason_code'],
                         'ACTOR_IDENTITY_MISSING')
        self.assertIn('UNATTRIBUTED_EVIDENCE_PRESENT', s['coverage_gaps'])

    def test_known_but_unauthorized_identity_is_withheld_not_auto_added(self):
        e = copy.deepcopy(self.evidence[0])
        e['identity'] = copy.deepcopy(self.sam['identity'])
        s = self.accepted(self.run_bind(evidence=[e]))
        self.assertEqual(len(s['actors']), 1)
        self.assertEqual(s['actors'][0]['evidence_refs'], [])
        self.assertEqual(s['unattributed_evidence'][0]['reason_code'],
                         'ACTOR_NOT_AUTHORIZED_OR_DECLARED')
        self.assertNotIn('10002', json.dumps(s))

    def test_actor_identity_raw_values_and_display_labels_are_not_serialized(self):
        s = self.accepted(self.run_bind())
        raw = json.dumps(s)
        for secretish in ('github', 'acme', '10001', 'Alex'):
            self.assertNotIn(secretish, raw)

    def test_email_username_or_display_name_fields_cannot_be_identity_aliases(self):
        for field,value in (('email','alex@example.com'),
                            ('username','alex'),
                            ('display_name','Alex')):
            a = copy.deepcopy(self.alex)
            a['identity'][field] = value
            with self.subTest(field=field):
                self.refused(self.run_bind(actors=[a], evidence=[]),
                             reason='IDENTITY_FIELDS_INVALID')

    def test_identity_tuple_requires_exact_fields_and_nfc(self):
        cases = [
            {'authority':'GitHub','tenant':'acme','immutable_subject_id':'1'},
            {'authority':'github','tenant':'e\u0301','immutable_subject_id':'1'},
            {'authority':'github','tenant':'acme','immutable_subject_id':'1','name':'x'},
            {'authority':'github','tenant':'','immutable_subject_id':'1'},
        ]
        for ident in cases:
            a = copy.deepcopy(self.alex); a['identity'] = ident
            with self.subTest(ident=ident): self.refused(self.run_bind(actors=[a], evidence=[]))

    def test_duplicate_identity_is_refused_even_with_different_label(self):
        b = copy.deepcopy(self.alex); b['display_label'] = 'Someone Else'
        self.refused(self.run_bind(actors=[self.alex, b], evidence=[]),
                     reason='DUPLICATE_ACTOR_IDENTITY')

    def test_authorization_is_explicit_and_must_cover_report_window(self):
        for left,right in (('2026-10-23T01:00:00Z','2026-10-24T00:00:00Z'),
                           ('2026-10-23T00:00:00Z','2026-10-23T23:59:59Z'),
                           ('2026-10-24T00:00:00Z','2026-10-24T00:00:00Z')):
            a = copy.deepcopy(self.alex)
            a['authorization']['valid_from_utc'] = left
            a['authorization']['valid_until_exclusive_utc'] = right
            with self.subTest(left=left,right=right):
                self.refused(self.run_bind(actors=[a], evidence=[]))

    def test_authorization_wrong_purpose_or_receipt_is_refused(self):
        a = copy.deepcopy(self.alex); a['authorization']['purpose'] = 'performance_review'
        self.refused(self.run_bind(actors=[a], evidence=[]), reason='AUTHORIZATION_PURPOSE_INVALID')
        a = copy.deepcopy(self.alex); a['authorization']['receipt_sha256'] = 'A' * 64
        self.refused(self.run_bind(actors=[a], evidence=[]), reason='AUTHORIZATION_RECEIPT_INVALID')

    def test_authorization_receipt_never_becomes_authenticated(self):
        s = self.accepted(self.run_bind())
        self.assertEqual(s['actors'][0]['authorization']['state'],
                         'DECLARED_GRANTED_UNVERIFIED')
        self.assertIn('ACTOR_AUTHORIZATION_NOT_AUTHENTICATED', s['coverage_gaps'])
        self.assertFalse(s['claims']['actor_authorization_authenticated'])

    def test_missing_identity_receipt_is_gap_not_fabricated_proof(self):
        s = self.accepted(self.run_bind(actors=[self.sam], evidence=[]))
        self.assertIsNone(s['actors'][0]['identity_receipt_sha256'])
        self.assertIn('ACTOR_IDENTITY_RECEIPT_MISSING', s['coverage_gaps'])


    def test_missing_identity_receipt_blocks_evidence_attribution(self):
        e = copy.deepcopy(self.evidence[0])
        e['identity'] = copy.deepcopy(self.sam['identity'])
        s = self.accepted(self.run_bind(actors=[self.sam], evidence=[e]))
        self.assertEqual(s['actors'][0]['evidence_refs'], [])
        self.assertEqual(s['actors'][0]['identity_state'],
                         'DECLARED_STABLE_SCOPE_UNVERIFIED_NO_RECEIPT')
        self.assertEqual(s['unattributed_evidence'][0]['reason_code'],
                         'ACTOR_IDENTITY_PROOF_MISSING')
        self.assertIn('ACTOR_IDENTITY_RECEIPT_MISSING', s['coverage_gaps'])

    def test_evidence_requires_exact_repository_report_and_source_binding(self):
        for field,value,reason in (
            ('repository_id','cesrepo1:' + '0'*64,'EVIDENCE_REPOSITORY_MISMATCH'),
            ('report_subject_id','cesrs1:' + '0'*64,'EVIDENCE_REPORT_SUBJECT_MISMATCH'),
            ('source_binding_sha256','0'*64,'EVIDENCE_SOURCE_BINDING_MISMATCH'),
        ):
            e = copy.deepcopy(self.evidence[0]); e[field] = value
            with self.subTest(field=field): self.refused(self.run_bind(evidence=[e]), reason=reason)

    def test_evidence_must_be_inside_exact_ec193_coverage_window(self):
        for stamp in ('2026-10-22T23:59:59Z','2026-10-24T00:00:00Z'):
            e = copy.deepcopy(self.evidence[0]); e['occurred_at_utc'] = stamp
            with self.subTest(stamp=stamp):
                self.refused(self.run_bind(evidence=[e]), reason='EVIDENCE_OUTSIDE_REPORT_WINDOW')

    def test_evidence_time_and_digest_formats_are_strict(self):
        e = copy.deepcopy(self.evidence[0]); e['occurred_at_utc'] = '2026-10-23T12:00:00-00:00'
        self.refused(self.run_bind(evidence=[e]), reason='EVIDENCE_TIME_INVALID')
        e = copy.deepcopy(self.evidence[0]); e['evidence_sha256'] = 'F' * 64
        self.refused(self.run_bind(evidence=[e]), reason='EVIDENCE_DIGEST_INVALID')

    def test_duplicate_evidence_id_is_refused(self):
        e2 = copy.deepcopy(self.evidence[0]); e2['evidence_sha256'] = '5' * 64
        self.refused(self.run_bind(evidence=self.evidence + [e2]), reason='DUPLICATE_EVIDENCE_ID')

    def test_evidence_and_actor_input_order_do_not_change_canonical_subject(self):
        a2 = copy.deepcopy(self.sam)
        e2 = copy.deepcopy(self.evidence[0])
        e2.update(evidence_id='evt-002', identity=copy.deepcopy(self.sam['identity']),
                  occurred_at_utc='2026-10-23T11:00:00Z', evidence_sha256='5'*64)
        s1 = self.accepted(self.run_bind(actors=[self.alex,a2], evidence=[self.evidence[0],e2]))
        s2 = self.accepted(self.run_bind(actors=[a2,self.alex], evidence=[e2,self.evidence[0]]))
        self.assertEqual(s1, s2)

    def test_no_evidence_is_not_interpreted_as_no_contribution(self):
        s = self.accepted(self.run_bind(evidence=[]))
        self.assertIn('NO_CONTRIBUTION_EVIDENCE_DECLARED', s['coverage_gaps'])
        self.assertFalse(s['claims']['complete_contribution_coverage_verified'])

    def test_no_authorized_actor_with_unknown_evidence_is_partial_and_explicit(self):
        e = copy.deepcopy(self.evidence[0]); e['identity'] = None
        s = self.accepted(self.run_bind(actors=[], evidence=[e]))
        self.assertEqual(s['actors'], [])
        self.assertIn('NO_AUTHORIZED_ACTOR_SUBJECTS', s['coverage_gaps'])
        self.assertEqual(len(s['unattributed_evidence']), 1)

    def test_empty_people_subject_is_refused(self):
        self.refused(self.run_bind(actors=[], evidence=[]), reason='EMPTY_PEOPLE_REPORT_SUBJECT')

    def test_actor_and_evidence_limits_are_bounded(self):
        many = []
        for i in range(129):
            a = copy.deepcopy(self.alex)
            a['identity']['immutable_subject_id'] = str(20000+i)
            a['authorization']['receipt_sha256'] = f'{i:064x}'[-64:]
            many.append(a)
        self.refused(self.run_bind(actors=many, evidence=[]), reason='ACTOR_LIST_INVALID')
        ev = [copy.deepcopy(self.evidence[0]) for _ in range(1025)]
        self.refused(self.run_bind(evidence=ev), reason='EVIDENCE_LIST_INVALID')

    def test_repository_subject_is_replayed_not_just_trusted_as_json(self):
        data = json.loads(self.repo['canonical_json'])
        data['binding_sha256'] = '0' * 64
        raw = json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
        self.refused(self.run_bind(repository_subject_json=raw))

    def test_from_json_round_trip_replays_ec193_and_actor_hashes(self):
        result = self.run_bind(actors=[self.alex,self.sam], evidence=[])
        subject = self.accepted(result)
        replay = self.api.from_json(serialized=result['canonical_json'])
        self.assertEqual(list(VALIDATOR.iter_errors(replay)), [], replay)
        self.assertEqual(self.accepted(replay), subject)
        self.assertEqual(replay['reason_code'], 'ACTOR_REPORT_SUBJECT_REVALIDATED')

    def test_from_json_refuses_noncanonical_and_duplicate_keys(self):
        result = self.run_bind(evidence=[])
        self.refused(self.api.from_json(serialized=result['canonical_json'] + ' '),
                     reason='JSON_NONCANONICAL')
        raw = '{"schema":"x","schema":"y"}'
        self.refused(self.api.from_json(serialized=raw), reason='JSON_DUPLICATE_KEY')

    def test_from_json_refuses_tampered_actor_key(self):
        result = self.run_bind(evidence=[])
        data = json.loads(result['canonical_json'])
        data['actors'][0]['actor_key'] = 'cesra1:' + '0' * 64
        raw = json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
        self.refused(self.api.from_json(serialized=raw), reason='ACTOR_KEY_BINDING_INVALID')

    def test_from_json_refuses_tampered_authorization_binding(self):
        result = self.run_bind(evidence=[])
        data = json.loads(result['canonical_json'])
        data['actors'][0]['authorization']['authorization_binding_sha256'] = '0' * 64
        raw = json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
        self.refused(self.api.from_json(serialized=raw), reason='AUTHORIZATION_BINDING_INVALID')

    def test_from_json_refuses_tampered_binding_digest(self):
        result = self.run_bind(evidence=[])
        data = json.loads(result['canonical_json'])
        data['binding_sha256'] = '0' * 64
        raw = json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
        self.refused(self.api.from_json(serialized=raw), reason='BINDING_DIGEST_INVALID')

    def test_binding_changes_with_auth_or_evidence_but_people_slot_stays_stable(self):
        a = self.accepted(self.run_bind(evidence=[]))
        x = copy.deepcopy(self.alex); x['authorization']['receipt_sha256'] = '9'*64
        b = self.accepted(self.run_bind(actors=[x], evidence=[]))
        self.assertEqual(a['people_subject_id'], b['people_subject_id'])
        self.assertEqual(a['actors'][0]['actor_key'], b['actors'][0]['actor_key'])
        self.assertNotEqual(a['binding_sha256'], b['binding_sha256'])
        c = self.accepted(self.run_bind())
        self.assertEqual(a['people_subject_id'], c['people_subject_id'])
        self.assertNotEqual(a['binding_sha256'], c['binding_sha256'])

    def test_changed_report_key_changes_people_subject_not_repo_actor_key(self):
        p = NaturalPeriod().from_id(period_id='cesnp1:day:UTC:2026-10-23')
        alt = RepositoryReportSubject().bind(
            period_json=p['canonical_json'],
            repository={'namespace_key':'divisionA','project_key':'demo','repository_key':'api',
                        'locator':{'kind':'local_root','value':'/work/demo/api'}},
            report_key='security-people',
            source={'mode':'WorkingTree','selector':{'kind':'checkout_key','key':'working-main'},
                    'git_object':{'algorithm':'sha1','oid':'a'*40},
                    'receipt_sha256':None,'observed_at_utc':'2026-10-24T12:00:00Z'},
            coverage={'window':{'start_utc':'2026-10-23T00:00:00Z',
                                'end_exclusive_utc':'2026-10-24T00:00:00Z'},
                      'includes':[{'kind':'repository','path':''}],
                      'excludes':[],'inventory_state':'partial_declared'})
        a = self.accepted(self.run_bind(evidence=[]))
        b = self.accepted(self.run_bind(repository_subject_json=alt['canonical_json'], evidence=[]))
        self.assertNotEqual(a['people_subject_id'], b['people_subject_id'])
        self.assertEqual(a['actors'][0]['actor_key'], b['actors'][0]['actor_key'])

    def test_schema_rejects_extra_output_fields(self):
        result = self.run_bind(evidence=[])
        mutated = copy.deepcopy(result); mutated['subject']['grade'] = 'A'
        self.assertTrue(list(VALIDATOR.iter_errors(mutated)))


if __name__ == '__main__':
    unittest.main()
