#!/usr/bin/env python3
"""EC193 focused *development* checks; no live repository/provider/PowerShell tests."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator
from natural_period import NaturalPeriod
from repository_report_subject import RepositoryReportSubject

HERE = Path(__file__).resolve().parent
SCHEMA = json.loads((HERE.parent / 'references' /
                     'repository-report-subject-result.v1.schema.json').read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


class RepositoryReportSubjectTests(unittest.TestCase):
    def setUp(self):
        self.api = RepositoryReportSubject()
        self.period = NaturalPeriod().from_id(period_id='cesnp1:day:UTC:2026-10-23')
        self.assertEqual(self.period['status'], 'partial')
        self.inputs = {
            'period_json': self.period['canonical_json'],
            'report_key': 'repo-activity',
            'repository': {
                'namespace_key': 'divisionA',
                'project_key': 'demo',
                'repository_key': 'api',
                'locator': {'kind': 'local_root', 'value': '/work/demo/api'},
            },
            'source': {
                'mode': 'WorkingTree',
                'selector': {'kind': 'checkout_key', 'key': 'working-main'},
                'git_object': {'algorithm': 'sha1', 'oid': 'a' * 40},
                'receipt_sha256': None,
                'observed_at_utc': '2026-10-24T12:00:00Z',
            },
            'coverage': {
                'window': {
                    'start_utc': self.period['period']['start_utc'],
                    'end_exclusive_utc': self.period['period']['end_exclusive_utc'],
                },
                'includes': [{'kind': 'directory', 'path': 'src'},
                             {'kind': 'file', 'path': 'README.md'}],
                'excludes': [{'kind': 'directory', 'path': 'src/generated'}],
                'inventory_state': 'partial_declared',
            },
        }

    def run_binding(self, **changes):
        x = copy.deepcopy(self.inputs)
        x.update(changes)
        result = self.api.bind(**x)
        self.assertEqual(list(VALIDATOR.iter_errors(result)), [], result)
        return result

    def accepted(self, result):
        self.assertEqual(result['status'], 'partial', result)
        self.assertEqual(result['exit_code'], 2)
        self.assertIsNotNone(result['subject'])
        self.assertIsNotNone(result['canonical_json'])
        self.assertFalse(any(result['limitations'].values()))
        self.assertEqual(json.dumps(result['subject'], sort_keys=True,
                                    ensure_ascii=True, separators=(',', ':')),
                         result['canonical_json'])
        return result['subject']

    def refused(self, result, status='invalid_input', reason=None):
        self.assertEqual(result['status'], status, result)
        self.assertEqual(result['exit_code'], 5 if status == 'unavailable' else 4)
        self.assertIsNone(result['subject'])
        self.assertIsNone(result['canonical_json'])
        self.assertFalse(any(result['limitations'].values()))
        if reason:
            self.assertEqual(result['reason_code'], 'REPORT_SUBJECT_' + reason)

    def test_working_tree_explicit_declared_subset_and_exclusion(self):
        subject = self.accepted(self.run_binding())
        self.assertEqual(subject['schema'], 'ces.repository_report_subject.v1')
        self.assertEqual(subject['repository']['identity_state'], 'CALLER_DECLARED_ONLY')
        self.assertEqual(subject['source']['provenance_state'], 'CALLER_DECLARED_ONLY')
        self.assertEqual(subject['coverage']['path_scope'], 'SELECTED_PATHS')
        self.assertTrue(subject['coverage']['period_window_complete'])
        self.assertIn('PATH_EXCLUSIONS_DECLARED', subject['coverage_gaps'])
        self.assertIn('WORKING_TREE_NOT_ATOMICALLY_PINNED', subject['coverage_gaps'])
        self.assertTrue(all(v is False for v in subject['claims'].values()))
        self.assertNotIn('/work/demo/api', json.dumps(subject))  # locator digest only

    def test_whole_repository_is_explicit_intent_not_real_inventory(self):
        x = copy.deepcopy(self.inputs['coverage'])
        x['includes'] = [{'kind':'repository','path':''}]
        x['excludes'] = []
        x['inventory_state'] = 'complete_declared'
        s = self.accepted(self.run_binding(coverage=x))
        self.assertEqual(s['coverage']['path_scope'], 'ENTIRE_REPOSITORY_DECLARED')
        self.assertNotIn('PATH_SCOPE_SELECTED_SUBSET', s['coverage_gaps'])
        self.assertNotIn('PATH_INVENTORY_NOT_CLAIMED_COMPLETE', s['coverage_gaps'])
        self.assertIn('PATH_INVENTORY_UNVERIFIED', s['coverage_gaps'])
        self.assertFalse(s['claims']['coverage_inventory_verified'])

    def test_delivered_target_explicit_key_still_not_authenticated(self):
        repo = copy.deepcopy(self.inputs['repository'])
        repo['locator'] = {'kind':'remote_repository',
                           'value':'https://git.example.com/team/api'}
        source = copy.deepcopy(self.inputs['source'])
        source['mode'] = 'DeliveredTarget'
        source['selector'] = {'kind':'delivery_key', 'key':'release-2026-10-23'}
        s = self.accepted(self.run_binding(repository=repo, source=source))
        self.assertIn('DELIVERY_NOT_AUTHENTICATED', s['coverage_gaps'])
        self.assertFalse(s['claims']['remote_delivery_verified'])
        self.assertFalse(s['claims']['git_object_verified'])

    def test_proposed_pr_provider_id_cannot_be_promoted_to_delivered(self):
        repo = copy.deepcopy(self.inputs['repository'])
        repo['locator'] = {'kind':'provider_repository_id','value':'github:58392'}
        source = copy.deepcopy(self.inputs['source'])
        source['mode'] = 'ProposedPR'
        source['selector'] = {'kind':'proposal_key', 'key':'pr-17'}
        s = self.accepted(self.run_binding(repository=repo, source=source))
        self.assertIn('PROPOSED_PR_NOT_DELIVERED', s['coverage_gaps'])
        self.assertFalse(s['claims']['remote_delivery_verified'])

    def test_source_kind_mismatch_cannot_relabel_a_pr(self):
        source = copy.deepcopy(self.inputs['source'])
        source['mode'] = 'ProposedPR'
        self.refused(self.run_binding(source=source), reason='SOURCE_SELECTOR_INVALID')

    def test_weak_source_mode_locator_pairs_are_refused(self):
        r = copy.deepcopy(self.inputs['repository'])
        r['locator'] = {'kind':'remote_repository','value':'https://git.example.com/x/y'}
        self.refused(self.run_binding(repository=r), reason='SOURCE_LOCATOR_MODE_MISMATCH')
        s = copy.deepcopy(self.inputs['source'])
        s['mode'] = 'ProposedPR'
        s['selector']['kind'] = 'proposal_key'
        self.refused(self.run_binding(source=s), reason='SOURCE_LOCATOR_MODE_MISMATCH')

    def test_git_sha256_claim_and_receipt_are_unverified(self):
        s = copy.deepcopy(self.inputs['source'])
        s['git_object'] = {'algorithm':'sha256','oid':'b'*64}
        s['receipt_sha256'] = 'c'*64
        result = self.accepted(self.run_binding(source=s))
        self.assertEqual(result['source']['git_object']['algorithm'], 'sha256')
        self.assertIn('SOURCE_RECEIPT_UNVERIFIED', result['coverage_gaps'])
        self.assertFalse(result['claims']['source_provenance_verified'])
        self.assertFalse(result['claims']['git_object_verified'])

    def test_missing_git_claim_is_gap_not_fabricated_sha(self):
        s = copy.deepcopy(self.inputs['source'])
        s['git_object'] = None
        result = self.accepted(self.run_binding(source=s))
        self.assertIn('GIT_OBJECT_CLAIM_MISSING', result['coverage_gaps'])
        self.assertIsNone(result['source']['git_object'])

    def test_git_claims_require_hex_algorithm_and_exact_length(self):
        for obj in ({'algorithm':'sha1','oid':'A'*40},
                    {'algorithm':'sha256','oid':'a'*40},
                    {'algorithm':'sha512','oid':'a'*128},
                    {'algorithm':'sha1','oid':'g'*40},
                    {'algorithm':'sha1','oid':True},
                    {'algorithm':'sha1','oid':'a'*40,'verified':True}):
            s = copy.deepcopy(self.inputs['source'])
            s['git_object'] = obj
            with self.subTest(obj=obj):
                self.refused(self.run_binding(source=s))

    def test_receipt_and_observation_cannot_smuggle_freshness(self):
        s = copy.deepcopy(self.inputs['source'])
        s['receipt_sha256'] = 'A'*64
        self.refused(self.run_binding(source=s), reason='RECEIPT_DIGEST_INVALID')
        for stamp in ('2026-10-23T08:00:00-07:00','2026-10-23T08:00:00',
                      '2026-02-30T00:00:00Z',8,True):
            s = copy.deepcopy(self.inputs['source'])
            s['observed_at_utc'] = stamp
            with self.subTest(stamp=stamp):
                self.refused(self.run_binding(source=s), reason='SOURCE_OBSERVED_TIME_INVALID')

    def test_period_is_replayed_from_real_ec192_canonical_bytes(self):
        result = self.accepted(self.run_binding())
        self.assertEqual(result['period'], self.period['period'])
        period2 = NaturalPeriod().from_id(period_id='cesnp1:day:America/New_York:2026-03-08')
        self.assertEqual(period2['period']['elapsed_seconds'], 82800)
        cov = copy.deepcopy(self.inputs['coverage'])
        cov['window'] = {'start_utc':period2['period']['start_utc'],
                         'end_exclusive_utc':period2['period']['end_exclusive_utc']}
        s = self.accepted(self.run_binding(period_json=period2['canonical_json'],coverage=cov))
        self.assertEqual(s['period']['elapsed_seconds'], 82800)

    def test_bad_period_bytes_fail_closed(self):
        for raw in ('cesnp1:day:UTC:2026-10-23', '{}', '', None,
                    self.period['canonical_json'] + ' ', '[]'):
            with self.subTest(raw=repr(raw)[:30]):
                self.refused(self.run_binding(period_json=raw))

    def test_cross_year_iso_week_period_binding(self):
        p = NaturalPeriod().from_id(period_id='cesnp1:week:Europe/Berlin:2020-W53')
        cov = copy.deepcopy(self.inputs['coverage'])
        cov['window'] = {'start_utc':p['period']['start_utc'],
                         'end_exclusive_utc':p['period']['end_exclusive_utc']}
        s = self.accepted(self.run_binding(period_json=p['canonical_json'],coverage=cov))
        self.assertEqual(s['period']['label'], '2020-W53')
        self.assertEqual(s['period']['actual_end_exclusive_local_date'], '2021-01-04')

    def test_temporal_window_within_period_and_explicit_gap(self):
        c = copy.deepcopy(self.inputs['coverage'])
        c['window']['start_utc'] = '2026-10-23T06:00:00Z'
        c['window']['end_exclusive_utc'] = '2026-10-23T18:00:00Z'
        s = self.accepted(self.run_binding(coverage=c))
        self.assertFalse(s['coverage']['period_window_complete'])
        self.assertIn('WINDOW_PARTIAL_PERIOD', s['coverage_gaps'])
        self.assertEqual(s['coverage']['window'], c['window'])

    def test_out_of_period_or_empty_window_denied(self):
        for left,right in (
            ('2026-10-22T23:59:59Z','2026-10-23T12:00:00Z'),
            ('2026-10-23T12:00:00Z','2026-10-24T00:00:01Z'),
            ('2026-10-23T12:00:00Z','2026-10-23T12:00:00Z'),
            ('2026-10-23T18:00:00Z','2026-10-23T06:00:00Z'),
        ):
            c = copy.deepcopy(self.inputs['coverage'])
            c['window']={'start_utc':left,'end_exclusive_utc':right}
            with self.subTest(left=left,right=right):
                self.refused(self.run_binding(coverage=c),reason='WINDOW_OUTSIDE_PERIOD')

    def test_unsupported_or_naive_coverage_times_denied(self):
        for value in ('2026-10-23T01:00:00+01:00','2026-10-23T01:00:00',
                      '2026-10-23T01:00:00.0Z',None,False):
            c = copy.deepcopy(self.inputs['coverage'])
            c['window']['start_utc'] = value
            with self.subTest(value=value):
                self.refused(self.run_binding(coverage=c),reason='WINDOW_START_INVALID')

    def test_path_coverage_overlapping_inclusions_denied(self):
        for includes in (
            [{'kind':'directory','path':'src'}, {'kind':'file','path':'src/a.py'}],
            [{'kind':'repository','path':''}, {'kind':'directory','path':'src'}],
            [{'kind':'file','path':'Readme.md'}, {'kind':'file','path':'README.md'}],
            [{'kind':'file','path':'src/a.py'}, {'kind':'file','path':'src/a.py'}],
        ):
            c = copy.deepcopy(self.inputs['coverage'])
            c['includes'] = includes
            c['excludes'] = []
            with self.subTest(includes=includes):
                self.refused(self.run_binding(coverage=c),
                             reason='COVERAGE_OVERLAPPING_SELECTORS')

    def test_path_exclusions_must_be_explicit_and_in_scope(self):
        for ex in ([{'kind':'directory','path':'other'}],
                   [{'kind':'file','path':'README.md'}],
                   [{'kind':'repository','path':''}]):
            c = copy.deepcopy(self.inputs['coverage'])
            c['excludes'] = ex
            with self.subTest(ex=ex):
                self.refused(self.run_binding(coverage=c))

    def test_path_traversal_and_ambiguous_spelling_denied(self):
        for p in ('/root/file', '../secret', 'src/../secret', 'src//file',
                  'src/./file', 'a\\b', 'a:b', 'readme%2fsecret',
                  'src/*', 'src/secret\x00', 'src/\u202emalware',
                  'e\u0301.txt','src/', ''):
            c = copy.deepcopy(self.inputs['coverage'])
            c['includes'] = [{'kind':'file','path':p}]
            c['excludes'] = []
            with self.subTest(path=repr(p)):
                self.refused(self.run_binding(coverage=c))

    def test_selector_limit_and_inventory_unknown(self):
        c = copy.deepcopy(self.inputs['coverage'])
        c['includes'] = [{'kind':'file','path':f'file-{i}'} for i in range(65)]
        c['excludes'] = []
        self.refused(self.run_binding(coverage=c),
                     reason='COVERAGE_SELECTOR_COUNT_INVALID')
        c['includes'] = [{'kind':'file','path':'main.py'}]
        c['inventory_state'] = 'asserted_pass'
        self.refused(self.run_binding(coverage=c),reason='INVENTORY_STATE_INVALID')

    def test_sorting_makes_coverage_hash_independent_of_input_order(self):
        initial = self.accepted(self.run_binding())
        c = copy.deepcopy(self.inputs['coverage'])
        c['includes'].reverse()
        self.assertEqual(initial, self.accepted(self.run_binding(coverage=c)))

    def test_changed_coverage_changes_binding_not_stable_subject_slot(self):
        a = self.accepted(self.run_binding())
        c = copy.deepcopy(self.inputs['coverage'])
        c['inventory_state'] = 'complete_declared'
        b = self.accepted(self.run_binding(coverage=c))
        self.assertEqual(a['report_subject_id'], b['report_subject_id'])
        self.assertNotEqual(a['binding_sha256'], b['binding_sha256'])
        self.assertNotEqual(a['coverage']['coverage_sha256'],b['coverage']['coverage_sha256'])

    def test_changed_source_receipt_oid_changes_binding_not_subject_id(self):
        a = self.accepted(self.run_binding())
        s = copy.deepcopy(self.inputs['source'])
        s['git_object']['oid'] = 'd'*40
        s['receipt_sha256'] = 'e'*64
        b = self.accepted(self.run_binding(source=s))
        self.assertEqual(a['report_subject_id'],b['report_subject_id'])
        self.assertNotEqual(a['binding_sha256'],b['binding_sha256'])

    def test_report_type_separates_subject_slots_without_metrics_semantics(self):
        a = self.accepted(self.run_binding())
        b = self.accepted(self.run_binding(report_key='repo-quality'))
        self.assertNotEqual(a['report_subject_id'], b['report_subject_id'])
        self.assertEqual(a['repository']['repository_id'], b['repository']['repository_id'])
        self.refused(self.run_binding(report_key=''), reason='REPORT_KEY_INVALID')

    def test_distinct_project_repository_and_mode_do_not_collapse(self):
        a = self.accepted(self.run_binding())
        for key in ('namespace_key','project_key','repository_key'):
            r = copy.deepcopy(self.inputs['repository'])
            r[key] += '2'
            b = self.accepted(self.run_binding(repository=r))
            self.assertNotEqual(a['repository']['repository_id'],b['repository']['repository_id'])
            self.assertNotEqual(a['report_subject_id'],b['report_subject_id'])
        s = copy.deepcopy(self.inputs['source'])
        s['mode']='DeliveredTarget'
        s['selector']['kind']='delivery_key'
        b = self.accepted(self.run_binding(source=s))
        self.assertNotEqual(a['report_subject_id'],b['report_subject_id'])

    def test_repo_locator_does_not_masquerade_as_logical_identity(self):
        a = self.accepted(self.run_binding())
        r = copy.deepcopy(self.inputs['repository'])
        r['locator']['value'] = '/other/checkout'
        b = self.accepted(self.run_binding(repository=r))
        self.assertEqual(a['repository']['repository_id'], b['repository']['repository_id'])
        self.assertEqual(a['report_subject_id'], b['report_subject_id'])
        self.assertNotEqual(a['repository']['locator_sha256'],b['repository']['locator_sha256'])
        self.assertNotEqual(a['binding_sha256'],b['binding_sha256'])

    def test_local_paths_are_lexical_no_scan_and_support_windows_drive(self):
        for root in ('C:\\work\\api', '/work/my source/api'):
            r = copy.deepcopy(self.inputs['repository'])
            r['locator']['value'] = root
            self.accepted(self.run_binding(repository=r))
        for root in ('relative/root', '/root/../other', '/root//a',
                     'C:relative', 'C:\\repo\\..\\secret',
                     '\\\\unc\\host\\repo', 'C:\\repo\\', '/trailing/',
                     '/', 'C:\\', 'C:\\CON', 'C:\\dir.\\file'):
            r = copy.deepcopy(self.inputs['repository'])
            r['locator']['value'] = root
            with self.subTest(root=root):
                self.refused(self.run_binding(repository=r))

    def test_remote_locator_rejects_secrets_and_ambiguous_urls(self):
        s = copy.deepcopy(self.inputs['source'])
        s['mode']='ProposedPR'
        s['selector']['kind']='proposal_key'
        for url in ('http://git.example.com/acme/repo',
                    'https://alice:secret@git.example.com/acme/repo',
                    'https://git.example.com/acme/repo?token=abc',
                    'https://git.example.com/acme/repo#f',
                    'https://git.example.com/acme/../repo',
                    'https://git.example.com/acme/%2e%2e',
                    'https://git.example.com/acme',
                    'https://git.example.com/acme/repo/'): 
            r = copy.deepcopy(self.inputs['repository'])
            r['locator']={'kind':'remote_repository','value':url}
            with self.subTest(url=url):
                self.refused(self.run_binding(repository=r))

    def test_replay_preserves_full_canonical_subject(self):
        bound = self.run_binding()
        self.accepted(bound)
        replay = self.api.from_json(serialized=bound['canonical_json'])
        self.assertEqual(list(VALIDATOR.iter_errors(replay)), [], replay)
        self.assertEqual(replay['status'],'partial',replay)
        self.assertEqual(replay['subject'],bound['subject'])
        self.assertEqual(replay['canonical_json'],bound['canonical_json'])
        self.assertEqual(replay['reason_code'],'REPORT_SUBJECT_DECLARATION_REVALIDATED')

    def test_replay_rejects_untrusted_noncanonical_json(self):
        raw=self.run_binding()['canonical_json']
        for value in (raw+'\n',' '+raw,raw.upper(), '{}', '[]',None,
                      '"literal"','{"a":1,"a":1}',
                      '{"a": 1e999}',raw*6):
            with self.subTest(value=repr(value)[:50]):
                result=self.api.from_json(serialized=value)
                self.assertEqual(list(VALIDATOR.iter_errors(result)),[],result)
                self.refused(result)

    def test_replay_rejects_forged_claim_or_provenance_or_hash(self):
        original = self.run_binding()['subject']
        for field, value in (
            (('claims','remote_delivery_verified'),True),
            (('source','provenance_state'),'VERIFIED'),
            (('repository','repository_id'),'cesrepo1:'+'0'*64),
            (('coverage','coverage_sha256'),'0'*64),
            (('report_subject_id',),'cesrs1:'+'0'*64),
            (('binding_sha256',),'1'*64),
        ):
            x=copy.deepcopy(original)
            node=x
            for k in field[:-1]:
                node=node[k]
            node[field[-1]]=value
            with self.subTest(field=field):
                result=self.api.from_json(serialized=json.dumps(x,sort_keys=True,
                                                   ensure_ascii=True,separators=(',',':')))
                self.assertEqual(list(VALIDATOR.iter_errors(result)),[],result)
                self.refused(result)

    def test_replay_revalidates_original_ec192_period_interval(self):
        x=copy.deepcopy(self.run_binding()['subject'])
        x['period']['start_utc']='2026-10-23T01:00:00Z'
        raw=json.dumps(x,sort_keys=True,ensure_ascii=True,separators=(',',':'))
        self.refused(self.api.from_json(serialized=raw))

    def test_extraneous_fields_and_input_type_denied(self):
        r=copy.deepcopy(self.inputs['repository'])
        r['verified']=True
        self.refused(self.run_binding(repository=r),reason='REPOSITORY_FIELDS_INVALID')
        r=copy.deepcopy(self.inputs['repository'])
        r['namespace_key']=42
        self.refused(self.run_binding(repository=r),reason='REPOSITORY_KEY_INVALID')
        c=copy.deepcopy(self.inputs['coverage'])
        c['includes'] = None
        self.refused(self.run_binding(coverage=c))


if __name__ == '__main__':
    unittest.main()
