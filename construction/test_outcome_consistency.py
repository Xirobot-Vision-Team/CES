#!/usr/bin/env python3
"""EC243 focused status/coverage semantics; no enterprise/native acceptance."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from outcome_consistency import (CLAIMED_SUCCESS, STATUS_EXITS,
                                 normalize_handler, normalize_router_rejection)
from unified_action_router import (REQUEST_SCHEMA, SCHEMA, ROUTES, LEGACY,
                                   dispatch, inventory)

ROOT = Path(__file__).resolve().parent.parent


class NormalizerTests(unittest.TestCase):
    def norm(self, status, code=None, **extra):
        data = {'status': status, **extra}
        return normalize_handler(data, exit_code=code, handler_status=status)

    def test_all_five_status_families_are_fixed(self):
        pairs = (('partial', 2, 'partial'), ('OFFLINE', 3, 'offline'),
                 ('permission_denied', 3, 'denied'),
                 ('invalid_input', 4, 'invalid'),
                 ('UNKNOWN_BLOCKED', 5, 'unavailable'))
        for status, code, normalized in pairs:
            with self.subTest(status=status):
                r = self.norm(status, code)
                self.assertEqual(r.status, normalized)
                self.assertEqual(r.exit_code, code)
                self.assertTrue(r.handler_outcome_consistent)

    def test_stated_success_is_only_a_partial_unverified_observation(self):
        for status in sorted(CLAIMED_SUCCESS):
            with self.subTest(status=status):
                r = self.norm(status, 0)
                self.assertEqual(r.status, 'partial')
                self.assertEqual(r.exit_code, 2)
                self.assertEqual(r.reason_code, 'ROUTER_HANDLER_SUCCESS_CLAIM_NOT_BUSINESS_PROOF')

    def test_unknown_and_missing_status_are_not_success(self):
        for status in (None, 'INVENTED_SUCCESS', 'metadata_inspected', 'DAG_REVIEW_ONLY'):
            with self.subTest(status=status):
                r = normalize_handler({}, exit_code=0, handler_status=status)
                self.assertEqual(r.status, 'partial')
                self.assertEqual(r.exit_code, 2)

    def test_positive_status_with_negative_exit_cannot_be_success(self):
        for code, category in ((3, 'denied'), (4, 'invalid'), (5, 'unavailable')):
            with self.subTest(code=code):
                r = self.norm('success', code)
                self.assertEqual(r.status, category)
                self.assertFalse(r.handler_outcome_consistent)
                self.assertEqual(r.reason_code, 'ROUTER_HANDLER_STATUS_EXIT_INCONSISTENT')

    def test_declared_status_negative_without_negative_exit_is_not_lost(self):
        r = self.norm('invalid_input', 0)
        self.assertEqual((r.status, r.exit_code), ('invalid', 4))
        self.assertFalse(r.handler_outcome_consistent)

    def test_abnormal_exit_and_conflicting_declared_exit_fail_closed(self):
        for abnormal in (-9, 42, 255, True, '0'):
            with self.subTest(code=abnormal):
                r = self.norm('success', abnormal)
                self.assertEqual((r.status, r.exit_code), ('unavailable', 5))
                self.assertFalse(r.handler_outcome_consistent)
        bad = self.norm('success', 0, exit_code=4)
        self.assertEqual(bad.reason_code, 'ROUTER_HANDLER_EXIT_CONFLICT')
        self.assertEqual(bad.exit_code, 5)

    def test_declared_exit_malformed_is_not_accepted(self):
        for value in (True, '2', -3, 7, None):
            with self.subTest(value=value):
                r = self.norm('partial', 2, exit_code=value)
                self.assertEqual(r.status, 'unavailable')

    def test_malformed_handler_status_is_unavailable(self):
        for status in (5, [], {}, 'z' * 161):
            with self.subTest(status=type(status).__name__):
                r = normalize_handler({}, exit_code=0, handler_status=status)
                self.assertEqual(r.status, 'unavailable')
                self.assertFalse(r.handler_outcome_consistent)

    def test_coverage_missing_false_flags_are_claims_not_proof(self):
        r = self.norm('partial', 2, coverage={
            'source_identity_bound': True,
            'path_inventory_complete': False,
            'content_released': False,
            'content_complete_for_selected_source': None,
            'missing_requirements': ['SENSITIVE/PRIVATE/PATH']})
        self.assertEqual(r.coverage_assessment, 'DECLARED_GAPS_UNVERIFIED')
        self.assertEqual(r.coverage_missing_claims,
                         ('path_inventory_complete', 'content_released'))
        self.assertNotIn('SENSITIVE', repr(r))

    def test_empty_or_fake_complete_coverage_not_attestation(self):
        for cv in (None, {}, {'source_currentness_proven': True}):
            with self.subTest(cv=cv):
                r = self.norm('success', 0, coverage=cv)
                self.assertEqual(r.coverage_assessment, 'NOT_ATTESTED_BY_ROUTER')
        r = self.norm('partial', 2, coverage={'missing_requirements': ['NOT_READ']})
        self.assertEqual(r.coverage_assessment, 'PARTIAL_OR_INCOMPLETE_UNVERIFIED')

    def test_rejections_never_fake_handler_invocation(self):
        for raw, normalized in (('invalid_input','invalid'),('permission_denied','denied'),
                                ('not_implemented','denied'),('legacy_native_only','denied'),
                                ('offline','offline'),('unavailable','unavailable'),
                                ('anything_else','unavailable')):
            r = normalize_router_rejection(status=raw, reason_code='TEST_UNCALLED')
            self.assertEqual(r.status,normalized)
            self.assertEqual(r.exit_code, STATUS_EXITS[normalized])
            self.assertEqual(r.coverage_assessment, 'NOT_OBSERVED_NO_VALID_HANDLER_RESULT')


class RealRouterTests(unittest.TestCase):
    def call(self, action, mode, **options):
        return dispatch(action, mode, {'schema': REQUEST_SCHEMA, 'action': action,
                                       'mode': mode, **options})

    def test_no_handler_route_and_host_only_never_success(self):
        for a,m in [('UnknownEC243','Pretend'),('IssueCreate','Create'),
                    ('CodeSave','Snapshot'),('QualityRun','Execute')]:
            with self.subTest(a=a,m=m):
                out,code=self.call(a,m)
                self.assertEqual((out['status'],code),('denied',3))
                self.assertFalse(out['handler_invoked'])
                self.assertFalse(out['handler_attempted'])
                self.assertIsNone(out['handler_result'])
                self.assertFalse(out['business_effect_verified'])
                self.assertEqual(out['normalized_exit_code'],code)

    def test_real_partial_and_invalid_calendar_normalize(self):
        good,code = self.call('Due','Evaluate',parameters={
            'project_timezone':'UTC','cadence':'day',
            'observed_at':'2026-10-24T10:00:00Z','never_processed':True})
        self.assertEqual((good['status'],code),('partial',2))
        self.assertEqual(good['handler_status'],'partial')
        self.assertEqual(good['handler_result']['decision']['state'],'DUE')
        self.assertFalse(good['tasks_advanced_by_router'])
        bad,code = self.call('Due','Evaluate',parameters={
            'project_timezone':'UTC','cadence':'INVALID'})
        self.assertEqual((bad['status'],code),('invalid',4))
        self.assertTrue(bad['handler_invoked'])
        self.assertEqual(bad['handler_status'],'invalid_input')

    def test_real_schema_inventory_audit_are_not_business_acceptance(self):
        for mode in ('Inventory','Audit'):
            with self.subTest(mode=mode):
                out,code=self.call('SchemaReview',mode,argv=[])
                self.assertEqual((out['status'],code),('partial',2))
                self.assertEqual(out['handler_result']['schema'],
                                 'ces.schema_migration_review.v1')
                self.assertFalse(out['business_effect_verified'])
                self.assertTrue(out['handler_invoked'])
                if mode=='Audit':
                    self.assertEqual(out['handler_result']['reason_code'],
                                     'KNOWN_LEGACY_SCHEMA_DEBT')
                    self.assertEqual(out['handler_result']['data']['drift_count'],0)

    def test_missing_cycle_run_is_unknown_not_created_or_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700)
            out,code=self.call('Cycle','Summary',argv=[
                '--store',tmp,'--run-id','run_v1_'+'a'*48])
        self.assertEqual((out['status'],code),('unavailable',5))
        self.assertFalse(out['business_effect_verified'])
        self.assertEqual(out['handler_result']['status'],'UNKNOWN_BLOCKED')

    def test_real_prepare_missing_local_input_keeps_explicit_coverage_gap(self):
        out,code=self.call('CodePrepare','MultiSource',argv=[
            '--source-mode','WorkingTree'])
        self.assertEqual((out['status'],code),('invalid',4))
        self.assertEqual(out['coverage_assessment'],'DECLARED_GAPS_UNVERIFIED')
        self.assertIn('content_released',out['coverage_missing_claims'])

    def test_malformed_cli_output_records_attempt_but_no_valid_result(self):
        def duplicate_status(cmd, *, stdout, **kwargs):
            stdout.write(b'{"status":"success","Status":"invalid_input"}')
            return subprocess.CompletedProcess(cmd,0)
        with mock.patch('unified_action_router.subprocess.run',side_effect=duplicate_status):
            out,code=self.call('SchemaReview','Inventory',argv=[])
        self.assertEqual((out['status'],code),('unavailable',5))
        self.assertTrue(out['handler_attempted'])
        self.assertFalse(out['handler_invoked'])
        self.assertIsNone(out['handler_result'])
        self.assertEqual(out['reason_code'],'ROUTER_HANDLER_NONJSON_OUTPUT')

    def test_synthetic_offline_exit_is_classified_at_actual_router_boundary(self):
        def offline(cmd, *, stdout, **kwargs):
            stdout.write(b'{"status":"OFFLINE","exit_code":3,"reason_code":"HOST_NETWORK_DISABLED"}')
            return subprocess.CompletedProcess(cmd,3)
        with mock.patch('unified_action_router.subprocess.run',side_effect=offline):
            out,code=self.call('SchemaReview','Inventory',argv=[])
        self.assertEqual((out['status'],code),('offline',3))
        self.assertEqual(out['handler_status'],'OFFLINE')
        self.assertTrue(out['handler_outcome_consistent'])
        self.assertFalse(out['business_effect_verified'])

    def test_synthetic_conflicting_child_status_and_exit_no_promotion(self):
        def contradictory(cmd, *, stdout, **kwargs):
            stdout.write(b'{"status":"success","exit_code":4}')
            return subprocess.CompletedProcess(cmd,4)
        with mock.patch('unified_action_router.subprocess.run',side_effect=contradictory):
            out,code=self.call('SchemaReview','Inventory',argv=[])
        self.assertEqual((out['status'],code),('invalid',4))
        self.assertFalse(out['handler_outcome_consistent'])
        self.assertEqual(out['reason_code'],'ROUTER_HANDLER_STATUS_EXIT_INCONSISTENT')

    def test_actual_entrypoint_has_one_json_line_and_nonzero_invalid_exit(self):
        with tempfile.TemporaryDirectory() as d:
            req=Path(d)/'req.json'
            req.write_text(json.dumps({'schema':REQUEST_SCHEMA,'action':'Due',
                 'mode':'Evaluate','parameters':{'project_timezone':'UTC','cadence':'bad'}}))
            proc=subprocess.run([sys.executable,'-I',str(ROOT/'scripts/ces_router.py'),
                                 '-Action','Due','-Mode','Evaluate',
                                 '-RequestPath',str(req)],text=True,capture_output=True,
                                timeout=15,check=False)
        self.assertEqual(proc.returncode,4)
        self.assertEqual(proc.stderr,'')
        self.assertEqual(len(proc.stdout.splitlines()),1)
        data=json.loads(proc.stdout)
        self.assertEqual(data['status'],'invalid')
        self.assertEqual(data['version'],'1.0.0')
        self.assertEqual(data['schema'],SCHEMA)

    def test_abnormal_child_exit_no_result_promotion(self):
        def abnormal(cmd, *, stdout, **kwargs):
            stdout.write(b'{"status":"success","exit_code":0}')
            return subprocess.CompletedProcess(cmd,-9)
        with mock.patch('unified_action_router.subprocess.run',side_effect=abnormal):
            out,code=self.call('SchemaReview','Inventory',argv=[])
        self.assertEqual((out['status'],code),('unavailable',5))
        self.assertFalse(out['handler_outcome_consistent'])
        self.assertTrue(out['handler_attempted'])

    def test_untouched_original_schema_catalog_all_pins_unchanged(self):
        cat=json.loads((ROOT/'construction/SCHEMA_CATALOG.json').read_text())
        self.assertEqual(len(cat['contracts']),112)
        for entry in cat['contracts']:
            with self.subTest(path=entry['path']):
                path=ROOT/entry['path']
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),entry['sha256'])
        # EC243 v2 contract is intentionally a separate explicit JSON contract.
        self.assertTrue((ROOT/'references/unified-action-router-result.v2.json').is_file())

    def test_router_has_still_74_fixed_routes(self):
        result=inventory()
        self.assertEqual(result['route_count'],74)
        self.assertEqual(len(ROUTES),58)
        self.assertEqual(sum(map(len,LEGACY.values())),16)
        self.assertEqual(result['version'],'1.0.0')


class SchemaBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from jsonschema import Draft202012Validator
        cls.schema=json.loads((ROOT/'references/unified-action-router-result.v2.json').read_text())
        Draft202012Validator.check_schema(cls.schema)
        cls.validator=Draft202012Validator(cls.schema)

    def test_real_partial_invalid_denied_unavailable_validate(self):
        cases=[('Due','Evaluate',{'parameters':{
                  'project_timezone':'UTC','cadence':'day',
                  'observed_at':'2026-10-24T10:00:00Z','never_processed':True}}),
               ('Due','Evaluate',{'parameters':{'project_timezone':'UTC','cadence':'not-a-cadence'}}),
               ('IssueCreate','Create',{}),('Cycle','Summary',{'argv':['--store','/tmp','--run-id','run_v1_'+'a'*48]})]
        for a,m,extra in cases:
            with self.subTest(action=a,mode=m):
                out,_ = dispatch(a,m,{'schema':REQUEST_SCHEMA,'action':a,'mode':m,**extra})
                self.validator.validate(out)
                self.assertEqual(out['schema'],SCHEMA)
                self.assertFalse(out['business_effect_verified'])

    def test_schema_rejects_false_business_success(self):
        obj,_=dispatch('IssueCreate','Create',{'schema':REQUEST_SCHEMA,
                                               'action':'IssueCreate','mode':'Create'})
        for field,value in [('status','success'),('business_effect_verified',True),
                            ('permissions_granted_by_router',True),
                            ('handler_invoked',True),('normalized_exit_code',0),
                            ('handler_result',{'status':'success'})]:
            with self.subTest(field=field):
                cand={**obj,field:value}
                self.assertFalse(self.validator.is_valid(cand))

    def test_schema_rejects_no_attempt_with_valid_response(self):
        obj,_=dispatch('Due','Evaluate',{'schema':REQUEST_SCHEMA,'action':'Due',
                                       'mode':'Evaluate','parameters':{
                                           'project_timezone':'UTC','cadence':'day',
                                           'observed_at':'2026-10-24T10:00:00Z',
                                           'never_processed':True}})
        self.assertTrue(self.validator.is_valid(obj))
        self.assertFalse(self.validator.is_valid({**obj,'handler_attempted':False}))
        self.assertFalse(self.validator.is_valid({**obj,'coverage_missing_claims':['random_sensitive_path']}))


if __name__=='__main__':
    unittest.main()
