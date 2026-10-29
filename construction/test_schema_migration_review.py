#!/usr/bin/env python3
"""EC242 focused read/deny/no-migration cases; all input claims synthetic."""
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

import schema_migration_review as sr
import unified_action_router as router

FIX = sr.ROOT / 'construction' / 'fixtures' / 'ec242'
LEGACY = sr.ROOT / 'construction' / 'fixtures' / 'ec158'


class SchemaReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = sr.catalog()

    def read(self, name: str, domain: str, *, contract: str | None = None):
        p = FIX / name
        return sr.inspect(p.read_bytes(), domain=domain, registry=self.registry,
                          contract=contract, path=str(p))

    def test_01_all_7_new_domains_have_schema_accepted_examples(self):
        for dom in ('Finding', 'Quality', 'Report', 'Knowledge', 'Issue', 'Delivery', 'Cycle'):
            with self.subTest(dom=dom):
                out = self.read(dom.lower() + '-v1.json', dom)
                self.assertEqual(out['status'], 'readable')
                self.assertEqual(out['exit_code'], 0)
                self.assertTrue(out['schema_pin_checked'])
                self.assertTrue(out['structural_validation'])
                self.assertFalse(out['source_authority_verified'])
                self.assertFalse(out['business_authorization_verified'])
                self.assertFalse(out['migration_executed'])

    def test_02_legacy_codeinsight_real_reader_and_unknown_future(self):
        current = LEGACY / 'ci-example.json'
        report = sr.inspect(current.read_bytes(), domain='CodeInsight',
                            path=str(current), registry=self.registry)
        self.assertEqual(report['source_contract'], 'code_insight_saved')
        self.assertEqual(report['status'], 'readable')
        self.assertFalse(report['identity_or_record_authentication_verified'])
        future = LEGACY / 'future-version.json'
        result = sr.inspect(future.read_bytes(), domain='CodeInsight',
                            path=str(future), registry=self.registry)
        self.assertEqual(result['status'], 'rejected')

    def test_03_legacy_collect_and_owner_are_distinct_roles(self):
        for file in ('collect.v1.json', 'owner.json'):
            with self.subTest(file=file):
                raw = (LEGACY / file).read_bytes()
                out = sr.inspect(raw, domain='CodeInsight', registry=self.registry)
                self.assertEqual(out['status'], 'readable')
        collect = (LEGACY / 'collect.v1.json').read_bytes()
        denied = sr.inspect(collect, domain='CodeInsight', contract='code_insight_saved',
                            registry=self.registry)
        self.assertEqual(denied['status'], 'rejected')

    def test_04_unknown_version_never_downgraded(self):
        doc = json.loads((FIX / 'cycle-v1.json').read_text())
        doc['schema'] = 'ces.cycle_cross_action_snapshot.v2'
        raw = json.dumps(doc).encode()
        with self.assertRaisesRegex(sr.ReviewError, 'FUTURE_OR_UNREGISTERED_ROOT_VERSION'):
            sr.inspect(raw, domain='Cycle', registry=self.registry)
        out = sr.inspect(raw, domain='Cycle', contract='cycle-cross-action-snapshot.v1',
                         registry=self.registry)
        self.assertEqual(out['reason_code'], 'WRONG_CONTRACT_VERSION_OR_FAMILY')
        self.assertEqual(out['exit_code'], 3)

    def test_05_no_root_version_needs_explicit_contract_and_stays_shape_only(self):
        p = FIX / 'issue-unversioned.json'
        with self.assertRaisesRegex(sr.ReviewError, 'UNVERSIONED_OR_AMBIGUOUS_ROOT_MARKER'):
            sr.inspect(p.read_bytes(), domain='Issue', registry=self.registry)
        out = self.read('issue-unversioned.json', 'Issue', contract='issue-create-content.v1')
        self.assertEqual(out['status'], 'review_required')
        self.assertTrue(out['structural_validation'])
        self.assertEqual(out['exit_code'], 2)
        self.assertEqual(out['disposition'], 'EXPLICIT_CONTRACT_SHAPE_ONLY_NO_VERSION_MIGRATION')

    def test_06_versionless_shape_cannot_be_forced_with_fake_schema(self):
        doc = json.loads((FIX / 'issue-unversioned.json').read_text())
        doc['schema'] = 'ces.fake.v9'
        out = sr.inspect(json.dumps(doc).encode(), domain='Issue',
                         contract='issue-create-content.v1', registry=self.registry)
        self.assertEqual(out['status'], 'rejected')

    def test_07_cross_domain_contract_selectors_forbidden(self):
        with self.assertRaisesRegex(sr.ReviewError, 'UNREGISTERED_CONTRACT_OR_WRONG_DOMAIN'):
            self.read('cycle-v1.json', 'Issue', contract='cycle-cross-action-snapshot.v1')

    def test_08_exact_raw_identity_pin(self):
        raw = (FIX / 'cycle-v1.json').read_bytes()
        good = sr.inspect(raw, domain='Cycle', registry=self.registry,
                          expect_sha256=hashlib.sha256(raw).hexdigest())
        self.assertEqual(good['status'], 'readable')
        altered = sr.inspect(raw, domain='Cycle', registry=self.registry,
                             expect_sha256='0' * 64)
        self.assertEqual(altered['disposition'], 'REJECT_SOURCE_SHA_DRIFT')
        self.assertFalse(altered['schema_pin_checked'])

    def test_09_json_schema_rejects_invalid_deep_shapes_no_content_echo(self):
        obj = json.loads((FIX / 'quality-v1.json').read_text())
        obj['permission']['host_scope'] = 'PRIVATE_VALUE_NEVER_IN_RESULT'
        out = sr.inspect(json.dumps(obj).encode(), domain='Quality', registry=self.registry)
        self.assertEqual(out['status'], 'rejected')
        self.assertEqual(out['reason_code'], 'JSON_SCHEMA_INSTANCE_REJECTED')
        self.assertNotIn('PRIVATE_VALUE_NEVER_IN_RESULT', json.dumps(out))
        self.assertEqual(out['data']['values_disclosed'], False)

    def test_10_readonly_noop_plan_retains_exact_bytes(self):
        raw = (FIX / 'cycle-v1.json').read_bytes()
        with tempfile.TemporaryDirectory() as t:
            file = Path(t) / 'record.json'
            file.write_bytes(raw)
            pre = file.stat().st_mtime_ns
            source = sr.inspect(file.read_bytes(), domain='Cycle', registry=self.registry)
            out = sr.plan(source, target='cycle-cross-action-snapshot.v1', registry=self.registry)
            self.assertEqual(out['disposition'], 'NOOP_KEEP_EXACT_ORIGINAL_BYTES')
            self.assertFalse(out['migration_executed'])
            self.assertEqual(file.read_bytes(), raw)
            self.assertEqual(file.stat().st_mtime_ns, pre)

    def test_11_cross_contract_no_migration_authority(self):
        source = self.read('cycle-v1.json', 'Cycle')
        other = sr.plan(source, target='cycle-run-metadata.v1', registry=self.registry)
        self.assertEqual(other['disposition'], 'BLOCKED_NEW_IMMUTABLE_RECORD_REQUIRED')
        self.assertFalse(other['data']['migration_available'])
        self.assertFalse(other['data']['write_permitted'])
        wrong = sr.plan(source, target='issue-eligibility-review.v1', registry=self.registry)
        self.assertEqual(wrong['reason_code'], 'UNKNOWN_OR_CROSS_DOMAIN_TARGET')

    def test_12_unversioned_cannot_be_migrated_by_retaging(self):
        source = self.read('issue-unversioned.json','Issue',contract='issue-create-content.v1')
        out = sr.plan(source,target='issue-eligibility-review.v1',registry=self.registry)
        self.assertEqual(out['disposition'],'QUARANTINE_NO_TRANSFORM')

    def test_13_finding_v1_v2_id_collision_requires_true_reissue(self):
        a = next(x for x in self.registry['contracts'] if x['contract']=='finding-save-batch.v1')
        b = next(x for x in self.registry['contracts'] if x['contract']=='finding-save-batch.v2')
        self.assertEqual(a['declared_id'], b['declared_id'])
        self.assertNotEqual(a['sha256'], b['sha256'])
        self.assertEqual(a['markers'][0]['value'],'ces.finding_save_batch.v1')
        self.assertEqual(b['markers'][0]['value'],'ces.finding_save_batch.v2')
        source=sr._base('inspect','Finding')
        source.update(status='readable', source_contract='finding-save-batch.v1',
                      structural_validation=True,observed_content_sha256='1'*64)
        plan=sr.plan(source,target='finding-save-batch.v2',registry=self.registry)
        self.assertTrue(plan['data']['historical_schema_id_collision'])
        self.assertEqual(plan['reason_code'],'FINDING_V1_V2_REISSUE_REQUIRED')
        self.assertFalse(plan['migration_executed'])

    def test_14_catalog_fully_pinned_known_debt_not_silent_pass(self):
        a = sr.audit(self.registry)
        self.assertEqual(a['status'], 'review_required')
        self.assertEqual(a['data']['pinned_contract_count'],112)
        self.assertEqual(a['data']['drift_count'],0)
        self.assertEqual(len(a['data']['colliding_declared_schema_ids']),1)
        self.assertEqual(len(a['data']['missing_declared_schema_id']),9)
        self.assertEqual(len(a['data']['no_version_marker_requires_explicit_contract']),9)
        self.assertFalse(a['data']['remote_ref_resolution_attempted'])

    def test_15_catalog_schema_drift_is_detected(self):
        e = next(x for x in self.registry['contracts'] if x['contract']=='cycle-cross-action-snapshot.v1')
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); (root/'references').mkdir()
            p=root/e['path'];p.write_bytes((sr.ROOT/e['path']).read_bytes()+b' ')
            with mock.patch.object(sr,'ROOT',root):
                with self.assertRaisesRegex(sr.ReviewError,'PINNED_SCHEMA_BYTES_DRIFT'):
                    sr.local_contract(e)

    def test_16_no_symlink_input(self):
        with tempfile.TemporaryDirectory() as t:
            real=Path(t)/'real';real.write_bytes((FIX/'cycle-v1.json').read_bytes())
            link=Path(t)/'alias';link.symlink_to(real)
            with self.assertRaisesRegex(sr.ReviewError,'NON_REGULAR_OR_SYMLINK_INPUT'):
                sr.read_regular(link,sr.MAX_INPUT_BYTES,input_stdin=True)

    def test_17_strict_duplicate_case_collisions_bom_nonfinite_and_surrogates(self):
        for raw in (b'{"schema":"x","SCHEMA":"x"}', b'{"a":2,"a":3}',
                    b'\xef\xbb\xbf{}', b'{"i":NaN}', b'{"a":"\\ud800"}'):
            with self.subTest(raw=raw):
                with self.assertRaises(sr.ReviewError):
                    sr.strict_decode(raw)

    def test_18_no_remote_ref_via_local_schema(self):
        with self.assertRaisesRegex(sr.ReviewError,'REMOTE_OR_UNSAFE_SCHEMA_REF'):
            sr._check_local_refs({'$ref':'https://evil.example/schema.json'})

    def test_19_result_contract_on_all_local_operations(self):
        import jsonschema
        schema=json.loads((sr.ROOT/'references/schema-migration-review-result.v1.schema.json').read_text())
        validator=jsonschema.Draft202012Validator(schema)
        outputs=[sr.inventory(self.registry), sr.audit(self.registry),
                 self.read('finding-v1.json','Finding'),
                 self.read('issue-unversioned.json','Issue',contract='issue-create-content.v1')]
        outputs.append(sr.plan(outputs[2],target='finding-save-batch.v2',registry=self.registry))
        for out in outputs:
            with self.subTest(mode=out['mode'],status=out['status']):
                validator.validate(out)

    def test_20_cli_lifecycle_and_router_actual_handler(self):
        task = (sr.ROOT/'construction/schema_migration_review.py')
        cmd = [sys.executable,str(task),'inspect','--domain','Cycle',
               '--input',str(FIX/'cycle-v1.json')]
        process=subprocess.run(cmd,cwd=sr.ROOT,stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,timeout=15,check=False)
        self.assertEqual(process.returncode,0,process.stderr.decode()[:200])
        self.assertEqual(json.loads(process.stdout)['status'],'readable')
        req={'schema':router.REQUEST_SCHEMA,'action':'SchemaReview',
             'mode':'Inspect', 'argv':['--domain','Cycle','--input',str(FIX/'cycle-v1.json')]}
        payload, code=router.dispatch('SchemaReview','Inspect',req)
        self.assertEqual(code,2)
        self.assertTrue(payload['handler_invoked'])
        self.assertEqual(payload['handler_result']['status'],'readable')
        self.assertFalse(payload['business_effect_verified'])
        self.assertFalse(payload['permissions_granted_by_router'])
        self.assertEqual(router.inventory()['route_count'],74)

    def test_21_codeinsight_unchanged_code_boundaries(self):
        p=LEGACY/'ci-example.json'
        input_sha=hashlib.sha256(p.read_bytes()).hexdigest()
        origin=sr.inspect(p.read_bytes(),domain='CodeInsight',registry=self.registry,path=str(p))
        plan=sr.plan(origin,target='code_insight_saved',registry=self.registry)
        self.assertEqual(plan['disposition'],'NOOP_KEEP_EXACT_ORIGINAL_BYTES')
        self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),input_sha)

    def test_22_semantic_fail_is_not_a_schema_pass(self):
        # A well-shaped synthetic Issue signature is *not* authenticated.
        report=self.read('issue-v1.json','Issue')
        self.assertEqual(report['status'],'readable')
        self.assertFalse(report['source_authority_verified'])
        self.assertFalse(report['identity_or_record_authentication_verified'])
        self.assertFalse(report['business_authorization_verified'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
