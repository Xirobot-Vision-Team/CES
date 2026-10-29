"""EC185 focused synthetic development cases; NOT production or native acceptance."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import jsonschema

import quality_observation as qo
import quality_detect as det
import quality_ci_evidence as ev
import quality_read_ci as ci
import quality_sha_bind as qb
import test_quality_ci_evidence as et
import test_quality_read_ci as ct
import test_quality_sha_bind as bt

GH, GL, NOW = et.GH, et.GL, et.NOW
SCHEMA = json.loads((Path(__file__).parent.parent / 'references' /
    'quality-observation-result.v1.schema.json').read_text())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())


class Context:
    def __init__(self, key=GH, *, local=False, remote=True, mode='DeliveredTarget',
                 body=et.PASS_LOG, report=None, content=None,
                 compose_grant=None, local_grant=None, remote_grant=None,
                 allow_synthetic=True):
        self.temp = tempfile.TemporaryDirectory() if local else None
        self.path = Path(self.temp.name) if local else None
        self.local = None
        self.local_grants = []
        self.compose_grants = []
        if local:
            self.path.joinpath('pyproject.toml').write_text('[tool.pytest.ini_options]\naddopts="-q"\n')
            pin = det.QualityDetector.observe_root(str(self.path),
                authorize_observation=lambda _: True, clock=lambda: NOW)
            self.local = qo.LocalConfigSelection(str(self.path), pin, ['pyproject.toml'])
        self.remote = qb.SourceSelection(key, mode, 7 if mode == 'ProposedPR' else None) if remote else None
        self.report = report
        self.receipt = self.association = None
        self.content = None
        if remote:
            self.receipt, *_ = ct.scenario(key)
            self.association, *_ = bt.run(key, mode=mode, receipt=self.receipt)
            self.ci_transport = bt.Transport(bt.ci_replies(key.provider) * 2)
            self.source_transport = bt.Transport(bt.replies(key.provider, mode == 'ProposedPR') * 2)
            binder = qb.QualitySHABinder(self.source_transport,
                ci.QualityCIReader(self.ci_transport, clock=lambda: NOW),
                clock=lambda: NOW)
            self.content = et.BinaryFake(content if content is not None
                              else et.job_log(key.provider, body))
            adapter = ev.QualityCIEvidence(byte_transport=self.content,
                                          binder=binder, clock=lambda: NOW)
            self.adapter = adapter
        else:
            adapter = None
        self.observer = qo.QualityObservation(ci_evidence=adapter, clock=lambda: NOW)
        self.compose_grant = compose_grant
        self.local_grant = local_grant
        self.remote_grant = remote_grant
        self.allow_synthetic = allow_synthetic

    def close(self):
        if self.temp is not None:
            self.temp.cleanup()

    def collect(self, **override):
        def compose_grant(f):
            self.compose_grants.append(deepcopy(f))
            return self.compose_grant(f) if self.compose_grant else True
        def local_grant(f):
            self.local_grants.append(deepcopy(f))
            return self.local_grant(f) if self.local_grant else True
        p = dict(
            local=self.local, remote=self.remote, report=self.report,
            ci_receipt=self.receipt, association_receipt=self.association,
            ci_credential='ci-secret' if self.remote else None,
            source_credential='source-secret' if self.remote else None,
            allow_compose=True, allow_local_config=self.local is not None,
            allow_remote_ci_evidence=self.remote is not None,
            allow_network=self.remote is not None,
            allow_ci_recheck=self.remote is not None,
            allow_source_recheck=self.remote is not None,
            allow_receipt_reuse=self.remote is not None,
            allow_job_log=self.remote is not None,
            allow_report=self.report is not None,
            authorize_compose=compose_grant,
            authorize_local_source=local_grant if self.local else None,
            authorize_local_path=local_grant if self.local else None,
            authorize_ci=lambda f: self.remote_grant(f) if self.remote_grant else True,
            authorize_source=lambda f: self.remote_grant(f) if self.remote_grant else True,
            authorize_content=lambda f: self.remote_grant(f) if self.remote_grant else True,
            allow_synthetic_development=self.allow_synthetic)
        p.update(override)
        return self.observer.collect(**p)


class EC185Focused(unittest.TestCase):
    def work(self, *args, **kwargs):
        ctx = Context(*args, **kwargs)
        self.addCleanup(ctx.close)
        return ctx

    def good(self, r):
        self.assertEqual((r['status'],r['exit_code']),('partial',2), r['reason_code'])
        self.assertEqual(r['observation_sha256'], qo._hash({k:r[k] for k in
            ('observed_at_utc','source','observations','evidence_refs',
             'execution_environment','grants','proof')}))
        self.assertFalse(r['proof']['overall_quality_pass_verified'])
        self.assertFalse(r['proof']['actual_tests_executed_by_ces'])
        self.assertFalse(r['proof']['performance_measured'])
        self.assertEqual(r['observations']['performance']['state'],'not_measured')
        self.assertEqual(r['observations']['performance']['metrics'],[])
        self.assertEqual(r['status'],'partial')
        self.assertFalse(r['effects']['writes_performed'])
        self.assertFalse(r['effects']['executed_commands'])
        self.assertNotIn('ci-secret',json.dumps(r))
        self.assertNotIn('source-secret',json.dumps(r))
        VALIDATOR.validate(r)

    def refuse(self, r, status='unavailable'):
        self.assertEqual((r['status'],r['exit_code']), (status,qo.EXIT[status]),r['reason_code'])
        for key in ('source','observations','execution_environment','grants',
                    'proof','observation_sha256','observed_at_utc'):
            self.assertIsNone(r[key])
        self.assertEqual(r['evidence_refs'],[])
        VALIDATOR.validate(r)

    def test_local_only_real_config_parser_and_schema(self):
        c=self.work(local=True,remote=False)
        r=c.collect()
        self.good(r)
        self.assertIsNone(r['source']['remote'])
        self.assertEqual(r['source']['local']['source_mode'],'WorkingTree')
        self.assertEqual(r['observations']['local_config']['parsed_configs'],1)
        self.assertEqual(r['effects']['local_config_scans'],1)
        self.assertIsNone(r['observations']['tests'])
        self.assertEqual(r['grants']['transport'],'NOT_USED')
        self.assertTrue(all(x['digest_authenticates_origin'] is False for x in r['evidence_refs']))

    def test_remote_only_github_pass_remains_partial_claim(self):
        c=self.work()
        r=c.collect()
        self.good(r)
        self.assertEqual(r['observations']['tests']['classification'],'pass')
        self.assertEqual(r['observations']['tests']['counts']['passed'],2)
        self.assertEqual(r['observations']['tests']['counts_scope'],'EXACT_JOB_LOG')
        self.assertEqual(r['grants']['transport'],'SYNTHETIC')
        self.assertEqual(r['effects']['live_network_get_requests'],0)
        self.assertEqual(len(c.source_transport.calls),10)
        self.assertEqual(len(c.ci_transport.calls),6)
        self.assertIsNone(r['source']['local'])

    def test_remote_gitlab_pass_provider_claim(self):
        c=self.work(GL)
        r=c.collect()
        self.good(r)
        self.assertEqual(r['source']['remote']['provider'],'gitlab')
        self.assertIsNone(r['source']['remote']['attempt'])
        self.assertEqual(r['observations']['tests']['classification'],'pass')

    def test_both_tracks_same_revision_is_explicitly_unproved(self):
        c=self.work(local=True)
        r=c.collect()
        self.good(r)
        self.assertFalse(r['source']['same_revision_proven'])
        self.assertEqual(r['effects']['local_config_scans'],2)
        self.assertFalse(r['proof']['local_remote_same_revision_verified'])
        self.assertEqual(r['observations']['local_config']['present_paths'],1)
        self.assertEqual({x['kind'] for x in r['evidence_refs']},
                         {'local_config_inventory','ci_metadata_receipt',
                          'sha_association_receipt','ci_evidence_receipt','job_log'})

    def test_proposed_pr_github_remote_identity(self):
        c=self.work(mode='ProposedPR')
        r=c.collect()
        self.good(r)
        self.assertEqual(r['source']['remote']['source_mode'],'ProposedPR')
        self.assertEqual(r['source']['remote']['proposal_number'],7)

    def test_missing_log_not_run_report_absent(self):
        for key in (GH,GL):
            c=self.work(key,content=[ev.FetchResponse(404)])
            r=c.collect()
            self.good(r)
            self.assertEqual(r['observations']['tests']['classification'],'missing')
            self.assertIsNone(r['observations']['tests']['counts'])
            self.assertEqual(r['evidence_refs'][2]['availability'],'missing')

    def test_zero_tests_not_run_not_pass(self):
        c=self.work(GL,body=b'TAP version 13\n1..0 # SKIP no tests')
        r=c.collect()
        self.good(r)
        self.assertEqual(r['observations']['tests']['classification'],'not_run')
        self.assertEqual(r['observations']['tests']['counts']['total'],0)

    def test_malformed_claim_remains_partial(self):
        c=self.work(GL,body=b'TAP version 13\n1..3\nok 1\nok 2')
        r=c.collect()
        self.good(r)
        self.assertEqual(r['observations']['tests']['classification'],'partial')
        self.assertIsNone(r['observations']['tests']['counts'])

    def test_gitlab_coverage_is_not_verified_benchmark(self):
        rep=ev.ReportSelection(kind='coverage_json', gitlab_path='reports/cov.json')
        c=self.work(GL,report=rep,content=et.job_log('gitlab')+[
            ev.FetchResponse(200,'application/json',et.COVERAGE)])
        r=c.collect()
        self.good(r)
        cov=r['observations']['coverage']
        self.assertEqual((cov['state'],cov['metrics']['percent']),('provider_reported',80.0))
        self.assertFalse(cov['independently_measured_by_ces'])
        self.assertEqual(cov['report_scope'],'EXACT_GITLAB_JOB')
        self.assertEqual(r['observations']['performance']['benchmark_samples'],0)

    def test_github_run_level_junit_conflicts_job_log_without_job_proof(self):
        report=ev.ReportSelection(kind='junit_xml',github_artifact_id=991,
                                  github_entry='junit/result.xml')
        zipbytes=et.zip_report('junit/result.xml',et.JUNIT_FAIL)
        c=self.work(report=report,content=et.job_log('github')+et.gh_artifact(zipbytes))
        r=c.collect()
        self.good(r)
        self.assertEqual(r['observations']['tests']['classification'],'pass')
        self.assertEqual(r['observations']['tests']['junit_report_state'],'fail')
        self.assertTrue(r['observations']['tests']['github_run_artifact_not_job_proof'])
        self.assertEqual([v for v in r['evidence_refs'] if v['kind']=='report'][0]['scope'],
                         'RUN_LEVEL_ARTIFACT')

    def test_gitlab_job_specific_junit_disagreement_degrades_to_partial(self):
        report=ev.ReportSelection(kind='junit_xml',gitlab_path='reports/tests.xml')
        c=self.work(GL, report=report,
            content=et.job_log('gitlab') +
                    [ev.FetchResponse(200,'application/xml',et.JUNIT_FAIL)])
        r=c.collect()
        self.good(r)
        self.assertEqual(r['observations']['tests']['classification'],'partial')
        self.assertEqual(r['observations']['tests']['junit_report_state'],'fail')
        self.assertIsNone(r['observations']['tests']['counts'])
        self.assertEqual(r['observations']['tests']['junit_report_counts']['failed'],1)

    def test_evidence_selector_reproducible_without_report_paths_or_signed_url(self):
        report=ev.ReportSelection(kind='coverage_json',gitlab_path='reports/private/cov.json')
        c=self.work(GL,report=report,content=et.job_log('gitlab')+[
            ev.FetchResponse(200,'application/json',et.COVERAGE)])
        r=c.collect()
        self.good(r)
        refs={entry['kind']:entry for entry in r['evidence_refs']}
        self.assertIn('selector_sha256',refs['report'])
        self.assertEqual(len(refs['report']['selector_sha256']),64)
        self.assertEqual(refs['report']['byte_count'],len(et.COVERAGE))
        self.assertNotIn('reports/private/cov.json',json.dumps(r))
        self.assertNotIn('secret-query',json.dumps(r))

    def test_wrong_report_provenance_rejected_even_with_matching_digest(self):
        report=ev.ReportSelection(kind='coverage_json',gitlab_path='reports/cov.json')
        base,*_=et.harness(GL,report=report,
            evidence=et.job_log('gitlab')+[ev.FetchResponse(200,'application/json',et.COVERAGE)])
        base['report_evidence']['source_scope']='RUN_ONLY_JOB_ATTEMPT_UNVERIFIED'
        base['evidence_sha256']=ev.digest({k:base[k] for k in
            ('scope','test_evidence','report_evidence','classification',
             'coverage','permission')})
        c=self.work(GL,report=report)
        c.adapter.read=lambda *a,**kw:deepcopy(base)
        r=c.collect()
        self.refuse(r)
        self.assertEqual(r['reason_code'],'QUALITYOBSERVATION_REMOTE_TEST_REPORT_INVALID')

    def test_missing_gitlab_coverage_does_not_invent_percentage(self):
        report=ev.ReportSelection(kind='cobertura_xml',gitlab_path='coverage/report.xml')
        c=self.work(GL,report=report,content=et.job_log('gitlab')+[ev.FetchResponse(404)])
        r=c.collect()
        self.good(r)
        self.assertEqual(r['observations']['coverage']['state'],'missing')
        self.assertIsNone(r['observations']['coverage']['metrics'])

    def test_revoked_compose_before_reads_denies_everything(self):
        c=self.work(local=True,compose_grant=lambda f: False)
        r=c.collect()
        self.refuse(r)
        self.assertEqual(c.content.calls,[])
        self.assertEqual(c.local_grants,[])

    def test_compose_final_revoke_no_partial_evidence_return(self):
        c=self.work(local=True,compose_grant=lambda f:f['stage']!='FINALIZE')
        r=c.collect()
        self.refuse(r)
        self.assertEqual(r['reason_code'],'QUALITYOBSERVATION_COMPOSITION_FINAL_GRANT_DENIED')
        self.assertEqual(len(c.compose_grants),2)

    def test_local_grant_denied_denies_all_no_remote_access(self):
        c=self.work(local=True,local_grant=lambda f: False)
        r=c.collect()
        self.refuse(r)
        self.assertEqual(c.content.calls,[])

    def test_content_permission_revoked_is_atomic_refusal(self):
        c=self.work(remote_grant=lambda f:f.get('read_kind')!='SIGNED_JOB_LOG')
        r=c.collect()
        self.refuse(r)
        self.assertGreaterEqual(r['effects']['remote_content_get_calls'],1)

    def test_changed_local_config_during_remote_get_rejected(self):
        c=self.work(local=True)
        def changed(f):
            if f.get('read_kind')=='SIGNED_JOB_LOG':
                c.path.joinpath('pyproject.toml').write_text('[tool.pytest.ini_options]\naddopts="-vv"\n')
            return True
        c.remote_grant=changed
        r=c.collect()
        self.refuse(r)
        self.assertEqual(r['reason_code'],'QUALITYOBSERVATION_LOCAL_CONFIG_CHANGED_DURING_REMOTE_READ')

    def test_bad_association_receipt_rejected_not_hash_trusted(self):
        c=self.work()
        bad=deepcopy(c.association)
        bad['binding']['source_commit_sha']='0'*40
        r=c.collect(association_receipt=bad)
        self.refuse(r)
        self.assertEqual(c.content.calls,[])

    def test_source_ci_recheck_drift_refuses(self):
        c=self.work()
        # Replace the second source repository field. It cannot be
        # compensated by a forged observation digest.
        c.source_transport.replies[-1]['id'] = 999999
        r=c.collect()
        self.refuse(r)

    def test_remote_optin_absent_denies(self):
        c=self.work()
        r=c.collect(allow_remote_ci_evidence=False)
        self.refuse(r,'invalid_input')
        self.assertEqual(c.content.calls,[])

    def test_local_optin_absent_denies(self):
        c=self.work(local=True,remote=False)
        r=c.collect(allow_local_config=False)
        self.refuse(r,'invalid_input')

    def test_synthetic_never_claimed_live_without_development_consent(self):
        c=self.work(allow_synthetic=False)
        r=c.collect()
        self.refuse(r)

    def test_falsified_remote_proof_rejected_even_with_recomputed_checksum(self):
        base,*_=et.harness()
        base['coverage']['performance_measured']=True
        base['evidence_sha256']=ev.digest({k:base[k] for k in
                ('scope','test_evidence','report_evidence','classification',
                 'coverage','permission')})
        c=self.work()
        c.adapter.read=lambda *a,**kw:deepcopy(base)
        r=c.collect()
        self.refuse(r)
        self.assertEqual(r['reason_code'],'QUALITYOBSERVATION_REMOTE_PROOF_INVALID')

    def test_forged_counts_rejected_even_with_recomputed_checksum(self):
        base,*_=et.harness()
        base['test_evidence']['counts']['passed']=999
        base['evidence_sha256']=ev.digest({k:base[k] for k in
                ('scope','test_evidence','report_evidence','classification',
                 'coverage','permission')})
        c=self.work()
        c.adapter.read=lambda *a,**kw:deepcopy(base)
        r=c.collect()
        self.refuse(r)
        self.assertEqual(r['reason_code'],'QUALITYOBSERVATION_REMOTE_TEST_COUNTS_INVALID')

    def test_schema_rejects_false_attestation_execution_or_performance(self):
        c=self.work(local=True)
        valid=c.collect()
        self.good(valid)
        for mutate in (
            lambda d:d['proof'].__setitem__('performance_measured',True),
            lambda d:d['proof'].__setitem__('overall_quality_pass_verified',True),
            lambda d:d['observations']['performance'].__setitem__('metrics',[{'fps':120}]),
            lambda d:d['observations']['tests'].__setitem__('ces_tests_executed',True),
            lambda d:d['execution_environment'].__setitem__('ci_runner_identity','alice'),
            lambda d:d['source'].__setitem__('same_revision_proven',True),
            lambda d:d['evidence_refs'][0].__setitem__('digest_authenticates_origin',True),
            lambda d:d.__setitem__('status','pass'),
        ):
            with self.subTest(mutate=mutate):
                d=deepcopy(valid)
                mutate(d)
                self.assertFalse(VALIDATOR.is_valid(d))

    def test_incompatible_tracks_or_missing_trust_is_refused(self):
        c=self.work(local=True)
        r=c.collect(allow_network=False)
        self.refuse(r)
        # A missing independent network grant is rejected by the original EC184.
        self.assertFalse(r['proof'] if r['proof'] else False)

    def test_contract_is_valid_draft2020_12(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)


if __name__ == '__main__':
    unittest.main()
