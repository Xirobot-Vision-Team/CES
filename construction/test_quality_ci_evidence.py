#!/usr/bin/env python3
"""EC184 offline GH/GL evidence parsing, drift, authorization and hostile inputs."""
from copy import deepcopy
from io import BytesIO
import hashlib
import json
from zipfile import ZipFile, ZIP_DEFLATED
import unittest

import quality_ci_evidence as ev
import quality_read_ci as ci
import quality_sha_bind as qb
import test_quality_read_ci as ct
import test_quality_sha_bind as bt

GH, GL = ct.GH, ct.GL
NOW = ct.NOW
SIGNED = 'https://productionresultssa1.blob.core.windows.net/actions-results/job-1.txt?sig=secret-query'
PASS_LOG = b'TAP version 13\n1..2\nok 1 - a\nok 2 - b\n'
FAIL_LOG = b'TAP version 13\n1..2\nok 1 - a\nnot ok 2 - b\n'
JUNIT_PASS = b'<testsuite tests="2" failures="0" errors="0"><testcase name="a"/><testcase name="b"/></testsuite>'
JUNIT_FAIL = b'<testsuite tests="2" failures="1" errors="0"><testcase name="a"><failure>secret</failure></testcase><testcase name="b"/></testsuite>'
COVERAGE = b'{"files": {"src/foo.py": {}}, "totals": {"num_statements": 10, "covered_lines": 8, "missing_lines": 2, "percent_covered": 80.0}}'
COBERTURA = b'<coverage lines-valid="10" lines-covered="8" line-rate="0.8"/>'


class BinaryFake:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def fetch(self, url, headers, timeout, byte_limit):
        self.calls.append((url, dict(headers), byte_limit))
        if not self.replies:
            raise AssertionError('unplanned content GET')
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return deepcopy(r)


def job_log(provider, body=PASS_LOG):
    if provider == 'github':
        return [ev.FetchResponse(302, location=SIGNED),
                ev.FetchResponse(200, 'text/plain', body)]
    return [ev.FetchResponse(200, 'text/plain', body)]


def zip_report(path, data, *, extra=None):
    out = BytesIO()
    with ZipFile(out, 'w', compression=ZIP_DEFLATED) as z:
        z.writestr(path, data)
        if extra:
            for k, v in extra.items():
                z.writestr(k, v)
    return out.getvalue()


def artifact_meta(zip_bytes, *, diff=None, digest=True):
    obj = {'id': 991, 'name': 'coverage-ci', 'size_in_bytes': len(zip_bytes),
           'expired': False, 'workflow_run': {'id': GH.run_id,
                                               'repository_id': GH.project_id,
                                               'head_sha': GH.commit_sha,
                                               'head_branch': GH.branch}}
    if digest:
        obj['digest'] = 'sha256:' + hashlib.sha256(zip_bytes).hexdigest()
    if diff:
        obj.update(diff)
    return ev.FetchResponse(200, 'application/json', json.dumps(obj).encode('utf-8'))


def gh_artifact(zip_bytes, *, before=None, after=None):
    return [before or artifact_meta(zip_bytes),
            ev.FetchResponse(302, location=SIGNED),
            ev.FetchResponse(200, 'application/zip', zip_bytes),
            after or artifact_meta(zip_bytes)]


def harness(key=GH, *, body=PASS_LOG, report=None, evidence=None,
            mode='DeliveredTarget', new_ci=None, new_source=None,
            old_ci=None, old_bind=None, grants=None, flags=None,
            fake_bytes=None, clock=None):
    clock = clock or (lambda: NOW)
    if old_ci is None:
        old_ci, _, _ = ct.scenario(key)
    if old_bind is None:
        old_bind, *_ = bt.run(key, mode=mode,
                               new_ci=new_ci if new_ci is not None else bt.SENTINEL,
                               receipt=old_ci, clock=clock)
    source = bt.Transport(new_source if new_source is not None
                          else bt.replies(key.provider, mode == 'ProposedPR') * 2)
    remote_ci = bt.Transport((new_ci if new_ci is not None
                              else bt.ci_replies(key.provider)) * 2)
    binder = qb.QualitySHABinder(source, ci.QualityCIReader(remote_ci, clock=clock),
                                 clock=clock)
    bs = fake_bytes or BinaryFake(evidence if evidence is not None
                                  else job_log(key.provider, body))
    reader = ev.QualityCIEvidence(byte_transport=bs, binder=binder, clock=clock)
    opt = dict(allow_network=True, allow_ci_recheck=True, allow_source_recheck=True,
               allow_receipt_reuse=True, allow_job_log=True,
               allow_report=(report is not None))
    opt.update(flags or {})
    trace = []
    def content_grant(facts):
        trace.append(facts)
        return grants(facts) if grants else True
    result = reader.read(
        qb.SourceSelection(key, mode, 7 if mode == 'ProposedPR' else None),
        report=report or ev.ReportSelection(), ci_receipt=old_ci,
        association_receipt=old_bind,
        ci_credential='ci-secret', source_credential='source-secret',
        authorize_ci=lambda x: True, authorize_source=lambda x: True,
        authorize_content=content_grant, allow_synthetic_development=True, **opt)
    return result, bs, source, remote_ci, trace


class EC184Focused(unittest.TestCase):
    def positive(self, r, classification):
        self.assertEqual((r['status'], r['exit_code']), ('partial', 2), r['reason_code'])
        self.assertEqual(r['classification'], classification)
        self.assertFalse(r['effects']['tests_executed_by_ces'])
        self.assertFalse(r['effects']['writes_performed'])
        self.assertEqual(r['effects']['live_content_get_requests'], 0)
        self.assertFalse(r['coverage']['provider_cross_request_atomic'])
        self.assertEqual(r['permission']['transport'], 'SYNTHETIC')
        self.assertEqual(ev.digest({k: r[k] for k in
                         ('scope', 'test_evidence', 'report_evidence', 'classification',
                          'coverage', 'permission')}), r['evidence_sha256'])
        self.assertNotIn('ci-secret', json.dumps(r))
        self.assertNotIn('source-secret', json.dumps(r))

    def negative(self, r, code, *, status='unavailable'):
        self.assertEqual((r['status'], r['exit_code']), (status, ev.EXIT[status]))
        self.assertEqual(r['reason_code'], 'QUALITYCIEVIDENCE_' + code)
        for key in ('scope', 'test_evidence', 'report_evidence', 'classification', 'coverage',
                    'evidence_sha256'):
            self.assertIsNone(r[key])

    def test_gh_tap_complete_pass_signed_link_strips_auth(self):
        r, transport, source, remote, gates = harness()
        self.positive(r, 'pass')
        self.assertEqual(r['test_evidence']['counts']['passed'], 2)
        self.assertEqual(len(transport.calls), 2)
        self.assertIn('Authorization', transport.calls[0][1])
        self.assertNotIn('Authorization', transport.calls[1][1])
        self.assertNotIn('PRIVATE-TOKEN', transport.calls[1][1])
        self.assertEqual(gates[1]['read_kind'], 'SIGNED_JOB_LOG')
        self.assertEqual(gates[1]['signed_host'], 'productionresultssa1.blob.core.windows.net')
        self.assertNotIn('secret-query', json.dumps(r))
        self.assertEqual((len(source.calls), len(remote.calls)), (10, 6))

    def test_gl_tap_complete_pass(self):
        r, content, *_ = harness(GL)
        self.positive(r, 'pass')
        self.assertEqual(len(content.calls), 1)
        self.assertIn('/jobs/' + str(GL.job_id) + '/trace', content.calls[0][0])

    def test_gh_with_timestamped_pytest_summary(self):
        raw = b'2026-10-22T10:00:00Z ==== 3 passed in 0.17s ====\n'
        r, *_ = harness(body=raw)
        self.positive(r, 'pass')
        self.assertEqual(r['test_evidence']['counts']['total'], 3)

    def test_gl_pytest_failed_job_attributed(self):
        cr, _, _ = ct.scenario(GL)
        cr['observation']['run']['state'] = 'failed'
        cr['observation']['run']['conclusion'] = 'failure'
        cr['observation']['job']['state'] = 'failed'
        cr['observation']['job']['conclusion'] = 'failure'
        cr['observation_sha256'] = ci._hash({k: cr[k] for k in
            ('source', 'observation', 'permission', 'coverage')})
        replies = bt.ci_replies('gitlab')
        for item in (replies[1], replies[3]): item['status'] = 'failed'
        replies[2]['status'] = 'failed'
        assoc, *_ = bt.run(GL, new_ci=replies, receipt=cr)
        self.assertEqual(assoc['status'], 'partial')
        r, *_ = harness(GL, body=b'== 1 failed, 2 passed in 1.01s ==',
                        new_ci=replies, old_ci=cr, old_bind=assoc)
        self.positive(r, 'fail')
        self.assertEqual(r['test_evidence']['counts']['failed'], 1)

    def test_no_log_is_missing_not_pass(self):
        for key in (GH, GL):
            with self.subTest(provider=key.provider):
                r, *_ = harness(key, evidence=[ev.FetchResponse(404)])
                self.positive(r, 'missing')
                self.assertEqual(r['test_evidence']['availability'], 'missing')

    def test_tap_plan_zero_marked_not_run(self):
        r, *_ = harness(GL, body=b'TAP version 13\n1..0 # SKIP no collected tests')
        self.positive(r, 'not_run')

    def test_malformed_tap_is_partial_not_false_pass(self):
        for raw in (b'TAP version 13\n1..3\nok 1\nok 2',
                    b'TAP version 13\n1..2\nok 1\nok 1',
                    b'TAP version 13\n1..2\nok 1\nok 2\nok 3',
                    b'last text contains 1 passed', b'\xff\x00',
                    b'== 1 passed in 0.01s ==\n== 2 passed in 0.01s ==',
                    b'TAP version 13\n1..1\nok 1 # SKIP'):
            with self.subTest(raw=raw[:30]):
                r, *_ = harness(GL, body=raw)
                self.positive(r, 'partial')

    def test_log_pass_when_ci_job_failed_is_partial(self):
        cr, _, _ = ct.scenario(GH)
        cr['observation']['run']['conclusion'] = 'failure'
        cr['observation']['job']['conclusion'] = 'failure'
        cr['observation_sha256'] = ci._hash({k: cr[k] for k in
            ('source', 'observation', 'permission', 'coverage')})
        replies = bt.ci_replies('github')
        replies[0]['conclusion'] = replies[2]['conclusion'] = 'failure'
        replies[1]['jobs'][0]['conclusion'] = 'failure'
        assoc, *_ = bt.run(GH, new_ci=replies, receipt=cr)
        r, *_ = harness(GH, new_ci=replies, old_ci=cr, old_bind=assoc)
        self.positive(r, 'partial')
        self.assertEqual(r['test_evidence']['parse_format'], 'CI_JOB_TEST_CONCLUSION_CONFLICT')

    def test_gl_coverage_json_exact_job(self):
        rep = ev.ReportSelection('coverage_json', 'reports/coverage.json')
        replies = job_log('gitlab') + [ev.FetchResponse(200, 'application/json', COVERAGE)]
        r, _, _, _, gates = harness(GL, report=rep, evidence=replies)
        self.positive(r, 'pass')
        self.assertEqual(r['report_evidence']['state'], 'measured')
        self.assertEqual(r['report_evidence']['coverage_metrics']['percent'], 80.0)
        self.assertTrue(r['coverage']['report_is_job_attributed'])
        self.assertIn('JOB_REPORT', [x['read_kind'] for x in gates])

    def test_gl_cobertura_scoped(self):
        rep = ev.ReportSelection('cobertura_xml', 'reports/coverage.xml')
        r, *_ = harness(GL, report=rep, evidence=job_log('gitlab') +
                        [ev.FetchResponse(200, 'application/xml', COBERTURA)])
        self.positive(r, 'pass')
        self.assertEqual(r['report_evidence']['coverage_metrics']['lines_total'], 10)

    def test_gl_junit_is_job_scoped_when_log_missing(self):
        rep = ev.ReportSelection('junit_xml', 'tests/junit.xml')
        r, *_ = harness(GL, report=rep,
                        evidence=[ev.FetchResponse(404),
                                  ev.FetchResponse(200, 'text/xml', JUNIT_PASS)])
        self.positive(r, 'pass')
        self.assertEqual(r['test_evidence']['parse_format'], 'JUNIT_XML')

    def test_gl_junit_error_counter_is_not_misreported_as_failure(self):
        xml = (b'<testsuites tests="2" failures="0" errors="1" skipped="0">'
               b'<testsuite tests="2" failures="0" errors="1">'
               b'<testcase name="ok"/><testcase name="error"><error/></testcase>'
               b'</testsuite></testsuites>')
        parsed = ev._parse_report(xml, 'junit_xml')
        self.assertEqual(parsed['state'], 'fail')
        self.assertEqual(parsed['counts']['failed'], 1)
        malformed = xml.replace(b'errors="1"', b'errors="0"', 1)
        self.assertEqual(ev._parse_report(malformed, 'junit_xml')['state'], 'partial')

    def test_reject_forged_association_effects_or_trust_even_with_digest(self):
        receipt, *_ = bt.run(GH)
        bad = deepcopy(receipt)
        bad['effects']['writes_performed'] = True
        r, *_ = harness(GH, old_bind=bad)
        self.negative(r, 'ASSOCIATION_EFFECTS_OR_TRUST_INVALID', status='invalid_input')
        bad = deepcopy(receipt)
        bad['trust_boundary'] = 'EXECUTED_TESTS_PROVED'
        r, *_ = harness(GH, old_bind=bad)
        self.negative(r, 'ASSOCIATION_EFFECTS_OR_TRUST_INVALID', status='invalid_input')

    def test_gl_junit_log_disagreement_is_partial(self):
        rep = ev.ReportSelection('junit_xml', 'tests/junit.xml')
        r, *_ = harness(GL, report=rep, evidence=job_log('gitlab') +
                        [ev.FetchResponse(200, 'text/xml', JUNIT_FAIL)])
        self.positive(r, 'partial')
        self.assertEqual(r['test_evidence']['parse_format'], 'LOG_REPORT_CONFLICT')

    def test_gh_artifact_valid_but_run_only(self):
        archive = zip_report('tests/junit.xml', JUNIT_PASS)
        rep = ev.ReportSelection('junit_xml', github_artifact_id=991,
                                 github_entry='tests/junit.xml')
        r, *_ = harness(GH, report=rep, evidence=[ev.FetchResponse(404)] +
                        gh_artifact(archive))
        self.positive(r, 'partial')
        self.assertTrue(r['coverage']['github_report_run_only'])
        self.assertFalse(r['coverage']['report_is_job_attributed'])
        self.assertEqual(r['report_evidence']['state'], 'pass')
        self.assertEqual(r['report_evidence']['source_scope'], 'RUN_ONLY_JOB_ATTEMPT_UNVERIFIED')

    def test_gh_artifact_coverage_valid_and_original_log_pass(self):
        archive = zip_report('reports/coverage.json', COVERAGE)
        rep = ev.ReportSelection('coverage_json', github_artifact_id=991,
                                 github_entry='reports/coverage.json')
        r, content, *_ = harness(GH, report=rep,
                                 evidence=job_log('github') + gh_artifact(archive))
        self.positive(r, 'pass')
        self.assertEqual(r['report_evidence']['state'], 'measured')
        self.assertEqual(r['effects']['content_get_calls'], 6)
        self.assertEqual(len(content.replies), 0)

    def test_gh_artifact_mismatched_run_or_digest_refused(self):
        archive = zip_report('reports/coverage.json', COVERAGE)
        rep = ev.ReportSelection('coverage_json', github_artifact_id=991,
                                 github_entry='reports/coverage.json')
        mismatch = artifact_meta(archive)
        data = json.loads(mismatch.data)
        data['workflow_run']['id'] = 12345
        mismatch = ev.FetchResponse(200, 'application/json', json.dumps(data).encode())
        r, *_ = harness(GH, report=rep, evidence=job_log('github') +
                        [mismatch])
        self.negative(r, 'ARTIFACT_RUN_IDENTITY_UNVERIFIED')
        mutated = ev.FetchResponse(200, 'application/zip', b'not-zip')
        r, *_ = harness(GH, report=rep, evidence=job_log('github') +
                        [artifact_meta(archive), ev.FetchResponse(302, location=SIGNED),
                         mutated])
        self.negative(r, 'ARTIFACT_SIZE_MISMATCH')

    def test_gh_artifact_changed_after_download_refused(self):
        archive = zip_report('reports/coverage.json', COVERAGE)
        rep = ev.ReportSelection('coverage_json', github_artifact_id=991,
                                 github_entry='reports/coverage.json')
        changed = artifact_meta(archive, diff={'name':'renamed'})
        r, *_ = harness(GH, report=rep, evidence=job_log('github') +
                        gh_artifact(archive, after=changed))
        self.negative(r, 'ARTIFACT_METADATA_DRIFT')

    def test_gh_zip_path_traversal_refused(self):
        archive = zip_report('reports/coverage.json', COVERAGE,
                             extra={'../secrets': b'secret'})
        rep = ev.ReportSelection('coverage_json', github_artifact_id=991,
                                 github_entry='reports/coverage.json')
        r, *_ = harness(GH, report=rep, evidence=job_log('github') +
                        gh_artifact(archive))
        self.negative(r, 'ARCHIVE_ENTRY_UNSAFE')

    def test_invalid_coverage_percent_partial(self):
        rep = ev.ReportSelection('coverage_json', 'reports/coverage.json')
        invalid = COVERAGE.replace(b'80.0', b'98.0')
        r, *_ = harness(GL, report=rep, evidence=job_log('gitlab') +
                        [ev.FetchResponse(200, 'application/json', invalid)])
        self.positive(r, 'pass')
        self.assertEqual(r['report_evidence']['state'], 'partial')
        self.assertIsNone(r['report_evidence']['coverage_metrics'])

    def test_double_json_keys_or_dtd_do_not_parse(self):
        rep = ev.ReportSelection('coverage_json', 'reports/coverage.json')
        bad = b'{"totals": {}, "totals": {}, "files": {}}'
        r, *_ = harness(GL, report=rep, evidence=job_log('gitlab') +
                        [ev.FetchResponse(200, 'application/json', bad)])
        self.positive(r, 'pass')
        self.assertEqual(r['report_evidence']['state'], 'partial')
        rep = ev.ReportSelection('junit_xml', 'tests/junit.xml')
        dtd = b'<!DOCTYPE x [<!ENTITY xx "payload">]><testsuite tests="1" failures="0" />'
        r, *_ = harness(GL, report=rep, evidence=job_log('gitlab') +
                        [ev.FetchResponse(200, 'application/xml', dtd)])
        self.positive(r, 'pass')
        self.assertEqual(r['report_evidence']['state'], 'partial')

    def test_missing_report_is_explicit(self):
        rep = ev.ReportSelection('coverage_json', 'reports/coverage.json')
        r, *_ = harness(GL, report=rep, evidence=job_log('gitlab') +
                        [ev.FetchResponse(404)])
        self.positive(r, 'pass')
        self.assertEqual(r['report_evidence']['state'], 'missing')

    def test_declining_any_optin_blocks_all_calls(self):
        for name in ('allow_network', 'allow_ci_recheck', 'allow_source_recheck',
                     'allow_receipt_reuse', 'allow_job_log'):
            with self.subTest(name=name):
                r, content, source, remote, _ = harness(flags={name:False})
                self.negative(r, 'INDEPENDENT_OPTINS_REQUIRED', status='invalid_input')
                self.assertFalse(content.calls or source.calls or remote.calls)

    def test_report_optin_is_separate(self):
        r, content, source, remote, _ = harness(
            GL, report=ev.ReportSelection('coverage_json', 'reports/coverage.json'),
            flags={'allow_report': False})
        self.negative(r, 'REPORT_CONSENT_MISMATCH', status='invalid_input')
        self.assertFalse(content.calls or source.calls or remote.calls)
        r, *_ = harness(flags={'allow_report': True})
        self.negative(r, 'REPORT_CONSENT_MISMATCH', status='invalid_input')

    def test_report_path_and_kind_restricted(self):
        for bad in ('../secret.xml', '/abs/report.xml', '.git/config.xml',
                    'reports\\file.xml', 'reports/%2e.xml', 'reports/junit.txt'):
            with self.subTest(path=bad):
                r, content, *_ = harness(GL, report=ev.ReportSelection('junit_xml', bad))
                self.negative(r, 'REPORT_PATH_UNSAFE', status='invalid_input')
                self.assertFalse(content.calls)

    def test_source_rebind_rejects_observation_drift_after_log(self):
        reply = bt.replies('github') + bt.replies('github')
        reply[8]['object']['sha'] = 'f'*40
        r, content, *_ = harness(GH, new_source=reply)
        self.negative(r, 'FRESH_SOURCE_CI_ASSOCIATION_REFUSED')
        self.assertEqual(len(content.calls), 2)

    def test_association_receipt_tamper_stops_content(self):
        old, *_ = bt.run(GH)
        old['source']['branch'] = 'elsewhere'
        r, content, source, remote, _ = harness(old_bind=old)
        self.negative(r, 'ASSOCIATION_RECEIPT_DIGEST_INVALID', status='invalid_input')
        self.assertFalse(content.calls or source.calls or remote.calls)

    def test_association_receipt_mismatched_hash_digest_recomputed_still_rejected(self):
        old, *_ = bt.run(GH)
        old['ci_observation']['job_id'] = 12
        old['association_sha256'] = qb.checksum({k: old[k] for k in
            ('source', 'ci_observation', 'binding', 'permission', 'coverage')})
        r, content, *_ = harness(old_bind=old)
        self.negative(r, 'ASSOCIATION_CI_MISMATCH')
        self.assertFalse(content.calls)

    def test_blocked_content_callback_before_get(self):
        r, content, *_ = harness(grants=lambda x:x['read_kind']!='JOB_LOG')
        self.negative(r, 'CONTENT_SCOPE_DENIED')
        self.assertFalse(content.calls)
        r, content, *_ = harness(grants=lambda x:x['read_kind']!='SIGNED_JOB_LOG')
        self.negative(r, 'CONTENT_SCOPE_DENIED')
        self.assertEqual(len(content.calls), 1)

    def test_signed_url_no_ssrf_and_no_more_redirect(self):
        for location in ('http://productionresultssa1.blob.core.windows.net/content',
                         'https://127.0.0.1/secret',
                         'https://evil.blob.core.windows.net.evil.com/x',
                         'https://user:pass@productionresultssa1.blob.core.windows.net/a',
                         'https://productionresultssa1.blob.core.windows.net:123/a',
                         'https://productionresultssa1.blob.core.windows.net/a/../private'):
            with self.subTest(location=location):
                r, content, *_ = harness(evidence=[ev.FetchResponse(302,location=location)])
                self.negative(r, 'SIGNED_URL_UNTRUSTED')
                self.assertEqual(len(content.calls), 1)
        r, content, *_ = harness(evidence=[ev.FetchResponse(302,location=SIGNED),
                                          ev.FetchResponse(302,location=SIGNED)])
        self.negative(r, 'SIGNED_DOWNLOAD_UNAVAILABLE')
        self.assertEqual(len(content.calls), 2)

    def test_gitlab_redirect_not_followed_with_credential(self):
        r, content, *_ = harness(GL, evidence=[ev.FetchResponse(302,location=SIGNED)])
        self.negative(r, 'GITLAB_LOG_REDIRECT_UNTRUSTED')
        # A provider trace redirect has no validated text body; deny rather
        # than issue a credentialed or unapproved cross-origin request.
        self.assertEqual(r['status'], 'unavailable')
        self.assertEqual(len(content.calls), 1)

    def test_reject_oversized_fake_content(self):
        raw = b'X' * (ev.MAX_LOG_BYTES + 1)
        r, *_ = harness(GL, evidence=[ev.FetchResponse(200,'text/plain',raw)])
        self.negative(r, 'CONTENT_RESPONSE_INVALID')

    def test_synthetic_optin_required(self):
        # Injection must never become authenticated LIVE_HTTPS evidence.
        ci_receipt, *_ = ct.scenario(GH)
        assoc, *_ = bt.run(GH)
        source = bt.Transport(bt.replies('github')*2)
        reader = ci.QualityCIReader(bt.Transport(bt.ci_replies('github')*2),clock=lambda:NOW)
        binder = qb.QualitySHABinder(source,reader,clock=lambda:NOW)
        content = BinaryFake(job_log('github'))
        r = ev.QualityCIEvidence(byte_transport=content,binder=binder,clock=lambda:NOW).read(
            qb.SourceSelection(GH,'DeliveredTarget'),report=ev.ReportSelection(),
            ci_receipt=ci_receipt,association_receipt=assoc,
            ci_credential='ci',source_credential='source',
            allow_network=True,allow_ci_recheck=True,allow_source_recheck=True,
            allow_receipt_reuse=True,allow_job_log=True,allow_report=False,
            authorize_ci=lambda x:True,authorize_source=lambda x:True,
            authorize_content=lambda x:True,allow_synthetic_development=False)
        self.negative(r,'SYNTHETIC_DEVELOPMENT_DENIED',status='invalid_input')
        self.assertFalse(content.calls)

    def test_raw_logs_and_report_paths_not_disclosed(self):
        body = b'\nsecret upstream access_token abc123\n' + PASS_LOG
        r, *_ = harness(GL, body=body)
        self.positive(r, 'pass')
        self.assertNotIn('abc123', json.dumps(r))
        self.assertNotIn('secret upstream', json.dumps(r))


if __name__ == '__main__':
    unittest.main()
