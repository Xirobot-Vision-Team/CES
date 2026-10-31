"""Test protocols and opt-in execution on disposable fixture projects; no live services."""
import contextlib,copy,io,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import ces_testing as t
import ces_test_results as r
import ces_tracking
import ces_lifecycle
import test_notification_cc as cc_tests

class ResultTests(unittest.TestCase):
    def parse(self,body,fmt='junit_xml',**kw):return r.parse(body.encode(),dict(format=fmt,**kw))
    def test_junit_failure_overrides_zero_exit(self):
        cases=self.parse('<testsuite tests="2" failures="1"><testcase classname="math" name="one"/><testcase classname="math" name="two"><failure message="wrong">expected 2</failure></testcase></testsuite>')
        self.assertEqual(r.summarize(cases,0)['status'],'failed');self.assertEqual(cases[1]['id'],'math::two')
    def test_nested_junit_counts_not_double_counted(self):
        cases=self.parse('<testsuites tests="1"><testsuite tests="1"><testcase name="a" time=".2"/></testsuite></testsuites>')
        self.assertEqual(len(cases),1);self.assertEqual(cases[0]['duration_seconds'],.2)
    def test_inconsistent_declared_counts_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'COUNT_MISMATCH'):self.parse('<testsuite tests="2"><testcase name="a"/></testsuite>')
    def test_junit_all_skipped_not_pass(self):
        self.assertEqual(r.summarize(self.parse('<testsuite><testcase name="a"><skipped/></testcase></testsuite>'),0)['status'],'inconclusive')
    def test_empty_or_missing_results_not_pass(self):
        self.assertEqual(r.summarize([],0)['status'],'inconclusive')
        self.assertEqual(r.summarize([],1)['status'],'inconclusive')
    def test_nonzero_exit_with_green_cases_is_execution_error(self):
        cases=self.parse('<testsuite><testcase name="a"/></testsuite>')
        self.assertEqual(r.summarize(cases,1)['status'],'execution_error')
    def test_bad_duration(self):
        with self.assertRaisesRegex(RuntimeError,'DURATION'):self.parse('<testsuite><testcase name="a" time="NaN"/></testsuite>')
    def test_duplicate_case_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'DUPLICATE'):self.parse('<testsuite><testcase name="a"/><testcase name="a"/></testsuite>')
    def test_conflicting_case_outcomes(self):
        with self.assertRaisesRegex(RuntimeError,'CONFLICTING'):self.parse('<testsuite><testcase name="a"><failure/><skipped/></testcase></testsuite>')
    def test_xml_entities_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'DTD_FORBIDDEN'):self.parse('<!DOCTYPE foo [<!ENTITY x "bad">]><testsuite/>')
    def test_utf16_dtd_cannot_bypass_xml_guard(self):
        raw='<!DOCTYPE foo [<!ENTITY x "bad">]><testsuite/>'.encode('utf-16')
        with self.assertRaisesRegex(RuntimeError,'DTD_FORBIDDEN'):r.parse(raw,dict(format='junit_xml'))
    def test_deep_xml_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'STRUCTURE_LIMIT'):self.parse('<testsuite>'+'<a>'*130+'</a>'*130+'</testsuite>')
    def test_trx_namespace_and_error(self):
        rows=self.parse('<TestRun xmlns="urn:test"><Results><UnitTestResult testId="a" outcome="Passed" duration="00:00:01.5"/><UnitTestResult testId="b" outcome="Timeout"><Output><ErrorInfo><Message>timed out</Message></ErrorInfo></Output></UnitTestResult></Results></TestRun>','trx_xml')
        self.assertEqual(rows[0]['duration_seconds'],1.5);self.assertEqual(rows[1]['status'],'error')
    def test_trx_unknown_status_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'STATUS_UNKNOWN'):self.parse('<TestRun><UnitTestResult testId="x" outcome="NotKnown"/></TestRun>','trx_xml')
    def test_custom_json_paths_and_states(self):
        rows=self.parse('{"run":{"cases":[{"key":"a","outcome":"OK"}]}}','json',mapping=dict(cases='run.cases',id='key',status='outcome',statuses={'OK':'passed'}))
        self.assertEqual(rows[0]['status'],'passed')
    def test_boolean_status_and_numeric_id_use_explicit_mapping(self):
        rows=self.parse('{"tests":[{"id":7,"ok":true}]}','json',mapping=dict(status='ok',statuses={'true':'passed','false':'failed'}))
        self.assertEqual(rows[0]['id'],'7');self.assertEqual(rows[0]['status'],'passed')
    def test_json_lines_and_csv(self):
        self.assertEqual(len(self.parse('{"id":"a","status":"passed"}\n{"id":"b","status":"failed"}','json_lines')),2)
        self.assertEqual(self.parse('id,status,message\na,failed,bad\n','csv')[0]['message'],'bad')
    def test_unknown_json_state_not_pass(self):
        with self.assertRaisesRegex(RuntimeError,'UNKNOWN'):self.parse('{"tests":[{"id":"a","status":"maybe"}]}','json')
    def test_json_declared_total_matches_complete_case_list(self):
        with self.assertRaisesRegex(RuntimeError,'COUNT_MISMATCH'):self.parse('{"count":2,"tests":[{"id":"a","status":"passed"}]}','json',mapping=dict(total='count'))
    def test_console_regex_is_case_evidence_not_substring_pass(self):
        rows=self.parse('some PASS text\nCASE a passed\nCASE b failed\n','console_regex',pattern=r'CASE (?P<id>\w+) (?P<status>\w+)')
        self.assertEqual(len(rows),2);self.assertEqual(r.summarize(rows,0)['status'],'failed')
        self.assertEqual(self.parse('PASS','console_regex',pattern=r'CASE (?P<id>\w+) (?P<status>\w+)'),[])
    def test_timeout_and_dirty_sources_override_green(self):
        rows=[r.case('a','passed')]
        self.assertEqual(r.summarize(rows,0,timed_out=True)['status'],'timed_out')
        self.assertEqual(r.summarize(rows,0,source_stable=False)['status'],'invalidated')
    def test_missing_required_case_is_inconclusive(self):
        self.assertEqual(r.summarize([r.case('a','passed')],0,required=['b'])['status'],'inconclusive')
    def test_legacy_build_step_cannot_be_run_as_test(self):
        cfg=dict(execution_policy=dict(run_runtime_tests=True),issue_tracking=dict(enabled=True),build_validation=dict(enabled=True,steps=[dict(name='build',kind='build')]))
        with self.assertRaisesRegex(RuntimeError,'BUILD_ONLY_STEP_IS_NOT_TEST_EVIDENCE'):ces_tracking.run_test(cfg,1,'build')
    def test_legacy_missing_runtime_grant_cannot_execute(self):
        with self.assertRaisesRegex(RuntimeError,'RUNTIME_TESTS_DISABLED'):ces_tracking.run_test({},1,'unit')

WRITER='''import json,sys,time
from pathlib import Path
# Source contract: the runner writes a JSON test report containing a tests array.
root=Path(sys.argv[1]);mode=sys.argv[2]
if mode=='timeout':
    print('starting',flush=True);time.sleep(30)
if mode=='missing':
    print('report was not generated');sys.exit(0)
if mode=='emptyconsole':
    sys.exit(0)
if mode=='dirty':
    Path('writer.py').write_text('changed by fixture');print('modified source')
status='failed' if mode=='failed' else ('skipped' if mode=='skip' else 'passed')
(root/'report.json').write_text(json.dumps({'tests':[{'id':'case-one','status':status,'message':'expected output differs' if status=='failed' else ''}]}))
print('fixture test completed')
sys.exit(2 if mode=='nonzero' else 0)
'''

class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.repo=self.root/'repo';self.repo.mkdir();(self.repo/'writer.py').write_text(WRITER,encoding='utf-8')
        self.c=dict(repository_path=str(self.repo),cache_root=str(self.root/'cache'),state_root=str(self.root/'state'),output_root=str(self.root/'out'),repository_sync=dict(branch='main'),github=dict(repository='example/project',repository_id=2,account_id=1),notifications=dict(allow_publish=True,cc_recipients=['other']),execution_policy=dict(run_runtime_tests=True),testing=dict(enabled=True,allow_execute=True,allow_publish=True,project_owners=['lead'],test_maintainers=['developer'],entries=[dict(name='fixture',argv=[sys.executable,'{repository}/writer.py','{results}','passed'],cwd='{repository}',timeout_seconds=10,sources=['writer.py'])]))
        self.head='a'*40;self.dirty=False
        def fake_git(c,*args):
            if args==('rev-parse','HEAD'):return self.head
            if args[0]=='ls-remote':return self.head+'\trefs/heads/main'
            if args[0]=='status':return ' M writer.py' if self.dirty else ''
            if args[0]=='ls-files':return 'writer.py'
            if args[0]=='show':return (self.repo/'writer.py').read_text(encoding='utf-8')
            raise AssertionError(args)
        self.addCleanup(patch.stopall)
        patch.object(t.w,'git',side_effect=fake_git).start()
        patch.object(t.w,'snapshot',return_value=dict(head=self.head,index_sha256='original',status='')).start()
    def setup_contract(self,mode='passed'):
        self.c['testing']['entries'][0]['argv'][-1]=mode
        prepared=t.prepare(self.c,'fixture');inp=t.w.load(prepared['input'])
        self.contract=dict(schema='ces.test_contract.v1',input_binding_sha256=inp['input_binding_sha256'],summary='The selected runner writes JSON with one tests array; output is directed to the unique results directory argument.',artifacts=[dict(glob='report.json',format='json')],required_cases=['case-one'],citations=[dict(path='writer.py',line_start=3,line_end=4,quote='# Source contract: the runner writes a JSON test report containing a tests array.')])
        self.draft=self.root/'contract.json';t.w.save(self.draft,self.contract)
        t.register(self.c,prepared['input'],self.draft,True)
        return prepared
    def run_fixture(self,mode='passed'):
        self.setup_contract(mode);return t.run_test(self.c,'fixture',True)
    def analysis(self,run):
        receipt=t.w.load(Path(run)/'receipt.json');normalized=t.w.load(Path(run)/'results.json')
        text='The actual bounded fixture evidence supports this observed result; the source of failure still requires review.'
        draft=dict(schema='ces.test_analysis.v1',receipt_id=receipt['receipt_id'],normalized_sha256=receipt['normalized_sha256'],observed_status=normalized['summary']['status'],summary=text,root_cause=text,recommendation=text,verification=text,limitations=text,citations=[dict(kind='artifact',path='results.json',quote=normalized['summary']['status'])])
        path=self.root/'analysis-draft.json';t.w.save(path,draft);return path
    def test_prepare_never_executes_and_hints_are_not_contract(self):
        with patch.object(t,'execute_process',side_effect=AssertionError('execution')):result=t.prepare(self.c,'fixture')
        self.assertGreater(result['hints'],0);self.assertFalse((t.home(self.c)/'contracts').exists())
    def test_registration_preview_does_not_enable(self):
        inp=self.setup_contract();pointer=t.home(self.c)/'contracts/fixture/current.json';pointer.unlink()
        result=t.register(self.c,inp['input'],self.draft,False)
        self.assertEqual(result['status'],'test_contract_preview');self.assertFalse(pointer.exists())
    def test_changed_source_requires_rereview(self):
        self.setup_contract();(self.repo/'writer.py').write_text(WRITER+'\n# changed')
        with self.assertRaisesRegex(RuntimeError,'SOURCE_CHANGED_REREVIEW'):t.run_test(self.c,'fixture',True)
    def test_changed_command_requires_rereview(self):
        self.setup_contract();self.c['testing']['entries'][0]['argv'].append('changed')
        with self.assertRaisesRegex(RuntimeError,'CONFIGURATION_CHANGED'):t.run_test(self.c,'fixture',True)
    def test_dirty_checkout_stops(self):
        self.setup_contract();self.dirty=True
        with self.assertRaisesRegex(RuntimeError,'DIRTY'):t.run_test(self.c,'fixture',True)
    def test_run_preview_does_not_execute(self):
        with patch.object(t,'execute_process',side_effect=AssertionError('execution')):result=t.run_test(self.c,'fixture',False)
        self.assertEqual(result['status'],'test_execution_preview')
    def test_each_execution_gate_is_required(self):
        self.setup_contract()
        for key in ('enabled','allow_execute'):
            self.c['testing'][key]=False
            with self.assertRaisesRegex(RuntimeError,'EXECUTION_DISABLED'):t.run_test(self.c,'fixture',True)
            self.c['testing'][key]=True
        self.c['execution_policy']['run_runtime_tests']=False
        with self.assertRaisesRegex(RuntimeError,'RUNTIME_TESTS_DISABLED'):t.run_test(self.c,'fixture',True)
    def test_real_fixture_passes_and_keeps_evidence(self):
        result=self.run_fixture();self.assertEqual(result['result']['status'],'passed')
        run,receipt,normalized=t.verify_run(self.c,result['run'])
        self.assertEqual(normalized['summary']['total'],1);self.assertFalse(receipt['semantic_fix_verification'])
        self.assertEqual(receipt['executable_sha256'],t.w.sha(Path(sys.executable).read_bytes()))
    def test_fixture_failure_with_zero_exit(self):
        result=self.run_fixture('failed');self.assertEqual(result['result']['status'],'failed');self.assertEqual(result['result']['exit_code'],0)
    def test_skipped_cases_and_missing_files_not_green(self):
        self.assertEqual(self.run_fixture('skip')['result']['status'],'inconclusive')
        self.assertEqual(self.run_fixture('missing')['result']['status'],'inconclusive')
    def test_nonzero_exit_reported_independently(self):
        self.assertEqual(self.run_fixture('nonzero')['result']['status'],'execution_error')
    def test_unique_run_directories_prevent_stale_reuse(self):
        first=self.run_fixture();second=t.run_test(self.c,'fixture',True)
        self.assertNotEqual(first['run'],second['run'])
    def test_actual_timeout_is_recorded(self):
        self.c['testing']['entries'][0]['timeout_seconds']=1;result=self.run_fixture('timeout')
        self.assertEqual(result['result']['status'],'timed_out');self.assertTrue(result['result']['timed_out'])
    def test_modified_source_during_execution_invalidates(self):
        result=self.run_fixture('dirty');self.assertEqual(result['result']['status'],'invalidated')
    def test_artifact_tamper_refuses_analysis(self):
        result=self.run_fixture();draft=self.analysis(result['run']);(Path(result['run'])/'results/report.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError,'ARTIFACT_CHANGED'):t.analyze(self.c,result['run'],draft)
    def test_normalized_result_tamper_refused(self):
        result=self.run_fixture();path=Path(result['run'])/'results.json';path.write_text('{}')
        with self.assertRaisesRegex(RuntimeError,'RESULTS_CHANGED'):t.verify_run(self.c,result['run'])
    def test_analysis_cannot_turn_failure_into_pass(self):
        result=self.run_fixture('failed');draft=self.analysis(result['run']);doc=t.w.load(draft);doc['observed_status']='passed';t.w.save(draft,doc)
        with self.assertRaisesRegex(RuntimeError,'CANNOT_CHANGE_RESULT'):t.analyze(self.c,result['run'],draft)
    def test_analysis_rejects_invented_quote(self):
        result=self.run_fixture();draft=self.analysis(result['run']);doc=t.w.load(draft);doc['citations'][0]['quote']='invented quote';t.w.save(draft,doc)
        with self.assertRaisesRegex(RuntimeError,'QUOTE_INVALID'):t.analyze(self.c,result['run'],draft)
    def test_empty_console_missing_report_still_has_gap_evidence(self):
        result=self.run_fixture('emptyconsole');self.assertEqual(result['result']['status'],'inconclusive')
        self.assertEqual(t.analyze(self.c,result['run'],self.analysis(result['run']))['status'],'test_analysis_ready')
    def test_publish_routes_owner_engineer_global_cc_and_dedups(self):
        result=self.run_fixture('failed');t.analyze(self.c,result['run'],self.analysis(result['run']))
        server=cc_tests.Server()
        with patch.object(t.w,'credential',return_value='test-only'),patch.object(t.w,'api',side_effect=server.api):
            first=t.publish(self.c,result['run'],True);second=t.publish(self.c,result['run'],True)
        self.assertEqual(first['cc_recipients'],['developer','lead','other']);self.assertEqual(first['primary_recipients'],[])
        self.assertEqual(len(server.writes),1);self.assertEqual(second['status'],'duplicate_skipped')
        self.assertFalse(ces_tracking.managed(server.issues[0]));self.assertEqual(server.issues[0]['assignees'],[])
        self.assertFalse(first['email_delivery_verified'])
    def test_publish_requires_analysis_roles_and_opt_in(self):
        result=self.run_fixture()
        with self.assertRaises(FileNotFoundError):t.publish(self.c,result['run'],True)
        t.analyze(self.c,result['run'],self.analysis(result['run']))
        self.c['testing']['test_maintainers']=[];self.c['testing']['project_owners']=[];self.c['notifications']['cc_recipients']=[]
        with patch.object(t.reports,'Client',side_effect=AssertionError('No live publisher')),self.assertRaisesRegex(RuntimeError,'RECIPIENT_REQUIRED'):t.publish(self.c,result['run'],True)
        self.c['testing']['test_maintainers']=['developer'];self.c['testing']['allow_publish']=False
        with self.assertRaisesRegex(RuntimeError,'PUBLICATION_DISABLED'):t.publish(self.c,result['run'],True)
    def test_lock_collision_does_not_remove_other_lock(self):
        self.setup_contract();path=t.home(self.c)/'fixture.lock';path.write_text('other')
        with self.assertRaises(FileExistsError):t.run_test(self.c,'fixture',True)
        self.assertEqual(path.read_text(),'other')
    def test_publication_replays_analysis_instead_of_trusting_rendered_text(self):
        result=self.run_fixture();t.analyze(self.c,result['run'],self.analysis(result['run']))
        path=Path(result['run'])/'analysis.json';doc=t.w.load(path);doc['markdown']='tampered report';doc.pop('analysis_id');doc['analysis_id']=t.digest(doc);t.w.save(path,doc)
        with self.assertRaisesRegex(RuntimeError,'RENDERING_CHANGED'):t.publish(self.c,result['run'],False)
    def test_repository_cache_is_rejected(self):
        self.c['cache_root']=str(self.repo/'cache')
        with self.assertRaisesRegex(RuntimeError,'OUTSIDE_REPOSITORY'):t.home(self.c)
    def test_traversal_and_link_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'RELATIVE_PATH'):t.relative('../outside')
        with patch.object(t,'unsafe',return_value=True):
            with self.assertRaisesRegex(RuntimeError,'REPARSE'):t.bounded_path(self.root,'report.json')
    def test_changed_head_before_execution_blocks(self):
        self.setup_contract()
        with patch.object(t,'pinned_head',side_effect=RuntimeError('TEST_HEAD_NOT_CURRENT_REMOTE_HEAD')):
            with self.assertRaisesRegex(RuntimeError,'HEAD_NOT_CURRENT'):t.run_test(self.c,'fixture',True)
    def test_legacy_fix_gate_does_not_accept_project_receipts(self):
        result=self.run_fixture();receipt=t.w.load(Path(result['run'])/'receipt.json')
        self.assertNotEqual(receipt['schema'],'ces.issue_test_receipt.v1');self.assertFalse(receipt['semantic_fix_verification'])
    def test_source_citation_tamper_rejected_at_registration(self):
        inp=self.setup_contract();self.contract['citations'][0]['quote']='not in source';t.w.save(self.draft,self.contract)
        with self.assertRaisesRegex(RuntimeError,'QUOTE_INVALID'):t.register(self.c,inp['input'],self.draft,True)
    def test_other_project_cannot_read_run(self):
        result=self.run_fixture();other=copy.deepcopy(self.c);other['github']['repository_id']=3
        with self.assertRaisesRegex(RuntimeError,'OUTSIDE_PROJECT_CACHE'):t.verify_run(other,result['run'])
    def test_build_lane_remains_build_only_when_tests_enabled(self):
        self.assertTrue(ces_lifecycle.build_only_policy(self.c))
        self.c['testing']['allow_execute']=False;self.assertFalse(ces_lifecycle.build_only_policy(self.c))
    def test_entry_environment_is_applied_to_real_child_and_bound(self):
        item=self.c['testing']['entries'][0];item['environment']={'CES_TEST_SAMPLE':'value-{repository}'}
        text=(self.repo/'writer.py').read_text();text=text.replace('root=Path(sys.argv[1]);mode=sys.argv[2]','import os\nassert os.environ["CES_TEST_SAMPLE"].startswith("value-")\nassert Path(os.environ["CES_TEST_SAMPLE"][6:]).samefile(Path.cwd())\nroot=Path(sys.argv[1]);mode=sys.argv[2]');(self.repo/'writer.py').write_text(text)
        self.setup_contract();result=t.run_test(self.c,'fixture',True)
        self.assertEqual(result['result']['status'],'passed',(Path(result['run'])/'console.log').read_text(errors='replace'));receipt=t.w.load(Path(result['run'])/'receipt.json')
        self.assertEqual(receipt['environment_spec_sha256'],t.digest(item['environment']));self.assertNotIn('value-',json.dumps(receipt))
    def test_environment_change_requires_fresh_contract(self):
        self.c['testing']['entries'][0]['environment']={'CES_TEST_SAMPLE':'one'};self.setup_contract()
        self.c['testing']['entries'][0]['environment']['CES_TEST_SAMPLE']='two'
        with self.assertRaisesRegex(RuntimeError,'CONFIGURATION_CHANGED'):t.run_test(self.c,'fixture',True)
    def test_environment_rejects_git_injection_and_controls(self):
        for value in ({'GIT_CONFIG_COUNT':'1'},{'Path':'x','PATH':'y'},{'OK':'bad\nline'},{'BAD=KEY':'x'},{'OK':None}):
            self.c['testing']['entries'][0]['environment']=value
            with self.subTest(environment=value),self.assertRaisesRegex(RuntimeError,'ENVIRONMENT'):t.entry(self.c,'fixture')
    def test_owner_only_report_does_not_require_invented_test_engineer(self):
        result=self.run_fixture();t.analyze(self.c,result['run'],self.analysis(result['run']));self.c['testing']['test_maintainers']=[]
        preview=t.publish(self.c,result['run'],False);self.assertEqual(preview['test_maintainers'],[]);self.assertIn('lead',preview['cc_recipients'])
    def test_explicit_primary_report_recipient_gets_all_results_and_is_access_checked(self):
        result=self.run_fixture();t.analyze(self.c,result['run'],self.analysis(result['run']));self.c['testing'].update(project_owners=[],test_maintainers=[],report_recipients=['developer'])
        server=cc_tests.Server()
        with patch.object(t.w,'credential',return_value='test-only'),patch.object(t.w,'api',side_effect=server.api):
            first=t.publish(self.c,result['run'],True);second=t.publish(self.c,result['run'],True)
        self.assertEqual(first['primary_recipients'],['developer']);self.assertEqual(first['cc_recipients'],['other']);self.assertEqual(second['status'],'duplicate_skipped')
        self.c['testing']['report_recipients']=['unknown-user']
        with patch.object(t.w,'credential',return_value='test-only'),patch.object(t.w,'api',side_effect=server.api),self.assertRaisesRegex(RuntimeError,'NOT_REPOSITORY_MEMBER'):t.publish(self.c,result['run'],True)
    def test_managed_export_contains_reviewed_reports_not_raw_artifacts(self):
        result=self.run_fixture();t.analyze(self.c,result['run'],self.analysis(result['run']))
        documents=t.export_reports(self.c)
        self.assertEqual(list(documents),['reports/tests/fixture/latest.md'])
        self.assertIn('测试审查报告',documents['reports/tests/fixture/latest.md'])
        self.assertNotIn('console.log',documents)

if __name__=='__main__':unittest.main(verbosity=2)
