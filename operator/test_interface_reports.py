"""Reports separate interfaces using immutable run registrations, including green cases."""
import copy,json,unittest
from pathlib import Path
from unittest.mock import patch
import ces_testing as t
import test_project_testing as pipeline
import test_notification_cc as cc

class InterfaceReportsTests(unittest.TestCase):
    setUp=pipeline.PipelineTests.setUp
    setup_contract=pipeline.PipelineTests.setup_contract
    analysis=pipeline.PipelineTests.analysis
    def start(self,missing=False):
        self.c['testing'].update(report_grouping='registered_interface',report_recipients=['static-wrong'],report_signers=['static-wrong'],project_owners=[],test_maintainers=[],cc_recipients=['other'])
        rows=[dict(id='config-a',kind='function',name='InterfaceAlpha',developers=['developer'],case_ids=['case-one']),dict(id='config-b',kind='function',name='InterfaceBeta',developers=['lead'],case_ids=['case-two'])]
        self.c['testing']['entries'][0]['ownership']=rows
        if not missing:
            path=self.repo/'writer.py';source=path.read_text(encoding='utf-8')
            source=source.replace("print('fixture test completed')","doc=json.loads((root/'report.json').read_text());doc['tests'].append({'id':'case-two','status':'failed','message':'beta assertion failed; author=@outsider'});(root/'report.json').write_text(json.dumps(doc))\nprint('fixture test completed')")
            path.write_text(source,encoding='utf-8')
        prepared=self.setup_contract();self.contract['required_cases']=['case-one','case-two'];t.w.save(self.draft,self.contract);t.register(self.c,prepared['input'],self.draft,True)
        result=t.run_test(self.c,'fixture',True);return Path(result['run'])
    def grouped_analysis(self,run):
        path=self.analysis(run);draft=t.w.load(path);packet=t.w.load(run/'analysis-input.json')
        fields=('summary','root_cause','recommendation','verification','limitations','citations')
        draft['interface_analyses']=[dict(interface_id=g['interface_id'],case_ids=g['case_ids'],**{k:copy.deepcopy(draft[k]) for k in fields}) for g in packet['interface_reports']]
        t.w.save(path,draft);return path
    def test_one_run_sends_distinct_interface_reports_and_credits_from_snapshot(self):
        run=self.start();self.c['testing']['entries'][0]['ownership'][0]['developers']=['new-owner']
        t.analyze(self.c,run,self.grouped_analysis(run));original=(run/'analysis.json').read_bytes();server=cc.Server()
        with patch.object(t.w,'credential',return_value='test-only'),patch.object(t.w,'api',side_effect=server.api):
            published=t.publish(self.c,run,True);again=t.publish(self.c,run,True)
        self.assertEqual(len(server.issues),2);self.assertEqual(again['status'],'duplicate_skipped')
        recipients={tuple(x['primary_recipients']) for x in published['reports']};self.assertEqual(recipients,{('developer',),('lead',)})
        for issue in server.issues:
            body=issue['body'];self.assertIn('接口开发者署名',body);self.assertNotIn('static-wrong',body);self.assertNotIn('new-owner',body)
            if 'InterfaceAlpha' in body:
                self.assertIn('case-one',body);self.assertNotIn('case-two',body);self.assertNotIn('@lead',body)
                self.assertIn('整轮状态：failed；本接口状态：passed',body)
            else:
                self.assertIn('case-two',body);self.assertNotIn('case-one',body);self.assertNotIn('@developer',body)
            self.assertIn('@other',body)
        self.assertEqual(original,(run/'analysis.json').read_bytes())
        docs=t.export_reports(self.c);self.assertEqual(len(docs),3);self.assertIn('接口测试报告索引',docs['reports/tests/fixture/latest.md'])
    def test_each_interface_requires_its_own_bound_analysis(self):
        run=self.start()
        with self.assertRaisesRegex(RuntimeError,'ANALYSES_REQUIRED'):t.analyze(self.c,run,self.analysis(run))
        path=self.grouped_analysis(run);draft=t.w.load(path);draft['interface_analyses'][0]['case_ids']=['wrong'];t.w.save(path,draft)
        with self.assertRaisesRegex(RuntimeError,'CASE_SCOPE_CHANGED'):t.analyze(self.c,run,path)
    def test_nonmember_in_any_group_stops_all_sends(self):
        run=self.start();t.analyze(self.c,run,self.grouped_analysis(run));server=cc.Server();server.members.remove('lead')
        with patch.object(t.w,'credential',return_value='test-only'),patch.object(t.w,'api',side_effect=server.api),self.assertRaisesRegex(RuntimeError,'NOT_REPOSITORY_MEMBER'):t.publish(self.c,run,True)
        self.assertEqual(server.writes,[])
    def test_required_case_missing_remains_in_its_interface_report(self):
        run=self.start(missing=True);t.analyze(self.c,run,self.grouped_analysis(run));plan=t.publish(self.c,run,False)
        beta=next(x for x in plan['reports'] if x['name']=='InterfaceBeta')
        self.assertEqual(beta['summary']['status'],'inconclusive');self.assertEqual(beta['summary']['missing_required_cases'],['case-two'])
        self.assertEqual(beta['report_signers'],['lead'])
    def test_unmapped_green_case_is_not_assigned_to_project_recipient(self):
        run=self.start();receipt=t.w.load(run/'receipt.json');data=t.w.load(run/'results.json')
        data['cases'].append(dict(id='unregistered-pass',status='passed'))
        with self.assertRaisesRegex(RuntimeError,'UNMAPPED_CASES'):t.interface_groups(self.c,run,receipt,data)
    def test_multiple_configs_of_same_interface_coalesce_without_using_registration_id(self):
        run=self.start();receipt=t.w.load(run/'receipt.json');data=t.w.load(run/'results.json')
        snapshot=t.w.load(run/'ownership.json');snapshot['mappings'][1]['name']='InterfaceAlpha'
        snapshot.pop('ownership_snapshot_id');snapshot['ownership_snapshot_id']=t.digest(snapshot);t.w.save(run/'ownership.json',snapshot)
        receipt['ownership_sha256']=t.w.sha((run/'ownership.json').read_bytes())
        groups=t.interface_groups(self.c,run,receipt,data);self.assertEqual(len(groups),1)
        self.assertEqual(groups[0]['case_ids'],['case-one','case-two']);self.assertEqual(groups[0]['developers'],['developer','lead'])
    def test_global_process_or_parser_uncertainty_cannot_become_green_interface(self):
        run=self.start();receipt=t.w.load(run/'receipt.json');data=t.w.load(run/'results.json')
        receipt['timed_out']=True
        self.assertEqual({x['summary']['status'] for x in t.interface_groups(self.c,run,receipt,data)},{'timed_out'})
        receipt['timed_out']=False;data['summary']['parse_errors']=['missing-report-part']
        self.assertEqual({x['summary']['status'] for x in t.interface_groups(self.c,run,receipt,data)},{'inconclusive'})
        data['summary']['source_stable']=False
        with self.assertRaisesRegex(RuntimeError,'SOURCE_INVALIDATED'):t.interface_groups(self.c,run,receipt,data)

if __name__=='__main__':unittest.main()
