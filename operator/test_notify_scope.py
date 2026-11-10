"""Account reminders select only current-run or explicitly supplied period reports."""
import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import ces_product as p
import ces_workflow as w
import ces_documents as d

class FakeClient:
    account_login='sender';prefix='/repos/example/repo'
    def __init__(self):self.gets=[];self.writes=[];self.closed=False
    def pages(self,path):
        if path.endswith('/assignees'):return [dict(login='alice')]
        raise AssertionError('Unexpected detail/comment inventory: '+path)
    def maintainers(self):return ['alice']
    def get(self,path):
        self.gets.append(path);number=int(path.rsplit('/',1)[1])
        return dict(number=number,body='<!-- ces-report-topic:daily -->',state='closed' if self.closed else 'open',assignees=[dict(login='alice')],html_url='https://example.invalid/issues/'+str(number))
    def write(self,*args):self.writes.append(args);raise AssertionError('Unexpected write')

class NotifyScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.run=self.root/'run';self.run.mkdir()
        self.c=dict(output_root=str(self.root),github=dict(repository_id=1),notifications=dict(cc_recipients=[]))
        w.save(self.run/'issue-proposals.json',[]);w.save(self.run/'issue-results.json',[])
        w.save(self.run/'daily-report-records.json',dict(records=[dict(recipient='alice',publication=dict(number=10))]))
        self.client=FakeClient()
        a=patch('ces_reports.Client',return_value=self.client);a.start();self.addCleanup(a.stop)
        a=patch('ces_reports.resolve_origins',return_value={});a.start();self.addCleanup(a.stop)
    def period(self):
        core=dict(repository_id=1,kind='weekly',id='a',generated_at='2026-01-01T00:00:00Z')
        row=dict(schema='ces.period_report_record.v1',core=core,core_sha256=d.digest(core),publication=dict(number=20))
        path=self.root/'reports/weekly/period/a.json';w.save(path,row);return path,row
    def test_daily_does_not_follow_global_latest_or_archived_periods(self):
        path,row=self.period();w.save(self.root/'notifications/weekly-latest.json',dict(path=str(path),publication=dict(number=20)))
        result=p.notify(self.c,self.run,True)
        self.assertEqual([x['number'] for x in result['items']],[10])
        self.assertEqual(self.client.gets,[self.client.prefix+'/issues/10'])
    def test_explicit_period_archive_is_bound_to_the_request(self):
        path,_=self.period();result=p.notify(self.c,self.run,False,[path])
        self.assertEqual([x['number'] for x in result['items']],[10,20])
    def test_tampered_foreign_or_unpublished_period_rejected_before_assignment(self):
        for variant in ('hash','foreign','unpublished'):
            path,row=self.period()
            if variant=='hash':row['core']['id']='tamper'
            elif variant=='foreign':row['core']['repository_id']=2;row['core_sha256']=d.digest(row['core'])
            else:row['publication']=None
            w.save(path,row)
            with self.subTest(variant=variant),self.assertRaisesRegex(RuntimeError,'NOTIFY_PERIOD_'):p.notify(self.c,self.run,True,[path])
            self.assertEqual(self.client.writes,[])
    def test_outside_report_root_is_refused(self):
        with self.assertRaisesRegex(RuntimeError,'OUTSIDE_REPORT_ROOT'):p.notify(self.c,self.run,False,[self.root/'foreign.json'])
    def test_report_only_assignment_does_not_revalidate_unrelated_source_head(self):
        path,_=self.period()
        with patch('ces_reports.resolve_origins',side_effect=AssertionError('Unrelated source review')):
            self.assertEqual(len(p.notify(self.c,self.run,False,[path])['items']),2)
    def test_closed_code_issue_is_history_only_without_comments_or_assignment(self):
        self.client.closed=True
        w.save(self.run/'daily-report-records.json',dict(records=[]))
        w.save(self.run/'issue-proposals.json',[dict(title='old',finding_ids=[])])
        w.save(self.run/'issue-results.json',[dict(title='old',number=30)])
        result=p.notify(self.c,self.run,True)
        self.assertEqual(result['items'][0]['status'],'closed_history_preserved')
        self.assertEqual(self.client.writes,[])

if __name__=='__main__':unittest.main()
