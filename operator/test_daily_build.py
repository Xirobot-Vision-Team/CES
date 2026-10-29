"""Published daily reports must carry the build bound to that reviewed run."""
import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import ces_reports as r

class Client:
    def commit(self,sha):return dict(author_login='developer',committer_login='developer')
    def publish(self,*args):return dict(status='readback_verified',number=1,url='https://github.com/example/repo/issues/1',recipients=args[-1])

class DailyBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);root=Path(self.tmp.name)
        self.run=root/'run';self.run.mkdir()
        self.c=dict(output_root=str(root/'output'),cache_root=str(root/'cache'),state_root=str(root/'state'),
                    github=dict(repository_id=1,repository='example/repo'),execution_policy=dict(build_before_analysis=True),utc_offset='+08:00')
        for name,value in {
            'run.json':dict(head='a'*40,source_mode='delivered_target_diff'),
            'daily-activity.json':dict(start='2026-01-02T00:00:00+08:00',end='2026-01-02T18:00:00+08:00',commits=[dict(sha='a'*40,subject='Update docs')]),
            'validate.json':dict(data=dict(packet_sha256='b'*64,summary='Reviewed documentation changes; no new business source.',checked_findings=[],limitations=['Static review only.'])),
            'issue-proposals.json':[],'issue-results.json':[],
            'preflight.json':dict(status='ready',build=dict(head='a'*40,status='passed',configuration='Release',platform='x64',steps=[dict(name='solution',exit_code=0,seconds=1.2)]))
        }.items():r.w.save(self.run/name,value)
    def reports(self):
        with patch('ces_tracking.for_report',return_value=None):return r.daily_reports(self.c,self.run,Client(),{},False)
    def test_daily_contains_bound_build_and_overall_review(self):
        core=self.reports()[0]['core']
        self.assertEqual(core['preanalysis_build']['build']['head'],'a'*40)
        self.assertIn('Release｜x64',core['markdown']);self.assertIn('退出码 0',core['markdown'])
        self.assertIn('Reviewed documentation changes',core['markdown'])
    def test_global_latest_build_cannot_replace_run_build(self):
        first=self.reports()[0]['core']
        r.w.save(Path(self.c['cache_root'])/'lifecycle/last-preflight.json',dict(status='build_failed',build=dict(head='c'*40)))
        second=self.reports()[0]['core']
        self.assertEqual(first['id'],second['id']);self.assertEqual(second['preanalysis_build']['build']['status'],'passed')
    def test_failed_bound_build_changes_report_snapshot(self):
        passed=self.reports()[0]['core'];value=r.w.load(self.run/'preflight.json')
        value['status']='build_failed';value['build']['status']='failed';value['build']['steps'][0]['exit_code']=1;r.w.save(self.run/'preflight.json',value)
        failed=self.reports()[0]['core']
        self.assertNotEqual(passed['id'],failed['id']);self.assertIn('结果：failed',failed['markdown'])
    def test_missing_required_receipt_stops_report(self):
        (self.run/'preflight.json').unlink()
        with self.assertRaisesRegex(RuntimeError,'BOUND_BUILD_RECEIPT_REQUIRED'):self.reports()
    def test_wrong_source_build_stops_report(self):
        value=r.w.load(self.run/'preflight.json');value['build']['head']='c'*40;r.w.save(self.run/'preflight.json',value)
        with self.assertRaisesRegex(RuntimeError,'BUILD_SOURCE_MISMATCH'):self.reports()

if __name__=='__main__':unittest.main(verbosity=2)
