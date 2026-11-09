"""Repository conclusions remain primary; operational evidence is an appendix."""
import tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import ces_periods as periods
import ces_workflow as w

class ReportingStandardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=dict(output_root=self.tmp.name,state_root=self.tmp.name,cache_root=self.tmp.name,
                    github=dict(repository_id=1,repository='example/repo'),utc_offset='+00:00')
        self.context=dict(repository_id=1,kind='weekly',period_start='2026-01-05',as_of='2026-01-11',
                          children=[dict(id='child',url=None,core_sha256='a'*64)],daily_records=[],
                          commits=[],findings=[],missing_dates=[],input_binding_sha256='b'*64,
                          preanalysis_build=dict(build=dict(status='passed',head='c'*40,
                            configuration='Release',platform='x64',steps=[],runtime_tests_executed=False,application_launched=False)))
        self.analysis=Path(self.tmp.name)/'analysis.json'
        w.save(self.analysis,dict(schema='ces.period_synthesis.v1',input_binding_sha256='b'*64,
                                 achievements=['The parser preserves field order.'],risks=[],next_steps=[],knowledge_updates=[]))
    def render(self):
        with patch.object(periods,'load_inputs',return_value=self.context):
            result=periods.build(self.c,'weekly','2026-01-11',analysis_path=self.analysis)
        return result,w.load(result['path'])
    def test_repository_analysis_precedes_evidence_without_product_process_text(self):
        _,record=self.render();text=record['core']['markdown'];main,appendix=text.split('<details>',1)
        self.assertTrue(main.startswith('# 仓库周总结'))
        self.assertIn('The parser preserves field order.',main)
        self.assertNotIn('汇总不重新分析业务源码',text)
        self.assertNotIn('GitHub内的个人提醒',text)
        self.assertIn('构建结果',appendix);self.assertIn('Release｜x64',appendix)
        self.assertTrue(text.rstrip().endswith('</details>'))
    def test_build_failure_remains_visible_in_main_report(self):
        self.context['preanalysis_build']['build']['status']='failed'
        _,record=self.render();main=record['core']['markdown'].split('<details>',1)[0]
        self.assertIn('结果：failed',main)
    def test_existing_archive_is_reused_without_rewriting_or_new_identity(self):
        result,record=self.render();legacy=dict(record);legacy['core']=dict(record['core'],markdown='# Historical report\n')
        legacy['core_sha256']=periods.d.digest(legacy['core']);w.save(result['path'],legacy)
        before=Path(result['path']).read_bytes();again,observed=self.render()
        self.assertEqual(result['id'],again['id']);self.assertEqual(observed,legacy)
        self.assertEqual(Path(result['path']).read_bytes(),before)

if __name__=='__main__':unittest.main()
