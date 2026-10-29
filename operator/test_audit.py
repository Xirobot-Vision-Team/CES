"""Audit exclusion must not hide real work; no Git repositories or remote writes."""
import copy,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from datetime import date
import ces_audit as a
import ces_reports as r
import ces_periods as periods
import test_daily_build as daily_fixtures
from test_daily_build import Client

SHA='a'*40;PARENT='b'*40
class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=dict(repository_path=self.tmp.name,state_root=self.tmp.name,cache_root=self.tmp.name,
                    github=dict(repository_id=1),repository_docs=dict(relative_directory='docs/ces'),audit=dict(exclude_ces_generated_documents=True))
        self.paths=['docs/ces/.ces-documents.json','docs/ces/knowledge/a.md']
        self.message='ordinary docs update'
        self.manifest=dict(schema='ces.repository_documents.v1',repository_id=1,files={'knowledge/a.md':{'sha256':'c'*64}})
    def git(self,c,*args):
        if args[:2]==('show','-s'):return PARENT+'\n'+self.message
        if args[0]=='diff':return '\0'.join(self.paths)+'\0'
        if args[0]=='show':return a.json.dumps(self.manifest)
        raise AssertionError(args)
    def receipt(self,**changes):
        row=dict(schema='ces.document_git_publish.v1',repository_id=1,commit=SHA,parent=PARENT,paths=self.paths,status='published_and_local_branch_synchronized');row.update(changes)
        a.w.save(a.receipt_root(self.c)/(SHA+'.json'),row)
    def classify(self):
        with patch.object(a.w,'git',side_effect=self.git):return a.classify(self.c,SHA)
    def test_human_docs_without_proof_are_kept(self):self.assertIsNone(self.classify())
    def test_title_and_author_are_not_proof(self):
        self.message='docs: update CES reports and source-cited knowledge';self.assertIsNone(self.classify())
    def test_verified_receipt_and_managed_scope_are_excluded(self):
        self.receipt();self.assertEqual(self.classify()['proof'],'verified_publication_receipt')
    def test_machine_trailers_and_manifest_are_excluded(self):
        self.message+='\n\nCES-Generated-By: CES\nCES-Repository-Id: 1';self.assertEqual(self.classify()['proof'],'ces_commit_trailers')
    def test_mixed_business_commit_is_kept_even_with_trailers(self):
        self.message+='\nCES-Generated-By: CES\nCES-Repository-Id: 1';self.paths.append('src/main.cpp');self.assertIsNone(self.classify())
    def test_unowned_document_is_kept(self):
        self.paths.append('docs/ces/human.md');self.receipt();self.assertIsNone(self.classify())
    def test_wrong_repository_receipt_is_kept(self):
        self.receipt(repository_id=2);self.assertIsNone(self.classify())
    def test_unconfirmed_push_receipt_is_kept(self):
        self.receipt(status='commit_prepared');self.assertIsNone(self.classify())
    def test_receipt_scope_mismatch_is_kept(self):
        self.receipt(paths=['docs/ces/other.md']);self.assertIsNone(self.classify())
    def test_merge_commit_is_kept(self):
        with patch.object(a.w,'git',return_value=PARENT+' '+'c'*40+'\nCES-Generated-By: CES\nCES-Repository-Id: 1'):self.assertIsNone(a.classify(self.c,SHA))
    def test_unavailable_evidence_keeps_commit_and_discloses_warning(self):
        rows=[dict(sha=SHA)]
        with patch.object(a,'classify',side_effect=RuntimeError('unavailable')):kept,excluded,warnings=a.filter_commits(self.c,rows)
        self.assertEqual(kept,rows);self.assertEqual(excluded,[]);self.assertEqual(warnings[0]['status'],'kept_unverified')
    def test_normalization_does_not_rewrite_archived_source(self):
        row=dict(id='source',commits=[dict(sha=SHA)],findings=[dict(origins=[dict(commit=SHA)])]);old=copy.deepcopy(row)
        with patch.object(a,'classify',return_value=dict(sha=SHA,reason='ces_generated_managed_documents',proof='verified_publication_receipt',paths=self.paths)):
            normalized=a.normalize_daily(self.c,row)
        self.assertEqual(row,old);self.assertEqual(normalized['commits'],[]);self.assertEqual(normalized['findings'],[])
    def test_exported_daily_does_not_reuse_old_work_count(self):
        core=dict(id='source',date='2026-01-02',commits=[dict(sha=SHA)],findings=[],markdown='本人提交：1 条')
        proof=dict(sha=SHA,reason='ces_generated_managed_documents',proof='verified_publication_receipt',paths=self.paths)
        with patch.object(a,'classify',return_value=proof):text=a.daily_markdown(self.c,core)
        self.assertIn('有效工作提交：0',text);self.assertNotIn('本人提交：1',text)
    def test_exported_legacy_period_has_correct_filtered_count(self):
        core=dict(id='period',kind='monthly',period_start='2026-01-01',period_end='2026-01-31',markdown='去重提交：1',daily_records=[dict(id='source',commits=[dict(sha=SHA)],findings=[])])
        proof=dict(sha=SHA,reason='ces_generated_managed_documents',proof='verified_publication_receipt',paths=self.paths)
        with patch.object(a,'classify',return_value=proof):text=a.period_markdown(self.c,core)
        self.assertIn('有效工作提交：0',text);self.assertNotIn('去重提交：1',text)

class DailyAuditTests(unittest.TestCase):
    def setUp(self):
        daily_fixtures.DailyBuildTests.setUp(self);self.c['audit']=dict(exclude_ces_generated_documents=True)
    def test_maintenance_only_day_is_a_repository_status_without_personal_post(self):
        proof=dict(sha=SHA,reason='ces_generated_managed_documents',proof='verified_publication_receipt',paths=['docs/ces/a.md'])
        with patch.object(a,'classify',return_value=proof),patch('ces_tracking.for_report',return_value=None),patch.object(Client,'publish',side_effect=AssertionError('personal POST')):
            rows=r.daily_reports(self.c,self.run,Client(),{},True)
        self.assertEqual(rows[0]['core']['recipient'],'_repository');self.assertEqual(rows[0]['core']['commits'],[])
        self.assertIsNone(rows[0]['publication']);self.assertIn('有效提交：0',rows[0]['core']['markdown'])

class PeriodAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=dict(output_root=self.tmp.name,cache_root=self.tmp.name,state_root=self.tmp.name,github=dict(repository_id=1),audit=dict(exclude_ces_generated_documents=True))
        self.daily=dict(id='daily',date='2026-01-02',recipient='developer',generated_at='2026-01-02T18:00:00+08:00',commits=[dict(sha=SHA)],findings=[])
    def test_all_periods_refilter_old_child_reports(self):
        for kind,child in [('weekly','daily'),('monthly','weekly'),('yearly','monthly')]:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as folder:
                self.c['output_root']=folder
                if child=='daily':
                    core=self.daily;record=dict(schema='ces.daily_report_record.v1',core=core,core_sha256=periods.d.digest(core))
                    path=Path(folder)/'reports/daily/2026-01-02/developer/source.json'
                else:
                    core=dict(repository_id=1,id='child',period_start='2026-01-01',generated_at='2026-01-03T20:00:00+08:00',daily_records=[self.daily])
                    record=dict(schema='ces.period_report_record.v1',core=core,core_sha256=periods.d.digest(core));path=Path(folder)/('reports/'+child+'/2026-01-01/source.json')
                if child=='daily':core['repository_id']=1;record['core_sha256']=periods.d.digest(core)
                a.w.save(path,record)
                proof=dict(sha=SHA,reason='ces_generated_managed_documents',proof='verified_publication_receipt',paths=['docs/ces/a.md'])
                with patch.object(a,'classify',return_value=proof),patch('ces_tracking.for_report',return_value=None):context=periods.load_inputs(self.c,kind,date(2026,1,3))
                self.assertEqual(context['commits'],[]);self.assertEqual(len(context['excluded_maintenance_commits']),1)

if __name__=='__main__':unittest.main(verbosity=2)
