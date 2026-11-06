"""Large source batches, explicit gaps, citation binding and author-scoped reports."""
import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import ces_code_review as review
import ces_workflow as w
from test_daily_build import DailyBuildTests,Client

BASE='1'*40
HEAD='a'*40
def config(root):
    return dict(repository_path=str(root/'repo'),github=dict(repository_id=1,repository='example/repo'),
                cache_root=str(root/'cache'),state_root=str(root/'state'),output_root=str(root/'out'))

def fake_git(c,*args):
    if args[0]=='rev-parse':return BASE if args[-1].startswith(BASE) else HEAD
    if args[0]=='status':return ''
    if args[0]=='rev-list':return HEAD
    raise AssertionError(args)

def raw_git(c,*args):
    if args[0]=='diff':return b'src/widget.cpp\0'
    if args[0]=='diff-tree':return b'src/widget.cpp\0'
    raise AssertionError(args)

def draft_for(plan,commit=HEAD):
    refs=[dict(unit_id=u['id'],line_start=u['line_start'],line_end=u['line_start'],quote=u['text'].splitlines()[0]) for u in plan['units']]
    feature=dict(id='widget',title='Widget matching behavior',commits=[commit],purpose='Computes the matched feature position from input geometry.',
        behavior_change='Previously accepted all candidates; now scores candidates before selection.',
        mechanism='The caller builds candidates, then a bounded loop computes each distance and selects the minimum.',
        correctness='A candidate outside the range is rejected before selection; boundary equality remains included. Static reasoning only.',
        optimization='Cache repeated distances only if profiling confirms reuse; extra memory and invalidation add cost. Compare numerical outputs and latency first.',citations=refs)
    return dict(schema='ces.functional_review.v1',input_binding_sha256=plan['binding_sha256'],features=[feature],
                coverage=[dict(unit_id=u['id'],status='reviewed',reason='Read this source interval and its surrounding feature flow.') for u in plan['units']])

class BatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.c=config(self.root)
        self.raw=(b'int match(int x) { return x + 1; }\n')*12000
        for name,replacement in [('git',fake_git),('snapshot',lambda c:dict(head=HEAD)),]:
            p=patch.object(w,name,replacement);p.start();self.addCleanup(p.stop)
        p=patch.object(review,'raw_git',raw_git);p.start();self.addCleanup(p.stop)
        p=patch.object(review,'read_blob',lambda c,rev,path:self.raw);p.start();self.addCleanup(p.stop)
    def plan(self):return w.load(review.prepare(self.c,BASE)['plan'])
    def test_large_file_is_fully_split_and_before_after_retained(self):
        plan=self.plan();self.assertGreater(len(self.raw),262144)
        self.assertGreater(len(plan['units']),4)
        for side in ['before','after']:
            units=[x for x in plan['units'] if x['side']==side]
            self.assertEqual(sum(x['line_end']-x['line_start']+1 for x in units),12000)
            self.assertEqual(units[0]['line_start'],1);self.assertEqual(units[-1]['line_end'],12000)
            self.assertTrue(all(len(x['text'].encode())<=plan['budget']['batch_bytes'] for x in units))
        self.assertEqual(review.validate(self.c,plan,draft_for(plan))['reviewed_units'],len(plan['units']))
    def test_budget_gap_never_silently_becomes_read_source(self):
        self.c['review']=dict(budget=dict(max_total_bytes=1024))
        plan=self.plan();self.assertFalse(plan['units']);self.assertTrue(all(x['status']=='deferred' for x in plan['files']))
    def test_read_decision_for_every_batch_and_citation_required(self):
        plan=self.plan();draft=draft_for(plan);draft['coverage'].pop()
        with self.assertRaisesRegex(RuntimeError,'COVERAGE_INCOMPLETE'):review.validate(self.c,plan,draft)
        draft=draft_for(plan);draft['features'][0]['citations'].pop()
        with self.assertRaisesRegex(RuntimeError,'WITHOUT_ANALYSIS'):review.validate(self.c,plan,draft)
    def test_deferred_batch_not_accepted_as_cited_review(self):
        plan=self.plan();draft=draft_for(plan);draft['coverage'][0]['status']='deferred'
        with self.assertRaisesRegex(RuntimeError,'UNREVIEWED_SOURCE'):review.validate(self.c,plan,draft)
    def test_source_and_plan_changes_invalidate_analysis(self):
        plan=self.plan();draft=draft_for(plan);self.raw+=b'changed\n'
        with self.assertRaisesRegex(RuntimeError,'SOURCE_HASH_CHANGED'):review.validate(self.c,plan,draft)
        plan['units'][0]['text']='fake source'
        with self.assertRaisesRegex(RuntimeError,'PLAN_BINDING_INVALID'):review.validate(self.c,plan,draft)
    def test_resealed_fake_source_text_still_fails_against_git_blob(self):
        plan=self.plan();unit=plan['units'][0];unit['text']=unit['text'].replace('x + 1','x - 1')
        body=dict(unit);body.pop('id');unit['id']=review.digest(body)
        body=dict(plan);body.pop('binding_sha256');plan['binding_sha256']=review.digest(body)
        with self.assertRaisesRegex(RuntimeError,'UNIT_SOURCE_MISMATCH'):review.validate(self.c,plan,draft_for(plan))
    def test_resealed_omitted_interval_does_not_claim_complete_file(self):
        plan=self.plan();plan['units'].pop()
        body=dict(plan);body.pop('binding_sha256');plan['binding_sha256']=review.digest(body)
        with self.assertRaisesRegex(RuntimeError,'INTERVAL_INCOMPLETE'):review.validate(self.c,plan,draft_for(plan))
    def test_wrong_quote_line_and_unrelated_commit_rejected(self):
        plan=self.plan()
        for change,error in [(lambda f:f.update(commits=['f'*40]),'COMMIT_SCOPE'),
                             (lambda f:f['citations'][0].update(quote='not in source'),'QUOTE_MISSING'),
                             (lambda f:f['citations'][0].update(line_start=0),'LINE_RANGE')]:
            draft=draft_for(plan);change(draft['features'][0])
            with self.assertRaisesRegex(RuntimeError,error):review.validate(self.c,plan,draft)
    def test_explicit_encoding_retains_raw_hash(self):
        self.raw='函数测试\n'.encode('gb18030');plan=self.plan()
        self.assertTrue(all(x['status']=='deferred' for x in plan['files']))
        self.c['review']=dict(encoding_overrides={'src/widget.cpp':'gb18030'});plan=self.plan()
        self.assertEqual(plan['units'][0]['raw_sha256'],w.sha(self.raw));self.assertIn('函数',plan['units'][0]['text'])
    def test_binary_long_line_and_file_count_are_visible_gaps(self):
        for raw,reason in [(b'abc\0xyz','binary_or_unregistered_encoding'),(b'x'*150000,'single_line_exceeds_batch')]:
            self.raw=raw;self.assertTrue(all(x['reason']==reason for x in self.plan()['files']))
        self.raw=b'line\n';self.c['review']=dict(budget=dict(max_files=1))
        plan=w.load(review.prepare(self.c,BASE,context=['z/context.cpp'])['plan'])
        self.assertTrue(any(x.get('reason')=='file_budget' for x in plan['files']))
    def test_verified_maintenance_commit_exclusion_preserves_mixed_work(self):
        with patch('ces_audit.filter_commits',return_value=([],[dict(sha=HEAD)],[])):
            self.assertFalse(self.plan()['units'])
        self.assertTrue(self.plan()['units'])
    def test_invalid_budget_and_dirty_checkout_stop(self):
        self.c['review']=dict(budget=dict(max_files=True))
        with self.assertRaisesRegex(RuntimeError,'BUDGET_INVALID'):self.plan()
        self.c['review']={}
        with patch.object(w,'git',side_effect=lambda c,*a:' M file' if a[0]=='status' else fake_git(c,*a)):
            with self.assertRaisesRegex(RuntimeError,'CLEAN_CURRENT_HEAD'):self.plan()

class FunctionalDailyTests(DailyBuildTests):
    def add_functional(self):
        c=self.c;c['repository_path']=str(Path(self.tmp.name)/'repo');c['review']=dict(require_functional_analysis=True)
        with patch.object(w,'git',fake_git),patch.object(w,'snapshot',return_value=dict(head=HEAD)),patch.object(review,'raw_git',raw_git),patch.object(review,'read_blob',return_value=b'int match() { return 1; }\n'):
            plan=w.load(review.prepare(c,BASE)['plan']);draft=draft_for(plan)
            review.complete(c,Path(c['cache_root'])/'code-review'/plan['binding_sha256']/'plan.json',self.write_draft(draft),self.run/'functional-review.json')
        return plan,draft
    def write_draft(self,draft):
        p=Path(self.tmp.name)/'draft.json';w.save(p,draft);return p
    def reports(self):
        with patch('ces_tracking.for_report',return_value=None),patch.object(w,'git',fake_git),patch.object(review,'read_blob',return_value=b'int match() { return 1; }\n'):
            return __import__('ces_reports').daily_reports(self.c,self.run,Client(),{},False)
    def test_functional_analysis_exists_without_issue_and_precedes_build(self):
        self.add_functional();core=self.reports()[0]['core'];body=core['markdown']
        self.assertEqual(len(core['findings']),0);self.assertEqual(len(core['functional_review']['features']),1)
        self.assertLess(body.index('Computes the matched'),body.index('实际构建'))
        self.assertLess(body.index('<details>'),body.index('退出码 0'))
    def test_functional_policy_requires_analysis_and_preserves_legacy_optout(self):
        self.c['review']=dict(require_functional_analysis=True)
        with self.assertRaisesRegex(RuntimeError,'FUNCTIONAL_REVIEW_REQUIRED'):self.reports()
        self.c['review']={};self.assertTrue(self.reports())
    def test_unsupported_author_feature_does_not_leak_into_other_report(self):
        plan,draft=self.add_functional()
        self.assertFalse(review.feature_lines(self.c,dict(plan=plan,draft=draft),{'c'*40}))
    def test_changed_analysis_creates_new_semantic_snapshot(self):
        plan,draft=self.add_functional();first=self.reports()[0]['core']['id']
        record=w.load(self.run/'functional-review.json');record['draft']['features'][0]['optimization']+=' Prefer no change without a profile.'
        with patch.object(w,'git',fake_git),patch.object(review,'read_blob',return_value=b'int match() { return 1; }\n'):
            record['receipt']=review.validate(self.c,record['plan'],record['draft'])
        w.save(self.run/'functional-review.json',record);self.assertNotEqual(first,self.reports()[0]['core']['id'])

if __name__=='__main__':unittest.main()
