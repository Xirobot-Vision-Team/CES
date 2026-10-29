"""Tracking state-machine and evidence-boundary tests; no Git repos or network."""
import base64,copy,json,sqlite3,tempfile,unittest
from pathlib import Path
from datetime import datetime,timezone,timedelta
from unittest.mock import patch
import ces_tracking as t

HEAD="a"*40
def issue(number=1):
    return dict(number=number,id=100+number,title="Code problem",body="<!-- ces-issue:"+"c"*64+" -->",html_url="https://github.com/example/project/issues/"+str(number),
                state="open",state_reason=None,closed_at=None,created_at="2026-01-01T00:00:00Z",assignees=[dict(login="developer")],labels=[])
class Fake:
    def __init__(self,c):self.c=c;self.prefix="/repos/example/project";self.account_login="operator";self.head=HEAD;self.items=[issue()];self.comments=[];self.events=[];self.fail=False;self.writes=[]
    def pages(self,path):
        if self.fail:raise RuntimeError("unavailable")
        if "/comments" in path:return self.comments
        if "/timeline" in path:return self.events
        return self.items
    def get(self,path):
        if path==self.prefix:return dict(default_branch="main")
        if "/commits/" in path:return dict(sha=self.head)
        if "/issues/" in path:return self.items[0]
        raise AssertionError(path)
    def write(self,path,payload,method="POST"):
        self.writes.append((path,payload,method))
        if method=="PATCH":
            self.items[0].update(payload)
            return self.items[0],"verified"
        return dict(html_url="https://github.com/example/project/issues/1#issuecomment-1"),"verified"
class TrackingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=dict(state_root=self.tmp.name+"/state",output_root=self.tmp.name+"/out",repository_path=self.tmp.name,
                    github=dict(repository_id=1,repository="example/project"),
                    notifications=dict(allow_publish=True),
                    execution_policy=dict(run_runtime_tests=True),
                    issue_tracking=dict(enabled=True,allow_reminders=True,stale_days=7,reminder_cooldown_days=7,required_test_steps=["unit"],review_max_age_days=7),
                    build_validation=dict(steps=[dict(name="unit",kind='test',argv=["runner","--unit"],cwd=str(Path(self.tmp.name).resolve()))]))
        self.client=Fake(self.c)
    def sync(self,execute=False):
        with patch.object(t.reports,"Client",return_value=self.client):return t.sync(self.c,execute)
    def snapshot(self,state="open",comments=None):
        x=issue();x["state"]=state
        return t.projection(x,comments or [],[],[],HEAD)
    def input(self):
        body=dict(schema="ces.issue_fix_input.v1",repository_id=1,number=1,issue_id=101,head_sha=HEAD,issue_sha="d"*64,snapshot_sha="e"*64,
                  sources=[dict(path="source.cpp",sha256=t.w.sha("return true;"),git_blob_sha="f"*40,text="return true;")])
        body["input_sha256"]=t.digest(body);return body
    def review(self,verdict="fixed"):
        return dict(schema="ces.issue_fix_review.v1",input_sha256=self.input()["input_sha256"],verdict=verdict,
                    reasoning="A source-bound assessment of the exact error propagation and its expected contract.",
                    verification_criteria="Both branch failures must be returned to the caller.",
                    citations=[dict(path="source.cpp",line_start=1,line_end=1,quote="return true;")],test_receipts=[])
    def receipt(self,exit_code=0):
        r=dict(repository_id=1,number=1,step="unit",kind='test',configuration_sha256=t.digest(self.c['build_validation']['steps'][0]),head_sha=HEAD,source_clean_before_and_after=True,
               completed_at=t.stamp(t.now()),argv=["runner","--unit"],cwd=str(Path(self.tmp.name).resolve()),exit_code=exit_code)
        r["receipt_id"]=t.digest(r);return r
    def test_managed_reports_excluded(self):
        x=issue();x["body"]="<!-- ces-report-topic:daily:1 -->";self.assertFalse(t.managed(x))
        self.assertTrue(t.managed(issue()))
    def test_prs_excluded(self):
        x=issue();x["pull_request"]={};self.assertFalse(t.managed(x))
    def test_closed_is_not_fixed(self):self.assertEqual(t.classify(self.snapshot("closed"),None,None),"closed_unverified")
    def test_no_auto_progress_from_assignment(self):self.assertEqual(t.classify(self.snapshot(),None,None),"open")
    def test_claimed_comment_is_only_progress(self):
        comment=dict(id=1,body="fixed please close",updated_at="2026-01-02T00:00:00Z",user=dict(login="developer"),html_url="https://example.test/comment")
        self.assertEqual(t.classify(self.snapshot(comments=[comment]),None,None),"in_progress")
    def test_own_reminder_not_progress(self):
        comment=dict(id=1,body="<!-- ces-tracking:key -->",updated_at="2026-01-02T00:00:00Z",user=dict(login="operator"),html_url="")
        self.assertEqual(t.classify(self.snapshot(comments=[comment]),None,None),"open")
    def test_linked_pr_is_not_fix(self):
        snap=self.snapshot();snap["pulls"]=[dict(merged=True,state="closed")]
        self.assertEqual(t.classify(snap,None,None),"fix_candidate")
    def test_verified_source_and_verdict(self):
        s=self.snapshot();rv=dict(head_sha=HEAD,issue_sha=t.issue_sha(s),verdict="fixed")
        self.assertEqual(t.classify(s,None,rv),"resolved_verified")
    def test_new_head_invalidates_verification(self):
        s=self.snapshot();rv=dict(head_sha="b"*40,issue_sha=t.issue_sha(s),verdict="fixed")
        self.assertNotEqual(t.classify(s,None,rv),"resolved_verified")
    def test_reopen_after_verified_is_suspect(self):
        self.assertEqual(t.classify(self.snapshot(),dict(lifecycle="resolved_verified"),None),"regression_suspected")
    def test_unknown_not_absence(self):
        s=self.snapshot();s["unavailable"]=True
        self.assertEqual(t.classify(s,None,None),"unknown")
    def test_baseline_then_no_duplicate_events(self):
        first=self.sync();second=self.sync()
        self.assertEqual(len(first["changes"]),1);self.assertEqual(second["changes"],[])
        self.assertEqual(first["sync_id"],second["sync_id"])
    def test_close_and_reopen_events(self):
        self.sync();self.client.items[0]["state"]="closed"
        self.assertEqual(self.sync()["changes"][0]["kind"],"closed_unverified")
        self.client.items[0]["state"]="open"
        self.assertEqual(self.sync()["changes"][0]["kind"],"reopened")
    def test_known_issue_read_failure_becomes_unknown(self):
        self.sync()
        with patch.object(t,"observe",side_effect=RuntimeError("unavailable")):result=self.sync()
        self.assertEqual(result["issues"][0]["lifecycle"],"unknown")
    def test_failure_preserves_previous_snapshot(self):
        self.sync();previous=(t.output(self.c)/"latest.json").read_bytes();self.client.fail=True
        with self.assertRaises(RuntimeError):self.sync()
        self.assertEqual((t.output(self.c)/"latest.json").read_bytes(),previous)
        self.assertTrue((t.output(self.c)/"sync-error.json").exists())
    def test_no_first_baseline_reminder(self):
        result=self.sync(True);self.assertEqual(result["notifications"],[]);self.assertEqual(self.client.writes,[])
    def test_stale_reminder_then_cooldown(self):
        self.sync()
        db=t.dbopen(self.c)
        old=t.stamp(t.now()-timedelta(days=8))
        db.execute("UPDATE issues SET last_change=?",(old,));db.close()
        first=self.sync(True);second=self.sync(True)
        self.assertEqual(len(first["notifications"]),1);self.assertEqual(second["notifications"],[])
        self.assertEqual(len(self.client.writes),1)
    def test_repo_scoped_db(self):
        x=copy.deepcopy(self.c);x["github"]["repository_id"]=2
        self.assertNotEqual(t.home(x),t.home(self.c))
    def test_binding_tamper_rejected(self):
        inp=self.input();inp["head_sha"]="b"*40
        with self.assertRaisesRegex(RuntimeError,"BINDING_INVALID"):t.verify_review(self.c,self.review(),inp)
    def test_quote_tamper_rejected(self):
        review=self.review("not_fixed");review["citations"][0]["quote"]="does not exist"
        with self.assertRaisesRegex(RuntimeError,"NOT_PRESENT"):t.verify_review(self.c,review,self.input())
    def test_no_tests_never_fixed(self):
        with self.assertRaisesRegex(RuntimeError,"REAL_TEST_RECEIPTS"):t.verify_review(self.c,self.review(),self.input())
    def test_not_fixed_can_be_source_only(self):
        self.assertEqual(t.verify_review(self.c,self.review("not_fixed"),self.input())["verdict"],"not_fixed")
    def test_successful_bound_test_admits_fixed(self):
        receipt=self.receipt();review=self.review();review["test_receipts"]=[receipt["receipt_id"]]
        self.assertEqual(t.verify_review(self.c,review,self.input(),lambda key:receipt)["verdict"],"fixed")
    def test_failed_test_does_not_admit_fixed(self):
        receipt=self.receipt(1);review=self.review();review["test_receipts"]=[receipt["receipt_id"]]
        with self.assertRaisesRegex(RuntimeError,"MISSING_OR_FAILED"):t.verify_review(self.c,review,self.input(),lambda key:receipt)
    def test_other_commit_test_rejected(self):
        receipt=self.receipt();receipt["head_sha"]="b"*40;receipt.pop("receipt_id");receipt["receipt_id"]=t.digest(receipt)
        review=self.review();review["test_receipts"]=[receipt["receipt_id"]]
        with self.assertRaisesRegex(RuntimeError,"SOURCE_MISMATCH"):t.verify_review(self.c,review,self.input(),lambda key:receipt)
    def test_regression_requires_failing_test(self):
        receipt=self.receipt();review=self.review("regression");review["test_receipts"]=[receipt["receipt_id"]]
        with self.assertRaisesRegex(RuntimeError,"REQUIRES_FAILURE"):t.verify_review(self.c,review,self.input(),lambda key:receipt)
    def test_closed_transition_disabled_by_default(self):
        with self.assertRaisesRegex(RuntimeError,"NOT_AUTHORIZED"):t.transition(self.c,1,"closed",True)
    def test_missing_build_config_cannot_execute(self):
        with self.assertRaisesRegex(RuntimeError,"NOT_CONFIGURED"):t.run_test(self.c,1,"missing")
    def test_projection_stable_without_check_time(self):
        self.sync();first=t.for_report(self.c);self.sync()
        self.assertEqual(first,t.for_report(self.c))
    def test_lock_collision_does_not_write(self):
        guard=t.lock(self.c)
        try:
            with self.assertRaises(FileExistsError):self.sync()
        finally:guard.unlink()
    def test_status_history_persists_between_connections(self):
        self.sync();self.assertEqual(t.history(self.c,1)['events'][0]['kind'],'baseline')
    def test_not_fixed_assessment_is_explicit(self):
        snap=self.snapshot();review=dict(head_sha=HEAD,issue_sha=t.issue_sha(snap),verdict='not_fixed')
        self.assertEqual(t.classify(snap,None,review),'not_fixed')
    def test_reminder_failure_blocks_future_buckets(self):
        self.sync();db=t.dbopen(self.c);old=t.stamp(t.now()-timedelta(days=8))
        db.execute('UPDATE issues SET last_change=?',(old,));db.close()
        with patch.object(self.client,'write',side_effect=RuntimeError('network')):
            with self.assertRaisesRegex(RuntimeError,'network'):self.sync(True)
        result=self.sync(True)
        self.assertEqual(result['notifications'][0]['status'],'unresolved_previous_delivery_no_retry')
    def test_identity_replacement_refused(self):
        self.sync();self.client.items[0]['id']=999
        with self.assertRaisesRegex(RuntimeError,'IDENTITY_CHANGED'):self.sync()
    def test_changed_test_config_refused(self):
        receipt=self.receipt();review=self.review();review['test_receipts']=[receipt['receipt_id']]
        self.c['build_validation']['steps'][0]['argv']=['other-runner']
        with self.assertRaisesRegex(RuntimeError,'CONFIG_CHANGED'):t.verify_review(self.c,review,self.input(),lambda key:receipt)
    def test_test_log_tamper_refused(self):
        receipt=self.receipt();receipt.pop('receipt_id');receipt['log_sha256']=t.w.sha(b'correct')
        receipt['receipt_id']=t.digest(receipt);key=receipt['receipt_id']
        dest=t.home(self.c)/'test-receipts';dest.mkdir(parents=True)
        t.w.save(dest/(key+'.json'),receipt);(dest/(key+'.log')).write_bytes(b'changed')
        review=self.review();review['test_receipts']=[key]
        with self.assertRaisesRegex(RuntimeError,'LOG_HASH_MISMATCH'):t.verify_review(self.c,review,self.input())
    def test_source_content_is_verified_as_git_blob(self):
        raw=b'valid source\n';hash=__import__('hashlib')
        blob=hash.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        response=dict(type='file',encoding='base64',size=len(raw),sha=blob,content=base64.b64encode(raw).decode())
        with patch.object(self.client,'get',return_value=response):self.assertEqual(t.source(self.c,self.client,HEAD,'source.cpp')['text'],'valid source\n')
        response['sha']='0'*40
        with patch.object(self.client,'get',return_value=response):
            with self.assertRaisesRegex(RuntimeError,'BLOB_MISMATCH'):t.source(self.c,self.client,HEAD,'source.cpp')
    def test_transition_without_valid_review_cannot_close(self):
        self.sync();self.c['issue_tracking']['allow_auto_close']=True
        with patch.object(t.reports,'Client',return_value=self.client):
            with self.assertRaisesRegex(RuntimeError,'REQUIRES_VERIFIED_REVIEW'):t.transition(self.c,1,'closed',True)
    def test_read_failure_never_destroys_durable_events(self):
        self.sync();before=t.history(self.c,1)['events'];self.client.fail=True
        with self.assertRaises(RuntimeError):self.sync()
        self.assertEqual(before,t.history(self.c,1)['events'])
    def test_new_issue_timeline_failure_is_unknown(self):
        with patch.object(t,'observe',side_effect=RuntimeError('unavailable')):result=self.sync()
        self.assertEqual(result['issues'][0]['lifecycle'],'unknown')
    def verified_assessment(self,verdict='fixed'):
        self.sync();db=t.dbopen(self.c);row=db.execute('SELECT * FROM issues WHERE number=1').fetchone();snap=json.loads(row['snapshot_json']);db.close()
        inp=self.input();inp.pop('input_sha256');inp['snapshot_sha']=row['snapshot_sha'];inp['issue_sha']=t.issue_sha(snap);inp['input_sha256']=t.digest(inp)
        dest=t.home(self.c)/'review-inputs'/(inp['input_sha256']+'.json');t.w.save(dest,inp)
        receipt=self.receipt(0 if verdict=='fixed' else 1);receipt.pop('receipt_id');receipt['log_sha256']=t.w.sha(b'real captured log');receipt['receipt_id']=t.digest(receipt)
        logs=t.home(self.c)/'test-receipts';logs.mkdir(parents=True,exist_ok=True)
        (logs/(receipt['receipt_id']+'.log')).write_bytes(b'real captured log');t.w.save(logs/(receipt['receipt_id']+'.json'),receipt)
        review=self.review(verdict);review['input_sha256']=inp['input_sha256'];review['test_receipts']=[receipt['receipt_id']]
        draft=Path(self.tmp.name)/'review.json';t.w.save(draft,review)
        with patch.object(t.reports,'Client',return_value=self.client),patch.object(t,'source',return_value=inp['sources'][0]):result=t.review(self.c,dest,draft)
        return result
    def test_review_persists_and_sync_preserves_verification(self):
        result=self.verified_assessment()
        self.assertEqual(result['lifecycle'],'resolved_verified')
        self.assertEqual(self.sync()['issues'][0]['lifecycle'],'resolved_verified')
    def test_reviewed_close_rebinds_own_state_event(self):
        self.verified_assessment();self.c['issue_tracking']['allow_auto_close']=True
        with patch.object(t.reports,'Client',return_value=self.client):result=t.transition(self.c,1,'closed',True)
        self.assertEqual(result['state'],'closed')
        self.assertEqual(self.sync()['issues'][0]['lifecycle'],'resolved_verified')
    def test_reviewed_regression_can_reopen_when_enabled(self):
        self.client.items[0]['state']='closed';self.verified_assessment('regression')
        self.c['issue_tracking']['allow_auto_reopen']=True
        with patch.object(t.reports,'Client',return_value=self.client):result=t.transition(self.c,1,'open',True)
        self.assertEqual(result['state'],'open')
        self.assertEqual(self.sync()['issues'][0]['lifecycle'],'regression_suspected')
    def test_closure_rejects_new_remote_head_after_review(self):
        self.verified_assessment();self.c['issue_tracking']['allow_auto_close']=True;self.client.head='b'*40
        with patch.object(t.reports,'Client',return_value=self.client):
            with self.assertRaisesRegex(RuntimeError,'REVIEW_STALE'):t.transition(self.c,1,'closed',True)
    def test_uncertain_comment_can_be_reconciled_without_post(self):
        self.sync();db=t.dbopen(self.c);db.execute('UPDATE issues SET last_change=?',(t.stamp(t.now()-timedelta(days=8)),));db.close()
        def uncertain(path,payload,method='POST'):
            self.client.comments.append(dict(id=1,body=payload['body'],updated_at=t.stamp(t.now()),user=dict(login='operator'),html_url='https://github.com/example/project/issues/1#issuecomment-1'))
            raise RuntimeError('response lost')
        with patch.object(self.client,'write',side_effect=uncertain):
            with self.assertRaisesRegex(RuntimeError,'response lost'):self.sync(True)
        result=self.sync(True)
        self.assertEqual(result['notifications'][0]['status'],'previous_delivery_reconciled')
        self.assertEqual(self.client.writes,[])
if __name__=="__main__":unittest.main(verbosity=2)

