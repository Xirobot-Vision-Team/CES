"""CC routing, actual message payloads and durable dedup without remote writes."""
import copy,json,tempfile,unittest
import contextlib,io
from pathlib import Path
from unittest.mock import patch
import ces_notifications as n
import ces_reports as r
import ces_workflow as w
import ces_issue_quality as q
import ces_product as product
import ces_tracking as tracking
import test_tracking as tracking_tests

class Server:
    def __init__(self):
        self.issues=[];self.comments=[];self.writes=[];self.members=['developer','lead','other'];self.uncertain=False
    def api(self,token,path,payload=None,method=None):
        verb=method or ('POST' if payload is not None else 'GET')
        if verb=='GET':
            if path=='/user':return dict(id=1,login='operator'),200
            if path=='/repos/example/project':return dict(id=2,has_issues=True,permissions=dict(push=True)),200
            if '/commits/' in path:return dict(sha='a'*40),200
            if '/collaborators?' in path:return [dict(login=x) for x in self.members],200
            if path.startswith('/repos/example/project/issues/comments/'):
                return copy.deepcopy(next(x for x in self.comments if x['id']==int(path.rsplit('/',1)[1]))),200
            if '/comments?' in path:
                number=int(path.split('/issues/')[1].split('/')[0])
                return [copy.deepcopy(x) for x in self.comments if x['number']==number],200
            if '/issues?' in path:return copy.deepcopy(self.issues),200
            if '/issues/' in path:return copy.deepcopy(next(x for x in self.issues if x['number']==int(path.rsplit('/',1)[1]))),200
            raise AssertionError(path)
        self.writes.append((path,copy.deepcopy(payload),verb))
        if verb=='POST' and path.endswith('/comments'):
            number=int(path.split('/issues/')[1].split('/')[0]);i=len(self.comments)+1
            obj=dict(id=i,number=number,body=payload['body'],html_url=f'https://github.com/example/project/issues/{number}#issuecomment-{i}')
            self.comments.append(obj)
        elif verb=='POST':
            number=len(self.issues)+1
            obj=dict(number=number,id=number+100,html_url=f'https://github.com/example/project/issues/{number}',**payload)
            obj['assignees']=[dict(login=x) for x in payload.get('assignees',[])]
            self.issues.append(obj)
        else:
            obj=next(x for x in self.issues if x['number']==int(path.rsplit('/',1)[1]))
            obj.update(payload)
            if 'assignees' in payload:obj['assignees']=[dict(login=x) for x in payload['assignees']]
        if self.uncertain:raise RuntimeError('response lost')
        return copy.deepcopy(obj),201 if verb=='POST' else 200

class CCTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=dict(state_root=self.tmp.name,notifications=dict(allow_publish=True,cc_recipients=['lead']),github=dict(repository_id=2,account_id=1,repository='example/project'))
        self.server=Server()
        self.addCleanup(patch.stopall)
        patch.object(w,'credential',return_value='test-only').start()
        patch.object(w,'api',side_effect=self.server.api).start()
    def client(self):return r.Client(self.c)
    def test_empty_config_preserves_bytes(self):
        self.c['notifications'].pop('cc_recipients')
        body='Original body\n\n';self.assertEqual(n.message(self.c,body),body)
        client=self.client();result=client.publish('daily:2','s','Title','Body',['developer'])
        self.assertEqual(result['snapshot'],'s');self.assertEqual(result['cc_recipients'],[])
    def test_validated_and_case_insensitive_dedup(self):
        self.c['notifications']['cc_recipients']=['Lead','lead','other']
        result=n.route(self.c,['LEAD','developer'])
        self.assertEqual(result['cc_recipients'],['other'])
        self.assertEqual(result['primary_recipients'],['developer','LEAD'])
    def test_invalid_input_fails_before_write(self):
        for bad in ('lead',None,['@lead'],['person@example.test'],['bad/name'],['-bad'],['bad-'],['two--hyphens'],['a\n@lead'],[12]):
            self.c['notifications']['cc_recipients']=bad
            with self.assertRaises(RuntimeError):self.client()
        self.assertEqual(self.server.writes,[])
    def test_non_member_stops_before_write(self):
        self.c['notifications']['cc_recipients']=['outsider']
        with self.assertRaisesRegex(RuntimeError,'NOT_REPOSITORY_MEMBER'):self.client()
        self.assertEqual(self.server.writes,[])
    def test_member_lookup_failure_stops(self):
        with patch.object(r.Client,'pages',side_effect=RuntimeError('unavailable')):
            with self.assertRaisesRegex(RuntimeError,'unavailable'):self.client()
    def test_message_idempotent_and_no_false_assignment(self):
        body=n.message(self.c,'Message',['developer'])
        self.assertEqual(n.message(self.c,body),body)
        self.assertEqual(body.count('@lead'),1)
        result,_=self.client().write('/repos/example/project/issues',dict(title='Code',body='Message',assignees=['developer']))
        self.assertEqual(self.server.writes[0][1]['assignees'],['developer'])
        self.assertIn('抄送：@lead',result['body'])
    def test_existing_primary_is_not_copied_again(self):
        result=self.client().publish('weekly:2','s','Title','Body',['lead','developer'])
        body=self.server.writes[0][1]['body']
        self.assertEqual(body.count('@lead'),1);self.assertEqual(result['cc_recipients'],[])
    def test_all_periods_and_daily_include_cc(self):
        client=self.client()
        for kind in ('daily','weekly','monthly','yearly'):
            result=client.publish(kind+':2','s',kind,'Body',['developer'])
            self.assertEqual(result['primary_recipients'],['developer'])
            self.assertEqual(result['cc_recipients'],['lead'])
            self.assertFalse(result['email_delivery_verified'])
            self.assertIn('@lead',self.server.writes[-1][1]['body'])
        self.assertEqual(len(self.server.writes),4)
    def test_same_snapshot_not_reposted(self):
        client=self.client();first=client.publish('daily:2','s','Title','Body',['developer'])
        second=client.publish('daily:2','s','Title','Body',['developer'])
        self.assertEqual(first['snapshot'],second['snapshot']);self.assertEqual(second['status'],'duplicate_skipped')
        self.assertEqual(len(self.server.writes),1)
    def test_changed_cc_routes_one_new_comment(self):
        client=self.client();first=client.publish('daily:2','s','Title','Body',['developer'])
        self.c['notifications']['cc_recipients']=['other']
        client=self.client();second=client.publish('daily:2','s','Title','Body',['developer'])
        self.assertNotEqual(first['snapshot'],second['snapshot'])
        self.assertIn('抄送：@other',self.server.comments[0]['body'])
        client.publish('daily:2','s','Title','Body',['developer'])
        self.assertEqual(len(self.server.writes),2)
    def test_unknown_post_reconciled_by_snapshot_without_resend(self):
        client=self.client();self.server.uncertain=True
        with self.assertRaisesRegex(RuntimeError,'response lost'):client.publish('daily:2','s','Title','Body',['developer'])
        self.server.uncertain=False
        result=client.publish('daily:2','s','Title','Body',['developer'])
        self.assertEqual(result['status'],'duplicate_skipped');self.assertEqual(len(self.server.writes),1)
    def test_unknown_unobserved_post_is_not_retried(self):
        client=self.client();self.server.uncertain=True
        with self.assertRaises(RuntimeError):client.write('/repos/example/project/issues',dict(title='X',body='Body'))
        self.server.uncertain=False;self.server.issues=[]
        with self.assertRaisesRegex(RuntimeError,'UNCERTAIN_NO_RETRY'):client.write('/repos/example/project/issues',dict(title='X',body='Body'))
        self.assertEqual(len(self.server.writes),1)
    def test_assignment_patch_does_not_assign_cc_or_change_body(self):
        client=self.client();client.write('/repos/example/project/issues',dict(title='X',body='Body'))
        client.write('/repos/example/project/issues/1',dict(assignees=['developer']),'PATCH')
        self.assertEqual(self.server.writes[-1][1],dict(assignees=['developer']))
    def test_comment_payload_cc_and_readback(self):
        client=self.client();client.publish('daily:2','s','X','Body',['developer'])
        obj,status=client.write('/repos/example/project/issues/1/comments',dict(body='Status @developer'))
        self.assertIn('@lead',obj['body']);self.assertEqual(status,'published_readback_verified')
    def test_cc_has_independent_inbox_verification(self):
        result=self.client().publish('daily:2','s','Title','Body',['developer'])
        cc=next(x for x in result['recipient_delivery'] if x['login']=='lead')
        self.assertFalse(cc['email_delivery_verified']);self.assertFalse(cc['github_personal_inbox_verified'])
    def test_message_config_change_replaces_section(self):
        before=n.message(self.c,'Body');self.c['notifications']['cc_recipients']=['other']
        after=n.message(self.c,before)
        self.assertNotIn('@lead',after);self.assertEqual(after.count('@other'),1)
    def test_manual_mentions_do_not_duplicate(self):
        self.assertEqual(n.message(self.c,'收件人：@lead\nBody'),'收件人：@lead\nBody')
    def test_readback_matches_account_not_prefix_or_case(self):
        self.assertTrue(n.mentions_verified(['cc @LEAD'],['lead']))
        self.assertFalse(n.mentions_verified(['cc @leader'],['lead']))
    def test_code_issue_creation_copies_without_assigning_lead(self):
        self.c['github'].update(allow_create=True,allow_improvements=True,max_new_issues_per_run=3)
        run=Path(self.tmp.name)/'run';run.mkdir()
        proposal=dict(kind='defect',title='A code defect',finding_ids=['f'])
        w.save(run/'issue-proposals.json',[proposal])
        w.save(run/'run.json',dict(head='a'*40,source_mode='delivered_target_diff'))
        f=dict(id='f',path='source.cpp',quote_sha256='b'*64,title='Defect',severity='high',confidence='high',reasoning='Evidence',impact='Impact',recommendation='Fix')
        checked=dict(data=dict(validated=True,checked_findings=[f]))
        origin=dict(author_login='developer',path='source.cpp',line=1,code_url='https://example.test/code',commit='a'*40,commit_url='https://example.test/commit')
        client=self.client()
        with patch.object(w,'ces',return_value=checked),patch.object(w,'git',return_value='a'*40),patch.object(r,'Client',return_value=client),patch.object(r,'resolve_origins',return_value={'f':[origin]}),patch.object(q,'details',return_value=('Deep content',[])),patch.object(client,'pages',side_effect=lambda path:[dict(login='developer')] if path.endswith('/assignees') else []),contextlib.redirect_stdout(io.StringIO()):
            w.issue_host(self.c,run,True)
        self.assertEqual(self.server.issues[0]['assignees'],[dict(login='developer')])
        self.assertIn('抄送：@lead',self.server.issues[0]['body'])
        result=w.load(run/'issue-results.json')[0]
        self.assertEqual(result['cc_recipients'],['lead']);self.assertTrue(result['cc_mentions_readback_verified'])
    def test_issue_enrichment_keeps_single_cc_section(self):
        client=self.client();client.write('/repos/example/project/issues',dict(title='X',body='Existing'))
        run=Path(self.tmp.name)/'run';run.mkdir()
        w.save(run/'issue-proposals.json',[dict(title='X')]);w.save(run/'issue-results.json',[dict(title='X',number=1)])
        section='<!-- ces-deep-analysis:start -->\nDetails @developer\n<!-- ces-deep-analysis:end -->'
        with patch.object(r,'resolve_origins',return_value={}),patch.object(q,'details',return_value=(section,['developer'])):
            q.enrich(self.c,run,client,True);result=q.enrich(self.c,run,client,True)
        self.assertEqual(result[0]['status'],'already_enriched')
        self.assertEqual(self.server.issues[0]['body'].count(n.START),1)
        self.assertEqual(result[0]['cc_recipients'],['lead'])

class CCReminderTests(unittest.TestCase):
    setUp=tracking_tests.TrackingTests.setUp
    sync=tracking_tests.TrackingTests.sync
    def test_stale_cc_keeps_owner_and_cooldown(self):
        from datetime import timedelta
        self.c['notifications']['cc_recipients']=['lead']
        self.sync();db=tracking.dbopen(self.c)
        db.execute('UPDATE issues SET last_change=?',(tracking.stamp(tracking.now()-timedelta(days=8)),));db.close()
        first=self.sync(True);second=self.sync(True)
        row=first['notifications'][0]
        self.assertEqual(row['primary_recipients'],['developer']);self.assertEqual(row['cc_recipients'],['lead'])
        self.assertIn('抄送：@lead',self.client.writes[0][1]['body'])
        self.assertEqual(self.client.items[0]['assignees'],[dict(login='developer')])
        self.assertEqual(second['notifications'],[])

if __name__=='__main__':unittest.main(verbosity=2)
