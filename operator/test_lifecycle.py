"""Pure/mocked lifecycle boundary tests; never creates or runs a temporary Git repository."""
import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import ces_lifecycle as l
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=dict(repository_path=self.tmp.name,state_root=self.tmp.name+"/state",cache_root=self.tmp.name+"/cache",
                    github=dict(repository="owner/repo",repository_id=1),
                    repository_sync=dict(enabled=True,allow_pull=True,remote="origin",branch="main"),
                    execution_policy=dict(build_before_analysis=True,run_runtime_tests=False),
                    build_validation=dict(enabled=True,steps=[dict(name="release",kind="build",argv=["builder","{repository}","{build_log}"],cwd="{repository}")]),
                    repository_docs=dict(relative_directory="docs/ces",allow_git_commit=True,allow_git_push=True),
                    repository_push=dict(allow=True,automatic_after_document_write=True))
    def test_arguments_are_configured_not_sample_specific(self):
        result=l.expand(self.c,["builder","{repository}","{build_log}"],Path(self.tmp.name)/"build.log")
        self.assertEqual(result[1],self.tmp.name);self.assertIn("build.log",result[2])
    def test_runtime_tests_rejected(self):
        self.c["build_validation"]["steps"][0]["kind"]="test"
        with self.assertRaisesRegex(RuntimeError,"RUNTIME_TEST_STEPS_FORBIDDEN"):l.build(self.c)
    def test_explicit_no_runtime_policy_required(self):
        self.c["execution_policy"]["run_runtime_tests"]=True
        with self.assertRaisesRegex(RuntimeError,"BUILD_ONLY_POLICY"):l.build(self.c)
    def test_dirty_business_source_not_built(self):
        with patch.object(l,"business_changes",return_value=" M source.cpp"):
            with self.assertRaisesRegex(RuntimeError,"UNCOMMITTED_BUSINESS"):l.build(self.c)
    def test_unconfigured_build_refused(self):
        self.c["build_validation"]["enabled"]=False
        with self.assertRaisesRegex(RuntimeError,"BUILD_NOT_CONFIGURED"):l.build(self.c)
    def test_wrong_branch_refused(self):
        with patch.object(l,"run",return_value="feature"):
            with self.assertRaisesRegex(RuntimeError,"CONFIGURED_BRANCH"):l.branch(self.c)
    def test_pull_opt_in_required(self):
        self.c["repository_sync"]["allow_pull"]=False
        with self.assertRaisesRegex(RuntimeError,"NOT_AUTHORIZED"):l.sync(self.c)
    def test_no_stash_or_reset_in_pull(self):
        calls=[]
        def fake(c,*args,**kw):
            calls.append(args)
            if args[:2]==("branch","--show-current"):return "main"
            if args[:3]==("diff","--cached","--name-only"):return ""
            if args==("rev-parse","FETCH_HEAD"):return "b"*40
            if args[:3]==("diff","--name-only","a"*40):return "new.cpp"
            return ""
        snaps=[dict(head="a"*40),dict(head="b"*40)]
        with patch.object(l,"run",side_effect=fake),patch.object(l.w,"snapshot",side_effect=snaps),patch.object(l,"file_inventory",return_value={}),patch.object(l.subprocess,"run",return_value=type("P",(),{"returncode":0})()):
            result=l.sync(self.c)
        self.assertEqual(result["status"],"fast_forwarded")
        self.assertTrue(any("merge" in x and "--ff-only" in x for x in calls))
        self.assertFalse(any("reset" in x or "stash" in x or "rebase" in x for x in calls))
    def test_staged_change_blocks_pull_before_fetch(self):
        def fake(c,*args,**kw):return "main" if args[0]=="branch" else "source.cpp"
        with patch.object(l,"run",side_effect=fake),patch.object(l.w,"snapshot",return_value=dict(head="a"*40)):
            with self.assertRaisesRegex(RuntimeError,"STAGED_USER"):l.sync(self.c)
    def test_overlap_blocks_ff_merge(self):
        local=Path(self.tmp.name)/"source.cpp";local.write_text("user edit")
        calls=[]
        def fake(c,*args,**kw):
            calls.append(args)
            if args[0]=="branch":return "main"
            if args[:2]==("diff","--cached"):return ""
            if args==("rev-parse","FETCH_HEAD"):return "b"*40
            if args[0]=="diff":return "source.cpp"
            return ""
        with patch.object(l,"run",side_effect=fake),patch.object(l.w,"snapshot",return_value=dict(head="a"*40)),patch.object(l,"file_inventory",return_value={"source.cpp":l.w.sha(local.read_bytes())}),patch.object(l.subprocess,"run",return_value=type("P",(),{"returncode":0})()):
            with self.assertRaisesRegex(RuntimeError,"OVERWRITE_LOCAL"):l.sync(self.c)
        self.assertFalse(any("merge" in x for x in calls));self.assertEqual(local.read_text(),"user edit")
    def test_publish_disabled(self):
        self.c["repository_push"]["allow"]=False
        with patch.object(l,"branch",return_value="main"):
            with self.assertRaisesRegex(RuntimeError,"NOT_AUTHORIZED"):l.publish(self.c)
    def test_manifest_required(self):
        with self.assertRaisesRegex(RuntimeError,"MANIFEST_REQUIRED"):l.managed_files(self.c)
    def test_member_edit_blocks_autopublish(self):
        root=Path(self.tmp.name)/"docs/ces";root.mkdir(parents=True)
        (root/"a.md").write_text("member edit",encoding="utf-8")
        l.w.save(root/".ces-documents.json",dict(schema="ces.repository_documents.v1",repository_id=1,files={"a.md":dict(sha256=l.w.sha("older"))}))
        with self.assertRaisesRegex(RuntimeError,"EXTERNAL_CHANGE"):l.managed_files(self.c)
    def test_manifest_cannot_reach_outside_docs(self):
        root=Path(self.tmp.name)/"docs/ces";root.mkdir(parents=True)
        l.w.save(root/".ces-documents.json",dict(schema="ces.repository_documents.v1",repository_id=1,files={"../../secret.txt":dict(sha256="a"*64)}))
        with self.assertRaisesRegex(RuntimeError,"DOC_PATH"):l.managed_files(self.c)
    def test_manifest_schema_required(self):
        root=Path(self.tmp.name)/"docs/ces";root.mkdir(parents=True)
        l.w.save(root/".ces-documents.json",dict(schema="unknown",repository_id=1,files={}))
        with self.assertRaisesRegex(RuntimeError,"WRONG_REPOSITORY"):l.managed_files(self.c)
    def test_manifest_reparse_refused_before_read(self):
        root=Path(self.tmp.name)/"docs/ces";root.mkdir(parents=True)
        l.w.save(root/".ces-documents.json",dict(schema="ces.repository_documents.v1",repository_id=1,files={}))
        with patch.object(l.docs,"unsafe",side_effect=lambda p:p.name==".ces-documents.json"):
            with self.assertRaisesRegex(RuntimeError,"MANIFEST_UNSAFE"):l.managed_files(self.c)
    def test_nested_document_reparse_refused_before_read(self):
        root=Path(self.tmp.name)/"docs/ces";folder=root/"knowledge";folder.mkdir(parents=True)
        (folder/"a.md").write_text("knowledge",encoding="utf-8")
        l.w.save(root/".ces-documents.json",dict(schema="ces.repository_documents.v1",repository_id=1,files={"knowledge/a.md":dict(sha256=l.w.sha("knowledge"))}))
        with patch.object(l.docs,"unsafe",side_effect=lambda p:p.name=="knowledge"):
            with self.assertRaisesRegex(RuntimeError,"REPARSE_POINT"):l.managed_files(self.c)
    def test_no_automatic_publish_when_disabled(self):
        self.c["repository_push"]["automatic_after_document_write"]=False
        with patch.object(l,"publish",side_effect=AssertionError("publish")):
            self.assertEqual(l.autocommit(self.c)["status"],"automatic_git_publish_disabled")
    def test_preflight_build_failure_is_reported_not_success(self):
        with patch.object(l,"sync",return_value=dict(status="up_to_date")),patch.object(l,"build",return_value=dict(status="failed",head="a"*40)):
            result=l.preflight(self.c)
        self.assertEqual(result["status"],"build_failed");self.assertFalse(result["runtime_tests_executed"])
    def test_preflight_pull_failure_stops_build(self):
        with patch.object(l,"sync",side_effect=RuntimeError("conflict")),patch.object(l,"build",side_effect=AssertionError("build")):
            with self.assertRaisesRegex(RuntimeError,"conflict"):l.preflight(self.c)
        self.assertEqual(l.w.load(l.home(self.c)/"last-preflight.json")["status"],"blocked")
    def test_no_secret_or_git_directory_in_tests(self):
        self.assertFalse((Path(self.tmp.name)/".git").exists())
    def publication_fixture(self):
        root=Path(self.tmp.name)/'docs/ces';root.mkdir(parents=True)
        (root/'knowledge.md').write_text('source-cited knowledge\n',encoding='utf-8')
        l.w.save(root/'.ces-documents.json',dict(schema="ces.repository_documents.v1",repository_id=1,files={'knowledge.md':dict(sha256=l.w.sha('source-cited knowledge\n'))}))
        index=Path(self.tmp.name)/'source.index';index.write_bytes(b'user-index-before')
        state={'remote':'b'*40,'local':'b'*40,'index':index,'calls':[]}
        def fake(c,*args,**kw):
            state['calls'].append(args)
            if args[0]=='branch':return 'main'
            if args[:2]==('diff','--cached'):
                return 'docs/ces/.ces-documents.json\ndocs/ces/knowledge.md' if kw.get('env') else ''
            if args[0]=='ls-remote':return state['remote']+'\trefs/heads/main'
            if args[0]=='ls-files':return 'docs/ces/.ces-documents.json\ndocs/ces/knowledge.md'
            if args[0]=='diff':return 'docs/ces/knowledge.md'
            if args==('rev-parse','HEAD'):return state['local']
            if args[0]=='rev-parse':return str(index)
            if args[0]=='read-tree':Path(kw['env']['GIT_INDEX_FILE']).write_bytes(b'new-doc-only-index');return ''
            if args[0]=='write-tree':return 'c'*40
            if args[0]=='commit-tree':return 'd'*40
            if args[0]=='push':state['remote']='d'*40;return ''
            if args[0]=='update-ref':state['local']='d'*40;return ''
            return ''
        return state,fake
    def test_isolated_publication_advances_local_after_verified_push(self):
        state,fake=self.publication_fixture();snapshot=dict(head='b'*40,index_sha256='original',status='docs changes')
        with patch.object(l,'run',side_effect=fake),patch.object(l.w,'snapshot',return_value=snapshot),patch.object(l,'file_inventory',return_value={}):result=l.publish(self.c,True)
        self.assertEqual(result['status'],'published_and_local_branch_synchronized')
        self.assertEqual(state['remote'],state['local']);self.assertEqual(state['index'].read_bytes(),b'new-doc-only-index')
        self.assertFalse(any('--force' in x or 'reset' in x for x in state['calls']))
        commit_call=next(x for x in state['calls'] if x[0]=='commit-tree')
        self.assertIn('CES-Generated-By: CES\nCES-Repository-Id: 1',commit_call)
        receipt=l.w.load(l.home(self.c)/'publications'/('d'*40+'.json'))
        self.assertEqual(receipt['status'],'published_and_local_branch_synchronized');self.assertEqual(receipt['repository_id'],1)
    def test_rejected_push_preserves_local_branch_and_index(self):
        state,fake=self.publication_fixture()
        def refusing(c,*args,**kw):
            if args[0]=='push':raise RuntimeError('non-fast-forward')
            return fake(c,*args,**kw)
        with patch.object(l,'run',side_effect=refusing),patch.object(l.w,'snapshot',return_value=dict(head='b'*40)),patch.object(l,'file_inventory',return_value={}):
            with self.assertRaisesRegex(RuntimeError,'non-fast-forward'):l.publish(self.c,True)
        self.assertEqual(state['local'],'b'*40);self.assertEqual(state['index'].read_bytes(),b'user-index-before')
        self.assertEqual(l.w.load(l.home(self.c)/'last-publish.json')['status'],'commit_prepared')
    def test_advanced_remote_stops_before_commit(self):
        state,fake=self.publication_fixture();state['remote']='e'*40
        with patch.object(l,'run',side_effect=fake),patch.object(l.w,'snapshot',return_value=dict(head='b'*40)):
            with self.assertRaisesRegex(RuntimeError,'REMOTE_ADVANCED'):l.publish(self.c,True)
        self.assertFalse(any(x[0]=='commit-tree' for x in state['calls']))
    def test_existing_index_lock_preserves_its_owner(self):
        state,fake=self.publication_fixture();lock=Path(str(state['index'])+'.lock');lock.write_bytes(b'other git operation')
        with patch.object(l,'run',side_effect=fake),patch.object(l.w,'snapshot',return_value=dict(head='b'*40)),patch.object(l,'file_inventory',return_value={}):
            with self.assertRaises(FileExistsError):l.publish(self.c,True)
        self.assertEqual(lock.read_bytes(),b'other git operation');self.assertEqual(state['local'],'b'*40)
if __name__=="__main__":unittest.main(verbosity=2)

