"""End-to-end knowledge→README→isolated Git push/audit using disposable local Git only."""
import copy,subprocess,tempfile,unittest
from pathlib import Path
import ces_knowledge as k
import ces_readmes as r
import ces_lifecycle as life
import ces_audit as audit

class ReadmeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name);self.repo=self.home/'repository';self.repo.mkdir()
        self.remote=self.home/'remote.git';self.git_at(self.home,'init','--bare',str(self.remote));self.git_at(self.repo,'init','-b','main')
        for name,value in [('user.name','CES fixture'),('user.email','fixture@example.invalid'),('core.autocrlf','false'),('core.hooksPath',str(self.home/'empty-hooks'))]:self.git_at(self.repo,'config',name,value)
        (self.repo/'README.md').write_bytes(b'# Original human README\n\nHuman details remain.  \n')
        (self.repo/'app.py').write_text('def compute():\n    return 42\n',encoding='utf-8')
        (self.repo/'pyproject.toml').write_text('[project]\nname="fixture"\n',encoding='utf-8')
        self.git_at(self.repo,'add','README.md','app.py','pyproject.toml');self.git_at(self.repo,'commit','-m','Initial fixture')
        self.git_at(self.repo,'remote','add','origin',str(self.remote));self.git_at(self.repo,'push','origin','main')
        self.c=dict(repository_path=str(self.repo),state_root=str(self.home/'state'),cache_root=str(self.home/'cache'),github=dict(repository_id=1,repository='owner/project'),
                    knowledge=dict(sources=['app.py','pyproject.toml']),repository_docs=dict(relative_directory='docs/ces',allow_write=True,allow_git_commit=True,allow_git_push=True),
                    repository_sync=dict(branch='main',remote='origin'),repository_push=dict(allow=True,automatic_after_document_write=True),audit=dict(exclude_ces_generated_documents=True))
    def git_at(self,path,*args):
        result=subprocess.run(['git','-C',str(path),*args],capture_output=True,text=True,encoding='utf-8',env=k.w.clean_env(),timeout=30)
        self.assertEqual(result.returncode,0,result.stderr);return result.stdout.strip()
    def ready(self,body='## Project function\n\nThe selected compute function returns the integer 42. Execution is not validated by this documentation.'):
        result=k.prepare(self.c);inp=k.w.load(result['input']);ref=dict(path='app.py',line_start=1,line_end=2,quote='def compute():\n    return 42')
        draft=dict(schema='ces.knowledge_draft.v1',input_binding_sha256=inp['binding_sha256'],summary='Reviewed the actual compute implementation.',
                   chapters=[dict(path='function.md',title='Function',markdown='The source declares compute and returns 42. No runtime execution was performed.',citations=[ref])],
                   readmes=[dict(path='README.md',action='update',markdown=body,reasoning='The root README introduces the repository and this public function; preserve the human introduction.',knowledge_paths=['function.md'],citations=[ref])])
        dest=self.home/'draft.json';k.w.save(dest,draft);return result,inp,dest
    def test_actual_publish_preserves_human_text_and_excludes_verified_output(self):
        old=(self.repo/'README.md').read_bytes();ready,inp,draft=self.ready()
        preview=k.publish(self.c,ready['input'],draft,False)
        self.assertEqual((self.repo/'README.md').read_bytes(),old);self.assertEqual(len(preview['readme_maintenance']['updates']),1)
        result=k.publish(self.c,ready['input'],draft,True);commit=result['git_publication']['commit']
        self.assertEqual(result['git_publication']['status'],'published_and_local_branch_synchronized')
        self.assertTrue((self.repo/'README.md').read_bytes().startswith(old));self.assertEqual(self.git_at(self.repo,'status','--porcelain=v1'),'')
        self.assertEqual(self.git_at(self.repo,'ls-remote','origin','refs/heads/main').split()[0],commit)
        excluded=audit.classify(self.c,commit);self.assertIsNotNone(excluded);self.assertEqual(excluded['proof'],'verified_publication_receipt')
        self.assertIn('README.md',excluded['paths']);self.assertNotIn('app.py',excluded['paths'])
        # Fresh source bindings with unchanged claims do not rewrite the README fragment just for new HEAD.
        again,_,draft=self.ready();second=k.publish(self.c,again['input'],draft,True)
        self.assertEqual(second['readme_maintenance']['updates'],[])
        # A human README change with copied machine trailers is still effective work.
        p=self.repo/'README.md';p.write_bytes(p.read_bytes().replace(b'Human details',b'Member updated details'))
        self.git_at(self.repo,'add','README.md');self.git_at(self.repo,'commit','-m','Human edit','-m','CES-Generated-By: CES\nCES-Repository-Id: 1')
        human_commit=self.git_at(self.repo,'rev-parse','HEAD')
        rows=[dict(sha=human_commit)];kept,removed,warnings=audit.filter_commits(self.c,rows)
        self.assertEqual(kept,rows);self.assertFalse(removed)
    def test_disabled_keeps_readme_untouched_but_publishes_knowledge(self):
        self.c['knowledge']['readme_maintenance']=dict(enabled=False);before=(self.repo/'README.md').read_bytes();ready,inp,draft=self.ready()
        result=k.publish(self.c,ready['input'],draft,True)
        self.assertEqual(result['readme_maintenance']['status'],'disabled');self.assertEqual((self.repo/'README.md').read_bytes(),before)
        self.assertNotIn('README.md',result['git_publication']['paths'])
    def test_readme_conflict_prevents_any_knowledge_write(self):
        ready,inp,draft=self.ready();p=self.repo/'README.md';p.write_bytes(p.read_bytes()+b'New user work\n')
        with self.assertRaisesRegex(RuntimeError,'CHANGED_AFTER_PREPARE'):k.publish(self.c,ready['input'],draft,True)
        self.assertFalse((self.repo/'docs/ces/knowledge/function.md').exists());self.assertTrue(p.read_bytes().endswith(b'New user work\n'))
    def test_remote_advancement_stops_before_any_write(self):
        ready,inp,draft=self.ready();tree=self.git_at(self.repo,'rev-parse','HEAD^{tree}')
        other=self.git_at(self.repo,'commit-tree',tree,'-p',inp['head'],'-m','Remote advanced')
        self.git_at(self.repo,'push','origin',other+':refs/heads/main')
        before=(self.repo/'README.md').read_bytes()
        with self.assertRaisesRegex(RuntimeError,'REMOTE_ADVANCED'):k.publish(self.c,ready['input'],draft,True)
        self.assertEqual(before,(self.repo/'README.md').read_bytes());self.assertFalse((self.repo/'docs/ces/knowledge/function.md').exists())
    def test_staged_user_changes_stop_before_any_write(self):
        ready,inp,draft=self.ready();(self.repo/'app.py').write_text('user staged work\n');self.git_at(self.repo,'add','app.py')
        before=self.git_at(self.repo,'diff','--cached')
        with self.assertRaisesRegex(RuntimeError,'STAGED_CHANGES'):k.publish(self.c,ready['input'],draft,True)
        self.assertEqual(before,self.git_at(self.repo,'diff','--cached'));self.assertFalse((self.repo/'docs/ces/knowledge/function.md').exists())

if __name__=='__main__':unittest.main()
