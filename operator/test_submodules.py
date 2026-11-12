"""Disposable real Git fixtures; no network, project programs or credentials."""
import copy,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import ces_workflow as w
import ces_submodules as s
import ces_code_review as review
import ces_knowledge as knowledge
import ces_readmes as readmes
import ces_lifecycle as lifecycle
import ces_testing as testing
from test_code_review import draft_for

class SubmoduleTests(unittest.TestCase):
    def git(self,root,*args):
        env={**os.environ,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_TERMINAL_PROMPT':'0'}
        p=subprocess.run(['git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-C',str(root),*args],capture_output=True,env=env)
        if p.returncode:raise AssertionError(p.stderr.decode('utf-8',errors='replace'))
        return p.stdout.decode('utf-8').strip()
    def commit(self,root,message):
        self.git(root,'add','.');self.git(root,'commit','-qm',message);return self.git(root,'rev-parse','HEAD')
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.child=self.root/'source';self.child.mkdir();self.git(self.child,'init','-q','-b','main')
        (self.child/'a.cpp').write_text('int value = 1;\n',encoding='utf-8',newline='\n')
        (self.child/'README.md').write_text('# Component\n',encoding='utf-8',newline='\n')
        (self.child/'part.vcxproj').write_text('<Project />\n',encoding='utf-8',newline='\n')
        self.v1=self.commit(self.child,'component initial')
        (self.child/'a.cpp').write_text('int value = 2;\n',encoding='utf-8',newline='\n');self.v2=self.commit(self.child,'component behavior')
        self.repo=self.root/'parent';self.repo.mkdir();self.git(self.repo,'init','-q','-b','main')
        (self.repo/'README.md').write_text('# Parent\n',encoding='utf-8')
        (self.repo/'pkg').mkdir()
        for name in ('a.cpp','README.md','part.vcxproj'):(self.repo/'pkg'/name).write_bytes(self.git(self.child,'show',self.v1+':'+name).encode()+b'\n')
        self.flat=self.commit(self.repo,'flat source')
        self.git(self.repo,'rm','-qr','pkg');self.git(self.root,'clone','-q',str(self.child),str(self.repo/'pkg'))
        self.git(self.repo/'pkg','remote','set-url','origin','https://github.com/example/component.git')
        self.git(self.repo/'pkg','checkout','-q','--detach',self.v1)
        (self.repo/'.gitmodules').write_text('[submodule "pkg"]\n path = pkg\n url = https://github.com/example/component.git\n',encoding='utf-8')
        self.git(self.repo,'add','pkg','.gitmodules');self.pinned=self.commit(self.repo,'convert flat component')
        self.c=dict(repository_path=str(self.repo),github=dict(repository='example/parent',repository_id=1),cache_root=str(self.root/'cache'),state_root=str(self.root/'state'),output_root=str(self.root/'out'),
                    repository_sync=dict(branch='main',submodules=dict(enabled=True,allow_init=True,entries=[dict(path='pkg',repository='example/component')])),
                    repository_docs=dict(relative_directory='docs/ces',allow_write=True))
    def advance(self):
        self.git(self.repo/'pkg','checkout','-q','--detach',self.v2);self.git(self.repo,'add','pkg');return self.commit(self.repo,'advance integration pin')
    def test_fixed_source_binding_and_cross_repo_url(self):
        head=self.advance();item=s.binding(self.c,head,'pkg/a.cpp')
        self.assertEqual(item['source_commit'],self.v2);self.assertEqual(item['parent_commit'],head)
        self.assertEqual(item['chain'],[dict(path='pkg',repository='example/component',commit=self.v2)])
        self.assertIn('/example/component/blob/'+self.v2+'/a.cpp',w.source_link(self.c,head,'pkg/a.cpp'))
        self.assertEqual(s.read(self.c,self.pinned,'pkg/a.cpp'),b'int value = 1;\n')
    def test_gitlink_is_not_a_blob_and_symlinks_refused(self):
        with self.assertRaisesRegex(RuntimeError,'NONREGULAR'):s.read(self.c,self.pinned,'pkg')
        self.git(self.repo,'update-index','--add','--cacheinfo','120000',self.git(self.repo,'rev-parse','HEAD:README.md'),'link')
        self.git(self.repo,'commit','-qm','synthetic symlink tree')
        with self.assertRaisesRegex(RuntimeError,'NONREGULAR'):s.read(self.c,'HEAD','link')
    def test_flat_migration_does_not_invent_mass_code_deletion(self):
        paths=s.changed(self.c,self.flat,self.pinned)
        self.assertEqual(paths,['.gitmodules'])
        self.assertEqual(s.changes(self.c,self.flat,self.pinned)[0]['migration'],'added_or_flat_to_submodule')
    def test_child_pin_delta_is_expanded_and_attribution_separate(self):
        head=self.advance();self.assertEqual(s.changed(self.c,self.pinned,head),['pkg/a.cpp'])
        changes=s.changes(self.c,self.pinned,head)
        self.assertEqual([x['sha'] for x in changes[0]['commits']],[self.v2])
        self.assertEqual(changes[0]['commits'][0]['author_name'],'Fixture')
        plan=w.load(review.prepare(self.c,self.pinned)['plan'])
        self.assertEqual({x['path'] for x in plan['files']},{'pkg/a.cpp'})
        self.assertTrue(all(x['source_binding']['chain'] for x in plan['units']))
        draft=draft_for(plan,head)
        self.assertEqual(review.validate(self.c,plan,draft)['reviewed_units'],2)
    def test_resealed_source_binding_tampering_rejected(self):
        head=self.advance();plan=w.load(review.prepare(self.c,self.pinned)['plan'])
        plan['files'][0]['source_binding']['source_commit']='f'*40
        body=dict(plan);body.pop('binding_sha256');plan['binding_sha256']=review.digest(body)
        with self.assertRaisesRegex(RuntimeError,'BINDING_CHANGED'):review.validate(self.c,plan,draft_for(plan,head))
    def test_dirty_and_wrong_pin_prevent_reproducible_build(self):
        self.git(self.repo/'pkg','checkout','-q','--detach',self.v2)
        with self.assertRaisesRegex(RuntimeError,'WRONG_PIN'):s.inventory(self.c,strict=True)
        self.git(self.repo/'pkg','checkout','-q','--detach',self.v1)
        (self.repo/'pkg/a.cpp').write_text('member edit\n')
        with self.assertRaisesRegex(RuntimeError,'DIRTY'):s.inventory(self.c,strict=True)
        with self.assertRaisesRegex(RuntimeError,'LOCAL_EDITS'):s.sync(self.c)
        self.assertEqual((self.repo/'pkg/a.cpp').read_text(),'member edit\n')
    def test_allowlist_url_and_origin_are_enforced(self):
        bad=copy.deepcopy(self.c);bad['repository_sync']['submodules']['entries'][0]['repository']='other/repository'
        with self.assertRaisesRegex(RuntimeError,'NOT_ALLOWLISTED'):s.inventory(bad)
        self.git(self.repo/'pkg','remote','set-url','origin','https://github.com/other/repository.git')
        with self.assertRaisesRegex(RuntimeError,'ORIGIN_MISMATCH'):s.inventory(self.c)
        for url in ('file:///tmp/repo','https://secret@github.com/example/component.git','ssh://github.com/example/component'):
            with self.assertRaisesRegex(RuntimeError,'HTTPS'):s.repository(url)
    def test_path_traversal_and_nonempty_init_not_destroyed(self):
        for path in ('../pkg','/pkg','pkg/../x','pkg/.git/x','C:/pkg','pkg\\x'):
            with self.assertRaises(RuntimeError):s.safe(path)
        marker=self.repo/'pkg/.git';marker.rename(self.repo/'pkg/.git-saved')
        with self.assertRaisesRegex(RuntimeError,'NOT_EMPTY'):s.sync(self.c)
        self.assertTrue((self.repo/'pkg/a.cpp').exists());marker.with_name('.git-saved').rename(marker)
    def test_sync_uses_checkout_and_no_remote_branch_following(self):
        original=s.raw;observed=[]
        def spy(c,*args,**kwargs):
            if 'submodule' in args and 'update' in args:
                observed.append(args);return b''
            return original(c,*args,**kwargs)
        with patch.object(s,'raw',spy):s.sync(self.c)
        self.assertIn('--checkout',observed[0]);self.assertNotIn('--remote',observed[0])
        self.assertIn('protocol.file.allow=never',observed[0])
        self.assertTrue(s.inventory(self.c,strict=True)[0]['clean'])
    def test_knowledge_and_test_sources_bind_child_identity(self):
        info=knowledge.prepare(self.c,['pkg/a.cpp']);inp=w.load(info['input'])
        self.assertEqual(inp['sources'][0]['source_binding']['source_repository'],'example/component')
        self.assertEqual(knowledge.tracked_source(self.c,'pkg/a.cpp',self.pinned),'int value = 1;')
        sources=testing.sources(self.c,dict(sources=['pkg/a.cpp']),self.pinned)
        self.assertIn('source_binding',testing.fingerprint(sources)[0])
        self.assertIn('submodule_readme_separate_publication_required',[x['reason'] for x in inp['readme_maintenance']['gaps']])
    def test_readme_migration_detaches_metadata_without_child_write(self):
        head=self.pinned;inp=dict(head=head,readme_maintenance=dict(enabled=True,targets=[],gaps=[]))
        meta=dict(schema='ces.readme_manifest.v1',repository_id=1,files={'pkg/README.md':dict(sha256='historical')})
        raw=(self.repo/'pkg/README.md').read_bytes()
        with patch.object(readmes,'manifest',return_value=meta):
            result,changed=readmes.plan(self.c,inp,dict(chapters=[],readmes=[]))
        self.assertFalse(result['updates']);self.assertFalse(changed['files'])
        self.assertEqual(changed['detached_submodule_readmes']['pkg/README.md']['metadata']['sha256'],'historical')
        self.assertEqual((self.repo/'pkg/README.md').read_bytes(),raw)
    def test_removed_pin_and_disabled_config_do_not_silently_read(self):
        no=copy.deepcopy(self.c);no['repository_sync']['submodules']['enabled']=False
        with self.assertRaisesRegex(RuntimeError,'NOT_CONFIGURED'):s.read(no,self.pinned,'pkg/a.cpp')
        self.assertIsNone(s.read(self.c,self.pinned,'pkg/missing.cpp'))
        self.assertEqual(s.read(self.c,self.flat,'pkg/a.cpp'),b'int value = 1;\n')
    def test_missing_pinned_object_is_actionable_and_does_not_build(self):
        self.git(self.repo,'update-index','--cacheinfo','160000,'+'f'*40+',pkg')
        self.git(self.repo,'commit','-qm','unavailable pin')
        with self.assertRaisesRegex(RuntimeError,'SUBMODULE_PIN_UNAVAILABLE:pkg:'):
            s.inventory(self.c,strict=True)
    def test_empty_mount_can_be_initialized_but_member_files_block(self):
        marker=self.repo/'pkg/.git';saved=self.root/'saved-child'
        (self.repo/'pkg').rename(saved)
        self.assertEqual(s.inventory(self.c,strict=True,allow_uninitialized=True),[])
        (self.repo/'pkg').mkdir();(self.repo/'pkg/member').write_text('preserve')
        with self.assertRaisesRegex(RuntimeError,'NOT_EMPTY'):s.inventory(self.c,strict=True,allow_uninitialized=True)
    def test_case_colliding_allowlist_rejected(self):
        self.c['repository_sync']['submodules']['entries'].append(dict(path='PKG',repository='example/component'))
        with self.assertRaisesRegex(RuntimeError,'ALLOWLIST_INVALID'):s.policy(self.c)

if __name__=='__main__':unittest.main()
