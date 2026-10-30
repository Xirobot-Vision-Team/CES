"""Real document bytes and mocked Git/provider boundaries for incremental README maintenance."""
import copy,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import ces_readmes as r
import ces_knowledge as k
import ces_lifecycle as life
import ces_audit as audit

HEAD='a'*40
class ReadmeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.c=dict(repository_path=self.tmp.name,cache_root=self.tmp.name+'/cache',state_root=self.tmp.name+'/state',
                    github=dict(repository_id=1,repository='owner/project'),knowledge={},repository_docs=dict(relative_directory='docs/ces',allow_write=True))
        self.files={'README.md':b'\xef\xbb\xbf# Human title\r\nOriginal introduction.  \r\n','Suite/README.md':b'# Solution\n',
                    'Suite/Suite.slnx':b'<Solution />\n','Suite/App/README.md':b'# App\n',
                    'Suite/App/App.csproj':b'<Project />\n','Suite/App/main.cs':b'public class App {}\n',
                    'vendor/README.md':b'# Vendor\n','docs/README.md':b'# Docs\n','docs/ces/README.md':b'# CES\n'}
        for name,raw in self.files.items():
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        self.sources=[dict(path='Suite/App/main.cs',content_sha256=r.w.sha('public class App {}'),line_count=1)]
    def git(self,c,*args):
        if args[0]=='ls-tree':return '\0'.join(self.files)+'\0'
        if args==('rev-parse','HEAD'):return HEAD
        if args[0]=='show':return self.files[args[1].split(':',1)[1]].decode('utf-8-sig').rstrip('\r\n')
        raise AssertionError(args)
    def patches(self):
        from contextlib import ExitStack
        stack=ExitStack();stack.enter_context(patch.object(r.w,'git',side_effect=self.git));stack.enter_context(patch.object(r,'blob',side_effect=lambda c,h,n:self.files[n]));return stack
    def input(self):return dict(head=HEAD,binding_sha256='b'*64,sources=self.sources,readme_maintenance=r.discover(self.c,HEAD,self.sources))
    def draft(self,paths=None):
        ref=dict(path='Suite/App/main.cs',line_start=1,line_end=1,quote='public class App {}')
        return dict(chapters=[dict(path='architecture.md',title='Architecture',markdown='Actual architecture source description '+'.'*30,citations=[ref])],
                    readmes=[dict(path=n,markdown='## Functional overview\n\nApp declares a public application class; runtime behavior remains unverified.',knowledge_paths=['architecture.md'],citations=[ref],reasoning='Reviewed actual implementation and the incremental architecture knowledge chapter.') for n in (paths or ['README.md','Suite/README.md','Suite/App/README.md'])])
    def first_plan(self):
        with self.patches():return r.plan(self.c,self.input(),self.draft())
    def save_manifest(self,data):
        r.w.save(r.docs.root(self.c)/r.MANIFEST,data)
    def test_default_enabled_and_discovery_roles_are_local_to_readme(self):
        with self.patches():data=self.input()['readme_maintenance']
        self.assertTrue(data['enabled']);roles={x['path']:x['roles'] for x in data['targets']}
        self.assertEqual(roles,{'README.md':['repository'],'Suite/README.md':['solution'],'Suite/App/README.md':['project']})
        self.assertTrue(any(x.get('path')=='docs/README.md' for x in data['gaps']))
        self.assertFalse(any(x['path'].startswith('vendor/') for x in data['targets']))
    def test_disabled_does_no_git_discovery_or_writes(self):
        self.c['knowledge']['readme_maintenance']=dict(enabled=False)
        with patch.object(r.w,'git',side_effect=AssertionError('Git')):self.assertEqual(r.discover(self.c,HEAD,self.sources)['targets'],[])
        plan,data=r.plan(self.c,{},{});self.assertEqual(plan['status'],'disabled');self.assertIsNone(data)
    def test_preview_preserves_all_human_bytes_and_nested_links(self):
        old={n:(self.root/n).read_bytes() for n in self.files};plan,data=self.first_plan()
        self.assertEqual(len(plan['updates']),3)
        for row in plan['updates']:
            self.assertTrue(row['content'].startswith(old[row['path']]))
            self.assertEqual((self.root/row['path']).read_bytes(),old[row['path']])
        app=next(x for x in plan['updates'] if x['path']=='Suite/App/README.md')
        self.assertIn(b'../../docs/ces/knowledge/architecture.md',app['content']);self.assertEqual(data['repository_id'],1)
    def test_write_and_isolated_publication_scope_validate_external_readmes(self):
        plan,data=self.first_plan();self.save_manifest(data);r.apply(self.c,plan)
        with self.patches():owned=r.managed_files(self.c)
        self.assertEqual(set(owned),{'README.md','Suite/README.md','Suite/App/README.md'})
    def test_member_edit_after_prepare_blocks_before_writes(self):
        with self.patches():inp=self.input();(self.root/'README.md').write_bytes(b'new human edit')
        with self.patches(),self.assertRaisesRegex(RuntimeError,'CHANGED_AFTER_PREPARE'):r.plan(self.c,inp,self.draft())
    def test_member_edit_before_prepare_blocks_instead_of_adopting(self):
        (self.root/'README.md').write_bytes(b'uncommitted member edit')
        with self.patches(),self.assertRaisesRegex(RuntimeError,'MEMBER_EDIT_PENDING'):self.input()
    def test_human_edits_in_same_commit_cannot_be_published_as_generated(self):
        plan,data=self.first_plan();r.apply(self.c,plan);self.save_manifest(data)
        p=self.root/'README.md';p.write_bytes(p.read_bytes().replace(b'Original introduction.',b'Modified business introduction.'))
        with self.patches(),self.assertRaisesRegex(RuntimeError,'EXTERNAL_CHANGE'):r.managed_files(self.c)
    def test_foreign_or_member_modified_block_is_not_overwritten(self):
        plan,data=self.first_plan();r.apply(self.c,plan);self.save_manifest(data)
        for row in plan['updates']:self.files[row['path']]=row['content']
        self.files['README.md']=self.files['README.md'].replace(b'Functional overview',b'Member section')
        (self.root/'README.md').write_bytes(self.files['README.md'])
        with self.patches():inp=self.input()
        with self.patches(),self.assertRaisesRegex(RuntimeError,'BLOCK_MEMBER_EDIT'):r.plan(self.c,inp,self.draft())
    def test_forged_or_duplicate_target_and_bad_citations_fail(self):
        with self.patches():inp=self.input()
        for kind in ('path','quote','scope','duplicate','chapter'):
            draft=self.draft()
            if kind=='path':draft['readmes'][0]['path']='../README.md'
            if kind=='quote':draft['readmes'][0]['citations'][0]['quote']='not present'
            if kind=='scope':draft['readmes'][0]['citations'][0]['path']='elsewhere.cpp'
            if kind=='duplicate':draft['readmes'].append(copy.deepcopy(draft['readmes'][0]))
            if kind=='chapter':draft['readmes'][0]['knowledge_paths']=['unknown.md']
            with self.subTest(kind=kind),self.patches(),self.assertRaises(RuntimeError):r.plan(self.c,inp,draft)
    def test_missing_draft_is_gap_not_claimed_successful_update(self):
        with self.patches():plan,data=r.plan(self.c,self.input(),dict(chapters=self.draft()['chapters']))
        self.assertEqual(len([x for x in plan['gaps'] if x.get('reason')=='readme_draft_missing']),3);self.assertEqual(plan['updates'],[])
    def test_reasoned_unchanged_requires_source_binding(self):
        draft=self.draft();draft['readmes'][0]['action']='unchanged'
        with self.patches():plan,_=r.plan(self.c,self.input(),draft)
        self.assertEqual(len(plan['updates']),2)
    def test_unchanged_semantics_does_not_rewrite_on_new_head(self):
        plan,data=self.first_plan();r.apply(self.c,plan);self.save_manifest(data)
        for row in plan['updates']:self.files[row['path']]=row['content']
        with self.patches():inp=self.input();inp['head']='c'*40;next_plan,metadata=r.plan(self.c,inp,self.draft())
        self.assertEqual(next_plan['updates'],[]);self.assertIsNone(metadata)
    def test_committed_human_edit_outside_block_is_preserved(self):
        plan,data=self.first_plan();r.apply(self.c,plan);self.save_manifest(data)
        for row in plan['updates']:self.files[row['path']]=row['content']
        self.files['README.md']=self.files['README.md'].replace(b'Original introduction.',b'New committed introduction.')
        (self.root/'README.md').write_bytes(self.files['README.md'])
        with self.patches():plan,data=r.plan(self.c,self.input(),self.draft());owned=r.managed_files(self.c)
        self.assertEqual(plan['updates'],[]);self.assertIsNotNone(data);self.assertIn('README.md',owned)
    def test_reparse_and_unsafe_paths_fail(self):
        for name in ('../README.md','/README.md','C:/README.md','a\\README.md','a/.GIT/README.md','a//README.md'):
            with self.subTest(path=name),self.assertRaises(RuntimeError):r.target(self.c,name)
        with patch.object(r.docs,'unsafe',return_value=True),self.assertRaisesRegex(RuntimeError,'REPARSE'):r.target(self.c,'README.md')
    def test_after_plan_edit_blocks_all_readmes(self):
        plan,data=self.first_plan();old=(self.root/'README.md').read_bytes();(self.root/'Suite/App/README.md').write_bytes(b'new edit')
        with self.assertRaisesRegex(RuntimeError,'CHANGED_AFTER_PLAN'):r.apply(self.c,plan)
        self.assertEqual((self.root/'README.md').read_bytes(),old)
    def test_orphan_or_duplicate_markers_fail(self):
        for raw in (r.START,r.END,r.START+r.END+r.START+r.END):
            with self.subTest(raw=raw),self.assertRaises(RuntimeError):r.split(raw)
    def test_readme_only_selection_does_not_fabricate_functional_review(self):
        with self.patches():data=r.discover(self.c,HEAD,[dict(path='README.md')])
        self.assertEqual(data['targets'],[]);self.assertTrue(any(x['reason']=='no_code_or_build_source_selected' for x in data['gaps']))
    def test_write_authorization_and_policy_types(self):
        plan,_=self.first_plan();self.c['repository_docs']['allow_write']=False
        with self.assertRaisesRegex(RuntimeError,'NOT_AUTHORIZED'):r.apply(self.c,plan)
        self.c['knowledge']['readme_maintenance']=dict(enabled='true')
        with self.assertRaisesRegex(RuntimeError,'POLICY_INVALID'):r.policy(self.c)

    def test_historical_generated_block_excluded_and_mixed_human_work_kept(self):
        plan,data=self.first_plan();rows={x['path']:x['content'] for x in plan['updates']};old=copy.deepcopy(self.files)
        def blob(c,sha,name):return rows[name] if sha==HEAD else old[name]
        with patch.object(r.w,'git',side_effect=lambda *args:json.dumps(data)),patch.object(r,'blob',side_effect=blob):
            self.assertEqual(r.audit_paths(self.c,HEAD,'b'*40,['README.md'],'docs/ces'),{'README.md'})
            changed=rows['README.md'].replace(b'Original introduction.',b'Human work should count.')
            rows['README.md']=changed;data['files']['README.md']['sha256']=r.docs.text_hash(changed)
            with self.assertRaisesRegex(RuntimeError,'HUMAN_CHANGE'):r.audit_paths(self.c,HEAD,'b'*40,['README.md'],'docs/ces')

if __name__=='__main__':unittest.main()
