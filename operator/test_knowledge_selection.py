"""Knowledge expansion selects source-bound batches without changing normal profile scope."""
import copy,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import ces_knowledge as k

class KnowledgeSelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=dict(repository_path=self.tmp.name,state_root=self.tmp.name,github=dict(repository_id=1),knowledge=dict(sources=['README.md']))
    def prepare(self,selected=None):
        with patch.object(k.w,'git',return_value='a'*40),patch.object(k,'tracked_source',return_value='selected source\n'):
            result=k.prepare(self.c,selected)
        return result,k.w.load(result['input'])
    def test_explicit_batch_does_not_change_profile(self):
        before=copy.deepcopy(self.c);result,data=self.prepare(['src/module.cpp','build/release x64.props'])
        self.assertEqual(self.c,before)
        self.assertEqual([x['path'] for x in data['sources']],['src/module.cpp','build/release x64.props'])
        self.assertEqual(result['changed_sources'],['src/module.cpp','build/release x64.props'])
    def test_omitted_batch_uses_profile_sources(self):
        _,data=self.prepare();self.assertEqual([x['path'] for x in data['sources']],['README.md'])
    def test_binding_changes_for_different_batches(self):
        _,first=self.prepare(['src/a.cpp']);_,second=self.prepare(['src/b.cpp'])
        self.assertNotEqual(first['binding_sha256'],second['binding_sha256'])
    def test_invalid_batches_refused_before_source_access(self):
        for selected in ([],{},['a.cpp','a.cpp'],[None],[['nested']],['src/'+str(n) for n in range(65)]):
            with self.subTest(selected=selected),patch.object(k,'tracked_source',side_effect=AssertionError('read')):
                with self.assertRaisesRegex(RuntimeError,'SOURCES_INVALID'):k.prepare(self.c,selected)
    def test_traversal_and_control_paths_refused(self):
        for path in ('../secret','/absolute','C:/absolute','src\\a.cpp','src//a.cpp','src/./a.cpp','src/.GIT/config','src/a\n.cpp'):
            with self.subTest(path=path),self.assertRaisesRegex(RuntimeError,'SOURCE_PATH_INVALID'):k.source_path(path)
    def test_real_git_names_allow_spaces_unicode_and_punctuation(self):
        for path in ('build/release x64.props','src/模块 (v2)/a+b[1].cpp','src/-option.cpp'):
            self.assertEqual(k.source_path(path),path)
    def test_source_lookup_uses_literal_git_path_and_immutable_head(self):
        name='build/release x64.props'
        with patch.object(k.w,'git',side_effect=[name,'content']) as git:
            self.assertEqual(k.tracked_source(self.c,name,'a'*40),'content')
        self.assertEqual(git.call_args_list[0].args[1:],('ls-files','--',':(literal)'+name))
        self.assertEqual(git.call_args_list[1].args[1:],('show','a'*40+':'+name))
    def test_untracked_source_refused(self):
        with patch.object(k.w,'git',return_value=''):
            with self.assertRaisesRegex(RuntimeError,'NOT_TRACKED'):k.tracked_source(self.c,'src/a.cpp','a'*40)

if __name__=='__main__':unittest.main(verbosity=2)
