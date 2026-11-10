"""Behavioral regressions for reference-doc completeness and incremental retention."""
import copy
from unittest.mock import patch
from test_readmes import ReadmeTests,HEAD
import ces_readmes as r

class CatalogTests(ReadmeTests):
    def catalog_draft(self):
        draft=self.draft();entries=[]
        with self.patches():inp=self.input(modern=True)
        ref=dict(path='Suite/App/main.cs',line_start=1,line_end=1,quote='public class App {}')
        for item in inp['readme_maintenance']['targets']:
            sections=[]
            for ident in item['content_contract']['required_sections']:
                section=dict(id=ident,title=ident.title(),markdown='Stable reference describing the component contract and its usage.',citations=[ref],knowledge_paths=['architecture.md'])
                if ident=='components':section['descriptor_paths']=[x['path'] for x in item['component_inventory']]
                if ident=='interfaces':section['entries']=[dict(id='App',signature='public class App {}',purpose='Public application type.',parameters='No constructor parameters are declared.',returns='Application instance.',errors='Runtime behavior requires a separate implementation review.',citations=[ref])]
                sections.append(section)
            entries.append(dict(path=item['path'],sections=sections,migration_reason='Reviewed repository inventory and current public contracts to migrate the legacy fragment.',reasoning='Maintain the complete stable reference and retain unrelated section details.'))
        draft['readmes']=entries;return inp,draft
    def initial_catalog(self):
        inp,draft=self.catalog_draft()
        with self.patches():plan,data=r.plan(self.c,inp,draft)
        r.apply(self.c,plan);self.save_manifest(data)
        for row in plan['updates']:self.files[row['path']]=row['content']
        return inp,draft,plan,data
    def test_root_requires_all_descriptors_and_reference_sections(self):
        inp,draft=self.catalog_draft()
        root=draft['readmes'][0]
        self.assertEqual(root['path'],'README.md')
        self.assertEqual(len(inp['readme_maintenance']['targets'][0]['component_inventory']),2)
        root['sections'][1]['descriptor_paths']=[]
        with self.patches(),self.assertRaisesRegex(RuntimeError,'INVENTORY_INCOMPLETE'):r.plan(self.c,inp,draft)
    def test_daily_fragment_cannot_replace_root_overview(self):
        inp,draft=self.catalog_draft();draft['readmes'][0].pop('sections');draft['readmes'][0]['markdown']='Today changed only one feature.'
        with self.patches(),self.assertRaisesRegex(RuntimeError,'SECTIONS_REQUIRED'):r.plan(self.c,inp,draft)
    def test_period_narrative_is_rejected(self):
        for value in ('本轮新增接口功能说明与调用示例。','## 2026-01-02\n功能变更及结果。'):
            inp,draft=self.catalog_draft();draft['readmes'][0]['sections'][0]['markdown']=value+' reference content'
            with self.subTest(value=value),self.patches(),self.assertRaisesRegex(RuntimeError,'PERIOD_NARRATIVE'):r.plan(self.c,inp,draft)
    def test_project_requires_interface_details_and_actual_signature(self):
        for kind in ('missing','fake'):
            inp,draft=self.catalog_draft();api=next(s for e in draft['readmes'] for s in e['sections'] if s['id']=='interfaces')['entries'][0]
            if kind=='missing':api.pop('returns')
            else:api['signature']='invented_call()'
            with self.subTest(kind=kind),self.patches(),self.assertRaisesRegex(RuntimeError,'INTERFACE_'):r.plan(self.c,inp,draft)
    def test_partial_update_preserves_unrelated_sections_and_old_source_links(self):
        _,draft,_,data=self.initial_catalog()
        with self.patches():inp=self.input(modern=True)
        inp['head']='c'*40
        root=draft['readmes'][0];root['sections']=[root['sections'][0]]
        root['sections'][0]['markdown']='The application purpose is refined without replacing the other reference sections.'
        draft['readmes']=[root]
        with self.patches():plan,metadata=r.plan(self.c,inp,draft)
        self.assertEqual(len(plan['updates']),1)
        text=plan['updates'][0]['content'].decode('utf-8-sig')
        for ident in ('Components','Build','Usage','Navigation'):self.assertIn('## '+ident,text)
        self.assertIn('/blob/'+HEAD+'/',text)
        self.assertEqual(len(metadata['files']['README.md']['sections']),5)
        self.assertEqual(metadata['files']['README.md']['knowledge_paths'],['architecture.md'])
    def test_new_head_alone_does_not_rewrite_catalog(self):
        _,draft,_,_=self.initial_catalog()
        with self.patches():inp=self.input(modern=True)
        inp['head']='c'*40
        with self.patches():plan,data=r.plan(self.c,inp,draft)
        self.assertEqual(plan['updates'],[]);self.assertIsNone(data)
    def test_required_section_cannot_be_removed(self):
        _,draft,_,_=self.initial_catalog()
        with self.patches():inp=self.input(modern=True)
        root=draft['readmes'][0];root['sections']=[dict(id='overview',action='remove',reasoning='A deliberate removal needs to preserve the required reference contract.',citations=root['sections'][0]['citations'])]
        with self.patches(),self.assertRaisesRegex(RuntimeError,'REQUIRED_SECTION'):r.plan(self.c,inp,dict(chapters=draft['chapters'],readmes=[root]))
    def test_legacy_block_needs_explicit_complete_migration(self):
        inp,draft=self.catalog_draft();draft['readmes'][0].pop('migration_reason')
        with self.patches(),self.assertRaisesRegex(RuntimeError,'INITIAL_REVIEW'):r.plan(self.c,inp,draft)
    def test_unchanged_root_cannot_hide_a_new_component(self):
        self.initial_catalog()
        self.files['Suite/Extra/Extra.csproj']=b'<Project />'
        with self.patches():inp=self.input(modern=True)
        ref=dict(path='Suite/App/main.cs',line_start=1,line_end=1,quote='public class App {}')
        entry=dict(path='README.md',action='unchanged',reasoning='The old overview should only remain unchanged if every component is still represented.',citations=[ref])
        with self.patches(),self.assertRaisesRegex(RuntimeError,'INVENTORY_INCOMPLETE'):r.plan(self.c,inp,dict(readmes=[entry]))
    def test_one_interface_patch_retains_other_interfaces_and_their_sources(self):
        inp,draft=self.catalog_draft();project=next(e for e in draft['readmes'] if any(s['id']=='interfaces' for s in e['sections']))
        section=next(s for s in project['sections'] if s['id']=='interfaces')
        second=copy.deepcopy(section['entries'][0]);second['id']='App-alternate';section['entries'].append(second)
        with self.patches():plan,data=r.plan(self.c,inp,draft)
        r.apply(self.c,plan);self.save_manifest(data)
        for row in plan['updates']:self.files[row['path']]=row['content']
        with self.patches():inp=self.input(modern=True)
        inp['head']='c'*40;section['entries']=[second];second['purpose']='A refined description of the same public type.'
        project['sections']=[section]
        with self.patches():plan,data=r.plan(self.c,inp,dict(chapters=draft['chapters'],readmes=[project]))
        apis=next(s for s in data['files'][project['path']]['sections'] if s['id']=='interfaces')['entries']
        self.assertEqual([a['id'] for a in apis],['App','App-alternate'])
        self.assertEqual(apis[0]['source_revision'],HEAD)
        self.assertEqual(apis[1]['source_revision'],'c'*40)
    def test_partial_section_patch_cannot_drop_existing_knowledge_navigation(self):
        import ces_readme_catalog as catalog
        inp,draft=self.catalog_draft();item=inp['readme_maintenance']['targets'][0]
        owned=dict(sections=catalog.merge(draft['readmes'][0],item,None))
        section=copy.deepcopy(owned['sections'][0]);section['knowledge_paths']=['new-topic.md']
        merged=catalog.merge(dict(sections=[section]),item,owned)
        self.assertEqual(merged[0]['knowledge_paths'],['architecture.md','new-topic.md'])

if __name__=='__main__':
    import unittest
    unittest.main()
