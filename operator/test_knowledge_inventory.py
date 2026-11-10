"""Separate source batches retain cumulative coverage and chapter-specific staleness."""
import copy,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import ces_knowledge as k
import ces_knowledge_inventory as inventory

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.c=dict(repository_path=str(self.root/'repo'),state_root=str(self.root),cache_root=str(self.root/'cache'),github=dict(repository_id=1),knowledge=dict(readme_maintenance=dict(enabled=False)))
    def version(self,id,sources,chapter,stamp,precise=True,repo=1):
        row=dict(schema='ces.knowledge_docset.v1',snapshot_id=id,repository_id=repo,generated_at=stamp,repository_written=True,
                 sources=[dict(path=p,content_sha256=k.w.sha(text)) for p,text in sources.items()],documents=[dict(relative_path='knowledge/'+chapter)])
        if precise:row['chapter_sources']={chapter:{p:k.w.sha(text) for p,text in sources.items()}}
        k.w.save(k.cache(self.c)/'versions'/(id+'.json'),row);return row
    def prepare(self,sources):
        with patch.object(k.w,'git',return_value='a'*40),patch.object(k,'tracked_source',side_effect=lambda c,p,h:sources[p]):
            result=k.prepare(self.c,list(sources))
        return result,k.w.load(result['input'])
    def test_returning_to_older_batch_does_not_report_unchanged_source_as_new(self):
        first=self.version('first',{'src/a.cpp':'A'},'a.md','2026-01-01T01:00:00+00:00')
        second=self.version('second',{'src/b.cpp':'B'},'b.md','2026-01-02T01:00:00+00:00');k.w.save(k.cache(self.c)/'current.json',second)
        result,inp=self.prepare({'src/a.cpp':'A'})
        self.assertEqual(result['changed_sources'],[])
        self.assertEqual(inp['knowledge_inventory']['known_sources'],2)
        self.assertEqual(inp['knowledge_inventory']['known_chapters'],2)
        self.assertEqual(inp['knowledge_inventory']['affected_chapters'],[])
    def test_affected_chapters_follow_own_source_hash_not_last_batch(self):
        self.version('a',{'src/a.cpp':'A'},'a.md','2026-01-01T01:00:00+00:00')
        self.version('b',{'src/b.cpp':'B'},'b.md','2026-01-02T01:00:00+00:00')
        result,inp=self.prepare({'src/a.cpp':'A changed'})
        self.assertEqual(result['changed_sources'],['src/a.cpp'])
        self.assertEqual([x['path'] for x in inp['knowledge_inventory']['affected_chapters']],['a.md'])
    def test_shared_source_refresh_does_not_hide_other_stale_chapter(self):
        self.version('a',{'shared.h':'old'},'a.md','2026-01-01T01:00:00+00:00')
        self.version('b',{'shared.h':'new'},'b.md','2026-01-02T01:00:00+00:00')
        result,inp=self.prepare({'shared.h':'new'})
        self.assertEqual(result['changed_sources'],[])
        self.assertEqual(result['status'],'knowledge_input_ready')
        self.assertEqual([x['path'] for x in inp['knowledge_inventory']['affected_chapters']],['a.md'])
    def test_republished_chapter_replaces_its_own_binding_and_retains_others(self):
        self.version('a',{'a.cpp':'old'},'a.md','2026-01-01T01:00:00+00:00')
        self.version('b',{'b.cpp':'old'},'b.md','2026-01-02T01:00:00+00:00')
        self.version('c',{'a.cpp':'new'},'a.md','2026-01-03T01:00:00+00:00')
        _,inp=self.prepare({'a.cpp':'new','b.cpp':'new'})
        self.assertEqual([x['path'] for x in inp['knowledge_inventory']['affected_chapters']],['b.md'])
    def test_legacy_versions_use_explicitly_disclosed_batch_scope(self):
        self.version('legacy',{'a.cpp':'A','b.cpp':'B'},'old.md','2026-01-01T01:00:00+00:00',precise=False)
        _,inp=self.prepare({'b.cpp':'changed'})
        self.assertEqual(inp['knowledge_inventory']['affected_chapters'][0]['binding_kind'],'legacy_batch_scope')
    def test_corrupt_history_is_retained_and_disclosed_not_silently_treated_as_no_history(self):
        self.version('valid',{'a.cpp':'A'},'a.md','2026-01-01T01:00:00+00:00')
        p=k.cache(self.c)/'versions/bad.json';p.write_text('{broken',encoding='utf-8')
        result,inp=self.prepare({'a.cpp':'A'})
        self.assertEqual(p.read_text(),'{broken');self.assertEqual(result['changed_sources'],[])
        self.assertTrue(inp['knowledge_inventory']['warnings'])
    def test_foreign_repository_and_preview_versions_do_not_count(self):
        self.version('foreign',{'a.cpp':'A'},'a.md','2026-01-01T01:00:00+00:00',repo=2)
        row=self.version('preview',{'b.cpp':'B'},'b.md','2026-01-02T01:00:00+00:00');row['repository_written']=False
        k.w.save(k.cache(self.c)/'versions/preview.json',row)
        _,inp=self.prepare({'a.cpp':'A'})
        self.assertEqual(inp['knowledge_inventory']['known_sources'],0)
    def test_current_pointer_and_version_are_deduplicated(self):
        row=self.version('a',{'a.cpp':'A'},'a.md','2026-01-01T01:00:00+00:00');k.w.save(k.cache(self.c)/'current.json',row)
        self.assertEqual(inventory.load(k.cache(self.c),1)['snapshots'],1)
