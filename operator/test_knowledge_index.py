"""A partial knowledge update must not hide unchanged chapters."""
import tempfile,unittest
from pathlib import Path
import ces_knowledge as k
class KnowledgeIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=dict(repository_path=self.tmp.name,github=dict(repository_id=1))
        self.root=Path(self.tmp.name)/"docs/ces";self.root.mkdir(parents=True)
    def fixture(self):
        index=self.root/"knowledge/README.md";index.parent.mkdir()
        index.write_text("# 知识\n\n- [构建](build.md)\n- [接口](interfaces.md)\n",encoding="utf-8")
        k.w.save(self.root/".ces-documents.json",dict(schema="ces.repository_documents.v1",repository_id=1,files={
            "knowledge/README.md":dict(sha256=k.d.text_hash(index.read_bytes())),"knowledge/build.md":{},"knowledge/interfaces.md":{}}))
        return index
    def test_partial_update_preserves_untouched_chapter(self):
        self.fixture();links=k.chapter_index(self.c,[dict(path="build.md",title="构建与验证")])
        self.assertEqual(links,["- [构建与验证](build.md)","- [接口](interfaces.md)"])
    def test_member_edited_index_is_not_overwritten(self):
        index=self.fixture();index.write_text("member edit",encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError,"EXTERNALLY_MODIFIED"):k.chapter_index(self.c,[dict(path="build.md")])
    def test_initial_index(self):
        self.assertEqual(k.chapter_index(self.c,[dict(path="new.md",title="新章")]),["- [新章](new.md)"])
if __name__=="__main__":unittest.main(verbosity=2)
