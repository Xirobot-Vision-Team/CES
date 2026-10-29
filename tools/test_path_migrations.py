"""Check the functional-name migration without importing optional runtime hosts."""
import ast,hashlib,json,re,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent

class PathMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory=json.loads((ROOT/'tools/path_migrations.json').read_text(encoding='utf-8'))
    def test_every_migrated_target_exists_and_old_file_is_absent(self):
        paths=self.inventory['paths']
        self.assertEqual(len(paths.values()),len(set(paths.values())))
        for old,new in paths.items():
            with self.subTest(path=new):
                self.assertFalse((ROOT/old).is_file());self.assertTrue((ROOT/new).is_file())
    def test_no_numbered_source_directories_or_filenames(self):
        for path in ROOT.rglob('*'):
            if any(part in {'.git','__pycache__','.venv'} for part in path.relative_to(ROOT).parts):continue
            self.assertIsNone(re.search(r'(?i)(?:^|[_.-])ec\d+(?:[_.-]|$)',path.name),str(path.relative_to(ROOT)))
    def test_old_package_imports_cannot_return(self):
        old=set(self.inventory['packages'])
        for parent in ('construction','scripts'):
            for path in (ROOT/parent).rglob('*.py'):
                if '__pycache__' in path.parts:continue
                for node in ast.walk(ast.parse(path.read_text(encoding='utf-8-sig'))):
                    names=[x.name for x in node.names] if isinstance(node,ast.Import) else [node.module] if isinstance(node,ast.ImportFrom) else []
                    for name in names:
                        self.assertFalse(old.intersection((name or '').split('.')),str(path))
    def test_migrated_reference_navigation_has_no_missing_local_targets(self):
        for name in self.inventory['paths'].values():
            if not name.endswith('.md'):continue
            path=ROOT/name
            for target in re.findall(r'(?<!!)\[[^]\n]+\]\(([^)\n]+)\)',path.read_text(encoding='utf-8-sig')):
                target=target.split('#',1)[0]
                if target and '://' not in target and not target.startswith(('mailto:','<')):
                    self.assertTrue((path.parent/target).resolve().exists(),name+': '+target)
    def test_protocol_cli_and_byte_literals_match_reviewed_source(self):
        for row in self.inventory['runtime_wire_constants']:
            with self.subTest(path=row['path']):
                tree=ast.parse((ROOT/row['path']).read_text(encoding='utf-8-sig'));values=[]
                for node in ast.walk(tree):
                    if not isinstance(node,ast.Constant):continue
                    if isinstance(node.value,bytes):values.append(dict(bytes=node.value.hex()))
                    elif isinstance(node.value,str) and node.value.startswith(('ces.','https://schemas.','--','CES-')):values.append(dict(text=node.value))
                self.assertEqual(hashlib.sha256(json.dumps(values,sort_keys=True).encode()).hexdigest(),row['sha256'])

if __name__=='__main__':unittest.main()
