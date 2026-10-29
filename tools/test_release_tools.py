"""Release checks against temporary synthetic source trees only."""
import contextlib,io,json,tempfile,unittest
from pathlib import Path
import prepare_release as p
import release_check as r
import verify_product as v

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)/'source';self.root.mkdir()
    def write(self,name,content):
        path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content,encoding='utf-8');return path
    def source(self):
        self.write('PRODUCT.json',json.dumps(dict(operator_version='1.7.0')))
        self.write('ces-product','#!/bin/sh\nexit 0\n')
        self.write('operator/sample.py','print(1)\n')
        self.write('scripts/core.py','print(2)\n')
        self.write('BASELINE_SHA256.json',json.dumps(dict(sha256={'scripts/core.py':v.collect_file_hash(self.root/'scripts/core.py')})))
    def test_scanner_reports_location_not_matched_value(self):
        token='gh'+'p_'+'a'*30;self.write('example.py','token='+repr(token))
        found=r.candidates(self.root);self.assertEqual(found[0]['rule'],'credential_token')
        self.assertNotIn(token,json.dumps(found));self.assertEqual(found[0]['path'],'example.py')
    def test_private_paths_are_reported(self):
        self.write('notes.txt','C:'+chr(92)+'Users'+chr(92)+'private-person'+chr(92)+'file.txt')
        self.assertEqual(r.candidates(self.root)[0]['rule'],'personal_windows_path')
    def test_home_path_checks_are_generic_and_keep_documented_placeholders(self):
        self.write('notes.txt','/home/'+'private-person/project\n'+'/home/'+'operator/project\n')
        found=r.candidates(self.root)
        self.assertEqual(len(found),1);self.assertEqual(found[0]['rule'],'private_home_path');self.assertEqual(found[0]['line'],1)
    def test_new_key_marker_is_not_directory_allowlisted(self):
        self.write('tests/fake.py','BEGIN '+('-----BEGIN '+'PRIVATE KEY-----'))
        result=r.check(self.root,False)
        self.assertTrue(any(x.get('reason')=='unreviewed_sensitive_pattern' for x in result['errors']))
    def test_exact_exception_rejects_changed_line(self):
        path=self.write('fixture.py',repr('gh'+'p_'+'a'*30));row=r.candidates(self.root)[0]
        self.write('tools/release_allowlist.json',json.dumps(dict(entries=[dict(**row,reason='synthetic negative fixture')])))
        self.assertFalse(any(x.get('reason')=='unreviewed_sensitive_pattern' for x in r.check(self.root,False)['errors']))
        path.write_text(repr('gh'+'p_'+'b'*30))
        errors=r.check(self.root,False)['errors'];self.assertTrue(any(x['reason']=='stale_scanner_exception' for x in errors))
        self.assertTrue(any(x['reason']=='unreviewed_sensitive_pattern' for x in errors))
    def test_prepare_keeps_legacy_bytes_and_omits_local_evidence(self):
        self.source();self.write('docs/validation.json','private validation')
        self.write('.venv/private.txt','not source');self.write('cache/ledger.sqlite3','state')
        target=Path(self.tmp.name)/'release';result=p.prepare(self.root,target)
        self.assertFalse((target/'docs/validation.json').exists());self.assertFalse((target/'.venv').exists())
        self.assertEqual((target/'scripts/core.py').read_bytes(),(self.root/'scripts/core.py').read_bytes())
        manifest=json.loads((target/'PRODUCT_SHA256.json').read_text());self.assertEqual(manifest['sha256']['operator/sample.py'],v.collect_file_hash(target/'operator/sample.py'))
        self.assertIn('docs/validation.json',result['omitted'])
    def test_existing_destination_is_never_overwritten(self):
        self.source();target=Path(self.tmp.name)/'release';target.mkdir();(target/'keep').write_text('user content')
        with self.assertRaisesRegex(RuntimeError,'new directory'):p.prepare(self.root,target)
        self.assertEqual((target/'keep').read_text(),'user content')
    def test_nested_destination_rejected(self):
        self.source()
        with self.assertRaisesRegex(RuntimeError,'outside'):p.prepare(self.root,self.root/'release')
    def test_legacy_change_not_rebaselined(self):
        self.source();self.write('scripts/core.py','changed')
        with self.assertRaisesRegex(RuntimeError,'Protected legacy'):p.prepare(self.root,Path(self.tmp.name)/'release')
    def test_checks_do_not_execute_python_sources(self):
        self.write('danger.py','raise SystemExit(99)')
        r.check(self.root,False)
    def test_runtime_payload_file_rejected(self):
        self.write('secrets/state.sqlite3','state');errors=r.check(self.root,False)['errors']
        self.assertTrue(any(x['reason']=='runtime_or_private_file' for x in errors))
    def test_dotenv_never_enters_release(self):
        self.source();self.write('.env.local','PRIVATE_VALUE=not-a-token')
        errors=r.check(self.root,False)['errors'];self.assertTrue(any(x['path']=='.env.local' and x['reason']=='runtime_or_private_file' for x in errors))
        target=Path(self.tmp.name)/'release';p.prepare(self.root,target)
        self.assertFalse((target/'.env.local').exists())
    def test_no_git_directory_in_current_manifest(self):
        self.write('.git/config','local data');self.write('README.md','source')
        self.assertNotIn('.git/config',v.collect(self.root))

if __name__=='__main__':unittest.main(verbosity=2)
