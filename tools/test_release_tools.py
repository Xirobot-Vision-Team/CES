"""Release checks against temporary synthetic source trees only."""
import contextlib,io,json,tempfile,unittest
import hashlib,tarfile,zipfile
from unittest.mock import patch
from pathlib import Path
import prepare_release as p
import release_check as r
import verify_product as v
import build_release as b

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
    def cleanup(self,removed=None,modified=None):
        self.write('tools/legacy_cleanup.json',json.dumps(dict(schema='ces.legacy_cleanup.v1',removed=removed or [],modified=modified or [])))
    def test_explicit_retirement_preserves_historical_baseline(self):
        self.source();path=self.root/'scripts/core.py';baseline=v.collect_file_hash(path);path.unlink()
        self.cleanup([dict(path='scripts/core.py',baseline_sha256=baseline,reason='Retired one-time checker')])
        errors,_=v.legacy_review(self.root,v.collect(self.root));self.assertEqual(errors,[])
    def test_unlisted_missing_protocol_file_still_fails(self):
        self.source();(self.root/'scripts/core.py').unlink()
        errors,_=v.legacy_review(self.root,v.collect(self.root));self.assertIn('scripts/core.py',errors)
    def test_retired_file_cannot_silently_return(self):
        self.source();baseline=v.collect_file_hash(self.root/'scripts/core.py')
        self.cleanup([dict(path='scripts/core.py',baseline_sha256=baseline,reason='Retired checker')])
        errors,_=v.legacy_review(self.root,v.collect(self.root));self.assertIn('RETIRED_FILE_REINTRODUCED:scripts/core.py',errors)
    def test_reviewed_modification_rejects_subsequent_drift(self):
        self.source();path=self.root/'scripts/core.py';baseline=v.collect_file_hash(path);path.write_text('reviewed')
        self.cleanup(modified=[dict(path='scripts/core.py',baseline_sha256=baseline,current_sha256=v.collect_file_hash(path),reason='Exact reviewed inventory update')])
        self.assertEqual(v.legacy_review(self.root,v.collect(self.root))[0],[])
        path.write_text('different')
        self.assertIn('REVIEWED_LEGACY_FILE_CHANGED:scripts/core.py',v.legacy_review(self.root,v.collect(self.root))[0])
    def test_wrong_baseline_or_unprotected_path_is_not_an_exception(self):
        self.source();self.cleanup([dict(path='scripts/core.py',baseline_sha256='0'*64,reason='invalid')])
        self.assertIn('INVALID_LEGACY_CLEANUP:scripts/core.py',v.legacy_review(self.root,v.collect(self.root))[0])
        self.cleanup([dict(path='../outside',baseline_sha256='0'*64,reason='invalid')])
        self.assertIn('INVALID_LEGACY_CLEANUP:../outside',v.legacy_review(self.root,v.collect(self.root))[0])
    def moved_fixture(self):
        self.source();old=self.root/'scripts/core.py';baseline=v.collect_file_hash(old)
        target=self.root/'scripts/renamed.py';old.rename(target)
        row=dict(path='scripts/core.py',target='scripts/renamed.py',baseline_sha256=baseline,current_sha256=v.collect_file_hash(target),reason='Reviewed functional rename')
        return row,target
    def set_move(self,rows):
        self.write('tools/legacy_cleanup.json',json.dumps(dict(schema='ces.legacy_cleanup.v1',moved=rows)))
    def test_explicit_move_keeps_original_baseline_and_packages(self):
        row,target=self.moved_fixture();baseline=(self.root/'BASELINE_SHA256.json').read_bytes();self.set_move([row])
        self.assertEqual(v.legacy_review(self.root,v.collect(self.root))[0],[])
        destination=Path(self.tmp.name)/'release';p.prepare(self.root,destination)
        self.assertEqual((destination/'scripts/renamed.py').read_bytes(),target.read_bytes())
        self.assertEqual((destination/'BASELINE_SHA256.json').read_bytes(),baseline)
    def test_moved_file_tampering_and_old_name_return_fail(self):
        row,target=self.moved_fixture();self.set_move([row]);target.write_text('changed')
        self.assertIn('MIGRATED_LEGACY_FILE_CHANGED:scripts/core.py',v.legacy_review(self.root,v.collect(self.root))[0])
        target.write_text('print(2)\n');self.write('scripts/core.py','print(2)\n')
        self.assertIn('MIGRATED_LEGACY_FILE_CHANGED:scripts/core.py',v.legacy_review(self.root,v.collect(self.root))[0])
    def test_move_missing_digest_unsafe_or_missing_target_fail(self):
        row,target=self.moved_fixture()
        for name in ['../outside','/outside','C:/outside','scripts\\renamed.py','scripts//renamed.py','missing.py',None]:
            with self.subTest(target=name):
                self.set_move([dict(row,target=name)])
                self.assertIn('MIGRATED_LEGACY_FILE_CHANGED:scripts/core.py',v.legacy_review(self.root,v.collect(self.root))[0])
        target.unlink();self.set_move([{k:val for k,val in row.items() if k!='current_sha256'}])
        self.assertIn('MIGRATED_LEGACY_FILE_CHANGED:scripts/core.py',v.legacy_review(self.root,v.collect(self.root))[0])
    def test_two_old_files_cannot_claim_same_move_target(self):
        row,target=self.moved_fixture();baseline=json.loads((self.root/'BASELINE_SHA256.json').read_text())
        baseline['sha256']['scripts/second.py']=row['baseline_sha256'];self.write('BASELINE_SHA256.json',json.dumps(baseline))
        self.set_move([row,dict(row,path='scripts/second.py')])
        self.assertIn('MIGRATED_LEGACY_FILE_CHANGED:scripts/second.py',v.legacy_review(self.root,v.collect(self.root))[0])
    def release_fixture(self):
        self.source();self.write('PRODUCT_SHA256.json',json.dumps(dict(sha256={name:v.collect_file_hash(self.root/name) for name in ['PRODUCT.json','ces-product','operator/sample.py','scripts/core.py']})))
    def test_release_archives_have_only_manifest_files_and_same_bytes(self):
        self.release_fixture();self.write('private-unlisted.txt','never archive')
        with patch.object(b.release_check,'check',return_value=dict(status='PASS')):result=b.build(self.root,Path(self.tmp.name)/'assets')
        with zipfile.ZipFile(result['assets'][0]) as archive:
            self.assertEqual(len(archive.namelist()),5)
            self.assertFalse(any('private' in name for name in archive.namelist()))
            self.assertEqual(archive.read('CES-1.7.0/operator/sample.py'),(self.root/'operator/sample.py').read_bytes())
        with tarfile.open(result['assets'][1]) as archive:self.assertEqual(archive.getmember('CES-1.7.0/ces-product').mode,0o755)
    def test_release_archives_are_reproducible(self):
        self.release_fixture()
        with patch.object(b.release_check,'check',return_value=dict(status='PASS')):
            first=b.build(self.root,Path(self.tmp.name)/'a');second=b.build(self.root,Path(self.tmp.name)/'b')
        for x,y in zip(first['assets'],second['assets']):self.assertEqual(Path(x).read_bytes(),Path(y).read_bytes())
    def test_release_check_failure_prevents_packaging(self):
        self.release_fixture()
        with patch.object(b.release_check,'check',return_value=dict(status='FAIL')):
            with self.assertRaisesRegex(RuntimeError,'check failed'):b.build(self.root,Path(self.tmp.name)/'assets')
        self.assertFalse((Path(self.tmp.name)/'assets').exists())
    def test_release_output_cannot_pollute_source_or_overwrite_assets(self):
        self.release_fixture()
        with self.assertRaisesRegex(RuntimeError,'outside'):b.build(self.root,self.root/'assets')
        output=Path(self.tmp.name)/'assets';output.mkdir()
        with patch.object(b.release_check,'check',return_value=dict(status='PASS')):
            with self.assertRaises(FileExistsError):b.build(self.root,output)

if __name__=='__main__':unittest.main(verbosity=2)
