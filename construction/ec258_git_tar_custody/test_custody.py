#!/usr/bin/env python3
"""EC258 tests use a REAL local Git object DB, no simulated blobs.

Production Podman, enterprise Git origin and EC253 signed policy deployment
are deliberately not fixtures here. Run as an unprivileged Linux user.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec258_git_tar_custody import custody as c
from ec252_quality_run_host import broker as runner
from ec253_lease_host import test_broker as signed_fixture


@unittest.skipUnless(os.name == 'posix' and os.path.isfile('/usr/bin/git') and
                     os.geteuid() != 0, 'run on nonroot Linux with /usr/bin/git')
class RealGitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ec258-')
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.repo = base / 'approved-repo'
        self.repo.mkdir(mode=0o700)
        self.private = base / 'private'
        self.private.mkdir(mode=0o700)
        self.output = base / 'export'
        self.output.mkdir(mode=0o700)
        self.git('init', '-q', '-b', 'main')
        os.chmod(self.repo / '.git', 0o700)
        self.git('config', 'user.name', 'Operator')
        self.git('config', 'user.email', 'operator@invalid.example')
        self.git('config', 'commit.gpgsign', 'false')
        (self.repo / 'pkg').mkdir()
        (self.repo / 'pkg' / 'core.py').write_bytes(b'print("fixed commit")\n')
        (self.repo / 'pytest.ini').write_bytes(b'[pytest]\n')
        (self.repo / 'unselected.txt').write_bytes(b'never exported\n')
        self.git('add', '.')
        self.git('commit', '-q', '-m', 'approved commit')
        self.commit = self.git('rev-parse', 'HEAD').strip()
        self.allow = {'schema': c.ALLOW_SCHEMA, 'commit_oid': self.commit,
                      'source_paths': ['pkg/core.py', 'pytest.ini']}
        self.allowpath = self.private / 'approved.json'
        self.write_approval()

    def git(self, *args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(self.repo),
                                        *args], env={**c.GIT_ENV,
                                                     'GIT_CONFIG_GLOBAL': '/dev/null'}).decode('ascii')

    def write_approval(self, override=None):
        data = self.allow if override is None else override
        self.allowpath.write_bytes(c._canonical(data))
        os.chmod(self.allowpath, 0o600)

    def assert_code(self, code, fn, *args):
        with self.assertRaises(c.CustodyError) as err:
            fn(*args)
        self.assertEqual(err.exception.code, code)

    def prepare(self):
        return c.prepare(str(self.repo), str(self.allowpath), str(self.output))

    def verify(self):
        return c.verify(str(self.repo), str(self.allowpath),
                        str(self.output / 'source.tar'),
                        str(self.output / 'source.custody.json'))

    def test_git_object_reader_is_offline_and_bounded(self):
        self.assertEqual(c.GIT_ENV['GIT_NO_LAZY_FETCH'], '1')
        self.assertEqual(c.GIT_ENV['GIT_ALLOW_PROTOCOL'], '')
        self.assertEqual(c._git(str(self.repo), ['rev-parse', '--show-object-format']).strip(), b'sha1')
        self.assert_code('CUSTODY_GIT_OUTPUT_LIMIT', c._git,
                         str(self.repo), ['rev-parse', 'HEAD'], 8)

    def test_real_git_checkout_dirt_never_enters_archive(self):
        (self.repo / 'pkg' / 'core.py').write_bytes(b'DIRTY / NOT APPROVED\n')
        p = self.prepare()
        self.assertEqual(p['exit_code'], 2)
        with tarfile.open(self.output / 'source.tar', mode='r:') as tar:
            self.assertEqual(tar.getnames(), ['pkg/core.py', 'pytest.ini'])
            self.assertEqual(tar.extractfile('pkg/core.py').read(), b'print("fixed commit")\n')
        with tempfile.TemporaryDirectory(prefix='ec258-staged-') as root:
            n, total = runner._extract_source((self.output / 'source.tar').read_bytes(), root)
            self.assertEqual(n, 2)
            self.assertEqual(total, len(b'print("fixed commit")\n') + len(b'[pytest]\n'))
        self.assertTrue(self.verify()['content_custody_verified'])

    def test_real_cli_prepare_and_verify_exit_partial(self):
        script = str(Path(c.__file__).resolve())
        proc = subprocess.run([sys.executable, '-I', '-B', script, 'prepare',
                               '--repo', str(self.repo), '--allowlist', str(self.allowpath),
                               '--output-dir', str(self.output)], capture_output=True,
                              text=True, check=False)
        self.assertEqual(proc.returncode, 2, proc.stderr or proc.stdout)
        self.assertEqual(json.loads(proc.stdout)['status'], 'partial')
        proc = subprocess.run([sys.executable, '-I', '-B', script, 'verify',
                               '--repo', str(self.repo), '--allowlist', str(self.allowpath),
                               '--source-tar', str(self.output / 'source.tar'),
                               '--receipt', str(self.output / 'source.custody.json')],
                              capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 2, proc.stderr or proc.stdout)
        self.assertTrue(json.loads(proc.stdout)['content_custody_verified'])

    def test_cli_missing_approval_is_unavailable_not_pass(self):
        proc = subprocess.run([sys.executable, '-I', '-B', str(Path(c.__file__).resolve()),
                               'prepare', '--repo', str(self.repo),
                               '--allowlist', str(self.private / 'absent.json'),
                               '--output-dir', str(self.output)], capture_output=True,
                              text=True, check=False)
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(json.loads(proc.stdout)['status'], 'unavailable')
        self.assertFalse((self.output / 'source.tar').exists())

    def test_tar_is_bytewise_reproducible_in_two_export_directories(self):
        self.prepare()
        first = (self.output / 'source.tar').read_bytes()
        self.output = Path(self.tmp.name) / 'other-export'
        self.output.mkdir(mode=0o700)
        self.prepare()
        self.assertEqual((self.output / 'source.tar').read_bytes(), first)

    def test_receipt_lists_exact_git_object_and_bytes(self):
        self.prepare()
        receipt = json.loads((self.output / 'source.custody.json').read_text())
        self.assertEqual(receipt['commit_oid'], self.commit)
        self.assertEqual(receipt['source_file_count'], 2)
        self.assertEqual(receipt['files'][0]['git_mode'], '100644')
        self.assertEqual(receipt['files'][0]['path'], 'pkg/core.py')
        self.assertFalse(receipt['independent_git_origin_attested'])
        self.assertEqual(self.verify()['commit_oid'], self.commit)

    def test_tar_content_tamper_rejected(self):
        self.prepare()
        target = self.output / 'source.tar'
        data = target.read_bytes()
        target.write_bytes(data.replace(b'fixed commit', b'fake! commit'))
        self.assert_code('CUSTODY_TAR_NOT_GIT_CONTENT', self.verify)

    def test_receipt_content_tamper_rejected(self):
        self.prepare()
        target = self.output / 'source.custody.json'
        rec = json.loads(target.read_text())
        rec['quality_pass_verified'] = True
        target.write_bytes(c._canonical(rec))
        self.assert_code('CUSTODY_RECEIPT_NOT_GIT_CONTENT', self.verify)

    def test_approval_cannot_mutate_after_preparation(self):
        self.prepare()
        self.allow['source_paths'] = ['pytest.ini']
        self.write_approval()
        self.assert_code('CUSTODY_TAR_NOT_GIT_CONTENT', self.verify)

    def test_overwrite_existing_pair_fail_closed(self):
        self.prepare()
        before = (self.output / 'source.tar').read_bytes()
        self.assert_code('CUSTODY_OUTPUT_ALREADY_EXISTS', self.prepare)
        self.assertEqual((self.output / 'source.tar').read_bytes(), before)

    def test_approval_unsorted_or_duplicate_paths_rejected(self):
        for paths in (['pytest.ini', 'pkg/core.py'], ['pytest.ini', 'pytest.ini']):
            with self.subTest(paths=paths):
                self.allow['source_paths'] = paths
                self.write_approval()
                self.assert_code('CUSTODY_APPROVAL_PATHS', self.prepare)

    def test_missing_selected_path_rejected(self):
        self.allow['source_paths'] = ['unknown.py']
        self.write_approval()
        self.assert_code('CUSTODY_ALLOWLIST_PATH_ABSENT', self.prepare)

    def test_selected_symlink_and_subdirectory_rejected(self):
        (self.repo / 'link.py').symlink_to('pkg/core.py')
        self.git('add', 'link.py')
        self.git('commit', '-q', '-m', 'symlink')
        self.allow['commit_oid'] = self.git('rev-parse', 'HEAD').strip()
        for path in ('link.py', 'pkg'):
            with self.subTest(path=path):
                self.allow['source_paths'] = [path]
                self.write_approval()
                self.assert_code('CUSTODY_ALLOWLIST_NOT_REGULAR_FILE', self.prepare)

    def test_unselected_symlink_does_not_leak(self):
        (self.repo / 'external_link').symlink_to('/etc/passwd')
        self.git('add', 'external_link')
        self.git('commit', '-q', '-m', 'unselected link')
        self.allow['commit_oid'] = self.git('rev-parse', 'HEAD').strip()
        self.write_approval()
        self.prepare()
        with tarfile.open(self.output / 'source.tar', mode='r:') as tar:
            self.assertNotIn('external_link', tar.getnames())

    def test_approval_secret_paths_and_traversal_rejected(self):
        for path in ('../outside', '/root/.ssh/id_rsa', 'pkg/.env',
                     'pkg/secret.key', '.aws/credentials', 'pkg\\other.py',
                     'pkg//bad.py', 'pkg/./core.py', 'pkg/core.py/',
                     'pkg\x00core.py'):
            with self.subTest(path=path):
                self.allow['source_paths'] = [path]
                self.write_approval()
                self.assert_code('CUSTODY_PATH_UNSAFE' if path in ('/root/.ssh/id_rsa',
                                 'pkg\\other.py', 'pkg/core.py/', 'pkg\x00core.py')
                                 else 'CUSTODY_PATH_FORBIDDEN', self.prepare)

    def test_json_duplicate_key_rejected(self):
        self.allowpath.write_text('{"schema":"%s","schema":"%s",'
                                  '"commit_oid":"%s","source_paths":["pytest.ini"]}' %
                                  (c.ALLOW_SCHEMA, c.ALLOW_SCHEMA, self.commit))
        os.chmod(self.allowpath, 0o600)
        self.assert_code('CUSTODY_JSON_DUPLICATE_KEY', self.prepare)

    def test_group_readable_approval_rejected(self):
        os.chmod(self.allowpath, 0o640)
        self.assert_code('CUSTODY_PRIVATE_FILE_REQUIRED', self.prepare)

    def test_symlink_repo_rejected(self):
        symlink = Path(self.tmp.name) / 'repo-link'
        symlink.symlink_to(self.repo, target_is_directory=True)
        self.assert_code('CUSTODY_PRIVATE_DIRECTORY_REQUIRED', c.build,
                         str(symlink), self.allowpath.read_bytes())

    def test_external_object_alternates_rejected(self):
        alt = self.repo / '.git' / 'objects' / 'info' / 'alternates'
        alt.write_text('/elsewhere/.git/objects\n')
        self.assert_code('CUSTODY_EXTERNAL_OBJECT_ALTERNATES', self.prepare)

    def test_commit_must_be_full_oid_not_ref(self):
        self.allow['commit_oid'] = 'HEAD'
        self.write_approval()
        self.assert_code('CUSTODY_APPROVAL_FIELDS', self.prepare)

    def test_optional_policy_requires_profile_and_operator_ticket(self):
        self.prepare()
        with self.assertRaises(c.CustodyError) as er:
            c.verify(str(self.repo), str(self.allowpath),
                     str(self.output / 'source.tar'),
                     str(self.output / 'source.custody.json'), '/bogus/policy.json')
        self.assertEqual(er.exception.code, 'CUSTODY_PROFILE_ID_REQUIRED')

    def test_actual_ec253_two_ticket_local_policy_binding(self):
        self.prepare()
        fix = signed_fixture.LeaseHostTests(
            'test_private_policy_and_original_catalog_valid')
        fix.setUp()
        self.addCleanup(fix.doCleanups)
        fix.policy['source_tar_path'] = str(self.output / 'source.tar')
        fix.policy['expected_source_tar_sha256'] = c._sha(
            (self.output / 'source.tar').read_bytes())
        fix.write_policy()
        result = c.verify(str(self.repo), str(self.allowpath),
                          str(self.output / 'source.tar'),
                          str(self.output / 'source.custody.json'),
                          str(fix.policy_path), 'python.pytest')
        self.assertTrue(result['local_ec253_tickets_consistent'])
        self.assertFalse(result['independent_git_origin_attested'])
        # The EC186 ticket's source pin is an operator-specified scope; this
        # verifier proves only internally consistent signatures, not that
        # its opaque pin was independently computed from this Git commit.

    def test_ec253_policy_source_sha_mismatch_fails_closed(self):
        self.prepare()
        fix = signed_fixture.LeaseHostTests(
            'test_private_policy_and_original_catalog_valid')
        fix.setUp()
        self.addCleanup(fix.doCleanups)
        fix.policy['source_tar_path'] = str(self.output / 'source.tar')
        fix.policy['expected_source_tar_sha256'] = 'd' * 64
        fix.write_policy()
        with self.assertRaises(c.CustodyError) as err:
            c.verify(str(self.repo), str(self.allowpath),
                     str(self.output / 'source.tar'),
                     str(self.output / 'source.custody.json'),
                     str(fix.policy_path), 'python.pytest')
        self.assertEqual(err.exception.code, 'CUSTODY_EC253_POLICY_TAR_MISMATCH')

    def test_ec253_wrong_ticket_mac_rejected(self):
        self.prepare()
        fix = signed_fixture.LeaseHostTests(
            'test_private_policy_and_original_catalog_valid')
        fix.setUp()
        self.addCleanup(fix.doCleanups)
        fix.policy['source_tar_path'] = str(self.output / 'source.tar')
        fix.policy['expected_source_tar_sha256'] = c._sha(
            (self.output / 'source.tar').read_bytes())
        fix.write_policy()
        signed_fixture.store(fix.approval_key_path, b'X' * 64)
        with self.assertRaises(c.CustodyError) as err:
            c.verify(str(self.repo), str(self.allowpath),
                     str(self.output / 'source.tar'),
                     str(self.output / 'source.custody.json'),
                     str(fix.policy_path), 'python.pytest')
        self.assertEqual(err.exception.code, 'CUSTODY_EC253_SIGNED_BINDING_UNAVAILABLE')

    def test_sha256_object_format_supported(self):
        other = Path(self.tmp.name) / 'sha256-repo'
        other.mkdir(mode=0o700)
        try:
            subprocess.check_call(['/usr/bin/git', '-C', str(other), 'init', '-q',
                                   '--object-format=sha256'], env=c.GIT_ENV)
        except subprocess.CalledProcessError:
            self.skipTest('local Git has no SHA256 repository support')
        os.chmod(other / '.git', 0o700)
        (other / 'sample.py').write_bytes(b'pass\n')
        subprocess.check_call(['/usr/bin/git', '-C', str(other), 'add', '.'], env=c.GIT_ENV)
        subprocess.check_call(['/usr/bin/git', '-C', str(other), '-c', 'user.name=Operator',
                               '-c', 'user.email=operator@invalid.example', 'commit', '-qm', 'c'],
                              env=c.GIT_ENV)
        oid = subprocess.check_output(['/usr/bin/git', '-C', str(other),
                                       'rev-parse', 'HEAD'], env=c.GIT_ENV).strip().decode()
        self.write_approval({'schema': c.ALLOW_SCHEMA, 'commit_oid': oid,
                             'source_paths': ['sample.py']})
        tar, receipt = c.build(str(other), self.allowpath.read_bytes())
        self.assertEqual(len(oid), 64)
        self.assertEqual(receipt['git_object_format'], 'sha256')
        self.assertIn(b'pass\n', tar)


if __name__ == '__main__':
    unittest.main()
