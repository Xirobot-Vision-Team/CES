#!/usr/bin/env python3
"""EC181 focused POSIX disposable synthetic development cases (NOT final acceptance)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import quality_detect as qd

try:
    import jsonschema
except ImportError:
    jsonschema = None

BASE = Path(__file__).parent.parent
FIXED = datetime(2026, 10, 22, 12, 30, 0, tzinfo=timezone.utc)


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'),
                     'EC181 secure dirfd implementation is POSIX only')
class QualityDetectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ec181-')
        self.addCleanup(self.temp.cleanup)
        self.root = str(Path(self.temp.name) / 'worktree')
        os.mkdir(self.root)
        self.calls = []

    def put(self, relative: str, content: str | bytes):
        path = Path(self.root, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode('utf-8') if isinstance(content, str) else content)

    def pin(self):
        return qd.QualityDetector.observe_root(
            self.root, authorize_observation=lambda fact: self.calls.append(fact) or True,
            clock=lambda: FIXED)

    def run_detect(self, *paths: str, pin=None, grant_source=True, grant_file=True, now=None):
        if pin is None:
            pin = self.pin()
        return qd.QualityDetector.detect(
            self.root, pin, candidate_paths=list(paths), clock=lambda: now or FIXED,
            authorize_source=lambda facts: self.calls.append(facts) or grant_source,
            authorize_path=lambda facts: self.calls.append(facts) or grant_file)

    def assert_refused(self, output: dict, status=None):
        self.assertIn(output['status'], ('invalid_input', 'unavailable'))
        if status:
            self.assertEqual(output['status'], status)
        self.assertEqual(output['files'], [])
        self.assertEqual(output['tools'], [])
        self.assertIsNone(output['source'])
        self.assertIsNone(output['inventory_sha256'])
        self.assertFalse(output['effects']['executed_commands'])

    def test_python_detect_from_real_config(self):
        self.put('pyproject.toml', '[tool.pytest.ini_options]\naddopts = "-q"\n[tool.ruff]\nline-length = 88\n')
        r = self.run_detect('pyproject.toml', 'pytest.ini')
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['exit_code'], 2)
        self.assertEqual(r['coverage']['present_paths'], 1)
        self.assertEqual(r['coverage']['absent_selected_paths'], 1)
        self.assertEqual(r['coverage']['parsed_configs'], 1)
        self.assertEqual({x['tool_family'] for x in r['tools']}, {'pytest', 'ruff'})
        self.assertEqual({x['profile_id'] for x in r['profile_hints']}, {'python.pytest', 'python.ruff'})
        self.assertFalse(r['coverage']['dependencies_installed_verified'])
        self.assertFalse(r['coverage']['commands_usable_verified'])
        self.assertEqual(r['files'][0]['sha256'], hashlib.sha256(
            Path(self.root, 'pyproject.toml').read_bytes()).hexdigest())

    def test_pyproject_pep621_dependency_hints_are_declared_only(self):
        self.put('pyproject.toml', '[project]\nname="demo"\n'
                 'dependencies=["mypy>=1.0", "black==23.0"]\n'
                 '[project.optional-dependencies]\ntest=["pytest>=8; python_version>\'3.8\'", "ruff >= 0.5"]\n')
        r = self.run_detect('pyproject.toml')
        self.assertEqual(r['status'], 'partial')
        self.assertEqual({t['tool_family'] for t in r['tools']}, {'mypy', 'black', 'pytest', 'ruff'})
        self.assertFalse(r['coverage']['dependencies_installed_verified'])

    def test_stat_only_does_not_open_file_for_read(self):
        self.put('go.mod', 'module secret.example\n')
        p = Path(self.root, 'go.mod')
        p.chmod(0)
        self.addCleanup(lambda: p.chmod(0o600) if p.exists() else None)
        r = self.run_detect('go.mod')
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['files'][0]['parse_state'], 'METADATA_ONLY_NOT_EXECUTED_OR_PARSED')
        self.assertIsNone(r['files'][0]['sha256'])

    def test_node_scripts_names_only_and_never_interpreted(self):
        evil = 'printf dangerous-command-DO-NOT-INVOKE > /tmp/should-not-exist'
        self.put('package.json', json.dumps({
            'scripts': {'test': evil, 'lint': 'curl something', 'unexpected': 'secret!' },
            'devDependencies': {'vitest': '1', 'typescript': '5', 'eslint': '9'},
            'packageManager': 'pnpm@9.5.0'}))
        r = self.run_detect('package.json')
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['files'][0]['declared_script_keys'], ['test', 'lint'])
        self.assertIn('TypeScript', [x['language'] for x in r['languages']])
        self.assertEqual({x['tool_family'] for x in r['tools']},
                         {'vitest', 'typescript', 'eslint', 'pnpm'})
        self.assertNotIn('dangerous-command', json.dumps(r))
        self.assertFalse(r['effects']['writes_performed'])

    def test_ci_config_never_parses_untrusted_job_script(self):
        self.put('.github/workflows/check.yml', 'jobs: {build: {steps: [{run: "echo DANGEROUS"}]}}')
        r = self.run_detect('.github/workflows/check.yml')
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['files'][0]['parse_state'], 'METADATA_ONLY_NOT_EXECUTED_OR_PARSED')
        self.assertIsNone(r['files'][0]['sha256'])
        self.assertNotIn('DANGEROUS', json.dumps(r))
        self.assertIn('github-actions-config', [x['tool_family'] for x in r['tools']])
        self.assertFalse(r['coverage']['ci_results_read'])

    def test_large_lockfile_is_not_read_or_parsed(self):
        self.put('package-lock.json', b' ' * (qd.MAX_FILE_BYTES + 10))
        r = self.run_detect('package-lock.json')
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['coverage']['read_config_bytes'], 0)
        self.assertEqual(r['files'][0]['bytes'], qd.MAX_FILE_BYTES + 10)
        self.assertIsNone(r['files'][0]['sha256'])
        self.assertEqual(r['tools'][0]['tool_family'], 'npm')

    def test_vitest_alone_does_not_claim_typescript(self):
        self.put('package.json', '{"devDependencies":{"vitest":"1"}}')
        r = self.run_detect('package.json')
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['languages'][0]['language'], 'JavaScript')

    def test_cargo_build_config(self):
        self.put('Cargo.toml', '[package]\nname = "tool"\nversion = "0.1.0"\n')
        r = self.run_detect('Cargo.toml')
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['tools'][0]['tool_family'], 'cargo')
        self.assertEqual(r['languages'][0]['language'], 'Rust')

    def test_go_mod_metadata_only_no_body_read(self):
        self.put('go.mod', 'module private.org/mystery\n')
        r = self.run_detect('go.mod')
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['tools'][0]['tool_family'], 'go')
        self.assertIsNone(r['files'][0]['sha256'])
        self.assertNotIn('private.org', json.dumps(r))

    def test_malformed_toml_yields_unknown_not_tool(self):
        self.put('pyproject.toml', '[tool.pytest.ini_options\n')
        r = self.run_detect('pyproject.toml')
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['files'][0]['parse_state'], 'MALFORMED_CONFIG')
        self.assertEqual(r['tools'], [])

    def test_invalid_ini_yields_unknown_not_exception(self):
        self.put('tox.ini', 'not a section or valid ini')
        r = self.run_detect('tox.ini')
        self.assertEqual(r['files'][0]['parse_state'], 'MALFORMED_CONFIG')
        self.assertEqual(r['tools'], [])

    def test_duplicate_manifest_key_rejected_as_malformed(self):
        self.put('package.json', '{"scripts": {"test":"x"}, "scripts": {"test":"y"}}')
        r = self.run_detect('package.json')
        self.assertEqual(r['files'][0]['parse_state'], 'MALFORMED_CONFIG')
        self.assertEqual(r['files'][0]['declared_script_keys'], [])

    def test_nested_workspaces_allowlisted_only(self):
        self.put('apps/service/package.json', '{"devDependencies":{"jest":"29"}}')
        self.put('apps/other/package.json', '{"devDependencies":{"vitest":"1"}}')
        r = self.run_detect('apps/service/package.json')
        self.assertEqual([x['tool_family'] for x in r['tools']], ['jest'])
        self.assertEqual(r['coverage']['selected_paths'], 1)
        self.assertEqual(r['files'][0]['path'], 'apps/service/package.json')

    def test_absent_is_selected_path_only(self):
        r = self.run_detect('Cargo.toml')
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['languages'], [])
        self.assertEqual(r['coverage']['absent_selected_paths'], 1)
        self.assertFalse(r['coverage']['repository_wide_inventory_complete'])

    def test_untrusted_readme_not_supported_even_if_listed(self):
        self.put('README.md', 'run sudo rm -rf /')
        r = self.run_detect('README.md')
        self.assert_refused(r, 'invalid_input')

    def test_script_file_unrecognized(self):
        self.put('test.sh', 'echo should-never-be-read')
        self.assert_refused(self.run_detect('test.sh'), 'invalid_input')

    def test_path_traversal_absolute_and_backslash(self):
        for path in ('../package.json', '/etc/package.json', 'x/../../Cargo.toml',
                     'x\\package.json', 'node_modules/package.json', 'lib//package.json'):
            with self.subTest(path=path):
                self.assert_refused(self.run_detect(path), 'invalid_input')

    def test_case_collision_denied(self):
        self.assert_refused(self.run_detect('apps/web/package.json', 'APPS/web/package.json'),
                            'invalid_input')

    def test_unsupported_ci_filename_refused(self):
        self.assert_refused(self.run_detect('.github/workflows/../../script.yml'), 'invalid_input')

    def test_symlink_leaf_never_followed(self):
        self.put('other', 'secret')
        os.symlink('other', Path(self.root, 'package.json'))
        self.assert_refused(self.run_detect('package.json'), 'unavailable')

    def test_symlink_intermediate_never_followed(self):
        self.put('target/package.json', '{"devDependencies":{"jest":"1"}}')
        os.symlink('target', Path(self.root, 'alias'))
        self.assert_refused(self.run_detect('alias/package.json'), 'unavailable')

    def test_symlink_root_never_followed(self):
        badroot = str(Path(self.temp.name) / 'alias-root')
        os.symlink(self.root, badroot)
        with self.assertRaises(qd.QualityError):
            qd.QualityDetector.observe_root(badroot, authorize_observation=lambda _: True,
                                            clock=lambda: FIXED)

    def test_hardlinked_manifest_denied(self):
        self.put('original', 'data')
        os.link(Path(self.root, 'original'), Path(self.root, 'package.json'))
        self.assert_refused(self.run_detect('package.json'), 'unavailable')

    def test_fifo_never_blocks_and_refuses(self):
        os.mkfifo(Path(self.root, 'Cargo.toml'))
        self.assert_refused(self.run_detect('Cargo.toml'), 'unavailable')

    def test_oversized_manifest_fail_closed(self):
        self.put('package.json', b' ' * (qd.MAX_FILE_BYTES + 1))
        self.assert_refused(self.run_detect('package.json'), 'unavailable')

    def test_excessive_allowlist_rejected_without_read(self):
        paths = [f'x{i}/package.json' for i in range(qd.MAX_PATHS + 1)]
        self.assert_refused(self.run_detect(*paths), 'invalid_input')

    def test_stale_pin_no_scan(self):
        pin = self.pin()
        r = self.run_detect('package.json', pin=pin,
                            now=FIXED + timedelta(seconds=qd.MAX_PIN_AGE+1))
        self.assert_refused(r, 'unavailable')
        self.assertEqual(r['reason_code'], 'QUALITYDETECT_PIN_NOT_FRESH')

    def test_future_pin_no_scan(self):
        pin = self.pin()
        r = self.run_detect('package.json', pin=pin,
                            now=FIXED - timedelta(seconds=qd.MAX_CLOCK_SKEW+1))
        self.assert_refused(r, 'unavailable')

    def test_pin_replaced_root(self):
        pin = self.pin()
        os.rename(self.root, self.root + '-old')
        os.mkdir(self.root)
        r = self.run_detect('Cargo.toml', pin=pin)
        self.assert_refused(r, 'unavailable')
        self.assertEqual(r['reason_code'], 'QUALITYDETECT_PINNED_ROOT_DRIFT')

    def test_pin_modified_root(self):
        pin = self.pin()
        self.put('new-file', 'data')
        # A create in the same filesystem timestamp tick can leave both root
        # timestamps unchanged. Ensure this fixture actually changes the pinned
        # metadata; keep the production drift check and refusal assertion intact.
        observed = os.stat(self.root)
        os.utime(self.root, ns=(observed.st_atime_ns,
                               pin['root_identity']['mtime_ns'] + 1_000_000_000))
        self.assert_refused(self.run_detect('Cargo.toml', pin=pin), 'unavailable')

    def test_source_grant_is_independent(self):
        self.assert_refused(self.run_detect('package.json', grant_source=False), 'unavailable')

    def test_each_file_has_independent_grant(self):
        self.put('package.json', '{}')
        self.assert_refused(self.run_detect('package.json', grant_file=False), 'unavailable')

    def test_no_root_observation_permission(self):
        with self.assertRaises(qd.QualityError) as exc:
            qd.QualityDetector.observe_root(self.root,
                        authorize_observation=lambda _: False, clock=lambda: FIXED)
        self.assertEqual(exc.exception.code, 'QUALITYDETECT_ROOT_OBSERVATION_NOT_AUTHORIZED')

    def test_file_grant_explicit_reading_type(self):
        self.put('package.json', '{}')
        self.put('go.mod', 'module test')
        r = self.run_detect('go.mod', 'package.json')
        self.assertEqual(r['status'], 'partial')
        grants = [x for x in self.calls if x.get('purpose', '').startswith('QUALITYDETECT_READ_CONFIG_')]
        self.assertEqual([(g['path'], g['read_file_bytes']) for g in grants],
                         [('go.mod', False), ('package.json', True)])

    def test_callback_exception_is_denied(self):
        pin = self.pin()
        def explode(_):
            raise RuntimeError('ignored')
        r = qd.QualityDetector.detect(self.root, pin,
                        candidate_paths=['package.json'], authorize_source=explode,
                        authorize_path=lambda _: True, clock=lambda: FIXED)
        self.assert_refused(r, 'unavailable')

    def test_invalid_pin_shape(self):
        pin = self.pin()
        pin['source_mode'] = 'ProposedPR'
        self.assert_refused(self.run_detect('package.json', pin=pin), 'invalid_input')

    def test_mixed_input_must_refuse_all_no_partial_leak(self):
        self.put('package.json', '{"devDependencies":{"jest":"29"}}')
        self.put('Cargo.toml', b' ' * (qd.MAX_FILE_BYTES + 1))
        r = self.run_detect('package.json', 'Cargo.toml')
        self.assert_refused(r, 'unavailable')

    def test_cumulative_limit_with_nine_configs(self):
        # Different directory names avoid any allowlist collision.
        for i in range(9):
            self.put(f's{i}/package.json', '{}' + ' ' * (qd.MAX_FILE_BYTES - 2))
        r = self.run_detect(*(f's{i}/package.json' for i in range(9)))
        self.assert_refused(r, 'unavailable')
        self.assertEqual(r['reason_code'], 'QUALITYDETECT_CUMULATIVE_CONTENT_SIZE_EXCEEDED')

    def test_schema_accepts_real_results_and_refusals(self):
        if jsonschema is None:
            self.skipTest('jsonschema not installed; schema acceptance deferred')
        schema = json.loads((BASE/'references/quality-detect-result.v1.schema.json').read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        self.put('package.json', '{}')
        yes = self.run_detect('package.json')
        no = self.run_detect('README.md')
        validator.validate(yes)
        validator.validate(no)
        false_claim = json.loads(json.dumps(yes))
        false_claim['coverage']['commands_usable_verified'] = True
        self.assertRaises(jsonschema.ValidationError, validator.validate, false_claim)
        false_claim = json.loads(json.dumps(yes))
        false_claim['tools'] = [{'tool_family': 'pytest', 'role': 'test', 'evidence_paths': ['package.json'],
                                 'discovery_state': 'CONFIG_DECLARATION_ONLY',
                                 'installed': 'VERIFIED', 'command_usable': 'NOT_CHECKED', 'executed': False}]
        self.assertRaises(jsonschema.ValidationError, validator.validate, false_claim)

    def test_cli_denies_without_its_independent_flags(self):
        process = subprocess.run([sys.executable, str(BASE/'construction/quality_detect.py'),
            '--repo-root', self.root, '--path', 'package.json', '--json'],
            capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(process.returncode, 5)
        r = json.loads(process.stdout)
        self.assert_refused(r, 'unavailable')
        self.assertEqual(r['reason_code'], 'QUALITYDETECT_ROOT_OBSERVATION_NOT_AUTHORIZED')


if __name__ == '__main__':
    unittest.main()
