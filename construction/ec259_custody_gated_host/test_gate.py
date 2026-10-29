#!/usr/bin/env python3
"""EC259 local real Git + real EC253 HMAC gate tests (NO live OCI)."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec258_git_tar_custody import test_custody as git_fixture
from ec258_git_tar_custody import custody as c
from ec253_lease_host import test_broker as signed_fixture
from ec253_lease_host import broker as lease
from ec259_custody_gated_host import gate as gated
from ec259_custody_gated_host import serve


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     os.path.isfile('/usr/bin/git'), 'requires nonroot Linux + Git')
class PinnedGitGateTests(unittest.TestCase):
    def setUp(self):
        old_umask = os.umask(0o077)
        self.addCleanup(os.umask, old_umask)
        self.gitfx = git_fixture.RealGitTests('test_real_cli_prepare_and_verify_exit_partial')
        self.gitfx.setUp()
        self.addCleanup(self.gitfx.doCleanups)
        self.gitfx.prepare()
        self.fix = signed_fixture.LeaseHostTests('test_private_policy_and_original_catalog_valid')
        self.fix.setUp()
        self.addCleanup(self.fix.doCleanups)
        self.fix.policy['source_tar_path'] = str(self.gitfx.output / 'source.tar')
        self.fix.policy['expected_source_tar_sha256'] = c._sha(
            (self.gitfx.output / 'source.tar').read_bytes())
        self.fix.write_policy()
        self.gate = self.make_gate()

    def make_gate(self, **overrides):
        paths = {'policy_path': str(self.fix.policy_path),
                 'repo': str(self.gitfx.repo),
                 'allowlist_path': str(self.gitfx.allowpath),
                 'receipt_path': str(self.gitfx.output / 'source.custody.json'),
                 'profile_id': 'python.pytest'}
        paths.update(overrides)
        return gated.OperatorCustodyGate(**paths)

    def policy(self):
        return lease._policy(str(self.fix.policy_path))

    def startup(self):
        pol, sha = self.policy()
        self.gate.startup(pol, sha)
        return pol, sha

    def before(self, profile='python.pytest'):
        pol, sha = self.policy()
        self.gate.before_begin(pol, sha, {'profile_id': profile})

    def reject(self, code, action):
        with self.assertRaises(gated.CustodyGateError) as err:
            action()
        self.assertEqual(err.exception.code, code)

    def test_01_startup_arms_only_operator_local_partial_receipt(self):
        pol, sha = self.startup()
        self.assertEqual(sha, self.gate._policy_sha)
        r = self.gate.probe_result()
        self.assertEqual(r['source_tar_sha256'], pol['expected_source_tar_sha256'])
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['exit_code'], 2)
        self.assertFalse(r['strict_ec257_host_live_verified'])
        self.assertFalse(r['overall_quality_pass_verified'])
        self.before()

    def test_02_begin_without_prior_startup_is_denied(self):
        self.reject('EC259_STARTUP_NOT_ARMED', self.before)
        self.reject('EC259_STARTUP_NOT_ARMED', self.gate.probe_result)

    def test_03_different_profile_cannot_use_operator_approved_custody(self):
        self.startup()
        self.reject('EC259_UNAPPROVED_PROFILE', lambda: self.before('python.ruff'))

    def test_04_rearming_same_gate_is_denied(self):
        pol, sha = self.startup()
        self.reject('EC259_STARTUP_ALREADY_ARMED', lambda: self.gate.startup(pol, sha))

    def test_05_tar_changed_after_startup_blocks_begin(self):
        self.startup()
        tar = self.gitfx.output / 'source.tar'
        tar.write_bytes(tar.read_bytes().replace(b'fixed commit', b'other commit'))
        self.reject('EC259_CUSTODY_TAR_NOT_GIT_CONTENT', self.before)

    def test_06_receipt_changed_after_startup_blocks_begin(self):
        self.startup()
        p = self.gitfx.output / 'source.custody.json'
        receipt = json.loads(p.read_text())
        receipt['quality_pass_verified'] = True
        p.write_bytes(c._canonical(receipt))
        self.reject('EC259_CUSTODY_RECEIPT_NOT_GIT_CONTENT', self.before)

    def test_07_approval_changed_after_startup_blocks_begin(self):
        self.startup()
        self.gitfx.allow['source_paths'] = ['pytest.ini']
        self.gitfx.write_approval()
        self.reject('EC259_CUSTODY_TAR_NOT_GIT_CONTENT', self.before)

    def test_08_repo_replaced_after_startup_blocks_begin(self):
        self.startup()
        self.gitfx.git('commit', '--allow-empty', '-q', '-m', 'unselected new HEAD')
        # Approved full commit still works despite changing mutable HEAD.
        self.before()
        self.gitfx.allow['commit_oid'] = self.gitfx.git('rev-parse', 'HEAD').strip()
        self.gitfx.write_approval()
        self.reject('EC259_CUSTODY_RECEIPT_NOT_GIT_CONTENT', self.before)

    def test_09_signed_ticket_mac_revoked_after_startup_blocks_begin(self):
        self.startup()
        signed_fixture.store(self.fix.approval_key_path, b'Z' * 64)
        self.reject('EC259_CUSTODY_EC253_SIGNED_BINDING_UNAVAILABLE', self.before)

    def test_10_changed_original_ec253_policy_denied_after_startup(self):
        self.startup()
        self.fix.policy['grants'][0]['allow_output_text'] = True
        self.fix.write_policy()
        self.reject('EC259_POLICY_PIN_CHANGED', self.before)

    def test_11_unknown_local_git_profile_fails_before_ticket_resolution(self):
        self.gate = self.make_gate(profile_id='invalid.profile')
        pol, sha = self.policy()
        self.reject('EC259_PROFILE_NOT_BUILTIN', lambda: self.gate.startup(pol, sha))

    def test_12_unreadable_local_receipt_blocks_startup(self):
        (self.gitfx.output / 'source.custody.json').unlink()
        pol, sha = self.policy()
        self.reject('EC259_CUSTODY_PRIVATE_FILE_REQUIRED',
                    lambda: self.gate.startup(pol, sha))
        self.assertIsNone(self.gate._policy_sha)

    def test_13_operator_probe_cli_is_partial_and_never_host_ready(self):
        script = Path(serve.__file__)
        args = [sys.executable, '-I', '-B', str(script), 'probe',
                '--repo', str(self.gitfx.repo), '--allowlist', str(self.gitfx.allowpath),
                '--receipt', str(self.gitfx.output / 'source.custody.json'),
                '--policy', str(self.fix.policy_path), '--profile-id', 'python.pytest']
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2, result.stderr or result.stdout)
        out = json.loads(result.stdout)
        self.assertEqual(out['status'], 'partial')
        self.assertFalse(out['strict_ec257_host_live_verified'])
        self.assertFalse(out['independent_git_origin_attested'])

    def test_14_probe_cli_bad_approval_is_unavailable_without_false_pass(self):
        script = Path(serve.__file__)
        self.gitfx.allow['source_paths'] = ['pytest.ini']
        self.gitfx.write_approval()
        args = [sys.executable, '-I', '-B', str(script), 'probe',
                '--repo', str(self.gitfx.repo), '--allowlist', str(self.gitfx.allowpath),
                '--receipt', str(self.gitfx.output / 'source.custody.json'),
                '--policy', str(self.fix.policy_path), '--profile-id', 'python.pytest']
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 5, result.stderr)
        out = json.loads(result.stdout)
        self.assertEqual(out['status'], 'unavailable')
        self.assertEqual(out['reason_code'], 'EC259_CUSTODY_TAR_NOT_GIT_CONTENT')
        self.assertFalse(out['overall_quality_pass_verified'])

    def test_15_policy_sha_and_original_ticket_remain_unmodified(self):
        old_policy = self.fix.policy_path.read_bytes()
        old_ticket = self.fix.approval_path.read_bytes()
        self.startup()
        self.before()
        self.assertEqual(old_policy, self.fix.policy_path.read_bytes())
        self.assertEqual(old_ticket, self.fix.approval_path.read_bytes())


if __name__ == '__main__':
    unittest.main(verbosity=2)
