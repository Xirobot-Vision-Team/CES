"""Small offline EC248 tests; no PowerShell, repo write or E63-E66 claim."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import importlib.util
here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ec248_guarded_sequence', here / 'guarded_sequence.py')
gs = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gs
spec.loader.exec_module(gs)

ID1 = 'ci-' + 'a' * 64
ID2 = 'ci-' + 'b' * 64


def request(**options):
    baseline = dict(repo_path='/tmp/ec248 synthetic repo', record_ids=ID1 + ',' + ID2, top=10)
    baseline.update({key: None for key, _ in gs.SELECTORS})
    baseline.update(options)
    return argparse.Namespace(**baseline)


class PinnedSourceTests(unittest.TestCase):
    def test_unmodified_source_profile_and_lazy_assessment(self):
        r = gs.source_profile()
        self.assertEqual((r['unconditional_imports'], r['k_modules'], r['explicit_parent_replay_edges']), (124, 56, 19))
        self.assertGreater(r['import_plus_cli_source_bytes'], 6_000_000)
        self.assertEqual(r['lazy_loading'], 'ASSESS_ONLY_NOT_ENABLED')

    def test_source_drift_fails_closed_before_native(self):
        actual = gs._sha
        def one_changed(path):
            if path.name == 'codesequence.ps1':
                return '0' * 64
            return actual(path)
        with mock.patch.object(gs, '_sha', side_effect=one_changed):
            with self.assertRaises(gs.GuardError) as ctx:
                gs.source_profile()
        self.assertEqual(ctx.exception.code, 'GUARD_SOURCE_DRIFT')

    def test_frozen_original_bytes_match_ec244_source_lock(self):
        pins = json.loads(gs.LOCK.read_text('utf-8'))['source_sha256']
        for key in ('scripts/ces.ps1', 'scripts/codeshow.ps1', 'scripts/codesequence.ps1', 'tests/CodeSequence.Smoke.ps1'):
            self.assertEqual(gs._sha(gs.ROOT / key), pins[key])


class SelectorTests(unittest.TestCase):
    def test_supported_selector_forwarding_preserves_order_and_legacy_params(self):
        ns = request(sequence_pair_overview_index='2', sequence_pair_path_index='1', sequence_pair_path_anchor_index='4',
                     sequence_pair_path_anchor_finding_side='left', sequence_pair_path_anchor_finding_index='3',
                     sequence_pair_path_anchor_finding_counterpart_index='2')
        gs.validate_request(ns)
        cmd = gs.build_command(ns, '/usr/bin/pwsh')
        self.assertEqual(cmd[:5], ['/usr/bin/pwsh', '-NoProfile', '-NonInteractive', '-File', str(gs.CLI)])
        self.assertEqual(cmd[-1], '-Json')
        self.assertEqual(cmd.count('-Action'), 1)
        self.assertIn('-SequencePairPathAnchorFindingCounterpartIndex', cmd)
        self.assertEqual(cmd[cmd.index('-SequenceRecordIds') + 1], ID1 + ',' + ID2)
        self.assertFalse(any(x in cmd for x in ('-ApprovePersist', '-InputPath', '-EvidencePath', '-IncludePatches')))

    def test_source_matches_every_forwarded_param_name(self):
        source = gs.CLI.read_text('utf-8')
        for _, param in gs.SELECTORS:
            self.assertIn('$' + param, source)

    def test_invalid_ids_and_top_and_ordinals_rejected(self):
        for bad in (ID1 + ',' + ID1, ID1.upper() + ',' + ID2, ID1 + ', ' + ID2, ID1, ID1 + ',' + ID2 + ','):
            with self.subTest(bad=bad[-10:]):
                with self.assertRaises(gs.GuardError):
                    gs.validate_request(request(record_ids=bad))
        for bad in (0, 21):
            with self.assertRaises(gs.GuardError):
                gs.validate_request(request(top=bad))
        for bad in ('0', '01', '481', '9999'):
            with self.assertRaises(gs.GuardError):
                gs.validate_request(request(sequence_pair_path_anchor_index=bad))
        with self.assertRaises(gs.GuardError):
            gs.validate_request(request(repo_path='relative_repo'))

    def test_valid_legacy_focus_path_preserves_literal(self):
        ns = request(sequence_path='src/a b[0].ps1', sequence_finding_record_id=ID2,
                     sequence_finding_id='F_12')
        gs.validate_request(ns)
        c = gs.build_command(ns, '/usr/bin/pwsh')
        self.assertEqual(c[c.index('-SequencePath')+1], 'src/a b[0].ps1')

    def test_limits_are_explicit_and_bounded(self):
        gs.Limits().check()
        for kwargs in ({'wall_seconds': 0}, {'cpu_seconds': 901}, {'virtual_memory_mib': 100}, {'output_mib': 17}):
            with self.assertRaises(gs.GuardError):
                gs.Limits(**kwargs).check()


class ProcessTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'POSIX resources only')
    def test_real_bounded_child_keeps_raw_bytes(self):
        content = json.dumps({'schema_version':'ces.cli.v1', 'action':'CodeShow', 'status':'partial', 'reason_code':'SOURCE_MISMATCH'}, separators=(',', ':')).encode()
        child = "import sys;sys.stdout.buffer.write(" + repr(content) + ")"
        out, err, code = gs.run_bounded([sys.executable, '-I', '-c', child], gs.Limits(5,5,8192,1))
        self.assertEqual((out,err,code), (content,b'',0))
        # Native 'partial' cannot be made success by the guard on a zero exit.
        with self.assertRaises(gs.GuardError) as ctx:
            gs.validate_native_result(out, code)
        self.assertEqual(ctx.exception.code, 'GUARD_NATIVE_RESPONSE_INCONSISTENT')
        gs.validate_native_result(out, 2)

    @unittest.skipUnless(os.name == 'posix', 'POSIX resources only')
    def test_live_output_limit_without_disk_spool(self):
        child = "import sys;sys.stdout.buffer.write(b'Q'*1200000);sys.stdout.flush()"
        with self.assertRaises(gs.GuardError) as ctx:
            gs.run_bounded([sys.executable,'-I','-c',child], gs.Limits(5,5,8192,1))
        self.assertEqual(ctx.exception.code, 'GUARD_OUTPUT_LIMIT')

    @unittest.skipUnless(os.name == 'posix', 'POSIX resources only')
    def test_live_wall_timeout_terminates_worker(self):
        with self.assertRaises(gs.GuardError) as ctx:
            gs.run_bounded([sys.executable,'-I','-c','import time;time.sleep(30)'], gs.Limits(.4,5,8192,1))
        self.assertEqual(ctx.exception.code, 'GUARD_WALL_TIMEOUT')

    @unittest.skipUnless(os.name == 'posix', 'POSIX resources only')
    def test_real_child_cpu_and_virtual_memory_rlimits(self):
        child = "import json,resource;print(json.dumps({'cpu':resource.getrlimit(resource.RLIMIT_CPU)[0],'as':resource.getrlimit(resource.RLIMIT_AS)[0]}))"
        out, _, code = gs.run_bounded([sys.executable,'-I','-c',child], gs.Limits(5,9,2048,1))
        limits = json.loads(out)
        self.assertEqual((code, limits['cpu'], limits['as']), (0,9,2048*1024*1024))

    def test_main_success_forwards_original_native_json_without_wrapping(self):
        payload = b'{"schema_version":"ces.cli.v1","action":"CodeShow","status":"success","reason_code":"CODE_SHOW_SEQUENCE_OK","data":{"k":56}}'
        output_bytes = io.BytesIO()
        writer = io.TextIOWrapper(output_bytes, encoding='utf-8', write_through=True)
        with mock.patch.object(gs.shutil, 'which', return_value='/opt/pwsh'), \
             mock.patch.object(gs, 'run_bounded', return_value=(payload, b'', 0)) as bounded, \
             mock.patch.object(gs.sys, 'stdout', writer):
            exit_status = gs.main(['--repo-path', '/tmp/example', '--record-ids', ID1+','+ID2])
        self.assertEqual(exit_status,0)
        self.assertEqual(output_bytes.getvalue(), payload+b'\n')
        self.assertEqual(bounded.call_args[0][0][bounded.call_args[0][0].index('-Action')+1], 'CodeShow')

    def test_bogus_native_json_or_status_never_forwarded(self):
        for payload, code in ((b'{}',0), (b'{"status":"success"}',0),
                              (b'NOT JSON',4), (b'{"schema_version":"ces.cli.v1","action":"CodeShow","status":"success","reason_code":"OK"}',5)):
            with self.assertRaises(gs.GuardError):
                gs.validate_native_result(payload, code)

    def test_plan_does_not_spawn_native_or_echo_repo(self):
        with mock.patch.object(gs, 'run_bounded', side_effect=AssertionError('no spawn')):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(gs.main(['--plan', '--repo-path', '/private/secret/repo']), 0)
        observed = json.loads(output.getvalue())
        self.assertEqual(observed['k_modules'], 56)
        self.assertNotIn('/private', output.getvalue())

    def test_missing_pwsh_fails_closed_and_no_path_leak(self):
        with mock.patch.object(gs.shutil, 'which', return_value=None):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(gs.main(['--repo-path','/personal/path','--record-ids',ID1+','+ID2]), 5)
        observed = json.loads(output.getvalue())
        self.assertEqual(observed['reason_code'], 'GUARD_PWSH_MISSING')
        self.assertFalse(observed['native_executed'])
        self.assertNotIn('/personal', output.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
