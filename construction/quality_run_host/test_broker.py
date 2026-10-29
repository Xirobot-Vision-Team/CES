#!/usr/bin/env python3
"""EC252 local focused tests, not a production OCI/CI acceptance run.

Run under a NON-ROOT Linux UID with owner-private /tmp, e.g.
runuser -u nobody -- python3 -B construction/quality_run_host/test_broker.py
Tests use the actual parser, private files, tar extraction, UNIX IPC, bounded
child process controls, and a clearly mocked Podman control-plane; this host
cannot execute real Podman containers.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import broker as b


def archive(files: dict[str, bytes] | None = None,
            *, special: tuple[str, bytes, int] | None = None) -> bytes:
    buff = io.BytesIO()
    with tarfile.open(fileobj=buff, mode='w:') as tf:
        for name, data in (files or {'tests/test_smoke.py': b'def test_one():\n    assert 1\n'}).items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            tf.addfile(item, io.BytesIO(data))
        if special is not None:
            name, data, kind = special
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            tf.addfile(item, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return buff.getvalue()


def stored(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)
    path.chmod(0o600)


def js(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('ascii')


class QualityRunHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ec252-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.private = self.base / 'private'
        self.private.mkdir(mode=0o700)
        self.scratch = self.base / 'scratch'
        self.scratch.mkdir(mode=0o700)
        self.home = self.base / 'home'
        self.home.mkdir(mode=0o700)
        self.xdg = self.base / 'xdg'
        self.xdg.mkdir(mode=0o700)
        self.sock_dir = self.base / 'socket'
        self.sock_dir.mkdir(mode=0o700)
        self.tarfile = self.private / 'snapshot.tar'
        self.tar = archive()
        stored(self.tarfile, self.tar)
        self.policy_path = self.private / 'policy.json'
        self.req_path = self.private / 'request.json'
        self.request = {'schema': b.REQUEST_SCHEMA, 'scope_id': 'team-small',
                        'profile_id': 'python.pytest'}
        self.policy = {
            'schema': b.POLICY_SCHEMA,
            'source_tar_path': str(self.tarfile),
            'expected_source_tar_sha256': hashlib.sha256(self.tar).hexdigest(),
            'scratch_root': str(self.scratch),
            'runtime_path': '/usr/bin/podman',
            'expected_runtime_sha256': 'a' * 64,
            'runtime_home': str(self.home),
            'runtime_xdg_dir': str(self.xdg),
            'image_id': 'sha256:' + 'b' * 64,
            'expected_ec186_catalog_sha256':
                b.guard.catalog_entry('python.pytest')['catalog_sha256'],
            'grants': [{'uid': os.geteuid(), 'scope_id': 'team-small',
                        'profile_ids': ['python.pytest', 'python.ruff'],
                        'allow_output_text': False}],
        }
        self._write()
        self.assertNotEqual(os.geteuid(), 0,
                            'Run as nonroot, exactly as production service requires')

    def _write(self):
        stored(self.policy_path, js(self.policy))
        stored(self.req_path, js(self.request))

    def _execute(self, uid=None, raw=None):
        return b.execute(raw or js(self.request), str(self.policy_path),
                         uid if uid is not None else os.geteuid())

    def _fake_engine(self, *, exit_code=0, oom=False, cleaned=True,
                     on_inspect=None):
        events = []

        def fake(pol, args, **_kw):
            events.append(args)
            action = args[0]
            if action == 'create':
                return b.CommandResult(0, (b'a' * 64) + b'\n', b'', '', '', 65)
            if action == 'start':
                return b.CommandResult(exit_code, b'test result\n', b'',
                                       hashlib.sha256(b'test result\n').hexdigest(),
                                       hashlib.sha256(b'').hexdigest(), 12)
            if action == 'inspect':
                if on_inspect:
                    on_inspect()
                state = {'Running': False, 'StartedAt': '2026-10-24T10:00:00Z',
                         'ExitCode': exit_code, 'OOMKilled': oom}
                return b.CommandResult(0, js(state), b'', '', '', len(js(state)))
            if action == 'rm':
                return b.CommandResult(0, b'', b'', '', '', 0)
            if action == 'container':
                return b.CommandResult(1 if cleaned else 0, b'', b'', '', '', 0)
            raise AssertionError('Unexpected Podman command: %r' % args)
        return events, fake

    def _with_mock_engine(self, fake, callback):
        with mock.patch.object(b, '_runtime_ready', return_value=None), \
             mock.patch.object(b, '_run_command', side_effect=fake):
            return callback()

    def test_exact_private_policy_and_archive(self):
        self.assertEqual(b._policy(str(self.policy_path))[0], self.policy)
        self.assertEqual(b._source_archive(self.policy), self.tar)
        self.assertEqual(b._private_dir(str(self.scratch)), str(self.scratch))

    def test_request_does_not_choose_program_roots_or_extra_flags(self):
        for patch in ({'argv': ['/bin/sh']}, {'source_tar_path': '/tmp/other'},
                      {'allow_output_text': True}, {'image_id': 'latest'},
                      {'profile_id': 'whatever'}):
            raw = js(dict(self.request, **patch))
            result = self._execute(raw=raw)
            self.assertEqual(result['status'], 'invalid_input')
            self.assertIsNone(result['result'])

    def test_wrong_uid_and_permission_scope(self):
        self.assertEqual(self._execute(uid=os.geteuid() + 1)['status'],
                         'permission_denied')
        self.request['scope_id'] = 'other-scope'
        self.assertEqual(self._execute()['status'], 'permission_denied')

    def test_unauthorised_profile(self):
        self.policy['grants'][0]['profile_ids'] = ['python.ruff']
        self._write()
        self.assertEqual(self._execute()['status'], 'permission_denied')

    def test_duplicate_json_and_unknown_fields(self):
        raw = (b'{"schema":"' + b.REQUEST_SCHEMA.encode() +
               b'","scope_id":"team-small","scope_id":"team-small",'
               b'"profile_id":"python.pytest"}')
        self.assertEqual(self._execute(raw=raw)['status'], 'invalid_input')
        self.policy['unexpected'] = True
        self._write()
        self.assertEqual(self._execute()['status'], 'unavailable')

    def test_changed_source_archive_refused_before_runtime(self):
        stored(self.tarfile, self.tar + b'x')
        self.assertEqual(self._execute()['reason_code'],
                         'RUN_HOST_SOURCE_TAR_PIN_MISMATCH')

    def test_source_symlink_and_hardlink_refused(self):
        self.tarfile.unlink()
        os.symlink(self.req_path, self.tarfile)
        self.assertEqual(self._execute()['status'], 'unavailable')
        self.tarfile.unlink()
        os.link(self.req_path, self.tarfile)
        self.assertEqual(self._execute()['status'], 'unavailable')

    def test_policy_mutable_parent_and_public_mode_denied(self):
        self.policy_path.chmod(0o644)
        self.assertEqual(self._execute()['status'], 'unavailable')
        self.policy_path.chmod(0o600)
        self.private.chmod(0o777)
        self.addCleanup(self.private.chmod, 0o700)
        self.assertEqual(self._execute()['status'], 'unavailable')

    def test_policy_catalog_pin_and_duplicate_scope(self):
        self.policy['expected_ec186_catalog_sha256'] = 'f' * 64
        self._write()
        self.assertEqual(self._execute()['status'], 'unavailable')
        self.policy['expected_ec186_catalog_sha256'] = (
            b.guard.catalog_entry('python.pytest')['catalog_sha256'])
        self.policy['grants'].append(dict(self.policy['grants'][0]))
        self._write()
        self.assertEqual(self._execute()['status'], 'unavailable')

    def test_image_must_be_id_not_mutable_tag(self):
        self.policy['image_id'] = 'python:latest'
        self._write()
        self.assertEqual(self._execute()['status'], 'unavailable')

    def test_snapshot_extract_real_bytes_and_read_only(self):
        stage = self.base / 'stage'
        stage.mkdir(mode=0o700)
        n, size = b._extract_source(self.tar, str(stage))
        self.assertEqual(n, 1)
        self.assertEqual(size, len(b'def test_one():\n    assert 1\n'))
        target = stage / 'tests' / 'test_smoke.py'
        self.assertIn(b'assert 1', target.read_bytes())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o555)
        stage.chmod(0o700)
        (stage / 'tests').chmod(0o700)

    def test_snapshot_rejects_traversal_and_links(self):
        for raw in (archive({'../../escape': b'x'}),
                    archive({'/absolute': b'x'}),
                    archive({'a/.git/config': b'x'}),
                    archive({'a/.env': b'x'}),
                    archive(special=('link', b'', tarfile.SYMTYPE)),
                    archive(special=('hardlink', b'', tarfile.LNKTYPE))):
            with self.subTest(raw=hashlib.sha256(raw).hexdigest()[:8]):
                root = self.base / ('extract' + str(time.monotonic_ns()))
                root.mkdir()
                with self.assertRaises(b.HostRunError):
                    b._extract_source(raw, str(root))

    def test_fixed_profile_really_reuses_original_catalog(self):
        pytest_args = b._profile_arguments('python.pytest')
        self.assertEqual(pytest_args, ['-I', '-B', '-m', 'pytest',
                                       '-q', '-p', 'no:cacheprovider'])
        ruff_args = b._profile_arguments('python.ruff')
        self.assertEqual(ruff_args[-4:], ['-m', 'ruff', 'check', '.', '--no-cache'][-4:])
        cmd = b._create_args(self.policy, str(self.scratch), 'ces-ec252-test',
                             'python.pytest')
        for flag in ('--read-only', '--network=none', '--userns=auto',
                     '--cap-drop=all', '--security-opt=no-new-privileges',
                     '--pids-limit=32', '--memory=256m', '--pull=never'):
            self.assertIn(flag, cmd)
        self.assertEqual(cmd[-len(pytest_args):], pytest_args)
        self.assertNotIn('/bin/sh', cmd)

    def test_real_bounded_child_output(self):
        result = b._child_command(['/usr/bin/python3', '-c',
                                   'print("hello")'], env={'PATH': '/usr/bin:/bin'},
                                  timeout=3, output_limit=2048)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, b'hello\n')
        self.assertEqual(result.total_output, 6)

    def test_real_bounded_child_output_limit_and_wall(self):
        with self.assertRaisesRegex(b.HostRunError, 'OUTPUT_BUDGET'):
            b._child_command(['/usr/bin/python3', '-c',
                              'import os; os.write(1,b"x"*100000)'],
                             env={'PATH': '/usr/bin:/bin'},
                             timeout=3, output_limit=4096)
        with self.assertRaisesRegex(b.HostRunError, 'WALL_BUDGET'):
            b._child_command(['/usr/bin/python3', '-c', 'import time; time.sleep(4)'],
                             env={'PATH': '/usr/bin:/bin'}, timeout=0.2,
                             output_limit=4096)

    def test_actual_client_disconnection_stops_child(self):
        peer, client = socket.socketpair()
        client.close()
        try:
            with self.assertRaisesRegex(b.HostRunError, 'CLIENT_DISCONNECTED'):
                b._child_command(['/usr/bin/python3', '-c',
                                  'import time; time.sleep(4)'],
                                 env={'PATH': '/usr/bin:/bin'}, timeout=2,
                                 output_limit=4096, caller=peer)
        finally:
            peer.close()

    def test_run_mocked_oci_control_plane_is_partial_and_cleans(self):
        events, fake = self._fake_engine()
        result = self._with_mock_engine(fake, self._execute)
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(result['overall_quality_pass_verified'])
        self.assertEqual(result['result']['local_test_outcome'], 'exit_zero')
        self.assertIsNone(result['result']['captured_stdout'])
        self.assertEqual([x[0] for x in events],
                         ['create', 'start', 'inspect', 'rm', 'container'])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_local_container_nonzero_not_business_pass(self):
        events, fake = self._fake_engine(exit_code=1)
        result = self._with_mock_engine(fake, self._execute)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['result']['local_test_outcome'], 'nonzero')
        self.assertFalse(result['result']['overall_quality_pass_verified'])

    def test_output_is_only_granted_by_private_policy(self):
        self.policy['grants'][0]['allow_output_text'] = True
        self._write()
        _events, fake = self._fake_engine()
        result = self._with_mock_engine(fake, self._execute)
        self.assertEqual(result['result']['captured_stdout'], 'test result\n')

    def test_oom_is_not_a_verified_execution_result(self):
        events, fake = self._fake_engine(oom=True)
        result = self._with_mock_engine(fake, self._execute)
        self.assertEqual(result['status'], 'unavailable')
        self.assertIsNone(result['result'])
        self.assertEqual(events[-2][0], 'rm')

    def test_revocation_while_running_refuses_and_cleans(self):
        def revoke():
            if not hasattr(revoke, 'done'):
                revoke.done = True
                self.policy['grants'][0]['profile_ids'] = ['python.ruff']
                self._write()
        events, fake = self._fake_engine(on_inspect=revoke)
        result = self._with_mock_engine(fake, self._execute)
        self.assertEqual(result['status'], 'unavailable')
        self.assertIsNone(result['result'])
        self.assertEqual(events[-2][0], 'rm')

    def test_container_cleanup_uncertain_never_returns_pass(self):
        events, fake = self._fake_engine(cleaned=False)
        result = self._with_mock_engine(fake, self._execute)
        self.assertEqual(result['reason_code'],
                         'RUN_HOST_CONTAINER_OR_STAGE_CLEANUP_UNCONFIRMED')
        self.assertEqual(result['status'], 'unavailable')
        for stage in self.scratch.iterdir():
            for root, dirs, _ in os.walk(stage):
                os.chmod(root, 0o700)
            shutil.rmtree(stage)

    def test_no_podman_means_no_host_execution(self):
        result = self._execute()
        self.assertEqual(result['status'], 'unavailable')
        self.assertFalse(result['overall_quality_pass_verified'])
        self.assertIsNone(result['result'])

    def test_real_unix_socket_kernel_uid_and_contract(self):
        socket_path = str(self.sock_dir / 'run.sock')
        failure = []
        def server():
            try:
                b.serve(str(self.policy_path), socket_path, max_requests=1,
                        accept_timeout=2)
            except Exception as exc:
                failure.append(exc)
        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        for _ in range(100):
            if os.path.exists(socket_path):
                break
            time.sleep(0.01)
        self.assertTrue(os.path.exists(socket_path))
        reply = b.request(socket_path, str(self.req_path), os.geteuid())
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertFalse(failure, str(failure))
        self.assertTrue(reply['kernel_peer_uid_checked'])
        self.assertEqual(reply['status'], 'unavailable')  # no real Podman installed
        self.assertFalse(reply['ci_run_independently_verified'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
