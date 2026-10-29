#!/usr/bin/env python3
"""EC253 local contract / durable-journal / watchdog-focused developer fixtures.

Run under a non-root Linux account. All OCI calls are explicitly mocked;
there is no Podman or CI attestation in this development environment.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
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


APPROVAL_KEY = b'ec253-private-operator-approval' + b'A' * 32
LEASE_KEY = b'ec253-private-other-broker-key' + b'B' * 32


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def store(path, contents):
    Path(path).write_bytes(contents)
    Path(path).chmod(0o600)


def source_archive():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:') as tar:
        data = b'def test_ok():\n    assert True\n'
        info = tarfile.TarInfo('tests/test_ok.py')
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def sign(obj, key, domain):
    return {**obj, 'mac_sha256': hmac.new(key, domain + b.guard._canonical(obj),
                                       hashlib.sha256).hexdigest()}


class LeaseHostTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(), 0, 'Tests must run as nonroot')
        self.temp = tempfile.TemporaryDirectory(prefix='ec253-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for d in ('private', 'scratch', 'home', 'xdg', 'socket', 'ledger'):
            (self.root / d).mkdir(mode=0o700)
        self.private = self.root / 'private'
        self.policy_path = self.private / 'policy.json'
        self.approval_path = self.private / 'approval.json'
        self.lease_path = self.private / 'lease.json'
        self.approval_key_path = self.private / 'approval.key'
        self.lease_key_path = self.private / 'lease.key'
        self.source_path = self.private / 'source.tar'
        self.request_path = self.private / 'request.json'
        self.source = source_archive()
        store(self.source_path, self.source)
        store(self.approval_key_path, APPROVAL_KEY)
        store(self.lease_key_path, LEASE_KEY)
        self.pin = '8' * 64
        self.profile = 'python.pytest'
        self.policy = {
            'schema': b.POLICY_SCHEMA,
            'source_tar_path': str(self.source_path),
            'expected_source_tar_sha256': hashlib.sha256(self.source).hexdigest(),
            'scratch_root': str(self.root / 'scratch'),
            'runtime_path': '/usr/bin/podman',
            'expected_runtime_sha256': 'a' * 64,
            'runtime_home': str(self.root / 'home'),
            'runtime_xdg_dir': str(self.root / 'xdg'),
            'image_id': 'sha256:' + 'b' * 64,
            'expected_ec186_catalog_sha256': (
                b.guard.catalog_entry('python.pytest')['catalog_sha256']),
            'grants': [{'uid': os.geteuid(), 'scope_id': 'test-scope',
                        'profile_ids': ['python.pytest', 'python.ruff'],
                        'allow_output_text': False}],
            'authorized_source_pin_sha256': self.pin,
            'approval_ticket_path': str(self.approval_path),
            'isolation_ticket_path': str(self.lease_path),
            'approval_hmac_key_path': str(self.approval_key_path),
            'broker_hmac_key_path': str(self.lease_key_path),
            'ledger_root': str(self.root / 'ledger'),
        }
        self.req = {'schema': b.REQUEST_SCHEMA, 'scope_id': 'test-scope',
                    'profile_id': self.profile}
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.approval = None
        self.lease = None
        self.events = []
        self.make_tickets()
        self.write_policy()

    def write_policy(self):
        store(self.policy_path, encode(self.policy))
        store(self.request_path, encode(self.req))

    def make_tickets(self, ap_changes=None, lease_changes=None):
        def date(offset):
            return b.guard._stamp(self.now + timedelta(seconds=offset))
        entry = b.guard.catalog_entry(self.profile)
        approval = {
            'schema': b.guard.APPROVAL_SCHEMA,
            'ticket_id': 'approval-ec253-00001',
            'source_pin_sha256': self.pin,
            'profile_id': self.profile,
            'profile_sha256': entry['profile_sha256'],
            'approved_purpose': entry['profile']['purpose'],
            'issued_at_utc': date(-5),
            'expires_at_utc': date(100),
        }
        approval.update(ap_changes or {})
        self.approval = sign(approval, APPROVAL_KEY, b.guard.DOMAIN_APPROVAL)
        lease = {
            'schema': b.guard.LEASE_SCHEMA,
            'ticket_id': 'lease-ec253-0000001',
            'source_pin_sha256': self.pin,
            'profile_sha256': entry['profile_sha256'],
            'approval_receipt_sha256': b.guard._digest(
                b.guard.DOMAIN_RECEIPT, self.approval),
            'image_sha256': 'b' * 64,
            'controls': dict(b.guard.REQUIRED_CONTROLS),
            'issued_at_utc': date(-3),
            'expires_at_utc': date(90),
        }
        lease.update(lease_changes or {})
        self.lease = sign(lease, LEASE_KEY, b.guard.DOMAIN_LEASE)
        store(self.approval_path, encode(self.approval))
        store(self.lease_path, encode(self.lease))

    def _engine(self, *, status_code=0, cleaned=True, revoke=None):
        self.events = []
        state = {'created': False, 'removed': False, 'name': '', 'label': ''}
        identity = 'a' * 64
        def call(_pol, args, **_kw):
            self.events.append(args)
            if args[0] == 'create':
                state['created'] = True
                state['name'] = args[args.index('--name') + 1]
                state['label'] = next((x.split('=', 1)[1] for x in args
                                       if x.startswith('--label=io.ces.lease.sha256=')), '')
                # The command's label argument is a single --label=KEY=VALUE.
                state['label'] = state['label'].split('=', 1)[-1]
                return b.runner.CommandResult(0, (identity + '\n').encode(), b'', '', '', 65)
            if args[0] == 'ps':
                raw = ((identity + '\n').encode() if state['created'] and
                       not state['removed'] else b'')
                return b.runner.CommandResult(0, raw, b'', '', '', len(raw))
            if args[:2] == ['container', 'inspect']:
                raw = ('|'.join((identity, state['name'], state['label'],
                                 self.policy['image_id'][7:])) + '\n').encode()
                return b.runner.CommandResult(0, raw, b'', '', '', len(raw))
            if args[0] == 'start':
                return b.runner.CommandResult(status_code, b'ok\n', b'',
                    hashlib.sha256(b'ok\n').hexdigest(),
                    hashlib.sha256(b'').hexdigest(), 3)
            if args[0] == 'inspect':
                if revoke:
                    revoke()
                data = encode({'Running': False, 'StartedAt': '2026-10-24T09:00:00Z',
                               'ExitCode': status_code, 'OOMKilled': False})
                return b.runner.CommandResult(0, data, b'', '', '', len(data))
            if args[0] == 'rm':
                if cleaned:
                    state['removed'] = True
                return b.runner.CommandResult(0, b'', b'', '', '', 0)
            if args[:2] == ['container', 'exists']:
                return b.runner.CommandResult(
                    1 if state['removed'] or not state['created'] else 0,
                    b'', b'', '', '', 0)
            raise AssertionError(args)
        return call

    def execute(self, *, uid=None, raw=None, engine=None):
        policy, digest = b._policy(str(self.policy_path))
        with b.Ledger(policy, digest) as ledger:
            if engine is None:
                return b.execute(raw or encode(self.req), str(self.policy_path),
                                 uid if uid is not None else os.geteuid(), ledger)
            with mock.patch.object(b.runner, '_runtime_ready', return_value=None), \
                 mock.patch.object(b.runner, '_run_command', side_effect=engine), \
                 mock.patch.object(b, '_spawn_watchdog', return_value=987654), \
                 mock.patch.object(b, '_join_watchdog', return_value=True):
                return b.execute(raw or encode(self.req), str(self.policy_path),
                                 uid if uid is not None else os.geteuid(), ledger)

    def test_private_policy_and_original_catalog_valid(self):
        pol, digest = b._policy(str(self.policy_path))
        self.assertEqual(pol, self.policy)
        self.assertEqual(len(digest), 64)
        tickets = b._tickets(pol, self.profile)
        self.assertEqual(tickets['lease']['source_pin_sha256'], self.pin)

    def test_extra_request_fields_and_forced_program_denied(self):
        for value in ({'argv': ['/bin/bash']}, {'lease_ticket_id': 'foo'},
                      {'source_tar_path': '/tmp/other'}, {'profile_id': 'python.evil'}):
            r = self.execute(raw=encode(dict(self.req, **value)))
            self.assertEqual(r['status'], 'invalid_input')
            self.assertFalse(r['durable_one_use_lease_reserved'])

    def test_wrong_kernel_uid_and_scope_deny_before_tickets(self):
        r = self.execute(uid=os.geteuid() + 1)
        self.assertEqual(r['status'], 'permission_denied')
        self.assertFalse(r['ec186_signed_tickets_verified'])

    def test_duplicate_json_key_denied(self):
        r = self.execute(raw=(b'{"schema":"' + b.REQUEST_SCHEMA.encode() +
                        b'","scope_id":"test-scope","scope_id":"test-scope",'
                        b'"profile_id":"python.pytest"}'))
        self.assertEqual(r['status'], 'invalid_input')

    def test_unsigned_or_tampered_approval_fails(self):
        obj = dict(self.approval, approved_purpose='RUN_USER_SHELL')
        store(self.approval_path, encode(obj))
        r = self.execute(engine=self._engine())
        self.assertEqual(r['status'], 'unavailable')
        self.assertFalse(r['durable_one_use_lease_reserved'])
        self.assertEqual(self.events, [])

    def test_lease_mac_and_approval_receipt_both_verified(self):
        obj = dict(self.lease, image_sha256='c' * 64)
        store(self.lease_path, encode(obj))
        self.assertEqual(self.execute()['status'], 'unavailable')
        self.make_tickets(lease_changes={'approval_receipt_sha256': 'f' * 64})
        self.assertEqual(self.execute()['status'], 'unavailable')

    def test_separate_keys_required(self):
        store(self.lease_key_path, APPROVAL_KEY)
        self.assertEqual(self.execute()['status'], 'unavailable')

    def test_host_declared_source_pin_binding_required(self):
        self.policy['authorized_source_pin_sha256'] = '7' * 64
        self.write_policy()
        r = self.execute()
        self.assertEqual(r['status'], 'unavailable')
        self.assertEqual(r['reason_code'], 'LEASE_HOST_APPROVAL_NOT_BOUND_TO_POLICY')

    def test_lease_ticket_has_fixed_image_and_controls(self):
        self.make_tickets(lease_changes={'image_sha256': '0' * 64})
        self.assertEqual(self.execute()['status'], 'unavailable')
        self.make_tickets(lease_changes={'controls': dict(
            b.guard.REQUIRED_CONTROLS, network_access='ALLOWED')})
        self.assertEqual(self.execute()['status'], 'unavailable')

    def test_read_only_source_archive_mismatch_fails_before_reservation(self):
        store(self.source_path, self.source + b'changed')
        r = self.execute(engine=self._engine())
        self.assertEqual(r['reason_code'], 'RUN_HOST_SOURCE_TAR_PIN_MISMATCH')
        self.assertFalse(r['durable_one_use_lease_reserved'])

    def test_no_podman_cannot_consume_lease(self):
        result = self.execute()
        self.assertEqual(result['status'], 'unavailable')
        self.assertFalse(result['durable_one_use_lease_reserved'])
        self.assertEqual(os.listdir(self.policy['ledger_root']), ['leader.lock'])

    def test_real_source_staged_mock_oci_one_use_durable(self):
        r = self.execute(engine=self._engine())
        self.assertEqual(r['status'], 'partial')
        self.assertTrue(r['durable_one_use_lease_reserved'])
        self.assertTrue(r['container_cleanup_confirmed'])
        self.assertFalse(r['overall_quality_pass_verified'])
        self.assertFalse(r['kernel_oci_security_independently_attested'])
        self.assertTrue(r['result']['durable_lease_consumed_once'])
        self.assertEqual([evt[0] for evt in self.events],
                         ['create', 'ps', 'container', 'start', 'container',
                          'inspect', 'ps', 'container', 'rm', 'container'])
        self.assertIn('io.ces.lease.sha256=', repr(self.events[0]))
        self.assertTrue(any('a' * 64 in repr(evt) for evt in self.events
                            if evt[0] in ('start', 'rm')))
        self.assertEqual(os.listdir(self.policy['scratch_root']), [])
        self.assertEqual(len(list(Path(self.policy['ledger_root']).glob('lease-*'))), 1)
        replay = self.execute(engine=self._engine())
        self.assertEqual(replay['status'], 'permission_denied')
        self.assertEqual(replay['reason_code'], 'LEASE_HOST_LEASE_ALREADY_CONSUMED')
        self.assertEqual(self.events, [])

    def test_nonzero_exit_never_quality_pass(self):
        r = self.execute(engine=self._engine(status_code=3))
        self.assertEqual(r['status'], 'partial')
        self.assertEqual(r['result']['local_test_outcome'], 'nonzero')
        self.assertFalse(r['result']['overall_quality_pass_verified'])

    def test_policy_revoke_during_runtime_kills_and_burns_lease(self):
        def revoke():
            self.policy['grants'][0]['profile_ids'] = ['python.ruff']
            self.write_policy()
        r = self.execute(engine=self._engine(revoke=revoke))
        self.assertEqual(r['status'], 'unavailable')
        self.assertTrue(r['durable_one_use_lease_reserved'])
        self.assertTrue(r['container_cleanup_confirmed'])
        self.assertEqual(self.events[-2][0], 'rm')

    def test_uncertain_cleanup_quarantines_and_denies_replay(self):
        r = self.execute(engine=self._engine(cleaned=False))
        self.assertEqual(r['status'], 'unavailable')
        self.assertTrue(r['durable_one_use_lease_reserved'])
        self.assertFalse(r['container_cleanup_confirmed'])
        policy, sha = b._policy(str(self.policy_path))
        with b.Ledger(policy, sha) as ledger:
            self.assertFalse(ledger.safe())
            from oci_identity import binding
            with mock.patch.object(b.runner, '_runtime_binary', return_value=None), \
                 mock.patch.object(binding, 'verified_cleanup', return_value=True):
                self.assertEqual(ledger.recover(), 1)
            self.assertTrue(ledger.safe())
        self.assertEqual(os.listdir(self.policy['scratch_root']), [])
        self.assertEqual(self.execute(engine=self._engine())['status'],
                         'permission_denied')

    def test_recovery_handles_crash_after_reservation_before_create(self):
        policy, sha = b._policy(str(self.policy_path))
        lease = b._tickets(policy, self.profile)['lease']
        filename = b._lease_filename(lease['ticket_id'])
        stage = Path(self.policy['scratch_root']) / 'ec252-crashed'
        stage.mkdir(mode=0o700)
        (stage / 'file').write_bytes(b'temp')
        with b.Ledger(policy, sha) as ledger:
            ledger.reserve(filename, 'd' * 64, 'ces-ec252-' + '1' * 24,
                           str(stage))
        with b.Ledger(policy, sha) as ledger:
            with mock.patch.object(b.runner, '_runtime_binary', return_value=None), \
                 mock.patch.object(b.runner, '_cleanup', return_value=True):
                self.assertEqual(ledger.recover(), 1)
            self.assertTrue(ledger.safe())
            self.assertFalse(stage.exists())
            self.assertEqual(ledger.recover(), 0)
        self.assertEqual(self.execute(engine=self._engine())['status'],
                         'permission_denied')

    def test_ledger_symlink_unknown_file_and_lock_fail_closed(self):
        pol, sha = b._policy(str(self.policy_path))
        with b.Ledger(pol, sha) as l:
            with self.assertRaisesRegex(b.LeaseHostError, 'ALREADY_RUNNING'):
                with b.Ledger(pol, sha):
                    pass
            (self.root / 'ledger' / 'weird.tmp').write_text('x')
            with self.assertRaisesRegex(b.LeaseHostError, 'UNKNOWN_OR_TOO_MANY'):
                l.recover()

    def test_operator_private_policy_permissions_enforced(self):
        self.policy_path.chmod(0o644)
        with self.assertRaises(b.LeaseHostError):
            b._policy(str(self.policy_path))
        self.policy_path.chmod(0o600)
        self.lease_path.unlink()
        os.symlink(self.source_path, self.lease_path)
        self.assertEqual(self.execute()['status'], 'unavailable')

    def test_genuine_forked_watchdog_deadline_recovery_mock_engine(self):
        """A real OS child, not an in-process fake, completes recovery."""
        pol, sha = b._policy(str(self.policy_path))
        name = 'ces-ec252-' + '4' * 24
        stage = Path(self.policy['scratch_root']) / 'ec252-watchdog'
        stage.mkdir(mode=0o700)
        lease = b._tickets(pol, self.profile)['lease']
        filename = b._lease_filename(lease['ticket_id'])
        with b.Ledger(pol, sha) as ledger:
            ledger.reserve(filename, 'd' * 64, name, str(stage))
            with mock.patch.object(b.runner, '_runtime_binary', return_value=None), \
                 mock.patch.object(b.runner, '_cleanup', return_value=True):
                # The watchdog is a separate process, deadline expires even
                # though the parent remains alive; no real Podman involved.
                with mock.patch.object(b, 'WATCH_SECONDS', 0.4):
                    pid = b._spawn_watchdog(ledger, filename, pol)
                self.assertTrue(b._join_watchdog(pid) or self._wait_child(pid))
            self.assertEqual(ledger._read(filename)[-1]['event'],
                             'watchdog_cleaned')
            self.assertFalse(stage.exists())
            self.assertTrue(ledger.safe())

    @staticmethod
    def _wait_child(pid):
        try:
            os.waitpid(pid, 0)
            return True
        except ChildProcessError:
            return True

    def test_real_socket_bad_uid_no_runner(self):
        # Dedicated server test with no Podman so no forked watcher needed.
        socket_path = str(self.root / 'socket' / 'run.sock')
        problems = []
        def server():
            try:
                b.serve(str(self.policy_path), socket_path, max_requests=1,
                        accept_timeout=2)
            except Exception as exc:
                problems.append(exc)
        th = threading.Thread(target=server, daemon=True)
        th.start()
        for _ in range(100):
            if os.path.exists(socket_path):
                break
            time.sleep(0.01)
        self.assertTrue(os.path.exists(socket_path))
        result = b.request(socket_path, str(self.request_path), os.geteuid())
        th.join(timeout=4)
        self.assertFalse(problems, str(problems))
        self.assertFalse(th.is_alive())
        self.assertEqual(result['status'], 'unavailable')
        self.assertTrue(result['kernel_peer_uid_checked'])
        self.assertFalse(result['durable_one_use_lease_reserved'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
