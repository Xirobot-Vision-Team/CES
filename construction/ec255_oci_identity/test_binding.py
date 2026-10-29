#!/usr/bin/env python3
"""EC255 focused nonroot development fixtures; Podman is MOCKED.

Exercise the actual EC253 private fsynced journal and the EC255 control flow;
no live OCI, cgroup, kill-tree or independent source/host attestation occurs.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ec255_oci_identity import binding as b
from ec253_lease_host import broker as lease
from ec252_quality_run_host import broker as runner

spec = importlib.util.spec_from_file_location('ec253_fixture_for_ec255',
                                     ROOT / 'ec253_lease_host' / 'test_broker.py')
fixture = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(fixture)

ID1 = 'a'*64
ID2 = 'b'*64


class FakePodman:
    """Deterministic OCI store, with precise ID/name/label/command semantics."""
    def __init__(self, policy):
        self.policy = policy
        self.containers = {}  # full-id -> [name,label,image]
        self.commands = []
        self.ps_code = 0
        self.inspect_code = 0
        self.exists_code = None
        self.rm_code = 0

    def add(self, identity, name, label, image=None):
        self.containers[identity] = [name, label, image or self.policy['image_id'][7:]]

    @staticmethod
    def result(status=0, output=b''):
        return runner.CommandResult(status, output, b'', hashlib.sha256(output).hexdigest(),
                                    hashlib.sha256(b'').hexdigest(), len(output))

    def __call__(self, _pol, args, **_kw):
        self.commands.append(args)
        if args[0] == 'ps':
            digest = args[args.index('--filter')+1].split('=', 2)[2]
            ids = [i for i, v in self.containers.items() if v[1] == digest]
            return self.result(self.ps_code,
                               ('\n'.join(ids)+'\n').encode() if ids else b'')
        if args[:2] == ['container','inspect']:
            identity = args[-1]
            if self.inspect_code != 0 or identity not in self.containers:
                return self.result(self.inspect_code or 125)
            values = [identity, *self.containers[identity]]
            return self.result(0, ('|'.join(values)+'\n').encode())
        if args[:2] == ['container','exists']:
            identity = args[-1]
            return self.result(self.exists_code if self.exists_code is not None
                               else (0 if identity in self.containers or
                                     any(values[0] == identity for values
                                         in self.containers.values()) else 1))
        if args[0] == 'rm':
            if self.rm_code == 0:
                self.containers.pop(args[-1], None)
            return self.result(self.rm_code)
        raise AssertionError('Unexpected OCI command: %r' % args)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest('Must test real nonroot private ledger and permissions')
        self.fix = fixture.LeaseHostTests('test_private_policy_and_original_catalog_valid')
        self.fix.setUp()
        self.addCleanup(self.fix.doCleanups)
        self.policy, self.sha = lease._policy(str(self.fix.policy_path))
        self.base = lease._base_policy(self.policy)
        self.label = lease._tickets(self.policy, self.fix.profile)['lease_receipt_sha256']
        self.name = 'ces-ec252-' + 'f'*24
        self.engine = FakePodman(self.policy)
        self.patch = mock.patch.object(runner, '_run_command', side_effect=self.engine)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_01_create_marker_is_fixed_and_not_cli_controlled(self):
        argv = runner._create_args(self.base, '/stage/source', self.name,
                                   'python.pytest', lease_label_sha256=self.label)
        self.assertIn('--label=io.ces.lease.sha256='+self.label, argv)
        self.assertEqual(sum(x.startswith('--label') for x in argv), 1)
        self.assertIn('--network=none', argv)
        self.assertIn('--read-only', argv)
        self.assertIn('--pids-limit=32', argv)
        self.assertNotIn('shell', argv)
        with self.assertRaisesRegex(runner.HostRunError, 'LABEL_INVALID'):
            runner._create_args(self.base, '/stage', self.name, 'python.pytest',
                                lease_label_sha256='evil')
        self.assertFalse(any(x.startswith('--label') for x in
                             runner._create_args(self.base, '/stage', self.name,
                                                 'python.pytest')))

    def test_02_exact_create_binding(self):
        self.engine.add(ID1, self.name, self.label)
        b.before_start(self.base, self.label, self.name, ID1)
        self.assertEqual(self.engine.commands[0][0], 'ps')
        self.assertEqual(self.engine.commands[1][-1], ID1)

    def test_03_no_start_on_label_image_or_id_mismatch(self):
        for field in ('label', 'image', 'id', 'name'):
            self.engine.containers.clear()
            vals = [self.name, self.label, self.policy['image_id'][7:]]
            identity = ID2 if field == 'id' else ID1
            if field == 'label': vals[1] = 'f'*64
            if field == 'image': vals[2] = 'f'*64
            if field == 'name': vals[0] = 'unexpected-name'
            self.engine.add(identity, *vals)
            with self.assertRaises(runner.HostRunError, msg=field):
                b.before_start(self.base, self.label, self.name, ID1)

    def test_04_cleanup_targets_id_not_replaceable_name(self):
        self.engine.add(ID1, 'operator-renamed', self.label)
        self.assertTrue(b.verified_cleanup(self.base, self.label, self.name, ID1))
        removes = [args for args in self.engine.commands if args[0] == 'rm']
        self.assertEqual([row[-1] for row in removes], [ID1])
        self.assertEqual(self.engine.containers, {})

    def test_05_crash_before_created_append_recovers_label_by_name(self):
        self.engine.add(ID1, self.name, self.label)
        self.assertTrue(b.verified_cleanup(self.base, self.label, self.name))
        self.assertEqual(self.engine.containers, {})

    def test_06_unbound_renamed_object_fails_closed(self):
        self.engine.add(ID1, 'new-name', self.label)
        self.assertFalse(b.verified_cleanup(self.base, self.label, self.name))
        self.assertIn(ID1, self.engine.containers)
        self.assertFalse(any(row[0] == 'rm' for row in self.engine.commands))

    def test_07_duplicate_marker_refuses_to_remove_anything(self):
        self.engine.add(ID1, self.name, self.label)
        self.engine.add(ID2, 'other-object', self.label)
        self.assertFalse(b.verified_cleanup(self.base, self.label, self.name, ID1))
        self.assertEqual(len(self.engine.containers), 2)

    def test_08_missing_label_with_known_id_must_prove_absence(self):
        self.engine.add(ID1, self.name, 'e'*64)
        self.assertFalse(b.verified_cleanup(self.base, self.label, self.name, ID1))
        self.assertIn(ID1, self.engine.containers)
        self.engine.containers.clear()
        self.assertTrue(b.verified_cleanup(self.base, self.label, self.name, ID1))

    def test_09_engine_failure_is_not_evidence_of_absence(self):
        self.engine.add(ID1, self.name, self.label)
        self.engine.ps_code = 125
        self.assertFalse(b.verified_cleanup(self.base, self.label, self.name, ID1))
        self.engine.ps_code = 0
        self.engine.inspect_code = 125
        self.assertFalse(b.verified_cleanup(self.base, self.label, self.name, ID1))
        self.engine.inspect_code = 0
        self.engine.exists_code = 125
        self.assertFalse(b.verified_cleanup(self.base, self.label, self.name, ID1))

    def test_10_created_id_is_fsynced_and_durable(self):
        filename = lease._lease_filename(self.fix.lease['ticket_id'])
        stage = self.fix.root / 'scratch' / 'ec252-crashed'
        stage.mkdir(mode=0o700)
        with lease.Ledger(self.policy, self.sha) as ledger:
            ledger.reserve(filename, self.label, self.name, str(stage),
                           binding_sha256=self.label)
            ledger.bind(filename, ID1)
            self.assertEqual(ledger._read(filename)[1],
                             {'event':'created','container_id':ID1})
            with self.assertRaisesRegex(lease.LeaseHostError, 'REQUIRES_RESERVED'):
                ledger.bind(filename, ID1)
            self.assertEqual(ledger._read(filename)[0]['lease_label_sha256'], self.label)
        with lease.Ledger(self.policy, self.sha) as ledger:
            self.assertEqual(ledger._read(filename)[1]['container_id'], ID1)

    def test_11_restart_recovery_finds_renamed_by_bound_id(self):
        filename = lease._lease_filename(self.fix.lease['ticket_id'])
        stage = self.fix.root / 'scratch' / 'ec252-crashed'
        stage.mkdir(mode=0o700)
        with lease.Ledger(self.policy, self.sha) as ledger:
            ledger.reserve(filename, self.label, self.name, str(stage),
                           binding_sha256=self.label)
            ledger.bind(filename, ID1)
        self.engine.add(ID1, 'renamed-after-host-crash', self.label)
        with lease.Ledger(self.policy, self.sha) as ledger:
            with mock.patch.object(runner, '_runtime_binary', return_value=None):
                self.assertEqual(ledger.recover(), 1)
                self.assertTrue(ledger.safe())
                self.assertFalse(stage.exists())
                self.assertEqual(ledger.recover(), 0)
        self.assertEqual(self.engine.containers, {})
        self.assertEqual([r[-1] for r in self.engine.commands if r[0]=='rm'], [ID1])

    def test_12_restart_unbound_identity_collision_is_quarantined(self):
        filename = lease._lease_filename(self.fix.lease['ticket_id'])
        stage = self.fix.root / 'scratch' / 'ec252-crashed'
        stage.mkdir(mode=0o700)
        with lease.Ledger(self.policy, self.sha) as ledger:
            ledger.reserve(filename, self.label, self.name, str(stage),
                           binding_sha256=self.label)
        self.engine.add(ID1, 'unknown-owner', self.label)
        with lease.Ledger(self.policy, self.sha) as ledger:
            with mock.patch.object(runner, '_runtime_binary', return_value=None):
                with self.assertRaisesRegex(lease.LeaseHostError, 'UNCONFIRMED'):
                    ledger.recover()
            self.assertFalse(ledger.safe())
            self.assertTrue(stage.exists())
        self.assertIn(ID1, self.engine.containers)

    def test_13_reject_corrupt_created_id_in_permanent_journal(self):
        filename = lease._lease_filename(self.fix.lease['ticket_id'])
        stage = self.fix.root / 'scratch' / 'ec252-crashed'
        stage.mkdir(mode=0o700)
        with lease.Ledger(self.policy, self.sha) as ledger:
            ledger.reserve(filename, self.label, self.name, str(stage),
                           binding_sha256=self.label)
            path = self.fix.root / 'ledger' / filename
            with path.open('ab') as fd:
                fd.write(b'{"event":"created","container_id":"bad"}\n')
                fd.flush()
                os.fsync(fd.fileno())
            with self.assertRaisesRegex(lease.LeaseHostError, 'CREATED_INVALID'):
                ledger.recover()
            self.assertTrue(stage.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
