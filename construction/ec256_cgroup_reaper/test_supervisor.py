#!/usr/bin/env python3
"""EC256 focused development cases; simulated cgroupfs != real Podman evidence."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec256_cgroup_reaper import supervisor as cg
from ec253_lease_host import broker as lease
from ec252_quality_run_host import broker as runner
from ec255_oci_identity import binding as identity

ID = 'a' * 64
LABEL = 'b' * 64
BOOT = 'aabbccdd-1122-3344-5566-778899aabbcc'
SCOPE = '/user.slice/user-1000.slice/libpod-' + ID + '.scope'
NAME = 'ces-ec252-' + 'c'*24


class Cgroup256Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ec256-')
        self.addCleanup(self.temp.cleanup)
        self.mount = Path(self.temp.name)/'cgroup2'
        target = self.mount/SCOPE.lstrip('/')
        target.mkdir(parents=True)
        (target/'cgroup.events').write_text('populated 1\nfrozen 0\n')
        (target/'cgroup.kill').write_text('')
        self.target = target
        self.patches = [
            patch.object(cg, 'CGROUP_MOUNT', str(self.mount)),
            patch.object(cg, '_mount_root', lambda: None),
            patch.object(cg, '_boot_id', lambda: BOOT),
            patch.object(cg, '_path_for_pid', side_effect=self.proc_path),
            patch.object(cg, '_pid_starttime', lambda pid: 123456),
            patch.object(cg, '_state', lambda pol, container_id: (True, 3214)),
            patch.object(identity, 'verify', lambda *a, **kw: None),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        self.pol = {'image_id':'sha256:'+ID}

    @staticmethod
    def proc_path(pid):
        if pid == os.getpid():
            return '/user.slice/ces-host.service'
        return SCOPE + '/child-subgroup'

    def record(self):
        stat = self.target.stat()
        return cg.Binding(cg.BIND_SCHEMA, ID, BOOT, SCOPE,
                          stat.st_dev, stat.st_ino, 123456)

    def test_01_bind_real_scope_ancestor_not_child_leaf(self):
        proof = cg.bind_live(self.pol, ID, LABEL)
        self.assertEqual(proof, self.record())
        self.assertEqual(proof.journal_event()['event'], 'cgroup_bound')

    def test_02_reject_symlink_cgroup(self):
        self.target.rename(self.target.with_name(self.target.name+'-original'))
        self.target.symlink_to(self.target.with_name(self.target.name+'-original'),
                               target_is_directory=True)
        with self.assertRaises(cg.CgroupError):
            cg.bind_live(self.pol, ID, LABEL)

    def test_03_reject_outside_scope_pid(self):
        with patch.object(cg, '_path_for_pid', return_value='/user.slice/other.scope'):
            with self.assertRaisesRegex(cg.CgroupError, 'UNIQUE_LIBPOD'):
                cg.bind_live(self.pol, ID, LABEL)

    def test_04_reject_self_scope_ancestor(self):
        with patch.object(cg, '_path_for_pid', return_value=SCOPE+'/service'):
            with self.assertRaisesRegex(cg.CgroupError, 'WOULD_KILL_BROKER'):
                cg._validated_path(SCOPE, ID)

    def test_05_exact_scope_kills_populated_tree_before_rm(self):
        self.assertEqual((self.target/'cgroup.events').read_text().splitlines()[0],
                         'populated 1')
        originals = cg._kill
        def fake_kernel_kill(fd):
            self.assertTrue(os.path.samefile(f'/proc/self/fd/{fd}', self.target))
            self.target.joinpath('cgroup.kill').write_text('1')
            self.target.joinpath('cgroup.events').write_text('populated 0\n')
            originals(fd)  # a real write and empty-group observation
        with patch.object(cg, '_kill', fake_kernel_kill), \
             patch.object(identity, '_labels', return_value=[ID]):
            saved=[]
            cg.reap_before_remove(self.pol, LABEL, NAME, ID,
                                  on_bound=saved.append)
        self.assertEqual(saved, [self.record()])
        self.assertEqual((self.target/'cgroup.kill').read_text(),'1')
        fd = os.open(self.target, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.assertFalse(cg._populated(fd))
        finally:
            os.close(fd)  # simulated events, not live kernel evidence

    def test_06_incompatible_persisted_inode_never_killed(self):
        record = self.record().journal_event()
        record['cgroup_ino'] += 1
        with patch.object(identity, '_labels', return_value=[ID]):
            with self.assertRaisesRegex(cg.CgroupError, 'CHANGED_FROM_LEDGER'):
                cg.reap_before_remove(self.pol, LABEL, NAME, ID,
                                      recorded=record)
        self.assertEqual((self.target/'cgroup.events').read_text(),'populated 1\nfrozen 0\n')

    def test_07_invalid_kernel_group_blocked(self):
        bad = self.record().journal_event()
        bad['boot_id'] = 'spoof'
        with self.assertRaisesRegex(cg.CgroupError, 'JOURNAL'):
            cg._recorded(ID,bad)

    def test_08_absent_container_requires_confirmed_absence(self):
        with patch.object(identity, '_labels', return_value=[]), \
             patch.object(identity, '_absent', return_value=False):
            with self.assertRaisesRegex(cg.CgroupError, 'NOT_ABSENT'):
                cg.reap_before_remove(self.pol, LABEL, NAME, ID)

    def test_09_stopped_podman_still_reaps_recorded_live_cgroup(self):
        proof=self.record()
        with patch.object(identity, '_labels', return_value=[ID]), \
             patch.object(cg, '_state', return_value=(False,0)):
            (self.target/'cgroup.events').write_text('populated 0\n')
            cg.reap_before_remove(self.pol, LABEL, NAME, ID,
                                  recorded=proof.journal_event())

    def test_10_wrong_id_cannot_control_cgroup(self):
        with self.assertRaises(cg.CgroupError):
            cg._validated_path(SCOPE, 'd'*64)
        with self.assertRaises(cg.CgroupError):
            cg._scope_for_pid('/user.slice/other/'+SCOPE.lstrip('/'), 'd'*64)


class Ledger256Tests(unittest.TestCase):
    def test_11_strict_journal_created_start_cgroup_bound_are_durable(self):
        with tempfile.TemporaryDirectory(prefix='ec256-ledger-') as td:
            root=Path(td)
            ledger=root/'ledger'; ledger.mkdir(mode=0o700)
            scratch=root/'scratch'; scratch.mkdir(mode=0o700)
            policy={'ledger_root':str(ledger),
                    'scratch_root':str(scratch),
                    'expected_source_tar_sha256':'1'*64}
            with lease.Ledger(policy,'2'*64) as book:
                file=lease._lease_filename('ec256-signed-lease')
                book.reserve(file,LABEL,NAME,str(scratch/'ec252-abcdef'),
                             binding_sha256=LABEL,cgroup_required=True)
                book.bind(file,ID)
                book.arm_start(file)
                evt=cg.Binding(cg.BIND_SCHEMA,ID,BOOT,SCOPE,1,2,3)
                book.bind_cgroup(file,evt)
                book.bind_cgroup(file,evt)  # idempotent concurrent discovery
                proof=book._read(file)
                self.assertEqual([e['event'] for e in proof],
                                 ['reserved','created','start_armed','cgroup_bound'])
                self.assertEqual(book.cgroup_record(file),evt.journal_event())
                book.finish(file,'closed')
                self.assertTrue(book.safe())
            # Reopen after crash, and refuse mutation of immutable binding.
            with lease.Ledger(policy,'2'*64) as book:
                self.assertEqual(book.cgroup_record(file),evt.journal_event())
                self.assertTrue(book.used(file))
                with self.assertRaises(lease.LeaseHostError):
                    book.bind_cgroup(file,cg.Binding(cg.BIND_SCHEMA,ID,BOOT,SCOPE,1,2,4))

    def test_12_start_requires_created_id(self):
        with tempfile.TemporaryDirectory(prefix='ec256-ledger-') as td:
            root=Path(td); (root/'ledger').mkdir(mode=0o700)
            (root/'scratch').mkdir(mode=0o700)
            policy={'ledger_root':str(root/'ledger'),
                    'scratch_root':str(root/'scratch'),
                    'expected_source_tar_sha256':'1'*64}
            with lease.Ledger(policy,'2'*64) as book:
                file=lease._lease_filename('other-lease')
                book.reserve(file,LABEL,NAME,str(root/'scratch'/'ec252-abcdef'),
                             binding_sha256=LABEL,cgroup_required=True)
                with self.assertRaises(lease.LeaseHostError):
                    book.arm_start(file)
                self.assertEqual(len(book._read(file)),1)



class RunnerLifecycle256Tests(unittest.TestCase):
    """Exercise real EC252 order; only OCI subprocess results are simulated."""
    def _run(self, fail_reap: bool) -> tuple[list[str], bool]:
        events=[]
        removed=[]
        with tempfile.TemporaryDirectory(prefix='ec256-runner-') as td:
            state={'Running':False, 'ExitCode':0, 'StartedAt':'2026-10-24T00:00:01Z',
                   'OOMKilled':False}
            def command(pol, args, **kwargs):
                kind=args[0]
                events.append(kind)
                if kind == 'create':
                    return runner.CommandResult(0,(ID+'\n').encode(),b'', '', '',0)
                if kind == 'start':
                    if kwargs.get('on_spawn'):
                        kwargs['on_spawn'](1234)
                    return runner.CommandResult(0,b'',b'', '', '',0)
                if kind == 'inspect':
                    return runner.CommandResult(0,json.dumps(state).encode(),b'', '', '',0)
                raise AssertionError(args)
            def cleanup(pol, label, name, cid):
                removed.append(cid)
                events.append('verified_rm')
                return True
            def before_cleanup(name,cid):
                events.append('cgroup_reap')
                if fail_reap:
                    raise runner.HostRunError('CGROUP256_REAP_DENIED')
            with patch.object(runner, '_runtime_ready', lambda pol: None), \
                 patch.object(runner, '_private_dir', lambda p: p), \
                 patch.object(runner, '_extract_source', lambda src, dst: (1,1)), \
                 patch.object(runner, '_create_args', lambda *a, **k: ['create']), \
                 patch.object(runner, '_run_command', side_effect=command), \
                 patch.object(identity, 'before_start', lambda *a: events.append('bind')), \
                 patch.object(identity, 'verify', lambda *a: None), \
                 patch.object(identity, 'verified_cleanup', side_effect=cleanup):
                args={'scratch_root':td,'expected_source_tar_sha256':'1'*64}
                try:
                    runner._run_container(args,'python.pytest',b'x',
                        recheck=lambda:None,caller=None,
                        lease_label_sha256=LABEL,
                        on_reserved=lambda n,s:events.append('reserved'),
                        on_created=lambda n,c:events.append('created'),
                        on_before_start=lambda n,c:events.append('arm_start'),
                        on_before_cleanup=before_cleanup)
                    if fail_reap:
                        raise AssertionError('callback failure must fail closed')
                except runner.HostRunError:
                    if not fail_reap:
                        raise
                # Retained stage after failed kill; no confirmed close.
                still_staged=bool(list(Path(td).glob('ec252-*')))
        return events, still_staged

    def test_13_start_arm_and_cgroup_reap_order(self):
        events, retained=self._run(False)
        self.assertLess(events.index('reserved'),events.index('create'))
        self.assertLess(events.index('created'),events.index('arm_start'))
        self.assertLess(events.index('arm_start'),events.index('start'))
        self.assertLess(events.index('cgroup_reap'),events.index('verified_rm'))
        self.assertFalse(retained)

    def test_14_uncertain_kill_blocks_podman_rm_and_preserves_stage(self):
        events, retained=self._run(True)
        self.assertIn('cgroup_reap',events)
        self.assertNotIn('verified_rm',events)
        self.assertTrue(retained)


class Recovery256Tests(unittest.TestCase):
    """Restart recovery must never bypass the signed cgroup pre-rm gate."""
    def _attempt(self, reap_allowed: bool) -> tuple[list[str], bool, str]:
        actions=[]
        with tempfile.TemporaryDirectory(prefix='ec256-recover-') as td:
            tmp=Path(td)
            (tmp/'ledger').mkdir(mode=0o700)
            scratch=tmp/'scratch';scratch.mkdir(mode=0o700)
            stage=scratch/'ec252-abcdef';stage.mkdir(mode=0o700)
            pol={'ledger_root':str(tmp/'ledger'),'scratch_root':str(scratch),
                 'expected_source_tar_sha256':'7'*64}
            def cgroup_gate(pol,label,name,cid,**kwargs):
                actions.append('kernel_group_gate')
                self.assertEqual(cid,ID)
                self.assertEqual(kwargs['recorded']['event'],'cgroup_bound')
                if not reap_allowed:
                    raise cg.CgroupError('CGROUP256_FAKE_KERNEL_DENIED')
            def full_id_cleanup(*args):
                actions.append('verified_full_id_rm')
                return True
            with lease.Ledger(pol,'8'*64) as book:
                filename=lease._lease_filename('recover-cgroup-v2')
                book.reserve(filename,LABEL,NAME,str(stage),
                             binding_sha256=LABEL,cgroup_required=True)
                book.bind(filename,ID)
                book.arm_start(filename)
                book.bind_cgroup(filename,cg.Binding(cg.BIND_SCHEMA,ID,BOOT,
                                                   SCOPE,1,2,3))
                with patch.object(lease, '_base_policy', lambda pol: pol), \
                     patch.object(runner, '_runtime_binary', lambda pol: None), \
                     patch.object(cg,'reap_before_remove',side_effect=cgroup_gate), \
                     patch.object(identity,'verified_cleanup',side_effect=full_id_cleanup):
                    try:
                        book.recover()
                        if not reap_allowed:
                            raise AssertionError('failed kernel gate must block recovery')
                    except cg.CgroupError:
                        if reap_allowed:
                            raise
                absent=not stage.exists()
                latest=book._read(filename)[-1]['event']
        return actions, absent, latest

    def test_15_recovery_reaps_before_id_rm_and_stage_unmount(self):
        actions, absent, terminal=self._attempt(True)
        self.assertEqual(actions,['kernel_group_gate','verified_full_id_rm'])
        self.assertTrue(absent)
        self.assertEqual(terminal,'recovered')

    def test_16_failed_recovery_leaves_staging_and_nonterminal_ledger(self):
        actions, absent, terminal=self._attempt(False)
        self.assertEqual(actions,['kernel_group_gate'])
        self.assertFalse(absent)
        self.assertEqual(terminal,'cgroup_bound')

if __name__ == '__main__':
    unittest.main()
