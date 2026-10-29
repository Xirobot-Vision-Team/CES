#!/usr/bin/env python3
"""EC257 focused checks: actual FD reads on a fake cgroupfs; no live OCI claim."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec257_cgroup_metrics import metrics as km
from ec256_cgroup_reaper import supervisor as cg
from ec254_session_host import broker as session
import quality_run_budget as budget

ID = 'a' * 64
BOOT = 'aabbccdd-1122-3344-5566-778899aabbcc'
SCOPE = '/user.slice/user-1000.slice/libpod-' + ID + '.scope'


class Metrics257Tests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='ec257-meters-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / 'fake-cgroup'
        self.group = self.root / SCOPE.lstrip('/')
        self.group.mkdir(parents=True)
        self.files = {
            'cpu.stat': 'usage_usec 12345000\nuser_usec 9000000\nsystem_usec 3345000\n',
            'memory.peak': '10485760\n',
            'pids.peak': '4\n',
            'io.stat': '8:0 rbytes=1000 wbytes=2000 rios=3 wios=4\n'
                       '253:0 rbytes=100 wbytes=200 rios=1 wios=1\n',
        }
        self.write()
        st = self.group.stat()
        self.record = cg.Binding(cg.BIND_SCHEMA, ID, BOOT, SCOPE,
                                 st.st_dev, st.st_ino, 7123).journal_event()
        self._p = [patch.object(cg, 'CGROUP_MOUNT', str(self.root)),
                   patch.object(cg, '_mount_root', lambda: None),
                   patch.object(cg, '_boot_id', lambda: BOOT),
                   patch.object(cg, '_path_for_pid',
                                lambda _: '/user.slice/ces-meter.service')]
        for p in self._p:
            p.start()
            self.addCleanup(p.stop)

    def write(self):
        for name, value in self.files.items():
            (self.group / name).write_text(value)

    def sample(self, *, output=47, previous=None):
        return km.sample(ID, self.record, output,
                         previous if previous is not None else
                         {k: 0 for k in budget.RESOURCE_KEYS})

    def test_01_real_fd_kernel_counter_translation_and_peak(self):
        report = self.sample()
        self.assertEqual(report, {'cpu_ms': 12345, 'memory_peak_bytes': 10485760,
                                  'processes': 4, 'io_bytes': 3347})

    def test_02_monotonic_increases_include_output(self):
        before = self.sample(output=47)
        self.files['cpu.stat'] = 'usage_usec 12501000\n'
        self.files['memory.peak'] = '12600000\n'
        self.files['io.stat'] = '8:0 rbytes=4000 wbytes=2000\n'
        self.write()
        after = self.sample(output=60, previous=before)
        self.assertEqual(after['cpu_ms'], 12501)
        self.assertEqual(after['memory_peak_bytes'], 12600000)
        self.assertEqual(after['io_bytes'], 6060)

    def test_03_absent_peak_is_unavailable_not_zero(self):
        (self.group/'pids.peak').unlink()
        with self.assertRaisesRegex(km.KernelMetricError, 'COUNTER_UNAVAILABLE_PIDS_PEAK'):
            self.sample()

    def test_04_empty_io_stat_represents_zero_kernel_io(self):
        self.files['io.stat'] = ''
        self.write()
        self.assertEqual(self.sample()['io_bytes'], 47)

    def test_05_reject_duplicate_io_device(self):
        self.files['io.stat'] += '8:0 rbytes=10 wbytes=20\n'
        self.write()
        with self.assertRaisesRegex(km.KernelMetricError, 'IO_STAT_DEVICE_INVALID'):
            self.sample()

    def test_06_reject_missing_io_counter(self):
        self.files['io.stat'] = '8:0 rbytes=10 rios=1\n'
        self.write()
        with self.assertRaisesRegex(km.KernelMetricError, 'IO_STAT_REQUIRED_FIELDS_MISSING'):
            self.sample()

    def test_07_reject_symlinked_kernel_stat_file(self):
        target = self.group/'memory.peak'
        target.unlink()
        target.symlink_to(self.group/'cpu.stat')
        with self.assertRaisesRegex(km.KernelMetricError, 'COUNTER_UNAVAILABLE_MEMORY_PEAK'):
            self.sample()

    def test_08_inode_substitution_and_wrong_boot_fail(self):
        self.record['cgroup_ino'] += 1
        with self.assertRaisesRegex(km.KernelMetricError, 'CGROUP_INODE_CHANGED'):
            self.sample()
        self.record['cgroup_ino'] -= 1
        with patch.object(cg, '_boot_id', return_value='7'*8+'-'+'1'*4+'-'+'2'*4+'-'+'3'*4+'-'+'4'*12):
            with self.assertRaisesRegex(km.KernelMetricError, 'BOOT_CHANGED'):
                self.sample()

    def test_09_changed_host_cgroup_path_denied(self):
        self.record['cgroup_path'] = '/user.slice/libpod-' + ID + '.scope'
        with self.assertRaisesRegex(cg.CgroupError, 'CGROUP_DIRECTORY_ABSENT'):
            self.sample()

    def test_10_peak_over_hard_budget_rejected(self):
        self.files['memory.peak'] = str(budget.HARD_CEILINGS['memory_peak_bytes'] + 1) + '\n'
        self.write()
        with self.assertRaisesRegex(km.KernelMetricError, 'RESOURCE_LIMIT_EXCEEDED'):
            self.sample()

    def test_11_regressing_counter_is_not_fabricated(self):
        prior = self.sample()
        self.files['cpu.stat'] = 'usage_usec 100000\n'
        self.write()
        with self.assertRaisesRegex(km.KernelMetricError, 'KERNEL_COUNTER_REGRESSED'):
            self.sample(previous=prior)

    def test_12_malformed_cpu_stat_fails(self):
        self.files['cpu.stat'] = 'user_usec 12\n'
        self.write()
        with self.assertRaisesRegex(km.KernelMetricError, 'CPU_USAGE_MISSING'):
            self.sample()
        self.files['cpu.stat'] = 'usage_usec 12\nusage_usec 33\n'
        self.write()
        with self.assertRaisesRegex(km.KernelMetricError, 'CPU_STAT_INVALID'):
            self.sample()

    def test_13_overflow_and_bool_input_refused(self):
        self.files['memory.peak'] = str(2**63) + '\n'
        self.write()
        with self.assertRaisesRegex(km.KernelMetricError, 'COUNTER_OVERFLOW'):
            self.sample()
        with self.assertRaisesRegex(km.KernelMetricError, 'OUTPUT_METER_INVALID'):
            self.sample(output=True)
        with self.assertRaisesRegex(km.KernelMetricError, 'PREVIOUS_SAMPLE_INVALID'):
            self.sample(previous={k: True for k in budget.RESOURCE_KEYS})

    def test_14_final_worker_frame_cannot_lower_high_watermark(self):
        prior = self.sample()
        reported = {k: max(0, v - 1) for k,v in prior.items()}
        self.assertEqual(km.validate_sample(reported, previous=prior), prior)
        with self.assertRaisesRegex(km.KernelMetricError, 'WORKER_SAMPLE_INVALID'):
            km.validate_sample({'cpu_ms': True, **{k:0 for k in prior if k != 'cpu_ms'}},
                               previous=prior)

    def test_15_deliberate_legacy_stats_isolation(self):
        self.assertEqual(session.HostSession.__init__.__defaults__, (False, False))
        # No strict flags are client-accessible; server internally controls it.
        self.assertIn('require_kernel_metrics',
                      session.serve.__code__.co_varnames)
        self.assertNotIn('require_kernel_metrics', session.BEGIN_KEYS)

    def test_16_subtree_scope_record_and_own_group_are_rejected(self):
        self.record['cgroup_path'] = '/user.slice/ces-meter.service'
        with self.assertRaisesRegex(cg.CgroupError, 'PATH_NOT_FULL_CONTAINER_SCOPE'):
            self.sample()

    def test_17_final_message_is_bounded_seqpacket(self):
        x, y = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            body = {'type':'final_meter', 'resources': self.sample()}
            session._inner_send(x, body)
            self.assertEqual(session._inner_read(y), body)
        finally:
            x.close(); y.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
