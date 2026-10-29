#!/usr/bin/env python3
"""EC335 focused functional tests; inherited EC317/318 signed chain is MOCKED.

The eighth and ninth local test Ed25519 signatures are real, but an isolated
production EC335 create-closure must refuse this inherited mock history.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile

from ec295_delivery_anchor import anchor
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt
from ec334_portable_source_inventory import test_inventory as old_suite
from scripts import ces_next
from . import closure


class NestedOriginalClosureTests(unittest.TestCase):
    def setUp(self):
        self.old = old_suite.PrivateRelocationInventoryTests(
            methodName='test_actual_one_ec_first_hop_feature_original_unchanged_and_copy_verification')
        self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        self.root = self.old.root
        self.closure = str(self.root / 'ec335-private-nested-closure.json')
        self.mapping = str(self.root / 'ec335-private-nested-map.json')
        self.destination_root = str(self.root / 'recipient-private')
        self.closure_sha = None
        self.map_sha = None

    def create(self, **changes):
        self.old.old.build(role_reuse=True)
        created = self.old.old.create()
        self.old.plan_sha = closure.first.create_plan(
            out=self.old.plan, handoff_file=self.old.old.path,
            expected_handoff_sha256=created['handoff_original_raw_sha256'],
            **self.old.old.options())['inventory_original_raw_sha256']
        self.handoff_sha = created['handoff_original_raw_sha256']
        args = dict(out=self.closure, first_hop_plan_file=self.old.plan,
                    expected_first_hop_plan_sha256=self.old.plan_sha,
                    handoff_file=self.old.old.path,
                    expected_handoff_sha256=self.handoff_sha,
                    source_root=str(self.root), **self.old.old.options())
        args.update(changes)
        result = closure.create_closure(**args)
        self.closure_sha = result['closure_original_raw_sha256']
        return result

    def prepare(self):
        result = closure.prepare_map(
            out=self.mapping, first_hop_plan_file=self.old.plan,
            expected_first_hop_plan_sha256=self.old.plan_sha,
            closure_file=self.closure, expected_closure_sha256=self.closure_sha,
            source_root=str(self.root), destination_root=self.destination_root)
        self.map_sha = result['mapping_original_raw_sha256']
        return result

    def copy_sources(self):
        mapping = json.loads(Path(self.mapping).read_bytes())
        for row in mapping['locations']:
            dest = Path(row['destination_path'])
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(row['source_path'], dest)
            os.chmod(dest, 0o600)
        return mapping['locations']

    def options(self):
        return dict(first_hop_plan_file=self.old.plan,
                    expected_first_hop_plan_sha256=self.old.plan_sha,
                    closure_file=self.closure, expected_closure_sha256=self.closure_sha,
                    map_file=self.mapping, expected_map_sha256=self.map_sha)

    def ready(self):
        self.create()
        self.prepare()
        return self.copy_sources()

    def test_real_observation_separates_persistent_zip_members_and_temporary_replays(self):
        created = self.create()
        raw = Path(self.closure).read_bytes()
        doc = json.loads(raw)
        self.assertEqual(raw, receipt._raw(doc))
        self.assertEqual(created['exit_code'], 2)
        self.assertEqual(doc['source_count'],
                         json.loads(Path(self.old.plan).read_bytes())['source_count'])
        self.assertGreater(doc['read_event_count'], doc['source_count'])
        self.assertGreater(doc['excluded_replay_temporary_read_source_count'], 0)
        self.assertGreater(doc['embedded_original_member_count'], 0)
        self.assertTrue(any(len(r['member_chain']) >= 3 for r in doc['embedded']))
        self.assertTrue(all(r['owner_source_path'] in
                            {x['source_path'] for x in doc['sources']}
                            for r in doc['embedded']))
        self.assertTrue(all(not r['source_path'].startswith('/tmp/ces-ec323-import-')
                            for r in doc['sources']))
        self.assertTrue(all(not r['source_path'].startswith('/tmp/ces-ec321-fork-receive-')
                            for r in doc['sources']))
        self.assertEqual(os.stat(self.closure).st_mode & 0o777, 0o600)
        self.assertTrue(all(doc[key] is False for key in closure.FALSE_FIELDS))

    def test_complete_receiver_copy_audit_and_embedded_member_recheck(self):
        self.ready()
        result = closure.verify_copies(**self.options())
        self.assertEqual(result['exit_code'], 2)
        self.assertTrue(result['destination_all_observed_copy_bytes_verified'])
        self.assertGreater(result['embedded_original_member_count'], 0)
        self.assertFalse(result['old_path_sensitive_signatures_rebound_or_reverified_at_destination'])
        self.assertTrue(result['destination_replay_not_performed'])

    def test_tampered_copy_refused_instead_of_reporting_cryptographic_rebinding(self):
        rows = self.ready()
        with open(rows[-1]['destination_path'], 'ab') as output:
            output.write(b'\nINJECTED')
        with self.assertRaisesRegex(anchor.AnchorError,
                                    'ORIGINAL_COPY_BYTES_OR_LENGTH_MISMATCH'):
            closure.verify_copies(**self.options())

    def test_independent_full_sha_for_all_three_control_documents_required(self):
        self.ready()
        for field in ('expected_first_hop_plan_sha256', 'expected_closure_sha256',
                      'expected_map_sha256'):
            opts = self.options()
            opts[field] = 'ab' * 32
            with self.assertRaises(anchor.AnchorError):
                closure.verify_copies(**opts)

    def test_map_missing_row_collision_and_source_alias_are_denied(self):
        rows = self.ready()
        raw = json.loads(Path(self.mapping).read_bytes())
        missing = json.loads(json.dumps(raw))
        missing['locations'].pop()
        Path(self.mapping).write_bytes(receipt._raw(missing))
        with self.assertRaisesRegex(anchor.AnchorError, 'COVERAGE'):
            closure.verify_copies(**dict(self.options(),
                expected_map_sha256=case.sha(Path(self.mapping).read_bytes())))
        changed = json.loads(json.dumps(raw))
        changed['locations'][1]['destination_path'] = rows[0]['destination_path']
        Path(self.mapping).write_bytes(receipt._raw(changed))
        with self.assertRaisesRegex(anchor.AnchorError, 'NONALIAS'):
            closure.verify_copies(**dict(self.options(),
                expected_map_sha256=case.sha(Path(self.mapping).read_bytes())))
        changed = json.loads(json.dumps(raw))
        changed['locations'][0]['destination_path'] = rows[0]['source_path']
        Path(self.mapping).write_bytes(receipt._raw(changed))
        with self.assertRaisesRegex(anchor.AnchorError, 'NONALIAS'):
            closure.verify_copies(**dict(self.options(),
                expected_map_sha256=case.sha(Path(self.mapping).read_bytes())))

    def test_source_root_boundary_rejects_bad_inputs_before_candidate(self):
        with self.assertRaisesRegex(anchor.AnchorError,
                                    'FIRST_HOP_OUTSIDE_EXPLICIT_SOURCE_ROOT'):
            self.create(source_root=str(self.root / 'not-source-root'))
        self.assertFalse(os.path.lexists(self.closure))

    def test_existing_out_never_overwritten_and_originals_unchanged(self):
        self.create()
        before = Path(self.closure).read_bytes()
        oldbytes = Path(self.old.old.path).read_bytes()
        with self.assertRaisesRegex(anchor.AnchorError, 'ALREADY_EXISTS'):
            closure.create_closure(out=self.closure,
                first_hop_plan_file=self.old.plan,
                expected_first_hop_plan_sha256=self.old.plan_sha,
                handoff_file=self.old.old.path,
                expected_handoff_sha256=self.handoff_sha, source_root=str(self.root),
                **self.old.old.options())
        self.assertEqual(Path(self.closure).read_bytes(), before)
        self.assertEqual(Path(self.old.old.path).read_bytes(), oldbytes)

    def test_unsafe_embedded_archive_entry_refused_even_if_whole_bytes_present(self):
        candidate = str(self.root / 'bad.zip')
        with zipfile.ZipFile(candidate, 'w') as stream:
            i = zipfile.ZipInfo('../escape.json', (1980,1,1,0,0,0))
            i.external_attr = (0o100600 << 16)
            stream.writestr(i, b'{"schema":"ces.invalid"}\n')
        os.chmod(candidate, 0o600)
        content = Path(candidate).read_bytes()
        with self.assertRaisesRegex(anchor.AnchorError, 'CANONICAL_MEMBERS'):
            closure._embedded([{
                'source_path': candidate, 'source_original_raw_sha256': case.sha(content),
                'byte_length': len(content), 'original_format': 'original_zip'}])

    def test_actual_isolated_and_unified_receiver_subprocesses(self):
        self.ready()
        args = [v for key, value in self.options().items()
                for v in ('--' + key.replace('_','-'), value)]
        cmd = [sys.executable, '-I', '-B', 'scripts/ces_cas_relocation_closure.py',
               'verify-copies', *args]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertTrue(json.loads(result.stdout)['destination_all_observed_copy_bytes_verified'])
        cmd = [sys.executable, '-I', '-B', 'scripts/ces_next.py',
               'audit-relocation-closure-copies', 'DeliveryAudit',
               'VerifyNestedOriginalSourceCopies', *args]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertTrue(json.loads(result.stdout)['destination_all_observed_copy_bytes_verified'])

    def test_unified_entry_rejects_writer_and_fake_privilege_claim(self):
        self.assertNotIn('create-closure', ces_next.build_parser().format_help())
        with self.assertRaisesRegex(ces_next.ConsoleError, 'EC335_ONLY'):
            ces_next.audit_relocation_closure_copies(
                'DeliveryAudit', 'CreateNestedOriginalSourceCopies',
                first_hop_plan_file='/safe/a', expected_first_hop_plan_sha256='1'*64,
                closure_file='/safe/b', expected_closure_sha256='2'*64,
                map_file='/safe/c', expected_map_sha256='3'*64)
        self.ready()
        def forged(_argv, **_):
            return 0, {'status':'success', 'exit_code':0}
        with patch.object(ces_next, '_command', side_effect=forged):
            with self.assertRaisesRegex(ces_next.ConsoleError, 'PROCESS_EXIT_INVALID'):
                ces_next.audit_relocation_closure_copies(
                    'DeliveryAudit', 'VerifyNestedOriginalSourceCopies',
                    **self.options())

    def test_production_isolated_writer_refuses_mocked_inherited_old_signatures(self):
        self.create()
        new = str(self.root/'production-should-not-create.json')
        args = dict(out=new, first_hop_plan_file=self.old.plan,
                    expected_first_hop_plan_sha256=self.old.plan_sha,
                    handoff_file=self.old.old.path,
                    expected_handoff_sha256=self.handoff_sha,
                    source_root=str(self.root), **self.old.old.options())
        cmd = [sys.executable, '-I', '-B', 'scripts/ces_cas_relocation_closure.py',
               'create-closure', *[v for key, val in args.items()
                                   for v in ('--' + key.replace('_','-'), val)]]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 4, proc.stderr + proc.stdout)
        self.assertFalse(os.path.lexists(new))
        self.assertFalse(json.loads(proc.stdout)['destination_all_observed_copy_bytes_verified'])


if __name__ == '__main__':
    unittest.main()
