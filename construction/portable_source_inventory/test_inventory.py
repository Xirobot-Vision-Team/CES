#!/usr/bin/env python3
"""EC334 focused source-relocation behavior tests.

Local eighth/ninth Ed25519 are genuine. The inherited EC321 fixture MOCKS
EC317/318 deep signed history; real isolated production must reject it.
Tests do not prove the full unmocked EC294->334 signature chain or custody.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from delivery_anchor import anchor
from fork_case_transport import case
from dual_channel_receipt import receipt
from replayable_delta_handoff import test_handoff as old_suite
from scripts import ces_next
from . import inventory, operator


class PrivateRelocationInventoryTests(unittest.TestCase):
    def setUp(self):
        self.old = old_suite.ReconstructedHandoffTests(
            methodName='test_candidate_is_canonical_private_replayable_unsigned_and_no_remote_success')
        self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        self.root = self.old.root
        self.plan = str(self.root/'ec334-source-inventory.json')
        self.mapping = str(self.root/'ec334-private-path-map.json')
        self.receiver = str(self.root/'receiver')
        self.plan_sha = None
        self.map_sha = None

    def build_plan(self, **kwargs):
        self.old.build(**kwargs)
        created = self.old.create()
        result = inventory.create_plan(
            out=self.plan, handoff_file=self.old.path,
            expected_handoff_sha256=created['handoff_original_raw_sha256'],
            **self.old.options())
        self.plan_sha = result['inventory_original_raw_sha256']
        return result

    def make_map(self):
        result = inventory.prepare_map(
            out=self.mapping, plan_file=self.plan,
            expected_plan_sha256=self.plan_sha, source_root=str(self.root),
            destination_root=self.receiver)
        self.map_sha = result['mapping_original_raw_sha256']
        return result

    def copy_sources(self):
        rows = json.loads(Path(self.mapping).read_bytes())['locations']
        for row in rows:
            dest = Path(row['destination_path'])
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(row['source_path'], dest)
            os.chmod(dest, 0o600)
        return rows

    def verify(self, **kw):
        return inventory.verify_copies(**({
            'plan_file': self.plan, 'expected_plan_sha256': self.plan_sha,
            'map_file': self.mapping, 'expected_map_sha256': self.map_sha, **kw}))

    def test_actual_one_ec_first_hop_feature_original_unchanged_and_copy_verification(self):
        created = self.build_plan(role_reuse=True)
        raw = Path(self.plan).read_bytes()
        plan = json.loads(raw)
        self.assertEqual(raw, receipt._raw(plan))
        self.assertEqual(plan['schema'], inventory.PLAN_SCHEMA)
        self.assertEqual(plan['source_count'], len(plan['sources']))
        self.assertTrue(10 <= plan['source_count'] <= inventory.MAX_SOURCES)
        self.assertTrue(any('ninth_receipt' in r['roles'] for r in plan['sources']))
        self.assertTrue(any('left_capsule' in r['roles'] for r in plan['sources']))
        self.assertEqual(plan['offline_unresolved_exit_code'],2)
        self.assertEqual(os.stat(self.plan).st_mode & 0o777, 0o600)
        self.assertTrue(all(v is False for v in (plan[k] for k in inventory.FALSE_FIELDS)))
        self.assertEqual(created['exit_code'],2)
        mapping = self.make_map()
        self.assertEqual(mapping['exit_code'],2)
        self.copy_sources()
        checked = self.verify()
        self.assertTrue(checked['destination_bytes_match_every_first_hop_original'])
        self.assertEqual(checked['source_count'], plan['source_count'])
        self.assertFalse(checked['destination_replay_of_full_ec294_to_ec333_original_signatures_performed'])
        self.assertFalse(checked['first_hop_inventory_proves_all_nested_historical_originals_present'])
        self.assertEqual(checked['exit_code'],2)
        self.assertEqual(checked['mapping_original_raw_sha256'],self.map_sha)

    def test_source_sha_deduplicates_roles_but_never_creates_extra_signing_votes(self):
        self.build_plan(second_same=True)
        plan = json.loads(Path(self.plan).read_bytes())
        sources = plan['sources']
        self.assertEqual(len({x['source_path'] for x in sources}),len(sources))
        self.assertLess(len({x['source_original_raw_sha256'] for x in sources}),len(sources))
        self.assertEqual(plan['total_source_byte_length'],sum(x['byte_length'] for x in sources))
        # At least one old capsule is a post-replay measured SHA, not a new
        # 'signed source' or independently entrusted SHA claim.
        self.assertTrue(any(x['pin_basis']=='measured_after_full_source_replay_only'
                            for x in sources))

    def test_independent_three_document_raw_pins_never_self_authenticate(self):
        self.build_plan()
        self.make_map()
        self.copy_sources()
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            inventory.verify_copies(plan_file=self.plan,
                expected_plan_sha256='ab'*32,
                map_file=self.mapping, expected_map_sha256=self.map_sha)
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.verify(expected_map_sha256='ab'*32)
        bad=json.loads(Path(self.plan).read_bytes())
        bad['unsigned_inventory_or_mapping_is_signed_or_institutionally_authorized']=True
        Path(self.plan).write_bytes(receipt._raw(bad))
        with self.assertRaisesRegex(anchor.AnchorError,'NEGATIVE_FLAGS'):
            self.verify(expected_plan_sha256=case.sha(Path(self.plan).read_bytes()))

    def test_tampered_destination_only_recipient_byte_check_denies(self):
        self.build_plan()
        self.make_map()
        rows=self.copy_sources()
        with open(rows[0]['destination_path'],'ab') as f:
            f.write(b'one extra byte cannot be migrated as matching')
        with self.assertRaisesRegex(anchor.AnchorError,'ORIGINAL_COPY_BYTES_OR_LENGTH_MISMATCH'):
            self.verify()

    def test_map_missing_duplicate_alias_path_cross_and_root_escape_denied(self):
        self.build_plan()
        self.make_map()
        self.copy_sources()
        raw = Path(self.mapping).read_bytes()
        data = json.loads(raw)
        data['locations'].pop()
        Path(self.mapping).write_bytes(receipt._raw(data))
        with self.assertRaisesRegex(anchor.AnchorError,'FULL_COVERAGE'):
            self.verify(expected_map_sha256=case.sha(Path(self.mapping).read_bytes()))
        data = json.loads(raw)
        data['locations'][1]['destination_path']=data['locations'][0]['destination_path']
        Path(self.mapping).write_bytes(receipt._raw(data))
        with self.assertRaisesRegex(anchor.AnchorError,'DESTINATION_DISTINCT'):
            self.verify(expected_map_sha256=case.sha(Path(self.mapping).read_bytes()))
        with self.assertRaisesRegex(anchor.AnchorError,'EVERY_SOURCE_MUST_LIE'):
            inventory.prepare_map(out=str(self.root/'escape-map.json'),
                plan_file=self.plan, expected_plan_sha256=self.plan_sha,
                source_root=str(self.root/'totally-unrelated'),
                destination_root=self.receiver)

    def test_paths_symlink_private_mode_and_hardlink_refused(self):
        self.build_plan()
        self.make_map()
        rows=self.copy_sources()
        target=rows[1]['destination_path']
        os.unlink(target)
        os.symlink(rows[1]['source_path'],target)
        with self.assertRaises((anchor.AnchorError, OSError)):
            self.verify()
        os.unlink(target)
        shutil.copyfile(rows[1]['source_path'],target)
        os.chmod(target,0o644)
        with self.assertRaisesRegex(anchor.AnchorError,'OWNER_0600'):
            self.verify()
        os.chmod(target,0o600)
        alias=str(self.root/'linked-copy.json')
        os.link(target,alias)
        with self.assertRaisesRegex(anchor.AnchorError,'OWNER_0600'):
            self.verify()

    def test_plan_writer_exclusive_no_source_alias_and_no_stored_unsigned_cache(self):
        self.build_plan()
        plan_before=Path(self.plan).read_bytes()
        raw=Path(self.old.path).read_bytes()
        with self.assertRaisesRegex(anchor.AnchorError,'ALREADY_EXISTS'):
            inventory.create_plan(
                out=self.plan, handoff_file=self.old.path,
                expected_handoff_sha256=case.sha(raw), **self.old.options())
        self.assertEqual(plan_before,Path(self.plan).read_bytes())
        with self.assertRaisesRegex(anchor.AnchorError,'DISTINCT_ABSOLUTE_SOURCE'):
            inventory.create_plan(out=self.old.path,
                handoff_file=self.old.path, expected_handoff_sha256=case.sha(raw),
                **self.old.options())

    def test_source_side_cannot_use_fake_ec333_without_genuine_replay(self):
        self.old.build()
        self.old.create()
        with patch.object(inventory.handoff,'verify_handoff',return_value={
            'exit_code':0,
            'handoff_original_exactly_reconstructed_from_both_original_signed_histories':True,
            'both_ec331_manifests_and_all_inherited_old_signed_histories_replayed':True,
            'handoff_and_both_manifest_all_inherited_original_pins_late_rechecked':True}):
            with self.assertRaisesRegex(anchor.AnchorError,'REQUIRES_TRUE_EC333'):
                inventory.create_plan(out=self.plan,handoff_file=self.old.path,
                    expected_handoff_sha256=case.sha(Path(self.old.path).read_bytes()),
                    **self.old.options())
        self.assertFalse(os.path.lexists(self.plan))

    def test_late_source_change_refuses_and_removes_own_plan(self):
        self.old.build()
        created=self.old.create()
        original=inventory._exclusive
        target=self.old.options()['left_manifest_file']
        def changing(out, raw, forbidden, late_check):
            def mutated():
                with open(target,'ab') as f:
                    f.write(b'x')
                late_check()
            return original(out,raw,forbidden,mutated)
        with patch.object(inventory,'_exclusive',side_effect=changing):
            with self.assertRaisesRegex(anchor.AnchorError,'ORIGINAL_COPY_BYTES_OR_LENGTH_MISMATCH'):
                inventory.create_plan(out=self.plan,handoff_file=self.old.path,
                    expected_handoff_sha256=created['handoff_original_raw_sha256'],
                    **self.old.options())
        self.assertFalse(os.path.lexists(self.plan))

    def test_standalone_cli_and_isolated_unified_read_only_no_success_or_writer(self):
        self.build_plan()
        self.make_map()
        self.copy_sources()
        args=['verify-copies','--plan-file',self.plan,
              '--expected-plan-sha256',self.plan_sha,
              '--map-file',self.mapping,'--expected-map-sha256',self.map_sha]
        out=StringIO()
        with redirect_stdout(out):
            self.assertEqual(operator.main(args),2)
        self.assertTrue(json.loads(out.getvalue())['destination_bytes_match_every_first_hop_original'])
        good=self.verify()
        seen=[]
        with patch.object(ces_next,'_command',side_effect=lambda cmd,**kw:
                          (seen.append(cmd) or (2,good))):
            out=StringIO()
            with redirect_stdout(out):
                self.assertEqual(ces_next.audit_relocation_copies(
                    'DeliveryAudit','VerifyRelocatedFirstHopSourceCopies',
                    plan_file=self.plan,expected_plan_sha256=self.plan_sha,
                    map_file=self.mapping,expected_map_sha256=self.map_sha),2)
        self.assertEqual(len(seen),1)
        self.assertEqual(seen[0][1:3],['-I','-B'])
        self.assertEqual(seen[0][4],'verify-copies')
        self.assertFalse(any(x in seen[0] for x in (
            'create-plan','prepare-map','--out','--private-key','--remote')))
        with self.assertRaises(ces_next.ConsoleError):
            ces_next.audit_relocation_copies(
                'DeliveryAudit','CreatePlan',plan_file=self.plan,
                expected_plan_sha256=self.plan_sha,map_file=self.mapping,
                expected_map_sha256=self.map_sha)
        with patch.object(ces_next,'_command',return_value=(2,{
            **good,'copy_check_proves_external_cas_worm_actual_nonexecution_or_global_winner':True})):
            with self.assertRaisesRegex(ces_next.ConsoleError,'UNGROUNDED'):
                ces_next.audit_relocation_copies(
                    'DeliveryAudit','VerifyRelocatedFirstHopSourceCopies',
                    plan_file=self.plan,expected_plan_sha256=self.plan_sha,
                    map_file=self.mapping,expected_map_sha256=self.map_sha)
        with patch.object(ces_next,'_command',return_value=(0,good)):
            with self.assertRaisesRegex(ces_next.ConsoleError,'PROCESS_EXIT_INVALID'):
                ces_next.audit_relocation_copies(
                    'DeliveryAudit','VerifyRelocatedFirstHopSourceCopies',
                    plan_file=self.plan,expected_plan_sha256=self.plan_sha,
                    map_file=self.mapping,expected_map_sha256=self.map_sha)

    def test_actual_isolated_receiver_and_unified_cli_with_private_copies(self):
        self.build_plan()
        self.make_map()
        self.copy_sources()
        root=Path(__file__).resolve().parents[2]
        tokens=['--plan-file',self.plan,'--expected-plan-sha256',self.plan_sha,
                '--map-file',self.mapping,'--expected-map-sha256',self.map_sha]
        commands=[
            [sys.executable,'-I','-B',str(root/'scripts'/'ces_cas_relocation_inventory.py'),
             'verify-copies',*tokens],
            [sys.executable,'-I','-B',str(root/'scripts'/'ces_next.py'),
             'audit-relocation-copies','DeliveryAudit',
             'VerifyRelocatedFirstHopSourceCopies',*tokens],
        ]
        for cmd in commands:
            result=subprocess.run(cmd,capture_output=True,text=True,timeout=75)
            self.assertEqual(result.returncode,2,msg=result.stderr+'\n'+result.stdout)
            doc=json.loads(result.stdout)
            self.assertEqual(doc['schema'],inventory.RESULT_SCHEMA)
            self.assertTrue(doc['destination_bytes_match_every_first_hop_original'])
            self.assertNotIn(str(self.root),result.stdout)
            self.assertFalse(doc['copy_check_proves_external_cas_worm_actual_nonexecution_or_global_winner'])

    def test_real_isolated_new_writer_refuses_deep_structural_mock(self):
        self.old.build()
        made=self.old.create()
        script=Path(__file__).resolve().parents[2]/'scripts'/'ces_cas_relocation_inventory.py'
        args=['create-plan','--out',self.plan,
              '--handoff-file',self.old.path,
              '--expected-handoff-sha256',made['handoff_original_raw_sha256']]
        for k,v in self.old.options().items():
            args.extend(['--'+k.replace('_','-'),str(v)])
        proc=subprocess.run([sys.executable,'-I','-B',str(script),*args],
                            capture_output=True,text=True,timeout=75)
        self.assertEqual(proc.returncode,4)
        self.assertEqual(json.loads(proc.stdout)['schema'],inventory.DENIAL_SCHEMA)
        self.assertFalse(os.path.lexists(self.plan))


if __name__ == '__main__':
    unittest.main()
