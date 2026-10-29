#!/usr/bin/env python3
"""EC333 focused tests. Eighth/ninth Ed25519 are real in local fixtures,
EC317/318 deep inherited history uses structural MOCKs; true -I -B denies.
These tests are NOT a real production EC294->333 no-mock signed replay.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from delivery_anchor import anchor
from fork_case_transport import case
from dual_channel_receipt import receipt
from offline_report_set_crosscheck import crosscheck
from pinned_report_set_delta import test_delta as old_suite
from scripts import ces_next
from . import handoff, operator


class ReconstructedHandoffTests(unittest.TestCase):
    def setUp(self):
        self.old = old_suite.TwoPinnedSetDeltaTests(
            methodName='test_distinct_local_signed_siblings_differ_without_global_latest_claim')
        self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        self.root = self.old.root
        self.path = str(self.root/'ec333-owner-private-unsigned-delta-handoff.json')

    def build(self, **kw):
        self.old.build(**kw)

    def options(self):
        return self.old.kwargs()

    def create(self, out=None):
        return handoff.create_handoff(out=out or self.path, **self.options())

    def verify(self, expected=None, path=None, **changes):
        opts=dict(self.options(), **changes)
        return handoff.verify_handoff(
            handoff_file=path or self.path,
            expected_handoff_sha256=expected or case.sha(Path(path or self.path).read_bytes()),
            **opts)

    def args(self, cmd, **changes):
        opts = self.options()
        if cmd == 'create-handoff':
            opts['out'] = self.path
        else:
            opts['handoff_file'] = self.path
            opts['expected_handoff_sha256'] = case.sha(Path(self.path).read_bytes())
        opts.update(changes)
        return [cmd, *[i for key, value in opts.items()
                       for i in ('--'+key.replace('_','-'),str(value))]]

    def test_candidate_is_canonical_private_replayable_unsigned_and_no_remote_success(self):
        self.build(role_reuse=True)
        result=self.create()
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['handoff_original_raw_sha256'],case.sha(Path(self.path).read_bytes()))
        self.assertEqual(os.stat(self.path).st_mode & 0o777,0o600)
        raw=Path(self.path).read_bytes()
        doc=json.loads(raw)
        self.assertEqual(raw,receipt._raw(doc))
        self.assertEqual(set(doc),handoff.HANDOFF_FIELDS)
        self.assertEqual(doc['schema'],handoff.HANDOFF_SCHEMA)
        self.assertEqual(doc['offline_unresolved_exit_code'],2)
        self.assertEqual(doc['recomputed_ec332_local_delta']['exit_code'],2)
        self.assertEqual(doc['recomputed_ec332_local_delta']['combined_unique_signed_ninth_receipt_original_count'],3)
        self.assertFalse(any(doc[name] for name in handoff.FALSE_FIELDS))
        self.assertNotIn(str(self.root),raw.decode('utf8'))
        checked=self.verify(result['handoff_original_raw_sha256'])
        self.assertTrue(checked['handoff_original_exactly_reconstructed_from_both_original_signed_histories'])
        self.assertTrue(checked['both_ec331_manifests_and_all_inherited_old_signed_histories_replayed'])
        self.assertEqual(checked['handoff_original_raw_sha256'],result['handoff_original_raw_sha256'])
        self.assertFalse(any(checked[name] for name in handoff.FALSE_FIELDS))

    def test_same_old_originals_new_output_path_produces_identical_complete_bytes(self):
        self.build()
        first=self.create()
        other=str(self.root/'ec333-other-output-independent-original.json')
        second=self.create(other)
        self.assertEqual(Path(self.path).read_bytes(),Path(other).read_bytes())
        self.assertEqual(first['handoff_original_raw_sha256'],second['handoff_original_raw_sha256'])
        self.assertEqual(self.verify(first['handoff_original_raw_sha256'],other)['exit_code'],2)

    def test_same_original_manifest_bytes_at_distinct_paths_dedup_original_signatures(self):
        self.build(second_same=True)
        self.create()
        doc=json.loads(Path(self.path).read_bytes())['recomputed_ec332_local_delta']
        self.assertEqual(doc['combined_unique_report_original_count'],1)
        self.assertEqual(doc['combined_unique_signed_ninth_receipt_original_count'],2)
        self.assertEqual(doc['cross_input_only_ledger_pair_count'],0)
        self.assertEqual(self.verify()['exit_code'],2)

    def test_writer_never_overwrites_and_no_symlink_alias(self):
        self.build()
        self.create()
        before=Path(self.path).read_bytes()
        with self.assertRaisesRegex(anchor.AnchorError,'OUTPUT_ALREADY_EXISTS'):
            self.create()
        self.assertEqual(before,Path(self.path).read_bytes())
        with self.assertRaisesRegex(anchor.AnchorError,'PATH_MUST_BE_DISTINCT'):
            self.create(self.old.lpath)
        source=self.old.old.old.original_rows[0]['receipt_file']
        with self.assertRaisesRegex(anchor.AnchorError,'PATH_MUST_BE_DISTINCT'):
            self.create(source)
        link=str(self.root/'ec333-symlink.json')
        os.symlink(self.path,link)
        with self.assertRaises((anchor.AnchorError,OSError)):
            self.create(link)

    def test_independent_whole_sha_required_and_denies_changed_handoff(self):
        self.build()
        original=self.create()
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.verify('ab'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'WHOLE_RAW_SHA_FROM_INDEPENDENT_CHANNEL'):
            self.verify('0'*64)
        with open(self.path,'ab') as f: f.write(b'added untrusted tail')
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.verify(original['handoff_original_raw_sha256'])

    def test_forged_success_even_with_new_locally_computed_sha_denied(self):
        self.build()
        self.create()
        obj=json.loads(Path(self.path).read_bytes())
        obj['remote_global_latest_or_winner_proven']=True
        Path(self.path).write_bytes(receipt._raw(obj))
        with self.assertRaisesRegex(anchor.AnchorError,'SCHEMA_UNRESOLVED_FLAGS'):
            self.verify()

    def test_saved_unsigned_delta_cannot_change_and_advance_own_pin(self):
        self.build()
        self.create()
        obj=json.loads(Path(self.path).read_bytes())
        obj['recomputed_ec332_local_delta']['combined_unique_ledger_original_count']=999
        Path(self.path).write_bytes(receipt._raw(obj))
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EXACTLY_RECONSTRUCTED'):
            self.verify()

    def test_external_manifest_pin_is_not_inherited_from_handoff_document(self):
        self.build()
        self.create()
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.verify(right_expected_manifest_sha256='ab'*32)
        self.assertNotEqual(self.old.lsha,self.old.rsha)

    def test_pinned_old_signed_source_mutation_denies_replay_after_handoff(self):
        self.build()
        self.create()
        signed_ninth_path=self.old.old.old.original_rows[0]['receipt_file']
        with open(signed_ninth_path,'ab') as f: f.write(b'mutated signed input')
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.verify()

    def test_candidate_write_failure_on_late_pinned_source_mutation_not_committed(self):
        self.build()
        original=handoff._late_repin
        calls=[]
        def change_old_input(inputs):
            calls.append(1)
            if len(calls)==2:
                with open(self.old.lpath,'ab') as f: f.write(b'mutated late')
            return original(inputs)
        with patch.object(handoff,'_late_repin',side_effect=change_old_input):
            with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self.create()
        self.assertEqual(len(calls),2)
        self.assertFalse(os.path.lexists(self.path))

    def test_cannot_trust_mocked_ec332_console_output_without_true_replay(self):
        self.build()
        with patch.object(handoff.delta,'compare',return_value={
                'schema':handoff.delta.RESULT_SCHEMA,
                'exit_code':0,
                'both_ec331_sets_and_every_inherited_signed_history_genuinely_replayed': True}):
            with self.assertRaisesRegex(anchor.AnchorError,'REQUIRE_BOTH_GENUINE'):
                self.create()
        self.assertFalse(os.path.lexists(self.path))

    def test_standalone_create_and_verify_cli_results_and_denials(self):
        self.build()
        output=StringIO()
        with redirect_stdout(output):
            rc=operator.main(self.args('create-handoff'))
        self.assertEqual(rc,2)
        created=json.loads(output.getvalue())
        self.assertEqual(created['command'],'create-handoff')
        output=StringIO()
        with redirect_stdout(output):
            rc=operator.main(self.args('verify-handoff'))
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(output.getvalue())['schema'],handoff.RESULT_SCHEMA)
        output=StringIO()
        with redirect_stdout(output):
            rc=operator.main(self.args('verify-handoff',expected_handoff_sha256='ab'*32))
        self.assertIn(rc,(3,4,5))
        failed=json.loads(output.getvalue())
        self.assertEqual(failed['schema'],handoff.DENIAL_SCHEMA)
        self.assertFalse(failed['handoff_original_exactly_reconstructed_from_both_original_signed_histories'])
        self.assertFalse(any(failed[k] for k in handoff.FALSE_FIELDS))

    def test_unified_mode_fixed_isolated_verify_only_and_no_writer_or_signer(self):
        self.build()
        created=self.create()
        real=self.verify(created['handoff_original_raw_sha256'])
        captured=[]
        def fake_child(cmd, **kw):
            captured.append(cmd)
            return 2,real
        output=StringIO()
        with patch.object(ces_next,'_command',side_effect=fake_child):
            with redirect_stdout(output):
                rc=ces_next.audit_hold_report_set_handoff(
                    'DeliveryAudit','VerifyPinnedReportSetDeltaHandoff',
                    handoff_file=self.path,
                    expected_handoff_sha256=created['handoff_original_raw_sha256'],
                    **self.options())
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(output.getvalue())['schema'],handoff.RESULT_SCHEMA)
        self.assertEqual(len(captured),1)
        self.assertEqual(captured[0][1:3],['-I','-B'])
        self.assertEqual(captured[0][4],'verify-handoff')
        self.assertFalse(any(x in captured[0] for x in (
            'create-handoff','--out','--private-key','sign','cas-write')))
        with self.assertRaises(ces_next.ConsoleError):
            ces_next.audit_hold_report_set_handoff(
                'DeliveryAudit','CreateHandoff',handoff_file=self.path,
                expected_handoff_sha256=created['handoff_original_raw_sha256'],
                **self.options())

    def test_unified_denies_forged_remote_success_and_process_exit_zero(self):
        self.build()
        made=self.create()
        good=self.verify(made['handoff_original_raw_sha256'])
        opts=dict(handoff_file=self.path,
                  expected_handoff_sha256=made['handoff_original_raw_sha256'],
                  **self.options())
        with patch.object(ces_next,'_command',return_value=(2,{
                **good,'actual_external_nonexecution_or_hold_proven':True})):
            with self.assertRaisesRegex(ces_next.ConsoleError,'UNGROUNDED'):
                ces_next.audit_hold_report_set_handoff(
                    'DeliveryAudit','VerifyPinnedReportSetDeltaHandoff',**opts)
        with patch.object(ces_next,'_command',return_value=(0,good)):
            with self.assertRaisesRegex(ces_next.ConsoleError,'PROCESS_EXIT_INVALID'):
                ces_next.audit_hold_report_set_handoff(
                    'DeliveryAudit','VerifyPinnedReportSetDeltaHandoff',**opts)

    def test_real_isolated_process_rejects_structural_mock_deep_history(self):
        self.build()
        script=Path(__file__).resolve().parents[2]/'scripts'/'ces_cas_report_set_handoff.py'
        cmd=[sys.executable,'-I','-B',str(script),*self.args('create-handoff')]
        process=subprocess.run(cmd,capture_output=True,text=True,timeout=75)
        self.assertEqual(process.returncode,4)
        refusal=json.loads(process.stdout)
        self.assertEqual(refusal['schema'],handoff.DENIAL_SCHEMA)
        self.assertFalse(refusal['both_ec331_manifests_and_all_inherited_old_signed_histories_replayed'])
        self.assertFalse(os.path.lexists(self.path))


if __name__ == '__main__':
    unittest.main()
