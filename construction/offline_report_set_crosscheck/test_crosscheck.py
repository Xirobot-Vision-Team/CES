#!/usr/bin/env python3
"""EC331 focused local signatures and report-set tests.

Eighth and ninth Ed25519 fixtures are genuine; the inherited EC321 old
EC317/318 deep history still uses MOCKED structural fixtures. These tests
are NOT a claim of unmocked real full production EC294->331 acceptance.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import unittest
from unittest.mock import patch

from delivery_anchor import anchor
from fork_case_transport import case
from dual_channel_receipt import receipt
from offline_ledger_comparison import test_comparison as fixture
from replayable_comparison_report import report
from scripts import ces_next
from . import crosscheck, operator


class OfflineReportSetTests(unittest.TestCase):
    def setUp(self):
        self.old = fixture.GenuineDualLedgerComparisonTests(
            methodName='test_two_original_true_signature_chain_replays_direct_append')
        self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        self.root = self.old.folder
        self.p1 = self.old.params()
        self.manifest_file = str(self.root/'ec331-externally-pinned-original-manifest.json')

    def make_report(self, index, params):
        path = str(self.root / f'ec331-report-{index}.json')
        result = report.create_report(out=path, **params)
        self.assertEqual(result['exit_code'], 2)
        return {'report_file': path,
                'expected_report_sha256': result['report_original_raw_sha256'],
                'comparison_inputs': params}

    def sibling(self, *, reused=False, after_b=False):
        changes = {'ninth_responder_id': self.old.original_rows[1]['ninth_responder_id']} if reused else None
        row = self.old.f.add_review(3, 'deferred_without_submission',
                                    'external_transaction_evidence_unavailable',
                                    changes=changes)
        if after_b:
            target = self.old._make('ec331-direct-c',
                                    [*self.old.original_rows, row], prior_sha=self.old.b_sha)
            params = self.old.params(
                branch_a_ledger_file=self.old.b_file,
                expected_branch_a_ledger_sha256=self.old.b_sha,
                branch_a_prior_ledger_file=self.old.a_file,
                expected_branch_a_prior_ledger_sha256=self.old.a_sha,
                branch_b_ledger_file=target,
                expected_branch_b_ledger_sha256=case.sha(Path(target).read_bytes()),
                branch_b_prior_ledger_file=self.old.b_file,
                expected_branch_b_prior_ledger_sha256=self.old.b_sha)
        else:
            row['position'] = 2
            target = self.old._make('ec331-sibling-c',
                                    [self.old.original_rows[0], row],
                                    prior_sha=self.old.a_sha)
            params = self.old.params(
                branch_b_ledger_file=target,
                expected_branch_b_ledger_sha256=case.sha(Path(target).read_bytes()),
                branch_b_prior_ledger_file=self.old.a_file,
                expected_branch_b_prior_ledger_sha256=self.old.a_sha)
        return params

    def manifest(self, rows):
        doc = {'schema': crosscheck.MANIFEST_SCHEMA, 'reports': rows}
        receipt._write_exclusive(self.manifest_file, receipt._raw(doc))
        return case.sha(Path(self.manifest_file).read_bytes())

    def full_set(self, *, reused=False, after_b=False):
        r1 = self.make_report('a', self.p1)
        r2 = self.make_report('b', self.sibling(reused=reused, after_b=after_b))
        return self.manifest([r1,r2]), [r1,r2]

    def check(self, sha):
        return crosscheck.cross_reference(
            manifest_file=self.manifest_file, expected_manifest_sha256=sha)

    def test_two_signed_reports_reveal_true_same_parent_siblings_not_global_latest(self):
        sha, records = self.full_set()
        result = self.check(sha)
        self.assertEqual(result['exit_code'], 2)
        self.assertEqual(result['report_observation_count'], 2)
        self.assertEqual(result['distinct_report_original_raw_sha_count'], 2)
        self.assertEqual(result['distinct_verified_ledger_original_count'], 3)
        self.assertEqual(result['ledger_pair_count'], 3)
        self.assertEqual(result['new_cross_report_pair_count'], 1)
        self.assertEqual(result['deduplicated_unique_signed_ninth_receipt_original_count'],3)
        sibling = [p for p in result['ledger_pair_relationships']
                   if p['relationship'] ==
                   'verified_two_distinct_one_row_appends_to_same_parent_unresolved']
        self.assertEqual(len(sibling),1)
        self.assertTrue(sibling[0]['new_pair_relationship_only_visible_across_reports'])
        self.assertTrue(result['every_listed_report_and_both_signed_histories_replayed'])
        self.assertTrue(result['all_original_source_sha_pins_rechecked_after_batch'])
        self.assertEqual(result['manifest_original_raw_sha256'],sha)
        self.assertFalse(any(result[k] for k in crosscheck.FALSE_FIELDS))
        dumped = json.dumps(result)
        self.assertNotIn(str(self.root), dumped)
        self.assertNotIn(records[0]['report_file'], dumped)
        self.assertEqual(os.stat(self.manifest_file).st_mode & 0o777, 0o600)

    def test_verified_immediate_links_never_promote_unseen_two_hop_ancestry(self):
        sha, _ = self.full_set(after_b=True)
        doc = self.check(sha)
        names = {p['relationship'] for p in doc['ledger_pair_relationships']}
        self.assertTrue(any(name.startswith('verified_direct_one_row_append_')
                            for name in names))
        self.assertIn('common_signed_row_prefix_unproven_indirect_ancestry_unresolved', names)
        self.assertEqual(doc['deduplicated_unique_signed_ninth_receipt_original_count'],3)

    def test_two_identical_original_reports_different_files_do_not_create_votes(self):
        one = self.make_report('first', self.p1)
        second = str(self.root/'ec331-second-copy.json')
        receipt._write_exclusive(second, Path(one['report_file']).read_bytes())
        clone = dict(one, report_file=second)
        sha = self.manifest([one, clone])
        result = self.check(sha)
        self.assertEqual(result['report_observation_count'],2)
        self.assertEqual(result['distinct_report_original_raw_sha_count'],1)
        self.assertEqual(result['duplicate_report_observation_count'],1)
        self.assertEqual(result['distinct_verified_ledger_original_count'],2)
        self.assertEqual(result['deduplicated_unique_signed_ninth_receipt_original_count'],2)
        self.assertEqual(result['new_cross_report_pair_count'],0)
        # A byte-identical signed receipt copied to another ORIGINAL path is
        # still one cryptographic statement, not an inconsistent signer claim.
        signed_row = self.old.original_rows[0]
        duplicate_row = dict(signed_row, receipt_file=str(self.root/'second-local-copy.json'))
        counts, collisions, groups, only_new, multi_path_count = crosscheck._receipt_reuse(
            {'a'*64: {'entries':[signed_row]},
             'b'*64: {'entries':[duplicate_row]}},
            {'a'*64: {'r1'}, 'b'*64: {'r2'}})
        self.assertEqual(sum(counts.values()),1)
        self.assertEqual(groups,0)
        self.assertEqual(multi_path_count,1)
        self.assertEqual(result['observed_reports_not_new_signed_votes'][0][
                         'observed_original_file_count'], 2)

    def test_true_distinct_ninth_signed_receipts_reusing_role_are_disclosed(self):
        sha, _ = self.full_set(reused=True)
        result = self.check(sha)
        self.assertGreater(result['cross_report_distinct_signed_receipt_reused_ninth_role_groups'],0)
        self.assertGreater(result['new_ninth_role_reuse_groups_only_revealed_across_reports'],0)
        self.assertIn('ninth_responder_id',
            [x['reused_field'] for x in result['cross_report_ninth_role_reuse_group_examples']])
        self.assertNotIn(self.old.original_rows[0]['receipt_file'], json.dumps(result))

    def test_wrong_manifest_external_whole_raw_sha_is_not_accepted(self):
        self.full_set()
        with self.assertRaisesRegex(anchor.AnchorError, 'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.check('ab'*32)

    def test_tampered_manifest_with_new_valid_sha_but_unknown_fields_is_denied(self):
        _, records = self.full_set()
        doc = {'schema': crosscheck.MANIFEST_SCHEMA, 'reports': records,
               'external_atomic_cas_success':True}
        Path(self.manifest_file).write_bytes(receipt._raw(doc))
        with self.assertRaisesRegex(anchor.AnchorError,'TWO_TO_EIGHT_EXACT'):
            self.check(case.sha(Path(self.manifest_file).read_bytes()))

    def test_noncanonical_or_world_readable_manifest_denied(self):
        sha, _ = self.full_set()
        with open(self.manifest_file,'ab') as file:
            file.write(b' ')
        with self.assertRaisesRegex(anchor.AnchorError,'NONCANONICAL'):
            self.check(case.sha(Path(self.manifest_file).read_bytes()))
        os.chmod(self.manifest_file,0o644)
        with self.assertRaises((anchor.AnchorError, OSError)):
            self.check(sha)

    def test_two_records_with_same_report_file_or_alias_to_signed_original_denied(self):
        first = self.make_report('a',self.p1)
        fake = dict(first)
        sha = self.manifest([first,fake])
        with self.assertRaisesRegex(anchor.AnchorError,'SEPARATE_REPORT_FILES'):
            self.check(sha)

    def test_unknown_comparison_arguments_rejected_before_old_replay(self):
        first = self.make_report('a',self.p1)
        copy = str(self.root/'second.json')
        receipt._write_exclusive(copy,Path(first['report_file']).read_bytes())
        second = dict(first,report_file=copy,
                      comparison_inputs={**self.p1,'authorize_remote_cas':True})
        sha = self.manifest([first,second])
        with self.assertRaisesRegex(anchor.AnchorError,'EXACT_EC330_INDEPENDENT'):
            self.check(sha)

    def test_corrupt_second_report_fails_whole_batch_even_if_first_is_valid(self):
        sha, rows = self.full_set()
        with open(rows[1]['report_file'],'ab') as f:
            f.write(b' ')
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.check(sha)

    def test_corrupt_ninth_signed_original_after_report_replay_detected_late(self):
        sha, _ = self.full_set()
        native = crosscheck._receipt_reuse
        def mutate(ledgers, origins):
            result = native(ledgers, origins)
            with open(self.old.original_rows[0]['receipt_file'],'ab') as f:
                f.write(b' ')
            return result
        with patch.object(crosscheck,'_receipt_reuse',side_effect=mutate):
            with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
                self.check(sha)

    def test_downgraded_old_verifier_return_is_fail_closed(self):
        sha, _ = self.full_set()
        with patch.object(report,'verify_report',return_value={
             'schema':report.RESULT_SCHEMA,'exit_code':0,
             'all_current_signed_histories_genuinely_replayed_locally':True}):
            with self.assertRaisesRegex(anchor.AnchorError,'EVERY_EC330_REPORT_MUST'):
                self.check(sha)

    def test_standalone_cli_validates_and_denial_remains_unresolved(self):
        sha, _ = self.full_set()
        stdout = StringIO()
        with redirect_stdout(stdout):
            rc = operator.main(['compare-report-set','--manifest-file',
                                self.manifest_file,'--expected-manifest-sha256',sha])
        result=json.loads(stdout.getvalue())
        self.assertEqual(rc,2)
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['every_listed_report_and_both_signed_histories_replayed'])
        stdout=StringIO()
        with redirect_stdout(stdout):
            rc=operator.main(['compare-report-set','--manifest-file',
                self.manifest_file,'--expected-manifest-sha256','ab'*32])
        bad=json.loads(stdout.getvalue())
        self.assertIn(rc,(3,4,5))
        self.assertFalse(bad['every_listed_report_and_both_signed_histories_replayed'])
        self.assertTrue(all(bad[k] is False for k in crosscheck.FALSE_FIELDS))

    def test_unified_console_only_isolated_read_not_signer_or_writer(self):
        sha, _ = self.full_set()
        genuine = self.check(sha)
        invoked = []
        def execute(cmd, **opts):
            invoked.append((cmd,opts))
            return 2,genuine
        with patch.object(ces_next,'_command',side_effect=execute):
            stdout=StringIO()
            with redirect_stdout(stdout):
                code=ces_next.audit_hold_report_set(
                    'DeliveryAudit','CompareOfflinePinnedReportSet',
                    manifest_file=self.manifest_file,
                    expected_manifest_sha256=sha)
        self.assertEqual(code,2)
        self.assertEqual(len(invoked),1)
        cmd=invoked[0][0]
        self.assertEqual(cmd[1:3],['-I','-B'])
        self.assertEqual(cmd[4],'compare-report-set')
        self.assertNotIn('create-report',cmd)
        self.assertNotIn('sign',cmd)
        with self.assertRaises(ces_next.ConsoleError):
            ces_next.audit_hold_report_set('DeliveryAudit','CreateOfflineReportSet',
                manifest_file=self.manifest_file,expected_manifest_sha256=sha)

    def test_unified_console_rejects_forged_external_success_from_child(self):
        sha, _ = self.full_set()
        genuine=self.check(sha)
        forged=dict(genuine,remote_global_latest_or_winner_proven=True)
        with patch.object(ces_next,'_command',return_value=(2,forged)):
            with self.assertRaisesRegex(ces_next.ConsoleError,'NOT_GROUNDED'):
                ces_next.audit_hold_report_set(
                    'DeliveryAudit','CompareOfflinePinnedReportSet',
                    manifest_file=self.manifest_file,
                    expected_manifest_sha256=sha)

    def test_real_isolated_python_rejects_inherited_deep_mock_old_chain(self):
        sha, _ = self.full_set()
        target = Path(__file__).resolve().parents[2]/'scripts'/'ces_cas_report_set.py'
        completed = subprocess.run([sys.executable,'-I','-B',str(target),
             'compare-report-set','--manifest-file',self.manifest_file,
             '--expected-manifest-sha256',sha],
             capture_output=True,text=True,timeout=60)
        self.assertEqual(completed.returncode,4)
        bad=json.loads(completed.stdout)
        self.assertEqual(bad['status'],'invalid_input')
        self.assertFalse(bad['every_listed_report_and_both_signed_histories_replayed'])
        self.assertFalse(bad['remote_global_latest_or_winner_proven'])


if __name__ == '__main__':
    unittest.main()
