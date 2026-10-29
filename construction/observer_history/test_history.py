#!/usr/bin/env python3
"""EC310 local fixture tests; Ed25519 keys and CAS responses are SIMULATED.

Original EC294 through EC309 *real test signature code* is replayed. Nothing
here exercises a production CAS, real independent operators or Host grants.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from delivery_anchor import anchor as a
from portable_bundle import bundle as b
from cas_readback import readback as rb
from cas_readback.test_readback import EC309CasReadbackCases as Prev
from . import history as h

ROOT = Path(__file__).resolve().parents[2]


class EC310ObserverHistoryCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Prev.setUpClass()
        cls.observed_revision = Prev.cas_report['observed_cas_revision']
        cls.observed_head = Prev.cas_report['observed_head_chain_raw_sha256']

    @classmethod
    def tearDownClass(cls):
        Prev.tearDownClass()

    @classmethod
    def _chain(cls, revisions=None, heads=None, nonce_hex=('7','8','9')):
        """Genesis -> signed p1 -> signed p2 -> signed current (all pinned)."""
        rev = cls.observed_revision
        revisions = (rev-1, rev, rev) if revisions is None else revisions
        heads = (('a'*64), cls.observed_head, cls.observed_head) if heads is None else heads
        boundary = {'sequence': 0, 'raw_sha256': a.GENESIS,
                    'observed_revision': None}
        entries = []
        obs = Prev.observer.copy()
        for idx in range(3):
            obs = {**obs,
                   'expected_readback_request_nonce_sha256': nonce_hex[idx]*64,
                   'expected_previous_readback_sequence': idx,
                   'expected_previous_readback_raw_sha256':
                       a.GENESIS if idx == 0 else entries[-1][1],
                   'expected_previous_readback_observed_revision':
                       None if idx == 0 else revisions[idx-1]}
            path, sha = Prev._signed(observer=obs,
                observed_cas_revision=revisions[idx],
                observed_head_chain_raw_sha256=heads[idx])
            entries.append((path, sha, obs))
        previous = [
            {'file': path, 'raw_sha256': sha,
             'request_nonce_sha256': nonce_hex[idx]*64}
            for idx, (path, sha, _) in enumerate(entries[:2])]
        latest_path, latest_sha, latest_trust = entries[-1]
        args = Prev._opts(latest_path, latest_sha, observer=latest_trust)
        args['predecessors'] = previous
        args['boundary_trust'] = boundary
        return args, entries

    @staticmethod
    def _re_sign(doc: dict, key=None):
        key = Prev.key if key is None else key
        doc['observer_signature_ed25519'] = key.sign(
            rb.DOMAIN + a.canonical(doc['claim'])).hex()
        return Prev._file(doc)

    @classmethod
    def _current(cls, args: dict, *, changes=None, previous=None, observer=None):
        """Make a new valid latest signed record with supplied changes."""
        previous = args['observer_trust'] if previous is None else previous
        obs = {**previous, **(observer or {})}
        doc = json.loads(Path(args['readback_file']).read_text())
        doc['claim'].update(changes or {})
        doc['claim']['readback_request_nonce_sha256'] = obs[
            'expected_readback_request_nonce_sha256']
        doc['claim']['previous_readback_raw_sha256'] = obs[
            'expected_previous_readback_raw_sha256']
        doc['claim']['previous_readback_observed_revision'] = obs[
            'expected_previous_readback_observed_revision']
        doc['claim']['readback_sequence'] = obs['expected_previous_readback_sequence']+1
        path, sha = cls._re_sign(doc)
        return {**args, 'readback_file': path,
                'expected_readback_sha256': sha, 'observer_trust': obs}

    @staticmethod
    def _common_flags(args: dict) -> list[str]:
        c = args['cas_trust']; o = args['observer_trust']; e = args['boundary_trust']
        flags = [
            '--fork-case-file', args['fork_case_file'],
            '--expected-fork-case-sha256', args['expected_fork_case_sha256'],
            '--fork-evidence-file', args['fork_evidence_file'],
            '--expected-fork-evidence-sha256', args['expected_fork_evidence_sha256'],
            '--receipt-file', args['receipt_file'],
            '--expected-receipt-sha256', args['expected_receipt_sha256'],
            '--cas-authority-id', c['cas_authority_id'],
            '--cas-public-hex', c['cas_authority_public_hex'],
            '--request-nonce-sha256', c['expected_request_nonce_sha256'],
            '--expected-parent-cas-revision', str(c['expected_parent_cas_revision']),
            '--expected-parent-cas-head-sha256', c['expected_parent_cas_head_sha256'],
            '--readback-file', args['readback_file'],
            '--expected-readback-sha256', args['expected_readback_sha256'],
            '--cas-store-namespace-id', o['cas_store_namespace_id'],
            '--observer-id', o['observer_id'],
            '--observer-public-hex', o['observer_public_hex'],
            '--readback-request-nonce-sha256', o['expected_readback_request_nonce_sha256'],
            '--expected-previous-readback-sequence', str(o['expected_previous_readback_sequence']),
            '--expected-previous-readback-raw-sha256', o['expected_previous_readback_raw_sha256'],
            '--expected-previous-readback-observed-revision',
            'none' if o['expected_previous_readback_observed_revision'] is None else
                str(o['expected_previous_readback_observed_revision']),
            '--boundary-sequence', str(e['sequence']),
            '--boundary-raw-sha256', e['raw_sha256'],
            '--boundary-observed-revision',
            'none' if e['observed_revision'] is None else str(e['observed_revision']),
        ]
        for item in args['predecessors']:
            flags.extend(['--previous-readback', item['file'], item['raw_sha256'],
                          item['request_nonce_sha256']])
        return flags

    @classmethod
    def _cli(cls, script: str, command: list[str], expected: int) -> dict:
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
        proc = subprocess.run([sys.executable, '-I', '-B', str(ROOT/'scripts'/script),
                               *command], capture_output=True, text=True, timeout=480,
                              env=env)
        doc = json.loads(proc.stdout.strip())
        assert proc.returncode == expected, (proc.stdout, proc.stderr)
        return doc

    def test_01_complete_three_signed_sequence_real_inherited_crypto(self):
        args, _ = self._chain()
        report = h.evaluate(**args)
        self.assertEqual(report['status'], h.HISTORY_OK)
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual([r['sequence'] for r in report['history_window_signed_records']], [1,2])
        self.assertTrue(report['history_from_genesis_to_current_included'])
        self.assertTrue(report['original_ec294_through_ec309_current_decision_and_signature_replayed'])
        self.assertFalse(report['real_cas_commit_or_global_latest_proven'])
        self.assertFalse(report['previous_physical_external_cas_reads_verified'])
        self.assertNotIn(str(Prev.home), json.dumps(report))

    def test_02_non_genesis_boundary_only_proves_supplied_window(self):
        args, entries = self._chain()
        args['boundary_trust'] = {
            'sequence': 1, 'raw_sha256': entries[0][1],
            'observed_revision': self.observed_revision-1}
        args['predecessors'] = args['predecessors'][1:]
        doc = h.evaluate(**args)
        self.assertEqual(doc['status'], h.HISTORY_OK)
        self.assertFalse(doc['history_from_genesis_to_current_included'])
        self.assertFalse(doc['history_before_non_genesis_boundary_replayed'])
        self.assertEqual(doc['history_window_previous_count'], 1)

    def test_03_signed_previous_revision_rollback_is_real_observation_conflict(self):
        rev = self.observed_revision
        args, _ = self._chain(revisions=(rev, rev-2, rev),
                              heads=(self.observed_head, 'a'*64, self.observed_head))
        doc = h.evaluate(**args)
        self.assertEqual(doc['status'], h.HISTORY_ROLLBACK)
        self.assertEqual(doc['history_window_revision_regression_at_sequences'], [2])
        self.assertEqual(doc['exit_code'], 2)
        self.assertIsNone(doc['selected_candidate_corroborated_by_consistent_signed_window_raw_sha256'])

    def test_04_two_valid_previous_signed_heads_on_same_revision_denied_success(self):
        rev = self.observed_revision
        args, _ = self._chain(revisions=(rev,rev,rev),
             heads=(self.observed_head, 'a'*64, self.observed_head))
        doc = h.evaluate(**args)
        self.assertEqual(doc['status'], h.HISTORY_EQUIVOCATION)
        self.assertEqual(doc['history_window_same_revision_conflict_at_sequences'], [2,3])
        self.assertEqual(doc['exit_code'], 2)
        self.assertIsNone(doc['selected_candidate_corroborated_by_consistent_signed_window_raw_sha256'])

    def test_05_current_signed_claim_conflict_is_not_hidden_by_good_predecessors(self):
        args, _ = self._chain()
        changed = self._current(args, changes={'observed_head_chain_raw_sha256':'e'*64})
        doc = h.evaluate(**changed)
        self.assertEqual(doc['current_ec309_status'], rb.CONFLICT)
        self.assertEqual(doc['status'], h.HISTORY_EQUIVOCATION)
        self.assertEqual(doc['exit_code'], 2)

    def test_06_real_signature_required_for_each_pinned_predecessor(self):
        args, _ = self._chain()
        previous = json.loads(Path(args['predecessors'][0]['file']).read_text())
        previous['claim']['observed_head_chain_raw_sha256'] = 'f'*64
        bad_path, bad_sha = Prev._file(previous)  # recomputed *complete* SHA, old signature
        args['predecessors'][0] = {**args['predecessors'][0],
                                   'file': bad_path, 'raw_sha256': bad_sha}
        # Even if successor had an independently created matching prev SHA,
        # original signature is not valid and cannot be accepted.
        second = json.loads(Path(args['predecessors'][1]['file']).read_text())
        second['claim']['previous_readback_raw_sha256'] = bad_sha
        new_second_path, new_second_sha = self._re_sign(second)
        args['predecessors'][1] = {**args['predecessors'][1],
               'file': new_second_path, 'raw_sha256': new_second_sha}
        args = self._current(args, observer={
            'expected_previous_readback_raw_sha256': new_second_sha})
        with self.assertRaisesRegex(a.AnchorError, 'PREDECESSOR_OBSERVER_ED25519_SIGNATURE_INVALID'):
            h.evaluate(**args)

    def test_07_disconnected_sha_wrong_revision_or_sequence_is_denied(self):
        for change, message in (
            ({'previous_readback_raw_sha256':'f'*64}, 'DISCONTINUITY'),
            ({'previous_readback_observed_revision':self.observed_revision+1},
             'DISCONTINUITY'),
            ({'readback_sequence':8}, 'DISCONTINUITY'),
        ):
            with self.subTest(change=change):
                args, _ = self._chain()
                second = json.loads(Path(args['predecessors'][1]['file']).read_text())
                second['claim'].update(change)
                path, sha = self._re_sign(second)
                args['predecessors'][1] = {**args['predecessors'][1],
                    'file':path, 'raw_sha256':sha}
                args = self._current(args, observer={
                    'expected_previous_readback_raw_sha256':sha})
                with self.assertRaisesRegex(a.AnchorError, message):
                    h.evaluate(**args)

    def test_08_cross_namespace_observer_or_original_cas_receipt_splice_denied(self):
        for change in (
            {'cas_store_namespace_id':'different_namespace'},
            {'observer_id':'different_observer'},
            {'observer_public_hex': 'a'*64},
            {'ec308_cas_receipt_raw_sha256':'f'*64},
            {'decision_claimed_revision': self.observed_revision+1},
        ):
            with self.subTest(change=change):
                args, _ = self._chain()
                prior = json.loads(Path(args['predecessors'][0]['file']).read_text())
                prior['claim'].update(change)
                p, sha = self._re_sign(prior)
                args['predecessors'][0] = {**args['predecessors'][0],
                    'file':p, 'raw_sha256':sha}
                second = json.loads(Path(args['predecessors'][1]['file']).read_text())
                second['claim']['previous_readback_raw_sha256'] = sha
                p2, sha2 = self._re_sign(second)
                args['predecessors'][1] = {**args['predecessors'][1],
                    'file':p2, 'raw_sha256':sha2}
                args = self._current(args, observer={
                    'expected_previous_readback_raw_sha256': sha2})
                with self.assertRaisesRegex(a.AnchorError, 'PREDECESSOR_SIGNED_DECISION'):
                    h.evaluate(**args)

    def test_09_previous_nonce_reuse_or_incorrect_independent_pin_denied(self):
        for nonce in ('7'*64, '9'*64, 'd'*64, Prev.cas_options['trust']['expected_request_nonce_sha256']):
            with self.subTest(nonce=nonce):
                args, _ = self._chain()
                args['predecessors'][1]['request_nonce_sha256'] = nonce
                with self.assertRaises(a.AnchorError):
                    h.evaluate(**args)

    def test_10_bounded_window_independent_boundary_and_raw_file_sha(self):
        args, _ = self._chain()
        for change in (
            {'sequence': 1}, {'raw_sha256': 'f'*64},
            {'observed_revision': self.observed_revision},
        ):
            with self.subTest(change=change):
                with self.assertRaises(a.AnchorError):
                    h.evaluate(**{**args, 'boundary_trust':
                                  {**args['boundary_trust'], **change}})
        with self.assertRaises(a.AnchorError):
            h.evaluate(**{**args, 'predecessors':
                [{**args['predecessors'][0], 'raw_sha256':'c'*64},
                 args['predecessors'][1]]})
        with self.assertRaisesRegex(a.AnchorError, 'ONE_TO_SIXTEEN'):
            h.evaluate(**{**args, 'predecessors':args['predecessors']*9})
        with self.assertRaisesRegex(a.AnchorError, 'ONE_TO_SIXTEEN'):
            h.evaluate(**{**args, 'predecessors':[]})

    def test_11_boolean_sequence_observed_revision_and_extra_fields_denied(self):
        for change in (
            {'readback_sequence': True},
            {'observed_cas_revision': True},
            {'extra_undeclared_trust': True},
        ):
            with self.subTest(change=change):
                args, _ = self._chain()
                prior = json.loads(Path(args['predecessors'][0]['file']).read_text())
                prior['claim'].update(change)
                p, sha = self._re_sign(prior)
                args['predecessors'][0] = {**args['predecessors'][0],
                    'file':p, 'raw_sha256':sha}
                second = json.loads(Path(args['predecessors'][1]['file']).read_text())
                second['claim']['previous_readback_raw_sha256'] = sha
                p2, sha2 = self._re_sign(second)
                args['predecessors'][1] = {**args['predecessors'][1],
                    'file':p2, 'raw_sha256':sha2}
                args = self._current(args, observer={
                    'expected_previous_readback_raw_sha256':sha2})
                with self.assertRaises(a.AnchorError):
                    h.evaluate(**args)

    def test_12_independent_report_sha_and_fresh_full_crypto_replay(self):
        args, _ = self._chain()
        output = str(Prev.home / 'ec310-first-audit.json')
        result = h.verify(**args, out=output)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['audit_report_raw_sha256'], b.digest(Path(output).read_bytes()))
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
        self.assertEqual(h.verify_report(**args, audit_report_file=output,
            expected_audit_report_sha256=result['audit_report_raw_sha256'])['exit_code'], 0)
        with self.assertRaises(a.AnchorError):
            h.verify(**args, out=output)
        fake = json.loads(Path(output).read_text())
        fake['real_cas_commit_or_global_latest_proven'] = True
        bad_path, bad_sha = Prev._file(fake)
        with self.assertRaisesRegex(a.AnchorError, 'SAVED_HISTORY_AUDIT_DIFFERS'):
            h.verify_report(**args, audit_report_file=bad_path,
                            expected_audit_report_sha256=bad_sha)

    def test_13_independent_cli_and_console_readonly_success(self):
        args, _ = self._chain()
        flags = self._common_flags(args)
        cli = self._cli('ces_cas_history.py', ['verify', *flags], 0)
        console = self._cli('ces_next.py', ['audit-history',
            'DeliveryAudit', 'VerifySignedCasHistory', *flags], 0)
        for doc in (cli, console):
            self.assertEqual(doc['schema'], h.RESULT_SCHEMA)
            self.assertTrue(doc['bounded_predecessor_signatures_and_links_fully_replayed'])
            self.assertFalse(doc['real_external_store_read_performed'])
            self.assertFalse(doc['business_or_store_write_performed'])
        self.assertEqual(self._cli('ces_next.py', ['audit-history',
            'DeliveryAudit', 'CommitCAS', *flags], 3)['exit_code'], 3)
        # read-only console explicitly has no --out/commit/signer interface.
        command = subprocess.run([sys.executable, '-I', '-B',
            str(ROOT/'scripts/ces_next.py'), 'audit-history',
            'DeliveryAudit', 'VerifySignedCasHistory', *flags, '--out',
            str(Prev.home/'should-never-write')], capture_output=True, text=True)
        self.assertNotEqual(command.returncode, 0)
        self.assertFalse((Prev.home/'should-never-write').exists())

    def test_14_standalone_verify_report_and_signed_conflict_exit2(self):
        args, _ = self._chain(revisions=(self.observed_revision,)*3,
            heads=(self.observed_head,'f'*64,self.observed_head))
        self.assertEqual(self._cli('ces_cas_history.py',
            ['verify', *self._common_flags(args)], 2)['exit_code'], 2)
        self.assertEqual(self._cli('ces_next.py', ['audit-history',
            'DeliveryAudit', 'VerifySignedCasHistory', *self._common_flags(args)],
            2)['status'], h.HISTORY_EQUIVOCATION)
        audit = str(Prev.home/'ec310-cli-signed-conflict.json')
        first = self._cli('ces_cas_history.py',
            ['verify', *self._common_flags(args), '--out', audit], 2)
        saved = self._cli('ces_cas_history.py',
            ['verify-report', *self._common_flags(args),
             '--audit-report-file', audit,
             '--expected-audit-report-sha256', first['audit_report_raw_sha256']], 2)
        self.assertEqual(saved['audit_report_raw_sha256'], first['audit_report_raw_sha256'])


if __name__ == '__main__':
    unittest.main()
