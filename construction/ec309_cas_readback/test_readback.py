#!/usr/bin/env python3
"""EC309 focused local tests: actual inherited EC294-308 signed fixtures.

Test-only keys and signed JSON simulate authorities, not a live CAS server,
independent human custodians, actual readback or outside nonce issuance.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as store
from ec302_portable_bundle import bundle as b
from ec306_registrar_epochs.test_epochs import EC306EpochCases as OldEpochs
from ec308_cas_receipt import receipt as cas
from ec308_cas_receipt.test_receipt import EC308CasReceiptCases as OldCas
from . import readback as r

ROOT = Path(__file__).resolve().parents[2]


class EC309CasReadbackCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OldCas.setUpClass()
        try:
            cls.tmp = tempfile.TemporaryDirectory(prefix='ec309-cas-readback-')
            cls.home = Path(cls.tmp.name)
            cls.key = Ed25519PrivateKey.generate()
            cls.pub = cls.key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw).hex()
            cls.cas_path, cls.cas_sha = OldCas._signed_file()
            cls.cas_options = OldCas._options(cls.cas_path, cls.cas_sha)
            cls.cas_report = cas.evaluate(**cls.cas_options)
            cls.observer = {
                'cas_store_namespace_id': 'external_registry_namespace',
                'observer_id': 'readback_independent_site',
                'observer_public_hex': cls.pub,
                'expected_readback_request_nonce_sha256': '7'*64,
                'expected_previous_readback_sequence': 0,
                'expected_previous_readback_raw_sha256': a.GENESIS,
                'expected_previous_readback_observed_revision': None,
            }
            cls.counter = 0
        except BaseException:
            if hasattr(cls, 'tmp'):
                cls.tmp.cleanup()
            OldCas.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        OldCas.tearDownClass()

    @classmethod
    def _opts(cls, readback_file, readback_sha, cas_opts=None, observer=None):
        opts = cls.cas_options if cas_opts is None else cas_opts
        return {
            'fork_case_file': opts['fork_case_file'],
            'expected_fork_case_sha256': opts['expected_fork_case_sha256'],
            'fork_evidence_file': opts['fork_evidence_file'],
            'expected_fork_evidence_sha256': opts['expected_fork_evidence_sha256'],
            'receipt_file': opts['receipt_file'],
            'expected_receipt_sha256': opts['expected_receipt_sha256'],
            'cas_trust': opts['trust'],
            'readback_file': str(readback_file),
            'expected_readback_sha256': readback_sha,
            'observer_trust': cls.observer if observer is None else observer,
        }

    @classmethod
    def _claim(cls, *, cas_report=None, observer=None, **changes):
        cas_report = cls.cas_report if cas_report is None else cas_report
        observer = cls.observer if observer is None else observer
        claim = {
            'schema': r.CLAIM_SCHEMA,
            'registry_id': cas_report['registry_id'],
            'cas_authority_id': cls.cas_options['trust']['cas_authority_id'],
            'cas_authority_public_hex': cls.cas_options['trust']['cas_authority_public_hex'],
            'cas_store_namespace_id': observer['cas_store_namespace_id'],
            'observer_id': observer['observer_id'],
            'observer_public_hex': observer['observer_public_hex'],
            'ec307_fork_case_raw_sha256':
                cls.cas_options['expected_fork_case_sha256'],
            'ec307_fork_evidence_raw_sha256':
                cas_report['fork_evidence_raw_sha256'],
            'ec308_cas_receipt_raw_sha256':
                cas_report['signed_cas_receipt_raw_sha256'],
            'ec308_cas_claim_raw_sha256':
                cas_report['signed_cas_claim_raw_sha256'],
            'original_cas_request_nonce_sha256':
                cls.cas_options['trust']['expected_request_nonce_sha256'],
            'readback_request_nonce_sha256':
                observer['expected_readback_request_nonce_sha256'],
            'decision_signed_outcome': cas_report['issuer_signed_outcome'],
            'decision_claimed_revision': cas_report['observed_cas_revision'],
            'decision_claimed_head_raw_sha256':
                cas_report['observed_head_chain_raw_sha256'],
            'readback_sequence': observer['expected_previous_readback_sequence']+1,
            'previous_readback_raw_sha256':
                observer['expected_previous_readback_raw_sha256'],
            'previous_readback_observed_revision':
                observer['expected_previous_readback_observed_revision'],
            'observed_cas_revision': cas_report['observed_cas_revision'],
            'observed_head_chain_raw_sha256':
                cas_report['observed_head_chain_raw_sha256'],
        }
        claim.update(changes)
        return claim

    @classmethod
    def _file(cls, doc):
        cls.counter += 1
        path = cls.home / f'proof-{cls.counter:04d}.json'
        store.store(str(path), doc, 24_000)
        return str(path), b.digest(path.read_bytes())

    @classmethod
    def _signed(cls, *, key=None, claim=None, observer=None,
                cas_report=None, **changes):
        claim = cls._claim(observer=observer, cas_report=cas_report, **changes) \
            if claim is None else claim
        key = cls.key if key is None else key
        return cls._file({
            'schema': r.READBACK_SCHEMA,
            'claim': claim,
            'observer_signature_ed25519':
                key.sign(r.DOMAIN + a.canonical(claim)).hex(),
        })

    def test_01_real_original_replay_plus_distinct_observer_signed_agreement(self):
        file, sha = self._signed()
        report = r.evaluate(**self._opts(file, sha))
        self.assertEqual(report['status'], r.SAME)
        self.assertTrue(report['original_ec294_through_ec308_signatures_and_claim_replayed'])
        self.assertTrue(report['observer_ed25519_signature_verified'])
        self.assertEqual(report['signed_claims_corroborate_selected_candidate_raw_sha256'],
                         OldCas.candidates[0])
        self.assertFalse(report['actual_external_store_read_or_worm_performed'])
        self.assertFalse(report['globally_current_head_or_cas_tip_proven'])
        self.assertNotIn(str(self.home), json.dumps(report))
        self.assertEqual(r.verify(**self._opts(file, sha))['exit_code'], 0)

    def test_02_two_signatures_agree_on_failed_precondition_but_do_not_select(self):
        file, sha = OldCas._signed_file(
            outcome='compare_exchange_precondition_failed_claim',
            selected_candidate_chain_raw_sha256=None,
            observed_head_chain_raw_sha256='e'*64,
            observed_cas_revision=OldCas.revision+3)
        cas_opts = OldCas._options(file, sha)
        doc = cas.evaluate(**cas_opts)
        rb, rb_sha = self._signed(cas_report=doc)
        result = r.evaluate(**self._opts(rb, rb_sha, cas_opts=cas_opts))
        self.assertEqual(result['status'], r.SAME)
        self.assertIsNone(result['signed_claims_corroborate_selected_candidate_raw_sha256'])
        self.assertEqual(r.verify(**self._opts(rb, rb_sha, cas_opts=cas_opts))['exit_code'], 2)

    def test_03_true_signed_same_revision_disagreement_preserved_as_conflict(self):
        path, sha = self._signed(observed_head_chain_raw_sha256='d'*64)
        result = r.evaluate(**self._opts(path, sha))
        self.assertEqual(result['status'], r.CONFLICT)
        self.assertTrue(result['same_revision_conflicting_signed_heads'])
        self.assertIsNone(result['signed_claims_corroborate_selected_candidate_raw_sha256'])
        self.assertEqual(r.verify(**self._opts(path, sha))['exit_code'], 2)

    def test_04_later_signed_revision_does_not_backfill_missing_history(self):
        for head in (self.cas_report['observed_head_chain_raw_sha256'], 'a'*64):
            path, sha = self._signed(observed_cas_revision=
                self.cas_report['observed_cas_revision']+4,
                observed_head_chain_raw_sha256=head)
            result = r.evaluate(**self._opts(path, sha))
            self.assertEqual(result['status'], r.LATER)
            self.assertIsNone(result['signed_claims_corroborate_selected_candidate_raw_sha256'])

    def test_05_earlier_signed_revision_is_stale_or_rollback_unknown(self):
        path, sha = self._signed(
            observed_cas_revision=self.cas_report['observed_cas_revision']-1,
            observed_head_chain_raw_sha256=OldCas.parent_sha)
        result = r.evaluate(**self._opts(path, sha))
        self.assertEqual(result['status'], r.EARLIER)
        self.assertFalse(result['actual_store_identity_or_linearizability_proven'])

    def test_06_next_observer_sequence_and_external_revision_regression_detection(self):
        first, first_sha = self._signed()
        ext = {**self.observer,
            'expected_readback_request_nonce_sha256': '8'*64,
            'expected_previous_readback_sequence': 1,
            'expected_previous_readback_raw_sha256': first_sha,
            'expected_previous_readback_observed_revision':
                self.cas_report['observed_cas_revision']}
        good, good_sha = self._signed(observer=ext)
        report = r.evaluate(**self._opts(good, good_sha, observer=ext))
        self.assertEqual(report['readback_sequence'], 2)
        self.assertEqual(report['status'], r.SAME)
        newer, newer_sha = self._signed(observer=ext,
            observed_cas_revision=self.cas_report['observed_cas_revision']-1)
        self.assertEqual(r.evaluate(**self._opts(newer, newer_sha, observer=ext))['status'],
                         r.REGRESSION)
        self.assertEqual(r.verify(**self._opts(newer, newer_sha, observer=ext))['exit_code'],2)

    def test_07_offline_anchor_nonce_namespace_and_stored_receipt_cross_binding(self):
        path, sha = self._signed()
        for changed in (
            {'expected_readback_request_nonce_sha256': OldCas.nonce},
            {'cas_store_namespace_id': 'other_namespace'},
            {'expected_previous_readback_sequence': 1,
             'expected_previous_readback_raw_sha256': 'f'*64,
             'expected_previous_readback_observed_revision': 0},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(a.AnchorError):
                    r.evaluate(**self._opts(path, sha,
                        observer={**self.observer, **changed}))
        with self.assertRaises(a.AnchorError):
            r.evaluate(**self._opts(path, 'f'*64))
        other, other_sha = OldCas._signed_file(
            selected_candidate_chain_raw_sha256=OldCas.candidates[1],
            observed_head_chain_raw_sha256=OldCas.candidates[1])
        with self.assertRaisesRegex(a.AnchorError, 'BOUND_TO_REPLAYED_DECISION'):
            r.evaluate(**self._opts(path, sha,
                cas_opts=OldCas._options(other, other_sha)))

    def test_08_signed_claim_tampering_even_with_recomputed_raw_sha(self):
        file, sha = self._signed()
        doc = json.loads(Path(file).read_text())
        doc['claim']['readback_request_nonce_sha256'] = 'a'*64
        forged, forged_sha = self._file(doc)
        with self.assertRaisesRegex(a.AnchorError, 'SIGNATURE_INVALID'):
            r.evaluate(**self._opts(forged, forged_sha, observer={
                **self.observer, 'expected_readback_request_nonce_sha256': 'a'*64}))

    def test_09_distinct_observer_key_from_cas_and_original_registrar(self):
        cas_key = OldCas.key
        cas_pub = OldCas.pub
        rb_claim = self._claim(observer={**self.observer,
            'observer_public_hex': cas_pub})
        path, sha = self._signed(key=cas_key, claim=rb_claim)
        with self.assertRaisesRegex(a.AnchorError, 'DISTINCT_FROM_CAS_AUTHORITY'):
            r.evaluate(**self._opts(path, sha, observer={
                **self.observer, 'observer_public_hex': cas_pub}))
        registrar_key = io.private_from_file(str(OldEpochs.third_private))
        registrar_pub = registrar_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()
        obs = {**self.observer, 'observer_public_hex': registrar_pub}
        path, sha = self._signed(key=registrar_key,
                                 claim=self._claim(observer=obs))
        with self.assertRaisesRegex(a.AnchorError, 'REUSES_KNOWN_ORIGINAL'):
            r.evaluate(**self._opts(path, sha, observer=obs))

    def test_10_validly_signed_extra_fields_or_unbounded_revision_denied(self):
        for mutated in ({'extra_authority': True},
                        {'observed_cas_revision': True},
                        {'readback_sequence': True},
                        {'observed_head_chain_raw_sha256': '0'*64}):
            path, sha = self._signed(**mutated)
            with self.subTest(mutated=mutated):
                with self.assertRaises(a.AnchorError):
                    r.evaluate(**self._opts(path, sha))

    def test_11_private_report_no_overwrite_and_exact_full_replay_not_boolean_trust(self):
        path, sha = self._signed()
        audit = str(self.home/'immutable-audit-report.json')
        result = r.verify(**self._opts(path, sha), out=audit)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(os.stat(audit).st_mode & 0o777, 0o600)
        self.assertEqual(b.digest(Path(audit).read_bytes()), result['audit_report_raw_sha256'])
        rebuilt = r.verify_report(**self._opts(path, sha), audit_report_file=audit,
            expected_audit_report_sha256=result['audit_report_raw_sha256'])
        self.assertEqual(rebuilt['exit_code'], 0)
        with self.assertRaises(a.AnchorError):
            r.verify(**self._opts(path, sha), out=audit)
        fake = json.loads(Path(audit).read_text())
        fake['globally_current_head_or_cas_tip_proven'] = True
        modified, modified_sha = self._file(fake)
        with self.assertRaisesRegex(a.AnchorError, 'DIFFERS_FROM_FULL_SIGNATURE_REPLAY'):
            r.verify_report(**self._opts(path, sha), audit_report_file=modified,
                expected_audit_report_sha256=modified_sha)

    def test_12_fixed_cli_and_console_permissions(self):
        path, sha = self._signed()
        common = [
            '--fork-case-file', self.cas_options['fork_case_file'],
            '--expected-fork-case-sha256', self.cas_options['expected_fork_case_sha256'],
            '--fork-evidence-file', self.cas_options['fork_evidence_file'],
            '--expected-fork-evidence-sha256', self.cas_options['expected_fork_evidence_sha256'],
            '--receipt-file', self.cas_path, '--expected-receipt-sha256', self.cas_sha,
            '--cas-authority-id', OldCas.trust['cas_authority_id'],
            '--cas-public-hex', OldCas.pub,
            '--request-nonce-sha256', OldCas.nonce,
            '--expected-parent-cas-revision', str(OldCas.revision),
            '--expected-parent-cas-head-sha256', OldCas.parent_sha,
            '--readback-file', path, '--expected-readback-sha256', sha,
            '--cas-store-namespace-id', self.observer['cas_store_namespace_id'],
            '--observer-id', self.observer['observer_id'],
            '--observer-public-hex', self.pub,
            '--readback-request-nonce-sha256', self.observer['expected_readback_request_nonce_sha256'],
            '--expected-previous-readback-sequence', '0',
            '--expected-previous-readback-raw-sha256', a.GENESIS,
            '--expected-previous-readback-observed-revision', 'none',
        ]
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
        def cmd(args, expected):
            proc = subprocess.run([sys.executable, '-I', '-B', *args],
                capture_output=True, text=True, timeout=480, env=env)
            self.assertEqual(proc.returncode, expected, proc.stdout+proc.stderr)
            return json.loads(proc.stdout.strip())
        script = str(ROOT/'scripts/ces_cas_readback.py')
        console = str(ROOT/'scripts/ces_next.py')
        result = cmd([script, 'verify', *common], 0)
        self.assertFalse(result['real_external_store_read_performed'])
        checked = cmd([console, 'audit-readback', 'DeliveryAudit',
            'VerifySignedCasReadback', *common], 0)
        self.assertTrue(checked['independent_observer_ed25519_signature_verified'])
        self.assertFalse(checked['current_global_latest_verified'])
        reject = cmd([console, 'audit-readback', 'DeliveryAudit',
            'CommitCas', *common], 3)
        self.assertIn('ONLY_DELIVERYAUDIT', reject['reason_code'])
        denied = subprocess.run([sys.executable, '-I', '-B', console,
            'audit-readback', 'DeliveryAudit', 'VerifySignedCasReadback',
            *common, '--out', path], capture_output=True, text=True,
            timeout=480, env=env)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn('unrecognized arguments', denied.stderr)


if __name__ == '__main__':
    unittest.main()
