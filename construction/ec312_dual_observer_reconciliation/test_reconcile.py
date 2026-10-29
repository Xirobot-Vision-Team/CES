#!/usr/bin/env python3
"""EC312 local functional fixtures: genuine Ed25519 EC294..309 original replay.

Keys and CAS/readback assertions here are LOCAL test-only simulations; no
real off-host CAS, key custodian, trusted time, live store or quorum is tested.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec295_delivery_anchor import anchor as a
from ec302_portable_bundle import bundle as b
from ec308_cas_receipt import receipt as cas
from ec308_cas_receipt.test_receipt import EC308CasReceiptCases as CasFixture
from ec309_cas_readback import readback as rb
from ec309_cas_readback.test_readback import EC309CasReadbackCases as ObsFixture
from ec311_cas_decision_history.test_decisions import EC311SignedDecisionHistoryCases as Prev
from . import reconcile as r

ROOT = Path(__file__).resolve().parents[2]


class EC312TwoObserverSignedWindowCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Prev.setUpClass()
        try:
            cls.second_key = Ed25519PrivateKey.generate()
            cls.second_pub = cls.second_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw).hex()
            cls.good = cls._build(Prev._manifest())
        except BaseException:
            Prev.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        Prev.tearDownClass()

    @classmethod
    def _pin(cls, value: dict, label: str = 'ec312-manifest') -> tuple[str, str]:
        return Prev._private_json(value, label)

    @classmethod
    def _build(cls, original: dict) -> dict:
        # Original EC311 provides genuine TWO distinct signed fork+CAS paths
        # and a genuine A-observer original EC309 readback for each decision.
        name_a = original['observer_id']
        name_b = 'second_independent_site'
        assert name_a < name_b
        boundary_a = original['boundary']
        boundary_b = copy.deepcopy(boundary_a)
        previous_b = {
            'sequence': boundary_b['sequence'],
            'raw_sha256': boundary_b['raw_sha256'],
            'observed_revision': boundary_b['observed_revision'],
        }
        entries = []
        for index, old in enumerate(original['decisions'], start=1):
            issuer_trust = {
                'cas_authority_id': original['cas_authority_id'],
                'cas_authority_public_hex': original['cas_authority_public_hex'],
                'expected_request_nonce_sha256': old['expected_request_nonce_sha256'],
                'expected_parent_cas_revision': old['expected_parent_cas_revision'],
                'expected_parent_cas_head_sha256': old['expected_parent_cas_head_sha256'],
            }
            common = {k: old[k] for k in r.DECISION_FIELDS if k != 'readbacks'}
            signed = cas.evaluate(
                fork_case_file=old['fork_case_file'],
                expected_fork_case_sha256=old['expected_fork_case_sha256'],
                fork_evidence_file=old['fork_evidence_file'],
                expected_fork_evidence_sha256=old['expected_fork_evidence_sha256'],
                receipt_file=old['receipt_file'],
                expected_receipt_sha256=old['expected_receipt_sha256'],
                trust=issuer_trust)
            nonce_b = ('c' + str(index))*32  # 64 hex bytes, distinct by index
            trust_b = {
                'cas_store_namespace_id': original['cas_store_namespace_id'],
                'observer_id': name_b,
                'observer_public_hex': cls.second_pub,
                'expected_readback_request_nonce_sha256': nonce_b,
                'expected_previous_readback_sequence': previous_b['sequence'],
                'expected_previous_readback_raw_sha256': previous_b['raw_sha256'],
                'expected_previous_readback_observed_revision': previous_b['observed_revision'],
            }
            claim_b = ObsFixture._claim(cas_report=signed, observer=trust_b)
            claim_b.update({
                'ec307_fork_case_raw_sha256': old['expected_fork_case_sha256'],
                'ec307_fork_evidence_raw_sha256': old['expected_fork_evidence_sha256'],
                'ec308_cas_receipt_raw_sha256': old['expected_receipt_sha256'],
                'original_cas_request_nonce_sha256': old['expected_request_nonce_sha256'],
            })
            file_b, sha_b = ObsFixture._signed(key=cls.second_key, claim=claim_b)
            entries.append({**common, 'readbacks': [
                {'observer_id': name_a, 'readback_file': old['readback_file'],
                 'expected_readback_sha256': old['expected_readback_sha256'],
                 'expected_readback_request_nonce_sha256':
                     old['expected_readback_request_nonce_sha256']},
                {'observer_id': name_b, 'readback_file': file_b,
                 'expected_readback_sha256': sha_b,
                 'expected_readback_request_nonce_sha256': nonce_b},
            ]})
            previous_b = {
                'sequence': claim_b['readback_sequence'],
                'raw_sha256': sha_b,
                'observed_revision': claim_b['observed_cas_revision'],
            }
        return {
            'schema': r.MANIFEST_SCHEMA,
            'cas_authority_id': original['cas_authority_id'],
            'cas_authority_public_hex': original['cas_authority_public_hex'],
            'cas_store_namespace_id': original['cas_store_namespace_id'],
            'observers': [
                {'observer_id': name_a,
                 'observer_public_hex': original['observer_public_hex'],
                 'boundary': copy.deepcopy(boundary_a)},
                {'observer_id': name_b, 'observer_public_hex': cls.second_pub,
                 'boundary': boundary_b},
            ],
            'decisions': entries,
        }

    @classmethod
    def _evaluate(cls, manifest: dict) -> dict:
        file, sha = cls._pin(manifest)
        return r.evaluate(manifest_file=file, expected_manifest_sha256=sha)

    @classmethod
    def _resign(cls, manifest: dict, index: int, observer_index: int,
                changes: dict, *, real_signature: bool = True) -> dict:
        updated = copy.deepcopy(manifest)
        item = updated['decisions'][index]['readbacks'][observer_index]
        content = json.loads(Path(item['readback_file']).read_text())
        content['claim'].update(changes)
        if real_signature:
            key = ObsFixture.key if observer_index == 0 else cls.second_key
            content['observer_signature_ed25519'] = key.sign(
                rb.DOMAIN + a.canonical(content['claim'])).hex()
        path, sha = cls._pin(content, 'ec312-resigned-readback')
        item.update(readback_file=path, expected_readback_sha256=sha)
        return updated

    def test_01_true_distinct_cas_and_dual_signed_readback_original_replay(self):
        report = self._evaluate(self.good)
        self.assertEqual(report['status'], r.GOOD)
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual(report['complete_distinct_cas_decision_count'], 2)
        self.assertEqual(report['complete_original_signed_readback_count'], 4)
        self.assertEqual(len(report['signed_cas_and_dual_observation_records']), 2)
        self.assertTrue(report['each_observer_replayed_all_original_ec294_through_ec309_crypto'])
        self.assertFalse(report['actual_global_latest_or_linearizable_state_proven'])
        self.assertNotIn(str(Prev.home), json.dumps(report))

    def test_02_authentically_signed_cross_observer_same_revision_head_conflict(self):
        modified = self._resign(self.good, 1, 1, {
            'observed_head_chain_raw_sha256':'d'*64})
        report = self._evaluate(modified)
        self.assertEqual(report['status'], r.CROSS_CONFLICT)
        self.assertEqual(report['exit_code'], 2)
        self.assertTrue(report['cross_observer_same_revision_signed_head_conflicts'])
        self.assertIsNone(report['last_candidate_sha256_of_compatible_signed_claims_only'])

    def test_03_authentic_observer_later_revision_not_promoted_to_success(self):
        modified = self._resign(self.good, 1, 1, {
            'observed_cas_revision': CasFixture.revision+3})
        report = self._evaluate(modified)
        self.assertEqual(report['status'], r.DIFFERENT_REVISIONS)
        self.assertEqual(report['different_observer_revisions_at_same_decisions'], [2])
        self.assertEqual(report['exit_code'], 2)

    def test_04_authentic_single_observer_revision_regression(self):
        modified = self._resign(self.good, 1, 1, {
            'observed_cas_revision': CasFixture.revision})
        report = self._evaluate(modified)
        self.assertEqual(report['status'], r.ROLLBACK)
        self.assertEqual(report['signed_observer_revision_rollbacks'][0]['observer_id'],
                         'second_independent_site')

    def test_05_authentic_single_observer_same_revision_different_head(self):
        modified = self._resign(self.good, 1, 1, {
            'observed_cas_revision': CasFixture.revision+1,
            'observed_head_chain_raw_sha256':'d'*64})
        report = self._evaluate(modified)
        self.assertEqual(report['status'], r.SELF_CONFLICT)
        self.assertTrue(report['same_observer_signed_head_conflicts'])

    def test_06_new_original_signed_old_parent_decision_is_not_contiguous(self):
        report = self._evaluate(self._build(Prev._manifest(second_repeat_parent=True)))
        self.assertEqual(report['status'], r.BROKEN_PARENT)
        self.assertEqual(report['cas_parent_discontinuity_at_decisions'], [2])

    def test_07_reused_signer_key_id_or_role_nonce_denied_before_replay(self):
        for field, value in (
            ('observer_public_hex', self.good['observers'][0]['observer_public_hex']),
            ('observer_id', self.good['observers'][0]['observer_id']),
        ):
            modified = copy.deepcopy(self.good)
            modified['observers'][1][field] = value
            with self.subTest(field=field), self.assertRaises(a.AnchorError):
                self._evaluate(modified)
        modified = copy.deepcopy(self.good)
        modified['decisions'][1]['readbacks'][1][
            'expected_readback_request_nonce_sha256'] = \
            self.good['decisions'][0]['expected_request_nonce_sha256']
        with self.assertRaisesRegex(a.AnchorError, 'EC312_ANY_ROLE_QUERY_NONCE_REUSED'):
            self._evaluate(modified)

    def test_08_rehashed_forged_original_readback_without_real_signature_denied(self):
        modified = self._resign(self.good, 1, 1,
                                {'observed_head_chain_raw_sha256':'e'*64},
                                real_signature=False)
        with self.assertRaisesRegex(a.AnchorError, 'EC309_OBSERVER_ED25519_SIGNATURE_INVALID'):
            self._evaluate(modified)

    def test_09_true_resigned_observer_with_broken_prior_raw_sha_denied(self):
        modified = self._resign(self.good, 1, 1,
                                {'previous_readback_raw_sha256': 'f'*64})
        with self.assertRaisesRegex(a.AnchorError, 'EC309_SIGNED_READBACK_NOT_BOUND'):
            self._evaluate(modified)

    def test_10_independent_manifest_pin_strict_shapes_and_private_evidence(self):
        path, _ = self._pin(self.good)
        with self.assertRaises(a.AnchorError):
            r.evaluate(manifest_file=path, expected_manifest_sha256='f'*64)
        wrong = copy.deepcopy(self.good)
        wrong['decisions'][0]['expected_parent_cas_revision'] = True
        with self.assertRaisesRegex(a.AnchorError, 'EC312_PARENT_CAS_REVISION_INTEGER_INVALID'):
            self._evaluate(wrong)
        wrong = copy.deepcopy(self.good)
        wrong['decisions'][0]['readbacks'][1]['readback_file'] = 'relative/file.json'
        with self.assertRaisesRegex(a.AnchorError, 'EC312_SIGNED_READBACK_PATH_MUST_BE_ABSOLUTE'):
            self._evaluate(wrong)
        wrong = copy.deepcopy(self.good)
        wrong['decisions'][0]['surprise'] = True
        with self.assertRaises(a.AnchorError):
            self._evaluate(wrong)

    def test_11_private_report_exclusive_and_independent_full_replay(self):
        path, sha = self._pin(self.good)
        output = str(Prev.home/'ec312-dual-window-audit.json')
        result = r.verify(manifest_file=path, expected_manifest_sha256=sha,
                          out=output)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
        self.assertEqual(result['audit_report_raw_sha256'],
                         b.digest(Path(output).read_bytes()))
        checked = r.verify_report(
            manifest_file=path, expected_manifest_sha256=sha,
            audit_report_file=output,
            expected_audit_report_sha256=result['audit_report_raw_sha256'])
        self.assertEqual(checked['exit_code'], 0)
        with self.assertRaises(a.AnchorError):
            r.verify(manifest_file=path, expected_manifest_sha256=sha, out=output)

    @classmethod
    def _run(cls, script, flags, expected):
        done = subprocess.run([sys.executable, '-I', '-B', str(ROOT/'scripts'/script),
                               *flags], capture_output=True, text=True, timeout=480,
                              env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        assert done.returncode == expected, (done.stdout, done.stderr)
        return json.loads(done.stdout.strip())

    def test_12_standalone_and_unified_console_true_signed_replay(self):
        file, sha = self._pin(self.good)
        flags = ['--manifest-file', file, '--expected-manifest-sha256', sha]
        cli = self._run('ces_cas_observers.py', ['verify', *flags], 0)
        self.assertEqual(cli['schema'], r.RESULT_SCHEMA)
        self.assertEqual(cli['complete_original_signed_readback_count'], 4)
        console = self._run('ces_next.py',
            ['audit-observers', 'DeliveryAudit', 'ReconcileTwoSignedCasObservers',
             *flags], 0)
        self.assertEqual(console['status'], r.GOOD)
        self.assertFalse(console['external_cas_access_performed'])

    def test_13_independently_opaque_non_genesis_b_window(self):
        manifest = copy.deepcopy(self.good)
        opaque = 'e'*64
        manifest['observers'][1]['boundary'] = {
            'sequence': 5, 'raw_sha256': opaque,
            'observed_revision': CasFixture.revision,
            'observed_head_raw_sha256': CasFixture.parent_sha,
        }
        manifest = self._resign(manifest, 0, 1, {
            'readback_sequence': 6,
            'previous_readback_raw_sha256': opaque,
            'previous_readback_observed_revision': CasFixture.revision,
        })
        first_sha = manifest['decisions'][0]['readbacks'][1][
            'expected_readback_sha256']
        manifest = self._resign(manifest, 1, 1, {
            'readback_sequence': 7,
            'previous_readback_raw_sha256': first_sha,
        })
        report = self._evaluate(manifest)
        self.assertEqual(report['status'], r.GOOD)
        self.assertFalse(report['both_observers_genesis_to_last_record_included'])
        self.assertFalse(report['earlier_non_genesis_observer_or_cas_records_replayed'])

    def test_14_cross_site_namespace_or_identity_injection_resigned_denied(self):
        for change in ({'observer_id':'hijacked_observer'},
                       {'cas_store_namespace_id':'other_namespace'}):
            changed = self._resign(self.good, 1, 1, change)
            with self.subTest(change=change), self.assertRaisesRegex(
                    a.AnchorError, 'EC309_SIGNED_READBACK_NOT_BOUND'):
                self._evaluate(changed)

    def test_15_readonly_console_refuses_unknown_action_and_write_option(self):
        file, sha = self._pin(self.good)
        flags = ['--manifest-file', file, '--expected-manifest-sha256', sha]
        denied = self._run('ces_next.py',
            ['audit-observers', 'DeliveryAudit', 'ApproveCasCommit', *flags], 3)
        self.assertEqual(denied['reason_code'],
                         'EC312_ONLY_DELIVERYAUDIT_RECONCILE_TWO_SIGNED_CAS_OBSERVERS')
        done = subprocess.run([sys.executable, '-I', '-B', str(ROOT/'scripts'/'ces_next.py'),
                               'audit-observers','DeliveryAudit',
                               'ReconcileTwoSignedCasObservers', *flags,
                               '--out', '/tmp/forbidden'],
                              capture_output=True, text=True, timeout=20)
        self.assertNotEqual(done.returncode, 0)
