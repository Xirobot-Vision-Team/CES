#!/usr/bin/env python3
"""EC311 functional fixtures: genuine original EC294..309 signatures, LOCAL keys.

All CAS issuer and observer claims are test-only locally signed assertions.
Not a production store, trusted nonce issuer, authority, or off-host test.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from registrar_epochs import epochs as e
from registrar_epochs.test_epochs import EC306EpochCases as Base
from registrar_forks import forks
from registrar_forks.test_forks import EC307ForkCases as Forks
from cas_receipt import receipt as cas
from cas_receipt.test_receipt import EC308CasReceiptCases as CasFixture
from cas_readback import readback as rb
from cas_readback.test_readback import EC309CasReadbackCases as ObserverFixture
from . import decisions as d

ROOT = Path(__file__).resolve().parents[2]


class EC311SignedDecisionHistoryCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ObserverFixture.setUpClass()
        try:
            cls.tmp = tempfile.TemporaryDirectory(prefix='ec311-signed-decisions-')
            cls.home = Path(cls.tmp.name)
            # The FIRST original EC307 fork has s4 as parent and includes s5.
            # The SECOND is a NEW original EC307 fork with s5 as its parent.
            # Neither original branch is fabricated by modifying its index.
            cls.head1 = Base.s5['external']['chain_raw_sha256']
            assert cls.head1 in CasFixture.candidates
            branches = []
            for ix, challenge in enumerate(('0c'*32, '0d'*32)):
                ctx = Forks._signed_ack(f'ec311-second-step-{ix}', challenge)
                signed_file = cls.home/f'second-step-{ix}-ledger.json'
                signed = e.register(**Base.s5, **ctx,
                    active_private_key_file=Base.third_private,
                    out=str(signed_file))
                index_file = cls.home/f'second-step-{ix}-index.json'
                result = e.commit(**Base.s5, **ctx,
                    candidate_ledger_file=str(signed_file),
                    expected_candidate_ledger_sha256=signed['ledger_raw_sha256'],
                    expected_candidate_sequence=2,
                    out=str(index_file))
                stage = {
                    'chain_file': str(index_file),
                    'external': Base._external(result),
                    'ledger_files': Base.s5['ledger_files'][:-1]+[str(signed_file)],
                    'certificate_files': Base.s5['certificate_files'],
                }
                branches.append(Forks._branch(stage, ctx))
            cls.head2 = branches[0]['expected_chain_raw_sha256']
            cls.case2 = Forks._case(Base.s5, branches[0], branches[1])
            cls.case2_file = cls.home/'second-original-fork-case.json'
            store.store(str(cls.case2_file), cls.case2, e.MAX_CHAIN_BYTES)
            cls.case2_sha = b.digest(cls.case2_file.read_bytes())
            cls.fork2_file = cls.home/'second-original-fork-evidence.json'
            parent = cls.case2['parent']
            result = forks.compare(
                parent_chain_file=parent['chain_file'],
                parent_external=parent['external'],
                parent_ledger_files=parent['ledger_files'],
                parent_certificate_files=parent['certificate_files'],
                candidate_a=cls.case2['candidate_a'],
                candidate_b=cls.case2['candidate_b'],
                out=str(cls.fork2_file))
            cls.fork2_sha = result['evidence_report_raw_sha256']
            cls.fork2_report = forks._read_report(str(cls.fork2_file), cls.fork2_sha)
            assert cls.head2 in cls.fork2_report['external_cas_handoff'][
                'allowed_candidate_chain_raw_sha256']
            cls.one_nonce = 'a1'*32
            cls.two_nonce = 'a2'*32
            cls.one_obsnonce = 'b1'*32
            cls.two_obsnonce = 'b2'*32
            cls.counter = 0
        except BaseException:
            if hasattr(cls, 'tmp'):
                cls.tmp.cleanup()
            ObserverFixture.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        ObserverFixture.tearDownClass()

    @classmethod
    def _private_json(cls, data: dict, name: str = 'test') -> tuple[str, str]:
        cls.counter += 1
        path = cls.home/f'{name}-{cls.counter:04d}.json'
        store.store(str(path), data, 64_000)
        return str(path), b.digest(path.read_bytes())

    @classmethod
    def _issuer(cls, first: bool, *, fail: bool = False) -> tuple[dict, dict]:
        nonce = cls.one_nonce if first else cls.two_nonce
        head = cls.head1 if first else cls.head2
        parent_rev = CasFixture.revision if first else CasFixture.revision+1
        parent_head = CasFixture.parent_sha if first else cls.head1
        case_sha = str(Forks.case_sha if first else cls.case2_sha)
        fork_sha = str(CasFixture.fork_sha if first else cls.fork2_sha)
        handoff = (CasFixture.fork_report if first else cls.fork2_report)[
            'external_cas_handoff']
        claim = {
            **CasFixture._claim(),
            'ec307_fork_evidence_raw_sha256': fork_sha,
            'ec307_choice_request_raw_sha256': b.digest(b.canonical(handoff)),
            'request_nonce_sha256': nonce,
            'expected_parent_chain_raw_sha256': parent_head,
            'candidate_chain_raw_sha256': handoff['allowed_candidate_chain_raw_sha256'],
            'expected_parent_cas_revision': parent_rev,
            'expected_parent_cas_head_sha256': parent_head,
            'outcome': ('compare_exchange_precondition_failed_claim' if fail
                        else 'compare_exchange_committed_claim'),
            'observed_cas_revision': parent_rev + 1,
            'observed_head_chain_raw_sha256': 'e'*64 if fail else head,
            'selected_candidate_chain_raw_sha256': None if fail else head,
        }
        receipt_file, receipt_sha = CasFixture._signed_file(claim=claim)
        cas_trust = {
            **CasFixture.trust,
            'expected_request_nonce_sha256': nonce,
            'expected_parent_cas_revision': parent_rev,
            'expected_parent_cas_head_sha256': parent_head,
        }
        original = {
            'fork_case_file': str(Forks.case_path if first else cls.case2_file),
            'expected_fork_case_sha256': case_sha,
            'fork_evidence_file': str(CasFixture.fork_path if first else cls.fork2_file),
            'expected_fork_evidence_sha256': fork_sha,
            'receipt_file': receipt_file,
            'expected_receipt_sha256': receipt_sha,
            'expected_request_nonce_sha256': nonce,
            'expected_parent_cas_revision': parent_rev,
            'expected_parent_cas_head_sha256': parent_head,
        }
        report = cas.evaluate(
            fork_case_file=original['fork_case_file'],
            expected_fork_case_sha256=case_sha,
            fork_evidence_file=original['fork_evidence_file'],
            expected_fork_evidence_sha256=fork_sha,
            receipt_file=receipt_file, expected_receipt_sha256=receipt_sha,
            trust=cas_trust)
        return original, report

    @classmethod
    def _observation(cls, original: dict, cas_report: dict, *,
                     nonce: str, previous: dict, observed_rev=None,
                     observed_head=None) -> dict:
        trust = {
            **ObserverFixture.observer,
            'expected_readback_request_nonce_sha256': nonce,
            'expected_previous_readback_sequence': previous['sequence'],
            'expected_previous_readback_raw_sha256': previous['raw_sha256'],
            'expected_previous_readback_observed_revision': previous['revision'],
        }
        claim = ObserverFixture._claim(cas_report=cas_report, observer=trust)
        claim.update({
            'ec307_fork_case_raw_sha256': original['expected_fork_case_sha256'],
            'ec307_fork_evidence_raw_sha256': original['expected_fork_evidence_sha256'],
            'ec308_cas_receipt_raw_sha256': original['expected_receipt_sha256'],
            'original_cas_request_nonce_sha256': original['expected_request_nonce_sha256'],
        })
        if observed_rev is not None:
            claim['observed_cas_revision'] = observed_rev
        if observed_head is not None:
            claim['observed_head_chain_raw_sha256'] = observed_head
        path, sha = ObserverFixture._signed(claim=claim)
        return {**original, 'readback_file': path,
                'expected_readback_sha256': sha,
                'expected_readback_request_nonce_sha256': nonce}

    @classmethod
    def _manifest(cls, *, first=None, second=None,
                  second_fail=False, second_observed_rev=None,
                  second_observed_head=None, second_repeat_parent=False) -> dict:
        old, report1 = cls._issuer(True)
        new, report2 = cls._issuer(False, fail=second_fail)
        if second_repeat_parent:
            # A second authentic independently signed issuer decision with
            # the *old* fork parent, but a new nonce and a new signed receipt.
            again_claim = {**CasFixture._claim(),
                'request_nonce_sha256': cls.two_nonce,
                'observed_head_chain_raw_sha256': cls.head1,
                'selected_candidate_chain_raw_sha256': cls.head1}
            again_path, again_sha = CasFixture._signed_file(claim=again_claim)
            new = {**old, 'receipt_file':again_path,
                   'expected_receipt_sha256':again_sha,
                   'expected_request_nonce_sha256':cls.two_nonce}
            report2 = cas.evaluate(
                fork_case_file=new['fork_case_file'],
                expected_fork_case_sha256=new['expected_fork_case_sha256'],
                fork_evidence_file=new['fork_evidence_file'],
                expected_fork_evidence_sha256=new['expected_fork_evidence_sha256'],
                receipt_file=new['receipt_file'],
                expected_receipt_sha256=new['expected_receipt_sha256'],
                trust={**CasFixture.trust,
                       'expected_request_nonce_sha256':cls.two_nonce})
        start = {'sequence':0,'raw_sha256':a.GENESIS,'revision':None}
        first_item = cls._observation(old, report1,
                                      nonce=cls.one_obsnonce, previous=start)
        second_item = cls._observation(new, report2,
                    nonce=cls.two_obsnonce, previous={
                        'sequence':1,
                        'raw_sha256':first_item['expected_readback_sha256'],
                        'revision':report1['observed_cas_revision'],
                    }, observed_rev=second_observed_rev,
                    observed_head=second_observed_head)
        return {
            'schema': d.MANIFEST_SCHEMA,
            'cas_authority_id': CasFixture.trust['cas_authority_id'],
            'cas_authority_public_hex': CasFixture.pub,
            'cas_store_namespace_id': ObserverFixture.observer['cas_store_namespace_id'],
            'observer_id': ObserverFixture.observer['observer_id'],
            'observer_public_hex': ObserverFixture.pub,
            'boundary': {'sequence':0,'raw_sha256':a.GENESIS,
                         'observed_revision':None,
                         'observed_head_raw_sha256':None},
            'decisions': [first_item if first is None else first,
                          second_item if second is None else second],
        }

    @classmethod
    def _eval(cls, manifest: dict):
        file, sha = cls._private_json(manifest, 'manifest')
        return d.evaluate(manifest_file=file, expected_manifest_sha256=sha)

    @classmethod
    def _re_sign_observation(cls, record: dict, updates: dict) -> dict:
        doc = json.loads(Path(record['readback_file']).read_text())
        doc['claim'].update(updates)
        doc['observer_signature_ed25519'] = ObserverFixture.key.sign(
            rb.DOMAIN + a.canonical(doc['claim'])).hex()
        file, sha = cls._private_json(doc, 'resigned-observer')
        return {**record, 'readback_file': file,
                'expected_readback_sha256': sha}

    @classmethod
    def _cli(cls, script: str, flags: list[str], expected: int) -> dict:
        proc = subprocess.run([sys.executable, '-I', '-B', str(ROOT/'scripts'/script),
                               *flags], capture_output=True, text=True,
                              timeout=480,
                              env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'})
        assert proc.returncode == expected, (proc.stdout, proc.stderr)
        return json.loads(proc.stdout.strip())

    def test_01_two_distinct_real_signed_cas_commits_replayed_from_two_forks(self):
        manifest = self._manifest()
        report = self._eval(manifest)
        self.assertEqual(report['status'], d.GOOD)
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual(report['complete_decision_and_observation_count'], 2)
        records = report['signed_decision_observation_records']
        self.assertNotEqual(records[0]['signed_cas_receipt_raw_sha256'],
                            records[1]['signed_cas_receipt_raw_sha256'])
        self.assertNotEqual(records[0]['original_fork_case_raw_sha256'],
                            records[1]['original_fork_case_raw_sha256'])
        self.assertEqual(records[0]['signed_decision_head_raw_sha256'], self.head1)
        self.assertEqual(records[1]['parent_head_raw_sha256'], self.head1)
        self.assertEqual(records[1]['signed_decision_head_raw_sha256'], self.head2)
        self.assertTrue(report['each_decision_full_ec294_through_ec309_original_signatures_replayed'])
        self.assertFalse(report['actual_cas_commit_or_global_latest_proven'])
        self.assertNotIn(str(self.home), json.dumps(report))

    def test_02_two_authentic_commits_with_repeated_old_parent_have_no_winner(self):
        result = self._eval(self._manifest(second_repeat_parent=True))
        self.assertEqual(result['status'], d.PARENT_DISCONTINUITY)
        self.assertEqual(result['cas_parent_discontinuity_at_sequences'], [2])
        self.assertIsNone(result['last_candidate_sha256_of_consistent_signed_claims_only'])

    def test_03_authentic_readback_revision_rollback_detected(self):
        result = self._eval(self._manifest(second_observed_rev=CasFixture.revision-1))
        self.assertEqual(result['status'], d.OBSERVATION_ROLLBACK)
        self.assertEqual(result['observer_revision_regression_at_sequences'], [2])
        self.assertEqual(result['exit_code'], 2)

    def test_04_same_revision_signed_head_equivocation_detected(self):
        result = self._eval(self._manifest(
            second_observed_rev=CasFixture.revision+1,
            second_observed_head='d'*64))
        self.assertEqual(result['status'], d.OBSERVATION_EQUIVOCATION)
        self.assertEqual(result['observer_same_revision_conflicting_head_at_sequences'], [2])
        self.assertIsNone(result['last_candidate_sha256_of_consistent_signed_claims_only'])

    def test_05_failed_precondition_never_promoted_to_chain_success(self):
        result = self._eval(self._manifest(second_fail=True))
        self.assertEqual(result['status'], d.NOT_CORROBORATED)
        self.assertEqual(result['issuer_decision_or_observer_not_corroborated_at_sequences'], [2])
        self.assertIsNone(result['last_candidate_sha256_of_consistent_signed_claims_only'])

    def test_06_cas_receipt_tampered_and_re_sha_pinned_still_denied(self):
        manifest = self._manifest()
        record = manifest['decisions'][1]
        forged = json.loads(Path(record['receipt_file']).read_text())
        forged['claim']['observed_head_chain_raw_sha256'] = 'f'*64
        raw, sha = self._private_json(forged,'forged-issuer')
        replaced = {**record,'receipt_file':raw,'expected_receipt_sha256':sha}
        replaced = self._re_sign_observation(replaced, {
            'ec308_cas_receipt_raw_sha256':sha})
        manifest['decisions'][1]=replaced
        with self.assertRaisesRegex(a.AnchorError, 'EC308_.*SIGNATURE_INVALID'):
            self._eval(manifest)

    def test_07_observer_link_discontinuity_still_denied_if_resigned(self):
        manifest = self._manifest()
        manifest['decisions'][1] = self._re_sign_observation(
            manifest['decisions'][1], {'previous_readback_raw_sha256':'f'*64})
        with self.assertRaisesRegex(a.AnchorError,
                                    'EC309_.*SIGNED_READBACK_NOT_BOUND'):
            self._eval(manifest)

    def test_08_cross_namespace_or_observer_splice_denied(self):
        for updates in ({'cas_store_namespace_id':'other_namespace'},
                        {'observer_id':'other_readback_site'}):
            with self.subTest(updates=updates):
                manifest = self._manifest()
                manifest['decisions'][1] = self._re_sign_observation(
                    manifest['decisions'][1], updates)
                with self.assertRaisesRegex(a.AnchorError,
                                            'EC309_.*SIGNED_READBACK_NOT_BOUND'):
                    self._eval(manifest)

    def test_09_nonce_replay_and_duplicate_signatures_denied_before_replay(self):
        manifest = self._manifest()
        manifest['decisions'][1]['expected_request_nonce_sha256'] = self.one_nonce
        with self.assertRaisesRegex(a.AnchorError, 'EC311_CAS_AND_OBSERVER_QUERY_NONCES'):
            self._eval(manifest)
        manifest = self._manifest()
        manifest['decisions'][1]['expected_receipt_sha256'] = \
            manifest['decisions'][0]['expected_receipt_sha256']
        with self.assertRaisesRegex(a.AnchorError, 'EC311_DUPLICATE_SIGNED_CAS_DECISION'):
            self._eval(manifest)

    def test_10_strict_manifest_pins_shapes_and_boundary(self):
        manifest = self._manifest()
        path, sha = self._private_json(manifest, 'pinned-manifest')
        with self.assertRaises(a.AnchorError):
            d.evaluate(manifest_file=path, expected_manifest_sha256='f'*64)
        for change in (
            {'schema':'wrong-schema'},
            {'decisions':manifest['decisions'][:1]},
            {'decisions':manifest['decisions']*5},
            {'boundary':{**manifest['boundary'],'observed_head_raw_sha256':'f'*64}},
        ):
            with self.subTest(change=list(change)):
                with self.assertRaises(a.AnchorError):
                    self._eval({**manifest, **change})
        invalid = self._manifest()
        invalid['decisions'][1]['expected_parent_cas_revision'] = True
        with self.assertRaisesRegex(a.AnchorError,'CAS_PARENT_REVISION_INTEGER_INVALID'):
            self._eval(invalid)
        invalid = self._manifest()
        invalid['decisions'][1]['receipt_file'] = 'not/absolute'
        with self.assertRaisesRegex(a.AnchorError,'ALL_ORIGINAL_EVIDENCE_PATHS_MUST_BE_ABSOLUTE'):
            self._eval(invalid)
        invalid = self._manifest()
        invalid['decisions'][1]['unexpected_field'] = 'foo'
        with self.assertRaises(a.AnchorError):
            self._eval(invalid)

    def test_11_audit_report_private_exclusive_and_replay_detects_tampering(self):
        manifest = self._manifest()
        path, sha = self._private_json(manifest, 'manifest-report')
        audit = str(self.home/'cross-decision-audit.json')
        result = d.verify(manifest_file=path, expected_manifest_sha256=sha,
                          out=audit)
        self.assertTrue(result['audit_report_written'])
        self.assertEqual(result['exit_code'],0)
        self.assertEqual(os.stat(audit).st_mode & 0o777, 0o600)
        self.assertEqual(b.digest(Path(audit).read_bytes()),result['audit_report_raw_sha256'])
        checked = d.verify_report(manifest_file=path,expected_manifest_sha256=sha,
            audit_report_file=audit,
            expected_audit_report_sha256=result['audit_report_raw_sha256'])
        self.assertEqual(checked['exit_code'],0)
        with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OUTPUT_OR_FSYNC'):
            d.verify(manifest_file=path,expected_manifest_sha256=sha,out=audit)
        old = json.loads(Path(audit).read_text())
        old['actual_cas_commit_or_global_latest_proven']=True
        corrupt, corrupt_sha = self._private_json(old,'false-audit-claim')
        with self.assertRaisesRegex(a.AnchorError,'SAVED_AUDIT_REPORT_DIFFERS'):
            d.verify_report(manifest_file=path,expected_manifest_sha256=sha,
                audit_report_file=corrupt,expected_audit_report_sha256=corrupt_sha)

    def test_12_standalone_cli_console_allow_exact_read_only_and_deny_write(self):
        manifest = self._manifest()
        path, sha = self._private_json(manifest,'cli-manifest')
        cli = self._cli('ces_cas_decisions.py', ['verify','--manifest-file',path,
            '--expected-manifest-sha256',sha],0)
        self.assertEqual(cli['status'],d.GOOD)
        flags = ['audit-decisions','DeliveryAudit','VerifySignedCasDecisionHistory',
                 '--manifest-file',path,'--expected-manifest-sha256',sha]
        result = self._cli('ces_next.py',flags,0)
        self.assertEqual(result['status'],d.GOOD)
        self.assertFalse(result['external_cas_access_performed'])
        denied = self._cli('ces_next.py', [*flags[:2],'CommitCas',*flags[3:]],3)
        self.assertEqual(denied['status'],'permission_denied')
        proc = subprocess.run([sys.executable,'-I','-B',
                    str(ROOT/'scripts'/'ces_next.py'), *flags,'--out',str(self.home/'x')],
                   capture_output=True,text=True)
        self.assertNotEqual(proc.returncode,0)
        self.assertFalse((self.home/'x').exists())

    def test_13_standalone_cli_reports_true_signed_conflict_and_verify_report(self):
        manifest = self._manifest(second_fail=True)
        path, sha = self._private_json(manifest,'cli-failure-manifest')
        audit = str(self.home/'failed-audit.json')
        cli = self._cli('ces_cas_decisions.py', ['verify',
            '--manifest-file',path,'--expected-manifest-sha256',sha,
            '--out',audit],2)
        self.assertEqual(cli['status'],d.NOT_CORROBORATED)
        checked = self._cli('ces_cas_decisions.py', ['verify-report',
            '--manifest-file',path,'--expected-manifest-sha256',sha,
            '--audit-report-file',audit,
            '--expected-audit-report-sha256',cli['audit_report_raw_sha256']],2)
        self.assertEqual(checked['status'],d.NOT_CORROBORATED)
        console = self._cli('ces_next.py',['audit-decisions','DeliveryAudit',
            'VerifySignedCasDecisionHistory','--manifest-file',path,
            '--expected-manifest-sha256',sha],2)
        self.assertEqual(console['status'],d.NOT_CORROBORATED)

    def test_14_opaque_non_genesis_boundary_joins_first_signed_parent_exactly(self):
        manifest = self._manifest()
        # An operator separately pins a boundary record outside the window.
        # This test intentionally does NOT authenticate the unseen boundary.
        boundary_sha = 'd'*64
        manifest['boundary'] = {
            'sequence': 1, 'raw_sha256': boundary_sha,
            'observed_revision': CasFixture.revision,
            'observed_head_raw_sha256': CasFixture.parent_sha,
        }
        first = self._re_sign_observation(manifest['decisions'][0], {
            'readback_sequence': 2,
            'previous_readback_raw_sha256': boundary_sha,
            'previous_readback_observed_revision': CasFixture.revision,
        })
        second = self._re_sign_observation(manifest['decisions'][1], {
            'readback_sequence': 3,
            'previous_readback_raw_sha256': first['expected_readback_sha256'],
        })
        manifest['decisions'] = [first, second]
        report = self._eval(manifest)
        self.assertEqual(report['status'], d.GOOD)
        self.assertFalse(report['observer_genesis_to_current_sequence_included'])
        self.assertFalse(report['outside_window_earlier_cas_decisions_or_observations_replayed'])
        manifest['boundary']['observed_head_raw_sha256'] = 'e'*64
        result = self._eval(manifest)
        self.assertEqual(result['status'], d.PARENT_DISCONTINUITY)
        self.assertEqual(result['cas_parent_discontinuity_at_sequences'], [2])

    def test_15_private_manifest_permissions_and_undocumented_field_fail_closed(self):
        manifest = self._manifest()
        path, sha = self._private_json(manifest, 'private-manifest')
        os.chmod(path, 0o644)
        with self.assertRaises(a.AnchorError):
            d.read_manifest(path, sha)
        os.chmod(path, 0o600)
        manifest['new_untrusted_permission'] = True
        with self.assertRaises(a.AnchorError):
            self._eval(manifest)
