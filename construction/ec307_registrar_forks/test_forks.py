#!/usr/bin/env python3
"""EC307 limited focused behavior checks, genuine EC294->EC306 signed fixture.

Local-only: no claim of a real off-host atomic compare-and-swap, governance
selection, live Provider, cross-OS or full release acceptance.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as store
from ec302_portable_bundle import bundle as b
from ec303_receiver_ack import ack
from ec306_registrar_epochs import epochs as e
from ec306_registrar_epochs.test_epochs import EC306EpochCases as Base
from ec305_registrar_rollover.test_rollover import EC305RolloverCases as Early
from . import forks as f
from .operator import CASE_SCHEMA, read_case

ROOT=Path(__file__).resolve().parents[2]


class EC307ForkCases(unittest.TestCase):
    @classmethod
    def _signed_ack(cls, name: str, challenge: str) -> dict:
        # The EC305 inherited fixture is the issuer of EC302 import material.
        path=cls.home/(name+'-ack.json')
        result=ack.issue_ack(
            **{**Early.base.parent.context,'challenge_sha256':challenge},
            imported_dir=str(Early.base.parent.imported),
            receiver_private_key_file=str(Early.base.parent.private),
            out=str(path))
        return {**Base.thirdctx,'challenge_sha256':challenge,
                'acknowledgement_file':str(path),
                'expected_acknowledgement_sha256':result['acknowledgement_sha256']}

    @classmethod
    def _branch(cls, stage: dict, proof: dict | None = None) -> dict:
        return {
            'chain_file':stage['chain_file'],
            'expected_chain_raw_sha256':stage['external']['chain_raw_sha256'],
            'ledger_files':stage['ledger_files'],
            'certificate_files':stage['certificate_files'],
            'ack_proof':proof}

    @classmethod
    def _case(cls, base: dict, one: dict, two: dict) -> dict:
        return {'schema':CASE_SCHEMA,
                'parent':{
                    'chain_file':base['chain_file'],
                    'external':base['external'],
                    'ledger_files':base['ledger_files'],
                    'certificate_files':base['certificate_files']},
                'candidate_a':one,'candidate_b':two}

    @classmethod
    def setUpClass(cls):
        Base.setUpClass()
        try:
            cls.tmp=tempfile.TemporaryDirectory(prefix='ec307-two-forks-')
            cls.home=Path(cls.tmp.name)
            cls.otherctx=cls._signed_ack('second-child','f'*64)
            cls.other_ledger=cls.home/'second-verified-signed-ledger.json'
            cls.other_signed=e.register(**Base.s4,**cls.otherctx,
                active_private_key_file=Base.third_private,
                out=str(cls.other_ledger))
            cls.other_index=cls.home/'second-committed-index.json'
            cls.other_response=e.commit(**Base.s4,**cls.otherctx,
                candidate_ledger_file=str(cls.other_ledger),
                expected_candidate_ledger_sha256=cls.other_signed['ledger_raw_sha256'],
                expected_candidate_sequence=1,out=str(cls.other_index))
            cls.other_stage={
                'chain_file':str(cls.other_index),
                'external':Base._external(cls.other_response),
                'ledger_files':Base.s4['ledger_files']+[str(cls.other_ledger)],
                'certificate_files':Base.s4['certificate_files']}
            cls.case=cls._case(Base.s4,
                cls._branch(Base.s5,Base.thirdctx),
                cls._branch(cls.other_stage,cls.otherctx))
            cls.case_path=cls.home/'candidate-case.json'
            store.store(str(cls.case_path),cls.case,e.MAX_CHAIN_BYTES)
            cls.case_sha=b.digest(cls.case_path.read_bytes())
        except BaseException:
            if hasattr(cls,'tmp'):cls.tmp.cleanup()
            Base.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        Base.tearDownClass()

    def _args(self,case=None):
        c=self.case if case is None else case
        p=c['parent']
        return dict(parent_chain_file=p['chain_file'],
            parent_external=p['external'],
            parent_ledger_files=p['ledger_files'],
            parent_certificate_files=p['certificate_files'],
            candidate_a=c['candidate_a'],candidate_b=c['candidate_b'])

    def _case_file(self,name,case):
        path=self.home/name
        store.store(str(path),case,e.MAX_CHAIN_BYTES)
        return str(path),b.digest(path.read_bytes())

    def test_01_two_real_original_signed_candidate_children_are_observed(self):
        report=f.evaluate(**self._args())
        self.assertEqual(report['parent_chain_raw_sha256'],Base.s4['external']['chain_raw_sha256'])
        self.assertEqual(len(report['independently_pinned_candidates']),2)
        self.assertEqual({c['signed_successor_kind'] for c in
                          report['independently_pinned_candidates']},
                         {'signed_registrar_append'})
        self.assertTrue(all(c['original_ec303_latest_ack_replayed'] for c in
                            report['independently_pinned_candidates']))
        self.assertTrue(report['all_new_registrar_appends_original_ec303_to_ec294_replayed'])
        self.assertFalse(report['external_atomic_cas_or_worm_commit_proven'])
        self.assertIsNone(report['external_cas_handoff']['externally_authorized_selection_sha256'])
        self.assertFalse(report['cross_branch_reused_acknowledgement_sha256'])
        self.assertFalse(report['cross_branch_reused_challenge_sha256'])
        self.assertNotIn(str(self.home),json.dumps(report))
        self.assertNotIn('private_key_file',json.dumps(report))

    def test_02_case_index_order_independent_and_evidence_roundtrip(self):
        swapped={**self.case,'candidate_a':self.case['candidate_b'],
                 'candidate_b':self.case['candidate_a']}
        self.assertEqual(f.evaluate(**self._args()),f.evaluate(**self._args(swapped)))
        path=str(self.home/'fork-evidence.json')
        out=f.compare(**self._args(),out=path)
        self.assertEqual(out['exit_code'],2)
        self.assertEqual(os.stat(path).st_mode & 0o777,0o600)
        self.assertEqual(b.digest(Path(path).read_bytes()),out['evidence_report_raw_sha256'])
        self.assertEqual(f.verify_report(**self._args(),evidence_file=path,
            expected_evidence_report_sha256=out['evidence_report_raw_sha256'])['exit_code'],2)
        self.assertEqual(f.compare(**self._args(swapped))['evidence_report_raw_sha256'],
                         out['evidence_report_raw_sha256'])
        with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OUTPUT_OR_FSYNC'):
            f.compare(**self._args(),out=path)

    def test_03_independent_pins_and_true_parent_prevent_self_reanchoring(self):
        bad={**self.case,'candidate_b':{
            **self.case['candidate_b'],
            'expected_chain_raw_sha256':'a'*64}}
        with self.assertRaisesRegex(a.AnchorError,'CHAIN_BYTES_DIFFER_FROM_INDEPENDENT'):
            f.evaluate(**self._args(bad))
        wrong=dict(json.loads(Path(self.other_stage['chain_file']).read_bytes()))
        wrong['previous_chain_raw_sha256']='7'*64
        path,sha=self._case_file('wrong-parent-index.json',wrong)
        bad={**self.case,'candidate_b':{
            **self.case['candidate_b'],'chain_file':path,
            'expected_chain_raw_sha256':sha}}
        with self.assertRaisesRegex(a.AnchorError,'NOT_CHILD_OF_EXACT'):
            f.evaluate(**self._args(bad))
        with self.assertRaisesRegex(a.AnchorError,'TWO_DIFFERENT_INDEPENDENT_CHILD'):
            f.evaluate(**self._args({**self.case,
                'candidate_b':self.case['candidate_a']}))

    def test_04_forged_signed_record_even_with_recomputed_outer_pins_denied(self):
        ledger=json.loads(self.other_ledger.read_bytes())
        ledger['records'][-1]['claim']['acknowledgement_sha256']='1'*64
        led_path,led_sha=self._case_file('signed-ledger-forgery.json',ledger)
        idx=json.loads(Path(self.other_stage['chain_file']).read_bytes())
        idx['epochs'][-1]['ledger_raw_sha256']=led_sha
        idx_path,idx_sha=self._case_file('outer-signed-forgery.json',idx)
        bogus={**self.case,'candidate_b':{
            **self.case['candidate_b'],
            'chain_file':idx_path,'expected_chain_raw_sha256':idx_sha,
            'ledger_files':Base.s4['ledger_files']+[led_path]}}
        with self.assertRaisesRegex(a.AnchorError,'REGISTRAR_SIGNATURE_INVALID'):
            f.evaluate(**self._args(bogus))

    def test_05_original_latest_ack_proof_required_and_tampering_fails(self):
        no_proof={**self.case,'candidate_b':{
            **self.case['candidate_b'],'ack_proof':None}}
        with self.assertRaisesRegex(a.AnchorError,'LATEST_ORIGINAL_ACK_PROOF_MANDATORY'):
            f.evaluate(**self._args(no_proof))
        corrupt={**self.case,'candidate_b':{
            **self.case['candidate_b'],'ack_proof':{
                **self.otherctx,'expected_acknowledgement_sha256':'a'*64}}}
        with self.assertRaisesRegex(a.AnchorError,'ACKNOWLEDGEMENT_NOT_EQUAL|RECEIVER_ED25519'):
            f.evaluate(**self._args(corrupt))

    def test_06_signed_governance_cutover_competes_with_signed_append(self):
        # Base.s3 -> Base.s4 is the original independently voted emergency
        # cutover. Another valid child of *s3* is an original registrar append.
        ctx=self._signed_ack('before-cutover','1'*64)
        ledger=str(self.home/'branch-before-cutover-ledger.json')
        signed=e.register(**Base.s3,**ctx,
            active_private_key_file=Early.active_file,
            out=ledger)
        index=str(self.home/'branch-before-cutover-index.json')
        committed=e.commit(**Base.s3,**ctx,candidate_ledger_file=ledger,
            expected_candidate_ledger_sha256=signed['ledger_raw_sha256'],
            expected_candidate_sequence=3,out=index)
        stage={'chain_file':index,'external':Base._external(committed),
               'ledger_files':Base.s3['ledger_files'][:-1]+[ledger],
               'certificate_files':Base.s3['certificate_files']}
        case=self._case(Base.s3,self._branch(Base.s4),self._branch(stage,ctx))
        report=f.evaluate(**self._args(case))
        self.assertEqual({c['signed_successor_kind'] for c in
                          report['independently_pinned_candidates']},
                         {'governance_signed_epoch_rotation','signed_registrar_append'})
        self.assertEqual(sum(c['original_ec303_latest_ack_replayed'] for c in
                             report['independently_pinned_candidates']),1)

    def test_07_report_not_substitutable_even_when_attacker_rehashes_it(self):
        origin=str(self.home/'immutable-signed-report.json')
        result=f.compare(**self._args(),out=origin)
        amended=json.loads(Path(origin).read_bytes())
        amended['external_cas_handoff']['externally_authorized_selection_sha256']=\
            result['candidate_chain_raw_sha256'][0]
        altered,altered_sha=self._case_file('false-cas-handoff-report.json',amended)
        with self.assertRaisesRegex(a.AnchorError,'EVIDENCE_CONTENT_NOT_EQUAL'):
            f.verify_report(**self._args(),evidence_file=altered,
                expected_evidence_report_sha256=altered_sha)
        with self.assertRaisesRegex(a.AnchorError,'REPORT_BYTES_NOT_EQUAL'):
            f.verify_report(**self._args(),evidence_file=origin,
                expected_evidence_report_sha256='a'*64)

    def test_08_standalone_cli_and_exact_read_only_console(self):
        cmd=[sys.executable,'-B',str(ROOT/'scripts/ces_registrar_forks.py'),
            'compare','--case-file',str(self.case_path),
            '--expected-case-raw-sha256',self.case_sha]
        run=subprocess.run(cmd,text=True,capture_output=True,timeout=170)
        self.assertEqual(run.returncode,2,run.stdout+run.stderr)
        self.assertEqual(json.loads(run.stdout)['status'],
            'two_verified_competing_candidates_observed_external_cas_required')
        console=[sys.executable,'-B',str(ROOT/'scripts/ces_next.py'),
            'audit-forks','DeliveryAudit','CompareRegistrarForks',
            '--case-file',str(self.case_path),
            '--expected-case-raw-sha256',self.case_sha]
        run=subprocess.run(console,text=True,capture_output=True,timeout=170)
        self.assertEqual(run.returncode,2,run.stdout+run.stderr)
        self.assertFalse(json.loads(run.stdout)['evidence_report_written'])
        denied=subprocess.run([*console[:4], 'RotateRegistrar',*console[5:]],
            text=True,capture_output=True,timeout=25)
        self.assertEqual(denied.returncode,3,denied.stdout+denied.stderr)
        self.assertFalse(json.loads(denied.stdout)['permissions_granted'])
        # Read-only console has no --out argument and must reject it.
        denied=subprocess.run([*console,'--out',str(self.home/'should-not-exist')],
            text=True,capture_output=True,timeout=25)
        self.assertNotEqual(denied.returncode,0)
        self.assertFalse((self.home/'should-not-exist').exists())
        evidence=str(self.home/'cli-evidence.json')
        run=subprocess.run([*cmd,'--out',evidence],text=True,capture_output=True,timeout=170)
        self.assertEqual(run.returncode,2,run.stdout+run.stderr)
        sha=json.loads(run.stdout)['evidence_report_raw_sha256']
        check=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/ces_registrar_forks.py'),
            'verify-report','--case-file',str(self.case_path),
            '--expected-case-raw-sha256',self.case_sha,
            '--evidence-file',evidence,'--expected-evidence-report-sha256',sha],
            text=True,capture_output=True,timeout=170)
        self.assertEqual(check.returncode,2,check.stdout+check.stderr)
        self.assertEqual(json.loads(check.stdout)['evidence_report_raw_sha256'],sha)

    def test_09_untrusted_manifest_mutation_unpinned_and_wrong_mode_denied(self):
        obj=json.loads(self.case_path.read_bytes())
        obj['candidate_a']['ack_proof']=None
        alt,alt_sha=self._case_file('mutated-case.json',obj)
        with self.assertRaisesRegex(a.AnchorError,'CHAIN_BYTES_DIFFER'):
            read_case(alt,self.case_sha)
        with self.assertRaisesRegex(a.AnchorError,'LATEST_ORIGINAL_ACK_PROOF_MANDATORY'):
            f.evaluate(**self._args(obj))
        obj['candidate_a']['ack_proof']=Base.thirdctx
        obj['candidate_b']['ack_proof']['unexpected_secret_file']='x'
        with self.assertRaisesRegex(a.AnchorError,'ACK_PROOF_FIELDS_INVALID'):
            f.evaluate(**self._args(obj))


if __name__=='__main__':
    unittest.main()
