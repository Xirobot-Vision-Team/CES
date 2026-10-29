#!/usr/bin/env python3
"""EC308 local focused evidence tests using genuine EC294->EC307 signed fixtures.

These test-only keys simulate an issuer. No test proves a REAL off-host CAS,
real-world authorization, globally current head, or multi-operator key custody.
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
from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from registrar_epochs.test_epochs import EC306EpochCases as OldEpochs
from registrar_forks.test_forks import EC307ForkCases as OldForks
from registrar_forks import forks
from . import receipt as r

ROOT = Path(__file__).resolve().parents[2]


class EC308CasReceiptCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        OldForks.setUpClass()
        try:
            cls.tmp = tempfile.TemporaryDirectory(prefix="ec308-cas-receipt-")
            cls.home = Path(cls.tmp.name)
            cls.key = Ed25519PrivateKey.generate()
            cls.pub = cls.key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw).hex()
            cls.parent_sha = OldForks.case["parent"]["external"]["chain_raw_sha256"]
            cls.fork_path = cls.home / "genuine-fork-report.json"
            parent = OldForks.case["parent"]
            cls.fork_result = forks.compare(
                parent_chain_file=parent["chain_file"],
                parent_external=parent["external"],
                parent_ledger_files=parent["ledger_files"],
                parent_certificate_files=parent["certificate_files"],
                candidate_a=OldForks.case["candidate_a"],
                candidate_b=OldForks.case["candidate_b"],
                out=str(cls.fork_path))
            cls.fork_sha = cls.fork_result["evidence_report_raw_sha256"]
            cls.fork_report = forks._read_report(str(cls.fork_path), cls.fork_sha)
            cls.candidates = cls.fork_report["external_cas_handoff"][
                "allowed_candidate_chain_raw_sha256"]
            cls.nonce = "6"*64
            cls.revision = 27
            cls.trust = {
                "cas_authority_id": "independent_cas_site",
                "cas_authority_public_hex": cls.pub,
                "expected_request_nonce_sha256": cls.nonce,
                "expected_parent_cas_revision": cls.revision,
                "expected_parent_cas_head_sha256": cls.parent_sha,
            }
            cls.counter = 0
        except BaseException:
            if hasattr(cls, "tmp"):
                cls.tmp.cleanup()
            OldForks.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        OldForks.tearDownClass()

    @classmethod
    def _options(cls, receipt_file, receipt_sha, trust=None):
        return {
            "fork_case_file": str(OldForks.case_path),
            "expected_fork_case_sha256": OldForks.case_sha,
            "fork_evidence_file": str(cls.fork_path),
            "expected_fork_evidence_sha256": cls.fork_sha,
            "receipt_file": str(receipt_file),
            "expected_receipt_sha256": receipt_sha,
            "trust": cls.trust if trust is None else trust,
        }

    @classmethod
    def _claim(cls, **changes):
        handoff = cls.fork_report["external_cas_handoff"]
        doc = {
            "schema": r.CLAIM_SCHEMA,
            "registry_id": cls.fork_report["registry_id"],
            "cas_authority_id": cls.trust["cas_authority_id"],
            "cas_authority_public_hex": cls.pub,
            "ec307_fork_evidence_raw_sha256": cls.fork_sha,
            "ec307_choice_request_raw_sha256": b.digest(b.canonical(handoff)),
            "request_nonce_sha256": cls.nonce,
            "expected_parent_chain_raw_sha256": cls.parent_sha,
            "candidate_chain_raw_sha256": cls.candidates,
            "expected_parent_cas_revision": cls.revision,
            "expected_parent_cas_head_sha256": cls.parent_sha,
            "outcome": "compare_exchange_committed_claim",
            "observed_cas_revision": cls.revision + 1,
            "observed_head_chain_raw_sha256": cls.candidates[0],
            "selected_candidate_chain_raw_sha256": cls.candidates[0],
        }
        doc.update(changes)
        return doc

    @classmethod
    def _signed_file(cls, claim=None, key=None, **changes):
        claim = cls._claim(**changes) if claim is None else claim
        key = cls.key if key is None else key
        receipt = {
            "schema": r.RECEIPT_SCHEMA,
            "claim": claim,
            "authority_signature_ed25519":
                key.sign(r.DOMAIN + a.canonical(claim)).hex(),
        }
        return cls._file(receipt)

    @classmethod
    def _file(cls, doc):
        cls.counter += 1
        path = cls.home / f"receipt-{cls.counter:04d}.json"
        store.store(str(path), doc, r.MAX_RECEIPT_BYTES)
        return str(path), b.digest(path.read_bytes())

    def test_01_real_original_fork_and_true_issuer_signature_commit_claim(self):
        path, sha = self._signed_file()
        report = r.evaluate(**self._options(path, sha))
        self.assertEqual(report["issuer_signed_outcome"],
                         "compare_exchange_committed_claim")
        self.assertTrue(report["original_ec294_through_ec307_signatures_and_fork_replayed"])
        self.assertTrue(report["issuer_ed25519_signature_verified"])
        self.assertEqual(report["selected_candidate_chain_raw_sha256"],self.candidates[0])
        self.assertFalse(report["real_store_linearizability_durability_or_fresh_readback_proven"])
        self.assertFalse(report["independent_external_cas_authority_real_world_authorization_proven"])
        self.assertNotIn(str(self.home),json.dumps(report))

    def test_02_issuer_signed_failed_precondition_is_not_a_win_or_new_tip_proof(self):
        path, sha = self._signed_file(
            outcome="compare_exchange_precondition_failed_claim",
            selected_candidate_chain_raw_sha256=None,
            observed_head_chain_raw_sha256="a"*64,
            observed_cas_revision=self.revision + 4)
        result=r.verify(**self._options(path,sha))
        self.assertEqual(result["exit_code"],2)
        self.assertIsNone(result["selected_candidate_chain_raw_sha256"])
        self.assertFalse(result["real_external_cas_commit_or_latest_proven"])

    def test_03_private_audit_nonoverwrite_and_independent_full_reverification(self):
        path,sha=self._signed_file()
        audit=str(self.home/"audit-report.json")
        result=r.verify(**self._options(path,sha),out=audit)
        self.assertEqual(result["exit_code"],0)
        self.assertEqual(os.stat(audit).st_mode & 0o777,0o600)
        self.assertEqual(b.digest(Path(audit).read_bytes()),result["audit_report_raw_sha256"])
        rechecked=r.verify_report(**self._options(path,sha),
            audit_report_file=audit,
            expected_audit_report_sha256=result["audit_report_raw_sha256"])
        self.assertEqual(rechecked["exit_code"],0)
        with self.assertRaisesRegex(a.AnchorError,"EXCLUSIVE_OUTPUT_OR_FSYNC"):
            r.verify(**self._options(path,sha),out=audit)
        rewritten={**json.loads(Path(audit).read_text()),
                   "global_latest_head_or_competing_branch_resolution_proven":True}
        bad,bad_sha=self._file(rewritten)
        with self.assertRaisesRegex(a.AnchorError,"DIFFERS_FROM_FULL_REPLAY"):
            r.verify_report(**self._options(path,sha),
                audit_report_file=bad,expected_audit_report_sha256=bad_sha)

    def test_04_signature_mutation_is_denied_even_when_receipt_raw_sha_is_recomputed(self):
        path,sha=self._signed_file()
        forged=json.loads(Path(path).read_text())
        forged["claim"]["request_nonce_sha256"]="8"*64
        new,new_sha=self._file(forged)
        bad_trust={**self.trust,"expected_request_nonce_sha256":"8"*64}
        with self.assertRaisesRegex(a.AnchorError,"SIGNATURE_INVALID"):
            r.evaluate(**self._options(new,new_sha,bad_trust))

    def test_05_off_bundle_authority_identity_nonce_revision_and_head_pins(self):
        path,sha=self._signed_file()
        with self.assertRaisesRegex(a.AnchorError,"EXTERNAL_PINS_OR_REPLAYED_FORK"):
            r.evaluate(**self._options(path,sha,{
                **self.trust,"expected_request_nonce_sha256":"9"*64}))
        with self.assertRaisesRegex(a.AnchorError,"EXTERNAL_PINS_OR_REPLAYED_FORK"):
            r.evaluate(**self._options(path,sha,{
                **self.trust,"expected_parent_cas_revision":self.revision+1}))
        with self.assertRaisesRegex(a.AnchorError,"INDEPENDENT_PARENT_HEAD"):
            r.evaluate(**self._options(path,sha,{
                **self.trust,"expected_parent_cas_head_sha256":"7"*64}))
        with self.assertRaisesRegex(a.AnchorError,"RECEIPT_INDEPENDENT|CHAIN_BYTES"):
            r.evaluate(**self._options(path,"b"*64))

    def test_06_valid_signature_cannot_select_outside_two_original_cas_candidates(self):
        path,sha=self._signed_file(
            selected_candidate_chain_raw_sha256="9"*64,
            observed_head_chain_raw_sha256="9"*64)
        with self.assertRaisesRegex(a.AnchorError,"COMMIT_CLAIM_MUST_ADVANCE"):
            r.evaluate(**self._options(path,sha))

    def test_07_commit_revision_and_declared_head_must_be_exact_next(self):
        for fields in (
            dict(observed_cas_revision=self.revision+2),
            dict(observed_head_chain_raw_sha256=self.candidates[1]),
            dict(selected_candidate_chain_raw_sha256=None),
        ):
            with self.subTest(fields=fields):
                path,sha=self._signed_file(**fields)
                with self.assertRaisesRegex(a.AnchorError,"COMMIT_CLAIM_MUST_ADVANCE"):
                    r.evaluate(**self._options(path,sha))

    def test_08_failed_compare_cannot_choose_or_keep_same_head(self):
        for fields in (
            dict(selected_candidate_chain_raw_sha256=self.candidates[0],
                 observed_head_chain_raw_sha256="e"*64),
            dict(selected_candidate_chain_raw_sha256=None,
                 observed_head_chain_raw_sha256=self.parent_sha),
        ):
            path,sha=self._signed_file(
                outcome="compare_exchange_precondition_failed_claim",
                **fields)
            with self.assertRaisesRegex(a.AnchorError,"PRECONDITION_FAILURE"):
                r.evaluate(**self._options(path,sha))

    def test_09_reject_known_original_registrar_reused_as_cas_authority(self):
        key = io.private_from_file(str(OldEpochs.third_private))
        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()
        claim=self._claim(cas_authority_public_hex=pub)
        path,sha=self._signed_file(claim=claim,key=key)
        trust={**self.trust,"cas_authority_public_hex":pub}
        with self.assertRaisesRegex(a.AnchorError,"CAS_SIGNER_MUST_NOT_REUSE"):
            r.evaluate(**self._options(path,sha,trust))

    def test_10_full_original_signed_fork_replay_cannot_be_skipped(self):
        path,sha=self._signed_file()
        options=self._options(path,sha)
        options["expected_fork_evidence_sha256"]="d"*64
        with self.assertRaisesRegex(a.AnchorError,"REPORT_BYTES_NOT_EQUAL"):
            r.evaluate(**options)

    def test_11_fixed_standalone_cli_and_readonly_console(self):
        path,sha=self._signed_file()
        common=[
            "--fork-case-file",str(OldForks.case_path),
            "--expected-fork-case-sha256",OldForks.case_sha,
            "--fork-evidence-file",str(self.fork_path),
            "--expected-fork-evidence-sha256",self.fork_sha,
            "--receipt-file",path,"--expected-receipt-sha256",sha,
            "--cas-authority-id",self.trust["cas_authority_id"],
            "--cas-public-hex",self.pub,
            "--request-nonce-sha256",self.nonce,
            "--expected-parent-cas-revision",str(self.revision),
            "--expected-parent-cas-head-sha256",self.parent_sha,
        ]
        env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"}
        def call(args,expected):
            run=subprocess.run([sys.executable,"-I","-B",*args],
                capture_output=True,text=True,timeout=480,env=env)
            self.assertEqual(run.returncode,expected,run.stdout+run.stderr)
            return json.loads(run.stdout.strip())
        script=str(ROOT/"scripts/ces_cas_receipt.py")
        console=str(ROOT/"scripts/ces_next.py")
        output=call([script,"verify",*common],0)
        self.assertFalse(output["real_external_cas_commit_or_latest_proven"])
        self.assertFalse(output["audit_report_written"])
        read=call([console,"audit-cas","DeliveryAudit","VerifySignedCasReceipt",
                   *common],0)
        self.assertTrue(read["original_signed_fork_replayed"])
        self.assertFalse(read["current_global_latest_verified"])
        reject=call([console,"audit-cas","DeliveryAudit","CommitCas",*common],3)
        self.assertIn("ONLY_DELIVERYAUDIT",reject["reason_code"])
        denied=subprocess.run([sys.executable,"-I","-B",console,"audit-cas",
            "DeliveryAudit","VerifySignedCasReceipt",*common,"--out",path],
            capture_output=True,text=True,timeout=480,env=env)
        self.assertNotEqual(denied.returncode,0)
        self.assertIn("unrecognized arguments",denied.stderr)


if __name__ == "__main__":
    unittest.main()
