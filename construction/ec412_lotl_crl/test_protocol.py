#!/usr/bin/env python3
"""EC412 true locally issuer-signed RSA/P256 CRL original-byte adversity tests.

Only the immediate EC411.audit is mocked in these child tests using an EC411
report from genuinely RSA-signed local XAdES originals. Deeper fixture ancestry
has existing separate mocks. Production never mocks or manufactures CA/CRL.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

from ec295_delivery_anchor import anchor as errors
from ec411_xades_certificate import test_protocol as ec411fixture
from . import operator, protocol as core


class GenuineOriginalIssuerSignedLotlCRLs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ec411fixture.RealSignedOriginalXadesCertificateV2.setUpClass()

    @classmethod
    def tearDownClass(cls):
        ec411fixture.RealSignedOriginalXadesCertificateV2.tearDownClass()

    def setUp(self):
        self.b = ec411fixture.RealSignedOriginalXadesCertificateV2(
            "test_01_real_signed_rsa_both_original_window_certificate_v2")
        self.b.setUp()
        self.parent_report = self.b.calibrate()  # actual signed EC411 originals
        self.assertTrue(self.parent_report[
            "bounded_original_signed_xades_cert_v2_and_real_ec410_consistency"])
        self.extra = dict(self.b.extra)
        self.bundle = {
            "schema": core.BUNDLE_SCHEMA,
            "claimed_directory_lineage_id": self.b.f.lineage,
            "parent_ec410_signed_lotl_bundle_original": {
                "path": self.extra[core.lotl.NEW_SCALARS[0]],
                "sha256": self.extra[core.lotl.NEW_SCALARS[1]],
            },
            "parent_ec410_outside_operator_roster_original":
                self.b.f.bundle["outside_lotl_operator_roster_original"],
            "epochs": [{"epoch_index": 0, **{
                w + "_" + r + "_ca_crl_original": None
                for w in core.WINDOWS for r in core.CRL_ROLES
            }}],
        }
        self.raw_crls = {}
        self.options = {}
        self.new_crls()
        self.refresh()

    def tearDown(self):
        self.b.tearDown()

    def _raw(self, issuer, issuer_key, number, *, revoked=(), last=None,
             next_days=30, bad_aki=False, unknown=False, no_number=False,
             tamper_sign_key=None, remove=False):
        when = last or (self.b.f.now - timedelta(days=1))
        builder = (x509.CertificateRevocationListBuilder()
            .issuer_name(issuer.subject)
            .last_update(when)
            .next_update(when + timedelta(days=next_days)))
        if not no_number:
            builder = builder.add_extension(x509.CRLNumber(number), critical=False)
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_key.public_key() if not bad_aki else
            rsa.generate_private_key(public_exponent=65537,
                                     key_size=2048).public_key())
        builder = builder.add_extension(aki, critical=False)
        if unknown:
            builder = builder.add_extension(x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.55555.412"), b"\x05\x00"),
                critical=True)
        for certificate in revoked:
            row = (x509.RevokedCertificateBuilder()
                   .serial_number(certificate.serial_number)
                   .revocation_date(when - timedelta(hours=1)))
            if remove:
                row = row.add_extension(
                    x509.CRLReason(x509.ReasonFlags.remove_from_crl), critical=False)
            builder = builder.add_revoked_certificate(row.build())
        cert = builder.sign(private_key=tamper_sign_key or issuer_key,
                            algorithm=hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.DER)

    def new_crls(self, mutate=None):
        # Two fresh genuine issuer-signed CRL documents per source window.
        for window, num, shift in (("historical", 120, 2),
                                   ("evaluation", 121, 1)):
            for role in core.CRL_ROLES:
                issuer, key, target = (
                    (self.b.f.root, self.b.f.root_key, self.b.f.mid)
                    if role == "root" else
                    (self.b.f.mid, self.b.f.mid_key, self.b.f.signer))
                kwargs = {"last": self.b.f.now-timedelta(days=shift),
                          "next_days": 30}
                if mutate:
                    kwargs.update(mutate(window, role, issuer, key, target) or {})
                raw = self._raw(issuer, key, num, **kwargs)
                ref = self.b.f.archive(raw, "ec412-" + window + "-" + role +
                                       "-" + str(len(self.raw_crls)))
                self.bundle["epochs"][0][window + "_" + role +
                                         "_ca_crl_original"] = ref
                self.raw_crls[(window, role)] = raw

    def refresh(self, *, pins=True):
        ref = self.b.f.archive(self.bundle, "ec412-four-original-full-crl-bundle")
        self.extra[core.NEW_SCALARS[0]] = ref["path"]
        self.extra[core.NEW_SCALARS[1]] = ref["sha256"]
        if pins:
            self.extra.update({
                k: self.bundle["epochs"][0][w + "_" + role +
                                            "_ca_crl_original"]["sha256"]
                for k, (w, role) in zip(core.NEW_SCALARS[2:],
                                        ((w, r) for w in core.WINDOWS
                                         for r in core.CRL_ROLES))
            })
        self.extra[core.REPEAT_NAMES[0]] = ["f"*64]
        self.extra[core.REPEAT_NAMES[1]] = [0]

    def evaluate(self, deriving=True, check_inputs=False):
        opts = dict(self.extra)
        if deriving:
            opts.pop(core.AUDIT_ONLY[0], None)
        with patch.object(core.parent, "audit", return_value=self.parent_report):
            if check_inputs:
                return core.derive_inventory(**opts) if deriving else core.audit(**opts)
            with patch.object(core, "_inputs", return_value={}):
                return core.derive_inventory(**opts) if deriving else core.audit(**opts)

    def calibrate(self):
        r = self.evaluate()
        self.extra[core.REPEAT_NAMES[0]] = [
            r["lotl_ca_crl_epoch_reviews"][0][
                "lotl_ca_crl_epoch_inventory_sha256"]]
        self.extra[core.REPEAT_NAMES[1]] = [2]
        r = self.evaluate()
        self.extra[core.AUDIT_ONLY[0]] = (
            r["receiver_verified_lotl_ca_crl_inventory_sha256"])
        return self.evaluate(False)

    def denied(self, part):
        with self.assertRaises(errors.AnchorError) as raised:
            self.evaluate()
        self.assertEqual(raised.exception.status, "permission_denied")
        self.assertIn(part, raised.exception.code)

    def test_01_two_true_rsa_ca_signed_crls_in_both_original_windows(self):
        r = self.calibrate()
        self.assertEqual(r["exit_code"], 2)
        self.assertTrue(r["bounded_original_ca_crl_and_real_ec411_parent_consistency"])
        self.assertEqual(r["verified_joint_crl_and_real_ec411_parent_publishers"], 2)
        self.assertTrue(r[core.FLAGS[4]])
        self.assertFalse(any(r[k] for k in core.NEGATIVES))

    def test_02_true_p256_intermediate_ca_signed_crl(self):
        # Change genuine signer CA key+cert+LOTL signature, not only a mock key.
        new_mid_key = ec.generate_private_key(ec.SECP256R1())
        self.b.f.mid_key = new_mid_key
        self.b.f.mid = ec411fixture.ec410fixture.make_cert(
            "EC412 local ECDSA intermediate", new_mid_key,
            self.b.f.root, self.b.f.root_key, self.b.f.now,
            ca=True, path_len=0, serial=41202)
        self.b.f.signer = ec411fixture.ec410fixture.make_cert(
            "EC412 ECDSA CA signed LOTL signer", self.b.f.signer_key,
            self.b.f.mid, self.b.f.mid_key, self.b.f.now,
            ca=False, path_len=None, serial=41203)
        self.b.f.refresh(roster=True)
        self.b.resign(True)
        self.b.resign(False)
        self.b.f.refresh(roster=True)
        self.b.ec410_report = self.b.f.calibrate()
        self.b.extra.update(self.b.f.extra)
        self.parent_report = self.b.calibrate()
        self.extra.update(self.b.extra)
        self.bundle["parent_ec410_signed_lotl_bundle_original"] = {
            "path": self.extra[core.lotl.NEW_SCALARS[0]],
            "sha256": self.extra[core.lotl.NEW_SCALARS[1]]}
        self.bundle["parent_ec410_outside_operator_roster_original"] = (
            self.b.f.bundle["outside_lotl_operator_roster_original"])
        self.new_crls()
        self.refresh()
        r = self.calibrate()
        self.assertTrue(r["bounded_original_ca_crl_and_real_ec411_parent_consistency"])

    def test_03_actual_revoked_lotl_leaf_in_signed_intermediate_crl(self):
        self.new_crls(lambda w,r,i,k,t:
                      {"revoked": (t,)} if w=="historical" and r=="intermediate" else {})
        self.refresh()
        self.denied("PINNED_LOTL_CERTIFICATE_REVOKED")

    def test_04_actual_revoked_intermediate_in_signed_root_crl(self):
        self.new_crls(lambda w,r,i,k,t:
                      {"revoked": (t,)} if w=="evaluation" and r=="root" else {})
        self.refresh()
        self.denied("PINNED_LOTL_CERTIFICATE_REVOKED")

    def test_05_crl_signed_with_wrong_private_key(self):
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.new_crls(lambda w,r,i,k,t:
                      {"tamper_sign_key": wrong}
                      if w=="historical" and r=="root" else {})
        self.refresh()
        self.denied("SIGNATURE_INVALID")

    def test_06_crl_wrong_authority_key_identifier(self):
        self.new_crls(lambda w,r,i,k,t:
                      {"bad_aki": True}
                      if w=="historical" and r=="root" else {})
        self.refresh()
        self.denied("AUTHORITY_KEY_ID_MISMATCH")

    def test_07_stale_historical_crl_wont_cover_claim_time(self):
        self.new_crls(lambda w,r,i,k,t:
                      {"last": self.b.f.now-timedelta(days=90),
                       "next_days": 2}
                      if w=="historical" and r=="intermediate" else {})
        self.refresh()
        self.denied("SOURCE_WINDOW_NOT_COVERED")

    def test_08_no_number_in_full_crl_is_rejected(self):
        self.new_crls(lambda w,r,i,k,t:
                      {"no_number": True}
                      if w=="historical" and r=="root" else {})
        self.refresh()
        self.denied("EXACT_NUMBER_AND_AUTHORITY_KEY_ID")

    def test_09_critical_unrecognized_crl_extension_rejected(self):
        self.new_crls(lambda w,r,i,k,t:
                      {"unknown": True}
                      if w=="evaluation" and r=="root" else {})
        self.refresh()
        self.denied("EXACT_NUMBER_AND_AUTHORITY_KEY_ID")

    def test_10_crl_number_rollback_even_with_real_signature(self):
        self.new_crls(lambda w,r,i,k,t:
                      {"last": self.b.f.now-timedelta(days=3)}
                      if w=="evaluation" and r=="root" else {})
        self.refresh()
        self.denied("ROLLBACK")

    def test_11_original_full_crl_source_bytes_sha_tampered(self):
        ref = self.bundle["epochs"][0]["historical_root_ca_crl_original"]
        raw = Path(ref["path"]).read_bytes()
        self.bundle["epochs"][0]["historical_root_ca_crl_original"] = (
            {"path": ref["path"], "sha256": "a"*64})
        self.refresh(pins=False)
        with self.assertRaises(errors.AnchorError):
            self.evaluate()

    def test_12_external_first_original_sha_pin_disagreement_unresolved(self):
        r = self.calibrate()
        self.extra[core.NEW_SCALARS[2]] = "a"*64
        r = self.evaluate()
        self.assertTrue(r[core.FLAGS[1]])
        self.assertEqual(r["exit_code"], 2)
        self.assertFalse(r["bounded_original_ca_crl_and_real_ec411_parent_consistency"])

    def test_13_retained_inventory_sha_disagreement_unresolved(self):
        self.calibrate()
        self.extra[core.AUDIT_ONLY[0]] = "b"*64
        r = self.evaluate(False)
        self.assertTrue(r[core.FLAGS[1]])
        self.assertEqual(r["exit_code"], 2)

    def test_14_adverse_ec411_cannot_be_upgraded_by_good_crl(self):
        self.calibrate()
        report = dict(self.parent_report)
        report[core.parent.FLAGS[1]] = True
        report["bounded_original_signed_xades_cert_v2_and_real_ec410_consistency"] = False
        report["status"] = core.parent.OUTCOMES[1] + "_unresolved"
        self.parent_report = report
        r = self.evaluate()
        self.assertTrue(r[core.FLAGS[0]])
        self.assertEqual(r["verified_joint_crl_and_real_ec411_parent_publishers"], 0)

    def test_15_fabricated_ec411_positive_pass_denied(self):
        report = dict(self.parent_report)
        report["exit_code"] = 0
        self.parent_report = report
        with self.assertRaises(errors.AnchorError) as raised:
            self.evaluate()
        self.assertEqual(raised.exception.status, "unavailable")

    def test_16_first_ca_crl_missing_is_denied(self):
        self.bundle["epochs"][0]["historical_root_ca_crl_original"] = None
        self.refresh(pins=False)
        self.denied("PARTIAL_REAPPEARING")

    def test_17_reused_same_crl_path_across_windows_is_denied(self):
        self.bundle["epochs"][0]["evaluation_root_ca_crl_original"] = (
            self.bundle["epochs"][0]["historical_root_ca_crl_original"])
        self.refresh(pins=False)
        self.denied("PATH_ALIAS_OR_SHA_REPLAY")

    def test_18_untrusted_remove_from_crl_status_denied(self):
        self.new_crls(lambda w,r,i,k,t:
                      {"revoked": (t,), "remove": True}
                      if w=="historical" and r=="intermediate" else {})
        self.refresh()
        self.denied("DELTA_OR_REMOVE_FROM_CRL_NOT_SUPPORTED")

    def test_19_true_input_argument_count_and_first_pins(self):
        full = {k: self.extra.get(k, "not-used-for-input-unit-test")
                for k in (*core.PARENT_SCALARS, *core.NEW_SCALARS)}
        full.update({k: self.extra.get(k, []) for k in core.PARENT_REPEATS})
        full.update({k: self.extra[k] for k in core.REPEAT_NAMES})
        with patch.object(core.parent, "_inputs", return_value={}):
            self.assertEqual(set(core._inputs(full, True)),
                             set(core.PARENT_SCALARS) | set(core.PARENT_REPEATS))
            other = dict(full)
            other[core.REPEAT_NAMES[1]] = [3]
            with self.assertRaises(errors.AnchorError):
                core._inputs(other, True)

    def test_20_no_positive_or_legal_status_in_denial_response(self):
        result = operator.denial("audit-historical-ec339-lotl-crl",
              errors.AnchorError("EC412_BAD_CRL","permission_denied"))
        self.assertEqual(result["exit_code"], 3)
        self.assertFalse(any(result[k] for k in core.NEGATIVES))
        self.assertNotIn("bounded_original_ca_crl_and_real_ec411_parent_consistency",
                         result)

    def test_21_original_crl_without_target_revocation_has_extra_unrelated_serial(self):
        # A truly issuer-signed CRL with unrelated revoked serial is accepted.
        # Use an unrelated real local certificate serial in the issuer CRL.
        self.new_crls(lambda w,r,i,k,t:
                      {"revoked": (self.b.f.root,)}
                      if w=="historical" and r=="intermediate" else {})
        self.refresh()
        r = self.calibrate()
        self.assertTrue(r["bounded_original_ca_crl_and_real_ec411_parent_consistency"])

    def test_22_issuer_ca_key_usage_requires_crl_sign(self):
        # Can exercise direct original checker without mutating the already-
        # EC410-authenticated parent certificate chain.
        issuer = self.b.f.root
        key = self.b.f.root_key
        now = self.b.f.now
        no_crl_issuer = (
            x509.CertificateBuilder()
            .subject_name(issuer.subject).issuer_name(issuer.issuer)
            .public_key(key.public_key())
            .serial_number(41222)
            .not_valid_before(now-timedelta(days=30))
            .not_valid_after(now+timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True,path_length=1),True)
            .add_extension(x509.KeyUsage(
                digital_signature=False,content_commitment=False,
                key_encipherment=False,data_encipherment=False,
                key_agreement=False,key_cert_sign=True,crl_sign=False,
                encipher_only=False,decipher_only=False),True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False)
            .sign(key,hashes.SHA256())
        )
        raw = self._raw(no_crl_issuer,key,125)
        with self.assertRaises(errors.AnchorError) as raised:
            core._crl_window(raw,no_crl_issuer,self.b.f.mid,[now],
                             role="root",window="historical")
        self.assertIn("NOT_AUTHORIZED_TO_SIGN_CRLS",raised.exception.code)


    def test_23_unified_fixed_router_exact_result_contract(self):
        from scripts import ces_next
        doc = self.calibrate()
        inputs = {k: self.extra.get(k, "fixture-parent-argument-not-executed")
                  for k in ces_next.EC412_ALL_SCALARS}
        inputs.update({k: self.extra.get(k, []) for k,_ in ces_next.EC412_ALL_REPEATS})
        with patch.object(ces_next, "_command", return_value=(2, doc)), \
             patch.object(ces_next, "_emit") as emitted:
            rc = ces_next.audit_historical_ec339_lotl_crl(
                "DeliveryAudit", "AuditHistoricalEC339LOTLCARevocation",
                **inputs)
            self.assertEqual(rc, 2)
            emitted.assert_called_once()

    def test_24_unified_fixed_router_denies_wrong_mode(self):
        from scripts import ces_next
        with self.assertRaises(Exception):
            ces_next.audit_historical_ec339_lotl_crl(
                "DeliveryAudit", "AuditHistoricalEC339XAdESCertV2")

    def test_25_isolated_and_unified_cli_parsers_available(self):
        from scripts import ces_next
        iso = operator.parser()
        unified = ces_next.build_parser()
        self.assertIn("audit-historical-ec339-lotl-crl",
                      iso._subparsers._group_actions[0].choices)
        self.assertIn("audit-historical-ec339-lotl-crl",
                      unified._subparsers._group_actions[0].choices)


if __name__ == "__main__":
    unittest.main()
