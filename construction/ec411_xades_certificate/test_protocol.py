#!/usr/bin/env python3
"""EC411 genuine RSA/P256 locally signed XAdES V2, digest and IssuerSerial tests.

Only EC410.audit is mocked inside THIS child fixture using the genuine locally
cryptographically signed EC410 result. EC410's fixture independently mocks
EC409 audit and deeper fixtures are synthetic; NO official origins claimed.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
from pathlib import Path
from datetime import timedelta
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from lxml import etree

from ec295_delivery_anchor import anchor as errors
from ec410_lotl_authority import test_protocol as ec410fixture
from . import protocol as core, operator


class RealSignedOriginalXadesCertificateV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ec410fixture.RealOriginalSignedLOTL.setUpClass()

    @classmethod
    def tearDownClass(cls):
        ec410fixture.RealOriginalSignedLOTL.tearDownClass()

    def setUp(self):
        self.f = ec410fixture.RealOriginalSignedLOTL(
            'test_01_genuine_root_intermediate_leaf_lotl_both_windows')
        self.f.setUp()
        self.resign(True)
        self.resign(False)
        self.f.refresh()
        self.ec410_report = self.f.calibrate()
        self.assertTrue(self.ec410_report[
            'bounded_original_lotl_and_real_ec409_parent_consistency'])
        self.extra = dict(self.f.extra)
        self.extra[core.REPEAT_NAMES[0]] = ['f'*64]
        self.extra[core.REPEAT_NAMES[1]] = [0]

    def tearDown(self):
        self.f.tearDown()

    def _sign_extended_xades(self, historical, mutate=None):
        signer_der = self.f.signer.public_bytes(serialization.Encoding.DER)
        signer_cert = self.f.signer
        key = self.f.signer_key
        seq = 1 if historical else 2
        when = self.f.now if historical else self.f.now + timedelta(minutes=3)
        signed = ec410fixture.signed_lotl(
            signer_cert, key, signer_der, self.f.pointer_roles, when,
            sequence=seq, xades=True)
        root = etree.fromstring(signed)
        sig = root.find(core.parent.DSTAG('Signature'))
        props = sig.find('.//' + core.parent.XTAG('SignedProperties'))
        spp = props.find(core.parent.XTAG('SignedSignatureProperties'))
        v2 = etree.SubElement(spp, core.V2TAG('SigningCertificateV2'))
        cert = etree.SubElement(v2, core.V2TAG('Cert'))
        dg = etree.SubElement(cert, core.V2TAG('CertDigest'))
        etree.SubElement(dg, core.DSTAG('DigestMethod'), Algorithm=core.SHA256_URI)
        etree.SubElement(dg, core.DSTAG('DigestValue')).text = base64.b64encode(
            hashlib.sha256(signer_der).digest()).decode()
        etree.SubElement(cert, core.V2TAG('IssuerSerialV2')).text = base64.b64encode(
            core.issuer_serial_v2_der(signer_cert)).decode()
        if mutate:
            mutate(root, spp, cert)
        # New XAdES SignedProperties bytes get a TRUE SHA256 reference and
        # SignedInfo is REALLY re-signed; not simulated security checks.
        refs = sig.find(core.DSTAG('SignedInfo')).findall(core.DSTAG('Reference'))
        self.assertEqual(len(refs), 2)
        refs[1].find(core.DSTAG('DigestValue')).text = base64.b64encode(
            hashlib.sha256(etree.tostring(props, method='c14n', exclusive=True,
                                           with_comments=False)).digest()).decode()
        si = sig.find(core.DSTAG('SignedInfo'))
        payload = etree.tostring(si, method='c14n', exclusive=True,
                                 with_comments=False)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            esig = key.sign(payload, ec.ECDSA(hashes.SHA256()))
            r, s = utils.decode_dss_signature(esig)
            esig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        else:
            esig = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        sig.find(core.DSTAG('SignatureValue')).text = base64.b64encode(esig).decode()
        # Root digest is unchanged: all the edits were inside enveloped
        # Signature, which is explicitly removed for the root reference.
        return etree.tostring(root, encoding='utf8', xml_declaration=True)

    def resign(self, historical=True, mutate=None):
        raw = self._sign_extended_xades(historical, mutate)
        field = ('original_historical_signed_lotl_xml' if historical
                 else 'original_evaluation_signed_lotl_xml')
        self.f.bundle['epochs'][0][field] = self.f.archive(
            raw, 'ec411-xades-historical' if historical else 'ec411-xades-evaluation')

    def refresh(self, historical=True, mutate=None, re_calibrate=True):
        self.resign(historical, mutate)
        self.f.refresh()
        self.ec410_report = self.f.calibrate()
        self.extra.update(self.f.extra)

    def evaluate(self, deriving=True):
        opts = dict(self.extra)
        if deriving:
            opts.pop(core.AUDIT_ONLY[0], None)
        with patch.object(core.parent, 'audit', return_value=self.ec410_report):
            with patch.object(core, '_inputs', return_value={}):
                return core.derive_inventory(**opts) if deriving else core.audit(**opts)

    def calibrate(self):
        r = self.evaluate()
        self.extra[core.REPEAT_NAMES[0]] = [
            r['xades_cert_v2_epoch_reviews'][0]['xades_v2_epoch_inventory_sha256']]
        self.extra[core.REPEAT_NAMES[1]] = [2]
        r = self.evaluate()
        self.extra[core.AUDIT_ONLY[0]] = r['receiver_verified_xades_cert_v2_inventory_sha256']
        return self.evaluate(False)

    def denied(self, contains=''):
        with self.assertRaises(errors.AnchorError) as raised:
            self.evaluate()
        self.assertEqual(raised.exception.status, 'permission_denied')
        if contains:
            self.assertIn(contains, raised.exception.code)

    def test_01_real_signed_rsa_both_original_window_certificate_v2(self):
        r = self.calibrate()
        self.assertEqual(r['exit_code'], 2)
        self.assertTrue(r['bounded_original_signed_xades_cert_v2_and_real_ec410_consistency'])
        self.assertEqual(r['verified_joint_signed_xades_v2_and_real_ec410_parent_publishers'], 2)
        self.assertFalse(any(r[k] for k in core.NEGATIVES))
        self.assertTrue(r['unsigned_xades_cert_v2_original_inventory']
                        if 'unsigned_xades_cert_v2_original_inventory' in r
                        else r['verified_live_ec410_report_sha256'])

    def test_02_real_signed_p256_xml_and_certificate_v2(self):
        self.f.signer_key = ec.generate_private_key(ec.SECP256R1())
        self.f.signer = ec410fixture.make_cert(
            'EC411 P256 local signer', self.f.signer_key, self.f.mid,
            self.f.mid_key, self.f.now, ca=False, path_len=None, serial=41107)
        self.f.refresh(roster=True)
        self.resign(True); self.resign(False)
        self.f.refresh(roster=True)
        self.ec410_report = self.f.calibrate()
        self.extra.update(self.f.extra)
        r = self.calibrate()
        self.assertEqual(r['verified_joint_signed_xades_v2_and_real_ec410_parent_publishers'],2)

    def test_03_genuinely_signed_wrong_x509_sha256_denied(self):
        def mutate(_, spp, cert):
            cert.find('.//' + core.DSTAG('DigestValue')).text = (
                base64.b64encode(b'\x45'*32).decode())
        self.refresh(mutate=mutate)
        self.denied('X509_SHA256_MISMATCH')

    def test_04_genuinely_signed_wrong_issuer_serial_der_denied(self):
        def mutate(_, spp, cert):
            x = cert.find(core.V2TAG('IssuerSerialV2'))
            x.text = base64.b64encode(core.issuer_serial_v2_der(
                self.f.mid)).decode()
        self.refresh(mutate=mutate)
        self.denied('ISSUER_SERIAL_DER_MISMATCH')

    def test_05_genuinely_signed_missing_certificate_v2_denied(self):
        def mutate(_, spp, cert):
            spp.remove(cert.getparent())
        self.refresh(mutate=mutate)
        self.denied('SIGNING_TIME_AND_V132_SIGNING_CERTIFICATE_V2')

    def test_06_genuinely_signed_duplicate_certificate_v2_denied(self):
        def mutate(_, spp, cert):
            spp.append(deepcopy(cert.getparent()))
        self.refresh(mutate=mutate)
        self.denied('SIGNING_TIME_AND_V132_SIGNING_CERTIFICATE_V2')

    def test_07_genuinely_signed_nonsha256_digest_algorithm_denied(self):
        def mutate(_, spp, cert):
            cert.find('.//' + core.DSTAG('DigestMethod')).set(
                'Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1')
        self.refresh(mutate=mutate)
        self.denied('CERT_V2_SHA256_DIGEST_ISSUER_EXACT_STRUCTURE')

    def test_08_genuinely_signed_issuer_serial_wrong_base64_denied(self):
        def mutate(_, spp, cert):
            cert.find(core.V2TAG('IssuerSerialV2')).text = '%%%notbase64'
        self.refresh(mutate=mutate)
        self.denied('ISSUER_SERIAL_DER_CANONICAL_BASE64')

    def test_09_genuinely_signed_wrong_v2_namespace_denied(self):
        def mutate(_, spp, cert):
            cert.getparent().tag = '{http://uri.etsi.org/01903/v1.4.1#}SigningCertificateV2'
        self.refresh(mutate=mutate)
        self.denied('SIGNING_TIME_AND_V132_SIGNING_CERTIFICATE_V2')

    def test_10_signed_extra_certificate_digest_chain_denied(self):
        def mutate(_, spp, cert):
            cert.getparent().append(deepcopy(cert))
        self.refresh(mutate=mutate)
        self.denied('SIGNED_XADES_V2_EXACTLY_ONE_CERT')

    def test_11_source_byte_tampering_parent_denial_is_not_upgrade(self):
        # The actual EC410 parent sees a changed SHA-pinned original even if
        # our child is only given a previously returned valid parent report.
        entry = self.f.bundle['epochs'][0]['original_historical_signed_lotl_xml']
        raw = Path(entry['path']).read_bytes()
        bad = raw.replace(b'SigningCertificateV2', b'SigningCertificateV3',1)
        self.f.bundle['epochs'][0]['original_historical_signed_lotl_xml'] = (
            self.f.archive(bad, 'ec411-tampered-signature'))
        self.f.refresh()
        self.extra.update(self.f.extra)
        # Directly obtain the REAL local EC410 denial (with only its older EC409 mocked).
        with self.assertRaises(errors.AnchorError):
            self.f.evaluate()
        # The real parent must deny, not yield a positive report for EC411.

    def test_12_new_epoch_inventory_sha_mismatch_is_unresolved_not_pass(self):
        self.calibrate()
        self.extra[core.REPEAT_NAMES[0]] = ['a'*64]
        result = self.evaluate()
        self.assertTrue(result[core.FLAGS[1]])
        self.assertEqual(result['exit_code'], 2)

    def test_13_whole_original_inventory_pin_mismatch_no_upgrade(self):
        self.calibrate()
        self.extra[core.AUDIT_ONLY[0]] = 'b'*64
        r = self.evaluate(False)
        self.assertTrue(r[core.FLAGS[1]])
        self.assertFalse(r['bounded_original_signed_xades_cert_v2_and_real_ec410_consistency'])

    def test_14_parent_adverse_count_stays_zero(self):
        good = self.calibrate()
        r = dict(self.ec410_report)
        rows = [dict(x) for x in r['signed_lotl_epoch_reviews']]
        rows[0]['joint_real_ec409_and_signed_lotl_publisher_count'] = 0
        r['signed_lotl_epoch_reviews'] = rows
        r['verified_joint_signed_lotl_and_real_ec409_parent_publishers'] = 0
        r[core.parent.FLAGS[4]] = True
        r['bounded_original_lotl_and_real_ec409_parent_consistency'] = False
        r['status'] = core.parent.OUTCOMES[4] + '_unresolved'
        self.ec410_report = r
        bad = self.evaluate()
        self.assertTrue(bad[core.FLAGS[0]])
        self.assertEqual(bad['verified_joint_signed_xades_v2_and_real_ec410_parent_publishers'], 0)

    def test_15_der_issuer_serial_v2_encoding_positive_and_minimal(self):
        der = core.issuer_serial_v2_der(self.f.signer)
        self.assertTrue(der.startswith(b'\x30'))
        self.assertIn(self.f.signer.issuer.public_bytes(), der)
        self.assertEqual(der, core.issuer_serial_v2_der(
            x509.load_der_x509_certificate(
                self.f.signer.public_bytes(serialization.Encoding.DER))))

    def test_16_true_parent_output_contract_denies_forged_promoted_pass(self):
        self.calibrate()
        r = dict(self.ec410_report)
        r['exit_code'] = 0
        self.ec410_report = r
        with self.assertRaises(errors.AnchorError) as e:
            self.evaluate()
        self.assertEqual(e.exception.status, 'unavailable')

    def test_17_real_inherited_input_grammar_and_pins(self):
        full = {k: self.extra.get(k, 'fixture-old-unused')
                for k in core.PARENT_SCALARS}
        full.update({k: self.extra.get(k, []) for k in core.PARENT_REPEATS})
        full.update(self.extra)
        full.pop(core.AUDIT_ONLY[0], None)
        with patch.object(core.parent, '_inputs', return_value={}):
            self.assertIsInstance(core._inputs(full, True), dict)
            wrong = dict(full)
            wrong[core.REPEAT_NAMES[1]] = [3]
            with self.assertRaises(errors.AnchorError):
                core._inputs(wrong, True)

    def test_18_error_exit3_never_success_or_legal_trust(self):
        e = errors.AnchorError('EC411_SIGNER_CERT_BAD','permission_denied')
        result = operator.denial('audit-historical-ec339-xades-cert-v2', e)
        self.assertEqual(result['exit_code'], 3)
        self.assertFalse(any(result[k] for k in core.NEGATIVES))
        self.assertNotIn('bounded_original_signed_xades_cert_v2_and_real_ec410_consistency',
                         result)

    def test_19_missing_xades_in_original_ec410_is_rejected_by_child(self):
        self.f.resign(historical=True,xades=False)
        self.f.refresh()
        self.ec410_report = self.f.calibrate()
        self.extra.update(self.f.extra)
        self.denied('XADES_SIGNED_PROPERTIES_REQUIRED')

    def test_20_explicit_issuer_serial_v2_required(self):
        def mutate(_, spp, cert):
            cert.remove(cert.find(core.V2TAG('IssuerSerialV2')))
        self.refresh(mutate=mutate)
        self.denied('SIGNED_XADES_V2_EXACTLY_ONE_ISSUERSERIALV2')


    def test_21_signed_xades_v2_attribute_injection_denied(self):
        def mutate(_, spp, cert):
            cert.set('URI','https://untrusted.example.test/issuer')
        self.refresh(mutate=mutate)
        self.denied('CERT_V2_SHA256_DIGEST_ISSUER_EXACT_STRUCTURE')

    def test_22_signed_xades_v2_order_swap_denied(self):
        def mutate(_, spp, cert):
            children=list(cert)
            cert.remove(children[0]); cert.remove(children[1])
            cert.append(children[1]); cert.append(children[0])
        self.refresh(mutate=mutate)
        self.denied('CERT_V2_SHA256_DIGEST_ISSUER_EXACT_STRUCTURE')



if __name__ == '__main__':
    unittest.main()
