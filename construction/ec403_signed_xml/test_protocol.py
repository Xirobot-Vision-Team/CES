#!/usr/bin/env python3
"""EC403 actual XMLDSig cryptography tests, strictly scoped synthetic ancestry.

Only EC402.audit and child _inputs are mocked here. The inherited EC402
report comes from a REAL locally generated and validated signed PDF/CMS corpus,
whose EC401 parent is itself synthetic and mocked in the EC402 child fixture.
Neither real-world official origin nor unmocked all-ancestor history is tested.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from lxml import etree
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding, utils
from ec295_delivery_anchor import anchor as errors
from ec402_signed_pdf import test_protocol as parent_fixture
from . import protocol as core


def _sub(node, ns, name, **attrs):
    return etree.SubElement(node, '{%s}%s' % (ns, name), **attrs)


def make_original_xml(source, key, certificate, role, lineage, pdf_sha,
                      *, source_sha=None, epoch=0, time='2026-10-25T14:35:00Z',
                      wrong_cert=None, change_digest=False, tamper_signature=False,
                      wrong_method=False, external_uri=False,
                      wrong_transform=False, extra_object=False,
                      wrong_source=False, inject_doctype=False,
                      claim_role=None, wrong_pdf=False):
    """Create cryptographically *real* XMLDSig with canonical ds:Object ref.

    This signing helper is synthetic fixture code only: the production verifier
    never creates a key, certificate, claim, signature or new original file.
    """
    ds = core.NS
    root = etree.Element('{%s}Signature' % ds, nsmap={'ds': ds})
    info = _sub(root, ds, 'SignedInfo')
    _sub(info, ds, 'CanonicalizationMethod', Algorithm=core.C14N)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        method = core.METHOD_ED25519
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        method = (core.METHOD_P384 if isinstance(key.curve, ec.SECP384R1)
                  else core.METHOD_P256)
    else:
        method = core.METHOD_RSA
    if wrong_method:
        method = core.METHOD_RSA
    _sub(info, ds, 'SignatureMethod', Algorithm=method)
    reference = _sub(info, ds, 'Reference', URI=('https://attacker.example/x'
                        if external_uri else '#' + core.OBJECT_ID))
    trans = _sub(reference, ds, 'Transforms')
    _sub(trans, ds, 'Transform', Algorithm=(
         'http://www.w3.org/TR/1999/REC-xslt-19991116'
         if wrong_transform else core.C14N))
    _sub(reference, ds, 'DigestMethod', Algorithm=core.SHA256_URI)
    digest_value = _sub(reference, ds, 'DigestValue')
    value = _sub(root, ds, 'SignatureValue')
    key_info = _sub(root, ds, 'KeyInfo')
    cert_data = _sub(key_info, ds, 'X509Data')
    der = (wrong_cert or certificate).public_bytes(serialization.Encoding.DER)
    _sub(cert_data, ds, 'X509Certificate').text = base64.b64encode(der).decode()
    obj = _sub(root, ds, 'Object', Id=core.OBJECT_ID)
    body = etree.SubElement(obj, '{%s}GazetteClaim' % core.CNS,
        nsmap={'ces':core.CNS}, PublisherId=claim_role or role,
        DirectoryLineageId=lineage, EpochIndex=str(epoch), PublishedUTC=time,
        SourceSHA256=source_sha or hashlib.sha256(source).hexdigest(),
        ParentPDFSHA256=('f' * 64 if wrong_pdf else pdf_sha), Encoding='base64')
    etree.SubElement(body, '{%s}SourceBytes' % core.CNS).text = base64.b64encode(
        source + (b'FRAUD' if wrong_source else b'')).decode()
    if extra_object:
        _sub(root, ds, 'Object', Id=core.OBJECT_ID)
    object_c14n = etree.tostring(obj, method='c14n', exclusive=True, with_comments=False)
    digest = hashlib.sha256(object_c14n).digest()
    if change_digest:
        digest = bytes([digest[0] ^ 1]) + digest[1:]
    digest_value.text = base64.b64encode(digest).decode()
    info_c14n = etree.tostring(info, method='c14n', exclusive=True, with_comments=False)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        sig = key.sign(info_c14n)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        h = hashes.SHA384() if isinstance(key.curve, ec.SECP384R1) else hashes.SHA256()
        r, s = utils.decode_dss_signature(key.sign(info_c14n, ec.ECDSA(h)))
        size = (key.key_size + 7) // 8
        sig = r.to_bytes(size, 'big') + s.to_bytes(size, 'big')
    else:
        sig = key.sign(info_c14n, padding.PKCS1v15(), hashes.SHA256())
    if tamper_signature:
        sig = bytes([sig[0] ^ 1]) + sig[1:]
    value.text = base64.b64encode(sig).decode()
    data = etree.tostring(root, xml_declaration=True, encoding='UTF-8')
    if inject_doctype:
        data = data.replace(b'<ds:Signature',
                 b'<!DOCTYPE Signature [<!ENTITY out SYSTEM "file:///etc/passwd">]><ds:Signature', 1)
    return data


class GenuineOriginalXMLDSigTests(unittest.TestCase):
    def setUp(self):
        p = parent_fixture.SignedPDFEvidenceTests('test_01_two_real_different_signed_pdf_originals')
        p.setUp()
        self.addCleanup(p.doCleanups)
        p.calibrate()
        self.p402 = p.evaluate(False)  # true local original PDF signatures and CMS
        self.assertEqual(self.p402['verified_joint_parent_ocsp_and_signed_pdf_publishers'], 2)
        self.old = p
        self.fixture = p.fixture
        self.opts = dict(p.opts)
        self.keys = p.old.old.old.keys
        self.certificates = p.old.old.old.chains
        self.lineage = p.old.old.old.old.lineage
        self.source = p.source_bytes
        self.bundle = {'schema': core.BUNDLE_SCHEMA,
                       'claimed_directory_lineage_id': self.lineage,
                       'parent_ec402_signed_pdf_bundle_original': {
                           'path': p.opts[core.parent.NEW_SCALARS[0]],
                           'sha256': p.opts[core.parent.NEW_SCALARS[1]]},
                       'epochs': [{'epoch_index': 0, 'publishers': []}]}
        for name in ('A','B'):
            self.bundle['epochs'][0]['publishers'].append({
                'publisher_id': 'Publisher' + name,
                'signed_xml_original': self.fixture.archive(self.make(name),
                    'ec403-xmlsig-' + name)})
        self._save()
        self.opts[core.NEW_SCALARS[2]] = self.xmlref('A')['sha256']
        self.opts[core.NEW_SCALARS[3]] = self.xmlref('B')['sha256']
        self.opts[core.REPEAT_NAMES[0]] = ['a' * 64]
        self.opts[core.REPEAT_NAMES[1]] = [0]

    def make(self, role, **kwargs):
        return make_original_xml(self.source, self.keys[role][1],
            self.certificates[role]['leafcert'], 'Publisher' + role,
            self.lineage, self.old.pdfref(role)['sha256'], **kwargs)

    def xmlref(self, role):
        return self.bundle['epochs'][0]['publishers'][0 if role == 'A' else 1]['signed_xml_original']

    def _save(self):
        r = self.fixture.archive(self.bundle, 'ec403-genuine-xml-originals-bundle')
        self.opts[core.NEW_SCALARS[0]] = r['path']
        self.opts[core.NEW_SCALARS[1]] = r['sha256']

    def replace(self, role, raw=None, **kwargs):
        rr = self.fixture.archive(self.make(role, **kwargs) if raw is None else raw,
                                  'ec403-modified-xml-' + role)
        self.bundle['epochs'][0]['publishers'][0 if role == 'A' else 1][
            'signed_xml_original'] = rr
        self.opts[core.NEW_SCALARS[2 if role == 'A' else 3]] = rr['sha256']
        self._save()

    def evaluate(self, derive=True):
        with patch.object(core, '_inputs', return_value={}), \
             patch.object(core.parent, 'audit', return_value=self.p402):
            return (core.derive_inventory(**self.opts) if derive
                    else core.audit(**self.opts))

    def calibrate(self):
        first = self.evaluate()
        self.opts[core.REPEAT_NAMES[0]] = [first['original_xmldsig_epoch_reviews'][0][
            'original_xmlsig_epoch_inventory_sha256']]
        self.opts[core.REPEAT_NAMES[1]] = [2]
        second = self.evaluate()
        self.opts[core.AUDIT_ONLY[0]] = second[
            'receiver_verified_original_xmldsig_inventory_sha256']
        return second

    def denied(self):
        with self.assertRaises(errors.AnchorError):
            self.evaluate()

    def test_01_real_two_different_x509_xml_signatures(self):
        res = self.calibrate()
        self.assertTrue(res['bounded_local_original_xmldsig_and_real_ec402_parent_consistency'])
        self.assertEqual(res['verified_joint_parent_pdf_and_xmlsig_publishers'], 2)
        self.assertEqual(res['exit_code'], 2)
        rows = res['unsigned_original_xmldsig_evidence_inventory']['epochs'][0]['publishers']
        self.assertEqual([v['publisher_id'] for v in rows], ['PublisherA','PublisherB'])
        self.assertEqual([r['verified_original_xmlsig']['signature_method_uri'] for r in rows],
                         [core.METHOD_ED25519, core.METHOD_P256])

    def test_02_derive_then_audit_sha_pin(self):
        self.calibrate()
        res = self.evaluate(False)
        self.assertEqual(res['schema'], core.RESULT_SCHEMA)
        self.assertNotIn('unsigned_original_xmldsig_evidence_inventory', res)
        self.assertTrue(res[core.FLAGS[-1]])
        self.assertTrue(all(res[k] is False for k in core.NEGATIVES))

    def test_03_signature_tampering_rejected(self):
        self.replace('A', tamper_signature=True)
        self.denied()

    def test_04_reference_digest_tampering_rejected(self):
        self.replace('A', change_digest=True)
        self.denied()

    def test_05_original_parent_ec398_source_mismatch_rejected(self):
        self.replace('B', wrong_source=True)
        self.denied()

    def test_06_wrong_parent_pdf_original_sha_rejected(self):
        self.replace('A', wrong_pdf=True)
        self.denied()

    def test_07_wrong_real_publisher_role_rejected(self):
        self.replace('B', claim_role='PublisherA')
        self.denied()

    def test_08_offsite_external_reference_rejected(self):
        self.replace('A', external_uri=True)
        self.denied()

    def test_09_xslt_transform_rejected(self):
        self.replace('A', wrong_transform=True)
        self.denied()

    def test_10_xml_signature_wrapping_duplicate_object_rejected(self):
        self.replace('A', extra_object=True)
        self.denied()

    def test_11_xml_dtd_entity_rejected(self):
        self.replace('A', inject_doctype=True)
        self.denied()

    def test_12_invalid_signature_method_key_pair_rejected(self):
        self.replace('B', wrong_method=True)
        self.denied()

    def test_13_signing_time_claim_differs_from_original_notice(self):
        self.replace('A', time='2026-10-26T14:35:00Z')
        self.denied()

    def test_14_pinned_cert_does_not_match_original_ec399_leaf(self):
        self.replace('A', wrong_cert=self.certificates['B']['leafcert'])
        self.denied()

    def test_15_duplicate_xml_paths_across_real_publishers_refused(self):
        self.bundle['epochs'][0]['publishers'][1]['signed_xml_original'] = self.xmlref('A')
        self._save()
        self.denied()

    def test_16_xml_path_alias_to_original_signed_pdf_refused(self):
        self.bundle['epochs'][0]['publishers'][0]['signed_xml_original'] = self.old.pdfref('A')
        self._save()
        self.denied()

    def test_17_parent_joint_credit_zero_not_laundered_by_valid_xml(self):
        self.calibrate()
        bad = copy.deepcopy(self.p402)
        bad['signed_pdf_epoch_reviews'][0]['joint_verified_signed_pdf_and_ocsp_count'] = 0
        bad['verified_joint_parent_ocsp_and_signed_pdf_publishers'] = 0
        bad[core.parent.FLAGS[3]] = True
        bad['bounded_local_signed_pdf_and_real_ec401_parent_consistency'] = False
        bad['status'] = core.parent.OUTCOMES[3] + '_unresolved'
        self.p402 = bad
        res = self.evaluate()
        self.assertEqual(res['verified_joint_parent_pdf_and_xmlsig_publishers'], 0)
        self.assertTrue(res[core.FLAGS[0]])

    def test_18_fake_parent_unresolved_success_denied(self):
        forged = copy.deepcopy(self.p402)
        forged['status'] = 'success'
        self.p402 = forged
        self.denied()

    def test_19_independently_pinned_first_original_mismatch_reported(self):
        self.calibrate()
        self.opts[core.NEW_SCALARS[2]] = 'f' * 64
        res = self.evaluate(False)
        self.assertTrue(res[core.FLAGS[1]])
        self.assertEqual(res['exit_code'], 2)

    def test_20_external_epoch_inventory_and_floor_mismatch_reported(self):
        self.calibrate()
        self.opts[core.REPEAT_NAMES[0]] = ['b' * 64]
        res = self.evaluate(False)
        self.assertTrue(res[core.FLAGS[1]])

    def test_21_full_external_inventory_mismatch_reported(self):
        self.calibrate()
        self.opts[core.AUDIT_ONLY[0]] = 'a' * 64
        res = self.evaluate(False)
        self.assertTrue(res[core.FLAGS[1]])

    def test_22_first_real_publisher_xml_missing_is_denied(self):
        self.bundle['epochs'][0]['publishers'][0]['signed_xml_original'] = None
        self._save()
        self.denied()

    def test_23_corrupt_original_xml_document_byte_rejected(self):
        self.replace('A', raw=self.make('A') + b'<!-- extra document node -->')
        self.denied()

    def test_24_original_bundle_sha_pin_mismatch_denied(self):
        self.opts[core.NEW_SCALARS[1]] = 'f' * 64
        self.denied()

    def test_25_xml_reference_base64_malformed_rejected(self):
        raw = self.make('B').replace(b'<ds:DigestValue>', b'<ds:DigestValue>!!', 1)
        self.replace('B', raw=raw)
        self.denied()

    def _direct_algorithm_fixture(self, key):
        # Unit-test the precise algorithm-encoding branch only, not any
        # synthetic fake certificate's government/X509 chain authority.
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                    'LOCAL TEST ONLY NO OFFICIAL AUTHORITY')])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(99887)
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2035, 1, 1, tzinfo=timezone.utc))
            .sign(key, hashes.SHA384() if isinstance(key, ec.EllipticCurvePrivateKey)
                  else hashes.SHA256()))
        original = make_original_xml(self.source, key, cert,
            'PublisherA', self.lineage, self.old.pdfref('A')['sha256'])
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        ref = {'path': 'mock-local-xml-original',
               'sha256': hashlib.sha256(original).hexdigest()}
        chain = {'refs': [{'path': 'mock-local-cer',
                           'sha256': hashlib.sha256(cert_der).hexdigest()}],
                 'certs': [cert]}
        def read(requested, label, maximum):
            self.assertEqual(requested, ref)
            self.assertTrue(len(original) <= maximum)
            return original
        return core._verify_xml(ref, 'PublisherA', chain, self.source,
            hashlib.sha256(self.source).hexdigest(), self.old.pdfref('A')['sha256'],
            '2026-10-25T14:35:00Z', self.lineage, 0, read)

    def test_26_real_p384_ecdsa_raw_rs_canonical_signature(self):
        result = self._direct_algorithm_fixture(ec.generate_private_key(ec.SECP384R1()))
        self.assertEqual(result['signature_method_uri'], core.METHOD_P384)
        self.assertTrue(result['actual_xmldsig_signature_and_reference_verified'])

    def test_27_real_strong_rsa_pkcs1_sha256_canonical_signature(self):
        result = self._direct_algorithm_fixture(rsa.generate_private_key(
            public_exponent=65537, key_size=2048))
        self.assertEqual(result['signature_method_uri'], core.METHOD_RSA)
        self.assertTrue(result['actual_xmldsig_signature_and_reference_verified'])


if __name__ == '__main__':
    unittest.main()
