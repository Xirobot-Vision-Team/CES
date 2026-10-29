#!/usr/bin/env python3
"""EC402 real synthetic PDF /Contents ByteRange and signed CMS tests.

Mandatory EC401.audit is MOCKED ONLY in this child synthetic fixture using a
real local EC401 OCSP verification report. EC401 fixture itself mocks EC400,
and earlier fixtures mock older layers. Never call this real-world acceptance.
"""
from __future__ import annotations
import copy
import hashlib
from io import BytesIO
import re
import unittest
from unittest.mock import patch

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (ArrayObject, ByteStringObject, DictionaryObject,
                           NameObject, NumberObject, TextStringObject)
from ec295_delivery_anchor import anchor as errors
from ec401_ocsp_evidence import test_protocol as ec401_fixture
from ec400_native_cms import test_protocol as ec400_fixture
from . import protocol as core


MARKER = b'8888888888'
MAX_SIG_BYTES = 8192


def make_original_pdf(source, certs, role, *, tamper_cms=False,
                      wrong_embedded=False, unsigned_extra=False,
                      bad_range=False, wrong_subfilter=False,
                      omit_source=False, wrong_time=False,
                      wrong_signer=False, corrupt_bytes=False):
    """Actually sign a minimal pypdf PDF, with real signed DER CMS and byte spans.

    /ByteRange numbers are filled BEFORE the CMS signature is computed.
    Only the reserved /Contents hex digits, excluded by /ByteRange, are replaced
    after signing. No verifier, certificate validation or parent audit is mocked.
    """
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    if not omit_source:
        writer.add_attachment(core.ATTACHMENT_NAME,
                              source + b'altered' if wrong_embedded else source)
    sig = DictionaryObject({
        NameObject('/Type'): NameObject('/Sig'),
        NameObject('/Filter'): NameObject('/Adobe.PPKLite'),
        NameObject('/SubFilter'): NameObject('/adbe.pkcs7.sha1') if wrong_subfilter
                                   else NameObject('/ETSI.CAdES.detached'),
        NameObject('/ByteRange'): ArrayObject([NumberObject(0),
                                  NumberObject(8888888888),
                                  NumberObject(8888888888),
                                  NumberObject(8888888888)]),
        NameObject('/Contents'): ByteStringObject(b'\x00' * MAX_SIG_BYTES),
    })
    field = DictionaryObject({
        NameObject('/FT'): NameObject('/Sig'),
        NameObject('/T'): TextStringObject('CES Genuine Gazette Signing'),
        NameObject('/V'): writer._add_object(sig),
    })
    writer._root_object[NameObject('/AcroForm')] = writer._add_object(
        DictionaryObject({NameObject('/Fields'): ArrayObject([
            writer._add_object(field)])}))
    data = BytesIO()
    writer.write(data)
    raw = data.getvalue()
    gap_marker = b'<' + b'0' * (2 * MAX_SIG_BYTES) + b'>'
    assert raw.count(gap_marker) == 1, 'PDF fixture Contents serializer changed'
    left = raw.index(gap_marker)
    right = left + len(gap_marker)
    assert raw.count(MARKER) == 3
    values = [left, right, len(raw) - right]
    if bad_range:
        values[2] -= 1
    for number in values:
        raw = raw.replace(MARKER, f'{number:010d}'.encode('ascii'), 1)
    signed = raw[:left] + raw[right:]
    signing_time = ec400_fixture.SIGNED_TIME
    if wrong_time:
        from datetime import timedelta
        signing_time += timedelta(minutes=1)
    cms = ec400_fixture.make_cms(
        signed, certs, signers=('B' if wrong_signer else role,),
        certs=(role,), signing_time=signing_time,
        tamper_signature=tamper_cms)
    assert len(cms) < MAX_SIG_BYTES
    replacement = b'<' + (cms + b'\x00' * (MAX_SIG_BYTES - len(cms))).hex().encode() + b'>'
    raw = raw[:left] + replacement + raw[right:]
    if unsigned_extra:
        raw += b'\n%INCREMENTAL_UNCOVERED\n'
    if corrupt_bytes:
        raw = raw[:10] + bytes([raw[10] ^ 1]) + raw[11:]
    return raw


class SignedPDFEvidenceTests(unittest.TestCase):
    def setUp(self):
        p = ec401_fixture.GenuineSignedOCSPTests(
            'test_01_two_real_publisher_signed_historical_and_evaluation_responses')
        p.setUp()
        self.addCleanup(p.doCleanups)
        p.calibrate()
        self.p401report = p.evaluate(False)
        self.assertEqual(self.p401report[
            'verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'], 2)
        self.old = p
        self.source_bytes = p.old.source_bytes
        self.fixture = p.fixture
        self.opts = dict(p.opts)
        self.b401 = {'path': p.opts[core.parent.NEW_SCALARS[0]],
                     'sha256': p.opts[core.parent.NEW_SCALARS[1]]}
        self.bundle = {'schema': core.BUNDLE_SCHEMA,
                       'claimed_directory_lineage_id': p.old.old.old.lineage,
                       'parent_ec401_issuer_ocsp_bundle_original': self.b401,
                       'epochs': [{'epoch_index': 0, 'publishers': []}]}
        for role in ('A', 'B'):
            self.bundle['epochs'][0]['publishers'].append({
                'publisher_id': 'Publisher' + role,
                'signed_pdf_original': self.fixture.archive(
                    make_original_pdf(self.source_bytes, p.old.old, role),
                    'ec402-signed-pdf-' + role)})
        self._save()
        self.opts[core.NEW_SCALARS[2]] = self.pdfref('A')['sha256']
        self.opts[core.NEW_SCALARS[3]] = self.pdfref('B')['sha256']
        self.opts[core.REPEAT_NAMES[0]] = ['f' * 64]
        self.opts[core.REPEAT_NAMES[1]] = [0]

    def pdfref(self, role):
        return self.bundle['epochs'][0]['publishers'][0 if role == 'A' else 1][
            'signed_pdf_original']

    def _save(self):
        r = self.fixture.archive(self.bundle, 'ec402-pdf-bundle')
        self.opts[core.NEW_SCALARS[0]] = r['path']
        self.opts[core.NEW_SCALARS[1]] = r['sha256']

    def replace(self, role, **kwargs):
        raw = make_original_pdf(self.source_bytes, self.old.old.old,
                                role, **kwargs)
        rr = self.fixture.archive(raw, 'ec402-' + role + '-' +
                                  str(len(self.fixture.__dict__)))
        self.bundle['epochs'][0]['publishers'][0 if role == 'A' else 1][
            'signed_pdf_original'] = rr
        if role == 'A':
            self.opts[core.NEW_SCALARS[2]] = rr['sha256']
        else:
            self.opts[core.NEW_SCALARS[3]] = rr['sha256']
        self._save()

    def evaluate(self, deriving=True):
        with patch.object(core, '_inputs', return_value={}), \
             patch.object(core.parent, 'audit', return_value=self.p401report):
            return (core.derive_inventory(**self.opts) if deriving else
                    core.audit(**self.opts))

    def denied(self):
        with self.assertRaises(errors.AnchorError):
            self.evaluate()

    def calibrate(self):
        first = self.evaluate()
        self.opts[core.REPEAT_NAMES[0]] = [first['signed_pdf_epoch_reviews'][0][
            'signed_pdf_epoch_inventory_sha256']]
        self.opts[core.REPEAT_NAMES[1]] = [2]
        result = self.evaluate()
        self.opts[core.AUDIT_ONLY[0]] = result[
            'receiver_verified_signed_pdf_inventory_sha256']
        return result

    def test_01_two_real_different_signed_pdf_originals(self):
        out = self.calibrate()
        self.assertTrue(out['bounded_local_signed_pdf_and_real_ec401_parent_consistency'])
        self.assertEqual(out['verified_joint_parent_ocsp_and_signed_pdf_publishers'], 2)
        self.assertEqual(out['exit_code'], 2)
        entries = out['unsigned_signed_pdf_evidence_inventory']['epochs'][0]['publishers']
        self.assertEqual([x['publisher_id'] for x in entries], ['PublisherA', 'PublisherB'])
        self.assertTrue(all(x['signed_pdf']['actual_pdf_byte_range_and_cms_signature_valid']
                            for x in entries))

    def test_02_derive_then_exact_audit(self):
        self.calibrate()
        result = self.evaluate(False)
        self.assertNotIn('unsigned_signed_pdf_evidence_inventory', result)
        self.assertEqual(result['schema'], core.RESULT_SCHEMA)
        self.assertTrue(result[core.FLAGS[-1]])
        self.assertFalse(any(result[k] for k in core.NEGATIVES))

    def test_03_bad_real_cms_signature_is_denied(self):
        self.replace('A', tamper_cms=True)
        self.denied()

    def test_04_pdf_embedded_gazette_must_equal_actual_ec398_original(self):
        self.replace('A', wrong_embedded=True)
        self.denied()

    def test_05_cms_signer_must_equal_actual_external_ec399_leaf(self):
        self.replace('A', wrong_signer=True)
        self.denied()

    def test_06_parent_notice_signing_time_cannot_be_rewritten(self):
        self.replace('B', wrong_time=True)
        self.denied()

    def test_07_pdf_uncovered_incremental_append_rejected(self):
        self.replace('A', unsigned_extra=True)
        self.denied()

    def test_08_malformed_byte_range_rejected(self):
        self.replace('B', bad_range=True)
        self.denied()

    def test_09_wrong_pdf_signature_subfilter_rejected(self):
        self.replace('B', wrong_subfilter=True)
        self.denied()

    def test_10_missing_parent_source_attachment_rejected(self):
        self.replace('A', omit_source=True)
        self.denied()

    def test_11_corrupt_signed_pdf_byte_denied(self):
        self.replace('B', corrupt_bytes=True)
        self.denied()

    def test_12_pdf_alias_to_parent_source_denied(self):
        self.bundle['epochs'][0]['publishers'][0]['signed_pdf_original'] = \
            self.old.old.old.old.source
        self._save()
        self.denied()

    def test_13_duplicate_original_for_two_publishers_denied(self):
        self.bundle['epochs'][0]['publishers'][1]['signed_pdf_original'] = self.pdfref('A')
        self._save()
        self.denied()

    def test_14_unpinned_first_pdf_digest_cannot_credit(self):
        self.opts[core.NEW_SCALARS[2]] = 'd' * 64
        result = self.evaluate()
        self.assertTrue(result[core.FLAGS[1]])
        self.assertEqual(result['exit_code'], 2)

    def test_15_epoch_or_whole_hash_mismatch_remains_unresolved(self):
        self.calibrate()
        self.opts[core.REPEAT_NAMES[0]] = ['d' * 64]
        self.opts[core.AUDIT_ONLY[0]] = 'e' * 64
        result = self.evaluate(False)
        self.assertTrue(result[core.FLAGS[1]])
        self.assertEqual(result['exit_code'], 2)

    def test_16_incomplete_real_parent_ocsp_gives_zero_joint_credit(self):
        self.p401report = copy.deepcopy(self.p401report)
        self.p401report['ocsp_epoch_reviews'][0]['joint_verified_ocsp_publisher_count'] = 1
        self.p401report['verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'] = 1
        self.p401report[core.parent.FLAGS[3]] = True
        self.p401report['bounded_local_issuer_ocsp_and_real_parent_consistency'] = False
        self.p401report['status'] = core.parent.OUTCOMES[3] + '_unresolved'
        result = self.evaluate()
        self.assertEqual(result['verified_joint_parent_ocsp_and_signed_pdf_publishers'], 0)
        self.assertTrue(result[core.FLAGS[0]])

    def test_17_reject_forged_parent_report_without_real_schema(self):
        self.p401report = dict(self.p401report)
        self.p401report['status'] = 'PASS'
        self.denied()

    def test_18_missing_later_pdf_is_unresolved_and_not_credited(self):
        self.bundle['epochs'][0]['publishers'][0]['signed_pdf_original'] = None
        self._save()
        self.denied()  # first two originals independently held: mandatory

    def test_19_exact_external_pdf_bundle_sha_must_match(self):
        self.opts[core.NEW_SCALARS[1]] = 'a' * 64
        self.denied()

    def test_20_zero_padding_may_not_hide_unsigned_garbage(self):
        raw = make_original_pdf(self.source_bytes, self.old.old.old, 'A')
        from pypdf import PdfReader
        pr = PdfReader(BytesIO(raw))
        c = pr.get_fields()['CES Genuine Gazette Signing']['/V'].get_object()
        a, b, e, length = list(c['/ByteRange'])
        gap = raw[b:e]
        data = bytes.fromhex(gap[1:-1].decode())
        der = core._der_with_null_padding(data)
        corrupted = der + b'\x01' + b'\x00' * (len(data)-len(der)-1)
        raw = raw[:b] + b'<' + corrupted.hex().encode() + b'>' + raw[e:]
        rr = self.fixture.archive(raw, 'ec402-corrupt-pdf-padding')
        self.bundle['epochs'][0]['publishers'][0]['signed_pdf_original'] = rr
        self._save()
        self.denied()


if __name__ == '__main__':
    unittest.main()
