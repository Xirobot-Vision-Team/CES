#!/usr/bin/env python3
"""EC413 genuinely CA-signed RSA/P256 DER OCSP adversarial source tests.

Only immediate EC412.audit is mocked in this EC413 child fixture. The parent
report itself comes from real RSA/P256-signed local EC412 CRL and EC411 XAdES
originals. Deeper child fixtures retain their earlier synthetic/mock ancestry.
Production has no mock, signing or user-supplied success assertions.
"""
from __future__ import annotations

import base64
from datetime import timedelta
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509 import ocsp
from lxml import etree

from delivery_anchor import anchor as errors
from lotl_crl import test_protocol as ec412fixture
from . import operator, protocol as core


def make_ocsp(issuer, target, issuer_key, now, *, last_minutes=4,
              valid_days=2, status='good', signer_key=None,
              bad_responder_id=False, algorithm='sha256', embedded=False, forged=False,
              mismatch_target=None):
    state = {'good': ocsp.OCSPCertStatus.GOOD,
             'revoked': ocsp.OCSPCertStatus.REVOKED,
             'unknown': ocsp.OCSPCertStatus.UNKNOWN}[status]
    hash_alg = hashes.SHA1() if algorithm == 'sha1' else hashes.SHA256()
    builder = (ocsp.OCSPResponseBuilder()
        .add_response(cert=mismatch_target or target, issuer=issuer, algorithm=hash_alg,
                      cert_status=state,
                      this_update=now - timedelta(minutes=last_minutes),
                      next_update=now + timedelta(days=valid_days),
                      revocation_time=(now - timedelta(minutes=2)
                          if state is ocsp.OCSPCertStatus.REVOKED else None),
                      revocation_reason=(x509.ReasonFlags.key_compromise
                          if state is ocsp.OCSPCertStatus.REVOKED else None))
        .responder_id(ocsp.OCSPResponderEncoding.HASH, issuer))
    if bad_responder_id:
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong = ec412fixture.ec411fixture.ec410fixture.make_cert(
            'EC413 wrong OCSP responder', wrong_key, issuer, issuer_key, now,
            ca=False, path_len=None, serial=41380)
        signer_key = wrong_key
        builder = (ocsp.OCSPResponseBuilder()
           .add_response(cert=mismatch_target or target, issuer=issuer, algorithm=hash_alg,
              cert_status=state, this_update=now-timedelta(minutes=last_minutes),
              next_update=now+timedelta(days=valid_days),
              revocation_time=(now-timedelta(minutes=2) if
                  state is ocsp.OCSPCertStatus.REVOKED else None),
              revocation_reason=(x509.ReasonFlags.key_compromise if
                  state is ocsp.OCSPCertStatus.REVOKED else None))
           .responder_id(ocsp.OCSPResponderEncoding.HASH, wrong))
    if embedded:
        builder = builder.certificates([issuer])
    der = builder.sign(signer_key or issuer_key, hashes.SHA256()).public_bytes(
        serialization.Encoding.DER)
    return der[:-1] + bytes([der[-1] ^ 1]) if forged else der


class ActualSignedLotlIssuerOCSP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ec412fixture.GenuineOriginalIssuerSignedLotlCRLs.setUpClass()

    @classmethod
    def tearDownClass(cls):
        ec412fixture.GenuineOriginalIssuerSignedLotlCRLs.tearDownClass()

    def setUp(self):
        self.f = ec412fixture.GenuineOriginalIssuerSignedLotlCRLs(
            'test_01_two_true_rsa_ca_signed_crls_in_both_original_windows')
        self.f.setUp()
        # Correct the *synthetic* historical LOTL SigningTime to a truly
        # re-signed XAdES contemporary source UTC; it was originally 30 min
        # before these synthetic clock-issued OCSP originals. No runtime change.
        self._resign_synthetic_historical_xades_time()
        self.parent_report = self.f.calibrate()
        self.assertTrue(self.parent_report[
            'bounded_original_ca_crl_and_real_ec411_parent_consistency'])
        self.now = self.f.b.f.now
        self.extra = dict(self.f.extra)
        self.bundle = {
            'schema': core.BUNDLE_SCHEMA,
            'claimed_directory_lineage_id': self.f.b.f.lineage,
            'parent_ec412_original_lotl_crl_bundle_original': {
                'path': self.extra[core.parent.NEW_SCALARS[0]],
                'sha256': self.extra[core.parent.NEW_SCALARS[1]],
            },
            'epochs': [{
                'epoch_index': 0,
                **{w + '_' + r + '_ca_ocsp_original': None
                   for w in core.WINDOWS for r in core.ROLES},
            }],
        }
        self.raw = {}
        self.new_ocsp()
        self.refresh()

    def tearDown(self):
        self.f.tearDown()

    def _resign_synthetic_historical_xades_time(self):
        b = self.f.b
        previous = b.f.bundle['epochs'][0]['original_historical_signed_lotl_xml']
        root = etree.fromstring(Path(previous['path']).read_bytes())
        sign = root.find(core.lotl.DSTAG('Signature'))
        props = sign.find('.//' + core.lotl.XTAG('SignedProperties'))
        signing = props.find('.//' + core.lotl.XTAG('SigningTime'))
        signing.text = (b.f.now - timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        refs = sign.find(core.lotl.DSTAG('SignedInfo')).findall(
            core.lotl.DSTAG('Reference'))
        refs[1].find(core.lotl.DSTAG('DigestValue')).text = base64.b64encode(
            hashlib.sha256(etree.tostring(props, method='c14n', exclusive=True,
                                           with_comments=False)).digest()).decode()
        si = sign.find(core.lotl.DSTAG('SignedInfo'))
        payload = etree.tostring(si, method='c14n', exclusive=True,
                                 with_comments=False)
        key = b.f.signer_key
        if isinstance(key, ec.EllipticCurvePrivateKey):
            der = key.sign(payload, ec.ECDSA(hashes.SHA256()))
            a, c = utils.decode_dss_signature(der)
            signature = a.to_bytes(32, 'big') + c.to_bytes(32, 'big')
        else:
            signature = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        sign.find(core.lotl.DSTAG('SignatureValue')).text = base64.b64encode(
            signature).decode()
        raw = etree.tostring(root, encoding='utf8', xml_declaration=True)
        b.f.bundle['epochs'][0]['original_historical_signed_lotl_xml'] = (
            b.f.archive(raw, 'ec413-true-signed-contemporary-history'))
        b.f.refresh()
        b.ec410_report = b.f.calibrate()
        b.extra.update(b.f.extra)
        self.f.parent_report = b.calibrate()
        self.f.extra.update(b.extra)
        self.f.bundle['parent_ec410_signed_lotl_bundle_original'] = {
            'path': self.f.extra[core.lotl.NEW_SCALARS[0]],
            'sha256': self.f.extra[core.lotl.NEW_SCALARS[1]],
        }
        self.f.refresh()

    def archive(self, payload, label):
        return self.f.b.f.archive(payload, 'ec413-' + label)

    def new_ocsp(self, mutate=None):
        for w, last in (('historical', 5), ('evaluation', 4)):
            for r in core.ROLES:
                issuer, key, target = (
                    (self.f.b.f.root, self.f.b.f.root_key, self.f.b.f.mid)
                    if r == 'root' else
                    (self.f.b.f.mid, self.f.b.f.mid_key, self.f.b.f.signer))
                kwargs = {'last_minutes': last}
                if mutate:
                    kwargs.update(mutate(w, r, issuer, key, target) or {})
                raw = make_ocsp(issuer, target, key, self.now, **kwargs)
                ref = self.archive(raw, w + '-' + r + '-' + str(len(self.raw)))
                self.bundle['epochs'][0][w + '_' + r + '_ca_ocsp_original'] = ref
                self.raw[(w, r)] = raw

    def refresh(self, *, pins=True):
        bundle_ref = self.archive(self.bundle, 'four-real-issuer-ocsp-bundle')
        self.extra[core.NEW_SCALARS[0]] = bundle_ref['path']
        self.extra[core.NEW_SCALARS[1]] = bundle_ref['sha256']
        if pins:
            self.extra.update({
                k: self.bundle['epochs'][0][w + '_' + r + '_ca_ocsp_original']['sha256']
                for k, (w, r) in zip(core.NEW_SCALARS[2:],
                                      ((w, r) for w in core.WINDOWS
                                       for r in core.ROLES))})
        self.extra[core.REPEAT_NAMES[0]] = ['f' * 64]
        self.extra[core.REPEAT_NAMES[1]] = [0]

    def evaluate(self, deriving=True, *, check_inputs=False):
        opts = dict(self.extra)
        if deriving:
            opts.pop(core.AUDIT_ONLY[0], None)
        with patch.object(core.parent, 'audit', return_value=self.parent_report):
            if check_inputs:
                return core.derive_inventory(**opts) if deriving else core.audit(**opts)
            with patch.object(core, '_inputs', return_value={}):
                return core.derive_inventory(**opts) if deriving else core.audit(**opts)

    def calibrate(self, *, check_inputs=False):
        r = self.evaluate(check_inputs=check_inputs)
        self.extra[core.REPEAT_NAMES[0]] = [
            r['lotl_issuer_ocsp_epoch_reviews'][0][
                'original_lotl_ocsp_epoch_inventory_sha256']]
        self.extra[core.REPEAT_NAMES[1]] = [2]
        r = self.evaluate(check_inputs=check_inputs)
        self.extra[core.AUDIT_ONLY[0]] = (
            r['receiver_verified_lotl_issuer_ocsp_inventory_sha256'])
        return self.evaluate(False, check_inputs=check_inputs)

    def denied(self, part):
        with self.assertRaises(errors.AnchorError) as raised:
            self.evaluate()
        self.assertEqual(raised.exception.status, 'permission_denied')
        self.assertIn(part, raised.exception.code)

    def test_01_four_true_issuer_signed_rsa_ocsp_historical_evaluation(self):
        r = self.calibrate()
        self.assertEqual(r['exit_code'], 2)
        self.assertTrue(r['bounded_original_issuer_ocsp_and_real_ec412_parent_consistency'])
        self.assertEqual(r['verified_joint_ocsp_and_real_ec412_parent_publishers'], 2)
        self.assertTrue(r[core.FLAGS[-3]])
        self.assertFalse(any(r[k] for k in core.NEGATIVES))
        self.assertEqual(r['lotl_issuer_ocsp_epoch_reviews'][0][
            'signed_good_contemporaneous_four_source_windows'], 1)

    def test_02_real_p256_intermediate_ca_signed_ocsp(self):
        self.f.b.f.mid_key = ec.generate_private_key(ec.SECP256R1())
        self.f.b.f.mid = ec412fixture.ec411fixture.ec410fixture.make_cert(
            'EC413 P256 original OCSP mid', self.f.b.f.mid_key,
            self.f.b.f.root, self.f.b.f.root_key, self.now,
            ca=True, path_len=0, serial=41302)
        self.f.b.f.signer = ec412fixture.ec411fixture.ec410fixture.make_cert(
            'EC413 P256 mid original signer', self.f.b.f.signer_key,
            self.f.b.f.mid, self.f.b.f.mid_key, self.now,
            ca=False, path_len=None, serial=41303)
        self.f.b.f.refresh(roster=True)
        self.f.b.resign(True)
        self.f.b.resign(False)
        self.f.b.f.refresh(roster=True)
        self.f.b.ec410_report = self.f.b.f.calibrate()
        self.f.b.extra.update(self.f.b.f.extra)
        self.f.parent_report = self.f.b.calibrate()
        self.f.extra.update(self.f.b.extra)
        self.f.bundle['parent_ec410_signed_lotl_bundle_original'] = {
            'path': self.f.extra[core.lotl.NEW_SCALARS[0]],
            'sha256': self.f.extra[core.lotl.NEW_SCALARS[1]],
        }
        self.f.bundle['parent_ec410_outside_operator_roster_original'] = (
            self.f.b.f.bundle['outside_lotl_operator_roster_original'])
        self.f.new_crls()
        self.f.refresh()
        self.parent_report = self.f.calibrate()
        self.extra.update(self.f.extra)
        self.bundle['parent_ec412_original_lotl_crl_bundle_original'] = {
            'path': self.extra[core.parent.NEW_SCALARS[0]],
            'sha256': self.extra[core.parent.NEW_SCALARS[1]],
        }
        self.new_ocsp()
        self.refresh()
        # Historical fixture SigningTime moved to original 30min earlier by
        # re-sign; valid cryptographic P256, but freshness remains conservative.
        r = self.calibrate()
        self.assertEqual(r['exit_code'], 2)
        self.assertEqual(r['lotl_issuer_ocsp_epoch_reviews'][0][
            'verified_four_original_issuer_ocsp_documents'], 1)
        self.assertEqual(r['lotl_issuer_ocsp_epoch_reviews'][0][
            'signed_good_contemporaneous_four_source_windows'], 0)

    def test_03_true_signed_revoked_leaf_is_unresolved_adverse(self):
        self.new_ocsp(lambda w, r, *_:
            {'status': 'revoked'} if w == 'historical' and r == 'intermediate' else {})
        self.refresh()
        r = self.evaluate()
        self.assertTrue(r[core.FLAGS[3]])
        self.assertEqual(r['verified_joint_ocsp_and_real_ec412_parent_publishers'], 0)

    def test_04_true_signed_unknown_intermediate_is_not_good(self):
        self.new_ocsp(lambda w, r, *_:
            {'status': 'unknown'} if w == 'evaluation' and r == 'root' else {})
        self.refresh()
        r = self.evaluate()
        self.assertTrue(r[core.FLAGS[3]])
        self.assertFalse(r['bounded_original_issuer_ocsp_and_real_ec412_parent_consistency'])

    def test_05_tampered_true_issuer_ocsp_signature_denied(self):
        self.new_ocsp(lambda w, r, *_:
            {'forged': True} if w == 'historical' and r == 'root' else {})
        self.refresh()
        self.denied('INVALID_OR_UNSUPPORTED_TRUE_ISSUER_OCSP')

    def test_06_original_signed_sha1_certid_denied(self):
        self.new_ocsp(lambda w, r, *_:
            {'algorithm': 'sha1'} if w == 'evaluation' and r == 'root' else {})
        self.refresh()
        self.denied('SHA256_NO_EXTENSION')

    def test_07_wrong_responder_key_hash_denied(self):
        self.new_ocsp(lambda w, r, *_:
            {'bad_responder_id': True} if w == 'historical' and r == 'root' else {})
        self.refresh()
        self.denied('RESPONDER_ID_NOT_ACTUAL_DIRECT_ISSUER')

    def test_08_issuer_embedded_certificate_not_direct_subprofile(self):
        self.new_ocsp(lambda w, r, *_:
            {'embedded': True} if w == 'historical' and r == 'intermediate' else {})
        self.refresh()
        self.denied('NO_EMBEDDED_CERT')

    def test_09_signed_ocsp_expired_before_evaluation_utc_has_no_coverage(self):
        self.new_ocsp(lambda w, r, *_:
            {'valid_days': 0}
            if w == 'evaluation' and r == 'intermediate' else {})
        self.refresh()
        r = self.evaluate()
        self.assertTrue(r[core.FLAGS[4]])
        self.assertEqual(r['verified_joint_ocsp_and_real_ec412_parent_publishers'], 0)

    def test_10_authentic_source_ocsp_thisupdate_rolls_back(self):
        self.new_ocsp(lambda w, r, *_:
            {'last_minutes': 6} if w == 'evaluation' and r == 'root' else {})
        self.refresh()
        self.denied('ROLLBACK')

    def test_11_first_independently_held_ocsp_sha_wrong_unresolved(self):
        self.calibrate()
        self.extra[core.NEW_SCALARS[2]] = 'a' * 64
        r = self.evaluate(False)
        self.assertTrue(r[core.FLAGS[1]])
        self.assertEqual(r['exit_code'], 2)

    def test_12_retained_inventory_sha_wrong_unresolved(self):
        self.calibrate()
        self.extra[core.AUDIT_ONLY[0]] = 'e' * 64
        r = self.evaluate(False)
        self.assertTrue(r[core.FLAGS[1]])

    def test_13_parent_ec412_adverse_cannot_be_promoted(self):
        self.calibrate()
        report = dict(self.parent_report)
        report[core.parent.FLAGS[1]] = True
        report['bounded_original_ca_crl_and_real_ec411_parent_consistency'] = False
        report['status'] = core.parent.OUTCOMES[1] + '_unresolved'
        self.parent_report = report
        r = self.evaluate()
        self.assertTrue(r[core.FLAGS[0]])
        self.assertEqual(r['verified_joint_ocsp_and_real_ec412_parent_publishers'], 0)

    def test_14_fake_parent_exit_zero_is_rejected(self):
        report = dict(self.parent_report)
        report['exit_code'] = 0
        self.parent_report = report
        with self.assertRaises(errors.AnchorError) as raised:
            self.evaluate()
        self.assertEqual(raised.exception.status, 'unavailable')

    def test_15_original_ocsp_bytes_tampered_against_sha_pin_denied(self):
        old = self.bundle['epochs'][0]['evaluation_root_ca_ocsp_original']
        self.bundle['epochs'][0]['evaluation_root_ca_ocsp_original'] = {
            'path': old['path'], 'sha256': '9' * 64}
        self.refresh(pins=False)
        with self.assertRaises(errors.AnchorError):
            self.evaluate()

    def test_16_ocsp_reuses_parent_crl_original_path_denied(self):
        self.bundle['epochs'][0]['historical_root_ca_ocsp_original'] = (
            self.f.bundle['epochs'][0]['historical_root_ca_crl_original'])
        self.refresh(pins=False)
        self.denied('ALIASES_PREVIOUS_ORIGINAL')

    def test_17_first_original_ocsp_cannot_be_missing(self):
        self.bundle['epochs'][0]['evaluation_intermediate_ca_ocsp_original'] = None
        self.refresh(pins=False)
        self.denied('PARTIAL_REAPPEARING')

    def test_18_prevent_reuse_of_identical_signed_ocsp_between_windows(self):
        self.bundle['epochs'][0]['evaluation_root_ca_ocsp_original'] = (
            self.bundle['epochs'][0]['historical_root_ca_ocsp_original'])
        self.refresh(pins=False)
        self.denied('ALIASES_PREVIOUS_ORIGINAL')

    def test_19_input_contract_requires_four_unique_pins(self):
        good = {k: self.extra.get(k, 'intentionally-unavailable-ancestor-arg')
                for k in (*core.PARENT_SCALARS, *core.NEW_SCALARS)}
        good.update({k: self.extra.get(k, [])
                     for k in (*core.PARENT_REPEATS, *core.REPEAT_NAMES)})
        with patch.object(core.parent, '_inputs', return_value={}):
            self.assertEqual(set(core._inputs(good, True)),
                             set(core.PARENT_SCALARS) | set(core.PARENT_REPEATS))
            bad = dict(good)
            bad[core.NEW_SCALARS[3]] = bad[core.NEW_SCALARS[2]]
            with self.assertRaises(errors.AnchorError):
                core._inputs(bad, True)

    def test_20_denial_contract_no_legal_pass_or_sources(self):
        response = operator.denial('audit-historical-ec339-lotl-ocsp',
                     errors.AnchorError('EC413_DENIED', 'permission_denied'))
        self.assertEqual(response['exit_code'], 3)
        self.assertEqual(response['schema'], core.DENIAL_SCHEMA)
        self.assertFalse(any(response[k] for k in core.NEGATIVES))

    def test_21_unified_fixed_mode_and_result_contract(self):
        from scripts import ces_next
        response = self.calibrate()
        inputs = {k: self.extra.get(k, 'unused-fixture-parent-arg')
                  for k in ces_next.EC413_ALL_SCALARS}
        inputs.update({k: self.extra.get(k, [])
                       for k, _ in ces_next.EC413_ALL_REPEATS})
        with patch.object(ces_next, '_command', return_value=(2, response)), \
             patch.object(ces_next, '_emit') as emitted:
            rc = ces_next.audit_historical_ec339_lotl_ocsp(
                'DeliveryAudit', 'AuditHistoricalEC339LOTLIssuerOCSP', **inputs)
            self.assertEqual(rc, 2)
            emitted.assert_called_once()

    def test_22_unified_other_mode_denied(self):
        from scripts import ces_next
        with self.assertRaises(Exception):
            ces_next.audit_historical_ec339_lotl_ocsp(
                'DeliveryAudit', 'AuditHistoricalEC339LOTLCARevocation')

    def test_23_both_isolated_and_unified_commands_parse(self):
        from scripts import ces_next
        self.assertIn('audit-historical-ec339-lotl-ocsp',
                      operator.parser()._subparsers._group_actions[0].choices)
        self.assertIn('audit-historical-ec339-lotl-ocsp',
                      ces_next.build_parser()._subparsers._group_actions[0].choices)


    def test_24_genuine_signed_ocsp_for_different_target_certid_denied(self):
        foreign_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048)
        other = ec412fixture.ec411fixture.ec410fixture.make_cert(
            'EC413 wrong subordinate certificate', foreign_key,
            self.f.b.f.root, self.f.b.f.root_key, self.now,
            ca=True, path_len=0, serial=41390)
        self.new_ocsp(lambda w, r, *_:
            {'mismatch_target': other} if w == 'historical' and r == 'root' else {})
        self.refresh()
        self.denied('CERTID_NOT_ACTUAL_PINNED_CA_CHAIN_LINK')

    def test_25_signed_ocsp_unsuccessful_response_not_status_evidence(self):
        raw = ocsp.OCSPResponseBuilder.build_unsuccessful(
            ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(
                serialization.Encoding.DER)
        self.bundle['epochs'][0]['evaluation_root_ca_ocsp_original'] = (
            self.archive(raw, 'unsuccessful-ocsp-not-evidence'))
        self.refresh()
        self.denied('MUST_BE_SUCCESSFUL_BASIC_RESPONSE')

    def test_26_outside_joint_floor_does_not_promote_unknown_status(self):
        self.new_ocsp(lambda w, r, *_:
            {'status': 'unknown'} if w == 'historical' and r == 'root' else {})
        self.refresh()
        self.extra[core.REPEAT_NAMES[1]] = [2]
        r = self.evaluate()
        self.assertTrue(r[core.FLAGS[1]])
        self.assertTrue(r[core.FLAGS[3]])
        self.assertEqual(r['verified_joint_ocsp_and_real_ec412_parent_publishers'], 0)


if __name__ == '__main__':
    unittest.main()
