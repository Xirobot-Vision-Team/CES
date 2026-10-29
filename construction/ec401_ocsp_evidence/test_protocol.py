#!/usr/bin/env python3
"""Synthetic real DER OCSP issuer/delegate signing and adversarial tests.

EC401 parent EC400.audit is MOCKED with a true locally generated EC400 report.
EC400 / EC399 parent audits were themselves mocked against synthetic deeper
ancestors. No unmocked official historical source, legal trust or PS smoke PASS.
"""
from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from asn1crypto import ocsp as aocsp, core as acore
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from ec295_delivery_anchor import anchor as errors
from ec400_native_cms import test_protocol as cms_fixture
from . import protocol as core

UTC = timezone.utc
H = datetime(2026, 10, 25, 14, 35, tzinfo=UTC)
E = datetime(2026, 10, 26, 11, 0, tzinfo=UTC)


def _signed(key, body):
    return key.sign(body, ec.ECDSA(hashes.SHA256())) if isinstance(
        key, ec.EllipticCurvePrivateKey) else key.sign(body)


def make_response(certificate, issuer, key, produced, *, responder=None,
                  status=ocsp.OCSPCertStatus.GOOD, digest=hashes.SHA256(),
                  stale=False, wrong_serial=False, bad_signature=False,
                  no_embedded=False, time_basis=None, sign_as_key=None):
    """Actual OCSP signed DER, with deterministic time re-signed after build.

    cryptography chooses runtime producedAt when building. asn1crypto is only
    used to change producedAt and re-sign the genuine ResponseData (not bypass
    verification). Every resulting DER is parsed and verified by the receiver.
    """
    subject = certificate
    if wrong_serial:
        subject = x509.CertificateBuilder().subject_name(certificate.subject).issuer_name(
            certificate.issuer).public_key(certificate.public_key()).serial_number(12345678).not_valid_before(
            datetime(2024, 1, 1, tzinfo=UTC)).not_valid_after(
            datetime(2030, 1, 1, tzinfo=UTC)).sign(key, algorithm=None if isinstance(
                key, ed25519.Ed25519PrivateKey) else hashes.SHA256())
    basis = time_basis or produced
    is_hist = basis == H
    this = (H - timedelta(hours=1) if is_hist else E - timedelta(hours=1))
    until = (H + timedelta(hours=1) if is_hist else E + timedelta(hours=1))
    if stale:
        this = H - timedelta(hours=2)
        until = H - timedelta(minutes=90)
        produced = H - timedelta(minutes=95)
    rb = (ocsp.OCSPResponseBuilder()
          .add_response(cert=subject, issuer=issuer, algorithm=digest,
                        cert_status=status, this_update=this, next_update=until,
                        revocation_time=(H-timedelta(days=1) if status ==
                                         ocsp.OCSPCertStatus.REVOKED else None),
                        revocation_reason=(x509.ReasonFlags.key_compromise if status ==
                                           ocsp.OCSPCertStatus.REVOKED else None))
          .responder_id(ocsp.OCSPResponderEncoding.HASH, responder or issuer))
    if responder is not None and not no_embedded:
        rb = rb.certificates([responder])
    out = rb.sign(key, algorithm=None if isinstance(key, ed25519.Ed25519PrivateKey)
                  else hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    obj = aocsp.OCSPResponse.load(out, strict=True)
    basic = obj['response_bytes']['response'].parsed
    basic['tbs_response_data']['produced_at'] = acore.GeneralizedTime(produced)
    new_data = basic['tbs_response_data'].dump(force=True)
    sig = _signed(sign_as_key or key, new_data)
    if bad_signature:
        sig = bytes([sig[0] ^ 1]) + sig[1:]
    basic['signature'] = sig
    obj['response_bytes']['response'] = basic
    return obj.dump(force=True)


class GenuineSignedOCSPTests(unittest.TestCase):
    def setUp(self):
        parent = cms_fixture.NativeCMSOriginalTests(
            'test_01_authentic_two_algorithms_detached_der_two_true_signers')
        parent.setUp()
        self.addCleanup(parent.doCleanups)
        parent.calibrate()
        self.p400 = parent.evaluate(False)
        self.assertEqual(self.p400['verified_parent_and_native_cms_joint_signer_count'], 2)
        self.old = parent
        self.opts = dict(parent.opts)
        self.p400ref = {'path': self.opts[core.parent.NEW_SCALARS[0]],
                        'sha256': self.opts[core.parent.NEW_SCALARS[1]]}
        self.fixture = parent.old.fixture
        self.chains = parent.old.chains
        self.keys = parent.old.keys
        self.bundle = {'schema': core.BUNDLE_SCHEMA,
                       'claimed_directory_lineage_id': parent.old.old.lineage,
                       'parent_ec400_native_cms_bundle_original': self.p400ref,
                       'epochs': [{'epoch_index': 0, 'publishers': []}]}
        for role in ('A', 'B'):
            chain = self.chains[role]
            link = {'subject_certificate_sha256': chain['leaf']['sha256'],
                    'issuer_certificate_sha256': chain['root']['sha256'],
                    'historical_responder_certificate_original': None,
                    'evaluation_responder_certificate_original': None}
            for phase, time in [('historical', H), ('evaluation', E)]:
                link[phase + '_ocsp_response_original'] = self.fixture.archive(
                    make_response(chain['leafcert'], chain['rootcert'],
                                  self.keys[role][0], time),
                    'ec401-'+role+'-'+phase)
            self.bundle['epochs'][0]['publishers'].append({
                'publisher_id': 'Publisher' + role, 'chain_links': [link]})
        self._save()
        self.opts[core.NEW_SCALARS[2]] = self.link('A')[
            'historical_ocsp_response_original']['sha256']
        self.opts[core.NEW_SCALARS[3]] = self.link('B')[
            'historical_ocsp_response_original']['sha256']
        self.opts[core.REPEAT_NAMES[0]] = ['a' * 64]
        self.opts[core.REPEAT_NAMES[1]] = [0]

    def link(self, role):
        return self.bundle['epochs'][0]['publishers'][0 if role=='A' else 1][
            'chain_links'][0]

    def _save(self):
        r = self.fixture.archive(self.bundle, 'ec401-ocsp-bundle')
        self.opts[core.NEW_SCALARS[0]] = r['path']
        self.opts[core.NEW_SCALARS[1]] = r['sha256']

    def replace(self, role, phase, raw, delegated=None):
        link = self.link(role)
        link[phase + '_ocsp_response_original'] = self.fixture.archive(
            raw, 'ec401-new-'+role+'-'+phase)
        if delegated is not None:
            link[phase + '_responder_certificate_original'] = self.fixture.archive(
                delegated.public_bytes(serialization.Encoding.DER),
                'ec401-delegate-'+role+'-'+phase)
        if role == 'A' and phase == 'historical':
            self.opts[core.NEW_SCALARS[2]] = link[phase+'_ocsp_response_original']['sha256']
        if role == 'B' and phase == 'historical':
            self.opts[core.NEW_SCALARS[3]] = link[phase+'_ocsp_response_original']['sha256']
        self._save()

    def evaluate(self, derive=True):
        with patch.object(core, '_inputs', return_value={}), \
             patch.object(core.parent, 'audit', return_value=self.p400):
            return core.derive_inventory(**self.opts) if derive else core.audit(**self.opts)

    def denied(self):
        with self.assertRaises(errors.AnchorError):
            self.evaluate()

    def calibrate(self):
        row = self.evaluate()['ocsp_epoch_reviews'][0]
        self.opts[core.REPEAT_NAMES[0]] = [row['ocsp_original_inventory_sha256']]
        self.opts[core.REPEAT_NAMES[1]] = [2]
        result = self.evaluate()
        self.opts[core.AUDIT_ONLY[0]] = result['receiver_verified_ocsp_inventory_sha256']
        return result

    def delegate(self, role, *, nocheck=True, wrong_eku=False):
        rootkey = self.keys[role][0]
        root = self.chains[role]['rootcert']
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                            'Synthetic OCSP delegated ' + role)])
        builder = (x509.CertificateBuilder()
            .issuer_name(root.subject).subject_name(name).public_key(key.public_key())
            .serial_number(3221 if role == 'A' else 3222)
            .not_valid_before(datetime(2025, 1, 1, tzinfo=UTC))
            .not_valid_after(datetime(2029, 1, 1, tzinfo=UTC))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True,
                 content_commitment=False, key_encipherment=False,
                 data_encipherment=False, key_agreement=False,
                 key_cert_sign=False, crl_sign=False,
                 encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH if wrong_eku else
                ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False))
        if nocheck:
            builder = builder.add_extension(x509.OCSPNoCheck(), critical=False)
        return (builder.sign(rootkey, algorithm=None if isinstance(
            rootkey, ed25519.Ed25519PrivateKey) else hashes.SHA256()), key)

    def test_01_two_real_publisher_signed_historical_and_evaluation_responses(self):
        out = self.calibrate()
        self.assertEqual(out['verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'], 2)
        self.assertTrue(out['bounded_local_issuer_ocsp_and_real_parent_consistency'])
        self.assertEqual(out['exit_code'], 2)
        proofs = out['unsigned_ocsp_evidence_inventory']['epochs'][0]['publishers']
        self.assertEqual([p['publisher_id'] for p in proofs], ['PublisherA','PublisherB'])
        self.assertEqual(proofs[0]['real_chain_link_ocsp'][0]['historical'][
            'responder_authorization'], 'direct_issuer')

    def test_02_exact_externally_held_derived_inventory_audit(self):
        self.calibrate()
        out = self.evaluate(False)
        self.assertEqual(out['schema'], core.RESULT_SCHEMA)
        self.assertNotIn('unsigned_ocsp_evidence_inventory', out)
        self.assertEqual(out['verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'],2)
        self.assertTrue(out[core.FLAGS[-1]])
        self.assertFalse(any(out[k] for k in core.NEGATIVES))

    def test_03_forged_response_signature_denied(self):
        ch = self.chains['A']
        self.replace('A', 'historical', make_response(ch['leafcert'], ch['rootcert'],
                     self.keys['A'][0], H, bad_signature=True))
        self.denied()

    def test_04_false_certid_or_different_subject_denied(self):
        ch = self.chains['A']
        self.replace('A', 'historical', make_response(ch['leafcert'], ch['rootcert'],
                     self.keys['A'][0], H, wrong_serial=True))
        self.denied()

    def test_05_sha1_certid_rejected_even_if_actually_signed(self):
        ch = self.chains['A']
        self.replace('A', 'historical', make_response(ch['leafcert'], ch['rootcert'],
                     self.keys['A'][0], H, digest=hashes.SHA1()))
        self.denied()

    def test_06_genuine_but_stale_response_not_credited(self):
        ch = self.chains['A']
        self.replace('A', 'historical', make_response(ch['leafcert'], ch['rootcert'],
                     self.keys['A'][0], H, stale=True))
        r=self.evaluate()
        self.assertEqual(r['verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'],1)
        self.assertTrue(r[core.FLAGS[3]])

    def test_07_valid_revoked_status_is_preserved_as_adverse_evidence(self):
        ch=self.chains['B']
        self.replace('B','evaluation',make_response(ch['leafcert'],ch['rootcert'],
                     self.keys['B'][0],E,status=ocsp.OCSPCertStatus.REVOKED))
        r=self.evaluate()
        self.assertEqual(r['verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'],1)
        self.assertTrue(r[core.FLAGS[4]])

    def test_08_valid_unknown_status_is_not_counted_as_good(self):
        ch=self.chains['B']
        self.replace('B','evaluation',make_response(ch['leafcert'],ch['rootcert'],
                     self.keys['B'][0],E,status=ocsp.OCSPCertStatus.UNKNOWN))
        r=self.evaluate()
        self.assertEqual(r['verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'],1)
        self.assertTrue(r[core.FLAGS[4]])

    def test_09_missing_original_degrades_count_never_invents_good(self):
        self.link('A')['evaluation_ocsp_response_original']=None
        self._save()
        r=self.evaluate()
        self.assertEqual(r['verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'],1)
        self.assertTrue(r[core.FLAGS[2]])

    def test_10_delegated_ocsp_certificate_with_real_issuer_signature_and_nocheck(self):
        d,k=self.delegate('A')
        for phase,time in (('historical',H),('evaluation',E)):
            self.replace('A',phase,make_response(self.chains['A']['leafcert'],
                         self.chains['A']['rootcert'],k,time,responder=d),d)
        r=self.calibrate()
        self.assertEqual(r['verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'],2)
        proof=r['unsigned_ocsp_evidence_inventory']['epochs'][0]['publishers'][0][
             'real_chain_link_ocsp'][0]['historical']
        self.assertEqual(proof['responder_authorization'],'issuer_delegated_nocheck')

    def test_11_delegated_without_nocheck_rejected(self):
        d,k=self.delegate('A',nocheck=False)
        self.replace('A','evaluation',make_response(self.chains['A']['leafcert'],
                     self.chains['A']['rootcert'],k,E,responder=d),d)
        self.denied()

    def test_12_delegated_without_ocsp_signing_eku_rejected(self):
        d,k=self.delegate('A',wrong_eku=True)
        self.replace('A','evaluation',make_response(self.chains['A']['leafcert'],
                     self.chains['A']['rootcert'],k,E,responder=d),d)
        self.denied()

    def test_13_replacement_with_other_publisher_original_denied(self):
        self.link('B')['evaluation_ocsp_response_original'] = copy.deepcopy(
            self.link('A')['historical_ocsp_response_original'])
        self._save()
        self.denied()

    def test_14_inaccurate_bundle_digest_refused(self):
        self.opts[core.NEW_SCALARS[1]]='f'*64
        self.denied()

    def test_15_parent_inconsistency_never_grants_independent_credit(self):
        self.p400[core.parent.FLAGS[0]]=True
        self.p400['bounded_local_native_cms_original_and_ec399_consistency']=False
        self.p400['status']=core.parent.OUTCOMES[0]+'_unresolved'
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[0]])
        self.assertEqual(r['verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'],0)

    def test_16_a_separately_signed_wrong_key_is_denied(self):
        ch=self.chains['A']
        self.replace('A','evaluation',make_response(ch['leafcert'],ch['rootcert'],
                     self.keys['A'][0],E,sign_as_key=self.keys['B'][0]))
        self.denied()

    def test_17_external_per_epoch_inventory_disagreement_detected(self):
        self.calibrate()
        self.opts[core.REPEAT_NAMES[0]]=['f'*64]
        r=self.evaluate(False)
        self.assertTrue(r[core.FLAGS[1]])
        self.assertEqual(r['exit_code'],2)

    def test_18_external_whole_inventory_mismatch_is_unresolved(self):
        self.calibrate()
        self.opts[core.AUDIT_ONLY[0]]='f'*64
        r=self.evaluate(False)
        self.assertTrue(r[core.FLAGS[1]])

    def test_19_original_der_file_tamper_denied(self):
        f=Path(self.link('A')['historical_ocsp_response_original']['path'])
        f.write_bytes(f.read_bytes()+b'BAD')
        self.denied()

    def test_20_response_generated_retroactively_not_historical_credit(self):
        ch=self.chains['A']
        self.replace('A','historical',make_response(ch['leafcert'],ch['rootcert'],
                     self.keys['A'][0],H+timedelta(minutes=15),time_basis=H))
        r=self.evaluate()
        self.assertEqual(r['verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'],1)


if __name__ == '__main__':
    unittest.main()
