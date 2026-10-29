#!/usr/bin/env python3
"""EC400 genuinely signed two-signer CMS; parent EC399/ancestors MOCKED.

Locally generated synthetic DER certificates, Ed25519 + P-256 signatures and
true CMS signed attributes prove parser/signature behavior, not official issuers.
"""
from __future__ import annotations
import copy
import hashlib
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from asn1crypto import cms, core as asn1core, x509 as ax509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from delivery_anchor import anchor as errors
from official_certificate import test_protocol as ec399_fixture
from . import protocol as core

UTC = timezone.utc
SIGNED_TIME = datetime(2026, 10, 25, 14, 35, tzinfo=UTC)


def make_cms(content, old, *, attached=False, signers=('A','B'),
             signing_time=SIGNED_TIME, override_content=None, certs=None,
             duplicate=False, weak=False, tamper_signature=False):
    """Real in-process RFC5652 CMS DER with true crypto, not a mocked verifier."""
    infos = []
    for role in signers:
        cert = old.chains[role]['leafcert']
        key = old.keys[role][1]
        native = ax509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
        is_ed = isinstance(key, ed25519.Ed25519PrivateKey)
        digest_name = 'sha1' if weak else ('sha512' if is_ed else 'sha256')
        attr = cms.CMSAttributes([
            cms.CMSAttribute({'type':'content_type', 'values':['data']}),
            cms.CMSAttribute({'type':'message_digest',
                              'values':[hashlib.new(digest_name, content).digest()]}),
            cms.CMSAttribute({'type':'signing_time',
                              'values':[asn1core.UTCTime(signing_time)]}),
        ])
        if duplicate:
            attr.append(cms.CMSAttribute({'type':'message_digest',
                                          'values':[hashlib.new(digest_name, content).digest()]}))
        signed_der = attr.dump(force=True)
        if is_ed:
            signature = key.sign(signed_der)
        else:
            signature = key.sign(signed_der, ec.ECDSA(
                hashes.SHA1() if weak else hashes.SHA256()))
        if tamper_signature:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        infos.append(cms.SignerInfo({
            'version':'v1',
            'sid': {'issuer_and_serial_number': {
                'issuer': native['tbs_certificate']['issuer'],
                'serial_number': cert.serial_number}},
            'digest_algorithm': {'algorithm': digest_name},
            'signed_attrs': attr,
            'signature_algorithm': {'algorithm': 'ed25519' if is_ed else
                                    ('sha1_ecdsa' if weak else 'sha256_ecdsa')},
            'signature': signature}))
    embedded = [cms.CertificateChoices({'certificate':
                ax509.Certificate.load(old.chains[r]['leafcert'].public_bytes(
                     serialization.Encoding.DER))}) for r in (certs or ('A','B'))]
    inner = {'version': 'v1',
             'digest_algorithms': [{'algorithm': x['digest_algorithm']['algorithm'].native}
                                   for x in infos],
             'encap_content_info': {'content_type': 'data'},
             'certificates': embedded, 'signer_infos': infos}
    if attached:
        inner['encap_content_info']['content'] = (
            content if override_content is None else override_content)
    return cms.ContentInfo({'content_type': 'signed_data',
                            'content': cms.SignedData(inner)}).dump(force=True)


class NativeCMSOriginalTests(unittest.TestCase):
    def setUp(self):
        old = ec399_fixture.CertificateGazetteTests('test_01_genuine_two_different_x509_chains_and_two_complete_crls')
        old.setUp()
        self.addCleanup(old.doCleanups)
        self.old = old
        old._calibrate()
        self.parent_report = old.evaluate(False)
        self.assertEqual(self.parent_report['verified_independent_x509_publisher_count'], 2)
        self.opts = dict(old.opts)
        self.source_bytes = Path(old.old.source['path']).read_bytes()
        self.p399ref = {'path':old.opts[core.parent.NEW_SCALARS[0]],
                        'sha256':old.opts[core.parent.NEW_SCALARS[1]]}
        self.body = {'schema':core.BUNDLE_SCHEMA,
                     'claimed_directory_lineage_id':old.old.lineage,
                     'parent_ec399_official_certificate_bundle_original': self.p399ref,
                     'epochs':[{'epoch_index':0, 'cms_signed_data_original':None}]}
        self.install_cms(make_cms(self.source_bytes, old))
        self.opts[core.NEW_SCALARS[2]] = self.body['epochs'][0][
            'cms_signed_data_original']['sha256']
        self.opts[core.REPEAT_NAMES[0]] = ['a' * 64]
        self.opts[core.REPEAT_NAMES[1]] = [0]

    def install_cms(self, raw):
        self.body['epochs'][0]['cms_signed_data_original'] = self.old.fixture.archive(
            raw, 'ec400-native-cms')
        self.install_bundle()

    def install_bundle(self):
        r = self.old.fixture.archive(self.body, 'ec400-native-cms-bundle')
        self.opts[core.NEW_SCALARS[0]] = r['path']
        self.opts[core.NEW_SCALARS[1]] = r['sha256']

    def evaluate(self, derive=True):
        with patch.object(core, '_inputs', return_value={}),\
             patch.object(core.parent, 'audit', return_value=self.parent_report):
            return core.derive_inventory(**self.opts) if derive else core.audit(**self.opts)

    def denied(self):
        with self.assertRaises(errors.AnchorError):
            self.evaluate()

    def calibrate(self):
        first = self.evaluate()
        self.opts[core.REPEAT_NAMES[0]] = [first['cms_epoch_reviews'][0][
            'cms_original_inventory_sha256']]
        self.opts[core.REPEAT_NAMES[1]] = [2]
        derived = self.evaluate()
        self.opts[core.AUDIT_ONLY[0]] = derived['receiver_verified_native_cms_inventory_sha256']
        return derived

    def test_01_authentic_two_algorithms_detached_der_two_true_signers(self):
        result = self.calibrate()
        self.assertEqual(result['verified_parent_and_native_cms_joint_signer_count'], 2)
        self.assertEqual([s['signature_algorithm'] for s in result[
            'unsigned_native_cms_inventory']['epochs'][0]['native_cms']['verified_signer_infos']],
                         ['ed25519','sha256_ecdsa'])
        self.assertTrue(result['bounded_local_native_cms_original_and_ec399_consistency'])
        self.assertEqual(result['exit_code'], 2)
        self.assertFalse(result[core.NEGATIVES[1]])

    def test_02_genuine_der_derive_then_independent_inventory_audit(self):
        self.calibrate()
        result = self.evaluate(False)
        self.assertEqual(result['schema'], core.RESULT_SCHEMA)
        self.assertNotIn('unsigned_native_cms_inventory', result)
        self.assertEqual(result['verified_parent_and_native_cms_joint_signer_count'],2)
        self.assertTrue(result['bounded_local_native_cms_original_and_ec399_consistency'])
        self.assertTrue(result[core.FLAGS[4]])  # SigningTime not qualified TSA

    def test_03_valid_attached_two_signers_binds_real_source_exact_bytes(self):
        self.install_cms(make_cms(self.source_bytes,self.old,attached=True))
        self.opts[core.NEW_SCALARS[2]] = self.body['epochs'][0][
            'cms_signed_data_original']['sha256']
        result = self.calibrate()
        self.assertEqual(result['unsigned_native_cms_inventory']['epochs'][0]
                         ['native_cms']['cms_encapsulated_content_mode'], 'attached')

    def test_04_genuine_signature_with_wrong_source_is_denied(self):
        self.install_cms(make_cms(b'INJECTED alternate original',self.old))
        self.denied()

    def test_05_modified_original_signature_is_denied(self):
        self.install_cms(make_cms(self.source_bytes,self.old,tamper_signature=True))
        self.denied()

    def test_06_one_signer_can_not_be_passed_as_two(self):
        self.install_cms(make_cms(self.source_bytes,self.old,signers=('A',)))
        self.denied()

    def test_07_same_publisher_twice_can_not_fake_independent_signers(self):
        self.install_cms(make_cms(self.source_bytes,self.old,signers=('A','A')))
        self.denied()

    def test_08_wrong_embedded_attached_content_denied(self):
        self.install_cms(make_cms(self.source_bytes,self.old,attached=True,
                                  override_content=b'DIFFERENT EMBEDDED BYTES'))
        self.denied()

    def test_09_absent_embedded_pinned_signer_certificate_denied(self):
        self.install_cms(make_cms(self.source_bytes,self.old,certs=('A',)))
        self.denied()

    def test_10_signed_time_disagrees_with_genuine_parent_notice_denied(self):
        self.install_cms(make_cms(self.source_bytes,self.old,
            signing_time=datetime(2026,10,25,14,36,tzinfo=UTC)))
        self.denied()

    def test_11_duplicate_signed_message_digest_is_denied(self):
        self.install_cms(make_cms(self.source_bytes,self.old,duplicate=True))
        self.denied()

    def test_12_sha1_digest_is_not_granted_native_cms_credit(self):
        self.install_cms(make_cms(self.source_bytes,self.old,weak=True))
        self.denied()

    def test_13_modified_original_der_on_disk_denied(self):
        p=Path(self.body['epochs'][0]['cms_signed_data_original']['path'])
        p.write_bytes(p.read_bytes() + b'junk')
        self.denied()

    def test_14_external_first_original_pin_mismatch_does_not_fabricate_pass(self):
        self.opts[core.NEW_SCALARS[2]]='f'*64
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[1]])
        self.assertFalse(r['bounded_local_native_cms_original_and_ec399_consistency'])

    def test_15_separate_unsigned_inventory_mismatch_is_unresolved(self):
        self.calibrate()
        self.opts[core.AUDIT_ONLY[0]]='f'*64
        r=self.evaluate(False)
        self.assertTrue(r[core.FLAGS[1]])

    def test_16_live_parent_revocation_or_crl_gap_cannot_gain_cms_credit(self):
        report=copy.deepcopy(self.parent_report)
        report['certificate_epoch_reviews'][0]['locally_verified_x509_publisher_count']=1
        report['verified_independent_x509_publisher_count']=1
        report[core.parent.FLAGS[3]]=True
        report['bounded_local_gazette_certificate_crl_parent_consistency']=False
        report['status']=core.parent.OUTCOMES[3]+'_unresolved'
        self.parent_report=report
        result=self.evaluate()
        self.assertEqual(result['verified_parent_and_native_cms_joint_signer_count'],0)
        self.assertTrue(result[core.FLAGS[0]])

    def test_17_forged_parent_report_is_denied(self):
        self.parent_report['status']='passed'
        self.denied()

    def test_18_cms_path_must_not_alias_parent_cert_or_source(self):
        self.body['epochs'][0]['cms_signed_data_original']=self.old.chains['A']['leaf']
        self.install_bundle()
        self.denied()

    def test_19_cms_missing_unresolved_not_authentic_and_not_credit(self):
        self.body['epochs'][0]['cms_signed_data_original']=None
        self.install_bundle()
        result=self.evaluate()
        self.assertTrue(result[core.FLAGS[2]])
        self.assertEqual(result['verified_parent_and_native_cms_joint_signer_count'],0)

    def test_20_whole_cms_bundle_wrong_parent_original_denied(self):
        self.body['parent_ec399_official_certificate_bundle_original']['sha256']='c'*64
        self.install_bundle()
        self.denied()

    def test_21_unknown_issuer_raw_certificate_must_fail_signature_identity(self):
        fake=copy.deepcopy(self.old.chains['A']['leaf'])
        self.body['epochs'][0]['cms_signed_data_original']=fake
        self.install_bundle()
        self.denied()

    def test_22_second_signer_original_leaves_are_verified_not_caller_names(self):
        result=self.evaluate()
        signers=result['unsigned_native_cms_inventory']['epochs'][0]['native_cms']['verified_signer_infos']
        self.assertEqual([s['publisher_id'] for s in signers],['PublisherA','PublisherB'])
        self.assertEqual([s['original_pinned_leaf_certificate_sha256'] for s in signers],
                         [self.old.chains['A']['leaf']['sha256'],
                          self.old.chains['B']['leaf']['sha256']])


if __name__=='__main__':
    unittest.main()
