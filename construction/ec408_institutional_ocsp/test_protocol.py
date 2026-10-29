#!/usr/bin/env python3
"""EC408 focused true signed DER RFC6960 originals (only parent audit mocked).

Fixtures generate genuine local RSA-signed OCSP responses, original EC407
RSA-signed CMS, EC406 Ed25519-signed custody, and EC405 RFC3161. They DO NOT
create public official issuer accreditation or a complete external history.
"""
from __future__ import annotations

from datetime import datetime,timedelta,timezone
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID,ExtensionOID,ExtendedKeyUsageOID
from ec295_delivery_anchor import anchor as errors
from ec407_institutional_cms import test_protocol as upstream
from . import protocol as core, operator


def ocsp_response(issuer, subject, issuer_key, at, *, status='good',
                  signer=None, signer_key=None, delegated=False, forged=False,
                  time_shift=0, freshness_shift=0):
    status={'good':ocsp.OCSPCertStatus.GOOD,
            'revoked':ocsp.OCSPCertStatus.REVOKED,
            'unknown':ocsp.OCSPCertStatus.UNKNOWN}[status]
    who=signer or issuer
    key=signer_key or issuer_key
    start=at+timedelta(minutes=freshness_shift-2+time_shift)
    end=at+timedelta(days=2,minutes=freshness_shift+time_shift)
    builder=(ocsp.OCSPResponseBuilder()
             .add_response(cert=subject,issuer=issuer,algorithm=hashes.SHA256(),
                           cert_status=status,this_update=start,next_update=end,
                           revocation_time=(at-timedelta(minutes=10) if
                                            status==ocsp.OCSPCertStatus.REVOKED else None),
                           revocation_reason=(x509.ReasonFlags.key_compromise if
                                              status==ocsp.OCSPCertStatus.REVOKED else None))
             .responder_id(ocsp.OCSPResponderEncoding.HASH, who))
    if delegated:
        builder=builder.certificates([who])
    response=builder.sign(private_key=key,algorithm=hashes.SHA256())
    result=response.public_bytes(serialization.Encoding.DER)
    if forged:result=result[:-1]+bytes([result[-1]^1])
    return result


def delegate_cert(root, key, at, number):
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                      'SyntheticOCSPDelegate'+str(number))])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(root.subject)
          .public_key(private.public_key()).serial_number(number)
          .not_valid_before(at-timedelta(days=30))
          .not_valid_after(at+timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
          .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,
                 key_encipherment=False,data_encipherment=False,key_agreement=False,
                 key_cert_sign=False,crl_sign=False,encipher_only=False,
                 decipher_only=False),True)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),False)
          .add_extension(x509.OCSPNoCheck(),False).sign(key,hashes.SHA256()))
    return cert,private


class RealInstitutionalOcspOriginals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        upstream.InstitutionalCMSOriginalTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        upstream.InstitutionalCMSOriginalTests.tearDownClass()

    def setUp(self):
        self.f=upstream.InstitutionalCMSOriginalTests(
            'test_01_real_detached_cms_two_cert_origins_and_crls')
        self.f.setUp()
        # Signed OCSP produced_at in cryptography's DER comes from the signing
        # clock; choose the same canonical evaluation second in this fixture.
        self.f.extra[core.parent.NEW_SCALARS[11]]=(self.f.now+timedelta(
            minutes=3)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.parent_report=self.f.calibrate()
        self.now=self.f.now
        self.extra=dict(self.f.extra)
        self.extra[core.REPEAT_NAMES[0]]=['f'*64]
        self.extra[core.REPEAT_NAMES[1]]=[0]
        self.bundle={'schema':core.BUNDLE_SCHEMA,
                     'claimed_directory_lineage_id':self.f.f.f.f.lineage,
                     'parent_ec407_original_institutional_cms_bundle_original':{
                       'path':self.f.extra[core.parent.NEW_SCALARS[0]],
                       'sha256':self.f.extra[core.parent.NEW_SCALARS[1]]},
                     'epochs':[{'epoch_index':0,'publishers':[]}]}
        for letter in ('A','B'):
            self.add_role(letter)
        self.refresh()

    def tearDown(self):
        self.f.tearDown()

    def archive(self,obj,label):
        return self.f.archive(obj,'ec408-'+label)

    def role(self,letter):
        return self.bundle['epochs'][0]['publishers'][0 if letter=='A' else 1]

    def add_role(self,letter):
        i=0 if letter=='A' else 1
        p=self.f.keys[letter]
        old=self.f.roster['assignments'][i]
        row={'publisher_id':'Publisher'+letter,
             'institutional_signer_id':old['institutional_signer_id'],
             'root_certificate_sha256':old['root_certificate_original']['sha256'],
             'leaf_certificate_sha256':old['leaf_certificate_original']['sha256'],
             'historical_delegated_responder_certificate_original':None,
             'evaluation_delegated_responder_certificate_original':None,
             'original_historical_ocsp_response':None,
             'original_evaluation_ocsp_response':None}
        self.bundle['epochs'][0]['publishers'].append(row)
        for current in (False,True):
            raw=ocsp_response(p['root'],p['leaf'],p['root_key'],self.now,
                              time_shift=1 if current else 0)
            row['original_evaluation_ocsp_response' if current else
                'original_historical_ocsp_response']=self.archive(
                      raw,letter+('-evaluation' if current else '-historical'))

    def refresh(self,*,pin=True):
        r=self.archive(self.bundle,'original-ocsp-bundle')
        self.extra[core.NEW_SCALARS[0]]=r['path']
        self.extra[core.NEW_SCALARS[1]]=r['sha256']
        if pin:
            for i,letter in enumerate(('A','B')):
                self.extra[core.NEW_SCALARS[2+i]]=self.role(letter)[
                    'original_historical_ocsp_response']['sha256']
                self.extra[core.NEW_SCALARS[4+i]]=self.role(letter)[
                    'original_evaluation_ocsp_response']['sha256']

    def replace_ocsp(self,letter,current=False,**opts):
        p=self.f.keys[letter]
        raw=ocsp_response(p['root'],p['leaf'],p['root_key'],self.now,
                          time_shift=opts.pop('time_shift',1 if current else 0),**opts)
        self.role(letter)['original_evaluation_ocsp_response' if current else
                          'original_historical_ocsp_response']=self.archive(raw,
                     letter+('-evaluation-mod' if current else '-historical-mod'))
        self.refresh()

    def evaluate(self,derive=True):
        kwargs=dict(self.extra)
        if derive:kwargs.pop(core.AUDIT_ONLY[0],None)
        with patch.object(core,'_inputs',return_value={}),\
             patch.object(core.parent,'audit',return_value=self.parent_report):
            return core.derive_inventory(**kwargs) if derive else core.audit(**kwargs)

    def calibrate(self):
        result=self.evaluate()
        self.extra[core.REPEAT_NAMES[0]]=[result[
            'institutional_ocsp_epoch_reviews'][0][
                 'institutional_ocsp_epoch_inventory_sha256']]
        self.extra[core.REPEAT_NAMES[1]]=[2]
        result=self.evaluate()
        self.extra[core.AUDIT_ONLY[0]]=result[
            'receiver_verified_institutional_ocsp_inventory_sha256']
        return self.evaluate(False)

    def denied(self,code=None):
        with self.assertRaises(errors.AnchorError) as failure:
            self.evaluate()
        if code:self.assertIn(code,failure.exception.code)

    def test_01_actual_signed_both_issuers_and_dual_windows(self):
        report=self.calibrate()
        self.assertEqual(report['exit_code'],2)
        self.assertEqual(report['verified_joint_institutional_ocsp_and_real_parent_publishers'],2)
        self.assertTrue(report['bounded_local_signed_ocsp_and_real_ec407_parent_consistency'])
        self.assertTrue(all(report[k] is False for k in core.NEGATIVES))

    def test_02_derive_is_unsigned_not_independent_qualified_trust(self):
        self.assertIn('unsigned_institutional_ocsp_evidence_inventory',self.evaluate())
        self.assertNotIn('unsigned_institutional_ocsp_evidence_inventory',self.calibrate())

    def test_03_unsigned_external_epoch_pin_disagrees_without_new_credit(self):
        report=self.evaluate()
        self.assertTrue(report[core.FLAGS[1]])
        self.assertEqual(report['exit_code'],2)

    def test_04_original_ocsp_unsigned_modified_der_denied(self):
        self.replace_ocsp('A',current=True,forged=True)
        self.denied()

    def test_05_signed_revoked_institutional_leaf_is_adverse(self):
        self.replace_ocsp('B',status='revoked')
        result=self.evaluate()
        self.assertTrue(result[core.FLAGS[4]])
        self.assertTrue(result[core.FLAGS[3]])
        self.assertEqual(result['verified_joint_institutional_ocsp_and_real_parent_publishers'],1)

    def test_06_actual_signed_unknown_is_not_good(self):
        self.replace_ocsp('A',current=True,status='unknown')
        result=self.evaluate()
        self.assertTrue(result[core.FLAGS[4]])
        self.assertEqual(result['institutional_ocsp_epoch_reviews'][0][
            'signed_good_contemporaneous_dual_window_count'],1)

    def test_07_ocsp_signed_by_an_unrelated_key_is_denied(self):
        unrelated=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        p=self.f.keys['A']
        badcert=upstream._certificate('UnrelatedOCSPAuthority',unrelated,None,
                unrelated,self.now,ca=True,number=9408)
        raw=ocsp_response(p['root'],p['leaf'],unrelated,self.now,
                          signer=badcert,signer_key=unrelated)
        self.role('A')['original_historical_ocsp_response']=self.archive(raw,'A-forged-signing')
        self.refresh()
        self.denied()

    def test_08_cross_institution_original_ocsp_path_alias_denied(self):
        self.role('B')['original_evaluation_ocsp_response']=self.role('A')[
            'original_historical_ocsp_response']
        self.refresh(pin=False)
        self.denied('NEW_OCSP_SOURCE_ALIASES')

    def test_09_missing_first_window_always_denied(self):
        self.role('A')['original_historical_ocsp_response']=None
        self.refresh(pin=False)
        self.denied('FIRST_BOTH_OCSP_ORIGINALS')

    def test_10_signed_parent_ec407_adverse_cannot_be_repaired(self):
        report=dict(self.parent_report)
        rows=[dict(x) for x in report['institutional_cms_epoch_reviews']]
        rows[0]['joint_real_ec406_and_institutional_cms_count']=0
        report['institutional_cms_epoch_reviews']=rows
        report['verified_joint_institutional_cms_and_real_parent_publishers']=0
        report['bounded_local_institutional_cms_and_real_ec406_parent_consistency']=False
        report[core.parent.FLAGS[4]]=True
        report['status']=core.parent.OUTCOMES[4]+'_unresolved'
        self.parent_report=report
        result=self.evaluate()
        self.assertTrue(result[core.FLAGS[0]])
        self.assertEqual(result['verified_joint_institutional_ocsp_and_real_parent_publishers'],0)

    def test_11_parent_report_sha_replacement_denied(self):
        self.parent_report=dict(self.parent_report)
        self.parent_report['original_institutional_cms_bundle_sha256']='e'*64
        self.denied('UNCHANGED_REAL_EC407_PARENT')

    def test_12_actual_issuer_delegated_nocheck_ocsp_signature(self):
        p=self.f.keys['B']
        cert,key=delegate_cert(p['root'],p['root_key'],self.now,8408)
        ref=self.archive(cert.public_bytes(serialization.Encoding.DER),'B-delegate')
        for current in (False,True):
            raw=ocsp_response(p['root'],p['leaf'],p['root_key'],self.now,
                   signer=cert,signer_key=key,delegated=True,
                   time_shift=1 if current else 0)
            label='evaluation' if current else 'historical'
            self.role('B')[label+'_delegated_responder_certificate_original']=ref
            self.role('B')['original_'+label+'_ocsp_response']=self.archive(
                      raw,'B-delegated-'+label)
        self.refresh()
        result=self.calibrate()
        self.assertEqual(result['verified_joint_institutional_ocsp_and_real_parent_publishers'],2)
        row=result['institutional_ocsp_epoch_reviews'][0]
        self.assertEqual(row['signed_good_contemporaneous_dual_window_count'],2)

    def test_13_cross_role_delegated_cert_original_denied(self):
        p=self.f.keys['A']
        cert,key=delegate_cert(p['root'],p['root_key'],self.now,8413)
        ref=self.archive(cert.public_bytes(serialization.Encoding.DER),'cross-role-delegate')
        a_response=ocsp_response(p['root'],p['leaf'],p['root_key'],self.now,
                                 signer=cert,signer_key=key,delegated=True)
        self.role('A')['original_historical_ocsp_response']=self.archive(
            a_response,'A-delegate-real')
        for letter in ('A','B'):
            self.role(letter)['historical_delegated_responder_certificate_original']=ref
        self.refresh()
        self.denied('DELEGATED_CERTIFICATE_ORIGINAL_PATH_ALIASES')

    def test_14_unknown_critical_or_unsanctioned_ocsp_is_denied(self):
        self.role('A')['historical_delegated_responder_certificate_original']=self.f.roster[
              'assignments'][0]['leaf_certificate_original']
        self.refresh()
        self.denied('DELEGATED_CERTIFICATE_ORIGINAL_PATH_ALIASES')

    def test_15_changed_pin_not_silently_repaired(self):
        self.extra[core.NEW_SCALARS[2]]='e'*64
        result=self.evaluate()
        self.assertTrue(result[core.FLAGS[1]])
        self.assertEqual(result['exit_code'],2)

    def test_16_signed_response_outside_history_window_adverse(self):
        self.replace_ocsp('A',time_shift=3)
        result=self.evaluate()
        self.assertTrue(result[core.FLAGS[3]])
        self.assertFalse(result['bounded_local_signed_ocsp_and_real_ec407_parent_consistency'])

    def test_17_exact_denial_cannot_report_PASS_or_issuer_status(self):
        result=operator.denial('audit-historical-ec339-institutional-ocsp',
                     errors.AnchorError('EC408_DENIED','permission_denied'))
        self.assertEqual(result['exit_code'],3)
        self.assertTrue(all(result[k] is False for k in core.NEGATIVES))

    def test_18_no_enrollment_of_unpinned_institutional_leaf(self):
        self.role('A')['leaf_certificate_sha256']='b'*64
        self.refresh()
        self.denied('NEW_OCSP_ROLE_CANNOT_SUBSTITUTE')

if __name__=='__main__':
    unittest.main()
