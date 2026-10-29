#!/usr/bin/env python3
"""EC409 original ETSI TSL subset: actual local RSA XMLDSig and original SHA.

Only immediate EC408 audit is mocked inside these EC409 child tests. Its report
comes from actual locally signed EC408 OCSP, EC407 CMS/CRL/X509 and EC406
cryptographic fixtures. None is a real EU trust-list signer or external trust.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from datetime import timedelta
import hashlib
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding,ec,utils
from lxml import etree

from delivery_anchor import anchor as errors
from institutional_cms import test_protocol as cms_fixture
from institutional_ocsp import test_protocol as ocsp_fixture
from . import protocol as core,operator


def tl_xml(signer,signer_key,root,at,*,sequence,territory='GB',
           service_type=None,status=core.GRANTED,valid=True,
           xades=False,mutate=None,identifier='local-tsl'):
    """Create a *genuinely signed* synthetic original (never public evidence)."""
    def t(name):return '{%s}%s'%(core.TSL,name)
    def d(name):return '{%s}%s'%(core.DS,name)
    def x(name):return '{%s}%s'%(core.XADES,name)
    from datetime import timezone
    issue=at-timedelta(minutes=30 if sequence==1 else 1)
    nxt=at+timedelta(minutes=90)
    utc=lambda dt:dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    rootnode=etree.Element(t('TrustServiceStatusList'),nsmap={None:core.TSL,'ds':core.DS,'xades':core.XADES})
    rootnode.set('Id',identifier)
    scheme=etree.SubElement(rootnode,t('SchemeInformation'))
    etree.SubElement(scheme,t('TSLType')).text=core.EU_GENERIC
    etree.SubElement(scheme,t('SchemeTerritory')).text=territory
    etree.SubElement(scheme,t('TSLSequenceNumber')).text=str(sequence)
    etree.SubElement(scheme,t('ListIssueDateTime')).text=utc(issue)
    nextnode=etree.SubElement(scheme,t('NextUpdate'))
    etree.SubElement(nextnode,t('dateTime')).text=utc(nxt)
    plist=etree.SubElement(rootnode,t('TrustServiceProviderList'))
    provider=etree.SubElement(plist,t('TrustServiceProvider'))
    services=etree.SubElement(provider,t('TSPServices'))
    service=etree.SubElement(services,t('TSPService'))
    info=etree.SubElement(service,t('ServiceInformation'))
    etree.SubElement(info,t('ServiceTypeIdentifier')).text=(
        service_type or 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC')
    identity=etree.SubElement(info,t('ServiceDigitalIdentity'))
    digit=etree.SubElement(identity,t('DigitalId'))
    etree.SubElement(digit,t('X509Certificate')).text=base64.b64encode(
        root.public_bytes(serialization.Encoding.DER)).decode('ascii')
    etree.SubElement(info,t('ServiceStatus')).text=status
    etree.SubElement(info,t('StatusStartingTime')).text=utc(issue-timedelta(days=5))
    if mutate is not None:
        mutate(rootnode)
    sig=etree.SubElement(rootnode,d('Signature'))
    if xades:sig.set('Id','tl-signature')
    signedinfo=etree.SubElement(sig,d('SignedInfo'))
    etree.SubElement(signedinfo,d('CanonicalizationMethod'),Algorithm=core.EXC)
    etree.SubElement(signedinfo,d('SignatureMethod'),Algorithm=(
        core.ECDSA_SHA256 if isinstance(signer_key,ec.EllipticCurvePrivateKey)
        else core.RSA_SHA256))
    r=etree.SubElement(signedinfo,d('Reference'),URI='#'+identifier)
    transforms=etree.SubElement(r,d('Transforms'))
    etree.SubElement(transforms,d('Transform'),Algorithm=core.ENV)
    etree.SubElement(transforms,d('Transform'),Algorithm=core.EXC)
    etree.SubElement(r,d('DigestMethod'),Algorithm=core.SHA256_URI)
    rdigest=etree.SubElement(r,d('DigestValue'))
    sv=etree.SubElement(sig,d('SignatureValue'))
    keyinfo=etree.SubElement(sig,d('KeyInfo'))
    data=etree.SubElement(keyinfo,d('X509Data'))
    etree.SubElement(data,d('X509Certificate')).text=base64.b64encode(
        signer.public_bytes(serialization.Encoding.DER)).decode('ascii')
    if xades:
        obj=etree.SubElement(sig,d('Object'))
        q=etree.SubElement(obj,x('QualifyingProperties'),Target='#tl-signature')
        props=etree.SubElement(q,x('SignedProperties'),Id='tl-properties')
        ssp=etree.SubElement(props,x('SignedSignatureProperties'))
        etree.SubElement(ssp,x('SigningTime')).text=utc(issue+timedelta(seconds=3))
        pr=etree.SubElement(signedinfo,d('Reference'),URI='#tl-properties',
                           Type='http://uri.etsi.org/01903#SignedProperties')
        pt=etree.SubElement(pr,d('Transforms'))
        etree.SubElement(pt,d('Transform'),Algorithm=core.EXC)
        etree.SubElement(pr,d('DigestMethod'),Algorithm=core.SHA256_URI)
        etree.SubElement(pr,d('DigestValue')).text=base64.b64encode(
            hashlib.sha256(etree.tostring(props,method='c14n',exclusive=True,
                                        with_comments=False)).digest()).decode('ascii')
    clone=deepcopy(rootnode);clone.remove(clone[-1])
    rdigest.text=base64.b64encode(hashlib.sha256(
        etree.tostring(clone,method='c14n',exclusive=True,
                       with_comments=False)).digest()).decode('ascii')
    message=etree.tostring(signedinfo,method='c14n',exclusive=True,with_comments=False)
    if isinstance(signer_key,ec.EllipticCurvePrivateKey):
        der_signature=signer_key.sign(message,ec.ECDSA(hashes.SHA256()))
        rnum,snum=utils.decode_dss_signature(der_signature)
        original_signature=rnum.to_bytes(32,'big')+snum.to_bytes(32,'big')
    else:
        original_signature=signer_key.sign(message,padding.PKCS1v15(),hashes.SHA256())
    sv.text=base64.b64encode(original_signature).decode('ascii')
    raw=etree.tostring(rootnode,encoding='utf-8',xml_declaration=True)
    if not valid:raw=raw.replace(b'granted',b'grantxd',1)
    return raw


class SignedTSLOriginals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):ocsp_fixture.RealInstitutionalOcspOriginals.setUpClass()
    @classmethod
    def tearDownClass(cls):ocsp_fixture.RealInstitutionalOcspOriginals.tearDownClass()

    def setUp(self):
        self.f=ocsp_fixture.RealInstitutionalOcspOriginals(
            'test_01_actual_signed_both_issuers_and_dual_windows')
        self.f.setUp()
        self.parent_report=self.f.calibrate()
        self.extra=dict(self.f.extra)
        self.extra[core.REPEAT_NAMES[0]]=['f'*64]
        self.extra[core.REPEAT_NAMES[1]]=[0]
        self.now=self.f.now
        self.lineage=self.f.bundle['claimed_directory_lineage_id']
        self.signers={}
        self.roster={'schema':core.ROSTER_SCHEMA,
                     'claimed_directory_lineage_id':self.lineage,
                     'assignments':[]}
        self.bundle={'schema':core.BUNDLE_SCHEMA,
                     'claimed_directory_lineage_id':self.lineage,
                     'parent_ec408_original_institutional_ocsp_bundle_original':{
                        'path':self.f.extra[core.parent.NEW_SCALARS[0]],
                        'sha256':self.f.extra[core.parent.NEW_SCALARS[1]]},
                     'outside_tsl_signer_roster_original':None,
                     'epochs':[{'epoch_index':0,'publishers':[]}]}
        for letter in ('A','B'):self.add_role(letter)
        self.refresh(roster=True)

    def tearDown(self):self.f.tearDown()

    def archive(self,original,label):
        return self.f.archive(original,'ec409-'+label)

    def role(self,letter):return self.bundle['epochs'][0]['publishers'][0 if letter=='A' else 1]

    def add_role(self,letter):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cert=cms_fixture._certificate('LocalSyntheticNonOfficialTLSigner'+letter,
                          key,None,key,self.now,ca=False,number=9409+(letter=='B'))
        cr=self.archive(cert.public_bytes(serialization.Encoding.DER),
                        'tsl-signer-'+letter)
        self.signers[letter]=(cert,key,cr)
        self.roster['assignments'].append({
            'publisher_id':'Publisher'+letter,
            'tsl_signer_certificate_original':cr,
            'scheme_territory':'GB',
            'required_service_type_uri':'http://uri.etsi.org/TrstSvc/Svctype/CA/QC'})
        self.bundle['epochs'][0]['publishers'].append({
            'publisher_id':'Publisher'+letter,
            'original_historical_signed_tsl_xml':None,
            'original_evaluation_signed_tsl_xml':None})
        self.resign(letter)

    def resign(self,letter,*,historical=True,**kwargs):
        cert,key,_=self.signers[letter]
        root=self.f.f.keys[letter]['root']
        sequence=1 if historical else 2
        at=self.now if historical else self.now+timedelta(minutes=3)
        raw=tl_xml(cert,key,root,at,sequence=sequence,**kwargs)
        field='original_historical_signed_tsl_xml' if historical else \
               'original_evaluation_signed_tsl_xml'
        self.role(letter)[field]=self.archive(raw,letter+'-'+str(sequence)+'-signed-tsl')
        if historical and self.role(letter)['original_evaluation_signed_tsl_xml'] is None:
            self.resign(letter,historical=False)

    def refresh(self,*,roster=False,pins=True):
        if roster:
            r=self.archive(self.roster,'outside-original-tl-signers')
            self.bundle['outside_tsl_signer_roster_original']=r
            self.extra[core.NEW_SCALARS[2]]=r['sha256']
            for i,letter in enumerate(('A','B')):
                self.extra[core.NEW_SCALARS[3+i]]=self.signers[letter][2]['sha256']
        b=self.archive(self.bundle,'original-signed-tl-bundle')
        self.extra[core.NEW_SCALARS[0]]=b['path']
        self.extra[core.NEW_SCALARS[1]]=b['sha256']
        if pins:
            for i,letter in enumerate(('A','B')):
                self.extra[core.NEW_SCALARS[5+i]]=self.role(letter)[
                    'original_historical_signed_tsl_xml']['sha256']
                self.extra[core.NEW_SCALARS[7+i]]=self.role(letter)[
                    'original_evaluation_signed_tsl_xml']['sha256']

    def evaluate(self,deriving=True):
        opts=dict(self.extra)
        if deriving:opts.pop(core.AUDIT_ONLY[0],None)
        with patch.object(core,'_inputs',return_value={}),\
             patch.object(core.parent,'audit',return_value=self.parent_report):
            return core.derive_inventory(**opts) if deriving else core.audit(**opts)

    def calibrate(self):
        r=self.evaluate()
        self.extra[core.REPEAT_NAMES[0]]=[r['signed_tsl_epoch_reviews'][0][
            'signed_tsl_epoch_inventory_sha256']]
        self.extra[core.REPEAT_NAMES[1]]=[2]
        r=self.evaluate()
        self.extra[core.AUDIT_ONLY[0]]=r['receiver_verified_signed_tsl_inventory_sha256']
        return self.evaluate(False)

    def denied(self,reason=None):
        with self.assertRaises(errors.AnchorError) as failure:
            self.evaluate()
        if reason:self.assertIn(reason,failure.exception.code)

    def test_01_actual_two_independent_signed_original_tl_windows(self):
        r=self.calibrate()
        self.assertEqual(r['exit_code'],2)
        self.assertEqual(r['verified_joint_signed_tsl_and_real_ec408_parent_publishers'],2)
        self.assertTrue(r['bounded_local_signed_tsl_and_real_ec408_parent_consistency'])
        self.assertFalse(any(r[k] for k in core.NEGATIVES))

    def test_02_xades_signed_properties_second_reference_is_verified(self):
        self.resign('A',xades=True)
        self.refresh()
        r=self.calibrate()
        proof=r['signed_tsl_epoch_reviews'][0]
        self.assertEqual(proof['joint_actual_ec408_ocsp_and_signed_tsl_count'],2)
        self.assertEqual(r['exit_code'],2)

    def test_03_derive_is_unsigned_never_legal_acceptance(self):
        r=self.evaluate()
        self.assertIn('unsigned_signed_tsl_original_inventory',r)
        self.assertEqual(r['exit_code'],2)
        self.assertNotIn('unsigned_signed_tsl_original_inventory',self.calibrate())

    def test_04_tampered_actual_xmlsig_signed_payload_is_denied(self):
        self.resign('A',valid=False)
        self.refresh()
        self.denied('REFERENCE_DIGEST_MISMATCH')

    def test_05_real_signed_withdrawn_service_not_granted(self):
        self.resign('B',historical=False,
            status='http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn')
        self.refresh()
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[3]])
        self.assertEqual(r['verified_joint_signed_tsl_and_real_ec408_parent_publishers'],1)

    def test_06_real_signed_wrong_territory_is_denied(self):
        self.resign('A',territory='FR')
        self.refresh()
        self.denied('TERRITORY_MISMATCH')

    def test_07_service_type_must_match_pinned_roster(self):
        self.resign('B',service_type='http://uri.etsi.org/TrstSvc/Svctype/CA/PKC')
        self.refresh()
        self.denied('EXACT_ONE_TYPED_SERVICE')

    def test_08_signer_original_pin_is_not_a_label(self):
        self.extra[core.NEW_SCALARS[3]]='d'*64
        self.denied('OUTSIDE_SIGNER_ORIGINAL_DER_PINS')

    def test_09_first_role_window_original_mandatory(self):
        self.role('A')['original_historical_signed_tsl_xml']=None
        self.refresh(pins=False)
        self.denied('FIRST_PAIR_REQUIRED')

    def test_10_original_xml_not_allowed_to_reuse_another_role_path(self):
        self.role('B')['original_evaluation_signed_tsl_xml']=self.role('A')[
            'original_historical_signed_tsl_xml']
        self.refresh(pins=False)
        self.denied('REPLAY_OR_PARENT_PATH_ALIAS')

    def test_11_original_parent_wrong_SHA_denied(self):
        self.parent_report=dict(self.parent_report)
        self.parent_report['original_institutional_ocsp_bundle_sha256']='f'*64
        self.denied('UNCHANGED_REAL_EC408_REPORT')

    def test_12_ancestor_adverse_OCSP_cannot_be_repaired(self):
        report=dict(self.parent_report)
        rows=[dict(r) for r in report['institutional_ocsp_epoch_reviews']]
        rows[0]['joint_real_ec407_parent_and_ocsp_count']=0
        report['institutional_ocsp_epoch_reviews']=rows
        report['verified_joint_institutional_ocsp_and_real_parent_publishers']=0
        report['bounded_local_signed_ocsp_and_real_ec407_parent_consistency']=False
        report[core.parent.FLAGS[5]]=True
        report['status']=core.parent.OUTCOMES[5]+'_unresolved'
        self.parent_report=report
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[0]])
        self.assertEqual(r['verified_joint_signed_tsl_and_real_ec408_parent_publishers'],0)

    def test_13_unsigned_outside_epoch_sha_disagrees_no_credit(self):
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[1]])
        self.assertEqual(r['exit_code'],2)

    def test_14_signed_xml_with_dtd_and_entity_prohibited(self):
        p=self.signers['A']
        raw=tl_xml(p[0],p[1],self.f.f.keys['A']['root'],self.now,sequence=1)
        raw=raw.replace(b'?>',b'?><!DOCTYPE evil [<!ENTITY ex SYSTEM "file:///etc/passwd">]>',1)
        self.role('A')['original_historical_signed_tsl_xml']=self.archive(raw,'dtd-evil')
        self.refresh()
        self.denied('DTD_OR_ENTITY')

    def test_15_signed_xml_id_wrapping_attack_rejected(self):
        def mutate(root):root.find('{%s}SchemeInformation'%core.TSL).set('Id','local-tsl')
        self.resign('A',mutate=mutate)
        self.refresh()
        self.denied('ID_COLLISION')

    def test_16_xml_unapproved_external_reference_rejected(self):
        # Replace a signed Reference URI without recomputing signature. The
        # validator denies the reference grammar *before* signature math.
        cert,key,_=self.signers['A']
        raw=tl_xml(cert,key,self.f.f.keys['A']['root'],self.now,sequence=1)
        raw=raw.replace(b'URI="#local-tsl"',b'URI="https://example.org/tl.xml"',1)
        self.role('A')['original_historical_signed_tsl_xml']=self.archive(raw,'remote-uri')
        self.refresh()
        self.denied('DETACHED_UNSAFE_REFERENCE')

    def test_17_signed_status_start_after_window_is_not_grant(self):
        def mutate(root):
            root.find('.//{%s}StatusStartingTime'%core.TSL).text=(
                self.now+timedelta(days=8)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.resign('B',mutate=mutate)
        self.refresh()
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[3]])
        self.assertEqual(r['signed_tsl_epoch_reviews'][0][
            'signed_granted_both_window_pair_count'],1)

    def test_18_two_matching_services_ambiguous_even_if_signed(self):
        def mutate(root):
            services=root.find('.//{%s}TSPServices'%core.TSL)
            services.append(deepcopy(services[0]))
        self.resign('A',mutate=mutate)
        self.refresh()
        self.denied('EXACT_ONE_TYPED_SERVICE')

    def test_19_inputs_check_real_new_arguments_and_floor(self):
        # These local child fixtures deliberately omit thousands of inherited
        # historical CLI arguments: make that explicit, then isolate the new
        # EC409 grammar while the already tested parent parser is mocked.
        data=dict(self.extra)
        data.pop(core.AUDIT_ONLY[0],None)
        with patch.object(core.parent,'_inputs',return_value={}):
            with self.assertRaises(errors.AnchorError):core._inputs(data,True)
            keys=set((*core.PARENT_SCALARS,*core.PARENT_REPEATS,
                      *core.NEW_SCALARS,*core.REPEAT_NAMES))
            for key in keys-set(data):data[key]='unused_in_child_fixture'
            self.assertEqual(core._inputs(data,True)['claimed_historical_directory_lineage_id'],
                             self.lineage)
            data[core.REPEAT_NAMES[1]]=[3]
            with self.assertRaises(errors.AnchorError):core._inputs(data,True)

    def test_20_denial_contract_never_claims_pass(self):
        denied=operator.denial('audit-historical-ec339-signed-tsl',
            errors.AnchorError('EC409_FORGERY','permission_denied'))
        self.assertEqual(denied['exit_code'],3)
        self.assertTrue(all(denied[k] is False for k in core.NEGATIVES))

    def test_22_actual_p256_xmlsig_with_distinct_external_cert(self):
        key=ec.generate_private_key(ec.SECP256R1())
        cert=cms_fixture._certificate('LocalSyntheticNonOfficialP256TSLSigner',
            key,None,key,self.now,ca=False,number=9463)
        cr=self.archive(cert.public_bytes(serialization.Encoding.DER),
                        'new-p256-tsl-signer-A')
        self.signers['A']=(cert,key,cr)
        self.roster['assignments'][0]['tsl_signer_certificate_original']=cr
        self.resign('A',historical=True,xades=True)
        self.resign('A',historical=False)
        self.refresh(roster=True)
        report=self.calibrate()
        self.assertTrue(report['bounded_local_signed_tsl_and_real_ec408_parent_consistency'])
        self.assertEqual(report['verified_joint_signed_tsl_and_real_ec408_parent_publishers'],2)
        self.assertEqual(report['exit_code'],2)

    def test_21_history_signed_revocation_is_evaluated_at_correct_time(self):
        # Historical granted followed by current withdrawn; the signed history
        # at the historic check may stay granted but current must lose credit.
        def mutate(root):
            svc=root.find('.//{%s}TSPService'%core.TSL)
            info=svc.find('{%s}ServiceInformation'%core.TSL)
            info.find('{%s}ServiceStatus'%core.TSL).text=(
                'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn')
            info.find('{%s}StatusStartingTime'%core.TSL).text=(
                self.now-timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
            history=etree.SubElement(svc,'{%s}ServiceHistory'%core.TSL)
            event=etree.SubElement(history,'{%s}ServiceHistoryInstance'%core.TSL)
            etree.SubElement(event,'{%s}ServiceTypeIdentifier'%core.TSL).text=(
                'http://uri.etsi.org/TrstSvc/Svctype/CA/QC')
            event.append(deepcopy(info.find('{%s}ServiceDigitalIdentity'%core.TSL)))
            etree.SubElement(event,'{%s}ServiceStatus'%core.TSL).text=core.GRANTED
            etree.SubElement(event,'{%s}StatusStartingTime'%core.TSL).text=(
                self.now-timedelta(days=20)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.resign('A',historical=False,mutate=mutate)
        self.refresh()
        r=self.evaluate()
        self.assertEqual(r['signed_tsl_epoch_reviews'][0][
            'signed_granted_both_window_pair_count'],1)

if __name__=='__main__':unittest.main()
