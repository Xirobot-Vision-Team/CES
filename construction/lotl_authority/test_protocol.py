#!/usr/bin/env python3
"""EC410 signed real locally synthetic LOTL/CA and national TL original fixtures.

Only immediate EC409.audit is mocked inside THIS new child test using EC409
crypto-produced signed national TSL evidence. EC408 and deeper fixture mocks
remain previous test machinery. Nothing is official OJEU or public history.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from datetime import timedelta
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding,ec,utils
from cryptography.x509.oid import NameOID
from lxml import etree

from delivery_anchor import anchor as errors
from trust_list import test_protocol as signed_tl_fixture
from . import protocol as core,operator


def make_cert(name,key,issuer,issuer_key,at,*,ca,path_len,serial):
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic Nonofficial '+name)])
    builder=(x509.CertificateBuilder()
       .subject_name(subject)
       .issuer_name(issuer.subject if issuer else subject)
       .public_key(key.public_key())
       .serial_number(serial)
       .not_valid_before(at-timedelta(days=3650))
       .not_valid_after(at+timedelta(days=3650))
       .add_extension(x509.BasicConstraints(ca=ca,path_length=path_len),critical=True)
       .add_extension(x509.KeyUsage(digital_signature=not ca,content_commitment=False,
                      key_encipherment=False,data_encipherment=False,
                      key_agreement=False,key_cert_sign=ca,crl_sign=ca,
                      encipher_only=False,decipher_only=False),critical=True)
       .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False)
       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                      issuer_key.public_key()),False))
    return builder.sign(issuer_key,hashes.SHA256())


def signed_lotl(cert,key,signer_raw,pointer_roles,at,*,sequence=1,xades=False,
                mutate=None,shift_issue_minutes=0):
    """Actually XMLDSig-sign full synthetic LOTL original; no external witness."""
    issue=at-timedelta(minutes=30 if sequence==1 else 1)+timedelta(
          minutes=shift_issue_minutes)
    nxt=at+timedelta(minutes=90)+timedelta(minutes=shift_issue_minutes)
    fmt=lambda d:d.strftime('%Y-%m-%dT%H:%M:%SZ')
    t=core.TAG;d=core.DSTAG;x=core.XTAG
    root=etree.Element(t('TrustServiceStatusList'),nsmap={None:core.TSL,
                        'ds':core.DS,'xades':core.XADES})
    root.set('Id','lotl-original')
    scheme=etree.SubElement(root,t('SchemeInformation'))
    etree.SubElement(scheme,t('TSLType')).text=core.LOTL_TYPE
    etree.SubElement(scheme,t('SchemeTerritory')).text='EU'
    etree.SubElement(scheme,t('TSLSequenceNumber')).text=str(sequence)
    etree.SubElement(scheme,t('ListIssueDateTime')).text=fmt(issue)
    etree.SubElement(etree.SubElement(scheme,t('NextUpdate')),
                     t('dateTime')).text=fmt(nxt)
    pointers=etree.SubElement(scheme,t('PointersToOtherTSL'))
    for territory,loc,raw,typ in [
        ('EU','https://lotl.example.test/lotl.xml',signer_raw,core.LOTL_TYPE),
        *[(v['territory'],v['url'],v['signer'],core.EU_GENERIC)
          for v in pointer_roles.values()]]:
        pointer=etree.SubElement(pointers,t('OtherTSLPointer'))
        identities=etree.SubElement(pointer,t('ServiceDigitalIdentities'))
        digit=etree.SubElement(etree.SubElement(identities,
                  t('ServiceDigitalIdentity')),t('DigitalId'))
        etree.SubElement(digit,t('X509Certificate')).text=base64.b64encode(
                      raw).decode('ascii')
        etree.SubElement(pointer,t('TSLLocation')).text=loc
        additional=etree.SubElement(pointer,t('AdditionalInformation'))
        one=etree.SubElement(additional,t('OtherInformation'))
        etree.SubElement(one,t('SchemeTerritory')).text=territory
        two=etree.SubElement(additional,t('OtherInformation'))
        etree.SubElement(two,t('TSLType')).text=typ
    if mutate is not None:mutate(root)
    sig=etree.SubElement(root,d('Signature'))
    if xades:sig.set('Id','original-lotl-signature')
    si=etree.SubElement(sig,d('SignedInfo'))
    etree.SubElement(si,d('CanonicalizationMethod'),Algorithm=core.EXC)
    etree.SubElement(si,d('SignatureMethod'),Algorithm=(
       core.ECDSA_SHA256 if isinstance(key,ec.EllipticCurvePrivateKey)
       else core.RSA_SHA256))
    r=etree.SubElement(si,d('Reference'),URI='#lotl-original')
    transforms=etree.SubElement(r,d('Transforms'))
    etree.SubElement(transforms,d('Transform'),Algorithm=core.ENV)
    etree.SubElement(transforms,d('Transform'),Algorithm=core.EXC)
    etree.SubElement(r,d('DigestMethod'),Algorithm=core.SHA256_URI)
    value=etree.SubElement(r,d('DigestValue'))
    sv=etree.SubElement(sig,d('SignatureValue'))
    keyinfo=etree.SubElement(sig,d('KeyInfo'))
    data=etree.SubElement(keyinfo,d('X509Data'))
    etree.SubElement(data,d('X509Certificate')).text=base64.b64encode(
                        cert.public_bytes(serialization.Encoding.DER)).decode('ascii')
    if xades:
        obj=etree.SubElement(sig,d('Object'))
        q=etree.SubElement(obj,x('QualifyingProperties'),
                           Target='#original-lotl-signature')
        props=etree.SubElement(q,x('SignedProperties'),Id='original-lotl-props')
        p=etree.SubElement(props,x('SignedSignatureProperties'))
        etree.SubElement(p,x('SigningTime')).text=fmt(issue+timedelta(seconds=5))
        prop_ref=etree.SubElement(si,d('Reference'),URI='#original-lotl-props',
                           Type='http://uri.etsi.org/01903#SignedProperties')
        tr=etree.SubElement(prop_ref,d('Transforms'))
        etree.SubElement(tr,d('Transform'),Algorithm=core.EXC)
        etree.SubElement(prop_ref,d('DigestMethod'),Algorithm=core.SHA256_URI)
        etree.SubElement(prop_ref,d('DigestValue')).text=base64.b64encode(
             hashlib.sha256(etree.tostring(props,method='c14n',exclusive=True,
                    with_comments=False)).digest()).decode('ascii')
    clone=deepcopy(root);clone.remove(clone[-1])
    value.text=base64.b64encode(hashlib.sha256(etree.tostring(
                clone,method='c14n',exclusive=True,
                with_comments=False)).digest()).decode('ascii')
    signedinfo=etree.tostring(si,method='c14n',exclusive=True,with_comments=False)
    if isinstance(key,ec.EllipticCurvePrivateKey):
        signature=key.sign(signedinfo,ec.ECDSA(hashes.SHA256()))
        rvalue,svalue=utils.decode_dss_signature(signature)
        signature=rvalue.to_bytes(32,'big')+svalue.to_bytes(32,'big')
    else:signature=key.sign(signedinfo,padding.PKCS1v15(),hashes.SHA256())
    sv.text=base64.b64encode(signature).decode('ascii')
    return etree.tostring(root,encoding='utf-8',xml_declaration=True)


class RealOriginalSignedLOTL(unittest.TestCase):
    def test_23_malformed_https_port_and_brackets_deny_without_io_fallback(self):
        for url in ('https://lotl.example.test:notaport/lotl.xml',
                    'https://[invalid-brackets/lotl.xml',
                    'https://lotl.example.test:65536/lotl.xml'):
            with self.subTest(url=url):
                with self.assertRaises(errors.AnchorError) as failure:
                    core._source_url(url)
                self.assertEqual(failure.exception.status,'permission_denied')

    @classmethod
    def setUpClass(cls):signed_tl_fixture.SignedTSLOriginals.setUpClass()

    @classmethod
    def tearDownClass(cls):signed_tl_fixture.SignedTSLOriginals.tearDownClass()

    def setUp(self):
        self.f=signed_tl_fixture.SignedTSLOriginals(
                    'test_01_actual_two_independent_signed_original_tl_windows')
        self.f.setUp()
        # EU LOTL maps one distinct territory to each actual national signer;
        # change only the EC409 LOCAL SYNTHETIC child fixture signed original B.
        self.f.roster['assignments'][1]['scheme_territory']='FR'
        self.f.resign('B',historical=True,territory='FR')
        self.f.resign('B',historical=False,territory='FR')
        self.f.refresh(roster=True)
        self.parent_report=self.f.calibrate()
        self.assertTrue(self.parent_report[
                  'bounded_local_signed_tsl_and_real_ec408_parent_consistency'])
        self.extra=dict(self.f.extra)
        self.extra[core.REPEAT_NAMES[0]]=['f'*64]
        self.extra[core.REPEAT_NAMES[1]]=[0]
        self.lineage=self.f.lineage
        self.now=self.f.now
        self.root_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.mid_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.signer_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.certificates()
        self.pointer_roles={}
        for letter,territory in (('A','GB'),('B','FR')):
            signer=self.f.signers[letter][0].public_bytes(serialization.Encoding.DER)
            self.pointer_roles['Publisher'+letter]={
                'territory':territory,
                'url':'https://tl-'+letter.lower()+'.example.test/original.xml',
                'signer':signer}
        self.roster={'schema':core.ROSTER_SCHEMA,
          'claimed_directory_lineage_id':self.lineage,
          'lotl_trust_anchor_certificate_original':None,
          'lotl_intermediate_ca_certificate_original':None,
          'lotl_signer_certificate_original':None,
          'expected_lotl_distribution_https_uri':'https://lotl.example.test/lotl.xml',
          'assignments':[{'publisher_id':role,'scheme_territory':v['territory'],
             'expected_national_tsl_location_https_uri':v['url']}
             for role,v in sorted(self.pointer_roles.items())]}
        self.bundle={'schema':core.BUNDLE_SCHEMA,
          'claimed_directory_lineage_id':self.lineage,
          'parent_ec409_original_signed_tsl_bundle_original':{
             'path':self.f.extra[core.parent.NEW_SCALARS[0]],
             'sha256':self.f.extra[core.parent.NEW_SCALARS[1]]},
          'outside_lotl_operator_roster_original':None,
          'epochs':[{'epoch_index':0,'original_historical_signed_lotl_xml':None,
                     'original_evaluation_signed_lotl_xml':None}]}
        self.refresh(roster=True)

    def tearDown(self):self.f.tearDown()

    def archive(self,payload,label):return self.f.archive(payload,'ec410-'+label)

    def certificates(self):
        self.root=make_cert('LOTL root',self.root_key,None,self.root_key,
                            self.now,ca=True,path_len=1,serial=41001)
        self.mid=make_cert('LOTL delegated CA',self.mid_key,self.root,
                           self.root_key,self.now,ca=True,path_len=0,serial=41002)
        self.signer=make_cert('LOTL XML operator signer',self.signer_key,
                              self.mid,self.mid_key,self.now,ca=False,path_len=None,
                              serial=41003)

    def resign(self,*,historical=True,mutate=None,xades=False,shift=0,sequence=None):
        seq=sequence if sequence is not None else (1 if historical else 2)
        at=self.now if historical else self.now+timedelta(minutes=3)
        raw=signed_lotl(self.signer,self.signer_key,self.signer.public_bytes(
               serialization.Encoding.DER),self.pointer_roles,at,
               sequence=seq,xades=xades,mutate=mutate,shift_issue_minutes=shift)
        field='original_historical_signed_lotl_xml' if historical else \
              'original_evaluation_signed_lotl_xml'
        self.bundle['epochs'][0][field]=self.archive(raw,
                                 'historical-lotl' if historical else 'evaluation-lotl')

    def refresh(self,*,roster=False,pins=True,autofill=True):
        if roster:
            for n,field,cert in (
                  (3,'lotl_trust_anchor_certificate_original',self.root),
                  (4,'lotl_intermediate_ca_certificate_original',self.mid),
                  (5,'lotl_signer_certificate_original',self.signer)):
                obj=self.archive(cert.public_bytes(serialization.Encoding.DER),
                                 'original-ca-'+str(n))
                self.roster[field]=obj
                self.extra[core.NEW_SCALARS[n]]=obj['sha256']
            r=self.archive(self.roster,'outside-original-lotl-roster')
            self.bundle['outside_lotl_operator_roster_original']=r
            self.extra[core.NEW_SCALARS[2]]=r['sha256']
        if autofill:
            if self.bundle['epochs'][0]['original_historical_signed_lotl_xml'] is None:
                self.resign(historical=True)
            if self.bundle['epochs'][0]['original_evaluation_signed_lotl_xml'] is None:
                self.resign(historical=False)
        b=self.archive(self.bundle,'original-lotl-bundle')
        self.extra[core.NEW_SCALARS[0]]=b['path']
        self.extra[core.NEW_SCALARS[1]]=b['sha256']
        if pins:
            self.extra[core.NEW_SCALARS[6]]=self.bundle['epochs'][0][
                      'original_historical_signed_lotl_xml']['sha256']
            self.extra[core.NEW_SCALARS[7]]=self.bundle['epochs'][0][
                      'original_evaluation_signed_lotl_xml']['sha256']

    def evaluate(self,derive=True,validate_inputs=False):
        opts=dict(self.extra)
        if derive:opts.pop(core.AUDIT_ONLY[0],None)
        with patch.object(core.parent,'audit',return_value=self.parent_report):
            if validate_inputs:
                return core.derive_inventory(**opts) if derive else core.audit(**opts)
            with patch.object(core,'_inputs',return_value={}):
                return core.derive_inventory(**opts) if derive else core.audit(**opts)

    def calibrate(self):
        r=self.evaluate()
        self.extra[core.REPEAT_NAMES[0]]=[
           r['signed_lotl_epoch_reviews'][0]['signed_lotl_epoch_inventory_sha256']]
        self.extra[core.REPEAT_NAMES[1]]=[2]
        r=self.evaluate()
        self.extra[core.AUDIT_ONLY[0]]=r['receiver_verified_signed_lotl_inventory_sha256']
        return self.evaluate(False)

    def denied(self,reason=''):
        with self.assertRaises(errors.AnchorError) as e:self.evaluate()
        if reason:self.assertIn(reason,e.exception.code)

    def test_01_genuine_root_intermediate_leaf_lotl_both_windows(self):
        r=self.calibrate()
        self.assertEqual(r['exit_code'],2)
        self.assertTrue(r['bounded_original_lotl_and_real_ec409_parent_consistency'])
        self.assertEqual(r['verified_joint_signed_lotl_and_real_ec409_parent_publishers'],2)
        self.assertFalse(any(r[k] for k in core.NEGATIVES))
        self.assertEqual(r['signed_lotl_epoch_reviews'][0][
                'matched_signed_national_pointer_dual_window_publisher_count'],2)

    def test_02_original_xades_signed_properties_reference(self):
        self.resign(historical=True,xades=True);self.refresh()
        r=self.calibrate()
        self.assertTrue(r['bounded_original_lotl_and_real_ec409_parent_consistency'])

    def test_03_real_ecdsa_p256_signed_lotl_with_rsa_ca_path(self):
        self.signer_key=ec.generate_private_key(ec.SECP256R1())
        self.signer=make_cert('EC410 local P256 operator',self.signer_key,
              self.mid,self.mid_key,self.now,ca=False,path_len=None,serial=41004)
        self.resign(historical=True);self.resign(historical=False)
        self.refresh(roster=True)
        r=self.calibrate()
        self.assertTrue(r['bounded_original_lotl_and_real_ec409_parent_consistency'])

    def test_04_signed_national_tsl_certificate_substitution_denied(self):
        def change(root):
            # Do not rely on XPath evaluator; fixed first national pointer.
            national=root.findall('.//'+core.TAG('OtherTSLPointer'))[1]
            el=national.find('.//'+core.TAG('X509Certificate'))
            el.text=base64.b64encode(self.signer.public_bytes(
               serialization.Encoding.DER)).decode('ascii')
        self.resign(mutate=change);self.refresh();self.denied('SIGNER_AND_URL')

    def test_05_genuinely_signed_wrong_national_url_denied(self):
        def change(root):
            p=root.findall('.//'+core.TAG('OtherTSLPointer'))[2]
            p.find(core.TAG('TSLLocation')).text='https://wrong.example.test/changed.xml'
        self.resign(mutate=change);self.refresh();self.denied('SIGNER_AND_URL')

    def test_06_signed_eu_self_distribution_location_wrong_denied(self):
        def change(root):
            p=root.findall('.//'+core.TAG('OtherTSLPointer'))[0]
            p.find(core.TAG('TSLLocation')).text='https://other.example.test/lotl.xml'
        self.resign(mutate=change);self.refresh();self.denied('SELF_DISTRIBUTION')

    def test_07_actual_signed_root_xml_tamper_denied(self):
        refobj=self.bundle['epochs'][0]['original_historical_signed_lotl_xml']
        raw=Path(refobj['path']).read_bytes().replace(b'https://tl-a.example.test/original.xml',b'https://tl-z.example.test/original.xml',1)
        self.bundle['epochs'][0]['original_historical_signed_lotl_xml']=self.archive(
               raw,'tampered-real-xml')
        self.refresh();self.denied('REFERENCE_DIGEST')

    def test_08_crypto_leaf_issuer_signature_forged_denied(self):
        other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.signer=make_cert('Forged locally unissued signer',self.signer_key,
            self.mid,other,self.now,ca=False,path_len=None,serial=41005)
        self.resign();self.resign(historical=False);self.refresh(roster=True)
        self.denied('SIGNER_SIGNED_REAL_ISSUER_SIGNATURE_INVALID')

    def test_09_wrong_independent_first_original_sha_never_credited(self):
        self.extra[core.NEW_SCALARS[6]]='a'*64
        r=self.calibrate()
        self.assertTrue(r[core.FLAGS[1]])
        self.assertFalse(r['bounded_original_lotl_and_real_ec409_parent_consistency'])

    def test_10_audit_retained_full_inventory_sha_differs(self):
        r=self.calibrate()
        self.extra[core.AUDIT_ONLY[0]]='e'*64
        r=self.evaluate(False)
        self.assertTrue(r[core.FLAGS[1]])

    def test_11_ancestor_adverse_parent_cannot_be_upgraded(self):
        self.parent_report=dict(self.parent_report)
        self.parent_report[core.parent.FLAGS[4]]=True
        self.parent_report['bounded_local_signed_tsl_and_real_ec408_parent_consistency']=False
        self.parent_report['status']=core.parent.OUTCOMES[4]+'_unresolved'
        rows=[dict(x) for x in self.parent_report['signed_tsl_epoch_reviews']]
        rows[0]['joint_actual_ec408_ocsp_and_signed_tsl_count']=0
        self.parent_report['signed_tsl_epoch_reviews']=rows
        self.parent_report['verified_joint_signed_tsl_and_real_ec408_parent_publishers']=0
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[0]])
        self.assertEqual(r['verified_joint_signed_lotl_and_real_ec409_parent_publishers'],0)

    def test_12_actual_signed_duplicate_pointer_denied(self):
        def change(root):
            p=root.find('.//'+core.TAG('PointersToOtherTSL'))
            p.append(deepcopy(p[1]))
        self.resign(mutate=change);self.refresh()
        self.denied('ONE_SELF_AND_TWO_NATIONAL')

    def test_13_signed_original_dtd_entity_not_accepted(self):
        h=self.bundle['epochs'][0]['original_historical_signed_lotl_xml']
        raw=Path(h['path']).read_bytes()
        raw=raw.replace(b'?>',b'?>\n<!DOCTYPE doc [<!ENTITY x SYSTEM "file:///etc/passwd">]>',1)
        self.bundle['epochs'][0]['original_historical_signed_lotl_xml']=self.archive(raw,'dtd-tl')
        self.refresh();self.denied('DTD_OR_ENTITY')

    def test_14_referenced_external_content_even_signed_info_denied(self):
        def mutate(root):
            root.set('Id','lotl-original')
        self.resign();self.refresh()
        refobj=self.bundle['epochs'][0]['original_historical_signed_lotl_xml']
        raw=Path(refobj['path']).read_bytes().replace(
             b'URI="#lotl-original"',b'URI="https://evil.example.test/extra"',1)
        self.bundle['epochs'][0]['original_historical_signed_lotl_xml']=self.archive(raw,'external-reference')
        self.refresh();self.denied('REFERENCE')

    def test_15_signed_xml_id_alias_wrapping_denied(self):
        def mutate(root):root.find(core.TAG('SchemeInformation')).set('Id','forged')
        self.resign(mutate=mutate);self.refresh();self.denied('UNSIGNED_OR_AMBIGUOUS_ID')

    def test_16_valid_signature_future_snapshot_cannot_cover_past(self):
        self.resign(historical=True,shift=-120);self.refresh()
        r=self.calibrate()
        self.assertTrue(r[core.FLAGS[3]])
        self.assertEqual(r['verified_joint_signed_lotl_and_real_ec409_parent_publishers'],0)

    def test_17_untrusted_intermediate_not_a_ca_denied(self):
        self.mid=make_cert('non-CA intermediate',self.mid_key,self.root,
              self.root_key,self.now,ca=False,path_len=None,serial=41006)
        self.signer=make_cert('issuer signed by non-CA',self.signer_key,
              self.mid,self.mid_key,self.now,ca=False,path_len=None,serial=41007)
        self.resign();self.resign(historical=False);self.refresh(roster=True)
        self.denied('INTERMEDIATE_CA_KEY_USAGE_OR_PATH_LENGTH_INVALID')

    def test_18_first_pair_is_mandatory(self):
        self.bundle['epochs'][0]['original_historical_signed_lotl_xml']=None
        self.refresh(pins=False,autofill=False);self.denied('FIRST_LOTL_PAIR_REQUIRED')

    def test_19_alias_original_parent_national_tl_path_denied(self):
        self.bundle['epochs'][0]['original_historical_signed_lotl_xml']=(
              self.f.role('A')['original_historical_signed_tsl_xml'])
        self.refresh(pins=False);self.denied('REPLAY_OR_PARENT')

    def test_20_denial_contract_is_a_denial_not_a_success(self):
        from delivery_anchor import anchor as a
        r=operator.denial('audit-historical-ec339-signed-lotl',
              a.AnchorError('EC410_EXPLICIT_FORGED_SOURCE','permission_denied'))
        self.assertEqual(r['exit_code'],3)
        self.assertFalse(any(r[k] for k in core.NEGATIVES))
        self.assertNotIn('bounded_original_lotl_and_real_ec409_parent_consistency',r)

    def test_21_actual_new_argument_grammar_required(self):
        # The inherited EC409 flags use the actual previous contract.
        with patch.object(core.parent,'_inputs',return_value={}):
            full={k:self.extra.get(k,'unused-in-patched-parent') for k in core.PARENT_SCALARS}
            full.update({k:self.extra.get(k,[]) for k in core.PARENT_REPEATS})
            full.update(self.extra)
            full.pop(core.AUDIT_ONLY[0],None)
            self.assertTrue(isinstance(core._inputs(full,True),dict))
            bad=dict(full);bad[core.REPEAT_NAMES[1]]=[3]
            with self.assertRaises(errors.AnchorError):core._inputs(bad,True)

    def test_22_lotl_signed_sequence_rollback_denied(self):
        self.resign(historical=True,sequence=3)
        self.resign(historical=False,sequence=2)
        self.refresh();self.denied('ROLLBACK')

if __name__=='__main__':unittest.main()
