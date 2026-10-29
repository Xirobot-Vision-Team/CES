#!/usr/bin/env python3
"""Focused genuine local DER X.509/CRL/CMS cryptography, no official issuer claim.

EC406.audit is mocked *only inside EC407 child fixtures*, with a report from
true local EC406 Ed25519 and EC405 RFC3161/WARC crypto (deeper ancestors in
those inherited fixtures remain synthetic). Production never uses this mock.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from asn1crypto import cms, core as asncore
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from ec295_delivery_anchor import anchor as errors
from ec406_custody_witness import test_protocol as previous
from . import protocol as core, operator

POLICY = '1.3.6.1.4.1.55555.407.1'


def _certificate(name, key, issuer, signer, at, *, ca, number):
    cn=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
    issuer_name=issuer.subject if issuer is not None else cn
    ku=x509.KeyUsage(digital_signature=True, content_commitment=False,
                     key_encipherment=False, data_encipherment=False,
                     key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                     encipher_only=False, decipher_only=False)
    builder=(x509.CertificateBuilder().subject_name(cn).issuer_name(issuer_name)
             .public_key(key.public_key()).serial_number(number)
             .not_valid_before(at-timedelta(days=200))
             .not_valid_after(at+timedelta(days=200))
             .add_extension(x509.BasicConstraints(ca=ca,path_length=0 if ca else None),
                            critical=True).add_extension(ku,critical=True))
    if not ca:
        builder=builder.add_extension(x509.CertificatePolicies([
            x509.PolicyInformation(x509.ObjectIdentifier(POLICY),None)]),critical=False)
    return builder.sign(signer,hashes.SHA256())


def _crl(root, key, leaf, at, revoked=False):
    builder=(x509.CertificateRevocationListBuilder().issuer_name(root.subject)
             .last_update(at-timedelta(days=2))
             .next_update(at+timedelta(days=2))
             .add_extension(x509.CRLNumber(1),critical=False))
    if revoked:
        rec=(x509.RevokedCertificateBuilder().serial_number(leaf.serial_number)
             .revocation_date(at-timedelta(days=1)).build())
        builder=builder.add_revoked_certificate(rec)
    return builder.sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _cms(raw, signer, leaf, claimed):
    # Real cryptography signs local fixture bytes. Rewrite only this synthetic
    # fixture's CMS signed signingTime to a chosen UTC, then sign actual DER SET.
    bundle=(pkcs7.PKCS7SignatureBuilder().set_data(raw)
            .add_signer(leaf,signer,hashes.SHA256()).sign(
                serialization.Encoding.DER,[pkcs7.PKCS7Options.DetachedSignature,
                                            pkcs7.PKCS7Options.NoCapabilities]))
    ci=cms.ContentInfo.load(bundle,strict=True)
    info=ci['content']['signer_infos'][0]
    timeattr=next(x for x in info['signed_attrs'] if x['type'].native=='signing_time')
    dt=core.utc(claimed)
    timeattr['values'][0]=cms.Time({'utc_time':asncore.UTCTime(dt)})
    info['signature']=signer.sign(info['signed_attrs'].untag().dump(force=True),
                                  padding.PKCS1v15(),hashes.SHA256())
    return ci.dump(force=True)


class InstitutionalCMSOriginalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        previous.OriginalCrossWitnessTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        previous.OriginalCrossWitnessTests.tearDownClass()

    def setUp(self):
        self.f=previous.OriginalCrossWitnessTests(
            'test_01_genuine_dual_signatures_and_original_token_sha')
        self.f.setUp()
        # Earlier synthetic witness +10 seconds can be ahead of CMS signer
        # wall-clock. Re-sign two genuine local witness originals at token time.
        for letter in ('A','B'):
            self.f.witnesses[letter]['claimed_witness_utc']=self.f.claims[letter][
                'verified_token_gen_time_utc']
            self.f.resign_witness(letter)
        self.f.refresh()
        self.parent_report=self.f.calibrate()
        self.extra=dict(self.f.extra)
        self.now=datetime.now(timezone.utc).replace(microsecond=0)
        self.claimed=self.now.strftime('%Y-%m-%dT%H:%M:%SZ')
        self.extra[core.NEW_SCALARS[11]]=(self.now+timedelta(minutes=10)).strftime(
            '%Y-%m-%dT%H:%M:%SZ')
        self.extra[core.REPEAT_NAMES[0]]=['f'*64]
        self.extra[core.REPEAT_NAMES[1]]=[0]
        lineage=self.f.f.f.lineage
        self.roster={'schema':core.ROSTER_SCHEMA,
                     'claimed_directory_lineage_id':lineage,'assignments':[]}
        self.bundle={'schema':core.BUNDLE_SCHEMA,
                     'claimed_directory_lineage_id':lineage,
                     'parent_ec406_original_custody_witness_bundle_original':{
                         'path':self.f.extra[core.parent.NEW_SCALARS[0]],
                         'sha256':self.f.extra[core.parent.NEW_SCALARS[1]]},
                     'outside_institutional_certificate_roster_original':None,
                     'epochs':[{'epoch_index':0,'publishers':[]}]}
        self.keys={};self.statements={}
        for letter in ('A','B'):
            self.add_role(letter)
        self.refresh(roster=True)

    def tearDown(self):
        self.f.tearDown()

    def archive(self, payload, suffix):
        return self.f.archive(payload,'ec407-'+suffix)

    def role(self, letter):
        return self.bundle['epochs'][0]['publishers'][0 if letter=='A' else 1]

    def add_role(self,letter):
        idx=0 if letter=='A' else 1
        role='Publisher'+letter
        root_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        leaf_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        root=_certificate('LocalSyntheticInstitutionRoot'+letter,root_key,None,
                          root_key,self.now,ca=True,number=507+idx)
        leaf=_certificate('LocalSyntheticCustodySigner'+letter,leaf_key,root,
                          root_key,self.now,ca=False,number=607+idx)
        root_ref=self.archive(root.public_bytes(serialization.Encoding.DER),
                              'root-'+letter)
        leaf_ref=self.archive(leaf.public_bytes(serialization.Encoding.DER),
                              'leaf-'+letter)
        crl_ref=self.archive(_crl(root,root_key,leaf,self.now),'crl-'+letter)
        self.keys[letter]={'root_key':root_key,'leaf_key':leaf_key,
                           'root':root,'leaf':leaf,'crl_ref':crl_ref}
        self.extra[core.NEW_SCALARS[3+idx]]=root_ref['sha256']
        self.extra[core.NEW_SCALARS[5+idx]]=leaf_ref['sha256']
        signid='LocalSyntheticInstitution'+letter
        self.roster['assignments'].append({
            'publisher_id':role,'institutional_signer_id':signid,
            'root_certificate_original':root_ref,'leaf_certificate_original':leaf_ref,
            'issuer_crl_originals':[crl_ref],
            'expected_certificate_policy_oid':POLICY})
        p406=self.f.role(letter)
        p405=self.f.f.role(letter)
        self.statements[letter]={
            'schema':core.STATEMENT_SCHEMA,'directory_lineage_id':self.f.f.f.lineage,
            'publisher_id':role,'institutional_signer_id':signid,'epoch_index':0,
            'sequence':1,'previous_cms_original_sha256':None,
            'custody_event_id':'LocalSyntheticCustodyEvent'+letter,
            'ec406_original_accession_sha256':p406['signed_accession_original']['sha256'],
            'ec406_original_witness_sha256':p406['signed_cross_witness_original']['sha256'],
            'ec405_original_warc_sha256':p405['warc_original']['sha256'],
            'ec405_original_rfc3161_sha256':p405['rfc3161_original']['sha256'],
            'claimed_custody_utc':self.claimed}
        self.bundle['epochs'][0]['publishers'].append({
            'publisher_id':role,'institutional_signer_id':signid,
            'original_custody_statement':None,'original_detached_cms':None})
        self.resign(letter)

    def resign(self,letter,*,bad_signature=False):
        raw=json.dumps(self.statements[letter],sort_keys=True,separators=(',',':'),
                       ensure_ascii=True).encode('ascii')
        s=self.archive(raw,'statement-'+letter)
        pair=self.keys[letter]
        cmsraw=_cms(raw,pair['leaf_key'],pair['leaf'],
                    self.statements[letter]['claimed_custody_utc'])
        if bad_signature:
            cmsraw=cmsraw[:-1]+bytes([cmsraw[-1]^1])
        c=self.archive(cmsraw,'cms-'+letter)
        self.role(letter).update({'original_custody_statement':s,
                                  'original_detached_cms':c})

    def refresh(self,*,roster=False,anchor=True):
        if roster:
            rr=self.archive(self.roster,'external-cert-roster')
            self.bundle['outside_institutional_certificate_roster_original']=rr
            self.extra[core.NEW_SCALARS[2]]=rr['sha256']
        b=self.archive(self.bundle,'original-bundle')
        self.extra[core.NEW_SCALARS[0]]=b['path']
        self.extra[core.NEW_SCALARS[1]]=b['sha256']
        if anchor:
            for idx,letter in enumerate(('A','B')):
                self.extra[core.NEW_SCALARS[7+idx]]=self.role(letter)[
                    'original_custody_statement']['sha256']
                self.extra[core.NEW_SCALARS[9+idx]]=self.role(letter)[
                    'original_detached_cms']['sha256']

    def evaluate(self,derive=True):
        opts=dict(self.extra)
        if derive:opts.pop(core.AUDIT_ONLY[0],None)
        with patch.object(core,'_inputs',return_value={}),\
             patch.object(core.parent,'audit',return_value=self.parent_report):
            return core.derive_inventory(**opts) if derive else core.audit(**opts)

    def calibrate(self):
        derived=self.evaluate()
        self.extra[core.REPEAT_NAMES[0]]=[derived['institutional_cms_epoch_reviews'][0][
            'institutional_cms_epoch_inventory_sha256']]
        self.extra[core.REPEAT_NAMES[1]]=[2]
        derived=self.evaluate()
        self.extra[core.AUDIT_ONLY[0]]=derived[
            'receiver_verified_institutional_cms_inventory_sha256']
        return self.evaluate(False)

    def denied(self,code=''):
        with self.assertRaises(errors.AnchorError) as err:
            self.evaluate()
        if code:self.assertIn(code,err.exception.code)

    def test_01_real_detached_cms_two_cert_origins_and_crls(self):
        result=self.calibrate()
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['bounded_local_institutional_cms_and_real_ec406_parent_consistency'])
        self.assertEqual(result['verified_joint_institutional_cms_and_real_parent_publishers'],2)
        self.assertEqual(result['institutional_cms_epoch_reviews'][0][
            'verified_original_cms_statement_count'],2)

    def test_02_derive_is_unsigned_not_legitimate_certification(self):
        out=self.evaluate()
        self.assertEqual(out['schema'],core.DERIVE_SCHEMA)
        self.assertEqual(out['exit_code'],2)
        self.assertTrue(all(not out[k] for k in core.NEGATIVES))
        self.calibrate()
        self.assertNotIn('unsigned_institutional_cms_evidence_inventory',self.evaluate(False))

    def test_03_original_statement_source_sha_alteration_denied(self):
        self.statements['A']['ec406_original_witness_sha256']='a'*64
        self.resign('A');self.refresh()
        self.denied('REAL_PARENT_SHA_CHAIN')

    def test_04_attestation_signature_forgery_denied(self):
        self.resign('B',bad_signature=True);self.refresh()
        self.denied('CMS')

    def test_05_statement_replacement_without_re_signing_denied(self):
        ref=self.role('A')['original_custody_statement']
        statement=json.loads(Path(ref['path']).read_text())
        statement['custody_event_id']='TamperedEvent'
        self.role('A')['original_custody_statement']=self.archive(statement,'tampered-no-sign')
        self.refresh()
        self.denied('CMS_AUTHENTICATED_SOURCE_CONTENT_DIGEST_MISMATCH')

    def test_06_external_root_pin_disagreement_denied(self):
        self.extra[core.NEW_SCALARS[3]]='a'*64
        self.denied('PINNED_CERTIFICATE_DER_SHA')

    def test_07_witness_signed_original_mismatch_denied(self):
        self.statements['B']['ec406_original_accession_sha256']='b'*64
        self.resign('B');self.refresh()
        self.denied('REAL_PARENT_SHA_CHAIN')

    def test_08_revoked_in_issuer_signed_crl_is_unresolved_no_credit(self):
        pair=self.keys['A']
        crl=self.archive(_crl(pair['root'],pair['root_key'],pair['leaf'],
                              self.now,revoked=True),'revoked-crl-A')
        self.roster['assignments'][0]['issuer_crl_originals']=[crl]
        self.refresh(roster=True)
        out=self.evaluate()
        self.assertTrue(out[core.FLAGS[3]])
        self.assertEqual(out['verified_joint_institutional_cms_and_real_parent_publishers'],1)

    def test_09_duplicate_institutional_signer_id_denied(self):
        self.roster['assignments'][1]['institutional_signer_id']=self.roster[
            'assignments'][0]['institutional_signer_id']
        self.refresh(roster=True)
        self.denied('INSTITUTIONAL_ROLE_ID')

    def test_10_parent_real_ec406_report_cannot_be_skipped(self):
        self.parent_report=dict(self.parent_report)
        self.parent_report['receiver_verified_custody_witness_inventory_sha256']='f'*64
        self.denied('UNCHANGED_REAL_EC406_PARENT')

    def test_11_first_signed_original_required(self):
        self.role('A')['original_detached_cms']=None
        self.refresh(anchor=False)
        self.denied('FIRST_TWO_STATEMENT')

    def test_12_wrong_first_sha_unresolved_not_autorepaired(self):
        self.extra[core.NEW_SCALARS[9]]='e'*64
        result=self.evaluate()
        self.assertTrue(result[core.FLAGS[1]])
        self.assertEqual(result['exit_code'],2)

    def test_13_cms_signer_claimed_time_mismatch_denied(self):
        self.statements['A']['claimed_custody_utc']=(self.now+timedelta(
            hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.resign('A')
        self.refresh()
        result=self.evaluate()
        self.assertTrue(result[core.FLAGS[3]])

    def test_14_parent_joint_coverage_cannot_be_repaired(self):
        report=dict(self.parent_report)
        rows=[dict(x) for x in report['custody_witness_epoch_reviews']]
        rows[0]['joint_signed_custody_witness_and_parent_count']=0
        report['custody_witness_epoch_reviews']=rows
        report['verified_joint_custody_witness_and_real_parent_publishers']=0
        report['bounded_local_custody_witness_and_real_ec405_parent_consistency']=False
        report[core.parent.FLAGS[4]]=True
        report['status']=core.parent.OUTCOMES[4]+'_unresolved'
        self.parent_report=report
        out=self.evaluate()
        self.assertTrue(out[core.FLAGS[0]])
        self.assertEqual(out['verified_joint_institutional_cms_and_real_parent_publishers'],0)

    def test_15_external_roster_path_reuses_parent_denied(self):
        self.roster['assignments'][0]['root_certificate_original']={
            'path':self.f.extra[core.parent.NEW_SCALARS[0]],
            'sha256':self.f.extra[core.parent.NEW_SCALARS[1]]}
        self.refresh(roster=True)
        self.denied('CERTIFICATE_ORIGINAL_PATH_ALIASES')

    def test_16_denial_never_signs_or_returns_pass(self):
        bad=operator.denial('audit-historical-ec339-institutional-cms',
            errors.AnchorError('EC407_DENIED','permission_denied'))
        self.assertEqual(bad['exit_code'],3)
        self.assertTrue(all(bad[k] is False for k in core.NEGATIVES))

    def test_17_unaccredited_claimed_cert_policy_cannot_be_substituted(self):
        self.roster['assignments'][0]['expected_certificate_policy_oid']=(
            '1.3.6.1.4.1.55555.407.999')
        self.refresh(roster=True)
        self.denied('LEAF_ORIGINAL_CERTIFICATE_POLICY_OID_MISMATCH')

    def test_18_crl_without_actual_issuer_signature_is_denied(self):
        pair=self.keys['B']
        unrelated=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        forged=self.archive(_crl(pair['root'],unrelated,pair['leaf'],self.now),
                            'issuer-crl-forged-B')
        self.roster['assignments'][1]['issuer_crl_originals']=[forged]
        self.refresh(roster=True)
        self.denied()

    def test_19_signed_duplicate_event_id_cross_roles_denied(self):
        self.statements['B']['custody_event_id']=self.statements['A'][
            'custody_event_id']
        self.resign('B');self.refresh()
        self.denied('REAL_PARENT_SHA_CHAIN_OR_EVENT_ID_INVALID')

    def test_20_identical_institutional_root_key_with_distinct_der_is_denied(self):
        # Distinct DER paths and certificate SHA values must not mask one RSA
        # institution root key controlled by both claimed separate institutions.
        original=self.keys['B']
        reused=self.keys['A']['root_key']
        replacement_root=_certificate('LocalSyntheticInstitutionRootB',reused,
                     None,reused,self.now,ca=True,number=508)
        replacement_leaf=_certificate('LocalSyntheticCustodySignerB',
                     original['leaf_key'],replacement_root,reused,self.now,
                     ca=False,number=608)
        rootref=self.archive(replacement_root.public_bytes(
            serialization.Encoding.DER),'reused-root-B')
        leafref=self.archive(replacement_leaf.public_bytes(
            serialization.Encoding.DER),'reused-leaf-B')
        crlref=self.archive(_crl(replacement_root,reused,replacement_leaf,
                                 self.now),'reused-root-crl-B')
        record=self.roster['assignments'][1]
        record.update(root_certificate_original=rootref,
                      leaf_certificate_original=leafref,
                      issuer_crl_originals=[crlref])
        self.extra[core.NEW_SCALARS[4]]=rootref['sha256']
        self.extra[core.NEW_SCALARS[6]]=leafref['sha256']
        original['root']=replacement_root
        original['leaf']=replacement_leaf
        self.resign('B');self.refresh(roster=True)
        self.denied('INSTITUTIONAL_RSA_PUBLIC_KEY_REUSED_WITH_ANCESTOR_OR_SIGNER')

if __name__=='__main__':
    unittest.main()
