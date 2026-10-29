#!/usr/bin/env python3
"""EC399 local genuine X.509 signature/CRL tests, EC398 deep parent MOCKED.

No real government trust anchor, legal issuer, OCSP, signed CMS/PDF government
bulletin, physical WORM or independent internet publication appears in tests.
"""
from __future__ import annotations
import base64
import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.x509.oid import NameOID, ObjectIdentifier
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from official_notice import test_protocol as ec398_fixture
from . import protocol as core

UTC=timezone.utc
PUBLISHED=datetime(2026,10,25,14,35,tzinfo=UTC)
EVALUATION=datetime(2026,10,26,11,tzinfo=UTC)
POLICY='1.3.6.1.4.1.55555.399.1'
EKU='1.3.6.1.4.1.55555.399.2'


def _name(text):return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,text)])


def _usage(ca):
    return x509.KeyUsage(digital_signature=True,content_commitment=False,
       key_encipherment=False,data_encipherment=False,key_agreement=False,
       key_cert_sign=ca,crl_sign=ca,encipher_only=False,decipher_only=False)


def _sign_builder(builder,key):
    return builder.sign(key,None if isinstance(key,ed25519.Ed25519PrivateKey)
                        else hashes.SHA256())


class CertificateGazetteTests(unittest.TestCase):
    def setUp(self):
        fixture=ec398_fixture.ExternalNoticeLocalTests(
            'test_02_two_phase_derive_and_audit_not_self_authorizing')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.old=fixture;self.fixture=fixture.fixture
        r=fixture.evaluate()
        for k,field in zip(core.parent.REPEAT_NAMES,
              ('notice_originals_inventory_sha256','custody_original_readback_inventory_sha256')):
            fixture.opts[k]=[r['external_notice_epoch_reviews'][0][field]]
        fixture.opts[core.parent.REPEAT_NAMES[2]]=[4]
        fixture.opts[core.parent.REPEAT_NAMES[3]]=[2]
        complete=fixture.evaluate()
        self.assertTrue(complete['bounded_local_external_notice_and_custody_consistency'])
        fixture.opts[core.parent.AUDIT_ONLY[0]]=complete[
            'receiver_verified_external_notice_inventory_sha256']
        self.parent_report=fixture.evaluate(False)
        self.parentref={'path':fixture.opts[core.parent.NEW_SCALARS[0]],
                        'sha256':fixture.opts[core.parent.NEW_SCALARS[1]]}
        self.roster={'schema':core.ROSTER_SCHEMA,
            'claimed_directory_lineage_id':fixture.lineage,'publishers':[]}
        self.keys={};self.chains={}
        for role,make_ec in [('A',False),('B',True)]:
            self._add_certificate(role,make_ec)
        self._save_roster()
        self.body={'schema':core.BUNDLE_SCHEMA,
           'claimed_directory_lineage_id':fixture.lineage,
           'parent_ec398_external_notice_bundle_original':self.parentref,
           'outside_publisher_roster_original':self.rosterref,
           'epochs':[{'epoch_index':0,'publishers':[]}]}
        self.opts=dict(fixture.opts)
        self.opts[core.NEW_SCALARS[2]]=self.rosterref['sha256']
        self.opts[core.NEW_SCALARS[7]]=POLICY
        for index,name in enumerate(('A','B')):
            c=self.chains[name]
            self.opts[core.NEW_SCALARS[3+index]]=c['root']['sha256']
            self.opts[core.NEW_SCALARS[5+index]]=c['leaf_spki']
            self.body['epochs'][0]['publishers'].append(self._publisher(name))
        self._save_body()
        self.opts[core.NEW_SCALARS[8]]=self.body['epochs'][0]['publishers'][0][
            'signed_gazette_attestation_original']['sha256']
        self.opts[core.NEW_SCALARS[9]]=self.body['epochs'][0]['publishers'][1][
            'signed_gazette_attestation_original']['sha256']
        for k in core.REPEAT_NAMES:
            self.opts[k]=[0] if k.startswith('minimum_') else ['a'*64]

    def _add_certificate(self,name,make_ec):
        rootkey=ec.generate_private_key(ec.SECP256R1()) if make_ec else ed25519.Ed25519PrivateKey.generate()
        leafkey=ec.generate_private_key(ec.SECP256R1()) if make_ec else ed25519.Ed25519PrivateKey.generate()
        ca_name=_name('FAKE Synthetic Publisher CA '+name)
        leaf_name=_name('FAKE Synthetic Gazette Signer '+name)
        rootb=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(rootkey.public_key()).serial_number(100+len(self.keys))
          .not_valid_before(datetime(2020,1,1,tzinfo=UTC))
          .not_valid_after(datetime(2035,1,1,tzinfo=UTC))
          .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
          .add_extension(_usage(True),critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(rootkey.public_key()),critical=False))
        root=_sign_builder(rootb,rootkey)
        leafb=(x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name)
          .public_key(leafkey.public_key()).serial_number(900+len(self.keys))
          .not_valid_before(datetime(2024,1,1,tzinfo=UTC))
          .not_valid_after(datetime(2030,1,1,tzinfo=UTC))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .add_extension(_usage(False),critical=True)
          .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier(EKU)]),critical=False)
          .add_extension(x509.CertificatePolicies([x509.PolicyInformation(
                       ObjectIdentifier(POLICY),None)]),critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(rootkey.public_key()),critical=False))
        leaf=_sign_builder(leafb,rootkey)
        rootref=self.fixture.archive(root.public_bytes(serialization.Encoding.DER),'root-cert-'+name)
        leafref=self.fixture.archive(leaf.public_bytes(serialization.Encoding.DER),'leaf-cert-'+name)
        pub=leafkey.public_key()
        leaf_spki=core.sha(pub.public_bytes(serialization.Encoding.DER,
                          serialization.PublicFormat.SubjectPublicKeyInfo))
        self.keys[name]=(rootkey,leafkey)
        self.chains[name]={'root':rootref,'leaf':leafref,'rootcert':root,
                            'leafcert':leaf,'leaf_spki':leaf_spki}
        self.roster['publishers'].append({'publisher_id':'Publisher'+name,
            'site_id':'SyntheticSite'+name,
            'certificate_chain_originals':[leafref,rootref],
            'required_policy_oid':POLICY,'required_publisher_eku_oid':EKU})

    def _save_roster(self):
        self.rosterref=self.fixture.archive(self.roster,'ec399-two-issuer-roster')
        if hasattr(self,'body'):
            self.body['outside_publisher_roster_original']=self.rosterref
            self.opts[core.NEW_SCALARS[2]]=self.rosterref['sha256']
            self._save_body()

    def _crl(self,name,asof,evaluation=False,revoked=False):
        rootkey,_=self.keys[name]
        issuer=self.chains[name]['rootcert'].subject
        crlb=(x509.CertificateRevocationListBuilder().issuer_name(issuer)
          .last_update(datetime(2026,10,26,10,tzinfo=UTC) if evaluation else
                       datetime(2026,10,25,0,tzinfo=UTC))
          .next_update(datetime(2026,10,27,0,tzinfo=UTC) if evaluation else
                       datetime(2026,10,26,0,tzinfo=UTC)))
        if revoked:
            revoked_serial=self.chains[name]['leafcert'].serial_number
            entry=(x509.RevokedCertificateBuilder().serial_number(revoked_serial)
                   .revocation_date(datetime(2026,10,24,tzinfo=UTC)).build())
            crlb=crlb.add_revoked_certificate(entry)
        crl=_sign_builder(crlb,rootkey)
        return self.fixture.archive(crl.public_bytes(serialization.Encoding.DER),
                  'eval-crl-'+name if evaluation else 'historic-crl-'+name)

    def _publisher(self,name):
        ch=self.chains[name];entry=self.old.body['epochs'][0]
        nref=entry['notice']['signed_original']
        source=entry['source_notice_original']
        nclaim=json.loads(Path(nref['path']).read_bytes())['claim']
        c={'schema':core.CLAIM_SCHEMA,'directory_lineage_id':self.old.lineage,
          'epoch_index':0,'publisher_id':'Publisher'+name,
          'parent_ec398_bundle_sha256':self.parentref['sha256'],
          'parent_ec398_verified_inventory_sha256':self.parent_report[
               'receiver_verified_external_notice_inventory_sha256'],
          'parent_signed_notice_original_sha256':nref['sha256'],
          'parent_ec396_signed_registry_snapshot_sha256':
               nclaim['parent_ec396_signed_registry_snapshot_sha256'],
          'source_gazette_original_sha256':source['sha256'],
          'leaf_certificate_der_sha256':ch['leaf']['sha256'],
          'certificate_chain_sha256':core.cdigest([ch['leaf']['sha256'],ch['root']['sha256']]),
          'previous_signed_attestation_original_sha256':core.ZERO,
          'claimed_published_utc':'2026-10-25T14:35:00Z',
          'required_policy_oid':POLICY}
        key=self.keys[name][1]
        msg=core.DOMAIN+canonical.canonical(c)
        sig=key.sign(msg,ec.ECDSA(hashes.SHA256())) if isinstance(key,ec.EllipticCurvePrivateKey) else key.sign(msg)
        s={'schema':core.ATTEST_SCHEMA,'claim':c,
           'signature_base64':base64.b64encode(sig).decode('ascii')}
        attestation=self.fixture.archive(s,'signed-x509-gazette-'+name)
        return {'publisher_id':'Publisher'+name,
          'signed_gazette_attestation_original':attestation,
          'issuer_crl_coverage':[{'issuer_certificate_sha256':ch['root']['sha256'],
             'historical_crl_original':self._crl(name,PUBLISHED),
             'evaluation_crl_original':self._crl(name,EVALUATION,True)}]}

    def _save_body(self):
        b=self.fixture.archive(self.body,'ec399-dual-root-bundle')
        self.opts[core.NEW_SCALARS[0]]=b['path']
        self.opts[core.NEW_SCALARS[1]]=b['sha256']

    def evaluate(self,derive=True):
        with patch.object(core,'_inputs',return_value={}),\
             patch.object(core.parent,'audit',return_value=self.parent_report):
            return core.derive_inventory(**self.opts) if derive else core.audit(**self.opts)

    def denial(self):
        with self.assertRaises(errors.AnchorError):self.evaluate()

    def _calibrate(self):
        d=self.evaluate()
        row=d['certificate_epoch_reviews'][0]
        self.opts[core.REPEAT_NAMES[0]]=[row['signed_original_inventory_sha256']]
        self.opts[core.REPEAT_NAMES[1]]=[row['historical_current_crl_inventory_sha256']]
        self.opts[core.REPEAT_NAMES[2]]=[2]
        d=self.evaluate()
        self.opts[core.AUDIT_ONLY[0]]=d['receiver_verified_certificate_inventory_sha256']
        return d

    def test_01_genuine_two_different_x509_chains_and_two_complete_crls(self):
        d=self._calibrate()
        self.assertEqual(d['verified_independent_x509_publisher_count'],2)
        self.assertEqual(d['visible_historically_revoked_certificate_count'],0)
        self.assertTrue(d['bounded_local_gazette_certificate_crl_parent_consistency'])
        self.assertFalse(d[core.NEGATIVES[0]])
        self.assertEqual(d['exit_code'],2)

    def test_02_complete_derive_then_outside_inventory_audit(self):
        self._calibrate()
        report=self.evaluate(False)
        self.assertEqual(report['schema'],core.RESULT_SCHEMA)
        self.assertEqual(report['verified_independent_x509_publisher_count'],2)
        self.assertNotIn('unsigned_two_root_certificate_inventory',report)
        self.assertEqual(report['exit_code'],2)

    def test_03_forged_detached_signature_denied(self):
        ref=self.body['epochs'][0]['publishers'][0]['signed_gazette_attestation_original']
        s=json.loads(Path(ref['path']).read_bytes())
        s['signature_base64']=base64.b64encode(b'fake').decode()
        self.body['epochs'][0]['publishers'][0]['signed_gazette_attestation_original']=self.fixture.archive(s,'fake-sig')
        self._save_body();self.denial()

    def test_04_external_trust_anchor_pin_substitution_denied(self):
        self.opts[core.NEW_SCALARS[3]]='f'*64
        self.denial()

    def test_05_external_leaf_spki_pin_substitution_denied(self):
        self.opts[core.NEW_SCALARS[6]]='e'*64
        self.denial()

    def test_06_wrong_signed_parent_source_hash_denied(self):
        ref=self.body['epochs'][0]['publishers'][0]['signed_gazette_attestation_original']
        signed=json.loads(Path(ref['path']).read_bytes())
        signed['claim']['source_gazette_original_sha256']='a'*64
        self.body['epochs'][0]['publishers'][0]['signed_gazette_attestation_original']=self.fixture.archive(signed,'wrong-parent-hash')
        self._save_body();self.denial()

    def test_07_valid_signed_history_contains_revoked_leaf_no_credit(self):
        row=self.body['epochs'][0]['publishers'][0]['issuer_crl_coverage'][0]
        row['historical_crl_original']=self._crl('A',PUBLISHED,revoked=True)
        self._save_body()
        d=self.evaluate()
        self.assertEqual(d['verified_independent_x509_publisher_count'],1)
        self.assertEqual(d['visible_historically_revoked_certificate_count'],1)
        self.assertTrue(d[core.FLAGS[3]])

    def test_08_revoked_only_at_evaluation_no_current_credit(self):
        row=self.body['epochs'][0]['publishers'][1]['issuer_crl_coverage'][0]
        row['evaluation_crl_original']=self._crl('B',EVALUATION,True,revoked=True)
        self._save_body();d=self.evaluate()
        self.assertEqual(d['verified_independent_x509_publisher_count'],1)
        self.assertTrue(d[core.FLAGS[3]])

    def test_09_missing_historical_crl_unresolved(self):
        self.body['epochs'][0]['publishers'][0]['issuer_crl_coverage'][0]['historical_crl_original']=None
        self._save_body();d=self.evaluate()
        self.assertEqual(d['verified_independent_x509_publisher_count'],1)
        self.assertTrue(d[core.FLAGS[3]])

    def test_10_signed_crl_forgery_denied(self):
        row=self.body['epochs'][0]['publishers'][0]['issuer_crl_coverage'][0]
        crlref=row['historical_crl_original'];raw=bytearray(Path(crlref['path']).read_bytes())
        raw[-1]^=8
        row['historical_crl_original']=self.fixture.archive(bytes(raw),'fake-crl')
        self._save_body();self.denial()

    def test_11_missing_second_publisher_unresolved_not_pass(self):
        entry=self.body['epochs'][0]['publishers'][1]
        entry['signed_gazette_attestation_original']=None
        entry['issuer_crl_coverage']=None
        self._save_body();d=self.evaluate()
        self.assertEqual(d['verified_independent_x509_publisher_count'],1)
        self.assertTrue(d[core.FLAGS[2]])

    def test_12_same_crl_path_reused_for_two_purposes_denied(self):
        row=self.body['epochs'][0]['publishers'][0]['issuer_crl_coverage'][0]
        row['evaluation_crl_original']=row['historical_crl_original']
        self._save_body();self.denial()

    def test_13_certificate_bundle_parent_path_alias_denied(self):
        self.body['epochs'][0]['publishers'][0]['issuer_crl_coverage'][0][
            'evaluation_crl_original']=self.old.body['epochs'][0]['source_notice_original']
        self._save_body();self.denial()

    def test_14_publisher_role_duplicate_denied(self):
        self.body['epochs'][0]['publishers'][1]['publisher_id']='PublisherA'
        self._save_body();self.denial()

    def test_15_certificate_policy_not_pinned_denied(self):
        self.opts[core.NEW_SCALARS[7]]='1.3.6.1.4.1.55555.399.999'
        self.denial()

    def test_16_parent_fake_report_status_rejected(self):
        self.parent_report=copy.deepcopy(self.parent_report)
        self.parent_report['receiver_verified_external_notice_inventory_sha256']='f'*64
        self.denial()

    def test_17_parent_signed_revocation_not_overridden_by_x509(self):
        self.parent_report=copy.deepcopy(self.parent_report)
        rows=self.parent_report['external_notice_epoch_reviews']
        rows[0]['verified_corroborated_active_role_count']=0
        self.parent_report['verified_corroborated_active_notice_role_count']=0
        self.parent_report[core.parent.FLAGS[3]]=True
        self.parent_report['bounded_local_external_notice_and_custody_consistency']=False
        self.parent_report['status']=core.parent.OUTCOMES[3]+'_unresolved'
        d=self.evaluate()
        self.assertEqual(d['verified_independent_x509_publisher_count'],0)
        self.assertTrue(d[core.FLAGS[0]])

    def test_18_wrong_subject_signed_policy_denied(self):
        r=self.roster['publishers'][1]
        r['required_publisher_eku_oid']='1.3.6.1.4.1.55555.399.999'
        self._save_roster();self.denial()

    def test_19_tampered_parent_original_gazette_denied(self):
        Path(self.old.source['path']).write_bytes(b'ATTACK EDITED GAZETTE')
        self.denial()

    def test_20_external_minimum_floor_mismatch_flagged(self):
        self._calibrate()
        self.opts[core.REPEAT_NAMES[0]]=['f'*64]
        self.assertTrue(self.evaluate()[core.FLAGS[1]])

    def test_21_separate_whole_inventory_pin_mismatch_flagged(self):
        self._calibrate()
        self.opts[core.AUDIT_ONLY[0]]='f'*64
        self.assertTrue(self.evaluate(False)[core.FLAGS[1]])

    def test_22_bad_source_has_no_parser_write_escape(self):
        self.body['epochs'][0]['publishers'][0]['signed_gazette_attestation_original']='not_a_ref'
        self._save_body();self.denial()


    def test_23_root_to_intermediate_to_leaf_chain_is_cryptographically_checked(self):
        rootkey,leafkey=self.keys['A']
        intermediate_key=ed25519.Ed25519PrivateKey.generate()
        root_name=self.chains['A']['rootcert'].subject
        intermediate_name=_name('FAKE Intermediate Publisher CA A')
        old_root=self.chains['A']['rootcert']
        root=(x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
          .public_key(rootkey.public_key()).serial_number(3011)
          .not_valid_before(datetime(2020,1,1,tzinfo=UTC))
          .not_valid_after(datetime(2035,1,1,tzinfo=UTC))
          .add_extension(x509.BasicConstraints(ca=True,path_length=1),critical=True)
          .add_extension(_usage(True),critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(rootkey.public_key()),critical=False))
        root=_sign_builder(root,rootkey)
        middle=(x509.CertificateBuilder().subject_name(intermediate_name)
          .issuer_name(root_name).public_key(intermediate_key.public_key())
          .serial_number(3012).not_valid_before(datetime(2020,1,1,tzinfo=UTC))
          .not_valid_after(datetime(2035,1,1,tzinfo=UTC))
          .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
          .add_extension(_usage(True),critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(rootkey.public_key()),critical=False))
        middle=_sign_builder(middle,rootkey)
        leaf=(x509.CertificateBuilder().subject_name(_name('FAKE Via Intermediate Leaf'))
          .issuer_name(intermediate_name).public_key(leafkey.public_key())
          .serial_number(3013).not_valid_before(datetime(2024,1,1,tzinfo=UTC))
          .not_valid_after(datetime(2030,1,1,tzinfo=UTC))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .add_extension(_usage(False),critical=True)
          .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier(EKU)]),critical=False)
          .add_extension(x509.CertificatePolicies([x509.PolicyInformation(ObjectIdentifier(POLICY),None)]),critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()),critical=False))
        leaf=_sign_builder(leaf,intermediate_key)
        refs=[self.fixture.archive(c.public_bytes(serialization.Encoding.DER),slug)
              for c,slug in ((leaf,'via-intermediate-leaf'),(middle,'via-intermediate-ca'),
                             (root,'via-intermediate-root'))]
        role=copy.deepcopy(self.roster['publishers'][0])
        role['certificate_chain_originals']=refs
        # Reuse the actual no-symlink original reader, not an invented chain validator.
        read,doc,late=core.parent.parent.parent.parent.prior._readers()
        chain=core._chain(role,{core.NEW_SCALARS[7]:POLICY},read)
        self.assertEqual(len(chain['certs']),3)
        self.assertTrue(core._certificate_time(chain,PUBLISHED))
        # Real end-entity attestation must still be cryptographically signed.
        claim={'proof':'not-an-official-gazette'}
        sig=leafkey.sign(core.DOMAIN+canonical.canonical(claim))
        core._verify_signature(chain['certs'][0].public_key(),sig,core.DOMAIN+canonical.canonical(claim))
        # Reject signed but policy-violating CA path length, not just forged bytes.
        role['certificate_chain_originals']=[refs[0],refs[1],self.chains['A']['root']]
        with self.assertRaises(errors.AnchorError):
            core._chain(role,{core.NEW_SCALARS[7]:POLICY},read)

    def test_24_issuer_crl_expired_for_evaluation_is_unresolved(self):
        row=self.body['epochs'][0]['publishers'][0]['issuer_crl_coverage'][0]
        row['evaluation_crl_original']=row['historical_crl_original']
        # Nonaliased duplicate original bytes but expired at evaluation.
        raw=Path(row['historical_crl_original']['path']).read_bytes()
        row['evaluation_crl_original']=self.fixture.archive(raw,'copy-old-expired-crl')
        self._save_body();d=self.evaluate()
        self.assertEqual(d['verified_independent_x509_publisher_count'],1)
        self.assertTrue(d[core.FLAGS[3]])

    def test_25_forged_duplicate_signed_json_fields_are_denied(self):
        r=self.body['epochs'][0]['publishers'][0]['signed_gazette_attestation_original']
        raw=Path(r['path']).read_bytes()
        self.assertIn(b'"schema":',raw)
        raw=raw.replace(b'"schema":',b'"schema":"duplicate","schema":',1)
        self.body['epochs'][0]['publishers'][0]['signed_gazette_attestation_original']=self.fixture.archive(
           raw,'duplicate-field-signed-gazette')
        self._save_body();self.denial()


if __name__=='__main__':unittest.main()
