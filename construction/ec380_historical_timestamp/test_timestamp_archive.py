#!/usr/bin/env python3
"""EC380 focused actual locally generated RFC3161 DER/CMS, X509, Ed25519
EC349 receipt, signed CRL and OCSP. Synthetic local keys are NOT outside TSA.
Inherited EC366->EC337 deep fixture is MOCKED and not exercised here.
"""
from __future__ import annotations

from datetime import datetime,timedelta,timezone
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,ed25519
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec349_dual_channel_anchor import anchor as ec349
from . import timestamp_archive as core

CHANNEL='HistoricTsaChannelA'
POLICY='1.2.3.4.5.380'
UTC=timezone.utc


def at(t):return t.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')

class ActualHistoricTimestampOriginalTests(unittest.TestCase):
    def setUp(self):
        if shutil.which('openssl') is None:
            self.skipTest('OpenSSL executable missing; actual RFC3161 token not fabricated')
        self.tmp=tempfile.TemporaryDirectory(prefix='ec380-original-')
        self.addCleanup(self.tmp.cleanup)
        self.directory=Path(self.tmp.name)
        self.counter=0
        self.now=datetime.now(UTC).replace(microsecond=0)
        self.rootkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.signerkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.receiptkey=ed25519.Ed25519PrivateKey.generate()
        rootname=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'EC380 local root CA')])
        signername=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'EC380 local TSA signer')])
        self.root=(x509.CertificateBuilder().subject_name(rootname).issuer_name(rootname)
          .public_key(self.rootkey.public_key()).serial_number(104380)
          .not_valid_before(self.now-timedelta(days=7))
          .not_valid_after(self.now+timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True,path_length=1),critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,
             key_encipherment=False,data_encipherment=False,key_agreement=False,
             key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),
             critical=True).sign(self.rootkey,hashes.SHA256()))
        self.signer=(x509.CertificateBuilder().subject_name(signername).issuer_name(rootname)
          .public_key(self.signerkey.public_key()).serial_number(104381)
          .not_valid_before(self.now-timedelta(days=7))
          .not_valid_after(self.now+timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,
             key_encipherment=False,data_encipherment=False,key_agreement=False,
             key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),
             critical=True)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
                         critical=True).sign(self.rootkey,hashes.SHA256()))
        self.rootref=self.write('root.pem',self.root.public_bytes(serialization.Encoding.PEM))
        self.signerref=self.write('leaf.pem',self.signer.public_bytes(serialization.Encoding.PEM))
        self.private=self.write('local-temporary-leaf.key',self.signerkey.private_bytes(
            serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.receiptref=self.make_receipt()
        self.tokenref=self.make_token()
        self.crlref=self.make_crl()
        self.ocspref=self.make_ocsp()
        self.source={'channel':CHANNEL,'root_ref':self.rootref,
           'binding':{'tsa_policy_oid':POLICY},
           'attester_sha':'11'*32,
           'issued':self.now-timedelta(days=1),
           'document':{'issued_utc':at(self.now-timedelta(days=1)),
                       'expires_utc':at(self.now+timedelta(days=1))}}
        self.token={'tsa_channel_id':CHANNEL,'ec349_receipt_original':self.receiptref,
            'rfc3161_timestamp_original':self.tokenref,
            'tsa_signer_certificate_original':self.signerref,
            'tsa_intermediate_certificate_originals':[],
            'issuer_crl_originals':[self.crlref],
            'issuer_ocsp_originals':[{'signed_ocsp_original':self.ocspref,
                                      'expected_nonce_hex':'NONE'}]}
        self.evaluation=self.now+timedelta(minutes=3)

    def write(self,label,bytes_or_doc):
        self.counter+=1
        p=self.directory/f'{self.counter:04d}-{label}'
        p.write_bytes(bytes_or_doc if type(bytes_or_doc) is bytes else
                      canonical.canonical(bytes_or_doc))
        return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}

    def make_receipt(self,received=None):
        received=received or self.now
        claim={'schema':ec349.RECEIPT_CLAIM,
            'case_id':'ec380_local_case','ec348_inputs_canonical_sha256':'22'*32,
            'ec348_verified_result_canonical_sha256':'23'*32,
            'channel_id':CHANNEL,'channel_directory_original_raw_sha256':'24'*32,
            'receipt_signer_id':'LocalEc349Signer',
            'receipt_signer_public_hex':self.receiptkey.public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex(),
            'receipt_signer_organization_id':'LocalTestOrganization',
            'keeper_visible_heads':[],'keeper_signed_originals':[],
            'statement_kind':'capture_claim','sequence':1,
            'previous_statement_file':None,
            'previous_statement_original_raw_sha256':None,
            'statement_nonce_sha256':'25'*32,
            'claimed_received_utc':at(received),
            'expires_utc':at(received+timedelta(days=1)),
            'scope':'signed_out_of_band_keeper_heads_claim_only',
            'no_remote_custody_or_external_time_authority':True}
        return self.write('real-signed-ec349-receipt.json',{
            'schema':ec349.RECEIPT_SCHEMA,'claim':claim,
            'signature_ed25519':self.receiptkey.sign(
                ec349.D_RECEIPT+canonical.canonical(claim)).hex()})

    def make_token(self,receipt=None,policy=POLICY):
        receipt=receipt or self.receiptref
        serial=self.write('tsaserial.txt',b'01\n')
        config=self.write('openssl-tsa.cnf',(
            '[tsa_config]\nserial = '+serial['path']+'\n'
            'signer_cert = '+self.signerref['path']+'\n'
            'signer_key = '+self.private['path']+'\n'
            'certs = '+self.rootref['path']+'\nsigner_digest = sha256\n'
            'default_policy = '+policy+'\ndigests = sha256, sha384, sha512\n'
            'accuracy = secs:1\nordering = yes\ntsa_name = yes\n'
            'ess_cert_id_chain = no\ness_cert_id_alg = sha256\n').encode())
        q=str(self.directory/'request.tsq');out=str(self.directory/'token.der')
        for command in (
          ['openssl','ts','-query','-data',receipt['path'],'-sha256',
           '-cert','-out',q],
          ['openssl','ts','-reply','-queryfile',q,'-token_out',
           '-config',config['path'],'-section','tsa_config','-out',out]):
            p=subprocess.run(command,text=True,capture_output=True)
            if p.returncode:self.fail('genuine local OpenSSL fixture failed: '+p.stderr)
        return self.write('captured-real-rfc3161-token.der',Path(out).read_bytes())

    def make_crl(self,revoked=False,stale=False):
        b=x509.CertificateRevocationListBuilder().issuer_name(self.root.subject)
        if stale:b=b.last_update(self.now-timedelta(days=4)).next_update(
            self.now-timedelta(days=1))
        else:b=b.last_update(self.now-timedelta(minutes=1)).next_update(
            self.now+timedelta(days=2))
        if revoked:b=b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(self.signer.serial_number)
            .revocation_date(self.now-timedelta(days=1)).build())
        return self.write('signed-issuer.crl',b.sign(self.rootkey,hashes.SHA256()).public_bytes(
            serialization.Encoding.DER))

    def make_ocsp(self,revoked=False,stale=False,foreign=False):
        cert=self.signer
        if foreign:
            cert=(x509.CertificateBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME,'foreign OCSP certificate')]))
              .issuer_name(self.root.subject).public_key(self.signerkey.public_key())
              .serial_number(104382).not_valid_before(self.now-timedelta(days=2))
              .not_valid_after(self.now+timedelta(days=2)).sign(
                  self.rootkey,hashes.SHA256()))
        start=self.now-timedelta(days=4) if stale else self.now-timedelta(minutes=1)
        end=self.now-timedelta(days=1) if stale else self.now+timedelta(days=1)
        builder=(ocsp.OCSPResponseBuilder().add_response(
           cert=cert,issuer=self.root,algorithm=hashes.SHA256(),
           cert_status=ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD,
           this_update=start,next_update=end,
           revocation_time=self.now-timedelta(hours=2) if revoked else None,
           revocation_reason=x509.ReasonFlags.key_compromise if revoked else None)
           .responder_id(ocsp.OCSPResponderEncoding.HASH,self.root))
        return self.write('signed-ocsp.der',builder.sign(
            self.rootkey,hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    def read(self,ref,role,cap):
        self.assertEqual(type(ref),dict)
        raw=Path(ref['path']).read_bytes()
        self.assertLessEqual(len(raw),cap)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),ref['sha256'])
        return raw

    def verify(self,**updates):
        t=copy.deepcopy(self.token);t.update(updates)
        return core._timestamp(t,self.source,self.read,self.evaluation)

    def deny(self,fragment,**changes):
        with self.assertRaises(errors.AnchorError) as ex:self.verify(**changes)
        self.assertIn(fragment,ex.exception.code)

    def test_01_actual_cms_receipt_signature_ess_root_crl_ocsp(self):
        d=self.verify()
        self.assertTrue(d['real_cms_signed_attributes_esscertid_and_receipt_imprint_verified'])
        self.assertTrue(d['actual_ec349_receipt_ed25519_self_claim_signature_verified'])
        self.assertEqual(d['policy_oid_signed_in_tstinfo'],POLICY)
        self.assertEqual(len(d['explicit_original_certificate_path_der_shas']),2)
        self.assertEqual(d['signed_ocsp_matching_certificate_edge_count'],1)
        self.assertTrue(d['signed_token_within_original_source_window'])
        self.assertTrue(d['signed_ec349_receipt_claim_close_to_tst_gen_time'])
        self.assertFalse(d['adverse_or_missing_crl_evidence'])
        self.assertFalse(d['adverse_or_missing_ocsp_evidence'])

    def test_02_signed_rfc3161_policy_conflict_denied(self):
        self.source['binding']['tsa_policy_oid']='1.2.3.4.5.999'
        self.deny('TIMESTAMP_TSTINFO_POLICY')

    def test_03_token_imprint_does_not_match_different_actual_signed_receipt(self):
        r=self.make_receipt(self.now+timedelta(seconds=1))
        self.deny('TSTINFO_IMPRINT',ec349_receipt_original=r)

    def test_04_broken_old_ec349_receipt_ed25519_signature_denied(self):
        doc=json.loads(Path(self.receiptref['path']).read_text())
        doc['signature_ed25519']='00'*64
        self.deny('ED25519_INVALID',ec349_receipt_original=self.write('invalid-receipt.json',doc))

    def test_05_ec349_fake_unsigned_receipt_denied_before_cms(self):
        doc=json.loads(Path(self.receiptref['path']).read_text())
        del doc['signature_ed25519']
        self.deny('EXACT_FIELDS_REQUIRED',ec349_receipt_original=self.write('unsigned-receipt.json',doc))

    def test_06_cms_tampered_signature_denied_even_when_original_sha_updated(self):
        from asn1crypto import cms
        obj=cms.ContentInfo.load(Path(self.tokenref['path']).read_bytes())
        sig=obj['content']['signer_infos'][0]['signature'].native
        obj['content']['signer_infos'][0]['signature']=bytes([sig[0]^1])+sig[1:]
        self.deny('SIGNED_CERTIFICATE_OR_TOKEN_SIGNATURE_INVALID',
                  rfc3161_timestamp_original=self.write('invalid-cms.der',obj.dump()))

    def test_07_signed_ocsp_missing_never_assumed_good(self):
        d=self.verify(issuer_ocsp_originals=[])
        self.assertTrue(d['adverse_or_missing_ocsp_evidence'])
        self.assertFalse(d['adverse_or_missing_crl_evidence'])

    def test_08_signed_crl_missing_never_assumed_good(self):
        d=self.verify(issuer_crl_originals=[])
        self.assertTrue(d['adverse_or_missing_crl_evidence'])
        self.assertFalse(d['adverse_or_missing_ocsp_evidence'])

    def test_09_signed_crl_revoked_before_timestamp_visible(self):
        d=self.verify(issuer_crl_originals=[self.make_crl(revoked=True)])
        self.assertTrue(d['signed_crl_status']['revoked_at_or_before_gen_time'])
        self.assertTrue(d['adverse_or_missing_crl_evidence'])

    def test_10_signed_crl_stale_visible(self):
        d=self.verify(issuer_crl_originals=[self.make_crl(stale=True)])
        self.assertTrue(d['adverse_or_missing_crl_evidence'])

    def test_11_second_signed_crl_same_issuer_no_winner(self):
        d=self.verify(issuer_crl_originals=[self.crlref,self.make_crl(stale=True)])
        self.assertTrue(d['signed_crl_status']['crl_multiple_for_issuer'])
        self.assertTrue(d['adverse_or_missing_crl_evidence'])

    def test_12_actual_signed_ocsp_revoked_visible(self):
        d=self.verify(issuer_ocsp_originals=[{'signed_ocsp_original':self.make_ocsp(revoked=True),
                                              'expected_nonce_hex':'NONE'}])
        self.assertTrue(d['adverse_or_missing_ocsp_evidence'])
        self.assertTrue(d['signed_revocation_edges'][0][
            'matching_signed_ocsp_originals'][0]['status_revoked_at_signed_tsa_time'])

    def test_13_actual_signed_ocsp_stale_visible(self):
        d=self.verify(issuer_ocsp_originals=[{'signed_ocsp_original':self.make_ocsp(stale=True),
                                              'expected_nonce_hex':'NONE'}])
        self.assertTrue(d['adverse_or_missing_ocsp_evidence'])

    def test_14_signed_ocsp_unrelated_certid_denied(self):
        self.deny('CERTID_OUTSIDE',issuer_ocsp_originals=[{
            'signed_ocsp_original':self.make_ocsp(foreign=True),'expected_nonce_hex':'NONE'}])

    def test_15_ocsp_expected_nonce_not_in_original_denied(self):
        self.deny('OCSP_SIGNED_NONCE',issuer_ocsp_originals=[{
            'signed_ocsp_original':self.ocspref,'expected_nonce_hex':'ab'*16}])

    def test_16_duplicate_signed_ocsp_original_denied(self):
        self.deny('DUPLICATE_SIGNED_OCSP',issuer_ocsp_originals=[
            {'signed_ocsp_original':self.ocspref,'expected_nonce_hex':'NONE'}]*2)

    def test_17_wrong_explicit_signer_cert_denied(self):
        other=self.write('wrong-signer.der',self.root.public_bytes(serialization.Encoding.DER))
        self.deny('PINNED_TSA_SIGNER_CERTIFICATE_NOT_CMS_SIGNER',
                  tsa_signer_certificate_original=other)

    def test_18_missing_explicit_intermediate_count_rejected(self):
        self.deny('EXPLICIT_INTERMEDIATE',tsa_intermediate_certificate_originals=[self.rootref])

    def test_19_issuer_attester_key_role_collision_denied(self):
        self.source['attester_sha']=hashlib.sha256(bytes.fromhex(
            json.loads(Path(self.receiptref['path']).read_text())['claim'][
                'receipt_signer_public_hex'])).hexdigest()
        self.deny('RECEIPT_SIGNER_MUST_NOT_REUSE')

    def test_20_signed_receipt_claimed_utc_rollback_reported_not_trusted(self):
        changed=self.make_receipt(self.now-timedelta(days=3))
        token=self.make_token(changed)
        d=self.verify(ec349_receipt_original=changed,rfc3161_timestamp_original=token)
        self.assertFalse(d['signed_ec349_receipt_claim_close_to_tst_gen_time'])
        self.assertTrue(d['real_cms_signed_attributes_esscertid_and_receipt_imprint_verified'])

    def test_21_original_ec351_source_claim_window_dispute(self):
        self.source['issued']=self.now+timedelta(hours=1)
        self.source['document']['issued_utc']=at(self.source['issued'])
        d=self.verify()
        self.assertFalse(d['signed_token_within_original_source_window'])

    def test_22_one_issuer_ocsp_signed_good_does_not_establish_global_census(self):
        d=self.verify()
        for entry in d['signed_revocation_edges']:
            for x in entry['matching_signed_ocsp_originals']:
                self.assertFalse(x['caller_precommitment_itself_externally_authenticated'])
        self.assertNotIn('all_world_revocation_proven',d)

    def test_23_wrong_channel_claim_denied(self):
        self.deny('TOKEN_CHANNEL_DOES_NOT_MATCH',tsa_channel_id='OtherTsa')

    def test_24_unrelated_original_crl_root_denied(self):
        self.deny('DUPLICATED_CRL',issuer_crl_originals=[self.crlref,self.crlref])

    def test_25_tampered_token_sha_pin_not_substitutable(self):
        ref=dict(self.tokenref,sha256='aa'*32)
        with self.assertRaises(AssertionError):self.verify(rfc3161_timestamp_original=ref)

    def test_26_disallowed_unexpected_record_field_denied(self):
        self.deny('EXACT_FIELDS_REQUIRED',arbitrary_caller_trust=True)

    def test_27_new_input_contract_does_not_accept_caller_parent_report(self):
        with self.assertRaises(errors.AnchorError) as exc:
            core.derive_inventory(caller_success_report={'schema':'PASS'})
        self.assertIn('EXACT_PARENT',exc.exception.code)

    def test_28_negatives_are_explicit_and_cannot_be_current_success(self):
        self.assertIn('old_ec349_receipt_signature_and_full_channel_ancestry_rebuilt',
                      core.NEGATIVES)
        self.assertIn('signed_timestamp_selects_winner_of_hidden_ec349_forks',
                      core.NEGATIVES)


    def engine_fixture(self,*,sender_label=None,wrong_parent=False,epochs=1):
        """Exercise the new receiver archive under a deliberately MOCKED
        production parent. Actual CMS, receipt and CRL/OCSP remain real.
        This is NOT a real EC379->EC369 or EC366->EC337 replay.
        """
        from ec377_historical_transparency import transparency_archive as p377
        from ec378_historical_registry import registry_archive as p378
        from ec379_historical_source import source_archive as p379
        parent={'schema':p379.RESULT_SCHEMA,'exit_code':2,
          'sender_origin_path_required_or_read':False,
          'ec350_through_ec337_full_historical_parent_replay_performed':False,
          'historical_source_epoch_reviews':[{'epoch_index':e} for e in range(epochs)],
          'local_pinned_ec351_source_signatures_and_old_registry_binding_consistent':True}
        parentsha=core.sha(canonical.canonical(parent))
        lineage='HistoricLineageEc380'
        src=self.write('ec379-verified-receiver-source.json',{
          'schema':p379.BUNDLE_SCHEMA,
          'parent_ec378_canonical_result_sha256':'11'*32,
          'ec378_historical_registry_archive_original_sha256':'22'*32,
          'claimed_directory_lineage_id':lineage,
          'epochs':[{'epoch_index':e,'sources':[
            {'tsa_channel_id':CHANNEL,
             'tsa_root_certificate_original':self.rootref}]}
             for e in range(epochs)]})
        registry=self.write('ec378-verified-receiver-registry.json',{
          'schema':p378.BUNDLE_SCHEMA,
          'parent_ec377_canonical_result_sha256':'33'*32,
          'ec377_historical_transparency_archive_original_sha256':'44'*32,
          'claimed_directory_lineage_id':lineage,
          'epochs':[{'epoch_index':e,'claimed_tsa_channel_ids':[CHANNEL],
          'registries':[{'registry_channel_id':'RegistryA'},
                        {'registry_channel_id':'RegistryB'}]}
             for e in range(epochs)]})
        pub=self.write('ec353-old-publication-original.json',{
            'schema':'untrusted-old-ec353-labels',
            'labels':[{'path':sender_label or str(self.directory/'old-sender-nonexistent.txt')}]})
        transparency=self.write('ec377-verified-receiver-archive.json',{
          'schema':p377.BUNDLE_SCHEMA,
          'parent_ec376_canonical_result_sha256':'55'*32,
          'ec376_historical_disclosure_archive_original_sha256':'66'*32,
          'claimed_directory_lineage_id':lineage,
          'epochs':[{'epoch_index':e,'ec353_publication_bundle_original':pub,'logs':[]}
             for e in range(epochs)]})
        receiver=self.write('ec380-receiver-originals.json',{
          'schema':core.BUNDLE_SCHEMA,
          'parent_ec379_canonical_result_sha256':('77'*32 if wrong_parent else parentsha),
          'ec379_historical_source_archive_original_sha256':src['sha256'],
          'claimed_directory_lineage_id':lineage,
          'epochs':[{'epoch_index':e,'timestamps':[self.token]} for e in range(epochs)]})
        opts={'historical_directory_root_shas':['12'*32 for _ in range(epochs)],
          'detached_evaluation_utc':at(self.evaluation),
          'claimed_historical_directory_lineage_id':lineage,
          'historical_source_archive_bundle_file':src['path'],
          'expected_historical_source_archive_bundle_sha256':src['sha256'],
          'historical_registry_archive_bundle_file':registry['path'],
          'expected_historical_registry_archive_bundle_sha256':registry['sha256'],
          'historical_transparency_archive_bundle_file':transparency['path'],
          'expected_historical_transparency_archive_bundle_sha256':transparency['sha256'],
          'historical_timestamp_archive_bundle_file':receiver['path'],
          'expected_historical_timestamp_archive_bundle_sha256':receiver['sha256'],
          'historical_timestamp_evidence_inventory_shas':['aa'*32 for _ in range(epochs)],
          'historical_timestamp_revocation_inventory_shas':['bb'*32 for _ in range(epochs)],
          'minimum_historical_verified_timestamp_counts':[1 for _ in range(epochs)],
          'minimum_historical_signed_revocation_edge_counts':[1 for _ in range(epochs)]}
        return parent,opts

    def engine_call(self,parent,opts,derive=True):
        from ec378_historical_registry import registry_archive as p378
        with (patch.object(core,'_inputs',return_value={}),
              patch.object(core.previous,'audit',return_value=parent),
              patch.object(core.previous,'_source',return_value=self.source),
              patch.object(p378,'_registry',side_effect=lambda r,*_a,**_k:{'id':r['registry_channel_id']}),
              patch.object(core.previous,'_claim_status',return_value='authorized_claim_exact_binding')):
            return core.derive_inventory(**opts) if derive else core.audit(**opts)

    def test_29_real_signed_originals_in_mock_parent_receiver_engine(self):
        parent,opts=self.engine_fixture()
        d=self.engine_call(parent,opts)
        self.assertEqual(d['exit_code'],2)
        self.assertEqual(d['verified_real_rfc3161_timestamp_receipt_imprint_count'],1)
        self.assertEqual(d['signed_ocsp_matching_certificate_edge_count'],1)
        self.assertEqual(d['missing_authenticated_source_tsa_timestamp_count'],0)
        self.assertTrue(d['independently_retained_timestamp_or_revocation_inventory_floor_disagrees'])
        self.assertFalse(d['sender_origin_path_required_or_read'])
        self.assertTrue(d['complete_old_ec349_through_ec337_original_canonical_parents_not_rebuilt'])
        self.assertEqual(d['historical_timestamp_epoch_reviews'][0][
            'signed_ocsp_matching_certificate_edge_count'],1)
        # An absent OCSP edge is never silently counted as a signed match.
        receiverdoc=json.loads(Path(opts['historical_timestamp_archive_bundle_file']).read_text())
        receiverdoc['epochs'][0]['timestamps'][0]['issuer_ocsp_originals']=[]
        no_ocsp=self.write('ec380-receiver-without-ocsp.json',receiverdoc)
        no_ocsp_opts=dict(opts,historical_timestamp_archive_bundle_file=no_ocsp['path'],
                          expected_historical_timestamp_archive_bundle_sha256=no_ocsp['sha256'])
        no_ocsp_result=self.engine_call(parent,no_ocsp_opts)
        self.assertEqual(no_ocsp_result['signed_ocsp_matching_certificate_edge_count'],0)
        self.assertEqual(no_ocsp_result['historical_timestamp_epoch_reviews'][0][
            'signed_ocsp_matching_certificate_edge_count'],0)
        self.assertTrue(no_ocsp_result['real_ec351_signed_ocsp_missing_stale_unknown_revoked_or_conflicting'])
        # A reused genuine signed receipt/token in a later epoch is a dispute:
        # no second new timestamp may be inferred from old unchanged bytes.
        replay_parent,replay_opts=self.engine_fixture(epochs=2)
        replay=self.engine_call(replay_parent,replay_opts)
        self.assertTrue(replay['old_ec350_signed_timestamp_epoch_rollback_or_double_binding'])
        self.assertEqual(replay['verified_real_rfc3161_timestamp_receipt_imprint_count'],2)
        self.assertFalse(replay['local_signed_timestamp_and_revocation_inputs_consistent'])
        self.assertEqual(replay['exit_code'],2)

    def test_30_exact_original_inventory_derive_then_audit_still_unresolved(self):
        parent,opts=self.engine_fixture()
        derived=self.engine_call(parent,opts)
        r=derived['historical_timestamp_epoch_reviews'][0]
        opts.update(historical_timestamp_evidence_inventory_shas=[r[
            'timestamp_original_inventory_sha256']],
            historical_timestamp_revocation_inventory_shas=[r[
            'signed_revocation_original_inventory_sha256']],
            expected_retained_historical_timestamp_inventory_sha256=derived[
             'receiver_verified_historical_timestamp_inventory_sha256'])
        d=self.engine_call(parent,opts,False)
        self.assertTrue(d['local_signed_timestamp_and_revocation_inputs_consistent'])
        self.assertFalse(any(d[f] for f in core.FLAGS[:7]))
        self.assertTrue(all(d[f] for f in core.FLAGS[-2:]))
        self.assertEqual(d['status'],core.OUTCOMES[7]+'_unresolved')
        self.assertEqual(d['exit_code'],2)

    def test_31_changed_archive_parent_hash_denied_even_with_file_sha_updated(self):
        parent,opts=self.engine_fixture(wrong_parent=True)
        with self.assertRaises(errors.AnchorError) as r:self.engine_call(parent,opts)
        self.assertIn('NOT_BIND_LIVE_EC379',r.exception.code)

    def test_32_sender_origin_path_label_never_opened_for_receipt(self):
        parent,opts=self.engine_fixture(sender_label=self.receiptref['path'])
        with self.assertRaises(errors.AnchorError) as r:self.engine_call(parent,opts)
        self.assertIn('ALIASES_SENDER',r.exception.code)

    def test_33_fake_success_parent_report_not_accepted(self):
        parent,opts=self.engine_fixture()
        parent['exit_code']=0
        with self.assertRaises(errors.AnchorError) as r:self.engine_call(parent,opts)
        self.assertIn('REAL_EC379',r.exception.code)

    def test_34_independently_retained_wrong_inventory_does_not_pass(self):
        parent,opts=self.engine_fixture()
        d=self.engine_call(parent,opts)
        r=d['historical_timestamp_epoch_reviews'][0]
        opts.update(historical_timestamp_evidence_inventory_shas=[r[
          'timestamp_original_inventory_sha256']],
          historical_timestamp_revocation_inventory_shas=[r[
          'signed_revocation_original_inventory_sha256']],
          expected_retained_historical_timestamp_inventory_sha256='ee'*32)
        d=self.engine_call(parent,opts,False)
        self.assertTrue(d['independently_retained_timestamp_or_revocation_inventory_floor_disagrees'])
        self.assertFalse(d['local_signed_timestamp_and_revocation_inputs_consistent'])
        self.assertEqual(d['exit_code'],2)


if __name__=='__main__':unittest.main()
