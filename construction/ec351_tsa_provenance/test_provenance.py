#!/usr/bin/env python3
"""EC351 focused genuine OpenSSL RFC3161 + cryptography signed OCSP fixtures.

Every key, source statement, TSA and 'external organization' here is LOCAL
synthetic test material, not an actual independent publisher or trusted clock.
Old deep EC317/318 nested suite still uses historical MOCK fixtures.
"""
from __future__ import annotations
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,ed25519
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from ec295_delivery_anchor import anchor as errors
from ec349_dual_channel_anchor import test_anchor as old_fixture
from ec350_tsa_timestamp import test_timestamp as prior
from ec319_offline_transfer_registry import registry as reg
from . import provenance as core
from . import operator as op

ROOT=Path(__file__).resolve().parents[2]
POLICY=prior.POLICY


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def keyusage(*,ca=False):
    return x509.KeyUsage(digital_signature=not ca,content_commitment=False,
        key_encipherment=False,data_encipherment=False,key_agreement=False,
        key_cert_sign=ca,crl_sign=ca,encipher_only=False,decipher_only=False)


class ProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('openssl'):
            raise unittest.SkipTest('OpenSSL binary unavailable for locally signed DER TSA')
        old_fixture.DualChannelTests.setUpClass()
        cls.f=old_fixture.DualChannelTests.f
        cls.root=old_fixture.DualChannelTests.root

    @classmethod
    def tearDownClass(cls):old_fixture.DualChannelTests.tearDownClass()

    def setUp(self):
        old_fixture.DualChannelTests.setUp(self)
        self.capture_both()
        # Local clock and local signers only; align caller claims for EC350
        # success-with-external-trust-UNPROVEN, never actual verified UTC.
        self.now=datetime.now(timezone.utc)
        utc=lambda dt:dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        self.directories=[self.make_channel_directory(i,
            valid_until_utc=utc(self.now+timedelta(hours=4))) for i in (0,1)]
        self.channel_receipts=[];self.time_receipts=[]
        for idx in (0,1):
            receipt=self.sign_anchor(idx,received=utc(self.now),
                expires=utc(self.now+timedelta(hours=3)))
            self.sign_time(receipt,idx,observed=utc(self.now))
        self.tokens={};self.certserial=0
        self.tsa_certificates={}
        self.auths={};self.ocsp_rows=[]

    def make_token(self,channel=0,*,revoked=False):
        self.certserial+=1;n=self.certserial
        d=Path(self.w)
        rootkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        leafkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,f'local ec351 test root {n}')])
        leafname=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,f'local ec351 test TSA {n}')])
        ca=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(
            rootkey.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
            self.now-timedelta(days=3)).not_valid_after(
            self.now+timedelta(days=30)).add_extension(
            x509.BasicConstraints(ca=True,path_length=1),critical=True).add_extension(
            keyusage(ca=True),critical=True).sign(rootkey,hashes.SHA256())
        tsa=x509.CertificateBuilder().subject_name(leafname).issuer_name(name).public_key(
            leafkey.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
            self.now-timedelta(days=3)).not_valid_after(
            self.now+timedelta(days=30)).add_extension(
            x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(
            keyusage(),critical=True).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=True).sign(rootkey,hashes.SHA256())
        rootfile=d/f'ec351-root-{n}.pem';rootfile.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        leafcert=d/f'ec351-leaf-{n}.pem';leafcert.write_bytes(tsa.public_bytes(serialization.Encoding.PEM))
        leafkeyfile=d/f'ec351-leaf-{n}.key';leafkeyfile.write_bytes(leafkey.private_bytes(
            serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        crl_builder=x509.CertificateRevocationListBuilder().issuer_name(name).last_update(
            self.now-timedelta(minutes=2)).next_update(self.now+timedelta(days=1))
        if revoked:
            crl_builder=crl_builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(tsa.serial_number).revocation_date(
                self.now-timedelta(days=1)).build())
        crlfile=d/f'ec351-root-{n}.crl';crlfile.write_bytes(crl_builder.sign(
            rootkey,hashes.SHA256()).public_bytes(serialization.Encoding.DER))
        serial=d/f'ec351-serial-{n}.txt';serial.write_text('01\n')
        conf=d/f'ec351-tsa-{n}.cnf';conf.write_text(
            '[tsa_config]\nserial = '+str(serial)+'\nsigner_cert = '+str(leafcert)+
            '\nsigner_key = '+str(leafkeyfile)+'\ncerts = '+str(rootfile)+
            '\nsigner_digest = sha256\ndefault_policy = '+POLICY+
            '\ndigests = sha256, sha384, sha512\naccuracy = secs:1\nordering = yes\n'+
            'tsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n')
        receipt=[r for r in self.channel_receipts
                 if r[2]['channel_id']==f'channel_{channel}'][-1]
        req=d/f'ec351-query-{n}.tsq';token=d/f'ec351-token-{n}.der'
        for cmd in (
            ['openssl','ts','-query','-data',receipt[0],'-sha256','-cert','-out',str(req)],
            ['openssl','ts','-reply','-queryfile',str(req),'-config',str(conf),
             '-section','tsa_config','-token_out','-out',str(token)]):
            ran=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
        self.tokens[channel]=(str(token),sha(token),str(rootfile),sha(rootfile),
                              str(crlfile),sha(crlfile))
        self.tsa_certificates[channel]=(ca,tsa,rootkey)
        return self.tokens[channel]

    def make_authority(self,channel=0,*,wrong_root=False,wrong_sig=False):
        # LOCAL Ed25519 authority key: no real external certification.
        d=Path(self.w);key=ed25519.Ed25519PrivateKey.generate()
        pub=key.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw)
        keyfile=d/f'ec351-claimed-authority-{channel}.pub';keyfile.write_bytes(pub)
        source=d/f'ec351-claimed-policy-source-{channel}.pdf'
        source.write_bytes(b'FAKE LOCAL FIXTURE; NOT A THIRD-PARTY POLICY OR TSA.\n')
        source_file_sha=sha(source)
        tok=self.tokens[channel]
        root=x509.load_pem_x509_certificate(Path(tok[2]).read_bytes())
        body={'schema':core.ATTESTATION_SCHEMA,'channel_id':f'channel_{channel}',
              'tsa_root_original_sha256':('f'*64 if wrong_root else tok[3]),
              'tsa_root_certificate_der_sha256':root.fingerprint(hashes.SHA256()).hex(),
              'tsa_policy_oid':POLICY,'source_document_original_sha256':source_file_sha,
              'attester_public_key_original_sha256':sha(keyfile),
              'claimed_source_organization':'Local fake test only',
              'claimed_source_uri':'https://invalid.example.test/local-fixture',
              'issued_utc':(self.now-timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
              'expires_utc':(self.now+timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ')}
        signature=key.sign(core.DOMAIN+reg.canonical(body))
        if wrong_sig:signature=bytes([signature[0]^1])+signature[1:]
        doc={**body,'signature_ed25519_hex':signature.hex()}
        stmt=d/f'ec351-signed-origin-{channel}.json';stmt.write_bytes(reg.canonical(doc))
        self.auths[channel]=(str(stmt),sha(stmt),str(keyfile),sha(keyfile),
                             str(source),sha(source))
        return stmt

    def make_ocsp(self,channel=0,*,status='good',stale=False,
                  wrong_signer=False,wrong_signature=False,future_revocation=False,nonce='a1'*16):
        d=Path(self.w);root,tsa,rootkey=self.tsa_certificates[channel]
        signerkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        signername=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                 'EC351 local synthetic OCSP delegate')])
        rootissuer=root.subject
        if wrong_signer:
            roguekey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            signed_by=roguekey
        else:signed_by=rootkey
        signer=x509.CertificateBuilder().subject_name(signername).issuer_name(
            rootissuer).public_key(signerkey.public_key()).serial_number(
            x509.random_serial_number()).not_valid_before(
            self.now-timedelta(days=2)).not_valid_after(
            self.now+timedelta(days=3)).add_extension(
            x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(
            keyusage(),critical=True).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=False).sign(signed_by,hashes.SHA256())
        code={'good':ocsp.OCSPCertStatus.GOOD,'revoked':ocsp.OCSPCertStatus.REVOKED,
              'unknown':ocsp.OCSPCertStatus.UNKNOWN}[status]
        b=ocsp.OCSPResponseBuilder().add_response(cert=tsa,issuer=root,
            algorithm=hashes.SHA256(),cert_status=code,
            this_update=self.now-timedelta(days=3) if stale else self.now-timedelta(minutes=1),
            next_update=self.now-timedelta(days=1) if stale else self.now+timedelta(days=1),
            revocation_time=(self.now+timedelta(hours=4) if future_revocation else
                             self.now-timedelta(days=1)) if status=='revoked' else None,
            revocation_reason=x509.ReasonFlags.key_compromise if status=='revoked' else None)
        b=b.responder_id(ocsp.OCSPResponderEncoding.HASH,signer).certificates([signer])
        if nonce is not None:b=b.add_extension(x509.OCSPNonce(bytes.fromhex(nonce)),critical=False)
        response=b.sign(signerkey,hashes.SHA256())
        raw=response.public_bytes(serialization.Encoding.DER)
        if wrong_signature:
            sig=response.signature
            where=raw.find(sig)
            self.assertGreater(where,0)
            raw=raw[:where]+bytes([sig[0]^1])+raw[where+1:]
        outfile=d/f'ec351-ocsp-{channel}-{len(self.ocsp_rows)}.der'
        outfile.write_bytes(raw)
        self.ocsp_rows.append((str(outfile),sha(outfile),nonce or 'NONE'))
        return outfile

    def args(self,*,with_crls=True,**overrides):
        base=self.dual_arguments()
        ids=sorted(self.tokens)
        base.update(dual_evaluation_utc=(self.now+timedelta(minutes=1))
                    .strftime('%Y-%m-%dT%H:%M:%SZ'),
            tsa_evaluation_utc=(self.now+timedelta(minutes=2))
                    .strftime('%Y-%m-%dT%H:%M:%SZ'),
            provenance_evaluation_utc=(self.now+timedelta(minutes=3))
                    .strftime('%Y-%m-%dT%H:%M:%SZ'),
            tsa_channel_ids=[f'channel_{i}' for i in ids],
            tsa_token_files=[self.tokens[i][0] for i in ids],
            tsa_token_shas=[self.tokens[i][1] for i in ids],
            tsa_root_files=[self.tokens[i][2] for i in ids],
            tsa_root_shas=[self.tokens[i][3] for i in ids],
            tsa_policy_oids=[POLICY for _ in ids],
            tsa_crl_files=[self.tokens[i][4] for i in ids] if with_crls else [],
            tsa_crl_shas=[self.tokens[i][5] for i in ids] if with_crls else [],
            authority_channel_ids=[f'channel_{i}' for i in sorted(self.auths)],
            authority_statement_files=[self.auths[i][0] for i in sorted(self.auths)],
            authority_statement_shas=[self.auths[i][1] for i in sorted(self.auths)],
            authority_key_files=[self.auths[i][2] for i in sorted(self.auths)],
            authority_key_shas=[self.auths[i][3] for i in sorted(self.auths)],
            authority_source_files=[self.auths[i][4] for i in sorted(self.auths)],
            authority_source_shas=[self.auths[i][5] for i in sorted(self.auths)],
            ocsp_files=[x[0] for x in self.ocsp_rows],
            ocsp_shas=[x[1] for x in self.ocsp_rows],
            ocsp_expected_nonces=[x[2] for x in self.ocsp_rows])
        base.update(overrides)
        return base

    def assert_denial(self,code,**changes):
        with self.assertRaises(errors.AnchorError) as cm:
            core.audit(**self.args(**changes))
        self.assertIn(code,cm.exception.code)

    def test_a_real_signed_source_and_ocsp_good_crl_are_still_not_external_authority(self):
        self.make_token();self.make_authority();self.make_ocsp()
        result=core.audit(**self.args())
        row=result['channel_evidence'][0]
        self.assertEqual(row['outcome'],core.OUTCOMES[6])
        self.assertEqual(row['revocation_edge_evidence'][0]['crl_ocsp_consistency'],
                         'signed_crl_ocsp_agree')
        self.assertTrue(row['source_attestation']['source_byte_pin_and_ed25519_signature_verified'])
        self.assertFalse(row['source_attestation']['real_world_source_provenance_authenticated'])
        self.assertFalse(result['caller_pinned_attester_public_key_proves_independent_real_organization'])
        self.assertEqual(result['exit_code'],2)

    def test_b_no_auth_source_keeps_absent_not_authentic(self):
        self.make_token();self.make_ocsp()
        r=core.audit(**self.args())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[4])

    def test_c_no_ocsp_keeps_independent_revocation_incomplete(self):
        self.make_token();self.make_authority()
        r=core.audit(**self.args())
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])

    def test_d_bad_signed_attestation_rejected(self):
        self.make_token();self.make_authority(wrong_sig=True)
        self.assert_denial('ATTESTATION_ED25519_SIGNATURE_INVALID')

    def test_e_signed_root_binding_conflict_refused(self):
        self.make_token();self.make_authority(wrong_root=True)
        self.assert_denial('ATTESTATION_SOURCE_ROOT_POLICY_OR_KEY_BINDING_MISMATCH')

    def test_f_source_document_changed_with_pinned_sha_rejected(self):
        self.make_token();self.make_authority()
        Path(self.auths[0][4]).write_bytes(b'FAKE LOCAL SOURCE MODIFIED')
        self.assert_denial('WHOLE_ORIGINAL_SHA_MISMATCH_POLICY_SOURCE')

    def test_g_wrong_ocsp_signed_nonce_denied(self):
        self.make_token();self.make_authority();self.make_ocsp()
        self.assert_denial('OCSP_SIGNED_NONCE_MISMATCH_OR_MISSING',
                           ocsp_expected_nonces=['bb'*16])

    def test_h_unsigned_claim_of_live_nonce_denied(self):
        self.make_token();self.make_ocsp(nonce=None)
        self.assert_denial('OCSP_SIGNED_NONCE_MISMATCH_OR_MISSING',
                           ocsp_expected_nonces=['bb'*16])

    def test_i_rogue_responder_cert_name_with_wrong_ca_signature_denied(self):
        self.make_token();self.make_authority();self.make_ocsp(wrong_signer=True)
        self.assert_denial('SIGNED_CERTIFICATE_OR_TOKEN_SIGNATURE_INVALID')

    def test_j_stale_signed_ocsp_not_promoted_to_current(self):
        self.make_token();self.make_authority();self.make_ocsp(stale=True)
        result=core.audit(**self.args())
        self.assertEqual(result['channel_evidence'][0]['outcome'],core.OUTCOMES[5])
        edge=result['channel_evidence'][0]['revocation_edge_evidence'][0]
        self.assertFalse(edge['signed_ocsp']['fresh_for_caller_evaluation'])

    def test_k_real_signed_revoked_ocsp_conflicts_with_current_crl_good(self):
        self.make_token();self.make_authority();self.make_ocsp(status='revoked')
        result=core.audit(**self.args())
        self.assertEqual(result['channel_evidence'][0]['outcome'],core.OUTCOMES[3])
        edge=result['channel_evidence'][0]['revocation_edge_evidence'][0]
        self.assertTrue(edge['signed_ocsp']['revoked_at_or_before_tsa_gen_time'])
        self.assertEqual(edge['crl_ocsp_consistency'],'signed_crl_ocsp_conflict')

    def test_l_crl_missing_is_not_repaired_by_a_single_good_ocsp(self):
        self.make_token();self.make_authority();self.make_ocsp()
        out=core.audit(**self.args(with_crls=False))
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[2])
        self.assertEqual(out['channel_evidence'][0]['revocation_edge_evidence'][0][
            'crl_ocsp_consistency'],'crl_not_fresh_or_absent')

    def test_m_same_subject_multiple_ocsp_responses_no_arbitrary_winner(self):
        self.make_token();self.make_authority();self.make_ocsp(nonce='a1'*16)
        self.make_ocsp(nonce='a2'*16)
        out=core.audit(**self.args())
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[5])
        self.assertEqual(out['channel_evidence'][0]['revocation_edge_evidence'][0][
            'crl_ocsp_consistency'],'multiple_matching_ocsp_snapshots_no_winner')

    def test_n_fork_in_parent_does_not_select_a_latest_with_source(self):
        first=self.channel_receipts[0]
        self.sign_anchor(0,seq=2,prev=first,kind='renewal_claim',
                         received=self.now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                         expires=(self.now+timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        self.sign_anchor(0,seq=2,prev=first,kind='revocation_claim',
                         received=self.now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                         expires=(self.now+timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        # Not presenting channel_0 token is required to audit visible fork.
        out=core.audit(**self.args())
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[0])
        self.assertFalse(out['source_statement_supersedes_ec350_parent_ancestry_or_forks'])

    def test_o_explicit_originals_cannot_alias_old_token(self):
        self.make_token();self.make_authority()
        self.assert_denial('EC351_NEW_ORIGINAL_FILES_MUST_BE_DISTINCT',
                           authority_statement_files=[self.tokens[0][0]])

    def test_p_tsa_timestamp_parent_mismatch_not_fixed_by_auth_signature(self):
        self.channel_receipts=[];self.time_receipts=[]
        claimed=(self.now-timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        expiry=(self.now+timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        for i in (0,1):
            receipt=self.sign_anchor(i,received=claimed,expires=expiry)
            self.sign_time(receipt,i,observed=claimed)
        self.make_token();self.make_authority();self.make_ocsp()
        out=core.audit(**self.args())
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_q_readonly_standalone_and_unified_real_subprocess(self):
        self.make_token();self.make_authority();self.make_ocsp()
        data=self.args()
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_cas_tsa_provenance.py'),
             'audit-provenance-evidence']
        from scripts import ces_next
        for k in ces_next.EC351_KEYS:
            cmd.extend(['--'+k.replace('_','-'),str(data[k])])
        for k,flag in ces_next.EC351_REPEATS:
            for v in data[k]:cmd.extend([flag,str(v)])
        proc=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=360)
        self.assertEqual(proc.returncode,2,proc.stdout+proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['signed_ocsp_original_count'],1)
        unified=[sys.executable,'-B',str(ROOT/'scripts'/'ces_next.py'),
                 'audit-tsa-provenance','DeliveryAudit','AuditOfflineTSASourceAndOCSPProvenance',
                 *cmd[5:]]
        proc=subprocess.run(unified,cwd=ROOT,capture_output=True,text=True,timeout=360)
        self.assertEqual(proc.returncode,2,proc.stdout+proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['signed_ocsp_original_count'],1)
        denied=unified[:]
        denied[4]='IssueOCSP'
        proc=subprocess.run(denied,cwd=ROOT,capture_output=True,text=True,timeout=360)
        self.assertEqual(proc.returncode,3,proc.stdout+proc.stderr)
        self.assertFalse(json.loads(proc.stdout)['permissions_granted'])
        options={v for a in ces_next.build_parser()._subparsers._group_actions[0]
                 .choices['audit-tsa-provenance']._actions for v in a.option_strings}
        for forbidden in ('--private-key-file','--sign','--output','--network',
                          '--remote-provider-write'):
            self.assertNotIn(forbidden,options)


    def test_r_two_verified_channels_still_not_a_pair_of_real_independent_tsa_orgs(self):
        for channel in (0,1):
            self.make_token(channel);self.make_authority(channel);self.make_ocsp(channel)
        out=core.audit(**self.args())
        self.assertEqual([r['outcome'] for r in out['channel_evidence']],
                         [core.OUTCOMES[6],core.OUTCOMES[6]])
        self.assertFalse(out['attesters_share_pinned_public_key'])
        self.assertFalse(out['distinct_statement_files_prove_independent_real_institutions'])

    def test_s_signed_unknown_ocsp_remains_incomplete_not_signed_revocation(self):
        self.make_token();self.make_authority();self.make_ocsp(status='unknown')
        out=core.audit(**self.args())
        edge=out['channel_evidence'][0]['revocation_edge_evidence'][0]
        self.assertEqual(edge['crl_ocsp_consistency'],'signed_ocsp_unknown_incomplete')
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[5])

    def test_t_valid_delegate_certificate_with_invalid_ocsp_signature_denied(self):
        self.make_token();self.make_authority();self.make_ocsp(wrong_signature=True)
        self.assert_denial('SIGNED_CERTIFICATE_OR_TOKEN_SIGNATURE_INVALID')

    def test_u_duplicate_responses_cannot_hide_a_forged_ocsp_signature(self):
        self.make_token();self.make_authority();self.make_ocsp(nonce='a1'*16)
        self.make_ocsp(nonce='a2'*16,wrong_signature=True)
        self.assert_denial('SIGNED_CERTIFICATE_OR_TOKEN_SIGNATURE_INVALID')

    def test_v_ocsp_nonce_without_independent_request_commitment_not_live(self):
        self.make_token();self.make_authority();self.make_ocsp()
        out=core.audit(**self.args(ocsp_expected_nonces=['NONE']))
        nonce=out['channel_evidence'][0]['revocation_edge_evidence'][0]['signed_ocsp']
        self.assertTrue(nonce['nonce_present'])
        self.assertFalse(nonce['nonce_matches_independently_provided_expected_bytes'])
        self.assertFalse(out['unsigned_or_nonprecommitted_nonce_proves_live_ocsp_exchange'])



    def test_w_crl_future_dated_revocation_is_not_current_revoked(self):
        self.make_token();self.make_authority();self.make_ocsp()
        ca,tsa,rootkey=self.tsa_certificates[0]
        builder=x509.CertificateRevocationListBuilder().issuer_name(ca.subject).last_update(
            self.now-timedelta(minutes=1)).next_update(self.now+timedelta(days=1))
        builder=builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(
            tsa.serial_number).revocation_date(self.now+timedelta(hours=3)).build())
        path=Path(self.tokens[0][4]);path.write_bytes(builder.sign(rootkey,hashes.SHA256())
                                                    .public_bytes(serialization.Encoding.DER))
        entry=self.tokens[0];self.tokens[0]=(*entry[:5],sha(path))
        out=core.audit(**self.args())
        edge=out['channel_evidence'][0]['revocation_edge_evidence'][0]
        self.assertEqual(edge['signed_crl_status_at_evaluation'],'signed_good')
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[6])

    def test_x_ocsp_signed_future_revocation_is_denied(self):
        self.make_token();self.make_authority()
        self.make_ocsp(status='revoked',future_revocation=True)
        self.assert_denial('OCSP_SIGNED_REVOCATION_TIME_AFTER_PRODUCED_OR_EVALUATED')



for method in ('capture_both','dual_arguments','make_channel_directory','sign_anchor',
               'sign_time','configure','sign','parameters','audit','copies',
               'observation','show','challenge','response','kw','nonce_sha',
               'issue','reply','params','write','sign_document','make_directory',
               'record','options','present','arguments','actor'):
    setattr(ProvenanceTests,method,getattr(old_fixture.DualChannelTests,method))

if __name__=='__main__':unittest.main()
