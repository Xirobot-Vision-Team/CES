#!/usr/bin/env python3
"""EC350 local real OpenSSL RFC3161 signed tokens; NOT an independent TSA.

Old EC317/318 nested fixture continues to be MOCK; this suite never labels
locally generated roots, CRLs, timestamp claims or times as outside evidence.
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
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from delivery_anchor import anchor as errors
from dual_channel_anchor import test_anchor as old_fixture
from . import timestamp as core
from . import operator as op

ROOT=Path(__file__).resolve().parents[2]
POLICY='1.2.3.4.5.350'


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def local_test_certs(directory:Path, index:int, *, revoked=False,stale=False):
    """Synthetic local CA/TSA, only to exercise real RSA/CMS/CRL verification."""
    now=datetime.now(timezone.utc)
    rootkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leafkey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    rootname=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,f'EC350 local test CA {index}')])
    leafname=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,f'EC350 local test TSA {index}')])
    ca=x509.CertificateBuilder().subject_name(rootname).issuer_name(rootname).public_key(
        rootkey.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        now-timedelta(days=3)).not_valid_after(now+timedelta(days=30)).add_extension(
        x509.BasicConstraints(ca=True,path_length=1),critical=True).add_extension(
        x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,
                      data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,
                      encipher_only=False,decipher_only=False),critical=True).sign(rootkey,hashes.SHA256())
    tsa=x509.CertificateBuilder().subject_name(leafname).issuer_name(rootname).public_key(
        leafkey.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        now-timedelta(days=3)).not_valid_after(now+timedelta(days=30)).add_extension(
        x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(
        x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,
                      data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,
                      encipher_only=False,decipher_only=False),critical=True).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),critical=True).sign(
        rootkey,hashes.SHA256())
    rootfile=directory/f'tsa-root-{index}.pem';rootfile.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    leafcert=directory/f'tsa-leaf-{index}.pem';leafcert.write_bytes(tsa.public_bytes(serialization.Encoding.PEM))
    leafpriv=directory/f'tsa-leaf-{index}.key';leafpriv.write_bytes(leafkey.private_bytes(
        serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    b=x509.CertificateRevocationListBuilder().issuer_name(rootname)
    if stale:
        b=b.last_update(now-timedelta(days=3)).next_update(now-timedelta(days=1))
    else:
        b=b.last_update(now-timedelta(minutes=1)).next_update(now+timedelta(days=2))
    if revoked:
        b=b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(
            tsa.serial_number).revocation_date(now-timedelta(days=1)).build())
    crl=b.sign(rootkey,hashes.SHA256())
    crlfile=directory/f'tsa-root-{index}.crl';crlfile.write_bytes(crl.public_bytes(serialization.Encoding.DER))
    return rootfile,leafcert,leafpriv,crlfile


class TimestampAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which('openssl') is None:
            raise unittest.SkipTest('OpenSSL executable unavailable for signed RFC3161 test fixture')
        old_fixture.DualChannelTests.setUpClass()
        cls.f=old_fixture.DualChannelTests.f
        cls.root=old_fixture.DualChannelTests.root

    @classmethod
    def tearDownClass(cls):old_fixture.DualChannelTests.tearDownClass()

    def setUp(self):
        old_fixture.DualChannelTests.setUp(self)
        self.capture_both()
        self.tokens={}
        self.certserial=0

    def make_token(self,channel=0,*,input_file=None,revoked=False,stale=False,
                   use_response=False,policy=POLICY):
        """Generate actual RFC3161 CMS DER via local OpenSSL, not trusted TSA."""
        self.certserial+=1
        n=self.certserial
        d=Path(self.w)
        root,cert,priv,crl=local_test_certs(d,n,revoked=revoked,stale=stale)
        receipt=[r for r in self.channel_receipts if r[2]['channel_id']==f'channel_{channel}'][-1]
        source=input_file or receipt[0]
        conf=d/f'ec350-tsa-{n}.cnf';serial=d/f'ec350-serial-{n}.txt'
        serial.write_text('01\n',encoding='ascii')
        conf.write_text('[tsa_config]\nserial = '+str(serial)+'\nsigner_cert = '+str(cert)+
            '\nsigner_key = '+str(priv)+'\ncerts = '+str(root)+'\nsigner_digest = sha256\n'+
            'default_policy = '+policy+'\ndigests = sha256, sha384, sha512\n'+
            'accuracy = secs:1\nordering = yes\ntsa_name = yes\n'+
            'ess_cert_id_chain = no\ness_cert_id_alg = sha256\n',encoding='ascii')
        req=d/f'ec350-query-{n}.tsq';token=d/f'ec350-token-{n}.der'
        queries=[['openssl','ts','-query','-data',str(source),'-sha256','-cert','-out',str(req)],
                 ['openssl','ts','-reply','-queryfile',str(req),'-config',str(conf),
                  '-section','tsa_config','-out',str(token)]]
        if not use_response:queries[1].insert(-2,'-token_out')
        for command in queries:
            p=subprocess.run(command,capture_output=True,text=True)
            if p.returncode:
                raise AssertionError(f'openssl local fixture failure: {p.stdout} {p.stderr}')
        tup=(str(token),sha(token),str(root),sha(root),str(crl),sha(crl))
        self.tokens[channel]=tup
        return tup

    def args(self,*,with_crls=False,**overrides):
        a=self.dual_arguments()
        ids=sorted(self.tokens)
        a.update(tsa_evaluation_utc=(datetime.now(timezone.utc)+timedelta(minutes=2))
                   .strftime('%Y-%m-%dT%H:%M:%SZ'),
            tsa_channel_ids=[f'channel_{i}' for i in ids],
            tsa_token_files=[self.tokens[i][0] for i in ids],
            tsa_token_shas=[self.tokens[i][1] for i in ids],
            tsa_root_files=[self.tokens[i][2] for i in ids],
            tsa_root_shas=[self.tokens[i][3] for i in ids],
            tsa_policy_oids=[POLICY for _ in ids],
            tsa_crl_files=list(dict.fromkeys(self.tokens[i][4] for i in ids)) if with_crls else [],
            tsa_crl_shas=[sha(p) for p in dict.fromkeys(self.tokens[i][4] for i in ids)]
                if with_crls else [])
        a.update(overrides)
        return a

    def assert_denial(self,code,**kw):
        with self.assertRaises(errors.AnchorError) as r:
            core.audit(**self.args(**kw))
        self.assertIn(code,r.exception.code)

    def test_a_no_token_still_replays_349_and_reports_not_presented(self):
        out=core.audit(**self.args())
        self.assertEqual(out['outcome_counts'][core.OUTCOMES[1]],2)
        self.assertTrue(out['ec349_full_signed_history_replayed'])
        self.assertFalse(out['valid_signed_gen_time_proves_independently_trusted_utc'])

    def test_b_unsigned_handoff_real_history_no_tsa_signer(self):
        d=core.checklist(**self.dual_arguments())
        self.assertEqual(d['exit_code'],2)
        self.assertEqual(len(d['channel_latest_signed_receipt_heads']),2)
        self.assertNotIn('private_key',str(d))

    def test_c_real_der_signed_token_root_path_and_imprint_without_crl(self):
        self.make_token()
        out=core.audit(**self.args())
        r=out['channel_evidence'][0]
        self.assertEqual(r['outcome'],core.OUTCOMES[4])
        self.assertEqual(r['verified_tsa_path_certificate_count'],2)
        self.assertEqual(r['imprint_algorithm'],'sha256')
        self.assertFalse(r['revocation_evidence']['all_chain_edges_have_single_fresh_crl_as_furnished'])

    def test_d_full_test_crl_verifies_but_gen_time_vs_claim_discrepancy_remains(self):
        self.make_token()
        out=core.audit(**self.args(with_crls=True))
        row=out['channel_evidence'][0]
        self.assertTrue(row['revocation_evidence']['all_chain_edges_have_single_fresh_crl_as_furnished'])
        self.assertTrue(row['signed_gen_time_minus_receipt_claim_seconds']>300)
        self.assertEqual(row['outcome'],core.OUTCOMES[5])

    def test_e_wrong_policy_is_cryptographic_denial(self):
        self.make_token()
        self.assert_denial('TIMESTAMP_TSTINFO_POLICY',tsa_policy_oids=['1.2.3.999'])

    def test_f_token_imprint_over_other_bytes_is_denied(self):
        fake=Path(self.w)/'unrelated.txt';fake.write_bytes(b'not an actual EC349 signed original')
        self.make_token(input_file=str(fake))
        self.assert_denial('TSTINFO_IMPRINT')

    def test_g_tampered_cms_signature_even_with_recomputed_outer_sha_denied(self):
        token=self.make_token()[0]
        from asn1crypto import cms
        doc=cms.ContentInfo.load(Path(token).read_bytes())
        sig=doc['content']['signer_infos'][0]['signature'].native
        doc['content']['signer_infos'][0]['signature']=bytes([sig[0]^1])+sig[1:]
        Path(token).write_bytes(doc.dump())
        self.assert_denial('SIGNED_CERTIFICATE_OR_TOKEN_SIGNATURE_INVALID',
                           tsa_token_shas=[sha(token)])

    def test_h_wrong_root_is_denied(self):
        self.make_token(0);other=self.make_token(1)
        self.assert_denial('MISSING_OR_AMBIGUOUS_TSA_CERTIFICATE_ISSUER',
                           tsa_root_files=[other[2]],tsa_root_shas=[other[3]],
                           tsa_channel_ids=['channel_0'],
                           tsa_token_files=[self.tokens[0][0]],
                           tsa_token_shas=[self.tokens[0][1]],
                           tsa_policy_oids=[POLICY])

    def test_i_signed_crl_revoked_before_gen_time_visible(self):
        self.make_token(revoked=True)
        out=core.audit(**self.args(with_crls=True))
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[3])
        self.assertTrue(out['channel_evidence'][0]['revocation_evidence']['revoked_at_or_before_gen_time'])

    def test_j_stale_crl_is_not_fresh_revocation_check(self):
        self.make_token(stale=True)
        out=core.audit(**self.args(with_crls=True))
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[4])
        self.assertTrue(out['channel_evidence'][0]['revocation_evidence']['crl_stale'])

    def test_k_two_distinct_local_tokens_do_not_prove_real_tsa_independence(self):
        self.make_token(0);self.make_token(1)
        out=core.audit(**self.args(with_crls=True))
        self.assertEqual(len(out['cross_token_time_comparison']),1)
        self.assertEqual(out['token_original_count'],2)
        self.assertFalse(out['separate_token_files_prove_physically_independent_tsa_institutions'])

    def test_l_full_timestamp_response_wrapper_supported(self):
        self.make_token(0,use_response=True)
        out=core.audit(**self.args())
        self.assertEqual(out['channel_evidence'][0]['verified_tsa_path_certificate_count'],2)

    def test_m_missing_pin_even_if_bytes_correct_denied(self):
        self.make_token(0)
        self.assert_denial('SHA_PIN_OR_PATH_INVALID_TSA_TOKEN',tsa_token_shas=['UNPINNED'])

    def test_n_tampered_root_without_pinned_sha_denied(self):
        p=self.make_token(0)[2]
        with open(p,'ab') as f:f.write(b'changed')
        self.assert_denial('WHOLE_ORIGINAL_SHA_MISMATCH_TSA_ROOT')

    def test_o_channel_fork_can_never_be_resolved_by_token(self):
        first=self.channel_receipts[0]
        self.sign_anchor(0,seq=2,prev=first,kind='renewal_claim',received='2026-10-25T14:38:00Z')
        self.sign_anchor(0,seq=2,prev=first,kind='revocation_claim',received='2026-10-25T14:39:00Z')
        self.make_token(0)
        self.assert_denial('CANNOT_BIND_TSA_TOKEN_TO_ABSENT_OR_FORKED_EC349_HEAD')

    def test_p_no_explicit_tsa_token_for_fork_does_not_select_winner(self):
        first=self.channel_receipts[0]
        self.sign_anchor(0,seq=2,prev=first,kind='renewal_claim',received='2026-10-25T14:38:00Z')
        self.sign_anchor(0,seq=2,prev=first,kind='revocation_claim',received='2026-10-25T14:39:00Z')
        out=core.audit(**self.args())
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[0])

    def test_q_old_unpinned_receipt_not_repaired_by_later_tsa_signature(self):
        # Core EC349 must continue carrying the original UNPINNED fact.
        self.channel_receipts[0]=(self.channel_receipts[0][0],
                                  self.channel_receipts[0][1],
                                  self.channel_receipts[0][2],False)
        self.make_token(0)
        out=core.audit(**self.args(with_crls=True))
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_r_standalone_and_unified_fixed_readonly_cli(self):
        self.make_token(0)
        args=self.args(with_crls=True)
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_cas_tsa_evidence.py'),
             'audit-tsa-evidence']
        for key in (*op.SCALARS,'dual_evaluation_utc','tsa_evaluation_utc'):
            cmd.extend(['--'+key.replace('_','-'),str(args[key])])
        for key in (*op.old_cli.old_cli.PARENT_REPEATS,
                    *op.old_cli.old_cli.EXTRA_REPEATS):
            flag=op.old_cli.old_cli.FLAGS[key]
            for v in args[key]:cmd.extend(['--'+flag.replace('_','-'),str(v)])
        for key,flag in op.old_cli.ADDED_REPEATS:
            for v in args[key]:cmd.extend(['--'+flag.replace('_','-'),str(v)])
        for key,flag in op.NEW_REPEATS:
            for v in args[key]:cmd.extend(['--'+flag.replace('_','-'),str(v)])
        reply=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,timeout=300)
        self.assertEqual(reply.returncode,2,reply.stdout+reply.stderr)
        self.assertEqual(json.loads(reply.stdout)['token_original_count'],1)
        unified=[sys.executable,'-B',str(ROOT/'scripts'/'ces_next.py'),
                 'audit-tsa-evidence','DeliveryAudit','AuditOfflineRFC3161TSAEvidence']
        from scripts import ces_next
        for k in ces_next.EC350_KEYS:
            unified.extend(['--'+k.replace('_','-'),str(args[k])])
        for k,flag in ces_next.EC350_REPEATS:
            for v in args[k]:unified.extend([flag,str(v)])
        reply=subprocess.run(unified,cwd=ROOT,text=True,capture_output=True,timeout=300)
        self.assertEqual(reply.returncode,2,reply.stdout+reply.stderr)
        self.assertEqual(json.loads(reply.stdout)['token_original_count'],1)
        deny=unified[:];deny[5]='WriteTimeToken'
        reply=subprocess.run(deny,cwd=ROOT,text=True,capture_output=True,timeout=300)
        self.assertEqual(reply.returncode,3,reply.stdout+reply.stderr)
        self.assertFalse(json.loads(reply.stdout)['permissions_granted'])
        options={o for ac in ces_next.build_parser()._subparsers._group_actions[0]
                 .choices['audit-tsa-evidence']._actions for o in ac.option_strings}
        for forbidden in ('--private-key-file','--sign','--out','--cas-write','--provider'):
            self.assertNotIn(forbidden,options)


    def test_s_bounded_cryptographic_success_does_not_promote_external_clock(self):
        # Align EC349's *locally generated* signed claims with the real OpenSSL
        # token generation clock. Even success remains NOT independently trusted.
        now=datetime.now(timezone.utc)
        claimed=now.strftime('%Y-%m-%dT%H:%M:%SZ')
        expiry=(now+timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.directories=[self.make_channel_directory(i,
            valid_until_utc=(now+timedelta(hours=3)).strftime('%Y-%m-%dT%H:%M:%SZ'))
            for i in (0,1)]
        self.channel_receipts=[];self.time_receipts=[]
        for idx in (0,1):
            row=self.sign_anchor(idx,received=claimed,expires=expiry)
            self.sign_time(row,idx,observed=claimed)
        self.make_token(0)
        a=self.args(with_crls=True,
            dual_evaluation_utc=(now+timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        out=core.audit(**a)
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[6])
        self.assertFalse(out['valid_signed_gen_time_proves_independently_trusted_utc'])
        self.assertFalse(out['caller_furnished_tsa_root_proves_real_outside_trust_anchor'])

    def test_t_crl_with_matching_issuer_name_but_fake_key_is_denied(self):
        self.make_token(0)
        rootfile=Path(self.tokens[0][2]);crlfile=Path(self.tokens[0][4])
        issuer=x509.load_pem_x509_certificate(rootfile.read_bytes()).subject
        now=datetime.now(timezone.utc)
        rogue=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        fake=x509.CertificateRevocationListBuilder().issuer_name(issuer).last_update(
            now-timedelta(minutes=1)).next_update(now+timedelta(days=1)).sign(
            rogue,hashes.SHA256())
        crlfile.write_bytes(fake.public_bytes(serialization.Encoding.DER))
        self.assert_denial('SIGNED_CERTIFICATE_OR_TOKEN_SIGNATURE_INVALID',
                           with_crls=True,tsa_crl_shas=[sha(crlfile)])

    def test_u_same_root_and_signer_for_two_tokens_is_reported_not_independence(self):
        first=self.make_token(0)
        receipt=[r for r in self.channel_receipts if r[2]['channel_id']=='channel_1'][0]
        d=Path(self.w);req=d/'ec350-shared-query.tsq'; token=d/'ec350-shared-token.der'
        conf=d/'ec350-tsa-1.cnf'
        for cmd in (
            ['openssl','ts','-query','-data',receipt[0],'-sha256','-cert','-out',str(req)],
            ['openssl','ts','-reply','-queryfile',str(req),'-config',str(conf),
             '-section','tsa_config','-token_out','-out',str(token)]):
            p=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        self.tokens[1]=(str(token),sha(token),first[2],first[3],first[4],first[5])
        out=core.audit(**self.args(with_crls=True))
        peer=out['cross_token_time_comparison'][0]
        self.assertTrue(peer['common_tsa_root_der_fingerprint'])
        self.assertTrue(peer['common_tsa_signer_certificate'])
        self.assertFalse(out['separate_token_files_prove_physically_independent_tsa_institutions'])


for method in ('configure','sign','parameters','audit','copies','observation',
               'show','challenge','response','kw','nonce_sha','issue','reply','params',
               'write','sign_document','make_directory','record','options','present','arguments',
               'actor','make_channel_directory','sign_anchor','sign_time',
               'capture_both','dual_arguments'):
    setattr(TimestampAuditTests,method,getattr(old_fixture.DualChannelTests,method))

if __name__=='__main__':unittest.main()
