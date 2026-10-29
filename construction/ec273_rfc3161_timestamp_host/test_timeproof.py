#!/usr/bin/env python3
"""EC273 functional RFC3161 fixture: real local OpenSSL CA/TSA and real EC272 chain.

All certificates are synthetic and locally controlled. These tests do not
attest a production TSA, independent trusted UTC or external revocation.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from ec263_offline_anchor_host import checkpoint as cp
from ec266_source_provenance_host import provenance as prov
from ec272_freshness_rollover_host.test_rollover import RolloverTests as original
from ec272_freshness_rollover_host import rollover as roll
from ec273_rfc3161_timestamp_host import timeproof as tsa


class LocalTSA:
    tsa_policy='1.3.6.1.4.1.55555.273'
    openssl='/usr/bin/openssl'

    def issue_tsa(self):
        private=self.fix.private
        self.tsa_request=private/'ec273-current-query.tsq'
        result=tsa.prepare_request(segment=str(self.tail),segment_sha256=self.tail_pin,
            checkpoint_sha256=self.cp_pin,policy_oid=self.tsa_policy,
            output=str(self.tsa_request))
        self.tsa_request_pin=result['request_sha256']
        self.ca=private/'ec273-ca.pem'
        ca_key=private/'ec273-ca.key'
        cert=private/'ec273-leaf.pem'
        key=private/'ec273-leaf.key'
        csr=private/'ec273-leaf.csr'
        ext=private/'ec273-ext.cnf'
        self.tsa_response=private/'ec273-response.tsr'
        config=private/'ec273-tsa.cnf'
        serial=private/'ec273-serial'
        serial.write_text('01\n')
        ext.write_text('[ tsa ]\nbasicConstraints=critical,CA:FALSE\n'
            'keyUsage=critical,digitalSignature\n'
            'extendedKeyUsage=critical,timeStamping\n'
            'subjectKeyIdentifier=hash\n')
        self.run_openssl('req','-x509','-newkey','rsa:2048','-nodes',
            '-sha256','-days','1','-subj','/CN=EC273 Development Root',
            '-keyout',str(ca_key),'-out',str(self.ca))
        self.run_openssl('req','-new','-newkey','rsa:2048','-nodes',
            '-sha256','-subj','/CN=EC273 Development TSA',
            '-keyout',str(key),'-out',str(csr))
        self.run_openssl('x509','-req','-sha256','-days','1',
            '-in',str(csr),'-CA',str(self.ca),'-CAkey',str(ca_key),
            '-CAcreateserial','-extfile',str(ext),'-extensions','tsa',
            '-out',str(cert))
        config.write_text('[ tsa ]\ndefault_tsa=ec273\n[ ec273 ]\n'
            f'serial={serial}\n'
            f'signer_cert={cert}\nsigner_key={key}\n'
            f'certs={self.ca}\n'
            'signer_digest=sha256\n'
            f'default_policy={self.tsa_policy}\n'
            'digests=sha256\naccuracy=secs:1\nordering=yes\n'
            'tsa_name=yes\ness_cert_id_chain=no\n')
        self.run_openssl('ts','-reply','-config',str(config),
            '-queryfile',str(self.tsa_request),'-out',str(self.tsa_response))
        self.run_openssl('ts','-verify','-queryfile',str(self.tsa_request),
            '-in',str(self.tsa_response),'-CAfile',str(self.ca),
            '-tspolicy',self.tsa_policy)
        # OpenSSL creates 0644 files; the host requires privately readable 0600.
        for candidate in (self.ca,self.tsa_response):
            candidate.chmod(0o600)
        der=subprocess.run([self.openssl,'x509','-in',str(cert),'-outform','DER'],
            check=True,capture_output=True).stdout
        self.leaf_pin=hashlib.sha256(der).hexdigest()
        self.response_pin=prov._digest(self.tsa_response.read_bytes())
        self.binary_pin=prov._digest(Path(self.openssl).read_bytes())
        return result

    def run_openssl(self,*args):
        result=subprocess.run([self.openssl,*args],capture_output=True,
                              check=False,timeout=10)
        if result.returncode != 0:
            raise AssertionError('OpenSSL fixture failed: '+result.stderr.decode('utf8','replace')[:1500])

    def verify(self,**changes):
        opts=dict(segment=str(self.tail),segment_sha256=self.tail_pin,
            checkpoint_sha256=self.cp_pin,
            request=str(self.tsa_request),request_sha256=self.tsa_request_pin,
            response=str(self.tsa_response),response_sha256=self.response_pin,
            ca_bundle=str(self.ca),ca_bundle_sha256=prov._digest(self.ca.read_bytes()),
            leaf_cert_sha256=self.leaf_pin,policy_oid=self.tsa_policy,
            openssl_binary=self.openssl,openssl_binary_sha256=self.binary_pin,
            effective_now=time.time(),maximum_age_seconds=600,
            minimum_time_unix=self.issued-30)
        opts.update(changes)
        return tsa.verify_timestamp(**opts)


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and
                     os.geteuid()!=0 and Path('/usr/bin/git').exists() and
                     Path('/usr/bin/openssl').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux Git/OpenSSL/Ed25519 required')
class TimestampTests(unittest.TestCase,LocalTSA):
    setUp=original.setUp
    prepare=original.prepare
    remote=original.remote
    begin_request=original.begin_request
    kill_host=original.kill_host
    _prepare=original._prepare
    new_gate=original.new_gate
    prepare_base=original.prepare_base
    prepare_ec266=original.prepare_ec266
    new_gov=original.new_gov
    make_handover=original.make_handover
    renew_policy=original.renew_policy
    create_chain=original.create_chain
    issue=original.issue
    write_gate=original.write_gate
    _kwargs=original._kwargs
    sign_recovery=original.sign_recovery
    sign_closure=original.sign_closure
    closure_material=original.closure_material
    material=original.material
    _context=original._context
    _signed_checkpoint=original._signed_checkpoint
    sign_seal=original.sign_seal
    historic=original.historic
    freshness_options=original.freshness_options
    prepare_base=original.prepare_base

    def test_01_real_rfc3161_signature_chain_nonce_policy_and_latest_tail(self):
        self.prepare()
        detail=self.issue_tsa()
        self.assertEqual(detail['freshness_sequence'],2)
        self.assertTrue(detail['request_has_128bit_nonce'])
        report=self.verify()
        self.assertTrue(report['trusted_external_timestamp_signature_verified'])
        self.assertEqual(report['timestamp_bound_to_latest_receipt_sha256'],self.next_receipt_pin)
        self.assertEqual(report['timestamp_query_nonce_bits'],128)
        self.assertFalse(report['timestamp_cross_restart_nonrollbackable_escrow_verified'])

    def test_02_incorrect_policy_leaf_pin_ca_or_executable_fails_closed(self):
        self.prepare();self.issue_tsa()
        changes=[{'policy_oid':'1.3.6.1.4.1.55555.274'},
                 {'leaf_cert_sha256':'0'*64},
                 {'ca_bundle_sha256':'0'*64},
                 {'openssl_binary_sha256':'0'*64},
                 {'openssl_binary':'/bin/sh'}]
        for kwargs in changes:
            with self.subTest(kwargs=kwargs),self.assertRaises(Exception):
                self.verify(**kwargs)

    def test_03_bound_to_exact_receipt_checkpoint_and_manifest(self):
        self.prepare();self.issue_tsa()
        for kwargs in ({'checkpoint_sha256':'0'*64},
                       {'segment_sha256':'0'*64}):
            with self.subTest(kwargs=kwargs),self.assertRaises(Exception):
                self.verify(**kwargs)
        changed=self.tsa_request.read_bytes()
        self.tsa_request.write_bytes(changed[:-1]+bytes([changed[-1]^1]))
        with self.assertRaises(Exception):
            self.verify(request_sha256=prov._digest(self.tsa_request.read_bytes()))

    def test_04_signature_and_response_pin_both_mandatory(self):
        self.prepare();self.issue_tsa()
        raw=self.tsa_response.read_bytes()
        self.tsa_response.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
        with self.assertRaises(Exception):
            self.verify()
        with self.assertRaises(Exception):
            self.verify(response_sha256=prov._digest(self.tsa_response.read_bytes()))

    def test_05_age_future_and_operator_floor_reject(self):
        self.prepare();self.issue_tsa()
        actual=self.verify()
        certified=actual['timestamp_gen_time_unix']
        with self.assertRaises(Exception):
            self.verify(effective_now=certified+601)
        with self.assertRaises(Exception):
            self.verify(effective_now=certified-31)
        with self.assertRaises(Exception):
            self.verify(minimum_time_unix=int(certified)+1)
        with self.assertRaises(Exception):
            self.verify(maximum_age_seconds=901)

    def test_06_missing_source_and_required_offline_request_exclusive(self):
        self.prepare();self.issue_tsa()
        with self.assertRaises(Exception):
            tsa.prepare_request(segment=str(self.tail),segment_sha256=self.tail_pin,
                checkpoint_sha256=self.cp_pin,policy_oid=self.tsa_policy,
                output=str(self.tsa_request))
        self.tsa_response.unlink()
        with self.assertRaises(Exception):
            self.verify()

    def test_08_new_valid_tail_cannot_reuse_old_signed_tsa_response(self):
        self.prepare();self.issue_tsa()
        draft=self.fix.private/'ec273-next-draft.json'
        stage=self.fix.private/'ec273-next-stage.json'
        final=self.fix.private/'ec273-next-complete.json'
        pin=self.sign_seal(sequence=3,draft=draft,first=stage,complete=final,
            start=self.issued,expiry=self.issued+240,
            previous=self.next_receipt,previous_pin=self.next_receipt_pin)
        next_chain=self.fix.private/'ec273-next-chain.json'
        created=roll.append_segment(checkpoint=str(self.cp_file),
            checkpoint_sha256=self.cp_pin,segment_receipt=str(final),
            segment_receipt_sha256=pin,witness_public_keys=self.witness_keys,
            closure_sha256=self.closure_pin,
            recovered_root_public_sha256=self.new_root_pin,
            allowed_governance_epochs=self.epochs,output=str(next_chain),
            previous_segment=str(self.tail),previous_segment_sha256=self.tail_pin)
        with self.assertRaises(tsa.TimestampError):
            self.verify(segment=str(next_chain),segment_sha256=created['segment_sha256'])

    def test_07_der_rejects_noncanonical_randomness_and_broken_tstinfo(self):
        sha=hashlib.sha256(b'test').digest()
        raw=tsa._request(sha,self.tsa_policy,(1<<127)+12)
        self.assertEqual(tsa._parse_request(raw,self.tsa_policy,sha),(1<<127)+12)
        for modified in (raw+b'junk', raw.replace(b'\xff',b'\x00'),
                         raw.replace(sha,hashlib.sha256(b'other').digest())):
            with self.assertRaises(tsa.TimestampError):
                tsa._parse_request(modified,self.tsa_policy,sha)
        with self.assertRaises(tsa.TimestampError):
            tsa._tstinfo(b'\x30\x00',self.tsa_policy,sha,(1<<127)+12)


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(TimestampTests)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
