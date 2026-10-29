#!/usr/bin/env python3
"""EC275 integration: actual two TLS endpoints, CA chains, Ed25519 and journals.

Two localhost services are *synthetic*, not independently administered machines
or verified WORM media. This exercises the real EC274 daemon wire protocol.
"""
from __future__ import annotations

import contextlib
import io
import json

import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from offline_anchor_host import checkpoint as cp
from source_provenance_host import provenance as prov
from remote_escrow_host import escrow as esc
from remote_escrow_host.daemon import BoundedTLSServer, Handler
from remote_escrow_host.test_escrow import EscrowProtocolTests
from dual_escrow_host.quorum import DualEscrow, DualEscrowError
from dual_escrow_host import operator as ops


class SecondaryEscrowSite:
    """Independent local signer/CA/TLS socket/private journal for integration."""

    def __init__(self, directory:Path, *, namespace:str,keys:dict,
                 root:str,closure:str,bootstrap_sequence:int,bootstrap_epoch:int):
        self.dir=directory
        self.dir.mkdir(mode=0o700)
        self.sec=self.dir/'secondary-signing.raw'
        self.pub=self.dir/'secondary-public.raw'
        cp.generate_offline_keypair(str(self.sec),str(self.pub))
        self.signer_pin=esc.sha(self.pub.read_bytes())
        self.namespace=namespace
        self.keys=keys
        self.root=root
        self.closure=closure
        self.bootstrap_sequence=bootstrap_sequence
        self.bootstrap_epoch=bootstrap_epoch
        self.http=None
        self.ledger=None
        self.thread=None
        self._certificates()

    def _certificates(self):
        self.ca=self.dir/'secondary-ca.pem'
        ca_key=self.dir/'secondary-ca-key.pem'
        csr=self.dir/'secondary.csr'
        self.cert=self.dir/'secondary-leaf.pem'
        self.tls_key=self.dir/'secondary-leaf-key.pem'
        ext=self.dir/'secondary-ext.cnf'
        ext.write_text('[v3_req]\nsubjectAltName=DNS:localhost\n'
            'keyUsage=critical,digitalSignature,keyEncipherment\n'
            'extendedKeyUsage=serverAuth\n')
        commands=[
            ('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-sha256',
             '-subj','/CN=EC275 Secondary CA',
             '-addext','basicConstraints=critical,CA:TRUE',
             '-addext','keyUsage=critical,keyCertSign,cRLSign',
             '-keyout',str(ca_key),'-out',str(self.ca)),
            ('req','-newkey','rsa:2048','-nodes','-sha256','-subj','/CN=localhost',
             '-keyout',str(self.tls_key),'-out',str(csr)),
            ('x509','-req','-sha256','-days','1','-in',str(csr),'-CA',str(self.ca),
             '-CAkey',str(ca_key),'-CAcreateserial',
             '-extfile',str(ext),'-extensions','v3_req','-out',str(self.cert)),
        ]
        for args in commands:
            result=subprocess.run(('/usr/bin/openssl',*args),capture_output=True,timeout=20)
            if result.returncode:
                raise AssertionError(result.stderr.decode('utf8','replace')[:400])
        for p in (self.ca,self.cert,self.tls_key):
            p.chmod(0o600)
        der=subprocess.run(('/usr/bin/openssl','x509','-in',str(self.cert),'-outform','DER'),
                           capture_output=True,check=True,timeout=10).stdout
        self.ca_pin=prov._digest(self.ca.read_bytes())
        self.leaf_pin=prov._digest(der)

    def start(self):
        self.ledger=esc.EscrowLedger(str(self.dir/'secondary-journal.jsonl'),
            namespace=self.namespace,keys=self.keys,root=self.root,
            closure=self.closure,escrow_secret_path=str(self.sec),
            escrow_pin=self.signer_pin,
            minimum_bootstrap_sequence=self.bootstrap_sequence,
            minimum_bootstrap_epoch=self.bootstrap_epoch)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert),str(self.tls_key))
        self.http=BoundedTLSServer(('127.0.0.1',0),Handler,context)
        self.http.ledger=self.ledger
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True)
        self.thread.start()
        return self

    def client(self):
        return esc.RemoteClient(host='localhost',port=self.http.server_port,
            namespace=self.namespace,ca_path=str(self.ca),ca_pin=self.ca_pin,
            leaf_pin=self.leaf_pin,escrow_public_path=str(self.pub),
            escrow_public_pin=self.signer_pin,witness_keys_map=self.keys,
            root=self.root,closure=self.closure)

    def stop(self):
        if self.http is not None:
            self.http.shutdown()
            self.http.server_close()
            self.thread.join(timeout=4)
            self.http=None
        if self.ledger is not None:
            self.ledger.close()
            self.ledger=None


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and
    os.geteuid()!=0 and cp.Ed25519PrivateKey is not None and
    Path('/usr/bin/openssl').exists(),'nonroot OpenSSL/Ed25519 required')
class DualEscrowTests(unittest.TestCase):
    def setUp(self):
        t=EscrowProtocolTests('test_04_quorum_wrong_signer_duplicate_and_signature_tamper')
        t.setUp()
        self.t=t
        self.addCleanup(t.temp.cleanup)
        self.addCleanup(t.stop_server)
        t.start_server()
        self.site=SecondaryEscrowSite(t.private/'second-site',
            namespace=t.namespace,keys=t.keys,root=t.root,closure=t.closure,
            bootstrap_sequence=2,bootstrap_epoch=3).start()
        self.addCleanup(self.site.stop)
        self.dual=DualEscrow(t.client,self.site.client())

    @staticmethod
    def subject(record):
        return {k:v for k,v in record['proposal'].items()
                if k not in ('schema','nonce','record_index','previous_record_sha256')}

    def test_01_genesis_two_site_advance_readback_and_noop(self):
        first=self.t.signed(self.t.subject())
        pin=esc.sha(esc.canonical(first))
        state=self.dual.inspect_advance(first,record_sha256=pin,previous_sha256=esc.ZERO)
        self.assertEqual((state['primary'],state['secondary']),('pending','pending'))
        committed=self.dual.advance(first,record_sha256=pin,previous_sha256=esc.ZERO)
        self.assertTrue(committed['both_independently_signed_nonce_readbacks_verified'])
        self.assertFalse(committed['distributed_atomic_commit_claimed'])
        self.assertEqual(self.dual.read_pair(minimum_index=1),(first,pin))
        report=self.dual.verify_current(self.subject(first),expected_head=pin,minimum_index=1)
        self.assertTrue(report['ec275_both_remote_heads_equal_operator_pin'])
        replay=self.dual.advance(first,record_sha256=pin,previous_sha256=esc.ZERO)
        self.assertEqual(replay['record_sha256'],pin)
        second=self.t.signed(self.t.subject(seq=3,previous=first),previous=first)
        second_pin=esc.sha(esc.canonical(second))
        self.assertEqual(self.dual.advance(second,record_sha256=second_pin,
                          previous_sha256=pin)['record_index'],2)
        with self.assertRaises(esc.EscrowError):
            self.dual.verify_current(self.subject(first),expected_head=pin,minimum_index=1)

    def test_02_partial_commit_resumes_exact_target_without_rebasing(self):
        first=self.t.signed(self.t.subject())
        pin=esc.sha(esc.canonical(first))
        self.assertEqual(self.t.client.advance(first)[1],pin)
        pending=self.dual.inspect_advance(first,record_sha256=pin,previous_sha256=esc.ZERO)
        self.assertEqual((pending['primary'],pending['secondary']),('advanced','pending'))
        result=self.dual.advance(first,record_sha256=pin,previous_sha256=esc.ZERO)
        self.assertEqual(result['record_sha256'],pin)
        second=self.t.signed(self.t.subject(seq=3,previous=first),previous=first)
        second_pin=esc.sha(esc.canonical(second))
        self.assertEqual(self.site.client().advance(second)[1],second_pin)
        pending=self.dual.inspect_advance(second,record_sha256=second_pin,
                                          previous_sha256=pin)
        self.assertEqual((pending['primary'],pending['secondary']),('pending','advanced'))
        self.assertEqual(self.dual.advance(second,record_sha256=second_pin,
                         previous_sha256=pin)['record_index'],2)

    def test_03_forked_heads_rejected_before_mutating_either(self):
        a=self.t.signed(self.t.subject())
        b=self.t.signed(self.t.subject())
        self.assertNotEqual(esc.sha(esc.canonical(a)),esc.sha(esc.canonical(b)))
        self.t.client.advance(a)
        self.site.client().advance(b)
        with self.assertRaises(DualEscrowError): self.dual.read_pair(minimum_index=1)
        with self.assertRaises(DualEscrowError):
            self.dual.advance(a,record_sha256=esc.sha(esc.canonical(a)),
                              previous_sha256=esc.ZERO)
        self.assertEqual(self.t.client.read()[0],a)
        self.assertEqual(self.site.client().read()[0],b)

    def test_04_identity_pin_and_invalid_record_denied(self):
        first=self.t.signed(self.t.subject())
        pin=esc.sha(esc.canonical(first))
        with self.assertRaises(DualEscrowError):
            self.dual.advance(first,record_sha256=pin,previous_sha256='f'*64)
        with self.assertRaises(DualEscrowError):
            DualEscrow(self.t.client,self.t.client)
        clone=self.site.client();clone.escrow_pin=self.t.client.escrow_pin
        with self.assertRaises(DualEscrowError):
            DualEscrow(self.t.client,clone)
        clone=self.site.client();clone.ca_pin=self.t.client.ca_pin
        with self.assertRaises(DualEscrowError):
            DualEscrow(self.t.client,clone)
        corrupted={'schema':first['schema'],'proposal':first['proposal'],
                   'approvals':[dict(x) for x in first['approvals']]}
        corrupted['approvals'][1]['signature_ed25519']='f'*128
        with self.assertRaises(esc.EscrowError):
            self.dual.advance(corrupted,record_sha256=esc.sha(esc.canonical(corrupted)),
                              previous_sha256=esc.ZERO)

    def test_05_one_service_offline_fails_closed(self):
        first=self.t.signed(self.t.subject())
        pin=esc.sha(esc.canonical(first))
        self.dual.advance(first,record_sha256=pin,previous_sha256=esc.ZERO)
        self.site.stop()
        with self.assertRaises(esc.EscrowError): self.dual.read_pair(minimum_index=1)
        with self.assertRaises(esc.EscrowError):
            self.dual.verify_current(self.subject(first),expected_head=pin,minimum_index=1)
        with self.assertRaises(esc.EscrowError):
            self.dual.advance(first,record_sha256=pin,previous_sha256=esc.ZERO)

    def test_06_second_site_outage_after_first_cas_never_claims_success(self):
        first=self.t.signed(self.t.subject())
        pin=esc.sha(esc.canonical(first))
        with mock.patch.object(self.dual.secondary,'advance',
                               side_effect=OSError('offline after first commit')):
            with self.assertRaisesRegex(DualEscrowError,
                    'EC275_PARTIAL_OR_UNCERTAIN_ADVANCE_REREAD_AND_RESUME'):
                self.dual.advance(first,record_sha256=pin,
                                  previous_sha256=esc.ZERO)
        self.assertEqual(self.t.client.read()[1],pin)
        self.assertEqual(self.site.client().read()[1],esc.ZERO)
        resumed=self.dual.advance(first,record_sha256=pin,
                                   previous_sha256=esc.ZERO)
        self.assertEqual(resumed['record_sha256'],pin)
        self.assertEqual(self.dual.read_pair(minimum_index=1)[1],pin)

    def test_07_operator_cli_writes_and_inspects_both_live_heads(self):
        first=self.t.signed(self.t.subject())
        pin=esc.sha(esc.canonical(first))
        file=self.t.private/'ec275-operator-record.json'
        prov._new(str(file),esc.canonical(first))
        common=['--escrow-host','localhost',
           '--escrow-port',str(self.t.http.server_port),
           '--escrow-namespace',self.t.namespace,
           '--escrow-tls-ca',str(self.t.ca),
           '--escrow-tls-ca-sha256',esc.sha(self.t.ca.read_bytes()),
           '--escrow-tls-leaf-sha256',self.t.tls_pin,
           '--escrow-public',str(self.t.publics[3]),
           '--escrow-public-sha256',self.t.escrow_pin,
           '--secondary-escrow-host','localhost',
           '--secondary-escrow-port',str(self.site.http.server_port),
           '--secondary-escrow-tls-ca',str(self.site.ca),
           '--secondary-escrow-tls-ca-sha256',self.site.ca_pin,
           '--secondary-escrow-tls-leaf-sha256',self.site.leaf_pin,
           '--secondary-escrow-public',str(self.site.pub),
           '--secondary-escrow-public-sha256',self.site.signer_pin,
           '--root-sha256',self.t.root,'--closure-sha256',self.t.closure]
        for path,witness_pin in self.t.witnesses:
            common.extend(['--freshness-witness-public',path,
                           '--freshness-witness-public-sha256',witness_pin])
        def command(action,opts):
            buffer=io.StringIO()
            with contextlib.redirect_stdout(buffer):
                status=ops.main([action,*common,*opts])
            return status,json.loads(buffer.getvalue())
        signed=['--record',str(file),'--record-sha256',pin,
                '--expected-previous-sha256',esc.ZERO]
        code,result=command('inspect-advance',signed)
        self.assertEqual(code,2)
        self.assertEqual((result['primary'],result['secondary']),('pending','pending'))
        code,result=command('advance-dual',signed)
        self.assertEqual(code,2)
        self.assertEqual(result['record_sha256'],pin)
        code,result=command('inspect-dual',
            ['--expected-head-sha256',pin,'--minimum-index','1'])
        self.assertEqual(code,2)
        self.assertTrue(result['both_nonce_bound_signatures_verified'])
        code,result=command('inspect-dual',
            ['--expected-head-sha256','f'*64,'--minimum-index','1'])
        self.assertEqual(code,5)
        self.assertEqual(result['status'],'unavailable')


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(DualEscrowTests)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
