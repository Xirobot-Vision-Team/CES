#!/usr/bin/env python3
"""EC274 signed remote quorum/CAS/append-only/TLS behavior tests.

Real localhost TLS and Ed25519, synthetic CA/key custody and storage.
Not a physical independent escrow machine or immutable WORM acceptance.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from offline_anchor_host import checkpoint as cp
from source_provenance_host import provenance as prov
from remote_escrow_host import escrow as esc
from remote_escrow_host.daemon import Handler, BoundedTLSServer


def digest(text): return hashlib.sha256(text.encode('ascii')).hexdigest()


@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and
    os.geteuid()!=0 and cp.Ed25519PrivateKey is not None and
    Path('/usr/bin/openssl').is_file(),'nonroot OpenSSL + Ed25519 required')
class EscrowProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ces-ec274-')
        self.addCleanup(self.temp.cleanup)
        self.private=Path(self.temp.name)
        self.publics=[]
        self.secrets=[]
        for i in range(4):
            sk=self.private/f'key-{i}.raw';pk=self.private/f'pub-{i}.raw'
            cp.generate_offline_keypair(str(sk),str(pk))
            self.secrets.append(sk);self.publics.append(pk)
        self.witnesses=[(str(p),prov._digest(p.read_bytes())) for p in self.publics[:3]]
        self.witness_pins=sorted(pin for _,pin in self.witnesses)
        self.escrow_pin=prov._digest(self.publics[3].read_bytes())
        self.keys=esc.witness_keys(self.witnesses,self.escrow_pin)
        self.namespace='ces-project-alpha'
        self.root=digest('root-A');self.closure=digest('closure-A')
        self.journal=self.private/'remote-ledger.jsonl'
        self.ledger=None;self.http=None;self.thread=None
        self.addCleanup(self.stop_server)

    def new_ledger(self):
        return esc.EscrowLedger(str(self.journal),namespace=self.namespace,
            keys=self.keys,root=self.root,closure=self.closure,
            escrow_secret_path=str(self.secrets[3]),escrow_pin=self.escrow_pin,
            minimum_bootstrap_sequence=2,minimum_bootstrap_epoch=3)

    def subject(self, seq=2, previous=None):
        return {'namespace':self.namespace,
            'checkpoint_number':1 if seq<=3 else 2,
            'checkpoint_sha256':digest('checkpoint-1' if seq<=3 else 'checkpoint-2'),
            'segment_sha256':digest('segment-'+str(seq)),
            'freshness_sequence':seq,
            'latest_receipt_sha256':digest('receipt-'+str(seq)),
            'previous_receipt_sha256':digest('receipt-'+str(seq-1)) if previous is None
                                     else previous['proposal']['latest_receipt_sha256'],
            'governance_epoch':3,'governance_sha256':digest('governance-3'),
            'recovered_root_public_sha256':self.root,'closure_sha256':self.closure,
            'tsa_request_sha256':digest('tsq-'+str(seq)),
            'tsa_response_sha256':digest('tsr-'+str(seq)),
            'tsa_statement_sha256':digest('message-'+str(seq)),
            'tsa_gen_time_microseconds':int(time.time()*1_000_000)+seq,
            'witness_public_sha256':self.witness_pins}

    def signed(self, subject, previous=None):
        name=secrets.token_hex(4)
        proposal=self.private/f'proposal-{name}.json'
        res=esc.prepare_proposal(subject,previous,output=str(proposal))
        votes=[]
        for _,pin in sorted(self.witnesses,key=lambda x:x[1])[:2]:
            idx=self.witnesses.index(next(pair for pair in self.witnesses if pair[1]==pin))
            output=self.private/f'vote-{name}-{idx}.json'
            signed=esc.sign_proposal(str(proposal),res['proposal_sha256'],
                str(self.secrets[idx]),pin,str(output))
            votes.append((str(output),signed['vote_sha256']))
        assembled=self.private/f'record-{name}.json'
        result=esc.assemble(str(proposal),res['proposal_sha256'],votes,
            self.keys,self.namespace,self.root,self.closure,str(assembled))
        doc=esc._parse(assembled.read_bytes(),esc.MAX_RECORD,'TEST_RECORD_INVALID')
        self.assertEqual(esc.sha(assembled.read_bytes()),result['record_sha256'])
        return doc

    def issue_tls(self):
        self.ca=self.private/'remote-ca.pem'
        cakey=self.private/'remote-ca-key.pem'
        csr=self.private/'remote.csr'
        self.cert=self.private/'remote-leaf.pem'
        key=self.private/'remote-leaf-key.pem'
        ext=self.private/'remote-ext.cnf'
        self.ext_data='[v3_req]\nsubjectAltName=DNS:localhost\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
        ext.write_text(self.ext_data)
        for cmd in [
            ('req','-x509','-newkey','rsa:2048','-nodes','-days','1','-sha256',
             '-subj','/CN=EC274 Dev CA',
             '-addext','basicConstraints=critical,CA:TRUE',
             '-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(cakey),'-out',str(self.ca)),
            ('req','-newkey','rsa:2048','-nodes','-sha256',
             '-subj','/CN=localhost','-keyout',str(key),'-out',str(csr)),
            ('x509','-req','-sha256','-days','1','-in',str(csr),'-CA',str(self.ca),
             '-CAkey',str(cakey),'-CAcreateserial',
             '-extfile',str(ext),'-extensions','v3_req','-out',str(self.cert))]:
            result=subprocess.run(('/usr/bin/openssl',*cmd),capture_output=True,timeout=15)
            if result.returncode:
                raise AssertionError(result.stderr.decode('utf-8','replace')[:800])
        for p in (self.ca,self.cert,key): p.chmod(0o600)
        der=subprocess.run(['/usr/bin/openssl','x509','-in',str(self.cert),
                 '-outform','DER'],capture_output=True,check=True).stdout
        self.tls_pin=prov._digest(der)
        self.tls_key=key

    def start_server(self):
        self.issue_tls()
        self.ledger=self.new_ledger()
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert),str(self.tls_key))
        self.http=BoundedTLSServer(('127.0.0.1',0),Handler,context)
        self.http.ledger=self.ledger
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True)
        self.thread.start()
        self.client=esc.RemoteClient(host='localhost',port=self.http.server_port,
            namespace=self.namespace,ca_path=str(self.ca),
            ca_pin=prov._digest(self.ca.read_bytes()),leaf_pin=self.tls_pin,
            escrow_public_path=str(self.publics[3]),escrow_public_pin=self.escrow_pin,
            witness_keys_map=self.keys,root=self.root,closure=self.closure)

    def stop_server(self):
        if self.http is not None:
            self.http.shutdown();self.http.server_close();self.thread.join(timeout=5)
            self.http=None
        if self.ledger is not None:
            self.ledger.close();self.ledger=None

    def test_01_signed_tls_nonce_cas_and_verified_remote_head(self):
        first=self.signed(self.subject())
        self.start_server()
        record,head=self.client.read()
        self.assertIsNone(record);self.assertEqual(head,esc.ZERO)
        signed,pin=self.client.advance(first)
        self.assertEqual(signed,first)
        self.assertEqual(pin,esc.sha(esc.canonical(first)))
        report=self.client.verify_current({k:v for k,v in first['proposal'].items()
            if k not in ('schema','nonce','record_index','previous_record_sha256')},
            expected_head=pin,minimum_index=1)
        self.assertTrue(report['escrow_nonce_bound_signed_remote_reply_verified'])
        self.assertFalse(report['physical_remote_worm_or_hardware_monotonic_verified'])
        second=self.signed(self.subject(seq=3,previous=first),previous=first)
        self.assertEqual(self.client.advance(second)[0],second)
        with self.assertRaises(esc.EscrowError):
            self.client.advance(first)  # stale duplicate/cas replay
        with self.assertRaises(esc.EscrowError):
            self.client.verify_current(self.subject(),expected_head=pin,minimum_index=1)

    def test_02_exact_sequence_predecessor_checkpoint_and_epoch_forks_denied(self):
        first=self.signed(self.subject())
        with self.new_ledger() as ledger:
            ledger.advance(first,secrets.token_hex(16))
            second=self.signed(self.subject(seq=3,previous=first),previous=first)
            ledger.advance(second,secrets.token_hex(16))
            for name,changes in [
                ('sequence_skip',{'freshness_sequence':5}),
                ('receipt_fork',{'previous_receipt_sha256':digest('wrong')}),
                ('checkpoint_relabel',{'checkpoint_number':1,'checkpoint_sha256':digest('fork')}),
                ('checkpoint_skip',{'checkpoint_number':3}),
                ('epoch_rollback',{'governance_epoch':2}),
                ('same_epoch_fork',{'governance_sha256':digest('fork')}),
                ('time_rollback',{'tsa_gen_time_microseconds':1}),
                ('tsa_replay',{'tsa_response_sha256':second['proposal']['tsa_response_sha256']}),
            ]:
                candidate={**self.subject(seq=4,previous=second),**changes}
                signed=self.signed(candidate,previous=second)
                with self.subTest(name=name),self.assertRaises(esc.EscrowError):
                    esc._record(signed,namespace=self.namespace,keys=self.keys,
                        root=self.root,closure=self.closure,previous=second)

    def test_03_journal_replay_restart_and_torn_or_removed_byte_rejection(self):
        first=self.signed(self.subject())
        with self.new_ledger() as ledger:
            ledger.advance(first,secrets.token_hex(16))
            self.assertEqual(ledger.count,1)
        with self.new_ledger() as ledger:
            self.assertEqual(ledger.current,first)
            second=self.signed(self.subject(seq=3,previous=first),previous=first)
            ledger.advance(second,secrets.token_hex(16))
            self.assertEqual(ledger.count,2)
        raw=self.journal.read_bytes()
        self.journal.write_bytes(raw[:-1])
        with self.assertRaises(esc.EscrowError): self.new_ledger()
        self.journal.write_bytes(raw)
        self.journal.write_bytes(raw[:-8]+b'0000000\n')
        with self.assertRaises(esc.EscrowError): self.new_ledger()

    def test_04_quorum_wrong_signer_duplicate_and_signature_tamper(self):
        first=self.signed(self.subject())
        altered=dict(first);altered['approvals']=first['approvals'][:1]
        with self.new_ledger() as ledger:
            for invalid in (altered,):
                with self.assertRaises(esc.EscrowError):
                    esc._record(invalid,namespace=self.namespace,keys=self.keys,
                       root=self.root,closure=self.closure,previous=None)
            duplicate={'schema':esc.RECORD_SCHEMA,'proposal':first['proposal'],
                       'approvals':[first['approvals'][0]]*2}
            with self.assertRaises(esc.EscrowError):
                esc._record(duplicate,namespace=self.namespace,keys=self.keys,
                    root=self.root,closure=self.closure,previous=None)
            forged={'schema':esc.RECORD_SCHEMA,'proposal':first['proposal'],
                    'approvals':[dict(v) for v in first['approvals']]}
            forged['approvals'][1]['signature_ed25519']='0'*128
            with self.assertRaises(esc.EscrowError):
                esc._record(forged,namespace=self.namespace,keys=self.keys,
                    root=self.root,closure=self.closure,previous=None)

    def test_05_tls_pin_and_signature_reply_are_not_optional(self):
        first=self.signed(self.subject())
        self.start_server()
        self.client.advance(first)
        self.client.leaf_pin='0'*64
        with self.assertRaises(esc.EscrowError): self.client.read()
        self.client.leaf_pin=self.tls_pin
        self.client.escrow_pin='0'*64
        with self.assertRaises(esc.EscrowError): self.client.read()
        self.client.escrow_pin=self.escrow_pin
        report=self.client.read()
        self.assertEqual(report[0],first)
        # A valid signature for another challenge cannot be reused.
        signed=esc._sign_reply(self.secrets[3].read_bytes(),namespace=self.namespace,
            nonce=secrets.token_hex(16),record=first,escrow_pub=self.escrow_pin)
        with self.assertRaises(esc.EscrowError):
            esc._verify_reply(signed,namespace=self.namespace,nonce='f'*32,
                escrow_key=self.publics[3].read_bytes(),escrow_pin=self.escrow_pin,
                witness_keys_map=self.keys,root=self.root,closure=self.closure)

    def test_06_server_cannot_run_concurrently_and_client_fails_closed_offline(self):
        self.start_server()
        with self.assertRaises((OSError,esc.EscrowError)):
            with self.new_ledger(): pass
        self.stop_server()
        with self.assertRaises(esc.EscrowError): self.client.read()

    def test_07_refuse_different_authority_namespace_and_floor(self):
        first=self.signed(self.subject())
        self.start_server();self.client.advance(first)
        with self.assertRaises(esc.EscrowError):
            self.client.read(minimum_index=2)
        self.client.namespace='wrong-tenant'
        with self.assertRaises(esc.EscrowError):
            self.client.read()
        self.client.namespace=self.namespace
        self.client.root=digest('different-root')
        with self.assertRaises(esc.EscrowError): self.client.read()


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(EscrowProtocolTests)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
