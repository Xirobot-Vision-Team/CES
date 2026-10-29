#!/usr/bin/env python3
"""EC277 separately deployable TLS escrow server enforcing EC276 approvals.

Only /v1/read and /v1/advance-approved are served. The EC274 unauthenticated
/v1/advance route is intentionally NOT exposed here; callers cannot opt out of
the 2-of-3 approval requirement by switching client CLI. Both sites verify
independently before touching their private EC274 CAS journals.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler
import json
import math
import ssl
import sys
from pathlib import Path
import time

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from offline_anchor_host import checkpoint as cp
from source_provenance_host import provenance as prov
from emergency_recovery_host import recovery as rec
from remote_escrow_host import escrow as esc
from remote_escrow_host.daemon import BoundedTLSServer
from approval_enforced_escrow.policy import TrustPolicy,PolicyError

COMMIT_SCHEMA='ces.ec277.approved_remote_commit_receipt.v1'
COMMIT_DOMAIN=b'CES/EC277/server-approved-remote-cas/v1\x00'
COMMIT_FIELDS=frozenset({'schema','namespace','nonce','site_role',
    'approval_sha256','record_sha256','record_index','admitted_at_unix',
    'signed_head','signature_ed25519'})
MAX_RPC=16000
MAX_REPLY=16000


class AnchoredClock:
    """In-process observed non-decreasing clock. Not trusted across reboots."""

    def __init__(self):
        self.wall=time.time()
        self.monotonic=time.monotonic()
        self.highest=math.floor(self.wall)

    def now(self)->int:
        observed=max(time.time(),self.wall+(time.monotonic()-self.monotonic))
        self.highest=max(self.highest,math.ceil(observed))
        return self.highest


def sign_commit(*,ledger:esc.EscrowLedger, role:str, nonce:str,
                approval_sha256:str, intent:dict, admitted_at:int,
                signed_head:dict)->dict:
    core={'schema':COMMIT_SCHEMA,'namespace':ledger.namespace,'nonce':nonce,
        'site_role':role,'approval_sha256':approval_sha256,
        'record_sha256':intent['record_sha256'],
        'record_index':intent['record_index'],'admitted_at_unix':admitted_at,
        'signed_head':signed_head}
    signature=cp.Ed25519PrivateKey.from_private_bytes(ledger.secret).sign(
        COMMIT_DOMAIN+esc.canonical(core)).hex()
    return {**core,'signature_ed25519':signature}


class ApprovedHandler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    server_version='CES-ApprovedEscrow/1'
    sys_version=''

    def log_message(self, format, *args):
        # Never log untrusted approvals, private paths or signatures.
        pass

    def do_POST(self):
        headers=self.headers
        lengths=headers.get_all('Content-Length',[])
        content_types=headers.get_all('Content-Type',[])
        if (len(lengths)!=1 or len(content_types)!=1 or
                len(lengths[0])>5 or not lengths[0].isascii() or
                not lengths[0].isdecimal() or not 0<int(lengths[0])<=MAX_RPC or
                content_types[0]!='application/json' or
                headers.get('Transfer-Encoding') is not None or
                headers.get('Content-Encoding') is not None):
            self.send_error(413)
            return
        try:
            request=esc._parse(self.rfile.read(int(lengths[0])),
                MAX_RPC,'EC277_RPC_NOT_CANONICAL')
            if request.get('namespace')!=self.server.ledger.namespace:
                esc.deny('EC277_WRONG_NAMESPACE')
            nonce=request.get('nonce')
            if type(nonce) is not str or esc.NONCE.fullmatch(nonce) is None:
                esc.deny('EC277_NONCE_INVALID')
            if self.path=='/v1/read' and set(request)=={'namespace','nonce'}:
                reply=self.server.ledger.read(nonce)
            elif self.path=='/v1/advance-approved' and set(request)=={
                    'namespace','nonce','approval'}:
                # Neither an unsigned 'record' nor a client-supplied approval
                # status is accepted. Exact record is extracted ONLY from the
                # reverified two-person signed document.
                if len(esc.canonical(request['approval']))>10500:
                    esc.deny('EC277_APPROVAL_TOO_LARGE')
                admitted_at=self.server.clock.now()
                intent=self.server.policy.verify(request['approval'],now=admitted_at)
                record=intent['record']
                if self.server.ledger.namespace!=intent['namespace']:
                    esc.deny('EC277_APPROVAL_NAMESPACE_MISMATCH')
                # Even a valid authorization for a fork/old head cannot bypass
                # the underlying strict EC274 signed predecessor + CAS policy.
                head=self.server.ledger.advance(record,nonce)
                if head['head_sha256']!=intent['record_sha256'] or head['record']!=record:
                    esc.deny('EC277_DURABLE_CAS_HEAD_NOT_APPROVED_RECORD')
                reply=sign_commit(ledger=self.server.ledger,role=self.server.role,
                    nonce=nonce,approval_sha256=esc.sha(esc.canonical(request['approval'])),
                    intent=intent,admitted_at=admitted_at,signed_head=head)
            else:
                # Explicitly deny *including* the pre-EC277 /v1/advance API.
                esc.deny('EC277_SIGNED_APPROVAL_ENDPOINT_REQUIRED')
            data=esc.canonical(reply)
            if len(data)>MAX_REPLY:
                esc.deny('EC277_RPC_REPLY_OVERSIZE')
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (esc.EscrowError,rec.RecoveryError,prov.ProvenanceError,
                OSError,ValueError,TypeError,OverflowError):
            self.send_error(409)


def serve(*,bind:str, port:int, role:str, policy_path:str, policy_sha256:str,
          journal:str,escrow_secret:str,tls_cert:str,tls_key:str,
          bootstrap_minimum_sequence:int,bootstrap_minimum_epoch:int)->None:
    policy=TrustPolicy(policy_path,policy_sha256)
    policy.validate_server_files(role,port=port,journal=journal,
        escrow_secret=escrow_secret,tls_cert=tls_cert,tls_key=tls_key)
    policy.recheck()
    with esc.EscrowLedger(journal,namespace=policy.namespace,keys=policy.witness_keys,
        root=policy.root,closure=policy.closure,escrow_secret_path=escrow_secret,
        escrow_pin=policy.site(role).escrow_pin,
        minimum_bootstrap_sequence=bootstrap_minimum_sequence,
        minimum_bootstrap_epoch=bootstrap_minimum_epoch) as ledger:
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(tls_cert,tls_key)
        server=BoundedTLSServer((bind,port),ApprovedHandler,ctx)
        server.ledger=ledger
        server.policy=policy
        server.role=role
        server.clock=AnchoredClock()
        try:
            server.serve_forever(poll_interval=0.25)
        finally:
            server.server_close()


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description='EC277 opt-in 2-of-3 approval-enforcing escrow daemon')
    p.add_argument('--bind',required=True)
    p.add_argument('--port',type=int,required=True)
    p.add_argument('--role',choices=('primary','secondary'),required=True)
    p.add_argument('--policy',required=True)
    p.add_argument('--policy-sha256',required=True)
    p.add_argument('--journal',required=True)
    p.add_argument('--escrow-secret',required=True)
    p.add_argument('--tls-cert',required=True)
    p.add_argument('--tls-key',required=True)
    p.add_argument('--bootstrap-minimum-sequence',type=int,required=True)
    p.add_argument('--bootstrap-minimum-epoch',type=int,required=True)
    args=p.parse_args(argv)
    try:
        serve(bind=args.bind,port=args.port,role=args.role,
            policy_path=args.policy,policy_sha256=args.policy_sha256,
            journal=args.journal,escrow_secret=args.escrow_secret,
            tls_cert=args.tls_cert,tls_key=args.tls_key,
            bootstrap_minimum_sequence=args.bootstrap_minimum_sequence,
            bootstrap_minimum_epoch=args.bootstrap_minimum_epoch)
        return 0
    except (esc.EscrowError,rec.RecoveryError,prov.ProvenanceError,
            OSError,ValueError,TypeError) as exc:
        print(json.dumps({'status':'unavailable','exit_code':5,
            'reason_code':getattr(exc,'code','EC277_APPROVAL_ENFORCED_DAEMON_UNAVAILABLE')},
            sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())
