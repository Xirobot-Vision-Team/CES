#!/usr/bin/env python3
"""EC274 independent TLS escrow authority; deploy on a different governed host.

This daemon never receives private witness keys. Its own Ed25519 response key
is distinct from the 3 independently held witness signing keys. Remote
filesystem rollback/WORM resistance requires a real separate storage owner.
"""
from __future__ import annotations

import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import ssl
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from ec274_remote_escrow_host import escrow as esc
from ec266_source_provenance_host import provenance as prov
from ec269_emergency_recovery_host import recovery as rec


class BoundedTLSServer(HTTPServer):
    """Bound TLS handshakes and HTTP reads to avoid a trivial idle-client stall.

    Keep the ledger single-threaded: its checked CAS and private append fd must
    not be concurrently modified inside this server process.
    """

    def __init__(self, address: tuple[str,int], handler, context: ssl.SSLContext):
        self.tls_context=context
        super().__init__(address,handler)

    def get_request(self):
        # The TCP accept is plain; set a timeout *before* the TLS handshake.
        # Wrapping the listening socket instead blocks inside SSLSocket.accept()
        # before code can set a per-connection timeout.
        conn,peer=super().get_request()
        try:
            conn.settimeout(4)
            wrapped=self.tls_context.wrap_socket(conn,server_side=True)
            return wrapped,peer
        except BaseException:
            conn.close()
            raise


class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    server_version='CES-Escrow/1'
    sys_version=''

    def log_message(self, format, *args):
        # Protocol errors never print request bytes, private paths or tokens.
        pass

    def do_POST(self):
        length=self.headers.get('Content-Length')
        if (type(length) is not str or len(length)>5 or not length.isascii() or
                not length.isdecimal() or
                not 0<int(length)<=esc.MAX_RPC or
                self.headers.get('Content-Type')!='application/json'):
            self.send_error(413)
            return
        try:
            request=esc._parse(self.rfile.read(int(length)),esc.MAX_RPC,
                               'EC274_RPC_REQUEST_NOT_CANONICAL')
            if request.get('namespace')!=self.server.ledger.namespace:
                esc.deny('EC274_REMOTE_NAMESPACE_MISMATCH')
            nonce=request.get('nonce')
            if type(nonce) is not str or esc.NONCE.fullmatch(nonce) is None:
                esc.deny('EC274_REMOTE_CHALLENGE_INVALID')
            if self.path=='/v1/read' and set(request)=={'namespace','nonce'}:
                reply=self.server.ledger.read(nonce)
            elif self.path=='/v1/advance' and set(request)=={'namespace','nonce','record'}:
                reply=self.server.ledger.advance(request['record'],nonce)
            else:
                esc.deny('EC274_RPC_ACTION_INVALID')
            data=esc.canonical(reply)
            if len(data)>esc.MAX_REPLY:
                esc.deny('EC274_REMOTE_REPLY_TOO_LARGE')
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (esc.EscrowError,ValueError,TypeError,OSError):
            # Deny consistently; never echo untrusted data or denial internals.
            self.send_error(409)


def serve(*, bind: str, port: int, namespace: str, journal: str,
          escrow_secret: str, escrow_public_sha256: str,
          witnesses: list[tuple[str,str]],
          root_sha256: str, closure_sha256: str,
          tls_cert: str, tls_key: str,
          bootstrap_minimum_sequence: int,
          bootstrap_minimum_epoch: int) -> None:
    esc.validate_namespace(namespace)
    esc.integer(port,1,65535,'EC274_PORT_INVALID')
    keys=esc.witness_keys(witnesses,escrow_public_sha256)
    for candidate in (tls_cert,tls_key,journal,escrow_secret):
        prov._path(candidate)
    if len({tls_cert,tls_key,journal,escrow_secret,*[p for p,_ in witnesses]})!=4+len(witnesses):
        esc.deny('EC274_SERVER_CREDENTIAL_OR_LEDGER_PATH_COLLISION')
    # TLS cert and private key must be confined by the same owner-private file
    # contract as witness public keys and the remote escrow signing key.
    prov._bytes(tls_cert,65536)
    prov._bytes(tls_key,65536)
    with esc.EscrowLedger(journal,namespace=namespace,keys=keys,
        root=root_sha256,closure=closure_sha256,
        escrow_secret_path=escrow_secret,escrow_pin=escrow_public_sha256,
        minimum_bootstrap_sequence=bootstrap_minimum_sequence,
        minimum_bootstrap_epoch=bootstrap_minimum_epoch) as ledger:
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(tls_cert,tls_key)
        http=BoundedTLSServer((bind,port),Handler,ctx)
        http.ledger=ledger
        try:
            http.serve_forever(poll_interval=0.25)
        finally:
            http.server_close()


def main(argv: list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description='EC274 independently operated private TLS escrow authority')
    parser.add_argument('--bind',required=True)
    parser.add_argument('--port',type=int,required=True)
    parser.add_argument('--namespace',required=True)
    parser.add_argument('--journal',required=True)
    parser.add_argument('--escrow-secret',required=True)
    parser.add_argument('--escrow-public-sha256',required=True)
    parser.add_argument('--witness-public',action='append',required=True)
    parser.add_argument('--witness-public-sha256',action='append',required=True)
    parser.add_argument('--root-sha256',required=True)
    parser.add_argument('--closure-sha256',required=True)
    parser.add_argument('--tls-cert',required=True)
    parser.add_argument('--tls-key',required=True)
    parser.add_argument('--bootstrap-minimum-sequence',type=int,required=True)
    parser.add_argument('--bootstrap-minimum-epoch',type=int,required=True)
    args=parser.parse_args(argv)
    try:
        if len(args.witness_public)!=len(args.witness_public_sha256):
            esc.deny('EC274_WITNESS_KEY_PIN_PAIR_REQUIRED')
        serve(bind=args.bind,port=args.port,namespace=args.namespace,
            journal=args.journal,escrow_secret=args.escrow_secret,
            escrow_public_sha256=args.escrow_public_sha256,
            witnesses=list(zip(args.witness_public,args.witness_public_sha256)),
            root_sha256=args.root_sha256,closure_sha256=args.closure_sha256,
            tls_cert=args.tls_cert,tls_key=args.tls_key,
            bootstrap_minimum_sequence=args.bootstrap_minimum_sequence,
            bootstrap_minimum_epoch=args.bootstrap_minimum_epoch)
        return 0
    except (esc.EscrowError,rec.RecoveryError,OSError,ValueError,TypeError):
        print(json.dumps({'status':'unavailable','exit_code':5,
            'reason_code':'EC274_REMOTE_ESCROW_DAEMON_UNAVAILABLE'},sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())
