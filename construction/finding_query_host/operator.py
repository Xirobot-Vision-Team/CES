#!/usr/bin/env python3
"""EC279 offline two-role read-grant workflow + online AF_UNIX query client.

A host never sees either offline issuer private key. A client never supplies
`authorize_store_read=True` or private store roots. No generic Router bypass.
"""
from __future__ import annotations

import argparse
import os
import secrets
import socket
import stat
import sys
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import daemon
from . import protocol as p


def _public(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


def _keygen(out: str) -> dict:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    p.require(os.path.isabs(out), 'EC279_KEYFILE_ABSOLUTE_OUTPUT_REQUIRED')
    fd = None
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as f:
            fd = None
            f.write(private)
            f.flush()
            os.fsync(f.fileno())
        parent = os.open(os.path.dirname(out), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError as exc:
        raise p.HostError('EC279_KEYFILE_EXCLUSIVE_CREATE_FAILED', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)
    return {'schema': 'ces.ec279.offline_keygen_result.v1',
            'public_hex': _public(key), 'private_key_file_created': True,
            'private_key_material_returned': False}


def _vote(role: str, subject_path: str, private_key: str, out: str) -> dict:
    s = p.validate_subject(p.read_doc(subject_path))
    key = p.private_from_file(private_key)
    vote = {'schema': p.VOTE_SCHEMA, 'role': role,
            'subject_sha256': p.sha(p.canonical(s)),
            'signer_public_hex': _public(key),
            'signature_ed25519': p.sign(role, s, key)}
    p.write_exclusive(out, vote)
    return {'status': 'offline_vote_written', 'role': role,
            'subject_sha256': vote['subject_sha256'], 'private_key_returned': False}


def _assemble(subject_path: str, store_vote: str, query_vote: str,
              store_pub: str, query_pub: str, out: str) -> dict:
    s = p.validate_subject(p.read_doc(subject_path))
    p.require(store_pub != query_pub, 'EC279_DISTINCT_OFFLINE_ROLES_REQUIRED')
    public = {'store': store_pub, 'query': query_pub}
    votes = {}
    for role, file in [('store', store_vote), ('query', query_vote)]:
        vote = p.read_doc(file)
        p.require(set(vote) == {'schema', 'role', 'subject_sha256',
                                'signer_public_hex', 'signature_ed25519'} and
                  vote['schema'] == p.VOTE_SCHEMA and vote['role'] == role and
                  vote['subject_sha256'] == p.sha(p.canonical(s)) and
                  vote['signer_public_hex'] == public[role],
                  'EC279_OFFLINE_VOTE_MISMATCH', 'permission_denied')
        p.verify(role, s, vote['signature_ed25519'], public[role])
        votes[role] = vote['signature_ed25519']
    grant = {'schema': p.GRANT_SCHEMA, 'subject': s,
             'store_signature_ed25519': votes['store'],
             'query_signature_ed25519': votes['query']}
    p.write_exclusive(out, grant)
    return {'status': 'offline_dual_signed_grant_written',
            'grant_sha256': p.sha(p.canonical(grant)),
            'issuer_publics_distinct': True, 'host_admission': False}


def request_query(*, socket_path: str, grant_path: str, policy_sha: str,
                  server_public_hex: str, cursor: str | None = None,
                  timeout: float = 12.0) -> tuple[int, dict]:
    p.require(type(socket_path) is str and os.path.isabs(socket_path) and
              len(socket_path) < 100, 'EC279_SOCKET_ABSOLUTE_PATH_REQUIRED')
    p.require(type(policy_sha) is str and p.HASH.fullmatch(policy_sha) is not None,
              'EC279_CLIENT_TRUSTED_POLICY_SHA_REQUIRED')
    p.pub_from_hex(server_public_hex)
    grant = p.read_doc(grant_path)
    # Local syntactic checks avoid ever sending obviously malformed grants.
    p.require(grant.get('schema') == p.GRANT_SCHEMA and
              type(grant.get('subject')) is dict,
              'EC279_QUERY_GRANT_FILE_INVALID')
    p.validate_subject(grant['subject'])
    if cursor is not None:
        p.require(type(cursor) is str and 0 < len(cursor) <= 4096,
                  'EC279_QUERY_CURSOR_INVALID')
    req = {'schema': p.REQUEST_SCHEMA, 'nonce': secrets.token_hex(16),
           'grant': grant, 'cursor': cursor}
    raw = p.canonical(req) + b'\n'
    p.require(len(raw) <= p.MAX_RPC, 'EC279_QUERY_REQUEST_TOO_LARGE')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(socket_path)
            conn.sendall(raw)
            chunks = bytearray()
            while len(chunks) <= p.MAX_REPLY:
                data = conn.recv(min(16384, p.MAX_REPLY + 1 - len(chunks)))
                if not data:
                    break
                chunks.extend(data)
                if b'\n' in data:
                    break
    except (OSError, TimeoutError) as exc:
        raise p.HostError('EC279_INDEPENDENT_HOST_UNAVAILABLE', 'unavailable') from exc
    p.require(chunks.endswith(b'\n') and chunks.count(b'\n') == 1 and
              0 < len(chunks) <= p.MAX_REPLY,
              'EC279_SIGNED_HOST_RESPONSE_TRUNCATED_OR_OVERSIZE', 'unavailable')
    reply = p.parse(bytes(chunks[:-1]), p.MAX_REPLY)
    result = p.verify_reply(reply, req, public_hex=server_public_hex,
                            policy_sha=policy_sha, now=int(time.time()))
    # Keep the complete signed server evidence and refusal, not just a claim.
    return result['exit_code'], {'schema': 'ces.ec279.verified_host_result.v1',
                                 'verified_server_signature': True,
                                 'result': result, 'signed_reply': reply,
                                 'overall_business_effect_verified': False}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='EC279 independently authorized FindingShow read host')
    sub = parser.add_subparsers(dest='action', required=True)
    a = sub.add_parser('keygen-offline', help='separate offline store/query or host signing key')
    a.add_argument('--private-out', required=True)
    a = sub.add_parser('prepare-offline', help='prepare exact immutable query subject; does not authorize it')
    a.add_argument('--query-file', required=True)
    a.add_argument('--uid', type=int, required=True)
    a.add_argument('--store-pin', required=True)
    a.add_argument('--ttl-seconds', type=int, required=True)
    a.add_argument('--out', required=True)
    for role in ('store', 'query'):
        a = sub.add_parser(f'sign-{role}-offline', help=f'sign with offline {role} issuer only')
        a.add_argument('--subject-file', required=True)
        a.add_argument('--private-key-file', required=True)
        a.add_argument('--out', required=True)
    a = sub.add_parser('assemble-offline', help='verify both issuer votes then create read ticket')
    a.add_argument('--subject-file', required=True)
    a.add_argument('--store-vote', required=True)
    a.add_argument('--query-vote', required=True)
    a.add_argument('--store-public-hex', required=True)
    a.add_argument('--query-public-hex', required=True)
    a.add_argument('--out', required=True)
    a = sub.add_parser('serve', help='run a separate OS-administered read-only AF_UNIX host')
    a.add_argument('--policy-file', required=True)
    a.add_argument('--policy-sha256', required=True)
    a.add_argument('--socket', required=True)
    a.add_argument('--server-private-key', required=True)
    a = sub.add_parser('query', help='query the dedicated host with an already dual-signed ticket')
    a.add_argument('--socket', required=True)
    a.add_argument('--grant-file', required=True)
    a.add_argument('--policy-sha256', required=True)
    a.add_argument('--server-public-hex', required=True)
    a.add_argument('--cursor', default=None)
    a.add_argument('--pretty', action='store_true')
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.action == 'keygen-offline':
            payload = _keygen(args.private_out)
        elif args.action == 'prepare-offline':
            q = p.validate_query(p.read_doc(args.query_file))
            s = p.new_subject(q=q, uid=args.uid, store_pin=args.store_pin,
                              ttl=args.ttl_seconds)
            p.write_exclusive(args.out, s)
            payload = {'status': 'unsigned_subject_written',
                       'subject_sha256': p.sha(p.canonical(s)),
                       'private_key_used': False}
        elif args.action.startswith('sign-'):
            payload = _vote(args.action.split('-')[1], args.subject_file,
                            args.private_key_file, args.out)
        elif args.action == 'assemble-offline':
            payload = _assemble(args.subject_file, args.store_vote, args.query_vote,
                                args.store_public_hex, args.query_public_hex, args.out)
        elif args.action == 'serve':
            with daemon.FindingServer(path=args.socket, policy_path=args.policy_file,
                                     policy_sha=args.policy_sha256,
                                     private_key_file=args.server_private_key) as host:
                host.serve_forever(poll_interval=0.25)
            return 0
        elif args.action == 'query':
            rc, payload = request_query(socket_path=args.socket, grant_path=args.grant_file,
                                        policy_sha=args.policy_sha256,
                                        server_public_hex=args.server_public_hex,
                                        cursor=args.cursor)
            print(p.canonical(payload).decode('ascii') if not args.pretty else
                  __import__('json').dumps(payload, indent=2, sort_keys=True, ensure_ascii=True))
            return rc
        else:
            raise AssertionError('unknown command')
        print(p.canonical(payload).decode('ascii'))
        return 0
    except (p.HostError, OSError) as exc:
        code = exc.code if isinstance(exc, p.HostError) else 'EC279_HOST_OS_FAILURE'
        status = exc.status if isinstance(exc, p.HostError) else 'unavailable'
        payload = p.denial(code, status)
        print(p.canonical(payload).decode('ascii'))
        return payload['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
