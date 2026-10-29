#!/usr/bin/env python3
"""EC280 quality evidence/query offline approvals and verified Unix-socket client."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time

from ec279_finding_query_host import operator as old_op
from ec279_finding_query_host import protocol as io
from . import daemon
from . import protocol as p


def _secret_file(path: str, data: bytes) -> None:
    p.need(type(path) is str and os.path.isabs(path),
           'EC280_ABSOLUTE_KEYFILE_OUTPUT_REQUIRED')
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        parent = os.open(os.path.dirname(path),
                         os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError as exc:
        raise p.HostError('EC280_EXCLUSIVE_KEYFILE_CREATE_FAILED', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)


def keygen_signer(path: str) -> dict:
    # EC279 helper creates one raw private Ed25519 key with exclusive 0600 mode.
    result = old_op._keygen(path)
    return {'schema': 'ces.ec280.offline_keygen_result.v1',
            'public_hex': result['public_hex'],
            'private_key_file_created': True, 'private_key_material_returned': False}


def keygen_cursor(path: str) -> dict:
    key = secrets.token_bytes(32)
    _secret_file(path, key)
    return {'schema': 'ces.ec280.cursor_keygen_result.v1',
            'cursor_key_sha256': p.sha(key),
            'cursor_key_file_created': True, 'cursor_key_material_returned': False}


def vote(role: str, subject_path: str, key_path: str, out: str) -> dict:
    subject = p.validate_subject(p.read_doc(subject_path))
    key = io.private_from_file(key_path)
    doc = {'schema': p.VOTE_SCHEMA, 'role': role,
           'subject_sha256': p.sha(p.canonical(subject)),
           'signer_public_hex': p.public_hex(key),
           'signature_ed25519': p.sign(role, subject, key)}
    p.write_exclusive(out, doc)
    return {'status': 'offline_vote_written', 'role': role,
            'subject_sha256': doc['subject_sha256'],
            'private_key_returned': False}


def assemble(subject_file: str, evidence_vote_file: str,
             query_vote_file: str, evidence_pub: str,
             query_pub: str, out: str) -> dict:
    subject = p.validate_subject(p.read_doc(subject_file))
    p.need(evidence_pub != query_pub, 'EC280_DISTINCT_OFFLINE_ISSUERS_REQUIRED')
    roles = [('evidence', evidence_vote_file, evidence_pub),
             ('query', query_vote_file, query_pub)]
    votes = {}
    for role, path, pub in roles:
        entry = p.read_doc(path)
        p.need(set(entry) == {'schema', 'role', 'subject_sha256',
                              'signer_public_hex', 'signature_ed25519'} and
               entry.get('schema') == p.VOTE_SCHEMA and
               entry.get('role') == role and
               entry.get('subject_sha256') == p.sha(p.canonical(subject)) and
               entry.get('signer_public_hex') == pub,
               'EC280_OFFLINE_VOTE_SCOPE_MISMATCH', 'permission_denied')
        p.verify(role, subject, entry['signature_ed25519'], pub)
        votes[role] = entry['signature_ed25519']
    grant = {'schema': p.GRANT_SCHEMA, 'subject': subject,
             'evidence_signature_ed25519': votes['evidence'],
             'query_signature_ed25519': votes['query']}
    p.write_exclusive(out, grant)
    return {'status': 'offline_dual_signed_grant_written',
            'grant_sha256': p.sha(p.canonical(grant)),
            'host_admission': False, 'issuer_publics_distinct': True}


def request_query(*, socket_path: str, grant_path: str, policy_sha: str,
                  server_public_hex: str, cursor: str | None = None,
                  timeout: float = 12.0) -> tuple[int, dict]:
    p.need(type(socket_path) is str and os.path.isabs(socket_path) and
           len(socket_path) < 100, 'EC280_SOCKET_ABSOLUTE_PATH_REQUIRED')
    p.need(type(policy_sha) is str and io.HASH.fullmatch(policy_sha) is not None,
           'EC280_EXTERNAL_POLICY_PIN_REQUIRED')
    io.pub_from_hex(server_public_hex)
    grant = p.read_doc(grant_path)
    p.need(grant.get('schema') == p.GRANT_SCHEMA and
           type(grant.get('subject')) is dict,
           'EC280_GRANT_FILE_INVALID')
    subject = p.validate_subject(grant['subject'])
    p.need(subject['policy_sha256'] == policy_sha,
           'EC280_GRANT_CLIENT_POLICY_PIN_MISMATCH', 'permission_denied')
    if cursor is not None:
        p.need(type(cursor) is str and 0 < len(cursor) <= 2048,
               'EC280_CURSOR_LENGTH_INVALID')
    req = {'schema': p.REQUEST_SCHEMA, 'nonce': secrets.token_hex(16),
           'grant': grant, 'cursor': cursor}
    raw = p.canonical(req) + b'\n'
    p.need(len(raw) <= p.MAX_RPC, 'EC280_SOCKET_REQUEST_TOO_LARGE')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(socket_path)
            conn.sendall(raw)
            reply_buf = bytearray()
            while len(reply_buf) <= p.MAX_REPLY:
                chunk = conn.recv(min(16384, p.MAX_REPLY + 1 - len(reply_buf)))
                if not chunk:
                    break
                reply_buf.extend(chunk)
                if b'\n' in chunk:
                    break
    except (OSError, TimeoutError) as exc:
        raise p.HostError('EC280_INDEPENDENT_HOST_UNAVAILABLE', 'unavailable') from exc
    p.need(reply_buf.endswith(b'\n') and reply_buf.count(b'\n') == 1 and
           0 < len(reply_buf) <= p.MAX_REPLY,
           'EC280_SIGNED_REPLY_TRUNCATED_OR_OVERSIZE', 'unavailable')
    reply = io.parse(bytes(reply_buf[:-1]), p.MAX_REPLY)
    result = p.verify_reply(reply, req, server_public_hex=server_public_hex,
                            policy_sha=policy_sha, now=int(time.time()))
    return result['exit_code'], {
        'schema': p.RESULT_SCHEMA, 'verified_server_signature': True,
        'result': result, 'signed_reply': reply,
        'overall_business_effect_verified': False}


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description='EC280 independently signed fixed-batch QualityShow.Query host')
    sub = ap.add_subparsers(dest='action', required=True)
    a = sub.add_parser('keygen-offline', help='create one independent signer key')
    a.add_argument('--private-out', required=True)
    a = sub.add_parser('keygen-cursor', help='create server-private cursor HMAC key')
    a.add_argument('--private-out', required=True)
    a = sub.add_parser('prepare-offline', help='create unsigned exact query subject')
    a.add_argument('--query-file', required=True)
    a.add_argument('--uid', type=int, required=True)
    a.add_argument('--policy-sha256', required=True)
    a.add_argument('--evidence-sha256', required=True)
    a.add_argument('--ttl-seconds', type=int, required=True)
    a.add_argument('--out', required=True)
    for role in ('evidence', 'query'):
        a = sub.add_parser('sign-' + role + '-offline')
        a.add_argument('--subject-file', required=True)
        a.add_argument('--private-key-file', required=True)
        a.add_argument('--out', required=True)
    a = sub.add_parser('assemble-offline')
    a.add_argument('--subject-file', required=True)
    a.add_argument('--evidence-vote', required=True)
    a.add_argument('--query-vote', required=True)
    a.add_argument('--evidence-public-hex', required=True)
    a.add_argument('--query-public-hex', required=True)
    a.add_argument('--out', required=True)
    a = sub.add_parser('serve', help='separate OS-controlled read-only Unix host')
    a.add_argument('--socket', required=True)
    a.add_argument('--policy-file', required=True)
    a.add_argument('--policy-sha256', required=True)
    a.add_argument('--server-private-key', required=True)
    a = sub.add_parser('query', help='request an exact two-signed QualityShow projection')
    a.add_argument('--socket', required=True)
    a.add_argument('--grant-file', required=True)
    a.add_argument('--policy-sha256', required=True)
    a.add_argument('--server-public-hex', required=True)
    a.add_argument('--cursor')
    a.add_argument('--pretty', action='store_true')
    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.action == 'keygen-offline':
            doc = keygen_signer(args.private_out)
        elif args.action == 'keygen-cursor':
            doc = keygen_cursor(args.private_out)
        elif args.action == 'prepare-offline':
            q = p.validate_query(p.read_doc(args.query_file))
            s = p.make_subject(q, args.uid, args.policy_sha256,
                               args.evidence_sha256, args.ttl_seconds)
            p.write_exclusive(args.out, s)
            doc = {'status': 'unsigned_subject_written',
                   'subject_sha256': p.sha(p.canonical(s)),
                   'private_key_used': False}
        elif args.action in ('sign-evidence-offline', 'sign-query-offline'):
            doc = vote(args.action.split('-')[1], args.subject_file,
                       args.private_key_file, args.out)
        elif args.action == 'assemble-offline':
            doc = assemble(args.subject_file, args.evidence_vote, args.query_vote,
                           args.evidence_public_hex, args.query_public_hex, args.out)
        elif args.action == 'serve':
            with daemon.QualityServer(path=args.socket, policy_path=args.policy_file,
                                      policy_sha=args.policy_sha256,
                                      private_key_file=args.server_private_key) as host:
                host.serve_forever(poll_interval=0.25)
            return 0
        elif args.action == 'query':
            rc, doc = request_query(socket_path=args.socket,
                                    grant_path=args.grant_file,
                                    policy_sha=args.policy_sha256,
                                    server_public_hex=args.server_public_hex,
                                    cursor=args.cursor)
            print(json.dumps(doc, ensure_ascii=True, sort_keys=True,
                             indent=2 if args.pretty else None,
                             separators=None if args.pretty else (',', ':')))
            return rc
        else:
            raise AssertionError('unreachable command')
        print(p.canonical(doc).decode('ascii'))
        return 0
    except (p.HostError, io.HostError, OSError) as exc:
        code = exc.code if isinstance(exc, (p.HostError, io.HostError)) else (
            'EC280_HOST_OS_UNAVAILABLE')
        status = exc.status if isinstance(exc, (p.HostError, io.HostError)) else (
            'unavailable')
        doc = p.denial(code, status)
        print(p.canonical(doc).decode('ascii'))
        return doc['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
