#!/usr/bin/env python3
"""EC281 offline issuer, pinned host and signed plan-only preflight client."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time

from finding_query_host import operator as old_op
from finding_query_host import protocol as io
import quality_detect as detect
from . import daemon, protocol as p


def keygen(path: str) -> dict:
    r = old_op._keygen(path)
    return {'status': 'offline_key_created', 'public_hex': r['public_hex'],
            'private_key_returned': False}

def capture_root(repo_root: str, out: str) -> dict:
    # An *explicit host administrator* locally observes its own root. This is
    # merely an EC181 directory-identity observation, not a Git source seal.
    def root_grant(facts: dict) -> bool:
        return facts == {
            'purpose': 'QUALITYDETECT_OBSERVE_LOCAL_ROOT',
            'source_mode': 'WorkingTree', 'repo_root': repo_root}
    pin = detect.QualityDetector.observe_root(
        repo_root, authorize_observation=root_grant)
    io.write_exclusive(out, pin)
    return {'status': 'source_pin_captured_for_host_review',
            'source_pin_sha256': p.sha((p.canonical(pin) + b'\n')),
            'host_policy_installed': False, 'git_bytes_verified': False}

def vote(role: str, subject_file: str, private_file: str, out: str) -> dict:
    subject = p.validate_subject(io.read_doc(subject_file))
    key = io.private_from_file(private_file)
    record = {
        'schema': p.VOTE_SCHEMA, 'role': role,
        'subject_sha256': p.sha(p.canonical(subject)),
        'signer_public_hex': p.public_hex(key),
        'signature_ed25519': p.sign(role, subject, key),
    }
    io.write_exclusive(out, record)
    return {'status': 'offline_vote_written', 'role': role,
            'subject_sha256': record['subject_sha256'],
            'private_key_returned': False}

def assemble(subject_file: str, policy_vote: str, isolation_vote: str,
             policy_pub: str, isolation_pub: str, out: str) -> dict:
    subject = p.validate_subject(io.read_doc(subject_file))
    p.need(policy_pub != isolation_pub,
           'EC281_DISTINCT_OFFLINE_ISSUERS_REQUIRED', 'permission_denied')
    votes = {}
    for role, name, pub in (('policy', policy_vote, policy_pub),
                            ('isolation', isolation_vote, isolation_pub)):
        doc = io.read_doc(name)
        p.need(type(doc) is dict and set(doc) == {
            'schema', 'role', 'subject_sha256',
            'signer_public_hex', 'signature_ed25519'} and
            doc.get('schema') == p.VOTE_SCHEMA and doc.get('role') == role and
            doc.get('signer_public_hex') == pub and
            doc.get('subject_sha256') == p.sha(p.canonical(subject)),
            'EC281_OFFLINE_VOTE_SCOPE_MISMATCH', 'permission_denied')
        p.verify(role, subject, doc['signature_ed25519'], pub)
        votes[role] = doc['signature_ed25519']
    grant = {'schema': p.GRANT_SCHEMA, 'subject': subject,
             'policy_signature_ed25519': votes['policy'],
             'isolation_signature_ed25519': votes['isolation']}
    io.write_exclusive(out, grant)
    return {'status': 'two_offline_votes_assembled',
            'grant_sha256': p.sha(p.canonical(grant)),
            'host_admission': False}

def preflight(*, socket_path: str, grant_file: str, policy_sha: str,
              server_public_hex: str, timeout: float = 12) -> tuple[int, dict]:
    p.need(type(socket_path) is str and os.path.isabs(socket_path) and
           len(socket_path) < 100, 'EC281_SOCKET_ABSOLUTE_PATH_REQUIRED')
    p.need(type(policy_sha) is str and io.HASH.fullmatch(policy_sha) is not None,
           'EC281_CLIENT_POLICY_PIN_REQUIRED')
    io.pub_from_hex(server_public_hex)
    grant = io.read_doc(grant_file, p.MAX_RPC)
    p.need(grant.get('schema') == p.GRANT_SCHEMA and
           type(grant.get('subject')) is dict,
           'EC281_CLIENT_GRANT_FILE_INVALID')
    s = p.validate_subject(grant['subject'])
    p.need(s['policy_sha256'] == policy_sha,
           'EC281_CLIENT_POLICY_GRANT_MISMATCH', 'permission_denied')
    req = {'schema': p.REQUEST_SCHEMA, 'nonce': secrets.token_hex(16),
           'grant': grant}
    raw = p.canonical(req) + b'\n'
    p.need(len(raw) <= p.MAX_RPC, 'EC281_CLIENT_REQUEST_TOO_LARGE')
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
        raise p.HostError('EC281_SIGNED_PREFLIGHT_HOST_UNAVAILABLE',
                          'unavailable') from exc
    p.need(reply_buf.endswith(b'\n') and reply_buf.count(b'\n') == 1 and
           0 < len(reply_buf) <= p.MAX_REPLY,
           'EC281_SIGNED_PREFLIGHT_REPLY_TRUNCATED', 'unavailable')
    reply = io.parse(bytes(reply_buf[:-1]), p.MAX_REPLY)
    result = p.verify_reply(reply, req, server_public_hex=server_public_hex,
                            policy_sha=policy_sha, now=int(time.time()))
    return result['exit_code'], {
        'schema': p.RESULT_SCHEMA, 'verified_server_signature': True,
        'result': result, 'signed_reply': reply,
        'tests_executed': False, 'overall_business_effect_verified': False}

def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description='EC281 QualityRun.Preflight independent signed plan-only host')
    sub = ap.add_subparsers(dest='action', required=True)
    a = sub.add_parser('keygen-offline')
    a.add_argument('--private-out', required=True)
    a = sub.add_parser('capture-root',
                       help='host-admin directory observation, not Git trust')
    a.add_argument('--repo-root', required=True)
    a.add_argument('--out', required=True)
    a = sub.add_parser('prepare-offline')
    a.add_argument('--profile-id', required=True)
    a.add_argument('--uid', type=int, required=True)
    a.add_argument('--policy-sha256', required=True)
    a.add_argument('--source-pin-sha256', required=True)
    a.add_argument('--approval-ticket-sha256', required=True)
    a.add_argument('--lease-ticket-sha256', required=True)
    a.add_argument('--ttl-seconds', type=int, required=True)
    a.add_argument('--out', required=True)
    for role in ('policy', 'isolation'):
        a = sub.add_parser(f'sign-{role}-offline')
        a.add_argument('--subject-file', required=True)
        a.add_argument('--private-key-file', required=True)
        a.add_argument('--out', required=True)
    a = sub.add_parser('assemble-offline')
    a.add_argument('--subject-file', required=True)
    a.add_argument('--policy-vote', required=True)
    a.add_argument('--isolation-vote', required=True)
    a.add_argument('--policy-public-hex', required=True)
    a.add_argument('--isolation-public-hex', required=True)
    a.add_argument('--out', required=True)
    a = sub.add_parser('serve')
    a.add_argument('--socket', required=True)
    a.add_argument('--policy-file', required=True)
    a.add_argument('--policy-sha256', required=True)
    a.add_argument('--server-private-key', required=True)
    a = sub.add_parser('preflight')
    a.add_argument('--socket', required=True)
    a.add_argument('--grant-file', required=True)
    a.add_argument('--policy-sha256', required=True)
    a.add_argument('--server-public-hex', required=True)
    a.add_argument('--pretty', action='store_true')
    return ap

def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.action == 'keygen-offline':
            doc = keygen(args.private_out)
        elif args.action == 'capture-root':
            doc = capture_root(args.repo_root, args.out)
        elif args.action == 'prepare-offline':
            s = p.new_subject(
                profile_id=args.profile_id, uid=args.uid,
                policy_sha=args.policy_sha256,
                source_pin_sha=args.source_pin_sha256,
                approval_sha=args.approval_ticket_sha256,
                lease_sha=args.lease_ticket_sha256,
                ttl=args.ttl_seconds)
            io.write_exclusive(args.out, s)
            doc = {'status': 'unsigned_preflight_subject_written',
                   'subject_sha256': p.sha(p.canonical(s))}
        elif args.action in ('sign-policy-offline', 'sign-isolation-offline'):
            doc = vote(args.action.split('-')[1], args.subject_file,
                       args.private_key_file, args.out)
        elif args.action == 'assemble-offline':
            doc = assemble(args.subject_file, args.policy_vote,
                           args.isolation_vote, args.policy_public_hex,
                           args.isolation_public_hex, args.out)
        elif args.action == 'serve':
            with daemon.PreflightServer(
                path=args.socket, policy_path=args.policy_file,
                policy_sha=args.policy_sha256,
                private_key_file=args.server_private_key) as host:
                host.serve_forever(poll_interval=0.25)
            return 0
        elif args.action == 'preflight':
            rc, doc = preflight(
                socket_path=args.socket, grant_file=args.grant_file,
                policy_sha=args.policy_sha256,
                server_public_hex=args.server_public_hex)
            print(json.dumps(doc, sort_keys=True, ensure_ascii=True,
                             indent=2 if args.pretty else None,
                             separators=None if args.pretty else (',', ':')))
            return rc
        else:
            raise AssertionError('unreachable')
        print(p.canonical(doc).decode('ascii'))
        return 0
    except (p.HostError, io.HostError, detect.QualityError, OSError,
            ValueError) as exc:
        code = getattr(exc, 'code', None) or 'EC281_LOCAL_OPERATOR_INVALID'
        status = getattr(exc, 'status', None) or 'invalid_input'
        doc = p.denial(code, status if status in (
            'permission_denied', 'invalid_input', 'unavailable') else 'unavailable')
        print(p.canonical(doc).decode('ascii'))
        return doc['exit_code']

if __name__ == '__main__':
    raise SystemExit(main())
