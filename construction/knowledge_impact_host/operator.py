#!/usr/bin/env python3
"""EC282 exact-job private host, offline two-reviewer authorization and client."""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import secrets
import socket
import time

from finding_query_host import operator as old_op
from finding_query_host import protocol as io
from . import daemon, protocol as p



def _create_private_job(path: str, job: dict) -> None:
    """Exclusive and fsynced writer; EC279's 24 KiB helper is too small.

    No overwrite, no symlink target, and no plaintext private job is printed.
    """
    p.need(type(path) is str and os.path.isabs(path) and len(path) <= 4096,
           'EC282_OUTPUT_ABSOLUTE_FILE_REQUIRED')
    raw = p.canonical(job) + b'\n'
    p.need(len(raw) <= p.MAX_JOB, 'EC282_JOB_EXCEEDS_PRIVATE_SIZE_BUDGET')
    handle = None
    try:
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'wb') as stream:
            handle = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        parent = os.open(os.path.dirname(path), os.O_RDONLY |
                         getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError as exc:
        raise p.HostError('EC282_PRIVATE_JOB_EXCLUSIVE_CREATE_FAILED',
                          'unavailable') from exc
    finally:
        if handle is not None:
            os.close(handle)


def _signature_file(path: str) -> str:
    data = io._open_regular(path, 256, private=True).strip()
    try:
        sig = data.decode('ascii', 'strict')
        decoded = base64.b64decode(sig, validate=True)
        p.need(len(decoded) == 64 and
               base64.b64encode(decoded).decode('ascii') == sig,
               'EC282_DETACHED_SIGNATURE_NOT_CANONICAL')
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise p.HostError('EC282_DETACHED_SIGNATURE_NOT_CANONICAL') from exc
    return sig


def prepare_job(args: argparse.Namespace) -> dict:
    p.need(bool(args.baseline_statement_file) == bool(args.baseline_signature_file),
           'EC282_BASELINE_STATEMENT_SIGNATURE_PAIR_REQUIRED')
    p.need(bool(args.baseline_statement_file),
           'EC282_FULL_GIT_BASELINE_REQUIRED_FOR_VERIFIED_HOST_RESULT')
    read = lambda filename, limit: io.read_doc(filename, limit, private=True)
    obj = {
        'schema': p.JOB_SCHEMA,
        'repository_root': args.repository_root,
        'knowledge_root': args.knowledge_root,
        'repository_ref': args.repository_ref,
        'target_ref': args.target_ref,
        'git_executable': args.git_executable,
        'trusted_target_public_hex_by_id': read(args.target_keys_file, 8192),
        'trusted_baseline_public_hex_by_id': read(args.baseline_keys_file, 8192),
        'request': read(args.request_file, 262144),
        'bootstrap_read_policy': read(args.bootstrap_policy_file, 65536),
        'target_read_policy': read(args.target_policy_file, 65536),
        'impact_read_policy': read(args.impact_policy_file, 65536),
        'target_statement': read(args.target_statement_file, 8192),
        'target_signature_base64': _signature_file(args.target_signature_file),
        'baseline_statement': read(args.baseline_statement_file, 8192),
        'baseline_signature_base64': _signature_file(args.baseline_signature_file),
    }
    p.validate_job(obj)
    _create_private_job(args.out, obj)
    return {'schema': 'ces.ec282.private_job_prepared.v1',
            'status': 'private_exact_job_created_pending_offline_approval',
            'job_sha256': p.sha(p.canonical(obj) + b'\n'),
            'repository_ref': obj['repository_ref'],
            'target_ref': obj['target_ref'],
            'backend_git_comparison_executed': False,
            'private_job_returned': False}


def keygen(path: str) -> dict:
    key = old_op._keygen(path)
    return {'schema': 'ces.ec282.offline_keygen_result.v1',
            'public_hex': key['public_hex'], 'private_key_returned': False}


def vote(role: str, subject_file: str, private_file: str, out: str) -> dict:
    subject = p.validate_subject(io.read_doc(subject_file))
    key = io.private_from_file(private_file)
    record = {'schema': p.VOTE_SCHEMA, 'role': role,
              'subject_sha256': p.sha(p.canonical(subject)),
              'signer_public_hex': p.public_hex(key),
              'signature_ed25519': p.sign(role, subject, key)}
    io.write_exclusive(out, record)
    return {'status': 'independent_offline_vote_written', 'role': role,
            'subject_sha256': record['subject_sha256'],
            'private_key_returned': False}


def assemble(subject_file: str, source_vote: str, reader_vote: str,
             source_pub: str, reader_pub: str, out: str) -> dict:
    subject = p.validate_subject(io.read_doc(subject_file))
    p.need(source_pub != reader_pub,
           'EC282_DISTINCT_OFFLINE_SIGNERS_REQUIRED', 'permission_denied')
    signatures: dict[str, str] = {}
    for role, filename, pub in (('source', source_vote, source_pub),
                                ('reader', reader_vote, reader_pub)):
        entry = io.read_doc(filename)
        p.need(type(entry) is dict and set(entry) == {
            'schema', 'role', 'subject_sha256',
            'signer_public_hex', 'signature_ed25519'} and
            entry['schema'] == p.VOTE_SCHEMA and entry['role'] == role and
            entry['subject_sha256'] == p.sha(p.canonical(subject)) and
            entry['signer_public_hex'] == pub,
            'EC282_OFFLINE_VOTE_MISMATCH', 'permission_denied')
        p.verify(role, subject, entry['signature_ed25519'], pub)
        signatures[role] = entry['signature_ed25519']
    grant = {'schema': p.GRANT_SCHEMA, 'subject': subject,
             'source_signature_ed25519': signatures['source'],
             'reader_signature_ed25519': signatures['reader']}
    io.write_exclusive(out, grant)
    return {'status': 'offline_dual_signature_grant_written',
            'grant_sha256': p.sha(p.canonical(grant)),
            'private_key_returned': False, 'server_authorization': False}


def analyze(*, socket_path: str, grant_file: str, policy_sha: str,
            server_public_hex: str, timeout: float = 90.0) -> tuple[int, dict]:
    p.need(type(socket_path) is str and os.path.isabs(socket_path) and
           len(socket_path) < 100,
           'EC282_CLIENT_SOCKET_ABSOLUTE_PATH_REQUIRED')
    p.need(type(policy_sha) is str and io.HASH.fullmatch(policy_sha) is not None,
           'EC282_CLIENT_POLICY_PIN_REQUIRED')
    io.pub_from_hex(server_public_hex)
    grant = io.read_doc(grant_file, p.MAX_RPC)
    p.need(type(grant) is dict and grant.get('schema') == p.GRANT_SCHEMA and
           type(grant.get('subject')) is dict,
           'EC282_CLIENT_GRANT_INVALID')
    subject = p.validate_subject(grant['subject'])
    p.need(subject['policy_sha256'] == policy_sha,
           'EC282_CLIENT_GRANT_POLICY_MISMATCH', 'permission_denied')
    req = {'schema': p.REQUEST_SCHEMA,
           'nonce': secrets.token_hex(16), 'grant': grant}
    raw = p.canonical(req) + b'\n'
    p.need(len(raw) <= p.MAX_RPC,
           'EC282_CLIENT_REQUEST_TOO_LARGE')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(socket_path)
            conn.sendall(raw)
            buf = bytearray()
            while len(buf) <= p.MAX_REPLY:
                chunk = conn.recv(min(16384, p.MAX_REPLY + 1 - len(buf)))
                if not chunk:
                    break
                buf.extend(chunk)
                if b'\n' in chunk:
                    break
    except (OSError, TimeoutError) as exc:
        raise p.HostError('EC282_INDEPENDENT_READ_HOST_UNAVAILABLE',
                          'unavailable') from exc
    p.need(buf.endswith(b'\n') and buf.count(b'\n') == 1 and
           0 < len(buf) <= p.MAX_REPLY,
           'EC282_SIGNED_RESULT_TRUNCATED', 'unavailable')
    reply = io.parse(bytes(buf[:-1]), p.MAX_REPLY)
    result = p.verify_reply(reply, req, server_public_hex=server_public_hex,
                            policy_sha=policy_sha, now=int(time.time()))
    return result['exit_code'], {
        'schema': p.RESULT_SCHEMA, 'verified_server_signature': True,
        'result': result, 'signed_reply': reply,
        'read_only_operation': True,
        'knowledge_semantic_impact_verified': False,
        'business_effect_verified': False}


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description='EC282 independently authorized KnowledgeImpact.Analyze live Git reader')
    sub = ap.add_subparsers(dest='action', required=True)
    a = sub.add_parser('keygen-offline')
    a.add_argument('--private-out', required=True)
    a = sub.add_parser('inspect-job',
        help='local host-admin pin and job shape review, not organizational attestation')
    a.add_argument('--job-file', required=True)
    a = sub.add_parser('prepare-job',
        help='create private job JSON from host-only EC202/203/204 signed inputs')
    a.add_argument('--repository-root', required=True)
    a.add_argument('--knowledge-root', required=True)
    a.add_argument('--repository-ref', required=True)
    a.add_argument('--target-ref', required=True)
    a.add_argument('--git-executable', required=True)
    a.add_argument('--target-keys-file', required=True)
    a.add_argument('--baseline-keys-file', required=True)
    a.add_argument('--request-file', required=True)
    a.add_argument('--bootstrap-policy-file', required=True)
    a.add_argument('--target-policy-file', required=True)
    a.add_argument('--impact-policy-file', required=True)
    a.add_argument('--target-statement-file', required=True)
    a.add_argument('--target-signature-file', required=True)
    a.add_argument('--baseline-statement-file', required=True)
    a.add_argument('--baseline-signature-file', required=True)
    a.add_argument('--out', required=True)
    a = sub.add_parser('prepare-offline')
    a.add_argument('--uid', type=int, required=True)
    a.add_argument('--policy-sha256', required=True)
    a.add_argument('--job-sha256', required=True)
    a.add_argument('--repository-ref', required=True)
    a.add_argument('--target-ref', required=True)
    a.add_argument('--ttl-seconds', type=int, required=True)
    a.add_argument('--out', required=True)
    for role in ('source', 'reader'):
        a = sub.add_parser(f'sign-{role}-offline')
        a.add_argument('--subject-file', required=True)
        a.add_argument('--private-key-file', required=True)
        a.add_argument('--out', required=True)
    a = sub.add_parser('assemble-offline')
    a.add_argument('--subject-file', required=True)
    a.add_argument('--source-vote', required=True)
    a.add_argument('--reader-vote', required=True)
    a.add_argument('--source-public-hex', required=True)
    a.add_argument('--reader-public-hex', required=True)
    a.add_argument('--out', required=True)
    a = sub.add_parser('serve')
    a.add_argument('--socket', required=True)
    a.add_argument('--policy-file', required=True)
    a.add_argument('--policy-sha256', required=True)
    a.add_argument('--server-private-key', required=True)
    a = sub.add_parser('analyze')
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
            result = keygen(args.private_out)
        elif args.action == 'prepare-job':
            result = prepare_job(args)
        elif args.action == 'inspect-job':
            raw = io._open_regular(args.job_file, p.MAX_JOB, private=True)
            job = p.validate_job(io.parse(raw, p.MAX_JOB))
            result = {'schema': 'ces.ec282.host_job_inspection.v1',
                      'status': 'configuration_observed_only',
                      'job_sha256': p.sha(raw),
                      'repository_ref': job['repository_ref'],
                      'target_ref': job['target_ref'],
                      'private_job_released': False,
                      'Git_or_source_or_issuer_authority_verified': False}
        elif args.action == 'prepare-offline':
            subject = p.new_subject(
                uid=args.uid, policy_sha=args.policy_sha256,
                job_sha=args.job_sha256, repository_ref=args.repository_ref,
                target_ref=args.target_ref, ttl=args.ttl_seconds)
            io.write_exclusive(args.out, subject)
            result = {'status': 'unsigned_exact_job_subject_written',
                      'subject_sha256': p.sha(p.canonical(subject))}
        elif args.action in ('sign-source-offline', 'sign-reader-offline'):
            result = vote(args.action.split('-')[1], args.subject_file,
                          args.private_key_file, args.out)
        elif args.action == 'assemble-offline':
            result = assemble(args.subject_file, args.source_vote,
                              args.reader_vote, args.source_public_hex,
                              args.reader_public_hex, args.out)
        elif args.action == 'serve':
            with daemon.ImpactServer(
                path=args.socket, policy_path=args.policy_file,
                policy_sha=args.policy_sha256,
                private_key_file=args.server_private_key) as server:
                server.serve_forever(poll_interval=.25)
            return 0
        elif args.action == 'analyze':
            rc, result = analyze(
                socket_path=args.socket, grant_file=args.grant_file,
                policy_sha=args.policy_sha256,
                server_public_hex=args.server_public_hex)
            print(json.dumps(result, sort_keys=True, ensure_ascii=True,
                             indent=2 if args.pretty else None,
                             separators=None if args.pretty else (',', ':')))
            return rc
        else:
            raise AssertionError('unreachable action')
        print(p.canonical(result).decode('ascii'))
        return 0
    except (p.HostError, io.HostError, OSError, ValueError) as exc:
        code = exc.code if isinstance(exc, (p.HostError, io.HostError)) else (
            'EC282_HOST_LOCAL_FAILURE')
        status = exc.status if isinstance(exc, (p.HostError, io.HostError)) else (
            'unavailable')
        denial = p.denial(code, status)
        print(p.canonical(denial).decode('ascii'))
        return denial['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
