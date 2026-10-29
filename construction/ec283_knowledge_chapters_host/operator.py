#!/usr/bin/env python3
"""EC283 independently signed exact KnowledgeQuery.Chapters CLI.

The offline signer never needs the private query contents: it signs an
operator-supplied fixed SHA, projection, version view, kernel UID and expiry.
The store host owns its job, EC202 policies and existing EC206/208 journals.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time

from ec279_finding_query_host import operator as old_op
from ec279_finding_query_host import protocol as io
from . import daemon, protocol as p


def _private_job(path: str, doc: dict) -> None:
    p.need(type(path) is str and os.path.isabs(path) and
           len(path) <= 4096, 'EC283_PRIVATE_JOB_OUT_PATH_INVALID')
    raw = p.canonical(doc) + b'\n'
    p.need(len(raw) <= p.MAX_JOB, 'EC283_JOB_TOO_LARGE')
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
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
        raise p.HostError('EC283_PRIVATE_JOB_CREATE_FAILED', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)


def _read_revoked(filename: str) -> list[str]:
    doc = io.read_doc(filename, 8192, private=True)
    p.need(set(doc) == {'revoked_approvers'} and
           type(doc['revoked_approvers']) is list,
           'EC283_REVOKED_APPROVER_FILE_INVALID', 'unavailable')
    return doc['revoked_approvers']


def prepare_job(a: argparse.Namespace) -> dict:
    read = lambda x, cap: io.read_doc(x, cap, private=True)
    job = {'schema': p.JOB_SCHEMA,
        'repository_root': a.repository_root, 'knowledge_root': a.knowledge_root,
        'candidate_root': a.candidate_root, 'version_root': a.version_root,
        'candidate_store_id': a.candidate_store_id,
        'version_store_id': a.version_store_id,
        'repository_ref': a.repository_ref,
        'knowledge_space_key': a.knowledge_space_key,
        'period_id': a.period_id, 'source_policy_revision': a.source_policy_revision,
        'chapter_path': a.chapter_path,
        'trusted_approvers': read(a.trusted_approvers_file, 8192),
        'revoked_approvers': (_read_revoked(a.revoked_approvers_file)
                              if a.revoked_approvers_file else []),
        'query_request': read(a.query_request_file, p.MAX_JOB),
        'query_policy': read(a.query_policy_file, 8192),
        'bootstrap_request': (read(a.bootstrap_request_file, 262144)
                              if a.bootstrap_request_file else None),
        'bootstrap_read_policy': (read(a.bootstrap_policy_file, 65536)
                                  if a.bootstrap_policy_file else None),
        'version_evidence': (read(a.version_evidence_file, 262144)
                             if a.version_evidence_file else None)}
    p.validate_job(job)
    _private_job(a.out, job)
    return {'schema': 'ces.ec283.private_exact_query_prepared.v1',
        'status': 'private_exact_query_created_pending_independent_approvals',
        'job_sha256': p.sha(p.canonical(job) + b'\n'),
        'repository_ref': job['repository_ref'],
        'query_view': job['query_request']['view'],
        'projection': job['query_request']['projection'],
        'query_request_sha256': p.sha(p.canonical(job['query_request'])),
        'section_count': len(job['query_request']['section_indices']),
        'private_job_returned': False, 'knowledge_data_read': False}


def keygen(path: str) -> dict:
    result = old_op._keygen(path)
    return {'schema': 'ces.ec283.offline_keygen.v1',
            'public_hex': result['public_hex'], 'private_key_returned': False}


def vote(role: str, subject_file: str, private_file: str, out: str) -> dict:
    subject = p.validate_subject(io.read_doc(subject_file))
    key = io.private_from_file(private_file)
    receipt = {'schema': p.VOTE_SCHEMA, 'role': role,
        'subject_sha256': p.sha(p.canonical(subject)),
        'signer_public_hex': p.public_hex(key),
        'signature_ed25519': p.sign(role, subject, key)}
    io.write_exclusive(out, receipt)
    return {'status': 'independent_exact_query_vote_written', 'role': role,
            'subject_sha256': receipt['subject_sha256'],
            'private_key_returned': False}


def assemble(subject_file: str, custodian_vote: str, reader_vote: str,
             custodian_pub: str, reader_pub: str, out: str) -> dict:
    subject = p.validate_subject(io.read_doc(subject_file))
    p.need(custodian_pub != reader_pub, 'EC283_TWO_DISTINCT_AUTHORITIES_REQUIRED',
           'permission_denied')
    sigs = {}
    for role, filename, public in (
        ('custodian', custodian_vote, custodian_pub),
        ('reader', reader_vote, reader_pub)):
        entry = io.read_doc(filename)
        p.need(type(entry) is dict and set(entry) == {
            'schema', 'role', 'subject_sha256', 'signer_public_hex',
            'signature_ed25519'} and entry['schema'] == p.VOTE_SCHEMA and
            entry['role'] == role and
            entry['subject_sha256'] == p.sha(p.canonical(subject)) and
            entry['signer_public_hex'] == public,
            'EC283_OFFLINE_VOTE_SUBJECT_OR_ROLE_MISMATCH', 'permission_denied')
        p.verify(role, subject, entry['signature_ed25519'], public)
        sigs[role] = entry['signature_ed25519']
    grant = {'schema': p.GRANT_SCHEMA, 'subject': subject,
             'custodian_signature_ed25519': sigs['custodian'],
             'reader_signature_ed25519': sigs['reader']}
    io.write_exclusive(out, grant)
    return {'status': 'offline_dual_query_grant_written',
            'grant_sha256': p.sha(p.canonical(grant)),
            'private_keys_returned': False, 'host_connected': False}


def query(*, socket_path: str, grant_file: str, policy_sha: str,
          server_public_hex: str, timeout: float = 90.0) -> tuple[int, dict]:
    p.need(type(socket_path) is str and os.path.isabs(socket_path) and
           len(socket_path) < 100,
           'EC283_CLIENT_SOCKET_PATH_INVALID')
    p.need(type(policy_sha) is str and io.HASH.fullmatch(policy_sha) is not None,
           'EC283_CLIENT_POLICY_PIN_INVALID')
    io.pub_from_hex(server_public_hex)
    grant = io.read_doc(grant_file, p.MAX_RPC)
    p.need(type(grant) is dict and grant.get('schema') == p.GRANT_SCHEMA and
           type(grant.get('subject')) is dict,
           'EC283_CLIENT_GRANT_FIELDS_INVALID')
    s = p.validate_subject(grant['subject'])
    p.need(s['policy_sha256'] == policy_sha,
           'EC283_CLIENT_POLICY_GRANT_MISMATCH', 'permission_denied')
    request = {'schema': p.REQUEST_SCHEMA,
               'nonce': secrets.token_hex(16), 'grant': grant}
    raw = p.canonical(request) + b'\n'
    p.need(len(raw) <= p.MAX_RPC, 'EC283_CLIENT_RPC_TOO_LARGE')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(socket_path)
            conn.sendall(raw)
            answer = bytearray()
            while len(answer) <= p.MAX_REPLY:
                part = conn.recv(min(16384, p.MAX_REPLY + 1 - len(answer)))
                if not part:
                    break
                answer.extend(part)
                if b'\n' in part:
                    break
    except (OSError, TimeoutError) as exc:
        raise p.HostError('EC283_INDEPENDENT_CHAPTERS_HOST_UNAVAILABLE',
                          'unavailable') from exc
    p.need(answer.endswith(b'\n') and answer.count(b'\n') == 1 and
           0 < len(answer) <= p.MAX_REPLY,
           'EC283_SIGNED_CHAPTERS_RESULT_TRUNCATED', 'unavailable')
    reply = io.parse(bytes(answer[:-1]), p.MAX_REPLY)
    result = p.verify_reply(reply, request,
        server_public_hex=server_public_hex, policy_sha=policy_sha,
        now=int(time.time()))
    return result['exit_code'], {
        'schema': p.RESULT_SCHEMA, 'verified_server_signature': True,
        'result': result, 'signed_reply': reply,
        'read_only_operation': True, 'private_metadata_written': False,
        'source_knowledge_file_written': False, 'business_effect_verified': False,
        'knowledge_truth_or_publication_verified': False}


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=
        'EC283 independent KnowledgeQuery.Chapters original EC210 read-only host')
    sub = ap.add_subparsers(dest='action', required=True)
    x = sub.add_parser('keygen-offline')
    x.add_argument('--private-out', required=True)
    x = sub.add_parser('prepare-job', help='host-admin creates private pinned query')
    for field in ('repository-root', 'knowledge-root', 'candidate-root',
                  'version-root', 'candidate-store-id', 'version-store-id',
                  'repository-ref', 'knowledge-space-key', 'period-id',
                  'source-policy-revision', 'chapter-path',
                  'trusted-approvers-file', 'query-request-file',
                  'query-policy-file', 'out'):
        x.add_argument('--' + field, required=True)
    for field in ('revoked-approvers-file', 'bootstrap-request-file',
                  'bootstrap-policy-file', 'version-evidence-file'):
        x.add_argument('--' + field)
    x = sub.add_parser('inspect-job', help='private admin inspection only')
    x.add_argument('--job-file', required=True)
    x = sub.add_parser('prepare-offline')
    x.add_argument('--uid', type=int, required=True)
    for field in ('policy-sha256', 'job-sha256', 'repository-ref',
                  'query-view', 'projection', 'query-request-sha256',
                  'ttl-seconds', 'out'):
        x.add_argument('--' + field, required=True,
                       type=int if field == 'ttl-seconds' else str)
    for role in ('custodian', 'reader'):
        x = sub.add_parser('sign-' + role + '-offline')
        x.add_argument('--subject-file', required=True)
        x.add_argument('--private-key-file', required=True)
        x.add_argument('--out', required=True)
    x = sub.add_parser('assemble-offline')
    for field in ('subject-file', 'custodian-vote', 'reader-vote',
                  'custodian-public-hex', 'reader-public-hex', 'out'):
        x.add_argument('--' + field, required=True)
    x = sub.add_parser('serve')
    for field in ('socket', 'policy-file', 'policy-sha256', 'server-private-key'):
        x.add_argument('--' + field, required=True)
    x = sub.add_parser('query')
    for field in ('socket', 'grant-file', 'policy-sha256', 'server-public-hex'):
        x.add_argument('--' + field, required=True)
    x.add_argument('--pretty', action='store_true')
    return ap


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    try:
        if a.action == 'keygen-offline':
            output = keygen(a.private_out)
        elif a.action == 'prepare-job':
            output = prepare_job(a)
        elif a.action == 'inspect-job':
            raw = io._open_regular(a.job_file, p.MAX_JOB, private=True)
            job = p.validate_job(io.parse(raw, p.MAX_JOB))
            output = {'schema': 'ces.ec283.host_job_inspection.v1',
                'status': 'host_configuration_observed_only',
                'job_sha256': p.sha(raw),
                'repository_ref': job['repository_ref'],
                'query_view': job['query_request']['view'],
                'projection': job['query_request']['projection'],
                'query_request_sha256': p.sha(p.canonical(job['query_request'])),
                'private_job_returned': False,
                'existing_store_trusted_or_read': False}
        elif a.action == 'prepare-offline':
            subject = p.new_subject(uid=a.uid, policy_sha=a.policy_sha256,
                job_sha=a.job_sha256, repository_ref=a.repository_ref,
                query_view=a.query_view, projection=a.projection,
                query_sha=a.query_request_sha256, ttl=a.ttl_seconds)
            io.write_exclusive(a.out, subject)
            output = {'status': 'unsigned_exact_query_subject_written',
                      'subject_sha256': p.sha(p.canonical(subject))}
        elif a.action in ('sign-custodian-offline', 'sign-reader-offline'):
            output = vote(a.action.split('-')[1], a.subject_file,
                          a.private_key_file, a.out)
        elif a.action == 'assemble-offline':
            output = assemble(a.subject_file, a.custodian_vote,
                a.reader_vote, a.custodian_public_hex, a.reader_public_hex, a.out)
        elif a.action == 'serve':
            with daemon.ChaptersServer(path=a.socket, policy_path=a.policy_file,
                policy_sha=a.policy_sha256,
                private_key_file=a.server_private_key) as host:
                host.serve_forever(poll_interval=.25)
            return 0
        elif a.action == 'query':
            rc, output = query(socket_path=a.socket, grant_file=a.grant_file,
                policy_sha=a.policy_sha256, server_public_hex=a.server_public_hex)
            print(json.dumps(output, sort_keys=True, ensure_ascii=True,
                indent=2 if a.pretty else None,
                separators=None if a.pretty else (',', ':')))
            return rc
        else:
            raise AssertionError('unexpected CLI action')
        print(p.canonical(output).decode('ascii'))
        return 0
    except (p.HostError, io.HostError, OSError, ValueError) as exc:
        code = exc.code if isinstance(exc, (p.HostError, io.HostError)) else \
               'EC283_LOCAL_OPERATOR_UNAVAILABLE'
        status = exc.status if isinstance(exc, (p.HostError, io.HostError)) else \
                 'unavailable'
        result = p.denial(code, status)
        print(p.canonical(result).decode('ascii'))
        return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
