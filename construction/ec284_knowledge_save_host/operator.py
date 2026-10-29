#!/usr/bin/env python3
"""EC284 prepare/pin, two offline votes, inspect and execute exact EC208 append.

The offline signing machines require only public fingerprints and a fresh exact
subject; source content and original EC208 approval secrets stay on their own
owners' machines. The server never generates an authorization on their behalf.
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
from . import protocol as p, daemon


def _create_private(path: str, obj: dict) -> None:
    p.need(p.plain_abs(path), 'EC284_PRIVATE_JOB_OUTPUT_PATH_INVALID')
    raw = p.canonical(obj) + b'\n'
    p.need(len(raw) <= p.MAX_JOB, 'EC284_PRIVATE_JOB_TOO_LARGE')
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
        raise p.HostError('EC284_PRIVATE_JOB_CREATION_FAILED', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)


def _read_revoked(path: str) -> list[str]:
    r = io.read_doc(path, 8192, private=True)
    p.need(type(r) is dict and set(r) == {'revoked_approvers'} and
           type(r['revoked_approvers']) is list,
           'EC284_REVOKED_APPROVER_FILE_INVALID', 'unavailable')
    return r['revoked_approvers']


def prepare_job(a: argparse.Namespace) -> dict:
    read = lambda name, lim: io.read_doc(getattr(a, name), lim, private=True)
    job = {'schema': p.JOB_SCHEMA,
        'repository_root': a.repository_root,
        'knowledge_root': a.knowledge_root,
        'candidate_root': a.candidate_root,
        'version_root': a.version_root,
        'candidate_store_id': a.candidate_store_id,
        'version_store_id': a.version_store_id,
        'repository_ref': a.repository_ref,
        'knowledge_space_key': a.knowledge_space_key,
        'period_id': a.period_id,
        'source_policy_revision': a.source_policy_revision,
        'chapter_path': a.chapter_path,
        'trusted_approvers': read('trusted_approvers_file', 8192),
        'revoked_approvers': (_read_revoked(a.revoked_approvers_file)
                              if a.revoked_approvers_file else []),
        'save_request': read('save_request_file', 32768),
        'handoff_request': read('handoff_request_file', 8192),
        'handoff_policy': read('handoff_policy_file', 8192),
        'candidate_read_policies': read('candidate_read_policies_file', 65536),
        'save_policy': read('save_policy_file', 8192),
        'approvals': read('approvals_file', 8192)}
    p.validate_job(job)
    _create_private(a.out, job)
    return inspect_public(job, p.sha(p.canonical(job) + b'\n'), created=True)


def inspect_public(job: dict, job_sha: str, *, created: bool = False) -> dict:
    return {'schema': 'ces.ec284.host_job_inspection.v1',
        'status': ('private_save_job_created_pending_two_independent_host_votes'
                   if created else 'private_save_job_pins_observed_only'),
        'job_sha256': job_sha,
        'repository_ref': job['repository_ref'],
        'save_key': job['save_request']['save_key'],
        'save_request_sha256': p.sha(p.canonical(job['save_request'])),
        'authorization_scope_sha256': job['save_policy']['authorization_scope_sha256'],
        'new_chapter_sha256': job['save_request']['expected_new_chapter_sha256'],
        'chapter_text_returned': False, 'save_invoked': False,
        'permissions_granted': False}


def vote(role: str, subject_file: str, private_key_file: str,
         out: str) -> dict:
    subject = p.validate_subject(io.read_doc(subject_file, 8192))
    key = io.private_from_file(private_key_file)
    receipt = {'schema': p.VOTE_SCHEMA, 'role': role,
        'subject_sha256': p.sha(p.canonical(subject)),
        'signer_public_hex': p.public_hex(key),
        'signature_ed25519': p.sign(role, subject, key)}
    io.write_exclusive(out, receipt)
    return {'status': 'offline_exact_local_save_vote_written',
            'role': role, 'subject_sha256': receipt['subject_sha256'],
            'private_key_returned': False}


def assemble(subject_file: str, custodian_vote: str, authorizer_vote: str,
             custodian_public_hex: str, authorizer_public_hex: str,
             out: str) -> dict:
    subject = p.validate_subject(io.read_doc(subject_file, 8192))
    p.need(custodian_public_hex != authorizer_public_hex,
           'EC284_INDEPENDENT_TWO_HOST_AUTHORITIES_REQUIRED', 'permission_denied')
    sigs = {}
    for role, filename, public in (
            ('custodian', custodian_vote, custodian_public_hex),
            ('authorizer', authorizer_vote, authorizer_public_hex)):
        item = io.read_doc(filename, 8192)
        p.need(type(item) is dict and set(item) == {'schema','role',
             'subject_sha256','signer_public_hex','signature_ed25519'} and
             item['schema'] == p.VOTE_SCHEMA and item['role'] == role and
             item['subject_sha256'] == p.sha(p.canonical(subject)) and
             item['signer_public_hex'] == public,
             'EC284_OFFLINE_VOTE_SUBJECT_OR_ROLE_MISMATCH', 'permission_denied')
        p.verify(role, subject, item['signature_ed25519'], public)
        sigs[role] = item['signature_ed25519']
    grant = {'schema': p.GRANT_SCHEMA, 'subject': subject,
             'custodian_signature_ed25519': sigs['custodian'],
             'authorizer_signature_ed25519': sigs['authorizer']}
    io.write_exclusive(out, grant)
    return {'status': 'exact_local_write_dual_grant_created',
            'grant_sha256': p.sha(p.canonical(grant)),
            'private_keys_returned': False, 'save_invoked': False}


def save(*, socket_path: str, grant_file: str, policy_sha: str,
         server_public_hex: str, timeout: float = 90.0) -> tuple[int, dict]:
    p.need(type(socket_path) is str and os.path.isabs(socket_path) and
           len(socket_path) < 100, 'EC284_CLIENT_SOCKET_PATH_INVALID')
    p.need(type(policy_sha) is str and io.HASH.fullmatch(policy_sha) is not None,
           'EC284_CLIENT_POLICY_PIN_INVALID')
    io.pub_from_hex(server_public_hex)
    grant = io.read_doc(grant_file, p.MAX_RPC)
    p.need(type(grant) is dict and grant.get('schema') == p.GRANT_SCHEMA and
           type(grant.get('subject')) is dict,
           'EC284_CLIENT_GRANT_FIELDS_INVALID')
    subject = p.validate_subject(grant['subject'])
    p.need(subject['policy_sha256'] == policy_sha,
           'EC284_CLIENT_GRANT_POLICY_MISMATCH', 'permission_denied')
    request = {'schema': p.REQUEST_SCHEMA, 'nonce': secrets.token_hex(16),
               'grant': grant}
    raw = p.canonical(request) + b'\n'
    p.need(len(raw) <= p.MAX_RPC, 'EC284_CLIENT_RPC_TOO_LARGE')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(socket_path)
            conn.sendall(raw)
            answer = bytearray()
            while len(answer) <= p.MAX_REPLY:
                part = conn.recv(min(8192, p.MAX_REPLY + 1 - len(answer)))
                if not part:
                    break
                answer.extend(part)
                if b'\n' in part:
                    break
    except (OSError, TimeoutError) as exc:
        raise p.HostError('EC284_TRANSPORT_UNKNOWN_INSPECT_STORE_BEFORE_RETRY',
                          'unavailable') from exc
    p.need(answer.endswith(b'\n') and answer.count(b'\n') == 1 and
           0 < len(answer) <= p.MAX_REPLY,
           'EC284_SIGNED_RECEIPT_MISSING_OUTCOME_UNKNOWN', 'unavailable')
    reply = io.parse(bytes(answer[:-1]), p.MAX_REPLY)
    result = p.verify_reply(reply, request, server_public_hex=server_public_hex,
                            policy_sha=policy_sha, now=int(time.time()))
    return result['exit_code'], {'schema': p.RESULT_SCHEMA,
         'verified_server_signature': True,
         'result': result, 'signed_reply': reply,
         'source_knowledge_file_written': False,
         'business_repository_written': False,
         'publication_verified': False,
         'organizational_signer_identity_authenticated': False,
         'local_metadata_may_have_changed': (
             result.get('local_version_metadata_written') is True or
             result.get('local_write_outcome_unknown') is True)}


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=
        'EC284 independently approved exact original EC208 KnowledgeSave.SaveLocal host')
    sub = ap.add_subparsers(dest='action', required=True)
    x = sub.add_parser('keygen-offline')
    x.add_argument('--private-out', required=True)
    x = sub.add_parser('prepare-job')
    for field in ('repository-root','knowledge-root','candidate-root',
                  'version-root','candidate-store-id','version-store-id',
                  'repository-ref','knowledge-space-key','period-id',
                  'source-policy-revision','chapter-path',
                  'trusted-approvers-file','save-request-file',
                  'handoff-request-file','handoff-policy-file',
                  'candidate-read-policies-file','save-policy-file',
                  'approvals-file','out'):
        x.add_argument('--'+field, required=True)
    x.add_argument('--revoked-approvers-file')
    x = sub.add_parser('inspect-job')
    x.add_argument('--job-file', required=True)
    x = sub.add_parser('prepare-offline')
    x.add_argument('--uid', type=int, required=True)
    for field in ('policy-sha256','job-sha256','repository-ref',
                  'save-key','save-request-sha256',
                  'authorization-scope-sha256','new-chapter-sha256',
                  'ttl-seconds','out'):
        x.add_argument('--'+field, required=True,
                       type=int if field == 'ttl-seconds' else str)
    for role in ('custodian','authorizer'):
        x = sub.add_parser('sign-'+role+'-offline')
        x.add_argument('--subject-file', required=True)
        x.add_argument('--private-key-file', required=True)
        x.add_argument('--out', required=True)
    x = sub.add_parser('assemble-offline')
    for field in ('subject-file','custodian-vote','authorizer-vote',
                  'custodian-public-hex','authorizer-public-hex','out'):
        x.add_argument('--'+field, required=True)
    x = sub.add_parser('serve')
    for field in ('socket','policy-file','policy-sha256','server-private-key'):
        x.add_argument('--'+field, required=True)
    x = sub.add_parser('save')
    for field in ('socket','grant-file','policy-sha256','server-public-hex'):
        x.add_argument('--'+field, required=True)
    x.add_argument('--pretty', action='store_true')
    return ap


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    try:
        if a.action == 'keygen-offline':
            original = old_op._keygen(a.private_out)
            output = {'schema': 'ces.ec284.host_offline_keygen.v1',
                      'public_hex': original['public_hex'],
                      'private_key_returned': False}
        elif a.action == 'prepare-job':
            output = prepare_job(a)
        elif a.action == 'inspect-job':
            raw = io._open_regular(a.job_file, p.MAX_JOB, private=True)
            output = inspect_public(p.validate_job(io.parse(raw, p.MAX_JOB)),
                                    p.sha(raw))
        elif a.action == 'prepare-offline':
            s = p.new_subject(uid=a.uid, policy_sha=a.policy_sha256,
                job_sha=a.job_sha256, repository_ref=a.repository_ref,
                save_key=a.save_key, request_sha=a.save_request_sha256,
                authorization_scope_sha=a.authorization_scope_sha256,
                chapter_sha=a.new_chapter_sha256, ttl=a.ttl_seconds)
            io.write_exclusive(a.out, s)
            output = {'status': 'unsigned_exact_save_subject_created',
                      'subject_sha256': p.sha(p.canonical(s))}
        elif a.action in ('sign-custodian-offline','sign-authorizer-offline'):
            output = vote(a.action.split('-')[1], a.subject_file,
                          a.private_key_file, a.out)
        elif a.action == 'assemble-offline':
            output = assemble(a.subject_file, a.custodian_vote,
                a.authorizer_vote, a.custodian_public_hex,
                a.authorizer_public_hex, a.out)
        elif a.action == 'serve':
            with daemon.SaveServer(path=a.socket, policy_path=a.policy_file,
                policy_sha=a.policy_sha256,
                private_key_file=a.server_private_key) as host:
                host.serve_forever(poll_interval=.25)
            return 0
        elif a.action == 'save':
            rc, output = save(socket_path=a.socket, grant_file=a.grant_file,
                policy_sha=a.policy_sha256,
                server_public_hex=a.server_public_hex)
            print(json.dumps(output, sort_keys=True, ensure_ascii=True,
                indent=2 if a.pretty else None,
                separators=None if a.pretty else (',', ':')))
            return rc
        else:
            raise AssertionError('unsupported action')
        print(p.canonical(output).decode('ascii'))
        return 0
    except (p.HostError, io.HostError, OSError, ValueError) as exc:
        code = exc.code if isinstance(exc, (p.HostError, io.HostError)) else \
               'EC284_LOCAL_OPERATOR_UNAVAILABLE'
        status = exc.status if isinstance(exc, (p.HostError, io.HostError)) else \
                 'unavailable'
        # A missing, forged, late or malformed reply cannot prove no write.
        uncertain = (a.action == 'save' and status == 'unavailable')
        out = p.denial(code, status, write_outcome_unknown=uncertain)
        print(p.canonical(out).decode('ascii'))
        return out['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
