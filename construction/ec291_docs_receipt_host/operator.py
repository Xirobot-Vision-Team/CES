#!/usr/bin/env python3
"""EC291 operator: offline EC230 read signature + two independent Host votes.

Reuses the private *original* EC285 job file as immutable source; never emits
original document text, repository path, private key or a Git push/cleanup.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time

from ec279_finding_query_host import protocol as io
from ec279_finding_query_host import operator as legacy_operator
from ec285_docs_sandbox_host import operator as previous_operator
import delivery_preview as dp
import publication_receipts as rec
from . import protocol as p, daemon


def write_private(path: str, doc: dict, limit: int) -> str:
    p.need(p.old.plain_abs(path), 'EC291_PRIVATE_OUTPUT_ABSOLUTE_PATH_REQUIRED')
    return previous_operator.create_private(path, doc, limit)


def prepare_policy(*, job_file: str, audit_root: str, admission_root: str,
                   allowed_uids: list[int], read_public_hex: str,
                   cleanup_public_hex: str, receipt_epoch: int,
                   custodian_public_hex: str, inspector_public_hex: str,
                   server_public_hex: str, out: str, enable: bool) -> dict:
    p.need(enable is True, 'EC291_EXPLICIT_ONE_GIT_READBACK_OPT_IN_REQUIRED',
           'permission_denied')
    raw = p.old.private_file(job_file, p.old.MAX_JOB)
    p.old.validate_job(io.parse(raw, p.old.MAX_JOB))
    pol = {'schema': p.POLICY_SCHEMA, 'job_file': job_file,
           'job_sha256': p.sha(raw), 'audit_root': audit_root,
           'admission_root': admission_root,
           'allowed_uids': sorted(set(allowed_uids)),
           'read_public_hex': read_public_hex,
           'cleanup_public_hex': cleanup_public_hex,
           'receipt_epoch': receipt_epoch,
           'custodian_public_hex': custodian_public_hex,
           'inspector_public_hex': inspector_public_hex,
           'server_public_hex': server_public_hex,
           'original_receipt_code_sha256': rec.ACTIVE_CODE_SHA256,
           'original_docs_code_sha256': p.original_sha(),
           'host_code_sha256': p.host_sha(),
           'enable_one_private_docs_readback': True}
    p.validate_policy(pol)
    exact = p.operation_scope(pol)  # original four EC229 signatures actually checked
    digest = write_private(out, pol, p.MAX_POLICY)
    return {'schema': 'ces.ec291.owner_docs_readback_policy.v1',
            'status': 'one_private_local_git_readback_configured_no_git_read_yet',
            'policy_sha256': digest, 'operation': exact,
            'original_ec229_write_grant_reused_for_read': False,
            'original_publisher_invoked': False,
            'production_or_remote_git_access': False}


def prepare_read_template(policy_file: str, policy_sha: str,
                          seconds: int, out: str) -> dict:
    p.need(type(seconds) is int and 1 <= seconds <= 35,
           'EC291_READ_TICKET_SECONDS_MUST_BE_1_TO_35')
    pol = p.load_policy(policy_file, policy_sha)
    op = p.operation_scope(pol)
    now = rec._time()
    body = {'schema': rec.READ_SCHEMA, 'mode': rec.MODE_DOCS,
            'operation_id': op['operation_sha256'],
            'target_sha256': op['target_sha256'],
            'original_grant_sha256': op['original_grant_sha256'],
            'inspection_nonce': secrets.token_hex(16),
            'receipt_epoch': pol['receipt_epoch'],
            'code_revision_sha256': rec.ACTIVE_CODE_SHA256,
            'permission': rec.READ_PERMISSION,
            'issued_at': now - 1, 'expires_at': now + seconds}
    write_private(out, {'schema': p.READ_TEMPLATE_SCHEMA, 'statement': body}, 4000)
    return {'schema': 'ces.ec291.original_ec230_read_template.v1',
            'statement_sha256': p.sha(p.canonical(body)),
            'operation_sha256': op['operation_sha256'],
            'git_ref_read_attempted': False, 'signed': False}


def sign_read_template(template_file: str, key_file: str, out: str) -> dict:
    template = io.read_doc(template_file, 4000, private=True)
    p.fields(template, {'schema', 'statement'}, 'EC291_READ_TEMPLATE_EXACT_FIELDS')
    p.need(template['schema'] == p.READ_TEMPLATE_SCHEMA and
           type(template['statement']) is dict,
           'EC291_READ_TEMPLATE_INVALID')
    p.old.private_file(key_file, 64)
    key = io.private_from_file(key_file)
    document = {'statement': template['statement'],
                'signature_hex': key.sign(rec.READ_DOMAIN +
                                          dp.canonical(template['statement'])).hex()}
    p.read_statement(document, p.old.public_hex(key))
    write_private(out, document, 4000)
    return {'schema': 'ces.ec291.original_ec230_read_grant.v1',
            'read_grant_sha256': p.sha(p.canonical(document)),
            'read_public_hex': p.old.public_hex(key),
            'git_ref_read_attempted': False}


def prepare_subject(policy_file: str, policy_sha: str, read_file: str,
                    uid: int, ttl: int, out: str) -> dict:
    pol = p.load_policy(policy_file, policy_sha)
    read = io.read_doc(read_file, 4000, private=True)
    subject = p.new_subject(pol, policy_sha, read, uid, ttl)
    write_private(out, subject, p.MAX_RPC)
    return {'schema': 'ces.ec291.unsigned_host_read_subject.v1',
            'subject_sha256': p.sha(p.canonical(subject)),
            'read_grant_sha256': subject['read_grant_sha256'],
            'git_ref_read_attempted': False}


def vote(role: str, subject_file: str, key_file: str, out: str) -> dict:
    p.need(role in ('custodian', 'inspector'), 'EC291_INVALID_HOST_VOTER_ROLE')
    subject = p.validate_subject(io.read_doc(subject_file, p.MAX_RPC, private=True))
    p.old.private_file(key_file, 64)
    key = io.private_from_file(key_file)
    document = {'schema': p.VOTE_SCHEMA, 'role': role,
                'subject_sha256': p.sha(p.canonical(subject)),
                'signer_public_hex': p.old.public_hex(key),
                'signature_ed25519': p.sign(role, subject, key)}
    write_private(out, document, 4000)
    return {'schema': 'ces.ec291.docs_offline_vote_completed.v1',
            'role': role, 'subject_sha256': document['subject_sha256'],
            'private_key_returned': False}


def assemble(subject_file: str, custodian_vote: str, inspector_vote: str,
             custodian_public_hex: str, inspector_public_hex: str,
             out: str) -> dict:
    subject = p.validate_subject(io.read_doc(subject_file, p.MAX_RPC, private=True))
    p.need(custodian_public_hex != inspector_public_hex,
           'EC291_TWO_DIFFERENT_HOST_APPROVERS_REQUIRED', 'permission_denied')
    sigs = {}
    for role, path, pub in (
        ('custodian', custodian_vote, custodian_public_hex),
        ('inspector', inspector_vote, inspector_public_hex)):
        entry = io.read_doc(path, 4000, private=True)
        p.fields(entry, {'schema', 'role', 'subject_sha256',
                         'signer_public_hex', 'signature_ed25519'},
                 'EC291_OFFLINE_VOTE_EXACT_FIELDS_REQUIRED')
        p.need(entry['schema'] == p.VOTE_SCHEMA and entry['role'] == role and
               entry['subject_sha256'] == p.sha(p.canonical(subject)) and
               entry['signer_public_hex'] == pub,
               'EC291_OFFLINE_VOTE_DIFFERENT_SUBJECT_OR_ROLE',
               'permission_denied')
        p.verify(role, subject, entry['signature_ed25519'], pub)
        sigs[role] = entry['signature_ed25519']
    grant = {'schema': p.GRANT_SCHEMA, 'subject': subject,
             'custodian_signature_ed25519': sigs['custodian'],
             'inspector_signature_ed25519': sigs['inspector']}
    write_private(out, grant, p.MAX_RPC)
    return {'schema': 'ces.ec291.two_vote_exact_host_read_grant.v1',
            'grant_sha256': p.sha(p.canonical(grant)),
            'git_ref_read_attempted': False}


def submit(*, socket_path: str, grant_file: str, read_grant_file: str,
           policy_sha: str, server_pub: str, timeout: float = 65) -> tuple[int, dict]:
    p.need(p.old.plain_abs(socket_path) and len(socket_path.encode()) < 100,
           'EC291_CLIENT_ABSOLUTE_UNIX_SOCKET_REQUIRED')
    p.need(type(policy_sha) is str and p.HEX.fullmatch(policy_sha) is not None,
           'EC291_CLIENT_POLICY_SHA_REQUIRED')
    io.pub_from_hex(server_pub)
    grant = io.read_doc(grant_file, p.MAX_RPC, private=True)
    read = io.read_doc(read_grant_file, 4000, private=True)
    p.fields(grant, {'schema', 'subject', 'custodian_signature_ed25519',
                     'inspector_signature_ed25519'},
             'EC291_CLIENT_TWO_VOTE_GRANT_REQUIRED')
    subject = p.validate_subject(grant['subject'])
    p.need(grant['schema'] == p.GRANT_SCHEMA and
           subject['policy_sha256'] == policy_sha and
           subject['read_grant_sha256'] == p.sha(p.canonical(read)),
           'EC291_CLIENT_AUTHORITY_OR_EC230_READ_GRANT_CHANGED',
           'permission_denied')
    req = {'schema': p.REQUEST_SCHEMA, 'nonce': secrets.token_hex(16),
           'grant': grant, 'read_grant': read}
    raw = p.canonical(req) + b'\n'
    p.need(len(raw) <= p.MAX_RPC, 'EC291_OUTBOUND_RPC_TOO_LARGE')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(socket_path)
            conn.sendall(raw)
            reply_raw = bytearray()
            while len(reply_raw) <= p.MAX_REPLY:
                part = conn.recv(min(4096, p.MAX_REPLY + 1 - len(reply_raw)))
                if not part:
                    break
                reply_raw.extend(part)
                if b'\n' in part:
                    break
    except (OSError, TimeoutError) as exc:
        raise p.HostError('EC291_SIGNED_REPLY_MISSING_INSPECT_HOST_AND_EC230_AUDITS_NO_RETRY') from exc
    p.need(0 < len(reply_raw) <= p.MAX_REPLY and
           reply_raw.endswith(b'\n') and reply_raw.count(b'\n') == 1,
           'EC291_TRUNCATED_OR_UNSIGNED_REPLY_UNKNOWN_NO_RETRY')
    try:
        reply = io.parse(bytes(reply_raw[:-1]), p.MAX_REPLY)
        result = p.verify_reply(reply, req, server_pub, policy_sha, int(time.time()))
    except (p.HostError, io.HostError, TypeError, ValueError, KeyError) as exc:
        raise p.HostError('EC291_UNTRUSTED_SERVER_REPLY_INSPECT_AUDITS_NO_RETRY') from exc
    proven = result.get('receipt_state') == 'VERIFIED_PRIVATE_LOCAL_REF_ONLY'
    return result['exit_code'], {'schema': p.RESULT_SCHEMA,
        'verified_server_signature': True, 'result': result, 'signed_reply': reply,
        'verified_private_local_git_ref_observed': proven,
        'private_git_only_not_production_publication': proven,
        'public_or_production_published': False,
        'original_docs_publish_retried': False, 'worktree_cleanup_attempted': False,
        'private_document_bytes_or_paths_returned': False,
        'automatic_git_read_or_publish_retry_allowed': False,
        'organization_signer_independence_verified': False}


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description='EC291 original EC230 private Docs Git read host')
    sub = ap.add_subparsers(dest='command', required=True)
    x = sub.add_parser('keygen-offline')
    x.add_argument('--private-out', required=True)
    x = sub.add_parser('prepare-policy')
    for name in ('job-file', 'audit-root', 'admission-root', 'read-public-hex',
                 'cleanup-public-hex', 'receipt-epoch', 'custodian-public-hex',
                 'inspector-public-hex', 'server-public-hex', 'out'):
        x.add_argument('--' + name, required=True,
                       type=int if name == 'receipt-epoch' else str)
    x.add_argument('--allowed-uid', action='append', required=True, type=int)
    x.add_argument('--enable-one-private-docs-readback', action='store_true')
    x = sub.add_parser('prepare-read-template')
    for name in ('policy-file', 'policy-sha256', 'ttl-seconds', 'out'):
        x.add_argument('--' + name, required=True,
                       type=int if name == 'ttl-seconds' else str)
    x = sub.add_parser('sign-read-offline')
    for name in ('template-file', 'private-key-file', 'out'):
        x.add_argument('--' + name, required=True)
    x = sub.add_parser('prepare-offline')
    for name in ('policy-file', 'policy-sha256', 'read-grant-file', 'uid',
                 'ttl-seconds', 'out'):
        x.add_argument('--' + name, required=True,
                       type=int if name in ('uid', 'ttl-seconds') else str)
    for role in ('custodian', 'inspector'):
        x = sub.add_parser('sign-' + role + '-offline')
        for name in ('subject-file', 'private-key-file', 'out'):
            x.add_argument('--' + name, required=True)
    x = sub.add_parser('assemble-offline')
    for name in ('subject-file', 'custodian-vote', 'inspector-vote',
                 'custodian-public-hex', 'inspector-public-hex', 'out'):
        x.add_argument('--' + name, required=True)
    x = sub.add_parser('serve')
    for name in ('socket', 'policy-file', 'policy-sha256', 'server-private-key'):
        x.add_argument('--' + name, required=True)
    x = sub.add_parser('submit')
    for name in ('socket', 'grant-file', 'read-grant-file', 'policy-sha256',
                 'server-public-hex'):
        x.add_argument('--' + name, required=True)
    x.add_argument('--pretty', action='store_true')
    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == 'keygen-offline':
            key = legacy_operator._keygen(args.private_out)
            outcome = {'schema': 'ces.ec291.offline_signer_key.v1',
                       'public_hex': key['public_hex'],
                       'private_key_returned': False}
        elif args.command == 'prepare-policy':
            outcome = prepare_policy(job_file=args.job_file,
                audit_root=args.audit_root, admission_root=args.admission_root,
                allowed_uids=args.allowed_uid,
                read_public_hex=args.read_public_hex,
                cleanup_public_hex=args.cleanup_public_hex,
                receipt_epoch=args.receipt_epoch,
                custodian_public_hex=args.custodian_public_hex,
                inspector_public_hex=args.inspector_public_hex,
                server_public_hex=args.server_public_hex,
                out=args.out, enable=args.enable_one_private_docs_readback)
        elif args.command == 'prepare-read-template':
            outcome = prepare_read_template(args.policy_file, args.policy_sha256,
                                             args.ttl_seconds, args.out)
        elif args.command == 'sign-read-offline':
            outcome = sign_read_template(args.template_file, args.private_key_file,
                                         args.out)
        elif args.command == 'prepare-offline':
            outcome = prepare_subject(args.policy_file, args.policy_sha256,
                args.read_grant_file, args.uid, args.ttl_seconds, args.out)
        elif args.command in ('sign-custodian-offline', 'sign-inspector-offline'):
            role = args.command.split('-')[1]
            outcome = vote(role, args.subject_file, args.private_key_file, args.out)
        elif args.command == 'assemble-offline':
            outcome = assemble(args.subject_file, args.custodian_vote,
                args.inspector_vote, args.custodian_public_hex,
                args.inspector_public_hex, args.out)
        elif args.command == 'serve':
            with daemon.DocsReceiptHost(path=args.socket,
                 policy_path=args.policy_file, policy_sha=args.policy_sha256,
                 private_key_file=args.server_private_key) as host:
                host.serve_forever(poll_interval=0.2)
            return 0
        elif args.command == 'submit':
            rc, outcome = submit(socket_path=args.socket,
                grant_file=args.grant_file,
                read_grant_file=args.read_grant_file,
                policy_sha=args.policy_sha256, server_pub=args.server_public_hex)
            print(json.dumps(outcome, sort_keys=True, ensure_ascii=True,
                             indent=2 if args.pretty else None,
                             separators=None if args.pretty else (',', ':')))
            return rc
        else:
            raise AssertionError('unreachable')
        print(p.canonical(outcome).decode('ascii'))
        return 0
    except (p.HostError, io.HostError, rec.ReceiptDenied, OSError, ValueError) as exc:
        code = exc.code if isinstance(exc, (p.HostError, io.HostError)) else \
            'EC291_OPERATOR_PRIVATE_INPUT_OR_ENVIRONMENT_UNAVAILABLE'
        status = exc.status if isinstance(exc, (p.HostError, io.HostError)) else 'unavailable'
        if status not in ('unavailable', 'invalid_input', 'permission_denied'):
            status = 'unavailable'
        denial = p.denial(code, status, attempted=args.command == 'submit')
        print(p.canonical(denial).decode('ascii'))
        return denial['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
