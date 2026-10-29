#!/usr/bin/env python3
"""EC292 operator: four-stage original + new independent cleanup approval.

The original EC291 private readback result must be captured as a 0600 complete
signed JSON wrapper. This tool never copies repository data, cleanup source
paths, private keys or worktree contents onto the host socket.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time

from ec279_finding_query_host import protocol as io
from ec279_finding_query_host import operator as keytool
from ec285_docs_sandbox_host import operator as original_operator
import delivery_preview as dp
import publication_receipts as rec
from . import protocol as p, daemon


def write_private(path: str, document: dict, limit: int) -> str:
    p.need(p.old.plain_abs(path), 'EC292_PRIVATE_OUTPUT_ABSOLUTE_PATH_REQUIRED')
    return original_operator.create_private(path, document, limit)


def prepare_policy(*, ec291_policy_file: str, ec291_policy_sha256: str,
                   readback_result_file: str, admission_root: str,
                   allowed_uids: list[int], cleanup_custodian_public_hex: str,
                   independent_reviewer_public_hex: str,
                   server_public_hex: str, out: str, enable: bool) -> dict:
    p.need(enable is True, 'EC292_EXPLICIT_WORKTREE_REMOVAL_OPT_IN_REQUIRED',
           'permission_denied')
    previous = p.prior.load_policy(ec291_policy_file, ec291_policy_sha256)
    policy = {'schema': p.POLICY_SCHEMA,
              'ec291_policy_file': ec291_policy_file,
              'ec291_policy_sha256': ec291_policy_sha256,
              'readback_result_file': readback_result_file,
              'admission_root': admission_root,
              'allowed_uids': sorted(set(allowed_uids)),
              'cleanup_custodian_public_hex': cleanup_custodian_public_hex,
              'independent_reviewer_public_hex': independent_reviewer_public_hex,
              'server_public_hex': server_public_hex,
              'enable_one_clean_linked_worktree': True,
              'job_sha256': previous['job_sha256'],
              'original_receipt_code_sha256': rec.ACTIVE_CODE_SHA256,
              'original_docs_code_sha256': p.prior.original_sha(),
              'ec291_host_code_sha256': p.prior.host_sha(),
              'host_code_sha256': p.host_sha()}
    p.validate_policy(policy)
    original = p.prior.operation_scope(previous)
    digest = write_private(out, policy, p.MAX_POLICY)
    return {'schema': 'ces.ec292.owner_cleanup_policy.v1',
            'status': 'one_worktree_cleanup_configured_not_executed',
            'policy_sha256': digest, 'operation': original,
            'private_git_ref_removed': False, 'local_worktree_removed': False,
            'original_publish_replayed': False}


def prepare_cleanup_template(policy_file: str, policy_sha: str,
                             seconds: int, out: str) -> dict:
    p.need(type(seconds) is int and 1 <= seconds <= 35,
           'EC292_ORIGINAL_CLEANUP_TTL_MUST_BE_1_TO_35')
    policy = p.load_policy(policy_file, policy_sha)
    scope = p.exact_snapshot(policy)
    previous = p.parent_policy(policy)
    now = rec._time()
    body = {'schema': rec.CLEAN_SCHEMA, 'mode': rec.MODE_DOCS,
            'operation_id': scope['operation_sha256'],
            'target_sha256': scope['target_sha256'],
            'original_grant_sha256': scope['original_grant_sha256'],
            'inspection_id': scope['inspection_id'],
            'observation_sha256': scope['observation_sha256'],
            'candidate_commit_sha': scope['candidate_commit_sha'],
            'worktree_inode': scope['worktree_inode'],
            'cleanup_epoch': previous['receipt_epoch'],
            'permission': rec.CLEAN_PERMISSION,
            'code_revision_sha256': rec.ACTIVE_CODE_SHA256,
            'issued_at': now - 1, 'expires_at': now + seconds}
    write_private(out, {'schema': p.TEMPLATE_SCHEMA, 'statement': body}, 4000)
    return {'schema': 'ces.ec292.original_ec230_cleanup_template.v1',
            'statement_sha256': p.sha(p.canonical(body)),
            'inspection_id': scope['inspection_id'],
            'candidate_commit_sha': scope['candidate_commit_sha'],
            'worktree_inode': scope['worktree_inode'],
            'signed': False, 'cleanup_executed': False}


def sign_cleanup_template(template_file: str, key_file: str, out: str) -> dict:
    template = io.read_doc(template_file, 4000, private=True)
    p.fields(template, {'schema', 'statement'},
             'EC292_CLEANUP_TEMPLATE_EXACT_FIELDS_REQUIRED')
    body = template['statement']
    p.need(template['schema'] == p.TEMPLATE_SCHEMA and type(body) is dict and
           body.get('schema') == rec.CLEAN_SCHEMA and
           body.get('mode') == rec.MODE_DOCS and
           body.get('permission') == rec.CLEAN_PERMISSION and
           body.get('code_revision_sha256') == rec.ACTIVE_CODE_SHA256,
           'EC292_ONLY_EC230_LOCAL_WORKTREE_CLEANUP_CAN_BE_SIGNED')
    p.old.private_file(key_file, 64)
    key = io.private_from_file(key_file)
    document = {'statement': body,
                'signature_hex': key.sign(rec.CLEAN_DOMAIN + dp.canonical(body)).hex()}
    # The offline signer need not have the Git repository, job or EC291 host.
    rec._signed(rec.da.SignedAuthorizationStatement(body, document['signature_hex']),
                bytes.fromhex(p.old.public_hex(key)), rec.CLEAN_DOMAIN,
                {'schema', 'mode', 'operation_id', 'target_sha256',
                 'original_grant_sha256', 'inspection_id', 'observation_sha256',
                 'candidate_commit_sha', 'worktree_inode', 'cleanup_epoch',
                 'permission', 'code_revision_sha256', 'issued_at', 'expires_at'},
                'CLEANUP_GRANT')
    rec._window(body, rec._time())
    write_private(out, document, 4000)
    return {'schema': 'ces.ec292.original_ec230_cleanup_grant.v1',
            'cleanup_grant_sha256': p.sha(p.canonical(document)),
            'cleanup_public_hex': p.old.public_hex(key),
            'worktree_removed': False}


def prepare_subject(policy_file: str, policy_sha: str, cleanup_file: str,
                    uid: int, seconds: int, out: str) -> dict:
    pol = p.load_policy(policy_file, policy_sha)
    cleanup = io.read_doc(cleanup_file, 4000, private=True)
    subject = p.new_subject(pol, policy_sha, cleanup, uid, seconds)
    write_private(out, subject, p.MAX_RPC)
    return {'schema': 'ces.ec292.unsigned_exact_cleanup_host_subject.v1',
            'subject_sha256': p.sha(p.canonical(subject)),
            'cleanup_grant_sha256': subject['cleanup_grant_sha256'],
            'worktree_removed': False}


def vote(role: str, subject_file: str, key_file: str, out: str) -> dict:
    p.need(role in ('custodian', 'reviewer'),
           'EC292_INVALID_INDEPENDENT_HOST_APPROVER_ROLE')
    subject = p.validate_subject(io.read_doc(subject_file, p.MAX_RPC, private=True))
    p.old.private_file(key_file, 64)
    key = io.private_from_file(key_file)
    document = {'schema': p.VOTE_SCHEMA, 'role': role,
                'subject_sha256': p.sha(p.canonical(subject)),
                'signer_public_hex': p.old.public_hex(key),
                'signature_ed25519': p.sign(role, subject, key)}
    write_private(out, document, 4000)
    return {'schema': 'ces.ec292.cleanup_offline_vote_completed.v1',
            'role': role, 'subject_sha256': document['subject_sha256'],
            'worktree_removed': False}


def assemble(subject_file: str, custodian_vote: str, reviewer_vote: str,
             custodian_public_hex: str, reviewer_public_hex: str,
             out: str) -> dict:
    subject = p.validate_subject(io.read_doc(subject_file, p.MAX_RPC, private=True))
    p.need(custodian_public_hex != reviewer_public_hex,
           'EC292_TWO_DIFFERENT_APPROVERS_REQUIRED', 'permission_denied')
    signatures = {}
    for role, path, public in (
        ('custodian', custodian_vote, custodian_public_hex),
        ('reviewer', reviewer_vote, reviewer_public_hex)):
        entry = io.read_doc(path, 4000, private=True)
        p.fields(entry, {'schema', 'role', 'subject_sha256', 'signer_public_hex',
                         'signature_ed25519'},
                 'EC292_OFFLINE_VOTE_EXACT_FIELDS_REQUIRED')
        p.need(entry['schema'] == p.VOTE_SCHEMA and entry['role'] == role and
               entry['subject_sha256'] == p.sha(p.canonical(subject)) and
               entry['signer_public_hex'] == public,
               'EC292_HOST_VOTES_MUST_SIGN_SAME_SUBJECT_AND_ROLES',
               'permission_denied')
        p.verify(role, subject, entry['signature_ed25519'], public)
        signatures[role] = entry['signature_ed25519']
    grant = {'schema': p.GRANT_SCHEMA, 'subject': subject,
             'custodian_signature_ed25519': signatures['custodian'],
             'reviewer_signature_ed25519': signatures['reviewer']}
    write_private(out, grant, p.MAX_RPC)
    return {'schema': 'ces.ec292.two_vote_cleanup_host_grant.v1',
            'grant_sha256': p.sha(p.canonical(grant)), 'worktree_removed': False}


def submit(*, socket_path: str, grant_file: str, cleanup_grant_file: str,
           policy_sha: str, server_pub: str,
           timeout: float = 65) -> tuple[int, dict]:
    p.need(p.old.plain_abs(socket_path) and len(socket_path.encode()) < 100,
           'EC292_ABSOLUTE_UNIX_SOCKET_REQUIRED')
    p.need(type(policy_sha) is str and p.HEX.fullmatch(policy_sha) is not None,
           'EC292_POLICY_DIGEST_REQUIRED')
    io.pub_from_hex(server_pub)
    grant = io.read_doc(grant_file, p.MAX_RPC, private=True)
    cleanup = io.read_doc(cleanup_grant_file, 4000, private=True)
    p.fields(grant, {'schema', 'subject', 'custodian_signature_ed25519',
                     'reviewer_signature_ed25519'},
             'EC292_CLIENT_TWO_VOTE_GRANT_REQUIRED')
    subject = p.validate_subject(grant['subject'])
    p.need(grant['schema'] == p.GRANT_SCHEMA and
           subject['policy_sha256'] == policy_sha and
           subject['cleanup_grant_sha256'] == p.sha(p.canonical(cleanup)),
           'EC292_CLIENT_AUTHORITIES_OR_CLEANUP_DOCUMENT_DRIFT',
           'permission_denied')
    request = {'schema': p.REQUEST_SCHEMA, 'nonce': secrets.token_hex(16),
               'grant': grant, 'cleanup_grant': cleanup}
    raw = p.canonical(request) + b'\n'
    p.need(len(raw) <= p.MAX_RPC, 'EC292_CLIENT_RPC_EXCEEDS_LIMIT')
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
        raise p.HostError('EC292_ACK_MISSING_INSPECT_BOTH_JOURNALS_NO_RETRY') from exc
    p.need(0 < len(reply_raw) <= p.MAX_REPLY and
           reply_raw.endswith(b'\n') and reply_raw.count(b'\n') == 1,
           'EC292_TRUNCATED_UNSIGNED_ACK_MANUAL_RECONCILIATION_REQUIRED')
    try:
        reply = io.parse(bytes(reply_raw[:-1]), p.MAX_REPLY)
        result = p.verify_reply(reply, request, server_pub, policy_sha, int(time.time()))
    except (p.HostError, io.HostError, TypeError, ValueError, KeyError) as exc:
        raise p.HostError('EC292_UNVERIFIED_HOST_ACK_MANUAL_RECONCILIATION') from exc
    confirmed = result.get('local_worktree_cleanup_confirmed') is True and \
                result.get('reason_code') == \
                'PUBLICATION_RECEIPT_VERIFIED_LOCAL_WORKTREE_REMOVED_KEEP_REF_AND_JOURNALS'
    return result['exit_code'], {'schema': p.RESULT_SCHEMA,
        'verified_server_signature': True, 'result': result,
        'signed_reply': reply,
        'verified_exact_linked_worktree_removed': confirmed,
        'original_private_bare_ref_retained_locally': confirmed,
        'original_ec229_journals_retained': True,
        'public_or_production_published': False,
        'original_docs_publish_retried': False,
        'remote_git_ref_or_original_source_modified': False,
        'automatic_cleanup_or_publish_retry_allowed': False,
        'organization_signer_independence_verified': False}


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description='EC292 independently authorized EC230 cleanup host')
    sub = ap.add_subparsers(dest='command', required=True)
    x = sub.add_parser('keygen-offline')
    x.add_argument('--private-out', required=True)
    x = sub.add_parser('prepare-policy')
    for name in ('ec291-policy-file', 'ec291-policy-sha256',
                 'readback-result-file', 'admission-root',
                 'cleanup-custodian-public-hex',
                 'independent-reviewer-public-hex', 'server-public-hex', 'out'):
        x.add_argument('--' + name, required=True)
    x.add_argument('--allowed-uid', action='append', required=True, type=int)
    x.add_argument('--enable-one-clean-linked-worktree', action='store_true')
    x = sub.add_parser('prepare-cleanup-template')
    for name in ('policy-file', 'policy-sha256', 'ttl-seconds', 'out'):
        x.add_argument('--' + name, required=True,
                       type=int if name == 'ttl-seconds' else str)
    x = sub.add_parser('sign-cleanup-offline')
    for name in ('template-file', 'private-key-file', 'out'):
        x.add_argument('--' + name, required=True)
    x = sub.add_parser('prepare-offline')
    for name in ('policy-file', 'policy-sha256', 'cleanup-grant-file',
                 'uid', 'ttl-seconds', 'out'):
        x.add_argument('--' + name, required=True,
                       type=int if name in ('uid', 'ttl-seconds') else str)
    for role in ('custodian', 'reviewer'):
        x = sub.add_parser('sign-' + role + '-offline')
        for name in ('subject-file', 'private-key-file', 'out'):
            x.add_argument('--' + name, required=True)
    x = sub.add_parser('assemble-offline')
    for name in ('subject-file', 'custodian-vote', 'reviewer-vote',
                 'custodian-public-hex', 'reviewer-public-hex', 'out'):
        x.add_argument('--' + name, required=True)
    x = sub.add_parser('serve')
    for name in ('socket', 'policy-file', 'policy-sha256', 'server-private-key'):
        x.add_argument('--' + name, required=True)
    x = sub.add_parser('submit')
    for name in ('socket', 'grant-file', 'cleanup-grant-file',
                 'policy-sha256', 'server-public-hex'):
        x.add_argument('--' + name, required=True)
    x.add_argument('--pretty', action='store_true')
    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == 'keygen-offline':
            key = keytool._keygen(args.private_out)
            outcome = {'schema': 'ces.ec292.offline_signer_key.v1',
                       'public_hex': key['public_hex'], 'private_key_returned': False}
        elif args.command == 'prepare-policy':
            outcome = prepare_policy(ec291_policy_file=args.ec291_policy_file,
                ec291_policy_sha256=args.ec291_policy_sha256,
                readback_result_file=args.readback_result_file,
                admission_root=args.admission_root, allowed_uids=args.allowed_uid,
                cleanup_custodian_public_hex=args.cleanup_custodian_public_hex,
                independent_reviewer_public_hex=args.independent_reviewer_public_hex,
                server_public_hex=args.server_public_hex, out=args.out,
                enable=args.enable_one_clean_linked_worktree)
        elif args.command == 'prepare-cleanup-template':
            outcome = prepare_cleanup_template(args.policy_file,
                        args.policy_sha256, args.ttl_seconds, args.out)
        elif args.command == 'sign-cleanup-offline':
            outcome = sign_cleanup_template(args.template_file,
                                            args.private_key_file, args.out)
        elif args.command == 'prepare-offline':
            outcome = prepare_subject(args.policy_file, args.policy_sha256,
                        args.cleanup_grant_file, args.uid, args.ttl_seconds, args.out)
        elif args.command in ('sign-custodian-offline', 'sign-reviewer-offline'):
            role = args.command.split('-')[1]
            outcome = vote(role, args.subject_file, args.private_key_file, args.out)
        elif args.command == 'assemble-offline':
            outcome = assemble(args.subject_file, args.custodian_vote,
                args.reviewer_vote, args.custodian_public_hex,
                args.reviewer_public_hex, args.out)
        elif args.command == 'serve':
            with daemon.CleanupHost(path=args.socket,
                 policy_path=args.policy_file, policy_sha=args.policy_sha256,
                 private_key_file=args.server_private_key) as host:
                host.serve_forever(poll_interval=0.2)
            return 0
        elif args.command == 'submit':
            rc, outcome = submit(socket_path=args.socket,
                grant_file=args.grant_file,
                cleanup_grant_file=args.cleanup_grant_file,
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
            'EC292_OPERATOR_PRIVATE_INPUT_OR_ENVIRONMENT_UNAVAILABLE'
        status = exc.status if isinstance(exc, (p.HostError, io.HostError)) else 'unavailable'
        if status not in ('unavailable', 'invalid_input', 'permission_denied'):
            status = 'unavailable'
        result = p.denial(code, status, attempted=args.command == 'submit')
        print(p.canonical(result).decode('ascii'))
        return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
