#!/usr/bin/env python3
"""EC290 operator: owner-private EC230 readback job, OFFLINE signers and Unix client.

A complete flow is deliberately split: original immutable report + trust and
separate provider GET credential -> exact unsigned read permit template ->
independent EC230 read signer -> two further independent short-lived host votes
-> one live host request -> verified signed observation or conservative unknown.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time
from dataclasses import asdict

from finding_query_host import protocol as io
from finding_query_host import operator as legacy_op
from report_publish_host import operator as prev_op
import delivery_authorization as da
import delivery_preview as dp
import publication_receipts as rec
from . import protocol as p, daemon


def write_private(path: str, doc: dict, limit: int) -> str:
    return prev_op.write_private(path, doc, limit)


def prepare_policy(*, job_file: str, trust_file: str, read_credential_file: str,
                   outbox_root: str, audit_root: str, admission_root: str,
                   allowed_uids: list[int], read_public_hex: str,
                   cleanup_public_hex: str, receipt_epoch: int,
                   custodian_public_hex: str, inspector_public_hex: str,
                   server_public_hex: str, out: str, enable: bool) -> dict:
    p.need(enable is True, 'EC290_EXPLICIT_PRIVATE_READBACK_OPT_IN_REQUIRED',
           'permission_denied')
    files = {'job': (job_file, p.old.MAX_JOB),
             'trust': (trust_file, p.old.MAX_TRUST),
             'read_credential': (read_credential_file, p.old.MAX_TOKEN)}
    sha = {key + '_sha256': p.sha(p.old.private_file(path, limit))
           for key, (path, limit) in files.items()}
    p.old.validate_job(io.parse(p.old.private_file(job_file, p.old.MAX_JOB),
                                p.old.MAX_JOB))
    p.old.validate_trust(io.parse(p.old.private_file(trust_file, p.old.MAX_TRUST),
                                  p.old.MAX_TRUST))
    for folder in (outbox_root, audit_root, admission_root):
        p.old.private_directory(folder)
    policy = {'schema': p.POLICY_SCHEMA,
        **{key + '_file': path for key, (path, _limit) in files.items()},
        **sha, 'outbox_root': outbox_root, 'audit_root': audit_root,
        'admission_root': admission_root,
        'allowed_uids': sorted(set(allowed_uids)),
        'read_public_hex': read_public_hex,
        'cleanup_public_hex': cleanup_public_hex,
        'receipt_epoch': receipt_epoch,
        'custodian_public_hex': custodian_public_hex,
        'inspector_public_hex': inspector_public_hex,
        'server_public_hex': server_public_hex,
        'original_receipt_code_sha256': rec.ACTIVE_CODE_SHA256,
        'original_publish_code_sha256': p.source_sha(),
        'host_code_sha256': p.host_sha(),
        'enable_one_private_report_readback': True}
    p.validate_policy(policy)
    # Reconstruct ORIGINAL trusted access, validate all 11 key roles, verify
    # sources and target, but never send an HTTP GET at provisioning time.
    operation = p.operation_scope(policy)
    policy_sha = write_private(out, policy, p.MAX_POLICY)
    return {'schema': 'ces.ec290.owner_policy_prepared.v1',
            'status': 'signed_readback_host_configured_no_provider_egress',
            'policy_sha256': policy_sha, 'operation': operation,
            'read_token_returned': False,
            'original_ec228_write_credential_loaded': False,
            'provider_readback_attempted': False}


def prepare_read_template(policy_file: str, policy_sha: str, seconds: int,
                          out: str) -> dict:
    p.need(type(seconds) is int and 1 <= seconds <= 35,
           'EC290_READ_GRANT_WINDOW_MUST_BE_1_TO_35_SECONDS')
    pol = p.load_policy(policy_file, policy_sha)
    ops = p.operation_scope(pol)
    now = rec._time()
    body = {'schema': rec.READ_SCHEMA, 'mode': rec.MODE_REPORT,
            'operation_id': ops['operation_sha256'],
            'target_sha256': ops['target_sha256'],
            'original_grant_sha256': ops['original_grant_sha256'],
            'inspection_nonce': secrets.token_hex(16),
            'receipt_epoch': pol['receipt_epoch'],
            'code_revision_sha256': rec.ACTIVE_CODE_SHA256,
            'permission': rec.READ_PERMISSION,
            'issued_at': now - 1, 'expires_at': now + seconds}
    doc = {'schema': p.READ_TEMPLATE_SCHEMA, 'statement': body}
    write_private(out, doc, 3000)
    return {'schema': 'ces.ec290.read_template_prepared.v1',
            'status': 'unsigned_precise_one_time_readback_not_executed',
            'statement_sha256': p.sha(p.canonical(body)),
            'operation_sha256': body['operation_id'],
            'issuer_not_impersonated': True, 'provider_get_attempted': False}


def sign_read_template(template_file: str, private_file: str, out: str) -> dict:
    template = io.read_doc(template_file, 3000, private=True)
    p.fields(template, {'schema', 'statement'}, 'EC290_READ_TEMPLATE_FIELDS_INVALID')
    p.need(template['schema'] == p.READ_TEMPLATE_SCHEMA and
           type(template['statement']) is dict,
           'EC290_EXACT_READ_TEMPLATE_REQUIRED')
    p.old.private_file(private_file, 64)
    key = io.private_from_file(private_file)
    signed = {'statement': template['statement'],
              'signature_hex': key.sign(rec.READ_DOMAIN +
                                        dp.canonical(template['statement'])).hex()}
    p.read_statement(signed, p.old.public_hex(key))
    write_private(out, signed, 4000)
    return {'schema': 'ces.ec290.read_grant_signed.v1',
            'status': 'independent_ec230_read_signer_approved_no_get',
            'grant_sha256': p.sha(p.canonical(signed)),
            'read_signer_public_hex': p.old.public_hex(key),
            'get_attempted': False}


def prepare_subject(policy_file: str, policy_sha: str, read_file: str,
                    uid: int, ttl: int, out: str) -> dict:
    pol = p.load_policy(policy_file, policy_sha)
    signed = io.read_doc(read_file, 4000, private=True)
    subject = p.new_subject(pol, policy_sha, signed, uid, ttl)
    write_private(out, subject, p.MAX_RPC)
    return {'schema': 'ces.ec290.short_host_subject.v1',
            'subject_sha256': p.sha(p.canonical(subject)),
            'read_grant_sha256': subject['read_grant_sha256'],
            'provider_get_attempted': False}


def vote(role: str, subject_file: str, key_file: str, out: str) -> dict:
    p.need(role in ('custodian', 'inspector'),
           'EC290_UNKNOWN_OFFLINE_ROLE')
    sub = p.validate_subject(io.read_doc(subject_file, p.MAX_RPC, private=True))
    p.old.private_file(key_file, 64)
    key = io.private_from_file(key_file)
    result = {'schema': p.VOTE_SCHEMA, 'role': role,
              'subject_sha256': p.sha(p.canonical(sub)),
              'signer_public_hex': p.old.public_hex(key),
              'signature_ed25519': p.sign(role, sub, key)}
    write_private(out, result, 4000)
    return {'schema': 'ces.ec290.offline_vote_prepared.v1', 'role': role,
            'subject_sha256': result['subject_sha256'], 'get_attempted': False}


def assemble(subject_file: str, custodian_vote: str, inspector_vote: str,
             custodian_public_hex: str, inspector_public_hex: str,
             out: str) -> dict:
    subject = p.validate_subject(io.read_doc(subject_file, p.MAX_RPC, private=True))
    p.need(custodian_public_hex != inspector_public_hex,
           'EC290_INDEPENDENT_HOST_APPROVERS_REQUIRED', 'permission_denied')
    signed: dict[str, str] = {}
    for role, filepath, pub in (
        ('custodian', custodian_vote, custodian_public_hex),
        ('inspector', inspector_vote, inspector_public_hex)):
        row = io.read_doc(filepath, 4000, private=True)
        p.fields(row, {'schema', 'role', 'subject_sha256',
                       'signer_public_hex', 'signature_ed25519'},
                 'EC290_VOTE_FIELDS_INVALID')
        p.need(row['schema'] == p.VOTE_SCHEMA and row['role'] == role and
               row['subject_sha256'] == p.sha(p.canonical(subject)) and
               row['signer_public_hex'] == pub,
               'EC290_OFFLINE_VOTE_SCOPE_OR_ROLE_DRIFT', 'permission_denied')
        p.verify(role, subject, row['signature_ed25519'], pub)
        signed[role] = row['signature_ed25519']
    grant = {'schema': p.GRANT_SCHEMA, 'subject': subject,
             'custodian_signature_ed25519': signed['custodian'],
             'inspector_signature_ed25519': signed['inspector']}
    write_private(out, grant, p.MAX_RPC)
    return {'schema': 'ces.ec290.two_vote_host_grant.v1',
            'status': 'ready_for_at_most_one_separate_private_receipt_get',
            'grant_sha256': p.sha(p.canonical(grant)), 'get_attempted': False}


def submit(*, socket_path: str, grant_file: str, read_grant_file: str,
           policy_sha: str, server_pub: str, timeout: float = 55) -> tuple[int, dict]:
    p.need(p.old.absolute(socket_path) and len(socket_path.encode()) < 100,
           'EC290_CLIENT_SOCKET_PATH_INVALID')
    p.need(type(policy_sha) is str and p.HEX.fullmatch(policy_sha) is not None,
           'EC290_CLIENT_POLICY_SHA_REQUIRED')
    io.pub_from_hex(server_pub)
    grant = io.read_doc(grant_file, p.MAX_RPC, private=True)
    read = io.read_doc(read_grant_file, 4000, private=True)
    p.fields(grant, {'schema', 'subject', 'custodian_signature_ed25519',
                     'inspector_signature_ed25519'}, 'EC290_CLIENT_GRANT_FIELDS_INVALID')
    sub = p.validate_subject(grant['subject'])
    p.need(grant['schema'] == p.GRANT_SCHEMA and
           sub['policy_sha256'] == policy_sha and
           sub['read_grant_sha256'] == p.sha(p.canonical(read)),
           'EC290_CLIENT_SIGNED_READ_SUBJECT_CHANGED', 'permission_denied')
    request = {'schema': p.REQUEST_SCHEMA, 'nonce': secrets.token_hex(16),
               'grant': grant, 'read_grant': read}
    raw = p.canonical(request) + b'\n'
    p.need(len(raw) <= p.MAX_RPC, 'EC290_CLIENT_RPC_TOO_LARGE')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(socket_path)
            sock.sendall(raw)
            response = bytearray()
            while len(response) <= p.MAX_REPLY:
                part = sock.recv(min(4096, p.MAX_REPLY + 1 - len(response)))
                if not part:
                    break
                response.extend(part)
                if b'\n' in part:
                    break
    except (OSError, TimeoutError) as exc:
        raise p.HostError('EC290_MISSING_REPLY_INSPECT_HOST_AND_EC230_AUDITS_NO_RETRY') from exc
    p.need(response.endswith(b'\n') and response.count(b'\n') == 1 and
           len(response) <= p.MAX_REPLY,
           'EC290_UNSIGNED_OR_TRUNCATED_READBACK_RESULT_UNKNOWN_NO_RETRY')
    try:
        reply = io.parse(bytes(response[:-1]), p.MAX_REPLY)
        result = p.verify_reply(reply, request, server_pub, policy_sha,
                                int(time.time()))
    except (p.HostError, io.HostError, TypeError, KeyError, ValueError) as exc:
        raise p.HostError('EC290_INVALID_HOST_SIGNATURE_INSPECT_AUDITS_NO_RETRY') from exc
    evidence = result.get('receipt_state') == 'SIGNED_PROVIDER_PRIVATE_TEST_RECORD_OBSERVED'
    return result['exit_code'], {'schema': p.RESULT_SCHEMA,
        'verified_server_signature': True, 'result': result, 'signed_reply': reply,
        'independent_private_provider_record_observed': evidence,
        'private_receipt_only_not_publication_confirmation': evidence,
        'public_or_production_published': False,
        'publish_retry_allowed': False,
        'automatic_provider_read_retry_allowed': False,
        'private_report_token_endpoint_or_markdown_returned': False,
        'physical_signer_independence_verified': False}


def parser() -> argparse.ArgumentParser:
    a = argparse.ArgumentParser(description='EC290 original EC230 readback host')
    sub = a.add_subparsers(dest='command', required=True)
    k = sub.add_parser('keygen-offline')
    k.add_argument('--private-out', required=True)
    k = sub.add_parser('prepare-policy')
    for arg in ('job-file', 'trust-file', 'read-credential-file', 'outbox-root', 'audit-root',
                'admission-root', 'read-public-hex', 'cleanup-public-hex',
                'receipt-epoch', 'custodian-public-hex', 'inspector-public-hex',
                'server-public-hex', 'out'):
        k.add_argument('--' + arg, required=True,
                       type=int if arg == 'receipt-epoch' else str)
    k.add_argument('--allowed-uid', action='append', type=int, required=True)
    k.add_argument('--enable-one-private-report-readback', action='store_true')
    k = sub.add_parser('prepare-read-template')
    for arg in ('policy-file', 'policy-sha256', 'ttl-seconds', 'out'):
        k.add_argument('--' + arg, required=True,
                       type=int if arg == 'ttl-seconds' else str)
    k = sub.add_parser('sign-read-offline')
    for arg in ('template-file', 'private-key-file', 'out'):
        k.add_argument('--' + arg, required=True)
    k = sub.add_parser('prepare-offline')
    for arg in ('policy-file', 'policy-sha256', 'read-grant-file', 'uid',
                'ttl-seconds', 'out'):
        k.add_argument('--' + arg, required=True,
                       type=int if arg in ('uid', 'ttl-seconds') else str)
    for role in ('custodian', 'inspector'):
        k = sub.add_parser('sign-' + role + '-offline')
        for arg in ('subject-file', 'private-key-file', 'out'):
            k.add_argument('--' + arg, required=True)
    k = sub.add_parser('assemble-offline')
    for arg in ('subject-file', 'custodian-vote', 'inspector-vote',
                'custodian-public-hex', 'inspector-public-hex', 'out'):
        k.add_argument('--' + arg, required=True)
    k = sub.add_parser('serve')
    for arg in ('socket', 'policy-file', 'policy-sha256', 'server-private-key'):
        k.add_argument('--' + arg, required=True)
    k = sub.add_parser('submit')
    for arg in ('socket', 'grant-file', 'read-grant-file', 'policy-sha256',
                'server-public-hex'):
        k.add_argument('--' + arg, required=True)
    k.add_argument('--pretty', action='store_true')
    return a


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    try:
        if a.command == 'keygen-offline':
            original = legacy_op._keygen(a.private_out)
            result = {'schema': 'ces.ec290.offline_role_key.v1',
                      'public_hex': original['public_hex'],
                      'private_key_returned': False}
        elif a.command == 'prepare-policy':
            result = prepare_policy(
                job_file=a.job_file, trust_file=a.trust_file,
                read_credential_file=a.read_credential_file,
                outbox_root=a.outbox_root, audit_root=a.audit_root,
                admission_root=a.admission_root, allowed_uids=a.allowed_uid,
                read_public_hex=a.read_public_hex,
                cleanup_public_hex=a.cleanup_public_hex,
                receipt_epoch=a.receipt_epoch,
                custodian_public_hex=a.custodian_public_hex,
                inspector_public_hex=a.inspector_public_hex,
                server_public_hex=a.server_public_hex,
                out=a.out, enable=a.enable_one_private_report_readback)
        elif a.command == 'prepare-read-template':
            result = prepare_read_template(a.policy_file, a.policy_sha256,
                                           a.ttl_seconds, a.out)
        elif a.command == 'sign-read-offline':
            result = sign_read_template(a.template_file, a.private_key_file, a.out)
        elif a.command == 'prepare-offline':
            result = prepare_subject(a.policy_file, a.policy_sha256,
                a.read_grant_file, a.uid, a.ttl_seconds, a.out)
        elif a.command.startswith('sign-'):
            role = a.command.split('-')[1]
            result = vote(role, a.subject_file, a.private_key_file, a.out)
        elif a.command == 'assemble-offline':
            result = assemble(a.subject_file, a.custodian_vote, a.inspector_vote,
                              a.custodian_public_hex, a.inspector_public_hex,
                              a.out)
        elif a.command == 'serve':
            with daemon.ReceiptHost(path=a.socket, policy_path=a.policy_file,
                                    policy_sha=a.policy_sha256,
                                    private_key_file=a.server_private_key) as host:
                host.serve_forever(poll_interval=0.20)
            return 0
        elif a.command == 'submit':
            rc, result = submit(socket_path=a.socket, grant_file=a.grant_file,
                read_grant_file=a.read_grant_file,
                policy_sha=a.policy_sha256, server_pub=a.server_public_hex)
            print(json.dumps(result, sort_keys=True, ensure_ascii=True,
                             indent=2 if a.pretty else None,
                             separators=None if a.pretty else (',', ':')))
            return rc
        else:
            raise AssertionError('unreachable')
        print(p.canonical(result).decode('ascii'))
        return 0
    except (p.HostError, io.HostError, rec.ReceiptDenied, OSError, ValueError) as exc:
        code = exc.code if isinstance(exc, (p.HostError, io.HostError)) else \
            'EC290_OPERATOR_PRECONDITION_OR_PRIVATE_IO_FAILED'
        status = exc.status if isinstance(exc, (p.HostError, io.HostError)) else 'unavailable'
        if status not in ('unavailable', 'invalid_input', 'permission_denied'):
            status = 'unavailable'
        result = p.denial(code, status, attempted=a.command == 'submit')
        print(p.canonical(result).decode('ascii'))
        return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
