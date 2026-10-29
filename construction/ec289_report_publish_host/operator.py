#!/usr/bin/env python3
"""EC289 provisioning, separated offline signers and bounded signed socket client.

The user-facing client sees ONLY precise signed metadata and always refuses
automatic retry, even if network or host response is lost before its receipt.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time

from ec279_finding_query_host import operator as old_operator
from ec279_finding_query_host import protocol as io
from . import daemon, protocol as p


def write_private(path: str, doc: dict, limit: int) -> str:
    p.private_parent(path)
    raw = p.canonical(doc) + b'\n'
    p.need(len(raw) <= limit, 'EC289_PRIVATE_OUTPUT_TOO_LARGE')
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        parent = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError as exc:
        raise p.HostError('EC289_PRIVATE_OUTPUT_CREATE_OR_DURABILITY_FAILED') from exc
    finally:
        if fd is not None:
            os.close(fd)
    return p.digest(raw)


def prepare_job(source_json: str, out: str) -> dict:
    job = io.parse(p.private_file(source_json, p.MAX_JOB), p.MAX_JOB)
    req = p.validate_job(job)
    sha = write_private(out, job, p.MAX_JOB)
    return {'schema': 'ces.ec289.private_job_prepared.v1',
            'status': 'exact_original_report_job_private_not_published',
            'job_sha256': sha, 'report_ref_sha256': p.digest(req.report_ref.encode()),
            'rendered_markdown_sha256': req.rendered_sha256,
            'original_grant_sha256': p.digest(p.canonical(
                {'statement': req.side_effect_grant.statement,
                 'signature_hex': req.side_effect_grant.signature_hex})),
            'markdown_or_credential_returned': False,
            'provider_network_requested': False}


def prepare_policy(*, job_file: str, trust_file: str, credential_file: str,
                   outbox_root: str, admission_root: str, allowed_uids: list[int],
                   custodian_pub: str, publisher_pub: str, server_pub: str,
                   out: str, enable: bool) -> dict:
    p.need(enable is True, 'EC289_EXPLICIT_PRIVATE_PUBLISH_OPT_IN_REQUIRED',
           'permission_denied')
    job_raw = p.private_file(job_file, p.MAX_JOB)
    trust_raw = p.private_file(trust_file, p.MAX_TRUST)
    cred_raw = p.private_file(credential_file, p.MAX_TOKEN)
    req = p.validate_job(io.parse(job_raw, p.MAX_JOB))
    trust = p.validate_trust(io.parse(trust_raw, p.MAX_TRUST))
    p.private_directory(outbox_root)
    p.private_directory(admission_root)
    p.need(len(set(p.trust_keys(trust) + [custodian_pub, publisher_pub, server_pub])) == 9,
           'EC289_NINE_UNIQUE_ROLE_KEYS_REQUIRED')
    policy = {'schema': p.POLICY_SCHEMA,
              'job_file': job_file, 'job_sha256': p.digest(job_raw),
              'trust_file': trust_file, 'trust_sha256': p.digest(trust_raw),
              'credential_file': credential_file,
              'credential_sha256': p.digest(cred_raw),
              'outbox_root': outbox_root, 'admission_root': admission_root,
              'allowed_uids': sorted(set(allowed_uids)),
              'custodian_issuer_public_hex': custodian_pub,
              'publisher_issuer_public_hex': publisher_pub,
              'server_public_hex': server_pub,
              'original_backend_sha256': p.backend_sha(),
              'host_backend_sha256': p.host_code_sha(),
              'enable_one_private_test_publication': True}
    p.validate_policy(policy)
    # Original type constructor enforces *all* original six-key independence,
    # private sandbox HTTPS endpoint, and no mock adapter in the real path.
    p.build_publisher(trust, p.load_credential(policy), outbox_root)
    sha = write_private(out, policy, p.MAX_POLICY)
    return {'schema': 'ces.ec289.private_publish_policy_prepared.v1',
            'status': 'owner_policy_written_without_provider_egress',
            'policy_sha256': sha,
            'original_backend_sha256': policy['original_backend_sha256'],
            'host_backend_sha256': policy['host_backend_sha256'],
            'original_publish_grant_sha256': p.job_pins(policy, req)[
                'original_publish_grant_sha256'],
            'credential_or_endpoint_returned': False,
            'publication_attempted': False}


def prepare_subject(policy_file: str, sha: str, uid: int,
                    ttl: int, out: str) -> dict:
    pol = p.load_policy(policy_file, sha)
    job = p.load_job(pol)
    p.load_trust(pol)
    p.load_credential(pol)
    p.need(uid in pol['allowed_uids'], 'EC289_UID_NOT_ALLOWLISTED',
           'permission_denied')
    sub = p.new_subject(uid, sha, p.job_pins(pol, job), ttl)
    io.write_exclusive(out, sub)
    return {'schema': 'ces.ec289.offline_subject_prepared.v1',
            'status': 'exact_private_publish_subject_not_published',
            'subject_sha256': p.digest(p.canonical(sub)),
            'network_requested': False}


def vote(role: str, subject_file: str, key_file: str, out: str) -> dict:
    sub = p.validate_subject(io.read_doc(subject_file, p.MAX_RPC))
    p.private_file(key_file, 64)
    key = io.private_from_file(key_file)
    v = {'schema': p.VOTE_SCHEMA, 'role': role,
         'subject_sha256': p.digest(p.canonical(sub)),
         'signer_public_hex': p.public_hex(key),
         'signature_ed25519': p.sign(role, sub, key)}
    io.write_exclusive(out, v)
    return {'schema': 'ces.ec289.offline_vote_created.v1',
            'role': role, 'subject_sha256': v['subject_sha256'],
            'publication_attempted': False}


def assemble(subject_file: str, custodian_vote: str, publisher_vote: str,
             custodian_pub: str, publisher_pub: str, out: str) -> dict:
    sub = p.validate_subject(io.read_doc(subject_file, p.MAX_RPC))
    p.need(custodian_pub != publisher_pub,
           'EC289_INDEPENDENT_VOTE_KEYS_REQUIRED', 'permission_denied')
    votes = {}
    for role, path, pub in (
        ('custodian', custodian_vote, custodian_pub),
        ('publisher', publisher_vote, publisher_pub),
    ):
        row = io.read_doc(path, p.MAX_RPC)
        p.keys(row, {'schema', 'role', 'subject_sha256', 'signer_public_hex',
                     'signature_ed25519'}, 'EC289_OFFLINE_VOTE_FIELDS_INVALID')
        p.need(row['schema'] == p.VOTE_SCHEMA and row['role'] == role and
               row['subject_sha256'] == p.digest(p.canonical(sub)) and
               row['signer_public_hex'] == pub,
               'EC289_OFFLINE_VOTE_ROLE_OR_SOURCE_CHANGED', 'permission_denied')
        p.verify(role, sub, row['signature_ed25519'], pub)
        votes[role] = row['signature_ed25519']
    grant = {'schema': p.GRANT_SCHEMA, 'subject': sub,
             'custodian_signature_ed25519': votes['custodian'],
             'publisher_signature_ed25519': votes['publisher']}
    io.write_exclusive(out, grant)
    return {'schema': 'ces.ec289.two_vote_grant_assembled.v1',
            'status': 'two_independent_votes_assembled_not_published',
            'grant_sha256': p.digest(p.canonical(grant)),
            'publication_attempted': False}


def submit(*, socket_path: str, grant_file: str,
           policy_sha: str, server_pub: str, timeout: float = 75
           ) -> tuple[int, dict]:
    p.need(p.absolute(socket_path) and len(socket_path.encode()) < 100,
           'EC289_UNIX_SOCKET_PATH_INVALID')
    p.need(type(policy_sha) is str and p.HEX.fullmatch(policy_sha) is not None,
           'EC289_CLIENT_POLICY_SHA_INVALID')
    io.pub_from_hex(server_pub)
    grant = io.read_doc(grant_file, p.MAX_RPC)
    p.keys(grant, {'schema', 'subject', 'custodian_signature_ed25519',
                   'publisher_signature_ed25519'}, 'EC289_CLIENT_GRANT_INVALID')
    p.need(grant['schema'] == p.GRANT_SCHEMA,
           'EC289_CLIENT_GRANT_SCHEMA_INVALID')
    sub = p.validate_subject(grant['subject'])
    p.need(sub['policy_sha256'] == policy_sha,
           'EC289_CLIENT_POLICY_SCOPE_CHANGED', 'permission_denied')
    req = {'schema': p.REQUEST_SCHEMA, 'nonce': secrets.token_hex(16),
           'grant': grant}
    raw = p.canonical(req) + b'\n'
    p.need(len(raw) <= p.MAX_RPC, 'EC289_RPC_TOO_LARGE')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(socket_path)
            sock.sendall(raw)
            out = bytearray()
            while len(out) <= p.MAX_REPLY:
                part = sock.recv(min(4096, p.MAX_REPLY + 1 - len(out)))
                if not part:
                    break
                out.extend(part)
                if b'\n' in part:
                    break
    except (OSError, TimeoutError) as exc:
        raise p.HostError('EC289_SOCKET_OR_PUBLISH_OUTCOME_UNKNOWN_INSPECT_TWO_LEDGERS') from exc
    p.need(out.endswith(b'\n') and out.count(b'\n') == 1 and
           len(out) <= p.MAX_REPLY,
           'EC289_MISSING_REPLY_OUTCOME_UNKNOWN_NO_RETRY')
    try:
        reply = io.parse(bytes(out[:-1]), p.MAX_REPLY)
        result = p.verify_reply(reply, req, server_pub,
                                policy_sha, int(time.time()))
    except (p.HostError, io.HostError, ValueError, TypeError, KeyError) as exc:
        raise p.HostError('EC289_UNVERIFIED_REPLY_PUBLISH_OUTCOME_UNKNOWN_NO_RETRY') from exc
    unknown = (result.get('publication_outcome_unknown') is True or
               (result.get('claim_committed') is True and
                result.get('publication_state') != 'SUBMISSION_UNCONFIRMED'))
    return result['exit_code'], {
        'schema': p.RESULT_SCHEMA, 'verified_server_signature': True,
        'result': result, 'signed_reply': reply,
        'publication_outcome_unknown': unknown,
        'provider_http_only_not_publication':
            result.get('publication_state') == 'SUBMISSION_UNCONFIRMED',
        'published_or_remote_visibility_verified': False,
        'private_markdown_endpoint_or_credential_returned': False,
        'automatic_publish_retry_allowed': False,
        'independent_real_organizational_humans_verified_by_ces': False}


def parser() -> argparse.ArgumentParser:
    a = argparse.ArgumentParser(description='EC289 original EC228 private report publish host')
    sub = a.add_subparsers(dest='command', required=True)
    k = sub.add_parser('keygen-offline')
    k.add_argument('--private-out', required=True)
    k = sub.add_parser('prepare-job')
    k.add_argument('--source-json', required=True)
    k.add_argument('--out', required=True)
    k = sub.add_parser('inspect-job')
    k.add_argument('--job-file', required=True)
    k = sub.add_parser('prepare-policy')
    for option in ('job-file', 'trust-file', 'credential-file', 'outbox-root',
                   'admission-root', 'custodian-public-hex', 'publisher-public-hex',
                   'server-public-hex', 'out'):
        k.add_argument('--' + option, required=True)
    k.add_argument('--allowed-uid', action='append', type=int, required=True)
    k.add_argument('--enable-one-private-test-publish', action='store_true')
    k = sub.add_parser('prepare-offline')
    for option in ('policy-file', 'policy-sha256', 'uid', 'ttl-seconds', 'out'):
        k.add_argument('--' + option, required=True,
                       type=int if option in ('uid', 'ttl-seconds') else str)
    for role in ('custodian', 'publisher'):
        k = sub.add_parser('sign-' + role + '-offline')
        for option in ('subject-file', 'private-key-file', 'out'):
            k.add_argument('--' + option, required=True)
    k = sub.add_parser('assemble-offline')
    for option in ('subject-file', 'custodian-vote', 'publisher-vote',
                   'custodian-public-hex', 'publisher-public-hex', 'out'):
        k.add_argument('--' + option, required=True)
    k = sub.add_parser('serve')
    for option in ('socket', 'policy-file', 'policy-sha256', 'server-private-key'):
        k.add_argument('--' + option, required=True)
    k = sub.add_parser('submit')
    for option in ('socket', 'grant-file', 'policy-sha256', 'server-public-hex'):
        k.add_argument('--' + option, required=True)
    k.add_argument('--pretty', action='store_true')
    return a


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    try:
        if a.command == 'keygen-offline':
            output = old_operator._keygen(a.private_out)
            result = {'schema': 'ces.ec289.offline_keygen.v1',
                      'public_hex': output['public_hex'],
                      'private_key_returned': False}
        elif a.command == 'prepare-job':
            result = prepare_job(a.source_json, a.out)
        elif a.command == 'inspect-job':
            raw = p.private_file(a.job_file, p.MAX_JOB)
            job = p.validate_job(io.parse(raw, p.MAX_JOB))
            result = {'schema': 'ces.ec289.private_job_inspection.v1',
                      'status': 'exact_private_job_not_published',
                      'job_sha256': p.digest(raw),
                      'rendered_markdown_sha256': job.rendered_sha256,
                      'private_report_text_returned': False}
        elif a.command == 'prepare-policy':
            result = prepare_policy(
                job_file=a.job_file, trust_file=a.trust_file,
                credential_file=a.credential_file,
                outbox_root=a.outbox_root, admission_root=a.admission_root,
                allowed_uids=a.allowed_uid,
                custodian_pub=a.custodian_public_hex,
                publisher_pub=a.publisher_public_hex,
                server_pub=a.server_public_hex, out=a.out,
                enable=a.enable_one_private_test_publish)
        elif a.command == 'prepare-offline':
            result = prepare_subject(a.policy_file, a.policy_sha256,
                                     a.uid, a.ttl_seconds, a.out)
        elif a.command.startswith('sign-'):
            role = a.command.split('-')[1]
            result = vote(role, a.subject_file, a.private_key_file, a.out)
        elif a.command == 'assemble-offline':
            result = assemble(a.subject_file, a.custodian_vote, a.publisher_vote,
                              a.custodian_public_hex, a.publisher_public_hex,
                              a.out)
        elif a.command == 'serve':
            with daemon.ReportPublishHost(
                path=a.socket, policy_path=a.policy_file,
                policy_sha=a.policy_sha256,
                private_key_file=a.server_private_key) as host:
                host.serve_forever(poll_interval=0.25)
            return 0
        elif a.command == 'submit':
            rc, result = submit(socket_path=a.socket, grant_file=a.grant_file,
                                policy_sha=a.policy_sha256,
                                server_pub=a.server_public_hex)
            print(json.dumps(result, ensure_ascii=True, sort_keys=True,
                             indent=2 if a.pretty else None,
                             separators=None if a.pretty else (',', ':')))
            return rc
        else:
            raise AssertionError('unreachable')
        print(p.canonical(result).decode('ascii'))
        return 0
    except (p.HostError, io.HostError, OSError, ValueError) as exc:
        code = exc.code if isinstance(exc, (p.HostError, io.HostError)) else \
            'EC289_PRIVATE_OPERATOR_FAILURE'
        status = exc.status if isinstance(exc, (p.HostError, io.HostError)) else 'unavailable'
        if status not in ('unavailable', 'invalid_input', 'permission_denied'):
            status = 'unavailable'
        result = p.denial(code, status,
                          publication_outcome_unknown=(a.command == 'submit'))
        print(p.canonical(result).decode('ascii'))
        return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
