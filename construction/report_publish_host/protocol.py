#!/usr/bin/env python3
"""EC289 original EC228 REPORT PUBLISH host: exact private job + two offline votes.

No report Markdown, credential, destination, endpoint, trust root, or arbitrary
command is accepted over the socket. This is a separate additional permission
layer; the UNMODIFIED EC228 signer chain and immutable report store remain the
authority. HTTP 2xx only means SUBMISSION_UNCONFIRMED, NEVER published.
"""
from __future__ import annotations

from dataclasses import asdict, fields
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from finding_query_host import protocol as io
import delivery_authorization as da
import report_publish as rp

POLICY_SCHEMA = 'ces.ec289.report_publish_policy.v1'
JOB_SCHEMA = 'ces.ec289.exact_original_report_publish_job.v1'
TRUST_SCHEMA = 'ces.ec289.report_publish_trust.v1'
SUBJECT_SCHEMA = 'ces.ec289.offline_publish_subject.v1'
VOTE_SCHEMA = 'ces.ec289.offline_publish_vote.v1'
GRANT_SCHEMA = 'ces.ec289.two_vote_publish_grant.v1'
REQUEST_SCHEMA = 'ces.ec289.publish_host_request.v1'
REPLY_SCHEMA = 'ces.ec289.publish_host_signed_reply.v1'
DENIAL_SCHEMA = 'ces.ec289.publish_host_denial.v1'
RESULT_SCHEMA = 'ces.ec289.verified_report_publish_result.v1'
DOMAINS = {
    'custodian': b'CES/EC289/ReportPublish/ExactReportSourceCustodian/v1\x00',
    'publisher': b'CES/EC289/ReportPublish/SingleSandboxPublisher/v1\x00',
    'server': b'CES/EC289/ReportPublish/IndependentSignedHostReply/v1\x00',
}
MAX_POLICY, MAX_TRUST, MAX_JOB, MAX_TOKEN = 16000, 16000, 300000, 4096
MAX_RPC, MAX_REPLY, MAX_TTL, CLOCK_SKEW = 8192, 16000, 20, 5
HOST_FILES = ('protocol.py', 'daemon.py', 'operator.py')
SOURCE_FILES = ('report_publish.py', 'report_history.py', 'report_render.py',
                'report_prepare.py', 'report_writing_handoff.py',
                'delivery_preview.py', 'delivery_authorization.py', 'delivery_send.py')
POLICY_KEYS = {'schema', 'job_file', 'job_sha256', 'trust_file', 'trust_sha256',
               'credential_file', 'credential_sha256', 'outbox_root', 'admission_root',
               'allowed_uids', 'custodian_issuer_public_hex',
               'publisher_issuer_public_hex', 'server_public_hex',
               'original_backend_sha256', 'host_backend_sha256',
               'enable_one_private_test_publication'}
SUBJECT_KEYS = {'schema', 'grant_id', 'uid', 'policy_sha256', 'job_sha256',
                'trust_sha256', 'credential_sha256', 'original_backend_sha256',
                'host_backend_sha256', 'original_publish_grant_sha256',
                'rendered_markdown_sha256', 'issued_at_unix', 'expires_at_unix'}
BACKEND_KEYS = {'schema', 'status', 'exit_code', 'reason_code', 'operation_id',
                'attempt_receipt_id', 'publication_state', 'claim_committed',
                'provider_capability_verified', 'network_requested',
                'publish_post_attempted', 'published', 'provider_accepted',
                'external_visibility_verified', 'external_publication_confirmed',
                'resent', 'effects'}
EFFECT_KEYS = {'provider_publish_post_requested', 'external_network_requested',
               'git_or_business_files_written', 'existing_remote_content_modified',
               'ces_report_store_modified', 'delivery_submit_requested'}
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'unavailable'):
        super().__init__(code)
        self.code, self.status = code, status


def need(value: bool, code: str, status: str = 'unavailable') -> None:
    if value is not True:
        raise HostError(code, status)


def canonical(doc: Any) -> bytes:
    return io.canonical(doc)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def keys(value: Any, expected: set, code: str) -> dict:
    need(type(value) is dict and set(value) == expected, code)
    return value


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign(role: str, doc: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(DOMAINS[role] + canonical(doc)).hex()


def verify(role: str, doc: dict, signature: Any, pub: str) -> None:
    need(type(signature) is str and io.HEX_SIG.fullmatch(signature) is not None,
         'EC289_SIGNATURE_SHAPE_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(pub).verify(bytes.fromhex(signature),
                                    DOMAINS[role] + canonical(doc))
    except Exception as exc:
        raise HostError('EC289_SIGNATURE_NOT_AUTHORIZED', 'permission_denied') from exc


def absolute(path: Any) -> bool:
    return (type(path) is str and 1 < len(path) < 2048 and path.startswith('/')
            and not path.startswith('//') and '\x00' not in path
            and os.path.normpath(path) == path)


def private_parent(path: str) -> None:
    need(absolute(path), 'EC289_PRIVATE_ABSOLUTE_PATH_REQUIRED')
    try:
        need(not any(x.is_symlink() for x in (Path(path), *Path(path).parents)),
             'EC289_SYMLINK_PATH_FORBIDDEN')
        st = os.lstat(os.path.dirname(path))
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
             and stat.S_IMODE(st.st_mode) & 0o077 == 0,
             'EC289_PRIVATE_PARENT_OWNER_MODE_REQUIRED')
    except OSError as exc:
        raise HostError('EC289_PRIVATE_PARENT_UNAVAILABLE') from exc


def private_file(path: str, limit: int) -> bytes:
    private_parent(path)
    try:
        st = os.lstat(path)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid()
             and stat.S_IMODE(st.st_mode) & 0o077 == 0 and st.st_nlink == 1
             and 0 < st.st_size <= limit, 'EC289_PRIVATE_FILE_OWNER_MODE_SIZE_INVALID')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            actual = os.fstat(fd)
            need((actual.st_dev, actual.st_ino) == (st.st_dev, st.st_ino)
                 and actual.st_uid == st.st_uid and actual.st_size == st.st_size,
                 'EC289_PRIVATE_FILE_RACE_DETECTED')
            raw = os.read(fd, limit + 1)
            need(len(raw) == st.st_size, 'EC289_PRIVATE_FILE_UNSTABLE')
            return raw
        finally:
            os.close(fd)
    except OSError as exc:
        raise HostError('EC289_PRIVATE_FILE_UNAVAILABLE') from exc


def pinned(path: str, sha256: str, limit: int) -> dict:
    raw = private_file(path, limit)
    need(hmac.compare_digest(digest(raw), sha256),
         'EC289_OWNER_PRIVATE_BYTES_CHANGED')
    return io.parse(raw, limit)


def private_directory(path: str) -> None:
    private_parent(path)
    try:
        st = os.lstat(path)
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
             and stat.S_IMODE(st.st_mode) & 0o077 == 0,
             'EC289_OWNER_ONLY_DURABLE_DIRECTORY_REQUIRED')
    except OSError as exc:
        raise HostError('EC289_DURABLE_DIRECTORY_MISSING') from exc


def _source_code_sha(domain: bytes, root: Path, names: tuple[str, ...]) -> str:
    h = hashlib.sha256(domain)
    for name in names:
        file = root / name
        need(file.is_file() and not file.is_symlink(),
             'EC289_CODE_SOURCE_MISSING_OR_SYMLINK')
        raw = file.read_bytes()
        h.update(name.encode('ascii') + b'\x00' + len(raw).to_bytes(8, 'big') + raw)
    return h.hexdigest()


def backend_sha() -> str:
    return _source_code_sha(b'CES/EC289/ORIGINAL-EC228-PUBLISH-CODE/v1\x00',
                            Path(__file__).resolve().parents[1], SOURCE_FILES)


def host_code_sha() -> str:
    return _source_code_sha(b'CES/EC289/NEW-PRIVILEGED-HOST-CODE/v1\x00',
                            Path(__file__).resolve().parent, HOST_FILES)


def original_signed(doc: Any) -> da.SignedAuthorizationStatement:
    keys(doc, {'statement', 'signature_hex'}, 'EC289_SIGNED_STATEMENT_FIELDS_INVALID')
    need(type(doc['statement']) is dict and
         len(canonical(doc['statement'])) <= da.MAX_SIGNED_JSON_BYTES and
         type(doc['signature_hex']) is str and
         io.HEX_SIG.fullmatch(doc['signature_hex']) is not None,
         'EC289_ORIGINAL_SIGNED_STATEMENT_INVALID')
    return da.SignedAuthorizationStatement(doc['statement'], doc['signature_hex'])


def encode_original_request(req: rp.ReportPublishRequest) -> dict:
    """Trusted private Python ONLY; never serialize actual Markdown to a caller."""
    need(type(req) is rp.ReportPublishRequest,
         'EC289_ORIGINAL_TYPED_REPORT_PUBLISH_REQUEST_REQUIRED')
    job = {'schema': JOB_SCHEMA, 'publish_request': asdict(req)}
    need(len(canonical(job)) <= MAX_JOB, 'EC289_EXACT_PRIVATE_JOB_TOO_LARGE')
    validate_job(job)
    return job


def decode_job(doc: Any) -> rp.ReportPublishRequest:
    keys(doc, {'schema', 'publish_request'}, 'EC289_JOB_FIELDS_INVALID')
    need(doc['schema'] == JOB_SCHEMA, 'EC289_JOB_SCHEMA_INVALID')
    fields_required = {f.name for f in fields(rp.ReportPublishRequest)}
    obj = keys(doc['publish_request'], fields_required,
               'EC289_ORIGINAL_REPORT_PUBLISH_FIELDS_INVALID')
    args = {k: original_signed(v) if k in (
            'organization', 'route', 'revocation', 'content_review',
            'side_effect_grant') else v for k, v in obj.items()}
    return rp.ReportPublishRequest(**args)


def validate_job(doc: Any) -> rp.ReportPublishRequest:
    try:
        req = decode_job(doc)
    except HostError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError) as exc:
        raise HostError('EC289_PRIVATE_ORIGINAL_JOB_INVALID') from exc
    need(absolute(req.storage_root) and type(req.slot_key) is str
         and type(req.period_id) is str and type(req.slot_members) is list
         and 1 <= len(req.slot_members) <= 128
         and all(type(x) is dict and all(type(k) is str and type(v) is str
                 for k, v in x.items()) for x in req.slot_members)
         and type(req.read_policy) is dict
         and type(req.version) is int and 1 <= req.version <= 10000
         and all(type(x) is str and HEX.fullmatch(x) for x in (
             req.record_sha256, req.rendered_sha256, req.entry_sha256,
             req.index_binding_sha256))
         and type(req.report_ref) is str and req.report_ref.startswith('cesrr1:')
         and req.explicitly_approve_exact_private_publication is True
         and req.permit_sandbox_network_egress is True,
         'EC289_ONLY_EXACT_SAVED_REVIEWED_SANDBOX_REPORT', 'permission_denied')
    return req


def load_job(pol: dict) -> rp.ReportPublishRequest:
    return validate_job(pinned(pol['job_file'], pol['job_sha256'], MAX_JOB))


def validate_trust(doc: Any) -> dict:
    keys(doc, {'schema', 'roots', 'target', 'enable_live_private_publication'},
         'EC289_TRUST_FIELDS_INVALID')
    need(doc['schema'] == TRUST_SCHEMA and
         doc['enable_live_private_publication'] is True,
         'EC289_HOST_PUBLISH_NOT_EXPLICITLY_ENABLED', 'permission_denied')
    keys(doc['roots'], {
        'issuer_id', 'operator_id', 'minimum_policy_epoch',
        'organization_public_hex', 'route_public_hex', 'revocation_public_hex',
        'content_reviewer_public_hex', 'side_effect_public_hex',
        'provider_public_hex'}, 'EC289_ORIGINAL_SIX_TRUST_ROOT_FIELDS_INVALID')
    keys(doc['target'], {f.name for f in fields(rp.HostPrivatePublishTarget)},
         'EC289_SINGLE_PRIVATE_TARGET_FIELDS_INVALID')
    for name in original_key_fields():
        io.pub_from_hex(doc['roots'][name])
    need(doc['target']['sandbox_private'] is True and
         doc['target']['single_destination'] is True,
         'EC289_NON_PRIVATE_OR_MULTIPLE_TARGETS_FORBIDDEN', 'permission_denied')
    return doc


def original_key_fields() -> tuple[str, ...]:
    return ('organization_public_hex', 'route_public_hex', 'revocation_public_hex',
            'content_reviewer_public_hex', 'side_effect_public_hex',
            'provider_public_hex')


def trust_keys(doc: dict) -> list[str]:
    return [doc['roots'][name] for name in original_key_fields()]


def load_trust(pol: dict) -> dict:
    return validate_trust(pinned(pol['trust_file'], pol['trust_sha256'], MAX_TRUST))


def build_publisher(trust: dict, credential: str,
                    outbox_root: str) -> rp.ReportPublisher:
    r = trust['roots']
    root = rp.TrustedPublishRoots(
        r['issuer_id'], r['operator_id'],
        *(bytes.fromhex(r[k]) for k in original_key_fields()),
        r['minimum_policy_epoch'])
    target = rp.HostPrivatePublishTarget(**trust['target'])
    access = rp.HostPublishAccess(root, target, credential, outbox_root,
                                  True, False)
    # PRODUCTION INVARIANT: NEVER inject a development port or clock.
    result = rp.ReportPublisher(access, transport=None)
    need(type(result._transport) is rp.HTTPSPrivatePublishTransport,
         'EC289_ORIGINAL_HTTPS_TRANSPORT_REQUIRED')
    return result


def load_credential(pol: dict) -> str:
    raw = private_file(pol['credential_file'], MAX_TOKEN)
    need(hmac.compare_digest(digest(raw), pol['credential_sha256']),
         'EC289_PRIVATE_CREDENTIAL_CHANGED')
    try:
        text = raw.decode('ascii')
    except UnicodeError as exc:
        raise HostError('EC289_PRIVATE_CREDENTIAL_NON_ASCII') from exc
    need(16 <= len(text) <= 2048 and
         all(33 <= ord(c) <= 126 for c in text),
         'EC289_PRIVATE_SCOPED_CREDENTIAL_INVALID')
    return text


def validate_policy(pol: Any) -> dict:
    keys(pol, POLICY_KEYS, 'EC289_HOST_POLICY_FIELDS_INVALID')
    need(pol['schema'] == POLICY_SCHEMA and
         pol['enable_one_private_test_publication'] is True,
         'EC289_HOST_NOT_ENABLED_FOR_ONE_PRIVATE_PUBLICATION')
    for field in ('job_file', 'trust_file', 'credential_file',
                  'outbox_root', 'admission_root'):
        need(absolute(pol[field]), 'EC289_ABSOLUTE_OWNER_PATH_REQUIRED')
    paths = [pol[k] for k in ('job_file', 'trust_file', 'credential_file',
                               'outbox_root', 'admission_root')]
    need(len(set(paths)) == len(paths), 'EC289_HOST_PATH_COLLISION')
    for ledger in (pol['outbox_root'], pol['admission_root']):
        need(not any(f == ledger or f.startswith(ledger + '/')
                     for f in (pol['job_file'], pol['trust_file'],
                               pol['credential_file'])) and
             not any(ledger != other and ledger.startswith(other + '/')
                     for other in (pol['outbox_root'], pol['admission_root'])),
             'EC289_LEDGER_AND_SOURCE_PATHS_MUST_BE_SEPARATE')
    for k in ('job_sha256', 'trust_sha256', 'credential_sha256',
              'original_backend_sha256', 'host_backend_sha256'):
        need(type(pol[k]) is str and HEX.fullmatch(pol[k]) is not None,
             'EC289_HOST_SHA_PIN_INVALID')
    need(pol['original_backend_sha256'] == backend_sha(),
         'EC289_ORIGINAL_EC228_SOURCE_BYTES_CHANGED')
    need(pol['host_backend_sha256'] == host_code_sha(),
         'EC289_PRIVILEGED_HOST_BYTES_CHANGED')
    uids = pol['allowed_uids']
    need(type(uids) is list and 1 <= len(uids) <= 32 and
         all(type(v) is int and 0 <= v <= 2**31-1 for v in uids)
         and sorted(set(uids)) == uids, 'EC289_ALLOWED_PEER_UIDS_INVALID')
    rolekeys = [pol[k] for k in ('custodian_issuer_public_hex',
                                  'publisher_issuer_public_hex',
                                  'server_public_hex')]
    for k in rolekeys:
        io.pub_from_hex(k)
    need(len(set(rolekeys)) == 3, 'EC289_DISTINCT_THREE_HOST_ROOTS_REQUIRED')
    return pol


def load_policy(path: str, sha: str) -> dict:
    need(type(sha) is str and HEX.fullmatch(sha) is not None,
         'EC289_POLICY_EXPECTED_SHA_REQUIRED')
    return validate_policy(pinned(path, sha, MAX_POLICY))


def job_pins(pol: dict, req: rp.ReportPublishRequest) -> dict:
    return {'job_sha256': pol['job_sha256'],
            'trust_sha256': pol['trust_sha256'],
            'credential_sha256': pol['credential_sha256'],
            'original_backend_sha256': pol['original_backend_sha256'],
            'host_backend_sha256': pol['host_backend_sha256'],
            'original_publish_grant_sha256': digest(canonical(
                asdict(req.side_effect_grant))),
            'rendered_markdown_sha256': req.rendered_sha256}


def validate_subject(s: Any) -> dict:
    keys(s, SUBJECT_KEYS, 'EC289_SUBJECT_FIELDS_INVALID')
    need(s['schema'] == SUBJECT_SCHEMA and
         type(s['grant_id']) is str and io.HEX_NONCE.fullmatch(s['grant_id']) is not None
         and type(s['uid']) is int and 0 <= s['uid'] <= 2**31-1
         and all(type(s[k]) is str and HEX.fullmatch(s[k]) is not None
                 for k in (SUBJECT_KEYS - {'schema', 'grant_id', 'uid',
                                          'issued_at_unix', 'expires_at_unix'}))
         and type(s['issued_at_unix']) is int
         and type(s['expires_at_unix']) is int
         and 946684800 <= s['issued_at_unix'] < s['expires_at_unix'] <= 4102444800
         and s['expires_at_unix'] - s['issued_at_unix'] <= MAX_TTL,
         'EC289_SUBJECT_UID_TTL_OR_SHA_SCOPE_INVALID')
    return s


def new_subject(uid: int, policy_sha: str, pins: dict, ttl: int) -> dict:
    need(type(ttl) is int and 1 <= ttl <= MAX_TTL,
         'EC289_OFFLINE_TTL_EXCEEDS_LIMIT')
    now = int(time.time())
    return validate_subject({'schema': SUBJECT_SCHEMA,
                             'grant_id': secrets.token_hex(16),
                             'uid': uid, 'policy_sha256': policy_sha,
                             **pins, 'issued_at_unix': now,
                             'expires_at_unix': now + ttl})


def validate_grant(grant: Any, pol: dict, req: rp.ReportPublishRequest,
                   *, uid: int, now: int, policy_sha: str) -> dict:
    keys(grant, {'schema', 'subject', 'custodian_signature_ed25519',
                 'publisher_signature_ed25519'}, 'EC289_EXACT_TWO_OFFLINE_VOTES_REQUIRED')
    need(grant['schema'] == GRANT_SCHEMA, 'EC289_GRANT_SCHEMA_INVALID')
    sub = validate_subject(grant['subject'])
    need(uid in pol['allowed_uids'] and sub['uid'] == uid
         and sub['policy_sha256'] == policy_sha
         and all(sub[k] == v for k, v in job_pins(pol, req).items())
         and sub['issued_at_unix'] <= now + CLOCK_SKEW
         and now < sub['expires_at_unix'],
         'EC289_KERNEL_UID_PRIVATE_SOURCE_OR_TIME_DENIED', 'permission_denied')
    for role in ('custodian', 'publisher'):
        verify(role, sub, grant[role + '_signature_ed25519'],
               pol[role + '_issuer_public_hex'])
    return sub


def validate_backend(result: Any) -> dict:
    keys(result, BACKEND_KEYS, 'EC289_ORIGINAL_EC228_RESULT_FIELDS_UNEXPECTED')
    need(result['schema'] == rp.SCHEMA and
         (result['status'], result['exit_code']) in (
             ('partial', 2), ('blocked', 5),
             ('unavailable', 5), ('invalid_input', 4)) and
         type(result['reason_code']) is str and
         re.fullmatch(r'REPORT_PUBLISH_[A-Z0-9_]{1,150}',
                      result['reason_code']) is not None,
         'EC289_EC228_STATUS_NOT_RECOGNIZED')
    flags = ('claim_committed', 'provider_capability_verified', 'network_requested',
             'publish_post_attempted', 'published', 'provider_accepted',
             'external_visibility_verified', 'external_publication_confirmed', 'resent')
    need(all(type(result[k]) is bool for k in flags) and
         all(result[k] is False for k in (
             'published', 'provider_accepted', 'external_visibility_verified',
             'external_publication_confirmed', 'resent')),
         'EC289_BACKEND_CANNOT_CERTIFY_EXTERNAL_PUBLICATION')
    fx = keys(result['effects'], EFFECT_KEYS,
              'EC289_ORIGINAL_PUBLISH_EFFECTS_UNEXPECTED')
    need(all(type(fx[k]) is bool for k in EFFECT_KEYS) and
         all(fx[k] is False for k in (
             'git_or_business_files_written', 'existing_remote_content_modified',
             'ces_report_store_modified', 'delivery_submit_requested')) and
         fx['provider_publish_post_requested'] == result['publish_post_attempted'] and
         fx['external_network_requested'] == result['network_requested'] and
         (not result['publish_post_attempted'] or (
             result['claim_committed'] and result['network_requested'])) and
         (not result['provider_capability_verified'] or result['network_requested']),
         'EC289_ORIGINAL_PUBLISH_LEDGER_OR_EFFECTS_INVALID')
    operation = result['operation_id']
    receipt = result['attempt_receipt_id']
    need(operation is None or (type(operation) is str and HEX.fullmatch(operation) is not None),
         'EC289_PUBLISH_OPERATION_ID_INVALID')
    need(receipt is None or (type(receipt) is str and
                            re.fullmatch(r'cesrp1:[a-f0-9]{64}', receipt) is not None),
         'EC289_PUBLISH_RECEIPT_ID_INVALID')
    need(result['publication_state'] in ('NOT_ATTEMPTED',
         'UNKNOWN_UNCONFIRMED', 'SUBMISSION_UNCONFIRMED'),
         'EC289_PUBLICATION_STATE_INVALID')
    if result['status'] == 'partial':
        need(result['claim_committed'] and
             result['provider_capability_verified'] and
             result['network_requested'] and result['publish_post_attempted'] and
             result['publication_state'] == 'SUBMISSION_UNCONFIRMED' and
             operation is not None and receipt is not None,
             'EC289_HTTP_RESPONSE_IS_NOT_PUBLISHED')
    else:
        need(receipt is None and result['publication_state'] != 'SUBMISSION_UNCONFIRMED' and
             (not result['publish_post_attempted'] or
              result['publication_state'] == 'UNKNOWN_UNCONFIRMED'),
             'EC289_FAILING_RESULT_CANNOT_CLAIM_PUBLICATION')
    return result


def denial(code: str, status: str = 'unavailable', *,
           handler_invoked: bool = False, publication_outcome_unknown: bool = False) -> dict:
    need(status in ('unavailable', 'invalid_input', 'permission_denied'),
         'EC289_UNSUPPORTED_DENIAL_STATUS')
    return {'schema': DENIAL_SCHEMA, 'status': status,
            'exit_code': {'unavailable': 5, 'invalid_input': 4,
                          'permission_denied': 3}[status],
            'reason_code': code, 'handler_invoked': handler_invoked,
            'publication_outcome_unknown': publication_outcome_unknown,
            'published': False, 'private_markdown_or_credential_returned': False,
            'automatic_retry_allowed': False}


def signed_reply(req: dict, result: dict, policy_sha: str,
                 job_sha: str, key: Ed25519PrivateKey, now: int) -> dict:
    doc = {'schema': REPLY_SCHEMA, 'nonce': req['nonce'],
           'request_sha256': digest(canonical(req)),
           'policy_sha256': policy_sha, 'job_sha256': job_sha,
           'issued_at_unix': now, 'result': result}
    return {**doc, 'signature_ed25519': sign('server', doc, key)}


def verify_reply(reply: Any, req: dict, pub: str, policy_sha: str,
                 now: int) -> dict:
    keys(reply, {'schema', 'nonce', 'request_sha256', 'policy_sha256',
                 'job_sha256', 'issued_at_unix', 'result', 'signature_ed25519'},
         'EC289_SIGNED_REPLY_FIELDS_INVALID')
    sub = validate_subject(req['grant']['subject'])
    need(reply['schema'] == REPLY_SCHEMA and reply['nonce'] == req['nonce'] and
         reply['request_sha256'] == digest(canonical(req)) and
         reply['policy_sha256'] == policy_sha == sub['policy_sha256'] and
         reply['job_sha256'] == sub['job_sha256'] and
         type(reply['issued_at_unix']) is int and
         abs(now - reply['issued_at_unix']) <= 90,
         'EC289_REPLY_REQUEST_NONCE_OR_PIN_MISMATCH')
    verify('server', {k: v for k, v in reply.items() if k != 'signature_ed25519'},
           reply['signature_ed25519'], pub)
    result = reply['result']
    need(type(result) is dict, 'EC289_SIGNED_RESULT_INVALID')
    if result.get('schema') == rp.SCHEMA:
        return validate_backend(result)
    keys(result, {'schema', 'status', 'exit_code', 'reason_code',
                  'handler_invoked', 'publication_outcome_unknown', 'published',
                  'private_markdown_or_credential_returned', 'automatic_retry_allowed'},
         'EC289_SIGNED_DENIAL_FIELDS_INVALID')
    need(result['schema'] == DENIAL_SCHEMA and
         (result['status'], result['exit_code']) in (
            ('unavailable', 5), ('invalid_input', 4), ('permission_denied', 3)) and
         type(result['reason_code']) is str and
         re.fullmatch(r'EC289_[A-Z0-9_]{1,150}', result['reason_code']) is not None and
         type(result['handler_invoked']) is bool and
         type(result['publication_outcome_unknown']) is bool and
         result['published'] is False and
         result['private_markdown_or_credential_returned'] is False and
         result['automatic_retry_allowed'] is False,
         'EC289_SIGNED_DENIAL_UNSAFE')
    return result
