#!/usr/bin/env python3
"""EC290: exact, separately authorized EC230 REPORT receipt GET host protocol.

The single socket API supplies only a signed EC230 read permit and an exact
short-lived two-vote admission, never a report, repository path, URL or token.
All original report verification, durable audit and provider signature checks
remain in the UNCHANGED EC230 PublicationReceiptService.inspect_report.
"""
from __future__ import annotations

from dataclasses import asdict
import hmac
import os
from pathlib import Path
import re
import secrets
import time
from typing import Any

from ec279_finding_query_host import protocol as io
from ec289_report_publish_host import protocol as old
import delivery_authorization as da
import delivery_preview as dp
import publication_receipts as rec
import report_publish as rp

POLICY_SCHEMA = 'ces.ec290.receipt_host_policy.v1'
SUBJECT_SCHEMA = 'ces.ec290.exact_read_subject.v1'
VOTE_SCHEMA = 'ces.ec290.offline_vote.v1'
GRANT_SCHEMA = 'ces.ec290.two_vote_grant.v1'
REQUEST_SCHEMA = 'ces.ec290.receipt_request.v1'
REPLY_SCHEMA = 'ces.ec290.signed_receipt_reply.v1'
DENIAL_SCHEMA = 'ces.ec290.receipt_denial.v1'
RESULT_SCHEMA = 'ces.ec290.verified_receipt_readback.v1'
READ_TEMPLATE_SCHEMA = 'ces.ec290.read_permit_template.v1'
DOMAINS = {
    'custodian': b'CES/EC290/PrivateReport/SourceCustodian/v1\0',
    'inspector': b'CES/EC290/PrivateReport/ReceiptInspector/v1\0',
    'server': b'CES/EC290/PrivateReport/SignedResult/v1\0',
}
MAX_POLICY, MAX_RPC, MAX_REPLY, MAX_TTL = 20000, 14000, 17000, 25
# A syntactically valid but intentionally NON-PROVISIONED original EC228
# credential: EC230 historical verification expects an access object, but the
# read host must NEVER hold an actual EC228 publish/write provider credential.
INERT_ORIGINAL_PUBLISH_TOKEN = 'CES_EC290_NEVER_ISSUED_PUBLISH_CREDENTIAL'
HEX = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
KEYS = {'schema', 'job_file', 'job_sha256', 'trust_file', 'trust_sha256',
        'read_credential_file', 'read_credential_sha256',
        'outbox_root', 'audit_root', 'admission_root', 'allowed_uids',
        'read_public_hex', 'cleanup_public_hex', 'receipt_epoch',
        'custodian_public_hex', 'inspector_public_hex', 'server_public_hex',
        'original_receipt_code_sha256', 'original_publish_code_sha256',
        'host_code_sha256', 'enable_one_private_report_readback'}
PINS = ('job_sha256', 'trust_sha256', 'read_credential_sha256', 'original_receipt_code_sha256',
        'original_publish_code_sha256', 'host_code_sha256')
SUBJECT_KEYS = {'schema', 'grant_id', 'uid', 'policy_sha256',
                'read_grant_sha256', 'operation_sha256', 'target_sha256',
                'original_grant_sha256', 'issued_at_unix', 'expires_at_unix', *PINS}
RESULT_KEYS = {'schema', 'mode', 'operation_id', 'status', 'exit_code',
               'reason_code', 'receipt_state', 'inspection_id',
               'observation_sha256', 'evidence_kind', 'historical_journal_present',
               'provider_receipt_read_attempted', 'cleanup_attempted',
               'local_worktree_cleanup_confirmed', 'public_or_production_published',
               'external_publication_confirmed', 'original_post_or_push_retried',
               'remote_ref_or_provider_content_deleted',
               'original_journal_deleted', 'original_source_or_index_modified'}
SOURCES = ('publication_receipts.py', 'report_publish.py', 'report_history.py',
           'report_render.py', 'delivery_authorization.py', 'delivery_preview.py',
           'docs_only_publish.py', 'delivery_send.py',
           'ec289_report_publish_host/protocol.py')
HOST_FILES = ('protocol.py', 'daemon.py', 'operator.py')


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'unavailable'):
        super().__init__(code)
        self.code, self.status = code, status


def need(ok: bool, code: str, status: str = 'unavailable') -> None:
    if ok is not True:
        raise HostError(code, status)


def canonical(doc: Any) -> bytes:
    return io.canonical(doc)


def sha(doc: bytes) -> str:
    return old.digest(doc)


def fields(doc: Any, names: set, code: str) -> dict:
    need(type(doc) is dict and set(doc) == names, code, 'invalid_input')
    return doc


def code_sha(domain: bytes, root: Path, names: tuple[str, ...]) -> str:
    import hashlib
    dig = hashlib.sha256(domain)
    for name in names:
        path = root / name
        need(path.is_file() and not path.is_symlink(),
             'EC290_PINNED_CODE_UNAVAILABLE')
        contents = path.read_bytes()
        dig.update(name.encode('ascii') + b'\0' + len(contents).to_bytes(8, 'big') + contents)
    return dig.hexdigest()


def source_sha() -> str:
    return code_sha(b'CES/EC290/Original-EC230-and-EC228/v1\0',
                    Path(__file__).resolve().parents[1], SOURCES)


def host_sha() -> str:
    return code_sha(b'CES/EC290/Independent-Readback-Host/v1\0',
                    Path(__file__).resolve().parent, HOST_FILES)


def private_bytes(path: str, expected: str, limit: int) -> bytes:
    raw = old.private_file(path, limit)
    need(hmac.compare_digest(sha(raw), expected),
         'EC290_PINNED_PRIVATE_FILE_CHANGED')
    return raw


def original_request(pol: dict) -> rp.ReportPublishRequest:
    raw = private_bytes(pol['job_file'], pol['job_sha256'], old.MAX_JOB)
    return old.validate_job(io.parse(raw, old.MAX_JOB))


def trust(pol: dict) -> dict:
    raw = private_bytes(pol['trust_file'], pol['trust_sha256'], old.MAX_TRUST)
    return old.validate_trust(io.parse(raw, old.MAX_TRUST))


def read_token(pol: dict) -> str:
    raw = private_bytes(pol['read_credential_file'],
                        pol['read_credential_sha256'], old.MAX_TOKEN)
    try:
        value = raw.decode('ascii')
    except UnicodeError as exc:
        raise HostError('EC290_PRIVATE_TOKEN_NONASCII') from exc
    need(16 <= len(value) <= 2048 and all(33 <= ord(c) <= 126 for c in value),
         'EC290_TOKEN_FORMAT_INVALID')
    return value


def validate_policy(doc: Any) -> dict:
    pol = fields(doc, KEYS, 'EC290_POLICY_EXACT_FIELDS_REQUIRED')
    need(pol['schema'] == POLICY_SCHEMA and
         pol['enable_one_private_report_readback'] is True,
         'EC290_OWNER_MUST_EXPLICITLY_ENABLE_READBACK', 'permission_denied')
    files = [pol[k] for k in ('job_file', 'trust_file', 'read_credential_file')]
    dirs = [pol[k] for k in ('outbox_root', 'audit_root', 'admission_root')]
    need(all(old.absolute(x) for x in files + dirs) and
         len(set(files + dirs)) == 6,
         'EC290_OWNER_PRIVATE_PATHS_INVALID')
    for i, d in enumerate(dirs):
        need(not any(x == d or x.startswith(d + '/') or d.startswith(x + '/')
                     for x in files), 'EC290_LEDGER_OVERLAPS_SOURCE_FILE')
        need(not any(d == x or d.startswith(x + '/') or x.startswith(d + '/')
                     for j, x in enumerate(dirs) if j != i),
             'EC290_LEDGER_ROOTS_OVERLAP')
    need(all(type(pol[k]) is str and HEX.fullmatch(pol[k]) is not None
             for k in PINS), 'EC290_RAW_BYTES_SHA_PINS_REQUIRED')
    need(pol['original_receipt_code_sha256'] == rec.ACTIVE_CODE_SHA256 == rec._code_hash()
         and pol['original_publish_code_sha256'] == source_sha()
         and pol['host_code_sha256'] == host_sha(),
         'EC290_ORIGINAL_OR_HOST_CODE_DRIFT')
    need(type(pol['receipt_epoch']) is int and 1 <= pol['receipt_epoch'] < 2**63,
         'EC290_RECEIPT_EPOCH_INVALID')
    uids = pol['allowed_uids']
    need(type(uids) is list and 1 <= len(uids) <= 32 and
         all(type(u) is int and 0 <= u <= 2**31-1 for u in uids) and
         uids == sorted(set(uids)), 'EC290_ALLOWED_UIDS_INVALID')
    role_keys = [pol[k] for k in ('read_public_hex', 'cleanup_public_hex',
                                   'custodian_public_hex', 'inspector_public_hex',
                                   'server_public_hex')]
    for value in role_keys:
        io.pub_from_hex(value)
    need(len(set(role_keys)) == 5, 'EC290_FIVE_NEW_SIGNERS_MUST_BE_DISTINCT')
    return pol


def load_policy(path: str, digest: str) -> dict:
    need(type(digest) is str and HEX.fullmatch(digest) is not None,
         'EC290_PINNED_POLICY_SHA_REQUIRED')
    return validate_policy(io.parse(private_bytes(path, digest, MAX_POLICY), MAX_POLICY))


def service(pol: dict) -> tuple[rec.PublicationReceiptService, rp.HostPublishAccess]:
    job = original_request(pol)
    trusted = trust(pol)
    keys = old.trust_keys(trusted) + [pol[k] for k in (
        'read_public_hex', 'cleanup_public_hex', 'custodian_public_hex',
        'inspector_public_hex', 'server_public_hex')]
    need(len(set(keys)) == 11, 'EC290_ALL_ELEVEN_ROLE_PUBLIC_KEYS_MUST_DIFFER')
    credential = read_token(pol)
    need(credential != INERT_ORIGINAL_PUBLISH_TOKEN,
         'EC290_PRIVATE_GET_CANNOT_USE_INERT_HISTORY_TOKEN')
    old.private_directory(pol['outbox_root'])
    old.private_directory(pol['audit_root'])
    old.private_directory(pol['admission_root'])
    # In this separate EC290 pathway publish_once is NEVER called.
    access = old.build_publisher(
        trusted, INERT_ORIGINAL_PUBLISH_TOKEN, pol['outbox_root']).access
    protected = [pol['outbox_root'], job.storage_root,
                 pol['audit_root'], pol['admission_root']]
    need(all(old.absolute(x) for x in protected),
         'EC290_ORIGINAL_PROTECTED_ROOT_INVALID')
    need(all(not (x == y or x.startswith(y + '/') or y.startswith(x + '/'))
             for i, x in enumerate(protected) for y in protected[i + 1:]),
         'EC290_AUDIT_OR_ADMISSION_OVERLAPS_HISTORICAL_DATA')
    roots = rec.ReceiptRoots(bytes.fromhex(pol['read_public_hex']),
                             bytes.fromhex(pol['cleanup_public_hex']),
                             pol['receipt_epoch'])
    scope = rec.HostReceiptScope(roots, pol['audit_root'], True, False, False,
                                 credential)
    svc = rec.PublicationReceiptService(scope)  # real HTTPS GET port, no injection
    need(type(svc.reader) is rec.HTTPSPrivateReceiptReader,
         'EC290_ORIGINAL_HTTPS_GET_REQUIRED')
    return svc, access


def operation_scope(pol: dict) -> dict:
    svc, access = service(pol)
    _pub, operation, target, grant_sha, _journal, _pins = svc._base(
        rec.MODE_REPORT, original_request(pol), access)
    return {'operation_sha256': operation, 'target_sha256': target,
            'original_grant_sha256': grant_sha}


def read_statement(body: Any, read_public_hex: str) -> da.SignedAuthorizationStatement:
    item = fields(body, {'statement', 'signature_hex'},
                  'EC290_READ_GRANT_SERIALIZATION_INVALID')
    try:
        signed = old.original_signed(item)
        verified = rec._signed(signed, bytes.fromhex(read_public_hex),
            rec.READ_DOMAIN, {'schema', 'mode', 'operation_id', 'target_sha256',
              'original_grant_sha256', 'inspection_nonce', 'receipt_epoch',
              'code_revision_sha256', 'permission', 'issued_at', 'expires_at'},
            'READ_GRANT')
        rec._window(verified, rec._time())
        need(verified['schema'] == rec.READ_SCHEMA and
             verified['mode'] == rec.MODE_REPORT and
             verified['permission'] == rec.READ_PERMISSION and
             verified['code_revision_sha256'] == rec.ACTIVE_CODE_SHA256,
             'EC290_ONLY_ORIGINAL_EXACT_REPORT_READ_PERMISSION', 'permission_denied')
    except (rec.ReceiptDenied, da.AuthorizationDenied, ValueError, TypeError) as exc:
        raise HostError('EC290_INDEPENDENT_READ_GRANT_DENIED',
                        'permission_denied') from exc
    return signed


def sign(role: str, doc: dict, key) -> str:
    return key.sign(DOMAINS[role] + canonical(doc)).hex()


def verify(role: str, doc: dict, signature: Any, public_hex: str) -> None:
    need(type(signature) is str and io.HEX_SIG.fullmatch(signature) is not None,
         'EC290_SIGNATURE_SHAPE_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(public_hex).verify(bytes.fromhex(signature),
                                           DOMAINS[role] + canonical(doc))
    except Exception as exc:
        raise HostError('EC290_INDEPENDENT_SIGNATURE_INVALID',
                        'permission_denied') from exc


def new_subject(pol: dict, policy_sha: str, read: dict,
                uid: int, ttl: int) -> dict:
    need(type(uid) is int and uid in pol['allowed_uids'] and
         type(ttl) is int and 1 <= ttl <= MAX_TTL,
         'EC290_OFFLINE_UID_OR_TTL_NOT_ALLOWED', 'permission_denied')
    signed = read_statement(read, pol['read_public_hex'])
    ops = operation_scope(pol)
    need(signed.statement['operation_id'] == ops['operation_sha256'] and
         signed.statement['target_sha256'] == ops['target_sha256'] and
         signed.statement['original_grant_sha256'] == ops['original_grant_sha256'] and
         signed.statement['receipt_epoch'] >= pol['receipt_epoch'],
         'EC290_READ_GRANT_IS_NOT_FOR_THIS_ORIGINAL_REPORT', 'permission_denied')
    now = int(time.time())
    return validate_subject({'schema': SUBJECT_SCHEMA,
        'grant_id': secrets.token_hex(16), 'uid': uid,
        'policy_sha256': policy_sha, **{k: pol[k] for k in PINS},
        **ops, 'read_grant_sha256': sha(canonical(read)),
        'issued_at_unix': now, 'expires_at_unix': now + ttl})


def validate_subject(s: Any) -> dict:
    fields(s, SUBJECT_KEYS, 'EC290_EXACT_SUBJECT_FIELDS_REQUIRED')
    need(s['schema'] == SUBJECT_SCHEMA and type(s['grant_id']) is str and
         io.HEX_NONCE.fullmatch(s['grant_id']) is not None and
         type(s['uid']) is int and 0 <= s['uid'] <= 2**31-1 and
         all(type(s[k]) is str and HEX.fullmatch(s[k]) is not None
             for k in SUBJECT_KEYS - {'schema', 'grant_id', 'uid',
                                       'issued_at_unix', 'expires_at_unix'}) and
         type(s['issued_at_unix']) is int and
         type(s['expires_at_unix']) is int and
         946684800 <= s['issued_at_unix'] < s['expires_at_unix'] <= 4102444800 and
         s['expires_at_unix'] - s['issued_at_unix'] <= MAX_TTL,
         'EC290_SUBJECT_SCOPE_OR_FRESHNESS_INVALID')
    return s


def validate_grant(grant: dict, pol: dict, read: dict, uid: int,
                   policy_sha: str, now: int) -> dict:
    fields(grant, {'schema', 'subject', 'custodian_signature_ed25519',
                   'inspector_signature_ed25519'},
           'EC290_TWO_OFFLINE_VOTES_REQUIRED')
    need(grant['schema'] == GRANT_SCHEMA, 'EC290_GRANT_SCHEMA_INVALID')
    s = validate_subject(grant['subject'])
    need(uid in pol['allowed_uids'] and s['uid'] == uid and
         s['policy_sha256'] == policy_sha and
         all(s[k] == pol[k] for k in PINS) and
         s['read_grant_sha256'] == sha(canonical(read)) and
         s['issued_at_unix'] <= now + 5 and now < s['expires_at_unix'],
         'EC290_UID_GRANT_OR_PIN_DRIFT', 'permission_denied')
    signed = read_statement(read, pol['read_public_hex'])
    need(signed.statement['operation_id'] == s['operation_sha256'] and
         signed.statement['target_sha256'] == s['target_sha256'] and
         signed.statement['original_grant_sha256'] == s['original_grant_sha256'] and
         signed.statement['receipt_epoch'] >= pol['receipt_epoch'],
         'EC290_SIGNED_READ_SUBJECT_MISMATCH', 'permission_denied')
    for role in ('custodian', 'inspector'):
        verify(role, s, grant[role + '_signature_ed25519'],
               pol[role + '_public_hex'])
    return s


def validate_backend(doc: Any) -> dict:
    fields(doc, RESULT_KEYS, 'EC290_ORIGINAL_EC230_RESULT_FIELDS_CHANGED')
    need(doc['schema'] == rec.SCHEMA and doc['mode'] == rec.MODE_REPORT and
         (doc['status'], doc['exit_code']) in (
             ('partial', 2), ('blocked', 4), ('invalid_input', 4), ('unavailable', 5)) and
         type(doc['reason_code']) is str and re.fullmatch(
             r'PUBLICATION_RECEIPT_[A-Z0-9_]{1,150}', doc['reason_code']) is not None and
         all(doc[k] is False for k in (
             'cleanup_attempted', 'local_worktree_cleanup_confirmed',
             'public_or_production_published', 'external_publication_confirmed',
             'original_post_or_push_retried', 'remote_ref_or_provider_content_deleted',
             'original_journal_deleted', 'original_source_or_index_modified')) and
         all(type(doc[k]) is bool for k in (
             'historical_journal_present', 'provider_receipt_read_attempted',
             'cleanup_attempted', 'local_worktree_cleanup_confirmed',
             'public_or_production_published', 'external_publication_confirmed',
             'original_post_or_push_retried', 'remote_ref_or_provider_content_deleted',
             'original_journal_deleted', 'original_source_or_index_modified')) and
         all(x is None or (type(x) is str and HEX.fullmatch(x) is not None)
             for x in (doc['operation_id'], doc['inspection_id'],
                       doc['observation_sha256'])) and
         type(doc['evidence_kind']) is str and type(doc['receipt_state']) is str,
         'EC290_UNSAFE_OR_INCONSISTENT_EC230_EVIDENCE')
    if doc['status'] == 'partial':
        need(doc['receipt_state'] in (
            'SIGNED_PROVIDER_PRIVATE_TEST_RECORD_OBSERVED',
            'UNKNOWN_PROVIDER_REPORTS_NOT_FOUND') and
            doc['evidence_kind'] == 'SIGNED_PROVIDER_PRIVATE_RECEIPT_READBACK' and
            doc['historical_journal_present'] is True and
            doc['provider_receipt_read_attempted'] is True and
            doc['inspection_id'] is not None and
            doc['observation_sha256'] is not None and
            doc['reason_code'].endswith(doc['receipt_state']),
            'EC290_ONLY_SIGNED_PRIVATE_READBACK_ALLOWED')
    else:
        need(doc['evidence_kind'] == 'NONE' and
             doc['observation_sha256'] is None,
             'EC290_FAILED_READBACK_CANNOT_CLAIM_REMOTE_EVIDENCE')
    return doc


def denial(code: str, status: str = 'unavailable', *, attempted: bool = False) -> dict:
    need(status in ('unavailable', 'permission_denied', 'invalid_input'),
         'EC290_BAD_HOST_DENIAL')
    return {'schema': DENIAL_SCHEMA, 'status': status,
            'exit_code': {'unavailable': 5, 'permission_denied': 3,
                          'invalid_input': 4}[status],
            'reason_code': code, 'provider_readback_may_have_been_attempted': attempted,
            'remote_publication_confirmed': False,
            'original_publish_retried': False,
            'automatic_read_or_publish_retry_allowed': False}


def signed_reply(request: dict, result: dict, policy_sha: str, job_sha: str,
                 key, now: int) -> dict:
    body = {'schema': REPLY_SCHEMA, 'nonce': request['nonce'],
            'request_sha256': sha(canonical(request)),
            'policy_sha256': policy_sha, 'job_sha256': job_sha,
            'issued_at_unix': now, 'result': result}
    return {**body, 'signature_ed25519': sign('server', body, key)}


def verify_reply(reply: Any, req: dict, pub: str, polsha: str, now: int) -> dict:
    fields(reply, {'schema', 'nonce', 'request_sha256', 'policy_sha256',
                   'job_sha256', 'issued_at_unix', 'result', 'signature_ed25519'},
           'EC290_REPLY_FIELDS_CHANGED')
    subj = validate_subject(req['grant']['subject'])
    need(reply['schema'] == REPLY_SCHEMA and reply['nonce'] == req['nonce'] and
         reply['request_sha256'] == sha(canonical(req)) and
         reply['policy_sha256'] == polsha == subj['policy_sha256'] and
         reply['job_sha256'] == subj['job_sha256'] and
         type(reply['issued_at_unix']) is int and abs(now - reply['issued_at_unix']) <= 90,
         'EC290_REPLY_NONCE_OR_SOURCE_PIN_MISMATCH')
    verify('server', {k: v for k, v in reply.items() if k != 'signature_ed25519'},
           reply['signature_ed25519'], pub)
    res = reply['result']
    if type(res) is dict and res.get('schema') == rec.SCHEMA:
        return validate_backend(res)
    fields(res, set(denial('EC290_EXAMPLE')),
           'EC290_DENIAL_RESULT_FIELDS_CHANGED')
    need(res['schema'] == DENIAL_SCHEMA and
         (res['status'], res['exit_code']) in (
             ('permission_denied', 3), ('invalid_input', 4), ('unavailable', 5)) and
         type(res['reason_code']) is str and re.fullmatch(
             r'EC290_[A-Z0-9_]{1,150}', res['reason_code']) is not None and
         type(res['provider_readback_may_have_been_attempted']) is bool and
         res['remote_publication_confirmed'] is False and
         res['original_publish_retried'] is False and
         res['automatic_read_or_publish_retry_allowed'] is False,
         'EC290_DENIAL_RESULT_INVALID')
    return res
