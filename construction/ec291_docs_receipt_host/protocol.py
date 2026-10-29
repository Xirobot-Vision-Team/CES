#!/usr/bin/env python3
"""EC291: separately authorized original EC230 *DocsOnly* Git readback.

The wire carries only a signed EC230 READ grant and two exact short-lived Host
votes. The complete original EC229 job and its four original approvals remain
owner-only on the host. No Git write, original publish or cleanup function is
exposed, and no Git ref/contents are accepted from the socket client.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import time
from typing import Any

from ec279_finding_query_host import protocol as io
from ec285_docs_sandbox_host import protocol as old, daemon as original_docs
import delivery_authorization as da
import delivery_preview as dp
import docs_only_publish as docs
import publication_receipts as rec

POLICY_SCHEMA = 'ces.ec291.docs_receipt_policy.v1'
SUBJECT_SCHEMA = 'ces.ec291.docs_exact_read_subject.v1'
VOTE_SCHEMA = 'ces.ec291.docs_offline_vote.v1'
GRANT_SCHEMA = 'ces.ec291.docs_two_vote_grant.v1'
REQUEST_SCHEMA = 'ces.ec291.docs_readback_request.v1'
REPLY_SCHEMA = 'ces.ec291.docs_signed_readback_reply.v1'
DENIAL_SCHEMA = 'ces.ec291.docs_receipt_denial.v1'
RESULT_SCHEMA = 'ces.ec291.verified_docs_local_readback.v1'
READ_TEMPLATE_SCHEMA = 'ces.ec291.docs_read_template.v1'
DOMAINS = {
    'custodian': b'CES/EC291/DocsReceipt/RepositoryCustodian/v1\0',
    'inspector': b'CES/EC291/DocsReceipt/IndependentInspector/v1\0',
    'server': b'CES/EC291/DocsReceipt/SignedResult/v1\0',
}
MAX_POLICY, MAX_RPC, MAX_REPLY, MAX_TTL = 14000, 14000, 19000, 25
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
PINS = ('job_sha256', 'original_receipt_code_sha256',
        'original_docs_code_sha256', 'host_code_sha256')
POLICY_KEYS = {'schema', 'job_file', 'job_sha256', 'audit_root',
               'admission_root', 'allowed_uids', 'read_public_hex',
               'cleanup_public_hex', 'receipt_epoch', 'custodian_public_hex',
               'inspector_public_hex', 'server_public_hex',
               'original_receipt_code_sha256', 'original_docs_code_sha256',
               'host_code_sha256', 'enable_one_private_docs_readback'}
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
# Pin every original executable/verification dependency used by this host.
ORIGINAL_SOURCES = ('publication_receipts.py', 'docs_only_publish.py',
                    'delivery_authorization.py', 'delivery_preview.py',
                    'delivery_send.py', 'report_publish.py',
                    'ec285_docs_sandbox_host/protocol.py',
                    'ec285_docs_sandbox_host/daemon.py')
HOST_SOURCES = ('protocol.py', 'daemon.py', 'operator.py')


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'unavailable'):
        super().__init__(code)
        self.code, self.status = code, status


def need(ok: bool, code: str, status: str = 'unavailable') -> None:
    if ok is not True:
        raise HostError(code, status)


def canonical(obj: Any) -> bytes:
    return io.canonical(obj)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fields(obj: Any, names: set, code: str) -> dict:
    need(type(obj) is dict and set(obj) == names, code, 'invalid_input')
    return obj


def code_sha(domain: bytes, root: Path, names: tuple[str, ...]) -> str:
    digest = hashlib.sha256(domain)
    for name in names:
        p = root / name
        need(p.is_file() and not p.is_symlink(),
             'EC291_CODE_SOURCE_MISSING_OR_SYMLINK')
        raw = p.read_bytes()
        digest.update(name.encode('ascii') + b'\0' +
                      len(raw).to_bytes(8, 'big') + raw)
    return digest.hexdigest()


def original_sha() -> str:
    return code_sha(b'CES/EC291/Original-EC229-230-285/v1\0',
                    Path(__file__).resolve().parents[1], ORIGINAL_SOURCES)


def host_sha() -> str:
    return code_sha(b'CES/EC291/Independent-Docs-Readback-Host/v1\0',
                    Path(__file__).resolve().parent, HOST_SOURCES)


def private_bytes(path: str, expected: str, limit: int) -> bytes:
    raw = old.private_file(path, limit)
    need(hmac.compare_digest(sha(raw), expected),
         'EC291_PRIVATE_FILE_RAW_BYTES_CHANGED')
    return raw


def load_job(pol: dict) -> dict:
    raw = private_bytes(pol['job_file'], pol['job_sha256'], old.MAX_JOB)
    return old.validate_job(io.parse(raw, old.MAX_JOB))


def _distinct_roots(job: dict, pol: dict) -> None:
    """No audit/admission content may be inside source, bare, worktree or journal."""
    access = job['access']
    originals = [access[k] for k in ('repository_root', 'journal_root',
                                    'worktree_root', 'sandbox_bare_root')]
    controlled = [pol['job_file'], pol['audit_root'], pol['admission_root']]
    # Audit/admission paths must not alias or nest *any* original scope.
    for pos, x in enumerate(controlled):
        for y in controlled[pos + 1:] + originals:
            need(not (x == y or x.startswith(y + '/') or y.startswith(x + '/')),
                 'EC291_ORIGINAL_AND_READ_HOST_PATHS_OVERLAP')
    for x in (pol['audit_root'], pol['admission_root']):
        rec._safe_private_dir(x)


def validate_policy(doc: Any) -> dict:
    pol = fields(doc, POLICY_KEYS, 'EC291_POLICY_EXACT_FIELDS_REQUIRED')
    need(pol['schema'] == POLICY_SCHEMA and
         pol['enable_one_private_docs_readback'] is True,
         'EC291_OWNER_OPT_IN_REQUIRED', 'permission_denied')
    need(all(old.plain_abs(pol[k]) for k in
             ('job_file', 'audit_root', 'admission_root')),
         'EC291_ABSOLUTE_OWNER_PRIVATE_PATHS_REQUIRED')
    need(all(type(pol[k]) is str and HEX.fullmatch(pol[k]) is not None
             for k in PINS), 'EC291_CODE_AND_DATA_SHA_PINS_REQUIRED')
    need(pol['original_receipt_code_sha256'] == rec.ACTIVE_CODE_SHA256 == rec._code_hash()
         and pol['original_docs_code_sha256'] == original_sha()
         and pol['host_code_sha256'] == host_sha(),
         'EC291_ORIGINAL_OR_HOST_CODE_DRIFT')
    need(type(pol['receipt_epoch']) is int and 1 <= pol['receipt_epoch'] < 2**63,
         'EC291_RECEIPT_EPOCH_INVALID')
    uids = pol['allowed_uids']
    need(type(uids) is list and 1 <= len(uids) <= 32 and
         all(type(n) is int and 0 <= n <= 2**31-1 for n in uids) and
         uids == sorted(set(uids)), 'EC291_KERNEL_UID_ALLOWLIST_INVALID')
    key_names = ('read_public_hex', 'cleanup_public_hex',
                 'custodian_public_hex', 'inspector_public_hex',
                 'server_public_hex')
    keys = [pol[k] for k in key_names]
    try:
        for key in keys:
            io.pub_from_hex(key)
    except (TypeError, ValueError) as exc:
        raise HostError('EC291_PUBLIC_ROOT_INVALID') from exc
    need(len(set(keys)) == 5, 'EC291_FIVE_NEW_PUBLIC_ROOTS_MUST_DIFFER')
    return pol


def load_policy(path: str, digest: str) -> dict:
    need(type(digest) is str and HEX.fullmatch(digest) is not None,
         'EC291_PINNED_POLICY_SHA_REQUIRED')
    return validate_policy(io.parse(private_bytes(path, digest, MAX_POLICY),
                                    MAX_POLICY))


def service(pol: dict) -> tuple[rec.PublicationReceiptService,
                                docs.HostDocsScope, docs.DocsOnlyPublishRequest]:
    """Construct original verification/read services, never a publication call."""
    job = load_job(pol)
    orig = [job['access'][k] for k in ('policy_public_hex',
        'reviewer_public_hex', 'revocation_public_hex', 'side_effect_public_hex')]
    added = [pol[k] for k in ('read_public_hex', 'cleanup_public_hex',
                              'custodian_public_hex', 'inspector_public_hex',
                              'server_public_hex')]
    need(len(set(orig + added)) == 9,
         'EC291_ALL_NINE_SIGNER_PUBLIC_ROOTS_MUST_DIFFER')
    _distinct_roots(job, pol)
    original_publisher, original_request = original_docs.original_backend(job)
    # No original publisher.publish_once/cleanup_docs method is called.
    roots = rec.ReceiptRoots(bytes.fromhex(pol['read_public_hex']),
                             bytes.fromhex(pol['cleanup_public_hex']),
                             pol['receipt_epoch'])
    scope = rec.HostReceiptScope(roots, pol['audit_root'], True, False, False, '')
    svc = rec.PublicationReceiptService(scope)
    need(svc.host.enable_clean_linked_worktree is False and
         svc.host.provider_read_credential == '' and
         svc.host.allow_synthetic_receipt_reader_for_development is False,
         'EC291_GIT_READBACK_ONLY_NO_GET_NO_CLEANUP')
    return svc, original_publisher.access, original_request


def operation_scope(pol: dict) -> dict:
    svc, access, req = service(pol)
    _pub, operation, target, original_grant, _journal, pins = svc._base(
        rec.MODE_DOCS, req, access)
    # An exact operation reconstruction is required before preparing tickets.
    current = old.job_pins(load_job(pol))
    need(operation == old.operation_id(current) and
         target == current['target_binding_sha256'] and
         pins['manifest_sha256'] == current['manifest_sha256'],
         'EC291_ORIGINAL_DOCS_OPERATION_OR_MANIFEST_CHANGED')
    return {'operation_sha256': operation, 'target_sha256': target,
            'original_grant_sha256': original_grant}


def read_statement(doc: Any, public_hex: str) -> da.SignedAuthorizationStatement:
    try:
        fields(doc, {'statement', 'signature_hex'},
               'EC291_ORIGINAL_EC230_READ_ENVELOPE_REQUIRED')
        signed = da.SignedAuthorizationStatement(doc['statement'], doc['signature_hex'])
        body = rec._signed(signed, bytes.fromhex(public_hex), rec.READ_DOMAIN,
            {'schema', 'mode', 'operation_id', 'target_sha256',
             'original_grant_sha256', 'inspection_nonce', 'receipt_epoch',
             'code_revision_sha256', 'permission', 'issued_at', 'expires_at'},
            'READ_GRANT')
        rec._window(body, rec._time())
        need(body['schema'] == rec.READ_SCHEMA and body['mode'] == rec.MODE_DOCS and
             body['permission'] == rec.READ_PERMISSION and
             body['expires_at'] - body['issued_at'] <= 36 and
             type(body['inspection_nonce']) is str and
             io.HEX_NONCE.fullmatch(body['inspection_nonce']) is not None and
             body['code_revision_sha256'] == rec.ACTIVE_CODE_SHA256,
             'EC291_ONLY_ORIGINAL_DOCS_READ_GRANT_ALLOWED', 'permission_denied')
        return signed
    except (rec.ReceiptDenied, da.AuthorizationDenied, ValueError,
            TypeError, KeyError) as exc:
        raise HostError('EC291_EC230_READ_GRANT_INVALID',
                        'permission_denied') from exc


def sign(role: str, body: dict, key) -> str:
    return key.sign(DOMAINS[role] + canonical(body)).hex()


def verify(role: str, body: dict, signature: Any, public_hex: str) -> None:
    need(type(signature) is str and io.HEX_SIG.fullmatch(signature) is not None,
         'EC291_SIGNATURE_SHAPE_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(public_hex).verify(bytes.fromhex(signature),
                                           DOMAINS[role] + canonical(body))
    except Exception as exc:
        raise HostError('EC291_HOST_SIGNATURE_INVALID',
                        'permission_denied') from exc


def new_subject(pol: dict, policy_sha: str, read: dict,
                uid: int, ttl: int) -> dict:
    need(type(uid) is int and uid in pol['allowed_uids'] and
         type(ttl) is int and 1 <= ttl <= MAX_TTL,
         'EC291_UID_OR_SHORT_HOST_TTL_INVALID', 'permission_denied')
    signed = read_statement(read, pol['read_public_hex'])
    original = operation_scope(pol)
    body = signed.statement
    need(body['operation_id'] == original['operation_sha256'] and
         body['target_sha256'] == original['target_sha256'] and
         body['original_grant_sha256'] == original['original_grant_sha256'] and
         body['receipt_epoch'] >= pol['receipt_epoch'],
         'EC291_EC230_READ_PERMISSION_WRONG_ORIGINAL_OPERATION',
         'permission_denied')
    now = rec._time()
    return validate_subject({'schema': SUBJECT_SCHEMA,
        'grant_id': secrets.token_hex(16), 'uid': uid,
        'policy_sha256': policy_sha, **{k: pol[k] for k in PINS},
        **original, 'read_grant_sha256': sha(canonical(read)),
        'issued_at_unix': now, 'expires_at_unix': now + ttl})


def validate_subject(doc: Any) -> dict:
    s = fields(doc, SUBJECT_KEYS, 'EC291_SUBJECT_EXACT_FIELDS_REQUIRED')
    digest_fields = SUBJECT_KEYS - {'schema', 'grant_id', 'uid',
                                    'issued_at_unix', 'expires_at_unix'}
    need(s['schema'] == SUBJECT_SCHEMA and
         type(s['grant_id']) is str and io.HEX_NONCE.fullmatch(s['grant_id']) is not None and
         type(s['uid']) is int and 0 <= s['uid'] <= 2**31-1 and
         all(type(s[k]) is str and HEX.fullmatch(s[k]) is not None
             for k in digest_fields) and
         type(s['issued_at_unix']) is int and
         type(s['expires_at_unix']) is int and
         946684800 <= s['issued_at_unix'] < s['expires_at_unix'] <= 4102444800 and
         s['expires_at_unix'] - s['issued_at_unix'] <= MAX_TTL,
         'EC291_SHORT_EXACT_HOST_SUBJECT_INVALID')
    return s


def validate_grant(grant: Any, pol: dict, read: dict, uid: int,
                   policy_sha: str, now: int) -> dict:
    fields(grant, {'schema', 'subject', 'custodian_signature_ed25519',
                   'inspector_signature_ed25519'},
           'EC291_TWO_INDEPENDENT_HOST_VOTES_REQUIRED')
    need(grant['schema'] == GRANT_SCHEMA,
         'EC291_OFFLINE_GRANT_SCHEMA_INVALID', 'permission_denied')
    try:
        s = validate_subject(grant['subject'])
    except (HostError, ValueError, TypeError, KeyError) as exc:
        raise HostError('EC291_HOST_SUBJECT_INVALID', 'permission_denied') from exc
    need(uid in pol['allowed_uids'] and s['uid'] == uid and
         s['policy_sha256'] == policy_sha and
         all(s[k] == pol[k] for k in PINS) and
         s['read_grant_sha256'] == sha(canonical(read)) and
         s['issued_at_unix'] <= now + 5 and now < s['expires_at_unix'],
         'EC291_PEER_UID_OR_PIN_OR_HOST_VOTE_EXPIRED', 'permission_denied')
    signed = read_statement(read, pol['read_public_hex'])
    need(signed.statement['operation_id'] == s['operation_sha256'] and
         signed.statement['target_sha256'] == s['target_sha256'] and
         signed.statement['original_grant_sha256'] == s['original_grant_sha256'] and
         signed.statement['receipt_epoch'] >= pol['receipt_epoch'],
         'EC291_READ_PERMISSION_AND_HOST_SUBJECT_MISMATCH', 'permission_denied')
    for role in ('custodian', 'inspector'):
        verify(role, s, grant[role + '_signature_ed25519'],
               pol[role + '_public_hex'])
    return s


def validate_backend(doc: Any, op: str | None = None) -> dict:
    fields(doc, RESULT_KEYS, 'EC291_ORIGINAL_EC230_RESULT_FIELDS_CHANGED')
    need(doc['schema'] == rec.SCHEMA and doc['mode'] == rec.MODE_DOCS and
         (doc['status'], doc['exit_code']) in (
             ('partial', 2), ('blocked', 4), ('invalid_input', 4),
             ('unavailable', 5)) and
         type(doc['reason_code']) is str and re.fullmatch(
             r'PUBLICATION_RECEIPT_[A-Z0-9_]{1,150}', doc['reason_code']) is not None and
         all(doc[k] is False for k in (
             'provider_receipt_read_attempted', 'cleanup_attempted',
             'local_worktree_cleanup_confirmed', 'public_or_production_published',
             'external_publication_confirmed', 'original_post_or_push_retried',
             'remote_ref_or_provider_content_deleted',
             'original_journal_deleted', 'original_source_or_index_modified')) and
         all(type(doc[k]) is bool for k in (
             'historical_journal_present', 'provider_receipt_read_attempted',
             'cleanup_attempted', 'local_worktree_cleanup_confirmed',
             'public_or_production_published', 'external_publication_confirmed',
             'original_post_or_push_retried', 'remote_ref_or_provider_content_deleted',
             'original_journal_deleted', 'original_source_or_index_modified')) and
         all(v is None or (type(v) is str and HEX.fullmatch(v) is not None)
             for v in (doc['operation_id'], doc['inspection_id'],
                       doc['observation_sha256'])) and
         (op is None or doc['operation_id'] in (None, op)) and
         type(doc['evidence_kind']) is str and type(doc['receipt_state']) is str,
         'EC291_UNSAFE_OR_INCONSISTENT_EC230_DOCS_RESULT')
    if doc['status'] == 'partial':
        need(doc['operation_id'] is not None and
             doc['receipt_state'] in (
                 'VERIFIED_PRIVATE_LOCAL_REF_ONLY', 'UNKNOWN_PRIVATE_REF_ABSENT') and
             doc['evidence_kind'] == 'LOCAL_GIT_PRIVATE_BARE_READBACK' and
             doc['historical_journal_present'] is True and
             doc['inspection_id'] is not None and
             doc['observation_sha256'] is not None and
             doc['reason_code'].endswith(doc['receipt_state']),
             'EC291_ONLY_ORIGINAL_EC230_PRIVATE_GIT_READBACK_ALLOWED')
    else:
        need(doc['evidence_kind'] == 'NONE' and
             doc['observation_sha256'] is None,
             'EC291_DENIED_GIT_READ_CANNOT_CLAIM_EVIDENCE')
    return doc


def denial(code: str, status: str = 'unavailable', *, attempted: bool = False) -> dict:
    need(status in ('unavailable', 'permission_denied', 'invalid_input'),
         'EC291_INTERNAL_DENIAL_STATUS_INVALID')
    return {'schema': DENIAL_SCHEMA, 'status': status,
            'exit_code': {'unavailable': 5, 'permission_denied': 3,
                          'invalid_input': 4}[status], 'reason_code': code,
            'git_readback_may_have_been_attempted': attempted,
            'publication_confirmed': False, 'worktree_cleanup_attempted': False,
            'git_ref_modified': False, 'original_docs_publish_retried': False,
            'automatic_git_read_or_publish_retry_allowed': False}


def signed_reply(request: dict, result: dict, policy_sha: str, job_sha: str,
                 signer, now: int) -> dict:
    body = {'schema': REPLY_SCHEMA, 'nonce': request['nonce'],
            'request_sha256': sha(canonical(request)),
            'policy_sha256': policy_sha, 'job_sha256': job_sha,
            'issued_at_unix': now, 'result': result}
    return {**body, 'signature_ed25519': sign('server', body, signer)}


def verify_reply(reply: Any, req: dict, public_hex: str,
                 policy_sha: str, now: int) -> dict:
    fields(reply, {'schema', 'nonce', 'request_sha256', 'policy_sha256',
                   'job_sha256', 'issued_at_unix', 'result', 'signature_ed25519'},
           'EC291_SIGNED_REPLY_EXACT_FIELDS_REQUIRED')
    subject = validate_subject(req['grant']['subject'])
    need(reply['schema'] == REPLY_SCHEMA and reply['nonce'] == req['nonce'] and
         reply['request_sha256'] == sha(canonical(req)) and
         reply['policy_sha256'] == policy_sha == subject['policy_sha256'] and
         reply['job_sha256'] == subject['job_sha256'] and
         type(reply['issued_at_unix']) is int and
         abs(now - reply['issued_at_unix']) <= 90,
         'EC291_REPLY_NONCE_REQUEST_OR_AUTHORITY_PIN_MISMATCH')
    verify('server', {k: v for k, v in reply.items() if k != 'signature_ed25519'},
           reply['signature_ed25519'], public_hex)
    result = reply['result']
    if type(result) is dict and result.get('schema') == rec.SCHEMA:
        return validate_backend(result, subject['operation_sha256'])
    fields(result, set(denial('EC291_EXAMPLE')),
           'EC291_SIGNED_DENIAL_EXACT_FIELDS_REQUIRED')
    need(result['schema'] == DENIAL_SCHEMA and
         (result['status'], result['exit_code']) in (
             ('permission_denied', 3), ('invalid_input', 4), ('unavailable', 5)) and
         type(result['reason_code']) is str and re.fullmatch(
             r'EC291_[A-Z0-9_]{1,150}', result['reason_code']) is not None and
         type(result['git_readback_may_have_been_attempted']) is bool and
         all(result[k] is False for k in (
             'publication_confirmed', 'worktree_cleanup_attempted',
             'git_ref_modified', 'original_docs_publish_retried',
             'automatic_git_read_or_publish_retry_allowed')),
         'EC291_SIGNED_HOST_DENIAL_UNSAFE')
    return result
