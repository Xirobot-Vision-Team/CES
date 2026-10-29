#!/usr/bin/env python3
"""EC285: exact EC229 docs-only local sandbox job, dual offline vote and signed result.

Private document bytes and original four domain-specific approvals never cross
the AF_UNIX request boundary. Host-specific signers DO NOT replace any of the
original EC229 reviewers/issuer/revocation/one-use grant signatures.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from finding_query_host import protocol as io
import delivery_preview as dp
import docs_only_publish as docs

POLICY_SCHEMA = 'ces.ec285.docs_host_policy.v1'
JOB_SCHEMA = 'ces.ec285.docs_private_exact_job.v1'
SUBJECT_SCHEMA = 'ces.ec285.docs_offline_subject.v1'
GRANT_SCHEMA = 'ces.ec285.docs_two_vote_grant.v1'
VOTE_SCHEMA = 'ces.ec285.docs_offline_vote.v1'
REQUEST_SCHEMA = 'ces.ec285.docs_publish_request.v1'
REPLY_SCHEMA = 'ces.ec285.docs_signed_reply.v1'
DENIAL_SCHEMA = 'ces.ec285.docs_host_denial.v1'
RESULT_SCHEMA = 'ces.ec285.verified_docs_sandbox_result.v1'
INSPECTION_SCHEMA = 'ces.ec285.docs_job_inspection.v1'
DOMAINS = {
    'custodian': b'CES/EC285/DocsOnlyPublish/SandboxCustodian/v1\0',
    'authorizer': b'CES/EC285/DocsOnlyPublish/ReleaseAuthorizer/v1\0',
    'server': b'CES/EC285/DocsOnlyPublish/ServerReceipt/v1\0',
}
POLICY_KEYS = {'schema','job_file','job_sha256','allowed_uids',
               'custodian_issuer_public_hex','authorizer_issuer_public_hex',
               'server_public_hex'}
ACCESS_KEYS = {'issuer_id','operator_id','project_id','repository_id',
               'policy_public_hex','reviewer_public_hex',
               'revocation_public_hex','side_effect_public_hex',
               'minimum_policy_epoch','repository_root','approved_base_commit',
               'allowed_exact_paths','worktree_root','journal_root',
               'sandbox_bare_root','git_executable',
               'enable_private_local_sandbox_publish'}
REQUEST_KEYS = {'documents','repository_policy','content_review',
                'current_revocation','one_use_grant',
                'explicitly_approve_exact_docs_only_local_publish'}
SUBJECT_KEYS = {'schema','grant_id','uid','policy_sha256','job_sha256',
                'project_id','repository_id','base_commit','manifest_sha256',
                'allowlist_sha256','target_binding_sha256',
                'docs_backend_sha256','issued_at_unix','expires_at_unix'}
MAX_JOB = 500 * 1024
MAX_POLICY = 8192
MAX_RPC = 8192
MAX_REPLY = 32768
MAX_TTL = 45
CLOCK_SKEW = 5


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input'):
        super().__init__(code)
        self.code, self.status = code, status


def need(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if ok is not True:
        raise HostError(code, status)


def canonical(doc: Any) -> bytes:
    return io.canonical(doc)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign(role: str, value: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(DOMAINS[role] + canonical(value)).hex()


def verify(role: str, value: dict, signature: Any, pub_hex: str) -> None:
    need(type(signature) is str and io.HEX_SIG.fullmatch(signature) is not None,
         'EC285_SIGNATURE_FORMAT_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(pub_hex).verify(bytes.fromhex(signature),
                                        DOMAINS[role] + canonical(value))
    except Exception as exc:
        raise HostError('EC285_SIGNATURE_INVALID', 'permission_denied') from exc


def plain_abs(s: Any) -> bool:
    return (type(s) is str and os.path.isabs(s) and s != '/' and
            not s.startswith('//') and len(s) < 2048 and '\0' not in s and
            os.path.normpath(s) == s)


def private_file(path: str, limit: int) -> bytes:
    """Owner-only private input, including owner-only immediate parent.

    The byte digest is checked by load_policy/load_job; never accept a
    symlink path or owner-writable public parent as authority.
    """
    need(plain_abs(path), 'EC285_PRIVATE_FILE_ABSOLUTE_REQUIRED', 'unavailable')
    try:
        parent = Path(path).parent
        need(not any(x.is_symlink() for x in (Path(path),*Path(path).parents)),
             'EC285_PRIVATE_PATH_SYMLINK_ANCESTOR','unavailable')
        st = os.lstat(parent)
        need(stat.S_ISDIR(st.st_mode) and
             st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) & 0o077 == 0,
             'EC285_PRIVATE_PARENT_NOT_OWNER_ONLY', 'unavailable')
        st = os.lstat(path)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
             stat.S_IMODE(st.st_mode) & 0o077 == 0,
             'EC285_PRIVATE_FILE_NOT_OWNER_ONLY', 'unavailable')
        return io._open_regular(path, limit, private=True)
    except OSError as exc:
        raise HostError('EC285_PRIVATE_FILE_UNAVAILABLE', 'unavailable') from exc


def validate_policy(value: Any) -> dict:
    need(type(value) is dict and set(value) == POLICY_KEYS and
         value.get('schema') == POLICY_SCHEMA and plain_abs(value['job_file']) and
         type(value['job_sha256']) is str and
         io.HASH.fullmatch(value['job_sha256']) is not None,
         'EC285_POLICY_FIELDS_INVALID', 'unavailable')
    uids = value['allowed_uids']
    need(type(uids) is list and 1 <= len(uids) <= 32 and
         all(type(n) is int and 0 <= n <= 2**31-1 for n in uids) and
         uids == sorted(set(uids)), 'EC285_POLICY_KERNEL_UIDS_INVALID', 'unavailable')
    keys = [value[f'{name}_issuer_public_hex'] for name in ('custodian', 'authorizer')]
    keys += [value['server_public_hex']]
    try:
        for key in keys:
            io.pub_from_hex(key)
    except (TypeError, ValueError) as exc:
        raise HostError('EC285_POLICY_HOST_KEYS_INVALID', 'unavailable') from exc
    need(len(set(keys)) == 3, 'EC285_THREE_SEPARATE_HOST_KEYS_REQUIRED', 'unavailable')
    return value


def load_policy(path: str, expected_sha: str) -> dict:
    need(type(expected_sha) is str and io.HASH.fullmatch(expected_sha) is not None,
         'EC285_POLICY_PIN_REQUIRED', 'unavailable')
    raw = private_file(path, MAX_POLICY)
    need(hmac.compare_digest(sha(raw), expected_sha),
         'EC285_POLICY_RAW_BYTES_DRIFT', 'unavailable')
    return validate_policy(io.parse(raw, MAX_POLICY))


def manifest_of(job: dict) -> tuple[str, str]:
    """Validate exact private text and derive public *hash only* review pins."""
    access, req = job['access'], job['request']
    manifest = []
    total = 0
    paths = []
    for record in req['documents']:
        need(type(record) is dict and set(record) ==
             {'relative_path', 'content_b64', 'content_sha256'} and
             type(record['relative_path']) is str and
             docs._safe_path(record['relative_path']) and
             type(record['content_b64']) is str and
             4 <= len(record['content_b64']) <= 4 * ((docs.MAX_FILE_BYTES+2)//3) and
             type(record['content_sha256']) is str and
             io.HASH.fullmatch(record['content_sha256']) is not None,
             'EC285_PRIVATE_DOC_FIELDS_INVALID', 'unavailable')
        try:
            content = base64.b64decode(record['content_b64'], validate=True)
            decoded = content.decode('utf-8', 'strict')
        except (binascii.Error, ValueError, UnicodeError) as exc:
            raise HostError('EC285_PRIVATE_DOC_ENCODING_INVALID','unavailable') from exc
        need(0 < len(content) <= docs.MAX_FILE_BYTES and
             base64.b64encode(content).decode('ascii') == record['content_b64'] and
             sha(content) == record['content_sha256'] and
             '\x00' not in decoded and '\r' not in decoded and
             all((ord(c) >= 32 or c in '\n\t') and ord(c) != 127 for c in decoded) and
             not any(rx.search(content) for rx in docs.CREDENTIAL),
             'EC285_PRIVATE_DOC_REVIEW_CONTENT_INVALID', 'unavailable')
        paths.append(record['relative_path'])
        manifest.append({'relative_path': record['relative_path'],
                         'sha256': record['content_sha256'],
                         'size_bytes': len(content)})
        total += len(content)
    need(total <= docs.MAX_DOC_BYTES and paths == sorted(set(paths)) and
         set(paths).issubset(set(access['allowed_exact_paths'])),
         'EC285_PRIVATE_DOC_MANIFEST_OR_ALLOWLIST_INVALID', 'unavailable')
    return dp.sha(docs.MANIFEST_DOMAIN, manifest), sha(canonical(access['allowed_exact_paths']))


def validate_job(value: Any) -> dict:
    need(type(value) is dict and set(value) == {'schema','access','request'} and
         value.get('schema') == JOB_SCHEMA and
         type(value['access']) is dict and set(value['access']) == ACCESS_KEYS and
         type(value['request']) is dict and set(value['request']) == REQUEST_KEYS,
         'EC285_PRIVATE_JOB_FIELDS_INVALID', 'unavailable')
    a, r = value['access'], value['request']
    need(all(type(a[k]) is str and plain_abs(a[k]) for k in
             ('repository_root','worktree_root','journal_root',
              'sandbox_bare_root','git_executable')) and
         type(a['approved_base_commit']) is str and
         docs.GIT_SHA.fullmatch(a['approved_base_commit']) is not None and
         type(a['minimum_policy_epoch']) is int and
         1 <= a['minimum_policy_epoch'] < 2**63 and
         a['enable_private_local_sandbox_publish'] is True,
         'EC285_EXACT_PRIVATE_GIT_SCOPE_INVALID', 'unavailable')
    need(all(type(a[k]) is str and docs.IDENT.fullmatch(a[k]) is not None
             for k in ('issuer_id','operator_id')) and
         type(a['project_id']) is str and docs.PROJECT.fullmatch(a['project_id']) is not None and
         type(a['repository_id']) is str and docs.REPO_ID.fullmatch(a['repository_id']) is not None and
         type(a['allowed_exact_paths']) is list and
         1 <= len(a['allowed_exact_paths']) <= docs.MAX_FILES and
         a['allowed_exact_paths'] == sorted(set(a['allowed_exact_paths'])) and
         all(docs._safe_path(path) for path in a['allowed_exact_paths']),
         'EC285_IDENTITIES_OR_EXACT_NEW_DOC_PATHS_INVALID', 'unavailable')
    pubkeys = [a[k] for k in ('policy_public_hex', 'reviewer_public_hex',
                              'revocation_public_hex', 'side_effect_public_hex')]
    try:
        for key in pubkeys:
            io.pub_from_hex(key)
    except (TypeError, ValueError) as exc:
        raise HostError('EC285_ORIGINAL_EC229_PUBLIC_KEYS_INVALID','unavailable') from exc
    need(len(set(pubkeys)) == 4,
         'EC285_ORIGINAL_FOUR_EC229_SIGNERS_MUST_DIFFER','unavailable')
    need(r['explicitly_approve_exact_docs_only_local_publish'] is True and
         type(r['documents']) is list and 1 <= len(r['documents']) <= docs.MAX_FILES,
         'EC285_PRIVATE_DOCS_ONLY_CONSENT_MISSING','unavailable')
    for name in ('repository_policy', 'content_review', 'current_revocation', 'one_use_grant'):
        record = r[name]
        need(type(record) is dict and set(record) == {'statement','signature_hex'} and
             type(record['statement']) is dict and type(record['signature_hex']) is str and
             io.HEX_SIG.fullmatch(record['signature_hex']) is not None,
             'EC285_ORIGINAL_EC229_SIGNED_RECORD_REQUIRED', 'unavailable')
    manifest, _ = manifest_of(value)
    grant = r['one_use_grant']['statement']
    need(grant.get('manifest_sha256') == manifest and
         type(docs.ACTIVE_CODE_SHA256) is str and
         io.HASH.fullmatch(docs.ACTIVE_CODE_SHA256) is not None and
         grant.get('code_revision_sha256') == docs.ACTIVE_CODE_SHA256 and
         grant.get('base_commit') == a['approved_base_commit'] and
         grant.get('repository_id') == a['repository_id'] and
         grant.get('project_id') == a['project_id'] and
         grant.get('action') == docs.ACTION and
         grant.get('target_binding_sha256') is not None and
         type(grant.get('target_binding_sha256')) is str and
         io.HASH.fullmatch(grant['target_binding_sha256']) is not None,
         'EC285_ORIGINAL_EXACT_GRANT_BINDING_INVALID', 'unavailable')
    return value


def load_job(pol: dict) -> dict:
    raw = private_file(pol['job_file'], MAX_JOB)
    need(hmac.compare_digest(sha(raw), pol['job_sha256']),
         'EC285_PRIVATE_JOB_RAW_BYTES_DRIFT','unavailable')
    return validate_job(io.parse(raw, MAX_JOB))


def job_pins(job: dict) -> dict:
    manifest, paths = manifest_of(job)
    a = job['access']
    return {'project_id': a['project_id'], 'repository_id': a['repository_id'],
            'base_commit': a['approved_base_commit'],
            'manifest_sha256': manifest,'allowlist_sha256': paths,
            'target_binding_sha256': job['request']['one_use_grant']['statement']['target_binding_sha256'],
            'docs_backend_sha256': docs.ACTIVE_CODE_SHA256}


def validate_subject(s: Any) -> dict:
    need(type(s) is dict and set(s) == SUBJECT_KEYS and
         s.get('schema') == SUBJECT_SCHEMA and
         type(s.get('grant_id')) is str and io.HEX_NONCE.fullmatch(s['grant_id']) is not None and
         type(s.get('uid')) is int and 0 <= s['uid'] <= 2**31-1 and
         type(s.get('project_id')) is str and docs.PROJECT.fullmatch(s['project_id']) is not None and
         type(s.get('repository_id')) is str and docs.REPO_ID.fullmatch(s['repository_id']) is not None and
         type(s.get('base_commit')) is str and docs.GIT_SHA.fullmatch(s['base_commit']) is not None and
         all(type(s[k]) is str and io.HASH.fullmatch(s[k]) is not None for k in
             ('policy_sha256','job_sha256','manifest_sha256','allowlist_sha256',
              'target_binding_sha256','docs_backend_sha256')),
         'EC285_OFFLINE_SUBJECT_FIELDS_INVALID')
    a,b = s['issued_at_unix'],s['expires_at_unix']
    need(type(a) is int and type(b) is int and 0 < a < b and b-a <= MAX_TTL,
         'EC285_OFFLINE_SUBJECT_LIFETIME_INVALID')
    return s


def new_subject(*, uid: int, policy_sha: str, job_sha: str,
                project_id: str, repository_id: str, base_commit: str,
                manifest_sha: str, allowlist_sha: str, target_sha: str,
                backend_sha: str, ttl: int, now: int | None = None) -> dict:
    need(type(ttl) is int and 1 <= ttl <= MAX_TTL,
         'EC285_TTL_OUT_OF_RANGE')
    t = int(time.time()) if now is None else now
    return validate_subject({'schema':SUBJECT_SCHEMA,'grant_id':secrets.token_hex(16),
        'uid':uid,'policy_sha256':policy_sha,'job_sha256':job_sha,
        'project_id':project_id,'repository_id':repository_id,
        'base_commit':base_commit,'manifest_sha256':manifest_sha,
        'allowlist_sha256':allowlist_sha,'target_binding_sha256':target_sha,
        'docs_backend_sha256':backend_sha,'issued_at_unix':t,'expires_at_unix':t+ttl})


def validate_grant(grant: Any, policy: dict, job: dict, *,
                   uid: int, now: int, policy_sha: str) -> dict:
    need(type(grant) is dict and set(grant) == {
        'schema','subject','custodian_signature_ed25519',
        'authorizer_signature_ed25519'} and
        grant.get('schema') == GRANT_SCHEMA,
        'EC285_TWO_OFFLINE_SIGNATURES_REQUIRED','permission_denied')
    try:
        subject = validate_subject(grant['subject'])
    except (HostError, ValueError, TypeError, KeyError) as exc:
        raise HostError('EC285_SIGNED_SUBJECT_INVALID','permission_denied') from exc
    pins = job_pins(job)
    need(uid in policy['allowed_uids'] and subject['uid'] == uid and
         subject['policy_sha256'] == policy_sha and
         subject['job_sha256'] == policy['job_sha256'] and
         all(subject[k] == pins[k] for k in pins) and
         subject['issued_at_unix'] <= now + CLOCK_SKEW and
         now < subject['expires_at_unix'],
         'EC285_UID_SCOPE_PIN_OR_EXPIRY_MISMATCH','permission_denied')
    for role in ('custodian','authorizer'):
        verify(role, subject, grant[f'{role}_signature_ed25519'],
               policy[f'{role}_issuer_public_hex'])
    return subject


def operation_id(subject: dict) -> str:
    return dp.sha(docs.OP_DOMAIN, {
        'repository_id':subject['repository_id'],
        'project_id':subject['project_id'],
        'base_commit':subject['base_commit'],
        'manifest_sha256':subject['manifest_sha256'],
        'private_target_sha256':subject['target_binding_sha256']})


def safe_success(result: Any, subject: dict) -> bool:
    """Verify the original EC229 side effect and *never* call it publication."""
    op = operation_id(subject)
    return (type(result) is dict and result.get('schema') == docs.SCHEMA and
        result.get('status') == 'partial' and result.get('exit_code') == 2 and
        result.get('reason_code') == 'DOCS_ONLY_PRIVATE_LOCAL_SANDBOX_REF_OBSERVED' and
        result.get('operation_id') == op and
        type(result.get('local_candidate_commit_sha')) is str and
        docs.GIT_SHA.fullmatch(result['local_candidate_commit_sha']) is not None and
        result.get('local_candidate_commit_sha') != subject['base_commit'] and
        result.get('private_sandbox_ref') == docs.REF_NAMESPACE + op and
        result.get('local_candidate_state') == 'PRIVATE_LOCAL_REF_OBSERVED_ONCE' and
        all(result.get(k) is True for k in (
            'claim_committed','isolated_worktree_created','local_commit_created',
            'private_push_attempted','private_sandbox_ref_observed',
            'original_repository_intact_verified')) and
        all(result.get(k) is False for k in (
            'published','production_or_public_published',
            'external_publication_confirmed','native_action_registered')) and
        type(result.get('effects')) is dict and
        all(result['effects'].get(k) is False for k in (
            'original_worktree_or_index_edited','business_ci_schema_path_staged',
            'existing_ref_overwritten','production_network_or_remote_requested',
            'automatic_cleanup_or_retry')) and
        result['effects'].get('private_local_sandbox_ref_write_attempted') is True)


def denial(code: str, status: str = 'unavailable', *,
           backend_invoked: bool = False,
           local_effect_outcome_unknown: bool = False) -> dict:
    need(status in ('unavailable','invalid_input','permission_denied'),
         'EC285_INTERNAL_DENIAL_STATUS_INVALID')
    return {'schema': DENIAL_SCHEMA, 'status': status,
            'exit_code': {'unavailable':5,'invalid_input':4,'permission_denied':3}[status],
            'reason_code': code,
            'handler_invoked': backend_invoked,
            'local_effect_outcome_unknown': local_effect_outcome_unknown,
            'private_local_ref_observed': None if local_effect_outcome_unknown else False,
            'business_repository_written': False,
            'production_network_or_remote_requested': False,
            'published': False,'business_effect_verified': False,
            'private_document_text_disclosed': False}


def signed_reply(req: dict, result: dict, pol_sha: str, job_sha: str,
                 key: Ed25519PrivateKey, now: int) -> dict:
    body = {'schema': REPLY_SCHEMA,'nonce':req['nonce'],
            'request_sha256': sha(canonical(req)),
            'policy_sha256':pol_sha,'job_sha256':job_sha,
            'issued_at_unix':now,'result':result}
    return {**body,'signature_ed25519':sign('server',body,key)}


def verify_reply(reply: Any, request: dict, server_pub: str,
                 policy_sha: str, now: int) -> dict:
    need(type(reply) is dict and set(reply) == {
        'schema','nonce','request_sha256','policy_sha256','job_sha256',
        'issued_at_unix','result','signature_ed25519'} and
        reply.get('schema') == REPLY_SCHEMA, 'EC285_REPLY_FIELDS_INVALID','unavailable')
    subject = validate_subject(request['grant']['subject'])
    need(reply['nonce'] == request['nonce'] and
         reply['request_sha256'] == sha(canonical(request)) and
         reply['policy_sha256'] == policy_sha == subject['policy_sha256'] and
         reply['job_sha256'] == subject['job_sha256'] and
         type(reply['issued_at_unix']) is int and
         abs(now - reply['issued_at_unix']) <= 90,
         'EC285_REPLY_REQUEST_PIN_OR_TIME_MISMATCH','unavailable')
    verify('server', {k:v for k,v in reply.items() if k!='signature_ed25519'},
           reply['signature_ed25519'],server_pub)
    result = reply['result']
    need(type(result) is dict, 'EC285_REPLY_RESULT_INVALID','unavailable')
    if result.get('status') == 'partial':
        need(safe_success(result,subject),'EC285_ORIGINAL_SANDBOX_RESULT_INVALID','unavailable')
    else:
        need(result.get('schema') == DENIAL_SCHEMA and
             (result.get('status'),result.get('exit_code')) in (
                 ('unavailable',5),('permission_denied',3),('invalid_input',4)) and
             result.get('published') is False and
             result.get('business_repository_written') is False and
             result.get('business_effect_verified') is False and
             result.get('private_document_text_disclosed') is False and
             type(result.get('local_effect_outcome_unknown')) is bool and
             ((result.get('private_local_ref_observed') is None) if
                  result['local_effect_outcome_unknown'] else
                  result.get('private_local_ref_observed') is False),
             'EC285_HOST_DENIAL_INVALID','unavailable')
    return result
