#!/usr/bin/env python3
"""EC284: exact EC208 local metadata append, never source/remote publication.

A private host administrator pins the original complete EC207+EC208 request,
policy and approvals. The AF_UNIX client supplies only a signed exact approval
for those private bytes and a fresh transport nonce. Five distinct signing
roles are enforced: original EC208 reviewer/owner, offline host custodian and
write authorizer, and separately pinned host reply signer.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec279_finding_query_host import protocol as io
import knowledge_boundary as kb
import knowledge_candidate_store as kc
import knowledge_version_save as vs

POLICY_SCHEMA = 'ces.ec284.knowledge_save_host_policy.v1'
JOB_SCHEMA = 'ces.ec284.knowledge_save_exact_job.v1'
SUBJECT_SCHEMA = 'ces.ec284.knowledge_save_offline_subject.v1'
VOTE_SCHEMA = 'ces.ec284.knowledge_save_offline_vote.v1'
GRANT_SCHEMA = 'ces.ec284.knowledge_save_dual_grant.v1'
REQUEST_SCHEMA = 'ces.ec284.knowledge_save_request.v1'
REPLY_SCHEMA = 'ces.ec284.knowledge_save_signed_reply.v1'
DENIAL_SCHEMA = 'ces.ec284.knowledge_save_denial.v1'
RESULT_SCHEMA = 'ces.ec284.verified_knowledge_save_result.v1'
DOMAINS = {
    'custodian': b'CES/EC284/KnowledgeSave.SaveLocal/StoreCustodian/v1\0',
    'authorizer': b'CES/EC284/KnowledgeSave.SaveLocal/WriteAuthorizer/v1\0',
    'server': b'CES/EC284/KnowledgeSave.SaveLocal/SignedHostReply/v1\0',
}
POLICY_KEYS = {'schema', 'job_file', 'job_sha256', 'allowed_uids',
               'custodian_issuer_public_hex', 'authorizer_issuer_public_hex',
               'server_public_hex'}
JOB_KEYS = {'schema', 'repository_root', 'knowledge_root', 'candidate_root',
            'version_root', 'candidate_store_id', 'version_store_id',
            'repository_ref', 'knowledge_space_key', 'period_id',
            'source_policy_revision', 'chapter_path', 'trusted_approvers',
            'revoked_approvers', 'save_request', 'handoff_request',
            'handoff_policy', 'candidate_read_policies', 'save_policy',
            'approvals'}
SUBJECT_KEYS = {'schema', 'grant_id', 'uid', 'policy_sha256', 'job_sha256',
                'repository_ref', 'save_key', 'save_request_sha256',
                'authorization_scope_sha256', 'new_chapter_sha256',
                'issued_at_unix', 'expires_at_unix'}
MAX_JOB = 192 * 1024
MAX_POLICY = 16 * 1024
MAX_RPC = 16 * 1024
MAX_REPLY = 64 * 1024
MAX_TTL = 300
CLOCK_SKEW = 30


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if ok is not True:
        raise HostError(code, status)


def canonical(obj: Any) -> bytes:
    return io.canonical(obj)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign(role: str, obj: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(DOMAINS[role] + canonical(obj)).hex()


def verify(role: str, obj: dict, sig: Any, pub: str) -> None:
    need(type(sig) is str and io.HEX_SIG.fullmatch(sig) is not None,
         'EC284_SIGNATURE_FORMAT_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(pub).verify(bytes.fromhex(sig), DOMAINS[role] + canonical(obj))
    except Exception as exc:
        raise HostError('EC284_SIGNATURE_INVALID', 'permission_denied') from exc


def plain_abs(value: Any) -> bool:
    return (type(value) is str and os.path.isabs(value) and value != '/' and
            not value.startswith('//') and len(value) <= 4096 and
            '\0' not in value and os.path.normpath(value) == value)


def validate_policy(pol: Any) -> dict:
    need(type(pol) is dict and set(pol) == POLICY_KEYS and
         pol.get('schema') == POLICY_SCHEMA,
         'EC284_POLICY_FIELDS_INVALID', 'unavailable')
    need(plain_abs(pol['job_file']) and type(pol['job_sha256']) is str and
         io.HASH.fullmatch(pol['job_sha256']) is not None,
         'EC284_POLICY_JOB_PIN_INVALID', 'unavailable')
    uids = pol['allowed_uids']
    need(type(uids) is list and 1 <= len(uids) <= 32 and
         len(set(uids)) == len(uids) and
         all(type(x) is int and 0 <= x <= 2**31-1 for x in uids),
         'EC284_POLICY_UID_ALLOWLIST_INVALID', 'unavailable')
    pub = [pol[f'{role}_issuer_public_hex'] for role in ('custodian','authorizer')]
    pub.append(pol['server_public_hex'])
    try:
        for key in pub:
            io.pub_from_hex(key)
    except (ValueError, TypeError) as exc:
        raise HostError('EC284_POLICY_SIGNING_KEYS_INVALID', 'unavailable') from exc
    need(len(set(pub)) == 3,
         'EC284_THREE_INDEPENDENT_HOST_SIGNERS_REQUIRED', 'unavailable')
    return pol


def load_policy(path: str, policy_sha: str) -> dict:
    need(type(policy_sha) is str and io.HASH.fullmatch(policy_sha) is not None,
         'EC284_POLICY_PIN_REQUIRED', 'unavailable')
    raw = io._open_regular(path, MAX_POLICY, private=True)
    need(hmac.compare_digest(sha(raw), policy_sha),
         'EC284_POLICY_BYTES_CHANGED', 'unavailable')
    return validate_policy(io.parse(raw, MAX_POLICY))


def validate_job(job: Any) -> dict:
    need(type(job) is dict and set(job) == JOB_KEYS and
         job.get('schema') == JOB_SCHEMA,
         'EC284_PRIVATE_JOB_FIELDS_INVALID', 'unavailable')
    roots = [job[k] for k in ('repository_root','knowledge_root','candidate_root',
                              'version_root')]
    need(all(plain_abs(v) for v in roots),
         'EC284_PRIVATE_JOB_ROOT_PATH_INVALID', 'unavailable')
    # A parent/child alias via symlinks is rejected BEFORE the business backend.
    roots_real = [os.path.realpath(v) for v in roots]
    for i, left in enumerate(roots_real):
        for right in roots_real[i+1:]:
            need(os.path.commonpath((left, right)) not in (left, right),
                 'EC284_PRIVATE_JOB_ROOTS_OVERLAP', 'unavailable')
    need(all(type(job[k]) is str and kc.STORE_ID.fullmatch(job[k]) is not None
             for k in ('candidate_store_id','version_store_id')),
         'EC284_PRIVATE_JOB_STORE_ID_INVALID', 'unavailable')
    need(type(job['repository_ref']) is str and
         kb.REPO.fullmatch(job['repository_ref']) is not None and
         all(kb.key(job[k]) for k in ('knowledge_space_key','period_id',
                                      'source_policy_revision')),
         'EC284_PRIVATE_JOB_SCOPE_INVALID', 'unavailable')
    try:
        vs._path(job['chapter_path'])
    except (vs.SaveError, ValueError) as exc:
        raise HostError('EC284_PRIVATE_JOB_CHAPTER_INVALID', 'unavailable') from exc
    approvers = job['trusted_approvers']
    need(type(approvers) is dict and 2 <= len(approvers) <= 32,
         'EC284_APPROVER_REGISTRY_INVALID', 'unavailable')
    seen_roles = set()
    for key, entry in approvers.items():
        need(kb.key(key) and type(entry) is dict and
             set(entry) == {'role','public_hex'} and
             type(entry['role']) is str and entry['role'] in vs.ROLES and
             type(entry['public_hex']) is str,
             'EC284_APPROVER_REGISTRY_ENTRY_INVALID', 'unavailable')
        try:
            io.pub_from_hex(entry['public_hex'])
        except (ValueError, TypeError) as exc:
            raise HostError('EC284_APPROVER_PUBLIC_KEY_INVALID', 'unavailable') from exc
        seen_roles.add(entry['role'])
    need(seen_roles == set(vs.ROLES), 'EC284_BOTH_EC208_APPROVER_ROLES_REQUIRED', 'unavailable')
    revoked = job['revoked_approvers']
    need(type(revoked) is list and revoked == sorted(set(revoked)) and
         all(type(k) is str and k in approvers for k in revoked) and
         all(any(entry['role'] == role and key not in revoked
                 for key, entry in approvers.items()) for role in vs.ROLES),
         'EC284_REVOKED_APPROVERS_INVALID', 'unavailable')
    req = job['save_request']
    need(type(req) is dict and req.get('schema') == vs.REQUEST_SCHEMA and
         req.get('operation') == 'knowledge.save.metadata_version' and
         all(req.get(k) == job[k] for k in (
             'repository_ref','knowledge_space_key','period_id',
             'source_policy_revision','chapter_path')) and
         type(req.get('save_key')) is str and
         kc.CANDIDATE_KEY.fullmatch(req['save_key']) is not None and
         type(req.get('expected_new_chapter_sha256')) is str and
         kb.sha(req['expected_new_chapter_sha256']),
         'EC284_EXACT_SAVE_REQUEST_INVALID', 'unavailable')
    need(all(type(job[k]) is dict for k in ('handoff_request','handoff_policy',
            'candidate_read_policies','save_policy','approvals')),
         'EC284_ORIGINAL_EC207_EC208_EVIDENCE_REQUIRED', 'unavailable')
    policy = job['save_policy']
    need(set(policy) == {'schema', 'purpose', 'store_instance_id',
         'store_scope_binding_sha256', 'authorization_scope_sha256',
         'permission_receipt_sha256', 'permit_local_version_append',
         'permit_reviewed_text_local_persistence',
         'permit_restricted_local_persistence', 'permit_source_knowledge_overwrite',
         'permit_business_repository_write', 'permit_issue_or_provider_write',
         'permit_publish'} and policy.get('schema') == vs.POLICY_SCHEMA and
         policy.get('purpose') == vs.PURPOSE and
         policy.get('permit_local_version_append') is True and
         policy.get('permit_reviewed_text_local_persistence') is True and
         all(policy.get(k) is False for k in ('permit_source_knowledge_overwrite',
             'permit_business_repository_write','permit_issue_or_provider_write',
             'permit_publish')) and
         type(policy.get('permit_restricted_local_persistence')) is bool and
         type(policy.get('authorization_scope_sha256')) is str and
         kb.sha(policy['authorization_scope_sha256']) and
         policy.get('permission_receipt_sha256') == req.get('save_permission_receipt_sha256'),
         'EC284_LOCAL_METADATA_ONLY_POLICY_REQUIRED', 'unavailable')
    need(job['approvals'].get('schema') == vs.APPROVALS_SCHEMA and
         type(job['approvals'].get('statements')) is list and
         len(job['approvals']['statements']) == 2,
         'EC284_EC208_TWO_APPROVALS_REQUIRED', 'unavailable')
    return job


def load_job(pol: dict) -> dict:
    raw = io._open_regular(pol['job_file'], MAX_JOB, private=True)
    need(hmac.compare_digest(sha(raw), pol['job_sha256']),
         'EC284_PRIVATE_JOB_BYTES_CHANGED', 'unavailable')
    return validate_job(io.parse(raw, MAX_JOB))


def validate_subject(s: Any) -> dict:
    need(type(s) is dict and set(s) == SUBJECT_KEYS and
         s.get('schema') == SUBJECT_SCHEMA and
         type(s.get('grant_id')) is str and
         io.HEX_NONCE.fullmatch(s['grant_id']) is not None and
         type(s.get('uid')) is int and 0 <= s['uid'] <= 2**31-1 and
         type(s.get('repository_ref')) is str and
         kb.REPO.fullmatch(s['repository_ref']) is not None and
         type(s.get('save_key')) is str and
         kc.CANDIDATE_KEY.fullmatch(s['save_key']) is not None and
         all(type(s[k]) is str and io.HASH.fullmatch(s[k]) is not None
             for k in ('policy_sha256','job_sha256','save_request_sha256',
                       'authorization_scope_sha256','new_chapter_sha256')),
         'EC284_OFFLINE_SUBJECT_INVALID')
    a, b = s['issued_at_unix'], s['expires_at_unix']
    need(type(a) is int and type(b) is int and 0 < a < b and b-a <= MAX_TTL,
         'EC284_OFFLINE_SUBJECT_TTL_INVALID')
    return s


def new_subject(*, uid: int, policy_sha: str, job_sha: str,
                repository_ref: str, save_key: str, request_sha: str,
                authorization_scope_sha: str, chapter_sha: str,
                ttl: int, now: int | None = None) -> dict:
    need(type(ttl) is int and 1 <= ttl <= MAX_TTL,
         'EC284_OFFLINE_GRANT_TTL_OUT_OF_RANGE')
    t = int(time.time()) if now is None else now
    return validate_subject({'schema': SUBJECT_SCHEMA,
        'grant_id': secrets.token_hex(16), 'uid': uid,
        'policy_sha256': policy_sha, 'job_sha256': job_sha,
        'repository_ref': repository_ref, 'save_key': save_key,
        'save_request_sha256': request_sha,
        'authorization_scope_sha256': authorization_scope_sha,
        'new_chapter_sha256': chapter_sha,
        'issued_at_unix': t, 'expires_at_unix': t + ttl})


def validate_grant(grant: Any, pol: dict, job: dict, *, uid: int,
                   now: int, policy_sha: str) -> dict:
    need(type(grant) is dict and set(grant) == {'schema', 'subject',
         'custodian_signature_ed25519','authorizer_signature_ed25519'} and
         grant['schema'] == GRANT_SCHEMA,
         'EC284_TWO_OFFLINE_VOTES_REQUIRED', 'permission_denied')
    try:
        subject = validate_subject(grant['subject'])
    except (HostError, KeyError, TypeError, ValueError) as exc:
        raise HostError('EC284_OFFLINE_GRANT_SUBJECT_INVALID', 'permission_denied') from exc
    req = job['save_request']
    need(uid in pol['allowed_uids'] and uid == subject['uid'] and
         hmac.compare_digest(subject['policy_sha256'], policy_sha) and
         hmac.compare_digest(subject['job_sha256'], pol['job_sha256']) and
         subject['repository_ref'] == job['repository_ref'] and
         subject['save_key'] == req['save_key'] and
         hmac.compare_digest(subject['save_request_sha256'], sha(canonical(req))) and
         subject['authorization_scope_sha256'] == job['save_policy']['authorization_scope_sha256'] and
         subject['new_chapter_sha256'] == req['expected_new_chapter_sha256'],
         'EC284_UID_OR_PRIVATE_SAVE_BINDING_MISMATCH', 'permission_denied')
    need(subject['issued_at_unix'] <= now + CLOCK_SKEW and
         now < subject['expires_at_unix'],
         'EC284_OFFLINE_WRITE_APPROVAL_EXPIRED_OR_FUTURE', 'permission_denied')
    for role in ('custodian','authorizer'):
        verify(role, subject, grant[f'{role}_signature_ed25519'],
               pol[f'{role}_issuer_public_hex'])
    return subject


def denial(reason: str, status: str = 'unavailable', *,
           backend_invoked: bool | None = False,
           write_outcome_unknown: bool = False) -> dict:
    return {'schema': DENIAL_SCHEMA, 'status': status,
            'exit_code': {'permission_denied': 3, 'invalid_input': 4,
                          'unavailable': 5}[status],
            'reason_code': reason,
            'handler_invoked': backend_invoked,
            'local_write_outcome_unknown': write_outcome_unknown,
            'local_version_metadata_written': False if not write_outcome_unknown else None,
            'source_knowledge_file_written': False,
            'business_repository_written': False,
            'issue_or_provider_written': False, 'published': False,
            'private_data_disclosed': False, 'business_effect_verified': False}


def safe_backend_result(res: Any, job: dict) -> bool:
    """Only expose receipts produced by the original EC208 save code."""
    if (type(res) is not dict or res.get('schema') != vs.SCHEMA or
        res.get('status') != 'partial' or res.get('exit_code') != 2 or
        res.get('reason_code') not in (
            'KNOWLEDGE_SAVE_NEW_IMMUTABLE_LOCAL_VERSION_APPENDED',
            'KNOWLEDGE_SAVE_ALREADY_SAVED_IDEMPOTENT_NO_WRITE') or
        any(res.get(k) is not False for k in (
            'local_write_outcome_unknown','private_store_initialized',
            'source_knowledge_file_written','business_repository_written',
            'existing_version_overwritten','issue_or_provider_written',
            'published','candidate_promoted_to_verified_fact',
            'organizational_signer_identity_authenticated',
            'current_architecture_or_delivery_verified',
            'native_knowledge_route_registered'))):
        return False
    s = res.get('subject')
    if (type(s) is not dict or s.get('save_key') != job['save_request']['save_key'] or
        type(s.get('version_id')) is not str or not kb.sha(s['version_id']) or
        type(s.get('version_number')) is not int or s['version_number'] < 1 or
        type(s.get('idempotent')) is not bool):
        return False
    if s['idempotent']:
        return (res['local_version_metadata_written'] is False and
                res['reason_code'] == 'KNOWLEDGE_SAVE_ALREADY_SAVED_IDEMPOTENT_NO_WRITE')
    return (res['local_version_metadata_written'] is True and
            res['reason_code'] == 'KNOWLEDGE_SAVE_NEW_IMMUTABLE_LOCAL_VERSION_APPENDED' and
            s.get('chapter_content_sha256') == job['save_request']['expected_new_chapter_sha256'] and
            s.get('source_knowledge_snapshot_untouched') is True and
            s.get('reviewer_and_owner_signatures_locally_verified') is True and
            s.get('organizational_approval_authority_unverified') is True and
            s.get('content_projected') is False)


def signed_reply(req: dict, result: dict, policy_sha: str, job_sha: str,
                 key: Ed25519PrivateKey, now: int) -> dict:
    payload = {'schema': REPLY_SCHEMA, 'nonce': req['nonce'],
               'request_sha256': sha(canonical(req)),
               'policy_sha256': policy_sha, 'job_sha256': job_sha,
               'issued_at_unix': now, 'result': result}
    return {**payload, 'signature_ed25519': sign('server', payload, key)}


def verify_reply(reply: Any, req: dict, *, server_public_hex: str,
                 policy_sha: str, now: int) -> dict:
    need(type(reply) is dict and set(reply) == {'schema','nonce','request_sha256',
         'policy_sha256','job_sha256','issued_at_unix','result',
         'signature_ed25519'} and reply.get('schema') == REPLY_SCHEMA,
         'EC284_REPLY_FIELDS_INVALID', 'unavailable')
    s = validate_subject(req['grant']['subject'])
    need(reply['nonce'] == req['nonce'] and
         type(reply['request_sha256']) is str and
         hmac.compare_digest(reply['request_sha256'], sha(canonical(req))) and
         reply['policy_sha256'] == policy_sha == s['policy_sha256'] and
         type(reply['job_sha256']) is str and
         io.HASH.fullmatch(reply['job_sha256']) is not None and
         type(reply['issued_at_unix']) is int and
         abs(now - reply['issued_at_unix']) <= 180,
         'EC284_REPLY_NONCE_SCOPE_OR_TIME_MISMATCH', 'unavailable')
    verify('server', {k:v for k,v in reply.items() if k!='signature_ed25519'},
           reply['signature_ed25519'], server_public_hex)
    res = reply['result']
    need(type(res) is dict, 'EC284_REPLY_RESULT_INVALID', 'unavailable')
    if res.get('status') == 'partial':
        need(reply['job_sha256'] == s['job_sha256'],
             'EC284_SUCCESS_REPLY_JOB_PIN_MISMATCH', 'unavailable')
        # A client does not carry the private job. It can still verify the
        # original save_key, expected content pin and original EC208 result.
        req_only = {'save_request': {
            'save_key': s['save_key'],
            'expected_new_chapter_sha256': s['new_chapter_sha256']}}
        need(safe_backend_result(res, req_only),
             'EC284_REPLY_ORIGINAL_SAVE_RECEIPT_INVALID', 'unavailable')
    else:
        need(res.get('schema') == DENIAL_SCHEMA and
             (res.get('status'),res.get('exit_code')) in (
                 ('permission_denied',3), ('invalid_input',4), ('unavailable',5)) and
             res.get('business_effect_verified') is False and
             res.get('private_data_disclosed') is False and
             res.get('source_knowledge_file_written') is False and
             res.get('business_repository_written') is False and
             type(res.get('local_write_outcome_unknown')) is bool and
             ((res.get('local_version_metadata_written') is None) if
                 res['local_write_outcome_unknown'] else
                 res.get('local_version_metadata_written') is False),
             'EC284_REPLY_DENIAL_INVALID', 'unavailable')
    return res
