#!/usr/bin/env python3
"""EC282: independent exact-job offline grants and authenticated read-only replies.

Use EC279's *low-level* nofollow file/strict JSON/Ed25519 primitives, NOT its
permissions or signatures. An EC282 ticket is useless in an EC279–281 host.
The job, policies, statement keys, repository and Git target are HOST-owned;
clients can only submit a short-lived two-authority signature over its SHA.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from finding_query_host import protocol as io
import knowledge_bootstrap as bootstrap
import knowledge_impact as impact
import knowledge_target_binding as target

POLICY_SCHEMA = 'ces.ec282.knowledge_impact_host_policy.v1'
JOB_SCHEMA = 'ces.ec282.knowledge_impact_job.v1'
SUBJECT_SCHEMA = 'ces.ec282.knowledge_impact_subject.v1'
VOTE_SCHEMA = 'ces.ec282.knowledge_impact_vote.v1'
GRANT_SCHEMA = 'ces.ec282.knowledge_impact_grant.v1'
REQUEST_SCHEMA = 'ces.ec282.knowledge_impact_request.v1'
REPLY_SCHEMA = 'ces.ec282.knowledge_impact_signed_reply.v1'
DENIAL_SCHEMA = 'ces.ec282.knowledge_impact_denial.v1'
RESULT_SCHEMA = 'ces.ec282.verified_knowledge_impact_host_result.v1'
DOMAINS = {
    'source': b'CES/EC282/KnowledgeImpact/PinnedSourceAuthority/v1\0',
    'reader': b'CES/EC282/KnowledgeImpact/ReadPermissionAuthority/v1\0',
    'server': b'CES/EC282/KnowledgeImpact/SignedReply/v1\0',
}
POLICY_KEYS = {'schema', 'job_file', 'job_sha256', 'allowed_uids',
               'source_issuer_public_hex', 'reader_issuer_public_hex',
               'server_public_hex'}
JOB_KEYS = {'schema', 'repository_root', 'knowledge_root', 'repository_ref',
            'target_ref', 'git_executable', 'trusted_target_public_hex_by_id',
            'trusted_baseline_public_hex_by_id', 'request', 'bootstrap_read_policy',
            'target_read_policy', 'impact_read_policy', 'target_statement',
            'target_signature_base64', 'baseline_statement',
            'baseline_signature_base64'}
SUBJECT_KEYS = {'schema', 'grant_id', 'uid', 'policy_sha256', 'job_sha256',
                'repository_ref', 'target_ref', 'issued_at_unix', 'expires_at_unix'}
MAX_POLICY = 16_384
MAX_JOB = 512 * 1024
MAX_RPC = 16_384
MAX_REPLY = 400 * 1024
MAX_TTL = 300
CLOCK_SKEW = 30


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(predicate: bool, code: str, status: str = 'invalid_input') -> None:
    if predicate is not True:
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


def verify(role: str, obj: dict, signature: Any, pub_hex: str) -> None:
    need(type(signature) is str and io.HEX_SIG.fullmatch(signature) is not None,
         'EC282_SIGNATURE_FORMAT_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(pub_hex).verify(bytes.fromhex(signature),
                                      DOMAINS[role] + canonical(obj))
    except Exception as exc:
        raise HostError('EC282_SIGNATURE_VERIFICATION_FAILED',
                        'permission_denied') from exc


def validate_policy(pol: Any) -> dict:
    need(type(pol) is dict and set(pol) == POLICY_KEYS and
         pol.get('schema') == POLICY_SCHEMA,
         'EC282_POLICY_FIELDS_INVALID', 'unavailable')
    need(type(pol['job_file']) is str and os.path.isabs(pol['job_file']) and
         0 < len(pol['job_file']) <= 4096 and
         type(pol['job_sha256']) is str and
         io.HASH.fullmatch(pol['job_sha256']) is not None,
         'EC282_JOB_FILE_AND_PIN_REQUIRED', 'unavailable')
    uids = pol['allowed_uids']
    need(type(uids) is list and 1 <= len(uids) <= 32 and
         len(set(uids)) == len(uids) and
         all(type(u) is int and 0 <= u <= 2**31-1 for u in uids),
         'EC282_ALLOWED_UIDS_INVALID', 'unavailable')
    keys = [pol[f'{role}_issuer_public_hex'] for role in ('source', 'reader')]
    keys.append(pol['server_public_hex'])
    try:
        for key in keys:
            io.pub_from_hex(key)
    except (TypeError, ValueError) as exc:
        raise HostError('EC282_POLICY_SIGNER_INVALID', 'unavailable') from exc
    need(len(set(keys)) == 3,
         'EC282_THREE_DISTINCT_AUTHORIZATION_ROLES_REQUIRED', 'unavailable')
    return pol


def load_policy(path: str, expected_sha: str) -> dict:
    need(type(expected_sha) is str and io.HASH.fullmatch(expected_sha) is not None,
         'EC282_OPERATOR_POLICY_PIN_REQUIRED', 'unavailable')
    raw = io._open_regular(path, MAX_POLICY, private=True)
    need(hmac.compare_digest(sha(raw), expected_sha),
         'EC282_HOST_POLICY_PIN_CHANGED', 'unavailable')
    return validate_policy(io.parse(raw, MAX_POLICY))


def _keys(raw: Any) -> dict[str, bytes]:
    need(type(raw) is dict and 1 <= len(raw) <= 16,
         'EC282_TRUSTED_SIGNER_REGISTRY_INVALID', 'unavailable')
    output = {}
    for name, hex_key in raw.items():
        need(type(name) is str and len(name) <= 64 and
             target.boundary.key(name),
             'EC282_TRUSTED_SIGNER_ID_INVALID', 'unavailable')
        try:
            pub = io.pub_from_hex(hex_key)
            output[name] = bytes.fromhex(hex_key)
            del pub
        except (TypeError, ValueError) as exc:
            raise HostError('EC282_TRUSTED_SIGNER_PUBLIC_INVALID', 'unavailable') from exc
    need(len(set(output.values())) == len(output),
         'EC282_TRUSTED_SIGNER_REGISTRY_ALIASES', 'unavailable')
    return output


def validate_job(job: Any) -> dict:
    need(type(job) is dict and set(job) == JOB_KEYS and
         job.get('schema') == JOB_SCHEMA,
         'EC282_PINNED_JOB_FIELDS_INVALID', 'unavailable')
    for name in ('repository_root', 'knowledge_root'):
        root = job[name]
        need(type(root) is str and os.path.isabs(root) and len(root) <= 4096 and
             root != '/' and '\x00' not in root,
             'EC282_ROOT_INVALID', 'unavailable')
    git = job['git_executable']
    need(type(git) is str and os.path.isabs(git) and len(git) <= 4096,
         'EC282_GIT_EXECUTABLE_NOT_HOST_SELECTED', 'unavailable')
    try:
        info = os.lstat(git)
    except OSError as exc:
        raise HostError('EC282_GIT_EXECUTABLE_UNAVAILABLE', 'unavailable') from exc
    need(stat.S_ISREG(info.st_mode) and (info.st_mode & 0o111) and
         (info.st_mode & 0o022) == 0,
         'EC282_GIT_EXECUTABLE_UNTRUSTED', 'unavailable')
    need(type(job['repository_ref']) is str and
         target.boundary.REPO.fullmatch(job['repository_ref']) is not None,
         'EC282_REPOSITORY_REF_INVALID', 'unavailable')
    try:
        target._ref(job['target_ref'])
        request = bootstrap._request(job['request'])
    except (target.TargetError, bootstrap.BootstrapError, ValueError, KeyError) as exc:
        raise HostError('EC282_JOB_REQUEST_OR_REF_INVALID', 'unavailable') from exc
    need(request['scope']['repository_ref'] == job['repository_ref'],
         'EC282_JOB_SCOPE_MISMATCH', 'unavailable')
    target_keys = _keys(job['trusted_target_public_hex_by_id'])
    baseline_keys = _keys(job['trusted_baseline_public_hex_by_id'])
    need(set(target_keys.values()).isdisjoint(baseline_keys.values()),
         'EC282_TARGET_AND_BASELINE_SIGNERS_NOT_DISTINCT', 'unavailable')
    for name in ('bootstrap_read_policy', 'target_read_policy',
                 'impact_read_policy', 'target_statement'):
        need(type(job[name]) is dict, 'EC282_JOB_POLICY_OR_STATEMENT_INVALID',
             'unavailable')
    need(type(job['target_signature_base64']) is str and
         len(job['target_signature_base64']) <= 128,
         'EC282_TARGET_SIGNATURE_INVALID', 'unavailable')
    need((job['baseline_statement'] is None and
          job['baseline_signature_base64'] is None) or
         (type(job['baseline_statement']) is dict and
          type(job['baseline_signature_base64']) is str and
          len(job['baseline_signature_base64']) <= 128),
         'EC282_BASELINE_PAIR_INCOMPLETE', 'unavailable')
    return job


def load_job(pol: dict) -> dict:
    raw = io._open_regular(pol['job_file'], MAX_JOB, private=True)
    need(hmac.compare_digest(sha(raw), pol['job_sha256']),
         'EC282_PINNED_JOB_BYTES_CHANGED', 'unavailable')
    return validate_job(io.parse(raw, MAX_JOB))


def validate_subject(s: Any) -> dict:
    need(type(s) is dict and set(s) == SUBJECT_KEYS and
         s.get('schema') == SUBJECT_SCHEMA and
         type(s.get('grant_id')) is str and
         io.HEX_NONCE.fullmatch(s['grant_id']) is not None and
         type(s['uid']) is int and 0 <= s['uid'] <= 2**31-1,
         'EC282_SUBJECT_FIELDS_INVALID')
    for name in ('policy_sha256', 'job_sha256'):
        need(type(s[name]) is str and io.HASH.fullmatch(s[name]) is not None,
             'EC282_SUBJECT_PIN_INVALID')
    need(type(s['repository_ref']) is str and
         target.boundary.REPO.fullmatch(s['repository_ref']) is not None,
         'EC282_SUBJECT_REPOSITORY_REF_INVALID')
    try:
        target._ref(s['target_ref'])
    except (target.TargetError, TypeError) as exc:
        raise HostError('EC282_SUBJECT_TARGET_REF_INVALID') from exc
    a, b = s['issued_at_unix'], s['expires_at_unix']
    need(type(a) is int and type(b) is int and 0 < a < b and b-a <= MAX_TTL,
         'EC282_SUBJECT_TTL_INVALID')
    return s


def new_subject(*, uid: int, policy_sha: str, job_sha: str,
                repository_ref: str, target_ref: str, ttl: int,
                now: int | None = None) -> dict:
    need(type(ttl) is int and 1 <= ttl <= MAX_TTL,
         'EC282_TTL_OUT_OF_RANGE')
    t = int(time.time()) if now is None else now
    return validate_subject({
        'schema': SUBJECT_SCHEMA, 'grant_id': secrets.token_hex(16),
        'uid': uid, 'policy_sha256': policy_sha, 'job_sha256': job_sha,
        'repository_ref': repository_ref, 'target_ref': target_ref,
        'issued_at_unix': t, 'expires_at_unix': t+ttl})


def validate_grant(grant: Any, pol: dict, job: dict, *, uid: int,
                   now: int, policy_sha: str) -> dict:
    need(type(grant) is dict and set(grant) == {
        'schema', 'subject', 'source_signature_ed25519',
        'reader_signature_ed25519'} and grant['schema'] == GRANT_SCHEMA,
        'EC282_GRANT_FIELDS_INVALID', 'permission_denied')
    try:
        s = validate_subject(grant['subject'])
    except (HostError, TypeError, KeyError, ValueError) as exc:
        raise HostError('EC282_GRANT_SUBJECT_INVALID', 'permission_denied') from exc
    need(uid in pol['allowed_uids'] and uid == s['uid'] and
         hmac.compare_digest(s['policy_sha256'], policy_sha) and
         hmac.compare_digest(s['job_sha256'], pol['job_sha256']) and
         s['repository_ref'] == job['repository_ref'] and
         s['target_ref'] == job['target_ref'],
         'EC282_UID_OR_EXACT_JOB_NOT_AUTHORIZED', 'permission_denied')
    need(s['issued_at_unix'] <= now + CLOCK_SKEW and now < s['expires_at_unix'],
         'EC282_GRANT_EXPIRED_OR_FUTURE', 'permission_denied')
    for role in ('source', 'reader'):
        verify(role, s, grant[f'{role}_signature_ed25519'],
               pol[f'{role}_issuer_public_hex'])
    return s


def denial(reason: str, status: str = 'permission_denied',
           *, backend_invoked: bool | None = False) -> dict:
    return {'schema': DENIAL_SCHEMA, 'status': status,
            'exit_code': {'permission_denied': 3, 'invalid_input': 4,
                          'unavailable': 5}[status],
            'reason_code': reason, 'handler_invoked': backend_invoked,
            'data_disclosed': False, 'repository_written': False,
            'knowledge_written': False, 'impact_verified': False}


def safe_backend_result(result: Any, job: dict) -> bool:
    if type(result) is not dict or result.get('schema') != impact.SCHEMA or \
            result.get('status') != 'partial' or result.get('exit_code') != 2:
        return False
    s = result.get('subject')
    if (type(s) is not dict or s.get('repository_ref') != job['repository_ref'] or
        s.get('model_revision') != 'EC204_ATTESTED_SELECTED_GIT_CHANGE_SET_ONLY' or
        s.get('no_write_actions_performed') is not True or
        s.get('knowledge_sections_to_update') != [] or
        s.get('verified_delivered_facts') != [] or
        s.get('knowledge_impact_state') !=
            'UNKNOWN_REQUIRES_EC205_SECTION_MAPPING_AND_REVIEW' or
        s.get('target_delivery_state') !=
            'SIGNED_DELIVERED_TARGET_OBSERVED_AT_REF' or
        s.get('baseline_binding_state') != 'BASELINE_COMMIT_OBJECT_VERIFIED' or
        s.get('selected_change_set_state') != 'SELECTED_REPOSITORY_PATHS_COMPARED'):
        # The underlying EC204 can return partial even when no Git ref or
        # detached delivery signature is trusted. This new host deliberately
        # exposes only an actually compared, fully selected-path change set.
        # Unknown/unauthorized inputs yield signed unavailable, never a
        # falsely positive or data-bearing "partial analysis" projection.
        return False
    summary = s.get('summary')
    if type(summary) is not dict or \
            summary.get('whole_repository_change_set_complete') is not False or \
            summary.get('knowledge_chapter_impact_verified') is not False or \
            summary.get('selected_source_comparison_complete') is not True or \
            type(summary.get('selected_repository_paths')) is not int or \
            summary['selected_repository_paths'] < 1 or \
            summary.get('source_paths_compared') != summary['selected_repository_paths'] or \
            summary.get('unknown_selected_paths') != 0:
        return False
    limits = result.get('limitations')
    if type(limits) is not dict or any(value is not False for value in limits.values()):
        return False
    return result.get('canonical_json') == target.boundary.canonical(s)


def signed_reply(req: dict, result: dict, pol_sha: str, job_sha: str,
                 key: Ed25519PrivateKey, now: int) -> dict:
    payload = {'schema': REPLY_SCHEMA, 'request_sha256': sha(canonical(req)),
               'nonce': req['nonce'], 'policy_sha256': pol_sha,
               'job_sha256': job_sha, 'issued_at_unix': now, 'result': result}
    return {**payload, 'signature_ed25519': sign('server', payload, key)}


def verify_reply(reply: Any, req: dict, *, server_public_hex: str,
                 policy_sha: str, now: int) -> dict:
    need(type(reply) is dict and set(reply) == {
        'schema', 'request_sha256', 'nonce', 'policy_sha256',
        'job_sha256', 'issued_at_unix', 'result', 'signature_ed25519'
    } and reply.get('schema') == REPLY_SCHEMA,
        'EC282_REPLY_FIELDS_INVALID', 'unavailable')
    s = validate_subject(req['grant']['subject'])
    # Wire replies are untrusted until the server signature is checked.
    # Guard types before constant-time comparisons: malformed JSON objects
    # must be rejected as an ordinary host denial, not crash the CLI.
    need(all(type(reply[field]) is str and
             io.HASH.fullmatch(reply[field]) is not None
             for field in ('request_sha256', 'policy_sha256', 'job_sha256')) and
         type(reply['nonce']) is str and
         type(reply['issued_at_unix']) is int,
         'EC282_REPLY_PIN_FORMAT_INVALID', 'unavailable')
    need(reply['nonce'] == req['nonce'] and
         hmac.compare_digest(reply['request_sha256'], sha(canonical(req))) and
         hmac.compare_digest(reply['policy_sha256'], policy_sha) and
         reply['policy_sha256'] == s['policy_sha256'] and
         reply['job_sha256'] == s['job_sha256'] and
         abs(now - reply['issued_at_unix']) <= 180,
         'EC282_REPLY_SCOPE_OR_TIME_MISMATCH', 'unavailable')
    try:
        verify('server', {k: v for k, v in reply.items()
                          if k != 'signature_ed25519'},
               reply['signature_ed25519'], server_public_hex)
    except HostError as exc:
        raise HostError('EC282_REPLY_SERVER_SIGNATURE_INVALID', 'unavailable') from exc
    result = reply['result']
    if type(result) is not dict:
        raise HostError('EC282_REPLY_RESULT_INVALID', 'unavailable')
    if result.get('status') == 'partial':
        # The signed job itself is private. Locally prove the invariant set,
        # and use the signed subject's repository id as a public consistency pin.
        minimal_job = {'repository_ref': s['repository_ref']}
        need(safe_backend_result(result, minimal_job),
             'EC282_REPLY_CLAIMS_UNSUPPORTED_KNOWLEDGE_IMPACT', 'unavailable')
    else:
        need(result.get('schema') == DENIAL_SCHEMA and
             (result.get('status'), result.get('exit_code')) in (
                 ('permission_denied', 3), ('invalid_input', 4),
                 ('unavailable', 5)) and
             result.get('impact_verified') is False and
             result.get('data_disclosed') is False and
             result.get('repository_written') is False and
             result.get('knowledge_written') is False,
             'EC282_REPLY_DENIAL_INVALID', 'unavailable')
    return result
