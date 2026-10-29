#!/usr/bin/env python3
"""EC281 QualityRun.Preflight: pinned host material + two offline signatures.

Low-level JSON, O_NOFOLLOW file I/O, Ed25519 are reused from EC279; all EC281
signature domains, subjects, response contracts and authorization are distinct.
An approved *preflight* is never an execution lease consumption or quality PASS.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ec279_finding_query_host import protocol as io
import quality_detect as detect
import quality_run_guard as guard

POLICY_SCHEMA = 'ces.ec281.preflight_host_policy.v1'
SUBJECT_SCHEMA = 'ces.ec281.preflight_subject.v1'
VOTE_SCHEMA = 'ces.ec281.preflight_vote.v1'
GRANT_SCHEMA = 'ces.ec281.preflight_grant.v1'
REQUEST_SCHEMA = 'ces.ec281.preflight_request.v1'
REPLY_SCHEMA = 'ces.ec281.preflight_signed_reply.v1'
DENIAL_SCHEMA = 'ces.ec281.preflight_denial.v1'
RESULT_SCHEMA = 'ces.ec281.verified_preflight_host_result.v1'
DOMAINS = {
    'policy': b'CES/EC281/QualityRun/PreflightPolicyApproval/v1\\0',
    'isolation': b'CES/EC281/QualityRun/PreflightIsolationApproval/v1\\0',
    'server': b'CES/EC281/QualityRun/PreflightSignedReply/v1\\0',
}
POLICY_FILES = (
    'source_pin', 'approval_ticket', 'lease_ticket', 'policy_key', 'broker_key'
)
POLICY_KEYS = {'schema', 'repo_root', 'allowed_profiles', 'allowed_uids',
               'policy_issuer_public_hex', 'isolation_issuer_public_hex',
               'server_public_hex'} | {
                   f'{name}_{suffix}' for name in POLICY_FILES
                   for suffix in ('file', 'sha256')
               }
SUBJECT_KEYS = {'schema', 'grant_id', 'uid', 'policy_sha256', 'profile_id',
                'source_pin_sha256', 'approval_ticket_sha256',
                'lease_ticket_sha256', 'issued_at_unix', 'expires_at_unix'}
MAX_POLICY = 16000
MAX_RPC = 12000
MAX_REPLY = 48000
MAX_TTL = 120
MAX_CLOCK_SKEW = 30
MAX_FILE = {'source_pin': 4096, 'approval_ticket': 8192, 'lease_ticket': 8192,
            'policy_key': 4096, 'broker_key': 4096}

class HostError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input'):
        super().__init__(code)
        self.code, self.status = code, status

def need(value: bool, code: str, status: str = 'invalid_input'):
    if value is not True:
        raise HostError(code, status)

def canonical(obj: Any) -> bytes:
    return io.canonical(obj)

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

def validate_policy(obj: Any) -> dict:
    need(type(obj) is dict and set(obj) == POLICY_KEYS and
         obj.get('schema') == POLICY_SCHEMA,
         'EC281_POLICY_SCHEMA_INVALID', 'unavailable')
    try:
        detect._root_parts(obj['repo_root'])
    except (TypeError, ValueError, AttributeError) as exc:
        raise HostError('EC281_REPOSITORY_ROOT_INVALID', 'unavailable') from exc
    need(type(obj['allowed_profiles']) is list and
         1 <= len(obj['allowed_profiles']) <= len(guard.BUILTIN_PROFILES) and
         all(type(v) is str and v in guard.BUILTIN_PROFILES
             for v in obj['allowed_profiles']) and
         len(set(obj['allowed_profiles'])) == len(obj['allowed_profiles']),
         'EC281_ALLOWED_PROFILES_INVALID', 'unavailable')
    uids = obj['allowed_uids']
    need(type(uids) is list and 1 <= len(uids) <= 32 and
         all(type(v) is int and 0 <= v <= 2**31-1 for v in uids) and
         len(set(uids)) == len(uids),
         'EC281_ALLOWED_UIDS_INVALID', 'unavailable')
    for name in POLICY_FILES:
        path, digest = obj[f'{name}_file'], obj[f'{name}_sha256']
        need(type(path) is str and os.path.isabs(path) and
             0 < len(path) <= 4096 and type(digest) is str and
             io.HASH.fullmatch(digest) is not None,
             'EC281_HOST_FILE_PATH_OR_PIN_INVALID', 'unavailable')
    need(len({obj[f'{name}_file'] for name in POLICY_FILES}) == len(POLICY_FILES),
         'EC281_HOST_FILE_PATHS_NOT_DISTINCT', 'unavailable')
    keys = [obj[k] for k in ('policy_issuer_public_hex',
                             'isolation_issuer_public_hex', 'server_public_hex')]
    for key in keys:
        try:
            io.pub_from_hex(key)
        except (ValueError, TypeError) as exc:
            raise HostError('EC281_SIGNER_PUBLIC_KEY_INVALID', 'unavailable') from exc
    need(len(set(keys)) == 3, 'EC281_SIGNING_ROLES_NOT_DISTINCT', 'unavailable')
    return obj

def load_policy(path: str, expected_sha: str) -> dict:
    need(type(expected_sha) is str and io.HASH.fullmatch(expected_sha) is not None,
         'EC281_EXTERNAL_POLICY_PIN_REQUIRED', 'unavailable')
    raw = io._open_regular(path, MAX_POLICY, private=True)
    need(hmac.compare_digest(sha(raw), expected_sha),
         'EC281_POLICY_PIN_CHANGED', 'unavailable')
    return validate_policy(io.parse(raw, MAX_POLICY))

def pinned_bytes(pol: dict, name: str) -> bytes:
    need(name in POLICY_FILES, 'EC281_UNKNOWN_PRIVATE_MATERIAL', 'unavailable')
    raw = io._open_regular(pol[f'{name}_file'], MAX_FILE[name], private=True)
    need(hmac.compare_digest(sha(raw), pol[f'{name}_sha256']),
         'EC281_PRIVATE_MATERIAL_PIN_CHANGED', 'unavailable')
    return raw

def load_material(pol: dict) -> tuple[dict, dict, dict, bytes, bytes]:
    raw = {name: pinned_bytes(pol, name) for name in POLICY_FILES}
    pin = io.parse(raw['source_pin'], MAX_FILE['source_pin'])
    approval = io.parse(raw['approval_ticket'], MAX_FILE['approval_ticket'])
    lease = io.parse(raw['lease_ticket'], MAX_FILE['lease_ticket'])
    policy_key, broker_key = raw['policy_key'], raw['broker_key']
    need(32 <= len(policy_key) <= 4096 and
         32 <= len(broker_key) <= 4096 and
         not hmac.compare_digest(policy_key, broker_key),
         'EC281_TWO_INDEPENDENT_HMAC_KEYS_REQUIRED', 'unavailable')
    return pin, approval, lease, policy_key, broker_key

def validate_subject(obj: Any) -> dict:
    need(type(obj) is dict and set(obj) == SUBJECT_KEYS and
         obj.get('schema') == SUBJECT_SCHEMA,
         'EC281_SUBJECT_SCHEMA_INVALID')
    need(type(obj['grant_id']) is str and
         io.HEX_NONCE.fullmatch(obj['grant_id']) is not None and
         type(obj['uid']) is int and 0 <= obj['uid'] <= 2**31-1 and
         type(obj['profile_id']) is str and
         obj['profile_id'] in guard.BUILTIN_PROFILES,
         'EC281_SUBJECT_ID_UID_OR_PROFILE_INVALID')
    for name in ('policy_sha256', 'source_pin_sha256',
                 'approval_ticket_sha256', 'lease_ticket_sha256'):
        need(type(obj[name]) is str and io.HASH.fullmatch(obj[name]) is not None,
             'EC281_SUBJECT_SHA_INVALID')
    a, b = obj['issued_at_unix'], obj['expires_at_unix']
    need(type(a) is int and type(b) is int and 0 < a < b and b - a <= MAX_TTL,
         'EC281_SUBJECT_TTL_INVALID')
    return obj

def new_subject(*, profile_id: str, uid: int, policy_sha: str,
                source_pin_sha: str, approval_sha: str,
                lease_sha: str, ttl: int, now: int | None = None) -> dict:
    need(type(ttl) is int and 1 <= ttl <= MAX_TTL, 'EC281_TTL_INVALID')
    t = int(time.time()) if now is None else now
    return validate_subject({
        'schema': SUBJECT_SCHEMA, 'grant_id': secrets.token_hex(16),
        'uid': uid, 'profile_id': profile_id, 'policy_sha256': policy_sha,
        'source_pin_sha256': source_pin_sha,
        'approval_ticket_sha256': approval_sha, 'lease_ticket_sha256': lease_sha,
        'issued_at_unix': t, 'expires_at_unix': t + ttl})

def sign(role: str, doc: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(DOMAINS[role] + canonical(doc)).hex()

def verify(role: str, doc: dict, signature: Any, pub: str):
    need(type(signature) is str and io.HEX_SIG.fullmatch(signature) is not None,
         'EC281_SIGNATURE_FORMAT_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(pub).verify(
            bytes.fromhex(signature), DOMAINS[role] + canonical(doc))
    except Exception as exc:
        raise HostError('EC281_SIGNATURE_INVALID', 'permission_denied') from exc

def validate_grant(grant: Any, pol: dict, *, uid: int, now: int,
                   policy_sha: str) -> dict:
    need(type(grant) is dict and set(grant) == {
        'schema', 'subject', 'policy_signature_ed25519',
        'isolation_signature_ed25519'} and grant.get('schema') == GRANT_SCHEMA,
         'EC281_GRANT_INVALID', 'permission_denied')
    try:
        s = validate_subject(grant['subject'])
    except (HostError, ValueError, TypeError, KeyError) as exc:
        raise HostError('EC281_SIGNED_SUBJECT_INVALID', 'permission_denied') from exc
    need(uid in pol['allowed_uids'] and uid == s['uid'] and
         s['profile_id'] in pol['allowed_profiles'] and
         hmac.compare_digest(s['policy_sha256'], policy_sha) and
         all(hmac.compare_digest(s[f'{name}_sha256'], pol[f'{name}_sha256'])
             for name in ('source_pin', 'approval_ticket', 'lease_ticket')),
         'EC281_UID_PROFILE_OR_HOST_FILE_NOT_APPROVED', 'permission_denied')
    need(s['issued_at_unix'] <= now + MAX_CLOCK_SKEW and
         now < s['expires_at_unix'],
         'EC281_GRANT_EXPIRED_OR_NOT_YET_VALID', 'permission_denied')
    for role in ('policy', 'isolation'):
        verify(role, s, grant[f'{role}_signature_ed25519'],
               pol[f'{role}_issuer_public_hex'])
    return s

def denial(reason: str, status: str = 'permission_denied', *,
           backend_invoked: bool | None = False) -> dict:
    # An unavailable backend after invocation MUST NOT claim it was never
    # called. None means unknown, not false or an invented successful result.
    return {'schema': DENIAL_SCHEMA, 'status': status,
            'exit_code': {'permission_denied': 3, 'invalid_input': 4,
                          'unavailable': 5}[status],
            'reason_code': reason, 'handler_invoked': backend_invoked,
            'tests_executed': False, 'lease_consumed': False,
            'quality_pass_verified': False}

def signed_reply(req: dict, result: dict, pol_sha: str, pol: dict,
                 key: Ed25519PrivateKey, now: int) -> dict:
    payload = {'schema': REPLY_SCHEMA, 'request_sha256': sha(canonical(req)),
               'nonce': req['nonce'], 'policy_sha256': pol_sha,
               'source_pin_sha256': pol['source_pin_sha256'],
               'approval_ticket_sha256': pol['approval_ticket_sha256'],
               'lease_ticket_sha256': pol['lease_ticket_sha256'],
               'issued_at_unix': now, 'result': result}
    return {**payload, 'signature_ed25519': sign('server', payload, key)}

def verify_reply(reply: Any, req: dict, *, server_public_hex: str,
                 policy_sha: str, now: int) -> dict:
    fields = {'schema', 'request_sha256', 'nonce', 'policy_sha256',
              'source_pin_sha256', 'approval_ticket_sha256',
              'lease_ticket_sha256', 'issued_at_unix', 'result',
              'signature_ed25519'}
    need(type(reply) is dict and set(reply) == fields and
         reply['schema'] == REPLY_SCHEMA,
         'EC281_REPLY_SCHEMA_INVALID', 'unavailable')
    subject = validate_subject(req['grant']['subject'])
    need(reply['request_sha256'] == sha(canonical(req)) and
         reply['nonce'] == req['nonce'] and
         reply['policy_sha256'] == subject['policy_sha256'] == policy_sha and
         all(reply[f'{name}_sha256'] == subject[f'{name}_sha256']
             for name in ('source_pin', 'approval_ticket', 'lease_ticket')) and
         type(reply['issued_at_unix']) is int and
         abs(now - reply['issued_at_unix']) <= 120,
         'EC281_REPLY_REQUEST_OR_TIME_MISMATCH', 'unavailable')
    try:
        verify('server', {k: v for k, v in reply.items()
                          if k != 'signature_ed25519'},
               reply['signature_ed25519'], server_public_hex)
    except HostError as exc:
        raise HostError('EC281_HOST_REPLY_SIGNATURE_INVALID', 'unavailable') from exc
    result = reply['result']
    need(type(result) is dict, 'EC281_REPLY_RESULT_INVALID', 'unavailable')
    if result.get('status') == 'partial':
        effects, proof = result.get('effects'), result.get('proof')
        plan, isolation = result.get('plan'), result.get('isolation')
        profile, source = result.get('profile'), result.get('source')
        authorization = result.get('authorization')
        need(result.get('schema') == guard.SCHEMA and
             result.get('exit_code') == 2 and
             type(plan) is dict and
             plan.get('state') == 'PREPARED_ONLY_NOT_EXECUTABLE' and
             plan.get('profile_id') == subject['profile_id'] and
             plan.get('has_executable_command') is False and
             plan.get('requires_ec187_fresh_reauthorization') is True and
             plan.get('requires_atomic_lease_consumption_before_run') is True and
             type(profile) is dict and
             profile.get('id') == subject['profile_id'] and
             plan.get('profile_sha256') == profile.get('spec_sha256') and
             type(source) is dict and
             source.get('mode') == 'WorkingTree' and
             source.get('root_path_redacted') is True and
             source.get('git_object_bytes_verified') is False and
             source.get('source_contents_sealed') is False and
             plan.get('source_pin_sha256') == source.get('source_pin_sha256') and
             type(authorization) is dict and
             authorization.get('policy_mac_verified') is True and
             authorization.get('broker_mac_verified') is True and
             type(isolation) is dict and
             isolation.get('lease_consumed') is False and
             isolation.get('actual_kernel_isolation_probed_by_ces') is False and
             type(effects) is dict and
             effects.get('commands_executed') is False and
             effects.get('tests_executed') is False and
             effects.get('network_access') is False and
             effects.get('writes_performed') is False and
             effects.get('lease_consumed') is False and
             type(proof) is dict and
             proof.get('test_execution_verified') is False and
             proof.get('overall_quality_pass_verified') is False and
             proof.get('trusted_future_runner_instantiated') is False and
             proof.get('actual_isolation_verified_by_ces') is False,
             'EC281_REPLY_CLAIMS_UNSUPPORTED_EXECUTION', 'unavailable')
    else:
        need(result.get('schema') == DENIAL_SCHEMA and
             (result.get('status'), result.get('exit_code')) in (
                 ('permission_denied', 3), ('invalid_input', 4),
                 ('unavailable', 5)),
             'EC281_REPLY_DENIAL_INVALID', 'unavailable')
    return result
