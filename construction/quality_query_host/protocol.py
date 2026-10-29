#!/usr/bin/env python3
"""EC280 separate, domain-bound authorization for a pinned QualityShow batch.

The EC279 module supplies only low-level secure JSON/file/Ed25519 primitives;
EC280 subjects, roles, policies, signatures and responses are a *different*
protocol. No EC241/243 HOST_REQUIRED permission is added to the router.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from finding_query_host import protocol as io
import quality_show as quality

POLICY_SCHEMA = 'ces.ec280.quality_host_policy.v1'
BATCH_SCHEMA = 'ces.ec280.pinned_quality_batch.v1'
SUBJECT_SCHEMA = 'ces.ec280.quality_read_subject.v1'
VOTE_SCHEMA = 'ces.ec280.quality_read_vote.v1'
GRANT_SCHEMA = 'ces.ec280.quality_read_grant.v1'
REQUEST_SCHEMA = 'ces.ec280.quality_query_request.v1'
REPLY_SCHEMA = 'ces.ec280.quality_query_signed_reply.v1'
DENIAL_SCHEMA = 'ces.ec280.quality_query_denial.v1'
RESULT_SCHEMA = 'ces.ec280.verified_quality_host_result.v1'
DOMAINS = {
    'evidence': b'CES/EC280/QualityShow/PinnedEvidenceRead/v1\0',
    'query': b'CES/EC280/QualityShow/ExactQuery/v1\0',
    'server': b'CES/EC280/QualityShow/SignedReply/v1\0',
}
POLICY_KEYS = {'schema', 'evidence_file', 'evidence_sha256',
               'cursor_key_file', 'cursor_key_sha256', 'source_scope',
               'evidence_issuer_public_hex', 'query_issuer_public_hex',
               'server_public_hex', 'allowed_uids'}
QUERY_KEYS = {'source_scope', 'filters', 'page_size',
              'include_numeric_metrics', 'acknowledge_historical_proposal'}
SUBJECT_KEYS = {'schema', 'grant_id', 'uid', 'policy_sha256', 'evidence_sha256',
                'issued_at_unix', 'expires_at_unix', 'query'}
MAX_POLICY = 16000
MAX_RPC = 16000
MAX_BATCH = 2 * 1024 * 1024 + 4096
MAX_REPLY = 135000
MAX_TTL = 600
MAX_CLOCK_SKEW = 30

class HostError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status

def need(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if not ok:
        raise HostError(code, status)

def canonical(obj: Any) -> bytes:
    return io.canonical(obj)

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def read_doc(path: str, limit: int = io.MAX_DOC, *, private: bool = False) -> dict:
    return io.read_doc(path, limit, private=private)

def write_exclusive(path: str, doc: dict) -> None:
    io.write_exclusive(path, doc)

def read_exact_file(path: str, limit: int, *, private: bool) -> bytes:
    return io._open_regular(path, limit, private=private)

def public_hex(key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

def sign(role: str, doc: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(DOMAINS[role] + canonical(doc)).hex()

def verify(role: str, doc: dict, signature: Any, pub_hex: str) -> None:
    need(type(signature) is str and io.HEX_SIG.fullmatch(signature) is not None,
         'EC280_SIGNATURE_FORMAT_INVALID', 'permission_denied')
    try:
        io.pub_from_hex(pub_hex).verify(
            bytes.fromhex(signature), DOMAINS[role] + canonical(doc))
    except Exception as exc:
        raise HostError('EC280_SIGNATURE_INVALID', 'permission_denied') from exc

def valid_scope(raw: Any) -> dict:
    try:
        return quality._scope(raw)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise HostError('EC280_EXACT_SOURCE_SCOPE_INVALID') from exc

def validate_query(q: Any) -> dict:
    need(type(q) is dict and set(q) == QUERY_KEYS, 'EC280_QUERY_FIELDS_INVALID')
    valid_scope(q['source_scope'])
    need(type(q['filters']) is dict and len(q['filters']) <= 4,
         'EC280_FILTERS_REQUIRED')
    try:
        quality._filters(q['filters'])
    except (ValueError, TypeError, OverflowError, KeyError) as exc:
        raise HostError('EC280_QUERY_FILTERS_INVALID') from exc
    need(type(q['page_size']) is int and 1 <= q['page_size'] <= quality.MAX_PAGE,
         'EC280_PAGE_SIZE_INVALID')
    for key in ('include_numeric_metrics', 'acknowledge_historical_proposal'):
        need(type(q[key]) is bool, 'EC280_QUERY_FLAGS_INVALID')
    need(q['source_scope']['source_mode'] != 'ProposedPR' or
         q['acknowledge_historical_proposal'],
         'EC280_HISTORICAL_PROPOSAL_ACK_REQUIRED')
    return q

def query_digest(q: dict) -> tuple[str, str]:
    scope_sha = quality.digest(quality.DOMAIN_SCOPE, q['source_scope'])
    spec = {'scope_sha256': scope_sha, 'filters': quality._filters(q['filters']),
            'page_size': q['page_size'],
            'include_numeric_metrics': q['include_numeric_metrics'],
            'historical_proposal_ack': q['acknowledge_historical_proposal']}
    return scope_sha, quality.digest(quality.DOMAIN_QUERY, spec)

def validate_policy(pol: Any) -> dict:
    need(type(pol) is dict and set(pol) == POLICY_KEYS and
         pol['schema'] == POLICY_SCHEMA, 'EC280_POLICY_SCHEMA_INVALID', 'unavailable')
    try:
        valid_scope(pol['source_scope'])
    except HostError as exc:
        raise HostError('EC280_POLICY_SCOPE_INVALID', 'unavailable') from exc
    for key in ('evidence_file', 'cursor_key_file'):
        value = pol[key]
        need(type(value) is str and os.path.isabs(value) and 0 < len(value) <= 4096,
             'EC280_POLICY_PRIVATE_FILE_PATH_INVALID', 'unavailable')
    for key in ('evidence_sha256', 'cursor_key_sha256'):
        need(type(pol[key]) is str and io.HASH.fullmatch(pol[key]) is not None,
             'EC280_POLICY_FILE_SHA_INVALID', 'unavailable')
    keys = [pol[k] for k in ('evidence_issuer_public_hex', 'query_issuer_public_hex',
                              'server_public_hex')]
    for key in keys:
        try:
            io.pub_from_hex(key)
        except (ValueError, TypeError) as exc:
            raise HostError('EC280_POLICY_PUBLIC_KEY_INVALID', 'unavailable') from exc
    need(len(set(keys)) == 3, 'EC280_THREE_DISTINCT_SIGNING_ROLES_REQUIRED', 'unavailable')
    uids = pol['allowed_uids']
    need(type(uids) is list and 1 <= len(uids) <= 32 and
         all(type(x) is int and 0 <= x <= 2**31-1 for x in uids) and
         len(set(uids)) == len(uids), 'EC280_ALLOWED_UIDS_INVALID', 'unavailable')
    return pol

def load_policy(path: str, expected_sha: str) -> dict:
    need(type(expected_sha) is str and io.HASH.fullmatch(expected_sha) is not None,
         'EC280_EXTERNAL_POLICY_SHA_REQUIRED', 'unavailable')
    data = read_exact_file(path, MAX_POLICY, private=True)
    need(hmac.compare_digest(sha(data), expected_sha),
         'EC280_HOST_POLICY_SHA_CHANGED', 'unavailable')
    return validate_policy(io.parse(data, MAX_POLICY))

def load_batch(pol: dict) -> tuple[dict, list]:
    raw = read_exact_file(pol['evidence_file'], MAX_BATCH, private=True)
    need(hmac.compare_digest(sha(raw), pol['evidence_sha256']),
         'EC280_PINNED_BATCH_CHANGED', 'unavailable')
    try:
        batch = io.parse(raw, MAX_BATCH)
        need(set(batch) == {'schema', 'source_scope', 'evidence'} and
             batch['schema'] == BATCH_SCHEMA and
             batch['source_scope'] == pol['source_scope'] and
             type(batch['evidence']) is list and
             len(batch['evidence']) <= quality.MAX_RECORDS,
             'EC280_PINNED_BATCH_SCOPE_OR_SHAPE_INVALID', 'unavailable')
    except (ValueError, TypeError, KeyError) as exc:
        raise HostError('EC280_PINNED_BATCH_UNREADABLE', 'unavailable') from exc
    # QualityShow validates receipts and their producer checksums itself.
    return batch, batch['evidence']

def load_cursor_key(pol: dict) -> bytes:
    key = read_exact_file(pol['cursor_key_file'], 64, private=True)
    need(len(key) in (32, 64) and
         hmac.compare_digest(sha(key), pol['cursor_key_sha256']),
         'EC280_CURSOR_KEY_REPLACED', 'unavailable')
    return key

def validate_subject(subject: Any) -> dict:
    need(type(subject) is dict and set(subject) == SUBJECT_KEYS and
         subject.get('schema') == SUBJECT_SCHEMA, 'EC280_SUBJECT_SCHEMA_INVALID')
    need(type(subject['grant_id']) is str and
         io.HEX_NONCE.fullmatch(subject['grant_id']) is not None and
         type(subject['uid']) is int and 0 <= subject['uid'] <= 2**31-1,
         'EC280_SUBJECT_UID_OR_ID_INVALID')
    for key in ('policy_sha256', 'evidence_sha256'):
        need(type(subject[key]) is str and io.HASH.fullmatch(subject[key]) is not None,
             'EC280_SUBJECT_SHA_INVALID')
    a, b = subject['issued_at_unix'], subject['expires_at_unix']
    need(type(a) is int and type(b) is int and 0 < a < b and b - a <= MAX_TTL,
         'EC280_SUBJECT_TTL_INVALID')
    validate_query(subject['query'])
    return subject

def make_subject(q: dict, uid: int, policy_sha: str,
                 evidence_sha: str, ttl: int, now: int | None = None) -> dict:
    need(type(ttl) is int and 1 <= ttl <= MAX_TTL, 'EC280_TTL_OUT_OF_RANGE')
    t = int(time.time()) if now is None else now
    return validate_subject({
        'schema': SUBJECT_SCHEMA, 'grant_id': secrets.token_hex(16),
        'uid': uid, 'policy_sha256': policy_sha, 'evidence_sha256': evidence_sha,
        'issued_at_unix': t, 'expires_at_unix': t + ttl, 'query': q})

def validate_grant(grant: Any, pol: dict, *, uid: int,
                   now: int, policy_sha: str) -> dict:
    need(type(grant) is dict and set(grant) == {
        'schema', 'subject', 'evidence_signature_ed25519', 'query_signature_ed25519'
    } and grant.get('schema') == GRANT_SCHEMA,
         'EC280_GRANT_SHAPE_INVALID', 'permission_denied')
    try:
        s = validate_subject(grant['subject'])
    except (ValueError, TypeError, KeyError) as exc:
        raise HostError('EC280_SIGNED_SUBJECT_INVALID', 'permission_denied') from exc
    need(uid in pol['allowed_uids'] and uid == s['uid'] and
         s['query']['source_scope'] == pol['source_scope'] and
         hmac.compare_digest(s['policy_sha256'], policy_sha) and
         hmac.compare_digest(s['evidence_sha256'], pol['evidence_sha256']),
         'EC280_UID_SOURCE_OR_BATCH_NOT_AUTHORIZED', 'permission_denied')
    need(s['issued_at_unix'] <= now + MAX_CLOCK_SKEW and s['expires_at_unix'] > now,
         'EC280_SIGNED_GRANT_EXPIRED_OR_FUTURE', 'permission_denied')
    verify('evidence', s, grant['evidence_signature_ed25519'],
           pol['evidence_issuer_public_hex'])
    verify('query', s, grant['query_signature_ed25519'],
           pol['query_issuer_public_hex'])
    return s

def denial(code: str, status: str = 'permission_denied') -> dict:
    return {'schema': DENIAL_SCHEMA, 'status': status,
            'exit_code': {'permission_denied': 3, 'invalid_input': 4,
                          'unavailable': 5}[status],
            'reason_code': code, 'handler_invoked': False,
            'business_effect_verified': False,
            'provider_or_source_authenticated': False}

def signed_reply(req: dict, result: dict, policy_sha: str,
                 evidence_sha: str, key: Ed25519PrivateKey, now: int) -> dict:
    payload = {'schema': REPLY_SCHEMA, 'request_sha256': sha(canonical(req)),
               'nonce': req['nonce'], 'policy_sha256': policy_sha,
               'evidence_sha256': evidence_sha, 'issued_at_unix': now,
               'result': result}
    return {**payload, 'signature_ed25519': sign('server', payload, key)}

def verify_reply(reply: Any, req: dict, *, server_public_hex: str,
                 policy_sha: str, now: int) -> dict:
    need(type(reply) is dict and set(reply) == {
        'schema', 'request_sha256', 'nonce', 'policy_sha256', 'evidence_sha256',
        'issued_at_unix', 'result', 'signature_ed25519'
    } and reply['schema'] == REPLY_SCHEMA,
         'EC280_REPLY_SCHEMA_INVALID', 'unavailable')
    subject = validate_subject(req['grant']['subject'])
    need(reply['request_sha256'] == sha(canonical(req)) and
         reply['nonce'] == req['nonce'] and
         reply['policy_sha256'] == policy_sha == subject['policy_sha256'] and
         reply['evidence_sha256'] == subject['evidence_sha256'] and
         type(reply['issued_at_unix']) is int and
         abs(now - reply['issued_at_unix']) <= 120,
         'EC280_REPLY_REQUEST_BATCH_OR_TIME_MISMATCH', 'unavailable')
    try:
        verify('server', {k: v for k, v in reply.items() if k != 'signature_ed25519'},
               reply['signature_ed25519'], server_public_hex)
    except HostError as exc:
        raise HostError('EC280_HOST_REPLY_SIGNATURE_INVALID', 'unavailable') from exc
    result = reply['result']
    need(type(result) is dict, 'EC280_HOST_REPLY_RESULT_INVALID', 'unavailable')
    if result.get('status') == 'partial':
        effects = result.get('effects')
        scope_sha, qsha = query_digest(subject['query'])
        need(result.get('schema') == quality.SCHEMA and
             result.get('exit_code') == 2 and
             result.get('query_sha256') == qsha and
             type(result.get('scope')) is dict and
             result['scope'].get('scope_sha256') == scope_sha and
             type(effects) is dict and effects.get('read_only') is True and
             all(effects.get(k) is False for k in (
                 'ces_store_written', 'business_repository_written',
                 'provider_requests', 'shell_or_tests_executed',
                 'stdout_or_source_disclosed', 'quality_pass_verified')) and
             type(result.get('proof')) is dict and
             result['proof'].get('verified_quality_pass') is False,
             'EC280_HOST_REPLY_CLAIMS_UNSUPPORTED_QUALITY_PASS', 'unavailable')
    else:
        need(result.get('schema') == DENIAL_SCHEMA and
             (result.get('status'), result.get('exit_code')) in (
                 ('permission_denied', 3), ('invalid_input', 4), ('unavailable', 5)),
             'EC280_HOST_REPLY_DENIAL_INVALID', 'unavailable')
    return result
