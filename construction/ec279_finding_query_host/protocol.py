#!/usr/bin/env python3
"""EC279 dual-authority, exact-scoped read grants and pinned service replies.

The original EC241/243 router continues to reject HOST_REQUIRED.  This module
only authorizes FindingShow.Query at a separately deployed AF_UNIX host; JSON
supplied by a client is never interpreted as an authorization flag by itself.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
from contextvars import ContextVar
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

POLICY_SCHEMA = 'ces.ec279.finding_host_policy.v1'
SUBJECT_SCHEMA = 'ces.ec279.finding_read_subject.v1'
GRANT_SCHEMA = 'ces.ec279.finding_read_grant.v1'
VOTE_SCHEMA = 'ces.ec279.finding_read_vote.v1'
REQUEST_SCHEMA = 'ces.ec279.finding_query_request.v1'
REPLY_SCHEMA = 'ces.ec279.finding_query_signed_reply.v1'
DENIAL_SCHEMA = 'ces.ec279.finding_query_denial.v1'
DOMAINS = {
    'store': b'CES/EC279/FindingShow/StoreReadGrant/v1\0',
    'query': b'CES/EC279/FindingShow/ExactQueryGrant/v1\0',
    'server': b'CES/EC279/FindingShow/HostReply/v1\0',
}
MAX_DOC = 24000
MAX_RPC = 24000
MAX_REPLY = 135000
MAX_LIFETIME = 600
MAX_CLOCK_SKEW = 30
HASH = re.compile(r'[0-9a-f]{64}\Z')
HEX_SIG = re.compile(r'[0-9a-f]{128}\Z')
HEX_NONCE = re.compile(r'[0-9a-f]{32}\Z')
QUERY_KEYS = frozenset({
    'source_binding', 'query_content_for', 'filters', 'page_size',
    'include_expired', 'include_digest_details', 'authorize_expired_audit',
    'authorize_path_digest_query', 'authorize_digest_details',
    'acknowledge_historical_proposal_metadata',
})
FLAGS = QUERY_KEYS - {'source_binding', 'query_content_for', 'filters', 'page_size'}
SUBJECT_KEYS = frozenset({'schema', 'grant_id', 'uid', 'store_pin',
                          'issued_at_unix', 'expires_at_unix', 'query'})
POLICY_KEYS = frozenset({'schema', 'stage_root', 'business_repo_root',
                         'finding_store_root', 'codesave_root', 'store_pin',
                         'store_issuer_public_hex', 'query_issuer_public_hex',
                         'server_public_hex', 'allowed_uids'})


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input'):
        super().__init__(code)
        self.code, self.status = code, status


def require(value: bool, code: str, status: str = 'invalid_input') -> None:
    if not value:
        raise HostError(code, status)


def canonical(doc: Any) -> bytes:
    try:
        return json.dumps(doc, sort_keys=True, ensure_ascii=True,
                          separators=(',', ':'), allow_nan=False).encode('ascii')
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise HostError('EC279_DOCUMENT_NOT_JSON') from exc


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict:
    obj = {}
    for k, v in pairs:
        require(k.casefold() not in {i.casefold() for i in obj},
                'EC279_DUPLICATE_OR_CASE_COLLIDING_KEY')
        obj[k] = v
    return obj


def parse(raw: bytes, limit: int = MAX_DOC) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= limit and
            not raw.startswith(b'\xef\xbb\xbf'), 'EC279_JSON_LENGTH_OR_BOM_INVALID')
    try:
        obj = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=strict_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except HostError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise HostError('EC279_JSON_INVALID') from exc
    require(type(obj) is dict, 'EC279_JSON_OBJECT_REQUIRED')
    return obj


# EC317: opt-in, scoped, read-only relocation of ORIGINAL source paths.
# No default behavior change; source signers, hosts and ordinary CLI calls do
# not set these context variables. Only source reads (never writes) consult it.
_SOURCE_READ_BINDINGS: ContextVar[dict[str, str] | None] = ContextVar(
    'ces_ec317_source_read_bindings', default=None)
_SOURCE_READ_OBSERVER: ContextVar[Any] = ContextVar(
    'ces_ec317_source_read_observer', default=None)
_INTERNAL_SNAPSHOT_READS: ContextVar[frozenset[str]] = ContextVar(
    'ces_ec317_verified_ec302_internal_snapshot_reads', default=frozenset())
# EC336: precise verifier-created temporary import grants. The permissions
# live only for the matching TemporaryDirectory and do NOT authorize arbitrary
# files by /tmp prefix. Unlike EC302 typed snapshots, imports are still seen
# by the ORIGINAL observer, preserving EC335's historical read accounting.
_VERIFIED_LOCAL_IMPORT_READS: ContextVar[frozenset[str]] = ContextVar(
    'ces_ec336_verified_local_import_reads', default=frozenset())


@contextmanager
def _scoped_original_source_reads(*, bindings: dict[str, str] | None = None,
                                  observer: Any = None):
    """EC317 restricted verifier scope, no implicit original-path fallback.

    Callers must first validate and SHA-pin every mapped private destination.
    This context is never accepted from the original RPC/router or Host.
    """
    bindings_token = _SOURCE_READ_BINDINGS.set(bindings)
    observer_token = _SOURCE_READ_OBSERVER.set(observer)
    try:
        yield
    finally:
        _SOURCE_READ_OBSERVER.reset(observer_token)
        _SOURCE_READ_BINDINGS.reset(bindings_token)


@contextmanager
def _scoped_verified_snapshot_reads(files: frozenset[str]):
    """EC302-generated typed snapshot docs only; never a general path prefix."""
    before = _INTERNAL_SNAPSHOT_READS.get()
    token = _INTERNAL_SNAPSHOT_READS.set(before | files)
    try:
        yield
    finally:
        _INTERNAL_SNAPSHOT_READS.reset(token)


@contextmanager
def _scoped_verified_local_import_reads(files: frozenset[str]):
    """Permit only exact locally materialized, verified historical ZIP members.

    Internal production import verifiers call this after creating their own
    private originals from previously SHA-checked source containers. The caller
    must construct the set from its own written destinations, not JSON claims.
    This is a read-only, context-local exemption; it does not expose a CLI grant.
    """
    require(type(files) is frozenset and all(
        type(path) is str and os.path.isabs(path) and not path.startswith('//')
        and '\x00' not in path and '\\' not in path and os.path.normpath(path) == path
        for path in files), 'EC336_LOCAL_IMPORT_GRANT_INVALID')
    token = _VERIFIED_LOCAL_IMPORT_READS.set(_VERIFIED_LOCAL_IMPORT_READS.get() | files)
    try:
        yield
    finally:
        _VERIFIED_LOCAL_IMPORT_READS.reset(token)


def _is_scoped_verified_local_import_read(path: str) -> bool:
    return type(path) is str and path in _VERIFIED_LOCAL_IMPORT_READS.get()


def _original_source_read_path(path: str) -> str:
    """Map only explicitly present originals; absent originals fail closed."""
    bindings = _SOURCE_READ_BINDINGS.get()
    if bindings is None:
        return path
    if type(path) is str and path in bindings:
        return bindings[path]
    if type(path) is str and path in _INTERNAL_SNAPSHOT_READS.get():
        return path
    if _is_scoped_verified_local_import_read(path):
        return path
    raise HostError('EC317_UNMAPPED_ORIGINAL_SOURCE_READ', 'permission_denied')


def _open_regular(path: str, limit: int, private: bool = False) -> bytes:
    require(type(path) is str and os.path.isabs(path) and len(path) <= 4096,
            'EC279_ABSOLUTE_FILE_REQUIRED')
    original_path = path
    path = _original_source_read_path(path)
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                     getattr(os, 'O_CLOEXEC', 0))
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit and
                (before.st_mode & 0o022) == 0 and
                (not private or (before.st_mode & 0o077) == 0),
                'EC279_FILE_TYPE_SIZE_OR_PERMISSIONS_INVALID', 'unavailable')
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns),
                'EC279_FILE_CHANGED_DURING_READ', 'unavailable')
        observer = _SOURCE_READ_OBSERVER.get()
        if observer is not None and original_path not in _INTERNAL_SNAPSHOT_READS.get():
            # EC302 has already decoded/verified these exact ephemeral files;
            # they must not be exported as non-existent external originals.
            observer(original_path, raw)
        return raw
    except OSError as exc:
        raise HostError('EC279_FILE_UNAVAILABLE', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)


def read_doc(path: str, limit: int = MAX_DOC, *, private: bool = False) -> dict:
    return parse(_open_regular(path, limit, private), limit)


def write_exclusive(path: str, doc: dict, *, mode: int = 0o600) -> None:
    require(type(path) is str and os.path.isabs(path), 'EC279_ABSOLUTE_OUTPUT_REQUIRED')
    data = canonical(doc) + b'\n'
    require(len(data) <= MAX_DOC, 'EC279_OUTPUT_TOO_LARGE')
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), mode)
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb', closefd=True) as f:
            fd = None
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        parent = os.open(os.path.dirname(path), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError as exc:
        raise HostError('EC279_EXCLUSIVE_OUTPUT_FAILED', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)


def pub_from_hex(raw: Any) -> Ed25519PublicKey:
    require(type(raw) is str and HASH.fullmatch(raw) is not None,
            'EC279_ED25519_PUBLIC_HEX_INVALID')
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(raw))


def private_from_file(path: str) -> Ed25519PrivateKey:
    key = _open_regular(path, 64, private=True)
    require(len(key) == 32, 'EC279_PRIVATE_ED25519_KEY_INVALID', 'unavailable')
    return Ed25519PrivateKey.from_private_bytes(key)


def sign(role: str, subject: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(DOMAINS[role] + canonical(subject)).hex()


def verify(role: str, subject: dict, sig: Any, pub_hex: str) -> None:
    require(type(sig) is str and HEX_SIG.fullmatch(sig) is not None,
            'EC279_SIGNED_GRANT_SIGNATURE_FORMAT_INVALID', 'permission_denied')
    try:
        pub_from_hex(pub_hex).verify(bytes.fromhex(sig),
                                     DOMAINS[role] + canonical(subject))
    except Exception as exc:
        raise HostError('EC279_SIGNED_GRANT_SIGNATURE_FAILED', 'permission_denied') from exc


def policy_check(obj: dict) -> dict:
    require(set(obj) == POLICY_KEYS and obj['schema'] == POLICY_SCHEMA,
            'EC279_POLICY_SCHEMA_INVALID', 'unavailable')
    for key in ('stage_root', 'business_repo_root', 'finding_store_root'):
        require(type(obj[key]) is str and os.path.isabs(obj[key]) and
                Path(obj[key]).is_dir(), 'EC279_HOST_ROOT_INVALID', 'unavailable')
    require(obj['codesave_root'] is None or (type(obj['codesave_root']) is str and
            os.path.isabs(obj['codesave_root']) and Path(obj['codesave_root']).is_dir()),
            'EC279_CODESAVE_ROOT_INVALID', 'unavailable')
    require(type(obj['store_pin']) is str and HASH.fullmatch(obj['store_pin']) is not None,
            'EC279_STORE_PIN_INVALID', 'unavailable')
    keys = [obj[k] for k in ('store_issuer_public_hex', 'query_issuer_public_hex',
                             'server_public_hex')]
    for key in keys:
        pub_from_hex(key)
    require(len(set(keys)) == 3, 'EC279_THREE_DISTINCT_ED25519_ROLES_REQUIRED', 'unavailable')
    uids = obj['allowed_uids']
    require(type(uids) is list and 0 < len(uids) <= 32 and
            all(type(u) is int and 0 <= u <= 2**31-1 for u in uids) and
            len(set(uids)) == len(uids), 'EC279_HOST_ALLOWED_UIDS_INVALID', 'unavailable')
    return obj


def load_policy(path: str, expected_sha: str) -> dict:
    require(type(expected_sha) is str and HASH.fullmatch(expected_sha) is not None,
            'EC279_HOST_POLICY_PIN_REQUIRED', 'unavailable')
    raw = _open_regular(path, MAX_DOC)
    require(hmac.compare_digest(sha(raw), expected_sha),
            'EC279_HOST_POLICY_CHANGED_OR_WRONG_PIN', 'unavailable')
    return policy_check(parse(raw))


def validate_query(q: Any) -> dict:
    require(type(q) is dict and set(q) == QUERY_KEYS,
            'EC279_EXACT_QUERY_FIELDS_REQUIRED')
    require(type(q['source_binding']) is dict and 0 < len(q['source_binding']) <= 24 and
            type(q['query_content_for']) is str and 1 <= len(q['query_content_for']) <= 48 and
            type(q['filters']) is dict and len(q['filters']) <= 30 and
            type(q['page_size']) is int and 1 <= q['page_size'] <= 25,
            'EC279_QUERY_TYPES_INVALID')
    require(all(type(q[f]) is bool for f in FLAGS), 'EC279_SIGNED_QUERY_BOOLEAN_FLAGS_REQUIRED')
    require(not q['include_expired'] or q['authorize_expired_audit'],
            'EC279_EXPIRED_AUDIT_SIGNED_GRANT_REQUIRED')
    require(not q['include_digest_details'] or q['authorize_digest_details'],
            'EC279_DIGEST_DETAILS_SIGNED_GRANT_REQUIRED')
    require('path_identity_sha256' not in q['filters'] or
            q['authorize_path_digest_query'], 'EC279_PATH_DIGEST_SIGNED_GRANT_REQUIRED')
    require(q['query_content_for'] != 'ProposedPR' or
            q['acknowledge_historical_proposal_metadata'],
            'EC279_HISTORICAL_METADATA_ACK_REQUIRED')
    return q


def validate_subject(s: Any) -> dict:
    require(type(s) is dict and set(s) == SUBJECT_KEYS and
            s.get('schema') == SUBJECT_SCHEMA, 'EC279_READ_SUBJECT_SCHEMA_INVALID')
    require(type(s['grant_id']) is str and HEX_NONCE.fullmatch(s['grant_id']) is not None and
            type(s['uid']) is int and 0 <= s['uid'] <= 2**31 - 1 and
            type(s['store_pin']) is str and HASH.fullmatch(s['store_pin']) is not None and
            type(s['issued_at_unix']) is int and type(s['expires_at_unix']) is int and
            0 < s['issued_at_unix'] < s['expires_at_unix'] and
            s['expires_at_unix'] - s['issued_at_unix'] <= MAX_LIFETIME,
            'EC279_SUBJECT_TTL_OR_IDENTITY_INVALID')
    validate_query(s['query'])
    return s


def validate_grant(grant: Any, policy: dict, *, peer_uid: int, now: int) -> dict:
    require(type(grant) is dict and set(grant) == {
        'schema', 'subject', 'store_signature_ed25519', 'query_signature_ed25519'
    } and grant.get('schema') == GRANT_SCHEMA,
            'EC279_GRANT_SCHEMA_INVALID', 'permission_denied')
    try:
        s = validate_subject(grant['subject'])
    except HostError as exc:
        raise HostError('EC279_SIGNED_SUBJECT_INVALID', 'permission_denied') from exc
    require(peer_uid in policy['allowed_uids'] and peer_uid == s['uid'] and
            hmac.compare_digest(s['store_pin'], policy['store_pin']),
            'EC279_UID_OR_STORE_PIN_NOT_AUTHORIZED', 'permission_denied')
    require(s['issued_at_unix'] <= now + MAX_CLOCK_SKEW and
            s['expires_at_unix'] > now,
            'EC279_SIGNED_GRANT_EXPIRED_OR_NOT_YET_VALID', 'permission_denied')
    verify('store', s, grant['store_signature_ed25519'], policy['store_issuer_public_hex'])
    verify('query', s, grant['query_signature_ed25519'], policy['query_issuer_public_hex'])
    return s


def new_subject(*, q: dict, uid: int, store_pin: str, ttl: int, now: int | None = None) -> dict:
    require(type(ttl) is int and 1 <= ttl <= MAX_LIFETIME,
            'EC279_GRANT_TTL_OUT_OF_BOUNDS')
    issued = int(time.time()) if now is None else now
    s = {'schema': SUBJECT_SCHEMA, 'grant_id': secrets.token_hex(16), 'uid': uid,
         'store_pin': store_pin, 'issued_at_unix': issued,
         'expires_at_unix': issued + ttl, 'query': q}
    return validate_subject(s)


def denial(code: str, status: str = 'permission_denied') -> dict:
    return {'schema': DENIAL_SCHEMA, 'status': status,
            'exit_code': {'permission_denied': 3, 'invalid_input': 4,
                          'unavailable': 5}[status],
            'reason_code': code, 'handler_invoked': False,
            'private_store_content_disclosed': False,
            'business_effect_verified': False}


def signed_reply(*, req: dict, result: dict, policy_sha: str,
                 server_key: Ed25519PrivateKey, now: int) -> dict:
    core = {'schema': REPLY_SCHEMA, 'request_sha256': sha(canonical(req)),
            'nonce': req['nonce'], 'policy_sha256': policy_sha,
            'issued_at_unix': now, 'result': result}
    return {**core, 'signature_ed25519': sign('server', core, server_key)}


def verify_reply(reply: Any, req: dict, *, public_hex: str,
                 policy_sha: str, now: int) -> dict:
    require(type(reply) is dict and set(reply) == {
        'schema', 'request_sha256', 'nonce', 'policy_sha256',
        'issued_at_unix', 'result', 'signature_ed25519'
    } and reply['schema'] == REPLY_SCHEMA,
            'EC279_REPLY_SCHEMA_INVALID', 'unavailable')
    require(reply['request_sha256'] == sha(canonical(req)) and
            reply['nonce'] == req['nonce'] and
            reply['policy_sha256'] == policy_sha and
            type(reply['issued_at_unix']) is int and
            abs(now - reply['issued_at_unix']) <= 120,
            'EC279_REPLY_WRONG_REQUEST_POLICY_OR_TIME', 'unavailable')
    try:
        verify('server', {k: v for k, v in reply.items() if k != 'signature_ed25519'},
               reply['signature_ed25519'], public_hex)
    except HostError as exc:
        raise HostError('EC279_REPLY_SIGNATURE_FAILED', 'unavailable') from exc
    result = reply['result']
    require(type(result) is dict and type(result.get('status')) is str and
            type(result.get('exit_code')) is int,
            'EC279_REPLY_RESULT_INVALID', 'unavailable')
    if result['status'] == 'partial':
        require(result.get('schema') == 'ces.finding_show_result.v1' and
                result['exit_code'] == 2 and
                type(result.get('effects')) is dict and
                result['effects'].get('external_transfer') is False and
                result['effects'].get('ces_records_written') is False and
                result['effects'].get('plaintext_source_or_model_released') is False,
                'EC279_REPLY_SUCCESS_NOT_READONLY', 'unavailable')
    else:
        require(result.get('schema') == DENIAL_SCHEMA and
                (result['status'], result['exit_code']) in {
                    ('permission_denied', 3), ('invalid_input', 4), ('unavailable', 5)
                }, 'EC279_REPLY_DENIAL_INVALID', 'unavailable')
    return result
