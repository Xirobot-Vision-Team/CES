#!/usr/bin/env python3
"""EC251: one Linux-only operator-pinned QualityShow/Query endpoint.

The Unix peer UID is a local kernel credential, NOT an enterprise identity.
Host-private policy selects a fixed source scope, snapshot and cursor key;
clients can only choose a pregranted scope handle and display filters.
The underlying EC188 projection consumes existing, unauthenticated receipts:
no source/CI/runner attestation, tests, provider calls or business writes occur.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
from typing import Any

CONSTRUCTION = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = CONSTRUCTION.parent
sys.path.insert(0, str(CONSTRUCTION))

import quality_show as quality  # fixed existing code, not client-selected
from ec250_finding_host import broker as fio  # reuse frozen OS peer/framing helpers

POLICY_SCHEMA = 'ces.ec251.quality_host_policy.v1'
SNAPSHOT_SCHEMA = 'ces.ec251.quality_evidence_snapshot.v1'
REQUEST_SCHEMA = 'ces.ec251.quality_host_query.v1'
RESPONSE_SCHEMA = 'ces.ec251.quality_host_response.v1'
MAX_POLICY = 131072
MAX_SNAPSHOT = quality.MAX_BATCH_BYTES
MAX_REQUEST = 8192
MAX_RESPONSE = 131072
MAX_GRANTS = 64
MAX_REQUESTS = 100
MAX_KEY_BYTES = 128
SCOPE_ID = re.compile(r'[a-z][a-z0-9_-]{2,63}\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')
POLICY_FIELDS = {'schema', 'source_scope', 'snapshot_path', 'expected_snapshot_sha256',
                 'cursor_key_path', 'expected_cursor_key_sha256', 'grants'}
GRANT_FIELDS = {'uid', 'scope_id', 'allowed_kinds', 'allow_numeric_metrics',
                'acknowledge_historical_proposal'}
REQUEST_FIELDS = {'schema', 'scope_id', 'filters', 'page_size', 'cursor',
                  'include_numeric_metrics'}
STATUS_EXIT = {'partial': 2, 'permission_denied': 3, 'invalid_input': 4,
               'unavailable': 5}


class QualityHostError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if not ok:
        raise QualityHostError(code, status)


def _parse(raw: bytes, limit: int, *, trusted: bool = False) -> dict[str, Any]:
    try:
        return fio._json(raw, limit)
    except fio.HostError as exc:
        raise QualityHostError('QUALITY_HOST_JSON_INVALID_OR_TOO_LARGE',
                               'unavailable' if trusted else 'invalid_input') from exc


def _path(path: Any) -> str:
    need(type(path) is str and 0 < len(path) <= 1024 and '\x00' not in path and
         path.startswith('/') and os.path.normpath(path) == path and
         all(part not in ('', '.', '..') for part in path[1:].split('/')) and
         os.path.commonpath((path, str(PACKAGE_ROOT))) != str(PACKAGE_ROOT),
         'QUALITY_HOST_PRIVATE_PATH_INVALID', 'unavailable')
    return path


def _private_bytes(path: str, limit: int) -> bytes:
    """Open host-owned data via no-follow parent dirfds; reject link/parent races.

    A private final parent (0700), owned single-link 0600 file and stable
    dev/inode/size/mtime/ctime are required. Sticky root-owned /tmp is allowed
    as an intermediate; untrusted writable nonsticky parents are not.
    """
    p = _path(path)
    fd = None
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        parts = p[1:].split('/')
        for index, component in enumerate(parts[:-1]):
            nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                          os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
            st = os.fstat(fd)
            need(stat.S_ISDIR(st.st_mode), 'QUALITY_HOST_PARENT_NOT_DIRECTORY', 'unavailable')
            if index == len(parts) - 2:
                need(st.st_uid == os.geteuid() and st.st_mode & 0o077 == 0,
                     'QUALITY_HOST_PRIVATE_PARENT_REQUIRED', 'unavailable')
            else:
                unsafe_writable = st.st_mode & 0o022
                sticky_root = st.st_uid == 0 and st.st_mode & stat.S_ISVTX != 0
                need(not unsafe_writable or sticky_root,
                     'QUALITY_HOST_WRITABLE_ANCESTOR', 'unavailable')
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                          os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            before = os.fstat(file_fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
                 before.st_nlink == 1 and before.st_mode & 0o077 == 0 and
                 0 < before.st_size <= limit,
                 'QUALITY_HOST_PRIVATE_REGULAR_FILE_REQUIRED', 'unavailable')
            raw = os.read(file_fd, limit + 1)
            after = os.fstat(file_fd)
            entry = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            need(len(raw) == before.st_size and
                 (before.st_dev, before.st_ino, before.st_size,
                  before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size,
                  after.st_mtime_ns, after.st_ctime_ns) and
                 (entry.st_dev, entry.st_ino) == (after.st_dev, after.st_ino),
                 'QUALITY_HOST_PRIVATE_FILE_CHANGED', 'unavailable')
            return raw
        finally:
            os.close(file_fd)
    except QualityHostError:
        raise
    except (OSError, ValueError, OverflowError) as exc:
        raise QualityHostError('QUALITY_HOST_PRIVATE_READ_UNAVAILABLE', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)


def _validate_policy(policy: dict[str, Any]) -> None:
    need(set(policy) == POLICY_FIELDS and policy.get('schema') == POLICY_SCHEMA,
         'QUALITY_HOST_POLICY_FIELDS_INVALID', 'unavailable')
    try:
        normalized_scope = quality._scope(policy['source_scope'])
    except (quality.QualityShowError, TypeError, KeyError, ValueError, AttributeError) as exc:
        raise QualityHostError('QUALITY_HOST_POLICY_SCOPE_INVALID', 'unavailable') from exc
    need(normalized_scope == policy['source_scope'],
         'QUALITY_HOST_POLICY_SCOPE_INVALID', 'unavailable')
    for name in ('expected_snapshot_sha256', 'expected_cursor_key_sha256'):
        value = policy[name]
        need(type(value) is str and SHA.fullmatch(value) is not None,
             'QUALITY_HOST_POLICY_SHA_INVALID', 'unavailable')
    _path(policy['snapshot_path'])
    _path(policy['cursor_key_path'])
    need(policy['snapshot_path'] != policy['cursor_key_path'],
         'QUALITY_HOST_DATA_AND_KEY_MUST_DIFFER', 'unavailable')
    grants = policy['grants']
    need(type(grants) is list and 1 <= len(grants) <= MAX_GRANTS,
         'QUALITY_HOST_POLICY_GRANTS_INVALID', 'unavailable')
    pairs = set()
    for grant in grants:
        need(type(grant) is dict and set(grant) == GRANT_FIELDS,
             'QUALITY_HOST_GRANT_FIELDS_INVALID', 'unavailable')
        uid, sid, kinds = grant['uid'], grant['scope_id'], grant['allowed_kinds']
        need(type(uid) is int and 0 <= uid < 2**32 - 1 and
             type(sid) is str and SCOPE_ID.fullmatch(sid) is not None and
             (uid, sid) not in pairs,
             'QUALITY_HOST_GRANT_ID_INVALID', 'unavailable')
        pairs.add((uid, sid))
        need(type(kinds) is list and 1 <= len(kinds) <= len(quality.KINDS) and
             all(type(k) is str and k in quality.KINDS for k in kinds) and
             kinds == sorted(set(kinds)),
             'QUALITY_HOST_GRANT_KINDS_INVALID', 'unavailable')
        need(type(grant['allow_numeric_metrics']) is bool and
             type(grant['acknowledge_historical_proposal']) is bool,
             'QUALITY_HOST_GRANT_FLAGS_INVALID', 'unavailable')
        if normalized_scope['source_mode'] == 'ProposedPR':
            need(grant['acknowledge_historical_proposal'] is True,
                 'QUALITY_HOST_HISTORICAL_ACK_REQUIRED', 'unavailable')


def _policy(path: str) -> tuple[dict[str, Any], str]:
    raw = _private_bytes(path, MAX_POLICY)
    policy = _parse(raw, MAX_POLICY, trusted=True)
    _validate_policy(policy)
    return policy, hashlib.sha256(raw).hexdigest()


def _snapshot(policy: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    raw = _private_bytes(policy['snapshot_path'], MAX_SNAPSHOT)
    sha = hashlib.sha256(raw).hexdigest()
    need(sha == policy['expected_snapshot_sha256'],
         'QUALITY_HOST_SNAPSHOT_PIN_MISMATCH', 'unavailable')
    data = _parse(raw, MAX_SNAPSHOT, trusted=True)
    need(set(data) == {'schema', 'source_scope', 'evidence'} and
         data.get('schema') == SNAPSHOT_SCHEMA and
         type(data.get('source_scope')) is dict and
         data['source_scope'] == policy['source_scope'] and
         type(data.get('evidence')) is list and
         len(data['evidence']) <= quality.MAX_RECORDS,
         'QUALITY_HOST_SNAPSHOT_FIELDS_OR_SCOPE_INVALID', 'unavailable')
    for item in data['evidence']:
        need(type(item) is dict and set(item) == {
                 'kind', 'result', 'source_scope', 'recorded_at_utc'} and
             type(item['source_scope']) is dict and
             item['source_scope'] == policy['source_scope'] and
             type(item['kind']) is str and item['kind'] in quality.KINDS,
             'QUALITY_HOST_SNAPSHOT_RECORD_SCOPE_INVALID', 'unavailable')
    return data['evidence'], sha


def _key(policy: dict[str, Any]) -> bytes:
    key = _private_bytes(policy['cursor_key_path'], MAX_KEY_BYTES)
    need(32 <= len(key) <= MAX_KEY_BYTES and
         hashlib.sha256(key).hexdigest() == policy['expected_cursor_key_sha256'],
         'QUALITY_HOST_CURSOR_KEY_PIN_MISMATCH', 'unavailable')
    return key


def _prepare_request(request: dict[str, Any], policy: dict[str, Any], uid: int
                     ) -> tuple[dict[str, Any], dict[str, Any]]:
    need(set(request) == REQUEST_FIELDS and request.get('schema') == REQUEST_SCHEMA,
         'QUALITY_HOST_REQUEST_FIELDS_INVALID')
    sid = request['scope_id']
    need(type(sid) is str and SCOPE_ID.fullmatch(sid) is not None and
         type(request['page_size']) is int and 1 <= request['page_size'] <= quality.MAX_PAGE and
         (request['cursor'] is None or
          (type(request['cursor']) is str and len(request['cursor']) <= quality.MAX_CURSOR_BYTES)) and
         type(request['include_numeric_metrics']) is bool and
         (request['filters'] is None or type(request['filters']) is dict),
         'QUALITY_HOST_REQUEST_TYPES_INVALID')
    grant = next((g for g in policy['grants'] if
                  g['uid'] == uid and g['scope_id'] == sid), None)
    need(grant is not None, 'QUALITY_HOST_PEER_SCOPE_NOT_GRANTED', 'permission_denied')
    need(not request['include_numeric_metrics'] or grant['allow_numeric_metrics'],
         'QUALITY_HOST_NUMERIC_NOT_GRANTED', 'permission_denied')
    raw_filters = request['filters'] or {}
    if 'kinds' in raw_filters:
        kinds = raw_filters['kinds']
        need(type(kinds) is list and all(type(k) is str for k in kinds),
             'QUALITY_HOST_REQUEST_KINDS_INVALID')
        need(set(kinds) <= set(grant['allowed_kinds']),
             'QUALITY_HOST_KIND_NOT_GRANTED', 'permission_denied')
    else:
        raw_filters = dict(raw_filters, kinds=grant['allowed_kinds'])
    try:
        filters = quality._filters(raw_filters)
    except (quality.QualityShowError, ValueError, TypeError, KeyError) as exc:
        raise QualityHostError('QUALITY_HOST_REQUEST_FILTERS_INVALID') from exc
    return grant, filters


def _reply(status: str, code: str, result: dict[str, Any] | None = None,
           *, peer: bool = False, policy: bool = False, snapshot: bool = False
           ) -> dict[str, Any]:
    return {'schema': RESPONSE_SCHEMA, 'status': status,
            'exit_code': STATUS_EXIT[status], 'reason_code': code,
            'host_os_peer_uid_verified': peer, 'host_scope_policy_checked': policy,
            'host_private_snapshot_pin_verified': snapshot,
            'source_identity_authenticated': False,
            'enterprise_actor_authenticated': False,
            'ci_runner_authenticated': False,
            'quality_pass_verified': False,
            'business_repository_written': False,
            'external_provider_called': False,
            'result': result}


def execute(request_bytes: bytes, policy_path: str, verified_peer_uid: int
            ) -> dict[str, Any]:
    """Called exclusively with server-obtained SO_PEERCRED UID; no caller UID field."""
    checked = False
    pinned = False
    try:
        request = _parse(request_bytes, MAX_REQUEST)
        pol, policy_pin = _policy(policy_path)  # independently owned, current
        grant, filters = _prepare_request(request, pol, verified_peer_uid)
        checked = True
        evidence, snapshot_pin = _snapshot(pol)
        pinned = True
        cursor_key = _key(pol)
        allowed = [item for item in evidence if item['kind'] in grant['allowed_kinds']]
        approved = {(quality.digest(quality.DOMAIN_RECORD, item), item['kind'],
                     hashlib.sha256(quality.canonical(item['result'])).hexdigest())
                    for item in allowed}
        scope = pol['source_scope']
        scope_hash = quality.digest(quality.DOMAIN_SCOPE, scope)

        def authorize_scope(facts: dict[str, Any]) -> bool:
            return (facts.get('source_scope') == scope and
                    facts.get('source_scope_sha256') == scope_hash and
                    facts.get('phase') in ('BEFORE_READ', 'FINALIZE') and
                    facts.get('include_numeric_metrics') is request['include_numeric_metrics'])

        def authorize_evidence(facts: dict[str, Any]) -> bool:
            return (facts.get('source_scope') == scope and
                    facts.get('source_scope_sha256') == scope_hash and
                    (facts.get('record_sha256'), facts.get('kind'),
                     facts.get('receipt_sha256')) in approved)

        def authorize_numeric(facts: dict[str, Any]) -> bool:
            return (grant['allow_numeric_metrics'] and authorize_scope(facts) and
                    facts.get('purpose') == 'QUALITYSHOW_NUMERIC_PROVIDER_METRICS')

        result = quality.QualityShow(cursor_key=cursor_key).query(
            source_scope=dict(scope), evidence=allowed,
            allow_query=True, allow_evidence_read=True,
            authorize_scope=authorize_scope, authorize_evidence=authorize_evidence,
            filters=filters, page_size=request['page_size'], cursor=request['cursor'],
            include_numeric_metrics=request['include_numeric_metrics'],
            authorize_numeric_metrics=authorize_numeric if grant['allow_numeric_metrics'] else None,
            acknowledge_historical_proposal=grant['acknowledge_historical_proposal'])
        need(type(result) is dict and result.get('schema') == quality.SCHEMA and
             result.get('status') in ('partial', 'invalid_input', 'unavailable') and
             type(result.get('exit_code')) is int and
             result['exit_code'] == STATUS_EXIT[result['status']],
             'QUALITY_HOST_RESULT_CONTRACT_INVALID', 'unavailable')
        # Reject mid-query data, policy, key changes instead of leaking a page
        # obtained before an operator revoke. No guarantee vs malicious owner ABA.
        next_pol, next_pin = _policy(policy_path)
        need(next_pin == policy_pin and next_pol == pol and
             _snapshot(next_pol)[1] == snapshot_pin and
             _key(next_pol) == cursor_key,
             'QUALITY_HOST_AUTHORIZATION_OR_SNAPSHOT_CHANGED', 'unavailable')
        return _reply(result['status'], result['reason_code'], result,
                      peer=True, policy=True, snapshot=True)
    except QualityHostError as exc:
        return _reply(exc.status, exc.code, peer=True, policy=checked,
                      snapshot=pinned)
    except (OSError, ValueError, RuntimeError, TypeError, KeyError,
            OverflowError, MemoryError, RecursionError, UnicodeError):
        return _reply('unavailable', 'QUALITY_HOST_OPERATION_UNAVAILABLE',
                      peer=True, policy=checked, snapshot=pinned)


def _wire(reply: dict[str, Any]) -> bytes:
    try:
        return fio._wire(reply, limit=MAX_RESPONSE)
    except fio.HostError:
        return fio._wire(_reply('unavailable', 'QUALITY_HOST_RESPONSE_TOO_LARGE'),
                         limit=MAX_RESPONSE)


def serve(policy_path: str, socket_path: str, *, max_requests: int = 1,
          accept_timeout: float = 60.0) -> None:
    fio._linux()
    need(type(max_requests) is int and 1 <= max_requests <= MAX_REQUESTS and
         type(accept_timeout) in (int, float) and 1 <= accept_timeout <= 300,
         'QUALITY_HOST_SERVER_BOUNDS_INVALID')
    pol, _ = _policy(policy_path)
    _snapshot(pol)
    _key(pol)
    target = fio._private_parent(socket_path, policy=False)
    need(len(os.fsencode(str(target))) < 100,
         'QUALITY_HOST_SOCKET_PATH_TOO_LONG', 'unavailable')
    try:
        os.lstat(target)
    except FileNotFoundError:
        pass
    else:
        raise QualityHostError('QUALITY_HOST_SOCKET_ALREADY_EXISTS', 'unavailable')
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    created: tuple[int, int] | None = None
    try:
        previous_umask = os.umask(0o117)
        try:
            listener.bind(str(target))
        finally:
            os.umask(previous_umask)
        st = os.lstat(target)
        created = (st.st_dev, st.st_ino)
        need(stat.S_ISSOCK(st.st_mode) and st.st_uid == os.geteuid() and
             st.st_mode & 0o007 == 0 and st.st_mode & 0o002 == 0,
             'QUALITY_HOST_SOCKET_MODE_INVALID', 'unavailable')
        listener.listen(8)
        listener.settimeout(accept_timeout)
        for _ in range(max_requests):
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                break
            with conn:
                conn.settimeout(5.0)
                try:
                    uid = fio._uid_from_peer(conn)
                    raw = fio._receive(conn, MAX_REQUEST)
                    reply = execute(raw, policy_path, uid)
                except fio.HostError as exc:
                    reply = _reply(exc.status, exc.code)
                except QualityHostError as exc:
                    reply = _reply(exc.status, exc.code)
                except (OSError, socket.timeout):
                    reply = _reply('unavailable', 'QUALITY_HOST_CLIENT_IO_UNAVAILABLE')
                try:
                    conn.sendall(_wire(reply))
                except OSError:
                    pass
    finally:
        listener.close()
        if created is not None:
            try:
                st = os.lstat(target)
                if stat.S_ISSOCK(st.st_mode) and (st.st_dev, st.st_ino) == created:
                    os.unlink(target)
            except FileNotFoundError:
                pass


def query(socket_path: str, request_file: str, expected_host_uid: int
          ) -> dict[str, Any]:
    fio._linux()
    need(type(expected_host_uid) is int and 0 <= expected_host_uid < 2**32 - 1,
         'QUALITY_HOST_EXPECTED_UID_REQUIRED')
    with open(request_file, 'rb') as fh:
        request = _parse(fh.read(MAX_REQUEST + 1), MAX_REQUEST)
    need(request.get('schema') == REQUEST_SCHEMA,
         'QUALITY_HOST_REQUEST_SCHEMA_INVALID')
    raw = fio._wire(request, limit=MAX_REQUEST)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5.0)
        conn.connect(socket_path)
        need(fio._uid_from_peer(conn) == expected_host_uid,
             'QUALITY_HOST_SERVER_UID_MISMATCH', 'permission_denied')
        conn.sendall(raw)
        result = _parse(fio._receive(conn, MAX_RESPONSE), MAX_RESPONSE, trusted=True)
    need(set(result) == {'schema', 'status', 'reason_code', 'exit_code',
                         'host_os_peer_uid_verified', 'host_scope_policy_checked',
                         'host_private_snapshot_pin_verified',
                         'source_identity_authenticated',
                         'enterprise_actor_authenticated', 'ci_runner_authenticated',
                         'quality_pass_verified', 'business_repository_written',
                         'external_provider_called', 'result'} and
         result.get('schema') == RESPONSE_SCHEMA and
         result.get('status') in STATUS_EXIT and
         type(result.get('exit_code')) is int and
         result.get('exit_code') == STATUS_EXIT[result['status']] and
         all(type(result[key]) is bool for key in (
             'host_os_peer_uid_verified', 'host_scope_policy_checked',
             'host_private_snapshot_pin_verified', 'source_identity_authenticated',
             'enterprise_actor_authenticated', 'ci_runner_authenticated',
             'quality_pass_verified', 'business_repository_written',
             'external_provider_called')) and
         all(result[key] is False for key in (
             'source_identity_authenticated', 'enterprise_actor_authenticated',
             'ci_runner_authenticated', 'quality_pass_verified',
             'business_repository_written', 'external_provider_called')) and
         (result['result'] is None or type(result['result']) is dict),
         'QUALITY_HOST_RESPONSE_INVALID', 'unavailable')
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC251 owner-scoped Linux QualityShow; no source/CI/test attestation')
    sub = parser.add_subparsers(dest='command', required=True)
    server = sub.add_parser('serve')
    server.add_argument('--policy', required=True)
    server.add_argument('--socket', required=True)
    server.add_argument('--max-requests', type=int, default=1)
    server.add_argument('--accept-timeout', type=float, default=60.0)
    client = sub.add_parser('query')
    client.add_argument('--socket', required=True)
    client.add_argument('--request-file', required=True)
    client.add_argument('--expect-host-uid', required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if args.command == 'serve':
            serve(args.policy, args.socket, max_requests=args.max_requests,
                  accept_timeout=args.accept_timeout)
            return 0
        result = query(args.socket, args.request_file, args.expect_host_uid)
    except QualityHostError as exc:
        result = _reply(exc.status, exc.code)
    except fio.HostError as exc:
        result = _reply(exc.status, exc.code)
    except (OSError, socket.timeout):
        result = _reply('unavailable', 'QUALITY_HOST_COMMAND_IO_UNAVAILABLE')
    print(_wire(result).decode('ascii').rstrip('\n'))
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
