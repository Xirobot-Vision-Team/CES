#!/usr/bin/env python3
"""EC250: operator-owned Linux AF_UNIX broker for one existing FindingShow/Query.

A JSON request never provides read authorization, store roots, grants or module
names. A separately installed, owner-private policy binds the kernel-verified
client UID to one exact EC179 source binding and disclosure permissions.
This is a local OS identity boundary, NOT enterprise SSO, actor attestation,
provider authorization or a business-success claim. Original router stays deny.
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
import struct
import sys
from typing import Any

MODULE_DIR = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = MODULE_DIR.parent
sys.path.insert(0, str(MODULE_DIR))

import finding_show as show  # noqa: E402 - fixed local module, no dynamic import

POLICY_SCHEMA = 'ces.ec250.finding_host_policy.v1'
REQUEST_SCHEMA = 'ces.ec250.finding_host_query.v1'
RESPONSE_SCHEMA = 'ces.ec250.finding_host_response.v1'
MAX_POLICY = 131_072
MAX_REQUEST = 16_384
MAX_RESPONSE = 262_144
MAX_GRANTS = 128
MAX_REQUESTS = 100
SCOPE_ID = re.compile(r'[a-z][a-z0-9_-]{2,63}\Z')
SHA = re.compile(r'[a-f0-9]{64}\Z')
POLICY_FIELDS = {'schema', 'store', 'grants'}
STORE_FIELDS = {'stage_root', 'business_repo_root', 'finding_store_root',
                'codesave_root', 'expected_finding_store_pin'}
GRANT_FIELDS = {'uid', 'scope_id', 'source_binding', 'source_mode',
                'allow_expired_audit', 'allow_path_digest_query',
                'allow_digest_details', 'acknowledge_historical_proposal'}
REQUEST_FIELDS = {'schema', 'scope_id', 'filters', 'page_size', 'cursor',
                  'include_expired', 'include_digest_details'}


class HostError(ValueError):
    def __init__(self, code: str, status: str = 'permission_denied') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def _need(ok: bool, code: str, status: str = 'invalid_input') -> None:
    if not ok:
        raise HostError(code, status)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('DUPLICATE_KEY')
        result[key] = value
    return result


def _json(raw: bytes, size: int) -> dict[str, Any]:
    _need(0 < len(raw) <= size, 'HOST_JSON_SIZE_INVALID')
    try:
        obj = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_pairs,
                         parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        raise HostError('HOST_JSON_INVALID') from exc
    _need(type(obj) is dict, 'HOST_JSON_OBJECT_REQUIRED')
    return obj


def _wire(obj: dict[str, Any], *, limit: int = MAX_RESPONSE) -> bytes:
    try:
        raw = json.dumps(obj, ensure_ascii=True, allow_nan=False,
                         sort_keys=True, separators=(',', ':')).encode('ascii') + b'\n'
    except (ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise HostError('HOST_RESULT_SERIALIZE_UNAVAILABLE', 'unavailable') from exc
    _need(len(raw) <= limit, 'HOST_RESPONSE_TOO_LARGE', 'unavailable')
    return raw


def _reply(status: str, code: str, *, result: dict[str, Any] | None = None,
           peer_checked: bool = False, policy_checked: bool = False) -> dict[str, Any]:
    out = {
        'schema': RESPONSE_SCHEMA,
        'status': status, 'reason_code': code,
        'exit_code': {'partial': 2, 'permission_denied': 3,
                      'invalid_input': 4, 'unavailable': 5}[status],
        'host_os_peer_uid_verified': peer_checked,
        'host_scope_policy_checked': policy_checked,
        'enterprise_actor_authenticated': False,
        'business_effect_verified': False,
        'provider_permissions_verified': False,
        'business_repository_written': False,
        'result': result,
    }
    return out


def _absolute_no_link(path: str, *, file: bool) -> Path:
    _need(type(path) is str and path and '\x00' not in path,
          'HOST_OPERATOR_PATH_INVALID', 'unavailable')
    p = Path(path)
    _need(p.is_absolute() and '..' not in p.parts,
          'HOST_OPERATOR_PATH_NOT_ABSOLUTE', 'unavailable')
    try:
        normalized = p.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise HostError('HOST_OPERATOR_PATH_UNAVAILABLE', 'unavailable') from exc
    _need(p == normalized and p != PACKAGE_ROOT and
          PACKAGE_ROOT not in p.parents,
          'HOST_POLICY_OR_SOCKET_INSIDE_PACKAGE_OR_SYMLINK', 'unavailable')
    # Reject even intermediate symlinks. Paths are host-owned configuration,
    # not dynamic client input, but their parent must not be mutable by others.
    cur = Path(p.anchor)
    try:
        for component in p.parts[1:-1] if file else p.parts[1:]:
            cur = cur / component
            st = os.lstat(cur)
            _need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode),
                  'HOST_OPERATOR_PARENT_SYMLINK_OR_NOT_DIRECTORY', 'unavailable')
    except OSError as exc:
        raise HostError('HOST_OPERATOR_PARENT_UNAVAILABLE', 'unavailable') from exc
    return p


def _private_parent(path: str, *, policy: bool) -> Path:
    p = _absolute_no_link(path, file=True)
    try:
        st = os.lstat(p.parent)
    except OSError as exc:
        raise HostError('HOST_PARENT_UNAVAILABLE', 'unavailable') from exc
    _need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
          st.st_mode & 0o022 == 0 and st.st_mode & 0o007 == 0 and
          (not policy or st.st_mode & 0o070 == 0),
          'HOST_PARENT_NOT_OWNER_PRIVATE', 'unavailable')
    return p


def _read_policy_file(policy_path: str) -> tuple[dict[str, Any], str]:
    p = _private_parent(policy_path, policy=True)
    fd: int | None = None
    try:
        fd = os.open(str(p), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                     getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0))
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
              before.st_uid == os.geteuid() and before.st_mode & 0o077 == 0 and
              0 < before.st_size <= MAX_POLICY,
              'HOST_POLICY_NOT_OWNER_PRIVATE_REGULAR', 'unavailable')
        raw = os.read(fd, MAX_POLICY + 1)
        after = os.fstat(fd)
        final_path = os.lstat(p)
        _need((before.st_dev, before.st_ino, before.st_size,
               before.st_mtime_ns, before.st_ctime_ns) ==
              (after.st_dev, after.st_ino, after.st_size,
               after.st_mtime_ns, after.st_ctime_ns) and
              (after.st_dev, after.st_ino) == (final_path.st_dev, final_path.st_ino) and
              len(raw) == before.st_size,
              'HOST_POLICY_CHANGED_DURING_READ', 'unavailable')
    except HostError:
        raise
    except OSError as exc:
        raise HostError('HOST_POLICY_READ_UNAVAILABLE', 'unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)
    policy = _json(raw, MAX_POLICY)
    _validate_policy(policy)
    return policy, hashlib.sha256(raw).hexdigest()


def _validate_policy(obj: dict[str, Any]) -> None:
    _need(set(obj) == POLICY_FIELDS and obj.get('schema') == POLICY_SCHEMA,
          'HOST_POLICY_SCHEMA_OR_FIELDS_INVALID', 'unavailable')
    store = obj['store']
    _need(type(store) is dict and set(store) == STORE_FIELDS and
          type(store['expected_finding_store_pin']) is str and
          SHA.fullmatch(store['expected_finding_store_pin']) is not None,
          'HOST_STORE_CONFIGURATION_INVALID', 'unavailable')
    for key in ('stage_root', 'business_repo_root', 'finding_store_root'):
        _need(type(store[key]) is str and store[key] and
              Path(store[key]).is_absolute() and '\x00' not in store[key] and
              '..' not in Path(store[key]).parts,
              'HOST_STORE_ROOT_INVALID', 'unavailable')
    cr = store['codesave_root']
    _need(cr is None or (type(cr) is str and cr and Path(cr).is_absolute() and
                         '..' not in Path(cr).parts and '\x00' not in cr),
          'HOST_CODESAVE_ROOT_INVALID', 'unavailable')
    grants = obj['grants']
    _need(type(grants) is list and 1 <= len(grants) <= MAX_GRANTS,
          'HOST_POLICY_GRANTS_INVALID', 'unavailable')
    unique: set[tuple[int, str]] = set()
    for grant in grants:
        _need(type(grant) is dict and set(grant) == GRANT_FIELDS,
              'HOST_POLICY_GRANT_FIELDS_INVALID', 'unavailable')
        uid, name, mode = grant['uid'], grant['scope_id'], grant['source_mode']
        _need(type(uid) is int and 0 <= uid <= 2 ** 32 - 2 and
              type(name) is str and SCOPE_ID.fullmatch(name) is not None,
              'HOST_GRANT_UID_OR_SCOPE_INVALID', 'unavailable')
        _need((uid, name) not in unique, 'HOST_POLICY_DUPLICATE_GRANT', 'unavailable')
        unique.add((uid, name))
        _need(type(mode) is str and mode in show.lc.SOURCE_MODES,
              'HOST_GRANT_SOURCE_MODE_INVALID', 'unavailable')
        try:
            show._binding(grant['source_binding'], mode)
        except (show.FindingShowError, TypeError, ValueError, KeyError) as exc:
            raise HostError('HOST_GRANT_SOURCE_BINDING_INVALID', 'unavailable') from exc
        for flag in GRANT_FIELDS - {'uid', 'scope_id', 'source_binding', 'source_mode'}:
            _need(type(grant[flag]) is bool, 'HOST_GRANT_BOOLEAN_REQUIRED', 'unavailable')
        if mode == 'ProposedPR':
            _need(grant['acknowledge_historical_proposal'] is True,
                  'HOST_GRANT_HISTORICAL_ACK_REQUIRED', 'unavailable')


def _query(request: dict[str, Any], policy: dict[str, Any], uid: int) -> tuple[dict[str, Any], dict[str, Any]]:
    _need(set(request) == REQUEST_FIELDS and request.get('schema') == REQUEST_SCHEMA,
          'HOST_REQUEST_FIELDS_INVALID')
    name = request['scope_id']
    _need(type(name) is str and SCOPE_ID.fullmatch(name) is not None,
          'HOST_SCOPE_ID_INVALID')
    _need(type(request['page_size']) is int and 1 <= request['page_size'] <= show.MAX_PAGE_SIZE and
          type(request['include_expired']) is bool and
          type(request['include_digest_details']) is bool and
          (request['cursor'] is None or (type(request['cursor']) is str and
            0 < len(request['cursor']) <= show.MAX_CURSOR_BYTES)),
          'HOST_REQUEST_OPTIONS_INVALID')
    # Existing FindingShow does strict digest/type/value filtering; do not
    # accept a request-supplied permission or root through an unknown key.
    filters = request['filters']
    _need(type(filters) is dict and len(filters) <= len(show.FILTERS),
          'HOST_REQUEST_FILTERS_INVALID')
    try:
        show._filter(filters)
    except (show.FindingShowError, TypeError, ValueError) as exc:
        raise HostError('HOST_REQUEST_FILTERS_INVALID') from exc
    grant = next((g for g in policy['grants'] if
                  g['uid'] == uid and g['scope_id'] == name), None)
    _need(grant is not None, 'HOST_PEER_UID_SCOPE_NOT_GRANTED', 'permission_denied')
    _need((not request['include_expired'] or grant['allow_expired_audit']) and
          (not request['include_digest_details'] or grant['allow_digest_details']) and
          ('path_identity_sha256' not in filters or grant['allow_path_digest_query']),
          'HOST_QUERY_DISCLOSURE_NOT_GRANTED', 'permission_denied')
    store = policy['store']
    kwargs = {
        'expected_finding_store_pin': store['expected_finding_store_pin'],
        'authorize_store_read': True, 'authorize_query': True,
        'authorized_source_binding': dict(grant['source_binding']),
        'query_content_for': grant['source_mode'],
        'filters': filters, 'page_size': request['page_size'],
        'cursor': request['cursor'],
        'include_expired': request['include_expired'],
        'authorize_expired_audit': grant['allow_expired_audit'],
        'authorize_path_digest_query': grant['allow_path_digest_query'],
        'include_digest_details': request['include_digest_details'],
        'authorize_digest_details': grant['allow_digest_details'],
        'acknowledge_historical_proposal_metadata': grant['acknowledge_historical_proposal'],
    }
    return store, kwargs


def execute(request_bytes: bytes, policy_path: str, verified_peer_uid: int) -> dict[str, Any]:
    """Execute after kernel SO_PEERCRED verification, not with a caller UID field."""
    policy_checked = False
    try:
        req = _json(request_bytes, MAX_REQUEST)
        policy, pin = _read_policy_file(policy_path)  # fresh on every page/query
        store, kwargs = _query(req, policy, verified_peer_uid)
        policy_checked = True
        shower = show.FindingShower(
            store['stage_root'], store['business_repo_root'], store['finding_store_root'],
            codesave_root=store['codesave_root'])
        result = shower.query(**kwargs)  # real EC178 private HMAC ledger; no mock success
        _need(type(result) is dict and
              type(result.get('status')) is str and
              result.get('status') in ('partial', 'invalid_input', 'unavailable') and
              type(result.get('exit_code')) is int and
              result['exit_code'] == {'partial': 2, 'invalid_input': 4,
                                      'unavailable': 5}[result['status']],
              'HOST_FINDING_RESULT_INVALID', 'unavailable')
        # A mid-read permission/config update invalidates the answer; never
        # return bytes gathered under an already-replaced policy.
        _need(_read_policy_file(policy_path)[1] == pin,
              'HOST_POLICY_REVISED_DURING_QUERY', 'unavailable')
        return _reply(result['status'], result.get('reason_code', 'HOST_FINDING_RESULT'),
                      result=result, peer_checked=True, policy_checked=True)
    except HostError as exc:
        return _reply(exc.status, exc.code, peer_checked=True,
                      policy_checked=policy_checked)
    except (OSError, ValueError, TypeError, RuntimeError, KeyError, MemoryError):
        return _reply('unavailable', 'HOST_FINDING_OPERATION_UNAVAILABLE',
                      peer_checked=True, policy_checked=policy_checked)


def _linux() -> None:
    _need(sys.platform.startswith('linux') and hasattr(socket, 'SO_PEERCRED') and
          hasattr(socket, 'AF_UNIX') and hasattr(os, 'geteuid'),
          'HOST_LINUX_PEERCRED_REQUIRED', 'unavailable')


def _uid_from_peer(conn: socket.socket) -> int:
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                              struct.calcsize('3i'))
        pid, uid, _gid = struct.unpack('3i', raw)
    except (OSError, ValueError, struct.error) as exc:
        raise HostError('HOST_PEER_CREDENTIALS_UNAVAILABLE', 'unavailable') from exc
    _need(pid > 0 and 0 <= uid < 2 ** 32 - 1,
          'HOST_PEER_CREDENTIALS_INVALID', 'unavailable')
    return uid


def _receive(conn: socket.socket, limit: int) -> bytes:
    body = bytearray()
    while True:
        chunk = conn.recv(min(4096, limit + 2 - len(body)))
        _need(chunk, 'HOST_REQUEST_INCOMPLETE')
        body.extend(chunk)
        _need(len(body) <= limit + 1, 'HOST_REQUEST_TOO_LARGE')
        if b'\n' in chunk:
            _need(body.endswith(b'\n') and body.count(b'\n') == 1,
                  'HOST_REQUEST_TRAILING_BYTES')
            return bytes(body[:-1])


def _safe_wire(reply: dict[str, Any]) -> bytes:
    try:
        return _wire(reply)
    except HostError:
        return _wire(_reply('unavailable', 'HOST_RESPONSE_TOO_LARGE'))


def serve(policy_path: str, socket_path: str, *, max_requests: int = 1,
          accept_timeout: float = 60.0) -> None:
    _linux()
    _need(type(max_requests) is int and 1 <= max_requests <= MAX_REQUESTS and
          1.0 <= accept_timeout <= 300.0, 'HOST_SERVER_BOUNDS_INVALID')
    _read_policy_file(policy_path)  # operator must install valid private policy
    target = _private_parent(socket_path, policy=False)
    _need(len(os.fsencode(str(target))) < 100,
          'HOST_SOCKET_PATH_TOO_LONG', 'unavailable')
    try:
        os.lstat(target)
    except FileNotFoundError:
        pass
    else:
        raise HostError('HOST_SOCKET_ALREADY_EXISTS', 'unavailable')
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    created: tuple[int, int] | None = None
    try:
        previous_umask = os.umask(0o117)  # newly created socket <= 0660
        try:
            listener.bind(str(target))
        finally:
            os.umask(previous_umask)
        st = os.lstat(target)
        created = (st.st_dev, st.st_ino)
        _need(stat.S_ISSOCK(st.st_mode) and st.st_uid == os.geteuid() and
              st.st_mode & 0o007 == 0 and st.st_mode & 0o002 == 0,
              'HOST_SOCKET_MODE_INVALID', 'unavailable')
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
                    uid = _uid_from_peer(conn)
                    req = _receive(conn, MAX_REQUEST)
                    reply = execute(req, policy_path, uid)
                except HostError as exc:
                    reply = _reply(exc.status, exc.code)
                except (OSError, socket.timeout):
                    reply = _reply('unavailable', 'HOST_CLIENT_IO_UNAVAILABLE')
                try:
                    conn.sendall(_safe_wire(reply))
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


def query(socket_path: str, request_file: str, expected_host_uid: int) -> dict[str, Any]:
    """Client verifies installed server UID; outputs are not signed attestations."""
    _linux()
    _need(type(expected_host_uid) is int and 0 <= expected_host_uid < 2 ** 32 - 1,
          'HOST_EXPECTED_SERVER_UID_REQUIRED')
    with open(request_file, 'rb') as fd:
        req = fd.read(MAX_REQUEST + 2)
    obj = _json(req, MAX_REQUEST)
    _need(obj.get('schema') == REQUEST_SCHEMA, 'HOST_REQUEST_SCHEMA_INVALID')
    raw = _wire(obj, limit=MAX_REQUEST + 1)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5.0)
        conn.connect(socket_path)
        _need(_uid_from_peer(conn) == expected_host_uid,
              'HOST_SERVER_UID_MISMATCH', 'permission_denied')
        conn.sendall(raw)
        answer = _receive(conn, MAX_RESPONSE)
    result = _json(answer, MAX_RESPONSE)
    _need(result.get('schema') == RESPONSE_SCHEMA and
          result.get('status') in ('partial', 'permission_denied', 'invalid_input', 'unavailable') and
          type(result.get('exit_code')) is int and
          result.get('exit_code') == {
              'partial': 2, 'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5
          }[result['status']], 'HOST_SERVER_RESPONSE_INVALID', 'unavailable')
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC250 Linux owner-configured FindingShow host broker; no enterprise attestation')
    subs = parser.add_subparsers(dest='command', required=True)
    server = subs.add_parser('serve')
    server.add_argument('--policy', required=True, help='operator-owned absolute private policy JSON')
    server.add_argument('--socket', required=True, help='new absolute socket in private owner directory')
    server.add_argument('--max-requests', type=int, default=1)
    server.add_argument('--accept-timeout', type=float, default=60)
    client = subs.add_parser('query')
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
    except HostError as exc:
        result = _reply(exc.status, exc.code)
    except (OSError, socket.timeout):
        result = _reply('unavailable', 'HOST_COMMAND_IO_UNAVAILABLE')
    print(_wire(result).decode('ascii').rstrip('\n'))
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
