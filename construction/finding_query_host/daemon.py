#!/usr/bin/env python3
"""EC279: dedicated, locally hosted FindingShow.Query read-only Unix socket.

Only server-owned policy chooses private roots and the exact store pin.  Each
request must carry TWO independent offline-signed grants for an exact source,
query, OS peer uid, store pin and bounded expiration.  A server signing key
pins the result for the unprivileged caller.  No generic/router grant exists.
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import time

from . import protocol as p


class AnchoredClock:
    """Nondecreasing in-process wall/monotonic floor; not durable trusted UTC."""
    def __init__(self):
        self.start = time.time()
        self.mono = time.monotonic()
        self.highest = int(self.start)

    def now(self) -> int:
        self.highest = max(self.highest, int(time.time()),
                           int(self.start + time.monotonic() - self.mono))
        return self.highest


def peer_uid(conn: socket.socket) -> int:
    if hasattr(socket, 'SO_PEERCRED'):
        payload = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                  struct.calcsize('3i'))
        _pid, uid, _gid = struct.unpack('3i', payload)
        return uid
    if hasattr(conn, 'getpeereid'):
        uid, _gid = conn.getpeereid()
        return uid
    raise p.HostError('EC279_OS_PEER_CREDENTIALS_UNAVAILABLE', 'unavailable')


def _decode_request(line: bytes) -> dict:
    p.require(line.endswith(b'\n'), 'EC279_SOCKET_REQUEST_TERMINATOR_REQUIRED')
    req = p.parse(line[:-1], p.MAX_RPC)
    p.require(set(req) == {'schema', 'nonce', 'grant', 'cursor'} and
              req['schema'] == p.REQUEST_SCHEMA and
              type(req['nonce']) is str and p.HEX_NONCE.fullmatch(req['nonce']) is not None and
              (req['cursor'] is None or type(req['cursor']) is str and
               0 < len(req['cursor']) <= 4096), 'EC279_REQUEST_SCHEMA_INVALID')
    return req


class QueryHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(8.0)
        # Bound allocation *before* parsing or touching the HMAC ledger.
        try:
            raw = self.rfile.readline(p.MAX_RPC + 2)
            req = _decode_request(raw)
        except (OSError, ValueError, TimeoutError):
            return   # Malformed anonymous messages do not earn signed replies.
        result: dict
        server: FindingServer = self.server
        try:
            now = server.clock.now()
            current = p.load_policy(server.policy_path, server.policy_sha)
            p.require(current == server.policy,
                      'EC279_HOST_POLICY_REPLACED', 'unavailable')
            uid = peer_uid(self.request)
            subj = p.validate_grant(req['grant'], current, peer_uid=uid, now=now)
            # Instantiate FindingShow only AFTER both offline authorizations,
            # OS peer identity and server-owned policy have passed.
            import finding_show
            query = subj['query']
            shower = finding_show.FindingShower(
                current['stage_root'], current['business_repo_root'],
                current['finding_store_root'], codesave_root=current['codesave_root'])
            raw_result = shower.query(
                expected_finding_store_pin=current['store_pin'],
                authorize_store_read=True, authorize_query=True,
                authorized_source_binding=query['source_binding'],
                query_content_for=query['query_content_for'],
                filters=query['filters'], page_size=query['page_size'],
                cursor=req['cursor'],
                include_expired=query['include_expired'],
                authorize_expired_audit=query['authorize_expired_audit'],
                authorize_path_digest_query=query['authorize_path_digest_query'],
                include_digest_details=query['include_digest_details'],
                authorize_digest_details=query['authorize_digest_details'],
                acknowledge_historical_proposal_metadata=(
                    query['acknowledge_historical_proposal_metadata']))
            if (type(raw_result) is not dict or
                    raw_result.get('schema') != 'ces.finding_show_result.v1' or
                    raw_result.get('status') != 'partial' or
                    raw_result.get('exit_code') != 2 or
                    raw_result.get('effects', {}).get('external_transfer') is not False or
                    raw_result.get('effects', {}).get('ces_records_written') is not False or
                    raw_result.get('effects', {}).get('plaintext_source_or_model_released') is not False):
                raise p.HostError('EC279_BACKEND_REFUSED_OR_UNEXPECTED', 'unavailable')
            result = raw_result
        except p.HostError as exc:
            result = p.denial(exc.code, exc.status)
        except Exception:
            # No store paths, tokens, untrusted JSON or backend exceptions escape.
            result = p.denial('EC279_PRIVATE_STORE_OR_HOST_UNAVAILABLE', 'unavailable')
        try:
            reply = p.signed_reply(req=req, result=result, policy_sha=server.policy_sha,
                                   server_key=server.signing_key, now=server.clock.now())
            raw = p.canonical(reply) + b'\n'
            if len(raw) > p.MAX_REPLY:
                result = p.denial('EC279_SIGNED_REPLY_EXCEEDS_BUDGET', 'unavailable')
                reply = p.signed_reply(req=req, result=result, policy_sha=server.policy_sha,
                                       server_key=server.signing_key, now=server.clock.now())
                raw = p.canonical(reply) + b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass


class FindingServer(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, *, path: str, policy_path: str, policy_sha: str,
                 private_key_file: str):
        p.require(hasattr(socket, 'AF_UNIX') and
                  (hasattr(socket, 'SO_PEERCRED') or hasattr(socket.socket, 'getpeereid')),
                  'EC279_UNIX_PEER_IDENTITY_OS_REQUIRED', 'unavailable')
        p.require(type(path) is str and os.path.isabs(path) and len(path) < 100,
                  'EC279_UNIX_SOCKET_ABSOLUTE_PATH_REQUIRED')
        parent = Path(path).parent
        try:
            fst = os.lstat(parent)
        except OSError as exc:
            raise p.HostError('EC279_SOCKET_PARENT_UNAVAILABLE', 'unavailable') from exc
        p.require(stat.S_ISDIR(fst.st_mode) and not fst.st_mode & 0o002,
                  'EC279_SOCKET_DIRECTORY_INSECURE', 'unavailable')
        try:
            os.lstat(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise p.HostError('EC279_SOCKET_PATH_UNAVAILABLE', 'unavailable') from exc
        else:
            raise p.HostError('EC279_SOCKET_ALREADY_EXISTS', 'unavailable')
        self.policy_path = policy_path
        self.policy_sha = policy_sha
        self.policy = p.load_policy(policy_path, policy_sha)
        self.signing_key = p.private_from_file(private_key_file)
        from cryptography.hazmat.primitives import serialization
        own_pub = self.signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()
        p.require(hmac.compare_digest(own_pub, self.policy['server_public_hex']),
                  'EC279_SERVER_KEY_NOT_PINNED_IN_POLICY', 'unavailable')
        self.clock = AnchoredClock()
        self._sock_inode = None
        try:
            super().__init__(path, QueryHandler, bind_and_activate=True)
            os.chmod(path, 0o660)
            self._sock_inode = (os.lstat(path).st_dev, os.lstat(path).st_ino)
        except Exception:
            # Do not remove any path other than our own newly bound socket.
            self.server_close()
            raise

    def server_close(self):
        super().server_close()
        if self._sock_inode is not None:
            try:
                st = os.lstat(self.server_address)
                if stat.S_ISSOCK(st.st_mode) and (st.st_dev, st.st_ino) == self._sock_inode:
                    os.unlink(self.server_address)
            except FileNotFoundError:
                pass
