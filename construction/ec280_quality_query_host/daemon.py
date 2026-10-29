#!/usr/bin/env python3
"""EC280 AF_UNIX QualityShow host: read an exact server-pinned private receipt batch.

The evidence/query signers each review the same offline subject, with separate
Ed25519 domains. Server owns the immutable-by-SHA batch and an HMAC cursor key.
Native peer UID is required before *any* private evidence read is attempted.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import socket
import socketserver
import stat

from ec279_finding_query_host.daemon import AnchoredClock, peer_uid
from ec279_finding_query_host import protocol as io
import quality_show as quality
from . import protocol as p


def decode_request(line: bytes) -> dict:
    p.need(line.endswith(b'\n') and len(line) <= p.MAX_RPC + 1,
           'EC280_SOCKET_REQUEST_TERMINATOR_OR_SIZE_INVALID')
    req = io.parse(line[:-1], p.MAX_RPC)
    p.need(set(req) == {'schema', 'nonce', 'grant', 'cursor'} and
           req['schema'] == p.REQUEST_SCHEMA and
           type(req['nonce']) is str and io.HEX_NONCE.fullmatch(req['nonce']) is not None and
           type(req['grant']) is dict and
           (req['cursor'] is None or type(req['cursor']) is str and
            0 < len(req['cursor']) <= quality.MAX_CURSOR_BYTES),
           'EC280_SOCKET_REQUEST_SHAPE_INVALID')
    return req


def perform_query(pol: dict, subject: dict, cursor: str | None) -> dict:
    # This call site is reachable only after *both* offline signatures and the
    # kernel UID succeeded. Evidence is NEVER supplied by the client.
    _, evidence = p.load_batch(pol)
    key = p.load_cursor_key(pol)
    q = subject['query']
    scope_sha, query_sha = p.query_digest(q)
    authorized_items = set()
    for item in evidence:
        # QualityShow itself still validates producer checkums, timestamp,
        # scope equality, each receipt's structure and its projection.
        if type(item) is not dict or set(item) != {
            'kind', 'result', 'source_scope', 'recorded_at_utc'
        } or type(item.get('result')) is not dict:
            raise p.HostError('EC280_PINNED_EVIDENCE_ITEM_SHAPE_INVALID', 'unavailable')
        authorized_items.add((
            item['kind'], item['recorded_at_utc'],
            hashlib.sha256(quality.canonical(item['result'])).hexdigest(),
            quality.digest(quality.DOMAIN_RECORD, item)
        ))

    def authorize_scope(facts: dict) -> bool:
        return (type(facts) is dict and
                facts.get('phase') in ('BEFORE_READ', 'FINALIZE') and
                facts.get('purpose') == 'QUALITYSHOW_READ_SCOPED_EVIDENCE' and
                facts.get('source_scope') == pol['source_scope'] and
                facts.get('source_scope_sha256') == scope_sha and
                facts.get('query_sha256') == query_sha and
                facts.get('include_numeric_metrics') is q['include_numeric_metrics'])

    def authorize_metrics(facts: dict) -> bool:
        return (q['include_numeric_metrics'] is True and
                type(facts) is dict and
                facts.get('phase') in ('BEFORE_READ', 'FINALIZE') and
                facts.get('purpose') == 'QUALITYSHOW_NUMERIC_PROVIDER_METRICS' and
                facts.get('source_scope') == pol['source_scope'] and
                facts.get('source_scope_sha256') == scope_sha and
                facts.get('query_sha256') == query_sha and
                facts.get('include_numeric_metrics') is True)

    def authorize_item(facts: dict) -> bool:
        return (type(facts) is dict and
                facts.get('purpose') == 'QUALITYSHOW_READ_EVIDENCE_ITEM' and
                facts.get('source_scope') == pol['source_scope'] and
                facts.get('source_scope_sha256') == scope_sha and
                (facts.get('kind'), facts.get('recorded_at_utc'),
                 facts.get('receipt_sha256'), facts.get('record_sha256'))
                in authorized_items)

    shower = quality.QualityShow(cursor_key=key)
    result = shower.query(
        source_scope=q['source_scope'], evidence=evidence,
        allow_query=True, allow_evidence_read=True,
        authorize_scope=authorize_scope, authorize_evidence=authorize_item,
        filters=q['filters'], page_size=q['page_size'], cursor=cursor,
        include_numeric_metrics=q['include_numeric_metrics'],
        authorize_numeric_metrics=authorize_metrics if q['include_numeric_metrics'] else None,
        acknowledge_historical_proposal=q['acknowledge_historical_proposal'])
    if (type(result) is not dict or result.get('schema') != quality.SCHEMA or
        result.get('status') != 'partial' or result.get('exit_code') != 2 or
        result.get('effects') != quality._effects() or
        result.get('proof', {}).get('verified_quality_pass') is not False):
        # A corrupt host-owned batch, invalid continuation or refused backend
        # never becomes a successfully authorized QualityShow result.
        raise p.HostError('EC280_BACKEND_QUALITYSHOW_REFUSED', 'unavailable')
    return result


class QueryHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(8.0)
        try:
            req = decode_request(self.rfile.readline(p.MAX_RPC + 2))
        except (OSError, ValueError, TimeoutError):
            return
        host: QualityServer = self.server
        try:
            current = p.load_policy(host.policy_path, host.policy_sha)
            p.need(current == host.policy, 'EC280_POLICY_REPLACED', 'unavailable')
            uid = peer_uid(self.request)
            subject = p.validate_grant(req['grant'], current, uid=uid,
                                       now=host.clock.now(), policy_sha=host.policy_sha)
            result = perform_query(current, subject, req['cursor'])
        except p.HostError as exc:
            result = p.denial(exc.code, exc.status)
        except Exception:
            result = p.denial('EC280_PRIVATE_EVIDENCE_HOST_UNAVAILABLE', 'unavailable')

        try:
            reply = p.signed_reply(req, result, host.policy_sha,
                                   host.policy['evidence_sha256'],
                                   host.signing_key, host.clock.now())
            raw = p.canonical(reply) + b'\n'
            if len(raw) > p.MAX_REPLY:
                reply = p.signed_reply(
                    req, p.denial('EC280_SIGNED_REPLY_TOO_LARGE', 'unavailable'),
                    host.policy_sha, host.policy['evidence_sha256'],
                    host.signing_key, host.clock.now())
                raw = p.canonical(reply) + b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (BrokenPipeError, OSError, ValueError):
            return


class QualityServer(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, *, path: str, policy_path: str, policy_sha: str,
                 private_key_file: str):
        p.need(hasattr(socket, 'AF_UNIX') and
               (hasattr(socket, 'SO_PEERCRED') or
                hasattr(socket.socket, 'getpeereid')),
               'EC280_KERNEL_PEER_UID_UNAVAILABLE', 'unavailable')
        p.need(type(path) is str and os.path.isabs(path) and len(path) < 100,
               'EC280_SOCKET_ABSOLUTE_PATH_REQUIRED')
        try:
            parent = os.lstat(Path(path).parent)
        except OSError as exc:
            raise p.HostError('EC280_SOCKET_DIRECTORY_UNAVAILABLE', 'unavailable') from exc
        p.need(stat.S_ISDIR(parent.st_mode) and parent.st_mode & 0o002 == 0,
               'EC280_SOCKET_DIRECTORY_INSECURE', 'unavailable')
        try:
            os.lstat(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise p.HostError('EC280_SOCKET_PATH_UNAVAILABLE', 'unavailable') from exc
        else:
            raise p.HostError('EC280_SOCKET_ALREADY_EXISTS', 'unavailable')

        self.policy_path = policy_path
        self.policy_sha = policy_sha
        self.policy = p.load_policy(policy_path, policy_sha)
        # Validate receipt and HMAC-key pins before binding a service.
        p.load_batch(self.policy)
        p.load_cursor_key(self.policy)
        self.signing_key = io.private_from_file(private_key_file)
        p.need(hmac.compare_digest(p.public_hex(self.signing_key),
                                   self.policy['server_public_hex']),
               'EC280_HOST_KEY_NOT_PINNED', 'unavailable')
        self.clock = AnchoredClock()
        self._socket_inode = None
        try:
            super().__init__(path, QueryHandler, bind_and_activate=True)
            os.chmod(path, 0o660)
            st = os.lstat(path)
            self._socket_inode = (st.st_dev, st.st_ino)
        except Exception:
            self.server_close()
            raise

    def server_close(self):
        super().server_close()
        if self._socket_inode is not None:
            try:
                st = os.lstat(self.server_address)
                if stat.S_ISSOCK(st.st_mode) and (
                    st.st_dev, st.st_ino) == self._socket_inode:
                    os.unlink(self.server_address)
            except FileNotFoundError:
                pass
