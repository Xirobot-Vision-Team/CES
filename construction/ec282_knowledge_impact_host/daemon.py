#!/usr/bin/env python3
"""EC282 real AF_UNIX host invoking unchanged EC204 KnowledgeImpact.analyze.

One private, content-addressed exact Git/knowledge analysis per socket service.
Unsigned callers are refused before ANY repository or knowledge read. A valid
request cannot select paths, policies, Git refs, signer keys or a command.
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path
import socket
import socketserver
import stat

from ec279_finding_query_host.daemon import AnchoredClock, peer_uid
from ec279_finding_query_host import protocol as io
import knowledge_boundary as boundary
import knowledge_impact as impact
from . import protocol as p


def decode_request(raw: bytes) -> dict:
    p.need(raw.endswith(b'\n') and 1 < len(raw) <= p.MAX_RPC + 1,
           'EC282_REQUEST_LENGTH_OR_TERMINATOR_INVALID')
    req = io.parse(raw[:-1], p.MAX_RPC)
    p.need(set(req) == {'schema', 'nonce', 'grant'} and
           req['schema'] == p.REQUEST_SCHEMA and
           type(req['nonce']) is str and
           io.HEX_NONCE.fullmatch(req['nonce']) is not None and
           type(req['grant']) is dict,
           'EC282_REQUEST_FIELDS_INVALID')
    return req


def perform_analysis(server: 'ImpactServer', pol: dict,
                     s: dict) -> dict:
    # Already checked kernel SO_PEERCRED and BOTH domain-separated offline
    # signatures before entering this function. No caller-supplied job data.
    job = p.load_job(pol)
    p.need(job == server.job, 'EC282_PINNED_JOB_REPLACED', 'unavailable')

    def live_authorization() -> bool:
        try:
            return (server.clock.now() < s['expires_at_unix'] and
                    p.load_policy(server.policy_path, server.policy_sha) == pol and
                    p.load_job(pol) == job)
        except (p.HostError, io.HostError, OSError, ValueError):
            return False

    p.need(live_authorization(),
           'EC282_READ_GRANT_REVOKED_BEFORE_ANALYSIS', 'unavailable')
    api = impact.KnowledgeImpact(
        repository_root=job['repository_root'],
        knowledge_root=job['knowledge_root'],
        repository_ref=job['repository_ref'],
        target_ref=job['target_ref'],
        trusted_target_keys=p._keys(job['trusted_target_public_hex_by_id']),
        trusted_baseline_keys=p._keys(job['trusted_baseline_public_hex_by_id']),
        git_executable=job['git_executable'])
    result = api.analyze(
        request_json=boundary.canonical(job['request']),
        bootstrap_read_policy_json=boundary.canonical(job['bootstrap_read_policy']),
        target_read_policy_json=boundary.canonical(job['target_read_policy']),
        impact_read_policy_json=boundary.canonical(job['impact_read_policy']),
        target_statement_json=boundary.canonical(job['target_statement']),
        target_signature_base64=job['target_signature_base64'],
        baseline_statement_json=(boundary.canonical(job['baseline_statement'])
                                 if job['baseline_statement'] is not None else None),
        baseline_signature_base64=job['baseline_signature_base64'])
    # An EC204 result is always partial even if one selected path was exactly
    # Git-compared. No semantic chapter assessment and NO writes.
    p.need(live_authorization(),
           'EC282_READ_GRANT_REVOKED_DURING_ANALYSIS', 'unavailable')
    p.need(p.safe_backend_result(result, job),
           'EC282_ORIGINAL_EC204_BACKEND_DID_NOT_AUTHORIZE_RESULT', 'unavailable')
    return result


class ImpactHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(10.0)
        try:
            req = decode_request(self.rfile.readline(p.MAX_RPC + 2))
        except (OSError, TimeoutError, ValueError):
            return  # Anonymous broken frames cannot obtain signed receipts.
        server: ImpactServer = self.server
        invoked = False
        try:
            current = p.load_policy(server.policy_path, server.policy_sha)
            p.need(current == server.policy,
                   'EC282_HOST_POLICY_REPLACED', 'unavailable')
            uid = peer_uid(self.request)
            subject = p.validate_grant(req['grant'], current, server.job,
                                       uid=uid, now=server.clock.now(),
                                       policy_sha=server.policy_sha)
            invoked = True
            result = perform_analysis(server, current, subject)
        except p.HostError as exc:
            result = p.denial(exc.code, exc.status, backend_invoked=invoked)
        except Exception:
            # Don't assert no read or that the backend was not invoked when
            # the failure stage is unknown. Private exception text not exposed.
            result = p.denial('EC282_PRIVATE_ANALYSIS_HOST_UNAVAILABLE',
                              'unavailable', backend_invoked=None)
        try:
            reply = p.signed_reply(req, result, server.policy_sha,
                                   server.policy['job_sha256'],
                                   server.signing_key, server.clock.now())
            raw = p.canonical(reply) + b'\n'
            if len(raw) > p.MAX_REPLY:
                reply = p.signed_reply(
                    req, p.denial('EC282_SIGNED_RESULT_TOO_LARGE', 'unavailable',
                                  backend_invoked=invoked),
                    server.policy_sha, server.policy['job_sha256'],
                    server.signing_key, server.clock.now())
                raw = p.canonical(reply) + b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError, ValueError, BrokenPipeError):
            return


class ImpactServer(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, *, path: str, policy_path: str, policy_sha: str,
                 private_key_file: str):
        p.need(hasattr(socket, 'AF_UNIX') and
               (hasattr(socket, 'SO_PEERCRED') or
                hasattr(socket.socket, 'getpeereid')),
               'EC282_KERNEL_PEER_UID_UNAVAILABLE', 'unavailable')
        p.need(type(path) is str and os.path.isabs(path) and len(path) < 100,
               'EC282_SOCKET_ABSOLUTE_PATH_REQUIRED')
        try:
            parent = os.lstat(Path(path).parent)
        except OSError as exc:
            raise p.HostError('EC282_SOCKET_DIRECTORY_MISSING', 'unavailable') from exc
        p.need(stat.S_ISDIR(parent.st_mode) and not (parent.st_mode & 0o002),
               'EC282_SOCKET_DIRECTORY_UNSAFE', 'unavailable')
        try:
            os.lstat(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise p.HostError('EC282_SOCKET_PATH_INVALID', 'unavailable') from exc
        else:
            raise p.HostError('EC282_SOCKET_ALREADY_EXISTS', 'unavailable')

        self.policy_path = policy_path
        self.policy_sha = policy_sha
        self.policy = p.load_policy(policy_path, policy_sha)
        self.job = p.load_job(self.policy)
        self.signing_key = io.private_from_file(private_key_file)
        p.need(hmac.compare_digest(p.public_hex(self.signing_key),
                                   self.policy['server_public_hex']),
               'EC282_SERVER_SIGNER_NOT_PINNED', 'unavailable')
        # A signed EC282 permission must NOT coincide with a target/baseline
        # source authority private key, even accidentally in a local demo.
        used = {self.policy[k] for k in (
            'source_issuer_public_hex', 'reader_issuer_public_hex',
            'server_public_hex')}
        for group in ('trusted_target_public_hex_by_id',
                      'trusted_baseline_public_hex_by_id'):
            p.need(used.isdisjoint(self.job[group].values()),
                   'EC282_BACKEND_AND_HOST_SIGNER_ROLE_COLLISION', 'unavailable')
        self.clock = AnchoredClock()
        self._socket_inode = None
        try:
            super().__init__(path, ImpactHandler, bind_and_activate=True)
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
                if (stat.S_ISSOCK(st.st_mode) and
                    (st.st_dev, st.st_ino) == self._socket_inode):
                    os.unlink(self.server_address)
            except FileNotFoundError:
                pass
