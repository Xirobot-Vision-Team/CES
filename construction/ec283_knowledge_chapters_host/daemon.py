#!/usr/bin/env python3
"""EC283 independently deployable AF_UNIX source/private-chapter reader.

The original EC210 KnowledgeLifecycle.query is the only data-plane engine.
The per-socket job fixes its store IDs, roots, chapter, selected immutable
version, section ordinals, terms and existing EC202/206/207/208 permissions.
Rejected/changed queries receive a newly host-signed denial without private
store content, not a speculative query result or route elevation.
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
import knowledge_boundary as kb
import knowledge_candidate_store as kc
import knowledge_version_save as vs
import knowledge_lifecycle as lc
from . import protocol as p


def decode_request(raw: bytes) -> dict:
    p.need(raw.endswith(b'\n') and 1 < len(raw) <= p.MAX_RPC + 1,
           'EC283_SOCKET_FRAME_INVALID')
    req = io.parse(raw[:-1], p.MAX_RPC)
    p.need(type(req) is dict and set(req) == {'schema', 'nonce', 'grant'} and
           req.get('schema') == p.REQUEST_SCHEMA and
           type(req.get('nonce')) is str and
           io.HEX_NONCE.fullmatch(req['nonce']) is not None and
           type(req.get('grant')) is dict,
           'EC283_RPC_REQUEST_FIELDS_INVALID')
    return req


def _backend(job: dict) -> lc.KnowledgeLifecycle:
    """Use only host-owned existing EC206/208 store configurations.

    Never call initialize/save, never create a scratch copy with weaker trust,
    and keep all original store manifest and source identity checks active.
    """
    candidate = kc.KnowledgeCandidateStore(
        root=job['candidate_root'], store_id=job['candidate_store_id'],
        repository_root=job['repository_root'], knowledge_root=job['knowledge_root'],
        repository_ref=job['repository_ref'],
        knowledge_space_key=job['knowledge_space_key'],
        period_id=job['period_id'],
        source_policy_revision=job['source_policy_revision'])
    registry = {key: {'role': row['role'],
                      'public_key': bytes.fromhex(row['public_hex'])}
                for key, row in job['trusted_approvers'].items()}
    version = vs.KnowledgeVersionSave(
        root=job['version_root'], store_id=job['version_store_id'],
        candidate_store=candidate, chapter_path=job['chapter_path'],
        trusted_approvers=registry,
        revoked_approvers=set(job['revoked_approvers']))
    return lc.KnowledgeLifecycle(version_store=version)


def perform_query(server: 'ChaptersServer', pol: dict, subject: dict) -> dict:
    job = p.load_job(pol)
    p.need(job == server.job, 'EC283_PRIVATE_JOB_REPLACED', 'unavailable')

    def live() -> bool:
        try:
            return (server.clock.now() < subject['expires_at_unix'] and
                    p.load_policy(server.policy_path, server.policy_sha) == pol and
                    p.load_job(pol) == job)
        except (p.HostError, io.HostError, OSError, ValueError):
            return False

    p.need(live(), 'EC283_AUTHORIZATION_REVOKED_BEFORE_READ', 'unavailable')
    api = _backend(job)
    request = job['query_request']
    result = api.query(
        query_request_json=kb.canonical(request),
        query_policy_json=kb.canonical(job['query_policy']),
        bootstrap_request_json=(kb.canonical(job['bootstrap_request'])
                                if job['bootstrap_request'] is not None else None),
        bootstrap_read_policy_json=(kb.canonical(job['bootstrap_read_policy'])
                                    if job['bootstrap_read_policy'] is not None else None),
        version_evidence_json=(kb.canonical(job['version_evidence'])
                               if job['version_evidence'] is not None else None))
    # Even when EC210 returns partial, recheck signed exact selections and
    # decode/rehash any disclosed section. An expired grant or a changed raw
    # policy/job is an unavailable denial and MUST NOT return cached text.
    p.need(live(), 'EC283_AUTHORIZATION_REVOKED_DURING_READ', 'unavailable')
    p.need(p.safe_backend_result(
        result, projection=request['projection'], view=request['view'],
        section_indices=request['section_indices']),
        'EC283_ORIGINAL_EC210_QUERY_NOT_VERIFIED', 'unavailable')
    return result


class ChaptersHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(10.0)
        try:
            req = decode_request(self.rfile.readline(p.MAX_RPC + 2))
        except (OSError, TimeoutError, ValueError):
            return  # Invalid anonymous frames never receive a signed receipt.
        server: ChaptersServer = self.server
        invoked = False
        try:
            current = p.load_policy(server.policy_path, server.policy_sha)
            p.need(current == server.policy,
                   'EC283_POLICY_REPLACED', 'unavailable')
            uid = peer_uid(self.request)
            s = p.validate_grant(req['grant'], current, server.job, uid=uid,
                                 now=server.clock.now(),
                                 policy_sha=server.policy_sha)
            invoked = True
            result = perform_query(server, current, s)
        except p.HostError as exc:
            result = p.denial(exc.code, exc.status, backend_invoked=invoked)
        except Exception:
            result = p.denial('EC283_PRIVATE_QUERY_HOST_UNAVAILABLE',
                              'unavailable', backend_invoked=None)
        try:
            reply = p.signed_reply(req, result, server.policy_sha,
                                   server.policy['job_sha256'],
                                   server.signing_key, server.clock.now())
            raw = p.canonical(reply) + b'\n'
            if len(raw) > p.MAX_REPLY:
                reply = p.signed_reply(
                    req, p.denial('EC283_SIGNED_QUERY_EXCEEDS_SIZE_BUDGET',
                                  'unavailable', backend_invoked=invoked),
                    server.policy_sha, server.policy['job_sha256'],
                    server.signing_key, server.clock.now())
                raw = p.canonical(reply) + b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError, ValueError, BrokenPipeError):
            return


class ChaptersServer(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, *, path: str, policy_path: str, policy_sha: str,
                 private_key_file: str):
        p.need(hasattr(socket, 'AF_UNIX') and
               (hasattr(socket, 'SO_PEERCRED') or
                hasattr(socket.socket, 'getpeereid')),
               'EC283_KERNEL_PEER_IDENTITY_UNAVAILABLE', 'unavailable')
        p.need(type(path) is str and os.path.isabs(path) and len(path) < 100,
               'EC283_SOCKET_ABSOLUTE_PATH_REQUIRED')
        try:
            parent = os.lstat(Path(path).parent)
        except OSError as exc:
            raise p.HostError('EC283_SOCKET_PARENT_UNAVAILABLE',
                              'unavailable') from exc
        p.need(stat.S_ISDIR(parent.st_mode) and not (parent.st_mode & 0o002),
               'EC283_SOCKET_DIRECTORY_UNTRUSTED', 'unavailable')
        try:
            os.lstat(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise p.HostError('EC283_SOCKET_PATH_UNAVAILABLE', 'unavailable') from exc
        else:
            raise p.HostError('EC283_SOCKET_ALREADY_EXISTS', 'unavailable')
        self.policy_path = policy_path
        self.policy_sha = policy_sha
        self.policy = p.load_policy(policy_path, policy_sha)
        self.job = p.load_job(self.policy)
        self.signing_key = io.private_from_file(private_key_file)
        p.need(hmac.compare_digest(p.public_hex(self.signing_key),
                                   self.policy['server_public_hex']),
               'EC283_HOST_SIGNER_MISMATCH', 'unavailable')
        # An old EC208 approval for a metadata version cannot double as an
        # EC283 read authority or server signing key, even in a local demo.
        host_keys = {self.policy[f'{role}_issuer_public_hex'] for role in
                     ('custodian', 'reader')}
        host_keys.add(self.policy['server_public_hex'])
        p.need(host_keys.isdisjoint(
            row['public_hex'] for row in self.job['trusted_approvers'].values()),
            'EC283_VERSION_APPROVER_AND_HOST_SIGNER_COLLISION', 'unavailable')
        self.clock = AnchoredClock()
        self._socket_inode = None
        try:
            super().__init__(path, ChaptersHandler, bind_and_activate=True)
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
                if stat.S_ISSOCK(st.st_mode) and \
                        (st.st_dev, st.st_ino) == self._socket_inode:
                    os.unlink(self.server_address)
            except FileNotFoundError:
                pass
