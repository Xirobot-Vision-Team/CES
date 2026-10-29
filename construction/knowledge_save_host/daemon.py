#!/usr/bin/env python3
"""EC284 independent AF_UNIX write host for ORIGINAL EC208.save.

Only an exact administrator-owned immutable job is passed to EC208; no caller
supplied path/content/authorization or generic Router privilege is accepted.
The parent EC208 never overwrites the original chapter or a version record.
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path
import socket
import socketserver
import stat

from finding_query_host.daemon import AnchoredClock, peer_uid
from finding_query_host import protocol as io
import knowledge_boundary as kb
import knowledge_candidate_store as kc
import knowledge_version_save as vs
from . import protocol as p


def decode_request(raw: bytes) -> dict:
    p.need(raw.endswith(b'\n') and 1 < len(raw) <= p.MAX_RPC + 1,
           'EC284_RPC_FRAME_INVALID')
    req = io.parse(raw[:-1], p.MAX_RPC)
    p.need(type(req) is dict and set(req) == {'schema','nonce','grant'} and
           req.get('schema') == p.REQUEST_SCHEMA and
           type(req.get('nonce')) is str and
           io.HEX_NONCE.fullmatch(req['nonce']) is not None and
           type(req.get('grant')) is dict,
           'EC284_RPC_REQUEST_FIELDS_INVALID')
    return req


def backend(job: dict) -> vs.KnowledgeVersionSave:
    """Instantiate original EC206/208 on the real, already initialized stores."""
    candidate = kc.KnowledgeCandidateStore(
        root=job['candidate_root'], store_id=job['candidate_store_id'],
        repository_root=job['repository_root'], knowledge_root=job['knowledge_root'],
        repository_ref=job['repository_ref'],
        knowledge_space_key=job['knowledge_space_key'],
        period_id=job['period_id'],
        source_policy_revision=job['source_policy_revision'])
    enrolled = {key: {'role': row['role'],
                      'public_key': bytes.fromhex(row['public_hex'])}
                for key, row in job['trusted_approvers'].items()}
    return vs.KnowledgeVersionSave(root=job['version_root'],
        store_id=job['version_store_id'], candidate_store=candidate,
        chapter_path=job['chapter_path'], trusted_approvers=enrolled,
        revoked_approvers=set(job['revoked_approvers']))


def perform_save(server: 'SaveServer', policy: dict, subject: dict) -> dict:
    """Preview scope then perform the real, signature-gated EC208 append.

    On post-save policy change the append outcome is UNKNOWN and the signed
    reply must not falsely claim that the store was untouched. The operator
    must inspect the real store before preparing a new grant or retrying.
    """
    job = p.load_job(policy)
    p.need(job == server.job, 'EC284_PRIVATE_SAVE_JOB_REPLACED', 'unavailable')

    def live() -> bool:
        try:
            return (server.clock.now() < subject['expires_at_unix'] and
                    p.load_policy(server.policy_path, server.policy_sha) == policy and
                    p.load_job(policy) == job)
        except (OSError, ValueError, io.HostError, p.HostError):
            return False

    p.need(live(), 'EC284_APPROVAL_REVOKED_BEFORE_PREVIEW', 'unavailable')
    api = backend(job)
    original_args = dict(request_json=kb.canonical(job['save_request']),
        handoff_request_json=kb.canonical(job['handoff_request']),
        handoff_policy_json=kb.canonical(job['handoff_policy']),
        candidate_read_policies_json=kb.canonical(job['candidate_read_policies']))
    preview = api.preview(**original_args)
    p.need(preview.get('schema') == vs.SCHEMA and
           preview.get('status') == 'partial' and
           preview.get('exit_code') == 2 and
           preview.get('reason_code') ==
             'KNOWLEDGE_SAVE_EXACT_VERSION_BINDING_PREVIEW_NO_WRITE' and
           type(preview.get('subject')) is dict and
           preview['subject'].get('write_authorized') is False and
           preview['subject'].get('body_disclosed') is False and
           preview['subject'].get('authorization_scope_sha256') ==
             subject['authorization_scope_sha256'] and
           preview['subject'].get('save_key') == subject['save_key'] and
           preview['subject'].get('expected_new_chapter_sha256') ==
             subject['new_chapter_sha256'] and
           preview['subject'].get('state') in ('NEW_VERSION', 'ALREADY_PERSISTED') and
           preview.get('local_version_metadata_written') is False,
           'EC284_ORIGINAL_EC208_PREVIEW_SCOPE_NOT_READY', 'unavailable')
    p.need(live(), 'EC284_APPROVAL_REVOKED_BEFORE_APPEND', 'unavailable')
    # This is the only EC284 call that may write. Original EC208 checks EC206/
    # EC207 evidence, fresh reviewer+owner approvals, exact metadata permission,
    # version head, filesystem root ownership, lock and exclusive append.
    server.save_started = True
    result = api.save(**original_args,
        save_policy_json=kb.canonical(job['save_policy']),
        approvals_json=kb.canonical(job['approvals']))
    if not live():
        return p.denial('EC284_POLICY_OR_JOB_CHANGED_AFTER_SAVE_INSPECT_REQUIRED',
                        'unavailable', backend_invoked=True,
                        write_outcome_unknown=True)
    if p.safe_backend_result(result, job):
        return result
    if type(result) is dict and result.get('schema') == vs.SCHEMA and \
       (result.get('status'), result.get('exit_code')) in (
            ('invalid_input', 4), ('unavailable', 5)):
        unknown = result.get('local_write_outcome_unknown') is True
        return p.denial('EC284_ORIGINAL_EC208_' + str(result.get('reason_code'))[:128],
                        result['status'], backend_invoked=True,
                        write_outcome_unknown=unknown)
    return p.denial('EC284_ORIGINAL_EC208_RESULT_UNRECOGNIZED_INSPECT_REQUIRED',
                    'unavailable', backend_invoked=True,
                    write_outcome_unknown=True)


class SaveHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(10.0)
        try:
            request = decode_request(self.rfile.readline(p.MAX_RPC + 2))
        except (OSError, TimeoutError, ValueError):
            return  # No untrusted client receives a signed pre-admission body.
        server: SaveServer = self.server
        started = False
        try:
            pol = p.load_policy(server.policy_path, server.policy_sha)
            p.need(pol == server.policy, 'EC284_PRIVATE_POLICY_REPLACED', 'unavailable')
            uid = peer_uid(self.request)
            subject = p.validate_grant(request['grant'], pol, server.job,
                            uid=uid, now=server.clock.now(),
                            policy_sha=server.policy_sha)
            started = True
            server.save_started = False
            result = perform_save(server, pol, subject)
        except p.HostError as exc:
            result = p.denial(exc.code, exc.status, backend_invoked=started,
                              write_outcome_unknown=bool(started and server.save_started))
        except Exception:
            # The original write may have committed before an unexpected
            # error. Never claim 'not written' after entering save().
            result = p.denial('EC284_PRIVATE_SAVE_HOST_UNAVAILABLE_INSPECT_REQUIRED',
                              'unavailable', backend_invoked=started,
                              write_outcome_unknown=bool(started and server.save_started))
        try:
            reply = p.signed_reply(request, result, server.policy_sha,
                                   server.policy['job_sha256'],
                                   server.signing_key, server.clock.now())
            raw = p.canonical(reply) + b'\n'
            if len(raw) > p.MAX_REPLY:
                reply = p.signed_reply(request,
                    p.denial('EC284_RESULT_SIZE_UNKNOWN_INSPECT_REQUIRED',
                             'unavailable', backend_invoked=started,
                             write_outcome_unknown=bool(started and server.save_started)),
                    server.policy_sha, server.policy['job_sha256'],
                    server.signing_key, server.clock.now())
                raw = p.canonical(reply) + b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError, ValueError):
            return  # The client must treat missing response as unknown.


class SaveServer(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, *, path: str, policy_path: str, policy_sha: str,
                 private_key_file: str):
        p.need(hasattr(socket, 'AF_UNIX') and
               (hasattr(socket, 'SO_PEERCRED') or
                hasattr(socket.socket, 'getpeereid')),
               'EC284_KERNEL_PEER_IDENTITY_UNAVAILABLE', 'unavailable')
        p.need(type(path) is str and os.path.isabs(path) and len(path) < 100,
               'EC284_SOCKET_ABSOLUTE_PATH_REQUIRED')
        try:
            parent = os.lstat(Path(path).parent)
        except OSError as exc:
            raise p.HostError('EC284_SOCKET_PARENT_UNAVAILABLE',
                              'unavailable') from exc
        p.need(stat.S_ISDIR(parent.st_mode) and not (parent.st_mode & 0o002),
               'EC284_SOCKET_DIRECTORY_UNTRUSTED', 'unavailable')
        try:
            os.lstat(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise p.HostError('EC284_SOCKET_PATH_UNAVAILABLE', 'unavailable') from exc
        else:
            raise p.HostError('EC284_SOCKET_ALREADY_EXISTS', 'unavailable')
        self.policy_path = policy_path
        self.policy_sha = policy_sha
        self.policy = p.load_policy(policy_path, policy_sha)
        self.job = p.load_job(self.policy)
        self.signing_key = io.private_from_file(private_key_file)
        p.need(hmac.compare_digest(p.public_hex(self.signing_key),
                                  self.policy['server_public_hex']),
               'EC284_HOST_SIGNER_MISMATCH', 'unavailable')
        keys = {self.policy['custodian_issuer_public_hex'],
                self.policy['authorizer_issuer_public_hex'],
                self.policy['server_public_hex']}
        enrolled = [row['public_hex'] for row in self.job['trusted_approvers'].values()]
        p.need(len(set(enrolled)) == len(enrolled) and keys.isdisjoint(enrolled),
               'EC284_HOST_AND_EC208_APPROVER_SIGNER_COLLISION', 'unavailable')
        self.clock = AnchoredClock()
        self.save_started = False
        self._socket_inode = None
        try:
            super().__init__(path, SaveHandler, bind_and_activate=True)
            os.chmod(path, 0o660)
            st = os.lstat(path)
            self._socket_inode = (st.st_dev, st.st_ino)
        except Exception:
            self.server_close()
            raise

    def server_close(self) -> None:
        super().server_close()
        if self._socket_inode is not None:
            try:
                st = os.lstat(self.server_address)
                if (stat.S_ISSOCK(st.st_mode) and
                    (st.st_dev, st.st_ino) == self._socket_inode):
                    os.unlink(self.server_address)
            except FileNotFoundError:
                pass
