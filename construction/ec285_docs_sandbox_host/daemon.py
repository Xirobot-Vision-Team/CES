#!/usr/bin/env python3
"""EC285 standalone AF_UNIX host invoking the UNMODIFIED EC229 DocsOnlyPublisher.

Only preowned, raw-hash-pinned, private exact jobs may create a local sandbox
ref. All original EC229 policy/reviewer/revocation/side-effect signatures
remain necessary. Never invoke any public or production provider.
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path
import socket
import socketserver
import stat
from typing import Any

from ec279_finding_query_host.daemon import AnchoredClock, peer_uid
from ec279_finding_query_host import protocol as io
import delivery_authorization as da
import docs_only_publish as docs
from . import protocol as p


def decode_request(raw: bytes) -> dict:
    p.need(raw.endswith(b'\n') and 1 < len(raw) <= p.MAX_RPC + 1,
           'EC285_RPC_FRAME_INVALID')
    req=io.parse(raw[:-1],p.MAX_RPC)
    p.need(type(req) is dict and set(req) == {'schema','nonce','grant'} and
           req.get('schema') == p.REQUEST_SCHEMA and
           type(req.get('nonce')) is str and
           io.HEX_NONCE.fullmatch(req['nonce']) is not None and
           type(req.get('grant')) is dict,
           'EC285_RPC_FIELDS_INVALID')
    return req


def original_backend(job: dict) -> tuple[docs.DocsOnlyPublisher, docs.DocsOnlyPublishRequest]:
    """Use original EC229 structures and original real Git publication method."""
    a, r = job['access'], job['request']
    root = docs.DocsTrustRoots(
        issuer_id=a['issuer_id'],operator_id=a['operator_id'],
        project_id=a['project_id'],repository_id=a['repository_id'],
        policy_public_key=bytes.fromhex(a['policy_public_hex']),
        reviewer_public_key=bytes.fromhex(a['reviewer_public_hex']),
        revocation_public_key=bytes.fromhex(a['revocation_public_hex']),
        side_effect_public_key=bytes.fromhex(a['side_effect_public_hex']),
        minimum_policy_epoch=a['minimum_policy_epoch'])
    scope=docs.HostDocsScope(
        roots=root,repository_root=a['repository_root'],
        approved_base_commit=a['approved_base_commit'],
        allowed_exact_paths=tuple(a['allowed_exact_paths']),
        worktree_root=a['worktree_root'],journal_root=a['journal_root'],
        sandbox_bare_root=a['sandbox_bare_root'],
        git_executable=a['git_executable'],
        enable_private_local_sandbox_publish=True)
    request=docs.DocsOnlyPublishRequest(
        documents=tuple(docs.ReviewedDocument(**d) for d in r['documents']),
        repository_policy=da.SignedAuthorizationStatement(**r['repository_policy']),
        content_review=da.SignedAuthorizationStatement(**r['content_review']),
        current_revocation=da.SignedAuthorizationStatement(**r['current_revocation']),
        one_use_grant=da.SignedAuthorizationStatement(**r['one_use_grant']),
        explicitly_approve_exact_docs_only_local_publish=True)
    return docs.DocsOnlyPublisher(scope), request


def perform(server: 'DocsHostServer', policy: dict, subject: dict) -> dict:
    job=p.load_job(policy)
    p.need(job == server.job,'EC285_PRIVATE_DOCS_JOB_CHANGED','unavailable')

    def live() -> bool:
        try:
            return (server.clock.now() < subject['expires_at_unix'] and
                    p.load_policy(server.policy_path,server.policy_sha) == policy and
                    p.load_job(policy) == job and
                    docs._code_sha() == subject['docs_backend_sha256'])
        except (ValueError, OSError, RuntimeError):
            return False

    p.need(live(),'EC285_OFFLINE_APPROVAL_OR_POLICY_REVOKED','unavailable')
    publisher, request=original_backend(job)

    # No side effects before original EC229 independently checks four native
    # signatures, bytes/manifest, Git content bindings and revocation freshness.
    _, checked=publisher._verify(request,server.clock.now())
    p.need(checked['manifest_sha256']==subject['manifest_sha256'] and
           checked['grant']['target_binding_sha256']==subject['target_binding_sha256'] and
           publisher._allowlist == job['request']['one_use_grant']['statement']['allowlist_sha256'],
           'EC285_ORIGINAL_REVIEW_AND_APPROVAL_SCOPE_MISMATCH','unavailable')
    p.need(live(),'EC285_HOST_POLICY_CHANGED_BEFORE_GIT','unavailable')

    # All original EC229 logic remains intact. Interpose a host-owned liveness
    # gate at original signature rechecks and at each mutating Git subprocess,
    # notably immediately before 'push' to the sole exact private bare root.
    original_verify=publisher._verify
    def checked_verify(req: docs.DocsOnlyPublishRequest, now: int):
        p.need(live(),'EC285_HOST_POLICY_OR_APPROVAL_REVOKED_AT_REVIEW','unavailable')
        response=original_verify(req,now)
        p.need(live(),'EC285_HOST_POLICY_CHANGED_AFTER_REVIEW','unavailable')
        return response
    publisher._verify=checked_verify
    original_git_run=publisher.git.run
    def checked_git(cwd: str,*args: str,**kwargs: Any):
        if args and args[0] in ('worktree','add','commit','push','update-ref'):
            p.need(live(),'EC285_HOST_POLICY_REVOKED_AT_GIT_EFFECT_EDGE','unavailable')
        return original_git_run(cwd,*args,**kwargs)
    publisher.git.run=checked_git

    server.effect_started=True
    result=publisher.publish_once(request)
    if not live():
        return p.denial('EC285_DOCS_HOST_POLICY_CHANGED_AFTER_EXECUTE_INSPECT_SANDBOX',
                        backend_invoked=True,local_effect_outcome_unknown=True)
    if p.safe_success(result,subject):
        return result
    if type(result) is dict and result.get('schema') == docs.SCHEMA:
        # Backend may have durably claimed before a failure or ambiguous push.
        # No response can prove "not written" after the one-shot claim.
        attempted = (result.get('claim_committed') is True or
                     result.get('private_push_attempted') is True or
                     result.get('local_candidate_state') == 'UNKNOWN_AFTER_EFFECT')
        safe_code = result.get('reason_code')
        if type(safe_code) is not str or len(safe_code)>150 or \
           not safe_code.startswith('DOCS_ONLY_') or \
           not safe_code.replace('_','').isalnum():
            safe_code='DOCS_ONLY_BACKEND_REFUSAL_UNCLASSIFIED'
        status = 'invalid_input' if result.get('status') in ('invalid_input','blocked') else 'unavailable'
        return p.denial('EC285_ORIGINAL_'+safe_code,status,
                        backend_invoked=True,local_effect_outcome_unknown=attempted)
    return p.denial('EC285_ORIGINAL_EC229_UNRECOGNIZED_OUTCOME_INSPECT',
                    backend_invoked=True,local_effect_outcome_unknown=True)


class DocsHostHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(15.0)
        try:
            req=decode_request(self.rfile.readline(p.MAX_RPC+2))
        except (OSError, TimeoutError, ValueError):
            return
        server: DocsHostServer=self.server
        started=False
        server.effect_started=False
        try:
            pol=p.load_policy(server.policy_path,server.policy_sha)
            p.need(pol==server.policy,'EC285_PRIVATE_POLICY_CHANGED','unavailable')
            subject=p.validate_grant(req['grant'],pol,server.job,
                                     uid=peer_uid(self.request),
                                     now=server.clock.now(),policy_sha=server.policy_sha)
            started=True
            result=perform(server,pol,subject)
        except p.HostError as exc:
            result=p.denial(exc.code,exc.status,backend_invoked=started,
                            local_effect_outcome_unknown=server.effect_started)
        except Exception:
            result=p.denial('EC285_PRIVATE_GIT_HOST_EXCEPTION_INSPECT_SANDBOX',
                            'unavailable',backend_invoked=started,
                            local_effect_outcome_unknown=server.effect_started)
        try:
            reply=p.signed_reply(req,result,server.policy_sha,
                                 server.policy['job_sha256'],
                                 server.signing_key,server.clock.now())
            raw=p.canonical(reply)+b'\n'
            if len(raw)>p.MAX_REPLY:
                raw=p.canonical(p.signed_reply(req,p.denial(
                    'EC285_TOO_LARGE_RECEIPT_INSPECT_SANDBOX','unavailable',
                    backend_invoked=started,
                    local_effect_outcome_unknown=server.effect_started),
                    server.policy_sha,server.policy['job_sha256'],
                    server.signing_key,server.clock.now()))+b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (ValueError,OSError):
            return  # An absent/untrusted reply is always UNKNOWN to the client.


class DocsHostServer(socketserver.UnixStreamServer):
    allow_reuse_address=False
    request_queue_size=8

    def __init__(self,*,path: str,policy_path: str,policy_sha: str,
                 private_key_file: str):
        p.need(hasattr(socket,'AF_UNIX') and
               (hasattr(socket,'SO_PEERCRED') or hasattr(socket.socket,'getpeereid')),
               'EC285_KERNEL_PEER_IDENTITY_UNAVAILABLE','unavailable')
        p.need(type(path) is str and os.path.isabs(path) and
               len(path.encode()) < 100,
               'EC285_SOCKET_ABSOLUTE_PATH_REQUIRED')
        try:
            st=os.lstat(Path(path).parent)
            p.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
                   stat.S_IMODE(st.st_mode) & 0o002 == 0,
                   'EC285_SOCKET_PARENT_UNTRUSTED','unavailable')
            try:
                os.lstat(path)
            except FileNotFoundError:
                pass
            else:
                raise p.HostError('EC285_SOCKET_ALREADY_EXISTS','unavailable')
        except OSError as exc:
            raise p.HostError('EC285_SOCKET_PATH_UNAVAILABLE','unavailable') from exc
        self.policy_path=policy_path
        self.policy_sha=policy_sha
        self.policy=p.load_policy(policy_path,policy_sha)
        self.job=p.load_job(self.policy)
        p.private_file(private_key_file,64)
        self.signing_key=io.private_from_file(private_key_file)
        p.need(hmac.compare_digest(p.public_hex(self.signing_key),
                                   self.policy['server_public_hex']),
               'EC285_SERVER_SIGNER_MISMATCH','unavailable')
        host_keys={self.policy['custodian_issuer_public_hex'],
                   self.policy['authorizer_issuer_public_hex'],
                   self.policy['server_public_hex']}
        original_keys={self.job['access'][k] for k in (
            'policy_public_hex','reviewer_public_hex',
            'revocation_public_hex','side_effect_public_hex')}
        p.need(len(original_keys)==4 and host_keys.isdisjoint(original_keys),
               'EC285_SEVEN_INDEPENDENT_EC229_AND_HOST_KEYS_REQUIRED','unavailable')
        self.clock=AnchoredClock()
        self.effect_started=False
        self._socket_inode=None
        try:
            super().__init__(path,DocsHostHandler,bind_and_activate=True)
            os.chmod(path,0o660)
            st=os.lstat(path)
            self._socket_inode=(st.st_dev,st.st_ino)
        except Exception:
            self.server_close()
            raise

    def server_close(self) -> None:
        super().server_close()
        if self._socket_inode is not None:
            try:
                st=os.lstat(self.server_address)
                if stat.S_ISSOCK(st.st_mode) and \
                   (st.st_dev,st.st_ino)==self._socket_inode:
                    os.unlink(self.server_address)
            except FileNotFoundError:
                pass
