#!/usr/bin/env python3
"""EC291 independent AF_UNIX local Git receipt readback host, NOT a Git writer.

For one fully preconfigured original EC229 exact job, require original EC230
one-use READ signature and two independent EC291 Host votes. Consume an
independent durable admission *before* the unmodified EC230 inspect_docs,
which consumes its own read audit slot before any Git observation. No ref
mutation, provider network request, worktree cleanup or original publication.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import time

from finding_query_host import protocol as io
import publication_receipts as rec
from . import protocol as p


class AnchoredClock:
    """Reject backward wall-clock steps during a live server session."""
    def __init__(self):
        self.wall, self.mono = time.time(), time.monotonic()

    def now(self) -> int:
        return int(max(time.time(), self.wall + time.monotonic() - self.mono))


def kernel_uid(sock: socket.socket) -> int:
    try:
        if hasattr(socket, 'SO_PEERCRED'):
            raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                  struct.calcsize('3i'))
            _pid, uid, _gid = struct.unpack('3i', raw)
        elif hasattr(sock, 'getpeereid'):
            uid, _gid = sock.getpeereid()
        else:
            raise OSError('kernel UID unavailable')
        p.need(type(uid) is int and 0 <= uid <= 2**31 - 1,
               'EC291_KERNEL_UID_UNRELIABLE', 'permission_denied')
        return uid
    except (OSError, struct.error) as exc:
        raise p.HostError('EC291_KERNEL_PEER_UID_REQUIRED',
                          'permission_denied') from exc


def decode_request(raw: bytes) -> dict:
    p.need(type(raw) is bytes and 1 < len(raw) <= p.MAX_RPC and
           raw.endswith(b'\n') and raw.count(b'\n') == 1,
           'EC291_RPC_ONE_LINE_FRAMING_REQUIRED', 'invalid_input')
    request = io.parse(raw[:-1], p.MAX_RPC)
    p.fields(request, {'schema', 'nonce', 'grant', 'read_grant'},
             'EC291_RPC_EXACT_FIELDS_REQUIRED')
    p.need(request['schema'] == p.REQUEST_SCHEMA and
           type(request['nonce']) is str and
           io.HEX_NONCE.fullmatch(request['nonce']) is not None and
           type(request['grant']) is dict and type(request['read_grant']) is dict,
           'EC291_RPC_FRAME_CONTENT_INVALID', 'invalid_input')
    return request


def admission_claim(root: str, grant_id: str, subject: dict, read: dict) -> None:
    """Append-once host journal, fsync child and parent before any Git read.

    A partial/failed admission is deliberately considered SPENT; an operator
    must reconcile the directory and EC230 audit before new authorization.
    """
    rec._safe_private_dir(root)
    p.need(type(grant_id) is str and io.HEX_NONCE.fullmatch(grant_id) is not None,
           'EC291_HOST_GRANT_ID_INVALID')
    parent = child = None
    try:
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        st = os.fstat(parent)
        p.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
               stat.S_IMODE(st.st_mode) & 0o077 == 0,
               'EC291_ADMISSION_ROOT_OWNER_OR_MODE_CHANGED')
        name = 'ec291-' + grant_id
        os.mkdir(name, mode=0o700, dir_fd=parent)
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent)
        st = os.fstat(child)
        p.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
               stat.S_IMODE(st.st_mode) & 0o077 == 0,
               'EC291_NEW_ADMISSION_DIRECTORY_RACED')
        evidence = {'schema': 'ces.ec291.host_admission_record.v1',
                    'grant_id': grant_id,
                    'operation_id': subject['operation_sha256'],
                    'read_grant_sha256': p.sha(p.canonical(read)),
                    'policy_sha256': subject['policy_sha256'],
                    'job_sha256': subject['job_sha256']}
        payload = p.canonical(evidence) + b'\n'
        fd = os.open('00_ADMISSION.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600, dir_fd=child)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
        finally:
            os.close(fd)
        os.fsync(child)
        os.fsync(parent)
    except FileExistsError as exc:
        raise p.HostError('EC291_HOST_GRANT_ALREADY_SPENT_NO_AUTOMATIC_RETRY',
                          'permission_denied') from exc
    except OSError as exc:
        raise p.HostError('EC291_HOST_ADMISSION_DURABILITY_UNKNOWN_NO_RETRY') from exc
    finally:
        for fd in (child, parent):
            if fd is not None:
                os.close(fd)


def perform(server: 'DocsReceiptHost', pol: dict, subject: dict,
            read: dict) -> dict:
    """Use *unchanged* original EC230 inspect_docs, never clean or publish."""
    def live() -> bool:
        try:
            latest = p.load_policy(server.policy_path, server.policy_sha)
            p.need(latest == server.policy and latest == pol,
                   'EC291_OWNER_POLICY_CHANGED')
            p.need(server.clock.now() < subject['expires_at_unix'],
                   'EC291_INDEPENDENT_HOST_VOTES_EXPIRED')
            p.need(p.sha(p.canonical(read)) == subject['read_grant_sha256'] and
                   all(subject[k] == latest[k] for k in p.PINS),
                   'EC291_READ_OR_ORIGINAL_CODE_PINS_CHANGED')
            p.need(p.operation_scope(latest) == {
                k: subject[k] for k in ('operation_sha256', 'target_sha256',
                                        'original_grant_sha256')},
                'EC291_ORIGINAL_EC229_OPERATION_CHANGED')
            return True
        except (p.HostError, rec.ReceiptDenied, ValueError, OSError, TypeError):
            return False

    p.need(live(), 'EC291_AUTHORITY_CHANGED_BEFORE_ADMISSION', 'permission_denied')
    svc, access, original = p.service(pol)
    _pub, op, _target, _grant_sha, journal, _pins = svc._base(
        rec.MODE_DOCS, original, access)
    p.need(op == subject['operation_sha256'],
           'EC291_ORIGINAL_OPERATION_UNEXPECTED')
    # Require the actual original EC229 durable push-attempt marker, not the
    # stdout of EC285. A missing marker cannot justify reading/ref presence.
    markers, _, _ = rec._view_markers(
        journal, 'ec229-' + op, '00_CLAIM_DURABLE', rec._ALLOWED_DOCS,
        frozenset(('05_COMMIT_CREATED', '07_SANDBOX_REF_OBSERVED')))
    p.need('06_PUSH_ATTEMPTED' in markers,
           'EC291_ORIGINAL_DURABLE_GIT_PUSH_ATTEMPT_REQUIRED', 'permission_denied')
    p.need(live(), 'EC291_AUTHORITY_CHANGED_AT_DURABLE_CLAIM',
           'permission_denied')
    server.git_read_maybe_attempted = True
    admission_claim(pol['admission_root'], subject['grant_id'], subject, read)
    p.need(live(), 'EC291_AUTHORITY_DRIFT_AFTER_HOST_ADMISSION_NO_RETRY')
    # Only EC230 itself may validate old approval documents and allocate its
    # independent ec230-read-* audit. inspect_docs performs *local* Git reads.
    result = svc.inspect_docs(original, access,
                              p.read_statement(read, pol['read_public_hex']))
    p.validate_backend(result, subject['operation_sha256'])
    if not live():
        raise p.HostError('EC291_AUTHORITY_CHANGED_AFTER_GIT_OBSERVATION_INSPECT_AUDITS')
    return result


class DocsReceiptHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(45)
        try:
            request = decode_request(self.rfile.readline(p.MAX_RPC + 2))
        except (OSError, TimeoutError, ValueError, io.HostError):
            return
        server: DocsReceiptHost = self.server
        server.git_read_maybe_attempted = False
        try:
            pol = p.load_policy(server.policy_path, server.policy_sha)
            p.need(pol == server.policy, 'EC291_BOOT_POLICY_CHANGED')
            subject = p.validate_grant(request['grant'], pol,
                request['read_grant'], kernel_uid(self.request),
                server.policy_sha, server.clock.now())
            result = perform(server, pol, subject, request['read_grant'])
        except p.HostError as exc:
            result = p.denial(exc.code, exc.status,
                              attempted=server.git_read_maybe_attempted)
        except (rec.ReceiptDenied, ValueError, OSError):
            result = p.denial('EC291_ORIGINAL_GIT_EVIDENCE_PREREQUISITE_FAILED',
                              attempted=server.git_read_maybe_attempted)
        except Exception:
            result = p.denial('EC291_GIT_READ_OUTCOME_UNKNOWN_INSPECT_BOTH_AUDITS',
                              attempted=server.git_read_maybe_attempted)
        try:
            reply = p.signed_reply(request, result, server.policy_sha,
                server.policy['job_sha256'], server.signer, server.clock.now())
            raw = p.canonical(reply) + b'\n'
            if len(raw) > p.MAX_REPLY:
                result = p.denial('EC291_SIGNED_REPLY_SIZE_EXCEEDED_INSPECT_AUDITS',
                                  attempted=server.git_read_maybe_attempted)
                raw = p.canonical(p.signed_reply(request, result, server.policy_sha,
                     server.policy['job_sha256'], server.signer,
                     server.clock.now())) + b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError, ValueError):
            return  # Untrusted/lost response never proves a ref's absence.


class DocsReceiptHost(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 4

    def __init__(self, *, path: str, policy_path: str, policy_sha: str,
                 private_key_file: str):
        p.need(hasattr(socket, 'AF_UNIX') and
               (hasattr(socket, 'SO_PEERCRED') or hasattr(socket.socket, 'getpeereid')),
               'EC291_KERNEL_PEER_IDENTITY_REQUIRED')
        p.need(p.old.plain_abs(path) and len(path.encode()) < 100,
               'EC291_SOCKET_ABSOLUTE_PATH_REQUIRED')
        try:
            st = os.lstat(Path(path).parent)
            p.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
                   stat.S_IMODE(st.st_mode) & 0o027 == 0,
                   'EC291_SOCKET_PARENT_NOT_PRIVATE')
            try:
                os.lstat(path)
            except FileNotFoundError:
                pass
            else:
                raise p.HostError('EC291_PREEXISTING_SOCKET_INODE_REFUSED')
        except OSError as exc:
            raise p.HostError('EC291_SOCKET_PARENT_UNAVAILABLE') from exc
        self.policy_path, self.policy_sha = policy_path, policy_sha
        self.policy = p.load_policy(policy_path, policy_sha)
        _ = p.operation_scope(self.policy)
        p.old.private_file(private_key_file, 64)
        self.signer = io.private_from_file(private_key_file)
        p.need(p.old.public_hex(self.signer) == self.policy['server_public_hex'],
               'EC291_HOST_SERVER_SIGNER_NOT_PINNED')
        self.clock = AnchoredClock()
        self.git_read_maybe_attempted = False
        self._socket_inode = None
        try:
            super().__init__(path, DocsReceiptHandler, bind_and_activate=True)
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
                if stat.S_ISSOCK(st.st_mode) and (
                        st.st_dev, st.st_ino) == self._socket_inode:
                    os.unlink(self.server_address)
            except FileNotFoundError:
                pass
