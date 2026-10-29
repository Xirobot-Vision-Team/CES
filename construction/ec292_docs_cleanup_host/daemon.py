#!/usr/bin/env python3
"""EC292 owner-private Unix host for exactly one original EC230 cleanup_docs call.

The durable EC292 per-*operation* admission precedes the untouched EC230
cleanup journal, which itself persists an attempt BEFORE git worktree remove.
No missing ACK, crash, expired ticket, or partial journal is retried.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import time

from ec279_finding_query_host import protocol as io
import publication_receipts as rec
from . import protocol as p


class AnchoredClock:
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
            raise OSError('kernel peer identity unavailable')
        p.need(type(uid) is int and 0 <= uid <= 2**31 - 1,
               'EC292_UNTRUSTED_KERNEL_UID', 'permission_denied')
        return uid
    except (OSError, struct.error) as exc:
        raise p.HostError('EC292_KERNEL_AF_UNIX_UID_REQUIRED',
                          'permission_denied') from exc


def decode_request(raw: bytes) -> dict:
    p.need(type(raw) is bytes and 1 < len(raw) <= p.MAX_RPC and
           raw.endswith(b'\n') and raw.count(b'\n') == 1,
           'EC292_ONE_LINE_RPC_REQUIRED', 'invalid_input')
    req = io.parse(raw[:-1], p.MAX_RPC)
    p.fields(req, {'schema', 'nonce', 'grant', 'cleanup_grant'},
             'EC292_RPC_EXACT_FIELDS_REQUIRED')
    p.need(req['schema'] == p.REQUEST_SCHEMA and
           type(req['nonce']) is str and
           p.HEX_NONCE.fullmatch(req['nonce']) is not None and
           type(req['grant']) is dict and type(req['cleanup_grant']) is dict,
           'EC292_RPC_FRAME_INVALID', 'invalid_input')
    return req


def admission_claim(root: str, subject: dict, cleanup: dict, grant: dict) -> None:
    """One admission per operation, not per EC292 host grant.

    Spent even on partial fsync failure or lost signature. This protects the
    worktree against a second grant after a collision/crash/ambiguous removal.
    """
    rec._safe_private_dir(root)
    op = subject['operation_sha256']
    p.need(type(op) is str and p.HEX.fullmatch(op) is not None,
           'EC292_ORIGINAL_OPERATION_ID_INVALID')
    parent = child = None
    try:
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        st = os.fstat(parent)
        p.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
               stat.S_IMODE(st.st_mode) & 0o077 == 0,
               'EC292_ADMISSION_ROOT_OWNER_CHANGED')
        name = 'ec292-clean-' + op
        os.mkdir(name, mode=0o700, dir_fd=parent)
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent)
        st = os.fstat(child)
        p.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
               stat.S_IMODE(st.st_mode) & 0o077 == 0,
               'EC292_ADMISSION_SLOT_INODE_CHANGED')
        evidence = {'schema': 'ces.ec292.cleanup_one_operation_admission.v1',
            'operation_id': op,
            'inspection_id': subject['inspection_id'],
            'observation_sha256': subject['observation_sha256'],
            'candidate_commit_sha': subject['candidate_commit_sha'],
            'worktree_inode': subject['worktree_inode'],
            'readback_sha256': subject['readback_sha256'],
            'cleanup_grant_sha256': p.sha(p.canonical(cleanup)),
            'host_grant_sha256': p.sha(p.canonical(grant)),
            'policy_sha256': subject['policy_sha256'],
            'job_sha256': subject['job_sha256']}
        payload = p.canonical(evidence) + b'\n'
        fd = os.open('00_ADMISSION.json',
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=child)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as out:
                out.write(payload)
                out.flush()
                os.fsync(out.fileno())
        finally:
            os.close(fd)
        os.fsync(child)
        os.fsync(parent)
    except FileExistsError as exc:
        raise p.HostError('EC292_OPERATION_ALREADY_ADMITTED_NO_RETRY',
                          'permission_denied') from exc
    except OSError as exc:
        raise p.HostError('EC292_ADMISSION_DURABILITY_UNKNOWN_NO_RETRY') from exc
    finally:
        for fd in (child, parent):
            if fd is not None:
                os.close(fd)


def perform(server: 'CleanupHost', policy: dict, subject: dict,
            grant: dict, cleanup: dict) -> dict:
    """Pass the pinned operation to unchanged EC230, no other effect path."""
    def live(*, after_cleanup: bool = False) -> bool:
        try:
            latest = p.load_policy(server.policy_path, server.policy_sha)
            p.need(latest == policy == server.policy,
                   'EC292_POLICY_CHANGED')
            p.need(server.clock.now() < subject['expires_at_unix'],
                   'EC292_SHORT_HOST_AUTHORIZATION_EXPIRED')
            p.need(subject['cleanup_grant_sha256'] == p.sha(p.canonical(cleanup)) and
                   all(subject[k] == latest[k] for k in p.PINS),
                   'EC292_CLEANUP_TICKET_OR_CODE_CHANGED')
            snapshot = p.exact_snapshot(latest, require_worktree=not after_cleanup)
            # Original EC230 successfully removes the worktree itself, so a
            # *post*-cleanup check must not require the removed inode. All
            # surviving Git refs, source pins and signed observations still
            # have to agree with the pre-removal operation and receipt.
            p.need(all(subject[k] == v for k, v in snapshot.items()
                       if not (after_cleanup and k == 'worktree_inode')),
                   'EC292_GIT_REF_OR_WORKTREE_IDENTITY_DRIFT')
            if not after_cleanup:
                previous = p.parent_policy(latest)
                p.cleanup_statement(cleanup, previous['cleanup_public_hex'],
                                    snapshot, previous['receipt_epoch'])
            return True
        except (p.HostError, rec.ReceiptDenied, ValueError, OSError,
                KeyError, TypeError):
            return False

    p.need(live(), 'EC292_FRESH_EC230_CLEANUP_AUTHORIZATION_REQUIRED',
           'permission_denied')
    svc, access, original = p.service(policy)
    _pub, op, target, grant_sha, _journal, _pins = svc._base(
        rec.MODE_DOCS, original, access)
    p.need(op == subject['operation_sha256'] and
           target == subject['target_sha256'] and
           grant_sha == subject['original_grant_sha256'],
           'EC292_ORIGINAL_EC229_PINS_CHANGED')
    p.need(live(), 'EC292_GIT_OR_AUTHORITY_DRIFT_BEFORE_DURABLE_CLAIM',
           'permission_denied')
    server.cleanup_may_have_been_attempted = True
    admission_claim(policy['admission_root'], subject, cleanup, grant)
    p.need(live(), 'EC292_POST_ADMISSION_DRIFT_MANUAL_RECONCILIATION_NO_RETRY')
    previous = p.parent_policy(policy)
    signed = p.cleanup_statement(cleanup, previous['cleanup_public_hex'],
                                 {k: subject[k] for k in (
                                     'operation_sha256', 'target_sha256',
                                     'original_grant_sha256', 'inspection_id',
                                     'observation_sha256', 'candidate_commit_sha',
                                     'worktree_inode')}, previous['receipt_epoch'])
    result = svc.cleanup_docs(original, access, subject['inspection_id'], signed)
    p.validate_backend(result, subject['operation_sha256'])
    if not live(after_cleanup=result.get('local_worktree_cleanup_confirmed') is True):
        # Cleanup can already have happened. Do not label it verified if the
        # security context changed after the original local deletion.
        raise p.HostError('EC292_POST_CLEANUP_AUTHORITY_UNKNOWN_INSPECT_JOURNALS')
    return result


class CleanupHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(45)
        try:
            req = decode_request(self.rfile.readline(p.MAX_RPC + 2))
        except (OSError, TimeoutError, ValueError, io.HostError):
            return
        server: CleanupHost = self.server
        server.cleanup_may_have_been_attempted = False
        try:
            policy = p.load_policy(server.policy_path, server.policy_sha)
            p.need(policy == server.policy, 'EC292_BOOT_POLICY_CHANGED')
            subject = p.validate_grant(req['grant'], policy,
                req['cleanup_grant'], kernel_uid(self.request),
                server.policy_sha, server.clock.now())
            result = perform(server, policy, subject,
                             req['grant'], req['cleanup_grant'])
        except p.HostError as exc:
            result = p.denial(exc.code, exc.status,
                              attempted=server.cleanup_may_have_been_attempted)
        except (rec.ReceiptDenied, OSError, ValueError):
            result = p.denial('EC292_ORIGINAL_EC230_CLEANUP_PREREQUISITE_FAILED',
                              attempted=server.cleanup_may_have_been_attempted)
        except Exception:
            result = p.denial('EC292_LOCAL_CLEANUP_OUTCOME_UNKNOWN_INSPECT_BOTH_AUDITS',
                              attempted=server.cleanup_may_have_been_attempted)
        try:
            reply = p.signed_reply(req, result, server.policy_sha,
                server.policy['job_sha256'], server.signer, server.clock.now())
            raw = p.canonical(reply) + b'\n'
            if len(raw) > p.MAX_REPLY:
                result = p.denial('EC292_SIGNED_REPLY_EXCEEDED_BOUND_INSPECT_AUDITS',
                                  attempted=server.cleanup_may_have_been_attempted)
                raw = p.canonical(p.signed_reply(req, result, server.policy_sha,
                    server.policy['job_sha256'], server.signer,
                    server.clock.now())) + b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError, ValueError):
            return


class CleanupHost(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 4

    def __init__(self, *, path: str, policy_path: str, policy_sha: str,
                 private_key_file: str):
        p.need(hasattr(socket, 'AF_UNIX') and
               (hasattr(socket, 'SO_PEERCRED') or hasattr(socket.socket, 'getpeereid')),
               'EC292_KERNEL_AF_UNIX_IDENTITY_REQUIRED')
        p.need(old_abs(path) and len(path.encode()) < 100,
               'EC292_SOCKET_ABSOLUTE_SHORT_PATH_REQUIRED')
        try:
            st = os.lstat(Path(path).parent)
            p.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
                   stat.S_IMODE(st.st_mode) & 0o027 == 0,
                   'EC292_SOCKET_PARENT_NOT_PRIVATE')
            try:
                os.lstat(path)
            except FileNotFoundError:
                pass
            else:
                raise p.HostError('EC292_PREEXISTING_SOCKET_PATH_REFUSED')
        except OSError as exc:
            raise p.HostError('EC292_SOCKET_PARENT_UNAVAILABLE') from exc
        self.policy_path, self.policy_sha = policy_path, policy_sha
        self.policy = p.load_policy(policy_path, policy_sha)
        _ = p.prior.operation_scope(p.parent_policy(self.policy))
        p.old.private_file(private_key_file, 64)
        self.signer = io.private_from_file(private_key_file)
        p.need(p.old.public_hex(self.signer) == self.policy['server_public_hex'],
               'EC292_HOST_SERVER_PRIVATE_KEY_NOT_PINNED')
        self.clock = AnchoredClock()
        self.cleanup_may_have_been_attempted = False
        self._socket_inode = None
        try:
            super().__init__(path, CleanupHandler, bind_and_activate=True)
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


def old_abs(path: str) -> bool:
    return p.old.plain_abs(path)
