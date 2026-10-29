#!/usr/bin/env python3
"""EC290 single-request private AF_UNIX host: UNMODIFIED EC230 inspect_report.

Actual live production path never injects a synthetic reader/clock and never
calls EC228 publish_once. Host admission and original EC230 audit are durable
one-use barriers; uncertain/unsigned responses are NOT grounds for re-GET.
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


def kernel_uid(conn: socket.socket) -> int:
    try:
        if hasattr(socket, 'SO_PEERCRED'):
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                  struct.calcsize('3i'))
            _pid, uid, _gid = struct.unpack('3i', raw)
        elif hasattr(conn, 'getpeereid'):
            uid, _gid = conn.getpeereid()
        else:
            raise OSError('kernel peer UID unavailable')
        p.need(type(uid) is int and 0 <= uid <= 2**31 - 1,
               'EC290_KERNEL_PEER_UID_INVALID', 'permission_denied')
        return uid
    except (OSError, struct.error) as exc:
        raise p.HostError('EC290_KERNEL_PEER_CREDENTIALS_REQUIRED',
                          'permission_denied') from exc


def decode_request(raw: bytes) -> dict:
    p.need(type(raw) is bytes and 0 < len(raw) <= p.MAX_RPC and
           raw.endswith(b'\n') and raw.count(b'\n') == 1,
           'EC290_RPC_FRAMING_INVALID', 'invalid_input')
    obj = io.parse(raw[:-1], p.MAX_RPC)
    p.fields(obj, {'schema', 'nonce', 'grant', 'read_grant'},
             'EC290_RPC_EXACT_FIELDS_REQUIRED')
    p.need(obj['schema'] == p.REQUEST_SCHEMA and
           type(obj['nonce']) is str and io.HEX_NONCE.fullmatch(obj['nonce']) is not None and
           type(obj['grant']) is dict and type(obj['read_grant']) is dict,
           'EC290_RPC_REQUEST_INVALID', 'invalid_input')
    return obj


def admission_claim(root: str, grant_id: str) -> None:
    """Exclusive owner-private, parent+child fsynced claim BEFORE any GET."""
    p.old.private_directory(root)
    p.need(type(grant_id) is str and io.HEX_NONCE.fullmatch(grant_id) is not None,
           'EC290_DURABLE_GRANT_ID_INVALID')
    name = 'ec290-' + grant_id
    parent = child = None
    try:
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        st = os.fstat(parent)
        p.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
               stat.S_IMODE(st.st_mode) & 0o077 == 0,
               'EC290_ADMISSION_DIR_OWNER_DRIFT')
        os.mkdir(name, mode=0o700, dir_fd=parent)
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=parent)
        os.fsync(child)
        os.fsync(parent)
    except FileExistsError as exc:
        raise p.HostError('EC290_HOST_ADMISSION_ALREADY_SPENT_NO_RETRY',
                          'permission_denied') from exc
    except OSError as exc:
        raise p.HostError('EC290_HOST_ADMISSION_DURABILITY_UNKNOWN_NO_RETRY') from exc
    finally:
        for fd in (child, parent):
            if fd is not None:
                os.close(fd)


def perform(server: 'ReceiptHost', pol: dict, subject: dict, signed_read: dict) -> dict:
    """No mutation of original report/publish data; exact signed GET only."""
    def pinned_now() -> bool:
        try:
            fresh = p.load_policy(server.policy_path, server.policy_sha)
            p.need(fresh == server.policy, 'EC290_POLICY_CHANGED')
            p.need(subject['read_grant_sha256'] == p.sha(p.canonical(signed_read)),
                   'EC290_SIGNED_READ_GRANT_CHANGED')
            p.need(all(subject[k] == fresh[k] for k in p.PINS),
                   'EC290_AUTHORITY_PINS_CHANGED')
            p.need(server.clock.now() < subject['expires_at_unix'],
                   'EC290_HOST_VOTE_EXPIRED', 'permission_denied')
            svc, access = p.service(fresh)
            ops = p.operation_scope(fresh)
            p.need(all(subject[k] == ops[k] for k in ops),
                   'EC290_ORIGINAL_OPERATION_CHANGED')
            return True
        except (p.HostError, rec.ReceiptDenied, ValueError, OSError):
            return False

    p.need(pinned_now(), 'EC290_OWNER_AUTHORITY_CHANGED_BEFORE_ADMISSION',
           'permission_denied')
    svc, access = p.service(pol)
    original = p.original_request(pol)
    operation = subject['operation_sha256']
    # A real durable original EC228 POST marker is a prerequisite. Do not
    # consume a new host grant just because EC289 returned an HTTP 2xx text.
    markers, _payloads, _journal = rec._view_markers(
        access.outbox_root, 'ec228-' + operation, '00_RESERVED_DURABLE',
        rec._ALLOWED_REPORT)
    p.need('03_POST_ATTEMPTED' in markers,
           'EC290_NO_ORIGINAL_DURABLE_POST_ATTEMPT', 'permission_denied')
    p.need(pinned_now(), 'EC290_PERMISSION_DRIFT_BEFORE_DURABLE_CLAIM',
           'permission_denied')
    server.read_outcome_may_be_unknown = True
    admission_claim(pol['admission_root'], subject['grant_id'])
    p.need(pinned_now(), 'EC290_PERMISSION_DRIFT_AFTER_DURABLE_CLAIM_NO_RETRY')
    # Original backend independently checks the historical five EC228 votes,
    # exact saved Markdown, fresh EC230 signature, journal and private target;
    # it fsyncs its own EC230 audit before sending exactly one HTTPS GET.
    result = svc.inspect_report(original, access,
                                p.read_statement(signed_read, pol['read_public_hex']))
    p.validate_backend(result)
    if not pinned_now():
        raise p.HostError('EC290_AUTHORITY_CHANGED_AFTER_READBACK_INSPECT_AUDITS')
    return result


class ReceiptHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(45)
        try:
            req = decode_request(self.rfile.readline(p.MAX_RPC + 2))
        except (OSError, TimeoutError, ValueError, io.HostError):
            return
        server: ReceiptHost = self.server
        server.read_outcome_may_be_unknown = False
        try:
            pol = p.load_policy(server.policy_path, server.policy_sha)
            p.need(pol == server.policy, 'EC290_BOOT_POLICY_DRIFT')
            subject = p.validate_grant(req['grant'], pol, req['read_grant'],
                kernel_uid(self.request), server.policy_sha, server.clock.now())
            result = perform(server, pol, subject, req['read_grant'])
        except p.HostError as exc:
            result = p.denial(exc.code, exc.status,
                              attempted=server.read_outcome_may_be_unknown)
        except (rec.ReceiptDenied, ValueError, OSError):
            result = p.denial('EC290_ORIGINAL_RECEIPT_PREREQUISITE_REJECTED',
                              attempted=server.read_outcome_may_be_unknown)
        except Exception:
            result = p.denial('EC290_READBACK_UNKNOWN_INSPECT_LOCAL_AUDITS',
                              attempted=server.read_outcome_may_be_unknown)
        try:
            reply = p.signed_reply(req, result, server.policy_sha,
                                   server.policy['job_sha256'],
                                   server.signer, server.clock.now())
            raw = p.canonical(reply) + b'\n'
            if len(raw) > p.MAX_REPLY:
                result = p.denial('EC290_REPLY_BUDGET_EXCEEDED_INSPECT_AUDITS',
                    attempted=server.read_outcome_may_be_unknown)
                raw = p.canonical(p.signed_reply(req, result, server.policy_sha,
                     server.policy['job_sha256'], server.signer, server.clock.now())) + b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError, ValueError):
            # Lost server reply does not authorize an automatic second GET.
            return


class ReceiptHost(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 4

    def __init__(self, *, path: str, policy_path: str,
                 policy_sha: str, private_key_file: str):
        p.need(hasattr(socket, 'AF_UNIX') and
               (hasattr(socket, 'SO_PEERCRED') or hasattr(socket.socket, 'getpeereid')),
               'EC290_KERNEL_UID_REQUIRED')
        p.need(p.old.absolute(path) and len(path.encode()) < 100,
               'EC290_SOCKET_PATH_INVALID')
        try:
            st = os.lstat(Path(path).parent)
            p.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
                   stat.S_IMODE(st.st_mode) & 0o027 == 0,
                   'EC290_SOCKET_PARENT_NOT_PRIVATE')
            try:
                os.lstat(path)
            except FileNotFoundError:
                pass
            else:
                raise p.HostError('EC290_EXISTING_SOCKET_INODE_REFUSED')
        except OSError as exc:
            raise p.HostError('EC290_SOCKET_PARENT_UNAVAILABLE') from exc
        self.policy_path, self.policy_sha = policy_path, policy_sha
        self.policy = p.load_policy(policy_path, policy_sha)
        p.original_request(self.policy)
        svc, access = p.service(self.policy)
        # A read-only host needs no original publication write permission.
        p.need(svc.host.enable_clean_linked_worktree is False and
               svc.host.enable_readback is True,
               'EC290_READBACK_ONLY_SCOPE_INVALID')
        p.old.private_file(private_key_file, 64)
        self.signer = io.private_from_file(private_key_file)
        p.need(p.old.public_hex(self.signer) == self.policy['server_public_hex'],
               'EC290_SIGNING_PRIVATE_KEY_MISMATCH')
        self.clock = AnchoredClock()
        self.read_outcome_may_be_unknown = False
        self._socket_inode = None
        try:
            super().__init__(path, ReceiptHandler, bind_and_activate=True)
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
