#!/usr/bin/env python3
"""EC289 real Unix-host integration with UNMODIFIED original EC228 publish_once.

At-most-once means two independent, durable local barriers (EC289 grant and
EC228 report+destination). No response or lack of response permits a retry.
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
from . import protocol as p
import report_publish as rp


class AnchoredClock:
    def __init__(self):
        self.wall, self.mono = time.time(), time.monotonic()

    def now(self) -> int:
        return int(max(time.time(), self.wall + time.monotonic() - self.mono))


def peer_uid(conn: socket.socket) -> int:
    try:
        if hasattr(socket, 'SO_PEERCRED'):
            data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                   struct.calcsize('3i'))
            _pid, uid, _gid = struct.unpack('3i', data)
        elif hasattr(conn, 'getpeereid'):
            uid, _gid = conn.getpeereid()
        else:
            raise OSError('no kernel peer credentials')
        p.need(type(uid) is int and 0 <= uid <= 2**31-1,
               'EC289_KERNEL_UID_INVALID', 'permission_denied')
        return uid
    except (OSError, struct.error) as exc:
        raise p.HostError('EC289_KERNEL_PEER_UID_UNAVAILABLE',
                          'permission_denied') from exc


def request_decode(raw: bytes) -> dict:
    p.need(type(raw) is bytes and 0 < len(raw) <= p.MAX_RPC
           and raw.endswith(b'\n') and raw.count(b'\n') == 1,
           'EC289_RPC_FRAMING_REJECTED', 'invalid_input')
    req = io.parse(raw[:-1], p.MAX_RPC)
    p.keys(req, {'schema', 'nonce', 'grant'}, 'EC289_RPC_FIELDS_INVALID')
    p.need(req['schema'] == p.REQUEST_SCHEMA and
           type(req['nonce']) is str and io.HEX_NONCE.fullmatch(req['nonce']) is not None
           and type(req['grant']) is dict,
           'EC289_RPC_REQUEST_INVALID', 'invalid_input')
    return req


def admission_claim(root: str, grant_id: str) -> bool:
    """Spend host authorization durably *before* invoking the original writer.

    Individual directories remain forever. Original EC228 protects against
    different host grants for the same report+provider destination.
    """
    p.private_directory(root)
    p.need(type(grant_id) is str and io.HEX_NONCE.fullmatch(grant_id) is not None,
           'EC289_ADMISSION_GRANT_ID_INVALID')
    fd = child = None
    try:
        st = os.lstat(root)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        actual = os.fstat(fd)
        p.need((actual.st_dev, actual.st_ino) == (st.st_dev, st.st_ino)
               and actual.st_uid == os.geteuid()
               and stat.S_IMODE(actual.st_mode) & 0o077 == 0,
               'EC289_ADMISSION_ROOT_CHANGED')
        entry = 'ec289-' + grant_id
        try:
            os.mkdir(entry, mode=0o700, dir_fd=fd)
        except FileExistsError:
            return False
        child = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=fd)
        os.fsync(child)
        os.fsync(fd)
        return True
    except OSError as exc:
        raise p.HostError('EC289_ADMISSION_DURABILITY_UNKNOWN_NO_RETRY') from exc
    finally:
        for handle in (child, fd):
            if handle is not None:
                os.close(handle)


def perform(server: 'ReportPublishHost', pol: dict, sub: dict) -> dict:
    """One original publish_once call, after host/source permissions are checked."""
    def live() -> bool:
        try:
            return (server.clock.now() < sub['expires_at_unix'] and
                    p.load_policy(server.policy_path, server.policy_sha) == pol and
                    p.digest(p.private_file(pol['job_file'], p.MAX_JOB)) == pol['job_sha256'] and
                    p.digest(p.private_file(pol['trust_file'], p.MAX_TRUST)) == pol['trust_sha256'] and
                    p.digest(p.private_file(pol['credential_file'], p.MAX_TOKEN)) == pol['credential_sha256'] and
                    p.backend_sha() == sub['original_backend_sha256'] and
                    p.host_code_sha() == sub['host_backend_sha256'])
        except Exception:
            return False

    p.need(live(), 'EC289_OWNER_PUBLISH_POLICY_CHANGED_BEFORE_ADMISSION')
    job = p.load_job(pol)
    p.need(all(sub[k] == v for k, v in p.job_pins(pol, job).items()),
           'EC289_EXACT_REPORT_OR_ORIGINAL_GRANT_DRIFT')
    trust = p.load_trust(pol)
    credential = p.load_credential(pol)
    p.private_directory(pol['outbox_root'])
    p.private_directory(pol['admission_root'])
    publisher = p.build_publisher(trust, credential, pol['outbox_root'])
    # Important: original EC228 signature and saved EC199/200 source checks
    # happen even before HOST grant reservation, then again inside publish_once.
    try:
        checked = publisher._verify(job, int(rp._clock()))
        publisher._read_exact(job, checked)
    except rp.PublishDenied as exc:
        # An original refusal is not evidence that a publish POST was made.
        # No host admission has yet been spent; original EC228 checks again.
        return rp._refused(exc.code, exc.status)
    p.need(live(), 'EC289_OWNER_PERMISSION_CHANGED_BEFORE_ADMISSION')
    # From this point even the admission fsync outcome may be ambiguous.
    server.effect_started = True
    consumed = admission_claim(pol['admission_root'], sub['grant_id'])
    if not consumed:
        raise p.HostError('EC289_HOST_GRANT_ALREADY_SPENT_NO_RETRY',
                          'permission_denied')
    server.effect_started = True
    p.need(live(), 'EC289_AUTHORITY_DRIFT_AFTER_DURABLE_ADMISSION_NO_RETRY')
    # This is ORIGINAL EC228, with its native strict HTTPSPrivatePublishTransport
    # and distinct operation-key durable outbox; no caller-selected port/clock.
    result = publisher.publish_once(job)
    try:
        p.validate_backend(result)
    except p.HostError:
        return p.denial('EC289_UNEXPECTED_ORIGINAL_EC228_RESULT_INSPECT_LEDGERS',
                        handler_invoked=True, publication_outcome_unknown=True)
    if not live():
        return p.denial('EC289_AUTHORITY_DRIFT_AFTER_ORIGINAL_EC228_RETURN',
                        handler_invoked=True, publication_outcome_unknown=True)
    return result


class PublishHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(65)
        try:
            req = request_decode(self.rfile.readline(p.MAX_RPC + 2))
        except (OSError, TimeoutError, ValueError):
            return
        server: ReportPublishHost = self.server
        server.effect_started = False
        started = False
        try:
            pol = p.load_policy(server.policy_path, server.policy_sha)
            p.need(pol == server.policy, 'EC289_STARTUP_POLICY_DRIFT')
            job = p.load_job(pol)
            sub = p.validate_grant(req['grant'], pol, job,
                                   uid=peer_uid(self.request),
                                   now=server.clock.now(),
                                   policy_sha=server.policy_sha)
            started = True
            result = perform(server, pol, sub)
        except p.HostError as exc:
            result = p.denial(exc.code, exc.status, handler_invoked=started,
                              publication_outcome_unknown=server.effect_started)
        except Exception:
            result = p.denial('EC289_HOST_FAILURE_INSPECT_DURABLE_LEDGERS',
                              handler_invoked=started,
                              publication_outcome_unknown=server.effect_started)
        try:
            reply = p.signed_reply(req, result, server.policy_sha,
                                   server.policy['job_sha256'],
                                   server.signer, server.clock.now())
            raw = p.canonical(reply) + b'\n'
            if len(raw) > p.MAX_REPLY:
                raw = p.canonical(p.signed_reply(req, p.denial(
                    'EC289_SIGNED_REPLY_TOO_LARGE_INSPECT_LEDGERS',
                    handler_invoked=started,
                    publication_outcome_unknown=server.effect_started),
                    server.policy_sha, server.policy['job_sha256'],
                    server.signer, server.clock.now())) + b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError, ValueError):
            # No signed receipt: result UNKNOWN. The original ledgers prevail.
            return


class ReportPublishHost(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 4

    def __init__(self, *, path: str, policy_path: str,
                 policy_sha: str, private_key_file: str):
        p.need(hasattr(socket, 'AF_UNIX') and (
               hasattr(socket, 'SO_PEERCRED') or hasattr(socket.socket, 'getpeereid')),
               'EC289_KERNEL_PEER_CREDENTIALS_REQUIRED')
        p.need(p.absolute(path) and len(path.encode('utf-8')) < 100,
               'EC289_SOCKET_PATH_INVALID')
        try:
            st = os.lstat(Path(path).parent)
            p.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
                   and stat.S_IMODE(st.st_mode) & 0o027 == 0,
                   'EC289_SOCKET_PARENT_MUST_BE_OWNER_GROUP_TRAVERSABLE_ONLY')
            try:
                os.lstat(path)
            except FileNotFoundError:
                pass
            else:
                raise p.HostError('EC289_EXISTING_SOCKET_INODE_REJECTED')
        except OSError as exc:
            raise p.HostError('EC289_SOCKET_PARENT_UNAVAILABLE') from exc
        self.policy_path, self.policy_sha = policy_path, policy_sha
        self.policy = p.load_policy(policy_path, policy_sha)
        p.load_job(self.policy)
        trust = p.load_trust(self.policy)
        roots = p.trust_keys(trust)
        hostkeys = [self.policy[k] for k in (
            'custodian_issuer_public_hex', 'publisher_issuer_public_hex',
            'server_public_hex')]
        p.need(len(set(roots + hostkeys)) == 9,
               'EC289_NINE_DISTINCT_ORIGINAL_AND_HOST_KEYS_REQUIRED')
        p.private_directory(self.policy['admission_root'])
        p.private_directory(self.policy['outbox_root'])
        credential = p.load_credential(self.policy)
        p.build_publisher(trust, credential, self.policy['outbox_root'])
        p.private_file(private_key_file, 64)
        self.signer = io.private_from_file(private_key_file)
        p.need(p.public_hex(self.signer) == self.policy['server_public_hex'],
               'EC289_HOST_PRIVATE_SIGNER_MISMATCH')
        self.clock = AnchoredClock()
        self.effect_started = False
        self._socket_inode = None
        try:
            super().__init__(path, PublishHandler, bind_and_activate=True)
            # Owner/operator group may connect only if deployer deliberately
            # provisions a trusted group and 0750 parent. Kernel peer UID
            # still independently gates actual authorization on every RPC.
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
