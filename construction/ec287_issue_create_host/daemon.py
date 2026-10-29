#!/usr/bin/env python3
"""EC287 trusted private IssueCreate host; actual original EC218 HTTPS codepath.

Single-threaded AF_UNIX server uses kernel peer UID, offline signatures, a
host-only one-use grant ledger, the ORIGINAL EC217 reserved grant ledger and
ORIGINAL EC218 durable operation ledger. No remote POST is ever retried here.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hmac
import os
from pathlib import Path
import socket
import socketserver
import sqlite3
import stat
import struct
import time

from ec279_finding_query_host import protocol as io
from . import protocol as p
import issue_create_grant as cg
import issue_create_write as cw
import issue_provider as ip


class AnchoredClock:
    def __init__(self):
        self.wall = time.time()
        self.mono = time.monotonic()

    def now(self) -> int:
        # A backward host-clock change cannot resurrect an expired grant.
        return int(max(time.time(), self.wall + time.monotonic()-self.mono))


def peer_uid(conn: socket.socket) -> int:
    try:
        if hasattr(socket, 'SO_PEERCRED'):
            data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                   struct.calcsize('3i'))
            _pid, uid, _gid = struct.unpack('3i', data)
        elif hasattr(conn, 'getpeereid'):
            uid, _gid = conn.getpeereid()
        else:
            raise OSError('peer identity unavailable')
        p.need(type(uid) is int and 0 <= uid <= 2**31-1,
               'EC287_KERNEL_PEER_UID_INVALID', 'permission_denied')
        return uid
    except (OSError, ValueError, struct.error) as exc:
        raise p.HostError('EC287_KERNEL_PEER_IDENTITY_UNAVAILABLE',
                          'permission_denied') from exc


def decode_request(raw: bytes) -> dict:
    p.need(type(raw) is bytes and raw.endswith(b'\n') and
           raw.count(b'\n') == 1 and 0 < len(raw) <= p.MAX_RPC,
           'EC287_RPC_REQUEST_FRAMING_INVALID')
    req = io.parse(raw[:-1],p.MAX_RPC)
    p.need(set(req) == {'schema','nonce','grant'} and
           req.get('schema') == p.REQUEST_SCHEMA and
           type(req.get('nonce')) is str and
           io.HEX_NONCE.fullmatch(req['nonce']) is not None and
           type(req.get('grant')) is dict,
           'EC287_RPC_REQUEST_SCHEMA_INVALID')
    return req


def admission_claim(path: str, grant_id: str) -> bool:
    """Persistent first-writer-wins barrier BEFORE any original EC218 call.

    Must be ONE local database per host/authority; never roll back or delete.
    'False' is a durable replay, not evidence no prior remote effect occurred.
    """
    p.private_parent(path)
    p.need(cw._private_db(Path(path), may_create=True),
           'EC287_HOST_ADMISSION_LEDGER_UNSAFE', 'unavailable')
    try:
        with closing(sqlite3.connect(path, timeout=4, isolation_level=None)) as db:
            db.execute('PRAGMA busy_timeout=4000')
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS admission ('
                       'grant_id TEXT PRIMARY KEY, created_at INTEGER NOT NULL)')
            try:
                db.execute('INSERT INTO admission(grant_id,created_at) VALUES(?,?)',
                           (grant_id, int(time.time())))
                db.commit()
                return True
            except sqlite3.IntegrityError:
                db.rollback()
                return False
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise p.HostError('EC287_HOST_ADMISSION_COMMIT_UNCERTAIN_NO_RETRY',
                          'unavailable') from exc


def token_from_private_file(path: str) -> str:
    raw = p.private_file(path, p.MAX_TOKEN)
    if raw.endswith(b'\n'):
        raw = raw[:-1]
    try:
        token = raw.decode('ascii','strict')
    except (UnicodeError, ValueError) as exc:
        raise p.HostError('EC287_HOST_PROVIDER_TOKEN_INVALID','unavailable') from exc
    p.need(ip.TOKEN.fullmatch(token) is not None,
           'EC287_HOST_PROVIDER_TOKEN_UNAVAILABLE','unavailable')
    return token


def perform(server: 'IssueCreateHostServer', policy: dict, subject: dict) -> dict:
    """Calls unmodified EC218; no injected transport/clock in production."""
    job = p.load_job(policy)
    p.need(job == server.job,'EC287_PRIVATE_ISSUE_JOB_CHANGED','unavailable')
    p.need(p.job_pins(policy,job)['backend_sha256'] ==
           subject['backend_sha256'],
           'EC287_ORIGINAL_BACKEND_SOURCE_CHANGED','unavailable')
    trust_doc = p.load_trust(policy)
    access = p.load_access(policy)
    trust_reviewers, trust_issuers = p.build_trust(trust_doc)
    intent = job['intent']
    p.need((access.provider,access.api_host,access.account_ref,
            access.repository,access.expected_repository_id,
            access.visibility,access.policy_revision_sha256,access.audience) ==
           (intent.provider,intent.api_host,intent.account_ref,
            intent.repository,intent.expected_repository_id,
            intent.visibility,intent.policy_revision_sha256,intent.audience),
           'EC287_INDEPENDENT_HOST_ACCESS_TARGET_MISMATCH','unavailable')

    def live() -> bool:
        try:
            return (server.clock.now() < subject['expires_at_unix'] and
                    p.load_policy(server.policy_path,server.policy_sha) == policy and
                    p.load_job(policy) == job and
                    p.load_trust(policy) == trust_doc and
                    p.load_access(policy) == access and
                    p.code_sha256() == subject['backend_sha256'])
        except Exception:
            return False

    p.need(live(), 'EC287_EXACT_CREATE_AUTHORIZATION_REVOKED','unavailable')
    # EC217 original, not a hand-written imitation: full EC214-216 replay,
    # trusted reviewer, human exact-content signature + issuer expiry.
    try:
        challenge, grant_id, _ = cg._inspect(
            job['evidence'],intent,job['content'],job['approval'],
            trust_reviewers,trust_issuers,None)
        reader = cw.SQLiteGrantReservationReader(
            policy['reservation_db'],intent.audience)
        cw._reservation(reader,intent.audience,grant_id,
                        challenge['challenge_sha256'],
                        job['approval'].issued_at_utc,
                        job['approval'].expires_at_utc,
                        cw._clock_now(None))
    except (cg.GrantError,cw.WriteError,ValueError,TypeError) as exc:
        raise p.HostError('EC287_ORIGINAL_EC217_APPROVAL_OR_RESERVATION_DENIED',
                          'permission_denied') from exc

    p.need(live(),'EC287_APPROVAL_OR_PRIVATE_POLICY_CHANGED_BEFORE_ADMISSION',
           'unavailable')
    admitted = admission_claim(policy['host_grant_db'],subject['grant_id'])
    if not admitted:
        # A previously spent Host grant might already have caused a POST.
        # This call does NOT POST, but the prior outcome is still UNKNOWN to
        # the caller. Never report a replay denial as evidence of no effect.
        server.effect_started = True
        raise p.HostError('EC287_HOST_GRANT_ALREADY_SPENT_NO_SECOND_REQUEST',
                          'permission_denied')
    # After this barrier, a missing acknowledgement is deliberately UNKNOWN.
    server.effect_started = True

    def supply_token() -> str:
        p.need(live(),'EC287_HOST_AUTHORIZATION_CHANGED_BEFORE_CREDENTIAL_USE',
               'unavailable')
        return token_from_private_file(policy['token_file'])

    p.need(live(),'EC287_OWNER_POLICY_CHANGED_BEFORE_ORIGINAL_EC218',
           'unavailable')
    result = cw.create_new_issue_once(
        job['evidence'],intent,job['content'],job['approval'],
        trusted_eligibility_review_keys=trust_reviewers,
        trusted_issuers=trust_issuers,
        reserved_grants=reader,
        attempt_ledger=cw.SQLiteCreateAttemptLedger(
            policy['attempt_db'],intent.audience),
        host_access=access,
        token_supplier=supply_token,
        # IMPORTANT: no injected transport or clock. The original EC218
        # StrictHTTPSIssueCreateTransport is the sole production HTTP writer.
        transport=None,clock=None)
    try:
        p.validate_backend(result,subject['operation_sha256'])
    except p.HostError:
        return p.denial('EC287_UNRECOGNIZED_ORIGINAL_RESULT_INSPECT_LEDGER',
                        handler_invoked=True,remote_effect_outcome_unknown=True)
    if not live():
        return p.denial('EC287_AUTHORIZATION_CHANGED_AFTER_ORIGINAL_EC218_INSPECT',
                        handler_invoked=True,remote_effect_outcome_unknown=True)
    return result


class IssueCreateHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(15.0)
        try:
            req = decode_request(self.rfile.readline(p.MAX_RPC+2))
        except (OSError,TimeoutError,ValueError):
            return
        server: IssueCreateHostServer = self.server
        started = False
        server.effect_started = False
        try:
            pol = p.load_policy(server.policy_path,server.policy_sha)
            p.need(pol == server.policy,'EC287_PRIVATE_POLICY_BYTES_CHANGED',
                   'unavailable')
            job = p.load_job(pol)
            subject = p.validate_grant(req['grant'],pol,job,
                uid=peer_uid(self.request),now=server.clock.now(),
                policy_sha=server.policy_sha)
            started = True
            result = perform(server,pol,subject)
        except p.HostError as exc:
            result = p.denial(exc.code,exc.status,
                              handler_invoked=started,
                              remote_effect_outcome_unknown=server.effect_started)
        except Exception:
            result = p.denial('EC287_PRIVATE_HOST_EXCEPTION_RECONCILE_LEDGER',
                              'unavailable',handler_invoked=started,
                              remote_effect_outcome_unknown=server.effect_started)
        try:
            reply = p.signed_reply(req,result,server.policy_sha,
                                   server.policy['job_sha256'],
                                   server.signing_key,server.clock.now())
            raw = p.canonical(reply)+b'\n'
            if len(raw) > p.MAX_REPLY:
                raw = p.canonical(p.signed_reply(req,p.denial(
                    'EC287_SIGNED_REPLY_TOO_LARGE_RECONCILE_LEDGER',
                    handler_invoked=started,
                    remote_effect_outcome_unknown=server.effect_started),
                    server.policy_sha,server.policy['job_sha256'],
                    server.signing_key,server.clock.now()))+b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError,ValueError):
            return  # Lost/invalid reply => unknown, do NOT replay the grant.


class IssueCreateHostServer(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, *, path: str, policy_path: str, policy_sha: str,
                 private_key_file: str):
        p.need(hasattr(socket,'AF_UNIX') and
               (hasattr(socket,'SO_PEERCRED') or hasattr(socket.socket,'getpeereid')),
               'EC287_KERNEL_PEER_CREDS_REQUIRED','unavailable')
        p.need(p.plain_abs(path) and len(path.encode()) < 100,
               'EC287_UNIX_SOCKET_PATH_INVALID','unavailable')
        try:
            st = os.lstat(Path(path).parent)
            p.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
                   stat.S_IMODE(st.st_mode) & 0o002 == 0,
                   'EC287_SOCKET_PARENT_UNTRUSTED','unavailable')
            try:
                os.lstat(path)
            except FileNotFoundError:
                pass
            else:
                raise p.HostError('EC287_EXISTING_SOCKET_CANNOT_BE_OVERWRITTEN',
                                  'unavailable')
        except OSError as exc:
            raise p.HostError('EC287_SOCKET_DIRECTORY_UNAVAILABLE',
                              'unavailable') from exc
        self.policy_path,self.policy_sha=policy_path,policy_sha
        self.policy=p.load_policy(policy_path,policy_sha)
        self.job=p.load_job(self.policy)
        trust_doc = p.load_trust(self.policy)
        p.load_access(self.policy)
        # A second authorization must not be silently satisfied by reusing an
        # original EC214 review or EC217 approval issuer key. Distinct PUBLIC
        # keys cannot prove organizational independence, which remains an
        # operator duty, but obvious key reuse can be rejected here.
        upstream_keys = set(trust_doc['eligibility_review_keys_hex'].values())
        upstream_keys.update(v['public_key_hex'] for v in trust_doc['issuers'].values())
        host_keys = (self.policy['custodian_issuer_public_hex'],
                     self.policy['authorizer_issuer_public_hex'],
                     self.policy['server_public_hex'])
        p.need(all(key not in upstream_keys for key in host_keys),
               'EC287_ORIGINAL_AND_HOST_APPROVAL_KEYS_MUST_BE_DISTINCT',
               'unavailable')
        # Validate all privileged private paths before accepting connections.
        for path_ in (self.policy['token_file'],self.policy['reservation_db'],
                      self.policy['attempt_db'],self.policy['host_grant_db']):
            p.private_parent(path_)
        p.private_file(self.policy['token_file'],p.MAX_TOKEN)
        p.private_file(private_key_file,64)
        self.signing_key=io.private_from_file(private_key_file)
        p.need(hmac.compare_digest(p.public_hex(self.signing_key),
                                   self.policy['server_public_hex']),
               'EC287_HOST_SERVER_SIGNER_MISMATCH','unavailable')
        self.clock=AnchoredClock()
        self.effect_started=False
        self._socket_inode=None
        try:
            super().__init__(path,IssueCreateHandler,bind_and_activate=True)
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
