#!/usr/bin/env python3
"""EC293 independent EC226 Unix status Host, original business reader unchanged."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import time

from ec279_finding_query_host import protocol as io
import delivery_status as st
from . import protocol as p


class AnchoredClock:
    def __init__(self):
        self.wall, self.monotonic = time.time(), time.monotonic()

    def now(self) -> int:
        return int(max(time.time(), self.wall + time.monotonic()-self.monotonic))


def peer_uid(conn: socket.socket) -> int:
    try:
        if hasattr(socket, 'SO_PEERCRED'):
            _pid, uid, _gid=struct.unpack('3i',conn.getsockopt(
                socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
        elif hasattr(conn, 'getpeereid'):
            uid,_gid=conn.getpeereid()
        else:
            raise OSError('peer credentials unavailable')
        p.need(type(uid) is int and 0<=uid<=2**31-1,
               'EC293_KERNEL_PEER_UID_INVALID','permission_denied')
        return uid
    except (OSError,struct.error) as exc:
        raise p.HostError('EC293_KERNEL_PEER_UID_UNAVAILABLE','permission_denied') from exc


def decode_request(raw: bytes) -> dict:
    p.need(type(raw) is bytes and 0<len(raw)<=p.MAX_RPC and
           raw.endswith(b'\n') and raw.count(b'\n')==1,
           'EC293_RPC_FRAMING_INVALID','invalid_input')
    request=io.parse(raw[:-1],p.MAX_RPC)
    p.keys(request,{'schema','nonce','grant','read_grant'},'EC293_RPC_FIELDS_INVALID')
    p.need(request['schema']==p.REQUEST_SCHEMA and
           type(request['nonce']) is str and
           p.HEX32.fullmatch(request['nonce']) is not None and
           type(request['grant']) is dict and type(request['read_grant']) is dict,
           'EC293_RPC_REQUEST_INVALID','invalid_input')
    return request


def admit_once(root: str, grant_id: str) -> bool:
    """Per-grant irreversible fsync barrier BEFORE delegating to original EC226.

    The original EC226 ledger independently spends the signed read nonce. A
    spent Host grant never retries, including partial writes/unknown ACKs.
    """
    p.previous.private_directory(root)
    p.need(type(grant_id) is str and p.HEX32.fullmatch(grant_id) is not None,
           'EC293_ADMISSION_GRANT_ID_INVALID')
    parent = slot = None
    try:
        parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        stat_parent=os.fstat(parent)
        p.need(stat_parent.st_uid==os.geteuid() and
               stat.S_IMODE(stat_parent.st_mode)&0o077==0,
               'EC293_ADMISSION_ROOT_CHANGED')
        try:
            os.mkdir('ec293-'+grant_id,0o700,dir_fd=parent)
        except FileExistsError:
            return False
        slot=os.open('ec293-'+grant_id,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                     dir_fd=parent)
        os.fsync(slot)
        os.fsync(parent)
        return True
    except OSError as exc:
        raise p.HostError('EC293_ADMISSION_UNCERTAIN_NO_AUTOMATIC_RETRY') from exc
    finally:
        if slot is not None: os.close(slot)
        if parent is not None: os.close(parent)


def perform(server: 'StatusHost',pol:dict,reader:st.DeliveryStatusReader,
            original_request,read:dict,sub:dict)->dict:
    def live()->bool:
        try:
            if server.clock.now()>=sub['expires_at_unix']:
                return False
            if p.load_policy(server.policy_path,server.policy_sha)!=pol:
                return False
            # Reread source/trust/job/read credential from owner-private SHA
            # pins. NEVER open the EC288 write/submit token file.
            newest,job,prior=p.build_reader(pol)
            pins=p.operation_pins(pol,newest,job)
            return all(sub.get(k)==v for k,v in pins.items())
        except Exception:
            return False

    p.need(live(),'EC293_HOST_CONTEXT_CHANGED_BEFORE_READ')
    # Preflight ORIGINAL read grant and ORIGINAL durable EC225 submit marker.
    # Neither signer approval alone nor EC288's Host admission equals an
    # actual original EC225 POST attempt.
    p.validate_read(read,reader,original_request,server.clock.now())
    with st.LocalStatusReadLedger(reader.sender.access.outbox_root) as ledger:
        ledger.verify_submit_marker(sub['operation_id'])
    p.need(live(),'EC293_CONTEXT_DRIFT_BEFORE_ADMISSION')
    # A failed fsync after mkdir is still a possibly consumed admission.
    server.effect_started=True
    claimed=admit_once(pol['admission_root'],sub['grant_id'])
    p.need(claimed,'EC293_HOST_GRANT_ALREADY_SPENT_NO_RETRY','permission_denied')
    p.need(live(),'EC293_CONTEXT_DRIFT_AFTER_DURABLE_ADMISSION_NO_RETRY')
    # This is the REAL UNMODIFIED ORIGINAL EC226 business method. It makes
    # at most one status-only HTTP /status request and never POSTs /submit.
    request=st.DeliveryStatusRequest(original_request,p.read_envelope(read),True,True)
    result=reader.observe_once(request)
    try:
        p.validate_backend(result)
        p.need(result['operation_id']==sub['operation_id'] or
               (result['status']!='partial' and result['operation_id'] is None),
               'EC293_UNEXPECTED_ORIGINAL_OPERATION')
    except p.HostError:
        return p.denial('EC293_ORIGINAL_EC226_UNVERIFIED_RESULT_INSPECT_BOTH_LEDGERS',
                        invoked=True,read_outcome_unknown=True)
    if not live():
        return p.denial('EC293_AUTHORITY_DRIFT_AFTER_STATUS_REQUEST_UNKNOWN',
                        invoked=True,read_outcome_unknown=True)
    return result


class StatusHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(45)
        try:
            raw=self.rfile.readline(p.MAX_RPC+2)
            req=decode_request(raw)
        except (OSError,TimeoutError,ValueError):
            return
        server:StatusHost=self.server
        started=False
        server.effect_started=False
        try:
            policy=p.load_policy(server.policy_path,server.policy_sha)
            p.need(policy==server.policy,'EC293_HOST_POLICY_DRIFT')
            reader,job,_prior=p.build_reader(policy)
            uid=peer_uid(self.request)
            now=server.clock.now()
            sub=p.validate_grant(req['grant'],req['read_grant'],policy,reader,job,
                                 uid,now,server.policy_sha)
            # Original EC226 independently verifies a DIFFERENT fresh role
            # signature; Host votes cannot substitute for that signer.
            p.validate_read(req['read_grant'],reader,job,now)
            started=True
            result=perform(server,policy,reader,job,req['read_grant'],sub)
        except p.HostError as exc:
            result=p.denial(exc.code,exc.status,invoked=started,
                            read_outcome_unknown=server.effect_started)
        except Exception:
            result=p.denial('EC293_HOST_STATUS_EXCEPTION_UNKNOWN_CHECK_ORIGINAL_AUDIT',
                            invoked=started,read_outcome_unknown=server.effect_started)
        try:
            reply=p.signed_reply(req,result,server.policy_sha,
                                  server.prior_policy['job_sha256'],
                                  server.signer,server.clock.now())
            raw=p.canonical(reply)+b'\n'
            if len(raw)>p.MAX_REPLY:
                reply=p.signed_reply(req,p.denial(
                    'EC293_SIGNED_REPLY_TOO_LARGE_UNKNOWN',invoked=started,
                    read_outcome_unknown=server.effect_started),
                    server.policy_sha,server.prior_policy['job_sha256'],
                    server.signer,server.clock.now())
                raw=p.canonical(reply)+b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError,ValueError):
            pass  # A lost ACK cannot authorize another read of this nonce.


class StatusHost(socketserver.UnixStreamServer):
    allow_reuse_address=False
    request_queue_size=4

    def __init__(self,*,path:str,policy_path:str,policy_sha:str,
                 private_key_file:str):
        p.need(hasattr(socket,'AF_UNIX') and
               (hasattr(socket,'SO_PEERCRED') or hasattr(socket.socket,'getpeereid')),
               'EC293_OS_PEER_CREDENTIALS_REQUIRED')
        p.need(p.previous.absolute(path) and len(path.encode())<100,
               'EC293_UNIX_SOCKET_PATH_INVALID')
        try:
            parent=Path(path).parent
            p.need(not any(part.is_symlink() for part in (parent,*parent.parents)),
                   'EC293_SYMLINK_SOCKET_PARENT_DENIED')
            stt=os.lstat(parent)
            p.need(stat.S_ISDIR(stt.st_mode) and stt.st_uid==os.geteuid() and
                   stat.S_IMODE(stt.st_mode)&0o022==0,
                   'EC293_UNTRUSTED_SOCKET_PARENT')
            try:os.lstat(path)
            except FileNotFoundError:pass
            else:raise p.HostError('EC293_SOCKET_ALREADY_EXISTS')
        except OSError as exc:
            raise p.HostError('EC293_SOCKET_PARENT_UNAVAILABLE') from exc
        self.policy_path,self.policy_sha=policy_path,policy_sha
        self.policy=p.load_policy(policy_path,policy_sha)
        _reader,_job,self.prior_policy=p.build_reader(self.policy)
        p.previous.private_directory(self.policy['admission_root'])
        p.previous.private_directory(self.prior_policy['outbox_root'])
        p.previous.private_file(private_key_file,64)
        self.signer=io.private_from_file(private_key_file)
        p.need(p.public_hex(self.signer)==self.policy['server_public_hex'],
               'EC293_SERVER_SIGNING_KEY_PIN_MISMATCH')
        self.clock=AnchoredClock()
        self.effect_started=False
        self._socket_inode=None
        try:
            super().__init__(path,StatusHandler,bind_and_activate=True)
            os.chmod(path,0o660)
            info=os.lstat(path)
            self._socket_inode=(info.st_dev,info.st_ino)
        except Exception:
            self.server_close()
            raise

    def server_close(self):
        super().server_close()
        if self._socket_inode is not None:
            try:
                info=os.lstat(self.server_address)
                if stat.S_ISSOCK(info.st_mode) and (info.st_dev,info.st_ino)==self._socket_inode:
                    os.unlink(self.server_address)
            except FileNotFoundError:
                pass
