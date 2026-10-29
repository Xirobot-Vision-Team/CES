#!/usr/bin/env python3
"""EC288 host daemon: one offline dual-signed, owner-private EC225 sandbox submit.

Single threaded AF_UNIX; it never accepts a payload, endpoint, credential,
recipient or executable command on the wire. No automatic network retry.
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
from . import protocol as p
import delivery_send as ds


class AnchoredClock:
    def __init__(self):
        self.wall,self.mono=time.time(),time.monotonic()

    def now(self)->int:
        return int(max(time.time(),self.wall+time.monotonic()-self.mono))


def peer_uid(conn: socket.socket)->int:
    try:
        if hasattr(socket,'SO_PEERCRED'):
            buf=conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i'))
            _pid,uid,_gid=struct.unpack('3i',buf)
        elif hasattr(conn,'getpeereid'):
            uid,_gid=conn.getpeereid()
        else:
            raise OSError('kernel peer credential unavailable')
        p.need(type(uid) is int and 0<=uid<=2**31-1,
               'EC288_KERNEL_PEER_UID_INVALID','permission_denied')
        return uid
    except (OSError,struct.error) as exc:
        raise p.HostError('EC288_KERNEL_PEER_UID_UNAVAILABLE','permission_denied') from exc


def request_decode(raw:bytes)->dict:
    p.need(type(raw) is bytes and 0<len(raw)<=p.MAX_RPC and
           raw.endswith(b'\n') and raw.count(b'\n')==1,
           'EC288_RPC_REQUEST_FRAMING_INVALID','invalid_input')
    req=io.parse(raw[:-1],p.MAX_RPC)
    p.keys(req,{'schema','nonce','grant'},'EC288_RPC_REQUEST_FIELDS_INVALID')
    p.need(req['schema']==p.REQUEST_SCHEMA and
           type(req['nonce']) is str and
           io.HEX_NONCE.fullmatch(req['nonce']) is not None and
           type(req['grant']) is dict,
           'EC288_RPC_REQUEST_INVALID','invalid_input')
    return req


def admission_claim(root: str, grant_id: str) -> bool:
    """Durably spend the Host grant before ORIGINAL EC225 is invoked.

    Even if no provider POST occurs, uncertainty about reservation/replay is
    never authorization for a second request. The original EC225 outbox remains
    a separate, per-EC224-grant durable at-most-once submit barrier.
    """
    p.private_directory(root)
    p.need(type(grant_id) is str and io.HEX_NONCE.fullmatch(grant_id) is not None,
           'EC288_GRANT_ID_INVALID')
    basefd=claimfd=None
    try:
        basefd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        st=os.fstat(basefd)
        p.need(st.st_uid==os.geteuid() and not stat.S_IMODE(st.st_mode)&0o077,
               'EC288_ADMISSION_ROOT_CHANGED')
        slot='ec288-'+grant_id
        try:
            os.mkdir(slot,0o700,dir_fd=basefd)
        except FileExistsError:
            return False
        claimfd=os.open(slot,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                        dir_fd=basefd)
        os.fsync(claimfd)
        os.fsync(basefd)
        return True
    except OSError as exc:
        raise p.HostError('EC288_ADMISSION_OUTCOME_UNKNOWN_NO_RETRY') from exc
    finally:
        for fd in (claimfd,basefd):
            if fd is not None:
                os.close(fd)


def perform(server:'DeliverySendHost',pol:dict,sub:dict)->dict:
    def live()->bool:
        try:
            return (server.clock.now()<sub['expires_at_unix'] and
                    p.load_policy(server.policy_path,server.policy_sha)==pol and
                    p.digest(p.private_file(pol['job_file'],p.MAX_JOB))==pol['job_sha256'] and
                    p.digest(p.private_file(pol['trust_file'],p.MAX_TRUST))==pol['trust_sha256'] and
                    p.digest(p.private_file(pol['credential_file'],p.MAX_TOKEN))==pol['credential_sha256'] and
                    p.backend_sha()==sub['original_backend_sha256'] and
                    p.host_code_sha()==sub['host_backend_sha256'])
        except Exception:
            return False

    p.need(live(),'EC288_PRIVATE_AUTHORITY_CHANGED_BEFORE_SEND')
    job=p.load_job(pol)
    p.need(all(sub[k]==v for k,v in p.job_pins(pol,job).items()),
           'EC288_ORIGINAL_APPROVAL_OR_PAYLOAD_PIN_CHANGED')
    trust=p.load_trust(pol)
    cred=p.load_credential(pol)
    p.private_directory(pol['outbox_root'])
    p.private_directory(pol['admission_root'])
    # Build *original* authority objects, which independently enforce the
    # complete real EC221->222->223->224->225 approval/source/expiry chain.
    sender=p.build_sender(trust,cred,pol['outbox_root'])
    p.need(live(),'EC288_AUTHORITY_CHANGED_BEFORE_HOST_ADMISSION')
    consumed=admission_claim(pol['admission_root'],sub['grant_id'])
    if not consumed:
        server.effect_started=True
        raise p.HostError('EC288_HOST_GRANT_ALREADY_SPENT_NO_RETRY','permission_denied')
    # After admission, a lost/replayed reply cannot establish whether a POST
    # occurred. This is deliberately conservative even for pre-POST failures.
    server.effect_started=True
    p.need(live(),'EC288_AUTHORITY_CHANGED_AFTER_ADMISSION_NO_RETRY')
    result=sender.send_once(job)        # UNMODIFIED ORIGINAL EC225.
    try:
        p.validate_backend(result)
    except p.HostError:
        return p.denial('EC288_ORIGINAL_EC225_RESULT_UNKNOWN_INSPECT_OUTBOX',
                        handler_invoked=True,send_outcome_unknown=True)
    if not live():
        return p.denial('EC288_POST_RETURNED_BUT_AUTHORIZATION_DRIFT_UNKNOWN',
                        handler_invoked=True,send_outcome_unknown=True)
    return result


class DeliveryHandler(socketserver.StreamRequestHandler):
    def handle(self)->None:
        self.request.settimeout(65)
        try:
            req=request_decode(self.rfile.readline(p.MAX_RPC+2))
        except (OSError,TimeoutError,ValueError):
            return
        server:DeliverySendHost=self.server
        started=False
        server.effect_started=False
        try:
            pol=p.load_policy(server.policy_path,server.policy_sha)
            p.need(pol==server.policy,'EC288_HOST_POLICY_CONTENT_CHANGED')
            job=p.load_job(pol)
            sub=p.validate_grant(req['grant'],pol,job,uid=peer_uid(self.request),
                                 now=server.clock.now(),policy_sha=server.policy_sha)
            started=True
            result=perform(server,pol,sub)
        except p.HostError as exc:
            result=p.denial(exc.code,exc.status,handler_invoked=started,
                            send_outcome_unknown=server.effect_started)
        except Exception:
            result=p.denial('EC288_HOST_ORIGINAL_SEND_EXCEPTION_INSPECT_OUTBOX',
                            handler_invoked=started,
                            send_outcome_unknown=server.effect_started)
        try:
            reply=p.signed_reply(req,result,server.policy_sha,
                                 server.policy['job_sha256'],
                                 server.signer,server.clock.now())
            raw=p.canonical(reply)+b'\n'
            if len(raw)>p.MAX_REPLY:
                raw=p.canonical(p.signed_reply(req,p.denial(
                    'EC288_REPLY_TOO_LARGE_INSPECT_OUTBOX',handler_invoked=started,
                    send_outcome_unknown=server.effect_started),
                    server.policy_sha,server.policy['job_sha256'],
                    server.signer,server.clock.now()))+b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError,ValueError):
            return   # Reply lost -> UNKNOWN; no automatic resend.


class DeliverySendHost(socketserver.UnixStreamServer):
    allow_reuse_address=False
    request_queue_size=4

    def __init__(self, *,path:str,policy_path:str,policy_sha:str,
                 private_key_file:str):
        p.need(hasattr(socket,'AF_UNIX') and (
            hasattr(socket,'SO_PEERCRED') or hasattr(socket.socket,'getpeereid')),
            'EC288_KERNEL_PEER_CREDENTIALS_REQUIRED')
        p.need(p.absolute(path) and len(path.encode())<100,
               'EC288_SOCKET_PATH_INVALID')
        try:
            st=os.lstat(Path(path).parent)
            p.need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
                   stat.S_IMODE(st.st_mode)&0o002==0,
                   'EC288_UNIX_SOCKET_PARENT_UNTRUSTED')
            try:
                os.lstat(path)
            except FileNotFoundError:
                pass
            else:
                raise p.HostError('EC288_EXISTING_UNIX_SOCKET_REJECTED')
        except OSError as exc:
            raise p.HostError('EC288_SOCKET_PARENT_UNAVAILABLE') from exc
        self.policy_path,self.policy_sha=policy_path,policy_sha
        self.policy=p.load_policy(policy_path,policy_sha)
        p.load_job(self.policy)
        trust=p.load_trust(self.policy)
        rootkeys=p.trust_keys(trust)
        hostkeys=[self.policy[k] for k in (
            'custodian_issuer_public_hex','authorizer_issuer_public_hex',
            'server_public_hex')]
        p.need(len(set(rootkeys+hostkeys))==11,
               'EC288_ELEVEN_DISTINCT_ORIGINAL_AND_HOST_PUBLIC_KEYS_REQUIRED')
        p.private_directory(self.policy['admission_root'])
        p.private_directory(self.policy['outbox_root'])
        cred=p.load_credential(self.policy)
        p.build_sender(trust,cred,self.policy['outbox_root'])
        p.private_file(private_key_file,64)
        self.signer=io.private_from_file(private_key_file)
        p.need(p.public_hex(self.signer)==self.policy['server_public_hex'],
               'EC288_HOST_PRIVATE_SIGNER_MISMATCH')
        self.clock=AnchoredClock()
        self.effect_started=False
        self._socket_inode=None
        try:
            super().__init__(path,DeliveryHandler,bind_and_activate=True)
            os.chmod(path,0o660)
            st=os.lstat(path)
            self._socket_inode=(st.st_dev,st.st_ino)
        except Exception:
            self.server_close()
            raise

    def server_close(self)->None:
        super().server_close()
        if self._socket_inode is not None:
            try:
                st=os.lstat(self.server_address)
                if stat.S_ISSOCK(st.st_mode) and (st.st_dev,st.st_ino)==self._socket_inode:
                    os.unlink(self.server_address)
            except FileNotFoundError:
                pass
