#!/usr/bin/env python3
"""EC294 fixed AF_UNIX signer/auditor Host; unchanged ORIGINAL EC227 invoked.

No status read is automatically repeated. Host admits a new offline two-vote
grant ONCE, before original EC227's START audit fsync and EC226's read nonce.
Readback never loads a Provider credential and never calls the network.
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
import delivery_status as st
from . import protocol as p

class AnchoredClock:
    def __init__(self):
        self.wall,self.mono=time.time(),time.monotonic()
    def now(self)->int:
        return int(max(time.time(),self.wall+time.monotonic()-self.mono))

def peer_uid(conn:socket.socket)->int:
    try:
        if hasattr(socket,'SO_PEERCRED'):
            _pid,uid,_gid=struct.unpack('3i',conn.getsockopt(
                socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
        elif hasattr(conn,'getpeereid'):
            uid,_gid=conn.getpeereid()
        else:raise OSError('kernel peer creds unavailable')
        p.need(type(uid) is int and 0<=uid<=2**31-1,
               'EC294_KERNEL_PEER_UID_INVALID','permission_denied')
        return uid
    except (OSError,struct.error) as exc:
        raise p.HostError('EC294_KERNEL_PEER_UID_UNAVAILABLE',
                          'permission_denied') from exc

def decode_request(raw:bytes)->dict:
    p.need(type(raw) is bytes and 0<len(raw)<=p.MAX_RPC and
           raw.endswith(b'\n') and raw.count(b'\n')==1,
           'EC294_RPC_FRAMING_INVALID','invalid_input')
    req=io.parse(raw[:-1],p.MAX_RPC)
    p.keys(req,{'schema','nonce','grant','read_grant'},'EC294_RPC_FIELDS_INVALID')
    p.need(req['schema']==p.REQUEST_SCHEMA and type(req['nonce']) is str and
           p.HEX32.fullmatch(req['nonce']) is not None and
           type(req['grant']) is dict and
           (req['read_grant'] is None or type(req['read_grant']) is dict),
           'EC294_RPC_SHAPE_INVALID','invalid_input')
    return req

def admit_once(root:str,grant_id:str)->bool:
    """Irreversible fsync per grant; never remove partially completed slot."""
    p.prev.previous.private_directory(root)
    p.need(type(grant_id) is str and p.HEX32.fullmatch(grant_id) is not None,
           'EC294_GRANT_ID_INVALID')
    parent=slot=None
    try:
        parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        entry=os.fstat(parent)
        p.need(stat.S_ISDIR(entry.st_mode) and entry.st_uid==os.geteuid() and
               stat.S_IMODE(entry.st_mode)&0o077==0,
               'EC294_ADMISSION_ROOT_CHANGED')
        try:os.mkdir('ec294-'+grant_id,0o700,dir_fd=parent)
        except FileExistsError:return False
        slot=os.open('ec294-'+grant_id,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                     dir_fd=parent)
        os.fsync(slot)
        os.fsync(parent)
        return True
    except OSError as exc:
        raise p.HostError('EC294_ADMISSION_FSYNC_UNCERTAIN_NO_RETRY') from exc
    finally:
        if slot is not None:os.close(slot)
        if parent is not None:os.close(parent)

def perform(server:'ReconcileHost',pol:dict,reader,job,read,sub:dict)->dict:
    def live()->bool:
        try:
            if server.clock.now()>=sub['expires_at_unix']:return False
            if p.load_policy(server.policy_path,server.policy_sha)!=pol:return False
            newreader,newjob,_,_=p.build_context(pol,
                                  credential=sub['mode']=='record')
            return all(sub.get(k)==v for k,v in p.pins(pol,newreader,newjob).items())
        except Exception:return False

    p.need(live(),'EC294_SOURCE_OR_AUTHORITY_CHANGED_BEFORE_AUDIT')
    record=sub['mode']=='record'
    if record:
        p.validate_original_read(read,reader,job,server.clock.now())
    # Original EC225 durable attempt required for either mode; unlike any
    # historical signed approval, only the original actual attempt is relevant.
    with st.LocalStatusReadLedger(reader.sender.access.outbox_root) as ledger:
        ledger.verify_submit_marker(sub['operation_id'])
    secret=p.audit_secret(pol)
    rec=p.reconciler(reader,secret)
    p.preflight_head(rec,job,sub['expected_head_hmac_sha256'])
    p.need(live(),'EC294_CONTEXT_OR_CHECKPOINT_CHANGED_BEFORE_ADMISSION')
    server.effect_started=True
    p.need(admit_once(pol['admission_root'],sub['grant_id']),
           'EC294_EXACT_HOST_GRANT_SPENT_NO_AUTO_RETRY','permission_denied')
    p.need(live(),'EC294_AUTHORITY_DRIFT_AFTER_DURABLE_ADMISSION_NO_RETRY')
    # Preflight again against a separately operator-pinned external head,
    # before the original EC227 audit mutation. Same-host calls are serialized
    # by the UnixStreamServer; other same-UID writers remain out of scope.
    p.preflight_head(rec,job,sub['expected_head_hmac_sha256'])
    if record:
        original=st.DeliveryStatusRequest(job,p.prev.read_envelope(read),True,True)
        result=rec.observe_and_record(original)  # unchanged original EC227
    else:
        result=rec.readback(job,
            expected_head_hmac_sha256=None if
                sub['expected_head_hmac_sha256']==p.GENESIS else
                sub['expected_head_hmac_sha256'])
    try:
        p.validate_backend(result,sub['mode'],sub['operation_id'],
                           sub['expected_head_hmac_sha256'])
    except p.HostError:
        return p.denial('EC294_ORIGINAL_EC227_UNVERIFIED_RESULT_INSPECT_AUDIT',
                        admission_uncertain=True)
    if not live():
        return p.denial('EC294_POST_AUDIT_AUTHORITY_DRIFT_OUTCOME_UNKNOWN',
                        admission_uncertain=True)
    return result

class ReconcileHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(45)
        try:req=decode_request(self.rfile.readline(p.MAX_RPC+2))
        except (OSError,TimeoutError,ValueError):return
        server:ReconcileHost=self.server
        server.effect_started=False
        try:
            pol=p.load_policy(server.policy_path,server.policy_sha)
            p.need(pol==server.policy,'EC294_SERVED_POLICY_DRIFT')
            mode=p.validate_subject(req['grant']['subject'])['mode']
            reader,job,par,prior=p.build_context(pol,credential=mode=='record')
            uid=peer_uid(self.request)
            sub=p.validate_grant(req['grant'],pol,server.policy_sha,reader,job,
                    uid,server.clock.now(),req['read_grant'])
            if mode=='record':
                p.validate_original_read(req['read_grant'],reader,job,server.clock.now())
            result=perform(server,pol,reader,job,req['read_grant'],sub)
        except p.HostError as exc:
            result=p.denial(exc.code,exc.status,
                            admission_uncertain=server.effect_started)
        except Exception:
            result=p.denial('EC294_HOST_EXCEPTION_OR_INDETERMINATE_AUDIT_NO_RETRY',
                            admission_uncertain=server.effect_started)
        try:
            reply=p.signed_reply(req,result,server.policy_sha,
                    server.prior_policy['job_sha256'],
                    server.signer,server.clock.now())
            raw=p.canonical(reply)+b'\n'
            if len(raw)>p.MAX_REPLY:
                reply=p.signed_reply(req,p.denial(
                    'EC294_SIGNED_ACK_TOO_LARGE_OUTCOME_UNKNOWN',
                    admission_uncertain=server.effect_started),
                    server.policy_sha,server.prior_policy['job_sha256'],
                    server.signer,server.clock.now())
                raw=p.canonical(reply)+b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (OSError,ValueError):
            pass  # Lost ACK never means original EC227 didn't write/read.

class ReconcileHost(socketserver.UnixStreamServer):
    allow_reuse_address=False
    request_queue_size=4
    def __init__(self,*,path:str,policy_path:str,policy_sha:str,
                 private_key_file:str):
        p.need(hasattr(socket,'AF_UNIX') and
               (hasattr(socket,'SO_PEERCRED') or hasattr(socket.socket,'getpeereid')),
               'EC294_AF_UNIX_WITH_KERNEL_CREDENTIALS_REQUIRED')
        p.need(p.prev.previous.absolute(path) and len(path.encode())<100,
               'EC294_SOCKET_PATH_INVALID')
        try:
            parent=Path(path).parent
            p.need(not any(x.is_symlink() for x in (parent,*parent.parents)),
                   'EC294_SOCKET_PARENT_SYMLINK_DENIED')
            info=os.lstat(parent)
            p.need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and
                   stat.S_IMODE(info.st_mode)&0o022==0,
                   'EC294_SOCKET_PARENT_UNTRUSTED')
            try:os.lstat(path)
            except FileNotFoundError:pass
            else:raise p.HostError('EC294_SOCKET_ALREADY_EXISTS')
        except OSError as exc:
            raise p.HostError('EC294_SOCKET_PARENT_UNAVAILABLE') from exc
        self.policy_path,self.policy_sha=policy_path,policy_sha
        self.policy=p.load_policy(policy_path,policy_sha)
        self._reader,_job,self.parent_policy,self.prior_policy=p.build_context(
            self.policy,credential=False)
        p.audit_secret(self.policy)
        p.prev.previous.private_directory(self.policy['admission_root'])
        p.prev.previous.private_directory(self.prior_policy['outbox_root'])
        p.prev.previous.private_file(private_key_file,64)
        self.signer=io.private_from_file(private_key_file)
        p.need(p.prev.public_hex(self.signer)==self.policy['server_public_hex'],
               'EC294_SERVER_PRIVATE_KEY_PIN_MISMATCH')
        self.clock=AnchoredClock()
        self.effect_started=False
        self._socket_inode=None
        try:
            super().__init__(path,ReconcileHandler,bind_and_activate=True)
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
                entry=os.lstat(self.server_address)
                if stat.S_ISSOCK(entry.st_mode) and (
                    entry.st_dev,entry.st_ino)==self._socket_inode:
                    os.unlink(self.server_address)
            except OSError:pass
