#!/usr/bin/env python3
"""EC286 independent AF_UNIX execution front-end for ORIGINAL EC187.

This service does NOT start an unprotected command or invent a broker. It uses
an already separately deployed EC259 strict source-custody/EC257 session host.
EC259 itself must enforce rootless Podman and real cgroup-v2. A kernel peer UID
and on-host Git custody are not cryptographic proof of EC259's process image.
"""
from __future__ import annotations

from datetime import datetime,timezone
import hmac
import os
from pathlib import Path
import socket
import socketserver
import stat
import time

from finding_query_host.daemon import AnchoredClock,peer_uid
from finding_query_host import protocol as io
from quality_preflight_host import protocol as pre
from session_host import broker as session
from custody_gated_host.gate import OperatorCustodyGate
import quality_detect as detect
import quality_run_budget as budget
import quality_run_guard as guard
from . import protocol as p


def decode_request(raw: bytes) -> dict:
    p.need(raw.endswith(b'\n') and 1<len(raw)<=p.MAX_RPC+1,
           'EC286_RPC_TERMINATOR_OR_LENGTH_INVALID','invalid_input')
    req=io.parse(raw[:-1],p.MAX_RPC)
    p.need(set(req)=={'schema','nonce','grant'} and
           req.get('schema')==p.REQUEST_SCHEMA and
           type(req.get('nonce')) is str and
           io.HEX_NONCE.fullmatch(req['nonce']) is not None and
           type(req.get('grant')) is dict,
           'EC286_RPC_FIELDS_INVALID','invalid_input')
    return req


def session_socket_pin(pol: dict) -> tuple[int,int]:
    """Pin local peer socket inode *and* configured UID; not EC259 attestation."""
    path=pol['session_socket']
    p.need(p.plain_abs(path) and len(os.fsencode(path))<100,
           'EC286_SESSION_SOCKET_PATH_INVALID')
    try:
        parent=os.lstat(Path(path).parent)
        st=os.lstat(path)
        p.need(stat.S_ISDIR(parent.st_mode) and
               parent.st_uid==pol['session_service_uid'] and
               stat.S_IMODE(parent.st_mode)&0o077==0 and
               stat.S_ISSOCK(st.st_mode) and
               st.st_uid==pol['session_service_uid'] and
               stat.S_IMODE(st.st_mode)&0o007==0,
               'EC286_TRUSTED_PRIVATE_SESSION_SOCKET_REQUIRED')
        return st.st_dev,st.st_ino
    except OSError as exc:
        raise p.HostError('EC286_STRICT_SESSION_HOST_NOT_AVAILABLE') from exc


def _private_live(server:'ExecuteServer', pol:dict, socket_pin:tuple[int,int],
                  *, grant_expiry:int|None=None) -> bool:
    try:
        return (server.clock.now() < grant_expiry if grant_expiry is not None else True) and (
            p.load_policy(server.policy_path,server.policy_sha)==pol and
            p.backend_code_sha()==pol['backend_code_sha256'] and
            p.sha(p.private_file(pol['preflight_policy_file'],pre.MAX_POLICY))==
                pol['preflight_policy_sha256'] and
            p.sha(p.private_file(pol['lease_policy_file'],65536))==
                pol['lease_policy_sha256'] and
            p.sha(p.private_file(pol['allowlist_file'],65536))==
                pol['allowlist_sha256'] and
            p.sha(p.private_file(pol['receipt_file'],65536))==
                pol['receipt_sha256'] and
            all(pre.pinned_bytes(server.pre_policy,name) is not None
                for name in pre.POLICY_FILES) and
            session_socket_pin(pol)==socket_pin)
    except (p.HostError,pre.HostError,io.HostError, OSError,ValueError,KeyError):
        return False


def run_original_ec187(server:'ExecuteServer', pol:dict, subject:dict) -> dict:
    """Really invoke the unchanged EC187 Controller with the EC259 broker.

    Local tests may replace only the actual session broker with a fake and are
    never evidence of real Podman, enterprise CI, or kernel isolation.
    """
    p.need(os.geteuid()!=0,'EC286_EXECUTION_HOST_MUST_BE_NONROOT')
    pref,lease_pol,pin,approval,ticket,key1,key2=p.load_dependencies(
        pol,verify_tickets=True)
    server.pre_policy=pref
    p.need(subject['source_pin_sha256']==guard._digest(detect.DOMAIN_PIN,pin) and
           subject['profile_sha256']==guard.catalog_entry(pol['profile_id'])['profile_sha256'],
           'EC286_SIGNED_SOURCE_PIN_OR_PROFILE_CHANGED')
    # The ORIGINAL EC259 custody guard checks real Git objects, exact TAR,
    # original EC253 dual-MAC lease and source pin before ANY session begin.
    custody=OperatorCustodyGate(
        pol['lease_policy_file'],pol['git_repo'],pol['allowlist_file'],
        pol['receipt_file'],pol['profile_id'])
    custody.startup(lease_pol,pol['lease_policy_sha256'])
    sock_pin=session_socket_pin(pol)

    def live(before_start:bool=True)->bool:
        return _private_live(server,pol,sock_pin,
                             grant_expiry=subject['expires_at_unix'] if before_start else None)

    p.need(live(),'EC286_HOST_APPROVAL_OR_SOURCE_REVOKED')
    profile=guard.catalog_entry(pol['profile_id'])
    pin_sha=guard._digest(detect.DOMAIN_PIN,pin)
    approval_sha=guard._digest(guard.DOMAIN_RECEIPT,approval)
    ticket_sha=guard._digest(guard.DOMAIN_RECEIPT,ticket)
    scope={'source_pin_sha256':pin_sha,'profile_id':pol['profile_id'],
           'profile_sha256':profile['profile_sha256'],
           'approval_receipt_sha256':approval_sha,
           'lease_receipt_sha256':ticket_sha,
           'image_sha256':lease_pol['image_id'][7:],
           'limits':dict(budget.HARD_CEILINGS)}
    stages=('BEFORE_PROFILE','APPROVED_PROFILE','ISOLATION_RESERVED','FINALIZE')

    def authorize_root(facts:dict)->bool:
        return (live() and type(facts) is dict and facts=={
            'purpose':'QUALITYDETECT_OBSERVE_LOCAL_ROOT',
            'source_mode':'WorkingTree','repo_root':pref['repo_root']})

    def authorize_gate(facts:dict)->bool:
        if not live() or type(facts) is not dict:
            return False
        stage=facts.get('stage')
        if stage not in stages:
            return False
        expected={'schema':guard.SCHEMA,'operation':'QUALITYRUN_CONFIGURE',
                  'stage':stage,'source_mode':'WorkingTree',
                  'repo_root':pref['repo_root'],'source_pin_sha256':pin_sha,
                  'profile_id':pol['profile_id'],
                  'profile_sha256':profile['profile_sha256']}
        if stage!='BEFORE_PROFILE':
            expected['approval_ticket_id']=approval['ticket_id']
        if stage in ('ISOLATION_RESERVED','FINALIZE'):
            expected['lease_ticket_id']=ticket['ticket_id']
        return facts==expected

    def authorize_execute(facts:dict)->bool:
        if not live() or type(facts) is not dict:
            return False
        if facts!={'schema':budget.SCHEMA,
                  'operation':'QUALITYRUN_EXECUTE_EXTERNAL',
                  'stage':facts.get('stage'),**scope} or\
           facts['stage'] not in ('BEFORE_BROKER','FINAL_BEFORE_BROKER'):
            return False
        # A new local verification of source custody precedes the original
        # EC253 ledger/OCI effect. The actual EC259 service MUST also verify
        # custody before begin (the Unix peer UID alone cannot prove this).
        try:
            custody.before_begin(lease_pol,pol['lease_policy_sha256'],
                                 {'profile_id':pol['profile_id']})
            return live()
        except (ValueError,OSError,KeyError,TypeError):
            return False

    class TrackedBroker:
        def __init__(self):
            self.actual=session.TrustedBroker(pol['session_socket'],
                pol['session_service_uid'],pol['scope_id'])
        def begin(self, request:dict):
            p.need(live(),'EC286_OFFLINE_GRANT_REVOKED_AT_LEASE_EDGE')
            custody.before_begin(lease_pol,pol['lease_policy_sha256'],
                                 {'profile_id':pol['profile_id']})
            p.need(live(),'EC286_APPROVAL_REVOKED_BEFORE_LEASE_CONSUMPTION')
            server.lease_begin_attempted=True  # attempt may consume lease
            return self.actual.begin(request)

    # The gate/callback controller are ORIGINAL EC186/EC187 modules.
    now=lambda:datetime.fromtimestamp(server.clock.now(),tz=timezone.utc)
    gate=guard.QualityRunSafetyGate(policy_verification_key=key1,
                                    broker_verification_key=key2,clock=now)
    controller=budget.QualityRunBudgetController(gate)
    server.backend_invoked=True
    result=controller.run(
        repo_root=pref['repo_root'],source_pin=pin,
        profile_id=pol['profile_id'],policy_ticket=approval,
        isolation_ticket=ticket,broker=TrackedBroker(),limits=None,
        allow_prepare=True,allow_profile_approval=True,
        allow_isolation_lease=True,allow_external_execution=True,
        allow_budget_controls=True,authorize_root=authorize_root,
        authorize_gate=authorize_gate,authorize_execute=authorize_execute)
    if not live(before_start=False):
        return p.denial('EC286_POLICY_OR_SOURCE_CHANGED_AFTER_RUN_INSPECT_LEASE',
                        backend_invoked=True,
                        effects_unknown=server.lease_begin_attempted)
    # Never transmit stdout/stderr previews. Sanitize a deep JSON copy
    # BEFORE strict acceptance and before signing the complete host report.
    # All fields (including extensions) are rejected by safe_backend_result.
    result=io.parse(p.canonical(result),budget.MAX_RESULT_SIZE)
    if type(result.get('output')) is dict:
        result['output']['stdout_preview']=None
        result['output']['stderr_preview']=None
    if not p.safe_backend_result(result):
        return p.denial('EC286_EC187_RESULT_CONTRACT_INVALID_INSPECT_LEASE',
                        backend_invoked=True,
                        effects_unknown=server.lease_begin_attempted)
    return result


class ExecuteHandler(socketserver.StreamRequestHandler):
    def handle(self)->None:
        self.request.settimeout(8.0)
        try:
            req=decode_request(self.rfile.readline(p.MAX_RPC+2))
        except (ValueError,OSError,TimeoutError):
            return
        server:ExecuteServer=self.server
        server.backend_invoked=False
        server.lease_begin_attempted=False
        try:
            pol=p.load_policy(server.policy_path,server.policy_sha)
            p.need(pol==server.policy,'EC286_POLICY_REPLACED')
            uid=peer_uid(self.request)
            subject=p.validate_grant(req['grant'],pol,uid=uid,
                 now=server.clock.now(),policy_sha=server.policy_sha)
            result=run_original_ec187(server,pol,subject)
        except p.HostError as exc:
            result=p.denial(exc.code,exc.status,
                            backend_invoked=server.backend_invoked,
                            effects_unknown=server.lease_begin_attempted)
        except Exception:
            result=p.denial('EC286_EXECUTION_HOST_EXCEPTION_INSPECT_LEASE',
                            backend_invoked=server.backend_invoked,
                            effects_unknown=server.lease_begin_attempted)
        try:
            reply=p.signed_reply(req,result,server.policy_sha,
                                 server.signing_key,server.clock.now())
            raw=p.canonical(reply)+b'\n'
            if len(raw)>p.MAX_REPLY:
                raw=p.canonical(p.signed_reply(req,p.denial(
                    'EC286_SIGNED_RESULT_EXCEEDS_LIMIT_INSPECT_LEASE',
                    effects_unknown=server.lease_begin_attempted,
                    backend_invoked=server.backend_invoked),
                    server.policy_sha,server.signing_key,server.clock.now()))+b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (ValueError,OSError):
            return  # Lost reply is always UNKNOWN to the caller.


class ExecuteServer(socketserver.UnixStreamServer):
    allow_reuse_address=False
    request_queue_size=4

    def __init__(self,*,path:str,policy_path:str,policy_sha:str,
                 private_key_file:str):
        p.need(hasattr(socket,'AF_UNIX') and
               (hasattr(socket,'SO_PEERCRED') or
                hasattr(socket.socket,'getpeereid')),
               'EC286_KERNEL_UNIX_PEER_CREDENTIALS_REQUIRED')
        p.need(os.geteuid()!=0,'EC286_REAL_HOST_MUST_BE_NONROOT')
        p.need(p.plain_abs(path) and len(os.fsencode(path))<100,
               'EC286_SERVER_SOCKET_PATH_INVALID')
        self.policy_path=policy_path
        self.policy_sha=policy_sha
        self.policy=p.load_policy(policy_path,policy_sha)
        p.load_dependencies(self.policy)  # Original authorization verified at execution
        self.signing_key=io.private_from_file(private_key_file)
        p.need(hmac.compare_digest(p.public_hex(self.signing_key),
              self.policy['server_public_hex']),
              'EC286_SERVER_SIGNATURE_KEY_NOT_PINNED')
        self.clock=AnchoredClock()
        self.pre_policy=None
        self.backend_invoked=False
        self.lease_begin_attempted=False
        self._socket_inode=None
        try:
            parent=os.lstat(Path(path).parent)
            p.need(stat.S_ISDIR(parent.st_mode) and
                   parent.st_uid==os.geteuid() and
                   stat.S_IMODE(parent.st_mode)&0o077==0,
                   'EC286_OWNER_ONLY_SOCKET_DIRECTORY_REQUIRED')
            p.need(not os.path.lexists(path),'EC286_SERVER_SOCKET_ALREADY_EXISTS')
            # The active EC259 strict session must already be deployed by the
            # operator. This probes socket *ownership*, not its process image.
            session_socket_pin(self.policy)
            super().__init__(path,ExecuteHandler,bind_and_activate=True)
            os.chmod(path,0o660)
            st=os.lstat(path)
            self._socket_inode=(st.st_dev,st.st_ino)
        except Exception:
            if hasattr(self,"socket"):
                self.server_close()
            raise

    def server_close(self):
        if hasattr(self,"socket"):
            super().server_close()
        if self._socket_inode is not None:
            try:
                st=os.lstat(self.server_address)
                if (stat.S_ISSOCK(st.st_mode) and
                    (st.st_dev,st.st_ino)==self._socket_inode):
                    os.unlink(self.server_address)
            except FileNotFoundError:
                pass
