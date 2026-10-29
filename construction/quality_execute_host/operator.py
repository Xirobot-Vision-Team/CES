#!/usr/bin/env python3
"""EC286 host-side policy, separate offline approvals and exact execute client.

Private HMAC key/ticket/Git TAR bytes remain on the trusted non-root host.
Neither the client nor this CLI signs the original EC186/253 authorizations.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time
from typing import Any

from finding_query_host import protocol as io
from finding_query_host import operator as prior
from quality_preflight_host import protocol as pre
from lease_host import broker as lease
from quality_run_host import broker as runner
from . import protocol as p,daemon


def private_create(path:str, data:dict, limit:int=p.MAX_POLICY) -> str:
    p.need(p.plain_abs(path),'EC286_PRIVATE_OUTPUT_ABSOLUTE_REQUIRED','invalid_input')
    # Owner-only parent and no symlink ancestors. No overwrite permitted.
    directory=os.path.dirname(path)
    p.need(os.path.isdir(directory) and not os.path.islink(directory),
           'EC286_PRIVATE_OUTPUT_PARENT_INVALID')
    st=os.stat(directory)
    p.need(st.st_uid==os.geteuid() and st.st_mode&0o077==0,
           'EC286_PRIVATE_OUTPUT_PARENT_NOT_OWNER_ONLY')
    raw=p.canonical(data)+b'\n'
    p.need(len(raw)<=limit,'EC286_PRIVATE_OUTPUT_TOO_LARGE')
    fd=None
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                   getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as stream:
            fd=None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        parent_fd=os.open(directory,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
        try: os.fsync(parent_fd)
        finally: os.close(parent_fd)
        return p.sha(raw)
    except OSError as exc:
        raise p.HostError('EC286_EXCLUSIVE_PRIVATE_OUTPUT_FAILED') from exc
    finally:
        if fd is not None: os.close(fd)


def keygen(path:str) -> dict:
    # Reuse already implemented secure owner-only Ed25519 generation.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,PrivateFormat,NoEncryption)
    key=Ed25519PrivateKey.generate()
    raw=key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
    p.need(p.plain_abs(path),'EC286_PRIVATE_KEY_PATH_INVALID','invalid_input')
    # io keyloader expects 32-byte raw private keys. Never print the secret.
    fd=None
    try:
        directory=os.path.dirname(path)
        st=os.stat(directory)
        p.need(st.st_uid==os.geteuid() and st.st_mode&0o077==0,
               'EC286_PRIVATE_KEY_DIRECTORY_REQUIRED')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                   getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as f:
            fd=None
            f.write(raw); f.flush(); os.fsync(f.fileno())
        return {'status':'offline_private_key_generated',
                'public_hex':p.public_hex(key),'private_key_bytes_returned':False}
    except OSError as exc:
        raise p.HostError('EC286_PRIVATE_KEY_CREATE_FAILED') from exc
    finally:
        if fd is not None: os.close(fd)


def prepare_policy(*,preflight_file:str,preflight_sha:str,lease_file:str,
                   lease_sha:str,git_repo:str,allowlist_file:str,
                   receipt_file:str,session_socket:str,session_uid:int,
                   scope_id:str,profile_id:str,uids:list[int],
                   custodian_pub:str,executor_pub:str,server_pub:str,
                   out:str) -> dict:
    allowlist=p.private_file(allowlist_file,65536)
    receipt=p.private_file(receipt_file,65536)
    lease_raw=p.private_file(lease_file,lease.MAX_POLICY)
    lease_pol,observed=lease._policy(lease_file)
    p.need(observed==p.sha(lease_raw)==lease_sha,
           'EC286_EC253_POLICY_SHA_MISMATCH')
    pol=p.validate_policy({
      'schema':p.POLICY_SCHEMA,'preflight_policy_file':preflight_file,
      'preflight_policy_sha256':preflight_sha,
      'lease_policy_file':lease_file,'lease_policy_sha256':lease_sha,
      'git_repo':git_repo,'allowlist_file':allowlist_file,
      'allowlist_sha256':p.sha(allowlist),'receipt_file':receipt_file,
      'receipt_sha256':p.sha(receipt),'session_socket':session_socket,
      'session_service_uid':session_uid,'scope_id':scope_id,
      'profile_id':profile_id,'allowed_uids':sorted(set(uids)),
      'custodian_issuer_public_hex':custodian_pub,
      'executor_issuer_public_hex':executor_pub,
      'server_public_hex':server_pub,
      'source_tar_sha256':lease_pol['expected_source_tar_sha256'],
      'backend_code_sha256':p.backend_code_sha()})
    # Mandatory original EC281/253 scope and server-rootless authorization.
    p.load_dependencies(pol,verify_tickets=False)
    digest=private_create(out,pol)
    return {'schema':p.POLICY_SCHEMA,'status':'exact_execution_policy_created_not_authorized',
            'policy_sha256':digest,'profile_id':profile_id,
            'source_tar_sha256':pol['source_tar_sha256'],
            'source_code_sha256':pol['backend_code_sha256'],
            'native_container_execution_verified':False}


def vote(role:str,subject_file:str,key_file:str,out:str) -> dict:
    subject=p.validate_subject(io.read_doc(subject_file,8192))
    key=io.private_from_file(key_file)
    entry={'schema':p.VOTE_SCHEMA,'role':role,
           'subject_sha256':p.sha(p.canonical(subject)),
           'signer_public_hex':p.public_hex(key),
           'signature_ed25519':p.sign(role,subject,key)}
    io.write_exclusive(out,entry)
    return {'status':'offline_execution_vote_written','role':role,
            'subject_sha256':entry['subject_sha256'],
            'private_key_returned':False}


def assemble(*,subject_file:str,custodian_vote:str,executor_vote:str,
             custodian_pub:str,executor_pub:str,out:str) -> dict:
    sub=p.validate_subject(io.read_doc(subject_file,8192))
    p.need(custodian_pub!=executor_pub,
           'EC286_TWO_SEPARATE_VOTERS_REQUIRED','permission_denied')
    sigs={}
    for role,path,pub in (('custodian',custodian_vote,custodian_pub),
                          ('executor',executor_vote,executor_pub)):
        v=io.read_doc(path,8192)
        p.need(type(v) is dict and set(v)=={'schema','role','subject_sha256',
             'signer_public_hex','signature_ed25519'} and
             v['schema']==p.VOTE_SCHEMA and v['role']==role and
             v['subject_sha256']==p.sha(p.canonical(sub)) and
             v['signer_public_hex']==pub,
             'EC286_OFFLINE_VOTE_ROLE_OR_SCOPE_INVALID','permission_denied')
        p.verify(role,sub,v['signature_ed25519'],pub)
        sigs[role]=v['signature_ed25519']
    grant={'schema':p.GRANT_SCHEMA,'subject':sub,
           'custodian_signature_ed25519':sigs['custodian'],
           'executor_signature_ed25519':sigs['executor']}
    io.write_exclusive(out,grant)
    return {'status':'independent_execution_two_vote_grant_created',
            'grant_sha256':p.sha(p.canonical(grant)),
            'execution_started':False}


def execute(*,socket_path:str,grant_file:str,policy_sha:str,
            server_pub:str,timeout:float=145)->tuple[int,dict]:
    p.need(p.plain_abs(socket_path) and len(os.fsencode(socket_path))<100,
           'EC286_CLIENT_SOCKET_INVALID','invalid_input')
    p.need(type(policy_sha) is str and io.HASH.fullmatch(policy_sha) is not None,
           'EC286_CLIENT_POLICY_PIN_REQUIRED','invalid_input')
    io.pub_from_hex(server_pub)
    grant=io.read_doc(grant_file,p.MAX_RPC)
    p.need(type(grant) is dict and grant.get('schema')==p.GRANT_SCHEMA and
           type(grant.get('subject')) is dict,
           'EC286_CLIENT_SIGNED_GRANT_REQUIRED','invalid_input')
    subject=p.validate_subject(grant['subject'])
    p.need(subject['policy_sha256']==policy_sha,
           'EC286_CLIENT_GRANT_POLICY_MISMATCH','permission_denied')
    req={'schema':p.REQUEST_SCHEMA,'nonce':secrets.token_hex(16),'grant':grant}
    raw=p.canonical(req)+b'\n'
    p.need(len(raw)<=p.MAX_RPC,'EC286_RPC_TOO_LARGE','invalid_input')
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(socket_path)
            conn.sendall(raw)
            buf=bytearray()
            while len(buf)<=p.MAX_REPLY:
                data=conn.recv(min(16384,p.MAX_REPLY+2-len(buf)))
                if not data: break
                buf.extend(data)
                if b'\n' in data:break
            p.need(buf.endswith(b'\n') and buf.count(b'\n')==1 and
                   len(buf)<=p.MAX_REPLY+1,
                   'EC286_SIGNED_RESPONSE_MISSING_OR_OVERSIZE')
            reply=io.parse(bytes(buf[:-1]),p.MAX_REPLY)
    except (OSError,TimeoutError,ValueError) as exc:
        raise p.HostError('EC286_SIGNED_RESPONSE_UNAVAILABLE_RUN_OUTCOME_UNKNOWN') from exc
    # Once the request is sent, *any* unsigned/invalid/stale/forged response
    # could hide a consumed EC253 lease. Do not report a harmless local deny.
    try:
        res=p.verify_reply(reply,req,server_pub,policy_sha,int(time.time()))
    except (p.HostError,io.HostError,ValueError,KeyError,TypeError) as exc:
        raise p.HostError('EC286_UNTRUSTED_SIGNED_RESPONSE_RUN_OUTCOME_UNKNOWN') from exc
    rc=res['exit_code']
    if res['schema']==p.DENIAL_SCHEMA:
        return rc,{'schema':p.RESULT_SCHEMA,'status':res['status'],
                   'exit_code':rc,'reason_code':res['reason_code'],
                   'verified_server_signature':True,'signed_reply':reply,
                   'result':res,'quality_pass_verified':False,
                   'remote_ci_verified':False,'business_repository_written':False,
                   'lease_or_container_effect_unknown':res['lease_or_container_effect_unknown'],
                   'private_output_disclosed':False}
    effects=res['effects']
    execution=res.get('execution')
    return rc,{'schema':p.RESULT_SCHEMA,'status':res['status'],
        'exit_code':rc,'reason_code':res['reason_code'],
        'verified_server_signature':True,'signed_reply':reply,'result':res,
        'original_ec187_controller_invoked':True,
        'original_ec259_session_begin_host_reported':
            effects.get('external_broker_begin_called') is True,
        'host_reported_execution_exit':(
            execution.get('host_reported_exit_code') if type(execution) is dict else None),
        'quality_pass_verified':False,'remote_ci_verified':False,
        'business_repository_written':False,'private_output_disclosed':False,
        'independent_kernel_or_strict_service_attestation':False,
        'lease_or_container_effect_unknown':
            effects.get('external_broker_begin_called') is True}


def parser()->argparse.ArgumentParser:
    ap=argparse.ArgumentParser(description='EC286 exact QualityRun.Execute with signed host')
    sub=ap.add_subparsers(dest='action',required=True)
    a=sub.add_parser('keygen-offline');a.add_argument('--private-out',required=True)
    a=sub.add_parser('prepare-policy')
    for flag in ('preflight-policy-file','preflight-policy-sha256',
                 'lease-policy-file','lease-policy-sha256','git-repo','allowlist-file',
                 'receipt-file','session-socket','session-service-uid','scope-id',
                 'profile-id','custodian-public-hex','executor-public-hex',
                 'server-public-hex','out'):
        a.add_argument('--'+flag,required=True,
                       type=int if flag=='session-service-uid' else str)
    a.add_argument('--allowed-uid',required=True,type=int,action='append')
    a=sub.add_parser('prepare-offline')
    a.add_argument('--policy-file',required=True)
    a.add_argument('--policy-sha256',required=True)
    a.add_argument('--uid',type=int,required=True)
    a.add_argument('--ttl-seconds',type=int,default=40)
    a.add_argument('--out',required=True)
    for role in ('custodian','executor'):
        a=sub.add_parser('sign-'+role+'-offline')
        a.add_argument('--subject-file',required=True)
        a.add_argument('--private-key-file',required=True)
        a.add_argument('--out',required=True)
    a=sub.add_parser('assemble-offline')
    for opt in ('subject-file','custodian-vote','executor-vote',
                'custodian-public-hex','executor-public-hex','out'):
        a.add_argument('--'+opt,required=True)
    a=sub.add_parser('serve')
    for opt in ('socket','policy-file','policy-sha256','server-private-key'):
        a.add_argument('--'+opt,required=True)
    a.add_argument('--max-requests',type=int,default=1)
    a=sub.add_parser('execute')
    for opt in ('socket','grant-file','policy-sha256','server-public-hex'):
        a.add_argument('--'+opt,required=True)
    a.add_argument('--pretty',action='store_true')
    return ap


def main(argv:list[str]|None=None)->int:
    args=parser().parse_args(argv)
    try:
        if args.action=='keygen-offline': result=keygen(args.private_out)
        elif args.action=='prepare-policy':result=prepare_policy(
            preflight_file=args.preflight_policy_file,
            preflight_sha=args.preflight_policy_sha256,
            lease_file=args.lease_policy_file,lease_sha=args.lease_policy_sha256,
            git_repo=args.git_repo,allowlist_file=args.allowlist_file,
            receipt_file=args.receipt_file,session_socket=args.session_socket,
            session_uid=args.session_service_uid,scope_id=args.scope_id,
            profile_id=args.profile_id,uids=args.allowed_uid,
            custodian_pub=args.custodian_public_hex,
            executor_pub=args.executor_public_hex,
            server_pub=args.server_public_hex,out=args.out)
        elif args.action=='prepare-offline':
            pol=p.load_policy(args.policy_file,args.policy_sha256)
            subject=p.new_subject(pol,args.policy_sha256,
                                   uid=args.uid,ttl=args.ttl_seconds)
            io.write_exclusive(args.out,subject)
            result={'status':'unsigned_exact_execution_subject_created',
                    'subject_sha256':p.sha(p.canonical(subject)),
                    'backend_executed':False}
        elif args.action in ('sign-custodian-offline','sign-executor-offline'):
            result=vote(args.action.split('-')[1],args.subject_file,
                        args.private_key_file,args.out)
        elif args.action=='assemble-offline':result=assemble(
            subject_file=args.subject_file,custodian_vote=args.custodian_vote,
            executor_vote=args.executor_vote,
            custodian_pub=args.custodian_public_hex,
            executor_pub=args.executor_public_hex,out=args.out)
        elif args.action=='serve':
            p.need(1<=args.max_requests<=4,'EC286_SERVER_MAX_REQUESTS_INVALID')
            with daemon.ExecuteServer(path=args.socket,
                 policy_path=args.policy_file,policy_sha=args.policy_sha256,
                 private_key_file=args.server_private_key) as server:
                server.timeout=180
                for _ in range(args.max_requests):server.handle_request()
            return 0
        elif args.action=='execute':
            rc,result=execute(socket_path=args.socket,
                grant_file=args.grant_file,policy_sha=args.policy_sha256,
                server_pub=args.server_public_hex)
            print(json.dumps(result,ensure_ascii=True,sort_keys=True,
                             indent=2 if args.pretty else None,
                             separators=None if args.pretty else (',',':')))
            return rc
        else: raise AssertionError('unreachable action')
        print(p.canonical(result).decode('ascii'))
        return 0
    except (p.HostError,io.HostError,pre.HostError,runner.HostRunError,
            lease.LeaseHostError,OSError,ValueError) as exc:
        code=getattr(exc,'code',None) or 'EC286_LOCAL_OPERATOR_UNAVAILABLE'
        state=getattr(exc,'status',None) or 'unavailable'
        if state not in ('unavailable','invalid_input','permission_denied'):
            state='unavailable'
        denial=p.denial(code,state,effects_unknown=(
            args.action=='execute' and code in (
                'EC286_SIGNED_RESPONSE_UNAVAILABLE_RUN_OUTCOME_UNKNOWN',
                'EC286_UNTRUSTED_SIGNED_RESPONSE_RUN_OUTCOME_UNKNOWN')))
        print(p.canonical(denial).decode('ascii'))
        return denial['exit_code']


if __name__=='__main__':
    raise SystemExit(main())
