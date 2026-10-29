#!/usr/bin/env python3
"""EC294 private audit-key provisioning, independent offline votes and signed client.

All grants bind an operator-supplied independent audit head. For first use
explicitly supply 64 zeros; for later writes supply the last independently
stored signed head (do not derive the authorization head from mutable local
files). Each record uses a FRESH original EC226 read grant and two EC294 votes.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import time

from finding_query_host import protocol as io
from finding_query_host import operator as legacy_op
from delivery_send_host import operator as send_op
from delivery_status_host import operator as status_op
from . import protocol as p, daemon


def write_private(path:str,doc:dict,limit:int)->str:
    return send_op.write_private(path,doc,limit)


def new_audit_hmac(path:str)->dict:
    """Never return audit HMAC secret to stdout/JSON or a status reply."""
    p.need(p.prev.previous.absolute(path),'EC294_AUDIT_HMAC_ABSOLUTE_PATH_REQUIRED')
    parent=Path(path).parent
    p.prev.previous.private_parent(path)
    secret=secrets.token_bytes(32)
    while secret==b'\0'*32:
        secret=secrets.token_bytes(32)
    fd=None
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        offset=0
        while offset<len(secret):
            written=os.write(fd,secret[offset:])
            p.need(written>0,'EC294_AUDIT_KEY_WRITE_DID_NOT_PROGRESS')
            offset+=written
        os.fsync(fd)
        os.close(fd);fd=None
        parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent_fd)
        finally:os.close(parent_fd)
    except OSError as exc:
        raise p.HostError('EC294_AUDIT_HMAC_EXCLUSIVE_CREATE_OR_FSYNC_FAILED') from exc
    finally:
        if fd is not None:os.close(fd)
    return {'schema':'ces.ec294.audit_key_provisioned.v1',
        'status':'owner_private_hmac_created_key_not_returned',
        'audit_hmac_sha256':p.digest(secret),'private_secret_returned':False}


def prepare_policy(*,ec293_policy_file:str,ec293_policy_sha256:str,
      audit_hmac_file:str,admission_root:str,allowed_uids:list[int],
      custodian_public_hex:str,auditor_public_hex:str,
      server_public_hex:str,out:str,enable:bool)->dict:
    p.need(enable is True,'EC294_PRIVATE_RECONCILIATION_OPT_IN_REQUIRED',
           'permission_denied')
    par=p.prev.load_policy(ec293_policy_file,ec293_policy_sha256)
    p.prev.previous.private_directory(admission_root)
    secret=p.prev.previous.private_file(audit_hmac_file,64)
    p.need(type(secret) is bytes and len(secret)==32 and secret!=b'\0'*32,
           'EC294_RAW_AUDIT_KEY_MUST_BE_32_BYTES')
    pol={'schema':p.POLICY_SCHEMA,
        'ec293_policy_file':ec293_policy_file,
        'ec293_policy_sha256':ec293_policy_sha256,
        'audit_hmac_file':audit_hmac_file,
        'audit_hmac_sha256':p.digest(secret),
        'admission_root':admission_root,'allowed_uids':sorted(set(allowed_uids)),
        'custodian_public_hex':custodian_public_hex,
        'auditor_public_hex':auditor_public_hex,
        'server_public_hex':server_public_hex,
        'original_ec227_code_sha256':p.original_sha(),
        'parent_ec293_host_code_sha256':p.prev.host_sha(),
        'host_code_sha256':p.host_sha(),
        'enable_private_reconciliation':True}
    p.validate_policy(pol)
    reader,job,_,prior=p.build_context(pol,credential=False)
    p.pins(pol,reader,job)
    p.audit_secret(pol)
    p.need(p.prev.previous.absolute(out),
           'EC294_POLICY_OUTPUT_MUST_BE_ABSOLUTE')
    write_private(out,pol,p.MAX_POLICY)
    return {'schema':'ces.ec294.private_reconcile_policy_prepared.v1',
        'status':'independent_private_policy_prepared_no_network',
        'policy_sha256':p.digest(p.canonical(pol)+b'\n'),
        'ec293_policy_sha256':ec293_policy_sha256,
        'original_operation_id':p.pins(pol,reader,job)['operation_id'],
        'audit_hmac_secret_returned':False,
        'original_ec225_send_token_loaded':False,
        'status_network_requested':False}


def prepare_subject(policy_file:str,policy_sha:str,mode:str,
          read_grant_file:str|None,uid:int,ttl:int,expected_head:str,out:str)->dict:
    pol=p.load_policy(policy_file,policy_sha)
    reader,job,par,prior=p.build_context(pol,credential=False)
    read=None
    if mode=='record':
        p.need(type(read_grant_file) is str,'EC294_RECORD_NEEDS_EC226_READ_GRANT',
               'invalid_input')
        read=io.read_doc(read_grant_file,p.MAX_RPC)
        p.validate_original_read(read,reader,job,int(time.time()))
    else:
        p.need(mode=='readback' and read_grant_file is None,
               'EC294_READBACK_MUST_NOT_HAVE_NETWORK_GRANT','invalid_input')
    sub=p.new_subject(pol,policy_sha,p.pins(pol,reader,job),uid,mode,
                      expected_head,read,ttl)
    write_private(out,sub,8192)
    return {'schema':'ces.ec294.offline_reconcile_subject_prepared.v1',
        'mode':mode,'subject_sha256':p.digest(p.canonical(sub)),
        'operation_id':sub['operation_id'],
        'expected_head_hmac_sha256':expected_head,
        'audit_key_returned':False,'status_network_requested':False}


def vote(role:str,subject_file:str,private_key_file:str,out:str)->dict:
    p.need(role in ('custodian','auditor'),
           'EC294_OFFLINE_SIGNER_ROLE_INVALID','invalid_input')
    sub=p.validate_subject(io.read_doc(subject_file,8192))
    now=int(time.time())
    p.need(sub['issued_at_unix']<=now+p.CLOCK_SKEW and now<sub['expires_at_unix'],
           'EC294_OFFLINE_SUBJECT_EXPIRED','permission_denied')
    p.prev.previous.private_file(private_key_file,64)
    key=io.private_from_file(private_key_file)
    v={'schema':p.VOTE_SCHEMA,'role':role,
       'subject_sha256':p.digest(p.canonical(sub)),
       'signer_public_hex':p.prev.public_hex(key),
       'signature_ed25519':p.sign(role,sub,key)}
    write_private(out,v,4096)
    return {'schema':'ces.ec294.offline_reconcile_vote_signed.v1',
        'role':role,'subject_sha256':v['subject_sha256'],
        'signer_public_hex':v['signer_public_hex'],
        'private_key_material_returned':False}


def assemble(subject_file:str,custodian_vote_file:str,auditor_vote_file:str,
             custodian_pub:str,auditor_pub:str,out:str)->dict:
    sub=p.validate_subject(io.read_doc(subject_file,8192))
    p.need(custodian_pub!=auditor_pub,
           'EC294_INDEPENDENT_VOTER_KEYS_REQUIRED','permission_denied')
    signatures={}
    for role,path,pub in (('custodian',custodian_vote_file,custodian_pub),
                          ('auditor',auditor_vote_file,auditor_pub)):
        v=io.read_doc(path,4096)
        p.keys(v,{'schema','role','subject_sha256','signer_public_hex',
                  'signature_ed25519'},'EC294_OFFLINE_VOTE_FIELDS_INVALID')
        p.need(v['schema']==p.VOTE_SCHEMA and v['role']==role and
               v['subject_sha256']==p.digest(p.canonical(sub)) and
               v['signer_public_hex']==pub,
               'EC294_VOTE_SUBJECT_OR_SIGNER_MISMATCH','permission_denied')
        p.verify(role,sub,v['signature_ed25519'],pub)
        signatures[role]=v['signature_ed25519']
    grant={'schema':p.GRANT_SCHEMA,'subject':sub,
           'custodian_signature_ed25519':signatures['custodian'],
           'auditor_signature_ed25519':signatures['auditor']}
    write_private(out,grant,10000)
    return {'schema':'ces.ec294.reconcile_host_grant_assembled.v1',
            'mode':sub['mode'],'grant_sha256':p.digest(p.canonical(grant)),
            'status_network_requested':False,'original_submit_requested':False}


def submit(*,socket_path:str,grant_file:str,read_grant_file:str|None,
           policy_sha:str,server_pub:str,timeout:float=55)->tuple[int,dict]:
    p.need(p.prev.previous.absolute(socket_path) and len(socket_path.encode())<100,
           'EC294_SOCKET_PATH_REQUIRED')
    p.need(type(policy_sha) is str and p.HEX.fullmatch(policy_sha) is not None,
           'EC294_POLICY_SHA_REQUIRED')
    io.pub_from_hex(server_pub)
    grant=io.read_doc(grant_file,p.MAX_RPC)
    p.keys(grant,{'schema','subject','custodian_signature_ed25519',
                  'auditor_signature_ed25519'},'EC294_CLIENT_GRANT_FIELDS_INVALID')
    sub=p.validate_subject(grant['subject'])
    p.need(grant['schema']==p.GRANT_SCHEMA and
           sub['policy_sha256']==policy_sha and
           (read_grant_file is not None)==(sub['mode']=='record'),
           'EC294_CLIENT_GRANT_MODE_OR_POLICY_MISMATCH','permission_denied')
    read=io.read_doc(read_grant_file,p.MAX_RPC) if read_grant_file else None
    p.need(sub['read_grant_sha256']==(p.digest(p.canonical(read)) if read is not None
                                else p.NO_READ_SHA),
           'EC294_EC226_READ_DOC_HASH_MISMATCH','permission_denied')
    if read is not None:p.prev.read_envelope(read)
    req={'schema':p.REQUEST_SCHEMA,'nonce':secrets.token_hex(16),
         'grant':grant,'read_grant':read}
    raw=p.canonical(req)+b'\n'
    p.need(len(raw)<=p.MAX_RPC,'EC294_RPC_EXCEEDS_BUDGET')
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(socket_path)
            conn.sendall(raw)
            received=bytearray()
            while len(received)<=p.MAX_REPLY:
                part=conn.recv(min(4096,p.MAX_REPLY+1-len(received)))
                if not part:break
                received.extend(part)
                if b'\n' in part:break
    except (OSError,TimeoutError) as exc:
        raise p.HostError('EC294_MISSING_SOCKET_ACK_AUDIT_OUTCOME_UNKNOWN_NO_RETRY') from exc
    p.need(len(received)<=p.MAX_REPLY and received.endswith(b'\n') and
           received.count(b'\n')==1,
           'EC294_LOST_OR_OVERSIZE_ACK_NO_RETRY')
    try:
        reply=io.parse(bytes(received[:-1]),p.MAX_REPLY)
        result=p.verify_reply(reply,req,server_pub,policy_sha,int(time.time()))
    except Exception as exc:
        raise p.HostError('EC294_UNVERIFIED_HOST_ACK_NO_RETRY') from exc
    return result['exit_code'],{
      'schema':p.RESULT_SCHEMA,'verified_server_signature':True,
      'mode':sub['mode'],'result':result,'signed_reply':reply,
      'audit_head_hmac_sha256':result.get('audit_head_hmac_sha256'),
      'audit_head_requires_independent_external_anchoring':True,
      'fresh_attested_delivery_state_this_call':(
          sub['mode']=='record' and
          result.get('fresh_independent_status_evidence_verified') is True and
          result.get('delivery_state') in p.dr.KNOWN_STATES),
      'original_ec225_submit_retried':False,
      'original_ec225_send_token_loaded_by_host':False,
      'automatic_status_query_or_send_retry_allowed':False,
      'production_inbox_delivery_proven':False,
      'real_world_signer_independence_proven':False,
      'raw_hmac_secret_or_private_payload_returned':False}


def parser():
    a=argparse.ArgumentParser(description='EC294 independent original EC227 private audit record and readback')
    sub=a.add_subparsers(dest='command',required=True)
    k=sub.add_parser('keygen-offline');k.add_argument('--private-out',required=True)
    k=sub.add_parser('keygen-audit-hmac');k.add_argument('--private-out',required=True)
    k=sub.add_parser('prepare-policy')
    for opt in ('ec293-policy-file','ec293-policy-sha256','audit-hmac-file',
                'admission-root','custodian-public-hex','auditor-public-hex',
                'server-public-hex','out'):
        k.add_argument('--'+opt,required=True)
    k.add_argument('--allowed-uid',type=int,action='append',required=True)
    k.add_argument('--enable-private-reconciliation',action='store_true')
    # Original EC226 read grant preparation is precisely the established EC293
    # tooling, not a new delivery/send grant or a network call.
    k=sub.add_parser('prepare-read-template')
    for opt in ('ec293-policy-file','ec293-policy-sha256','ttl-seconds','out'):
        k.add_argument('--'+opt,required=True,type=int if opt=='ttl-seconds' else str)
    k=sub.add_parser('sign-read-offline')
    for opt in ('template-file','private-key-file','out'):
        k.add_argument('--'+opt,required=True)
    k=sub.add_parser('prepare-offline')
    for opt in ('policy-file','policy-sha256','mode','uid','ttl-seconds',
                'expected-head','out'):
        k.add_argument('--'+opt,required=True,
                       type=int if opt in ('uid','ttl-seconds') else str)
    k.add_argument('--read-grant-file',default=None)
    for role in ('custodian','auditor'):
        k=sub.add_parser('sign-'+role+'-offline')
        for opt in ('subject-file','private-key-file','out'):k.add_argument('--'+opt,required=True)
    k=sub.add_parser('assemble')
    for opt in ('subject-file','custodian-vote-file','auditor-vote-file',
                'custodian-public-hex','auditor-public-hex','out'):
        k.add_argument('--'+opt,required=True)
    k=sub.add_parser('serve')
    for opt in ('socket','policy-file','policy-sha256','server-private-key-file'):
        k.add_argument('--'+opt,required=True)
    k=sub.add_parser('submit')
    for opt in ('socket','grant-file','policy-sha256','server-public-hex'):
        k.add_argument('--'+opt,required=True)
    k.add_argument('--read-grant-file',default=None)
    k.add_argument('--timeout-seconds',type=float,default=55)
    return a


def main(argv=None):
    args=parser().parse_args(argv)
    try:
        if args.command=='keygen-offline':
            info=legacy_op._keygen(args.private_out)
            result={'schema':'ces.ec294.offline_keygen.v1',
                    'public_hex':info['public_hex'],
                    'private_key_material_returned':False}
        elif args.command=='keygen-audit-hmac':
            result=new_audit_hmac(args.private_out)
        elif args.command=='prepare-policy':
            result=prepare_policy(ec293_policy_file=args.ec293_policy_file,
              ec293_policy_sha256=args.ec293_policy_sha256,
              audit_hmac_file=args.audit_hmac_file,admission_root=args.admission_root,
              allowed_uids=args.allowed_uid,
              custodian_public_hex=args.custodian_public_hex,
              auditor_public_hex=args.auditor_public_hex,
              server_public_hex=args.server_public_hex,out=args.out,
              enable=args.enable_private_reconciliation)
        elif args.command=='prepare-read-template':
            result=status_op.prepare_read_template(args.ec293_policy_file,
                     args.ec293_policy_sha256,args.ttl_seconds,args.out)
        elif args.command=='sign-read-offline':
            result=status_op.sign_read_template(args.template_file,
                     args.private_key_file,args.out)
        elif args.command=='prepare-offline':
            result=prepare_subject(args.policy_file,args.policy_sha256,args.mode,
                     args.read_grant_file,args.uid,args.ttl_seconds,
                     args.expected_head,args.out)
        elif args.command in ('sign-custodian-offline','sign-auditor-offline'):
            result=vote(args.command.split('-')[1],args.subject_file,
                        args.private_key_file,args.out)
        elif args.command=='assemble':
            result=assemble(args.subject_file,args.custodian_vote_file,
              args.auditor_vote_file,args.custodian_public_hex,
              args.auditor_public_hex,args.out)
        elif args.command=='serve':
            with daemon.ReconcileHost(path=args.socket,policy_path=args.policy_file,
                 policy_sha=args.policy_sha256,
                 private_key_file=args.server_private_key_file) as host:
                host.serve_forever(poll_interval=0.2)
            return 0
        elif args.command=='submit':
            rc,result=submit(socket_path=args.socket,grant_file=args.grant_file,
              read_grant_file=args.read_grant_file,
              policy_sha=args.policy_sha256,server_pub=args.server_public_hex,
              timeout=args.timeout_seconds)
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
            return rc
        else:raise AssertionError('unrecognized command')
        print(json.dumps(result,sort_keys=True,separators=(',',':')))
        return 0
    except Exception as exc:
        status=exc.status if isinstance(exc,p.HostError) else 'unavailable'
        code=exc.code if isinstance(exc,p.HostError) else 'EC294_OPERATOR_UNAVAILABLE_NO_RETRY'
        print(json.dumps(p.denial(code,status),sort_keys=True,separators=(',',':')))
        return {'permission_denied':3,'invalid_input':4,'unavailable':5}[status]

if __name__=='__main__':
    raise SystemExit(main())
