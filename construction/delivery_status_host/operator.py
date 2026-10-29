#!/usr/bin/env python3
"""EC293 offline original EC226 read grant + two Host votes + signed RPC client.

Provision only owner-private fixed files; do not send original payload, endpoint,
identity, read credential, original EC288 POST token, or key over AF_UNIX.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time

from finding_query_host import protocol as io
from finding_query_host import operator as legacy_op
from delivery_send_host import operator as previous_op
import delivery_authorization as da
import delivery_status as st
from . import protocol as p, daemon


def write_private(path:str,doc:dict,limit:int)->str:
    return previous_op.write_private(path,doc,limit)


def prepare_policy(*,ec288_policy_file:str,ec288_policy_sha256:str,
      status_trust_file:str,read_credential_file:str,admission_root:str,
      allowed_uids:list[int],custodian_public_hex:str,reviewer_public_hex:str,
      server_public_hex:str,out:str,enable:bool)->dict:
    p.need(enable is True,'EC293_EXPLICIT_PRIVATE_STATUS_READ_OPT_IN_REQUIRED',
           'permission_denied')
    previous=p.previous.load_policy(ec288_policy_file,ec288_policy_sha256)
    p.previous.private_directory(admission_root)
    p.previous.private_directory(previous['outbox_root'])
    statusraw=p.previous.private_file(status_trust_file,p.MAX_TRUST)
    p.validate_trust(io.parse(statusraw,p.MAX_TRUST))
    credraw=p.previous.private_file(read_credential_file,p.MAX_CREDENTIAL)
    p.need(p.digest(credraw)!=previous['credential_sha256'],
           'EC293_READ_TOKEN_REUSES_SEND_TOKEN')
    pol={'schema':p.POLICY_SCHEMA,
         'ec288_policy_file':ec288_policy_file,
         'ec288_policy_sha256':ec288_policy_sha256,
         'status_trust_file':status_trust_file,
         'status_trust_sha256':p.digest(statusraw),
         'read_credential_file':read_credential_file,
         'read_credential_sha256':p.digest(credraw),
         'admission_root':admission_root,
         'allowed_uids':sorted(set(allowed_uids)),
         'custodian_public_hex':custodian_public_hex,
         'reviewer_public_hex':reviewer_public_hex,
         'server_public_hex':server_public_hex,
         'original_ec226_code_sha256':p.original_sha(),
         'host_code_sha256':p.host_sha(),
         'enable_one_private_status_read':True}
    p.validate_policy(pol)
    reader,job,old=p.build_reader(pol)
    p.operation_pins(pol,reader,job) # authentic historical EC225 signer binding
    digest=p.digest(p.canonical(pol)+b'\n')
    p.need(p.previous.absolute(out),'EC293_POLICY_OUTPUT_PATH_REQUIRED')
    write_private(out,pol,p.MAX_POLICY)
    return {'schema':'ces.ec293.owner_private_status_policy_prepared.v1',
      'status':'private_policy_prepared_no_status_network',
      'policy_sha256':digest,'ec288_policy_sha256':ec288_policy_sha256,
      'job_sha256':old['job_sha256'],'original_ec226_code_sha256':p.original_sha(),
      'ec288_send_token_loaded':False,'external_status_query_requested':False}


def prepare_read_template(policy_file:str,policy_sha:str,ttl:int,out:str)->dict:
    pol=p.load_policy(policy_file,policy_sha)
    reader,job,_=p.build_reader(pol)
    template=p.original_read_template(pol,reader,job,ttl)
    write_private(out,template,8192)
    return {'schema':'ces.ec293.unsigned_original_ec226_status_read.v1',
      'status':'unsigned_status_read_template_prepared_no_network',
      'original_read_template_sha256':p.digest(p.canonical(template)),
      'operation_id':template['operation_id'],
      'ec225_submit_retried':False,'ec226_network_read_attempted':False}


def sign_read_template(template_file:str,key_file:str,out:str)->dict:
    statement=io.read_doc(template_file,8192)
    p.keys(statement,set(st.READ_KEYS),'EC293_EC226_READ_TEMPLATE_FIELDS_INVALID')
    p.need(statement['schema']==st.READ_SCHEMA and
           statement['purpose']==st.READ_PURPOSE and
           statement['expires_at']-statement['issued_at']<=35 and
           statement['issued_at']<=int(time.time())+5 and
           int(time.time())<statement['expires_at'],
           'EC293_ORIGINAL_READ_TEMPLATE_EXPIRED_OR_INVALID')
    p.previous.private_file(key_file,64)
    signer=io.private_from_file(key_file)
    read={'statement':statement,
          'signature_hex':signer.sign(st.READ_DOMAIN+p.canonical(statement)).hex()}
    write_private(out,read,10000)
    return {'schema':'ces.ec293.original_ec226_read_signed.v1',
      'read_grant_sha256':p.digest(p.canonical(read)),
      'signature_is_status_read_only_not_send':True}


def prepare_subject(policy_file:str,policy_sha:str,read_grant_file:str,
                    uid:int,ttl:int,out:str)->dict:
    pol=p.load_policy(policy_file,policy_sha)
    p.need(uid in pol['allowed_uids'],'EC293_UID_NOT_IN_PRIVATE_HOST_ALLOWLIST',
           'permission_denied')
    reader,job,_=p.build_reader(pol)
    read=io.read_doc(read_grant_file,12000)
    p.validate_read(read,reader,job,int(time.time()))
    pins=p.operation_pins(pol,reader,job)
    sub=p.new_subject(pol,policy_sha,pins,read,uid,ttl)
    write_private(out,sub,8192)
    return {'schema':'ces.ec293.status_host_subject_prepared.v1',
      'status':'exact_read_subject_prepared_no_network',
      'subject_sha256':p.digest(p.canonical(sub)),
      'operation_id':sub['operation_id'],
      'provider_submit_retried':False}


def vote(role:str,subject_file:str,key_file:str,out:str)->dict:
    p.need(role in ('custodian','reviewer'),'EC293_SIGNER_ROLE_INVALID')
    sub=p.validate_subject(io.read_doc(subject_file,8192))
    p.previous.private_file(key_file,64)
    key=io.private_from_file(key_file)
    data={'schema':p.VOTE_SCHEMA,'role':role,
          'subject_sha256':p.digest(p.canonical(sub)),
          'signer_public_hex':p.public_hex(key),
          'signature_ed25519':p.sign(role,sub,key)}
    write_private(out,data,8192)
    return {'schema':'ces.ec293.offline_status_host_vote.v1',
            'role':role,'subject_sha256':data['subject_sha256'],
            'network_or_send_attempted':False}


def assemble(subject_file:str,custodian_vote_file:str,reviewer_vote_file:str,
             custodian_pub:str,reviewer_pub:str,out:str)->dict:
    sub=p.validate_subject(io.read_doc(subject_file,8192))
    p.need(custodian_pub!=reviewer_pub,
           'EC293_DIFFERENT_OFFLINE_REVIEWER_REQUIRED','permission_denied')
    signatures={}
    for role,path,pub in (
      ('custodian',custodian_vote_file,custodian_pub),
      ('reviewer',reviewer_vote_file,reviewer_pub)):
        obj=io.read_doc(path,8192)
        p.keys(obj,{'schema','role','subject_sha256','signer_public_hex',
                    'signature_ed25519'},'EC293_OFFLINE_VOTE_FIELDS_INVALID')
        p.need(obj['schema']==p.VOTE_SCHEMA and obj['role']==role and
               obj['subject_sha256']==p.digest(p.canonical(sub)) and
               obj['signer_public_hex']==pub,
               'EC293_OFFLINE_VOTE_WRONG_SUBJECT_OR_SIGNER','permission_denied')
        p.verify(role,sub,obj['signature_ed25519'],pub)
        signatures[role]=obj['signature_ed25519']
    grant={'schema':p.GRANT_SCHEMA,'subject':sub,
           'custodian_signature_ed25519':signatures['custodian'],
           'reviewer_signature_ed25519':signatures['reviewer']}
    write_private(out,grant,10000)
    return {'schema':'ces.ec293.status_host_grant_assembled.v1',
       'grant_sha256':p.digest(p.canonical(grant)),
       'provider_read_requested':False,'provider_send_requested':False}


def submit(*,socket_path:str,grant_file:str,read_grant_file:str,
           policy_sha:str,server_pub:str,timeout:float=55)->tuple[int,dict]:
    p.need(p.previous.absolute(socket_path) and len(socket_path.encode())<100,
           'EC293_SOCKET_PATH_INVALID')
    p.need(type(policy_sha) is str and p.HEX.fullmatch(policy_sha) is not None,
           'EC293_POLICY_SHA_REQUIRED')
    io.pub_from_hex(server_pub)
    grant=io.read_doc(grant_file,p.MAX_RPC)
    read=io.read_doc(read_grant_file,p.MAX_RPC)
    p.keys(grant,{'schema','subject','custodian_signature_ed25519',
                  'reviewer_signature_ed25519'},'EC293_CLIENT_GRANT_INVALID')
    sub=p.validate_subject(grant['subject'])
    p.need(grant['schema']==p.GRANT_SCHEMA and sub['policy_sha256']==policy_sha and
           sub['read_grant_sha256']==p.digest(p.canonical(read)),
           'EC293_GRANT_OR_READ_SHA_MISMATCH','permission_denied')
    p.read_envelope(read)
    request={'schema':p.REQUEST_SCHEMA,'nonce':secrets.token_hex(16),
             'grant':grant,'read_grant':read}
    raw=p.canonical(request)+b'\n'
    p.need(len(raw)<=p.MAX_RPC,'EC293_RPC_EXCEEDS_MAX')
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
        raise p.HostError('EC293_UNVERIFIED_SOCKET_ACK_STATUS_OUTCOME_UNKNOWN') from exc
    p.need(len(received)<=p.MAX_REPLY and received.endswith(b'\n') and
           received.count(b'\n')==1,
           'EC293_LOST_OR_OVERSIZE_SIGNED_STATUS_ACK_NO_RETRY')
    try:
        reply=io.parse(bytes(received[:-1]),p.MAX_REPLY)
        result=p.verify_reply(reply,request,server_pub,policy_sha,int(time.time()))
    except Exception as exc:
        raise p.HostError('EC293_UNTRUSTED_STATUS_ACK_NO_RETRY') from exc
    unknown=result.get('read_outcome_unknown') is True or (
        result.get('status')!='partial' and
        result.get('status_network_requested') is True)
    return result['exit_code'],{
        'schema':p.RESULT_SCHEMA,'verified_server_signature':True,
        'result':result,'signed_reply':reply,
        'status_read_outcome_unknown':unknown,
        'provider_status_attested':result.get('provider_evidence_verified') is True,
        'inbox_delivery_observed':result.get('recipient_delivery_observed') is True,
        'provider_status_read_only':True,
        'original_ec225_send_token_loaded_by_host':False,
        'original_ec225_submit_retried':False,
        'automatic_status_read_or_send_retry_allowed':False,
        'public_or_production_delivery_claimed':False,
        'real_organizational_signer_independence_verified':False,
        'private_payload_or_provider_credential_returned':False}


def parser():
    a=argparse.ArgumentParser(description='EC293 independent original EC226 exact private delivery status read host')
    sub=a.add_subparsers(dest='command',required=True)
    k=sub.add_parser('keygen-offline');k.add_argument('--private-out',required=True)
    k=sub.add_parser('prepare-policy')
    for opt in ('ec288-policy-file','ec288-policy-sha256','status-trust-file',
                'read-credential-file','admission-root','custodian-public-hex',
                'reviewer-public-hex','server-public-hex','out'):
        k.add_argument('--'+opt,required=True)
    k.add_argument('--allowed-uid',type=int,action='append',required=True)
    k.add_argument('--enable-private-status-read',action='store_true')
    k=sub.add_parser('prepare-read-template')
    for opt in ('policy-file','policy-sha256','ttl-seconds','out'):
        k.add_argument('--'+opt,required=True,type=int if opt=='ttl-seconds' else str)
    k=sub.add_parser('sign-read-offline')
    for opt in ('template-file','private-key-file','out'):k.add_argument('--'+opt,required=True)
    k=sub.add_parser('prepare-offline')
    for opt in ('policy-file','policy-sha256','read-grant-file','uid','ttl-seconds','out'):
        k.add_argument('--'+opt,required=True,type=int if opt in ('uid','ttl-seconds') else str)
    for role in ('custodian','reviewer'):
        k=sub.add_parser('sign-'+role+'-offline')
        for opt in ('subject-file','private-key-file','out'):k.add_argument('--'+opt,required=True)
    k=sub.add_parser('assemble')
    for opt in ('subject-file','custodian-vote-file','reviewer-vote-file',
                'custodian-public-hex','reviewer-public-hex','out'):
        k.add_argument('--'+opt,required=True)
    k=sub.add_parser('serve')
    for opt in ('socket','policy-file','policy-sha256','server-private-key-file'):
        k.add_argument('--'+opt,required=True)
    k=sub.add_parser('submit')
    for opt in ('socket','grant-file','read-grant-file',
                'policy-sha256','server-public-hex'):
        k.add_argument('--'+opt,required=True)
    k.add_argument('--timeout-seconds',type=float,default=55)
    return a


def main(argv=None):
    args=parser().parse_args(argv)
    try:
        if args.command=='keygen-offline':
            info=legacy_op._keygen(args.private_out)
            result={'schema':'ces.ec293.offline_keygen.v1',
                    'public_hex':info['public_hex'],
                    'private_key_material_returned':False}
        elif args.command=='prepare-policy':
            result=prepare_policy(ec288_policy_file=args.ec288_policy_file,
              ec288_policy_sha256=args.ec288_policy_sha256,
              status_trust_file=args.status_trust_file,
              read_credential_file=args.read_credential_file,
              admission_root=args.admission_root,allowed_uids=args.allowed_uid,
              custodian_public_hex=args.custodian_public_hex,
              reviewer_public_hex=args.reviewer_public_hex,
              server_public_hex=args.server_public_hex,out=args.out,
              enable=args.enable_private_status_read)
        elif args.command=='prepare-read-template':
            result=prepare_read_template(args.policy_file,args.policy_sha256,
                                         args.ttl_seconds,args.out)
        elif args.command=='sign-read-offline':
            result=sign_read_template(args.template_file,args.private_key_file,args.out)
        elif args.command=='prepare-offline':
            result=prepare_subject(args.policy_file,args.policy_sha256,
                                   args.read_grant_file,args.uid,args.ttl_seconds,args.out)
        elif args.command in ('sign-custodian-offline','sign-reviewer-offline'):
            result=vote(args.command.split('-')[1],args.subject_file,
                        args.private_key_file,args.out)
        elif args.command=='assemble':
            result=assemble(args.subject_file,args.custodian_vote_file,
              args.reviewer_vote_file,args.custodian_public_hex,
              args.reviewer_public_hex,args.out)
        elif args.command=='serve':
            with daemon.StatusHost(path=args.socket,policy_path=args.policy_file,
                     policy_sha=args.policy_sha256,
                     private_key_file=args.server_private_key_file) as host:
                host.serve_forever(poll_interval=0.2)
            return 0
        elif args.command=='submit':
            code,result=submit(socket_path=args.socket,grant_file=args.grant_file,
              read_grant_file=args.read_grant_file,
              policy_sha=args.policy_sha256,server_pub=args.server_public_hex,
              timeout=args.timeout_seconds)
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
            return code
        else:raise AssertionError('unknown command')
        print(json.dumps(result,sort_keys=True,separators=(',',':')))
        return 0
    except Exception as exc:
        status=exc.status if isinstance(exc,p.HostError) else 'unavailable'
        code=exc.code if isinstance(exc,p.HostError) else 'EC293_OPERATOR_UNAVAILABLE_NO_RETRY'
        print(json.dumps(p.denial(code,status),sort_keys=True,separators=(',',':')))
        return {'permission_denied':3,'invalid_input':4,'unavailable':5}[status]


if __name__=='__main__':
    raise SystemExit(main())
