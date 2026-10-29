#!/usr/bin/env python3
"""EC288 private job provisioning, two OFFLINE signatures and bounded socket client.

Never send raw report, identity, credential, provider URL or payload on the wire.
Votes are valid for one exact private policy/job/trust/source revision and UID.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time

from finding_query_host import operator as old_op
from finding_query_host import protocol as io
from . import protocol as p, daemon


def write_private(path:str,doc:dict,limit:int)->str:
    p.private_parent(path)
    raw=p.canonical(doc)+b'\n'
    p.need(len(raw)<=limit,'EC288_PRIVATE_OUTPUT_TOO_LARGE')
    fd=None
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as f:
            fd=None
            f.write(raw);f.flush();os.fsync(f.fileno())
        parent=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
    except OSError as exc:
        raise p.HostError('EC288_PRIVATE_OUTPUT_ALREADY_EXISTS_OR_UNWRITABLE') from exc
    finally:
        if fd is not None:os.close(fd)
    return p.digest(raw)


def prepare_job(src:str,out:str)->dict:
    job=io.parse(p.private_file(src,p.MAX_JOB),p.MAX_JOB)
    parsed=p.validate_job(job)
    sh=write_private(out,job,p.MAX_JOB)
    return {'schema':'ces.ec288.prepared_private_delivery_job.v1',
            'status':'owner_private_job_prepared_not_sent',
            'job_sha256':sh,'source_count':len(parsed.authorization_request.identity_request
                 .sensitive_review_request.preview_request.sources),
            'approval_sha256':p.job_pins({'job_sha256':sh,'trust_sha256':'0'*64,
                   'credential_sha256':'0'*64,'original_backend_sha256':p.backend_sha(),'host_backend_sha256':p.host_code_sha()},
                   parsed)['original_approval_sha256'],
            'private_content_returned':False,'network_requested':False}


def prepare_policy(*,job_file:str,trust_file:str,credential_file:str,
        outbox_root:str,admission_root:str,allowed_uids:list[int],
        custodian_pub:str,authorizer_pub:str,server_pub:str,
        out:str,enable:bool)->dict:
    p.need(enable is True,'EC288_EXPLICIT_ONE_SANDBOX_SEND_OPT_IN_REQUIRED',
           'permission_denied')
    jobraw=p.private_file(job_file,p.MAX_JOB)
    trustraw=p.private_file(trust_file,p.MAX_TRUST)
    credraw=p.private_file(credential_file,p.MAX_TOKEN)
    job=p.validate_job(io.parse(jobraw,p.MAX_JOB))
    trust=p.validate_trust(io.parse(trustraw,p.MAX_TRUST))
    p.private_directory(outbox_root)
    p.private_directory(admission_root)
    p.need(outbox_root!=admission_root,'EC288_SEPARATE_LEDGER_ROOTS_REQUIRED')
    p.need(len(set(p.trust_keys(trust)+[
        custodian_pub,authorizer_pub,server_pub]))==11,
        'EC288_ELEVEN_DISTINCT_KEY_ROLES_REQUIRED')
    policy={'schema':p.POLICY_SCHEMA,'job_file':job_file,
        'job_sha256':p.digest(jobraw),'trust_file':trust_file,
        'trust_sha256':p.digest(trustraw),'credential_file':credential_file,
        'credential_sha256':p.digest(credraw),'outbox_root':outbox_root,
        'admission_root':admission_root,'allowed_uids':sorted(set(allowed_uids)),
        'custodian_issuer_public_hex':custodian_pub,
        'authorizer_issuer_public_hex':authorizer_pub,
        'server_public_hex':server_pub,
        'original_backend_sha256':p.backend_sha(),
        'host_backend_sha256':p.host_code_sha(),
        'enable_single_sandbox_delivery':True}
    p.validate_policy(policy)
    # Original constructor enforces 8 pinned, role-distinct source roots,
    # exact sandbox endpoint formatting and real HTTPS-only transport policy.
    p.build_sender(trust,p.load_credential(policy),outbox_root)
    digest=p.digest(p.canonical(job.authorization_request.exact_delivery_grant.__dict__))
    sh=write_private(out,policy,p.MAX_POLICY)
    return {'schema':'ces.ec288.prepared_delivery_host_policy.v1',
            'status':'private_policy_written_no_provider_request',
            'policy_sha256':sh,'job_sha256':policy['job_sha256'],
            'original_backend_sha256':policy['original_backend_sha256'],
            'host_backend_sha256':policy['host_backend_sha256'],
            'approval_sha256':digest,'credential_or_target_returned':False,
            'remote_sandbox_submit_attempted':False}


def prepare_subject(policy_file:str,sha:str,uid:int,ttl:int,out:str)->dict:
    pol=p.load_policy(policy_file,sha)
    req=p.load_job(pol)
    p.load_trust(pol)
    p.load_credential(pol)
    p.need(uid in pol['allowed_uids'],'EC288_UID_NOT_HOST_AUTHORIZED',
           'permission_denied')
    sub=p.new_subject(uid,sha,p.job_pins(pol,req),ttl)
    io.write_exclusive(out,sub)
    return {'schema':'ces.ec288.unsigned_subject.v1',
            'status':'exact_delivery_subject_prepared_not_sent',
            'subject_sha256':p.digest(p.canonical(sub)),
            'no_network_or_provider_submission':True}


def vote(role:str,subject_file:str,key_file:str,out:str)->dict:
    sub=p.validate_subject(io.read_doc(subject_file,8192))
    p.private_file(key_file,64)
    key=io.private_from_file(key_file)
    v={'schema':p.VOTE_SCHEMA,'role':role,
       'subject_sha256':p.digest(p.canonical(sub)),
       'signer_public_hex':p.public_hex(key),
       'signature_ed25519':p.sign(role,sub,key)}
    io.write_exclusive(out,v)
    return {'schema':'ces.ec288.offline_vote_created.v1',
            'role':role,'subject_sha256':v['subject_sha256'],
            'signed_approval_is_not_provider_submission':True}


def assemble(subject_file:str,custodian_vote:str,authorizer_vote:str,
             custodian_pub:str,authorizer_pub:str,out:str)->dict:
    sub=p.validate_subject(io.read_doc(subject_file,8192))
    p.need(custodian_pub!=authorizer_pub,
           'EC288_DISTINCT_OFFLINE_SIGNERS_REQUIRED','permission_denied')
    sigs={}
    for role,source,pub in (
          ('custodian',custodian_vote,custodian_pub),
          ('authorizer',authorizer_vote,authorizer_pub)):
        v=io.read_doc(source,8192)
        p.keys(v,{'schema','role','subject_sha256','signer_public_hex',
                  'signature_ed25519'},'EC288_VOTE_FIELDS_INVALID')
        p.need(v['schema']==p.VOTE_SCHEMA and v['role']==role and
               v['subject_sha256']==p.digest(p.canonical(sub)) and
               v['signer_public_hex']==pub,
               'EC288_OFFLINE_VOTE_SCOPE_OR_ROLE_MISMATCH',
               'permission_denied')
        p.verify(role,sub,v['signature_ed25519'],pub)
        sigs[role]=v['signature_ed25519']
    grant={'schema':p.GRANT_SCHEMA,'subject':sub,
           'custodian_signature_ed25519':sigs['custodian'],
           'authorizer_signature_ed25519':sigs['authorizer']}
    io.write_exclusive(out,grant)
    return {'schema':'ces.ec288.grant_assembled.v1',
            'status':'exact_two_vote_grant_assembled_not_sent',
            'grant_sha256':p.digest(p.canonical(grant))}


def submit(*,socket_path:str,grant_file:str,policy_sha:str,
           server_pub:str,timeout:float=75)->tuple[int,dict]:
    p.need(p.absolute(socket_path) and len(socket_path.encode())<100,
           'EC288_UNIX_SOCKET_PATH_INVALID')
    p.need(type(policy_sha) is str and p.HEX.fullmatch(policy_sha) is not None,
           'EC288_POLICY_SHA_INVALID')
    io.pub_from_hex(server_pub)
    grant=io.read_doc(grant_file,p.MAX_RPC)
    p.keys(grant,{'schema','subject','custodian_signature_ed25519',
                  'authorizer_signature_ed25519'},'EC288_CLIENT_GRANT_INVALID')
    p.need(grant['schema']==p.GRANT_SCHEMA,'EC288_GRANT_SCHEMA_INVALID')
    sub=p.validate_subject(grant['subject'])
    p.need(sub['policy_sha256']==policy_sha,
           'EC288_POLICY_BINDING_MISMATCH','permission_denied')
    req={'schema':p.REQUEST_SCHEMA,'nonce':secrets.token_hex(16),'grant':grant}
    raw=p.canonical(req)+b'\n'
    p.need(len(raw)<=p.MAX_RPC,'EC288_RPC_TOO_LARGE')
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(socket_path)
            sock.sendall(raw)
            out=bytearray()
            while len(out)<=p.MAX_REPLY:
                part=sock.recv(min(4096,p.MAX_REPLY+1-len(out)))
                if not part:break
                out.extend(part)
                if b'\n' in part:break
    except (OSError,TimeoutError) as exc:
        raise p.HostError('EC288_SOCKET_OUTCOME_UNKNOWN_INSPECT_TWO_LEDGERS') from exc
    p.need(out.endswith(b'\n') and out.count(b'\n')==1 and
           len(out)<=p.MAX_REPLY,
           'EC288_MISSING_REPLY_SUBMIT_OUTCOME_UNKNOWN_NO_RETRY')
    try:
        reply=io.parse(bytes(out[:-1]),p.MAX_REPLY)
        result=p.verify_reply(reply,req,server_pub,policy_sha,int(time.time()))
    except (p.HostError,io.HostError,ValueError,TypeError,KeyError) as exc:
        raise p.HostError('EC288_UNTRUSTED_SIGNED_REPLY_OUTCOME_UNKNOWN_NO_RETRY') from exc
    unknown=(result.get('send_outcome_unknown') is True or
             (result.get('claim_committed') is True and
              result.get('submission_state')!='SUBMISSION_UNCONFIRMED'))
    return result['exit_code'],{
        'schema':p.RESULT_SCHEMA,'verified_server_signature':True,
        'result':result,'signed_reply':reply,
        'send_outcome_unknown':unknown,
        'provider_http_submission_only_not_delivered':
             result.get('submission_state')=='SUBMISSION_UNCONFIRMED',
        'private_payload_credential_or_recipient_returned':False,
        'delivered_verified_by_ces':False,
        'automatic_submit_retry_allowed':False,
        'real_organizational_signer_identity_verified_by_ces':False}


def parser()->argparse.ArgumentParser:
    a=argparse.ArgumentParser(description='EC288 original EC225 exact sandbox delivery host')
    sub=a.add_subparsers(dest='command',required=True)
    k=sub.add_parser('keygen-offline');k.add_argument('--private-out',required=True)
    k=sub.add_parser('prepare-job')
    k.add_argument('--source-json',required=True);k.add_argument('--out',required=True)
    k=sub.add_parser('inspect-job');k.add_argument('--job-file',required=True)
    k=sub.add_parser('prepare-policy')
    for opt in ('job-file','trust-file','credential-file','outbox-root',
                'admission-root','custodian-public-hex','authorizer-public-hex',
                'server-public-hex','out'):
        k.add_argument('--'+opt,required=True)
    k.add_argument('--allowed-uid',action='append',type=int,required=True)
    k.add_argument('--enable-one-sandbox-send',action='store_true')
    k=sub.add_parser('prepare-offline')
    for opt in ('policy-file','policy-sha256','uid','ttl-seconds','out'):
        k.add_argument('--'+opt,required=True,
           type=int if opt in ('uid','ttl-seconds') else str)
    for role in ('custodian','authorizer'):
        k=sub.add_parser('sign-'+role+'-offline')
        for opt in ('subject-file','private-key-file','out'):
            k.add_argument('--'+opt,required=True)
    k=sub.add_parser('assemble-offline')
    for opt in ('subject-file','custodian-vote','authorizer-vote',
                'custodian-public-hex','authorizer-public-hex','out'):
        k.add_argument('--'+opt,required=True)
    k=sub.add_parser('serve')
    for opt in ('socket','policy-file','policy-sha256','server-private-key'):
        k.add_argument('--'+opt,required=True)
    k=sub.add_parser('submit')
    for opt in ('socket','grant-file','policy-sha256','server-public-hex'):
        k.add_argument('--'+opt,required=True)
    k.add_argument('--pretty',action='store_true')
    return a


def main(argv:list[str]|None=None)->int:
    a=parser().parse_args(argv)
    try:
        if a.command=='keygen-offline':
            info=old_op._keygen(a.private_out)
            out={'schema':'ces.ec288.keygen.v1','public_hex':info['public_hex'],
                 'private_key_returned':False}
        elif a.command=='prepare-job':
            out=prepare_job(a.source_json,a.out)
        elif a.command=='inspect-job':
            raw=p.private_file(a.job_file,p.MAX_JOB)
            req=p.validate_job(io.parse(raw,p.MAX_JOB))
            out={'schema':'ces.ec288.inspect_private_job.v1',
                 'status':'owner_private_job_observed_not_approved',
                 'job_sha256':p.digest(raw),
                 'source_count':len(req.authorization_request.identity_request
                     .sensitive_review_request.preview_request.sources),
                 'raw_payload_or_identity_returned':False}
        elif a.command=='prepare-policy':
            out=prepare_policy(job_file=a.job_file,trust_file=a.trust_file,
                credential_file=a.credential_file,outbox_root=a.outbox_root,
                admission_root=a.admission_root,allowed_uids=a.allowed_uid,
                custodian_pub=a.custodian_public_hex,
                authorizer_pub=a.authorizer_public_hex,
                server_pub=a.server_public_hex,out=a.out,
                enable=a.enable_one_sandbox_send)
        elif a.command=='prepare-offline':
            out=prepare_subject(a.policy_file,a.policy_sha256,a.uid,
                                a.ttl_seconds,a.out)
        elif a.command.startswith('sign-'):
            role=a.command.split('-')[1]
            out=vote(role,a.subject_file,a.private_key_file,a.out)
        elif a.command=='assemble-offline':
            out=assemble(a.subject_file,a.custodian_vote,a.authorizer_vote,
                         a.custodian_public_hex,a.authorizer_public_hex,a.out)
        elif a.command=='serve':
            with daemon.DeliverySendHost(
                 path=a.socket,policy_path=a.policy_file,
                 policy_sha=a.policy_sha256,
                 private_key_file=a.server_private_key) as host:
                host.serve_forever(poll_interval=.25)
            return 0
        elif a.command=='submit':
            rc,out=submit(socket_path=a.socket,grant_file=a.grant_file,
                          policy_sha=a.policy_sha256,server_pub=a.server_public_hex)
            print(json.dumps(out,ensure_ascii=True,sort_keys=True,
                  indent=2 if a.pretty else None,
                  separators=None if a.pretty else (',',':')))
            return rc
        else:
            raise AssertionError('unhandled')
        print(p.canonical(out).decode('ascii'))
        return 0
    except (p.HostError,io.HostError,OSError,ValueError) as exc:
        code=exc.code if isinstance(exc,(p.HostError,io.HostError)) else \
             'EC288_OWNER_OPERATOR_FAILURE'
        status=exc.status if isinstance(exc,(p.HostError,io.HostError)) else 'unavailable'
        if status not in ('unavailable','invalid_input','permission_denied'):
            status='unavailable'
        denied=p.denial(code,status,
                        send_outcome_unknown=(a.command=='submit'))
        print(p.canonical(denied).decode('ascii'))
        return denied['exit_code']


if __name__=='__main__':
    raise SystemExit(main())
