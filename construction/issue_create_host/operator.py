#!/usr/bin/env python3
"""EC287 owner-only job/policy provisioning, offline votes, one-shot host client.

There is intentionally NO CLI option for a token value, remote URL, title/body,
endpoint, untrusted issuer key registry or arbitrary command. Signed subjects
and socket requests only carry exact digests and independent signatures.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import time

from finding_query_host import operator as old_op
from finding_query_host import protocol as io
from . import protocol as p, daemon


def write_private(path: str, doc: dict, limit: int) -> str:
    p.private_parent(path)
    raw=p.canonical(doc)+b'\n'
    p.need(len(raw)<=limit,'EC287_PRIVATE_OUTPUT_TOO_LARGE')
    fd=None
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                   getattr(os,'O_NOFOLLOW',0),0o600)
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as f:
            fd=None
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        directory=os.open(os.path.dirname(path),os.O_RDONLY|
                          getattr(os,'O_DIRECTORY',0))
        try: os.fsync(directory)
        finally: os.close(directory)
    except OSError as exc:
        raise p.HostError('EC287_PRIVATE_OUTPUT_CREATE_FAILED','unavailable') from exc
    finally:
        if fd is not None:os.close(fd)
    return p.sha(raw)


def prepare_job(source: str, out: str) -> dict:
    doc=io.parse(p.private_file(source,p.MAX_JOB),p.MAX_JOB)
    parsed=p.validate_job(doc)
    digest=write_private(out,doc,p.MAX_JOB)
    return {'schema':'ces.ec287.inspect_private_job.v1',
        'status':'owner_private_exact_job_created_not_authorized',
        'job_sha256':digest,
        'operation_sha256':p.cw.operation_sha256(parsed['intent']),
        'approval_sha256':p.sha(p.canonical(asdict(parsed['approval']))),
        'raw_issue_title_or_body_returned':False,
        'original_ec217_signature_verified':False,
        'provider_post_attempted':False}


def prepare_policy(*,job_file: str,trust_file: str,access_file: str,
                   token_file: str,reservation_db: str,attempt_db: str,
                   host_grant_db: str,allowed_uids: list[int],
                   custodian_pub: str,authorizer_pub: str,server_pub: str,
                   out: str,explicit_enable: bool) -> dict:
    p.need(explicit_enable is True,
           'EC287_EXPLICIT_REMOTE_NEW_ISSUE_CREATE_OPT_IN_REQUIRED',
           'permission_denied')
    j=p.private_file(job_file,p.MAX_JOB)
    t=p.private_file(trust_file,p.MAX_TRUST)
    a=p.private_file(access_file,p.MAX_ACCESS)
    parsed=p.validate_job(io.parse(j,p.MAX_JOB))
    p.validate_trust(io.parse(t,p.MAX_TRUST))
    access=p.validate_access(io.parse(a,p.MAX_ACCESS))
    p.need((access.provider,access.repository,access.audience) ==
           (parsed['intent'].provider,parsed['intent'].repository,
            parsed['intent'].audience),
           'EC287_ACCESS_CANNOT_BELONG_TO_OTHER_JOB','unavailable')
    p.private_file(token_file,p.MAX_TOKEN)  # never return or hash token contents
    for path in (reservation_db,attempt_db,host_grant_db):
        p.private_parent(path)
    policy={'schema':p.POLICY_SCHEMA,'job_file':job_file,'job_sha256':p.sha(j),
        'trust_file':trust_file,'trust_sha256':p.sha(t),
        'access_file':access_file,'access_sha256':p.sha(a),
        'token_file':token_file,'reservation_db':reservation_db,
        'attempt_db':attempt_db,'host_grant_db':host_grant_db,
        'allowed_uids':sorted(set(allowed_uids)),
        'custodian_issuer_public_hex':custodian_pub,
        'authorizer_issuer_public_hex':authorizer_pub,
        'server_public_hex':server_pub,
        'enable_exact_remote_create':True}
    p.validate_policy(policy)
    digest=write_private(out,policy,p.MAX_POLICY)
    return {'status':'exact_private_remote_create_policy_written',
        'policy_sha256':digest,'job_sha256':policy['job_sha256'],
        'trust_sha256':policy['trust_sha256'],
        'access_sha256':policy['access_sha256'],
        'backend_sha256':p.code_sha256(),
        'provider_token_disclosed':False,
        'network_requested':False}


def prepare_subject(policy_file: str,policy_sha: str,
                    uid: int,ttl: int,out: str) -> dict:
    pol=p.load_policy(policy_file,policy_sha)
    job=p.load_job(pol)
    p.load_trust(pol)
    access=p.load_access(pol)
    p.need(uid in pol['allowed_uids'],
           'EC287_SUBJECT_UID_NOT_ALLOWED','permission_denied')
    p.need((access.provider,access.repository,access.audience) ==
           (job['intent'].provider,job['intent'].repository,
            job['intent'].audience),
           'EC287_ACCESS_AND_JOB_NOT_SAME_TARGET','unavailable')
    subject=p.new_subject(uid,policy_sha,p.job_pins(pol,job),ttl)
    io.write_exclusive(out,subject)
    return {'status':'unsigned_exact_issue_create_subject_created',
            'subject_sha256':p.sha(p.canonical(subject)),
            'operation_sha256':subject['operation_sha256'],
            'original_ec217_human_approval_independently_rechecked':False,
            'network_requested':False}


def vote(role: str, subject_file: str,keyfile: str,out: str) -> dict:
    subject=p.validate_subject(io.read_doc(subject_file,8192))
    p.private_file(keyfile,64)
    key=io.private_from_file(keyfile)
    document={'schema':p.VOTE_SCHEMA,'role':role,
              'subject_sha256':p.sha(p.canonical(subject)),
              'signer_public_hex':p.public_hex(key),
              'signature_ed25519':p.sign(role,subject,key)}
    io.write_exclusive(out,document)
    return {'status':'exact_issue_create_offline_vote_written',
            'role':role,'subject_sha256':document['subject_sha256'],
            'private_key_returned':False}


def assemble(subject_file: str,custodian_vote: str,authorizer_vote: str,
             custodian_pub: str,authorizer_pub: str,out: str) -> dict:
    subject=p.validate_subject(io.read_doc(subject_file,8192))
    p.need(custodian_pub != authorizer_pub,
           'EC287_INDEPENDENT_VOTE_KEYS_REQUIRED','permission_denied')
    signatures={}
    for role,source,pub in (('custodian',custodian_vote,custodian_pub),
                             ('authorizer',authorizer_vote,authorizer_pub)):
        v=io.read_doc(source,8192)
        p.need(set(v)=={'schema','role','subject_sha256',
                        'signer_public_hex','signature_ed25519'} and
               v['schema']==p.VOTE_SCHEMA and v['role']==role and
               v['subject_sha256']==p.sha(p.canonical(subject)) and
               v['signer_public_hex']==pub,
               'EC287_OFFLINE_VOTE_ROLE_OR_JOB_MISMATCH', 'permission_denied')
        p.verify(role,subject,v['signature_ed25519'],pub)
        signatures[role]=v['signature_ed25519']
    grant={'schema':p.GRANT_SCHEMA,'subject':subject,
           'custodian_signature_ed25519':signatures['custodian'],
           'authorizer_signature_ed25519':signatures['authorizer']}
    io.write_exclusive(out,grant)
    return {'status':'exact_issue_create_two_vote_grant_assembled',
            'grant_sha256':p.sha(p.canonical(grant)),
            'remote_create_attempted':False}


def create(*,socket_path: str,grant_file:str,policy_sha:str,
           server_pub:str,timeout:float=45) -> tuple[int,dict]:
    p.need(p.plain_abs(socket_path) and len(socket_path.encode())<100,
           'EC287_CLIENT_SOCKET_INVALID')
    p.need(type(policy_sha) is str and io.HASH.fullmatch(policy_sha) is not None,
           'EC287_CLIENT_POLICY_SHA_INVALID')
    io.pub_from_hex(server_pub)
    grant=io.read_doc(grant_file,p.MAX_RPC)
    p.need(type(grant) is dict and grant.get('schema')==p.GRANT_SCHEMA and
           type(grant.get('subject')) is dict,
           'EC287_CLIENT_OFFLINE_GRANT_INVALID')
    subject=p.validate_subject(grant['subject'])
    p.need(subject['policy_sha256']==policy_sha,
           'EC287_CLIENT_POLICY_BINDING_MISMATCH','permission_denied')
    req={'schema':p.REQUEST_SCHEMA,'nonce':secrets.token_hex(16),'grant':grant}
    raw=p.canonical(req)+b'\n'
    p.need(len(raw)<=p.MAX_RPC,'EC287_RPC_REQUEST_TOO_LARGE')
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(socket_path)
            connection.sendall(raw)
            response=bytearray()
            while len(response)<=p.MAX_REPLY:
                part=connection.recv(min(4096,p.MAX_REPLY+1-len(response)))
                if not part:break
                response.extend(part)
                if b'\n' in part:break
    except (OSError,TimeoutError) as exc:
        raise p.HostError('EC287_REMOTE_EFFECT_UNKNOWN_TRANSPORT_RECONCILE_NO_RETRY',
                          'unavailable') from exc
    p.need(response.endswith(b'\n') and response.count(b'\n')==1 and
           len(response)<=p.MAX_REPLY,
           'EC287_SIGNED_REPLY_MISSING_EFFECT_UNKNOWN_NO_RETRY','unavailable')
    try:
        reply=io.parse(bytes(response[:-1]),p.MAX_REPLY)
        result=p.verify_reply(reply,req,server_pub,policy_sha,int(time.time()))
    except (p.HostError,io.HostError,ValueError,KeyError,TypeError) as exc:
        raise p.HostError('EC287_SIGNED_REPLY_UNTRUSTED_EFFECT_UNKNOWN_NO_RETRY',
                          'unavailable') from exc
    unknown=(result.get('remote_effect_outcome_unknown') is True or
             result.get('same_request_replay_blocked') is True or
             (result.get('durable_attempt_barrier_recorded') is True and
              result.get('provider_reported_created') is False))
    output={'schema':p.RESULT_SCHEMA,'verified_server_signature':True,
            'result':result,'signed_reply':reply,
            'remote_effect_outcome_unknown':unknown,
            'provider_reported_created_not_independently_rechecked':
                result.get('provider_reported_created') is True,
            'private_issue_text_or_token_returned':False,
            'business_repository_written':False,
            'real_provider_or_organizational_authority_verified_by_ces':False,
            'automatic_post_retry_allowed':False}
    return result['exit_code'],output


def parser() -> argparse.ArgumentParser:
    a=argparse.ArgumentParser(description='EC287 original EC217/218 exact one-shot IssueCreate host')
    sub=a.add_subparsers(dest='command',required=True)
    x=sub.add_parser('keygen-offline')
    x.add_argument('--private-out',required=True)
    x=sub.add_parser('prepare-job')
    x.add_argument('--source-json',required=True)
    x.add_argument('--out',required=True)
    x=sub.add_parser('inspect-job')
    x.add_argument('--job-file',required=True)
    x=sub.add_parser('prepare-policy')
    for option in ('job-file','trust-file','access-file','token-file',
                   'reservation-db','attempt-db','host-grant-db',
                   'custodian-public-hex','authorizer-public-hex',
                   'server-public-hex','out'):
        x.add_argument('--'+option,required=True)
    x.add_argument('--allowed-uid',type=int,action='append',required=True)
    x.add_argument('--enable-exact-remote-create',action='store_true')
    x=sub.add_parser('prepare-offline')
    for option in ('policy-file','policy-sha256','uid','ttl-seconds','out'):
        x.add_argument('--'+option,required=True,
                       type=int if option in ('uid','ttl-seconds') else str)
    for role in ('custodian','authorizer'):
        x=sub.add_parser('sign-'+role+'-offline')
        for opt in ('subject-file','private-key-file','out'):
            x.add_argument('--'+opt,required=True)
    x=sub.add_parser('assemble-offline')
    for opt in ('subject-file','custodian-vote','authorizer-vote',
                'custodian-public-hex','authorizer-public-hex','out'):
        x.add_argument('--'+opt,required=True)
    x=sub.add_parser('serve')
    for opt in ('socket','policy-file','policy-sha256','server-private-key'):
        x.add_argument('--'+opt,required=True)
    x=sub.add_parser('create')
    for opt in ('socket','grant-file','policy-sha256','server-public-hex'):
        x.add_argument('--'+opt,required=True)
    x.add_argument('--pretty',action='store_true')
    return a


def main(argv: list[str]|None=None) -> int:
    a=parser().parse_args(argv)
    try:
        if a.command=='keygen-offline':
            result=old_op._keygen(a.private_out)
            output={'schema':'ces.ec287.keygen.v1',
                    'public_hex':result['public_hex'],
                    'private_key_returned':False}
        elif a.command=='prepare-job':
            output=prepare_job(a.source_json,a.out)
        elif a.command=='inspect-job':
            raw=p.private_file(a.job_file,p.MAX_JOB)
            job=p.validate_job(io.parse(raw,p.MAX_JOB))
            output={'schema':'ces.ec287.inspect_private_job.v1',
                    'status':'private_exact_issue_job_observed_not_authorized',
                    'job_sha256':p.sha(raw),
                    'operation_sha256':p.cw.operation_sha256(job['intent']),
                    'approval_sha256':p.sha(p.canonical(asdict(job['approval']))),
                    'private_issue_title_or_body_returned':False,
                    'network_requested':False}
        elif a.command=='prepare-policy':
            output=prepare_policy(job_file=a.job_file,trust_file=a.trust_file,
                access_file=a.access_file,token_file=a.token_file,
                reservation_db=a.reservation_db,attempt_db=a.attempt_db,
                host_grant_db=a.host_grant_db,allowed_uids=a.allowed_uid,
                custodian_pub=a.custodian_public_hex,
                authorizer_pub=a.authorizer_public_hex,
                server_pub=a.server_public_hex,out=a.out,
                explicit_enable=a.enable_exact_remote_create)
        elif a.command=='prepare-offline':
            output=prepare_subject(a.policy_file,a.policy_sha256,
                                   a.uid,a.ttl_seconds,a.out)
        elif a.command in ('sign-custodian-offline','sign-authorizer-offline'):
            role=a.command.split('-')[1]
            output=vote(role,a.subject_file,a.private_key_file,a.out)
        elif a.command=='assemble-offline':
            output=assemble(a.subject_file,a.custodian_vote,a.authorizer_vote,
                            a.custodian_public_hex,a.authorizer_public_hex,a.out)
        elif a.command=='serve':
            with daemon.IssueCreateHostServer(
                path=a.socket,policy_path=a.policy_file,
                policy_sha=a.policy_sha256,
                private_key_file=a.server_private_key) as host:
                host.serve_forever(poll_interval=.25)
            return 0
        elif a.command=='create':
            rc,output=create(socket_path=a.socket,grant_file=a.grant_file,
                policy_sha=a.policy_sha256,server_pub=a.server_public_hex)
            print(json.dumps(output,ensure_ascii=True,sort_keys=True,
                indent=2 if a.pretty else None,
                separators=None if a.pretty else (',',':')))
            return rc
        else:
            raise AssertionError('unhandled command')
        print(p.canonical(output).decode('ascii'))
        return 0
    except (p.HostError,io.HostError,OSError,ValueError) as exc:
        code=exc.code if isinstance(exc,(p.HostError,io.HostError)) else \
             'EC287_OWNER_OPERATOR_UNAVAILABLE'
        status=exc.status if isinstance(exc,(p.HostError,io.HostError)) else 'unavailable'
        if status not in ('invalid_input','permission_denied','unavailable'):
            status='unavailable'
        unknown=a.command=='create' and status=='unavailable'
        doc=p.denial(code,status,remote_effect_outcome_unknown=unknown)
        print(p.canonical(doc).decode('ascii'))
        return doc['exit_code']


if __name__=='__main__':
    raise SystemExit(main())
