#!/usr/bin/env python3
"""EC285 operator CLI: private exact job, two offline approvals, real EC229 publish.

The server never signs an operator vote. A client sees only the exact original
Git sandbox receipt signed by the independently provisioned server key.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import time

from ec279_finding_query_host import operator as old_op
from ec279_finding_query_host import protocol as io
from . import protocol as p, daemon


def create_private(path: str,doc: dict,limit: int) -> str:
    p.need(p.plain_abs(path),'EC285_PRIVATE_OUTPUT_PATH_INVALID')
    raw=p.canonical(doc)+b'\n'
    p.need(len(raw)<=limit,'EC285_PRIVATE_OUTPUT_TOO_LARGE')
    fd=None
    try:
        # Creation is exclusive: neither existing receipts nor Git operations
        # can be overwritten by a later operator request.
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                   getattr(os,'O_NOFOLLOW',0),0o600)
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as stream:
            fd=None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory=os.open(os.path.dirname(path),os.O_RDONLY|
                          getattr(os,'O_DIRECTORY',0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise p.HostError('EC285_PRIVATE_OUTPUT_CREATION_FAILED','unavailable') from exc
    finally:
        if fd is not None:
            os.close(fd)
    return p.sha(raw)


def public_inspection(job: dict, job_sha: str, *, created: bool=False) -> dict:
    return {'schema':p.INSPECTION_SCHEMA,
            'status':('private_exact_docs_job_created_two_votes_pending' if created
                      else 'private_exact_docs_job_observed_not_approved'),
            'job_sha256':job_sha,**p.job_pins(job),
            'private_document_count':len(job['request']['documents']),
            'private_document_text_returned':False,
            'original_four_ec229_signatures_locally_verified':False,
            'private_ref_written':False,
            'organization_review_authenticated':False}


def prepare_job(source: str,out: str) -> dict:
    job=p.validate_job(io.parse(p.private_file(source,p.MAX_JOB),p.MAX_JOB))
    digest=create_private(out,job,p.MAX_JOB)
    return public_inspection(job,digest,created=True)


def prepare_policy(*,job_file: str,allowed_uids: list[int],
                   custodian_pub: str,authorizer_pub: str,
                   server_pub: str,out: str) -> dict:
    raw=p.private_file(job_file,p.MAX_JOB)
    job=p.validate_job(io.parse(raw,p.MAX_JOB))
    policy=p.validate_policy({'schema':p.POLICY_SCHEMA,'job_file':job_file,
       'job_sha256':p.sha(raw),'allowed_uids':sorted(set(allowed_uids)),
       'custodian_issuer_public_hex':custodian_pub,
       'authorizer_issuer_public_hex':authorizer_pub,
       'server_public_hex':server_pub})
    keys={custodian_pub,authorizer_pub,server_pub}
    originals={job['access'][k] for k in (
        'policy_public_hex','reviewer_public_hex',
        'revocation_public_hex','side_effect_public_hex')}
    p.need(keys.isdisjoint(originals),
           'EC285_HOST_KEYS_COLLIDE_WITH_EC229_REVIEWERS','unavailable')
    digest=create_private(out,policy,p.MAX_POLICY)
    return {'schema':p.POLICY_SCHEMA,'status':'host_policy_created_not_serving',
            'policy_sha256':digest,'job_sha256':p.sha(raw),
            'private_documents_returned':False}


def vote(role: str,subject_file: str,key_file: str,out: str) -> dict:
    s=p.validate_subject(io.read_doc(subject_file,8192))
    key=io.private_from_file(key_file)
    document={'schema':p.VOTE_SCHEMA,'role':role,
              'subject_sha256':p.sha(p.canonical(s)),
              'signer_public_hex':p.public_hex(key),
              'signature_ed25519':p.sign(role,s,key)}
    io.write_exclusive(out,document)
    return {'status':'offline_exact_docs_vote_written',
            'role':role,'subject_sha256':document['subject_sha256'],
            'private_key_returned':False}


def assemble(subject_file: str,custodian_vote: str,
             authorizer_vote: str,custodian_pub: str,
             authorizer_pub: str,out: str) -> dict:
    s=p.validate_subject(io.read_doc(subject_file,8192))
    p.need(custodian_pub!=authorizer_pub,
           'EC285_DISTINCT_HOST_VOTERS_REQUIRED','permission_denied')
    signatures={}
    for role,filename,pub in (
        ('custodian',custodian_vote,custodian_pub),
        ('authorizer',authorizer_vote,authorizer_pub)):
        v=io.read_doc(filename,8192)
        p.need(type(v) is dict and set(v)=={'schema','role',
              'subject_sha256','signer_public_hex','signature_ed25519'} and
              v['schema']==p.VOTE_SCHEMA and v['role']==role and
              v['subject_sha256']==p.sha(p.canonical(s)) and
              v['signer_public_hex']==pub,
              'EC285_VOTE_ROLE_SCOPE_OR_SIGNER_INVALID','permission_denied')
        p.verify(role,s,v['signature_ed25519'],pub)
        signatures[role]=v['signature_ed25519']
    grant={'schema':p.GRANT_SCHEMA,'subject':s,
           'custodian_signature_ed25519':signatures['custodian'],
           'authorizer_signature_ed25519':signatures['authorizer']}
    io.write_exclusive(out,grant)
    return {'status':'independent_host_two_vote_docs_grant_created',
            'grant_sha256':p.sha(p.canonical(grant)),
            'local_private_git_write_performed':False}


def publish(*,socket_path: str,grant_file: str,
            policy_sha: str,server_pub: str,
            timeout: float=90) -> tuple[int,dict]:
    p.need(p.plain_abs(socket_path) and len(socket_path.encode()) < 100,
           'EC285_CLIENT_SOCKET_INVALID')
    p.need(type(policy_sha) is str and io.HASH.fullmatch(policy_sha) is not None,
           'EC285_CLIENT_POLICY_PIN_INVALID')
    io.pub_from_hex(server_pub)
    grant=io.read_doc(grant_file,p.MAX_RPC)
    p.need(type(grant) is dict and grant.get('schema')==p.GRANT_SCHEMA and
           type(grant.get('subject')) is dict,
           'EC285_CLIENT_TWO_VOTE_GRANT_MISSING')
    subject=p.validate_subject(grant['subject'])
    p.need(subject['policy_sha256']==policy_sha,
           'EC285_CLIENT_POLICY_VOTE_MISMATCH','permission_denied')
    req={'schema':p.REQUEST_SCHEMA,'nonce':secrets.token_hex(16),'grant':grant}
    raw=p.canonical(req)+b'\n'
    p.need(len(raw)<=p.MAX_RPC,'EC285_RPC_OUTBOUND_TOO_LARGE')
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(socket_path)
            conn.sendall(raw)
            answer=bytearray()
            while len(answer)<=p.MAX_REPLY:
                part=conn.recv(min(8192,p.MAX_REPLY+1-len(answer)))
                if not part:
                    break
                answer.extend(part)
                if b'\n' in part:
                    break
    except (OSError,TimeoutError) as exc:
        raise p.HostError('EC285_TRANSPORT_UNKNOWN_INSPECT_PRIVATE_REF_NO_AUTO_RETRY',
                          'unavailable') from exc
    p.need(answer.endswith(b'\n') and answer.count(b'\n')==1 and
           0<len(answer)<=p.MAX_REPLY,
           'EC285_SIGNED_REPLY_MISSING_PRIVATE_GIT_OUTCOME_UNKNOWN','unavailable')
    reply=io.parse(bytes(answer[:-1]),p.MAX_REPLY)
    try:
        result=p.verify_reply(reply,req,server_pub,policy_sha,int(time.time()))
    except (p.HostError,io.HostError,TypeError,KeyError,ValueError) as exc:
        # Once a request left this process an untrusted/forged reply cannot
        # establish whether the original Git side effect occurred.
        raise p.HostError('EC285_UNTRUSTED_SIGNED_REPLY_OUTCOME_UNKNOWN_INSPECT_REF',
                          'unavailable') from exc
    return result['exit_code'],{'schema':p.RESULT_SCHEMA,
        'verified_server_signature':True,'result':result,
        'signed_reply':reply,'original_source_repository_written':False,
        'production_publication_verified':False,
        'real_organizational_role_separation_verified':False,
        'private_local_git_effect_may_have_occurred':(
             result.get('claim_committed') is True or
             result.get('local_effect_outcome_unknown') is True)}


def parser() -> argparse.ArgumentParser:
    ap=argparse.ArgumentParser(description=
        'EC285 independent dual-sign original EC229 private Git docs sandbox host')
    sub=ap.add_subparsers(dest='command',required=True)
    x=sub.add_parser('keygen-offline')
    x.add_argument('--private-out',required=True)
    x=sub.add_parser('prepare-job',help='consume owner-only complete EC229 job JSON')
    x.add_argument('--source-json',required=True)
    x.add_argument('--out',required=True)
    x=sub.add_parser('inspect-job')
    x.add_argument('--job-file',required=True)
    x=sub.add_parser('prepare-policy')
    for option in ('job-file','custodian-public-hex',
                   'authorizer-public-hex','server-public-hex','out'):
        x.add_argument('--'+option,required=True)
    x.add_argument('--allowed-uid',type=int,action='append',required=True)
    x=sub.add_parser('prepare-offline')
    for option in ('uid','policy-sha256','job-sha256','project-id','repository-id',
                   'base-commit','manifest-sha256','allowlist-sha256',
                   'target-binding-sha256','docs-backend-sha256',
                   'ttl-seconds','out'):
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
    x=sub.add_parser('publish')
    for opt in ('socket','grant-file','policy-sha256','server-public-hex'):
        x.add_argument('--'+opt,required=True)
    x.add_argument('--pretty',action='store_true')
    return ap


def main(argv: list[str]|None=None) -> int:
    a=parser().parse_args(argv)
    try:
        if a.command=='keygen-offline':
            generated=old_op._keygen(a.private_out)
            output={'schema':'ces.ec285.host_keygen.v1',
                    'public_hex':generated['public_hex'],
                    'private_key_returned':False}
        elif a.command=='prepare-job':
            output=prepare_job(a.source_json,a.out)
        elif a.command=='inspect-job':
            raw=p.private_file(a.job_file,p.MAX_JOB)
            output=public_inspection(p.validate_job(io.parse(raw,p.MAX_JOB)),p.sha(raw))
        elif a.command=='prepare-policy':
            output=prepare_policy(job_file=a.job_file,
                allowed_uids=a.allowed_uid,custodian_pub=a.custodian_public_hex,
                authorizer_pub=a.authorizer_public_hex,
                server_pub=a.server_public_hex,out=a.out)
        elif a.command=='prepare-offline':
            subject=p.new_subject(uid=a.uid,policy_sha=a.policy_sha256,
                job_sha=a.job_sha256,project_id=a.project_id,
                repository_id=a.repository_id,base_commit=a.base_commit,
                manifest_sha=a.manifest_sha256,allowlist_sha=a.allowlist_sha256,
                target_sha=a.target_binding_sha256,backend_sha=a.docs_backend_sha256,
                ttl=a.ttl_seconds)
            io.write_exclusive(a.out,subject)
            output={'status':'unsigned_exact_private_docs_subject_created',
                    'subject_sha256':p.sha(p.canonical(subject))}
        elif a.command in ('sign-custodian-offline','sign-authorizer-offline'):
            output=vote(a.command.split('-')[1],a.subject_file,a.private_key_file,a.out)
        elif a.command=='assemble-offline':
            output=assemble(a.subject_file,a.custodian_vote,a.authorizer_vote,
                a.custodian_public_hex,a.authorizer_public_hex,a.out)
        elif a.command=='serve':
            with daemon.DocsHostServer(path=a.socket,policy_path=a.policy_file,
                policy_sha=a.policy_sha256,private_key_file=a.server_private_key) as host:
                host.serve_forever(poll_interval=.25)
            return 0
        elif a.command=='publish':
            rc,output=publish(socket_path=a.socket,grant_file=a.grant_file,
                policy_sha=a.policy_sha256,server_pub=a.server_public_hex)
            print(json.dumps(output,ensure_ascii=True,sort_keys=True,
                indent=2 if a.pretty else None,
                separators=None if a.pretty else (',',':')))
            return rc
        else:
            raise AssertionError('unreachable command')
        print(p.canonical(output).decode())
        return 0
    except (p.HostError,io.HostError,OSError,ValueError) as exc:
        code=exc.code if isinstance(exc,(p.HostError,io.HostError)) else \
             'EC285_LOCAL_OPERATOR_UNAVAILABLE'
        status=exc.status if isinstance(exc,(p.HostError,io.HostError)) else 'unavailable'
        if status not in ('invalid_input','permission_denied','unavailable'):
            status='unavailable'
        result=p.denial(code,status,
            local_effect_outcome_unknown=(a.command=='publish' and status=='unavailable'))
        print(p.canonical(result).decode())
        return result['exit_code']


if __name__=='__main__':
    raise SystemExit(main())
