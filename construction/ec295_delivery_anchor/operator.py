#!/usr/bin/env python3
"""EC295 offline operator: seal EC294 signed evidence; compare external pins.

No socket, HTTP, HMAC key or EC225 write credentials are used here. This file
is safe to deploy with *public* policy and signed receipts to a second system.
"""
from __future__ import annotations

import argparse
import json
import hashlib
import os
from pathlib import Path
import time

from cryptography.hazmat.primitives import serialization
from ec279_finding_query_host import protocol as io
from ec279_finding_query_host import operator as shared
from ec294_delivery_reconcile_host import protocol as old
from . import anchor as a


def store(path: str, doc: dict, limit: int) -> str:
    data = a.canonical(doc) + b'\n'
    a.need(len(data) <= limit, 'EC295_OUTPUT_EXCEEDS_DEFINED_BUDGET')
    # Original EC279 helper does 0600 exclusive creation + fsync file + parent.
    # Bound it to its 24K output budget? EC295 receipts can be >24K, so use
    # equivalent exclusive write with a larger EC295-specific size bound.
    a.need(type(path) is str and os.path.isabs(path) and len(path) <= 4096,
           'EC295_ABSOLUTE_OUTPUT_PATH_REQUIRED')
    try:
        old.prev.previous.private_parent(path)
    except Exception as exc:
        raise a.AnchorError('EC295_OUTPUT_PRIVATE_OWNER_PARENT_REQUIRED',
                            'permission_denied') from exc
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os,'O_NOFOLLOW',0), 0o600)
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=True) as out:
            fd = None
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        parent = os.open(str(Path(path).parent),os.O_RDONLY |
                         getattr(os,'O_DIRECTORY',0) |
                         getattr(os,'O_NOFOLLOW',0))
        try:os.fsync(parent)
        finally:os.close(parent)
    except OSError as exc:
        raise a.AnchorError('EC295_EXCLUSIVE_OUTPUT_OR_FSYNC_UNAVAILABLE',
                            'unavailable') from exc
    finally:
        if fd is not None:os.close(fd)
    return a.sha(doc)


def load(path: str, limit: int) -> dict:
    return io.read_doc(path,limit)


def policy(path: str, pin: str) -> dict:
    return a.load_policy(path,pin)


def create_policy(*,original_policy_file: str, original_policy_sha256: str,
                  operation_id: str, job_sha256: str,
                  keeper_public_hex: str, witness_public_hex: str, out: str) -> dict:
    doc = a.make_policy(original_policy_file,original_policy_sha256,
            operation_id,job_sha256,keeper_public_hex,witness_public_hex)
    store(out,doc,a.MAX_POLICY_BYTES)
    # Output JSON includes trailing newline; pin exact raw bytes, not canonical digest.
    actual = hashlib.sha256(a.canonical(doc)+b'\n').hexdigest()
    return {'schema':'ces.ec295.policy_prepared.v1','policy_sha256':actual,
            'ec294_policy_sha256':original_policy_sha256,
            'original_ec225_submit_or_status_query_executed':False}


def read_evidence(response_file: str, grant_file: str,
                  read_grant_file: str | None) -> dict:
    response = load(response_file,a.MAX_EVIDENCE_BYTES)
    grant = load(grant_file,a.MAX_EVIDENCE_BYTES)
    read = load(read_grant_file,a.MAX_EVIDENCE_BYTES) if read_grant_file else None
    return {'schema':a.EVIDENCE_SCHEMA,'response':response,
            'grant':grant,'read_grant':read}


def prepare(*,policy_file: str, policy_sha256: str, response_file: str,
            grant_file: str, read_grant_file: str | None, previous_file: str | None,
            expected_previous_tip: str | None, out: str) -> dict:
    pol = policy(policy_file,policy_sha256)
    evidence = read_evidence(response_file,grant_file,read_grant_file)
    prev = None
    if previous_file is not None:
        a.need(a.valid_sha(expected_previous_tip) and
               expected_previous_tip != a.GENESIS,
               'EC295_EXTERNAL_PREVIOUS_TIP_REQUIRED','permission_denied')
        prev = load(previous_file,a.MAX_CHECKPOINT_BYTES)
        a.need(a.sha(prev) == expected_previous_tip,
               'EC295_PREVIOUS_CHECKPOINT_NOT_EXTERNALLY_PINNED',
               'permission_denied')
        a.verify_checkpoint(prev,pol,policy_sha256)
    else:
        a.need(expected_previous_tip in (None,a.GENESIS),
               'EC295_FIRST_CHECKPOINT_REQUIRES_EXPLICIT_EMPTY_ANCESTRY')
    prepared = a.prepared_from_evidence(evidence,pol,policy_sha256,prev)
    digest = store(out,prepared,a.MAX_PREPARED_BYTES)
    return {'schema':'ces.ec295.prepared_checkpoint.v1',
            'prepared_sha256':digest,'sequence':prepared['claim']['sequence'],
            'audit_event_count':prepared['claim']['audit_event_count'],
            'audit_head_hmac_sha256':prepared['claim']['audit_head_hmac_sha256'],
            'original_send_or_status_query_executed':False,
            'trusted_external_off_host_pin_retained':False}


def offline_vote(*,role: str, policy_file: str, policy_sha256: str,
                 prepared_file: str, private_key_file: str, out: str) -> dict:
    a.need(role in a.DOMAINS,'EC295_OFFLINE_ROLE_INVALID')
    pol = policy(policy_file,policy_sha256)
    prep = load(prepared_file,a.MAX_PREPARED_BYTES)
    claim = a.validate_prepared(prep,pol,policy_sha256)
    key = io.private_from_file(private_key_file)
    public = key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
              format=serialization.PublicFormat.Raw).hex()
    a.need(public == pol[role+'_public_hex'],
           'EC295_OFFLINE_PRIVATE_KEY_IS_NOT_PINNED_ROLE','permission_denied')
    vote={'schema':a.VOTE_SCHEMA,'role':role,
          'prepared_sha256':a.sha(prep),
          'signature_ed25519':a.sign(role,claim,key)}
    store(out,vote,12000)
    return {'schema':'ces.ec295.offline_vote_created.v1','role':role,
            'prepared_sha256':vote['prepared_sha256'],
            'private_key_returned':False,'no_original_operation_retried':True}


def assemble(*,policy_file: str, policy_sha256: str, prepared_file: str,
             keeper_vote_file: str, witness_vote_file: str, out: str) -> dict:
    pol = policy(policy_file,policy_sha256)
    prep = load(prepared_file,a.MAX_PREPARED_BYTES)
    claim = a.validate_prepared(prep,pol,policy_sha256)
    signs = {}
    for role,file in (('keeper',keeper_vote_file),('witness',witness_vote_file)):
        vote=load(file,12000)
        a.exact(vote,a.VOTE_KEYS,'EC295_OFFLINE_VOTE_FIELDS_INVALID')
        a.need(vote['schema'] == a.VOTE_SCHEMA and
               vote['role'] == role and vote['prepared_sha256'] == a.sha(prep),
               'EC295_VOTE_NOT_FOR_EXACT_PREPARED_EVIDENCE')
        a.verify_signature(role,claim,vote['signature_ed25519'],
                           pol[role+'_public_hex'])
        signs[role+'_signature_ed25519'] = vote['signature_ed25519']
    checkpoint={'schema':a.CHECKPOINT_SCHEMA,
                'claim':claim,'evidence':prep['evidence'],**signs}
    a.verify_checkpoint(checkpoint,pol,policy_sha256)
    store(out,checkpoint,a.MAX_CHECKPOINT_BYTES)
    return {'schema':'ces.ec295.signed_checkpoint_created.v1',
            'sequence':claim['sequence'],'signed_checkpoint_tip_sha256':a.sha(checkpoint),
            'audit_head_hmac_sha256':claim['audit_head_hmac_sha256'],
            'off_host_immutable_retention_and_independent_external_pin_required':True,
            'retention_or_independence_proven':False,
            'live_provider_or_send_requested':False}


def verify(*,policy_file: str, policy_sha256: str, checkpoint_files: list[str],
           expected_tip: str) -> dict:
    pol = policy(policy_file,policy_sha256)
    a.need(1 <= len(checkpoint_files) <= a.MAX_CHECKPOINTS,
           'EC295_ORDERED_CHECKPOINT_LIST_REQUIRED')
    chain = [load(path,a.MAX_CHECKPOINT_BYTES) for path in checkpoint_files]
    return a.verify_chain(chain,pol,policy_sha256,expected_tip)


def compare(*,policy_file: str, policy_sha256: str,
            checkpoint_files: list[str], expected_tip: str,
            response_file: str, grant_file: str, minimum_reply_unix: int) -> dict:
    """Compare independently obtained NEW signed EC294 network-FREE Readback.

    This command never fetches a status and NEVER contacts EC294. The user
    must separately run a new, authorized EC294 Readback *after* their own
    independent minimum wall time and supply its signed response+grant.
    """
    verified = verify(policy_file=policy_file,policy_sha256=policy_sha256,
                      checkpoint_files=checkpoint_files,expected_tip=expected_tip)
    pol = policy(policy_file,policy_sha256)
    evidence=read_evidence(response_file,grant_file,None)
    observed=a.verify_evidence(evidence,pol)
    last=load(checkpoint_files[-1],a.MAX_CHECKPOINT_BYTES)['claim']
    a.need(type(minimum_reply_unix) is int and 946684800<=minimum_reply_unix<=4102444800,
           'EC295_EXTERNAL_MINIMUM_OBSERVATION_TIME_REQUIRED')
    a.need(observed['ec294_operation_mode']=='readback' and
           observed['ec294_reply_issued_at_unix']>=minimum_reply_unix and
           observed['ec294_reply_issued_at_unix']>last['ec294_reply_issued_at_unix'] and
           observed['ec294_signed_reply_sha256']!=last['ec294_signed_reply_sha256'] and
           observed['audit_event_count']==last['audit_event_count'] and
           observed['audit_head_hmac_sha256']==last['audit_head_hmac_sha256'],
           'EC295_FRESH_READBACK_NOT_CONSISTENT_WITH_EXTERNAL_ANCHOR',
           'permission_denied')
    # Original EC294 signed readback itself required its independently approved
    # external expected head; verify the signer really authorized the pinned tip.
    grant=load(grant_file,a.MAX_EVIDENCE_BYTES)
    a.need(grant['subject']['expected_head_hmac_sha256']==last['audit_head_hmac_sha256'],
           'EC295_READBACK_NOT_APPROVED_AGAINST_EXTERNALLY_PINNED_HEAD',
           'permission_denied')
    return {**verified,'status':'verified_offline_current_signed_readback_match',
        'fresh_ec294_local_readback_receipt_verified':True,
        'latest_signed_reply_issued_at_unix':observed['ec294_reply_issued_at_unix'],
        'current_original_ec227_audit_storage_checked':False,
        'current_ec294_readback_signed_claim_matches_external_tip':True,
        'live_hmac_disk_replay_performed_by_ec295':False,
        'trusted_clock_and_external_storage_independently_proven':False}


def parser() -> argparse.ArgumentParser:
    ap=argparse.ArgumentParser(description='EC295 portable delivery audit anchor; offline only')
    sub=ap.add_subparsers(dest='command',required=True)
    c=sub.add_parser('keygen-offline')
    c.add_argument('--private-out',required=True)
    c=sub.add_parser('prepare-policy')
    for opt in ('original-policy-file','original-policy-sha256','operation-id',
                'job-sha256','keeper-public-hex','witness-public-hex','out'):
        c.add_argument('--'+opt,required=True)
    c=sub.add_parser('prepare')
    for opt in ('policy-file','policy-sha256','response-file','grant-file','out'):
        c.add_argument('--'+opt,required=True)
    c.add_argument('--read-grant-file')
    c.add_argument('--previous-file')
    c.add_argument('--expected-previous-tip')
    for role in a.DOMAINS:
        c=sub.add_parser('sign-'+role+'-offline')
        for opt in ('policy-file','policy-sha256','prepared-file','private-key-file','out'):
            c.add_argument('--'+opt,required=True)
    c=sub.add_parser('assemble')
    for opt in ('policy-file','policy-sha256','prepared-file','keeper-vote-file',
                'witness-vote-file','out'):
        c.add_argument('--'+opt,required=True)
    c=sub.add_parser('verify-chain')
    for opt in ('policy-file','policy-sha256','expected-tip'):
        c.add_argument('--'+opt,required=True)
    c.add_argument('--checkpoint-file',action='append',required=True)
    c=sub.add_parser('compare-readback')
    for opt in ('policy-file','policy-sha256','expected-tip','response-file','grant-file'):
        c.add_argument('--'+opt,required=True)
    c.add_argument('--checkpoint-file',action='append',required=True)
    c.add_argument('--minimum-reply-unix',required=True,type=int)
    return ap


def main(argv=None) -> int:
    args=parser().parse_args(argv)
    try:
        if args.command=='keygen-offline':
            doc=shared._keygen(args.private_out)
            result={'schema':'ces.ec295.offline_keygen.v1',
                    'public_hex':doc['public_hex'], 'private_key_returned':False}
        elif args.command=='prepare-policy':
            result=create_policy(original_policy_file=args.original_policy_file,
                original_policy_sha256=args.original_policy_sha256,
                operation_id=args.operation_id,job_sha256=args.job_sha256,
                keeper_public_hex=args.keeper_public_hex,
                witness_public_hex=args.witness_public_hex,out=args.out)
        elif args.command=='prepare':
            result=prepare(policy_file=args.policy_file,policy_sha256=args.policy_sha256,
                response_file=args.response_file,grant_file=args.grant_file,
                read_grant_file=args.read_grant_file,previous_file=args.previous_file,
                expected_previous_tip=args.expected_previous_tip,out=args.out)
        elif args.command in ('sign-keeper-offline','sign-witness-offline'):
            result=offline_vote(role=args.command.split('-')[1],
                policy_file=args.policy_file,policy_sha256=args.policy_sha256,
                prepared_file=args.prepared_file,private_key_file=args.private_key_file,
                out=args.out)
        elif args.command=='assemble':
            result=assemble(policy_file=args.policy_file,policy_sha256=args.policy_sha256,
                prepared_file=args.prepared_file,keeper_vote_file=args.keeper_vote_file,
                witness_vote_file=args.witness_vote_file,out=args.out)
        elif args.command=='verify-chain':
            result=verify(policy_file=args.policy_file,policy_sha256=args.policy_sha256,
                checkpoint_files=args.checkpoint_file,expected_tip=args.expected_tip)
        elif args.command=='compare-readback':
            result=compare(policy_file=args.policy_file,policy_sha256=args.policy_sha256,
                checkpoint_files=args.checkpoint_file,expected_tip=args.expected_tip,
                response_file=args.response_file,grant_file=args.grant_file,
                minimum_reply_unix=args.minimum_reply_unix)
        else:raise AssertionError('unhandled action')
        print(json.dumps(result,sort_keys=True,separators=(',',':')))
        return 0
    except Exception as exc:
        status=exc.status if isinstance(exc,a.AnchorError) else 'unavailable'
        reason=exc.code if isinstance(exc,a.AnchorError) else 'EC295_OFFLINE_OPERATION_FAILED'
        print(json.dumps({'schema':'ces.ec295.offline_denial.v1','status':status,
            'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}[status],
            'reason_code':reason,'original_message_or_status_query_retried':False,
            'external_anchoring_success_claimed':False},sort_keys=True,
            separators=(',',':')))
        return {'permission_denied':3,'invalid_input':4,'unavailable':5}[status]

if __name__=='__main__':
    raise SystemExit(main())
