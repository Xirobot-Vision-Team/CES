#!/usr/bin/env python3
"""EC274 explicit off-host escrow enrollment; witness secrets only offline.

Workflow: prepare after complete EC272+273 verification and a fresh remote
read, independently inspect, obtain two offline witness votes, assemble,
then CAS advance the remote authority. Protected service only reads; it may
never propose, sign, advance or silently update a pinned head.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from ec266_source_provenance_host import provenance as prov
from ec269_emergency_recovery_host import recovery as rec
from ec269_emergency_recovery_host import serve as old_cli
from ec271_freshness_quorum_host import serve as fresh_cli
from ec273_rfc3161_timestamp_host import serve as ts_host
from ec273_rfc3161_timestamp_host import timeproof as tsa
from ec267_governed_source_host import governance as gov
from ec274_remote_escrow_host import escrow as esc


def _pairs(args:argparse.Namespace)->list[tuple[str,str]]:
    if len(args.freshness_witness_public)!=len(args.freshness_witness_public_sha256):
        esc.deny('EC274_PUBLIC_WITNESS_PIN_PAIR_REQUIRED')
    return list(zip(args.freshness_witness_public,args.freshness_witness_public_sha256))


def _client(args:argparse.Namespace,witnesses:dict[str,bytes],
            root:str,closure:str)->esc.RemoteClient:
    return esc.RemoteClient(host=args.escrow_host,port=int(args.escrow_port),
        namespace=args.escrow_namespace,
        ca_path=args.escrow_tls_ca,ca_pin=args.escrow_tls_ca_sha256,
        leaf_pin=args.escrow_tls_leaf_sha256,
        escrow_public_path=args.escrow_public,
        escrow_public_pin=args.escrow_public_sha256,
        witness_keys_map=witnesses,root=root,closure=closure)


def _get_verified_subject(args:argparse.Namespace)->tuple[dict,dict[str,bytes]]:
    parent=ts_host._tail_verified(args)  # verified full root/governance/checkpoints/live chain
    sealed=tsa.verify_timestamp(segment=args.freshness_chain,
        segment_sha256=args.freshness_chain_sha256,
        checkpoint_sha256=args.checkpoint_sha256,
        request=args.tsa_request,request_sha256=args.tsa_request_sha256,
        response=args.tsa_response,response_sha256=args.tsa_response_sha256,
        ca_bundle=args.tsa_ca_bundle,ca_bundle_sha256=args.tsa_ca_bundle_sha256,
        leaf_cert_sha256=args.tsa_leaf_cert_sha256,
        policy_oid=args.tsa_policy_oid,
        openssl_binary=args.tsa_openssl_binary,
        openssl_binary_sha256=args.tsa_openssl_binary_sha256,
        effective_now=gov._now()[0],maximum_age_seconds=int(args.tsa_max_age_seconds),
        minimum_time_unix=int(args.tsa_minimum_time_unix),
        intermediates=args.tsa_intermediates,
        intermediates_sha256=args.tsa_intermediates_sha256)
    _,newest,latest=tsa._tail(segment=args.freshness_chain,
        segment_sha256=args.freshness_chain_sha256,
        checkpoint_sha256=args.checkpoint_sha256)
    keys=esc.witness_keys(_pairs(args),args.escrow_public_sha256)
    subject=esc.progress(namespace=args.escrow_namespace,
        checkpoint_sha256=args.checkpoint_sha256,
        segment_sha256=args.freshness_chain_sha256,
        latest_receipt_sha256=latest,newest=newest,report=parent,
        timestamp=sealed,checkpoint_number=parent['sealed_checkpoint_number'],
        witness_pins=sorted(keys))
    return subject,keys


def prepare(args:argparse.Namespace)->dict:
    subject,keys=_get_verified_subject(args)
    client=_client(args,keys,subject['recovered_root_public_sha256'],
                   subject['closure_sha256'])
    previous,head=client.read(minimum_index=int(args.escrow_minimum_previous_index))
    if head!=esc._sha(args.escrow_expected_previous_sha256):
        esc.deny('EC274_REMOTE_HEAD_NOT_EQUAL_TO_OPERATOR_PREVIOUS_PIN')
    if previous is not None:
        old=previous['proposal']
        if (subject['freshness_sequence']!=old['freshness_sequence']+1 or
                subject['previous_receipt_sha256']!=old['latest_receipt_sha256']):
            esc.deny('EC274_PROPOSAL_MUST_EXTEND_LATEST_REMOTE_RECEIPT_BY_ONE')
    # Reject impossible checkpoint/epoch/time/receipt transitions before
    # inviting two independent offline witnesses to approve a proposal.
    pending={'record_index':1 if previous is None else previous['proposal']['record_index']+1,
        'previous_record_sha256':esc.ZERO if previous is None else esc.sha(esc.canonical(previous)),
        **subject}
    esc._check_transition(pending,previous)
    result=esc.prepare_proposal(subject,previous,output=args.output)
    return {**result,'ec272_full_chain_verified':True,
        'ec273_timestamp_signature_verified':True,
        'remote_previous_signed_nonce_read_verified':True}


def assemble(args:argparse.Namespace)->dict:
    keys=esc.witness_keys(_pairs(args))
    if len(args.vote)!=2 or len(args.vote_sha256)!=2:
        esc.deny('EC274_EXACT_TWO_VOTES_AND_PINS_REQUIRED')
    return esc.assemble(proposal_path=args.proposal,
        proposal_pin=args.proposal_sha256,
        vote_paths=list(zip(args.vote,args.vote_sha256)),keys=keys,
        namespace=args.escrow_namespace,
        root=args.root_sha256,closure=args.closure_sha256,
        output=args.output)


def advance(args:argparse.Namespace)->dict:
    keys=esc.witness_keys(_pairs(args),args.escrow_public_sha256)
    client=_client(args,keys,args.root_sha256,args.closure_sha256)
    original,current=client.read(minimum_index=int(args.escrow_minimum_previous_index))
    if current!=esc._sha(args.escrow_expected_previous_sha256):
        esc.deny('EC274_CAS_REMOTE_PREDECESSOR_CHANGED')
    raw=prov._bytes(args.record,esc.MAX_RECORD)
    if esc.sha(raw)!=esc._sha(args.record_sha256):
        esc.deny('EC274_LOCAL_ASSEMBLED_RECORD_PIN_MISMATCH')
    new=esc._parse(raw,esc.MAX_RECORD,'EC274_LOCAL_RECORD_NOT_CANONICAL')
    expected=esc._record(new,namespace=args.escrow_namespace,keys=keys,
        root=esc._sha(args.root_sha256),closure=esc._sha(args.closure_sha256),
        previous=original)
    seen,head=client.advance(new)
    if seen!=new or head!=expected:
        esc.deny('EC274_REMOTE_ACK_NOT_EQUAL_TO_PROPOSED_RECORD')
    # Independent second TLS/nonce round trip rechecks durable journal readback.
    persisted,persisted_head=client.read(minimum_index=new['proposal']['record_index'])
    if persisted!=new or persisted_head!=expected:
        esc.deny('EC274_REMOTE_DURABLE_READBACK_FAILED')
    return {'status':'partial','exit_code':2,
        'reason_code':'EC274_REMOTE_QUORUM_CAS_PERSISTED_AND_READBACK',
        'escrow_record_sha256':head,
        'escrow_record_index':new['proposal']['record_index'],
        'remote_nonce_bound_ack_and_new_readback_verified':True,
        'physical_remote_nonrollbackable_storage_verified':False}


def inspect(args:argparse.Namespace)->dict:
    keys=esc.witness_keys(_pairs(args),args.escrow_public_sha256)
    client=_client(args,keys,args.root_sha256,args.closure_sha256)
    entry,head=client.read(minimum_index=int(args.escrow_minimum_previous_index))
    return {'status':'partial','exit_code':2,
        'reason_code':'EC274_REMOTE_SIGNED_CURRENT_HEAD_READ',
        'escrow_record_sha256':head,
        'escrow_record_index':0 if entry is None else entry['proposal']['record_index'],
        'escrow_freshness_sequence':None if entry is None else entry['proposal']['freshness_sequence'],
        'escrow_governance_epoch':None if entry is None else entry['proposal']['governance_epoch'],
        'escrow_checkpoint_number':None if entry is None else entry['proposal']['checkpoint_number'],
        'escrow_signed_live_read_verified':True,
        'hardware_or_worm_antirollback_verified':False}


def parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser(description='EC274 explicit independently governed remote escrow operator')
    sub=p.add_subparsers(dest='action',required=True)
    remote=('escrow_host','escrow_port','escrow_namespace','escrow_tls_ca',
        'escrow_tls_ca_sha256','escrow_tls_leaf_sha256','escrow_public',
        'escrow_public_sha256')
    for action in ('prepare-proposal','sign-proposal','assemble-record','advance-remote','inspect-remote'):
        cmd=sub.add_parser(action)
        if action in ('prepare-proposal','advance-remote','inspect-remote'):
            old_cli._required(cmd,remote)
            cmd.add_argument('--escrow-minimum-previous-index',type=int,required=True)
        if action in ('prepare-proposal','advance-remote'):
            cmd.add_argument('--escrow-expected-previous-sha256',required=True)
        if action!='sign-proposal':
            cmd.add_argument('--freshness-witness-public',action='append',required=True)
            cmd.add_argument('--freshness-witness-public-sha256',action='append',required=True)
        if action=='prepare-proposal':
            original=('old_governance','old_governance_sha256','old_root_public',
                'old_root_public_sha256','charter','charter_sha256',
                'anchor_governance','anchor_governance_sha256',
                'governance_public','governance_public_sha256',
                'recovery_certificate','recovery_certificate_sha256',
                'witness_public','witness_public_sha256',
                'closure_certificate','closure_certificate_sha256',
                'governance_policy','governance_policy_sha256')
            tail=('checkpoint','checkpoint_sha256','freshness_chain',
                'freshness_chain_sha256','minimum_freshness_sequence',
                'expected_previous_receipt_sha256','minimum_checkpoint_number')
            tsa_opts=('tsa_request','tsa_request_sha256','tsa_response',
                'tsa_response_sha256','tsa_ca_bundle','tsa_ca_bundle_sha256',
                'tsa_leaf_cert_sha256','tsa_policy_oid','tsa_openssl_binary',
                'tsa_openssl_binary_sha256','tsa_max_age_seconds','tsa_minimum_time_unix')
            old_cli._required(cmd,original+tail+tsa_opts+('output',))
            old_cli._council_args(cmd)
            cmd.add_argument('--continuation-chain')
            cmd.add_argument('--continuation-chain-sha256')
            cmd.add_argument('--tsa-intermediates')
            cmd.add_argument('--tsa-intermediates-sha256')
            cmd.add_argument('--forbidden-public-sha256',action='append',default=[])
        elif action=='sign-proposal':
            old_cli._required(cmd,('proposal','proposal_sha256','witness_secret',
                'witness_public_sha256','output'))
        elif action=='assemble-record':
            old_cli._required(cmd,('proposal','proposal_sha256',
                'escrow_namespace','root_sha256','closure_sha256','output'))
            cmd.add_argument('--vote',action='append',required=True)
            cmd.add_argument('--vote-sha256',action='append',required=True)
        else:
            old_cli._required(cmd,('root_sha256','closure_sha256'))
            if action=='advance-remote':
                old_cli._required(cmd,('record','record_sha256'))
    return p


def main(argv:list[str]|None=None)->int:
    args=parser().parse_args(argv)
    try:
        if args.action=='prepare-proposal': result=prepare(args)
        elif args.action=='sign-proposal':
            result=esc.sign_proposal(proposal_path=args.proposal,
                proposal_pin=args.proposal_sha256,
                witness_secret=args.witness_secret,
                witness_public_sha256=args.witness_public_sha256,
                output=args.output)
        elif args.action=='assemble-record': result=assemble(args)
        elif args.action=='advance-remote': result=advance(args)
        else: result=inspect(args)
        print(json.dumps(result,sort_keys=True))
        return 2
    except (rec.RecoveryError,OSError,ValueError,TypeError) as exc:
        print(json.dumps({'status':'unavailable','exit_code':5,
            'reason_code':getattr(exc,'code','EC274_OPERATOR_UNAVAILABLE')},sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())
