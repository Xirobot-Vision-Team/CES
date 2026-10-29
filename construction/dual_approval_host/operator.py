#!/usr/bin/env python3
"""EC276 explicit offline approve -> pinned two-authority CAS workflow.

The 'sign-intent' command alone reads private approver keys. The online
commands load only pinned public keys and a SHA-pinned two-person signed file.
EC275 original operator remains independently available for backward use.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from source_provenance_host import provenance as prov
from emergency_recovery_host import recovery as rec
from emergency_recovery_host import serve as old_cli
from remote_escrow_host import escrow as esc
from dual_escrow_host import operator as prev
from dual_approval_host import approval as auth


def pairs(args:argparse.Namespace) -> list[tuple[str,str]]:
    if len(args.approver_public)!=len(args.approver_public_sha256):
        auth.deny('EC276_APPROVER_PUBLIC_PIN_PAIRS_REQUIRED')
    return list(zip(args.approver_public,args.approver_public_sha256))


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description='EC276 two offline approvers bind approved two-site escrow CAS')
    sub=p.add_subparsers(dest='action',required=True)
    actions=('prepare-intent','sign-intent','assemble-approval',
             'inspect-approved','inspect-advance-approved','advance-approved')
    for action in actions:
        cmd=sub.add_parser(action)
        if action=='sign-intent':
            old_cli._required(cmd,('intent','intent_sha256','approver_secret',
                                   'approver_public_sha256','output'))
            continue
        old_cli._required(cmd,('escrow_host','escrow_port','escrow_namespace',
            'escrow_tls_ca','escrow_tls_ca_sha256','escrow_tls_leaf_sha256',
            'escrow_public','escrow_public_sha256','secondary_escrow_host',
            'secondary_escrow_port','secondary_escrow_tls_ca',
            'secondary_escrow_tls_ca_sha256','secondary_escrow_tls_leaf_sha256',
            'secondary_escrow_public','secondary_escrow_public_sha256',
            'root_sha256','closure_sha256'))
        cmd.add_argument('--freshness-witness-public',action='append',required=True)
        cmd.add_argument('--freshness-witness-public-sha256',action='append',required=True)
        cmd.add_argument('--approver-public',action='append',required=True)
        cmd.add_argument('--approver-public-sha256',action='append',required=True)
        if action=='prepare-intent':
            old_cli._required(cmd,('record','record_sha256',
                'expected_previous_sha256','not_before_unix','expires_at_unix','output'))
        elif action=='assemble-approval':
            old_cli._required(cmd,('intent','intent_sha256','output'))
            cmd.add_argument('--approval-vote',action='append',required=True)
            cmd.add_argument('--approval-vote-sha256',action='append',required=True)
        else:
            old_cli._required(cmd,('approval','approval_sha256'))
    return p


def perform(args:argparse.Namespace) -> dict:
    if args.action=='sign-intent':
        return auth.sign_intent(intent_path=args.intent,intent_sha256=args.intent_sha256,
            secret_path=args.approver_secret,signer_sha256=args.approver_public_sha256,
            output=args.output)
    duo=prev.clients(args)
    keys=auth.approver_keys(pairs(args),duo)
    if args.action=='prepare-intent':
        record=prev._record(args)
        return auth.prepare_intent(duo,keys,record,
            previous_sha256=args.expected_previous_sha256,
            not_before_unix=int(args.not_before_unix),
            expires_at_unix=int(args.expires_at_unix),output=args.output)
    if args.action=='assemble-approval':
        if len(args.approval_vote)!=len(args.approval_vote_sha256):
            auth.deny('EC276_APPROVAL_VOTE_PIN_PAIRS_REQUIRED')
        return auth.assemble_approval(intent_path=args.intent,
            intent_sha256=args.intent_sha256,
            vote_paths=list(zip(args.approval_vote,args.approval_vote_sha256)),
            duo=duo,keys=keys,output=args.output)
    intent=auth.verified_file(args.approval,args.approval_sha256,duo,keys)
    record=intent['record']
    target=intent['record_sha256']
    previous=intent['previous_record_sha256']
    if args.action=='inspect-approved':
        stored,head=duo.read_pair(minimum_index=intent['record_index'])
        if head!=target or stored!=record:
            auth.deny('EC276_LIVE_DUAL_ESCROW_NOT_AT_SIGNED_APPROVED_HEAD')
        result={'status':'partial','exit_code':2,
            'reason_code':'EC276_TWO_OFFLINE_APPROVALS_AND_TWO_LIVE_HEADS_MATCH',
            'record_sha256':head,'record_index':intent['record_index'],
            'two_offline_approval_signatures_verified':True,
            'two_fresh_remote_signatures_verified':True}
    elif args.action=='inspect-advance-approved':
        result=duo.inspect_advance(record,record_sha256=target,previous_sha256=previous)
        result['ec276_two_offline_approvals_verified']=True
    else:
        # EC275 performs both trusted preflight reads and CAS, then independently
        # rereads both sites. Never generate a replacement signed record on retry.
        result=duo.advance(record,record_sha256=target,previous_sha256=previous)
        auth.verified_file(args.approval,args.approval_sha256,duo,keys)
        result['ec276_two_offline_approvals_verified']=True
    result['ec276_approval_sha256']=esc._sha(args.approval_sha256)
    result['ec276_approval_expires_at_unix']=intent['expires_at_unix']
    return result


def main(argv:list[str]|None=None)->int:
    args=parser().parse_args(argv)
    try:
        result=perform(args)
        print(json.dumps(result,sort_keys=True))
        return 2
    except (rec.RecoveryError,prov.ProvenanceError,OSError,ValueError,TypeError) as exc:
        print(json.dumps({'status':'unavailable','exit_code':5,
            'reason_code':getattr(exc,'code','EC276_OPERATOR_UNAVAILABLE')},
            sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())
