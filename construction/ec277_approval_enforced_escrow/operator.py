#!/usr/bin/env python3
"""EC277 online operator for *server-enforced*, already offline-approved CAS.

Keep EC276 prepare-intent/sign-intent/assemble-approval unchanged. Unlike the
older EC276 'advance-approved' command, this one sends the authorization to
both EC277 daemons, each of which must enforce it *at the write boundary*.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from ec266_source_provenance_host import provenance as prov
from ec269_emergency_recovery_host import recovery as rec
from ec274_remote_escrow_host import escrow as esc
from ec276_dual_approval_host import approval as auth
from ec277_approval_enforced_escrow.policy import TrustPolicy
from ec277_approval_enforced_escrow.client import ApprovedDualEscrow


def parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser(description='EC277 real two-site server-enforced approval CAS')
    sub=p.add_subparsers(dest='action',required=True)
    for action in ('inspect-approved','inspect-advance-approved','advance-approved'):
        c=sub.add_parser(action)
        for name in ('policy','policy_sha256','approval','approval_sha256'):
            c.add_argument('--'+name.replace('_','-'),required=True)
    return p


def perform(args:argparse.Namespace)->dict:
    policy=TrustPolicy(args.policy,args.policy_sha256)
    doc=auth.read_approval(args.approval,args.approval_sha256)
    dual=ApprovedDualEscrow(policy)
    if args.action=='inspect-approved':
        result=dual.inspect_approved(doc)
    elif args.action=='inspect-advance-approved':
        result=dual.inspect_advance_approved(doc)
    else:
        result=dual.advance_approved(doc)
    result['ec277_pinned_policy_sha256']=policy.pin
    result['ec277_two_person_approval_sha256']=esc._sha(args.approval_sha256)
    return result


def main(argv:list[str]|None=None)->int:
    args=parser().parse_args(argv)
    try:
        print(json.dumps(perform(args),sort_keys=True))
        return 2
    except (rec.RecoveryError,prov.ProvenanceError,esc.EscrowError,
            OSError,ValueError,TypeError) as exc:
        print(json.dumps({'status':'unavailable','exit_code':5,
            'reason_code':getattr(exc,'code','EC277_ENFORCED_CAS_UNAVAILABLE')},sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())
