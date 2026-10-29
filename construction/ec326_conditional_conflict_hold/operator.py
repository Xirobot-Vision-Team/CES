#!/usr/bin/env python3
"""EC326 CLI: offline eighth-role signed, conditional, NOT submitted hold."""
from __future__ import annotations
import argparse
import json
from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from . import hold


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC326: sign/verify an eighth independent Ed25519 OFFLINE request to '
        'hold a two-child EC325 dispute conditional on an external atomic '
        'parent-head comparison. Does NOT contact or write a remote CAS; '
        'exit 2 remains UNRESOLVED. All input original signatures replay.'))
    sub = p.add_subparsers(dest='command',required=True)
    for name in ('sign-request','verify-request'):
        s = sub.add_parser(name)
        for key in ('request-id','target-store-namespace-id',
                    'eighth-signer-id','eighth-signer-public-hex',
                    'request-challenge-sha256','case-file',
                    'expected-case-sha256','registry-id',
                    'expected-prior-registry-sha256'):
            s.add_argument('--'+key,required=True)
        s.add_argument('--expected-sequence',required=True,type=int)
        s.add_argument('--prior-registry-file')
        for side in ('left','right'):
            for key in ('registry-file','expected-registry-sha256',
                        'capsule-file','origin-file','expected-origin-sha256',
                        'recipient-file','expected-recipient-sha256'):
                s.add_argument('--'+side+'-'+key,required=True)
        if name == 'sign-request':
            s.add_argument('--private-key-file',required=True)
            s.add_argument('--out',required=True)
        else:
            s.add_argument('--request-file',required=True)
            s.add_argument('--expected-request-sha256',required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    left = {key:args.pop('left_'+key) for key in hold.proof.SIDE_FIELDS}
    right = {key:args.pop('right_'+key) for key in hold.proof.SIDE_FIELDS}
    try:
        operation = {'sign-request':hold.sign_request,
                     'verify-request':hold.verify_request}[command]
        observed = operation(left=left,right=right,**args)
        print(json.dumps({'schema':hold.RESULT_SCHEMA,'command':command,
                          **observed},sort_keys=True,separators=(',',':')))
        return observed['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc,(anchor.AnchorError,io.HostError))
                  else 'unavailable')
        code = (exc.code if isinstance(exc,(anchor.AnchorError,io.HostError))
                else 'EC326_CONDITIONAL_SIGNED_HOLD_UNAVAILABLE')
        exit_code = {'permission_denied':3,'invalid_input':4,
                     'unavailable':5}.get(status,5)
        print(json.dumps({
            'schema':hold.DENIAL_SCHEMA,'command':command,
            'status':status,'reason_code':code,'exit_code':exit_code,
            'signed_request_and_both_signed_histories_accepted':False,
            'external_cas_worm_global_latest_winner_or_commit_proven':False,
            'organizational_approval_proven':False,
            'business_or_external_store_writes_performed':False,
        },sort_keys=True,separators=(',',':')))
        return exit_code
