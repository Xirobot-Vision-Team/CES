#!/usr/bin/env python3
"""Standalone owner-private lossless registrar fork handoff; console: verify only."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from . import case

PIN_ARGUMENTS = (
    'case-id','witness-id','witness-public-hex',
    'witness-challenge-sha256','expected-witness-sha256',
    'expected-left-sha256','expected-right-sha256',
    'expected-left-head-raw-sha256','expected-right-head-raw-sha256',
    'expected-genesis-raw-sha256','registrar-id','registrar-public-hex',
)
SOURCE_ARGUMENTS = (
    'witness-file','left-file','left-materials-file','right-file',
    'right-materials-file',
)


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC321 exact-original-byte offline EC320 fork case export/verify. '
        'A verified fork exits 2, never CAS healthy/0. A separate whole ZIP '
        'SHA and every historical identity/head/attestation pin are required.'))
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('export','verify'):
        s=sub.add_parser(command)
        for field in PIN_ARGUMENTS:
            s.add_argument('--'+field,required=True)
        if command=='export':
            for field in SOURCE_ARGUMENTS:
                s.add_argument('--'+field,required=True)
            s.add_argument('--out',required=True)
        else:
            s.add_argument('--bundle-file',required=True)
            s.add_argument('--expected-bundle-sha256',required=True)
    return p


def main(argv: list[str]|None=None) -> int:
    args=parser().parse_args(argv)
    params=vars(args).copy()
    command=params.pop('command')
    try:
        result={'export':case.export,'verify':case.verify}[command](**params)
        print(json.dumps({'schema':case.RESULT_SCHEMA,'command':command,**result},
                         sort_keys=True,separators=(',',':')))
        return result['exit_code']
    except Exception as exc:
        status=(exc.status if isinstance(exc,(anchor.AnchorError,io.HostError))
                else 'unavailable')
        reason=(exc.code if isinstance(exc,(anchor.AnchorError,io.HostError))
                else 'EC321_PORTABLE_SIGNED_FORK_CASE_UNAVAILABLE')
        rc={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({'schema':case.DENIAL_SCHEMA,'command':command,
            'exit_code':rc,'status':status,'reason_code':reason,
            'original_case_or_fork_accepted':False,
            'global_latest_or_winner_proven':False,
            'business_writes_performed':False},sort_keys=True,separators=(',',':')))
        return rc
