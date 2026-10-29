#!/usr/bin/env python3
"""EC322 independent recipient Ed25519 ACK; unified console exposes VERIFY only."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from ec321_fork_case_transport.operator import PIN_ARGUMENTS
from . import ack

RECEIVER_ARGS = ('ack-id','seventh-receiver-id',
                 'seventh-receiver-public-hex',
                 'seventh-receiver-challenge-sha256')


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC322 genuine seventh identity signs only after fully replaying'
        ' EC321->EC294 original fork case; verify requires externally pinned'
        ' whole ACK SHA, whole case ZIP SHA and ALL historical trust pins.'
        ' Valid fork remains exit 2, not CAS winner/0.'))
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('attest','verify'):
        s=sub.add_parser(command)
        for name in (*PIN_ARGUMENTS,*RECEIVER_ARGS,
                     'bundle-file','expected-bundle-sha256'):
            s.add_argument('--'+name,required=True)
        if command=='attest':
            s.add_argument('--private-key-file',required=True)
            s.add_argument('--out',required=True)
        else:
            s.add_argument('--ack-file',required=True)
            s.add_argument('--expected-ack-sha256',required=True)
    return p


def main(argv: list[str]|None=None) -> int:
    args=parser().parse_args(argv)
    data=vars(args).copy()
    command=data.pop('command')
    try:
        result={'attest':ack.attest,'verify':ack.verify}[command](**data)
        print(json.dumps({'schema':ack.RESULT_SCHEMA,'command':command,**result},
                         sort_keys=True,separators=(',',':')))
        return result['exit_code']
    except Exception as exc:
        status=(exc.status if isinstance(exc,(anchor.AnchorError,io.HostError))
                else 'unavailable')
        reason=(exc.code if isinstance(exc,(anchor.AnchorError,io.HostError))
                else 'EC322_SIGNED_ACK_UNAVAILABLE')
        rc={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({'schema':ack.DENIAL_SCHEMA,'command':command,
            'exit_code':rc,'status':status,'reason_code':reason,
            'seventh_signature_or_full_history_accepted':False,
            'fork_winner_or_global_latest_proven':False,
            'business_writes_performed':False},sort_keys=True,separators=(',',':')))
        return rc
