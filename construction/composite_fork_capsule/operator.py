#!/usr/bin/env python3
"""EC323 portable capsule. Standalone seal|verify; unified console verify only."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from fork_case_transport.operator import PIN_ARGUMENTS
from receiver_fork_ack.operator import RECEIVER_ARGS
from . import capsule


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=(
        'EC323 seal both unchanged EC321 case ZIP and EC322 authentic seventh'
        ' receiver ACK in one deterministic, bounded ZIP. BOTH operations'
        ' replay all original historical signatures. Whole capsule SHA,'
        ' whole case SHA, whole ACK SHA, all historic pins, seventh identity'
        ' and challenge must be fixed outside the capsule. Authentic fork'
        ' remains exit 2. No private key or new signature is created.'))
    commands=p.add_subparsers(dest='command',required=True)
    for command in ('seal','verify'):
        s=commands.add_parser(command)
        for name in (*PIN_ARGUMENTS,*RECEIVER_ARGS,
                     'expected-bundle-sha256','expected-ack-sha256'):
            s.add_argument('--'+name,required=True)
        if command=='seal':
            s.add_argument('--bundle-file',required=True)
            s.add_argument('--ack-file',required=True)
            s.add_argument('--out',required=True)
        else:
            s.add_argument('--capsule-file',required=True)
            s.add_argument('--expected-capsule-sha256',required=True)
    return p


def main(argv: list[str]|None=None) -> int:
    params=vars(parser().parse_args(argv)).copy()
    command=params.pop('command')
    try:
        result={'seal':capsule.seal,'verify':capsule.verify}[command](**params)
        print(json.dumps({'schema':capsule.RESULT_SCHEMA,'command':command,**result},
                         sort_keys=True,separators=(',',':')))
        return result['exit_code']
    except Exception as exc:
        status=(exc.status if isinstance(exc,(anchor.AnchorError,io.HostError))
                else 'unavailable')
        reason=(exc.code if isinstance(exc,(anchor.AnchorError,io.HostError))
                else 'EC323_PORTABLE_COMPOSITE_ORIGINALS_UNAVAILABLE')
        rc={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({'schema':capsule.DENIAL_SCHEMA,'command':command,
            'exit_code':rc,'status':status,'reason_code':reason,
            'original_signed_case_ack_and_all_history_accepted':False,
            'fork_winner_or_cas_proven':False,'business_writes_performed':False},
            sort_keys=True,separators=(',',':')))
        return rc
