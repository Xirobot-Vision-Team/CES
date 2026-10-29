#!/usr/bin/env python3
"""EC369 independent detached-only CLI, never requires historical parent flags."""
from __future__ import annotations

import argparse
import json

from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as io
from . import detached as core


def parser():
    p=argparse.ArgumentParser(description=(
        'EC369 read-only receiver-only detached original-byte, Ed25519 and '
        'dual disclosure challenge replay; ALWAYS unresolved exit 2'))
    sub=p.add_subparsers(dest='command',required=True)
    q=sub.add_parser('audit-detached-receiver',help=(
        'verify copied EC366/EC367 originals + EC368 receipts + EC369 '
        'signed source-copy map and challenges; NEVER read original sender paths'))
    for key in core.SCALARS:
        q.add_argument('--'+key.replace('_','-'),required=True,
                       **({'type':int} if key.startswith('minimum_') else {}))
    for key,flag in core.REPEATS:
        q.add_argument(flag,dest=key,action='append',required=True)
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:status,reason='unavailable','EC369_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,
       'status':status,'reason_code':reason,
       'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
       'original_sender_source_paths_required_or_read':False,
       'ec365_through_ec337_historical_parent_or_directory_checkpoint_replay_performed':False,
       'offline_unresolved_exit_code':2,
       **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    opts=vars(parser().parse_args(argv));command=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
        None if v=='none' else v for v in opts['expected_source_attestation_head_shas']]
    try:result=core.audit(**opts)
    except Exception as exc:result=denial(command,exc)
    print(json.dumps(result,ensure_ascii=True,sort_keys=True,allow_nan=False,
                     separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
