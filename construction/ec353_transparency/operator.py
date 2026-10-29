#!/usr/bin/env python3
"""EC353 pure read-only publication manifest and merkle proof commands."""
from __future__ import annotations
import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as errors
from ec352_key_registry import operator as old_cli
from . import transparency as core


def parser():
    p=argparse.ArgumentParser(description='EC353 offline pinned witnessed transparency evidence')
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('derive-publication-handoff','audit-publication-witnesses'):
        s=sub.add_parser(command,help='actually re-execute EC352 down to EC337 signed originals')
        # Inherit the exact predecessor contract; do not synthesize a PASS JSON.
        old_cli.parent_cli.old_cli.old_cli.old_cli.old_cli._scalars(
            s,old_cli.parent_cli.SCALARS)
        old_cli.parent_cli.old_cli.old_cli.old_cli.old_cli._repeats(
            s,old_cli.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS)
        for k in old_cli.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS:
            flag=old_cli.parent_cli.old_cli.old_cli.old_cli.FLAGS[k]
            s.add_argument('--'+flag.replace('_','-'),action='append',default=[])
        s.add_argument('--dual-evaluation-utc',required=True)
        for k,flag in old_cli.parent_cli.old_cli.old_cli.ADDED_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        s.add_argument('--tsa-evaluation-utc',required=True)
        for k,flag in old_cli.parent_cli.old_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        s.add_argument('--provenance-evaluation-utc',required=True)
        for k,flag in old_cli.parent_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        s.add_argument('--registry-evaluation-utc',required=True)
        for k,flag in old_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        if command=='audit-publication-witnesses':
            s.add_argument('--publication-evaluation-utc',required=True)
            s.add_argument('--publication-bundle-file',required=True)
            s.add_argument('--expected-publication-bundle-sha256',required=True)
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,reason=exc.status,exc.code
    else:status,reason='unavailable','EC353_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':reason,
            'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
            'parent_actual_signed_originals_replayed':False,
            'offline_unresolved_exit_code':2,
            **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=vars(parser().parse_args(argv));command=args.pop('command')
    for k in (*old_cli.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
              *old_cli.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=old_cli.parent_cli.old_cli.old_cli.old_cli.FLAGS[k]
        if flag in args and flag!=k:args[k]=args.pop(flag)
    try:
        result=(core.checklist(**args) if command=='derive-publication-handoff'
                else core.audit(**args))
    except Exception as exc:result=denial(command,exc)
    print(json.dumps(result,sort_keys=True,separators=(',',':'),
                     ensure_ascii=True,allow_nan=False))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
