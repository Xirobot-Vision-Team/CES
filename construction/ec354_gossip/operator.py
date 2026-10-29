#!/usr/bin/env python3
"""EC354 explicitly pinned, purely read-only signed gossip CLI."""
from __future__ import annotations
import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as errors
from ec352_key_registry import operator as registry_cli
from . import gossip as core


def parser():
    p=argparse.ArgumentParser(description='EC354 offline signed cross-log gossip original verifier (READ ONLY)')
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('derive-gossip-handoff','audit-cross-log-gossip'):
        s=sub.add_parser(command,help='actually replay EC353 through EC337 original signatures')
        # Do not substitute any earlier audit JSON for its complete original evidence.
        registry_cli.parent_cli.old_cli.old_cli.old_cli.old_cli._scalars(
            s,registry_cli.parent_cli.SCALARS)
        registry_cli.parent_cli.old_cli.old_cli.old_cli.old_cli._repeats(
            s,registry_cli.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS)
        for k in registry_cli.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS:
            flag=registry_cli.parent_cli.old_cli.old_cli.old_cli.FLAGS[k]
            s.add_argument('--'+flag.replace('_','-'),action='append',default=[])
        s.add_argument('--dual-evaluation-utc',required=True)
        for k,flag in registry_cli.parent_cli.old_cli.old_cli.ADDED_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        s.add_argument('--tsa-evaluation-utc',required=True)
        for k,flag in registry_cli.parent_cli.old_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        s.add_argument('--provenance-evaluation-utc',required=True)
        for k,flag in registry_cli.parent_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        s.add_argument('--registry-evaluation-utc',required=True)
        for k,flag in registry_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        s.add_argument('--publication-evaluation-utc',required=True)
        s.add_argument('--publication-bundle-file',required=True)
        s.add_argument('--expected-publication-bundle-sha256',required=True)
        if command=='audit-cross-log-gossip':
            s.add_argument('--gossip-evaluation-utc',required=True)
            s.add_argument('--gossip-bundle-file',required=True)
            s.add_argument('--expected-gossip-bundle-sha256',required=True)
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,code=exc.status,exc.code
    else:status,code='unavailable','EC354_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':code,
            'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
            'actual_ec353_through_ec337_original_signatures_replayed':False,
            'offline_unresolved_exit_code':2,
            **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=vars(parser().parse_args(argv));command=args.pop('command')
    for k in (*registry_cli.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
              *registry_cli.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=registry_cli.parent_cli.old_cli.old_cli.old_cli.FLAGS[k]
        if flag in args and flag!=k:args[k]=args.pop(flag)
    try:
        result=core.checklist(**args) if command=='derive-gossip-handoff' else core.audit(**args)
    except Exception as exc:result=denial(command,exc)
    print(json.dumps(result,ensure_ascii=True,sort_keys=True,
                     separators=(',',':'),allow_nan=False))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
