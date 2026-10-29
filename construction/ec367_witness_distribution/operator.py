#!/usr/bin/env python3
"""EC367 offline witness-distribution CLI: true parent replay and no signing."""
from __future__ import annotations

import argparse
import copy
import json

from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as io
from ec366_root_provenance import operator as previous_cli
from . import distribution as core


def parser():
    inherited=previous_cli.parser()
    commands=next(a for a in inherited._actions
                  if isinstance(a,argparse._SubParsersAction))
    template=commands.choices['audit-root-provenance']
    p=argparse.ArgumentParser(description='EC367 true source-signed status proofs and two SHA-pinned signed distribution witness paths (offline/unresolved)')
    sub=p.add_subparsers(dest='command',required=True)
    for cmd in ('derive-witness-distribution-handoff','audit-witness-distribution'):
        q=sub.add_parser(cmd,help='read-only, no external root bootstrap, trusted clock, network, private signer or remote writes')
        for action in template._actions:
            if action.dest!='help':q._add_action(copy.deepcopy(action))
        if cmd=='audit-witness-distribution':
            q.add_argument('--witness-distribution-evaluation-utc',required=True)
            for k in core.NEW_OPTIONAL:
                q.add_argument('--'+k.replace('_','-'),
                    **({'type':int} if k.startswith('minimum_') else {}))
            for k,flag in core.NEW_REPEATS:
                q.add_argument(flag,dest=k,action='append',default=[])
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,reason=exc.status,exc.code
    else:
        status,reason='unavailable','EC367_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,
       'status':status,'reason_code':reason,
       'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
       'actual_ec366_through_ec337_signed_originals_replayed':False,
       'offline_unresolved_exit_code':2,
       **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    d=vars(parser().parse_args(argv))
    cmd=d.pop('command')
    # Inherited EC337-era historical alias dests are mapped exactly once.
    registry=previous_cli.previous_cli.last_cli.previous_cli.previous_cli.previous_cli.registry_cli
    for key in (*registry.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
                *registry.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=registry.parent_cli.old_cli.old_cli.old_cli.FLAGS[key]
        if flag in d and flag!=key:d[key]=d.pop(flag)
    try:
        result=(core.checklist(**d) if cmd=='derive-witness-distribution-handoff'
                else core.audit(**d))
    except Exception as exc:
        result=denial(cmd,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,allow_nan=False,
                     separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
