#!/usr/bin/env python3
"""EC365 strictly offline directory-authority key-transition CLI."""
from __future__ import annotations

import argparse
import copy
import json

from delivery_anchor import anchor as errors
from finding_query_host import protocol as io
from cross_epoch import operator as previous_cli
from . import lineage as core


def parser():
    inherited=previous_cli.parser()
    commands=next(a for a in inherited._actions
                  if isinstance(a,argparse._SubParsersAction))
    template=commands.choices['audit-cross-epoch']
    p=argparse.ArgumentParser(description='EC365 actual dual-directory authority signer transition (offline unresolved)')
    sub=p.add_subparsers(dest='command',required=True)
    for cmd in ('derive-directory-authority-handoff','audit-directory-authority'):
        q=sub.add_parser(cmd,help='no private signing, external root or global latest claim')
        for action in template._actions:
            if action.dest!='help':q._add_action(copy.deepcopy(action))
        if cmd=='audit-directory-authority':
            q.add_argument('--directory-lineage-evaluation-utc',required=True)
            for key in core.NEW_OPTIONAL:
                q.add_argument('--'+key.replace('_','-'),
                    **({'type':int} if key.startswith('minimum_') else {}))
            for key,flag in core.NEW_REPEATS:
                q.add_argument(flag,dest=key,action='append',default=[])
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,reason=exc.status,exc.code
    else:
        status,reason='unavailable','EC365_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
      'reason_code':reason,
      'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
      'actual_ec364_through_ec337_signed_originals_replayed':False,
      'offline_unresolved_exit_code':2,
      **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    d=vars(parser().parse_args(argv))
    cmd=d.pop('command')
    registry=previous_cli.last_cli.previous_cli.previous_cli.previous_cli.registry_cli
    for key in (*registry.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
                *registry.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=registry.parent_cli.old_cli.old_cli.old_cli.FLAGS[key]
        if flag in d and flag!=key:d[key]=d.pop(flag)
    try:
        result=(core.checklist(**d) if cmd=='derive-directory-authority-handoff'
                else core.audit(**d))
    except Exception as exc:
        result=denial(cmd,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,allow_nan=False,
                     separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
