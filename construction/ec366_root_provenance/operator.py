#!/usr/bin/env python3
"""EC366 self-contained offline provenance-claim read-only CLI."""
from __future__ import annotations

import argparse
import copy
import json

from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as io
from ec365_directory_lineage import operator as previous_cli
from . import provenance as core


def parser():
    inherited=previous_cli.parser()
    commands=next(a for a in inherited._actions
                  if isinstance(a,argparse._SubParsersAction))
    template=commands.choices['audit-directory-authority']
    p=argparse.ArgumentParser(description='EC366 independently SHA-pinned two-institution signed directory-root provenance (offline/unresolved)')
    sub=p.add_subparsers(dest='command',required=True)
    for cmd in ('derive-root-provenance-handoff','audit-root-provenance'):
        q=sub.add_parser(cmd,help='no signing, trust bootstrap, network or remote writes')
        for action in template._actions:
            if action.dest!='help':q._add_action(copy.deepcopy(action))
        if cmd=='audit-root-provenance':
            q.add_argument('--root-provenance-evaluation-utc',required=True)
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
        status,reason='unavailable','EC366_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,
      'status':status,'reason_code':reason,
      'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
      'actual_ec365_through_ec337_signed_originals_replayed':False,
      'offline_unresolved_exit_code':2,
      **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    d=vars(parser().parse_args(argv))
    cmd=d.pop('command')
    # Old flags with historic alias spellings have to map precisely, no new
    # positive outcome can be introduced by a missing inherited argument.
    registry=previous_cli.previous_cli.last_cli.previous_cli.previous_cli.previous_cli.registry_cli
    for key in (*registry.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
                *registry.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=registry.parent_cli.old_cli.old_cli.old_cli.FLAGS[key]
        if flag in d and flag!=key:d[key]=d.pop(flag)
    try:
        result=(core.checklist(**d) if cmd=='derive-root-provenance-handoff'
                else core.audit(**d))
    except Exception as exc:
        result=denial(cmd,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,allow_nan=False,
                     separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
