#!/usr/bin/env python3
"""EC368 bounded offline CLI: derives required copies or replays true parents."""
from __future__ import annotations

import argparse
import copy
import json

from delivery_anchor import anchor as errors
from finding_query_host import protocol as io
from witness_distribution import operator as previous_cli
from . import portable as core


def parser():
    inherited=previous_cli.parser()
    commands=next(a for a in inherited._actions
                  if isinstance(a,argparse._SubParsersAction))
    template=commands.choices['audit-witness-distribution']
    p=argparse.ArgumentParser(description='EC368 offline portable byte-for-byte receipt, independent sender/receiver Ed25519 and history (unresolved)')
    sub=p.add_subparsers(dest='command',required=True)
    for cmd in ('derive-portable-receiver-handoff','audit-portable-receiver'):
        q=sub.add_parser(cmd,help='read-only; no private keys, official identity, network, trusted time or remote writes')
        for action in template._actions:
            if action.dest!='help':q._add_action(copy.deepcopy(action))
        if cmd=='audit-portable-receiver':
            q.add_argument('--portable-receiver-evaluation-utc',required=True)
            for key in core.NEW_OPTIONAL:
                q.add_argument('--'+key.replace('_','-'),
                     **({'type':int} if key.startswith('minimum_') else {}))
            for k,flag in core.NEW_REPEATS:
                q.add_argument(flag,dest=k,action='append',default=[])
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,reason=exc.status,exc.code
    else:
        status,reason='unavailable','EC368_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,
        'status':status,'reason_code':reason,
        'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
        'actual_ec367_through_ec337_signed_originals_replayed':False,
        'offline_unresolved_exit_code':2,
        **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    parsed=vars(parser().parse_args(argv))
    cmd=parsed.pop('command')
    # EC367 inherits the same historical CLI alias normalization. This is
    # deliberately performed here because the standalone entrypoint bypasses
    # EC367.operator.main while calling the same parent.audit API.
    registry=previous_cli.previous_cli.previous_cli.last_cli.previous_cli.previous_cli.previous_cli.registry_cli
    for key in (*registry.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
                *registry.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=registry.parent_cli.old_cli.old_cli.old_cli.FLAGS[key]
        if flag in parsed and flag!=key:parsed[key]=parsed.pop(flag)
    try:
        result=(core.checklist(**parsed) if cmd=='derive-portable-receiver-handoff'
                else core.audit(**parsed))
    except Exception as exc:
        result=denial(cmd,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,allow_nan=False,
                     separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
