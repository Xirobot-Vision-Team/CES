#!/usr/bin/env python3
"""EC393 standalone receiver: no external writes or private-key operations."""
from __future__ import annotations
import argparse
import json

from delivery_anchor import anchor as errors
from finding_query_host import protocol as host
from crossview import operator as previous_cli
from . import custody_anchor as core


def parser():
    p=argparse.ArgumentParser(description=(
      'EC393 offline two-party original custody signatures, RFC6962 anchored '
      'log prefix, genuine DER RFC3161/CRL; all valid evidence stays unresolved'))
    sub=p.add_subparsers(dest='command',required=True)
    inherited_action=next(action.choices['audit-historical-ec339-crossview']
      for action in previous_cli.parser()._actions
      if isinstance(action,argparse._SubParsersAction))
    inherited_repeats={a.dest:a.option_strings[0] for a in inherited_action._actions
      if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(inherited_repeats)!=set(core.PARENT_REPEATS):
        raise RuntimeError('EC393 inherited crossview argument contract drift')
    for command in ('derive-historical-ec339-custody-anchor-inventory',
                    'audit-historical-ec339-custody-anchor'):
        q=sub.add_parser(command,help='Replay actual EC392 and compare real original custody and log proofs')
        scalars=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if command.startswith('audit-'):scalars+=core.AUDIT_ONLY
        for key in scalars:q.add_argument('--'+key.replace('_','-'),required=True)
        for key,flag in (*((k,inherited_repeats[k]) for k in core.PARENT_REPEATS),
                          *core.NEW_REPEATS):
            q.add_argument(flag,dest=key,action='append',
              **({'default':[]} if key=='historical_dual_handoff_shas' else
                 {'required':True}),
              **({'type':int} if key.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,code=exc.status,exc.code.upper()
    else:
        status,code='unavailable','EC393_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,
      'status':status,'reason_code':code,
      'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
      'offline_unresolved_exit_code':2,
      'sender_origin_path_required_or_read':False,
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
      **{key:False for key in core.NEGATIVES}}


def main(argv=None):
    opts=vars(parser().parse_args(argv));command=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
        None if x=='none' else x for x in opts['expected_source_attestation_head_shas']]
    try:
        result=core.derive_inventory(**opts) if command.startswith('derive-') else core.audit(**opts)
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,ensure_ascii=True,sort_keys=True,allow_nan=False,separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
