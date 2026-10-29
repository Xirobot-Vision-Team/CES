#!/usr/bin/env python3
"""EC394 standalone read-only registration + witnessed fork receiver."""
from __future__ import annotations
import argparse
import json

from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec393_custody_anchor import operator as inherited_cli
from . import registered_witness as core


def parser():
    p=argparse.ArgumentParser(description=(
      'EC394 genuine external Ed25519 site/key registration history, signed cutoff '
      'and two third-party RFC3161 timestamped signed-log witnesses; read-only unresolved'))
    sub=p.add_subparsers(dest='command',required=True)
    source=next(a.choices['audit-historical-ec339-custody-anchor']
       for a in inherited_cli.parser()._actions
       if isinstance(a,argparse._SubParsersAction))
    old={a.dest:a.option_strings[0] for a in source._actions
         if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(old)!=set(core.PARENT_REPEATS):
        raise RuntimeError('EC394 inherited EC393 argument contract drift')
    for command in ('derive-historical-ec339-registered-witness-inventory',
                    'audit-historical-ec339-registered-witness'):
        q=sub.add_parser(command,help='Reopen and verify real EC393/392/391 originals before new evidence')
        scalars=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if command.startswith('audit-'):scalars+=core.AUDIT_ONLY
        for key in scalars:q.add_argument('--'+key.replace('_','-'),required=True)
        for key,flag in (*((k,old[k]) for k in core.PARENT_REPEATS),*core.NEW_REPEATS):
            q.add_argument(flag,dest=key,action='append',
                **({'default':[]} if key=='historical_dual_handoff_shas' else
                   {'required':True}),
                **({'type':int} if key.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,code=exc.status,exc.code.upper()
    else:
        status,code='unavailable','EC394_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,
       'status':status,'reason_code':code,
       'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
       'offline_unresolved_exit_code':2,
       'sender_origin_path_required_or_read':False,
       'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
       **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    opts=vars(parser().parse_args(argv));command=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
       None if x=='none' else x for x in opts['expected_source_attestation_head_shas']]
    try:
        result=(core.derive_inventory(**opts) if command.startswith('derive-')
                else core.audit(**opts))
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,ensure_ascii=True,sort_keys=True,allow_nan=False,
                     separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
