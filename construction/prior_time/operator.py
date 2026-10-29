#!/usr/bin/env python3
"""EC391 read-only CLI: pass through all EC390 pinned parent arguments."""
from __future__ import annotations
import argparse
import json
from delivery_anchor import anchor as errors
from finding_query_host import protocol as host
from independent_archive import operator as predecessor
from . import prior_time as core


def parser():
    p=argparse.ArgumentParser(description='EC391 pre-existing signed offsite history and real offline RFC3161 trust-path replay; unresolved')
    subs=p.add_subparsers(dest='command',required=True)
    actions=next(a.choices['audit-historical-ec339-independent-archive-heads']
        for a in predecessor.parser()._actions if isinstance(a,argparse._SubParsersAction))._actions
    inherited={a.dest:a.option_strings[0] for a in actions if
               a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(inherited)!=set(core.PARENT_REPEATS):
        raise RuntimeError('EC391 inherited EC390 repeat CLI spelling drift')
    for command in ('derive-historical-ec339-prior-offsite-time-inventory',
                    'audit-historical-ec339-prior-offsite-time'):
        q=subs.add_parser(command,help='Replay actual prior EC390 audit and verify offsite signed heads and DER RFC3161 tokens')
        scalars=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if command.startswith('audit-'):scalars+=core.AUDIT_ONLY
        for key in scalars:
            q.add_argument('--'+key.replace('_','-'),required=True)
        for name,flag in (*((k,inherited[k]) for k in core.PARENT_REPEATS),*core.NEW_REPEATS):
            q.add_argument(flag,dest=name,action='append',
                **({'default':[]} if name=='historical_dual_handoff_shas' else {'required':True}),
                **({'type':int} if name.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,code=exc.status,exc.code.upper()
    else:
        status,code='unavailable','EC391_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
        'reason_code':code,'exit_code':{'permission_denied':3,'invalid_input':4,
        'unavailable':5}.get(status,5),'offline_unresolved_exit_code':2,
        'sender_origin_path_required_or_read':False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
        **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=parser().parse_args(argv);params=vars(args);command=params.pop('command')
    params['expected_source_attestation_head_shas']=[
        None if x=='none' else x for x in params['expected_source_attestation_head_shas']]
    try:
        result=(core.derive_inventory(**params) if command.startswith('derive-') else
                core.audit(**params))
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,ensure_ascii=True,sort_keys=True,allow_nan=False,separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
