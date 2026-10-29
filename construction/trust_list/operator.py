#!/usr/bin/env python3
"""EC409 fixed-mode isolated original signed TSL offline operator."""
from __future__ import annotations
import argparse
import json
from delivery_anchor import anchor as errors
from finding_query_host import protocol as host
from institutional_ocsp import operator as previous
from . import protocol as core


def parser():
    p=argparse.ArgumentParser(description=(
        'Offline original ETSI TSL bounded XMLDSig and optional XAdES sign-property '
        'verification over real EC408 evidence; never official trust or PASS.'))
    sub=p.add_subparsers(dest='command',required=True)
    old=next(a.choices['audit-historical-ec339-institutional-ocsp']
             for a in previous.parser()._actions
             if isinstance(a,argparse._SubParsersAction))
    oldflags={a.dest:a.option_strings[0] for a in old._actions
              if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(oldflags)!=set(core.PARENT_REPEATS):
        raise RuntimeError('EC409 inherited EC408 CLI flags changed')
    for cmd in ('derive-historical-ec339-signed-tsl-inventory',
                'audit-historical-ec339-signed-tsl'):
        sp=sub.add_parser(cmd,help='Original signed TSL read-only verification')
        scalars=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if cmd.startswith('audit-'):scalars+=core.AUDIT_ONLY
        for name in scalars:
            sp.add_argument('--'+name.replace('_','-'),required=True)
        for name,flag in (*((name,oldflags[name]) for name in core.PARENT_REPEATS),
                          *core.NEW_REPEATS):
            sp.add_argument(flag,dest=name,action='append',
                            **({'default':[]} if name=='historical_dual_handoff_shas'
                               else {'required':True}),
                            **({'type':int} if name.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,code=exc.status,exc.code.upper()
    else:
        status,code='unavailable','EC409_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':code,
            'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
            'offline_unresolved_exit_code':2,
            'sender_origin_path_required_or_read':False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
            **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    opts=vars(parser().parse_args(argv))
    command=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
        None if x=='none' else x for x in opts['expected_source_attestation_head_shas']]
    try:
        result=(core.derive_inventory(**opts) if command.startswith('derive-')
                else core.audit(**opts))
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,
                     allow_nan=False,separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':
    raise SystemExit(main())
