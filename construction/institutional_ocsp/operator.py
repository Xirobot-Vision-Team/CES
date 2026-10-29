#!/usr/bin/env python3
"""EC408 isolated offline original institutional OCSP operator (no signatures issued)."""
from __future__ import annotations

import argparse
import json
from delivery_anchor import anchor as errors
from finding_query_host import protocol as host
from institutional_cms import operator as prior
from . import protocol as core


def parser():
    p=argparse.ArgumentParser(description=(
        'Verify issuer/delegate-signed RFC6960 historical AND evaluation original '
        'OCSP for the two original EC407 institutional X.509 leaves, retaining '
        'all genuine parent original checks; always unresolved, never official trust.'))
    sub=p.add_subparsers(dest='command',required=True)
    old=next(a.choices['audit-historical-ec339-institutional-cms']
             for a in prior.parser()._actions
             if isinstance(a,argparse._SubParsersAction))
    oldflags={a.dest:a.option_strings[0] for a in old._actions
              if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(oldflags)!=set(core.PARENT_REPEATS):
        raise RuntimeError('EC408 inherited EC407 CLI flags changed')
    for cmd in ('derive-historical-ec339-institutional-ocsp-inventory',
                'audit-historical-ec339-institutional-ocsp'):
        sp=sub.add_parser(cmd,help='Read-only original DER, original SHA and temporal status')
        scalar=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if cmd.startswith('audit-'):
            scalar+=core.AUDIT_ONLY
        for k in scalar:
            sp.add_argument('--'+k.replace('_','-'),required=True)
        for name,flag in (*((k,oldflags[k]) for k in core.PARENT_REPEATS),
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
        status,code='unavailable','EC408_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
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
