#!/usr/bin/env python3
"""EC389 bounded original signed publication/custody read-only operator."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec388_historical_revocation import operator as predecessor
from . import witness_custody as core


def parser():
    p=argparse.ArgumentParser(description='EC389 verify two independently signed external historical EC339 revocation witness/custody originals; unresolved')
    sub=p.add_subparsers(dest='command',required=True)
    for cmd in ('derive-historical-ec339-external-witness-inventory',
                'audit-historical-ec339-external-witness-archive'):
        q=sub.add_parser(cmd,help='Reopen genuine EC388 signed revoked status and verify signed external publication plus custody')
        keys=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if cmd=='audit-historical-ec339-external-witness-archive':keys+=core.AUDIT_ONLY
        for key in keys:q.add_argument('--'+key.replace('_','-'),required=True,
                  **({'type':int} if key.startswith('minimum_') else {}))
        # Inherit the exact, already deployed EC388 command-line spelling of
        # every historic repeat; do not try to regenerate legacy --sha256 flags
        # from Python plural field names or silently omit an ancestor option.
        actions=next(a.choices['audit-historical-ec339-retirement-archive']
           for a in predecessor.parser()._actions
           if isinstance(a,argparse._SubParsersAction))._actions
        inherited={a.dest:a.option_strings[0] for a in actions
           if a.dest in core.PARENT_REPEATS and a.option_strings}
        if set(inherited)!=set(core.PARENT_REPEATS):
            raise RuntimeError('EC389 inherited EC388 repeat CLI contract drift')
        for name,flag in (*((n,inherited[n]) for n in core.PARENT_REPEATS),*core.NEW_REPEATS):
            q.add_argument(flag,dest=name,action='append',
                **({'default':[]} if name=='historical_dual_handoff_shas' else {'required':True}),
                **({'type':int} if name.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:status,reason='unavailable','EC389_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
       'reason_code':reason,'exit_code':{'permission_denied':3,'invalid_input':4,
       'unavailable':5}.get(status,5),'offline_unresolved_exit_code':2,
       'sender_origin_path_required_or_read':False,
       'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
       **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=parser().parse_args(argv);opts=vars(args);cmd=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[None if x=='none' else x for x in
         opts['expected_source_attestation_head_shas']]
    try:
        res=(core.derive_inventory(**opts) if cmd=='derive-historical-ec339-external-witness-inventory'
             else core.audit(**opts))
    except Exception as exc:res=denial(cmd,exc)
    print(json.dumps(res,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')))
    return res['exit_code']

if __name__=='__main__':raise SystemExit(main())
