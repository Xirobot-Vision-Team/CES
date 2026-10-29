#!/usr/bin/env python3
"""EC390 strict read-only operator, retaining EC389's exact CLI contract."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec389_external_revocation import operator as predecessor
from . import retained_heads as core


def parser():
    p=argparse.ArgumentParser(description='EC390 independent signed archive heads and independent retained receipts; strictly offline unresolved')
    subs=p.add_subparsers(dest='command',required=True)
    actions=next(a.choices['audit-historical-ec339-external-witness-archive']
        for a in predecessor.parser()._actions if isinstance(a,argparse._SubParsersAction))._actions
    inherited={a.dest:a.option_strings[0] for a in actions
               if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(inherited)!=set(core.PARENT_REPEATS):
        raise RuntimeError('EC390 inherited EC389 repeat CLI spelling drift')
    for cmd in ('derive-historical-ec339-independent-archive-inventory',
                'audit-historical-ec339-independent-archive-heads'):
        q=subs.add_parser(cmd,help='Require live EC389 audit then replay independently signed archive head/receipt originals')
        scalars=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if cmd.startswith('audit-'):scalars+=core.AUDIT_ONLY
        for key in scalars:
            q.add_argument('--'+key.replace('_','-'),required=True,
                           **({'type':int} if key.startswith('minimum_') else {}))
        for name,flag in (*((k,inherited[k]) for k in core.PARENT_REPEATS),*core.NEW_REPEATS):
            q.add_argument(flag,dest=name,action='append',
                **({'default':[]} if name=='historical_dual_handoff_shas' else {'required':True}),
                **({'type':int} if name.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,code=exc.status,exc.code.upper()
    else:status,code='unavailable','EC390_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
        'reason_code':code,'exit_code':{'permission_denied':3,'invalid_input':4,
        'unavailable':5}.get(status,5),'offline_unresolved_exit_code':2,
        'sender_origin_path_required_or_read':False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
        **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=parser().parse_args(argv);params=vars(args);cmd=params.pop('command')
    params['expected_source_attestation_head_shas']=[
        None if x=='none' else x for x in params['expected_source_attestation_head_shas']]
    try:
        res=(core.derive_inventory(**params) if cmd.startswith('derive-') else
             core.audit(**params))
    except Exception as exc:
        res=denial(cmd,exc)
    print(json.dumps(res,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')))
    return res['exit_code']

if __name__=='__main__':raise SystemExit(main())
