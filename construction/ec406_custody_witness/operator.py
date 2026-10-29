#!/usr/bin/env python3
"""EC406 isolated offline CLI for original dual-signed custody/cross-witness evidence."""
from __future__ import annotations

import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec405_warc_time import operator as prior
from . import protocol as core


def parser():
    p=argparse.ArgumentParser(description=(
        'EC406 original Ed25519 custodian accession plus separate cross-witness '
        'binding to real EC405 WARC/RFC3161, unbroken original history, no legal PASS.'))
    sub=p.add_subparsers(dest='command',required=True)
    old=next(a.choices['audit-historical-ec339-warc-timestamp']
             for a in prior.parser()._actions
             if isinstance(a,argparse._SubParsersAction))
    oldflags={a.dest:a.option_strings[0] for a in old._actions
              if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(oldflags)!=set(core.PARENT_REPEATS):
        raise RuntimeError('EC406 inherited EC405 real CLI flags changed')
    for cmd in ('derive-historical-ec339-custody-witness-inventory',
                'audit-historical-ec339-custody-witness'):
        sp=sub.add_parser(cmd,help='Read dual genuine original signatures, no issuance')
        scalars=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if cmd.startswith('audit-'):scalars+=core.AUDIT_ONLY
        for k in scalars:
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
        status,code='unavailable','EC406_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':code,'exit_code':{'permission_denied':3,
                'invalid_input':4,'unavailable':5}.get(status,5),
            'offline_unresolved_exit_code':2,
            'sender_origin_path_required_or_read':False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
            **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    data=vars(parser().parse_args(argv))
    command=data.pop('command')
    data['expected_source_attestation_head_shas']=[
        None if x=='none' else x for x in data['expected_source_attestation_head_shas']]
    try:
        result=core.derive_inventory(**data) if command.startswith('derive-') else core.audit(**data)
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,
                     allow_nan=False,separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':
    raise SystemExit(main())
