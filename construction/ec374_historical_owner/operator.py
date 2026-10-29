#!/usr/bin/env python3
"""EC374 receiver-only EC357+EC358 original signature archive CLI."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec370_publication_accountability import accountability as p370
from ec371_historical_archive import archive as p371
from ec372_historical_authority import authority_archive as p372
from ec373_historical_inclusion import inclusion_archive as p373
from . import owner_archive as core


def parser():
    p=argparse.ArgumentParser(description='EC374 receiver-held genuine EC357+EC358 signed originals; always unresolved')
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('derive-historical-owner-inventory','audit-historical-owner-archive'):
        q=sub.add_parser(command,help='Replay live EC373 receiver audit then verify historical owner signatures')
        scalars=(*p370.prior.SCALARS,*p370.NEW_SCALARS,
                 *p371.NEW_SCALARS,*p371.AUDIT_ONLY,
                 *p372.NEW_SCALARS,*p372.AUDIT_ONLY,
                 *p373.NEW_SCALARS,*p373.AUDIT_ONLY,*core.NEW_SCALARS)
        if command=='audit-historical-owner-archive':scalars+=core.AUDIT_ONLY
        for key in scalars:
            q.add_argument('--'+key.replace('_','-'),required=True,
                           **({'type':int} if key.startswith('minimum_') else {}))
        for key,flag in (*p370.prior.REPEATS,*p370.NEW_REPEATS,
                         *p371.NEW_REPEATS,*p372.NEW_REPEATS,
                         *p373.NEW_REPEATS,*core.NEW_REPEATS):
            q.add_argument(flag,dest=key,action='append',
                **({'required':True} if key!='historical_dual_handoff_shas'
                   else {'default':[]}),
                **({'type':int} if key.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:
        status,reason='unavailable','EC374_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
        'reason_code':reason,
        'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
        'offline_unresolved_exit_code':2,
        'sender_origin_path_required_or_read':False,
        'ec365_to_ec337_full_parent_original_replay_performed':False,
        **{name:False for name in core.NEGATIVES}}


def main(argv=None):
    args=parser().parse_args(argv);data=vars(args)
    command=data.pop('command')
    data['expected_source_attestation_head_shas']=[
        None if x=='none' else x for x in data['expected_source_attestation_head_shas']]
    try:
        doc=(core.derive_inventory(**data) if command==
             'derive-historical-owner-inventory' else core.audit(**data))
    except Exception as exc:
        doc=denial(command,exc)
    print(json.dumps(doc,sort_keys=True,ensure_ascii=True,allow_nan=False,
                     separators=(',',':')))
    return doc['exit_code']

if __name__=='__main__':raise SystemExit(main())
