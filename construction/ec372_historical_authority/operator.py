#!/usr/bin/env python3
"""EC372 bounded read-only receiver-only historical root/witness original CLI."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec370_publication_accountability import accountability as ec370
from ec371_historical_archive import archive as ec371
from . import authority_archive as core


def parser():
    p=argparse.ArgumentParser(description='EC372 true receiver historical EC360 signatures; all lawful responses exit2')
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('audit-historical-authority-archive',
                    'derive-historical-authority-inventory'):
        q=sub.add_parser(command,help='replays EC371 and verifies caller-pinned old authority original SHA/signatures')
        fields=(*ec370.prior.SCALARS, *ec370.NEW_SCALARS,
                *ec371.NEW_SCALARS,*ec371.AUDIT_ONLY,*core.NEW_SCALARS)
        if command=='audit-historical-authority-archive':fields+=core.AUDIT_ONLY
        for key in fields:
            q.add_argument('--'+key.replace('_','-'),required=True,
                  **({'type':int} if key.startswith('minimum_') else {}))
        for key,flag in (*ec370.prior.REPEATS,*ec370.NEW_REPEATS,
                         *ec371.NEW_REPEATS,*core.NEW_REPEATS):
            q.add_argument(flag,dest=key,action='append',
                  **({'required':True} if key not in ('historical_dual_handoff_shas',)
                     else {'default':[]}),
                  **({'type':int} if key.startswith('minimum_') else {}))
    return p


def denial(command, exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:
        status,reason='unavailable','EC372_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':reason,'exit_code':{
             'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
            'offline_unresolved_exit_code':2,
            'sender_origin_path_required_or_read':False,
            'ec365_to_ec337_full_parent_original_replay_performed':False,
            **{name:False for name in core.NEGATIVES}}


def main(argv=None):
    p=parser();args=p.parse_args(argv);fields=vars(args)
    command=fields.pop('command')
    fields['expected_source_attestation_head_shas']=[
         None if x=='none' else x for x in fields['expected_source_attestation_head_shas']]
    try:
        doc=(core.derive_inventory(**fields) if command==
             'derive-historical-authority-inventory' else core.audit(**fields))
    except Exception as exc:
        doc=denial(command,exc)
    print(json.dumps(doc,sort_keys=True,ensure_ascii=True,allow_nan=False,
                     separators=(',',':')))
    return doc['exit_code']

if __name__=='__main__':raise SystemExit(main())
