#!/usr/bin/env python3
"""EC373 isolated read-only historical inclusion + signed EC359 issuer CLI."""
from __future__ import annotations
import argparse
import json
from delivery_anchor import anchor as errors
from finding_query_host import protocol as host
from publication_accountability import accountability as p370
from historical_archive import archive as p371
from historical_authority import authority_archive as p372
from . import inclusion_archive as core


def parser():
    p=argparse.ArgumentParser(description='EC373 old genuine RFC6962 inclusion + EC359 signature audit; always unresolved')
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('audit-historical-inclusion-archive',
                    'derive-historical-inclusion-inventory'):
        q=sub.add_parser(command,help='Replays genuine receiver EC372 and original EC359 signatures')
        fields=(*p370.prior.SCALARS,*p370.NEW_SCALARS,
                *p371.NEW_SCALARS,*p371.AUDIT_ONLY,
                *p372.NEW_SCALARS,*p372.AUDIT_ONLY,*core.NEW_SCALARS)
        if command=='audit-historical-inclusion-archive':fields+=core.AUDIT_ONLY
        for key in fields:
            q.add_argument('--'+key.replace('_','-'),required=True,
                           **({'type':int} if key.startswith('minimum_') else {}))
        for key,flag in (*p370.prior.REPEATS,*p370.NEW_REPEATS,
                         *p371.NEW_REPEATS,*p372.NEW_REPEATS,*core.NEW_REPEATS):
            q.add_argument(flag,dest=key,action='append',
                     **({'required':True} if key!='historical_dual_handoff_shas'
                        else {'default':[]}),
                     **({'type':int} if key.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:
        status,reason='unavailable','EC373_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
        'reason_code':reason,
        'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
        'offline_unresolved_exit_code':2,
        'sender_origin_path_required_or_read':False,
        'ec365_to_ec337_full_parent_original_replay_performed':False,
        **{name:False for name in core.NEGATIVES}}


def main(argv=None):
    args=parser().parse_args(argv);fields=vars(args)
    command=fields.pop('command')
    fields['expected_source_attestation_head_shas']=[
        None if x=='none' else x for x in fields['expected_source_attestation_head_shas']]
    try:
        doc=(core.derive_inventory(**fields) if command==
             'derive-historical-inclusion-inventory' else core.audit(**fields))
    except Exception as exc:
        doc=denial(command,exc)
    print(json.dumps(doc,sort_keys=True,ensure_ascii=True,allow_nan=False,
                     separators=(',',':')))
    return doc['exit_code']

if __name__=='__main__':raise SystemExit(main())
