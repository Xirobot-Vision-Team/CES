#!/usr/bin/env python3
"""EC382 exact offline audit/derive entry point; lawful exit 2 unresolved."""
from __future__ import annotations
import argparse
import json

from delivery_anchor import anchor as errors
from finding_query_host import protocol as host
from publication_accountability import accountability as p370
from historical_archive import archive as p371
from historical_authority import authority_archive as p372
from historical_inclusion import inclusion_archive as p373
from historical_owner import owner_archive as p374
from historical_custody import custody_archive as p375
from historical_disclosure import disclosure_archive as p376
from historical_transparency import transparency_archive as p377
from historical_registry import registry_archive as p378
from historical_source import source_archive as p379
from historical_timestamp import timestamp_archive as p380
from historical_channel import channel_archive as p381
from . import keeper_archive as core


def parser():
    p=argparse.ArgumentParser(description='EC382 old EC348 signed keeper root, receipt graph, EC347 readback and ledger replay; exit 2')
    subs=p.add_subparsers(dest='command',required=True)
    for cmd in ('derive-historical-ec348-keeper-inventory','audit-historical-ec348-keeper-archive'):
        q=subs.add_parser(cmd,help='SHA-pinned receiver local originals, never sender path or network')
        scalars=(*p370.prior.SCALARS,*p370.NEW_SCALARS,
          *p371.NEW_SCALARS,*p371.AUDIT_ONLY,*p372.NEW_SCALARS,*p372.AUDIT_ONLY,
          *p373.NEW_SCALARS,*p373.AUDIT_ONLY,*p374.NEW_SCALARS,*p374.AUDIT_ONLY,
          *p375.NEW_SCALARS,*p375.AUDIT_ONLY,*p376.NEW_SCALARS,*p376.AUDIT_ONLY,
          *p377.NEW_SCALARS,*p377.AUDIT_ONLY,*p378.NEW_SCALARS,*p378.AUDIT_ONLY,
          *p379.NEW_SCALARS,*p379.AUDIT_ONLY,*p380.NEW_SCALARS,*p380.AUDIT_ONLY,*p381.NEW_SCALARS,*p381.AUDIT_ONLY,*core.NEW_SCALARS)
        if cmd=='audit-historical-ec348-keeper-archive':scalars+=core.AUDIT_ONLY
        for key in scalars:
            q.add_argument('--'+key.replace('_','-'),required=True,
                           **({'type':int} if key.startswith('minimum_') else {}))
        for key,flag in (*p370.prior.REPEATS,*p370.NEW_REPEATS,*p371.NEW_REPEATS,
                         *p372.NEW_REPEATS,*p373.NEW_REPEATS,*p374.NEW_REPEATS,
                         *p375.NEW_REPEATS,*p376.NEW_REPEATS,*p377.NEW_REPEATS,
                         *p378.NEW_REPEATS,*p379.NEW_REPEATS,*p380.NEW_REPEATS,*p381.NEW_REPEATS,*core.NEW_REPEATS):
            q.add_argument(flag,dest=key,action='append',
                **({'default':[]} if key=='historical_dual_handoff_shas' else {'required':True}),
                **({'type':int} if key.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:status,reason='unavailable','EC382_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
       'reason_code':reason,
       'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
       'offline_unresolved_exit_code':2,
       'sender_origin_path_required_or_read':False,
       'ec348_through_ec337_full_independent_historical_parent_acceptance_performed':False,
       **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=parser().parse_args(argv);opts=vars(args);cmd=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
        None if v=='none' else v for v in opts['expected_source_attestation_head_shas']]
    try:
        result=(core.derive_inventory(**opts) if cmd=='derive-historical-ec348-keeper-inventory'
                else core.audit(**opts))
    except Exception as exc:result=denial(cmd,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,allow_nan=False,
                     separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
