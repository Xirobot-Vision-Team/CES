#!/usr/bin/env python3
"""EC385 receiver-only original EC342 approval / EC343 signed transition operator."""
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
from historical_keeper import keeper_archive as p382
from historical_readback import readback_archive as p383
from historical_offer import offer_archive as p384
from . import change_archive as core


def parser():
    p=argparse.ArgumentParser(description='EC385 original EC342 signed approved hold and EC343 independent signed changes; read-only unresolved')
    subs=p.add_subparsers(dest='command',required=True)
    for cmd in ('derive-historical-ec343-change-inventory',
                'audit-historical-ec343-change-archive'):
        q=subs.add_parser(cmd,help='Historical SHA-pinned local originals; no private signer/network/provider')
        scalars=(*p370.prior.SCALARS,*p370.NEW_SCALARS,
          *p371.NEW_SCALARS,*p371.AUDIT_ONLY,*p372.NEW_SCALARS,*p372.AUDIT_ONLY,
          *p373.NEW_SCALARS,*p373.AUDIT_ONLY,*p374.NEW_SCALARS,*p374.AUDIT_ONLY,
          *p375.NEW_SCALARS,*p375.AUDIT_ONLY,*p376.NEW_SCALARS,*p376.AUDIT_ONLY,
          *p377.NEW_SCALARS,*p377.AUDIT_ONLY,*p378.NEW_SCALARS,*p378.AUDIT_ONLY,
          *p379.NEW_SCALARS,*p379.AUDIT_ONLY,*p380.NEW_SCALARS,*p380.AUDIT_ONLY,
          *p381.NEW_SCALARS,*p381.AUDIT_ONLY,*p382.NEW_SCALARS,*p382.AUDIT_ONLY,*p383.NEW_SCALARS,*p383.AUDIT_ONLY,*p384.NEW_SCALARS,*p384.AUDIT_ONLY,
          *core.NEW_SCALARS)
        if cmd=='audit-historical-ec343-change-archive':
            scalars+=core.AUDIT_ONLY
        for key in scalars:
            q.add_argument('--'+key.replace('_','-'),required=True,
                           **({'type':int} if key.startswith('minimum_') else {}))
        for key,flag in (*p370.prior.REPEATS,*p370.NEW_REPEATS,*p371.NEW_REPEATS,
                         *p372.NEW_REPEATS,*p373.NEW_REPEATS,*p374.NEW_REPEATS,
                         *p375.NEW_REPEATS,*p376.NEW_REPEATS,*p377.NEW_REPEATS,
                         *p378.NEW_REPEATS,*p379.NEW_REPEATS,*p380.NEW_REPEATS,
                         *p381.NEW_REPEATS,*p382.NEW_REPEATS,*p383.NEW_REPEATS,*p384.NEW_REPEATS,*core.NEW_REPEATS):
            q.add_argument(flag,dest=key,action='append',
                **({'default':[]} if key=='historical_dual_handoff_shas'
                   else {'required':True}),
                **({'type':int} if key.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:
        status,reason='unavailable','EC385_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
       'reason_code':reason,
       'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
       'offline_unresolved_exit_code':2,
       'sender_origin_path_required_or_read':False,
       'ec343_through_ec337_full_independent_original_historical_acceptance_performed':False,
       **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=parser().parse_args(argv);opts=vars(args);cmd=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
        None if v=='none' else v for v in opts['expected_source_attestation_head_shas']]
    try:
        result=(core.derive_inventory(**opts) if cmd=='derive-historical-ec343-change-inventory'
                else core.audit(**opts))
    except Exception as exc:result=denial(cmd,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,allow_nan=False,
                     separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
