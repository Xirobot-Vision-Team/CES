#!/usr/bin/env python3
"""EC388 strictly read-only, receiver supplied original EC339 retirement evidence."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec387_historical_rotation import operator as predecessor
from . import revocation_archive as core


def parser():
    p=argparse.ArgumentParser(description='EC388 authentic old EC338/EC339 signed actor/grant and retirement revocation status; read-only, unresolved')
    subs=p.add_subparsers(dest='command',required=True)
    for cmd in ('derive-historical-ec339-retirement-inventory',
                'audit-historical-ec339-retirement-archive'):
        q=subs.add_parser(cmd,help='Recheck 4 original role-signed receipts, grants and challenged historical status transitions')
        keys=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if cmd=='audit-historical-ec339-retirement-archive':keys+=core.AUDIT_ONLY
        for name in keys:
            q.add_argument('--'+name.replace('_','-'),required=True,
                           **({'type':int} if name.startswith('minimum_') else {}))
        for name,flag in (*predecessor.predecessor.previous.p370.prior.REPEATS,
             *predecessor.predecessor.previous.p370.NEW_REPEATS,
             *predecessor.predecessor.previous.p371.NEW_REPEATS,
             *predecessor.predecessor.previous.p372.NEW_REPEATS,
             *predecessor.predecessor.previous.p373.NEW_REPEATS,
             *predecessor.predecessor.previous.p374.NEW_REPEATS,
             *predecessor.predecessor.previous.p375.NEW_REPEATS,
             *predecessor.predecessor.previous.p376.NEW_REPEATS,
             *predecessor.predecessor.previous.p377.NEW_REPEATS,
             *predecessor.predecessor.previous.p378.NEW_REPEATS,
             *predecessor.predecessor.previous.p379.NEW_REPEATS,
             *predecessor.predecessor.previous.p380.NEW_REPEATS,
             *predecessor.predecessor.previous.p381.NEW_REPEATS,
             *predecessor.predecessor.previous.p382.NEW_REPEATS,
             *predecessor.predecessor.previous.p383.NEW_REPEATS,
             *predecessor.predecessor.previous.p384.NEW_REPEATS,
             *predecessor.predecessor.previous.core.NEW_REPEATS,
             *predecessor.predecessor.core.NEW_REPEATS,
             *predecessor.core.NEW_REPEATS,
             *core.NEW_REPEATS):
            q.add_argument(flag,dest=name,action='append',
                           **({'default':[]} if name=='historical_dual_handoff_shas'
                              else {'required':True}),
                           **({'type':int} if name.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:status,reason='unavailable','EC388_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
       'reason_code':reason,
       'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
       'offline_unresolved_exit_code':2,
       'sender_origin_path_required_or_read':False,
       'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
       **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=parser().parse_args(argv); opts=vars(args); cmd=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
        None if v=='none' else v for v in opts['expected_source_attestation_head_shas']]
    try:
        result=(core.derive_inventory(**opts) if cmd=='derive-historical-ec339-retirement-inventory'
                else core.audit(**opts))
    except Exception as exc:result=denial(cmd,exc)
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
