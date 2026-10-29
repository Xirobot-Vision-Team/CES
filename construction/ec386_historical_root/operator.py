#!/usr/bin/env python3
"""EC386 read-only offline signed root conflict archive operator."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from . import root_archive as core
from ec385_historical_change import operator as previous


def parser():
    p=argparse.ArgumentParser(description='EC386 genuine old EC341 signed sibling roots under EC342 approved hold; receiver-only, unresolved')
    sub=p.add_subparsers(dest='command',required=True)
    for cmd in ('derive-historical-ec341-root-inventory',
                'audit-historical-ec341-root-conflict-archive'):
        q=sub.add_parser(cmd,help='True pinned old signed lineage and independent hold; no signer/network/provider')
        keys=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if cmd=='audit-historical-ec341-root-conflict-archive': keys+=core.AUDIT_ONLY
        for k in keys:
            q.add_argument('--'+k.replace('_','-'),required=True,
                           **({'type':int} if k.startswith('minimum_') else {}))
        for k,flag in (*previous.p370.prior.REPEATS,*previous.p370.NEW_REPEATS,
            *previous.p371.NEW_REPEATS,*previous.p372.NEW_REPEATS,
            *previous.p373.NEW_REPEATS,*previous.p374.NEW_REPEATS,
            *previous.p375.NEW_REPEATS,*previous.p376.NEW_REPEATS,
            *previous.p377.NEW_REPEATS,*previous.p378.NEW_REPEATS,
            *previous.p379.NEW_REPEATS,*previous.p380.NEW_REPEATS,
            *previous.p381.NEW_REPEATS,*previous.p382.NEW_REPEATS,
            *previous.p383.NEW_REPEATS,*previous.p384.NEW_REPEATS,
            *previous.core.NEW_REPEATS,*core.NEW_REPEATS):
            q.add_argument(flag,dest=k,action='append',required=True,
                           **({'type':int} if k.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:status,reason='unavailable','EC386_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,
      'status':status,'reason_code':reason,
      'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
      'offline_unresolved_exit_code':2,
      'sender_origin_path_required_or_read':False,
      'ec341_through_ec337_full_independent_original_historical_acceptance_performed':False,
      **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=parser().parse_args(argv);opts=vars(args);cmd=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
        None if x=='none' else x for x in opts['expected_source_attestation_head_shas']]
    try:
        doc=(core.derive_inventory(**opts) if cmd=='derive-historical-ec341-root-inventory'
             else core.audit(**opts))
    except Exception as exc:doc=denial(cmd,exc)
    print(json.dumps(doc,sort_keys=True,ensure_ascii=True,allow_nan=False,
                     separators=(',',':')))
    return doc['exit_code']

if __name__=='__main__':raise SystemExit(main())
