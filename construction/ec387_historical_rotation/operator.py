#!/usr/bin/env python3
"""EC387 strict receiver-only old EC340 rotation inventory / audit entrypoint."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec386_historical_root import operator as predecessor
from . import rotation_archive as core


def parser():
    p=argparse.ArgumentParser(description='EC387 authentic old EC340 signed epoch1->2 handoff and EC341/342 parent; read-only, unresolved')
    subs=p.add_subparsers(dest='command',required=True)
    for cmd in ('derive-historical-ec340-rotation-inventory',
                'audit-historical-ec340-rotation-archive'):
        q=subs.add_parser(cmd,help='Original old 8-role edges, challenged witness, EC339 signed role history; no key/network/provider')
        keys=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if cmd=='audit-historical-ec340-rotation-archive':keys+=core.AUDIT_ONLY
        for key in keys:
            q.add_argument('--'+key.replace('_','-'),required=True,
                           **({'type':int} if key.startswith('minimum_') else {}))
        for key,flag in (*predecessor.previous.p370.prior.REPEATS,
             *predecessor.previous.p370.NEW_REPEATS,
             *predecessor.previous.p371.NEW_REPEATS,
             *predecessor.previous.p372.NEW_REPEATS,
             *predecessor.previous.p373.NEW_REPEATS,
             *predecessor.previous.p374.NEW_REPEATS,
             *predecessor.previous.p375.NEW_REPEATS,
             *predecessor.previous.p376.NEW_REPEATS,
             *predecessor.previous.p377.NEW_REPEATS,
             *predecessor.previous.p378.NEW_REPEATS,
             *predecessor.previous.p379.NEW_REPEATS,
             *predecessor.previous.p380.NEW_REPEATS,
             *predecessor.previous.p381.NEW_REPEATS,
             *predecessor.previous.p382.NEW_REPEATS,
             *predecessor.previous.p383.NEW_REPEATS,
             *predecessor.previous.p384.NEW_REPEATS,
             *predecessor.previous.core.NEW_REPEATS,
             *predecessor.core.NEW_REPEATS,
             *core.NEW_REPEATS):
            q.add_argument(flag,action='append',dest=key,
                           **({'default':[]} if key=='historical_dual_handoff_shas'
                              else {'required':True}),
                           **({'type':int} if key.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:status,reason='unavailable','EC387_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,
      'status':status,'reason_code':reason,
      'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
      'offline_unresolved_exit_code':2,
      'sender_origin_path_required_or_read':False,
      'ec340_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
      **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=parser().parse_args(argv);opts=vars(args);cmd=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
        None if x=='none' else x for x in opts['expected_source_attestation_head_shas']]
    try:
        doc=(core.derive_inventory(**opts) if cmd=='derive-historical-ec340-rotation-inventory'
             else core.audit(**opts))
    except Exception as exc:doc=denial(cmd,exc)
    print(json.dumps(doc,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')))
    return doc['exit_code']

if __name__=='__main__':raise SystemExit(main())
