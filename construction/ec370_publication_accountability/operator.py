#!/usr/bin/env python3
"""EC370 strict read-only publication-history standalone CLI."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as io
from ec369_detached_receiver import detached as inherited
from . import accountability as core


def parser():
    p=argparse.ArgumentParser(description=(
        'EC370 receiver-only publication/accountability: two actual Ed25519 '
        'signed SHA history streams, never global completeness, ALWAYS exit 2'))
    sub=p.add_subparsers(dest='command',required=True)
    q=sub.add_parser('audit-publication-accountability',help=(
        'replay live EC369 and cross-check two independent signed publication '
        'and observation streams from caller-pinned originals'))
    for k in (*inherited.SCALARS,*core.NEW_SCALARS):
        q.add_argument('--'+k.replace('_','-'),required=True,
                       **({'type':int} if k.startswith('minimum_') else {}))
    for k,flag in (*inherited.REPEATS,*core.NEW_REPEATS):
        q.add_argument(flag,dest=k,action='append',required=True)
    d=sub.add_parser('derive-publication-inventory',help=(
        'replay actual EC369 and export unsigned canonical SHA inventory for '
        'external genuine publisher/observer signing'))
    for k in inherited.SCALARS:
        d.add_argument('--'+k.replace('_','-'),required=True,
                       **({'type':int} if k.startswith('minimum_') else {}))
    for k,flag in inherited.REPEATS:
        d.add_argument(flag,dest=k,action='append',required=True)
    d.add_argument('--published-handoff-prefix-count',type=int)
    d.add_argument('--published-disclosure-prefix-count',type=int)
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:status,reason='unavailable','EC370_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,
        'status':status,'reason_code':reason,
        'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
        'offline_unresolved_exit_code':2,
        'original_sender_source_paths_required_or_read':False,
        'ec365_through_ec337_historical_parent_replay_performed':False,
        **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    opts=vars(parser().parse_args(argv));command=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
        None if v=='none' else v for v in opts['expected_source_attestation_head_shas']]
    try:
        if command=='derive-publication-inventory':
            h=opts.pop('published_handoff_prefix_count')
            d=opts.pop('published_disclosure_prefix_count')
            doc=core.derive_inventory(published_handoff_prefix_count=h,
                                      published_disclosure_prefix_count=d,**opts)
        else:doc=core.audit(**opts)
    except Exception as exc:doc=denial(command,exc)
    print(json.dumps(doc,ensure_ascii=True,sort_keys=True,allow_nan=False,
                     separators=(',',':')))
    return doc['exit_code']


if __name__=='__main__':raise SystemExit(main())
