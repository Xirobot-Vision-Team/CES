#!/usr/bin/env python3
"""EC396 no-network, read-only verifier command entry point."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec395_accredited_gossip import operator as inherited_cli
from . import protocol as core


def parser():
    p=argparse.ArgumentParser(description=(
        'EC396 actual EC395 audit -> externally pinned signed registry status, '
        'RFC6962 genuine signed originals, RFC3161/CRL and two signed device copy readbacks. '
        'Never asserts public legal authority or physical WORM; strictly read-only.'))
    subs=p.add_subparsers(dest='command',required=True)
    old=next(x.choices['audit-historical-ec339-credential-gossip-archive']
       for x in inherited_cli.parser()._actions
       if isinstance(x,argparse._SubParsersAction))
    repeated={x.dest:x.option_strings[0] for x in old._actions
              if x.dest in core.PARENT_REPEATS and x.option_strings}
    if set(repeated)!=set(core.PARENT_REPEATS):
        raise RuntimeError('EC396 inherited EC395 CLI changed')
    for cmd in ('derive-historical-ec339-public-integrity-inventory',
                'audit-historical-ec339-public-integrity'):
        q=subs.add_parser(cmd,help='Reaudit actual EC395 and independently pinned EC396 original bytes')
        scalars=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if cmd.startswith('audit-'):scalars+=core.AUDIT_ONLY
        for k in scalars:q.add_argument('--'+k.replace('_','-'),required=True)
        for k,flag in (*((name,repeated[name]) for name in core.PARENT_REPEATS),
                       *core.NEW_REPEATS):
            q.add_argument(flag,dest=k,action='append',
                   **({'default':[]} if k=='historical_dual_handoff_shas' else {'required':True}),
                   **({'type':int} if k.startswith('minimum_') else {}))
    return p


def denial(cmd,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,code=exc.status,exc.code.upper()
    else:
        status,code='unavailable','EC396_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':cmd,'status':status,
            'reason_code':code,
            'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
            'offline_unresolved_exit_code':2,
            'sender_origin_path_required_or_read':False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
            **{key:False for key in core.NEGATIVES}}


def main(argv=None):
    opts=vars(parser().parse_args(argv));cmd=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
        None if x=='none' else x for x in opts['expected_source_attestation_head_shas']]
    try:
        report=core.derive_inventory(**opts) if cmd.startswith('derive-') else core.audit(**opts)
    except Exception as exc:
        report=denial(cmd,exc)
    print(json.dumps(report,ensure_ascii=True,sort_keys=True,allow_nan=False,separators=(',',':')))
    return report['exit_code']

if __name__=='__main__':raise SystemExit(main())
