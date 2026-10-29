#!/usr/bin/env python3
"""EC398 fixed offline derive/audit commands. Only static source reads."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec397_publication_witness import operator as prior_cli
from . import protocol as core


def parser():
    p=argparse.ArgumentParser(description=(
       'EC398 real EC397 re-audit, new independently pinned registrar notice, '
       'revocation/status cross-check and two signed custodians each recovering '
       'three original files; offline and legally unresolved.'))
    subs=p.add_subparsers(dest='command',required=True)
    previous=next(a.choices['audit-historical-ec339-publication-witness']
        for a in prior_cli.parser()._actions if isinstance(a,argparse._SubParsersAction))
    repeats={a.dest:a.option_strings[0] for a in previous._actions
               if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(repeats)!=set(core.PARENT_REPEATS):
        raise RuntimeError('EC398 inherited EC397 flags unexpectedly changed')
    for cmd in ('derive-historical-ec339-external-notice-inventory',
                'audit-historical-ec339-external-notice'):
        q=subs.add_parser(cmd,help='Reopen real signed parent and new source/custody originals')
        scalars=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if cmd.startswith('audit-'):scalars+=core.AUDIT_ONLY
        for k in scalars:q.add_argument('--'+k.replace('_','-'),required=True)
        for k,flag in (*((k,repeats[k]) for k in core.PARENT_REPEATS),*core.NEW_REPEATS):
            q.add_argument(flag,dest=k,action='append',
                **({'default':[]} if k=='historical_dual_handoff_shas' else {'required':True}),
                **({'type':int} if k.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,reason=exc.status,exc.code.upper()
    else:
        status,reason='unavailable','EC398_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
       'reason_code':reason,
       'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
       'offline_unresolved_exit_code':2,'sender_origin_path_required_or_read':False,
       'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
       **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    opts=vars(parser().parse_args(argv));cmd=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
       None if x=='none' else x for x in opts['expected_source_attestation_head_shas']]
    try:
        report=core.derive_inventory(**opts) if cmd.startswith('derive-') else core.audit(**opts)
    except Exception as exc:
        report=denial(cmd,exc)
    print(json.dumps(report,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')))
    return report['exit_code']

if __name__=='__main__':raise SystemExit(main())
