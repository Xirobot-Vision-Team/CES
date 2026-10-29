#!/usr/bin/env python3
"""EC397 strict read-only CLI. Error results cannot be mistaken for success."""
from __future__ import annotations
import argparse
import json
from delivery_anchor import anchor as errors
from finding_query_host import protocol as host
from public_integrity import operator as parent_cli
from . import protocol as core


def parser():
    p=argparse.ArgumentParser(description=(
        'EC397 mandatory genuine EC396 re-audit, signed original publisher dispatch, '
        'two independent original-copy signed witness receipts and authentic fork '
        'evidence. Offline only; no claims of real-world publication or legal PASS.'))
    subs=p.add_subparsers(dest='command',required=True)
    old=next(a.choices['audit-historical-ec339-public-integrity']
       for a in parent_cli.parser()._actions if isinstance(a,argparse._SubParsersAction))
    repeated={a.dest:a.option_strings[0] for a in old._actions
              if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(repeated)!=set(core.PARENT_REPEATS):
        raise RuntimeError('EC397 inherited EC396 command has changed')
    for cmd in ('derive-historical-ec339-publication-witness-inventory',
                'audit-historical-ec339-publication-witness'):
        q=subs.add_parser(cmd,help='Open true EC396 originals, witness signed records and copies')
        names=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if cmd.startswith('audit-'):names+=core.AUDIT_ONLY
        for k in names:q.add_argument('--'+k.replace('_','-'),required=True)
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
        status,code='unavailable','EC397_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':cmd,'status':status,
        'reason_code':code,
        'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
        'offline_unresolved_exit_code':2,
        'sender_origin_path_required_or_read':False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
        **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    opts=vars(parser().parse_args(argv));cmd=opts.pop('command')
    opts['expected_source_attestation_head_shas']=[
      None if v=='none' else v for v in opts['expected_source_attestation_head_shas']]
    try:
        report=core.derive_inventory(**opts) if cmd.startswith('derive-') else core.audit(**opts)
    except Exception as exc:
        report=denial(cmd,exc)
    print(json.dumps(report,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')))
    return report['exit_code']

if __name__=='__main__':raise SystemExit(main())
