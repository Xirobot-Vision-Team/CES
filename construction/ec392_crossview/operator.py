#!/usr/bin/env python3
"""EC392 isolated read-only dual EC391 receiver; all pins explicit, no network."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec391_prior_time import operator as inherited_cli
from . import crossview as core


def parser():
    p=argparse.ArgumentParser(description=(
      'EC392 dual independently keyed offsite prior Head/RFC3161 histories, '
      'Ed25519 signed cross-view checkpoints, timestamped fork evidence; always unresolved'))
    sub=p.add_subparsers(dest='command',required=True)
    parent_action=next(action.choices['audit-historical-ec339-prior-offsite-time']
      for action in inherited_cli.parser()._actions
      if isinstance(action,argparse._SubParsersAction))
    inherited_repeats={a.dest:a.option_strings[0] for a in parent_action._actions
      if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(inherited_repeats)!=set(core.PARENT_REPEATS):
        raise RuntimeError('EC392 inherited EC391 CLI argument contract drift')
    for command in ('derive-historical-ec339-crossview-inventory',
                    'audit-historical-ec339-crossview'):
        q=sub.add_parser(command,help=(
          'Run BOTH real EC391->EC369 audits and verify signed cross-view '
          'checkpoints and their exact-byte CMS timestamp tokens'))
        scalars=(*core.PARENT_SCALARS,*core.NEW_SCALARS)
        if command.startswith('audit-'):scalars+=core.AUDIT_ONLY
        for name in scalars:
            q.add_argument('--'+name.replace('_','-'),required=True)
        for name,flag in (*((k,inherited_repeats[k]) for k in core.PARENT_REPEATS),
                          *core.NEW_REPEATS):
            q.add_argument(flag,dest=name,action='append',
              **({'default':[]} if name=='historical_dual_handoff_shas' else
                 {'required':True}),
              **({'type':int} if name.startswith('minimum_') else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,host.HostError)):
        status,code=exc.status,exc.code.upper()
    else:
        status,code='unavailable','EC392_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,
      'status':status,'reason_code':code,
      'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
      'offline_unresolved_exit_code':2,
      'sender_origin_path_required_or_read':False,
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
      **{key:False for key in core.NEGATIVES}}


def main(argv=None):
    args=parser().parse_args(argv);params=vars(args)
    command=params.pop('command')
    params['expected_source_attestation_head_shas']=[
       None if x=='none' else x for x in params['expected_source_attestation_head_shas']]
    try:
        result=(core.derive_inventory(**params) if command.startswith('derive-')
                else core.audit(**params))
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,ensure_ascii=True,sort_keys=True,allow_nan=False,
                     separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':
    raise SystemExit(main())
