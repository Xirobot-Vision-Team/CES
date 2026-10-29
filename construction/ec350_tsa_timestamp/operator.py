#!/usr/bin/env python3
"""EC350 read-only RFC3161 DER token audit, no signer/writer/network."""
from __future__ import annotations
import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as errors
from ec349_dual_channel_anchor import operator as old_cli
from . import timestamp as core

SCALARS = old_cli.SCALARS
PARENT_REPEATS = (*old_cli.PARENT_REPEATS,*old_cli.ADDED_REPEATS)
NEW_REPEATS = (
    ('tsa_channel_ids','tsa_token_channel_id'),
    ('tsa_token_files','tsa_token_file'),
    ('tsa_token_shas','expected_tsa_token_sha256'),
    ('tsa_root_files','tsa_root_certificate_file'),
    ('tsa_root_shas','expected_tsa_root_certificate_sha256'),
    ('tsa_policy_oids','tsa_expected_policy_oid'),
    ('tsa_crl_files','tsa_crl_file'),
    ('tsa_crl_shas','expected_tsa_crl_sha256'),
)


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description='EC350 independent DER RFC3161 TSA evidence; no outside clock authority implied')
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('derive-tsa-handoff','audit-tsa-evidence'):
        s=sub.add_parser(name,help='offline read-only EC349->EC337 real history replay')
        old_cli.old_cli.old_cli._scalars(s,SCALARS)
        old_cli.old_cli.old_cli._repeats(s,old_cli.old_cli.PARENT_REPEATS)
        for k in old_cli.old_cli.EXTRA_REPEATS:
            s.add_argument('--'+old_cli.old_cli.FLAGS[k].replace('_','-'),action='append',default=[])
        if name in ('derive-tsa-handoff','audit-tsa-evidence'):
            s.add_argument('--dual-evaluation-utc',required=True)
            for field,flag in old_cli.ADDED_REPEATS:
                s.add_argument('--'+flag.replace('_','-'),dest=field,action='append',default=[])
        if name=='audit-tsa-evidence':
            s.add_argument('--tsa-evaluation-utc',required=True)
            for field,flag in NEW_REPEATS:
                s.add_argument('--'+flag.replace('_','-'),dest=field,action='append',default=[])
    return p


def denial(command: str, exc:Exception)->dict:
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,code=exc.status,exc.code
    else:
        status,code='unavailable','EC350_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':code,'exit_code':{
                'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
            'ec349_full_signed_history_replayed':False,
            'offline_unresolved_exit_code':2,
            **{key:False for key in core.NEGATIVES}}


def main(argv=None)->int:
    args=vars(parser().parse_args(argv));command=args.pop('command')
    for k in (*old_cli.old_cli.PARENT_REPEATS,*old_cli.old_cli.EXTRA_REPEATS):
        flag=old_cli.old_cli.FLAGS[k]
        if flag in args and flag!=k:args[k]=args.pop(flag)
    try:
        doc=(core.checklist(**args) if command=='derive-tsa-handoff' else
             core.audit(**args))
    except Exception as exc:
        doc=denial(command,exc)
    print(json.dumps(doc,ensure_ascii=True,sort_keys=True,
                     allow_nan=False,separators=(',',':')))
    return doc['exit_code']

if __name__=='__main__':
    raise SystemExit(main())
