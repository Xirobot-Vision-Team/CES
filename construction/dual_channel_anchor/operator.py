#!/usr/bin/env python3
"""EC349 standalone offline, SHA-pinned no-private-key dual-channel audit."""
from __future__ import annotations
import argparse
import json
from finding_query_host import protocol as io
from delivery_anchor import anchor
from external_custody import operator as old_cli
from . import anchor as core

SCALARS = (*old_cli.SCALARS, *old_cli.EXTRA_SCALARS)
PARENT_REPEATS = (*old_cli.PARENT_REPEATS, *old_cli.EXTRA_REPEATS)
ADDED_REPEATS = (
    ('channel_directory_files','channel_directory_file'),
    ('channel_directory_shas','expected_channel_directory_sha256'),
    ('channel_root_public_hexes','expected_channel_root_public_hex'),
    ('channel_receipt_files','channel_receipt_file'),
    ('channel_receipt_shas','expected_channel_receipt_sha256'),
    ('time_witness_files','time_witness_file'),
    ('time_witness_shas','expected_time_witness_sha256'),
)


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description='EC349 two out-of-band SHA channel claims; never physical identity or trusted time')
    subs=p.add_subparsers(dest='command',required=True)
    for name in ('derive-handoff','audit-dual-anchors'):
        s=subs.add_parser(name,help='read-only full EC348->EC337 replay, no signing')
        old_cli.old_cli._scalars(s,SCALARS)
        old_cli.old_cli._repeats(s,old_cli.PARENT_REPEATS)
        for k in old_cli.EXTRA_REPEATS:
            s.add_argument('--'+old_cli.FLAGS[k].replace('_','-'),action='append',default=[])
        if name=='audit-dual-anchors':
            s.add_argument('--dual-evaluation-utc',required=True)
            for field,flag in ADDED_REPEATS:
                s.add_argument('--'+flag.replace('_','-'),dest=field,action='append',default=[])
    return p


def denial(command: str, exc: Exception)->dict:
    if isinstance(exc,(anchor.AnchorError,io.HostError)):
        status,code=exc.status,exc.code
    else:
        status,code='unavailable','EC349_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':code,'exit_code':{
                'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
            'ec348_full_signed_source_replayed':False,
            'offline_unresolved_exit_code':2,
            **{key:False for key in core.NEGATIVES}}


def main(argv=None)->int:
    args=vars(parser().parse_args(argv));command=args.pop('command')
    for k in PARENT_REPEATS:
        flag=old_cli.FLAGS[k]
        if k!=flag and flag in args:
            args[k]=args.pop(flag)
    try:
        result=(core.derive_handoff if command=='derive-handoff' else
                core.audit_dual_anchors)(**args)
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,ensure_ascii=True,sort_keys=True,
                     allow_nan=False,separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':
    raise SystemExit(main())
