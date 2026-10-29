#!/usr/bin/env python3
"""EC352 bounded, offline, all-original, read-only registry history CLI."""
from __future__ import annotations
import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as errors
from ec351_tsa_provenance import operator as parent_cli
from . import registry as core

NEW_REPEATS=(
    ('registry_channel_ids','registry_channel_id'),
    ('registry_root_reference_files','registry_root_reference_file'),
    ('registry_root_reference_shas','expected_registry_root_reference_sha256'),
    ('registry_root_key_files','registry_root_public_key_file'),
    ('registry_root_key_shas','expected_registry_root_public_key_sha256'),
    ('registry_event_channel_ids','registry_event_channel_id'),
    ('registry_event_files','registry_event_file'),
    ('registry_event_shas','expected_registry_event_sha256'),
    ('registry_signer_key_files','registry_signer_public_key_file'),
    ('registry_signer_key_shas','expected_registry_signer_public_key_sha256'),
)


def parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser(description='EC352 verified offline attester-key root references and signer rotation histories')
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('derive-registry-handoff','audit-registry-history'):
        s=sub.add_parser(command,help='actually re-execute all furnished EC351 through EC337 original evidence')
        parent_cli.old_cli.old_cli.old_cli.old_cli._scalars(s,parent_cli.SCALARS)
        parent_cli.old_cli.old_cli.old_cli.old_cli._repeats(
            s,parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS)
        for k in parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS:
            s.add_argument('--'+parent_cli.old_cli.old_cli.old_cli.FLAGS[k].replace('_','-'),
                           action='append',default=[])
        s.add_argument('--dual-evaluation-utc',required=True)
        for field,flag in parent_cli.old_cli.old_cli.ADDED_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=field,action='append',default=[])
        s.add_argument('--tsa-evaluation-utc',required=True)
        for field,flag in parent_cli.old_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=field,action='append',default=[])
        s.add_argument('--provenance-evaluation-utc',required=True)
        for field,flag in parent_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=field,action='append',default=[])
        if command=='audit-registry-history':
            s.add_argument('--registry-evaluation-utc',required=True)
            for field,flag in NEW_REPEATS:
                s.add_argument('--'+flag.replace('_','-'),dest=field,
                               action='append',default=[])
    return p


def denial(command:str,exc:Exception)->dict:
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,code=exc.status,exc.code
    else:status,code='unavailable','EC352_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':code,
            'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
            'ec351_to_ec337_actual_signed_originals_replayed':False,
            'offline_unresolved_exit_code':2,
            **{k:False for k in core.NEGATIVES}}


def main(argv=None)->int:
    args=vars(parser().parse_args(argv));command=args.pop('command')
    for k in (*parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
              *parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=parent_cli.old_cli.old_cli.old_cli.FLAGS[k]
        if flag in args and flag!=k:args[k]=args.pop(flag)
    try:
        result=(core.checklist(**args) if command=='derive-registry-handoff'
                else core.audit(**args))
    except Exception as exc:result=denial(command,exc)
    print(json.dumps(result,ensure_ascii=True,sort_keys=True,
                     allow_nan=False,separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
