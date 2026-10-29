#!/usr/bin/env python3
"""EC356 bounded offline two-channel custody operator: READ ONLY."""
from __future__ import annotations
import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as errors
from ec355_disclosure import operator as parent_operator
from ec352_key_registry import operator as registry_cli
from . import custody as core

EXTRA_KEYS=(
    'two_channel_custody_evaluation_utc','custody_bundle_file','expected_custody_bundle_sha256',
    'root_a_public_key_file','expected_root_a_public_key_sha256',
    'root_b_public_key_file','expected_root_b_public_key_sha256',
)


def parser():
    p=argparse.ArgumentParser(description='EC356 offline signed 2-root SHA custody (READ ONLY)')
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('derive-custody-handoff','audit-two-channel-custody'):
        s=sub.add_parser(command,help='replay EC355 through EC337 signed original bytes')
        registry_cli.parent_cli.old_cli.old_cli.old_cli.old_cli._scalars(
            s,registry_cli.parent_cli.SCALARS)
        registry_cli.parent_cli.old_cli.old_cli.old_cli.old_cli._repeats(
            s,registry_cli.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS)
        for k in registry_cli.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS:
            flag=registry_cli.parent_cli.old_cli.old_cli.old_cli.FLAGS[k]
            s.add_argument('--'+flag.replace('_','-'),action='append',default=[])
        s.add_argument('--dual-evaluation-utc',required=True)
        for k,flag in registry_cli.parent_cli.old_cli.old_cli.ADDED_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        s.add_argument('--tsa-evaluation-utc',required=True)
        for k,flag in registry_cli.parent_cli.old_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        s.add_argument('--provenance-evaluation-utc',required=True)
        for k,flag in registry_cli.parent_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        s.add_argument('--registry-evaluation-utc',required=True)
        for k,flag in registry_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=k,action='append',default=[])
        for key in ('publication_evaluation_utc','publication_bundle_file',
                    'expected_publication_bundle_sha256','gossip_evaluation_utc',
                    'gossip_bundle_file','expected_gossip_bundle_sha256',
                    'checkpoint_disclosure_evaluation_utc',
                    'checkpoint_disclosure_bundle_file',
                    'expected_checkpoint_disclosure_bundle_sha256'):
            s.add_argument('--'+key.replace('_','-'),required=True)
        if command=='audit-two-channel-custody':
            for key in EXTRA_KEYS:
                s.add_argument('--'+key.replace('_','-'),required=True)
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,code=exc.status,exc.code
    else:status,code='unavailable','EC356_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':code,
            'exit_code':{'permission_denied':3,'invalid_input':4,
                         'unavailable':5}.get(status,5),
            'actual_ec355_through_ec337_signed_originals_replayed':False,
            'offline_unresolved_exit_code':2,
            **{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=vars(parser().parse_args(argv));command=args.pop('command')
    for k in (*registry_cli.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
              *registry_cli.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=registry_cli.parent_cli.old_cli.old_cli.old_cli.FLAGS[k]
        if flag in args and flag!=k:args[k]=args.pop(flag)
    try:
        output=(core.checklist(**args) if command=='derive-custody-handoff'
                else core.audit(**args))
    except Exception as exc:output=denial(command,exc)
    print(json.dumps(output,ensure_ascii=True,sort_keys=True,
                     separators=(',',':'),allow_nan=False))
    return output['exit_code']

if __name__=='__main__':raise SystemExit(main())
