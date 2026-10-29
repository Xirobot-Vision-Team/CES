#!/usr/bin/env python3
"""EC357 read-only review operator; original signed files are caller supplied."""
from __future__ import annotations
import argparse
import json
from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as errors
from ec352_key_registry import operator as registry_cli
from ec356_custody import operator as previous
from . import provenance as core

EXTRA_KEYS=('provenance_review_evaluation_utc','provenance_review_bundle_file',
            'expected_provenance_review_bundle_sha256',
            'source_a_authority_public_key_file',
            'expected_source_a_authority_public_key_sha256',
            'source_b_authority_public_key_file',
            'expected_source_b_authority_public_key_sha256')

def parser():
    p=argparse.ArgumentParser(description='EC357 offline signed source reviews (READ ONLY)')
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('derive-provenance-review-handoff','audit-institution-provenance'):
        s=sub.add_parser(command,help='replay genuine EC356 through EC337 original signatures')
        registry_cli.parent_cli.old_cli.old_cli.old_cli.old_cli._scalars(
            s,registry_cli.parent_cli.SCALARS)
        registry_cli.parent_cli.old_cli.old_cli.old_cli.old_cli._repeats(
            s,registry_cli.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS)
        for key in registry_cli.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS:
            flag=registry_cli.parent_cli.old_cli.old_cli.old_cli.FLAGS[key]
            s.add_argument('--'+flag.replace('_','-'),action='append',default=[])
        s.add_argument('--dual-evaluation-utc',required=True)
        for key,flag in registry_cli.parent_cli.old_cli.old_cli.ADDED_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=key,action='append',default=[])
        s.add_argument('--tsa-evaluation-utc',required=True)
        for key,flag in registry_cli.parent_cli.old_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=key,action='append',default=[])
        s.add_argument('--provenance-evaluation-utc',required=True)
        for key,flag in registry_cli.parent_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=key,action='append',default=[])
        s.add_argument('--registry-evaluation-utc',required=True)
        for key,flag in registry_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=key,action='append',default=[])
        for key in ('publication_evaluation_utc','publication_bundle_file',
                    'expected_publication_bundle_sha256','gossip_evaluation_utc',
                    'gossip_bundle_file','expected_gossip_bundle_sha256',
                    'checkpoint_disclosure_evaluation_utc',
                    'checkpoint_disclosure_bundle_file',
                    'expected_checkpoint_disclosure_bundle_sha256',
                    *previous.EXTRA_KEYS):
            s.add_argument('--'+key.replace('_','-'),required=True)
        if command=='audit-institution-provenance':
            s.add_argument('--provenance-review-evaluation-utc',required=True)
            for key in EXTRA_KEYS[1:]:
                s.add_argument('--'+key.replace('_','-'))
    return p

def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,code=exc.status,exc.code
    else:status,code='unavailable','EC357_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':code,'exit_code':{'permission_denied':3,
                'invalid_input':4,'unavailable':5}.get(status,5),
            'actual_ec356_through_ec337_originals_replayed':False,
            'offline_unresolved_exit_code':2,**{x:False for x in core.NEGATIVES}}

def main(argv=None):
    args=vars(parser().parse_args(argv));command=args.pop('command')
    for k in (*registry_cli.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
              *registry_cli.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=registry_cli.parent_cli.old_cli.old_cli.old_cli.FLAGS[k]
        if flag in args and flag!=k:args[k]=args.pop(flag)
    try:
        answer=core.checklist(**args) if command=='derive-provenance-review-handoff' else core.audit(**args)
    except Exception as exc:answer=denial(command,exc)
    print(json.dumps(answer,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                     allow_nan=False))
    return answer['exit_code']

if __name__=='__main__':raise SystemExit(main())
