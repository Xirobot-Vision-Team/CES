#!/usr/bin/env python3
"""EC360 isolated, read-only offline authority and revocation entrypoint."""
from __future__ import annotations
import argparse
import json

from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as io
from ec352_key_registry import operator as registry_cli
from ec359_owner_distribution import operator as previous_cli
from . import authority as core

NEW_KEYS = (
    'authority_evaluation_utc',
    'authority_bundle_file','expected_authority_bundle_sha256',
    'authority_a_root_public_key_file','expected_authority_a_root_public_key_sha256',
    'authority_b_root_public_key_file','expected_authority_b_root_public_key_sha256',
    'origin_a_witness_public_key_file','expected_origin_a_witness_public_key_sha256',
    'origin_b_witness_public_key_file','expected_origin_b_witness_public_key_sha256',
    'minimum_a_revocation_sequence','minimum_b_revocation_sequence',
    'expected_a_revocation_head_sha256','expected_b_revocation_head_sha256',
    'directory_public_key_file','expected_directory_public_key_sha256',
    'directory_checkpoint_file','expected_directory_checkpoint_sha256',
    'minimum_directory_tree_size','expected_directory_head_sha256',
)
INTEGERS={'minimum_a_revocation_sequence','minimum_b_revocation_sequence',
          'minimum_directory_tree_size'}


def parser():
    p=argparse.ArgumentParser(description='EC360 genuine EC359..EC337 offline provenance and revocations')
    subs=p.add_subparsers(dest='command',required=True)
    for command in ('derive-authority-directory-handoff','audit-authority-directory'):
        s=subs.add_parser(command,help='never certify locally pinned keys as official institutions')
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
                    *previous_cli.previous.previous.previous.EXTRA_KEYS):
            s.add_argument('--'+key.replace('_','-'),required=True)
        for key in previous_cli.previous.previous.EXTRA_KEYS:
            s.add_argument('--'+key.replace('_','-'),
                           required=(key=='provenance_review_evaluation_utc'))
        s.add_argument('--reviewer-epoch-evaluation-utc',required=True)
        for key in previous_cli.previous.EXTRA_KEYS[1:]:
            s.add_argument('--'+key.replace('_','-'),
                           **({'type':int} if key in ('minimum_a_epoch','minimum_b_epoch') else {}))
        s.add_argument('--distribution-evaluation-utc',required=True)
        for key in previous_cli.EXTRA_KEYS[1:]:
            s.add_argument('--'+key.replace('_','-'),
                           **({'type':int} if key in ('minimum_a_distribution_sequence',
                                                     'minimum_b_distribution_sequence') else {}))
        if command=='audit-authority-directory':
            s.add_argument('--authority-evaluation-utc',required=True)
            for key in NEW_KEYS[1:]:
                s.add_argument('--'+key.replace('_','-'),
                               **({'type':int} if key in INTEGERS else {}))
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,reason=exc.status,exc.code
    else:
        status,reason='unavailable','EC360_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
            'reason_code':reason,'exit_code':{'permission_denied':3,
            'invalid_input':4,'unavailable':5}.get(status,5),
            'actual_ec359_through_ec337_signed_originals_replayed':False,
            'offline_unresolved_exit_code':2,**{k:False for k in core.NEGATIVES}}


def main(argv=None):
    args=vars(parser().parse_args(argv));cmd=args.pop('command')
    for key in (*registry_cli.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
                *registry_cli.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=registry_cli.parent_cli.old_cli.old_cli.old_cli.FLAGS[key]
        if flag in args and flag!=key:args[key]=args.pop(flag)
    try:
        result=(core.checklist(**args) if cmd=='derive-authority-directory-handoff'
                else core.audit(**args))
    except Exception as exc:
        result=denial(cmd,exc)
    print(json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                     allow_nan=False))
    return result['exit_code']

if __name__=='__main__':raise SystemExit(main())
