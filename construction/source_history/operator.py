#!/usr/bin/env python3
"""EC363 pinned, isolated, offline signed publication-history command line."""
from __future__ import annotations

import argparse
import json

from delivery_anchor import anchor as errors
from finding_query_host import protocol as io
from publication_custody import operator as previous_cli
from . import history as core

INTEGER_KEYS = {
    'minimum_source_a_retained_publication_sequence',
    'minimum_source_b_retained_publication_sequence',
    'minimum_source_a_retained_directory_tree_size',
    'minimum_source_b_retained_directory_tree_size',
}


def parser():
    p=argparse.ArgumentParser(description='EC363 signed history and real original-copy disclosure, offline unresolved')
    subs=p.add_subparsers(dest='command',required=True)
    prev=previous_cli.previous_cli
    registry=prev.previous_cli.registry_cli
    owner=prev.previous_cli.previous_cli
    for command in ('derive-publication-history-handoff','audit-publication-history'):
        s=subs.add_parser(command,help='read-only; independent legal provenance is NOT_PROVEN')
        registry.parent_cli.old_cli.old_cli.old_cli.old_cli._scalars(
            s,registry.parent_cli.SCALARS)
        registry.parent_cli.old_cli.old_cli.old_cli.old_cli._repeats(
            s,registry.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS)
        for key in registry.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS:
            flag=registry.parent_cli.old_cli.old_cli.old_cli.FLAGS[key]
            s.add_argument('--'+flag.replace('_','-'),action='append',default=[])
        s.add_argument('--dual-evaluation-utc',required=True)
        for key,flag in registry.parent_cli.old_cli.old_cli.ADDED_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=key,action='append',default=[])
        s.add_argument('--tsa-evaluation-utc',required=True)
        for key,flag in registry.parent_cli.old_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=key,action='append',default=[])
        s.add_argument('--provenance-evaluation-utc',required=True)
        for key,flag in registry.parent_cli.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=key,action='append',default=[])
        s.add_argument('--registry-evaluation-utc',required=True)
        for key,flag in registry.NEW_REPEATS:
            s.add_argument('--'+flag.replace('_','-'),dest=key,action='append',default=[])
        for key in ('publication_evaluation_utc','publication_bundle_file',
                    'expected_publication_bundle_sha256','gossip_evaluation_utc',
                    'gossip_bundle_file','expected_gossip_bundle_sha256',
                    'checkpoint_disclosure_evaluation_utc',
                    'checkpoint_disclosure_bundle_file',
                    'expected_checkpoint_disclosure_bundle_sha256',
                    *owner.previous.previous.previous.EXTRA_KEYS):
            s.add_argument('--'+key.replace('_','-'),required=True)
        for key in owner.previous.previous.EXTRA_KEYS:
            s.add_argument('--'+key.replace('_','-'),
                           required=(key=='provenance_review_evaluation_utc'))
        s.add_argument('--reviewer-epoch-evaluation-utc',required=True)
        for key in owner.previous.EXTRA_KEYS[1:]:
            s.add_argument('--'+key.replace('_','-'),
                **({'type':int} if key in ('minimum_a_epoch','minimum_b_epoch') else {}))
        s.add_argument('--distribution-evaluation-utc',required=True)
        for key in owner.EXTRA_KEYS[1:]:
            s.add_argument('--'+key.replace('_','-'),
                **({'type':int} if key in (
                    'minimum_a_distribution_sequence','minimum_b_distribution_sequence') else {}))
        s.add_argument('--authority-evaluation-utc',required=True)
        for key in prev.previous_cli.NEW_KEYS[1:]:
            s.add_argument('--'+key.replace('_','-'),
                **({'type':int} if key in prev.previous_cli.INTEGERS else {}))
        s.add_argument('--consistency-evaluation-utc',required=True)
        for key in prev.NEW_KEYS[1:]:
            s.add_argument('--'+key.replace('_','-'),
                **({'type':int} if key in prev.INTEGERS else {}))
        s.add_argument('--publication-copy-evaluation-utc',required=True)
        for key in previous_cli.NEW_KEYS[1:]:
            s.add_argument('--'+key.replace('_','-'),
                **({'type':int} if key in previous_cli.INTEGERS else {}))
        if command=='audit-publication-history':
            s.add_argument('--history-evaluation-utc',required=True)
            for key in core.NEW_OPTIONAL:
                s.add_argument('--'+key.replace('_','-'),
                    **({'type':int} if key in INTEGER_KEYS else {}))
            for key,flag in core.NEW_REPEATS:
                s.add_argument(flag,dest=key,action='append',default=[])
    return p


def denial(command,exc):
    if isinstance(exc,(errors.AnchorError,io.HostError)):
        status,reason=exc.status,exc.code
    else:
        status,reason='unavailable','EC363_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA,'command':command,'status':status,
       'reason_code':reason,
       'exit_code':{'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5),
       'actual_ec362_through_ec337_signed_originals_replayed':False,
       'offline_unresolved_exit_code':2,**{key:False for key in core.NEGATIVES}}


def main(argv=None):
    parsed=vars(parser().parse_args(argv))
    command=parsed.pop('command')
    registry=previous_cli.previous_cli.previous_cli.registry_cli
    for key in (*registry.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
                *registry.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag=registry.parent_cli.old_cli.old_cli.old_cli.FLAGS[key]
        if flag in parsed and flag!=key:parsed[key]=parsed.pop(flag)
    try:
        result=(core.checklist(**parsed)
            if command=='derive-publication-history-handoff'
            else core.audit(**parsed))
    except Exception as exc:
        result=denial(command,exc)
    print(json.dumps(result,ensure_ascii=True,allow_nan=False,sort_keys=True,
                     separators=(',',':')))
    return result['exit_code']

if __name__=='__main__':
    raise SystemExit(main())
