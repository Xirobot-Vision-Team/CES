#!/usr/bin/env python3
"""EC359 read-only import interface; true EC358..337 ancestors are mandatory."""
from __future__ import annotations
import argparse
import json

from delivery_anchor import anchor as errors
from finding_query_host import protocol as io
from key_registry import operator as registry_cli
from reviewer_epochs import operator as previous
from . import distribution as core

EXTRA_KEYS = (
    'distribution_evaluation_utc',
    'distribution_bundle_file', 'expected_distribution_bundle_sha256',
    'distributor_a_public_key_file', 'expected_distributor_a_public_key_sha256',
    'distributor_b_public_key_file', 'expected_distributor_b_public_key_sha256',
    'minimum_a_distribution_sequence', 'minimum_b_distribution_sequence',
    'expected_a_distribution_head_sha256', 'expected_b_distribution_head_sha256',
)


def parser():
    p = argparse.ArgumentParser(description='EC359 offline signed distribution evidence, READ ONLY')
    subs = p.add_subparsers(dest='command', required=True)
    for command in ('derive-owner-distribution-handoff', 'audit-owner-distribution'):
        s = subs.add_parser(command, help='replay actual EC358 through EC337 signed originals')
        registry_cli.parent_cli.old_cli.old_cli.old_cli.old_cli._scalars(
            s, registry_cli.parent_cli.SCALARS)
        registry_cli.parent_cli.old_cli.old_cli.old_cli.old_cli._repeats(
            s, registry_cli.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS)
        for key in registry_cli.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS:
            flag = registry_cli.parent_cli.old_cli.old_cli.old_cli.FLAGS[key]
            s.add_argument('--' + flag.replace('_', '-'), action='append', default=[])
        s.add_argument('--dual-evaluation-utc', required=True)
        for key, flag in registry_cli.parent_cli.old_cli.old_cli.ADDED_REPEATS:
            s.add_argument('--' + flag.replace('_', '-'), dest=key,
                           action='append', default=[])
        s.add_argument('--tsa-evaluation-utc', required=True)
        for key, flag in registry_cli.parent_cli.old_cli.NEW_REPEATS:
            s.add_argument('--' + flag.replace('_', '-'), dest=key,
                           action='append', default=[])
        s.add_argument('--provenance-evaluation-utc', required=True)
        for key, flag in registry_cli.parent_cli.NEW_REPEATS:
            s.add_argument('--' + flag.replace('_', '-'), dest=key,
                           action='append', default=[])
        s.add_argument('--registry-evaluation-utc', required=True)
        for key, flag in registry_cli.NEW_REPEATS:
            s.add_argument('--' + flag.replace('_', '-'), dest=key,
                           action='append', default=[])
        for key in ('publication_evaluation_utc', 'publication_bundle_file',
                    'expected_publication_bundle_sha256', 'gossip_evaluation_utc',
                    'gossip_bundle_file', 'expected_gossip_bundle_sha256',
                    'checkpoint_disclosure_evaluation_utc',
                    'checkpoint_disclosure_bundle_file',
                    'expected_checkpoint_disclosure_bundle_sha256',
                    *previous.previous.previous.EXTRA_KEYS):
            s.add_argument('--' + key.replace('_', '-'), required=True)
        for key in previous.previous.EXTRA_KEYS:
            s.add_argument('--' + key.replace('_', '-'),
                           required=(key == 'provenance_review_evaluation_utc'))
        s.add_argument('--reviewer-epoch-evaluation-utc', required=True)
        for key in previous.EXTRA_KEYS[1:]:
            s.add_argument('--' + key.replace('_', '-'),
                           **({'type':int} if key in ('minimum_a_epoch', 'minimum_b_epoch') else {}))
        if command == 'audit-owner-distribution':
            s.add_argument('--distribution-evaluation-utc', required=True)
            for key in EXTRA_KEYS[1:]:
                s.add_argument('--' + key.replace('_', '-'),
                               **({'type':int} if key in (
                                   'minimum_a_distribution_sequence',
                                   'minimum_b_distribution_sequence') else {}))
    return p


def denial(command, exc):
    if isinstance(exc, (errors.AnchorError, io.HostError)):
        status, code = exc.status, exc.code
    else:
        status, code = 'unavailable', 'EC359_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema':core.DENIAL_SCHEMA, 'command':command, 'status':status,
            'reason_code':code, 'exit_code':{
                'permission_denied':3, 'invalid_input':4, 'unavailable':5}.get(status,5),
            'actual_ec358_through_ec337_signed_originals_replayed':False,
            'offline_unresolved_exit_code':2,
            **{key:False for key in core.NEGATIVES}}


def main(argv=None):
    args = vars(parser().parse_args(argv));command = args.pop('command')
    for key in (*registry_cli.parent_cli.old_cli.old_cli.old_cli.PARENT_REPEATS,
                *registry_cli.parent_cli.old_cli.old_cli.old_cli.EXTRA_REPEATS):
        flag = registry_cli.parent_cli.old_cli.old_cli.old_cli.FLAGS[key]
        if flag in args and flag != key:args[key] = args.pop(flag)
    try:
        result = (core.checklist(**args)
                  if command == 'derive-owner-distribution-handoff'
                  else core.audit(**args))
    except Exception as exc:
        result = denial(command, exc)
    print(json.dumps(result, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False))
    return result['exit_code']

if __name__ == '__main__':raise SystemExit(main())
