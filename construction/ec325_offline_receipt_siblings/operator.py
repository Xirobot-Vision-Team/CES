#!/usr/bin/env python3
"""EC325 CLI: offline two-child local receipt dispute, unsigned only."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from . import proof


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC325 offline conflicting EC324 children of ONE pinned parent:'
        ' reconstruct both complete current signed original histories,'
        ' record an unsigned canonical dispute case, or independently verify'
        ' the case with all original sources. Exit 2 is UNRESOLVED CONFLICT,'
        ' not a CAS winner. No external WORM/CAS connection or authority.'))
    sub = p.add_subparsers(dest='command', required=True)
    for cmd in ('create-case', 'verify-case'):
        s = sub.add_parser(cmd, help=(
            'exclusive owner-private unsigned dispute evidence' if cmd ==
            'create-case' else 'read-only independent complete original replay'))
        s.add_argument('--registry-id', required=True)
        s.add_argument('--expected-sequence', type=int, required=True)
        s.add_argument('--expected-prior-registry-sha256', required=True)
        s.add_argument('--prior-registry-file')
        for side in ('left', 'right'):
            for name in ('registry-file', 'expected-registry-sha256',
                         'capsule-file', 'origin-file',
                         'expected-origin-sha256', 'recipient-file',
                         'expected-recipient-sha256'):
                s.add_argument('--'+side+'-'+name, required=True)
        if cmd == 'create-case':
            s.add_argument('--out', required=True)
        else:
            s.add_argument('--case-file', required=True)
            s.add_argument('--expected-case-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    left = {key: args.pop('left_'+key)
            for key in proof.SIDE_FIELDS}
    right = {key: args.pop('right_'+key)
             for key in proof.SIDE_FIELDS}
    try:
        fn = {'create-case': proof.create_case,
              'verify-case': proof.verify_case}[command]
        result = fn(left=left, right=right, **args)
        print(json.dumps({'schema': proof.RESULT_SCHEMA,
                          'command': command, **result},
                         sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        code = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                else 'EC325_OFFLINE_SIBLING_DISPUTE_UNAVAILABLE')
        rc = {'permission_denied': 3, 'invalid_input': 4,
              'unavailable': 5}.get(status, 5)
        print(json.dumps({'schema': proof.DENIAL_SCHEMA,
                          'command': command, 'status': status,
                          'reason_code': code, 'exit_code': rc,
                          'two_complete_original_signed_histories_accepted': False,
                          'external_cas_worm_latest_or_winner_proven': False,
                          'human_or_channel_independence_proven': False,
                          'business_or_external_cas_writes_performed': False},
                         sort_keys=True, separators=(',', ':')))
        return rc
