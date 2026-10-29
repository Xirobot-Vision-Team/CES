#!/usr/bin/env python3
"""EC329 standalone dual-EC328-original comparison; no writer or signer."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from offline_receipt_siblings import proof
from . import comparison


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC329 read-only comparison of TWO independently pinned EC328 originals. '
        'Each must have separate genuine ninth-signature and full old-history '
        'verification. Does NOT prove CAS, actual nonexecution, winner or latest.'))
    s = p.add_subparsers(dest='command', required=True).add_parser(
        'compare-ledgers', help='compare two complete independently SHA-pinned ledgers')
    for key in (
        'branch-a-ledger-file', 'expected-branch-a-ledger-sha256',
        'branch-b-ledger-file', 'expected-branch-b-ledger-sha256',
        'request-file', 'expected-request-sha256',
        'case-file', 'expected-case-sha256',
        'registry-id', 'expected-prior-registry-sha256',
        'request-id', 'target-store-namespace-id',
        'eighth-signer-id', 'eighth-signer-public-hex',
        'request-challenge-sha256',
    ):
        s.add_argument('--'+key, required=True)
    s.add_argument('--expected-sequence', required=True, type=int)
    for key in ('prior-registry-file',
                'branch-a-prior-ledger-file', 'branch-b-prior-ledger-file'):
        s.add_argument('--'+key)
    for key in ('expected-branch-a-prior-ledger-sha256',
                'expected-branch-b-prior-ledger-sha256'):
        s.add_argument('--'+key, default=comparison.ZERO)
    for branch in ('left', 'right'):
        for key in sorted(proof.SIDE_FIELDS):
            s.add_argument('--'+branch+'-'+key.replace('_', '-'), required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    try:
        left = {key: args.pop('left_'+key) for key in proof.SIDE_FIELDS}
        right = {key: args.pop('right_'+key) for key in proof.SIDE_FIELDS}
        doc = comparison.compare_ledgers(left=left, right=right, **args)
        print(json.dumps({'schema': comparison.RESULT_SCHEMA, 'command': command,
                          **doc}, sort_keys=True, separators=(',', ':')))
        return doc['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'EC329_DUAL_ORIGINAL_REPLAY_OR_ENVIRONMENT_UNAVAILABLE')
        code = {'permission_denied': 3, 'invalid_input': 4,
                'unavailable': 5}.get(status, 5)
        print(json.dumps({
            'schema': comparison.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': reason, 'exit_code': code,
            'two_ledger_signatures_and_full_original_histories_accepted': False,
            **{key: False for key in comparison.FALSE_FIELDS},
        }, sort_keys=True, separators=(',', ':')))
        return code


if __name__ == '__main__':
    raise SystemExit(main())
