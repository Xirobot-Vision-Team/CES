#!/usr/bin/env python3
"""EC330 standalone offline comparison report: create candidate or verify original.

No signature, private key, network/CAS, Host, Provider, or business operations.
Unified action console exposes only verify-report (no candidate writer).
"""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from offline_receipt_siblings import proof
from offline_ledger_comparison import comparison
from . import report


def _add_compare_arguments(parser: argparse.ArgumentParser) -> None:
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
        parser.add_argument('--'+key, required=True)
    parser.add_argument('--expected-sequence', required=True, type=int)
    for key in ('prior-registry-file', 'branch-a-prior-ledger-file',
                'branch-b-prior-ledger-file'):
        parser.add_argument('--'+key)
    for key in ('expected-branch-a-prior-ledger-sha256',
                'expected-branch-b-prior-ledger-sha256'):
        parser.add_argument('--'+key, default=comparison.ZERO)
    for side in ('left', 'right'):
        for key in sorted(proof.SIDE_FIELDS):
            parser.add_argument('--'+side+'-'+key.replace('_', '-'), required=True)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description='EC330 unsigned replayable offline comparison report. '
                    'Only external report SHA + complete real original replay can '
                    'independently verify it. No CAS, nonexecution or winner proof.')
    subs = p.add_subparsers(dest='command', required=True)
    create = subs.add_parser(
        'create-report', help='write one immutable unsigned candidate after full EC329 replay')
    create.add_argument('--out', required=True)
    _add_compare_arguments(create)
    verify = subs.add_parser(
        'verify-report', help='read-only independently pinned original report and full replay')
    verify.add_argument('--report-file', required=True)
    verify.add_argument('--expected-report-sha256', required=True)
    _add_compare_arguments(verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    left = {k: args.pop('left_'+k) for k in proof.SIDE_FIELDS}
    right = {k: args.pop('right_'+k) for k in proof.SIDE_FIELDS}
    try:
        if command == 'create-report':
            doc = report.create_report(left=left, right=right, **args)
        else:
            doc = report.verify_report(left=left, right=right, **args)
        print(json.dumps({'command': command, **doc},
                         sort_keys=True, separators=(',', ':'), allow_nan=False))
        return doc['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'EC330_REPORT_OR_ORIGINAL_REPLAY_ENVIRONMENT_UNAVAILABLE')
        code = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(
            status, 5)
        print(json.dumps({
            'schema': report.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': reason, 'exit_code': code,
            'report_and_all_original_signatures_verified': False,
            **{field: False for field in report.REMOTE_FALSE_FIELDS},
        }, sort_keys=True, separators=(',', ':')))
        return code


if __name__ == '__main__':
    raise SystemExit(main())
