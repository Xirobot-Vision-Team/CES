#!/usr/bin/env python3
"""EC328 bounded offline review-ledger CLI; parent console exposes verify only."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from offline_receipt_siblings import proof
from . import ledger


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC328 offline signed-ninth-response audit. A private unsigned candidate '
        'must be separately whole-SHA pinned outside this process. '
        'Never proves global latest, nonexecution, a winner or atomic CAS.'))
    sub = p.add_subparsers(dest='command', required=True)
    draft = sub.add_parser('prepare-unsigned-ledger', help=(
        'create an UNTRUSTED unsigned LF-JSON candidate, 0600/O_EXCL; '
        'no evidence verification and no external proof'))
    draft.add_argument('--draft-file', required=True)
    draft.add_argument('--out', required=True)
    s = sub.add_parser('verify-ledger', help=(
        'read-only pinned multi-EC327-signature + EC326/EC325 full originals replay'))
    for name in (
        'ledger-file', 'expected-ledger-sha256',
        'request-file', 'expected-request-sha256',
        'case-file', 'expected-case-sha256',
        'registry-id', 'expected-prior-registry-sha256',
        'request-id', 'target-store-namespace-id',
        'eighth-signer-id', 'eighth-signer-public-hex',
        'request-challenge-sha256'):
        s.add_argument('--'+name, required=True)
    s.add_argument('--expected-sequence', required=True, type=int)
    s.add_argument('--prior-registry-file')
    s.add_argument('--prior-ledger-file')
    s.add_argument('--expected-prior-ledger-sha256', default=ledger.ZERO)
    for side in ('left', 'right'):
        for key in sorted(proof.SIDE_FIELDS):
            s.add_argument('--'+side+'-'+key.replace('_', '-'), required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    try:
        if command == 'verify-ledger':
            left = {key: args.pop('left_'+key) for key in proof.SIDE_FIELDS}
            right = {key: args.pop('right_'+key) for key in proof.SIDE_FIELDS}
            observed = ledger.verify_ledger(left=left, right=right, **args)
        else:
            observed = ledger.prepare_unsigned_ledger(**args)
        print(json.dumps({'schema': ledger.RESULT_SCHEMA, 'command': command,
                          **observed}, sort_keys=True, separators=(',', ':')))
        return observed['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'EC328_OFFLINE_REVIEW_LEDGER_OR_ORIGINAL_REPLAY_UNAVAILABLE')
        code = {'permission_denied': 3, 'invalid_input': 4,
                'unavailable': 5}.get(status, 5)
        print(json.dumps({
            'schema': ledger.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': reason, 'exit_code': code,
            'all_signed_review_origins_or_historical_signatures_accepted': False,
            'external_store_write_or_actual_nonexecution_proven': False,
            'remote_global_latest_or_winner_proven': False,
            'organizational_identity_or_complete_global_history_proven': False,
            'business_or_external_store_writes_performed': False,
        }, sort_keys=True, separators=(',', ':')))
        return code


if __name__ == '__main__':
    raise SystemExit(main())
