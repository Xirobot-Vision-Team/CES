#!/usr/bin/env python3
"""EC327 fixed-scope, read-only CLI for ninth externally signed deferrals."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from ec325_offline_receipt_siblings import proof
from . import disposition


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC327: READ ONLY independently verify a ninth Ed25519 NON-EXECUTION '
        'disposition against a separately SHA-pinned EC326 signed request, '
        'EC325 sibling dispute and both complete signed historical branches. '
        'Never infer external CAS/WORM/remote state or a winning child.'))
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('verify-nonexecution')
    for name in (
        'receipt-file', 'expected-receipt-sha256',
        'request-file', 'expected-request-sha256',
        'case-file', 'expected-case-sha256',
        'registry-id', 'expected-prior-registry-sha256',
        'request-id', 'target-store-namespace-id',
        'eighth-signer-id', 'eighth-signer-public-hex',
        'request-challenge-sha256',
        'decision-id', 'ninth-responder-id', 'ninth-responder-public-hex',
        'response-challenge-sha256', 'expected-disposition',
        'expected-reason-code'):
        s.add_argument('--'+name, required=True)
    s.add_argument('--expected-sequence', required=True, type=int)
    s.add_argument('--prior-registry-file')
    for side in ('left', 'right'):
        for field in sorted(proof.SIDE_FIELDS):
            s.add_argument('--'+side+'-'+field.replace('_', '-'), required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    left = {key: args.pop('left_'+key) for key in proof.SIDE_FIELDS}
    right = {key: args.pop('right_'+key) for key in proof.SIDE_FIELDS}
    try:
        observed = disposition.verify_nonexecution(left=left, right=right, **args)
        print(json.dumps({'schema': disposition.RESULT_SCHEMA,
                          'command': command, **observed},
                         sort_keys=True, separators=(',', ':')))
        return observed['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        code = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                else 'EC327_READ_ONLY_ORIGINAL_REPLAY_UNAVAILABLE')
        exit_code = {'permission_denied': 3, 'invalid_input': 4,
                     'unavailable': 5}.get(status, 5)
        print(json.dumps({
            'schema': disposition.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': code, 'exit_code': exit_code,
            'ninth_signature_eighth_signature_and_histories_accepted': False,
            'external_atomic_cas_or_worm_write_performed': False,
            'actual_external_nonexecution_hold_or_remote_head_proven': False,
            'remote_global_latest_or_child_winner_proven': False,
            'organization_authorization_proven': False,
            'business_or_external_store_writes_performed': False,
        }, sort_keys=True, separators=(',', ':')))
        return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
