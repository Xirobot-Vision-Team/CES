#!/usr/bin/env python3
"""Standalone EC320 sixth-key fork witness. Unified console permits verify only."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor as anchor
from . import witness


BRANCH_FIELDS = (
    'left-file', 'expected-left-sha256', 'left-materials-file',
    'expected-left-head-raw-sha256', 'right-file', 'expected-right-sha256',
    'right-materials-file', 'expected-right-head-raw-sha256',
    'expected-genesis-raw-sha256', 'registrar-id', 'registrar-public-hex',
)
WITNESS_FIELDS = ('case-id', 'witness-id', 'witness-public-hex',
                  'witness-challenge-sha256')


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC320 genuine fifth-registrar signed sibling fork + independent SIXTH '
        'Ed25519 offline witness. Neither latest/winner nor external CAS is proven.'))
    sub = p.add_subparsers(dest='command', required=True)
    for command in ('attest', 'verify'):
        s = sub.add_parser(command)
        for field in BRANCH_FIELDS + WITNESS_FIELDS:
            s.add_argument('--' + field, required=True)
        if command == 'attest':
            s.add_argument('--private-key-file', required=True)
            s.add_argument('--out', required=True)
        else:
            s.add_argument('--witness-file', required=True)
            s.add_argument('--expected-witness-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    kwargs = vars(args).copy()
    command = kwargs.pop('command')
    try:
        result = {'attest':witness.attest, 'verify':witness.verify}[command](**kwargs)
        print(json.dumps({'schema':witness.RESULT_SCHEMA, 'command':command,
            **result}, sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        reason = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'EC320_SIGNED_FORK_WITNESS_UNAVAILABLE')
        rc = {'permission_denied':3, 'invalid_input':4, 'unavailable':5}.get(status,5)
        print(json.dumps({'schema':witness.DENIAL_SCHEMA, 'command':command,
            'exit_code':rc, 'status':status, 'reason_code':reason,
            'sixth_signature_or_original_fork_accepted':False,
            'global_latest_winner_or_external_cas_proven':False,
            'business_writes_performed':False},
            sort_keys=True, separators=(',', ':')))
        return rc
