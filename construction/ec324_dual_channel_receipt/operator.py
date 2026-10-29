#!/usr/bin/env python3
"""EC324 independent offline pin creation, local commit, receipt replay."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from ec321_fork_case_transport.operator import PIN_ARGUMENTS
from ec322_receiver_fork_ack.operator import RECEIVER_ARGS
from . import receipt


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC324 offline dual independently whole-SHA-pinned channel documents'
        ' and bounded, locally immutable, prior-head-linked fork receipt.'
        ' TWO real independent channels and external head custody must be'
        ' arranged outside this tool. Exit 2 means fork remains unresolved.'
        ' No new signature, global CAS, latest or organizational authority.'))
    sub = p.add_subparsers(dest='command', required=True)
    pre = sub.add_parser('prepare-channel', help='Create only UNSIGNED channel pins')
    for name in (*PIN_ARGUMENTS, *RECEIVER_ARGS,
                 'expected-capsule-sha256', 'expected-bundle-sha256',
                 'expected-ack-sha256', 'operator-id', 'handoff-id',
                 'registry-id', 'expected-prior-registry-raw-sha256', 'out'):
        pre.add_argument('--' + name, required=True)
    pre.add_argument('--channel-role', choices=receipt.ROLES, required=True)
    pre.add_argument('--expected-sequence', type=int, required=True)
    for command in ('receive', 'verify'):
        s = sub.add_parser(command)
        for name in ('capsule-file', 'origin-file', 'recipient-file',
                     'expected-origin-sha256', 'expected-recipient-sha256',
                     'registry-id', 'expected-prior-registry-sha256'):
            s.add_argument('--' + name, required=True)
        s.add_argument('--expected-sequence', type=int, required=True)
        if command == 'receive':
            s.add_argument('--out', required=True)
            s.add_argument('--prior-registry-file')
        else:
            s.add_argument('--registry-file', required=True)
            s.add_argument('--expected-registry-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    try:
        fn = {'prepare-channel': receipt.prepare_channel,
              'receive': receipt.receive, 'verify': receipt.verify}[command]
        result = fn(**args)
        print(json.dumps({'schema': receipt.RESULT_SCHEMA, 'command': command,
                          **result}, sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (anchor.AnchorError, io.HostError))
                  else 'unavailable')
        code = (exc.code if isinstance(exc, (anchor.AnchorError, io.HostError))
                else 'EC324_OFFLINE_TWO_CHANNEL_RECEIPT_UNAVAILABLE')
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(status, 5)
        print(json.dumps({'schema': receipt.DENIAL_SCHEMA,
                          'command': command, 'exit_code': rc,
                          'status': status, 'reason_code': code,
                          'signed_fork_full_history_accepted': False,
                          'trusted_independent_operators_or_channels_proven': False,
                          'external_cas_worm_latest_or_winner_proven': False,
                          'business_or_external_cas_writes_performed': False},
                         sort_keys=True, separators=(',', ':')))
        return rc
