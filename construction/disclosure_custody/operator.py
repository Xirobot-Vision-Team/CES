#!/usr/bin/env python3
"""EC346 standalone private signer and separate no-key read-only audit CLI."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from disclosure_challenge import operator as prev
from . import custody as c

BASELINE = (*prev.BASELINE, 'disclosure_evaluation_utc')
REPEAT = {
    'view_files': 'view_file',
    'view_shas': 'expected_view_sha256',
    'presented_item_ids': 'presented_item_id',
    'challenge_files': 'challenge_file',
    'challenge_shas': 'expected_challenge_sha256',
    'response_files': 'response_file',
    'response_shas': 'expected_response_sha256',
    'disclosed_item_ids': 'disclosed_item_id',
    'observation_files': 'observation_file',
    'observation_shas': 'expected_observation_sha256',
    'presented_receiver_ids': 'presented_receiver_id',
    'presented_snapshot_files': 'presented_snapshot_file',
    'presented_ack_set_files': 'presented_ack_set_file',
}


def _add(p: argparse.ArgumentParser, names: tuple[str, ...], required: bool=True) -> None:
    for k in names:
        p.add_argument('--' + k.replace('_', '-'), required=required,
                       **({'type': int} if k in (
                           'expected_current_root_epoch', 'minimum_acceptable_epoch',
                           'sequence') else {}))


def _repeat(p: argparse.ArgumentParser, names: tuple[str, ...]) -> None:
    for k in names:
        p.add_argument('--' + REPEAT[k].replace('_', '-'), action='append', default=[])


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='EC346 receiver-signed local copy bytes: NOT physical custody or remote CAS action')
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('sign-observation', help='EC343 receiver key, private non-overwrite signed local observation candidate')
    _add(s, (*BASELINE, 'out', 'private_key_file', 'item_id', 'copy_id',
             'claimed_storage_id', 'event_kind', 'sequence', 'event_nonce_sha256',
             'reported_utc'))
    _add(s, ('copy_snapshot_file', 'copy_ack_set_file',
             'previous_event_file', 'expected_previous_event_sha256'), False)
    _repeat(s, ('view_files', 'view_shas', 'presented_item_ids',
                'challenge_files', 'challenge_shas', 'response_files',
                'response_shas', 'disclosed_item_ids'))
    a = sub.add_parser('audit-copies', help='exact pinned signatures plus only expressly presented pair bytes, no writes')
    _add(a, (*BASELINE, 'item_id', 'custody_evaluation_utc'))
    _repeat(a, tuple(REPEAT))
    return p


def denial(command: str, exc: Exception) -> dict:
    if isinstance(exc, (anchor.AnchorError, io.HostError)):
        status, code = exc.status, exc.code
    else:
        status, code = 'unavailable', 'EC346_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    exit_code = {'permission_denied': 3, 'invalid_input': 4,
                 'unavailable': 5}.get(status, 5)
    return {
        'schema': c.DENIAL_SCHEMA, 'command': command, 'status': status,
        'reason_code': code, 'exit_code': exit_code,
        'verified_disclosed_source_replayed_ec345_through_ec337': False,
        'offline_unresolved_exit_code': 2,
        **{key: False for key in c.NEGATIVES},
    }


def main(argv=None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    for key, option in REPEAT.items():
        if option in args:
            args[key] = args.pop(option)
    fn = {'sign-observation': c.sign_observation,
          'audit-copies': c.audit_copies}[command]
    try:
        result = fn(**args)
    except Exception as exc:
        result = denial(command, exc)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True,
                     allow_nan=False, separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
