#!/usr/bin/env python3
"""EC347 separate write-candidate ceremony and offline read-only audit CLI."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor
from disclosure_custody import operator as prior_cli
from . import readback as r

SCALARS = (*prior_cli.BASELINE, 'item_id', 'custody_evaluation_utc')
PARENT_REPEATS = (
    'view_files', 'view_shas', 'presented_item_ids',
    'challenge_files', 'challenge_shas', 'response_files', 'response_shas',
    'disclosed_item_ids', 'observation_files', 'observation_shas',
)
AUDIT_REPEATS = ('readback_challenge_files', 'readback_challenge_shas',
                 'readback_response_files', 'readback_response_shas',
                 'presented_receiver_ids', 'presented_snapshot_files',
                 'presented_ack_set_files')
FLAGS = {**{k: v for k, v in prior_cli.REPEAT.items() if k in PARENT_REPEATS},
         'audience_receiver_ids': 'audience_receiver_id',
         'readback_challenge_files': 'readback_challenge_file',
         'readback_challenge_shas': 'expected_readback_challenge_sha256',
         'readback_response_files': 'readback_response_file',
         'readback_response_shas': 'expected_readback_response_sha256',
         **{k: prior_cli.REPEAT[k] for k in (
             'presented_receiver_ids', 'presented_snapshot_files',
             'presented_ack_set_files')}}


def _scalars(p: argparse.ArgumentParser, keys: tuple[str, ...],
             required: bool=True) -> None:
    for k in keys:
        p.add_argument('--' + k.replace('_', '-'), required=required,
            **({'type': int} if k in (
                'expected_current_root_epoch', 'minimum_acceptable_epoch',
                'round_number') else {}))


def _repeats(p: argparse.ArgumentParser, keys: tuple[str, ...]) -> None:
    for k in keys:
        p.add_argument('--' + FLAGS[k].replace('_', '-'),
                       action='append', default=[])


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='EC347 signed offline local byte re-opening; never physical custody proof')
    sub = p.add_subparsers(dest='command', required=True)
    a = sub.add_parser('issue-challenge', help='EC343 independent proposer private signed readback request candidate')
    _scalars(a, (*SCALARS, 'out', 'private_key_file', 'round_number',
                 'challenge_nonce_sha256', 'issued_utc'))
    _scalars(a, ('previous_challenge_file', 'expected_previous_challenge_sha256'), False)
    _repeats(a, (*PARENT_REPEATS, 'audience_receiver_ids'))
    s = sub.add_parser('sign-readback', help='EC343 challenged receiver reopens exact signed copy bytes or signs unavailable claim')
    _scalars(s, (*SCALARS, 'out', 'private_key_file', 'response_kind',
                 'response_nonce_sha256', 'reported_utc'))
    s.add_argument('--signed-readback-challenge-file', dest='challenge_file', required=True)
    s.add_argument('--signed-readback-challenge-sha256', dest='expected_challenge_sha256', required=True)
    _scalars(s, ('copy_snapshot_file', 'copy_ack_set_file'), False)
    _repeats(s, PARENT_REPEATS)
    u = sub.add_parser('audit-readbacks', help='no-key, no-copy-bytes-read unless explicitly presented last-round pair')
    _scalars(u, (*SCALARS, 'readback_evaluation_utc'))
    _repeats(u, (*PARENT_REPEATS, *AUDIT_REPEATS))
    return p


def denial(command: str, exc: Exception) -> dict:
    if isinstance(exc, (anchor.AnchorError, io.HostError)):
        status, code = exc.status, exc.code
    else:
        status, code = 'unavailable', 'EC347_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    code_num = {'permission_denied': 3, 'invalid_input': 4,
                'unavailable': 5}.get(status, 5)
    return {'schema': r.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': code, 'exit_code': code_num,
            'ec345_through_ec346_original_signed_history_replayed': False,
            'offline_unresolved_exit_code': 2,
            **{k: False for k in r.NEGATIVES}}


def main(argv=None) -> int:
    args = vars(parser().parse_args(argv))
    command = args.pop('command')
    for k in list(args):
        if k in FLAGS.values() and k not in FLAGS:
            args[next(x for x in FLAGS if FLAGS[x] == k)] = args.pop(k)
    fn = {'issue-challenge': r.issue_challenge,
          'sign-readback': r.sign_readback,
          'audit-readbacks': r.audit_readbacks}[command]
    try:
        result = fn(**args)
    except Exception as exc:
        result = denial(command, exc)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True,
                     allow_nan=False, separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
