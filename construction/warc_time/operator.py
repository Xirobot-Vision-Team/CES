#!/usr/bin/env python3
"""Isolated EC405 offline read-only WARC and genuine RFC3161 token commands."""
from __future__ import annotations

import argparse
import json
from delivery_anchor import anchor as errors
from finding_query_host import protocol as host
from public_access import operator as prior
from . import protocol as core


def parser():
    p = argparse.ArgumentParser(description=(
        'EC405 genuine WARC/1.1 record byte binding and independent RFC3161 '
        'token cryptography; real EC404 ancestry, no legal/public assurance.'))
    sub = p.add_subparsers(dest='command', required=True)
    old = next(a.choices['audit-historical-ec339-public-access']
               for a in prior.parser()._actions
               if isinstance(a, argparse._SubParsersAction))
    oldflags = {a.dest: a.option_strings[0] for a in old._actions
                if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(oldflags) != set(core.PARENT_REPEATS):
        raise RuntimeError('EC405 inherited real EC404 CLI flags changed')
    for command in ('derive-historical-ec339-warc-timestamp-inventory',
                    'audit-historical-ec339-warc-timestamp'):
        sp = sub.add_parser(command, help='Read actual WARC records and RFC3161 originals')
        scalars = (*core.PARENT_SCALARS, *core.NEW_SCALARS)
        if command.startswith('audit-'):
            scalars += core.AUDIT_ONLY
        for k in scalars:
            sp.add_argument('--' + k.replace('_', '-'), required=True)
        for name, flag in (*((k, oldflags[k]) for k in core.PARENT_REPEATS),
                           *core.NEW_REPEATS):
            sp.add_argument(flag, dest=name, action='append',
                            **({'default': []} if name == 'historical_dual_handoff_shas'
                               else {'required': True}),
                            **({'type': int} if name.startswith('minimum_') else {}))
    return p


def denial(command, exc):
    if isinstance(exc, (errors.AnchorError, host.HostError)):
        status, code = exc.status, exc.code.upper()
    else:
        status, code = 'unavailable', 'EC405_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema': core.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': code,
            'exit_code': {'permission_denied': 3, 'invalid_input': 4,
                          'unavailable': 5}.get(status, 5),
            'offline_unresolved_exit_code': 2,
            'sender_origin_path_required_or_read': False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
            **{k: False for k in core.NEGATIVES}}


def main(argv=None):
    data = vars(parser().parse_args(argv))
    command = data.pop('command')
    data['expected_source_attestation_head_shas'] = [
        None if x == 'none' else x for x in data['expected_source_attestation_head_shas']]
    try:
        result = (core.derive_inventory(**data) if command.startswith('derive-')
                  else core.audit(**data))
    except Exception as exc:
        result = denial(command, exc)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True,
                     allow_nan=False, separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
