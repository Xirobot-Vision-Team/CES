#!/usr/bin/env python3
"""EC400 standalone read-only native CMS SignedData original receiver CLI."""
from __future__ import annotations
import argparse
import json

from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec399_official_certificate import operator as prior_cli
from . import protocol as core


def parser():
    p = argparse.ArgumentParser(description=(
        'EC400 genuine original DER CMS SignedData, two real EC399 pinned X.509 '
        'leaf SignerInfos, original EC398 gazette source, historical issuer CRL '
        'credit inherited from actual EC399 audit. Legal result always unresolved.'))
    subs = p.add_subparsers(dest='command', required=True)
    ancestor = next(a.choices['audit-historical-ec339-official-certificate']
        for a in prior_cli.parser()._actions if isinstance(a, argparse._SubParsersAction))
    flags = {a.dest: a.option_strings[0] for a in ancestor._actions
             if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(flags) != set(core.PARENT_REPEATS):
        raise RuntimeError('EC400 original EC399 inherited CLI flags changed')
    for command in ('derive-historical-ec339-native-cms-inventory',
                    'audit-historical-ec339-native-cms'):
        q = subs.add_parser(command, help='Inspect real originals without writes')
        scalar = (*core.PARENT_SCALARS, *core.NEW_SCALARS)
        if command.startswith('audit-'):
            scalar += core.AUDIT_ONLY
        for key in scalar:
            q.add_argument('--' + key.replace('_', '-'), required=True)
        for key, option in (*((k, flags[k]) for k in core.PARENT_REPEATS),
                            *core.NEW_REPEATS):
            q.add_argument(option, dest=key, action='append',
                           **({'default': []} if key == 'historical_dual_handoff_shas'
                              else {'required': True}),
                           **({'type': int} if key.startswith('minimum_') else {}))
    return p


def denial(command, exc):
    if isinstance(exc, (errors.AnchorError, host.HostError)):
        status, reason = exc.status, exc.code.upper()
    else:
        status, reason = 'unavailable', 'EC400_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema': core.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': reason,
            'exit_code': {'permission_denied': 3, 'invalid_input': 4,
                          'unavailable': 5}.get(status, 5),
            'offline_unresolved_exit_code': 2,
            'sender_origin_path_required_or_read': False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
            **{key: False for key in core.NEGATIVES}}


def main(argv=None):
    values = vars(parser().parse_args(argv))
    command = values.pop('command')
    values['expected_source_attestation_head_shas'] = [
        None if x == 'none' else x
        for x in values['expected_source_attestation_head_shas']]
    try:
        result = (core.derive_inventory(**values) if command.startswith('derive-')
                  else core.audit(**values))
    except Exception as exc:
        result = denial(command, exc)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True,
                     allow_nan=False, separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
