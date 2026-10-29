#!/usr/bin/env python3
"""EC414 read-only original OCSP WARC + dual Ed25519 receipt receiver."""
from __future__ import annotations

import argparse
import json

from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec413_lotl_ocsp import operator as previous
from . import protocol as core


def parser():
    p = argparse.ArgumentParser(description=(
        'Offline original WARC/1.1 HTTP 200 OCSP DER snapshots and two separately '
        'signed Ed25519 observation claims. Mandatory unchanged real EC413 -> '
        'EC412 -> every older original auditor. No proof of true network delivery, '
        'official witness authority, legal status or independent clock; never PASS.'))
    sub = p.add_subparsers(dest='command', required=True)
    inherited = next(a.choices['audit-historical-ec339-lotl-ocsp']
                     for a in previous.parser()._actions
                     if isinstance(a, argparse._SubParsersAction))
    previous_flags = {a.dest: a.option_strings[0] for a in inherited._actions
                      if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(previous_flags) != set(core.PARENT_REPEATS):
        raise RuntimeError('EC414 strict inherited EC413 CLI flags changed')
    for command in ('derive-historical-ec339-lotl-ocsp-publication-inventory',
                    'audit-historical-ec339-lotl-ocsp-publication'):
        sp = sub.add_parser(command, help='Actual SHA-pinned signed source originals; no legal PASS')
        scalars = (*core.PARENT_SCALARS, *core.NEW_SCALARS)
        if command.startswith('audit-'):
            scalars += core.AUDIT_ONLY
        for key in scalars:
            sp.add_argument('--' + key.replace('_', '-'), required=True)
        for key, flag in (
            *((k, previous_flags[k]) for k in core.PARENT_REPEATS),
            *core.NEW_REPEATS
        ):
            sp.add_argument(flag, dest=key, action='append',
                **({'default': []} if key == 'historical_dual_handoff_shas'
                   else {'required': True}),
                **({'type': int} if key.startswith('minimum_') else {}))
    return p


def denial(command, exc):
    if isinstance(exc, (errors.AnchorError, host.HostError)):
        status, code = exc.status, exc.code.upper()
    else:
        status, code = 'unavailable', 'EC414_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {
        'schema': core.DENIAL_SCHEMA, 'command': command,
        'status': status, 'reason_code': code,
        'exit_code': {'permission_denied': 3, 'invalid_input': 4,
                      'unavailable': 5}.get(status, 5),
        'offline_unresolved_exit_code': 2,
        'sender_origin_path_required_or_read': False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
        **{k: False for k in core.NEGATIVES},
    }


def main(argv=None):
    parsed = vars(parser().parse_args(argv))
    command = parsed.pop('command')
    parsed['expected_source_attestation_head_shas'] = [
        None if s == 'none' else s
        for s in parsed['expected_source_attestation_head_shas']]
    try:
        result = (core.derive_inventory(**parsed) if command.startswith('derive-')
                  else core.audit(**parsed))
    except Exception as exc:
        result = denial(command, exc)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False,
                     separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
