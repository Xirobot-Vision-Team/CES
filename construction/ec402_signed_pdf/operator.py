#!/usr/bin/env python3
"""EC402 isolated JSON CLI for read-only signed PDF/CMS originals."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec401_ocsp_evidence import operator as prior
from . import protocol as core


def parser():
    p = argparse.ArgumentParser(description=(
        'EC402 two native original signed PDF/ByteRange/CMS source attachments; '
        'mandatory real EC401 OCSP and deep ancestors. Always unresolved.'))
    sub = p.add_subparsers(dest='command', required=True)
    old = next(a.choices['audit-historical-ec339-issuer-ocsp']
               for a in prior.parser()._actions
               if isinstance(a, argparse._SubParsersAction))
    flags = {a.dest: a.option_strings[0] for a in old._actions
             if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(flags) != set(core.PARENT_REPEATS):
        raise RuntimeError('EC402 parent CLI flags changed')
    for command in ('derive-historical-ec339-signed-pdf-inventory',
                    'audit-historical-ec339-signed-pdf'):
        q = sub.add_parser(command, help='Verify original file bytes offline')
        scalars = (*core.PARENT_SCALARS, *core.NEW_SCALARS)
        if command.startswith('audit-'):
            scalars += core.AUDIT_ONLY
        for name in scalars:
            q.add_argument('--' + name.replace('_', '-'), required=True)
        for name, flag in (*((k, flags[k]) for k in core.PARENT_REPEATS),
                           *core.NEW_REPEATS):
            q.add_argument(flag, dest=name, action='append',
                           **({'default': []} if name == 'historical_dual_handoff_shas'
                              else {'required': True}),
                           **({'type': int} if name.startswith('minimum_') else {}))
    return p


def denial(command, exc):
    if isinstance(exc, (errors.AnchorError, host.HostError)):
        status, code = exc.status, exc.code.upper()
    else:
        status, code = 'unavailable', 'EC402_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {'schema': core.DENIAL_SCHEMA, 'command': command,
            'status': status, 'reason_code': code,
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
        None if x == 'none' else x for x in values['expected_source_attestation_head_shas']]
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
