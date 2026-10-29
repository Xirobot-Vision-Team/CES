#!/usr/bin/env python3
"""EC411 isolated original XAdES SigningCertificateV2 receiver; always unresolved."""
from __future__ import annotations
import argparse
import json
from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec410_lotl_authority import operator as previous
from . import protocol as core


def parser():
    p = argparse.ArgumentParser(description=(
        'Offline exact original signed EU LOTL XAdES v1.3.2 SigningCertificateV2 '
        'SHA256 signer DER + RFC5035 IssuerSerial DER. Production real EC410 -> '
        'all older original signatures mandatory, never government status/PASS.'))
    sub = p.add_subparsers(dest='command', required=True)
    inherited_parser = next(
        a.choices['audit-historical-ec339-signed-lotl']
        for a in previous.parser()._actions
        if isinstance(a, argparse._SubParsersAction))
    inherited = {a.dest: a.option_strings[0] for a in inherited_parser._actions
                 if a.dest in core.PARENT_REPEATS and a.option_strings}
    if set(inherited) != set(core.PARENT_REPEATS):
        raise RuntimeError('EC411 inherited EC410 flag contract changed')
    for command in ('derive-historical-ec339-xades-cert-v2-inventory',
                    'audit-historical-ec339-xades-cert-v2'):
        sp = sub.add_parser(command, help='Strict original signed XAdES V2 '
                            'certificate/issuer serial; valid evidence unresolved')
        keys = (*core.PARENT_SCALARS,)
        if command.startswith('audit-'):
            keys += core.AUDIT_ONLY
        for key in keys:
            sp.add_argument('--' + key.replace('_', '-'), required=True)
        for key, flag in (*((k, inherited[k]) for k in core.PARENT_REPEATS),
                          *core.NEW_REPEATS):
            sp.add_argument(flag, dest=key, action='append',
                            **({'default': []} if key == 'historical_dual_handoff_shas'
                               else {'required': True}),
                            **({'type': int} if key.startswith('minimum_') else {}))
    return p


def denial(command, exc):
    if isinstance(exc, (errors.AnchorError, host.HostError)):
        status, code = exc.status, exc.code.upper()
    else:
        status, code = 'unavailable', 'EC411_LOCAL_IO_OR_UNEXPECTED_EXCEPTION'
    return {
        'schema': core.DENIAL_SCHEMA,
        'command': command, 'status': status, 'reason_code': code,
        'exit_code': {'permission_denied': 3, 'invalid_input': 4,
                      'unavailable': 5}.get(status, 5),
        'offline_unresolved_exit_code': 2,
        'sender_origin_path_required_or_read': False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
        **{k: False for k in core.NEGATIVES},
    }


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
    print(json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False,
                     separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
