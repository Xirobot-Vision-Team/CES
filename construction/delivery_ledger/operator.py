#!/usr/bin/env python3
"""EC315 offline original-signed delivery ledger; write only explicit private audit."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from . import ledger as l


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC315 independently SHA-pinned 1-4 delivery append-only CAS signed '
        'originals; full EC312->294 replay; no actual CAS I/O or signing.'))
    commands = p.add_subparsers(dest='command', required=True)
    for command in ('verify', 'verify-append', 'verify-report'):
        sub = commands.add_parser(command)
        sub.add_argument('--manifest-file', required=True)
        sub.add_argument('--expected-manifest-sha256', required=True)
        if command in ('verify-append', 'verify-report'):
            required = command == 'verify-append'
            sub.add_argument('--expected-prior-delivery-sha256', required=required)
            sub.add_argument('--expected-prior-originals-commitment-sha256',
                             required=required)
        if command == 'verify-report':
            sub.add_argument('--audit-report-file', required=True)
            sub.add_argument('--expected-audit-report-sha256', required=True)
        else:
            sub.add_argument('--out', help='optional exclusive private 0600 audit')
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        options = {'manifest_file': args.manifest_file,
                   'expected_manifest_sha256': args.expected_manifest_sha256}
        if args.command in ('verify-append', 'verify-report'):
            options.update(
                expected_prior_delivery_sha256=args.expected_prior_delivery_sha256,
                expected_prior_originals_commitment_sha256=
                    args.expected_prior_originals_commitment_sha256)
        if args.command == 'verify-report':
            result = l.verify_report(**options,
                audit_report_file=args.audit_report_file,
                expected_audit_report_sha256=args.expected_audit_report_sha256)
        else:
            result = l.verify(**options, out=args.out)
        print(json.dumps({
            'schema': l.RESULT_SCHEMA, 'command': args.command, **result,
            'external_cas_access_performed': False,
            'same_store_linearizability_or_global_latest_proven': False,
        }, sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = exc.status if isinstance(exc, (a.AnchorError, io.HostError)) else 'unavailable'
        reason = (exc.code if isinstance(exc, (a.AnchorError, io.HostError))
                  else 'EC315_ORIGINAL_SIGNED_DELIVERY_LEDGER_VERIFICATION_UNAVAILABLE')
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(status, 5)
        print(json.dumps({
            'schema': l.DENIAL_SCHEMA, 'command': args.command,
            'status': status, 'reason_code': reason, 'exit_code': rc,
            'all_original_signatures_successfully_replayed': False,
            'real_external_cas_or_global_latest_proven': False,
            'business_or_external_store_write_performed': False,
        }, sort_keys=True, separators=(',', ':')))
        return rc
