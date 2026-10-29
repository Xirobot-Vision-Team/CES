#!/usr/bin/env python3
"""Strictly offline EC313 two original EC312 signed-window verifier."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from . import intersection as r


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC313 independently pinned pair of partially overlapping EC312 '
        'signed CAS windows; full original Ed25519 replay, no CAS I/O.'))
    commands = p.add_subparsers(dest='command', required=True)
    for command in ('verify', 'verify-report'):
        sub = commands.add_parser(command)
        sub.add_argument('--manifest-file', required=True)
        sub.add_argument('--expected-manifest-sha256', required=True)
        if command == 'verify':
            sub.add_argument('--out', help='exclusive owner-private 0600/fsync audit')
        else:
            sub.add_argument('--audit-report-file', required=True)
            sub.add_argument('--expected-audit-report-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        options = {'manifest_file': args.manifest_file,
                   'expected_manifest_sha256': args.expected_manifest_sha256}
        if args.command == 'verify':
            result = r.verify(**options, out=args.out)
        else:
            result = r.verify_report(
                **options, audit_report_file=args.audit_report_file,
                expected_audit_report_sha256=args.expected_audit_report_sha256)
        print(json.dumps({
            'schema': r.RESULT_SCHEMA, 'command': args.command, **result,
            'external_cas_access_performed': False,
            'physical_same_store_or_global_latest_authenticated': False,
        }, sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = exc.status if isinstance(exc, (a.AnchorError, io.HostError)) else 'unavailable'
        code = (exc.code if isinstance(exc, (a.AnchorError, io.HostError))
                else 'EC313_SIGNED_CROSS_WINDOW_ORIGINALS_UNAVAILABLE')
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(status, 5)
        print(json.dumps({
            'schema': r.DENIAL_SCHEMA, 'command': args.command,
            'status': status, 'reason_code': code, 'exit_code': rc,
            'both_ec312_original_signed_windows_replayed': False,
            'real_external_cas_or_global_latest_proven': False,
            'business_or_external_store_write_performed': False,
        }, sort_keys=True, separators=(',', ':')))
        return rc
