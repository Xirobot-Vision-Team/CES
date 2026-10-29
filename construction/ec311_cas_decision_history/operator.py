#!/usr/bin/env python3
"""EC311 standalone, offline-only multi-decision history CLI."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from . import decisions as d


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC311 replay 2-8 separate original CAS issuer decisions and bound '
        'signed observer readbacks. Manifest raw SHA externally pinned, '
        'no external CAS, signing, global latest or business writes.'))
    subs = p.add_subparsers(dest='command', required=True)
    for command in ('verify', 'verify-report'):
        q = subs.add_parser(command)
        q.add_argument('--manifest-file', required=True)
        q.add_argument('--expected-manifest-sha256', required=True)
        if command == 'verify':
            q.add_argument('--out', help='optional private 0600 O_EXCL audit JSON')
        else:
            q.add_argument('--audit-report-file', required=True)
            q.add_argument('--expected-audit-report-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        opts = {
            'manifest_file': args.manifest_file,
            'expected_manifest_sha256': args.expected_manifest_sha256,
        }
        if args.command == 'verify':
            result = d.verify(**opts, out=args.out)
        else:
            result = d.verify_report(
                **opts, audit_report_file=args.audit_report_file,
                expected_audit_report_sha256=args.expected_audit_report_sha256)
        print(json.dumps({
            'schema': d.RESULT_SCHEMA, 'command': args.command, **result,
            'external_cas_access_performed': False,
            'global_authority_or_latest_authenticated': False,
        }, sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = exc.status if isinstance(exc, (a.AnchorError, io.HostError)) else 'unavailable'
        code = exc.code if isinstance(exc, (a.AnchorError, io.HostError)) else \
            'EC311_SIGNED_CROSS_DECISION_MATERIAL_UNAVAILABLE'
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(status, 5)
        print(json.dumps({
            'schema': d.DENIAL_SCHEMA, 'command': args.command,
            'status': status, 'reason_code': code, 'exit_code': rc,
            'all_original_signatures_replayed': False,
            'real_external_cas_or_global_latest_proven': False,
            'business_or_external_store_write_performed': False,
        }, sort_keys=True, separators=(',', ':')))
        return rc
