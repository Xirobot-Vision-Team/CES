#!/usr/bin/env python3
"""EC314 fixed read-only standalone CLI; explicit private audit is opt-in."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from . import mesh as m


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC314 three-to-six independently pinned genuine EC312 signed windows; '
        'connectivity, cycles, original Ed25519 claim replay, no CAS I/O.'))
    commands = p.add_subparsers(dest='command', required=True)
    for name in ('verify', 'verify-report'):
        sub = commands.add_parser(name)
        sub.add_argument('--manifest-file', required=True)
        sub.add_argument('--expected-manifest-sha256', required=True)
        if name == 'verify':
            sub.add_argument('--out', help='exclusive private 0600 audit file')
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
            result = m.verify(**options, out=args.out)
        else:
            result = m.verify_report(**options,
                audit_report_file=args.audit_report_file,
                expected_audit_report_sha256=args.expected_audit_report_sha256)
        print(json.dumps({
            'schema': m.RESULT_SCHEMA, 'command': args.command, **result,
            'external_cas_access_performed': False,
            'same_store_linearizability_or_global_latest_proven': False,
        }, sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = (exc.status if isinstance(exc, (a.AnchorError, io.HostError))
                  else 'unavailable')
        code = (exc.code if isinstance(exc, (a.AnchorError, io.HostError))
                else 'EC314_SIGNED_ORIGINAL_MESH_VERIFICATION_UNAVAILABLE')
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(status, 5)
        print(json.dumps({
            'schema': m.DENIAL_SCHEMA, 'command': args.command,
            'status': status, 'reason_code': code, 'exit_code': rc,
            'original_ec312_window_signatures_all_replayed': False,
            'real_external_cas_or_global_latest_proven': False,
            'business_or_external_store_write_performed': False,
        }, sort_keys=True, separators=(',', ':')))
        return rc
