#!/usr/bin/env python3
"""EC312 offline verifier for two original signed CAS observer windows."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from . import reconcile as r


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC312 two independent original Ed25519 observer readback windows '
        'against 2-8 identical original CAS issuer decisions; no CAS I/O.'))
    subs = p.add_subparsers(dest='command', required=True)
    for command in ('verify', 'verify-report'):
        q = subs.add_parser(command)
        q.add_argument('--manifest-file', required=True)
        q.add_argument('--expected-manifest-sha256', required=True)
        if command == 'verify':
            q.add_argument('--out', help='new owner-private O_EXCL 0600/fsync audit')
        else:
            q.add_argument('--audit-report-file', required=True)
            q.add_argument('--expected-audit-report-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        opts = {'manifest_file': args.manifest_file,
                'expected_manifest_sha256': args.expected_manifest_sha256}
        if args.command == 'verify':
            result = r.verify(**opts, out=args.out)
        else:
            result = r.verify_report(
                **opts, audit_report_file=args.audit_report_file,
                expected_audit_report_sha256=args.expected_audit_report_sha256)
        print(json.dumps({
            'schema': r.RESULT_SCHEMA, 'command': args.command, **result,
            'external_cas_access_performed': False,
            'real_store_or_global_authority_authenticated': False,
        }, sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = exc.status if isinstance(exc, (a.AnchorError, io.HostError)) else 'unavailable'
        code = (exc.code if isinstance(exc, (a.AnchorError, io.HostError))
                else 'EC312_SIGNED_DUAL_OBSERVER_MATERIAL_UNAVAILABLE')
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(status, 5)
        print(json.dumps({
            'schema': r.DENIAL_SCHEMA, 'command': args.command,
            'status': status, 'reason_code': code, 'exit_code': rc,
            'both_observer_original_signature_chains_replayed': False,
            'real_external_cas_or_global_latest_proven': False,
            'business_or_external_store_write_performed': False,
        }, sort_keys=True, separators=(',', ':')))
        return rc
