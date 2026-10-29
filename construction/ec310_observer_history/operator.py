#!/usr/bin/env python3
"""EC310: strictly offline bounded signed readback history command line."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from . import history as h


COMMON_FLAGS = (
    'fork-case-file', 'expected-fork-case-sha256',
    'fork-evidence-file', 'expected-fork-evidence-sha256',
    'receipt-file', 'expected-receipt-sha256',
    'cas-authority-id', 'cas-public-hex', 'request-nonce-sha256',
    'expected-parent-cas-revision', 'expected-parent-cas-head-sha256',
    'readback-file', 'expected-readback-sha256',
    'cas-store-namespace-id', 'observer-id', 'observer-public-hex',
    'readback-request-nonce-sha256', 'expected-previous-readback-sequence',
    'expected-previous-readback-raw-sha256',
    'expected-previous-readback-observed-revision',
    'boundary-sequence', 'boundary-raw-sha256', 'boundary-observed-revision',
)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC310 offline EC309 chain verifier: 1-16 independently pinned '
        'previous readbacks, in chronological order, same original signed '
        'CAS decision, same observer and namespace. No network/CAS I/O, '
        'signatures issued or true external storage authority proven.'))
    sub = p.add_subparsers(dest='command', required=True)
    for command in ('verify', 'verify-report'):
        q = sub.add_parser(command)
        for flag in COMMON_FLAGS:
            q.add_argument('--' + flag, required=True,
                           type=int if flag in (
                               'expected-parent-cas-revision',
                               'expected-previous-readback-sequence',
                               'boundary-sequence') else str)
        q.add_argument('--previous-readback', required=True, nargs=3,
                       action='append', metavar=('FILE', 'RAW_SHA256', 'NONCE_SHA256'),
                       help='repeat 1-16 times, OLDEST first; three off-record values')
        if command == 'verify':
            q.add_argument('--out', help='optional exclusive 0600 canonical audit evidence')
        else:
            q.add_argument('--audit-report-file', required=True)
            q.add_argument('--expected-audit-report-sha256', required=True)
    return p


def _canonical_revision(value: str) -> int | None:
    if value == 'none':
        return None
    if (type(value) is str and value.isascii() and value.isdecimal() and
            (value == '0' or not value.startswith('0')) and len(value) <= 19):
        return int(value)
    raise a.AnchorError('EC310_REVISION_MUST_BE_NONE_OR_CANONICAL_NONNEGATIVE_INTEGER',
                        'invalid_input')


def _opts(args: argparse.Namespace) -> dict:
    return {
        'fork_case_file': args.fork_case_file,
        'expected_fork_case_sha256': args.expected_fork_case_sha256,
        'fork_evidence_file': args.fork_evidence_file,
        'expected_fork_evidence_sha256': args.expected_fork_evidence_sha256,
        'receipt_file': args.receipt_file,
        'expected_receipt_sha256': args.expected_receipt_sha256,
        'cas_trust': {
            'cas_authority_id': args.cas_authority_id,
            'cas_authority_public_hex': args.cas_public_hex,
            'expected_request_nonce_sha256': args.request_nonce_sha256,
            'expected_parent_cas_revision': args.expected_parent_cas_revision,
            'expected_parent_cas_head_sha256': args.expected_parent_cas_head_sha256,
        },
        'readback_file': args.readback_file,
        'expected_readback_sha256': args.expected_readback_sha256,
        'observer_trust': {
            'cas_store_namespace_id': args.cas_store_namespace_id,
            'observer_id': args.observer_id,
            'observer_public_hex': args.observer_public_hex,
            'expected_readback_request_nonce_sha256': args.readback_request_nonce_sha256,
            'expected_previous_readback_sequence': args.expected_previous_readback_sequence,
            'expected_previous_readback_raw_sha256': args.expected_previous_readback_raw_sha256,
            'expected_previous_readback_observed_revision':
                _canonical_revision(args.expected_previous_readback_observed_revision),
        },
        'boundary_trust': {
            'sequence': args.boundary_sequence,
            'raw_sha256': args.boundary_raw_sha256,
            'observed_revision': _canonical_revision(args.boundary_observed_revision),
        },
        'predecessors': [
            {'file': file, 'raw_sha256': sha, 'request_nonce_sha256': nonce}
            for file, sha, nonce in args.previous_readback
        ],
    }


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        opts = _opts(args)
        if args.command == 'verify':
            result = h.verify(**opts, out=args.out)
        else:
            result = h.verify_report(**opts,
                audit_report_file=args.audit_report_file,
                expected_audit_report_sha256=args.expected_audit_report_sha256)
        print(json.dumps({
            'schema': h.RESULT_SCHEMA, 'command': args.command, **result,
            'real_external_store_read_performed': False,
            'observer_organization_or_global_tip_authenticated': False,
        }, sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = exc.status if isinstance(exc, (a.AnchorError, io.HostError)) else 'unavailable'
        code = exc.code if isinstance(exc, (a.AnchorError, io.HostError)) else \
            'EC310_BOUNDED_OBSERVER_HISTORY_MATERIAL_UNAVAILABLE'
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(status, 5)
        print(json.dumps({
            'schema': h.DENIAL_SCHEMA, 'command': args.command,
            'status': status, 'reason_code': code, 'exit_code': rc,
            'bounded_signed_history_fully_replayed': False,
            'real_external_cas_or_global_latest_proven': False,
            'business_or_external_store_write_performed': False,
        }, sort_keys=True, separators=(',', ':')))
        return rc
