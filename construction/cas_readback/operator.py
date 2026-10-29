#!/usr/bin/env python3
"""EC309 offline independent signed readback auditor (verify-only)."""
from __future__ import annotations

import argparse
import json

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from . import readback as r


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'Offline verification of SECOND independent Ed25519 CAS readback claim. '
        'No actual CAS/WORM read, external provenance, or global latest proof. '
        'All full-file SHA, IDs, signer keys, nonces, namespace and prior anchor '
        'must be obtained independently from the signed records.'))
    sub = p.add_subparsers(dest='command', required=True)
    common = (
        'fork-case-file', 'expected-fork-case-sha256',
        'fork-evidence-file', 'expected-fork-evidence-sha256',
        'receipt-file', 'expected-receipt-sha256',
        'cas-authority-id', 'cas-public-hex', 'request-nonce-sha256',
        'expected-parent-cas-revision', 'expected-parent-cas-head-sha256',
        'readback-file', 'expected-readback-sha256',
        'cas-store-namespace-id', 'observer-id', 'observer-public-hex',
        'readback-request-nonce-sha256', 'expected-previous-readback-sequence',
        'expected-previous-readback-raw-sha256',
    )
    for command in ('verify', 'verify-report'):
        q = sub.add_parser(command)
        for flag in common:
            q.add_argument('--' + flag, required=True, type=int if flag in (
                'expected-parent-cas-revision',
                'expected-previous-readback-sequence') else str)
        # string "none" for GENESIS. An integer otherwise. Never pick from claim.
        q.add_argument('--expected-previous-readback-observed-revision',
                       required=True)
        if command == 'verify':
            q.add_argument('--out', help='optional private exclusive/fsynced audit report')
        else:
            q.add_argument('--audit-report-file', required=True)
            q.add_argument('--expected-audit-report-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        previous_revision_arg = args.expected_previous_readback_observed_revision
        if previous_revision_arg == 'none':
            previous_revision = None
        elif (previous_revision_arg.isascii() and
              previous_revision_arg.isdecimal() and
              (previous_revision_arg == '0' or
               not previous_revision_arg.startswith('0')) and
              len(previous_revision_arg) <= 19):
            previous_revision = int(previous_revision_arg)
        else:
            raise a.AnchorError('EC309_PREVIOUS_REVISION_MUST_BE_NONE_OR_CANONICAL_INTEGER',
                                'invalid_input')
        opts = {
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
                'expected_readback_request_nonce_sha256':
                    args.readback_request_nonce_sha256,
                'expected_previous_readback_sequence':
                    args.expected_previous_readback_sequence,
                'expected_previous_readback_raw_sha256':
                    args.expected_previous_readback_raw_sha256,
                'expected_previous_readback_observed_revision': previous_revision,
            },
        }
        if args.command == 'verify':
            result = r.verify(**opts, out=args.out)
        else:
            result = r.verify_report(**opts, audit_report_file=args.audit_report_file,
                expected_audit_report_sha256=args.expected_audit_report_sha256)
        print(json.dumps({
            'schema': r.RESULT_SCHEMA, 'command': args.command, **result,
            'real_external_store_read_performed': False,
            'two_physical_independent_operators_verified': False,
            'current_global_latest_verified': False,
        }, sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = exc.status if isinstance(exc, (a.AnchorError, io.HostError)) else 'unavailable'
        code = exc.code if isinstance(exc, (a.AnchorError, io.HostError)) else \
            'EC309_OFFLINE_READBACK_MATERIAL_UNAVAILABLE'
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}.get(status, 5)
        print(json.dumps({
            'schema': r.DENIAL_SCHEMA, 'command': args.command,
            'status': status, 'reason_code': code, 'exit_code': rc,
            'full_original_cas_replay_and_observer_signature_verified': False,
            'real_external_cas_read_or_global_latest_proven': False,
            'external_store_or_original_business_write_performed': False,
        }, sort_keys=True, separators=(',', ':')))
        return rc
