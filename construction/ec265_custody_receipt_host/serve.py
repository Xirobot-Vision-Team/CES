#!/usr/bin/env python3
"""EC265 opt-in CLI: offline archive custody with independently pinned receipts.

No EC186/187 wire, PowerShell/Router, legacy service, or OCI policy changes.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec250_finding_host import broker as fio
from ec252_quality_run_host import broker as runner
from ec254_session_host import broker as session
from ec260_active_recall_host.serve import _gate, _recover_prior
from ec262_signed_audit_host.serve import _check_placement
from ec262_signed_audit_host.audit import _reason
from ec263_offline_anchor_host import checkpoint as cp
from ec264_segmented_audit_host.segment import _read_config
from ec265_custody_receipt_host.custody import (
    CustodyAudit, export_archive, receive_archive, verify_deposit,
)


def run_serve(args: argparse.Namespace) -> None:
    chain = _read_config(args.chain, args.chain_sha256)
    for entry in chain['archives'] + [chain['active']]:
        placement = argparse.Namespace(**vars(args))
        placement.audit_root = entry['audit_root']
        placement.audit_key = entry['audit_key']
        _check_placement(placement)
    gate = _gate(args)
    with CustodyAudit(args.chain, args.chain_sha256,
                      args.custody_gate, args.custody_gate_sha256) as audit:
        audit.record('service_start')
        try:
            _recover_prior(args.policy)
            audit.record('service_recovery_complete')
            session.serve(
                args.policy, args.socket,
                max_sessions=args.max_sessions,
                accept_timeout=args.accept_timeout,
                require_cgroup=True, require_kernel_metrics=True,
                startup_guard=gate.startup,
                before_begin_guard=gate.before_begin,
                during_session_guard=gate.before_begin,
                audit_event=audit.record,
            )
        except BaseException as exc:
            try:
                audit.record('service_failed', reason_code=_reason(
                    getattr(exc, 'code', 'EC265_CUSTODY_SERVICE_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC265 independently signed audit custody receipts')
    commands = parser.add_subparsers(dest='action', required=True)
    export = commands.add_parser('export-archive', help='Copy one fully signed archive without keys')
    for arg in ('chain', 'chain-sha256', 'output-dir'):
        export.add_argument('--' + arg, required=True)
    export.add_argument('--archive-index', required=True, type=int)
    keygen = commands.add_parser('custody-keygen', help='Offline custodian only; keep secret off host')
    for arg in ('signing-key', 'public-key'):
        keygen.add_argument('--' + arg, required=True)
    receive = commands.add_parser('receive-archive', help='Offline custodian only; verify/deposit/sign once')
    for arg in ('bundle-dir', 'vault-root', 'custody-signing-key',
                'custody-public-sha256'):
        receive.add_argument('--' + arg, required=True)
    verify = commands.add_parser('verify-deposit', help='Re-read locally stored deposit and signed receipt')
    for arg in ('vault-root', 'deposit-id', 'custody-public-key',
                'custody-public-sha256', 'receipt-sha256'):
        verify.add_argument('--' + arg, required=True)
    for cmd in (receive, verify):
        cmd.add_argument('--archive-index', type=int, required=True)
        for arg in ('checkpoint-sha256', 'continuation-sha256',
                    'parent-continuation-sha256', 'signer-public-sha256'):
            cmd.add_argument('--expected-' + arg, required=True)
    for action in ('verify-custody-gate', 'serve'):
        cmd = commands.add_parser(action)
        for arg in ('chain', 'chain-sha256', 'custody-gate', 'custody-gate-sha256'):
            cmd.add_argument('--' + arg, required=True)
        if action == 'serve':
            for arg in ('policy', 'repo', 'allowlist', 'receipt', 'profile-id', 'socket'):
                cmd.add_argument('--' + arg, required=True)
            cmd.add_argument('--max-sessions', type=int, default=1)
            cmd.add_argument('--accept-timeout', type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        if args.action == 'export-archive':
            result = export_archive(args.chain, args.chain_sha256,
                                    args.archive_index, args.output_dir)
        elif args.action == 'custody-keygen':
            result = cp.generate_offline_keypair(args.signing_key, args.public_key)
        elif args.action == 'receive-archive':
            result = receive_archive(
                args.bundle_dir, args.vault_root, args.custody_signing_key,
                args.custody_public_sha256,
                expected_index=args.archive_index,
                expected_checkpoint_pin=args.expected_checkpoint_sha256,
                expected_continuation_pin=args.expected_continuation_sha256,
                expected_parent_pin=args.expected_parent_continuation_sha256,
                expected_signer_pin=args.expected_signer_public_sha256)
        elif args.action == 'verify-deposit':
            result = verify_deposit(
                args.vault_root, args.deposit_id, args.custody_public_key,
                args.custody_public_sha256,
                expected_index=args.archive_index,
                expected_checkpoint_pin=args.expected_checkpoint_sha256,
                expected_continuation_pin=args.expected_continuation_sha256,
                expected_parent_pin=args.expected_parent_continuation_sha256,
                expected_signer_pin=args.expected_signer_public_sha256,
                receipt_pin=args.receipt_sha256)
        elif args.action == 'verify-custody-gate':
            with CustodyAudit(args.chain, args.chain_sha256,
                              args.custody_gate, args.custody_gate_sha256,
                              writable=False) as audit:
                result = audit.summary()
        else:
            run_serve(args)
            return 0
        print(json.dumps(result, sort_keys=True))
        return 2
    except (runner.HostRunError, fio.HostError, OSError, ValueError) as exc:
        print(json.dumps(session._reply('unavailable', _reason(
            getattr(exc, 'code', 'EC265_CUSTODY_UNAVAILABLE'))), sort_keys=True))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
