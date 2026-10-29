#!/usr/bin/env python3
"""EC266 explicit opt-in three-role admission on EC265 strict audited host.

The serve process loads only Ed25519 public keys; offline keys never pass to
this command. Remote source/CI/reviewer verification remains the issuer's
responsibility. Existing legacy shell/router modes remain unchanged.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from finding_host import broker as fio
from quality_run_host import broker as runner
from lease_host import broker as lease
from session_host import broker as session
from active_recall_host.serve import _recover_prior
from signed_audit_host.serve import _check_placement
from signed_audit_host.audit import _reason
from offline_anchor_host import checkpoint as cp
from segmented_audit_host.segment import _read_config
from custody_receipt_host.custody import CustodyAudit
from source_provenance_host.provenance import (
    ProvenanceError, SignedSourceGate, propose, sign_offline,
)


def _source_gate(args: argparse.Namespace, audit: CustodyAudit) -> SignedSourceGate:
    return SignedSourceGate(
        args.policy, args.repo, args.allowlist, args.receipt, args.profile_id,
        args.provenance_gate, args.provenance_gate_sha256,
        forbidden_signers=(audit.config['signer_public_sha256'],
                           audit.gate_config['custody_public_sha256']),
    )


def _ensure_gate_outside_audits(args: argparse.Namespace, audit: CustodyAudit,
                                gate: SignedSourceGate) -> None:
    """Authority metadata must not be part of a mutable EC262 journal tree."""
    config = gate._read_config()
    paths = [gate.gate_path, config['subject']]
    for record in config['authorities']:
        paths.extend(record[k] for k in ('assertion', 'public_key', 'evidence'))
    roots = [e['audit_root'] for e in audit.config['archives']]
    roots.append(audit.config['active']['audit_root'])
    for path in paths:
        for root in roots:
            if os.path.commonpath((path, root)) == root:
                raise ProvenanceError('EC266_AUTHORITY_FILE_INSIDE_AUDIT_ROOT')


def _open_preflight(args: argparse.Namespace, *, writable: bool):
    # Trust chain and custody receipts are validated by the EC265 context.
    # This helper only creates the context; caller owns and closes it.
    return CustodyAudit(args.chain, args.chain_sha256,
                        args.custody_gate, args.custody_gate_sha256,
                        writable=writable)


def run_serve(args: argparse.Namespace) -> None:
    chain = _read_config(args.chain, args.chain_sha256)
    for entry in chain['archives'] + [chain['active']]:
        placement = argparse.Namespace(**vars(args))
        placement.audit_root = entry['audit_root']
        placement.audit_key = entry['audit_key']
        _check_placement(placement)
    # Old leased resources are an unconditional cleanup obligation, even when
    # the newly presented origin/reviewer/CI keys or signatures are revoked.
    _recover_prior(args.policy)
    with _open_preflight(args, writable=True) as audit:
        gate = _source_gate(args, audit)
        _ensure_gate_outside_audits(args, audit, gate)
        policy, policy_sha = lease._policy(args.policy)
        gate.startup(policy, policy_sha)  # PRE socket/lease/audit-start
        audit.record('service_start')
        try:
            audit.record('service_recovery_complete')
            session.serve(
                args.policy, args.socket,
                max_sessions=args.max_sessions,
                accept_timeout=args.accept_timeout,
                require_cgroup=True, require_kernel_metrics=True,
                startup_guard=gate.recheck_startup,
                before_begin_guard=gate.before_begin,
                during_session_guard=gate.before_begin,
                audit_event=audit.record,
            )
        except BaseException as exc:
            try:
                audit.record('service_failed', reason_code=_reason(
                    getattr(exc, 'code', 'EC266_SOURCE_ADMISSION_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def verify_gate(args: argparse.Namespace) -> dict:
    with _open_preflight(args, writable=False) as audit:
        gate = _source_gate(args, audit)
        _ensure_gate_outside_audits(args, audit, gate)
        policy, sha = lease._policy(args.policy)
        gate.startup(policy, sha)
        result = gate.summary()
        result['custody_receipts_verified'] = audit.summary()['custody_receipts_verified']
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC266 independently signed source admission')
    sub = parser.add_subparsers(dest='action', required=True)
    source = sub.add_parser('propose', help='Unsigned local Git and EC253 subject, not proof')
    for name in ('policy', 'repo', 'allowlist', 'receipt', 'profile-id',
                 'origin-repository', 'origin-ref', 'output'):
        source.add_argument('--' + name, required=True)
    signer = sub.add_parser('sign-offline', help='For independent origin/review/CI authority only')
    for name in ('subject', 'subject-sha256', 'role', 'evidence',
                 'evidence-sha256', 'evidence-id', 'signing-key',
                 'expected-public-sha256', 'output'):
        signer.add_argument('--' + name, required=True)
    keygen = sub.add_parser('authority-keygen', help='Offline only; use 3 separate role identities')
    for name in ('signing-key', 'public-key'):
        keygen.add_argument('--' + name, required=True)
    for cmdname in ('verify-gate', 'serve'):
        cmd = sub.add_parser(cmdname)
        for name in ('chain', 'chain-sha256', 'custody-gate',
                     'custody-gate-sha256', 'provenance-gate',
                     'provenance-gate-sha256', 'policy', 'repo',
                     'allowlist', 'receipt', 'profile-id'):
            cmd.add_argument('--' + name, required=True)
        if cmdname == 'serve':
            cmd.add_argument('--socket', required=True)
            cmd.add_argument('--max-sessions', type=int, default=1)
            cmd.add_argument('--accept-timeout', type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        if args.action == 'propose':
            result = propose(args.repo, args.allowlist, args.receipt,
                             args.policy, args.profile_id,
                             args.origin_repository, args.origin_ref, args.output)
        elif args.action == 'sign-offline':
            result = sign_offline(
                args.subject, args.subject_sha256, args.role,
                args.evidence, args.evidence_sha256, args.evidence_id,
                args.signing_key, args.expected_public_sha256, args.output)
        elif args.action == 'authority-keygen':
            result = cp.generate_offline_keypair(args.signing_key, args.public_key)
        elif args.action == 'verify-gate':
            result = verify_gate(args)
        else:
            run_serve(args)
            return 0
        print(json.dumps(result, sort_keys=True))
        return 2
    except (runner.HostRunError, fio.HostError, ProvenanceError,
            OSError, ValueError) as exc:
        print(json.dumps(session._reply('unavailable', _reason(
            getattr(exc, 'code', 'EC266_SOURCE_ADMISSION_UNAVAILABLE'))), sort_keys=True))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
