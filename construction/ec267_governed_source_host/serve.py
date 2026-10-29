#!/usr/bin/env python3
"""EC267 optional strict host: EC266 + independent expiring issuer governance.

No default EC266/EC265/Router behavior or EC186-187 wire protocol is changed.
Signing keys must never be copied to a production host; only public keys
and pinned signed governance snapshots are used by `verify-gate`/`serve`.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec250_finding_host import broker as fio
from ec252_quality_run_host import broker as runner
from ec253_lease_host import broker as lease
from ec254_session_host import broker as session
from ec260_active_recall_host.serve import _recover_prior
from ec262_signed_audit_host.serve import _check_placement
from ec262_signed_audit_host.audit import _reason
from ec263_offline_anchor_host import checkpoint as cp
from ec264_segmented_audit_host.segment import _read_config
from ec265_custody_receipt_host.custody import CustodyAudit
from ec266_source_provenance_host.serve import (
    _ensure_gate_outside_audits, _open_preflight,
)
from ec266_source_provenance_host.provenance import ProvenanceError
from ec267_governed_source_host.governance import (
    GovernanceError, GovernedSourceGate, ZERO, prepare_policy, sign_offline,
)


def _gate(args: argparse.Namespace, audit: CustodyAudit) -> GovernedSourceGate:
    return GovernedSourceGate(
        args.policy, args.repo, args.allowlist, args.receipt, args.profile_id,
        args.provenance_gate, args.provenance_gate_sha256,
        args.governance_policy, args.governance_policy_sha256,
        args.governance_public, args.governance_public_sha256,
        minimum_epoch=args.minimum_governance_epoch,
        expected_previous_governance_sha256=args.expected_previous_governance_sha256,
        forbidden_signers=(audit.config['signer_public_sha256'],
                           audit.gate_config['custody_public_sha256']),
    )


def _preflight(args: argparse.Namespace, audit: CustodyAudit) -> GovernedSourceGate:
    gate = _gate(args, audit)
    _ensure_gate_outside_audits(args, audit, gate)
    occupied = [gate.gate_path, gate._read_config()['subject']]
    for role in gate._read_config()['authorities']:
        occupied.extend(role[k] for k in ('public_key', 'assertion', 'evidence'))
    roots = [gate.repo] + [entry['audit_root'] for entry in audit.config['archives']]
    roots.append(audit.config['active']['audit_root'])
    for path in gate.authority_paths():
        if path in occupied:
            raise GovernanceError('EC267_GOVERNANCE_FILE_COLLIDES_WITH_AUTHORITY')
        for root in roots:
            if os.path.commonpath((path, root)) == root:
                raise GovernanceError('EC267_GOVERNANCE_FILE_INSIDE_TRUSTED_TREE')
    return gate


def verify_gate(args: argparse.Namespace) -> dict:
    with _open_preflight(args, writable=False) as audit:
        gate = _preflight(args, audit)
        policy, pin = lease._policy(args.policy)
        gate.startup(policy, pin)
        summary = gate.summary()
        summary['custody_receipts_verified'] = audit.summary()['custody_receipts_verified']
        return summary


def run_serve(args: argparse.Namespace) -> None:
    chain = _read_config(args.chain, args.chain_sha256)
    for entry in chain['archives'] + [chain['active']]:
        placement = argparse.Namespace(**vars(args))
        placement.audit_root = entry['audit_root']
        placement.audit_key = entry['audit_key']
        _check_placement(placement)
    # Always repay historic lease debts, even after an issuer/root is revoked.
    _recover_prior(args.policy)
    with _open_preflight(args, writable=True) as audit:
        gate = _preflight(args, audit)
        policy, pin = lease._policy(args.policy)
        gate.startup(policy, pin)  # BEFORE socket / any new lease / service_start
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
                    getattr(exc, 'code', 'EC267_GOVERNANCE_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC267 expiring independent issuer trust gate')
    sub = parser.add_subparsers(dest='action', required=True)
    propose = sub.add_parser('prepare-policy', help='Unsigned issuer lifecycle proposal only')
    for key in ('provenance-gate', 'provenance-gate-sha256', 'epoch',
                'previous-governance-sha256', 'not-before-unix', 'expires-at-unix',
                'output'):
        propose.add_argument('--' + key, required=True)
    propose.add_argument('--revoke-public-sha256', action='append', default=[],
                         help='Repeatable 64 lowercase hex; preserve previous revocations')
    signer = sub.add_parser('sign-offline', help='Offline fourth independent governance authority')
    for key in ('proposal', 'proposal-sha256', 'signing-key',
                'expected-governance-public-sha256', 'output'):
        signer.add_argument('--' + key, required=True)
    keygen = sub.add_parser('governance-keygen', help='OFFLINE ONLY: governance root keypair')
    for key in ('signing-key', 'public-key'):
        keygen.add_argument('--' + key, required=True)
    for action in ('verify-gate', 'serve'):
        cmd = sub.add_parser(action)
        for key in ('chain', 'chain-sha256', 'custody-gate', 'custody-gate-sha256',
                    'provenance-gate', 'provenance-gate-sha256', 'governance-policy',
                    'governance-policy-sha256', 'governance-public',
                    'governance-public-sha256', 'policy', 'repo', 'allowlist',
                    'receipt', 'profile-id', 'minimum-governance-epoch',
                    'expected-previous-governance-sha256'):
            cmd.add_argument('--' + key, required=True)
        if action == 'serve':
            cmd.add_argument('--socket', required=True)
            cmd.add_argument('--max-sessions', type=int, default=1)
            cmd.add_argument('--accept-timeout', type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare-policy':
            result = prepare_policy(
                args.provenance_gate, args.provenance_gate_sha256,
                epoch=int(args.epoch),
                previous_governance_sha256=args.previous_governance_sha256,
                not_before_unix=int(args.not_before_unix),
                expires_at_unix=int(args.expires_at_unix),
                revoked_public_sha256=tuple(args.revoke_public_sha256),
                output=args.output)
        elif args.action == 'sign-offline':
            result = sign_offline(args.proposal, args.proposal_sha256,
                                  args.signing_key,
                                  args.expected_governance_public_sha256,
                                  args.output)
        elif args.action == 'governance-keygen':
            result = cp.generate_offline_keypair(args.signing_key, args.public_key)
        elif args.action == 'verify-gate':
            args.minimum_governance_epoch = int(args.minimum_governance_epoch)
            result = verify_gate(args)
        else:
            args.minimum_governance_epoch = int(args.minimum_governance_epoch)
            run_serve(args)
            return 0
        print(json.dumps(result, sort_keys=True))
        return 2
    except (runner.HostRunError, fio.HostError, GovernanceError,
            ProvenanceError, cp.AnchorError, OSError, ValueError) as exc:
        print(json.dumps(session._reply('unavailable', _reason(
            getattr(exc, 'code', 'EC267_GOVERNANCE_UNAVAILABLE'))), sort_keys=True))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
