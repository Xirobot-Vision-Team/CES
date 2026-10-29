#!/usr/bin/env python3
"""EC269 separate opt-in recovery CLI/strict host; no existing route changes.

Signatures are produced only by offline subcommands. The host's verify-gate
and serve routes take only public keys, signed artifacts and immutable pins.
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
from ec266_source_provenance_host.serve import _open_preflight, _ensure_gate_outside_audits
from ec266_source_provenance_host.provenance import ProvenanceError
from ec267_governed_source_host.governance import GovernanceError
from ec269_emergency_recovery_host.recovery import (
    RecoveryError, EmergencyRecoveryGate, prepare_charter, sign_charter,
    prepare_recovery, sign_recovery,
)


def _council(args: argparse.Namespace) -> tuple[tuple[str, str], ...]:
    files = getattr(args, 'council_public', None) or []
    pins = getattr(args, 'council_public_sha256', None) or []
    if len(files) != 3 or len(pins) != 3:
        raise RecoveryError('EC269_EXACTLY_THREE_INDEPENDENT_COUNCIL_PUBLIC_PINS_REQUIRED')
    return tuple(zip(files, pins))


def _basis(args: argparse.Namespace) -> dict:
    return dict(
        old_governance=args.old_governance,
        old_governance_sha256=args.old_governance_sha256,
        old_root_public=args.old_root_public,
        old_root_public_sha256=args.old_root_public_sha256,
        charter=args.charter,
        charter_sha256=args.charter_sha256,
        council_public_keys=_council(args),
        new_governance=args.governance_policy,
        new_governance_sha256=args.governance_policy_sha256,
        new_root_public=args.governance_public,
        new_root_public_sha256=args.governance_public_sha256,
    )


def _gate(args: argparse.Namespace, audit: CustodyAudit) -> EmergencyRecoveryGate:
    return EmergencyRecoveryGate(
        args.policy, args.repo, args.allowlist, args.receipt, args.profile_id,
        args.provenance_gate, args.provenance_gate_sha256,
        args.governance_policy, args.governance_policy_sha256,
        args.governance_public, args.governance_public_sha256,
        minimum_epoch=args.minimum_governance_epoch,
        expected_previous_governance_sha256=args.expected_previous_governance_sha256,
        old_governance=args.old_governance,
        old_governance_sha256=args.old_governance_sha256,
        old_root_public=args.old_root_public,
        old_root_public_sha256=args.old_root_public_sha256,
        charter=args.charter, charter_sha256=args.charter_sha256,
        council_public_keys=_council(args),
        recovery_certificate=args.recovery_certificate,
        recovery_certificate_sha256=args.recovery_certificate_sha256,
        anchor_governance=args.anchor_governance,
        anchor_governance_sha256=args.anchor_governance_sha256,
        continuation_chain=args.continuation_chain,
        continuation_chain_sha256=args.continuation_chain_sha256,
        forbidden_signers=(audit.config['signer_public_sha256'],
                           audit.gate_config['custody_public_sha256']),
    )


def _preflight(args: argparse.Namespace, audit: CustodyAudit) -> EmergencyRecoveryGate:
    gate = _gate(args, audit)
    _ensure_gate_outside_audits(args, audit, gate)
    cfg = gate._read_config()
    protected_source = [gate.gate_path, cfg['subject']]
    for authority in cfg['authorities']:
        protected_source.extend(authority[k] for k in ('public_key', 'assertion', 'evidence'))
    audit_roots = [item['audit_root'] for item in audit.config['archives']]
    audit_roots.append(audit.config['active']['audit_root'])
    for pathname in gate.authority_paths():
        if pathname in protected_source:
            raise RecoveryError('EC269_RECOVERY_FILE_COLLIDES_WITH_SOURCE_AUTHORITY')
        for root in [gate.repo, *audit_roots]:
            if os.path.commonpath((pathname, root)) == root:
                raise RecoveryError('EC269_RECOVERY_FILE_INSIDE_SOURCE_OR_AUDIT_TREE')
    return gate


def verify_gate(args: argparse.Namespace) -> dict:
    with _open_preflight(args, writable=False) as audit:
        gate = _preflight(args, audit)
        policy, sha = lease._policy(args.policy)
        gate.startup(policy, sha)
        result = gate.summary()
        result['custody_receipts_verified'] = audit.summary()['custody_receipts_verified']
        return result


def run_serve(args: argparse.Namespace) -> None:
    chain = _read_config(args.chain, args.chain_sha256)
    for entry in chain['archives'] + [chain['active']]:
        placement = argparse.Namespace(**vars(args))
        placement.audit_root = entry['audit_root']
        placement.audit_key = entry['audit_key']
        _check_placement(placement)
    # Recover abandoned original EC253/255/256 leases even if recovery fails.
    _recover_prior(args.policy)
    with _open_preflight(args, writable=True) as audit:
        gate = _preflight(args, audit)
        policy, sha = lease._policy(args.policy)
        gate.startup(policy, sha)  # before socket, service_start or a new lease
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
                    getattr(exc, 'code', 'EC269_RECOVERY_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def _required(cmd: argparse.ArgumentParser, names: tuple[str, ...]) -> None:
    for name in names:
        cmd.add_argument('--' + name.replace('_', '-'), required=True)


def _council_args(cmd: argparse.ArgumentParser) -> None:
    cmd.add_argument('--council-public', action='append', required=True)
    cmd.add_argument('--council-public-sha256', action='append', required=True)


OLD = ('old_governance', 'old_governance_sha256',
       'old_root_public', 'old_root_public_sha256')
NEW = ('governance_policy', 'governance_policy_sha256',
       'governance_public', 'governance_public_sha256')
CHARTER = ('charter', 'charter_sha256')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC269 pre-authorized quorum emergency root recovery (opt-in)')
    sub = parser.add_subparsers(dest='action', required=True)

    pre = sub.add_parser('prepare-charter', help='Old root pre-commits council before key loss')
    _required(pre, OLD + ('expires_at_unix', 'output'))
    _council_args(pre)

    charter_sign = sub.add_parser('sign-charter', help='Old root signs independent SHA-pinned charter')
    _required(charter_sign, OLD + ('proposal', 'proposal_sha256',
                                 'old_root_private', 'output'))
    _council_args(charter_sign)

    proposal = sub.add_parser('prepare-recovery', help='New-root epoch + old signed charter proof')
    _required(proposal, OLD + NEW + CHARTER + ('output',))
    _council_args(proposal)

    sign = sub.add_parser('sign-recovery', help='Ordered new-root then two council approvals')
    _required(sign, OLD + NEW + CHARTER +
              ('input_path', 'input_sha256', 'signing_key', 'expected_public_sha256', 'output'))
    sign.add_argument('--role', choices=('new', 'council'), required=True)
    _council_args(sign)

    for name in ('verify-gate', 'serve'):
        cmd = sub.add_parser(name, help='Verify all old/new/quorum evidence before session')
        _required(cmd, ('chain', 'chain_sha256', 'custody_gate', 'custody_gate_sha256',
                        'provenance_gate', 'provenance_gate_sha256') +
                  OLD + NEW + CHARTER +
                  ('recovery_certificate', 'recovery_certificate_sha256',
                   'policy', 'repo', 'allowlist', 'receipt', 'profile_id',
                   'minimum_governance_epoch', 'expected_previous_governance_sha256'))
        _council_args(cmd)
        cmd.add_argument('--anchor-governance')
        cmd.add_argument('--anchor-governance-sha256')
        cmd.add_argument('--continuation-chain')
        cmd.add_argument('--continuation-chain-sha256')
        if name == 'serve':
            cmd.add_argument('--socket', required=True)
            cmd.add_argument('--max-sessions', type=int, default=1)
            cmd.add_argument('--accept-timeout', type=float, default=60.0)

    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare-charter':
            result = prepare_charter(
                old_governance=args.old_governance,
                old_governance_sha256=args.old_governance_sha256,
                old_root_public=args.old_root_public,
                old_root_public_sha256=args.old_root_public_sha256,
                council_public_keys=_council(args),
                expires_at_unix=int(args.expires_at_unix), output=args.output)
        elif args.action == 'sign-charter':
            result = sign_charter(
                proposal=args.proposal, proposal_sha256=args.proposal_sha256,
                old_governance=args.old_governance,
                old_governance_sha256=args.old_governance_sha256,
                old_root_public=args.old_root_public,
                old_root_public_sha256=args.old_root_public_sha256,
                council_public_keys=_council(args),
                old_root_private=args.old_root_private, output=args.output)
        elif args.action == 'prepare-recovery':
            result = prepare_recovery(**_basis(args), output=args.output)
        elif args.action == 'sign-recovery':
            result = sign_recovery(
                **_basis(args), input_path=args.input_path,
                input_sha256=args.input_sha256, role=args.role,
                signing_key=args.signing_key,
                expected_public_sha256=args.expected_public_sha256,
                output=args.output)
        elif args.action == 'verify-gate':
            args.minimum_governance_epoch = int(args.minimum_governance_epoch)
            result = verify_gate(args)
        else:
            args.minimum_governance_epoch = int(args.minimum_governance_epoch)
            run_serve(args)
            return 0
        print(json.dumps(result, sort_keys=True))
        return 2
    except (runner.HostRunError, fio.HostError, GovernanceError, RecoveryError,
            ProvenanceError, cp.AnchorError, OSError, ValueError, TypeError) as exc:
        print(json.dumps(session._reply('unavailable', _reason(
            getattr(exc, 'code', 'EC269_RECOVERY_UNAVAILABLE'))), sort_keys=True))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
