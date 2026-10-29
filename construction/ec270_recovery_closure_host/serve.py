#!/usr/bin/env python3
"""EC270 opt-in offline closure ceremony and separately ratified strict host.

No root, council or witness private signing key is accepted by host routes.
Offline commands require independently pinned exact input and signed history.
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
from ec269_emergency_recovery_host import serve as prior
from ec269_emergency_recovery_host.recovery import RecoveryError
from ec270_recovery_closure_host.closure import (
    ClosureError, RatifiedRecoveryGate, prepare_closure, sign_closure, verify_closure,
)


def _basis(args: argparse.Namespace) -> dict:
    return dict(
        old_governance=args.old_governance,
        old_governance_sha256=args.old_governance_sha256,
        old_root_public=args.old_root_public,
        old_root_public_sha256=args.old_root_public_sha256,
        charter=args.charter, charter_sha256=args.charter_sha256,
        council_public_keys=prior._council(args),
        anchor_governance=args.anchor_governance,
        anchor_governance_sha256=args.anchor_governance_sha256,
        recovered_root_public=args.governance_public,
        recovered_root_public_sha256=args.governance_public_sha256,
        recovery_certificate=args.recovery_certificate,
        recovery_certificate_sha256=args.recovery_certificate_sha256,
        witness_public=args.witness_public,
        witness_public_sha256=args.witness_public_sha256,
    )


def _gate(args: argparse.Namespace, audit: CustodyAudit) -> RatifiedRecoveryGate:
    return RatifiedRecoveryGate(
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
        council_public_keys=prior._council(args),
        recovery_certificate=args.recovery_certificate,
        recovery_certificate_sha256=args.recovery_certificate_sha256,
        anchor_governance=args.anchor_governance,
        anchor_governance_sha256=args.anchor_governance_sha256,
        continuation_chain=args.continuation_chain,
        continuation_chain_sha256=args.continuation_chain_sha256,
        closure_certificate=args.closure_certificate,
        closure_certificate_sha256=args.closure_certificate_sha256,
        witness_public=args.witness_public,
        witness_public_sha256=args.witness_public_sha256,
        minimum_witness_observed_at_unix=args.minimum_closure_observed_at_unix,
        forbidden_signers=(audit.config['signer_public_sha256'],
                           audit.gate_config['custody_public_sha256']),
    )


def _preflight(args: argparse.Namespace, audit: CustodyAudit) -> RatifiedRecoveryGate:
    gate = _gate(args, audit)
    _ensure_gate_outside_audits(args, audit, gate)
    cfg = gate._read_config()
    protected_source = [gate.gate_path, cfg['subject']]
    for authority in cfg['authorities']:
        protected_source.extend(authority[key] for key in ('public_key', 'assertion', 'evidence'))
    audit_roots = [item['audit_root'] for item in audit.config['archives']]
    audit_roots.append(audit.config['active']['audit_root'])
    for pathname in gate.authority_paths():
        if pathname in protected_source:
            raise ClosureError('EC270_AUTHORITY_COLLIDES_WITH_SOURCE_EVIDENCE')
        for root in [gate.repo, *audit_roots]:
            if os.path.commonpath((pathname, root)) == root:
                raise ClosureError('EC270_AUTHORITY_INSIDE_SOURCE_OR_AUDIT_TREE')
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
    for item in chain['archives'] + [chain['active']]:
        placement = argparse.Namespace(**vars(args))
        placement.audit_root = item['audit_root']
        placement.audit_key = item['audit_key']
        _check_placement(placement)
    # Attempt recovery of historical durable leases even if closure is denied.
    _recover_prior(args.policy)
    with _open_preflight(args, writable=True) as audit:
        gate = _preflight(args, audit)
        policy, sha = lease._policy(args.policy)
        gate.startup(policy, sha)  # before socket, event or new lease
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
                    getattr(exc, 'code', 'EC270_RATIFIED_RECOVERY_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


OLD = ('old_governance', 'old_governance_sha256',
       'old_root_public', 'old_root_public_sha256')
ANCHOR = ('anchor_governance', 'anchor_governance_sha256',
          'governance_public', 'governance_public_sha256')
ARTIFACTS = ('charter', 'charter_sha256', 'recovery_certificate',
             'recovery_certificate_sha256', 'witness_public', 'witness_public_sha256')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC270 witnessed ratification of EC269 emergency recovery (opt-in)')
    sub = parser.add_subparsers(dest='action', required=True)

    prepare = sub.add_parser('prepare-closure', help='Prepare historic recovery closure proposal')
    prior._required(prepare, OLD + ANCHOR + ARTIFACTS + ('output',))
    prior._council_args(prepare)

    sign = sub.add_parser('sign-closure', help='Sign root, council 1+2, then witness')
    prior._required(sign, OLD + ANCHOR + ARTIFACTS +
                    ('input_path', 'input_sha256', 'signing_key',
                     'expected_public_sha256', 'output'))
    prior._council_args(sign)
    sign.add_argument('--role', choices=('root', 'council', 'witness'), required=True)

    audit = sub.add_parser('verify-closure', help='Verify signed ceremony, including historic expired charter')
    prior._required(audit, OLD + ANCHOR + ARTIFACTS +
                    ('closure_certificate', 'closure_certificate_sha256'))
    prior._council_args(audit)

    for name in ('verify-gate', 'serve'):
        cmd = sub.add_parser(name, help='Strict source+custody+ratified closure live admission')
        prior._required(cmd, OLD + ANCHOR + ARTIFACTS +
                        ('closure_certificate', 'closure_certificate_sha256',
                         'minimum_closure_observed_at_unix', 'chain', 'chain_sha256',
                         'custody_gate', 'custody_gate_sha256',
                         'provenance_gate', 'provenance_gate_sha256',
                         'policy', 'repo', 'allowlist', 'receipt', 'profile_id',
                         'minimum_governance_epoch',
                         'expected_previous_governance_sha256'))
        prior._council_args(cmd)
        # CURRENT governance is separate from the signed recovery anchor.
        cmd.add_argument('--governance-policy', required=True)
        cmd.add_argument('--governance-policy-sha256', required=True)
        cmd.add_argument('--continuation-chain')
        cmd.add_argument('--continuation-chain-sha256')
        if name == 'serve':
            cmd.add_argument('--socket', required=True)
            cmd.add_argument('--max-sessions', type=int, default=1)
            cmd.add_argument('--accept-timeout', type=float, default=60.0)

    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare-closure':
            result = prepare_closure(**_basis(args), output=args.output)
        elif args.action == 'sign-closure':
            result = sign_closure(
                **_basis(args), input_path=args.input_path,
                input_sha256=args.input_sha256, role=args.role,
                signing_key=args.signing_key,
                expected_public_sha256=args.expected_public_sha256,
                output=args.output)
        elif args.action == 'verify-closure':
            result = verify_closure(
                **_basis(args), closure_certificate=args.closure_certificate,
                closure_certificate_sha256=args.closure_certificate_sha256)
        elif args.action == 'verify-gate':
            args.minimum_governance_epoch = int(args.minimum_governance_epoch)
            args.minimum_closure_observed_at_unix = int(args.minimum_closure_observed_at_unix)
            result = verify_gate(args)
        else:
            args.minimum_governance_epoch = int(args.minimum_governance_epoch)
            args.minimum_closure_observed_at_unix = int(args.minimum_closure_observed_at_unix)
            run_serve(args)
            return 0
        print(json.dumps(result, sort_keys=True))
        return 2
    except (runner.HostRunError, fio.HostError, GovernanceError, RecoveryError,
            ProvenanceError, cp.AnchorError, OSError, ValueError, TypeError) as exc:
        print(json.dumps(session._reply('unavailable', _reason(
            getattr(exc, 'code', 'EC270_RATIFIED_RECOVERY_UNAVAILABLE'))), sort_keys=True))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
