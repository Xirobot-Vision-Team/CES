#!/usr/bin/env python3
"""EC268 standalone opt-in three-party root handover guarded strict Linux host.

No signing secrets reach serve/verify-gate. No modifications to existing
PowerShell, Router, EC186/187 protocol, or previous strict host entrypoints.
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
from source_provenance_host.serve import _open_preflight, _ensure_gate_outside_audits
from source_provenance_host.provenance import ProvenanceError
from governed_source_host.governance import GovernanceError
from root_handover_host.handover import (
    HandoverError, RootHandoverGate, prepare_handover, prepare_continuation, sign_offline,
)


def _gate(args: argparse.Namespace, audit: CustodyAudit) -> RootHandoverGate:
    return RootHandoverGate(
        args.policy, args.repo, args.allowlist, args.receipt, args.profile_id,
        args.provenance_gate, args.provenance_gate_sha256,
        args.governance_policy, args.governance_policy_sha256,
        args.governance_public, args.governance_public_sha256,
        minimum_epoch=args.minimum_governance_epoch,
        expected_previous_governance_sha256=args.expected_previous_governance_sha256,
        previous_governance=args.previous_governance_policy,
        previous_governance_sha256=args.previous_governance_policy_sha256,
        previous_governance_public=args.previous_governance_public,
        previous_governance_public_sha256=args.previous_governance_public_sha256,
        witness_public=args.witness_public,
        witness_public_sha256=args.witness_public_sha256,
        handover_certificate=args.handover_certificate,
        handover_certificate_sha256=args.handover_certificate_sha256,
        anchor_governance=args.anchor_governance,
        anchor_governance_sha256=args.anchor_governance_sha256,
        continuation_chain=getattr(args, 'continuation_chain', None),
        continuation_chain_sha256=getattr(args, 'continuation_chain_sha256', None),
        forbidden_signers=(audit.config['signer_public_sha256'],
                           audit.gate_config['custody_public_sha256']),
    )


def _preflight(args: argparse.Namespace, audit: CustodyAudit) -> RootHandoverGate:
    gate = _gate(args, audit)
    _ensure_gate_outside_audits(args, audit, gate)
    config = gate._read_config()
    occupied = [gate.gate_path, config['subject']]
    for authority in config['authorities']:
        occupied.extend(authority[k] for k in ('public_key', 'assertion', 'evidence'))
    roots = [gate.repo] + [item['audit_root'] for item in audit.config['archives']]
    roots.append(audit.config['active']['audit_root'])
    for path in gate.authority_paths():
        if path in occupied:
            raise HandoverError('EC268_HANDOVER_FILE_COLLIDES_WITH_SOURCE_AUTHORITY')
        for root in roots:
            if os.path.commonpath((path, root)) == root:
                raise HandoverError('EC268_HANDOVER_FILE_INSIDE_TRUSTED_SOURCE_OR_AUDIT')
    return gate


def verify_gate(args: argparse.Namespace) -> dict:
    with _open_preflight(args, writable=False) as audit:
        gate = _preflight(args, audit)
        policy, policy_sha = lease._policy(args.policy)
        gate.startup(policy, policy_sha)
        result = gate.summary()
        result['custody_receipts_verified'] = audit.summary()['custody_receipts_verified']
        return result


def run_serve(args: argparse.Namespace) -> None:
    chain = _read_config(args.chain, args.chain_sha256)
    for part in chain['archives'] + [chain['active']]:
        placement = argparse.Namespace(**vars(args))
        placement.audit_root = part['audit_root']
        placement.audit_key = part['audit_key']
        _check_placement(placement)
    # Always recover prior leases, including if the new handover was revoked.
    _recover_prior(args.policy)
    with _open_preflight(args, writable=True) as audit:
        gate = _preflight(args, audit)
        policy, policy_sha = lease._policy(args.policy)
        gate.startup(policy, policy_sha)  # BEFORE service_start, socket, or lease
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
                    getattr(exc, 'code', 'EC268_HANDOVER_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def _fields(parser: argparse.ArgumentParser, names: tuple[str, ...]) -> None:
    for key in names:
        parser.add_argument('--' + key, required=True)


CURRENT = ('governance-policy', 'governance-policy-sha256',
           'governance-public', 'governance-public-sha256')
PREVIOUS = ('previous-governance-policy', 'previous-governance-policy-sha256',
            'previous-governance-public', 'previous-governance-public-sha256')
WITNESS = ('witness-public', 'witness-public-sha256')
HANDOVER = ('handover-certificate', 'handover-certificate-sha256')
ANCHOR = ('anchor-governance', 'anchor-governance-sha256')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC268 independently pinned three-party root handover')
    sub = parser.add_subparsers(dest='action', required=True)
    prepare = sub.add_parser('prepare-handover', help='Check two signed epochs and create unsigned handover')
    _fields(prepare, PREVIOUS + CURRENT + WITNESS + ('output',))
    renew = sub.add_parser('prepare-continuation',
        help='Append a new-root-signed epoch without requiring old root or witness')
    _fields(renew, ANCHOR + ('governance-public', 'governance-public-sha256',
                    'next-governance', 'next-governance-sha256', 'output'))
    renew.add_argument('--previous-chain')
    renew.add_argument('--previous-chain-sha256')
    signer = sub.add_parser('sign-offline', help='Each party signs a separately SHA-pinned prior stage')
    signer.add_argument('--role', choices=('old', 'new', 'witness'), required=True)
    _fields(signer, ('input', 'input-sha256', 'signing-key', 'expected-public-sha256', 'output'))
    for key in ('previous-governance-public', 'previous-governance-public-sha256',
                'governance-public', 'governance-public-sha256'):
        signer.add_argument('--' + key)
    for name in ('verify-gate', 'serve'):
        cmd = sub.add_parser(name)
        _fields(cmd, ('chain', 'chain-sha256', 'custody-gate', 'custody-gate-sha256',
                      'provenance-gate', 'provenance-gate-sha256') +
                CURRENT + PREVIOUS + WITNESS + HANDOVER + ANCHOR +
                ('policy', 'repo', 'allowlist', 'receipt', 'profile-id',
                 'minimum-governance-epoch', 'expected-previous-governance-sha256'))
        cmd.add_argument('--continuation-chain')
        cmd.add_argument('--continuation-chain-sha256')
        if name == 'serve':
            cmd.add_argument('--socket', required=True)
            cmd.add_argument('--max-sessions', type=int, default=1)
            cmd.add_argument('--accept-timeout', type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare-handover':
            result = prepare_handover(
                old_governance=args.previous_governance_policy,
                old_governance_sha256=args.previous_governance_policy_sha256,
                new_governance=args.governance_policy,
                new_governance_sha256=args.governance_policy_sha256,
                old_root_public=args.previous_governance_public,
                old_root_public_sha256=args.previous_governance_public_sha256,
                new_root_public=args.governance_public,
                new_root_public_sha256=args.governance_public_sha256,
                witness_public=args.witness_public,
                witness_public_sha256=args.witness_public_sha256,
                output=args.output)
        elif args.action == 'prepare-continuation':
            result = prepare_continuation(
                anchor_governance=args.anchor_governance,
                anchor_governance_sha256=args.anchor_governance_sha256,
                new_root_public=args.governance_public,
                new_root_public_sha256=args.governance_public_sha256,
                next_governance=args.next_governance,
                next_governance_sha256=args.next_governance_sha256,
                previous_chain=args.previous_chain,
                previous_chain_sha256=args.previous_chain_sha256,
                output=args.output)
        elif args.action == 'sign-offline':
            previous = {}
            if args.role in ('new', 'witness'):
                if not args.previous_governance_public or not args.previous_governance_public_sha256:
                    raise HandoverError('EC268_OLD_ROOT_PUBLIC_PIN_REQUIRED')
                previous['old'] = (args.previous_governance_public,
                                   args.previous_governance_public_sha256)
            if args.role == 'witness':
                if not args.governance_public or not args.governance_public_sha256:
                    raise HandoverError('EC268_NEW_ROOT_PUBLIC_PIN_REQUIRED')
                previous['new'] = (args.governance_public, args.governance_public_sha256)
            result = sign_offline(args.input, args.input_sha256, args.role,
                                  args.signing_key, args.expected_public_sha256,
                                  args.output, previous_public_keys=previous)
        elif args.action == 'verify-gate':
            args.minimum_governance_epoch = int(args.minimum_governance_epoch)
            result = verify_gate(args)
        else:
            args.minimum_governance_epoch = int(args.minimum_governance_epoch)
            run_serve(args)
            return 0
        print(json.dumps(result, sort_keys=True))
        return 2
    except (runner.HostRunError, fio.HostError, GovernanceError, HandoverError,
            ProvenanceError, cp.AnchorError, OSError, ValueError) as exc:
        print(json.dumps(session._reply('unavailable', _reason(
            getattr(exc, 'code', 'EC268_HANDOVER_UNAVAILABLE'))), sort_keys=True))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
