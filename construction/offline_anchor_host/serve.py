#!/usr/bin/env python3
"""EC263 operator-only signed audit checkpoint and gated strict session host.

The original EC262 host stays opt-in and unchanged. This new host requires
out-of-band pinned Ed25519 checkpoint/public-key SHA-256 values, never accepts
an online signing key, and never modifies EC186/187 client protocol.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from finding_host import broker as fio
from quality_run_host import broker as runner
from session_host import broker as session
from active_recall_host.serve import _gate, _recover_prior
from signed_audit_host.serve import _check_placement
from signed_audit_host.audit import _reason
from offline_anchor_host.checkpoint import (
    AnchoredAudit, generate_offline_keypair, propose, sign_offline,
)


def run_serve(args: argparse.Namespace) -> None:
    _check_placement(args)
    gate = _gate(args)
    # Signer secret is explicitly NOT accepted as a serving parameter.
    with AnchoredAudit(args.audit_root, args.audit_key, args.checkpoint,
                       args.signer_public_key, args.signer_public_sha256,
                       args.checkpoint_sha256) as audit:
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
            # Best effort failure event only, without replacing the original
            # cleanup error; a poisoned audit must not be treated as healthy.
            try:
                audit.record('service_failed', reason_code=_reason(
                    getattr(exc, 'code', 'EC263_SERVICE_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC263 offline-Ed25519-checkpoint-gated EC262 strict audit host')
    commands = parser.add_subparsers(dest='action', required=True)
    keygen = commands.add_parser('offline-keygen',
        help='Run on an independent offline signer, never on the serving host')
    keygen.add_argument('--signing-key', required=True)
    keygen.add_argument('--signer-public-key', required=True)
    proposal = commands.add_parser('propose-checkpoint',
        help='Capture a stopped EC262 journal; operator must separately review')
    proposal.add_argument('--audit-root', required=True)
    proposal.add_argument('--audit-key', required=True)
    proposal.add_argument('--signer-public-sha256', required=True)
    proposal.add_argument('--output', required=True)
    signer = commands.add_parser('offline-sign',
        help='Run ONLY on offline signer, review proposal before signing')
    signer.add_argument('--proposal', required=True)
    signer.add_argument('--signing-key', required=True)
    signer.add_argument('--output', required=True)
    for name in ('verify-checkpoint', 'serve'):
        action = commands.add_parser(name)
        action.add_argument('--audit-root', required=True)
        action.add_argument('--audit-key', required=True)
        action.add_argument('--checkpoint', required=True)
        action.add_argument('--checkpoint-sha256', required=True)
        action.add_argument('--signer-public-key', required=True)
        action.add_argument('--signer-public-sha256', required=True)
        if name == 'serve':
            for field in ('policy', 'repo', 'allowlist', 'receipt', 'profile-id', 'socket'):
                action.add_argument('--' + field, required=True)
            action.add_argument('--max-sessions', type=int, default=1)
            action.add_argument('--accept-timeout', type=float, default=60.)
    args = parser.parse_args(argv)
    try:
        if args.action == 'offline-keygen':
            result = generate_offline_keypair(args.signing_key, args.signer_public_key)
        elif args.action == 'propose-checkpoint':
            result = propose(args.audit_root, args.audit_key,
                             args.signer_public_sha256, args.output)
        elif args.action == 'offline-sign':
            result = sign_offline(args.proposal, args.signing_key, args.output)
        elif args.action == 'verify-checkpoint':
            with AnchoredAudit(args.audit_root, args.audit_key, args.checkpoint,
                               args.signer_public_key, args.signer_public_sha256,
                               args.checkpoint_sha256, writable=False) as audit:
                result = audit.summary()
        else:
            run_serve(args)
            return 0
        print(json.dumps(result, sort_keys=True))
        return 2  # Local partial evidence, NEVER overall Quality PASS.
    except (runner.HostRunError, fio.HostError, OSError, ValueError) as exc:
        print(json.dumps(session._reply('unavailable', _reason(
            getattr(exc, 'code', 'EC263_ANCHOR_UNAVAILABLE'))), sort_keys=True))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
