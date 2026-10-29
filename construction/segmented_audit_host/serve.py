#!/usr/bin/env python3
"""EC264 opt-in strict service and operator-only offline rollover commands.

No session-wire/Router mode changes. No signing key is accepted by serve,
verify-chain or init-next. All three require independent config SHA256 pin.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from finding_host import broker as fio
from quality_run_host import broker as runner
from session_host import broker as session
from active_recall_host.serve import _gate, _recover_prior
from signed_audit_host.serve import _check_placement
from signed_audit_host.audit import _reason
from segmented_audit_host.segment import (
    SegmentAudit, SegmentError, _read_config, propose_transition,
    sign_transition_offline,
)


def run_serve(args: argparse.Namespace) -> None:
    config = _read_config(args.chain, args.chain_sha256)
    # Archive audit directories and keys must be as isolated from the OCI
    # staging/runtime/approval secrets as the active EC262 audit directory.
    for entry in config['archives'] + [config['active']]:
        placement = argparse.Namespace(**vars(args))
        placement.audit_root = entry['audit_root']
        placement.audit_key = entry['audit_key']
        _check_placement(placement)
    gate = _gate(args)
    with SegmentAudit(args.chain, args.chain_sha256) as audit:
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
            # Do not replace primary session cleanup fault if audit poisoned.
            try:
                audit.record('service_failed', reason_code=_reason(
                    getattr(exc, 'code', 'EC264_SERVICE_UNAVAILABLE')))
            except BaseException:
                pass
            raise
        audit.record('service_closed')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC264 offline-signed audit-segment rollover')
    commands = parser.add_subparsers(dest='action', required=True)
    proposal = commands.add_parser('propose-transition',
        help='Stopped, fully signed old journal -> unsigned successor proposal')
    for flag in ('archive-root', 'archive-key', 'checkpoint', 'checkpoint-sha256',
                 'signer-public-key', 'signer-public-sha256', 'successor-key',
                 'output'):
        proposal.add_argument('--' + flag, required=True)
    proposal.add_argument('--parent-continuation-sha256', default='0' * 64)
    offline = commands.add_parser('offline-sign-transition',
        help='Offline machine only; independently review proposal before signing')
    for flag in ('proposal', 'signing-key', 'output'):
        offline.add_argument('--' + flag, required=True)
    for action in ('init-next', 'verify-chain', 'serve'):
        command = commands.add_parser(action)
        command.add_argument('--chain', required=True,
                             help='Operator-private canonical segment chain config')
        command.add_argument('--chain-sha256', required=True,
                             help='Independent operator pin (no runtime auto-pinning)')
        if action == 'serve':
            for flag in ('policy', 'repo', 'allowlist', 'receipt', 'profile-id', 'socket'):
                command.add_argument('--' + flag, required=True)
            command.add_argument('--max-sessions', type=int, default=1)
            command.add_argument('--accept-timeout', type=float, default=60.)
    args = parser.parse_args(argv)
    try:
        if args.action == 'propose-transition':
            result = propose_transition(
                args.archive_root, args.archive_key, args.checkpoint,
                args.checkpoint_sha256, args.signer_public_key,
                args.signer_public_sha256, args.successor_key,
                args.parent_continuation_sha256, args.output)
        elif args.action == 'offline-sign-transition':
            result = sign_transition_offline(args.proposal, args.signing_key,
                                             args.output)
        elif args.action == 'init-next':
            with SegmentAudit(args.chain, args.chain_sha256,
                              initialize=True) as audit:
                result = {'status': 'partial', 'exit_code': 2,
                          'reason_code': 'EC264_EMPTY_SEGMENT_INITIALIZED_ONCE',
                          'overall_quality_pass_verified': False}
        elif args.action == 'verify-chain':
            with SegmentAudit(args.chain, args.chain_sha256, writable=False) as audit:
                result = audit.summary()
        else:
            run_serve(args)
            return 0
        print(json.dumps(result, sort_keys=True))
        return 2
    except (runner.HostRunError, fio.HostError, OSError, ValueError) as exc:
        print(json.dumps(session._reply('unavailable', _reason(
            getattr(exc, 'code', 'EC264_SEGMENT_UNAVAILABLE'))), sort_keys=True))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
