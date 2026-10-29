#!/usr/bin/env python3
"""EC260: opt-in active authority recall for signed EC259/257 host sessions.

Unlike EC259, a client can remain silent and the operator-selected service
still rechecks signed authorization AND Git→TAR content custody, then reaps
an affected OCI session. This is local authority freshness, NOT remote Git
origin trust, certified cgroup operation or enterprise Quality PASS.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec250_finding_host import broker as fio
from ec252_quality_run_host import broker as runner
from ec253_lease_host import broker as lease
from ec254_session_host import broker as session
from ec259_custody_gated_host.gate import OperatorCustodyGate, CustodyGateError


def _gate(args: argparse.Namespace) -> OperatorCustodyGate:
    # No untrusted session/client field is permitted to specify these paths.
    return OperatorCustodyGate(args.policy, args.repo, args.allowlist,
                               args.receipt, args.profile_id)


def _recover_prior(policy_path: str) -> None:
    """Existing durable OCI leases must be recovered before Git preflight.

    A revoked approval does not waive cleanup of an older running container.
    """
    pol, sha = lease._policy(policy_path)
    with lease.Ledger(pol, sha) as ledger:
        ledger.recover()
        if not ledger.safe():
            raise CustodyGateError('EC260_PRESTART_RECOVERY_UNCERTAIN')


def run_serve(args: argparse.Namespace) -> None:
    gate = _gate(args)
    _recover_prior(args.policy)
    # This is a NEW entrypoint. EC259's original serve still has no runtime
    # monitor, preserving its behaviour and existing public contract.
    session.serve(
        args.policy, args.socket,
        max_sessions=args.max_sessions, accept_timeout=args.accept_timeout,
        require_cgroup=True, require_kernel_metrics=True,
        startup_guard=gate.startup,
        before_begin_guard=gate.before_begin,
        during_session_guard=gate.before_begin,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC260 signed strict Git-custody host with active runtime recall')
    commands = parser.add_subparsers(dest='action', required=True)
    for name in ('serve', 'probe'):
        cmd = commands.add_parser(name)
        cmd.add_argument('--policy', required=True)
        cmd.add_argument('--repo', required=True)
        cmd.add_argument('--allowlist', required=True)
        cmd.add_argument('--receipt', required=True)
        cmd.add_argument('--profile-id', required=True)
        if name == 'serve':
            cmd.add_argument('--socket', required=True)
            cmd.add_argument('--max-sessions', type=int, default=1)
            cmd.add_argument('--accept-timeout', type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        if args.action == 'probe':
            policy, sha = lease._policy(args.policy)
            gate = _gate(args)
            gate.startup(policy, sha)
            # A preflight must NEVER certify an active OCI/recall watchdog.
            report = gate.probe_result()
            report['reason_code'] = 'EC260_LOCAL_PREFLIGHT_ONLY'
            report['active_recall_runtime_live_verified'] = False
            report['overall_quality_pass_verified'] = False
            print(json.dumps(report, sort_keys=True))
            return 2
        run_serve(args)
        return 0
    except (runner.HostRunError, fio.HostError, CustodyGateError,
            OSError, ValueError) as exc:
        print(json.dumps(session._reply(
            'unavailable', getattr(exc, 'code', 'EC260_SERVICE_UNAVAILABLE')),
            sort_keys=True))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
