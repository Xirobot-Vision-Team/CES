#!/usr/bin/env python3
"""EC259 opt-in strict EC257 service, gated by approved local Git custody.

No client flags can disable EC257 cgroup-v2/kernel-metering, source custody,
EC253 lease/signed ticket validation, or the original sandbox limits.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from quality_run_host import broker as runner
from finding_host import broker as fio
from session_host import broker as session
from custody_gated_host.gate import OperatorCustodyGate, CustodyGateError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC259 Git-custody-gated EC257 strict signed session host')
    sub = parser.add_subparsers(dest='action', required=True)
    for name in ('serve', 'probe'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--policy', required=True, help='Original EC253 private signed policy')
        cmd.add_argument('--repo', required=True, help='Operator-owned Git checkout')
        cmd.add_argument('--allowlist', required=True, help='EC258 operator private approved paths')
        cmd.add_argument('--receipt', required=True, help='EC258 local custody receipt')
        cmd.add_argument('--profile-id', required=True, help='One approved EC186 fixed profile')
        if name == 'serve':
            cmd.add_argument('--socket', required=True)
            cmd.add_argument('--max-sessions', type=int, default=1)
            cmd.add_argument('--accept-timeout', type=float, default=60.0)
    args = parser.parse_args(argv)
    gate = OperatorCustodyGate(args.policy, args.repo, args.allowlist,
                               args.receipt, args.profile_id)
    try:
        if args.action == 'probe':
            # The same startup callback, sans service: confirms only local
            # source/ticket consistency, never cgroup/Podman readiness.
            from lease_host import broker as lease
            policy, sha = lease._policy(args.policy)
            gate.startup(policy, sha)
            print(json.dumps(gate.probe_result(), sort_keys=True))
            return 2
        # Cleanup is a stronger obligation than proving a NEW source can run.
        # Recover prior signed orphaned sessions first even if this startup's
        # Git/receipt is now revoked. The core service repeats its own recovery.
        from lease_host import broker as lease
        policy, policy_sha = lease._policy(args.policy)
        with lease.Ledger(policy, policy_sha) as ledger:
            ledger.recover()
            if not ledger.safe():
                raise CustodyGateError('EC259_PRESTART_RECOVERY_UNCERTAIN')
        session.serve(args.policy, args.socket,
                      max_sessions=args.max_sessions,
                      accept_timeout=args.accept_timeout,
                      require_cgroup=True, require_kernel_metrics=True,
                      startup_guard=gate.startup,
                      before_begin_guard=gate.before_begin)
        # Graceful service exit says nothing about any run's Quality PASS.
        return 0
    except (runner.HostRunError, fio.HostError, CustodyGateError,
            OSError, ValueError) as exc:
        print(json.dumps(session._reply('unavailable',
                         getattr(exc, 'code', 'EC259_SERVICE_UNAVAILABLE')),
                         sort_keys=True))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
