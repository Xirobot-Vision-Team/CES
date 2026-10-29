#!/usr/bin/env python3
"""EC257 strict service: EC256 cgroup kill + kernel resource-meter gate.

Never expose require_cgroup/require_kernel_metrics as client-supplied toggles.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec254_session_host import broker as session
from ec252_quality_run_host import broker as runner
from ec250_finding_host import broker as fio


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC257 signed kernel cgroup-v2 session service')
    sub = parser.add_subparsers(dest='command', required=True)
    run = sub.add_parser('serve')
    run.add_argument('--policy', required=True)
    run.add_argument('--socket', required=True)
    run.add_argument('--max-sessions', type=int, default=1)
    run.add_argument('--accept-timeout', type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        session.serve(args.policy, args.socket,
                      max_sessions=args.max_sessions,
                      accept_timeout=args.accept_timeout,
                      require_cgroup=True, require_kernel_metrics=True)
        return 0
    except (runner.HostRunError, fio.HostError, OSError, ValueError) as exc:
        print(session._reply('unavailable',
                             getattr(exc, 'code', 'EC257_SERVICE_UNAVAILABLE')))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
