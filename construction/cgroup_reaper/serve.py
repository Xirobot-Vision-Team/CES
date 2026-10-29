#!/usr/bin/env python3
"""EC256 opt-in strict EC187 session service, no new client-authorized fields."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from session_host import broker as session
from quality_run_host import broker as runner
from finding_host import broker as fio


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC256 rootless Podman cgroup-v2 mandatory-reap host')
    commands = parser.add_subparsers(dest='command', required=True)
    server = commands.add_parser('serve')
    server.add_argument('--policy', required=True)
    server.add_argument('--socket', required=True)
    server.add_argument('--max-sessions', type=int, default=1)
    server.add_argument('--accept-timeout', type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        session.serve(args.policy, args.socket, max_sessions=args.max_sessions,
                      accept_timeout=args.accept_timeout, require_cgroup=True)
        return 0
    except (runner.HostRunError, fio.HostError, OSError, ValueError) as exc:
        print(session._reply('unavailable',
                             getattr(exc, 'code', 'CGROUP256_HOST_UNAVAILABLE')))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
