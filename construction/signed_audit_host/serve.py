#!/usr/bin/env python3
"""EC262: strict EC260/261 session host with a mandatory local HMAC audit.

This is a new operator opt-in entrypoint. Client protocol and all prior host
entrypoints are untouched, and audit evidence is not external attestation.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from finding_host import broker as fio
from quality_run_host import broker as runner
from lease_host import broker as lease
from session_host import broker as session
from custody_gated_host.gate import CustodyGateError
from active_recall_host.serve import _gate, _recover_prior
from signed_audit_host.audit import AuditLog, AuditError, _reason


def _check_placement(args: argparse.Namespace) -> None:
    """Do not put the audit under containers' transient staging or ledger."""
    pol, _ = lease._policy(args.policy)
    directory = runner._private_dir(args.audit_root)
    # Source repository is also long-lived operator-owned data, but must not
    # contain the audit or vice versa (Git snapshot/maintenance isolation).
    repo = runner._private_dir(args.repo)
    paths = [pol[x] for x in ('scratch_root', 'ledger_root',
                               'runtime_home', 'runtime_xdg_dir')] + [repo]
    # A log must be a separate durable operator-owned directory, not a
    # container runtime dir which the cleanup routine can erase.
    for path in paths:
        if os.path.commonpath((directory, path)) in (directory, path):
            raise AuditError('EC262_AUDIT_LOCATION_OVERLAPS_RUNTIME')
    for path in (args.audit_key, pol['approval_hmac_key_path'],
                 pol['broker_hmac_key_path'], args.policy, pol['source_tar_path']):
        if os.path.commonpath((directory, path)) == directory:
            raise AuditError('EC262_AUDIT_LOCATION_OVERLAPS_SECRETS')
    key = lease._key(args.audit_key)
    if (args.audit_key in (pol['approval_hmac_key_path'], pol['broker_hmac_key_path']) or
            any(hmac.compare_digest(key, lease._key(pol[name]))
                for name in ('approval_hmac_key_path', 'broker_hmac_key_path'))):
        raise AuditError('EC262_AUDIT_KEY_NOT_DISTINCT')


def run_serve(args: argparse.Namespace) -> None:
    _check_placement(args)
    gate = _gate(args)
    with AuditLog(args.audit_root, args.audit_key) as audit:
        # Audit availability is a requirement BEFORE recovery/worker handling,
        # and a failure to commit any required event stops the service.
        audit.record('service_start')
        try:
            _recover_prior(args.policy)
            audit.record('service_recovery_complete')
            session.serve(
                args.policy, args.socket,
                max_sessions=args.max_sessions, accept_timeout=args.accept_timeout,
                require_cgroup=True, require_kernel_metrics=True,
                startup_guard=gate.startup,
                before_begin_guard=gate.before_begin,
                during_session_guard=gate.before_begin,
                audit_event=audit.record,
            )
        except BaseException as exc:
            # No secrets, paths, requests or exception strings in durable log.
            audit.record('service_failed', reason_code=_reason(
                getattr(exc, 'code', 'EC262_SERVICE_UNAVAILABLE')))
            raise
        audit.record('service_closed')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC262 signed active-recall cgroup host with durable HMAC attempt log')
    command = parser.add_subparsers(dest='action', required=True)
    serve = command.add_parser('serve')
    for name in ('policy', 'repo', 'allowlist', 'receipt', 'profile-id', 'socket'):
        serve.add_argument('--' + name, required=True)
    serve.add_argument('--max-sessions', type=int, default=1)
    serve.add_argument('--accept-timeout', type=float, default=60.0)
    verify = command.add_parser('verify-audit')
    for cmd in (serve, verify):
        cmd.add_argument('--audit-root', required=True)
        cmd.add_argument('--audit-key', required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == 'verify-audit':
            with AuditLog(args.audit_root, args.audit_key, create=False) as audit:
                print(json.dumps(audit.summary(), sort_keys=True))
            return 2  # Partial local integrity evidence, not Quality PASS.
        run_serve(args)
        return 0
    except (runner.HostRunError, fio.HostError, OSError, ValueError) as exc:
        print(json.dumps(session._reply('unavailable', _reason(
            getattr(exc, 'code', 'EC262_SERVICE_UNAVAILABLE'))), sort_keys=True))
        return 5


if __name__ == '__main__':
    raise SystemExit(main())
