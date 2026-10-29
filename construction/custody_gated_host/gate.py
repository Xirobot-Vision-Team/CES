#!/usr/bin/env python3
"""EC259: fail-closed, operator-owned Git→TAR gate for signed EC257 sessions.

Checks only locally trusted Git objects, the deterministic exact Source TAR,
receipt and ORIGINAL EC253 dual-HMAC binding. Does NOT authenticate remote Git,
enterprise authors/reviewers, CI, source-pin derivation or global Quality PASS.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from session_host import broker as session
from lease_host import broker as lease
from git_tar_custody import custody
import quality_run_guard as guard


class CustodyGateError(session.SessionHostError):
    """Stable, non-secret fail-closed reason in the existing session wire."""


@dataclass
class OperatorCustodyGate:
    """One operator-selected profile and one fixed policy across this service.

    Startup/pre-begin are called by the trusted service only, NOT by clients.
    No mutation of EC186/253 keys, tickets, profile, TAR or Git objects.
    """

    policy_path: str
    repo: str
    allowlist_path: str
    receipt_path: str
    profile_id: str
    _policy_sha: str | None = field(default=None, init=False, repr=False)
    _last_result: dict[str, Any] | None = field(default=None, init=False, repr=False)

    def _verify(self, policy: dict[str, Any], policy_sha: str,
                *, expect_started: bool) -> dict[str, Any]:
        # Original session/EC253 validate these again, but the operator's
        # initial approved policy bytes may never change while this host lives.
        if expect_started and (self._policy_sha is None or
                               policy_sha != self._policy_sha):
            raise CustodyGateError('EC259_POLICY_PIN_CHANGED')
        if guard.catalog_entry(self.profile_id) is None:
            raise CustodyGateError('EC259_PROFILE_NOT_BUILTIN')
        try:
            # Exact Source TAR path is read from EC253's validated private
            # policy. Neither client request nor cwd can choose it.
            result = custody.verify(
                self.repo, self.allowlist_path, policy['source_tar_path'],
                self.receipt_path, self.policy_path, self.profile_id)
        except custody.CustodyError as exc:
            raise CustodyGateError('EC259_' + exc.code) from exc
        except (OSError, ValueError, lease.LeaseHostError) as exc:
            raise CustodyGateError('EC259_CUSTODY_RECHECK_UNAVAILABLE') from exc
        if not (type(result) is dict and result.get('status') == 'partial' and
                result.get('exit_code') == 2 and
                result.get('content_custody_verified') is True and
                result.get('local_ec253_tickets_consistent') is True and
                result.get('source_tar_sha256') ==
                policy['expected_source_tar_sha256']):
            raise CustodyGateError('EC259_CUSTODY_INCOMPLETE')
        # `verify` opens the policy to check the HMACs; require it to still
        # be byte-identical to the service's loaded/ledger-bound snapshot.
        try:
            latest, latest_sha = lease._policy(self.policy_path)
        except (OSError, ValueError, lease.LeaseHostError) as exc:
            raise CustodyGateError('EC259_POLICY_RECHECK_UNAVAILABLE') from exc
        if latest_sha != policy_sha or latest != policy:
            raise CustodyGateError('EC259_POLICY_RACED')
        return result

    def startup(self, policy: dict[str, Any], policy_sha: str) -> None:
        """Called before socket bind; pin only after full signed custody check."""
        if self._policy_sha is not None:
            raise CustodyGateError('EC259_STARTUP_ALREADY_ARMED')
        result = self._verify(policy, policy_sha, expect_started=False)
        self._policy_sha = policy_sha
        self._last_result = result

    def before_begin(self, policy: dict[str, Any], policy_sha: str,
                     request: dict[str, Any]) -> None:
        """Every begin, after EC254 signed-scope verification but BEFORE lease/fork."""
        if self._policy_sha is None:
            raise CustodyGateError('EC259_STARTUP_NOT_ARMED')
        if (type(request) is not dict or
                request.get('profile_id') != self.profile_id):
            raise CustodyGateError('EC259_UNAPPROVED_PROFILE')
        self._last_result = self._verify(policy, policy_sha, expect_started=True)

    def probe_result(self) -> dict[str, Any]:
        """Local development/preflight only; no host or quality attestation."""
        if self._last_result is None:
            raise CustodyGateError('EC259_STARTUP_NOT_ARMED')
        return {
            'status': 'partial', 'exit_code': 2,
            'reason_code': 'EC259_OPERATOR_LOCAL_CUSTODY_ONLY',
            'commit_oid': self._last_result['commit_oid'],
            'source_tar_sha256': self._last_result['source_tar_sha256'],
            'local_ec253_tickets_consistent': True,
            'strict_ec257_host_live_verified': False,
            'independent_git_origin_attested': False,
            'enterprise_actor_authenticated': False,
            'overall_quality_pass_verified': False,
        }
