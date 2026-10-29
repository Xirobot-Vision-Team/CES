#!/usr/bin/env python3
"""EC243: conservative, host-unattested status/coverage normalization.

Never promote child process exit 0, a reported `success`, a readable schema,
metadata creation or route availability into verified business completion. This
module interprets *untrusted* output for the opt-in EC241+ router only; direct
legacy PowerShell / direct Python callers retain their original contracts.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

STATUS_EXITS = {'partial': 2, 'offline': 3, 'denied': 3,
                'invalid': 4, 'unavailable': 5}
STATUS_NAMES = frozenset(STATUS_EXITS)

# Exact status tokens, never substring matching of arbitrary handler prose.
# `success` is *only* a claim by an untrusted handler and is always downgraded.
INVALID = frozenset({'invalid', 'invalid_input', 'invalid_request', 'rejected',
                     'validation_failed', 'INVALID'})
DENIED = frozenset({'denied', 'permission_denied', 'not_implemented',
                    'DECLINED', 'PERMISSION_DENIED', 'DENIED', 'DAG_CYCLE_BLOCKED'})
OFFLINE = frozenset({'offline', 'OFFLINE', 'network_disabled',
                     'NETWORK_DISABLED', 'offline_only'})
UNAVAILABLE = frozenset({'unavailable', 'UNAVAILABLE', 'UNKNOWN_BLOCKED',
                         'unknown_blocked', 'temporarily_unavailable', 'TIMEOUT'})
CLAIMED_SUCCESS = frozenset({'success', 'SUCCESS', 'ok', 'OK', 'completed',
                             'COMPLETED', 'ready', 'READY'})
PARTIAL = frozenset({'partial', 'PARTIAL', 'review_required', 'inventory_only',
                     'readable', 'audited', 'NOT_STARTED', 'DAG_VALID_NO_EXECUTION',
                     'metadata_created_not_started', 'PAUSED_PERMISSION_REQUIRED',
                     'CHECK_OBSERVED_ONLY', 'CHECK_BLOCKED', 'REPLAY_SUPPRESSED',
                     'AWAIT_PERMISSION_NO_CHECKPOINT', 'UNKNOWN_UNVERIFIED'})

# Known EC170 CodePrepare coverage fields. These are claims *by the handler*;
# a missing field is unknown, not an affirmative completeness assertion.
COVERAGE_FIELDS = (
    'source_identity_bound', 'path_inventory_complete', 'content_released',
    'content_complete_for_selected_source', 'source_currentness_proven',
    'remote_delivery_proven', 'provider_actor_verified',
)


@dataclass(frozen=True)
class Outcome:
    status: str
    reason_code: str
    exit_code: int
    basis: str
    coverage_assessment: str
    coverage_missing_claims: tuple[str, ...]
    handler_outcome_consistent: bool


def _coverage(value: dict[str, Any], *, declared_status: str | None) -> tuple[str, tuple[str, ...]]:
    declared = value.get('coverage')
    missing: list[str] = []
    if type(declared) is dict:
        for key in COVERAGE_FIELDS:
            if declared.get(key) is False:
                missing.append(key)
        # A provided explicit empty/failed requirement list is a handler
        # declaration only, never proof that unseen evidence is complete.
        if missing:
            return 'DECLARED_GAPS_UNVERIFIED', tuple(missing)
    if declared_status in PARTIAL or (type(declared) is dict and
                               declared.get('missing_requirements')):
        return 'PARTIAL_OR_INCOMPLETE_UNVERIFIED', tuple(missing)
    return 'NOT_ATTESTED_BY_ROUTER', tuple(missing)


def _class(raw: str | None) -> str | None:
    if raw in INVALID:
        return 'invalid'
    if raw in DENIED:
        return 'denied'
    if raw in OFFLINE:
        return 'offline'
    if raw in UNAVAILABLE:
        return 'unavailable'
    if raw in CLAIMED_SUCCESS or raw in PARTIAL:
        return 'partial'
    return None


def _code_class(exit_code: int | None) -> str | None:
    return {0: 'partial', 2: 'partial', 3: 'denied',
            4: 'invalid', 5: 'unavailable'}.get(exit_code)


def normalize_handler(value: dict[str, Any], *, exit_code: int | None,
                      handler_status: str | None) -> Outcome:
    """Normalize exactly one bounded validated handler result; no effects proven.

    Do not use arbitrary reason text as a status decision. Strongly negative
    exits override positive/partial status. Contradictory negative statuses are
    never downgraded to success, and receive an explicit consistency marker.
    """
    if type(value) is not dict:
        raise ValueError('EC243_EXPECTS_HANDLER_OBJECT')
    if exit_code is not None and (type(exit_code) is not int or
                                  exit_code not in (0, 2, 3, 4, 5)):
        return Outcome('unavailable', 'ROUTER_HANDLER_EXIT_UNRECOGNIZED', 5,
                       'abnormal_exit', 'NOT_ATTESTED_BY_ROUTER', (), False)
    if handler_status is not None and (type(handler_status) is not str or
                                       len(handler_status) > 160):
        return Outcome('unavailable', 'ROUTER_HANDLER_STATUS_MALFORMED', 5,
                       'invalid_status_type', 'NOT_ATTESTED_BY_ROUTER', (), False)
    # An actual CLI return is authoritative for detecting abnormal termination;
    # callers may not fabricate status via the JSON payload.
    if 'exit_code' in value:
        declared = value['exit_code']
        if type(declared) is not int or declared not in (0, 2, 3, 4, 5):
            return Outcome('unavailable', 'ROUTER_HANDLER_DECLARED_EXIT_INVALID', 5,
                           'invalid_declared_exit', 'NOT_ATTESTED_BY_ROUTER', (), False)
        if exit_code is not None and declared != exit_code:
            return Outcome('unavailable', 'ROUTER_HANDLER_EXIT_CONFLICT', 5,
                           'exit_conflict', 'NOT_ATTESTED_BY_ROUTER', (), False)
    raw_class = _class(handler_status)
    exit_class = _code_class(exit_code)
    if exit_class in ('invalid', 'denied', 'unavailable'):
        status = exit_class
        basis = 'handler_exit_code'
        consistent = raw_class in (None, status)
        # Unavailability and invalidity outrank a weak `partial`/`success` claim.
        # If the child explicitly says `offline` but exits 3, retain the
        # more specific class instead of miscalling an offline refusal denied.
        if exit_class == 'denied' and raw_class == 'offline':
            status = 'offline'
            consistent = True
            basis = 'offline_status_and_block_exit'
    elif raw_class is not None:
        status = raw_class
        basis = 'handler_status'
        consistent = (exit_class is None or exit_class == status or
                      (status == 'offline' and exit_class == 'denied'))
    else:
        # Even a code-0 JSON response is not proof; one unknown status remains
        # inspectable as a partial/unverified observation, never `success`.
        status = 'partial'
        basis = 'unrecognized_or_absent_status_unverified'
        # An unfamiliar domain-specific informational status is NOT evidence
        # of a contradiction; it is merely not a verified completion claim.
        consistent = True
    if handler_status in CLAIMED_SUCCESS:
        basis = 'success_claim_downgraded' if status == 'partial' else 'success_claim_conflicts_with_exit'
        consistent = status == 'partial'
    if status not in STATUS_NAMES:
        raise AssertionError('normalizer produced unregistered status')
    reasons = {
        'partial': 'ROUTER_HANDLER_PARTIAL_OR_UNVERIFIED',
        'offline': 'ROUTER_HANDLER_OFFLINE',
        'denied': 'ROUTER_HANDLER_DENIED',
        'invalid': 'ROUTER_HANDLER_INVALID',
        'unavailable': 'ROUTER_HANDLER_UNAVAILABLE',
    }
    reason = reasons[status]
    if basis == 'success_claim_downgraded':
        reason = 'ROUTER_HANDLER_SUCCESS_CLAIM_NOT_BUSINESS_PROOF'
    elif not consistent:
        reason = 'ROUTER_HANDLER_STATUS_EXIT_INCONSISTENT'
    coverage, missing = _coverage(value, declared_status=handler_status)
    return Outcome(status, reason, STATUS_EXITS[status], basis,
                   coverage, missing, consistent)


def normalize_router_rejection(*, status: str, reason_code: str,
                               handler_attempted: bool = False) -> Outcome:
    """Denials, bad input and missing handlers remain explicit no-result states."""
    mapping = {'invalid_input': 'invalid', 'invalid': 'invalid',
               'permission_denied': 'denied', 'denied': 'denied',
               'not_implemented': 'denied', 'legacy_native_only': 'denied',
               'offline': 'offline', 'unavailable': 'unavailable'}
    canonical = mapping.get(status, 'unavailable')
    return Outcome(canonical, reason_code, STATUS_EXITS[canonical],
                   'handler_attempt_failed' if handler_attempted else 'router_refusal',
                   'NOT_OBSERVED_NO_VALID_HANDLER_RESULT', (), True)
