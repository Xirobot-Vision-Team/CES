#!/usr/bin/env python3
"""EC-212: explicit-whitelist, in-memory, read-only IssueSync snapshot.

Composes EC211 read_issue for each caller-approved number, NOT an IssueShow,
IssueMatch, IssueCreate, provider-side synchronization, persistent cache, or
native CES PowerShell route. Both a batch-level EC212 grant AND distinct EC211
per-issue grants must be supplied; the dataclasses are host declarations, not
authenticated organizational grants.

All observations are non-atomic and metadata-projection-only. An inaccessible
Issue is UNKNOWN, never definitively absent. Caller-supplied baseline digests
are comparison hints, not authenticated earlier remote observations.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import sys
from typing import Callable, Mapping, Any

try:
    from . import issue_provider as ip
except ImportError:
    import issue_provider as ip

SCHEMA = 'ces.issue_sync.v1'
METHOD = 'READ_ISSUE_SYNC_SNAPSHOT'
HASH_DOMAIN = b'CES-EC212-ISSUE-SYNC-SELECTED-PROJECTIONS-v1\x00'
MAX_ISSUES = 8
MAX_BATCH_GRANT_SECONDS = 300
MAX_OBSERVATION_AGE_SECONDS = 120
SHA256 = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
DIGITS = re.compile(r'[1-9][0-9]{0,18}\Z', re.ASCII)
REASON = re.compile(r'ISSUE_[A-Z0-9_]{1,90}\Z', re.ASCII)


@dataclass(frozen=True)
class IssueSyncScope:
    repository: str
    expected_repository_id: int
    numbers: tuple[int, ...]   # Explicit sorted allowlist, never a range or discovery.


@dataclass(frozen=True)
class IssueSyncGrant:
    method: str
    provider: str
    api_host: str
    account_ref: str
    repository: str
    expected_repository_id: int
    numbers: tuple[int, ...]
    expires_at_utc: str
    authorized: bool
    allow_write: bool = False


@dataclass(frozen=True)
class BaselineFingerprint:
    number: int
    provider_issue_id: str
    identity_sha256: str
    snapshot_sha256: str


class SyncError(ValueError):
    def __init__(self, reason: str, status: str = 'unavailable') -> None:
        super().__init__(reason)
        self.reason = 'ISSUE_SYNC_' + reason
        self.status = status


def _need(ok: bool, reason: str, status: str = 'unavailable') -> None:
    if not ok:
        raise SyncError(reason, status)


def _now(clock: Callable[[], datetime] | None) -> datetime:
    try:
        return ip._now(clock)
    except ip.IssueError:
        raise SyncError('CLOCK_UNAVAILABLE') from None


def _stamp(dt: datetime) -> str:
    return dt.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _parse_stamp(value: str) -> datetime:
    try:
        return ip._at_utc(value)
    except ip.IssueError:
        raise SyncError('TIMESTAMP_INVALID') from None


def _scope(context: ip.ProviderContext, scope: IssueSyncScope) -> None:
    try:
        ip._validate_context(context)
    except ip.IssueError as e:
        raise SyncError('PROVIDER_CONTEXT_INVALID', e.status) from None
    _need(type(scope) is IssueSyncScope, 'SCOPE_INVALID', 'invalid_input')
    _need(ip._positive_id(scope.expected_repository_id),
          'REPOSITORY_ID_INVALID', 'invalid_input')
    _need(type(scope.numbers) is tuple and 1 <= len(scope.numbers) <= MAX_ISSUES,
          'ALLOWLIST_INVALID', 'invalid_input')
    _need(all(type(n) is int and 1 <= n <= 2147483647 for n in scope.numbers) and
          tuple(sorted(set(scope.numbers))) == scope.numbers,
          'ALLOWLIST_INVALID', 'invalid_input')
    try:
        ip._validate_scope(context, ip.IssueSelection(
            scope.repository, scope.numbers[0], scope.expected_repository_id))
    except ip.IssueError:
        raise SyncError('SCOPE_INVALID', 'invalid_input') from None


def _grant(grant: IssueSyncGrant | None, context: ip.ProviderContext,
           scope: IssueSyncScope, now: datetime) -> None:
    _need(type(grant) is IssueSyncGrant and grant.authorized is True and
          grant.allow_write is False and grant.method == METHOD, 'GRANT_REQUIRED')
    _need(grant.provider == context.provider and grant.api_host == context.api_host and
          grant.account_ref == context.account_ref and
          grant.repository == scope.repository and
          type(grant.expected_repository_id) is int and
          grant.expected_repository_id == scope.expected_repository_id and
          type(grant.numbers) is tuple and grant.numbers == scope.numbers,
          'GRANT_SCOPE_MISMATCH')
    deadline = _parse_stamp(grant.expires_at_utc)
    _need(now < deadline <= now + timedelta(seconds=MAX_BATCH_GRANT_SECONDS),
          'GRANT_EXPIRED_OR_TOO_BROAD')


def _read_grants(grants: Mapping[int, ip.IssueReadGrant] | None,
                 context: ip.ProviderContext, scope: IssueSyncScope,
                 now: datetime) -> None:
    _need(type(grants) is dict and
          all(type(k) is int for k in grants) and
          set(grants.keys()) == set(scope.numbers), 'PER_ISSUE_GRANTS_REQUIRED')
    for number in scope.numbers:
        try:
            ip._validate_grant(grants[number], context,
                               ip.IssueSelection(scope.repository, number,
                                                 scope.expected_repository_id), now)
        except ip.IssueError:
            raise SyncError('PER_ISSUE_GRANT_INVALID') from None


def _baseline(baseline: tuple[BaselineFingerprint, ...],
              scope: IssueSyncScope) -> dict[int, BaselineFingerprint]:
    _need(type(baseline) is tuple and len(baseline) <= MAX_ISSUES,
          'BASELINE_INVALID', 'invalid_input')
    hints: dict[int, BaselineFingerprint] = {}
    for entry in baseline:
        _need(type(entry) is BaselineFingerprint and type(entry.number) is int and
              entry.number in scope.numbers and entry.number not in hints and
              type(entry.provider_issue_id) is str and
              DIGITS.fullmatch(entry.provider_issue_id) is not None and
              int(entry.provider_issue_id) <= 2**63 - 1 and
              type(entry.identity_sha256) is str and
              SHA256.fullmatch(entry.identity_sha256) is not None and
              type(entry.snapshot_sha256) is str and
              SHA256.fullmatch(entry.snapshot_sha256) is not None,
              'BASELINE_INVALID', 'invalid_input')
        hints[entry.number] = entry
    return hints


def _safe_refusal(status: str, reason: str, synthetic: bool) -> dict[str, Any]:
    return {
        'schema': SCHEMA,
        'status': status,
        'reason_code': reason,
        'exit_code': {'partial': 2, 'unavailable': 5, 'invalid_input': 4}[status],
        'read_state': 'UNKNOWN',
        'coverage': 'UNKNOWN',
        'synthetic': synthetic,
        'scope': None,
        'requested_count': 0,
        'observed_count': 0,
        'unknown_count': 0,
        'provider_read_invocations': 0,
        'maximum_possible_provider_gets': 0,
        'entries': [],
        'aggregate_snapshot_sha256': None,
        'observed_started_at_utc': None,
        'observed_finished_at_utc': None,
        **_invariants(False),
    }


def _invariants(performed: bool) -> dict[str, Any]:
    return {
        'snapshot_collection_performed': performed,
        'complete_selection': False,
        'snapshot_atomic': False,
        'full_repository_inventory': False,
        'selected_metadata_projection_only': True,
        'baseline_authenticated': False,
        'organizational_grant_authenticated': False,
        'persisted': False,
        'external_cache_mutated': False,
        'native_issue_action_registered': False,
        'issue_created': False,
        'issue_delivered_or_published': False,
        'issue_or_provider_written': False,
        'business_repository_written': False,
        'knowledge_source_written': False,
    }


def _unknown(number: int, reason: str) -> dict[str, Any]:
    return {'number': number, 'state': 'UNKNOWN', 'reason_code': reason,
            'comparison': 'UNKNOWN', 'snapshot': None}


def _projection(source: Any, context: ip.ProviderContext,
                scope: IssueSyncScope, number: int, synthetic: bool) -> dict[str, Any]:
    """Whitelist-only re-projection; never relay arbitrary provider output."""
    _need(type(source) is dict, 'PROVIDER_RESULT_INVALID')
    identity = source.get('identity')
    _need(type(identity) is dict and
          identity.get('provider') == context.provider and
          identity.get('api_host') == context.api_host and
          type(identity.get('repository_path')) is str and
          identity['repository_path'].casefold() == scope.repository.casefold() and
          identity.get('provider_repository_id') == str(scope.expected_repository_id) and
          type(identity.get('issue_number')) is int and
          identity['issue_number'] == number and
          type(identity.get('provider_issue_id')) is str and
          DIGITS.fullmatch(identity['provider_issue_id']) is not None and
          int(identity['provider_issue_id']) <= 2**63 - 1,
          'PROVIDER_IDENTITY_DRIFT')
    _need(all(type(source.get(field)) is str and
              SHA256.fullmatch(source[field]) is not None
              for field in ('identity_sha256', 'snapshot_sha256')),
          'PROVIDER_RESULT_INVALID')
    _need(source.get('snapshot_semantics') ==
          'SELECTED_PROVIDER_METADATA_AND_UNEXPOSED_TITLE_DESCRIPTION_LABELS_V1' and
          source.get('origin') ==
          ('synthetic_fixture' if synthetic else 'provider_https_response') and
          source.get('snapshot_atomic') is False and
          source.get('all_issue_fields_collected') is False and
          source.get('title_body_labels_disclosed') is False and
          source.get('remote_creation_or_delivery_verified') is False and
          source.get('provider_state') in ('OPEN', 'CLOSED') and
          source.get('provider_confidentiality') in
          ('NOT_REPORTED', 'STANDARD', 'CONFIDENTIAL'),
          'PROVIDER_RESULT_INVALID')
    created = _parse_stamp(source.get('provider_created_at_utc'))
    updated = _parse_stamp(source.get('provider_updated_at_utc'))
    _need(updated >= created, 'PROVIDER_RESULT_INVALID')
    closed_raw = source.get('provider_closed_at_utc')
    closed = _parse_stamp(closed_raw) if closed_raw is not None else None
    _need(closed is None or closed >= created, 'PROVIDER_RESULT_INVALID')
    observed = _parse_stamp(source.get('observed_at_utc'))
    return {
        'identity': {
            'provider': context.provider,
            'api_host': context.api_host,
            'repository_path': identity['repository_path'],
            'provider_repository_id': str(scope.expected_repository_id),
            'issue_number': number,
            'provider_issue_id': identity['provider_issue_id'],
        },
        'identity_sha256': source['identity_sha256'],
        'snapshot_sha256': source['snapshot_sha256'],
        'provider_state': source['provider_state'],
        'provider_created_at_utc': _stamp(created),
        'provider_updated_at_utc': _stamp(updated),
        'provider_closed_at_utc': _stamp(closed) if closed is not None else None,
        'provider_confidentiality': source['provider_confidentiality'],
        'observed_at_utc': _stamp(observed),
        'observation_origin': source['origin'],
        'snapshot_semantics': source['snapshot_semantics'],
        'source_limited_to_selected_metadata': True,
    }


def _compare(value: dict[str, Any], hint: BaselineFingerprint | None) -> str:
    if hint is None:
        return 'NO_CALLER_BASELINE'
    if (value['identity']['provider_issue_id'] != hint.provider_issue_id or
            value['identity_sha256'] != hint.identity_sha256):
        return 'IDENTITY_CONFLICT_UNTRUSTED_BASELINE'
    return ('SAME_SELECTED_PROJECTION_AS_CALLER_HINT'
            if value['snapshot_sha256'] == hint.snapshot_sha256
            else 'DIFFERENT_SELECTED_PROJECTION_FROM_CALLER_HINT')


def sync_issues(context: ip.ProviderContext, scope: IssueSyncScope, *,
                sync_grant: IssueSyncGrant | None = None,
                issue_read_grants: dict[int, ip.IssueReadGrant] | None = None,
                baseline: tuple[BaselineFingerprint, ...] = (),
                allow_network: bool = False,
                token_supplier: Callable[[], str | None] | None = None,
                transport: ip.ReadTransport | None = None,
                clock: Callable[[], datetime] | None = None,
                timeout: float = ip.MAX_TIMEOUT) -> dict[str, Any]:
    """IssueSync selected metadata snapshot; no enumeration/persistence/writes.

    Preflights both independent grants for ALL selected numbers before the
    credential supplier or any GET. Rechecks all grants at completion; if
    permission expires, discards the whole previously observed batch.
    """
    synthetic = transport is not None or clock is not None
    try:
        _scope(context, scope)
        hints = _baseline(baseline, scope)
        _need(type(timeout) in (int, float) and
              not isinstance(timeout, bool) and 0 < timeout <= ip.MAX_TIMEOUT,
              'TIMEOUT_INVALID', 'invalid_input')
        _need(type(allow_network) is bool and allow_network, 'NETWORK_NOT_AUTHORIZED')
        started = _now(clock)
        _grant(sync_grant, context, scope, started)
        _read_grants(issue_read_grants, context, scope, started)
        # Explicit supplier: no implicit secrets, environment scan, or credential
        # fallback. Only one supplier invocation for the entire selected batch.
        _need(callable(token_supplier), 'CREDENTIALS_UNAVAILABLE')
        try:
            token = token_supplier()
        except Exception:
            raise SyncError('CREDENTIALS_UNAVAILABLE') from None
        _need(type(token) is str and ip.TOKEN.fullmatch(token) is not None,
              'CREDENTIALS_UNAVAILABLE')
        selected: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        canonical_path: str | None = None
        invocations = 0
        for number in scope.numbers:
            _grant(sync_grant, context, scope, _now(clock))
            _read_grants(issue_read_grants, context, scope, _now(clock))
            invocations += 1
            response = ip.read_issue(
                context,
                ip.IssueSelection(scope.repository, number, scope.expected_repository_id),
                grant=issue_read_grants[number],
                allow_network=True, token_supplier=lambda: token, transport=transport,
                clock=clock, timeout=float(timeout))
            if (type(response) is not dict or response.get('schema') != ip.SCHEMA or
                    response.get('synthetic') is not synthetic or
                    response.get('issue_or_provider_written') is not False or
                    response.get('business_repository_written') is not False or
                    response.get('issue_created') is not False or
                    response.get('native_issue_action_registered') is not False):
                raise SyncError('PROVIDER_RESULT_INVALID')
            if response.get('status') != 'partial' or response.get('source') is None:
                code = response.get('reason_code')
                if type(code) is not str or REASON.fullmatch(code) is None:
                    code = 'ISSUE_SYNC_PROVIDER_READ_UNKNOWN'
                selected.append(_unknown(number, code))
                continue
            # Guard against future provider-result schema expansion leaking
            # sensitive title/description/labels or trusting a changed response.
            value = _projection(response['source'], context, scope, number, synthetic)
            path = value['identity']['repository_path']
            if canonical_path is None:
                canonical_path = path
            if canonical_path != path:
                raise SyncError('REPOSITORY_LOCATOR_CHANGED_ACROSS_BATCH')
            stable_issue_id = value['identity']['provider_issue_id']
            if stable_issue_id in seen_ids:
                raise SyncError('ISSUE_ID_COLLISION_ACROSS_BATCH')
            seen_ids.add(stable_issue_id)
            comparison = _compare(value, hints.get(number))
            if comparison == 'IDENTITY_CONFLICT_UNTRUSTED_BASELINE':
                # Cannot settle whether old hint, current provider, or account
                # binding changed; no automatic reconciliation or overwrite.
                selected.append(_unknown(number, 'ISSUE_SYNC_IDENTITY_CONFLICT_UNKNOWN'))
                continue
            selected.append({'number': number, 'state': 'OBSERVED_SELECTED_METADATA',
                             'reason_code': 'ISSUE_SYNC_METADATA_OBSERVED',
                             'comparison': comparison, 'snapshot': value})
        finished = _now(clock)
        _grant(sync_grant, context, scope, finished)
        _read_grants(issue_read_grants, context, scope, finished)
        _need(finished >= started, 'CLOCK_ROLLBACK')
        # Old readings (even successfully fetched) become unknown, not current.
        for entry in selected:
            value = entry['snapshot']
            if value is None:
                continue
            observed = _parse_stamp(value['observed_at_utc'])
            if (observed < started or observed > finished or
                    (finished - observed).total_seconds() > MAX_OBSERVATION_AGE_SECONDS):
                entry.update(_unknown(entry['number'], 'ISSUE_SYNC_OBSERVATION_STALE'))
        observed_count = sum(entry['snapshot'] is not None for entry in selected)
        complete = observed_count == len(scope.numbers)
        status = 'partial' if observed_count else 'unavailable'
        if complete:
            reason = 'ISSUE_SYNC_SELECTED_SNAPSHOT_OBSERVED'
            coverage = 'COMPLETE_EXPLICIT_SELECTION_NONATOMIC'
        elif observed_count:
            reason = 'ISSUE_SYNC_PARTIAL_SELECTION_UNKNOWN'
            coverage = 'PARTIAL_SELECTION_UNKNOWN'
        else:
            reason = 'ISSUE_SYNC_ALL_SELECTED_UNKNOWN'
            coverage = 'UNKNOWN'
        aggregate = None
        if complete:
            normalized = {
                'provider': context.provider,
                'api_host': context.api_host,
                'repository_path': canonical_path,
                'provider_repository_id': str(scope.expected_repository_id),
                'selected': [{
                    'number': entry['number'],
                    'provider_issue_id': entry['snapshot']['identity']['provider_issue_id'],
                    'identity_sha256': entry['snapshot']['identity_sha256'],
                    'snapshot_sha256': entry['snapshot']['snapshot_sha256'],
                } for entry in selected],
            }
            aggregate = hashlib.sha256(
                HASH_DOMAIN + ip._canonical(normalized)).hexdigest()
        result = _safe_refusal(status, reason, synthetic)
        result.update({
            'read_state': 'SYNTHETIC_OBSERVED' if observed_count and synthetic
                          else 'PROVIDER_OBSERVED' if observed_count else 'UNKNOWN',
            'coverage': coverage,
            'scope': {
                'provider': context.provider,
                'api_host': context.api_host,
                'repository': scope.repository,
                'expected_repository_id': str(scope.expected_repository_id),
                'numbers': list(scope.numbers),
            },
            'requested_count': len(scope.numbers),
            'observed_count': observed_count,
            'unknown_count': len(scope.numbers) - observed_count,
            'provider_read_invocations': invocations,
            'maximum_possible_provider_gets': 3 * invocations,
            'entries': selected,
            'aggregate_snapshot_sha256': aggregate,
            'observed_started_at_utc': _stamp(started),
            'observed_finished_at_utc': _stamp(finished),
            **_invariants(observed_count > 0),
            'complete_selection': complete,
        })
        return result
    except SyncError as e:
        return _safe_refusal(e.status, e.reason, synthetic)
    except Exception:
        # Never forward provider text, tokens, tracebacks, or partial content.
        return _safe_refusal('unavailable', 'ISSUE_SYNC_UNEXPECTED_FAILURE', synthetic)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC212 no-write in-memory explicit-Issue whitelist snapshot; default offline')
    parser.add_argument('--provider', choices=['github', 'gitlab'], required=True)
    parser.add_argument('--host', help='exact public provider API host')
    parser.add_argument('--account-ref', help='opaque caller-provided account slot')
    parser.add_argument('--repository', required=True)
    parser.add_argument('--expected-repository-id', required=True, type=int)
    parser.add_argument('--numbers', required=True,
                        help='ascending unique comma-separated Issue numbers, max 8; no discovery')
    parser.add_argument('--authorize-sync', action='store_true',
                        help='declare independent short-lived EC212 host-level read approval')
    parser.add_argument('--authorize-issue-reads', action='store_true',
                        help='separately declare EC211 read approval for every exact Issue')
    parser.add_argument('--allow-network', action='store_true')
    parser.add_argument('--timeout', type=float, default=ip.MAX_TIMEOUT)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        numbers = tuple(int(s) for s in args.numbers.split(','))
    except ValueError:
        numbers = ()
    host = args.host or ip.API_HOST[args.provider]
    context = ip.ProviderContext(args.provider, host, args.account_ref or '')
    scope = IssueSyncScope(args.repository, args.expected_repository_id, numbers)
    expires = _stamp(datetime.now(timezone.utc) + timedelta(seconds=120))
    sync_grant = (IssueSyncGrant(METHOD, context.provider, context.api_host,
                  context.account_ref, scope.repository, scope.expected_repository_id,
                  scope.numbers, expires, True) if args.authorize_sync else None)
    read_grants = ({
        n: ip.IssueReadGrant(ip.METHOD, context.provider, context.api_host,
                             context.account_ref, scope.repository, n, expires, True)
        for n in scope.numbers
    } if args.authorize_issue_reads else None)
    # Explicit fixed provider token environment slot, only when network requested;
    # CLI grants are locally declared, never organizational authorization proof.
    token_supplier = (
        lambda: os.environ.get(ip.ENV_CREDENTIAL[context.provider])
        if args.allow_network else None)
    result = sync_issues(context, scope, sync_grant=sync_grant,
                         issue_read_grants=read_grants, allow_network=args.allow_network,
                         token_supplier=token_supplier, timeout=args.timeout)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
