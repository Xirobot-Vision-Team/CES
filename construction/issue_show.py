#!/usr/bin/env python3
"""EC-213: scoped, read-only IssueShow for ONE pinned Issue identity.

Uses the actual EC211 three-GET provider reader and EC212's whitelist projection
validator, not an unverified caller snapshot. Independent EC213 Show AND EC211
Issue read host declarations are needed. Neither dataclass authenticates a human,
organization, provider account, issuer or revocation. No implicit credentials,
listing, pagination, Issue mutation, cache, provider write or native CLI route.

A successful response is only a time-bounded, non-atomic selected-metadata
observation. 404, inaccessible, stale, identity drift and unavailable always
mean UNKNOWN, never definitive non-existence.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import math
import os
import sys
from typing import Any, Callable

try:
    from . import issue_provider as ip
    from . import issue_sync as es
except ImportError:
    import issue_provider as ip
    import issue_sync as es

SCHEMA = 'ces.issue_show.v1'
METHOD = 'READ_ISSUE_SHOW'
MAX_SHOW_GRANT_SECONDS = 300
MAX_OBSERVATION_AGE_SECONDS = 120
STATES = frozenset(('ANY', 'OPEN', 'CLOSED'))
PRIVACY = frozenset(('ANY', 'STANDARD', 'CONFIDENTIAL', 'NOT_REPORTED'))


@dataclass(frozen=True)
class ShowFilters:
    state: str = 'ANY'
    confidentiality: str = 'ANY'
    # Inclusive lower and exclusive upper bound on the provider update time.
    updated_not_before_utc: str | None = None
    updated_before_utc: str | None = None


@dataclass(frozen=True)
class IssueShowSelection:
    repository: str
    expected_repository_id: int
    number: int
    expected_provider_issue_id: int
    filters: ShowFilters = field(default_factory=ShowFilters)
    max_observation_age_seconds: int = MAX_OBSERVATION_AGE_SECONDS


@dataclass(frozen=True)
class IssueShowGrant:
    method: str
    provider: str
    api_host: str
    account_ref: str
    repository: str
    expected_repository_id: int
    number: int
    expected_provider_issue_id: int
    filters: ShowFilters
    max_observation_age_seconds: int
    expires_at_utc: str
    authorized: bool
    allow_write: bool = False


class ShowError(ValueError):
    def __init__(self, reason: str, status: str = 'unavailable') -> None:
        super().__init__(reason)
        self.reason = 'ISSUE_SHOW_' + reason
        self.status = status


def _need(predicate: bool, reason: str, status: str = 'unavailable') -> None:
    if not predicate:
        raise ShowError(reason, status)


def _now(clock: Callable[[], datetime] | None) -> datetime:
    try:
        return ip._now(clock)
    except ip.IssueError:
        raise ShowError('CLOCK_UNAVAILABLE') from None


def _timestamp(value: str) -> datetime:
    try:
        return ip._at_utc(value)
    except ip.IssueError:
        raise ShowError('TIMESTAMP_INVALID', 'invalid_input') from None


def _stamp(value: datetime) -> str:
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _filter_check(filters: ShowFilters) -> None:
    _need(type(filters) is ShowFilters, 'FILTER_INVALID', 'invalid_input')
    _need(type(filters.state) is str and filters.state in STATES and
          type(filters.confidentiality) is str and
          filters.confidentiality in PRIVACY, 'FILTER_INVALID', 'invalid_input')
    lower = (_timestamp(filters.updated_not_before_utc)
             if filters.updated_not_before_utc is not None else None)
    upper = (_timestamp(filters.updated_before_utc)
             if filters.updated_before_utc is not None else None)
    _need(lower is None or upper is None or lower < upper,
          'FILTER_INTERVAL_INVALID', 'invalid_input')


def _selection(context: ip.ProviderContext, selection: IssueShowSelection) -> None:
    try:
        ip._validate_context(context)
    except ip.IssueError as exc:
        raise ShowError('CONTEXT_INVALID', exc.status) from None
    _need(type(selection) is IssueShowSelection, 'SELECTION_INVALID', 'invalid_input')
    _need(ip._positive_id(selection.expected_repository_id) and
          ip._positive_id(selection.expected_provider_issue_id),
          'STABLE_ID_REQUIRED', 'invalid_input')
    _need(type(selection.max_observation_age_seconds) is int and
          1 <= selection.max_observation_age_seconds <= MAX_OBSERVATION_AGE_SECONDS,
          'FRESHNESS_INVALID', 'invalid_input')
    _filter_check(selection.filters)
    try:
        ip._validate_scope(context, ip.IssueSelection(
            selection.repository, selection.number, selection.expected_repository_id))
    except ip.IssueError:
        raise ShowError('SELECTION_INVALID', 'invalid_input') from None


def _show_grant(grant: IssueShowGrant | None, context: ip.ProviderContext,
                selection: IssueShowSelection, now: datetime) -> None:
    _need(type(grant) is IssueShowGrant and grant.authorized is True and
          grant.allow_write is False and grant.method == METHOD,
          'SHOW_GRANT_REQUIRED')
    _need(grant.provider == context.provider and
          grant.api_host == context.api_host and
          grant.account_ref == context.account_ref and
          grant.repository == selection.repository and
          type(grant.expected_repository_id) is int and
          grant.expected_repository_id == selection.expected_repository_id and
          type(grant.number) is int and grant.number == selection.number and
          type(grant.expected_provider_issue_id) is int and
          grant.expected_provider_issue_id == selection.expected_provider_issue_id and
          type(grant.filters) is ShowFilters and grant.filters == selection.filters and
          type(grant.max_observation_age_seconds) is int and
          grant.max_observation_age_seconds == selection.max_observation_age_seconds,
          'SHOW_GRANT_SCOPE_MISMATCH')
    deadline = _timestamp(grant.expires_at_utc)
    _need(now < deadline <= now + timedelta(seconds=MAX_SHOW_GRANT_SECONDS),
          'SHOW_GRANT_EXPIRED_OR_TOO_BROAD')


def _read_grant(grant: ip.IssueReadGrant | None, context: ip.ProviderContext,
                selection: IssueShowSelection, now: datetime) -> None:
    try:
        ip._validate_grant(
            grant, context,
            ip.IssueSelection(selection.repository, selection.number,
                              selection.expected_repository_id), now)
    except ip.IssueError:
        raise ShowError('PROVIDER_READ_GRANT_REQUIRED') from None


def _flags() -> dict[str, bool]:
    return {
        'metadata_projection_only': True,
        'full_issue_contents': False,
        'snapshot_atomic': False,
        'full_repository_inventory': False,
        'caller_snapshot_trusted': False,
        'organizational_grant_authenticated': False,
        'provider_account_ownership_authenticated': False,
        'native_issue_action_registered': False,
        'issue_sync_performed': False,
        'issue_created': False,
        'issue_delivered_or_published': False,
        'issue_or_provider_written': False,
        'business_repository_written': False,
        'knowledge_source_written': False,
        'persisted': False,
        'external_cache_mutated': False,
    }


def _unknown(status: str, reason: str, *, synthetic: bool,
             invoked: bool = False) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status, 'reason_code': reason,
        'exit_code': {'unavailable': 5, 'invalid_input': 4}[status],
        'read_state': 'UNKNOWN', 'issue_existence': 'UNKNOWN',
        'filter_outcome': 'UNKNOWN', 'coverage': 'UNKNOWN',
        'synthetic': synthetic, 'scope': None, 'issue': None,
        'source_origin': None, 'observed_at_utc': None,
        'freshness_seconds': None,
        'provider_read_invocations': 1 if invoked else 0,
        'maximum_possible_provider_gets': 3 if invoked else 0,
        **_flags(),
    }


def _allowed(source: dict[str, Any], filters: ShowFilters) -> bool:
    if filters.state != 'ANY' and source['provider_state'] != filters.state:
        return False
    if (filters.confidentiality != 'ANY' and
            source['provider_confidentiality'] != filters.confidentiality):
        return False
    updated = _timestamp(source['provider_updated_at_utc'])
    if (filters.updated_not_before_utc is not None and
            updated < _timestamp(filters.updated_not_before_utc)):
        return False
    if (filters.updated_before_utc is not None and
            updated >= _timestamp(filters.updated_before_utc)):
        return False
    return True


def show_issue(context: ip.ProviderContext, selection: IssueShowSelection, *,
               show_grant: IssueShowGrant | None = None,
               issue_read_grant: ip.IssueReadGrant | None = None,
               allow_network: bool = False,
               token_supplier: Callable[[], str | None] | None = None,
               transport: ip.ReadTransport | None = None,
               clock: Callable[[], datetime] | None = None,
               timeout: float = ip.MAX_TIMEOUT) -> dict[str, Any]:
    """Show only whitelisted metadata from one *live EC211* bounded GET read.

    `show_grant` and `issue_read_grant` are independent caller-host
    declarations; no credentials are read unless both were preflighted and
    explicit network opt-in is present. Returns only JSON-compatible values.
    """
    synthetic = transport is not None or clock is not None
    invoked = False
    try:
        _selection(context, selection)
        _need(type(timeout) in (int, float) and not isinstance(timeout, bool) and
              math.isfinite(timeout) and 0 < timeout <= ip.MAX_TIMEOUT,
              'TIMEOUT_INVALID', 'invalid_input')
        _need(type(allow_network) is bool and allow_network,
              'NETWORK_NOT_AUTHORIZED')
        started = _now(clock)
        _show_grant(show_grant, context, selection, started)
        _read_grant(issue_read_grant, context, selection, started)
        # Never inherit EC211's environment fallback; caller must explicitly
        # provide a supplier (CLI opts into one specific provider token slot).
        _need(callable(token_supplier), 'CREDENTIALS_UNAVAILABLE')
        try:
            token = token_supplier()
        except Exception:
            raise ShowError('CREDENTIALS_UNAVAILABLE') from None
        _need(type(token) is str and ip.TOKEN.fullmatch(token) is not None,
              'CREDENTIALS_UNAVAILABLE')
        _show_grant(show_grant, context, selection, _now(clock))
        _read_grant(issue_read_grant, context, selection, _now(clock))
        invoked = True
        response = ip.read_issue(
            context,
            ip.IssueSelection(selection.repository, selection.number,
                              selection.expected_repository_id),
            grant=issue_read_grant, allow_network=True,
            token_supplier=lambda: token, transport=transport, clock=clock,
            timeout=float(timeout))
        # Expired or revoked host declaration discards *all* observed content.
        finished = _now(clock)
        _show_grant(show_grant, context, selection, finished)
        _read_grant(issue_read_grant, context, selection, finished)
        _need(finished >= started, 'CLOCK_ROLLBACK')
        _need(type(response) is dict and response.get('schema') == ip.SCHEMA and
              type(response.get('synthetic')) is bool and
              response['synthetic'] is synthetic and
              response.get('issue_or_provider_written') is False and
              response.get('business_repository_written') is False and
              response.get('issue_created') is False and
              response.get('native_issue_action_registered') is False and
              response.get('issue_sync_performed') is False and
              response.get('metadata_projection_only') is True,
              'PROVIDER_RESULT_INVALID')
        if response.get('status') != 'partial' or response.get('source') is None:
            return _unknown('unavailable', 'ISSUE_SHOW_PROVIDER_UNKNOWN_OR_UNAVAILABLE',
                            synthetic=synthetic, invoked=invoked)
        _need(response.get('read_state') ==
              ('SYNTHETIC_OBSERVED' if synthetic else 'PROVIDER_OBSERVED') and
              response.get('issue_existence') ==
              ('SYNTHETIC_FIXTURE_PRESENT' if synthetic else 'PROVIDER_REPORTED_PRESENT'),
              'PROVIDER_RESULT_INVALID')
        # EC212 projection is deliberately strict and whitelist-only, never
        # relays a raw title/description/labels/actor or a provider error body.
        try:
            projection = es._projection(
                response['source'], context,
                es.IssueSyncScope(selection.repository,
                                  selection.expected_repository_id,
                                  (selection.number,)), selection.number, synthetic)
        except (es.SyncError, TypeError, ValueError):
            raise ShowError('PROVIDER_PROJECTION_REJECTED') from None
        ident = projection['identity']
        # EC211 already checks repository identity twice; IssueShow additionally
        # refuses even case-only locator changes and expected stable ID drift.
        _need(ident['repository_path'] == selection.repository,
              'REPOSITORY_LOCATOR_CHANGED')
        _need(ident['provider_issue_id'] == str(selection.expected_provider_issue_id),
              'STABLE_ISSUE_ID_MISMATCH')
        observed = _timestamp(projection['observed_at_utc'])
        _need(started <= observed <= finished, 'OBSERVATION_CLOCK_DRIFT')
        matched = _allowed(projection, selection.filters)
        # Check with a *fresh* completion time after projection/filtering:
        # even CPU-side work must not silently turn an old read into a fresh
        # display. Recheck both authorities as close as possible to return.
        completed = _now(clock)
        _need(completed >= finished, 'CLOCK_ROLLBACK')
        age = (completed - observed).total_seconds()
        _need(0 <= age <= selection.max_observation_age_seconds,
              'OBSERVATION_STALE')
        _show_grant(show_grant, context, selection, completed)
        _read_grant(issue_read_grant, context, selection, completed)
        return {
            'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
            'reason_code': ('ISSUE_SHOW_SELECTED_METADATA_OBSERVED' if matched
                            else 'ISSUE_SHOW_FILTER_EXCLUDED'),
            'read_state': 'SYNTHETIC_OBSERVED' if synthetic else 'PROVIDER_OBSERVED',
            'issue_existence': ('SYNTHETIC_FIXTURE_PRESENT' if synthetic
                                else 'PROVIDER_REPORTED_PRESENT'),
            'filter_outcome': 'MATCHED' if matched else 'EXCLUDED_BY_FILTER',
            'coverage': 'EXACT_ISSUE_SELECTED_METADATA_NONATOMIC',
            'synthetic': synthetic,
            'scope': {
                'provider': context.provider, 'api_host': context.api_host,
                'repository': selection.repository,
                'expected_repository_id': str(selection.expected_repository_id),
                'number': selection.number,
                'expected_provider_issue_id': str(selection.expected_provider_issue_id),
                'filters': {
                    'state': selection.filters.state,
                    'confidentiality': selection.filters.confidentiality,
                    'updated_not_before_utc': selection.filters.updated_not_before_utc,
                    'updated_before_utc': selection.filters.updated_before_utc,
                },
                'max_observation_age_seconds': selection.max_observation_age_seconds,
            },
            'issue': projection if matched else None,
            'source_origin': projection['observation_origin'],
            'observed_at_utc': _stamp(observed),
            'freshness_seconds': age,
            'provider_read_invocations': 1,
            'maximum_possible_provider_gets': 3,
            **_flags(),
        }
    except ShowError as exc:
        return _unknown(exc.status, exc.reason, synthetic=synthetic, invoked=invoked)
    except Exception:
        # Custom transports and suppliers may throw errors with secret-bearing
        # text. No traceback, original exception, token, raw payload or URL.
        return _unknown('unavailable', 'ISSUE_SHOW_UNEXPECTED_FAILURE',
                        synthetic=synthetic, invoked=invoked)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC213 standalone exact-Issue read-only Show; default offline')
    parser.add_argument('--provider', choices=('github', 'gitlab'), required=True)
    parser.add_argument('--host', help='fixed public provider host, no alternate domains')
    parser.add_argument('--account-ref', help='opaque explicit account context')
    parser.add_argument('--repository', required=True)
    parser.add_argument('--expected-repository-id', required=True, type=int)
    parser.add_argument('--number', required=True, type=int)
    parser.add_argument('--expected-issue-id', required=True, type=int)
    parser.add_argument('--state', default='ANY', choices=sorted(STATES))
    parser.add_argument('--confidentiality', default='ANY', choices=sorted(PRIVACY))
    parser.add_argument('--updated-not-before')
    parser.add_argument('--updated-before')
    parser.add_argument('--max-age', type=int, default=MAX_OBSERVATION_AGE_SECONDS)
    parser.add_argument('--authorize-show', action='store_true',
                        help='declare separate host EC213 IssueShow authorization')
    parser.add_argument('--authorize-provider-read', action='store_true',
                        help='declare separate EC211 exact Issue read authorization')
    parser.add_argument('--allow-network', action='store_true',
                        help='explicit opt-in: read only three public-provider HTTPS GETs')
    parser.add_argument('--timeout', type=float, default=ip.MAX_TIMEOUT)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    context = ip.ProviderContext(args.provider, args.host or ip.API_HOST[args.provider],
                                 args.account_ref or '')
    filters = ShowFilters(args.state, args.confidentiality,
                          args.updated_not_before, args.updated_before)
    selection = IssueShowSelection(args.repository, args.expected_repository_id,
                                   args.number, args.expected_issue_id, filters,
                                   args.max_age)
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=120)).isoformat(
        timespec='seconds').replace('+00:00', 'Z')
    show_grant = (IssueShowGrant(
        METHOD, context.provider, context.api_host, context.account_ref,
        selection.repository, selection.expected_repository_id, selection.number,
        selection.expected_provider_issue_id, filters,
        selection.max_observation_age_seconds, expiry, True)
        if args.authorize_show else None)
    read_grant = (ip.IssueReadGrant(
        ip.METHOD, context.provider, context.api_host, context.account_ref,
        selection.repository, selection.number, expiry, True)
        if args.authorize_provider_read else None)
    # Explicit CLI allow-network is still not an organizational approval.
    supplier = (lambda: os.environ.get(ip.ENV_CREDENTIAL[context.provider])
                if args.allow_network else None)
    outcome = show_issue(context, selection, show_grant=show_grant,
                         issue_read_grant=read_grant,
                         allow_network=args.allow_network,
                         token_supplier=supplier, timeout=args.timeout)
    print(json.dumps(outcome, ensure_ascii=False, sort_keys=True))
    return outcome['exit_code']


if __name__ == '__main__':
    sys.exit(main())
