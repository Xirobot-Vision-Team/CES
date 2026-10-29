#!/usr/bin/env python3
"""EC-211: opt-in, bounded, read-only GitHub/GitLab Issue provider adapter.

This is a standalone Python boundary, NOT native CES IssueSync/IssueShow.
No request is made without explicit host context, short-lived exact-scoped read grant,
network opt-in, and separately supplied provider credentials. The only remote
operation is a maximum of three HTTPS GETs on pinned public API hostnames.

A valid response is an observed *provider claim* about one Issue and is never
proof of successful issue creation, source delivery, a trusted actor, or Issue
synchronization. Raw titles, descriptions, comments and people are not output.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import socket
import ssl
import sys
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

try:
    from . import issue_existing_readonly as er
except ImportError:
    import issue_existing_readonly as er

SCHEMA = 'ces.issue_provider.v1'
DOMAIN = b'CES-EC211-ISSUE-METADATA-SNAPSHOT-v1\x00'
IDENTITY_DOMAIN = b'CES-EC211-ISSUE-IDENTITY-v1\x00'
ENV_CREDENTIAL = {'github': 'CES_ISSUE_GITHUB_TOKEN', 'gitlab': 'CES_ISSUE_GITLAB_TOKEN'}
API_HOST = {'github': 'api.github.com', 'gitlab': 'gitlab.com'}
METHOD = 'READ_ISSUE_METADATA'
MAX_BODY = 1024 * 1024
MAX_TIMEOUT = 8.0
MAX_GRANT_LIFETIME_SECONDS = 600
MAX_LABELS = 100
SEGMENT = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\Z', re.ASCII)
TOKEN = re.compile(r'[!-~]{1,4096}\Z', re.ASCII)
ACCOUNT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z', re.ASCII)
UTC_STAMP = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z\Z', re.ASCII)


class IssueError(ValueError):
    """Stable, non-sensitive error code; never contain tokens or payloads."""

    def __init__(self, reason: str, status: str = 'unavailable') -> None:
        super().__init__(reason)
        self.reason = 'ISSUE_' + reason
        self.status = status


def require(predicate: bool, reason: str, status: str = 'unavailable') -> None:
    if not predicate:
        raise IssueError(reason, status)


@dataclass(frozen=True)
class ProviderContext:
    provider: str
    api_host: str
    account_ref: str  # Opaque host-issued account slot, not a real authentication assertion.


@dataclass(frozen=True)
class IssueSelection:
    repository: str  # GH owner/repo, GL group/subgroup/project; NOT a URL.
    number: int  # repository-local Issue number (GH number, GL iid).
    expected_repository_id: int | None = None  # Optional stable provider ID pin.


@dataclass(frozen=True)
class IssueReadGrant:
    method: str
    provider: str
    api_host: str
    account_ref: str
    repository: str
    number: int
    expires_at_utc: str
    authorized: bool
    allow_write: bool = False


class ReadTransport(Protocol):
    def get_object(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int,
                         msg: str, headers: Any, newurl: str) -> None:
        return None


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError('duplicate JSON object member')
        obj[k] = v
    return obj


def _json_object(raw: bytes) -> dict[str, Any]:
    def bad_constant(_: str) -> None:
        raise ValueError('non-finite JSON number')
    try:
        obj = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_unique,
                         parse_constant=bad_constant)
        require(type(obj) is dict, 'PROVIDER_PAYLOAD_INVALID')
        return obj
    except (UnicodeError, ValueError, RecursionError, MemoryError):
        raise IssueError('PROVIDER_PAYLOAD_INVALID') from None


def _valid_endpoint(url: str) -> bool:
    if type(url) is not str or len(url) > 550:
        return False
    try:
        u = urlsplit(url)
        if (u.scheme != 'https' or u.port is not None or u.username is not None or
                u.password is not None or u.query or u.fragment):
            return False
        if u.netloc == 'api.github.com':
            match = re.fullmatch(
                r'/repos/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:/issues/([1-9][0-9]*))?',
                u.path, re.ASCII)
            return bool(match and all(SEGMENT.fullmatch(p) and p not in ('.', '..')
                                      for p in match.group(1, 2)))
        if u.netloc == 'gitlab.com':
            if re.fullmatch(r'/api/v4/projects/[1-9][0-9]*/issues/[1-9][0-9]*',
                            u.path, re.ASCII):
                return True
            match = re.fullmatch(r'/api/v4/projects/([A-Za-z0-9_.-]+(?:%2F[A-Za-z0-9_.-]+){1,11})',
                                 u.path, re.ASCII)
            if match:
                return all(SEGMENT.fullmatch(p) and p not in ('.', '..')
                           for p in match.group(1).split('%2F'))
    except ValueError:
        return False
    return False


class StrictHTTPSIssueTransport:
    """Only fixed public GH/GL API GET, with TLS, no redirects/proxies/retries."""

    def get_object(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        require(_valid_endpoint(url) and
                er.allow_issue_http('GET', url, profile='EC211_SELECTED', headers=headers),
                'ENDPOINT_REJECTED')
        require(type(timeout) in (int, float) and 0 < timeout <= MAX_TIMEOUT,
                'TIMEOUT_INVALID', 'invalid_input')
        request = Request(url, method='GET', headers=headers)
        opener = build_opener(ProxyHandler({}), _NoRedirect(),
                              HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(request, timeout=timeout) as response:
                require(response.status == 200 and response.geturl() == url,
                        'ENDPOINT_REJECTED')
                content_type = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                require(content_type == 'application/json' or
                        (content_type.startswith('application/') and content_type.endswith('+json')),
                        'PROVIDER_PAYLOAD_INVALID')
                claimed = response.headers.get('Content-Length')
                require(not (claimed and claimed.isdecimal() and int(claimed) > MAX_BODY),
                        'PROVIDER_PAYLOAD_TOO_LARGE')
                raw = response.read(MAX_BODY + 1)
                require(len(raw) <= MAX_BODY, 'PROVIDER_PAYLOAD_TOO_LARGE')
                return _json_object(raw)
        except HTTPError as e:
            if 300 <= e.code < 400:
                raise IssueError('REDIRECT_REFUSED') from None
            if e.code in (401, 403):
                raise IssueError('PROVIDER_ACCESS_UNAVAILABLE') from None
            if e.code == 404:
                # 404 also means hidden/private, moved or unauthorized: NEVER absent.
                raise IssueError('ISSUE_UNKNOWN_OR_INACCESSIBLE') from None
            if e.code == 429:
                raise IssueError('PROVIDER_RATE_LIMITED') from None
            raise IssueError('PROVIDER_HTTP_UNAVAILABLE') from None
        except (URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError):
            raise IssueError('PROVIDER_NETWORK_UNAVAILABLE') from None


def _positive_id(value: Any) -> bool:
    return type(value) is int and 0 < value <= 2**63 - 1


def _validate_scope(context: ProviderContext, issue: IssueSelection) -> None:
    require(type(issue) is IssueSelection, 'SELECTION_INVALID', 'invalid_input')
    require(type(issue.repository) is str and 3 <= len(issue.repository) <= 240,
            'REPOSITORY_INVALID', 'invalid_input')
    require(type(issue.number) is int and 1 <= issue.number <= 2147483647,
            'ISSUE_NUMBER_INVALID', 'invalid_input')
    require(issue.expected_repository_id is None or _positive_id(issue.expected_repository_id),
            'REPOSITORY_ID_INVALID', 'invalid_input')
    parts = issue.repository.split('/')
    require((len(parts) == 2 if context.provider == 'github' else 2 <= len(parts) <= 12) and
            all(part not in ('.', '..') and SEGMENT.fullmatch(part) for part in parts),
            'REPOSITORY_INVALID', 'invalid_input')


def _validate_context(context: ProviderContext) -> None:
    require(type(context) is ProviderContext, 'CONTEXT_INVALID', 'invalid_input')
    require(type(context.provider) is str and context.provider in API_HOST,
            'PROVIDER_UNSUPPORTED', 'invalid_input')
    require(type(context.api_host) is str and context.api_host == API_HOST[context.provider],
            'HOST_NOT_ALLOWED', 'invalid_input')
    require(type(context.account_ref) is str and ACCOUNT.fullmatch(context.account_ref),
            'ACCOUNT_CONTEXT_UNAVAILABLE')


def _at_utc(value: str) -> datetime:
    require(type(value) is str and UTC_STAMP.fullmatch(value), 'GRANT_EXPIRY_INVALID', 'invalid_input')
    try:
        return datetime.fromisoformat(value[:-1] + '+00:00')
    except (OverflowError, ValueError):
        raise IssueError('GRANT_EXPIRY_INVALID', 'invalid_input') from None


def _now(clock: Callable[[], datetime] | None) -> datetime:
    try:
        value = clock() if clock else datetime.now(timezone.utc)
        require(type(value) is datetime and value.tzinfo is not None and
                value.utcoffset() is not None, 'CLOCK_UNAVAILABLE')
        value = value.astimezone(timezone.utc)
        require(2000 <= value.year <= 9998, 'CLOCK_UNAVAILABLE')
        return value
    except (ValueError, OverflowError, TypeError):
        raise IssueError('CLOCK_UNAVAILABLE') from None


def _validate_grant(grant: IssueReadGrant | None, context: ProviderContext,
                    issue: IssueSelection, now: datetime) -> None:
    require(type(grant) is IssueReadGrant and grant.authorized is True and
            grant.allow_write is False and grant.method == METHOD,
            'READ_GRANT_REQUIRED')
    require(grant.provider == context.provider and grant.api_host == context.api_host and
            grant.account_ref == context.account_ref and grant.repository == issue.repository and
            type(grant.number) is int and grant.number == issue.number,
            'READ_GRANT_SCOPE_MISMATCH')
    deadline = _at_utc(grant.expires_at_utc)
    require(now < deadline <= now + timedelta(seconds=MAX_GRANT_LIFETIME_SECONDS),
            'READ_GRANT_EXPIRED_OR_TOO_BROAD')


def _canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _hash(domain: bytes, data: Any) -> str:
    return hashlib.sha256(domain + _canonical(data)).hexdigest()


def _utc_provider_timestamp(value: Any) -> str:
    require(type(value) is str and 20 <= len(value) <= 40 and
            re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)',
                         value, re.ASCII) is not None,
            'PROVIDER_METADATA_INCOMPLETE')
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(stamp.utcoffset() is not None, 'PROVIDER_METADATA_INCOMPLETE')
        return stamp.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
    except (ValueError, OverflowError):
        raise IssueError('PROVIDER_METADATA_INCOMPLETE') from None


def _provider_text(value: Any, max_chars: int, *, nullable: bool = False) -> str | None:
    require((value is None and nullable) or
            (type(value) is str and len(value) <= max_chars and
             not any(0xd800 <= ord(c) <= 0xdfff for c in value)),
            'PROVIDER_CONTENT_OUT_OF_BOUNDS')
    return value


def _parse_labels(labels: Any, provider: str) -> list[str]:
    require(type(labels) is list and len(labels) <= MAX_LABELS,
            'PROVIDER_CONTENT_OUT_OF_BOUNDS')
    result = []
    seen = set()
    for label in labels:
        name = label.get('name') if provider == 'github' and type(label) is dict else label
        name = _provider_text(name, 256)
        require(bool(name) and name.casefold() not in seen, 'PROVIDER_CONTENT_OUT_OF_BOUNDS')
        seen.add(name.casefold())
        result.append(name)
    return sorted(result, key=lambda t: (t.casefold(), t))


def _repository_metadata(raw: dict[str, Any], context: ProviderContext,
                         issue: IssueSelection) -> tuple[int, str]:
    require(type(raw) is dict and '_ces_fixture' not in raw, 'PROVIDER_PAYLOAD_INVALID')
    repo_id = raw.get('id')
    name = raw.get('full_name' if context.provider == 'github' else 'path_with_namespace')
    require(_positive_id(repo_id) and type(name) is str and 3 <= len(name) <= 240,
            'PROVIDER_METADATA_INCOMPLETE')
    require(name.casefold() == issue.repository.casefold(), 'REPOSITORY_LOCATOR_MISMATCH')
    require(issue.expected_repository_id is None or issue.expected_repository_id == repo_id,
            'REPOSITORY_ID_MISMATCH')
    return repo_id, name


def _issue_metadata(raw: dict[str, Any], context: ProviderContext, issue: IssueSelection,
                    repo_id: int, repo_name: str) -> tuple[int, dict[str, Any]]:
    require(type(raw) is dict and '_ces_fixture' not in raw, 'PROVIDER_PAYLOAD_INVALID')
    ident = raw.get('id')
    number = raw.get('number' if context.provider == 'github' else 'iid')
    require(_positive_id(ident), 'PROVIDER_METADATA_INCOMPLETE')
    require(type(number) is int and number == issue.number, 'ISSUE_IDENTITY_MISMATCH')
    if context.provider == 'github':
        # GH /issues/{number} also responds for PR objects; never relabel them.
        require('pull_request' not in raw, 'GITHUB_PULL_REQUEST_NOT_ISSUE')
        expected_api_url = 'https://api.github.com/repos/' + repo_name
        require(raw.get('repository_url') == expected_api_url,
                'ISSUE_REPOSITORY_MISMATCH')
        node_id = raw.get('node_id')
        require(type(node_id) is str and 1 <= len(node_id) <= 256 and
                all(33 <= ord(c) <= 126 for c in node_id), 'PROVIDER_METADATA_INCOMPLETE')
        state = raw.get('state')
        require(state in ('open', 'closed'), 'PROVIDER_METADATA_INCOMPLETE')
        require(type(raw.get('locked')) is bool, 'PROVIDER_METADATA_INCOMPLETE')
        reason = raw.get('state_reason')
        require(reason is None or (type(reason) is str and
                1 <= len(reason) <= 64 and re.fullmatch(r'[a-z_]+', reason, re.ASCII)),
                'PROVIDER_METADATA_INCOMPLETE')
        privacy = 'NOT_REPORTED'
        lock = raw['locked']
        description = raw.get('body')
        labels = _parse_labels(raw.get('labels'), 'github')
    else:
        require(raw.get('project_id') == repo_id and type(raw.get('project_id')) is int,
                'ISSUE_REPOSITORY_MISMATCH')
        reference = raw.get('references')
        if reference is not None:
            require(type(reference) is dict and
                    reference.get('full') == f'{repo_name}#{issue.number}',
                    'ISSUE_REPOSITORY_MISMATCH')
        state = raw.get('state')
        require(state in ('opened', 'closed'), 'PROVIDER_METADATA_INCOMPLETE')
        require(type(raw.get('confidential')) is bool,
                'PROVIDER_METADATA_INCOMPLETE')
        privacy = 'CONFIDENTIAL' if raw['confidential'] else 'STANDARD'
        lock_value = raw.get('discussion_locked')
        require(lock_value is None or type(lock_value) is bool,
                'PROVIDER_METADATA_INCOMPLETE')
        lock = lock_value
        reason = None
        description = raw.get('description')
        labels = _parse_labels(raw.get('labels'), 'gitlab')
    created = _utc_provider_timestamp(raw.get('created_at'))
    updated = _utc_provider_timestamp(raw.get('updated_at'))
    closed = (_utc_provider_timestamp(raw['closed_at'])
              if raw.get('closed_at') is not None else None)
    require(updated >= created and (closed is None or closed >= created),
            'PROVIDER_METADATA_INCONSISTENT')
    title = _provider_text(raw.get('title'), 512)
    require(bool(title), 'PROVIDER_METADATA_INCOMPLETE')
    description = _provider_text(description, 131072, nullable=True)
    metadata = {
        'state': 'OPEN' if state in ('open', 'opened') else 'CLOSED',
        'created_at_utc': created,
        'updated_at_utc': updated,
        'closed_at_utc': closed,
        'title': title,
        'description': description,
        'labels': labels,
        'locked': lock,
        'privacy': privacy,
        'provider_state_reason': reason,
    }
    return ident, metadata


def _endpoints(context: ProviderContext, issue: IssueSelection,
               repo_id: int | None = None) -> tuple[str, str | None]:
    if context.provider == 'github':
        prefix = f'https://api.github.com/repos/{quote(issue.repository.split("/")[0], safe="")}/{quote(issue.repository.split("/")[1], safe="")}'
        return prefix, prefix + f'/issues/{issue.number}'
    if repo_id is None:
        return f'https://gitlab.com/api/v4/projects/{quote(issue.repository, safe="")}', None
    return f'https://gitlab.com/api/v4/projects/{quote(issue.repository, safe="")}', f'https://gitlab.com/api/v4/projects/{repo_id}/issues/{issue.number}'


def _headers(provider: str, token: str) -> dict[str, str]:
    common = {'User-Agent': 'CES-EC211-issue-readonly/1', 'Accept-Encoding': 'identity'}
    if provider == 'github':
        return {**common, 'Accept': 'application/vnd.github+json',
                'Authorization': 'Bearer ' + token, 'X-GitHub-Api-Version': '2026-03-10'}
    return {**common, 'Accept': 'application/json', 'PRIVATE-TOKEN': token}


def _result(status: str, reason: str, *, source: dict[str, Any] | None = None,
            synthetic: bool = False) -> dict[str, Any]:
    return {
        'schema': SCHEMA,
        'status': status,
        'reason_code': 'ISSUE_' + reason if not reason.startswith('ISSUE_') else reason,
        'exit_code': {'partial': 2, 'unavailable': 5, 'invalid_input': 4}[status],
        'read_state': ('SYNTHETIC_OBSERVED' if synthetic else 'PROVIDER_OBSERVED') if source else 'UNKNOWN',
        'issue_existence': ('SYNTHETIC_FIXTURE_PRESENT' if synthetic else 'PROVIDER_REPORTED_PRESENT') if source else 'UNKNOWN',
        'source': source,
        'synthetic': synthetic,
        'metadata_projection_only': True,
        'organizational_grant_authenticated': False,
        'native_issue_action_registered': False,
        'issue_sync_performed': False,
        'issue_created': False,
        'issue_delivered_or_published': False,
        'issue_or_provider_written': False,
        'business_repository_written': False,
    }


def read_issue(context: ProviderContext, issue: IssueSelection, *,
               grant: IssueReadGrant | None = None, allow_network: bool = False,
               token_supplier: Callable[[], str | None] | None = None,
               transport: ReadTransport | None = None,
               clock: Callable[[], datetime] | None = None,
               timeout: float = MAX_TIMEOUT) -> dict[str, Any]:
    """Read three bounded GET observations, or return sanitized unknown/unavailable.

    Always rejects live fixture markers; injected transport or clock marks the
    result synthetic. The read grant is a host assertion, NOT a cryptographic
    provider, human, role, or organizational authorization verification.
    """
    synthetic = transport is not None or clock is not None
    try:
        _validate_context(context)
        _validate_scope(context, issue)
        require(type(timeout) in (float, int) and 0 < timeout <= MAX_TIMEOUT,
                'TIMEOUT_INVALID', 'invalid_input')
        require(type(allow_network) is bool and allow_network, 'NETWORK_NOT_AUTHORIZED')
        _validate_grant(grant, context, issue, _now(clock))
        supplier = token_supplier
        if supplier is None:
            supplier = lambda: os.environ.get(ENV_CREDENTIAL[context.provider])
        try:
            token = supplier()
        except Exception:
            raise IssueError('CREDENTIALS_UNAVAILABLE') from None
        require(type(token) is str and TOKEN.fullmatch(token), 'CREDENTIALS_UNAVAILABLE')
        active = transport if transport is not None else StrictHTTPSIssueTransport()
        headers = _headers(context.provider, token)
        repo_url, issue_url = _endpoints(context, issue)
        require(er.allow_issue_http('GET', repo_url, profile='EC211_SELECTED', headers=headers),
                'ENDPOINT_REJECTED')
        repo_one = active.get_object(repo_url, headers, float(timeout))
        repo_id, repo_name = _repository_metadata(repo_one, context, issue)
        if context.provider == 'gitlab':
            _, issue_url = _endpoints(context, issue, repo_id)
        require(type(issue_url) is str, 'ENDPOINT_REJECTED')
        require(er.allow_issue_http('GET', issue_url, profile='EC211_SELECTED', headers=headers),
                'ENDPOINT_REJECTED')
        raw_issue = active.get_object(issue_url, headers, float(timeout))
        iid, projection = _issue_metadata(raw_issue, context, issue, repo_id, repo_name)
        # Re-read project locator after Issue read: path transfer/rename/rebind
        # must not silently attach a different remote repository identity.
        repo_two = active.get_object(repo_url, headers, float(timeout))
        require(_repository_metadata(repo_two, context, issue) == (repo_id, repo_name),
                'REPOSITORY_CHANGED_DURING_READ')
        _validate_grant(grant, context, issue, _now(clock))
        identity = {'provider': context.provider, 'api_host': context.api_host,
                    'repository_path': repo_name, 'provider_repository_id': str(repo_id),
                    'issue_number': issue.number, 'provider_issue_id': str(iid)}
        source = {
            'identity': identity,
            'identity_sha256': _hash(IDENTITY_DOMAIN, {
                'provider': context.provider, 'api_host': context.api_host,
                'provider_repository_id': str(repo_id), 'provider_issue_id': str(iid)}),
            'snapshot_sha256': _hash(DOMAIN, {'identity': identity, 'metadata': projection}),
            'snapshot_semantics': 'SELECTED_PROVIDER_METADATA_AND_UNEXPOSED_TITLE_DESCRIPTION_LABELS_V1',
            'provider_state': projection['state'],
            'provider_created_at_utc': projection['created_at_utc'],
            'provider_updated_at_utc': projection['updated_at_utc'],
            'provider_closed_at_utc': projection['closed_at_utc'],
            'provider_confidentiality': projection['privacy'],
            'observed_at_utc': _now(clock).isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            'origin': 'synthetic_fixture' if synthetic else 'provider_https_response',
            'provider_identity_claim': 'OBSERVED_ID_AND_REPOSITORY_LOCATOR_DOUBLE_CHECKED',
            'snapshot_atomic': False,
            'all_issue_fields_collected': False,
            'title_body_labels_disclosed': False,
            'remote_creation_or_delivery_verified': False,
        }
        return _result('partial', 'METADATA_OBSERVED', source=source, synthetic=synthetic)
    except IssueError as exc:
        return _result(exc.status, exc.reason, synthetic=synthetic)
    except Exception:
        # A transport exception may contain credentials, URLs or provider text.
        return _result('unavailable', 'PROVIDER_READ_FAILED', synthetic=synthetic)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC211 read-only GH/GL Issue metadata provider; no native IssueSync')
    parser.add_argument('--provider', required=True, choices=['github', 'gitlab'])
    parser.add_argument('--repository', required=True)
    parser.add_argument('--number', required=True, type=int)
    parser.add_argument('--host', help='explicit API host (api.github.com or gitlab.com)')
    parser.add_argument('--account-ref', help='host-configured opaque account slot, never a token')
    parser.add_argument('--expected-repository-id', type=int)
    parser.add_argument('--authorize-read', action='store_true', help='attest one exact in-process GET read grant')
    parser.add_argument('--allow-network', action='store_true', help='opt in to bounded provider HTTPS GET')
    parser.add_argument('--timeout', type=float, default=MAX_TIMEOUT)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    host = args.host or API_HOST[args.provider]
    context = ProviderContext(args.provider, host, args.account_ref or '')
    selection = IssueSelection(args.repository, args.number, args.expected_repository_id)
    grant = None
    if args.authorize_read:
        grant = IssueReadGrant(METHOD, context.provider, context.api_host, context.account_ref,
                               selection.repository, selection.number,
                               (datetime.now(timezone.utc) + timedelta(seconds=120))
                               .isoformat(timespec='seconds').replace('+00:00', 'Z'), True)
    result = read_issue(context, selection, grant=grant, allow_network=args.allow_network,
                        timeout=args.timeout)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
