#!/usr/bin/env python3
"""EC220: central Issue HTTP verb/route boundary and fresh exact existing-Issue read.

This is a standalone host-called Python adapter, not a CES PowerShell Action.
Only official HTTPS repository and selected Issue GETs are possible through the
read adapter. An entirely separate EC218_CREATE profile describes the *single*
new-Issue collection POST; a route decision alone NEVER authorizes sending it.
No Issue update, comment, assign, label mutation, state transition or PR route
is implemented. Unknown/hidden/404 is never Issue absence. No raw content,
credentials, labels, repository paths or Issue numbers are returned.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import re
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

SCHEMA = 'ces.issue_existing_readonly.v1'
READ_METHOD = 'READ_ONE_EXISTING_ISSUE_EXACT_CONTENT_HASH'
READ_PROFILES = frozenset(('EC211_SELECTED', 'EC219_RECHECK', 'EC220_SELECTED'))
PROFILE_CREATE = 'EC218_NEW_CREATE'
API_HOSTS = {'github': 'api.github.com', 'gitlab': 'gitlab.com'}
MAX_READ_GRANT_SECONDS = 120
MAX_TIMEOUT = 8.0
SHA256 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
ACCOUNT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z', re.ASCII)
AUDIENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{2,95}\Z', re.ASCII)
SEGMENT = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\Z', re.ASCII)
NUMBER = re.compile(r'[1-9][0-9]*\Z', re.ASCII)
STAMP = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z\Z', re.ASCII)
GH_PAGE = re.compile(r'state=all&sort=created&direction=desc&per_page=50&page=([1-3])\Z', re.ASCII)
GL_PAGE = re.compile(r'scope=all&state=all&order_by=created_at&sort=desc&per_page=50&page=([1-3])\Z', re.ASCII)
BANNED_HEADERS = frozenset((
    'x-http-method-override', 'x-method-override', 'x-original-http-method',
    'x-original-method', 'x-http-method', 'x-http-override', 'x-rewrite-url',
    'x-original-url', 'x-forwarded-host', 'proxy-authorization',
))


class BoundaryDenied(ValueError):
    """Static safe error code; no remote/user payload interpolated."""
    def __init__(self, code: str, state: str = 'BLOCKED') -> None:
        super().__init__(code)
        self.code, self.state = code, state


def _need(test: bool, code: str, state: str = 'BLOCKED') -> None:
    if not test:
        raise BoundaryDenied(code, state)


@dataclass(frozen=True)
class IssueRoute:
    provider: str
    kind: str  # REPOSITORY | ISSUE_DETAIL | ISSUE_LIST | CREATE_NEW_COLLECTION
    repository: str | None
    repository_id: int | None
    number: int | None
    page: int | None


def _safe_segment(s: str) -> bool:
    return bool(s not in ('.', '..') and SEGMENT.fullmatch(s))


def _positive_id(value: Any) -> bool:
    return type(value) is int and 0 < value <= 2**63 - 1


def _headers_ok(headers: dict[str, str] | None) -> bool:
    if headers is None:
        return True
    if type(headers) is not dict or len(headers) > 32:
        return False
    seen: set[str] = set()
    for k, v in headers.items():
        if (type(k) is not str or type(v) is not str or len(k) > 100 or
                len(v) > 8192 or not re.fullmatch(r'[A-Za-z0-9-]+', k, re.ASCII) or
                '\r' in v or '\n' in v or '\0' in v):
            return False
        key = k.lower()
        if key in BANNED_HEADERS or key in seen:
            return False
        seen.add(key)
    return True


def issue_http_route(method: str, url: str, *, profile: str,
                     headers: dict[str, str] | None = None) -> IssueRoute:
    """Strict allowlist, never a generic CRUD/HTTP client or write permission.

    Profiles mirror actual EC211/218/219 and new EC220 network surfaces.
    EC218's POST classifier accepts only a NEW collection URI; the original
    EC217 approval and EC218 persistent UNIQUE-attempt barrier are still
    mandatory and deliberately not modeled as a read grant here.
    """
    _need(type(profile) is str and profile in (*READ_PROFILES, PROFILE_CREATE),
          'PROFILE_NOT_ALLOWED', 'INVALID_INPUT')
    _need(type(method) is str and method in ('GET', 'POST'), 'MUTATION_VERB_FORBIDDEN')
    _need(type(url) is str and 1 <= len(url) <= 650 and
          url.startswith('https://') and url == url.strip() and
          url.count('?') <= 1 and '#' not in url, 'URL_REJECTED')
    _need(_headers_ok(headers), 'UNSAFE_HEADER_REJECTED')
    try:
        p = urlsplit(url)
        _need(p.scheme == 'https' and p.netloc in ('api.github.com', 'gitlab.com') and
              p.username is None and p.password is None and p.port is None and
              not p.fragment and p.path.startswith('/') and
              '\\' not in url and any(c not in url for c in ('\r', '\n', '\0')),
              'URL_REJECTED')
    except (ValueError, TypeError):
        raise BoundaryDenied('URL_REJECTED') from None

    path = p.path
    kind: str | None = None
    repo: str | None = None
    repo_id: int | None = None
    number: int | None = None
    page: int | None = None
    if p.netloc == 'api.github.com':
        root = re.fullmatch(r'/repos/([^/]+)/([^/]+)(?:/(.*))?', path, re.ASCII)
        _need(root is not None and _safe_segment(root[1]) and _safe_segment(root[2]),
              'ENDPOINT_NOT_ALLOWLISTED')
        repo = root[1] + '/' + root[2]
        tail = root[3]
        if tail is None and not p.query:
            kind = 'REPOSITORY'
        elif tail == 'issues' and not p.query:
            kind = 'CREATE_NEW_COLLECTION' if method == 'POST' else None
        elif tail == 'issues' and method == 'GET':
            m = GH_PAGE.fullmatch(p.query)
            if m:
                kind, page = 'ISSUE_LIST', int(m[1])
        else:
            detail = re.fullmatch(r'issues/([1-9][0-9]*)', tail or '', re.ASCII)
            if detail and not p.query and int(detail[1]) <= 2147483647:
                kind, number = 'ISSUE_DETAIL', int(detail[1])
    elif p.netloc == 'gitlab.com':
        prefix = '/api/v4/projects/'
        _need(path.startswith(prefix), 'ENDPOINT_NOT_ALLOWLISTED')
        rest = path[len(prefix):]
        # A repository locator uses exactly the canonical case-sensitive %2F
        # encoding; repository-local Issue endpoints use the numeric project ID.
        if '/' not in rest and not p.query and '%2F' in rest:
            pieces = rest.split('%2F')
            if 2 <= len(pieces) <= 12 and all(_safe_segment(x) for x in pieces):
                kind, repo = 'REPOSITORY', '/'.join(pieces)
        else:
            m = re.fullmatch(r'([1-9][0-9]*)/issues(?:/([1-9][0-9]*))?', rest, re.ASCII)
            if m and int(m[1]) <= 2**63 - 1:
                repo_id = int(m[1])
                if m[2] is not None and not p.query and int(m[2]) <= 2147483647:
                    kind, number = 'ISSUE_DETAIL', int(m[2])
                elif m[2] is None and method == 'POST' and not p.query:
                    kind = 'CREATE_NEW_COLLECTION'
                elif m[2] is None and method == 'GET':
                    match_page = GL_PAGE.fullmatch(p.query)
                    if match_page:
                        kind, page = 'ISSUE_LIST', int(match_page[1])
    _need(kind is not None and (kind == 'ISSUE_LIST') == ('?' in url),
          'ENDPOINT_NOT_ALLOWLISTED')
    if profile in ('EC211_SELECTED', 'EC220_SELECTED'):
        _need(method == 'GET' and kind in ('REPOSITORY', 'ISSUE_DETAIL'),
              'READ_ROUTE_NOT_AUTHORIZED')
    elif profile == 'EC219_RECHECK':
        _need(method == 'GET' and kind in ('REPOSITORY', 'ISSUE_DETAIL', 'ISSUE_LIST'),
              'READ_ROUTE_NOT_AUTHORIZED')
    else:
        _need((method == 'GET' and kind == 'REPOSITORY') or
              (method == 'POST' and kind == 'CREATE_NEW_COLLECTION'),
              'NEW_CREATE_ONLY_ROUTE')
    return IssueRoute('github' if p.netloc == 'api.github.com' else 'gitlab',
                      kind, repo, repo_id, number, page)


def allow_issue_http(method: str, url: str, *, profile: str,
                     headers: dict[str, str] | None = None) -> bool:
    try:
        issue_http_route(method, url, profile=profile, headers=headers)
        return True
    except (BoundaryDenied, TypeError, ValueError):
        return False


@dataclass(frozen=True)
class HostExistingReadAccess:
    """Independent CURRENT host attestation, never an EC217/218 create grant.

    A trusted host issues this in memory; it is not cryptographic proof of the
    provider token's scope or of organizational authorization. No serializable
    JSON or CLI path automatically mints this capability.
    """
    method: str
    provider: str
    api_host: str
    account_ref: str
    repository: str
    expected_repository_id: int
    expected_issue_number: int
    expected_provider_issue_id: int
    visibility: str
    policy_revision_sha256: str
    audience: str
    expires_at_utc: str
    authorized: bool
    network_opt_in: bool
    read_issue_metadata_opt_in: bool
    read_full_issue_content_opt_in: bool
    read_private_or_confidential_opt_in: bool
    provider_credentials_attested_by_host: bool
    allow_write: bool = False


class ReadObjectTransport(Protocol):
    def get_object(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]: ...


def _utc(clock: Callable[[], datetime] | None) -> datetime:
    try:
        current = clock() if clock is not None else datetime.now(timezone.utc)
        _need(type(current) is datetime and current.tzinfo is not None and
              current.utcoffset() is not None and 2000 <= current.year <= 9998,
              'CLOCK_UNAVAILABLE')
        return current.astimezone(timezone.utc)
    except (ValueError, OverflowError, TypeError):
        raise BoundaryDenied('CLOCK_UNAVAILABLE') from None


def _access_ok(access: HostExistingReadAccess | None, context: Any,
               selection: Any, now: datetime) -> None:
    _need(type(access) is HostExistingReadAccess, 'INDEPENDENT_EXISTING_READ_REQUIRED')
    _need(access.method == READ_METHOD and access.authorized is True and
          access.allow_write is False, 'NOT_READ_ONLY_GRANT')
    _need(all(type(getattr(access, k)) is bool and getattr(access, k) is True for k in (
        'network_opt_in', 'read_issue_metadata_opt_in', 'read_full_issue_content_opt_in',
        'provider_credentials_attested_by_host')),
        'EXPLICIT_CONTENT_NETWORK_CREDENTIAL_READ_REQUIRED')
    _need(_positive_id(access.expected_repository_id) and
          _positive_id(access.expected_provider_issue_id) and
          type(access.expected_issue_number) is int and
          0 < access.expected_issue_number <= 2147483647 and
          type(access.visibility) is str and access.visibility in ('PUBLIC', 'PRIVATE') and
          type(access.policy_revision_sha256) is str and
          SHA256.fullmatch(access.policy_revision_sha256) is not None and
          type(access.audience) is str and AUDIENCE.fullmatch(access.audience) is not None and
          type(access.account_ref) is str and ACCOUNT.fullmatch(access.account_ref) is not None,
          'READ_GRANT_SHAPE_INVALID', 'INVALID_INPUT')
    _need(type(access.read_private_or_confidential_opt_in) is bool,
          'PRIVACY_READ_SCOPE_INVALID', 'INVALID_INPUT')
    # GitLab's Issue detail response can contain a confidential description
    # even in a PUBLIC project: no safe preview endpoint to establish the
    # confidentiality bit before fetching its body. Require consent up front.
    _need((access.visibility == 'PUBLIC' and access.provider != 'gitlab') or
          access.read_private_or_confidential_opt_in is True,
          'PRIVATE_OR_POSSIBLY_CONFIDENTIAL_CONTENT_NOT_GRANTED')
    _need((access.provider, access.api_host, access.account_ref, access.repository,
           access.expected_repository_id, access.expected_issue_number) ==
          (context.provider, context.api_host, context.account_ref,
           selection.repository, selection.expected_repository_id, selection.number) and
          access.api_host == API_HOSTS.get(access.provider),
          'READ_IDENTITY_OR_SCOPE_DRIFT')
    _need(type(access.expires_at_utc) is str and
          STAMP.fullmatch(access.expires_at_utc) is not None,
          'GRANT_EXPIRY_INVALID', 'INVALID_INPUT')
    try:
        exp = datetime.fromisoformat(access.expires_at_utc[:-1] + '+00:00')
    except (ValueError, OverflowError):
        raise BoundaryDenied('GRANT_EXPIRY_INVALID', 'INVALID_INPUT') from None
    _need(now < exp <= now + timedelta(seconds=MAX_READ_GRANT_SECONDS),
          'EXISTING_READ_EXPIRED')


def _repository_signature(raw: Any, context: Any,
                          access: HostExistingReadAccess) -> tuple[int, str, str]:
    _need(type(raw) is dict and '_ces_fixture' not in raw,
          'REPOSITORY_RESPONSE_UNVERIFIED')
    _need(_positive_id(raw.get('id')) and raw['id'] == access.expected_repository_id,
          'REPOSITORY_ID_DRIFT')
    field = 'full_name' if context.provider == 'github' else 'path_with_namespace'
    _need(type(raw.get(field)) is str and raw[field] == access.repository,
          'REPOSITORY_EXACT_PATH_DRIFT')
    if context.provider == 'github':
        _need(type(raw.get('private')) is bool and
              raw.get('has_issues') is True, 'REPOSITORY_PRIVACY_OR_ISSUES_UNKNOWN')
        visibility = 'PRIVATE' if raw['private'] else 'PUBLIC'
    else:
        _need(raw.get('visibility') in ('public', 'private') and
              raw.get('issues_enabled') is True,
              'REPOSITORY_PRIVACY_OR_ISSUES_UNKNOWN')
        visibility = raw['visibility'].upper()
    _need(visibility == access.visibility, 'REPOSITORY_VISIBILITY_DRIFT')
    return raw['id'], raw[field], visibility


def _output(status: str, code: str, *, source: dict[str, Any] | None = None,
            synthetic: bool, gets: int, issue_get_started: bool) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': {'partial': 2, 'unavailable': 5, 'invalid_input': 4}[status],
        'reason_code': 'ISSUE_EXISTING_READONLY_' + code,
        'read_state': ('SYNTHETIC_PINNED_ISSUE_OBSERVED' if synthetic
                       else 'PROVIDER_PINNED_ISSUE_OBSERVED') if source else 'UNKNOWN',
        'issue_existence': ('SYNTHETIC_PRESENT' if synthetic else 'PROVIDER_REPORTED_PRESENT') if source else 'UNKNOWN',
        'source': source, 'synthetic': synthetic,
        'provider_get_count': gets,
        'private_issue_content_may_have_been_read': bool(issue_get_started and not synthetic),
        'provider_token_scope_independently_verified': False,
        'host_organizational_role_cryptographically_verified': False,
        'existing_issue_edit_authorized': False,
        'issue_mutated': False, 'issue_closed': False, 'issue_reopened': False,
        'comment_created': False, 'labels_changed': False, 'assignees_changed': False,
        'provider_post_invoked': False, 'new_issue_created': False,
        'old_create_grant_reused': False, 'absence_proven': False,
        'all_issues_enumerated': False, 'hidden_issues_ruled_out': False,
        'native_issue_action_registered': False,
        'business_repository_written': False, 'external_ai_called': False,
        'git_or_knowledge_written': False, 'published_or_delivered': False,
    }


def read_existing_issue(context: Any, selection: Any, *,
                        access: HostExistingReadAccess | None,
                        token_supplier: Callable[[], str | None] | None,
                        transport: ReadObjectTransport | None = None,
                        clock: Callable[[], datetime] | None = None,
                        timeout: float = MAX_TIMEOUT) -> dict[str, Any]:
    """Bounded 3×GET of a pinned EXISTING Issue with separately granted content.

    No fallback from an old CREATE grant to read authorization. No GET without
    exact independent host consent. GitHub PRs and mismatched numeric Issue IDs
    are rejected. All error/hidden paths preserve UNKNOWN, not remote absence.
    """
    try:
        from . import issue_provider as ip
    except ImportError:
        import issue_provider as ip

    synthetic = transport is not None or clock is not None
    gets = 0
    issue_get_started = False
    try:
        _need(clock is None or transport is not None,
              'CUSTOM_CLOCK_REQUIRES_SYNTHETIC_TRANSPORT')
        ip._validate_context(context)
        ip._validate_scope(context, selection)
        _need(selection.expected_repository_id is not None,
              'STABLE_REPOSITORY_ID_REQUIRED', 'INVALID_INPUT')
        _need(type(timeout) in (float, int) and 0 < timeout <= MAX_TIMEOUT,
              'TIMEOUT_INVALID', 'INVALID_INPUT')
        _access_ok(access, context, selection, _utc(clock))
        _need(callable(token_supplier), 'CALLBACK_CREDENTIAL_REQUIRED')
        try:
            token = token_supplier()
        except Exception:
            raise BoundaryDenied('CREDENTIAL_UNAVAILABLE') from None
        _need(type(token) is str and ip.TOKEN.fullmatch(token) is not None,
              'CREDENTIAL_UNAVAILABLE')
        headers = ip._headers(context.provider, token)
        repo_url, issue_url = ip._endpoints(context, selection, selection.expected_repository_id)
        _need(type(issue_url) is str, 'READ_ENDPOINT_UNAVAILABLE')
        active = transport if transport is not None else ip.StrictHTTPSIssueTransport()
        _need(callable(getattr(active, 'get_object', None)), 'READ_TRANSPORT_UNAVAILABLE')

        def get(url: str, kind: str) -> dict[str, Any]:
            nonlocal gets, issue_get_started
            _access_ok(access, context, selection, _utc(clock))
            route = issue_http_route('GET', url, profile='EC220_SELECTED', headers=headers)
            _need(route.provider == context.provider and route.kind == kind,
                  'READ_ENDPOINT_WRONG_PROVIDER_OR_KIND')
            _need((route.repository == selection.repository if kind == 'REPOSITORY'
                   else route.number == selection.number and
                   (route.repository == selection.repository if context.provider == 'github'
                    else route.repository_id == selection.expected_repository_id)),
                  'READ_ENDPOINT_OUTSIDE_SELECTED_SCOPE')
            gets += 1
            if kind == 'ISSUE_DETAIL':
                issue_get_started = True
            try:
                raw = active.get_object(url, headers, float(timeout))
            except Exception:
                raise BoundaryDenied('REMOTE_READ_UNKNOWN') from None
            _need(type(raw) is dict and '_ces_fixture' not in raw,
                  'REMOTE_READ_PAYLOAD_UNVERIFIED')
            _need(len(ip._canonical(raw)) <= ip.MAX_BODY,
                  'REMOTE_READ_SIZE_LIMIT')
            return raw

        before = _repository_signature(get(repo_url, 'REPOSITORY'), context, access)
        issue = get(issue_url, 'ISSUE_DETAIL')
        # Existing EC211 parser explicitly rejects GH pull_request objects,
        # checks GL IID vs global ID, projects, privacy, state and timestamps.
        provider_id, projection = ip._issue_metadata(issue, context, selection,
                                                     before[0], before[1])
        _need(provider_id == access.expected_provider_issue_id,
              'GLOBAL_ISSUE_ID_NOT_PINNED')
        _need(projection['privacy'] != 'CONFIDENTIAL' or
              access.read_private_or_confidential_opt_in is True,
              'CONFIDENTIAL_CONTENT_NOT_GRANTED')
        after = _repository_signature(get(repo_url, 'REPOSITORY'), context, access)
        _need(before == after, 'REPOSITORY_CHANGED_DURING_READ')
        _access_ok(access, context, selection, _utc(clock))
        identity = {'provider': context.provider, 'provider_repository_id': before[0],
                    'provider_issue_id': provider_id, 'issue_number': selection.number}
        source = {
            'identity_sha256': hashlib.sha256(b'CES-EC220-EXISTING-ISSUE-ID-v1\0' +
                                              ip._canonical(identity)).hexdigest(),
            'selected_metadata_sha256': hashlib.sha256(
                b'CES-EC220-EXISTING-ISSUE-CONTENT-v1\0' +
                ip._canonical({'identity': identity, 'metadata': projection})).hexdigest(),
            'provider_state': projection['state'],
            'privacy': projection['privacy'],
            'provider_claim_not_atomic': True,
            'title_body_labels_disclosed': False,
            'repository_identity_double_checked': True,
            'provider_issue_global_id_pinned': True,
            'origin': 'synthetic_fixture' if synthetic else 'provider_https_response',
        }
        return _output('partial', 'PINNED_ISSUE_METADATA_OBSERVED', source=source,
                       synthetic=synthetic, gets=gets,
                       issue_get_started=issue_get_started)
    except BoundaryDenied as err:
        return _output('invalid_input' if err.state == 'INVALID_INPUT' else 'unavailable',
                       err.code, synthetic=synthetic, gets=gets,
                       issue_get_started=issue_get_started)
    except ip.IssueError as err:
        return _output('invalid_input' if err.status == 'invalid_input' else 'unavailable',
                       'UPSTREAM_' + err.reason, synthetic=synthetic, gets=gets,
                       issue_get_started=issue_get_started)
    except Exception:
        return _output('unavailable', 'READ_FAILURE_UNKNOWN', synthetic=synthetic,
                       gets=gets, issue_get_started=issue_get_started)
