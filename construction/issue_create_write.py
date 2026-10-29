#!/usr/bin/env python3
"""EC218: one-shot, exact-consent, application-idempotent NEW Issue creation.

Standalone opt-in Python integration boundary, NOT a PowerShell CES Action.
Unlike EC217, this module can perform an actual HTTPS POST to the official
GitHub/GitLab Issue creation endpoints. The host must independently provide
current credential/network permission, issuer keys, original evidence, and
read access to the *already committed* EC217 one-use reservation. Neither a
caller-supplied RESERVED_ONE_ATTEMPT JSON nor a valid signature alone grants
permission to send.

For a given audience, ALL workers must use the same trusted transactional
attempt ledger. A durable UNIQUE operation-key and grant-key insertion occurs
BEFORE the first POST. We never replay a recorded operation/grant, including
when there is a crash before POST, a timeout, malformed 201, or a 5xx. Provider
create APIs do not promise idempotency for our application key. The trade-off
is safety over liveness: an uncertain attempt remains uncertain until EC219's
separately authorized reconciliation, not a second POST.

No edit/comment/close/label mutation on an existing Issue is implemented.
Live credentials and remote targets are NOT provisioned or exercised here.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import stat
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, ProxyHandler, HTTPSHandler, build_opener

try:
    from . import issue_create_grant as cg
    from . import issue_provider as ip
    from . import issue_eligibility as ie
    from . import issue_existing_readonly as er
except ImportError:
    import issue_create_grant as cg
    import issue_provider as ip
    import issue_eligibility as ie
    import issue_existing_readonly as er

SCHEMA = 'ces.issue_create_write.v1'
OPERATION_DOMAIN = b'CES-EC218-SINGLE-NEW-ISSUE-OPERATION-v1\x00'
GRANT_DOMAIN = b'CES-EC218-ATTEMPT-GRANT-v1\x00'
IDENTITY_DOMAIN = b'CES-EC218-REMOTE-CREATE-IDENTITY-v1\x00'
HTTP_TIMEOUT_MAX = 8.0
MAX_RESPONSE = 1024 * 1024
MAX_POST_BYTES = 24 * 1024
MAX_ACCESS_SECONDS = 120


class WriteError(ValueError):
    """Only stable nonsecret codes; provider exception strings never escape."""
    def __init__(self, code: str, state: str = 'UNKNOWN') -> None:
        super().__init__(code)
        self.code, self.state = code, state


def _need(test: bool, code: str, state: str = 'BLOCKED') -> None:
    if not test:
        raise WriteError(code, state)


@dataclass(frozen=True)
class HostCreateAccess:
    """Fresh host-side credential/network approval; NOT applicant JSON.

    No token in this object. The host independently authenticates current
    account, policy revision and token permissions before constructing it.
    Actual remote permission remains the provider's decision.
    """
    provider: str
    api_host: str
    account_ref: str
    repository: str
    expected_repository_id: int
    visibility: str
    policy_revision_sha256: str
    audience: str
    expires_at_utc: str
    network_opt_in: bool
    create_new_issue_opt_in: bool
    current_provider_credentials_attested_by_host: bool


class GrantReservationReader(Protocol):
    audience: str
    def read_claim_time(self, grant_id: str, challenge_sha256: str) -> str | None: ...


class CreateAttemptLedger(Protocol):
    audience: str
    def atomic_start(self, operation_key: str, grant_id: str,
                     challenge_sha256: str, now: datetime) -> str: ...
    def record_outcome(self, operation_key: str, grant_id: str, outcome: str,
                       identity_sha256: str | None) -> bool: ...


class CreateTransport(Protocol):
    def get_object(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]: ...
    def post_create(self, url: str, headers: dict[str, str], body: bytes,
                    timeout: float) -> dict[str, Any]: ...


def _clock_now(clock: Callable[[], datetime] | None) -> datetime:
    try:
        now = clock() if clock else datetime.now(timezone.utc)
        _need(type(now) is datetime and now.tzinfo is not None and
              now.utcoffset() is not None, 'CLOCK_UNAVAILABLE', 'UNKNOWN')
        _need(2000 <= now.year <= 9998, 'CLOCK_UNAVAILABLE', 'UNKNOWN')
        return now.astimezone(timezone.utc)
    except (ValueError, OverflowError, TypeError):
        raise WriteError('CLOCK_UNAVAILABLE') from None


def _at(raw: str) -> datetime:
    try:
        return ie._time(raw)
    except Exception:
        raise WriteError('TIME_INVALID', 'INVALID_INPUT') from None


def _private_db(path: Path, *, may_create: bool) -> bool:
    """Single trusted local POSIX host only. Never create on a read probe."""
    try:
        if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW') or not path.is_absolute():
            return False
        parent = path.parent
        if any(p.is_symlink() for p in (parent, *parent.parents)):
            return False
        s = os.lstat(parent)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
            return False
        if may_create:
            try:
                fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        info = os.lstat(path)
        return bool(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                    not info.st_mode & 0o077 and info.st_nlink == 1)
    except (OSError, ValueError, TypeError):
        return False


def _reader_connection(path: Path) -> sqlite3.Connection:
    uri = 'file:' + quote(str(path), safe='/') + '?mode=ro'
    return sqlite3.connect(uri, uri=True, timeout=3)


class SQLiteGrantReservationReader:
    """Read, never reserve, the exact already committed EC217 SQLite claim.

    The old EC217 ledger is not modified, nor is a non-existent DB created.
    For multi-host use a host-owned shared transactional read adapter instead.
    """
    def __init__(self, path: str | Path, audience: str):
        self.path, self.audience = Path(path), audience

    def read_claim_time(self, grant_id: str, challenge_sha256: str) -> str | None:
        if (type(self.audience) is not str or not cg.AUDIENCE.fullmatch(self.audience) or
                type(grant_id) is not str or not cg.GRANT_ID.fullmatch(grant_id) or
                type(challenge_sha256) is not str or not ie.HEX.fullmatch(challenge_sha256) or
                not _private_db(self.path, may_create=False)):
            return None
        key = hashlib.sha256(cg.GRANT_ID_DOMAIN + self.audience.encode('ascii') +
                             bytes.fromhex(grant_id)).hexdigest()
        try:
            with closing(_reader_connection(self.path)) as db:
                rows = db.execute('SELECT challenge_sha256, claimed_at_utc FROM claim '
                                  'WHERE grant_key=? LIMIT 1', (key,)).fetchall()
            if len(rows) != 1 or type(rows[0][0]) is not str or rows[0][0] != challenge_sha256:
                return None
            return rows[0][1] if type(rows[0][1]) is str else None
        except (sqlite3.Error, OSError, ValueError, TypeError):
            return None


class SQLiteCreateAttemptLedger:
    """Durable first-writer-wins barrier, POSIX single host + local volume.

    Every process/audience must use one stable DB and must never roll it back,
    rename it, or independently re-create it. Multiple hosts require a shared
    transactional store with equivalent uniqueness/durability semantics.
    Contents are domain-separated digests + timestamps, never token or text.
    """
    def __init__(self, path: str | Path, audience: str):
        self.path, self.audience = Path(path), audience

    def _grant_key(self, grant_id: str) -> str:
        return hashlib.sha256(GRANT_DOMAIN + self.audience.encode('ascii') +
                              bytes.fromhex(grant_id)).hexdigest()

    def atomic_start(self, operation_key: str, grant_id: str,
                     challenge_sha256: str, now: datetime) -> str:
        if (type(self.audience) is not str or not cg.AUDIENCE.fullmatch(self.audience) or
                type(operation_key) is not str or not ie.HEX.fullmatch(operation_key) or
                type(grant_id) is not str or not cg.GRANT_ID.fullmatch(grant_id) or
                type(challenge_sha256) is not str or not ie.HEX.fullmatch(challenge_sha256) or
                type(now) is not datetime or now.tzinfo is None or
                not _private_db(self.path, may_create=True)):
            return 'UNAVAILABLE'
        try:
            with closing(sqlite3.connect(str(self.path), isolation_level=None, timeout=5)) as db:
                db.execute('PRAGMA busy_timeout=5000')
                db.execute('PRAGMA journal_mode=DELETE')
                db.execute('PRAGMA synchronous=FULL')
                db.execute('BEGIN IMMEDIATE')
                db.execute('CREATE TABLE IF NOT EXISTS issue_create_attempt ('
                           'operation_key TEXT PRIMARY KEY NOT NULL, '
                           'grant_key TEXT UNIQUE NOT NULL, '
                           'challenge_sha256 TEXT NOT NULL, '
                           'started_at_utc TEXT NOT NULL, '
                           'outcome TEXT NOT NULL, '
                           'identity_sha256 TEXT)')
                try:
                    db.execute('INSERT INTO issue_create_attempt VALUES (?,?,?,?,?,NULL)',
                               (operation_key, self._grant_key(grant_id), challenge_sha256,
                                now.isoformat(), 'POSSIBLY_SENT'))
                except sqlite3.IntegrityError:
                    db.execute('ROLLBACK')
                    return 'ALREADY_RECORDED'
                db.execute('COMMIT')
            return 'CLAIMED'
        except (sqlite3.Error, OSError, ValueError, TypeError):
            return 'UNAVAILABLE'

    def record_outcome(self, operation_key: str, grant_id: str, outcome: str,
                       identity_sha256: str | None) -> bool:
        if (type(operation_key) is not str or not ie.HEX.fullmatch(operation_key) or
                type(grant_id) is not str or not cg.GRANT_ID.fullmatch(grant_id) or
                outcome not in ('PROVIDER_REPORTED_CREATED', 'SYNTHETIC_RESPONSE',
                                'POST_REJECTED', 'POST_UNKNOWN') or
                (identity_sha256 is not None and
                 (type(identity_sha256) is not str or not ie.HEX.fullmatch(identity_sha256))) or
                not _private_db(self.path, may_create=False)):
            return False
        try:
            with closing(sqlite3.connect(str(self.path), isolation_level=None, timeout=5)) as db:
                db.execute('PRAGMA busy_timeout=5000')
                db.execute('PRAGMA synchronous=FULL')
                db.execute('BEGIN IMMEDIATE')
                cursor = db.execute('UPDATE issue_create_attempt SET outcome=?, identity_sha256=? '
                                    'WHERE operation_key=? AND grant_key=? AND outcome=?',
                                    (outcome, identity_sha256, operation_key,
                                     self._grant_key(grant_id), 'POSSIBLY_SENT'))
                if cursor.rowcount != 1:
                    db.execute('ROLLBACK')
                    return False
                db.execute('COMMIT')
            return True
        except (sqlite3.Error, OSError, ValueError, TypeError):
            return False


def operation_sha256(intent: cg.IssueCreateIntent) -> str:
    """Stable across new grant IDs for identical exact target/content/plan.

    Includes plan and content digests (the latter pins citations as well),
    policy, audience, exact case-sensitive repository path and numeric ID.
    Human reapproval without altering the operation cannot re-POST it.
    """
    _need(type(intent) is cg.IssueCreateIntent, 'INTENT_INVALID', 'INVALID_INPUT')
    data = {k: getattr(intent, k) for k in (
        'action', 'provider', 'api_host', 'account_ref', 'repository',
        'expected_repository_id', 'visibility', 'policy_revision_sha256',
        'expected_plan_sha256', 'expected_plan_result_sha256',
        'expected_final_content_sha256', 'audience')}
    try:
        return hashlib.sha256(OPERATION_DOMAIN + ip._canonical(data)).hexdigest()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise WriteError('INTENT_INVALID', 'INVALID_INPUT') from None


def _permit(access: HostCreateAccess | None, intent: cg.IssueCreateIntent,
            now: datetime) -> None:
    _need(type(access) is HostCreateAccess, 'INDEPENDENT_HOST_ACCESS_REQUIRED')
    _need(type(access.expected_repository_id) is int and
          all(type(getattr(access, k)) is str for k in
              ('provider', 'api_host', 'account_ref', 'repository',
               'visibility', 'policy_revision_sha256', 'audience', 'expires_at_utc')),
          'HOST_ACCESS_SHAPE_INVALID', 'INVALID_INPUT')
    _need(access.network_opt_in is True and access.create_new_issue_opt_in is True and
          access.current_provider_credentials_attested_by_host is True,
          'HOST_CREATE_OR_NETWORK_NOT_APPROVED')
    _need((access.provider, access.api_host, access.account_ref, access.repository,
           access.expected_repository_id, access.visibility,
           access.policy_revision_sha256, access.audience) ==
          (intent.provider, intent.api_host, intent.account_ref, intent.repository,
           intent.expected_repository_id, intent.visibility,
           intent.policy_revision_sha256, intent.audience),
          'HOST_ACCESS_SCOPE_DRIFT')
    deadline = _at(access.expires_at_utc)
    _need(now < deadline <= now + timedelta(seconds=MAX_ACCESS_SECONDS),
          'HOST_ACCESS_EXPIRED')


def _reservation(reader: GrantReservationReader | None, audience: str,
                 grant_id: str, challenge_sha256: str,
                 issued: str, expiry: str, now: datetime) -> None:
    _need(reader is not None and getattr(reader, 'audience', None) == audience and
          callable(getattr(reader, 'read_claim_time', None)),
          'ORIGINAL_RESERVATION_READER_REQUIRED')
    try:
        stamp = reader.read_claim_time(grant_id, challenge_sha256)
    except Exception:
        raise WriteError('ORIGINAL_RESERVATION_UNAVAILABLE') from None
    _need(type(stamp) is str, 'ORIGINAL_RESERVATION_NOT_CONFIRMED')
    try:
        reserved_at = datetime.fromisoformat(stamp)
    except (ValueError, TypeError, OverflowError):
        raise WriteError('ORIGINAL_RESERVATION_INVALID') from None
    _need(reserved_at.tzinfo is not None and _at(issued) <= reserved_at <= now and
          reserved_at < _at(expiry), 'ORIGINAL_RESERVATION_INVALID')


def _urls(intent: cg.IssueCreateIntent) -> tuple[str, str]:
    parts = intent.repository.split('/')
    _need((len(parts) == 2 if intent.provider == 'github' else 2 <= len(parts) <= 12)
          and all(p not in ('.', '..') and ip.SEGMENT.fullmatch(p) for p in parts),
          'REPOSITORY_PATH_INVALID', 'INVALID_INPUT')
    if intent.provider == 'github':
        base = 'https://api.github.com/repos/' + '/'.join(quote(p, safe='') for p in parts)
        return base, base + '/issues'
    return ('https://gitlab.com/api/v4/projects/' + quote(intent.repository, safe=''),
            'https://gitlab.com/api/v4/projects/' + str(intent.expected_repository_id) + '/issues')


def _allowed_url(url: str, method: str) -> bool:
    """EC220 shared policy: EC218 may only GET a repo or POST NEW /issues.

    A valid method/path does not grant permission; the real call still needs
    EC217 signatures and consumed grant plus EC218 durable one-use barrier.
    """
    return er.allow_issue_http(method, url, profile=er.PROFILE_CREATE)


class _NoRedirect(ip._NoRedirect):
    """Explicitly forbid urllib automatic redirect follow for POST and GET."""


class StrictHTTPSIssueCreateTransport:
    """Fixed GH/GL official HTTPS endpoints; no proxy/redirect/POST retry."""
    def _request(self, method: str, url: str, headers: dict[str, str],
                 body: bytes | None, timeout: float) -> dict[str, Any]:
        _need(_allowed_url(url, method) and
              er.allow_issue_http(method, url, profile=er.PROFILE_CREATE, headers=headers),
              'ENDPOINT_NOT_ALLOWLISTED')
        _need(type(timeout) in (int, float) and 0 < timeout <= HTTP_TIMEOUT_MAX,
              'TIMEOUT_INVALID', 'INVALID_INPUT')
        if method == 'POST':
            _need(type(body) is bytes and 0 < len(body) <= MAX_POST_BYTES,
                  'POST_PAYLOAD_OUT_OF_BOUNDS', 'INVALID_INPUT')
        opener = build_opener(ProxyHandler({}), _NoRedirect(),
                              HTTPSHandler(context=ssl.create_default_context()))
        request = Request(url, method=method, headers=headers, data=body)
        try:
            with opener.open(request, timeout=timeout) as response:
                expected = 201 if method == 'POST' else 200
                _need(response.status == expected and response.geturl() == url,
                      'PROVIDER_RESPONSE_UNCERTAIN')
                content_type = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                _need(content_type == 'application/json' or
                      (content_type.startswith('application/') and content_type.endswith('+json')),
                      'PROVIDER_RESPONSE_NOT_JSON')
                declared = response.headers.get('Content-Length')
                _need(not (declared and declared.isdecimal() and int(declared) > MAX_RESPONSE),
                      'PROVIDER_RESPONSE_TOO_LARGE')
                raw = response.read(MAX_RESPONSE + 1)
                _need(len(raw) <= MAX_RESPONSE, 'PROVIDER_RESPONSE_TOO_LARGE')
                try:
                    return ip._json_object(raw)
                except Exception:
                    raise WriteError('PROVIDER_RESPONSE_INVALID') from None
        except HTTPError as exc:
            if method == 'POST' and exc.code in (400, 401, 403, 404, 410, 422):
                raise WriteError('PROVIDER_POST_REJECTED', 'REJECTED_UNVERIFIED') from None
            raise WriteError('PROVIDER_HTTP_UNCERTAIN') from None
        except (URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError):
            raise WriteError('PROVIDER_NETWORK_UNCERTAIN') from None

    def get_object(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        return self._request('GET', url, headers, None, timeout)

    def post_create(self, url: str, headers: dict[str, str], body: bytes,
                    timeout: float) -> dict[str, Any]:
        return self._request('POST', url, headers, body, timeout)


def _headers(provider: str, token: str) -> dict[str, str]:
    common = {'User-Agent': 'CES-EC218-single-create/1', 'Accept-Encoding': 'identity'}
    if provider == 'github':
        return {**common, 'Accept': 'application/vnd.github+json',
                'Authorization': 'Bearer ' + token,
                'X-GitHub-Api-Version': '2026-03-10',
                'Content-Type': 'application/json'}
    return {**common, 'Accept': 'application/json', 'PRIVATE-TOKEN': token,
            'Content-Type': 'application/json'}


def _check_repo(raw: dict[str, Any], intent: cg.IssueCreateIntent) -> None:
    _need(type(raw) is dict and '_ces_fixture' not in raw,
          'REPOSITORY_RESPONSE_INVALID', 'UNKNOWN')
    _need(ip._positive_id(raw.get('id')) and raw['id'] == intent.expected_repository_id,
          'REPOSITORY_ID_DRIFT')
    name = raw.get('full_name' if intent.provider == 'github' else 'path_with_namespace')
    # Exact spelling, not casefold: the human approved precisely this target.
    _need(type(name) is str and name == intent.repository, 'REPOSITORY_PATH_DRIFT')
    if intent.provider == 'github':
        private, enabled = raw.get('private'), raw.get('has_issues')
        _need(type(private) is bool and type(enabled) is bool,
              'REPOSITORY_PRIVACY_OR_FEATURE_UNKNOWN', 'UNKNOWN')
        visibility = 'PRIVATE' if private else 'PUBLIC'
    else:
        visibility = {'private': 'PRIVATE', 'public': 'PUBLIC'}.get(raw.get('visibility'))
        enabled = raw.get('issues_enabled')
        _need(visibility is not None and type(enabled) is bool,
              'REPOSITORY_PRIVACY_OR_FEATURE_UNKNOWN', 'UNKNOWN')
    _need(visibility == intent.visibility, 'REPOSITORY_VISIBILITY_DRIFT')
    _need(enabled is True and raw.get('archived') is False,
          'REPOSITORY_ISSUES_UNAVAILABLE')


def _payload(intent: cg.IssueCreateIntent, content: cg.FinalIssueContent) -> bytes:
    # No appended idempotency marker: it would alter the exact human-signed
    # final body. API endpoints do NOT guarantee idempotency for arbitrary key.
    if intent.provider == 'github':
        data = {'title': content.title, 'body': content.body,
                'labels': list(content.labels)}
    else:
        data = {'title': content.title, 'description': content.body,
                'labels': ','.join(content.labels),
                'confidential': intent.visibility == 'PRIVATE'}
    raw = ip._canonical(data)
    _need(len(raw) <= MAX_POST_BYTES, 'POST_PAYLOAD_OUT_OF_BOUNDS', 'INVALID_INPUT')
    return raw


def _created(raw: dict[str, Any], intent: cg.IssueCreateIntent,
             content: cg.FinalIssueContent, repo_url: str) -> str:
    # The 201 response must be a NEW Issue at the bound repository with
    # exactly the human-reviewed title/body/labels. This is provider-reported,
    # not an independent EC219 reread.
    _need(type(raw) is dict and '_ces_fixture' not in raw and
          ip._positive_id(raw.get('id')),
          'CREATED_RESPONSE_ID_UNVERIFIED', 'UNKNOWN')
    if intent.provider == 'github':
        iid = raw.get('number')
        _need(type(iid) is int and 0 < iid <= 2147483647 and
              'pull_request' not in raw and
              raw.get('repository_url') == repo_url and
              raw.get('url') == repo_url + '/issues/' + str(iid) and
              raw.get('state') == 'open' and
              raw.get('title') == content.title and raw.get('body') == content.body,
              'CREATED_RESPONSE_SCOPE_OR_TEXT_UNVERIFIED', 'UNKNOWN')
        labels = raw.get('labels')
        _need(type(labels) is list and all(type(x) is dict and
              type(x.get('name')) is str for x in labels),
              'CREATED_RESPONSE_LABELS_UNVERIFIED', 'UNKNOWN')
        names = [x['name'] for x in labels]
    else:
        iid = raw.get('iid')
        _need(type(iid) is int and 0 < iid <= 2147483647 and
              type(raw.get('project_id')) is int and
              raw['project_id'] == intent.expected_repository_id and
              raw.get('state') == 'opened' and
              raw.get('confidential') is (intent.visibility == 'PRIVATE') and
              raw.get('title') == content.title and
              raw.get('description') == content.body,
              'CREATED_RESPONSE_SCOPE_OR_TEXT_UNVERIFIED', 'UNKNOWN')
        names = raw.get('labels')
    _need(type(names) is list and all(type(x) is str for x in names) and
          len(names) == len(content.labels) and sorted(names) == list(content.labels),
          'CREATED_RESPONSE_LABELS_UNVERIFIED', 'UNKNOWN')
    return hashlib.sha256(IDENTITY_DOMAIN + ip._canonical({
        'provider': intent.provider, 'repository_id': str(intent.expected_repository_id),
        'issue_id': str(raw['id']), 'issue_number': str(iid)})).hexdigest()


def _out(state: str, reason: str, *, operation: str | None = None,
         reservation_confirmed: bool = False, attempt_recorded: bool = False,
         post_invoked: bool = False,
         synthetic: bool = False, identity: str | None = None,
         replay_blocked: bool = False) -> dict[str, Any]:
    status = 'invalid_input' if state == 'INVALID_INPUT' else (
        'unavailable' if state == 'UNKNOWN' else 'partial')
    remote_claim = state == 'PROVIDER_REPORTED_CREATED' and not synthetic
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': {'partial': 2, 'unavailable': 5, 'invalid_input': 4}[status],
        'reason_code': 'ISSUE_CREATE_WRITE_' + reason,
        'create_state': state, 'operation_sha256': operation,
        'provider_issue_identity_sha256': identity if remote_claim else None,
        'synthetic': synthetic,
        'ec217_original_reservation_confirmed': reservation_confirmed,
        'durable_attempt_barrier_recorded': attempt_recorded,
        'provider_post_invoked': post_invoked,
        'same_request_replay_blocked': replay_blocked,
        'provider_reported_created': remote_claim,
        'issue_created': remote_claim,  # 201 + exact response; still provider claim.
        'remote_creation_independently_reread': False,
        'provider_write_may_have_occurred': bool(post_invoked and not synthetic),
        'external_final_text_may_have_been_disclosed': bool(post_invoked and not synthetic),
        'permission_to_modify_existing_issues': False,
        'issue_edited': False, 'issue_closed': False, 'comment_created': False,
        'business_repository_written': False,
        'git_or_knowledge_written': False, 'external_ai_called': False,
        'published_or_delivered': False, 'native_issue_action_registered': False,
        'all_existing_issues_enumerated': False, 'duplicate_absence_proven': False,
        'organizational_authority_independently_authenticated_by_ces': False,
        'safe_next_step': ('EC219_REMOTE_UNKNOWN_RECONCILIATION_NO_POST_RETRY' if
                           attempt_recorded and not remote_claim else
                           'NO_AUTOMATIC_SECOND_POST'),
    }


def create_new_issue_once(
        evidence: cg.PlanEvidence, intent: cg.IssueCreateIntent,
        content: cg.FinalIssueContent, approval: cg.HumanCreateApproval, *,
        trusted_eligibility_review_keys: Mapping[str, bytes] | None,
        trusted_issuers: Mapping[str, cg.IssuerAuthority] | None,
        reserved_grants: GrantReservationReader | None,
        attempt_ledger: CreateAttemptLedger | None,
        host_access: HostCreateAccess | None,
        token_supplier: Callable[[], str | None] | None,
        transport: CreateTransport | None = None,
        clock: Callable[[], datetime] | None = None,
        timeout: float = HTTP_TIMEOUT_MAX) -> dict[str, Any]:
    """Consume at most one durable attempt for exact review; POST at most once.

    Must be invoked by trusted host that holds all original private evidence,
    current issuer registry, genuine reserved EC217 claim and independently
    provisioned credential+two opt-ins. No auto retry and no CLI accepting
    caller provided keys/authorization. Injected transports or clocks are
    synthetic development results and NEVER claim live Issue creation.
    """
    synthetic = transport is not None or clock is not None
    operation = None
    reservation_confirmed = False
    recorded = False
    post_invoked = False
    try:
        # Test clocks must NEVER authorize real provider traffic. A callback
        # clock could otherwise resurrect an expired signed human approval.
        _need(clock is None or transport is not None,
              'CUSTOM_CLOCK_REQUIRES_SYNTHETIC_TRANSPORT')
        ip._validate_context(evidence.context)
        _need(type(timeout) in (int, float) and 0 < timeout <= HTTP_TIMEOUT_MAX,
              'TIMEOUT_INVALID', 'INVALID_INPUT')
        now = _clock_now(clock)
        _permit(host_access, intent, now)
        # Rebuild the entire EC216 -> EC215 -> EC214 evidence and independently
        # reverify exact EC217 signature and current host issuer role.
        challenge, grant_id, _ = cg._inspect(
            evidence, intent, content, approval,
            trusted_eligibility_review_keys, trusted_issuers, clock)
        _reservation(reserved_grants, challenge['audience'], grant_id,
                     challenge['challenge_sha256'], approval.issued_at_utc,
                     approval.expires_at_utc, now)
        reservation_confirmed = True
        _need(attempt_ledger is not None and
              getattr(attempt_ledger, 'audience', None) == challenge['audience'] and
              callable(getattr(attempt_ledger, 'atomic_start', None)) and
              callable(getattr(attempt_ledger, 'record_outcome', None)),
              'DURABLE_SHARED_ATTEMPT_LEDGER_REQUIRED')
        _need(callable(token_supplier), 'EXTERNAL_TOKEN_SUPPLIER_REQUIRED')
        try:
            token = token_supplier()
        except Exception:
            raise WriteError('PROVIDER_TOKEN_UNAVAILABLE') from None
        _need(type(token) is str and ip.TOKEN.fullmatch(token),
              'PROVIDER_TOKEN_UNAVAILABLE')
        operation = operation_sha256(intent)
        repo_url, issue_url = _urls(intent)
        post_body = _payload(intent, content)
        active = transport if transport is not None else StrictHTTPSIssueCreateTransport()
        _need(callable(getattr(active, 'get_object', None)) and
              callable(getattr(active, 'post_create', None)), 'TRANSPORT_UNAVAILABLE')
        headers = _headers(intent.provider, token)
        # Fresh provider repo identity/visibility BEFORE operation claim.
        _need(er.allow_issue_http('GET', repo_url, profile=er.PROFILE_CREATE, headers=headers),
              'REPOSITORY_GET_ROUTE_FORBIDDEN')
        remote = active.get_object(repo_url, headers, float(timeout))
        _check_repo(remote, intent)
        # Repo GET could take time. Recheck the whole consent/issuer/policy and
        # expiring separate host permission immediately before durable claim.
        now = _clock_now(clock)
        _permit(host_access, intent, now)
        challenge2, grant_id2, _ = cg._inspect(
            evidence, intent, content, approval,
            trusted_eligibility_review_keys, trusted_issuers, clock)
        _need(grant_id2 == grant_id and challenge2 == challenge,
              'CONSENT_CHANGED_DURING_PREFLIGHT')
        _reservation(reserved_grants, challenge['audience'], grant_id,
                     challenge['challenge_sha256'], approval.issued_at_utc,
                     approval.expires_at_utc, now)
        state = attempt_ledger.atomic_start(operation, grant_id,
                                            challenge['challenge_sha256'], now)
        if state == 'ALREADY_RECORDED':
            return _out('BLOCKED', 'OPERATION_OR_GRANT_ALREADY_SPENT',
                        operation=operation, replay_blocked=True, synthetic=synthetic,
                        reservation_confirmed=reservation_confirmed)
        _need(state == 'CLAIMED', 'ATOMIC_ATTEMPT_STORE_UNAVAILABLE', 'UNKNOWN')
        recorded = True
        # At this point ANY error can mean a remote creation happened.
        # Do not automatically retry even if a TCP error occurred before bytes.
        try:
            _need(er.allow_issue_http('POST', issue_url, profile=er.PROFILE_CREATE, headers=headers),
                  'NEW_COLLECTION_POST_ROUTE_FORBIDDEN')
            post_invoked = True
            created = active.post_create(issue_url, headers, post_body, float(timeout))
            identity = _created(created, intent, content, repo_url)
            outcome = 'SYNTHETIC_RESPONSE' if synthetic else 'PROVIDER_REPORTED_CREATED'
            _need(attempt_ledger.record_outcome(operation, grant_id, outcome, identity),
                  'CREATED_BUT_LEDGER_CONFIRMATION_UNAVAILABLE', 'UNKNOWN')
            return _out('SIMULATED_RESPONSE_MATCHED' if synthetic else
                        'PROVIDER_REPORTED_CREATED', '201_MATCHED_EXACT_REVIEWED_CONTENT',
                        operation=operation, reservation_confirmed=True,
                        attempt_recorded=True, post_invoked=True,
                        synthetic=synthetic, identity=identity)
        except WriteError as exc:
            try:
                attempt_ledger.record_outcome(operation, grant_id,
                                              'POST_REJECTED' if exc.state == 'REJECTED_UNVERIFIED'
                                              else 'POST_UNKNOWN', None)
            except Exception:
                pass
            return _out(exc.state if exc.state == 'REJECTED_UNVERIFIED' else 'UNKNOWN',
                        exc.code, operation=operation, reservation_confirmed=True, attempt_recorded=True,
                        post_invoked=True, synthetic=synthetic)
        except Exception:
            try:
                attempt_ledger.record_outcome(operation, grant_id, 'POST_UNKNOWN', None)
            except Exception:
                pass
            return _out('UNKNOWN', 'POST_RESULT_UNCERTAIN', operation=operation, reservation_confirmed=True,
                        attempt_recorded=True, post_invoked=True, synthetic=synthetic)
    except cg.GrantError as exc:
        state = ('INVALID_INPUT' if exc.state == 'INVALID_INPUT' else
                 'BLOCKED' if exc.state in ('BLOCKED', 'NEEDS_REVIEW') else 'UNKNOWN')
        return _out(state, 'EC217_' + exc.code, operation=operation,
                    reservation_confirmed=reservation_confirmed, synthetic=synthetic)
    except ip.IssueError as exc:
        return _out('INVALID_INPUT' if exc.status == 'invalid_input' else 'UNKNOWN',
                    'HOST_CONTEXT_' + exc.reason, operation=operation,
                    reservation_confirmed=reservation_confirmed, synthetic=synthetic)
    except WriteError as exc:
        return _out(exc.state, exc.code, operation=operation,
                    reservation_confirmed=reservation_confirmed, attempt_recorded=recorded, post_invoked=post_invoked,
                    synthetic=synthetic)
    except Exception:
        return _out('UNKNOWN', 'UNEXPECTED_FAILURE', operation=operation,
                    reservation_confirmed=reservation_confirmed, attempt_recorded=recorded, post_invoked=post_invoked,
                    synthetic=synthetic)
