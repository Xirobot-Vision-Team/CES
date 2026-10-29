#!/usr/bin/env python3
"""EC219: independently authorized, bounded, read-only reconciliation of EC218 UNKNOWN.

A previously consumed EC218 attempt is not permission to POST again. This
module reads the *original trusted attempt ledger*, historically verifies the
original full EC214-217 plan and signature against the attempt timestamp, then
requires a NEW exact host credential/network/full-content read approval. It
uses only bounded official GitHub/GitLab HTTPS GETs. A fresh repository GET
before and after paged search pins ID, path, privacy and Issue visibility.

A sole exact-time/title/body/label match is an independently reread *remote
candidate*, not proof that this EC218 POST caused its creation. The match is
recorded in a distinct durable local ledger; no API here authorizes another
POST, an Issue edit, or an absence claim. All errors and hidden/ambiguous
results are UNKNOWN. A forged local result cannot be used as an attempt.

No live credentials or real Issue requests are included in this package.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import socket
import sqlite3
import ssl
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, ProxyHandler, HTTPSHandler, build_opener

try:
    from . import issue_create_write as cw
    from . import issue_create_grant as cg
    from . import issue_provider as ip
    from . import issue_eligibility as ie
    from . import issue_existing_readonly as er
except ImportError:
    import issue_create_write as cw
    import issue_create_grant as cg
    import issue_provider as ip
    import issue_eligibility as ie
    import issue_existing_readonly as er

SCHEMA = 'ces.issue_unknown_recheck.v1'
EVIDENCE_DOMAIN = b'CES-EC219-VERIFIED-REMOTE-CANDIDATE-v1\x00'
PAGE_SIZE = 50
MAX_PAGES = 3
MAX_CANDIDATES = 8
MAX_GETS = 2 + MAX_PAGES + MAX_CANDIDATES
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_TIMEOUT = 8.0
MAX_READ_GRANT_SECONDS = 120
MAX_POST_WINDOW_SECONDS = 120
MAX_PROVIDER_CLOCK_SKEW_SECONDS = 2
# No automatic POST, even if all 150 list entries were read.


class RecheckError(ValueError):
    def __init__(self, code: str, state: str = 'UNKNOWN') -> None:
        super().__init__(code)
        self.code, self.state = code, state


def _need(ok: bool, code: str, state: str = 'UNKNOWN') -> None:
    if not ok:
        raise RecheckError(code, state)


@dataclass(frozen=True)
class HostRecheckAccess:
    """Host-attested current read rights, independent of EC217 CREATE rights.

    Must be assembled by a trusted operator/host after confirming the real
    account has permission for private/confidential content. Not user JSON.
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
    read_issue_metadata_opt_in: bool
    read_full_issue_content_opt_in: bool
    current_provider_credentials_attested_by_host: bool
    private_content_visibility_attested_by_host: bool


@dataclass(frozen=True)
class PriorAttempt:
    operation_sha256: str
    challenge_sha256: str
    started_at_utc: str
    outcome: str


class TrustedAttemptReader(Protocol):
    audience: str
    def read_attempt(self, operation_sha256: str, grant_id: str) -> PriorAttempt | None: ...


class DurableRecheckLedger(Protocol):
    audience: str
    def record_candidate(self, operation_sha256: str, grant_id: str,
                         identity_sha256: str, evidence_sha256: str,
                         observed_at: datetime) -> str: ...


@dataclass(frozen=True)
class ReadResponse:
    """JSON payload + sanitized header hints, never raw response headers."""
    payload: dict[str, Any] | list[Any]
    headers: dict[str, str]


class ReadOnlyTransport(Protocol):
    def get_json(self, url: str, headers: dict[str, str], timeout: float) -> ReadResponse: ...


class SQLiteCreateAttemptReader:
    """Read exact EC218 persistent attempt, never CREATE or upgrade its state.

    POSIX single-host trusted local volume ONLY, same path as EC218's writer.
    A missing DB never gets created by this reader. Grant ID and audience are
    bound via the exact EC218 domain-separated grant-key SHA.
    """
    def __init__(self, path: str | Path, audience: str):
        self.path, self.audience = Path(path), audience

    def read_attempt(self, operation_sha256: str, grant_id: str) -> PriorAttempt | None:
        if (type(self.audience) is not str or not cg.AUDIENCE.fullmatch(self.audience) or
                type(operation_sha256) is not str or not ie.HEX.fullmatch(operation_sha256) or
                type(grant_id) is not str or not cg.GRANT_ID.fullmatch(grant_id) or
                not cw._private_db(self.path, may_create=False)):
            return None
        grant_key = hashlib.sha256(cw.GRANT_DOMAIN + self.audience.encode('ascii') +
                                   bytes.fromhex(grant_id)).hexdigest()
        try:
            with closing(cw._reader_connection(self.path)) as db:
                rows = db.execute(
                    'SELECT operation_key, challenge_sha256, started_at_utc, outcome '
                    'FROM issue_create_attempt WHERE operation_key=? AND grant_key=? LIMIT 2',
                    (operation_sha256, grant_key)).fetchall()
            if len(rows) != 1:
                return None
            op, challenge, started, outcome = rows[0]
            if (op != operation_sha256 or type(challenge) is not str or
                    not ie.HEX.fullmatch(challenge) or type(started) is not str or
                    type(outcome) is not str):
                return None
            return PriorAttempt(op, challenge, started, outcome)
        except (sqlite3.Error, OSError, TypeError, ValueError):
            return None


class SQLiteRecheckLedger:
    """Append-only positive candidate observations; separate from EC218.

    A conflicting second remote candidate cannot overwrite a prior record.
    This local single-host SQLite example does NOT provide NFS or hostile
    filesystem guarantees. Never store raw title, body, token, or repo name.
    """
    def __init__(self, path: str | Path, audience: str):
        self.path, self.audience = Path(path), audience

    def record_candidate(self, operation_sha256: str, grant_id: str,
                         identity_sha256: str, evidence_sha256: str,
                         observed_at: datetime) -> str:
        if (type(self.audience) is not str or not cg.AUDIENCE.fullmatch(self.audience) or
                any(type(s) is not str or not ie.HEX.fullmatch(s) for s in
                    (operation_sha256, identity_sha256, evidence_sha256)) or
                type(grant_id) is not str or not cg.GRANT_ID.fullmatch(grant_id) or
                type(observed_at) is not datetime or observed_at.tzinfo is None or
                not cw._private_db(self.path, may_create=True)):
            return 'UNAVAILABLE'
        grant_key = hashlib.sha256(cw.GRANT_DOMAIN + self.audience.encode('ascii') +
                                   bytes.fromhex(grant_id)).hexdigest()
        try:
            with closing(sqlite3.connect(str(self.path), isolation_level=None, timeout=5)) as db:
                db.execute('PRAGMA busy_timeout=5000')
                db.execute('PRAGMA journal_mode=DELETE')
                db.execute('PRAGMA synchronous=FULL')
                db.execute('BEGIN IMMEDIATE')
                db.execute('CREATE TABLE IF NOT EXISTS issue_recheck_candidate ('
                           'operation_key TEXT PRIMARY KEY NOT NULL, '
                           'grant_key TEXT NOT NULL, identity_sha256 TEXT NOT NULL, '
                           'evidence_sha256 TEXT NOT NULL, observed_at_utc TEXT NOT NULL)')
                rows = db.execute('SELECT grant_key, identity_sha256, evidence_sha256 '
                                  'FROM issue_recheck_candidate WHERE operation_key=?',
                                  (operation_sha256,)).fetchall()
                if rows:
                    db.execute('ROLLBACK')
                    return ('ALREADY_RECORDED' if len(rows) == 1 and rows[0] ==
                            (grant_key, identity_sha256, evidence_sha256) else 'CONFLICT')
                db.execute('INSERT INTO issue_recheck_candidate VALUES (?,?,?,?,?)',
                           (operation_sha256, grant_key, identity_sha256,
                            evidence_sha256, observed_at.isoformat()))
                db.execute('COMMIT')
            return 'COMMITTED'
        except (sqlite3.Error, OSError, ValueError, TypeError):
            return 'UNAVAILABLE'


def _stamp(raw: str) -> datetime:
    """Read EC218 timestamp stored as datetime.isoformat(), not forged wall time."""
    try:
        _need(type(raw) is str and len(raw) <= 40, 'PRIOR_ATTEMPT_CLOCK_INVALID')
        stamp = datetime.fromisoformat(raw)
        _need(stamp.tzinfo is not None and stamp.utcoffset() is not None and
              2000 <= stamp.year <= 9998, 'PRIOR_ATTEMPT_CLOCK_INVALID')
        return stamp.astimezone(timezone.utc)
    except (ValueError, OverflowError, TypeError):
        raise RecheckError('PRIOR_ATTEMPT_CLOCK_INVALID') from None


def _permit(access: HostRecheckAccess | None, intent: cg.IssueCreateIntent,
            now: datetime) -> None:
    _need(type(access) is HostRecheckAccess, 'INDEPENDENT_READ_ACCESS_REQUIRED', 'BLOCKED')
    _need(type(access.expected_repository_id) is int and
          all(type(getattr(access, k)) is str for k in
              ('provider', 'api_host', 'account_ref', 'repository', 'visibility',
               'policy_revision_sha256', 'audience', 'expires_at_utc')),
          'READ_ACCESS_SHAPE_INVALID', 'INVALID_INPUT')
    _need(all(getattr(access, k) is True for k in
              ('network_opt_in', 'read_issue_metadata_opt_in',
               'read_full_issue_content_opt_in',
               'current_provider_credentials_attested_by_host',
               'private_content_visibility_attested_by_host')),
          'NETWORK_PRIVATE_CONTENT_READ_NOT_APPROVED', 'BLOCKED')
    _need((access.provider, access.api_host, access.account_ref, access.repository,
           access.expected_repository_id, access.visibility,
           access.policy_revision_sha256, access.audience) ==
          (intent.provider, intent.api_host, intent.account_ref, intent.repository,
           intent.expected_repository_id, intent.visibility,
           intent.policy_revision_sha256, intent.audience) and
          intent.api_host == ip.API_HOST.get(intent.provider),
          'READ_ACCESS_SCOPE_DRIFT', 'BLOCKED')
    try:
        expires = cw._at(access.expires_at_utc)
    except cw.WriteError:
        raise RecheckError('READ_ACCESS_DEADLINE_INVALID', 'INVALID_INPUT') from None
    _need(now < expires <= now + timedelta(seconds=MAX_READ_GRANT_SECONDS),
          'READ_ACCESS_EXPIRED', 'BLOCKED')


def _allowed_get(url: str) -> bool:
    """Shared EC220 audited GET-only route profile for EC219."""
    return er.allow_issue_http('GET', url, profile='EC219_RECHECK')


class StrictHTTPSIssueReadTransport:
    """Official-host GET only, no proxy, redirect, cache, retry or mutation."""
    def get_json(self, url: str, headers: dict[str, str], timeout: float) -> ReadResponse:
        _need(_allowed_get(url) and
              er.allow_issue_http('GET', url, profile='EC219_RECHECK', headers=headers),
              'ENDPOINT_NOT_ALLOWLISTED', 'BLOCKED')
        _need(type(timeout) in (int, float) and 0 < timeout <= MAX_TIMEOUT,
              'READ_TIMEOUT_INVALID', 'INVALID_INPUT')
        opener = build_opener(ProxyHandler({}), cw._NoRedirect(),
                              HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(Request(url, headers=headers, method='GET'), timeout=timeout) as r:
                _need(r.status == 200 and r.geturl() == url,
                      'PROVIDER_READ_RESPONSE_UNCERTAIN')
                kind = r.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                _need(kind == 'application/json' or
                      (kind.startswith('application/') and kind.endswith('+json')),
                      'PROVIDER_READ_NOT_JSON')
                length = r.headers.get('Content-Length')
                _need(not (length and length.isdecimal() and
                           int(length) > MAX_RESPONSE_BYTES), 'PROVIDER_READ_TOO_LARGE')
                blob = r.read(MAX_RESPONSE_BYTES + 1)
                _need(len(blob) <= MAX_RESPONSE_BYTES, 'PROVIDER_READ_TOO_LARGE')
                try:
                    def reject(_: str) -> None:
                        raise ValueError('nonfinite')
                    data = json.loads(blob.decode('utf-8', 'strict'),
                                      object_pairs_hook=ip._unique,
                                      parse_constant=reject)
                    _need(type(data) in (dict, list), 'PROVIDER_READ_JSON_INVALID')
                except (ValueError, UnicodeError, RecursionError, MemoryError):
                    raise RecheckError('PROVIDER_READ_JSON_INVALID') from None
                # Never return raw headers that might carry sensitive values.
                return ReadResponse(data, {})
        except HTTPError:
            # 404/403 may hide private/confidential Issues. No absence assertion.
            raise RecheckError('PROVIDER_READ_HTTP_UNCERTAIN') from None
        except (URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError):
            raise RecheckError('PROVIDER_READ_NETWORK_UNCERTAIN') from None


def _urls(intent: cg.IssueCreateIntent, number: int | None = None,
          page: int | None = None) -> str:
    repo, issue_list = cw._urls(intent)
    if number is not None:
        _need(type(number) is int and 0 < number <= 2147483647,
              'ISSUE_NUMBER_INVALID')
        return issue_list + '/' + str(number)
    if page is not None:
        _need(type(page) is int and 1 <= page <= MAX_PAGES,
              'READ_PAGE_OUT_OF_BOUNDS')
        if intent.provider == 'github':
            return (issue_list + '?state=all&sort=created&direction=desc&per_page=50&page='
                    + str(page))
        return (issue_list + '?scope=all&state=all&order_by=created_at&sort=desc'
                '&per_page=50&page=' + str(page))
    return repo


def _repo_matches(raw: Any, intent: cg.IssueCreateIntent) -> None:
    _need(type(raw) is dict and '_ces_fixture' not in raw, 'REPOSITORY_RESPONSE_INVALID')
    _need(ip._positive_id(raw.get('id')) and
          raw['id'] == intent.expected_repository_id, 'REPOSITORY_ID_DRIFT')
    path = raw.get('full_name' if intent.provider == 'github' else 'path_with_namespace')
    _need(type(path) is str and path == intent.repository, 'REPOSITORY_PATH_DRIFT')
    if intent.provider == 'github':
        private, enabled = raw.get('private'), raw.get('has_issues')
        _need(type(private) is bool and type(enabled) is bool,
              'REPOSITORY_VISIBILITY_UNKNOWN')
        visibility = 'PRIVATE' if private else 'PUBLIC'
    else:
        visibility = {'private': 'PRIVATE', 'public': 'PUBLIC'}.get(raw.get('visibility'))
        enabled = raw.get('issues_enabled')
        _need(visibility is not None and type(enabled) is bool,
              'REPOSITORY_VISIBILITY_UNKNOWN')
    _need(visibility == intent.visibility, 'REPOSITORY_VISIBILITY_DRIFT')
    _need(enabled is True, 'REPOSITORY_ISSUES_NOT_VISIBLE')
    # An archive may still have readable issues: do not require it unarchived.


def _list_identity(raw: Any, intent: cg.IssueCreateIntent) -> tuple[int, int, datetime] | None:
    """Return candidate ID/local-number/time for exact-title list entries."""
    _need(type(raw) is dict and '_ces_fixture' not in raw,
          'PROVIDER_LIST_ENTRY_UNVERIFIED')
    if intent.provider == 'github' and 'pull_request' in raw:
        return None  # GitHub GET /issues also contains pull requests.
    if intent.provider == 'github':
        num, scope = raw.get('number'), raw.get('repository_url')
        expected_repo = _urls(intent)
        _need(scope == expected_repo, 'PROVIDER_LIST_REPOSITORY_UNVERIFIED')
    else:
        num, scope = raw.get('iid'), raw.get('project_id')
        _need(type(scope) is int and scope == intent.expected_repository_id,
              'PROVIDER_LIST_REPOSITORY_UNVERIFIED')
    _need(ip._positive_id(raw.get('id')) and
          type(num) is int and 0 < num <= 2147483647,
          'PROVIDER_LIST_ISSUE_ID_UNVERIFIED')
    try:
        created = ie._time(raw.get('created_at'))
    except (ie.EligibilityError, ValueError, TypeError):
        raise RecheckError('PROVIDER_ISSUE_TIME_UNVERIFIED') from None
    return raw['id'], num, created


def _exact_detail(raw: Any, listed: tuple[int, int, datetime],
                  intent: cg.IssueCreateIntent, content: cg.FinalIssueContent,
                  started: datetime, now: datetime,
                  original_challenge_sha256: str) -> tuple[str, str]:
    _need(type(raw) is dict and '_ces_fixture' not in raw,
          'PROVIDER_DETAIL_INVALID')
    issue_id, number, created = listed
    _need(ip._positive_id(raw.get('id')) and raw['id'] == issue_id,
          'PROVIDER_DETAIL_ID_CHANGED')
    if intent.provider == 'github':
        _need('pull_request' not in raw and type(raw.get('number')) is int and
              raw['number'] == number and raw.get('state') in ('open', 'closed') and
              raw.get('repository_url') == _urls(intent) and
              raw.get('url') == _urls(intent, number=number),
              'PROVIDER_DETAIL_TARGET_CHANGED')
        label_objects = raw.get('labels')
        _need(type(label_objects) is list and all(
              type(x) is dict and type(x.get('name')) is str for x in label_objects),
              'PROVIDER_DETAIL_LABELS_UNVERIFIED')
        names = [x['name'] for x in label_objects]
        body = raw.get('body')
    else:
        _need(type(raw.get('project_id')) is int and
              raw['project_id'] == intent.expected_repository_id and
              type(raw.get('iid')) is int and raw['iid'] == number and
              raw.get('state') in ('opened', 'closed') and
              raw.get('confidential') is (intent.visibility == 'PRIVATE'),
              'PROVIDER_DETAIL_TARGET_OR_PRIVACY_CHANGED')
        names = raw.get('labels')
        body = raw.get('description')
    try:
        seen = ie._time(raw.get('created_at'))
    except (ie.EligibilityError, ValueError, TypeError):
        raise RecheckError('PROVIDER_DETAIL_TIME_UNVERIFIED') from None
    _need(seen == created and started - timedelta(seconds=MAX_PROVIDER_CLOCK_SKEW_SECONDS)
          <= seen <= started + timedelta(seconds=MAX_POST_WINDOW_SECONDS) and
          seen <= now + timedelta(seconds=MAX_PROVIDER_CLOCK_SKEW_SECONDS),
          'PROVIDER_DETAIL_TIME_MISMATCH')
    _need(raw.get('title') == content.title and type(body) is str and
          body == content.body and type(names) is list and
          all(type(x) is str for x in names) and
          len(names) == len(content.labels) and sorted(names) == list(content.labels),
          'PROVIDER_DETAIL_SOURCE_OR_CONTENT_MISMATCH')
    identity = hashlib.sha256(cw.IDENTITY_DOMAIN + ip._canonical({
        'provider': intent.provider, 'repository_id': str(intent.expected_repository_id),
        'issue_id': str(issue_id), 'issue_number': str(number)})).hexdigest()
    evidence = hashlib.sha256(EVIDENCE_DOMAIN + ip._canonical({
        'operation_sha256': cw.operation_sha256(intent),
        'original_challenge_sha256': original_challenge_sha256,
        'issue_identity_sha256': identity,
        'approved_content_sha256': intent.expected_final_content_sha256,
        'started_at_utc': started.isoformat(),
        'provider_created_at_utc': seen.isoformat(),
        'verification': 'full_remote_detail_exact_time_title_body_labels_target_privacy',
    })).hexdigest()
    return identity, evidence


def _out(state: str, reason: str, *, operation: str | None = None,
         reads: int = 0, attempted: bool = False, synthetic: bool = False,
         candidate_identity: str | None = None, recorded: bool = False,
         old_attempt_confirmed: bool = False) -> dict[str, Any]:
    status = 'invalid_input' if state == 'INVALID_INPUT' else (
        'unavailable' if state == 'UNKNOWN' else 'partial')
    provider_verified = state == 'REMOTE_EXACT_CANDIDATE_OBSERVED' and not synthetic and recorded
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': {'invalid_input': 4, 'unavailable': 5, 'partial': 2}[status],
        'reason_code': 'ISSUE_UNKNOWN_RECHECK_' + reason,
        'recheck_state': state, 'operation_sha256': operation,
        'provider_issue_identity_sha256': candidate_identity if provider_verified else None,
        'prior_ec218_attempt_confirmed': old_attempt_confirmed,
        'provider_get_attempted': attempted, 'provider_get_count': reads,
        'provider_private_content_may_have_been_read': bool(attempted and reads > 1 and not synthetic),
        'max_provider_get_count': MAX_GETS,
        'synthetic': synthetic,
        'remote_exact_candidate_observed': provider_verified,
        'remote_candidate_durable_recorded': provider_verified,
        'issue_creation_attributed_to_ec218_attempt': False,
        'issue_created': False,
        'provider_post_invoked': False, 'issue_mutated': False,
        'second_create_attempt_authorized': False,
        'all_issues_enumerated': False, 'hidden_issues_ruled_out': False,
        'duplicate_absence_proven': False,
        'business_repository_written': False, 'git_or_knowledge_written': False,
        'external_ai_called': False, 'published_or_delivered': False,
        'native_issue_action_registered': False,
        'organizational_authority_independently_authenticated_by_ces': False,
        'safe_next_step': 'NEVER_REPOST_OR_EDIT_FROM_RECHECK_RESULT',
    }


def recheck_unknown_issue(
        evidence: cg.PlanEvidence, intent: cg.IssueCreateIntent,
        content: cg.FinalIssueContent, approval: cg.HumanCreateApproval, *,
        trusted_eligibility_review_keys: Mapping[str, bytes] | None,
        trusted_historical_issuers: Mapping[str, cg.IssuerAuthority] | None,
        original_attempts: TrustedAttemptReader | None,
        observation_ledger: DurableRecheckLedger | None,
        host_access: HostRecheckAccess | None,
        token_supplier: Callable[[], str | None] | None,
        transport: ReadOnlyTransport | None = None,
        clock: Callable[[], datetime] | None = None,
        timeout: float = MAX_TIMEOUT) -> dict[str, Any]:
    """Recheck only an EC218 POSSIBLY_SENT/POST_UNKNOWN in a new read window.

    At most 13 official GETs; zero remote or business mutations. Historical
    replay verifies original signing at the *trusted ledger attempt instant*;
    it is NOT permission to create now. A custom clock requires an injected
    transport. Synthetic results never commit remote candidate evidence.
    """
    synthetic = transport is not None or clock is not None
    operation = None
    reads = 0
    old_confirmed = False
    try:
        _need(clock is None or transport is not None,
              'CUSTOM_CLOCK_REQUIRES_SYNTHETIC_TRANSPORT', 'BLOCKED')
        _need(type(intent) is cg.IssueCreateIntent and
              type(content) is cg.FinalIssueContent and
              type(approval) is cg.HumanCreateApproval,
              'ORIGINAL_APPROVED_INPUT_REQUIRED', 'INVALID_INPUT')
        _need(type(timeout) in (float, int) and 0 < timeout <= MAX_TIMEOUT,
              'READ_TIMEOUT_INVALID', 'INVALID_INPUT')
        now = cw._clock_now(clock)
        _permit(host_access, intent, now)
        operation = cw.operation_sha256(intent)
        _need(original_attempts is not None and
              getattr(original_attempts, 'audience', None) == intent.audience and
              callable(getattr(original_attempts, 'read_attempt', None)),
              'TRUSTED_ORIGINAL_ATTEMPT_READER_REQUIRED', 'BLOCKED')
        try:
            prior = original_attempts.read_attempt(operation, approval.grant_id)
        except Exception:
            raise RecheckError('ORIGINAL_ATTEMPT_UNAVAILABLE') from None
        _need(type(prior) is PriorAttempt and prior.operation_sha256 == operation,
              'ORIGINAL_ATTEMPT_NOT_CONFIRMED', 'BLOCKED')
        _need(prior.outcome in ('POSSIBLY_SENT', 'POST_UNKNOWN'),
              'ORIGINAL_OUTCOME_NOT_UNKNOWN', 'BLOCKED')
        _need(type(prior.challenge_sha256) is str and
              ie.HEX.fullmatch(prior.challenge_sha256) is not None,
              'ORIGINAL_CHALLENGE_INVALID')
        started = _stamp(prior.started_at_utc)
        _need(started <= now, 'ORIGINAL_ATTEMPT_IN_FUTURE')
        # Historical cryptographic/evidence verification has NO new create
        # authority. The immutable ledger timestamp is not substituted for
        # today's clock when authorizing remote/private data access.
        challenge, grant_id, _ = cg._inspect(
            evidence, intent, content, approval,
            trusted_eligibility_review_keys, trusted_historical_issuers,
            clock=lambda: started)
        _need(grant_id == approval.grant_id and
              challenge['challenge_sha256'] == prior.challenge_sha256,
              'ORIGINAL_APPROVAL_OR_CONTENT_DRIFT', 'BLOCKED')
        old_confirmed = True
        _need(observation_ledger is not None and
              getattr(observation_ledger, 'audience', None) == intent.audience and
              callable(getattr(observation_ledger, 'record_candidate', None)),
              'DURABLE_OBSERVATION_LEDGER_REQUIRED', 'BLOCKED')
        _need(callable(token_supplier), 'HOST_TOKEN_SUPPLIER_REQUIRED', 'BLOCKED')
        try:
            token = token_supplier()
        except Exception:
            raise RecheckError('PROVIDER_TOKEN_UNAVAILABLE', 'BLOCKED') from None
        _need(type(token) is str and ip.TOKEN.fullmatch(token),
              'PROVIDER_TOKEN_UNAVAILABLE', 'BLOCKED')
        headers = cw._headers(intent.provider, token)
        headers.pop('Content-Type', None)
        headers['User-Agent'] = 'CES-EC219-readonly-recheck/1'
        headers['Cache-Control'] = 'no-store'
        headers['Pragma'] = 'no-cache'
        active = transport if transport is not None else StrictHTTPSIssueReadTransport()
        _need(callable(getattr(active, 'get_json', None)),
              'READ_TRANSPORT_UNAVAILABLE', 'BLOCKED')

        def read(url: str) -> ReadResponse:
            nonlocal reads
            _permit(host_access, intent, cw._clock_now(clock))
            _need(reads < MAX_GETS, 'REMOTE_READ_BUDGET_EXHAUSTED')
            _need(_allowed_get(url) and
              er.allow_issue_http('GET', url, profile='EC219_RECHECK', headers=headers),
              'ENDPOINT_NOT_ALLOWLISTED', 'BLOCKED')
            reads += 1
            result = active.get_json(url, headers, float(timeout))
            _need(type(result) is ReadResponse and
                  type(result.headers) is dict and
                  type(result.payload) in (dict, list), 'REMOTE_RESPONSE_INVALID')
            _need(len(ip._canonical(result.payload)) <= MAX_RESPONSE_BYTES,
                  'REMOTE_RESPONSE_TOO_LARGE')
            return result

        _repo_matches(read(_urls(intent)).payload, intent)
        candidates: dict[tuple[int, int], tuple[int, int, datetime]] = {}
        ambiguous = False
        # Bounded scan only. Even if an empty page is encountered, lack of a
        # candidate can NEVER prove an Issue was absent or that listing is full.
        for page in range(1, MAX_PAGES + 1):
            entries = read(_urls(intent, page=page)).payload
            _need(type(entries) is list and len(entries) <= PAGE_SIZE,
                  'REMOTE_PAGE_UNVERIFIED')
            for row in entries:
                _need(type(row) is dict and '_ces_fixture' not in row,
                      'REMOTE_PAGE_ENTRY_INVALID')
                if intent.provider == 'github' and 'pull_request' in row:
                    continue
                title = row.get('title')
                if type(title) is not str:
                    ambiguous = True
                    continue
                if title != content.title:
                    continue
                try:
                    listed = _list_identity(row, intent)
                except RecheckError:
                    ambiguous = True
                    continue
                if listed is None:
                    continue
                issue_id, number, when = listed
                if not (started - timedelta(seconds=MAX_PROVIDER_CLOCK_SKEW_SECONDS)
                        <= when <= started + timedelta(seconds=MAX_POST_WINDOW_SECONDS)):
                    ambiguous = True  # Same name with unrelated creation time.
                    continue
                key = (issue_id, number)
                if key not in candidates:
                    candidates[key] = listed
                if len(candidates) > MAX_CANDIDATES:
                    ambiguous = True
                    break
            if len(candidates) > MAX_CANDIDATES or not entries:
                break

        matches: dict[str, str] = {}
        if not ambiguous:
            for _, listed in candidates.items():
                details = read(_urls(intent, number=listed[1])).payload
                try:
                    identity, proof = _exact_detail(details, listed, intent, content,
                                                    started, cw._clock_now(clock),
                                                    prior.challenge_sha256)
                    matches[identity] = proof
                except RecheckError:
                    ambiguous = True
                    break
        # Double-read target after search to reject rename/privacy/drift and
        # ensure a match has not been attributed to a different repository.
        _repo_matches(read(_urls(intent)).payload, intent)
        _permit(host_access, intent, cw._clock_now(clock))
        if ambiguous:
            return _out('UNKNOWN', 'AMBIGUOUS_OR_SOURCE_MISMATCH', operation=operation,
                        reads=reads, attempted=True, synthetic=synthetic,
                        old_attempt_confirmed=old_confirmed)
        if len(matches) != 1:
            return _out('UNKNOWN', 'NO_UNIQUE_EXACT_MATCH_IN_BOUNDED_READ',
                        operation=operation, reads=reads, attempted=True,
                        synthetic=synthetic, old_attempt_confirmed=old_confirmed)
        identity, proof = next(iter(matches.items()))
        if synthetic:
            return _out('SIMULATED_EXACT_CANDIDATE', 'INJECTED_DATA_NOT_REMOTE_PROOF',
                        operation=operation, reads=reads, attempted=True,
                        synthetic=True, old_attempt_confirmed=True)
        try:
            saved = observation_ledger.record_candidate(
                operation, approval.grant_id, identity, proof, cw._clock_now(),)
        except Exception:
            saved = 'UNAVAILABLE'
        if saved not in ('COMMITTED', 'ALREADY_RECORDED'):
            return _out('UNKNOWN', 'OBSERVATION_STORAGE_CONFLICT_OR_UNAVAILABLE',
                        operation=operation, reads=reads, attempted=True,
                        old_attempt_confirmed=True)
        return _out('REMOTE_EXACT_CANDIDATE_OBSERVED',
                    'DURABLE_REMOTE_CANDIDATE_NO_CAUSAL_PROOF', operation=operation,
                    reads=reads, attempted=True, candidate_identity=identity,
                    recorded=True, old_attempt_confirmed=True)
    except cg.GrantError as exc:
        return _out('BLOCKED' if exc.state in ('BLOCKED', 'NEEDS_REVIEW') else 'UNKNOWN',
                    'HISTORICAL_EC217_' + exc.code, operation=operation,
                    reads=reads, attempted=reads > 0, synthetic=synthetic,
                    old_attempt_confirmed=old_confirmed)
    except (cw.WriteError, ip.IssueError) as exc:
        return _out('UNKNOWN', 'ORIGINAL_INPUT_OR_HOST_CONTEXT_INVALID',
                    operation=operation, reads=reads, attempted=reads > 0,
                    synthetic=synthetic, old_attempt_confirmed=old_confirmed)
    except RecheckError as exc:
        return _out(exc.state, exc.code, operation=operation,
                    reads=reads, attempted=reads > 0, synthetic=synthetic,
                    old_attempt_confirmed=old_confirmed)
    except Exception:
        return _out('UNKNOWN', 'UNEXPECTED_READ_FAILURE', operation=operation,
                    reads=reads, attempted=reads > 0, synthetic=synthetic,
                    old_attempt_confirmed=old_confirmed)
