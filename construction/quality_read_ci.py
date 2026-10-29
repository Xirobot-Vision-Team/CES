#!/usr/bin/env python3
"""EC182 QualityReadCI: authorized bounded read-only CI metadata from GH/GL.

Exactly selected project/run/attempt/job, HTTPS GET only, independent per-read
host scope grants, credential supplied out of band, fail-closed observations.
A provider's success/failure is an observed *claim*, never CES test execution,
a Git commit binding, a complete check run or an authenticated human actor.
The test-injected transport is always labelled SYNTHETIC, not live evidence.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
from urllib.parse import urlsplit

SCHEMA = 'ces.quality_read_ci.v1'
REASON = 'QUALITYREADCI_'
EXIT = {'partial': 2, 'invalid_input': 4, 'unavailable': 5}
DOMAIN = b'CES-EC182-CI-OBSERVATION-v1\x00'
MAX_BODY = 1024 * 1024
MAX_PAGES = 3
PAGE_SIZE = 100
MAX_TOTAL_REQUESTS = MAX_PAGES + 2  # GH run + paged attempt jobs + run recheck; GL four
MAX_TIMEOUT = 8.0
MAX_TOTAL_SECONDS = 35.0
MAX_AGE = 30 * 86400
CLOCK_SKEW = 30
SEGMENT = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\Z', re.ASCII)
BRANCH = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_./-]{0,159}\Z', re.ASCII)
SHA = re.compile(r'[a-fA-F0-9]{40}\Z', re.ASCII)
TOKEN = re.compile(r'[!-~]{1,4096}\Z', re.ASCII)
ENV_TOKENS = {'github': 'CES_QUALITY_GITHUB_TOKEN', 'gitlab': 'CES_QUALITY_GITLAB_TOKEN'}
GITHUB_RUN_STATUS = {'completed'}
GITHUB_CONCLUSION = {'success', 'failure'}
GITLAB_RUN_STATUS = {'success', 'failed'}
GITLAB_JOB_STATUS = {'success', 'failed'}


class CIError(ValueError):
    """Opaque stable refusal code; never retain secrets or HTTP payload."""
    def __init__(self, reason: str, status: str = 'unavailable') -> None:
        super().__init__(REASON + reason)
        self.reason = REASON + reason
        self.status = status


def need(condition: bool, reason: str, status: str = 'unavailable') -> None:
    if not condition:
        raise CIError(reason, status)


def _canon(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def _hash(value: Any) -> str:
    return hashlib.sha256(DOMAIN + _canon(value)).hexdigest()


@dataclass(frozen=True)
class CISelection:
    provider: str
    repository: str  # GitHub owner/repo or GitLab group/project; never a URL
    project_id: int  # immutable provider repository/project ID
    workflow_id: int | None  # GH workflow ID; GL has no equivalent
    run_id: int  # GH workflow run or GL pipeline ID
    attempt: int | None  # GH run_attempt only; GL job IDs are per retry
    job_id: int
    branch: str  # explicit branch name; no refs/ prefix or implicit PR merge
    commit_sha: str  # observed exact API field equality, NOT EC183 Git binding
    max_result_age_seconds: int  # deliberate host/operator freshness budget


class ReadTransport(Protocol):
    def get(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int,
                         msg: str, headers: Any, newurl: str) -> None:
        return None


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for k, v in pairs:
        if k in result:
            raise ValueError('duplicate')
        result[k] = v
    return result


def _json_object(raw: bytes) -> dict[str, Any]:
    def no_constant(_: str) -> None:
        raise ValueError('nonfinite')
    try:
        value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_unique,
                           parse_constant=no_constant)
        need(type(value) is dict, 'PROVIDER_PAYLOAD_INVALID')
        return value
    except (UnicodeError, ValueError, RecursionError, MemoryError):
        raise CIError('PROVIDER_PAYLOAD_INVALID') from None


class StrictHTTPSCITransport:
    """Real TLS GET: fixed public API hosts, never redirects/proxy/retries."""
    def get(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        need(type(url) is str and len(url) <= 512 and '#' not in url and
             '@' not in url and '%2f' not in url.lower(), 'ENDPOINT_REJECTED')
        parsed = urlsplit(url)
        need(parsed.scheme == 'https' and parsed.username is None and
             parsed.password is None and parsed.port is None and
             ((parsed.netloc == 'api.github.com' and
               parsed.path.startswith('/repos/')) or
              (parsed.netloc == 'gitlab.com' and
               parsed.path.startswith('/api/v4/projects/'))) and
             (not parsed.query or re.fullmatch(
                 r'per_page=100&page=[123]', parsed.query) is not None) and
             re.fullmatch(r'/[a-zA-Z0-9_./%-]+', parsed.path) is not None,
             'ENDPOINT_REJECTED')
        need(type(timeout) in (float, int) and 0 < timeout <= MAX_TIMEOUT,
             'TIMEOUT_INVALID', 'invalid_input')
        request = Request(url, method='GET', headers=headers)
        opener = build_opener(ProxyHandler({}), _NoRedirect(),
                              HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(request, timeout=timeout) as response:
                need(response.status == 200 and response.geturl() == url,
                     'ENDPOINT_REJECTED')
                ctype = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                need(ctype == 'application/json' or
                     (ctype.startswith('application/') and ctype.endswith('+json')),
                     'PROVIDER_PAYLOAD_INVALID')
                length = response.headers.get('Content-Length')
                need(not (length and length.isdecimal() and int(length) > MAX_BODY),
                     'PROVIDER_PAYLOAD_TOO_LARGE')
                raw = response.read(MAX_BODY + 1)
                need(len(raw) <= MAX_BODY, 'PROVIDER_PAYLOAD_TOO_LARGE')
                return _json_object(raw)
        except HTTPError as err:
            if 300 <= err.code < 400:
                raise CIError('REDIRECT_REFUSED') from None
            if err.code in (401, 403):
                raise CIError('PROVIDER_PERMISSION_DENIED') from None
            if err.code == 404:
                raise CIError('SOURCE_UNAVAILABLE_OR_INACCESSIBLE') from None
            if err.code == 429:
                raise CIError('PROVIDER_RATE_LIMITED') from None
            raise CIError('PROVIDER_HTTP_UNAVAILABLE') from None
        except (URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError):
            raise CIError('PROVIDER_NETWORK_UNAVAILABLE') from None


def _valid_id(value: Any) -> bool:
    return type(value) is int and 0 < value <= 2**63 - 1


def _selection(raw: CISelection) -> CISelection:
    need(type(raw) is CISelection, 'SCOPE_INVALID', 'invalid_input')
    need(type(raw.provider) is str and raw.provider in ENV_TOKENS,
         'PROVIDER_UNSUPPORTED', 'invalid_input')
    need(type(raw.repository) is str and 3 <= len(raw.repository) <= 240 and
         all(SEGMENT.fullmatch(p) and p not in ('.', '..')
             for p in raw.repository.split('/')) and
         (len(raw.repository.split('/')) == 2 if raw.provider == 'github'
          else 2 <= len(raw.repository.split('/')) <= 12),
         'REPOSITORY_INVALID', 'invalid_input')
    need(all(_valid_id(x) for x in (raw.project_id, raw.run_id, raw.job_id)),
         'IDENTIFIER_INVALID', 'invalid_input')
    if raw.provider == 'github':
        need(_valid_id(raw.workflow_id) and _valid_id(raw.attempt),
             'WORKFLOW_OR_ATTEMPT_REQUIRED', 'invalid_input')
    else:
        need(raw.workflow_id is None and raw.attempt is None,
             'GITLAB_UNSUPPORTED_WORKFLOW_ATTEMPT', 'invalid_input')
    need(type(raw.branch) is str and BRANCH.fullmatch(raw.branch) is not None and
         '..' not in raw.branch and '//' not in raw.branch and not raw.branch.endswith('/') and
         not raw.branch.endswith('.') and not raw.branch.endswith('.lock') and
         not any(c in raw.branch for c in ('@{', '/.', './')),
         'BRANCH_INVALID', 'invalid_input')
    need(type(raw.commit_sha) is str and SHA.fullmatch(raw.commit_sha) is not None and
         any(c != '0' for c in raw.commit_sha),
         'COMMIT_FIELD_INVALID', 'invalid_input')
    need(type(raw.max_result_age_seconds) is int and
         60 <= raw.max_result_age_seconds <= MAX_AGE,
         'FRESHNESS_BUDGET_INVALID', 'invalid_input')
    return CISelection(**{**vars(raw), 'commit_sha': raw.commit_sha.lower()})


def _time(value: Any) -> datetime:
    need(type(value) is str and 20 <= len(value) <= 35 and
         re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)',
                      value) is not None,
         'PROVIDER_TIMESTAMP_INVALID')
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        need(stamp.utcoffset() is not None, 'PROVIDER_TIMESTAMP_INVALID')
        return stamp.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise CIError('PROVIDER_TIMESTAMP_INVALID') from None


def _fmt(stamp: datetime) -> str:
    return stamp.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _now(clock: Callable[[], datetime] | None) -> datetime:
    try:
        value = clock() if clock else datetime.now(timezone.utc)
        need(type(value) is datetime and value.tzinfo is not None and
             value.utcoffset() is not None, 'CLOCK_INVALID', 'invalid_input')
        value = value.astimezone(timezone.utc)
        need(2000 <= value.year <= 9998, 'CLOCK_INVALID', 'invalid_input')
        return value
    except CIError:
        raise
    except Exception:
        raise CIError('CLOCK_UNAVAILABLE') from None


def _fresh(stamp: datetime, now: datetime, budget: int) -> None:
    need(stamp <= now + timedelta(seconds=CLOCK_SKEW), 'FUTURE_PROVIDER_TIMESTAMP')
    need(now - stamp <= timedelta(seconds=budget), 'STALE_CI_RESULT')


def _string(value: Any, limit: int = 200) -> str:
    need(type(value) is str and 0 < len(value) <= limit and
         all(32 <= ord(x) <= 126 for x in value), 'PROVIDER_FIELD_INVALID')
    return value


def _remote_sha(value: Any) -> str:
    need(type(value) is str and SHA.fullmatch(value) is not None and
         any(c != '0' for c in value), 'PROVIDER_COMMIT_INVALID')
    return value.lower()


def _status(value: Any, allowed: set[str], *, unit: str) -> str:
    need(type(value) is str and value in allowed, unit + '_NOT_FINAL')
    return value


def _safe_flags() -> dict[str, Any]:
    return {'read_only': True, 'network_get_only': True, 'executed_commands': False,
            'read_logs': False, 'read_artifacts': False, 'git_operations': False,
            'writes_performed': False}


def _empty(reason: str, status: str, *, request_count: int,
           synthetic: bool) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status, 'exit_code': EXIT[status],
        'reason_code': reason, 'source': None, 'observation': None,
        'permission': {'host_scope': 'NOT_ATTESTED', 'provider_read': 'NOT_ESTABLISHED',
                       'transport': 'SYNTHETIC' if synthetic else 'LIVE_HTTPS',
                       'credential_identity': 'NOT_ATTESTED'},
        'coverage': None, 'observation_sha256': None,
        'effects': {**_safe_flags(), 'transport_get_calls': request_count,
                    'live_network_get_requests': 0 if synthetic else request_count},
        'trust_boundary': 'CI_METADATA_ONLY_NO_LOCAL_GIT_SHA_BINDING_OR_EXECUTION',
    }


def _endpoints(s: CISelection) -> tuple[str, ...]:
    if s.provider == 'github':
        prefix = 'https://api.github.com/repos/' + s.repository
        return (f'{prefix}/actions/runs/{s.run_id}',
                f'{prefix}/actions/runs/{s.run_id}/attempts/{s.attempt}/jobs',
                f'{prefix}/actions/runs/{s.run_id}')
    prefix = f'https://gitlab.com/api/v4/projects/{s.project_id}'
    return (prefix, f'{prefix}/pipelines/{s.run_id}',
            f'{prefix}/jobs/{s.job_id}', f'{prefix}/pipelines/{s.run_id}')


def _headers(s: CISelection, token: str) -> dict[str, str]:
    common = {'Accept-Encoding': 'identity', 'User-Agent': 'CES-EC182-QualityReadCI/1'}
    if s.provider == 'github':
        return {**common, 'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2026-03-10',
                'Authorization': 'Bearer ' + token}
    return {**common, 'Accept': 'application/json', 'PRIVATE-TOKEN': token}


def _github_run(value: dict[str, Any], s: CISelection, now: datetime) -> dict[str, Any]:
    need(_valid_id(value.get('id')) and value['id'] == s.run_id and
         _valid_id(value.get('workflow_id')) and value['workflow_id'] == s.workflow_id and
         _valid_id(value.get('run_attempt')) and value['run_attempt'] == s.attempt,
         'RUN_IDENTITY_MISMATCH')
    repo = value.get('repository')
    need(type(repo) is dict and _valid_id(repo.get('id')) and
         repo.get('id') == s.project_id and
         type(repo.get('full_name')) is str and
         repo['full_name'].casefold() == s.repository.casefold(),
         'REPOSITORY_IDENTITY_MISMATCH')
    need(_string(value.get('head_branch'), 160) == s.branch, 'BRANCH_FIELD_MISMATCH')
    need(_remote_sha(value.get('head_sha')) == s.commit_sha, 'COMMIT_FIELD_MISMATCH')
    state = _status(value.get('status'), GITHUB_RUN_STATUS, unit='RUN')
    conclusion = _status(value.get('conclusion'), GITHUB_CONCLUSION, unit='RUN')
    created = _time(value.get('created_at'))
    updated = _time(value.get('updated_at'))
    need(created <= updated, 'PROVIDER_TIMESTAMP_ORDER_INVALID')
    _fresh(updated, now, s.max_result_age_seconds)
    need(created <= now + timedelta(seconds=CLOCK_SKEW), 'FUTURE_PROVIDER_TIMESTAMP')
    return {'state': state, 'conclusion': conclusion, 'created_at': _fmt(created),
            'updated_at': _fmt(updated), 'attempt': s.attempt}


def _github_jobs(raw_pages: list[dict[str, Any]], s: CISelection,
                 now: datetime) -> dict[str, Any]:
    count = None
    ids: set[int] = set()
    chosen = None
    for page in raw_pages:
        total = page.get('total_count')
        rows = page.get('jobs')
        need(type(total) is int and 0 <= total <= MAX_PAGES * PAGE_SIZE and
             type(rows) is list and len(rows) <= PAGE_SIZE,
             'JOBS_PAGE_INCOMPLETE_OR_AMBIGUOUS')
        if count is None:
            count = total
        need(count == total, 'JOBS_PAGE_CHANGED_DURING_READ')
        for item in rows:
            need(type(item) is dict and _valid_id(item.get('id')) and
                 item['id'] not in ids, 'JOBS_PAGE_INCOMPLETE_OR_AMBIGUOUS')
            ids.add(item['id'])
            if item['id'] == s.job_id:
                chosen = item
    need(count == len(ids), 'JOBS_PAGE_INCOMPLETE_OR_AMBIGUOUS')
    need(chosen is not None, 'JOB_NOT_IN_SELECTED_ATTEMPT')
    need(_valid_id(chosen.get('run_id')) and chosen.get('run_id') == s.run_id and
         _remote_sha(chosen.get('head_sha')) == s.commit_sha,
         'JOB_RUN_OR_COMMIT_MISMATCH')
    # Some Actions API versions omit head_branch in job responses; if present,
    # ensure it cannot contradict the run's branch.
    if chosen.get('head_branch') is not None:
        need(_string(chosen['head_branch'], 160) == s.branch, 'JOB_BRANCH_MISMATCH')
    state = _status(chosen.get('status'), {'completed'}, unit='JOB')
    conclusion = _status(chosen.get('conclusion'), GITHUB_CONCLUSION, unit='JOB')
    started = _time(chosen.get('started_at'))
    completed = _time(chosen.get('completed_at'))
    need(started <= completed, 'PROVIDER_TIMESTAMP_ORDER_INVALID')
    _fresh(completed, now, s.max_result_age_seconds)
    return {'state': state, 'conclusion': conclusion,
            'started_at': _fmt(started), 'completed_at': _fmt(completed),
            'allow_failure': None}


def _gitlab_project(data: dict[str, Any], s: CISelection) -> None:
    need(_valid_id(data.get('id')) and data.get('id') == s.project_id and
         type(data.get('path_with_namespace')) is str and
         data['path_with_namespace'].casefold() == s.repository.casefold(),
         'REPOSITORY_IDENTITY_MISMATCH')


def _gitlab_run(value: dict[str, Any], s: CISelection, now: datetime) -> dict[str, Any]:
    need(_valid_id(value.get('id')) and _valid_id(value.get('project_id')) and
         value.get('id') == s.run_id and value.get('project_id') == s.project_id,
         'RUN_IDENTITY_MISMATCH')
    need(_string(value.get('ref'), 160) == s.branch, 'BRANCH_FIELD_MISMATCH')
    need(_remote_sha(value.get('sha')) == s.commit_sha, 'COMMIT_FIELD_MISMATCH')
    state = _status(value.get('status'), GITLAB_RUN_STATUS, unit='RUN')
    created = _time(value.get('created_at'))
    updated = _time(value.get('updated_at'))
    need(created <= updated, 'PROVIDER_TIMESTAMP_ORDER_INVALID')
    _fresh(updated, now, s.max_result_age_seconds)
    need(created <= now + timedelta(seconds=CLOCK_SKEW), 'FUTURE_PROVIDER_TIMESTAMP')
    return {'state': state, 'conclusion': 'success' if state == 'success' else 'failure',
            'created_at': _fmt(created), 'updated_at': _fmt(updated),
            'attempt': None}


def _gitlab_job(value: dict[str, Any], s: CISelection,
                now: datetime) -> dict[str, Any]:
    need(_valid_id(value.get('id')) and value.get('id') == s.job_id, 'JOB_IDENTITY_MISMATCH')
    pipe = value.get('pipeline')
    need(type(pipe) is dict and _valid_id(pipe.get('id')) and
         _valid_id(pipe.get('project_id')) and pipe.get('id') == s.run_id and
         pipe.get('project_id') == s.project_id,
         'JOB_RUN_OR_PROJECT_MISMATCH')
    need(_string(value.get('ref'), 160) == s.branch, 'JOB_BRANCH_MISMATCH')
    commit = value.get('commit')
    need(type(commit) is dict and _remote_sha(commit.get('id')) == s.commit_sha,
         'JOB_RUN_OR_COMMIT_MISMATCH')
    state = _status(value.get('status'), GITLAB_JOB_STATUS, unit='JOB')
    allow = value.get('allow_failure')
    need(type(allow) is bool, 'PROVIDER_FIELD_INVALID')
    started = _time(value.get('started_at'))
    completed = _time(value.get('finished_at'))
    need(started <= completed, 'PROVIDER_TIMESTAMP_ORDER_INVALID')
    _fresh(completed, now, s.max_result_age_seconds)
    need(value.get('archived') is False and value.get('erased_at') is None,
         'JOB_ARCHIVED_OR_ERASED')
    return {'state': state, 'conclusion': 'success' if state == 'success' else 'failure',
            'started_at': _fmt(started), 'completed_at': _fmt(completed),
            'allow_failure': allow}


class QualityCIReader:
    """No I/O unless both opt-ins + host per-endpoint callback approve.

    Injecting a custom transport is useful for synthetic tests but can never
    produce a result labelled LIVE_HTTPS. Callback is an embedder policy gate,
    not a signed human identity. The provider 200 only confirms those GET reads.
    """
    def __init__(self, transport: ReadTransport | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.transport = transport if transport is not None else StrictHTTPSCITransport()
        self.synthetic = type(self.transport) is not StrictHTTPSCITransport
        self.clock = clock

    def read(self, selection: CISelection, *, credential: str | None,
             allow_network: bool, allow_ci_metadata: bool,
             authorize: Callable[[dict[str, Any]], bool] | None) -> dict[str, Any]:
        count = 0
        try:
            s = _selection(selection)
            need(allow_network is True and allow_ci_metadata is True,
                 'EXPLICIT_READ_OPTIN_REQUIRED', 'invalid_input')
            need(type(credential) is str and TOKEN.fullmatch(credential) is not None,
                 'CREDENTIAL_MISSING_OR_INVALID', 'invalid_input')
            need(callable(authorize), 'INDEPENDENT_SCOPE_GRANT_MISSING', 'invalid_input')
            now = _now(self.clock)
            deadline = time.monotonic() + MAX_TOTAL_SECONDS
            route = _endpoints(s)
            headers = _headers(s, credential)
            scope = {'provider': s.provider, 'repository': s.repository,
                     'project_id': s.project_id, 'workflow_id': s.workflow_id,
                     'run_id': s.run_id, 'attempt': s.attempt,
                     'job_id': s.job_id, 'branch': s.branch,
                     'commit_sha': s.commit_sha,
                     'max_result_age_seconds': s.max_result_age_seconds}

            def grant(endpoint_kind: str) -> None:
                try:
                    approved = authorize({**scope, 'read_kind': endpoint_kind,
                                          'operation': 'GET_CI_METADATA_ONLY'})
                except Exception:
                    raise CIError('SCOPE_PERMISSION_DENIED') from None
                need(approved is True, 'SCOPE_PERMISSION_DENIED')

            def get(url: str, kind: str) -> dict[str, Any]:
                nonlocal count
                grant(kind)  # independently re-authorize every read, including recheck
                need(count < MAX_TOTAL_REQUESTS, 'REQUEST_BUDGET_EXCEEDED')
                remaining = deadline - time.monotonic()
                need(remaining > 0, 'REQUEST_DEADLINE_EXCEEDED')
                count += 1  # Count before transport: even failures attempted a GET
                try:
                    obj = self.transport.get(url, headers, min(MAX_TIMEOUT, remaining))
                except CIError:
                    raise
                except Exception:
                    raise CIError('TRANSPORT_FAILED') from None
                need(type(obj) is dict, 'PROVIDER_PAYLOAD_INVALID')
                # Synthetic transport must not manufacture authenticated evidence.
                need(len(_canon(obj)) <= MAX_BODY, 'PROVIDER_PAYLOAD_TOO_LARGE')
                return obj

            if s.provider == 'github':
                first = _github_run(get(route[0], 'RUN'), s, now)
                # Attempt-specific list is essential: GET /jobs/{id} alone
                # cannot prove a job belongs to the requested retry attempt.
                page1 = get(route[1] + '?per_page=100&page=1', 'ATTEMPT_JOBS')
                total = page1.get('total_count')
                need(type(total) is int and 0 <= total <= MAX_PAGES * PAGE_SIZE,
                     'JOBS_PAGE_INCOMPLETE_OR_AMBIGUOUS')
                pages = [page1]
                for p in range(2, (total - 1) // PAGE_SIZE + 2):
                    pages.append(get(route[1] + f'?per_page=100&page={p}', 'ATTEMPT_JOBS'))
                job = _github_jobs(pages, s, now)
                last = _github_run(get(route[2], 'RUN_RECHECK'), s, now)
                need(first == last, 'RUN_CHANGED_DURING_READ')
                run = last
                read_kinds = ('RUN', 'ATTEMPT_JOBS', 'RUN_RECHECK')
                api_version = 'github-2026-03-10'
            else:
                _gitlab_project(get(route[0], 'PROJECT'), s)
                first = _gitlab_run(get(route[1], 'PIPELINE'), s, now)
                job = _gitlab_job(get(route[2], 'JOB'), s, now)
                last = _gitlab_run(get(route[3], 'PIPELINE_RECHECK'), s, now)
                need(first == last, 'RUN_CHANGED_DURING_READ')
                run = last
                read_kinds = ('PROJECT', 'PIPELINE', 'JOB', 'PIPELINE_RECHECK')
                api_version = 'gitlab-v4-field-validated-unpinned'
            need(_time(job['completed_at']) <=
                 _time(run['updated_at']) + timedelta(seconds=CLOCK_SKEW),
                 'RUN_JOB_TIME_INCONSISTENT')
            grant('FINALIZE_OBSERVATION')  # revoked permission invalidates entire response
            finished = _now(self.clock)
            need(finished >= now - timedelta(seconds=CLOCK_SKEW) and
                 finished <= now + timedelta(seconds=MAX_TOTAL_SECONDS + CLOCK_SKEW),
                 'CLOCK_DRIFT_DURING_READ')
            result = {
                'source': {'provider': s.provider, 'repository': s.repository,
                           'project_id': s.project_id, 'workflow_id': s.workflow_id,
                           'run_id': s.run_id, 'attempt': s.attempt,
                           'job_id': s.job_id, 'branch': s.branch,
                           'commit_sha': s.commit_sha, 'api_version': api_version,
                           'observed_at': _fmt(finished)},
                'observation': {'run': run, 'job': job},
                'permission': {'host_scope': 'HOST_CALLBACK_ALLOWED',
                               'provider_read': ('NOT_PROVEN_SYNTHETIC' if self.synthetic
                                                 else 'HTTPS_200_TOKEN_PRESENT'),
                               'transport': 'SYNTHETIC' if self.synthetic else 'LIVE_HTTPS',
                               'credential_identity': 'NOT_ATTESTED'},
                'coverage': {'exact_project_id': True, 'exact_repository_path': True,
                             'workflow_run_identity': True, 'attempt_bound': s.provider == 'github',
                             'exact_job_identity': True,
                             'branch_field_equal': True, 'commit_field_equal': True,
                             'run_final': True, 'job_final': True,
                             'within_requested_age': True,
                             'rechecked_run_for_drift': True,
                             'bounded_endpoint_kinds': list(read_kinds),
                             'git_sha_binding_verified': False,
                             'job_logs_inspected': False,
                             'test_execution_by_ces': False,
                             'cross_request_atomic_snapshot': False},
            }
            obs_hash = _hash(result)
            return {
                'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                'reason_code': REASON + 'CI_METADATA_OBSERVED',
                **result, 'observation_sha256': obs_hash,
                'effects': {**_safe_flags(), 'transport_get_calls': count,
                            'live_network_get_requests': 0 if self.synthetic else count},
                'trust_boundary': 'CI_METADATA_ONLY_NO_LOCAL_GIT_SHA_BINDING_OR_EXECUTION',
            }
        except CIError as err:
            return _empty(err.reason, err.status, request_count=count,
                          synthetic=self.synthetic)
        except (TypeError, ValueError, RecursionError, OverflowError):
            # Untrusted nested/provider values must not crash the caller or leak.
            return _empty(REASON + 'UNEXPECTED_FIELD_TYPE', 'unavailable',
                          request_count=count, synthetic=self.synthetic)


def _arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='Read exact authorized CI metadata; no logs, Git or test commands.')
    p.add_argument('--provider', choices=('github', 'gitlab'), required=True)
    p.add_argument('--repository', required=True)
    p.add_argument('--project-id', type=int, required=True)
    p.add_argument('--workflow-id', type=int)
    p.add_argument('--run-id', type=int, required=True)
    p.add_argument('--attempt', type=int)
    p.add_argument('--job-id', type=int, required=True)
    p.add_argument('--branch', required=True)
    p.add_argument('--commit-sha', required=True)
    p.add_argument('--max-result-age-seconds', type=int, required=True)
    p.add_argument('--allow-network', action='store_true')
    p.add_argument('--allow-ci-metadata', action='store_true')
    return p


def main(argv: list[str] | None = None) -> int:
    args = _arg_parser().parse_args(argv)
    key = CISelection(args.provider, args.repository, args.project_id,
                      args.workflow_id, args.run_id, args.attempt, args.job_id,
                      args.branch, args.commit_sha, args.max_result_age_seconds)
    # CLI flags are operator declarations, NOT an authenticated account or a
    # grant from a repository; remote token additionally needs read access.
    token = os.environ.get(ENV_TOKENS[args.provider])
    result = QualityCIReader().read(
        key, credential=token, allow_network=args.allow_network,
        allow_ci_metadata=args.allow_ci_metadata,
        authorize=lambda facts: args.allow_ci_metadata and facts.get('operation') == 'GET_CI_METADATA_ONLY',
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
