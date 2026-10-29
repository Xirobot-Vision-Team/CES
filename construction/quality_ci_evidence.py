#!/usr/bin/env python3
"""EC184: bounded, authorized GH/GL selected CI job-log and report observation.

Requires the EC182 CI receipt and EC183 association receipt, each revalidated
against *fresh* EC183 provider source + CI reads before and after content GETs.
The receipts are self-reported digests, NOT signatures. A complete job log can
provide a bounded test-result *claim*, never independent runner/actor/test proof.
GitHub Actions artifacts are RUN-scoped, not provably a selected JOB/ATTEMPT.
No test execution, shell, archive extraction to disk, Git or provider writes.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
import xml.etree.ElementTree as ET
from zipfile import BadZipFile, ZipFile, ZIP_DEFLATED, ZIP_STORED

import quality_read_ci as ci
import quality_sha_bind as sha

SCHEMA = 'ces.quality_ci_evidence.v1'
REASON = 'QUALITYCIEVIDENCE_'
EXIT = {'partial': 2, 'invalid_input': 4, 'unavailable': 5}
DOMAIN = b'CES-EC184-EVIDENCE-v1\x00'
MAX_LOG_BYTES = 512 * 1024
MAX_REPORT_BYTES = 256 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_EXPANDED = 1024 * 1024
MAX_META_BYTES = 64 * 1024
MAX_FETCHES = 8
MAX_FETCH_TIMEOUT = 8.0
MAX_OVERALL_SECONDS = 120.0
MAX_ORIGINAL_AGE = 300
MAX_LINES = 8000
MAX_XML_ELEMENTS = 4000
ALLOW_REPORT_KINDS = {'junit_xml', 'coverage_json', 'cobertura_xml'}
REPORT_EXTENSION = {'junit_xml': '.xml', 'coverage_json': '.json', 'cobertura_xml': '.xml'}
SAFE_PATH_SEGMENT = re.compile(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,79}\Z', re.ASCII)
HEX64 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
GH_TIMESTAMP = re.compile(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ') 
TAP_RESULT = re.compile(r'^(not ok|ok)\s+(\d{1,5})(?:\s+-\s+[^#]{0,200})?(?:\s+#\s+(SKIP|TODO)(?:\s+.{0,100})?)?$', re.I)
PYTEST_SUMMARY = re.compile(r'^=+\s+((?:\d+\s+(?:passed|failed|error|errors|skipped|deselected|xfailed|xpassed)(?:,\s*|\s+and\s+)?)+)\s+in\s+\d+(?:\.\d+)?s\s+=+$', re.I)
PYTEST_COUNT = re.compile(r'(\d+)\s+(passed|failed|error|errors|skipped|deselected|xfailed|xpassed)\b', re.I)


class EvidenceError(ValueError):
    def __init__(self, reason: str, status: str = 'unavailable') -> None:
        super().__init__(REASON + reason)
        self.code, self.status = REASON + reason, status


def require(value: bool, reason: str, status: str = 'unavailable') -> None:
    if not value:
        raise EvidenceError(reason, status)


def canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def digest(value: Any) -> str:
    return hashlib.sha256(DOMAIN + canon(value)).hexdigest()


@dataclass(frozen=True)
class ReportSelection:
    kind: str | None = None
    gitlab_path: str | None = None
    github_artifact_id: int | None = None
    github_entry: str | None = None


@dataclass(frozen=True)
class FetchResponse:
    status: int
    content_type: str = ''
    data: bytes = b''
    location: str | None = None
    declared_length: int | None = None


class ByteTransport(Protocol):
    def fetch(self, url: str, headers: dict[str, str], timeout: float,
              byte_limit: int) -> FetchResponse: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int,
                         msg: str, headers: Any, newurl: str) -> None:
        return None


class StrictHTTPSBytes:
    """TLS, GET-only, no proxy/redirect/retry; no compression or arbitrary URLs."""
    def fetch(self, url: str, headers: dict[str, str], timeout: float,
              byte_limit: int) -> FetchResponse:
        require(type(url) is str and 0 < len(url) <= 4096 and
                all(32 < ord(c) < 127 for c in url) and '\\' not in url,
                'ENDPOINT_INVALID')
        u = urlsplit(url)
        require(u.scheme == 'https' and u.hostname is not None and u.port is None and
                u.username is None and u.password is None and not u.fragment and
                u.netloc == u.hostname and _endpoint_allowed(u), 'ENDPOINT_INVALID')
        require(type(timeout) in (float, int) and 0 < timeout <= MAX_FETCH_TIMEOUT and
                type(byte_limit) is int and 0 < byte_limit <= MAX_ARCHIVE_BYTES,
                'FETCH_BUDGET_INVALID', 'invalid_input')
        opener = build_opener(ProxyHandler({}), _NoRedirect(),
                              HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(Request(url, headers=headers, method='GET'), timeout=timeout) as r:
                require(r.status == 200 and r.geturl() == url, 'UNEXPECTED_HTTP_RESPONSE')
                encoding = r.headers.get('Content-Encoding', 'identity').strip().lower()
                require(encoding in ('', 'identity'), 'CONTENT_ENCODING_DENIED')
                length = r.headers.get('Content-Length')
                if length is not None:
                    require(length.isdecimal() and int(length) <= byte_limit,
                            'BODY_SIZE_DENIED')
                data = r.read(byte_limit + 1)
                require(len(data) <= byte_limit, 'BODY_SIZE_DENIED')
                return FetchResponse(200, r.headers.get('Content-Type', ''), data,
                                     None, int(length) if length is not None else None)
        except HTTPError as exc:
            if exc.code == 302:
                return FetchResponse(302, location=exc.headers.get('Location'))
            if exc.code in (404, 410):
                return FetchResponse(exc.code)
            if exc.code in (401, 403):
                raise EvidenceError('PROVIDER_READ_DENIED') from None
            if exc.code == 429:
                raise EvidenceError('PROVIDER_RATE_LIMIT') from None
            raise EvidenceError('PROVIDER_HTTP_UNAVAILABLE') from None
        except (URLError, TimeoutError, OSError, socket.timeout, ssl.SSLError):
            raise EvidenceError('PROVIDER_NETWORK_UNAVAILABLE') from None


def _endpoint_allowed(parts: Any) -> bool:
    host, path, query = parts.hostname, parts.path, parts.query
    if host == 'api.github.com':
        return (bool(re.fullmatch(r'/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/'
                      r'(?:jobs/[1-9][0-9]*/logs|artifacts/[1-9][0-9]*(?:/zip)?)', path))
                and query == '')
    if host == 'gitlab.com':
        return (bool(re.fullmatch(r'/api/v4/projects/[1-9][0-9]*/jobs/[1-9][0-9]*/'
                r'(?:trace|artifacts/[A-Za-z0-9_./-]+)', path)) and
                query == '' and '/..' not in path and '//' not in path)
    return _signed_host(host) and bool(path) and not path.startswith('//')


def _signed_host(host: str) -> bool:
    # GitHub Actions currently uses Azure Blob / GitHub Actions result hosts.
    # No arbitrary Location/host (including suffix-lookalikes or IP literals).
    return (bool(re.fullmatch(r'[a-z0-9-]+\.blob\.core\.windows\.net', host)) or
            bool(re.fullmatch(r'[a-z0-9-]+\.actions\.githubusercontent\.com', host)) or
            host == 'pipelines.actions.githubusercontent.com')


def _validate_signed_url(url: Any) -> tuple[str, str]:
    require(type(url) is str and 15 <= len(url) <= 4096 and
            all(32 < ord(c) < 127 for c in url) and '\\' not in url,
            'SIGNED_URL_INVALID')
    u = urlsplit(url)
    require(u.scheme == 'https' and u.hostname is not None and
            u.netloc == u.hostname and u.port is None and
            u.username is None and u.password is None and
            not u.fragment and _signed_host(u.hostname) and
            bool(u.path) and not u.path.startswith('//') and
            not re.search(r'%(?:0[0-9a-f]|1[0-9a-f]|2f|5c)', u.path.lower()) and
            not any(s in ('.', '..') for s in u.path.split('/')),
            'SIGNED_URL_UNTRUSTED')
    return u.hostname, hashlib.sha256(url.encode('ascii')).hexdigest()


def _path(value: Any, kind: str) -> str:
    require(type(value) is str and 1 <= len(value) <= 240 and
            not value.startswith('/') and '\\' not in value and
            not any(s in ('.', '..') or SAFE_PATH_SEGMENT.fullmatch(s) is None
                    for s in value.split('/')) and
            value.lower().endswith(REPORT_EXTENSION[kind]),
            'REPORT_PATH_UNSAFE', 'invalid_input')
    return value


def _report_scope(value: ReportSelection, provider: str) -> ReportSelection:
    require(type(value) is ReportSelection, 'REPORT_SELECTION_INVALID', 'invalid_input')
    if value.kind is None:
        require(value.gitlab_path is None and value.github_artifact_id is None and
                value.github_entry is None, 'REPORT_SELECTION_INCOMPLETE', 'invalid_input')
        return value
    require(type(value.kind) is str and value.kind in ALLOW_REPORT_KINDS,
            'REPORT_FORMAT_UNSUPPORTED', 'invalid_input')
    if provider == 'github':
        require(ci._valid_id(value.github_artifact_id) and
                value.gitlab_path is None, 'ARTIFACT_ID_REQUIRED', 'invalid_input')
        _path(value.github_entry, value.kind)
    else:
        _path(value.gitlab_path, value.kind)
        require(value.github_artifact_id is None and value.github_entry is None,
                'ARTIFACT_ID_FORBIDDEN', 'invalid_input')
    return value


def _utc(clock: Callable[[], datetime] | None) -> datetime:
    try:
        return ci._now(clock)
    except ci.CIError:
        raise EvidenceError('CLOCK_INVALID', 'invalid_input') from None


def _validate_association(result: Any, selection: sha.SourceSelection,
                          ci_receipt: dict[str, Any], now: datetime,
                          synthetic: bool, dev_allowed: bool) -> None:
    require(type(result) is dict and len(canon(result)) <= sha.MAX_RECEIPT and
            set(result) == {'schema', 'status', 'exit_code', 'reason_code', 'source',
                            'ci_observation', 'binding', 'coverage', 'permission',
                            'association_sha256', 'effects', 'trust_boundary'} and
            result['schema'] == sha.SCHEMA and result['status'] == 'partial' and
            type(result['exit_code']) is int and result['exit_code'] == 2 and
            result['reason_code'] == 'QUALITYSHABIND_CI_SOURCE_SHA_ASSOCIATED',
            'ASSOCIATION_RECEIPT_INVALID', 'invalid_input')
    names = ('source', 'ci_observation', 'binding', 'permission', 'coverage')
    require(all(type(result.get(k)) is dict for k in names) and
            type(result.get('association_sha256')) is str and
            HEX64.fullmatch(result['association_sha256']) is not None and
            sha.checksum({k: result[k] for k in names}) == result['association_sha256'],
            'ASSOCIATION_RECEIPT_DIGEST_INVALID', 'invalid_input')
    s, x, b, p, v = (result[k] for k in names)
    key = selection.ci
    expected = {'provider': key.provider, 'repository': key.repository,
                'project_id': key.project_id, 'source_mode': selection.mode,
                'proposal_number': selection.proposal_number,
                'branch': key.branch, 'commit_sha': key.commit_sha}
    require(all(type(s.get(k)) is type(t) and s.get(k) == t
                for k, t in expected.items()) and
            (ci._valid_id(s.get('proposal_object_id')) if selection.mode == 'ProposedPR'
             else s.get('proposal_object_id') is None),
            'ASSOCIATION_SCOPE_MISMATCH')
    assert_sha = (b.get('source_commit_sha') == key.commit_sha and
                  b.get('ci_commit_sha') == key.commit_sha and
                  b.get('sha_equal') is True and
                  b.get('git_object_bytes_hashed') is False and
                  b.get('working_tree_verified') is False and
                  b.get('tests_executed_by_ces') is False and b.get('actor_verified') is False)
    require(assert_sha and x.get('run_id') == key.run_id and
            x.get('workflow_id') == key.workflow_id and
            x.get('attempt') == key.attempt and x.get('job_id') == key.job_id and
            x.get('original_observation_sha256') == ci_receipt.get('observation_sha256') and
            x.get('run_conclusion') in ('success', 'failure') and
            x.get('job_conclusion') in ('success', 'failure') and
            HEX64.fullmatch(str(x.get('fresh_observation_sha256'))) is not None,
            'ASSOCIATION_CI_MISMATCH')
    require(p.get('transport') == ('SYNTHETIC' if synthetic else 'LIVE_HTTPS') and
            p.get('source_scope') == p.get('ci_scope') == 'HOST_CALLBACK_ALLOWED' and
            p.get('credential_identity') == 'NOT_ATTESTED' and
            s.get('authority') == ('SYNTHETIC_DEVELOPMENT' if synthetic else
                                   'LIVE_PROVIDER_METADATA') and
            b.get('association_level') == ('SYNTHETIC_EQUALITY_ONLY' if synthetic else
                                            'PROVIDER_SOURCE_CI_METADATA_ASSOCIATED') and
            (not synthetic or dev_allowed is True),
            'ASSOCIATION_PROVENANCE_INVALID')
    require(all(v.get(k) is True for k in
                ('exact_repository_id', 'repository_rechecked', 'branch_rechecked',
                 'commit_endpoint_read', 'fresh_ci_rechecked', 'ci_metadata_unchanged',
                 'receipt_age_checked')) and
            v.get('proposal_rechecked') is (selection.mode == 'ProposedPR') and
            v.get('ci_source_sha_associated') is (not synthetic) and
            all(v.get(k) is False for k in
                ('git_object_bytes_hashed', 'working_tree_verified',
                 'test_execution_by_ces', 'logs_inspected', 'atomic_cross_request_snapshot')),
            'ASSOCIATION_COVERAGE_INVALID')
    effect = result.get('effects')
    require(type(effect) is dict and
            set(effect) == {'read_only', 'source_get_calls', 'ci_get_calls',
                            'live_source_get_requests', 'live_ci_get_requests',
                            'executed_commands', 'git_operations', 'read_ci_logs',
                            'writes_performed'} and
            effect.get('read_only') is True and
            all(effect.get(k) is False for k in
                ('executed_commands', 'git_operations', 'read_ci_logs', 'writes_performed')) and
            all(type(effect.get(k)) is int and 0 <= effect[k] <= 100 for k in
                ('source_get_calls', 'ci_get_calls',
                 'live_source_get_requests', 'live_ci_get_requests')) and
            ((effect['live_source_get_requests'] == 0 and
              effect['live_ci_get_requests'] == 0) if synthetic else
             (effect['live_source_get_requests'] == effect['source_get_calls'] and
              effect['live_ci_get_requests'] == effect['ci_get_calls'])) and
            result.get('trust_boundary') == (
                'SYNTHETIC_UNVERIFIED' if synthetic else
                'PROVIDER_METADATA_ONLY_NO_GIT_BYTES_OR_RUNNER'),
            'ASSOCIATION_EFFECTS_OR_TRUST_INVALID', 'invalid_input')
    stamp = sha._time(s.get('observed_at'))
    fresh = sha._time(x.get('fresh_observed_at'))
    require(now - timedelta(seconds=MAX_ORIGINAL_AGE) <= stamp <=
            now + timedelta(seconds=sha.SKEW) and
            now - timedelta(seconds=MAX_ORIGINAL_AGE) <= fresh <=
            now + timedelta(seconds=sha.SKEW), 'ASSOCIATION_RECEIPT_STALE')


def _association_projection(data: dict[str, Any]) -> tuple[Any, ...]:
    s, x = data['source'], data['ci_observation']
    return (s['provider'], s['repository'].casefold(), s['project_id'],
            s['source_mode'], s['proposal_number'], s['proposal_object_id'],
            s['branch'], s['commit_sha'], x['run_id'], x['workflow_id'],
            x['attempt'], x['job_id'], x['run_conclusion'], x['job_conclusion'],
            x['original_observation_sha256'])


def _content_type(got: Any, accepted: set[str]) -> None:
    require(type(got) is str and got.split(';', 1)[0].strip().lower() in accepted,
            'CONTENT_TYPE_DENIED')


def _safe_text(raw: bytes, limit: int) -> list[str] | None:
    if len(raw) > limit or b'\x00' in raw or len(raw) == 0:
        return None
    try:
        val = raw.decode('utf-8-sig', 'strict')
    except UnicodeError:
        return None
    lines = val.replace('\r\n', '\n').split('\n')
    if len(lines) > MAX_LINES or any(len(ln) > 4000 or any(ord(ch) < 32 and ch != '\t'
                                                  for ch in ln) for ln in lines):
        return None
    return [(GH_TIMESTAMP.sub('', ln, count=1)).strip() for ln in lines]


def _tests_from_log(raw: bytes) -> dict[str, Any]:
    lines = _safe_text(raw, MAX_LOG_BYTES)
    if lines is None:
        return {'state': 'partial', 'format': 'UNPARSEABLE_TEXT', 'counts': None}
    heads = [i for i, v in enumerate(lines) if v == 'TAP version 13']
    summaries = [m for v in lines if (m := PYTEST_SUMMARY.fullmatch(v)) is not None]
    if len(heads) + len(summaries) != 1:
        return {'state': 'partial', 'format': 'UNRECOGNIZED_OR_AMBIGUOUS', 'counts': None}
    if summaries:
        counter = {'passed': 0, 'failed': 0, 'skipped': 0}
        used = set()
        summary = summaries[0].group(1)
        parsed = list(PYTEST_COUNT.finditer(summary))
        if not parsed or len(parsed) > 7 or len(summary) > 200:
            return {'state': 'partial', 'format': 'PYTEST_AMBIGUOUS', 'counts': None}
        for m in parsed:
            n, label = int(m.group(1)), m.group(2).lower()
            if label in used or n > 100000:
                return {'state': 'partial', 'format': 'PYTEST_AMBIGUOUS', 'counts': None}
            used.add(label)
            if label == 'passed': counter['passed'] += n
            elif label in ('failed', 'error', 'errors', 'xpassed'): counter['failed'] += n
            else: counter['skipped'] += n
        if 'passed' not in used and 'failed' not in used and 'error' not in used and 'errors' not in used:
            return {'state': 'partial', 'format': 'PYTEST_AMBIGUOUS', 'counts': None}
        counter['total'] = sum(counter.values())
        return _test_claim(counter, 'PYTEST_TERMINAL_SUMMARY')
    idx = heads[0]
    body = [v for v in lines[idx+1:] if v and not v.startswith('#')]
    plans = [re.fullmatch(r'1\.\.(\d{1,5})(?:\s+#\s+SKIP(?:\s+.{0,100})?)?', v, re.I)
             for v in body if v.startswith('1..')]
    if len(plans) != 1 or plans[0] is None:
        return {'state': 'partial', 'format': 'TAP_INCOMPLETE', 'counts': None}
    target = int(plans[0].group(1))
    if target > 5000:
        return {'state': 'partial', 'format': 'TAP_OUT_OF_BOUNDS', 'counts': None}
    entries = [v for v in body if not v.startswith('1..')]
    if target == 0:
        return ({'state': 'not_run', 'format': 'TAP13',
                 'counts': {'total': 0, 'passed': 0, 'failed': 0, 'skipped': 0}}
                if len(entries) == 0 and 'SKIP' in next(v for v in body if v.startswith('1..')).upper()
                else {'state': 'partial', 'format': 'TAP_AMBIGUOUS_EMPTY', 'counts': None})
    counts = {'total': target, 'passed': 0, 'failed': 0, 'skipped': 0}
    if len(entries) != target:
        return {'state': 'partial', 'format': 'TAP_PLAN_INCOMPLETE', 'counts': None}
    for i, line in enumerate(entries, start=1):
        m = TAP_RESULT.fullmatch(line)
        if m is None or int(m.group(2)) != i:
            return {'state': 'partial', 'format': 'TAP_RESULT_AMBIGUOUS', 'counts': None}
        if m.group(3): counts['skipped'] += 1
        elif m.group(1).lower() == 'ok': counts['passed'] += 1
        else: counts['failed'] += 1
    return _test_claim(counts, 'TAP13')


def _test_claim(counts: dict[str, int], fmt: str) -> dict[str, Any]:
    if counts['total'] == 0:
        state = 'not_run'
    elif counts['failed'] > 0:
        state = 'fail'
    elif counts['passed'] > 0 and counts['skipped'] == 0:
        state = 'pass'
    elif counts['passed'] > 0 or counts['skipped'] > 0:
        state = 'partial'  # skipped/deselected != all tests completed
    else:
        state = 'partial'
    return {'state': state, 'format': fmt, 'counts': counts}


def _xml(raw: bytes) -> ET.Element | None:
    if len(raw) == 0 or len(raw) > MAX_REPORT_BYTES or b'<!' in raw or b'\x00' in raw:
        return None
    try:
        root = ET.fromstring(raw)
        elems = 0
        stack = [(root, 1)]
        while stack:
            node, depth = stack.pop()
            elems += 1
            if elems > MAX_XML_ELEMENTS or depth > 12 or len(node.attrib) > 24:
                return None
            stack.extend((c, depth+1) for c in node)
        return root
    except (ET.ParseError, ValueError, RecursionError, MemoryError):
        return None


def _uint(value: Any, limit: int = 100000) -> int | None:
    if type(value) is int and 0 <= value <= limit:
        return value
    if type(value) is str and re.fullmatch(r'(?:0|[1-9][0-9]{0,5})', value) and int(value) <= limit:
        return int(value)
    return None


def _junit(raw: bytes) -> dict[str, Any]:
    root = _xml(raw)
    if root is None or root.tag not in ('testsuites', 'testsuite'):
        return {'state': 'partial', 'format': 'JUNIT_XML_INVALID', 'counts': None}
    # Compare declared suite counters with actual leaf testcases. No findings,
    # paths, testcase names, XML text or possible secrets are retained.
    suites = [root] if root.tag == 'testsuite' else [e for e in root if e.tag == 'testsuite']
    if not suites or len(suites) > 500:
        return {'state': 'partial', 'format': 'JUNIT_XML_AMBIGUOUS', 'counts': None}
    counts = {'total': 0, 'passed': 0, 'failed': 0, 'skipped': 0}
    aggregate_failures = aggregate_errors = 0
    for suite in suites:
        if any(child.tag == 'testsuite' for child in suite):
            return {'state': 'partial', 'format': 'JUNIT_NESTING_UNSUPPORTED', 'counts': None}
        cases = [e for e in suite if e.tag == 'testcase']
        n = _uint(suite.get('tests'))
        fails = _uint(suite.get('failures'))
        errors = _uint(suite.get('errors', '0'))
        skips = _uint(suite.get('skipped', '0'))
        if any(x is None for x in (n, fails, errors, skips)) or n != len(cases):
            return {'state': 'partial', 'format': 'JUNIT_COUNTS_INCONSISTENT', 'counts': None}
        f = e = k = 0
        for case in cases:
            tags = [item.tag for item in case]
            if sum(t in ('failure', 'error', 'skipped') for t in tags) > 1:
                return {'state': 'partial', 'format': 'JUNIT_CASE_AMBIGUOUS', 'counts': None}
            f += 'failure' in tags
            e += 'error' in tags
            k += 'skipped' in tags
        if fails != f or errors != e or skips != k:
            return {'state': 'partial', 'format': 'JUNIT_COUNTS_INCONSISTENT', 'counts': None}
        counts['total'] += n
        counts['failed'] += f + e
        counts['skipped'] += k
        counts['passed'] += n - f - e - k
        aggregate_failures += f
        aggregate_errors += e
    if root.tag == 'testsuites':
        for key, calc in (('tests', counts['total']),
                          ('failures', aggregate_failures),
                          ('errors', aggregate_errors),
                          ('skipped', counts['skipped'])):
            if root.get(key) is not None and _uint(root.get(key)) != calc:
                return {'state': 'partial', 'format': 'JUNIT_TOTALS_INCONSISTENT', 'counts': None}
    if counts['total'] > 5000 or min(counts.values()) < 0:
        return {'state': 'partial', 'format': 'JUNIT_TOO_MANY_TESTS', 'counts': None}
    return _test_claim(counts, 'JUNIT_XML')


def _coverage_json(raw: bytes) -> dict[str, Any]:
    try:
        obj = ci._json_object(raw)
    except ci.CIError:
        return {'state': 'partial', 'format': 'COVERAGE_JSON_INVALID', 'metrics': None}
    totals = obj.get('totals')
    if type(totals) is not dict or type(obj.get('files')) is not dict:
        return {'state': 'partial', 'format': 'COVERAGE_JSON_UNSCOPED', 'metrics': None}
    total = _uint(totals.get('num_statements'), 10000000)
    covered = _uint(totals.get('covered_lines'), 10000000)
    missing = _uint(totals.get('missing_lines'), 10000000)
    percent = totals.get('percent_covered')
    if (total is None or total == 0 or covered is None or missing is None or
        covered + missing != total or type(percent) not in (int, float) or
        not 0 <= percent <= 100 or abs(percent-100*covered/total) > 0.51):
        return {'state': 'partial', 'format': 'COVERAGE_JSON_INCONSISTENT', 'metrics': None}
    return {'state': 'measured', 'format': 'COVERAGE_PY_JSON',
            'metrics': {'lines_total': total, 'lines_covered': covered,
                        'percent': round(100 * covered / total, 2)}}


def _cobertura(raw: bytes) -> dict[str, Any]:
    root = _xml(raw)
    if root is None or root.tag != 'coverage':
        return {'state': 'partial', 'format': 'COBERTURA_XML_INVALID', 'metrics': None}
    total = _uint(root.get('lines-valid'), 10000000)
    covered = _uint(root.get('lines-covered'), 10000000)
    try:
        rate = float(root.get('line-rate', 'nan'))
    except (TypeError, ValueError, OverflowError):
        rate = float('nan')
    if (total is None or total == 0 or covered is None or covered > total or
        not 0 <= rate <= 1 or abs(rate-covered/total) > 0.0051):
        return {'state': 'partial', 'format': 'COBERTURA_INCONSISTENT', 'metrics': None}
    return {'state': 'measured', 'format': 'COBERTURA_XML',
            'metrics': {'lines_total': total, 'lines_covered': covered,
                        'percent': round(100*covered/total, 2)}}


def _parse_report(raw: bytes, kind: str) -> dict[str, Any]:
    if kind == 'junit_xml':
        return _junit(raw)
    if kind == 'coverage_json':
        return _coverage_json(raw)
    return _cobertura(raw)


def _unzip_selected(raw: bytes, entry: str) -> bytes | None:
    try:
        with ZipFile(BytesIO(raw)) as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= 64:
                raise EvidenceError('ARCHIVE_ENTRY_LIMIT')
            seen: set[str] = set()
            expanded = 0
            for info in infos:
                name = info.filename
                require(type(name) is str and 1 <= len(name) <= 240 and
                        not name.startswith('/') and '\\' not in name and
                        not any(x in ('.', '..', '') or SAFE_PATH_SEGMENT.fullmatch(x) is None
                                for x in name.rstrip('/').split('/')) and
                        name.casefold() not in seen and
                        info.compress_type in (ZIP_STORED, ZIP_DEFLATED) and
                        info.flag_bits & 1 == 0 and
                        ((info.external_attr >> 16) & 0o170000) not in (0o120000, 0o060000) and
                        info.file_size <= MAX_REPORT_BYTES and
                        info.compress_size <= MAX_ARCHIVE_BYTES and
                        info.file_size <= max(100, info.compress_size * 200),
                        'ARCHIVE_ENTRY_UNSAFE')
                expanded += info.file_size
                require(expanded <= MAX_ARCHIVE_EXPANDED, 'ARCHIVE_EXPANSION_DENIED')
                seen.add(name.casefold())
            if entry not in archive.namelist():
                return None
            with archive.open(entry, mode='r') as stream:
                data = stream.read(MAX_REPORT_BYTES + 1)
            require(len(data) <= MAX_REPORT_BYTES, 'ARCHIVE_ENTRY_SIZE_DENIED')
            return data
    except EvidenceError:
        raise
    except (BadZipFile, OSError, RuntimeError, EOFError, ValueError, MemoryError):
        raise EvidenceError('ARCHIVE_INVALID') from None


def _empty_test(state: str, fmt: str) -> dict[str, Any]:
    return {'state': state, 'format': fmt, 'counts': None}


def _empty_report(state: str, fmt: str) -> dict[str, Any]:
    return {'state': state, 'format': fmt, 'metrics': None}


def _refusal(code: str, status: str, fetches: int, bind_source: int, bind_ci: int,
             synthetic: bool) -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': status, 'exit_code': EXIT[status],
            'reason_code': code, 'scope': None, 'test_evidence': None,
            'report_evidence': None, 'classification': None, 'coverage': None,
            'permission': {'transport': 'SYNTHETIC' if synthetic else 'UNDETERMINED',
                           'host_scope': 'NOT_ATTESTED'}, 'evidence_sha256': None,
            'effects': _effects(fetches, bind_source, bind_ci, synthetic),
            'trust_boundary': 'NO_EVIDENCE_ON_REFUSAL'}


def _effects(fetches: int, source: int, ci_reads: int, synthetic: bool) -> dict[str, Any]:
    return {'read_only': True, 'content_get_calls': fetches,
            'source_metadata_get_calls': source, 'ci_metadata_get_calls': ci_reads,
            'live_content_get_requests': 0 if synthetic else fetches,
            'commands_executed': False, 'tests_executed_by_ces': False,
            'archive_written_or_extracted': False, 'writes_performed': False}


class QualityCIEvidence:
    """Observed, parsed evidence; never a native CES QualityReadCI/QualityRun."""
    def __init__(self, *, byte_transport: ByteTransport | None = None,
                 binder: sha.QualitySHABinder | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.byte_transport = byte_transport if byte_transport is not None else StrictHTTPSBytes()
        self.binder = binder if binder is not None else sha.QualitySHABinder(clock=clock)
        self.clock = clock
        self.synthetic = type(self.byte_transport) is not StrictHTTPSBytes

    def read(self, selected: sha.SourceSelection, *, report: ReportSelection,
             ci_receipt: dict[str, Any], association_receipt: dict[str, Any],
             ci_credential: str | None, source_credential: str | None,
             allow_network: bool, allow_ci_recheck: bool,
             allow_source_recheck: bool, allow_receipt_reuse: bool,
             allow_job_log: bool, allow_report: bool,
             authorize_ci: Callable[[dict[str, Any]], bool] | None,
             authorize_source: Callable[[dict[str, Any]], bool] | None,
             authorize_content: Callable[[dict[str, Any]], bool] | None,
             allow_synthetic_development: bool = False) -> dict[str, Any]:
        n_get = source_get = ci_get = 0
        synthetic = (self.synthetic or self.binder.source_synthetic or
                     self.binder.ci_reader.synthetic)
        try:
            selection = sha._scope(selected)
            selected_report = _report_scope(report, selection.ci.provider)
            require(all(x is True for x in (allow_network, allow_ci_recheck,
                    allow_source_recheck, allow_receipt_reuse, allow_job_log)),
                    'INDEPENDENT_OPTINS_REQUIRED', 'invalid_input')
            require((selected_report.kind is None and allow_report is False) or
                    (selected_report.kind is not None and allow_report is True),
                    'REPORT_CONSENT_MISMATCH', 'invalid_input')
            require(callable(authorize_ci) and callable(authorize_source) and
                    callable(authorize_content), 'INDEPENDENT_GRANTS_REQUIRED',
                    'invalid_input')
            require(type(ci_credential) is str and ci.TOKEN.fullmatch(ci_credential) and
                    type(source_credential) is str and ci.TOKEN.fullmatch(source_credential),
                    'TWO_CREDENTIALS_REQUIRED', 'invalid_input')
            require(self.synthetic == self.binder.source_synthetic ==
                    self.binder.ci_reader.synthetic, 'MIXED_TRANSPORT_PROVENANCE', 'invalid_input')
            require(not synthetic or allow_synthetic_development is True,
                    'SYNTHETIC_DEVELOPMENT_DENIED', 'invalid_input')
            now = _utc(self.clock)
            _validate_association(association_receipt, selection, ci_receipt, now,
                                  synthetic, allow_synthetic_development)
            deadline = time.monotonic() + MAX_OVERALL_SECONDS
            key = selection.ci
            base_scope = {'provider': key.provider, 'repository': key.repository,
                          'project_id': key.project_id, 'run_id': key.run_id,
                          'attempt': key.attempt, 'job_id': key.job_id,
                          'workflow_id': key.workflow_id, 'branch': key.branch,
                          'commit_sha': key.commit_sha, 'source_mode': selection.mode,
                          'proposal_number': selection.proposal_number}

            def rebind() -> dict[str, Any]:
                nonlocal ci_get, source_get
                r = self.binder.bind(
                    selection, ci_receipt=ci_receipt, source_credential=source_credential,
                    ci_credential=ci_credential, allow_network=allow_network,
                    allow_ci_read=allow_ci_recheck, allow_receipt_reuse=allow_receipt_reuse,
                    allow_source_read=allow_source_recheck,
                    authorize_source=authorize_source, authorize_ci=authorize_ci,
                    allow_synthetic_development=allow_synthetic_development)
                source_get += r.get('effects', {}).get('source_get_calls', 0)
                ci_get += r.get('effects', {}).get('ci_get_calls', 0)
                require(r.get('schema') == sha.SCHEMA and r.get('status') == 'partial' and
                        r.get('reason_code') == 'QUALITYSHABIND_CI_SOURCE_SHA_ASSOCIATED',
                        'FRESH_SOURCE_CI_ASSOCIATION_REFUSED')
                require(r['permission']['transport'] ==
                        ('SYNTHETIC' if synthetic else 'LIVE_HTTPS'),
                        'FRESH_ASSOCIATION_PROVENANCE_DRIFT')
                require(_association_projection(association_receipt) ==
                        _association_projection(r), 'ASSOCIATION_DRIFT')
                require(time.monotonic() < deadline, 'TOTAL_DEADLINE_EXCEEDED')
                return r

            first = rebind()
            headers = sha._headers(selection, ci_credential)
            approved_kinds: list[str] = []

            def grant(kind: str, host: str | None = None, locator_hash: str | None = None) -> None:
                facts = {**base_scope, 'operation': 'GET_JOB_EVIDENCE_ONLY',
                         'read_kind': kind, 'report_kind': selected_report.kind,
                         'signed_host': host, 'signed_location_sha256': locator_hash}
                try:
                    ok = authorize_content(facts)
                except Exception:
                    raise EvidenceError('CONTENT_SCOPE_DENIED') from None
                require(ok is True, 'CONTENT_SCOPE_DENIED')
                approved_kinds.append(kind)

            def fetch(url: str, kind: str, cap: int, *, signed: bool = False) -> FetchResponse:
                nonlocal n_get
                require(time.monotonic() < deadline, 'TOTAL_DEADLINE_EXCEEDED')
                host = urlsplit(url).hostname if signed else None
                locator = hashlib.sha256(url.encode('ascii')).hexdigest() if signed else None
                grant(kind, host, locator)
                require(n_get < MAX_FETCHES, 'CONTENT_REQUEST_BUDGET_EXCEEDED')
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'TOTAL_DEADLINE_EXCEEDED')
                n_get += 1
                safe_headers = ({'User-Agent': 'CES-EC184/1', 'Accept-Encoding': 'identity'}
                                if signed else headers)
                try:
                    resp = self.byte_transport.fetch(url, safe_headers,
                                                     min(MAX_FETCH_TIMEOUT, remaining), cap)
                except EvidenceError:
                    raise
                except Exception:
                    raise EvidenceError('CONTENT_TRANSPORT_FAILED') from None
                require(type(resp) is FetchResponse and
                        type(resp.status) is int and resp.status in (200, 302, 404, 410) and
                        type(resp.data) is bytes and len(resp.data) <= cap and
                        (resp.declared_length is None or
                         (type(resp.declared_length) is int and
                          len(resp.data) == resp.declared_length <= cap)),
                        'CONTENT_RESPONSE_INVALID')
                return resp

            def fetch_gh(url: str, kind: str, cap: int) -> FetchResponse:
                first_response = fetch(url, kind, cap)
                if first_response.status in (404, 410):
                    return first_response
                require(first_response.status == 302 and not first_response.data,
                        'EXPECTED_GITHUB_SIGNED_REDIRECT')
                _validate_signed_url(first_response.location)
                resp = fetch(first_response.location, 'SIGNED_' + kind, cap, signed=True)
                require(resp.status == 200 and resp.location is None,
                        'SIGNED_DOWNLOAD_UNAVAILABLE')
                return resp

            log_url = ('https://api.github.com/repos/' + key.repository +
                       '/actions/jobs/' + str(key.job_id) + '/logs' if key.provider == 'github'
                       else 'https://gitlab.com/api/v4/projects/' + str(key.project_id) +
                       '/jobs/' + str(key.job_id) + '/trace')
            log_resp = (fetch_gh(log_url, 'JOB_LOG', MAX_LOG_BYTES)
                        if key.provider == 'github' else
                        fetch(log_url, 'JOB_LOG', MAX_LOG_BYTES))
            if log_resp.status in (404, 410):
                log = _empty_test('missing', 'NO_JOB_LOG')
                log_meta = {'availability': 'missing', 'byte_count': 0, 'sha256': None,
                            'source_scope': ('EXACT_JOB_ATTEMPT_CI_RECHECKED' if key.provider == 'github'
                                             else 'EXACT_GITLAB_JOB_CI_RECHECKED')}
            else:
                require(log_resp.status == 200, 'GITLAB_LOG_REDIRECT_UNTRUSTED')
                _content_type(log_resp.content_type, {'text/plain', 'application/octet-stream'})
                log = _tests_from_log(log_resp.data)
                log_meta = {'availability': 'present', 'byte_count': len(log_resp.data),
                            'sha256': hashlib.sha256(log_resp.data).hexdigest(),
                            'source_scope': ('EXACT_JOB_ATTEMPT_CI_RECHECKED' if key.provider == 'github'
                                             else 'EXACT_GITLAB_JOB_CI_RECHECKED')}
            report_parsed: dict[str, Any] | None = None
            report_meta = {'availability': 'not_requested' if selected_report.kind is None
                           else 'missing', 'byte_count': 0, 'sha256': None,
                           'format': selected_report.kind, 'source_scope':
                           'NOT_REQUESTED' if selected_report.kind is None else
                           ('RUN_ONLY_JOB_ATTEMPT_UNVERIFIED' if key.provider == 'github'
                            else 'EXACT_GITLAB_JOB')}
            if selected_report.kind is not None:
                raw_report = None
                if key.provider == 'gitlab':
                    uri = ('https://gitlab.com/api/v4/projects/' + str(key.project_id) +
                           '/jobs/' + str(key.job_id) + '/artifacts/' +
                           quote(selected_report.gitlab_path, safe='/'))
                    response = fetch(uri, 'JOB_REPORT', MAX_REPORT_BYTES)
                    if response.status == 200:
                        _content_type(response.content_type,
                                      {'application/json', 'text/plain', 'application/xml',
                                       'text/xml', 'application/octet-stream'})
                        raw_report = response.data
                    else:
                        require(response.status in (404, 410),
                                'GITLAB_ARTIFACT_REDIRECT_UNTRUSTED')
                else:
                    base = 'https://api.github.com/repos/' + key.repository + '/actions/artifacts/' + str(selected_report.github_artifact_id)

                    def metadata(kind: str) -> dict[str, Any] | None:
                        response = fetch(base, kind, MAX_META_BYTES)
                        if response.status in (404, 410):
                            return None
                        require(response.status == 200, 'ARTIFACT_METADATA_REDIRECT_DENIED')
                        _content_type(response.content_type,
                                      {'application/json', 'application/vnd.github+json'})
                        try:
                            meta = ci._json_object(response.data)
                        except ci.CIError:
                            raise EvidenceError('ARTIFACT_METADATA_INVALID') from None
                        flow = meta.get('workflow_run')
                        require(type(flow) is dict and meta.get('id') == selected_report.github_artifact_id and
                                flow.get('id') == key.run_id and
                                flow.get('repository_id') == key.project_id and
                                flow.get('head_sha') == key.commit_sha and
                                flow.get('head_branch') == key.branch and
                                meta.get('expired') is False and
                                type(meta.get('name')) is str and len(meta['name']) <= 120 and
                                type(meta.get('size_in_bytes')) is int and
                                0 < meta['size_in_bytes'] <= MAX_ARCHIVE_BYTES,
                                'ARTIFACT_RUN_IDENTITY_UNVERIFIED')
                        dig = meta.get('digest')
                        require(dig is None or (type(dig) is str and
                                re.fullmatch('sha256:[0-9a-f]{64}', dig)),
                                'ARTIFACT_DIGEST_INVALID')
                        return {'id': meta['id'], 'name': meta['name'],
                                'size': meta['size_in_bytes'], 'sha256': dig,
                                'workflow_run': {'id': flow['id'],
                                                 'repository_id': flow['repository_id'],
                                                 'head_sha': flow['head_sha'],
                                                 'head_branch': flow['head_branch']}}

                    before = metadata('ARTIFACT_META_BEFORE')
                    if before is not None:
                        blob = fetch_gh(base + '/zip', 'ARTIFACT_ARCHIVE', MAX_ARCHIVE_BYTES)
                        require(blob.status == 200, 'ARTIFACT_ARCHIVE_DISAPPEARED')
                        _content_type(blob.content_type,
                                      {'application/zip', 'application/octet-stream'})
                        require(len(blob.data) == before['size'],
                                'ARTIFACT_SIZE_MISMATCH')
                        if before['sha256'] is not None:
                            require('sha256:' + hashlib.sha256(blob.data).hexdigest() ==
                                    before['sha256'], 'ARTIFACT_DIGEST_MISMATCH')
                        raw_report = _unzip_selected(blob.data, selected_report.github_entry)
                        after = metadata('ARTIFACT_META_AFTER')
                        require(after == before, 'ARTIFACT_METADATA_DRIFT')
                if raw_report is not None:
                    require(len(raw_report) <= MAX_REPORT_BYTES,
                            'REPORT_TOO_LARGE')
                    report_parsed = _parse_report(raw_report, selected_report.kind)
                    report_meta.update(availability='present', byte_count=len(raw_report),
                                       sha256=hashlib.sha256(raw_report).hexdigest())
                else:
                    report_parsed = (_empty_test('missing', 'REPORT_MISSING')
                                     if selected_report.kind == 'junit_xml' else
                                     _empty_report('missing', 'REPORT_MISSING'))
            final = rebind()
            grant('FINALIZE_EVIDENCE')
            finished = _utc(self.clock)
            require(now - timedelta(seconds=sha.SKEW) <= finished <=
                    now + timedelta(seconds=MAX_OVERALL_SECONDS + sha.SKEW) and
                    time.monotonic() < deadline, 'CLOCK_OR_DEADLINE_DRIFT')
            _validate_association(association_receipt, selection, ci_receipt,
                                  finished, synthetic, allow_synthetic_development)
            require(_association_projection(first) == _association_projection(final),
                    'SOURCE_CI_CHANGED_DURING_CONTENT')
            job_conclusion = final['ci_observation']['job_conclusion']
            test = log
            if selected_report.kind == 'junit_xml' and report_parsed is not None:
                if key.provider == 'gitlab' and report_parsed['state'] in ('pass', 'fail', 'not_run'):
                    if (log['state'] in ('pass', 'fail', 'not_run') and
                            log['state'] != report_parsed['state']):
                        test = _empty_test('partial', 'LOG_REPORT_CONFLICT')
                    else:
                        test = report_parsed
                elif key.provider == 'github' and log['state'] == 'missing':
                    # Run-level GH artifact alone cannot certify selected job.
                    test = _empty_test('partial', 'ARTIFACT_UNBOUND_TO_JOB')
            if test['state'] == 'pass' and job_conclusion != 'success':
                test = _empty_test('partial', 'CI_JOB_TEST_CONCLUSION_CONFLICT')
            if test['state'] == 'fail' and job_conclusion != 'failure':
                test = _empty_test('partial', 'CI_JOB_TEST_CONCLUSION_CONFLICT')
            if selected_report.kind == 'junit_xml' and report_parsed is not None:
                rep_state = report_parsed['state']
                rep_format = report_parsed['format']
                rep_count, rep_metrics = report_parsed['counts'], None
            elif selected_report.kind in ('coverage_json', 'cobertura_xml') and report_parsed is not None:
                rep_state = report_parsed['state']
                rep_format = report_parsed['format']
                rep_count, rep_metrics = None, report_parsed['metrics']
            else:
                rep_state = 'not_requested' if selected_report.kind is None else 'missing'
                rep_format, rep_count, rep_metrics = 'NOT_REQUESTED_OR_MISSING', None, None
            report_evidence = {**report_meta, 'state': rep_state, 'parse_format': rep_format,
                               'test_counts': rep_count, 'coverage_metrics': rep_metrics}
            classification = test['state']
            require(classification in ('missing', 'not_run', 'partial', 'fail', 'pass'),
                    'CLASSIFICATION_INVALID')
            # Never expose log excerpts, report XML or file paths; hashes are
            # observation checksums and not Provider artifact signatures.
            scope = {**base_scope, 'source_proposal_object_id':
                     final['source']['proposal_object_id'],
                     'association_receipt_sha256': association_receipt['association_sha256'],
                     'ci_receipt_observation_sha256': ci_receipt['observation_sha256'],
                     'observed_at': ci._fmt(finished)}
            test_evidence = {**log_meta, 'state': classification,
                             'parse_format': test['format'], 'counts': test['counts'],
                             'job_conclusion': job_conclusion,
                             'provider_claim_only': True}
            coverage = {'job_log_availability_checked': True,
                        'exact_job_identity_rechecked': True,
                        'exact_run_attempt_rechecked': key.provider == 'github',
                        'source_branch_commit_rechecked': True,
                        'association_freshness_checked': True,
                        'content_size_and_type_checked': True,
                        'report_requested': selected_report.kind is not None,
                        'report_is_job_attributed': (selected_report.kind is not None and
                                                     key.provider == 'gitlab' and
                                                     report_meta['availability'] == 'present'),
                        'github_report_run_only': (selected_report.kind is not None and
                                                   key.provider == 'github'),
                        'raw_content_disclosed': False,
                        'actual_tests_executed_by_ces': False,
                        'runner_integrity_verified': False,
                        'actor_identity_verified': False,
                        'git_object_bytes_verified': False,
                        'provider_cross_request_atomic': False,
                        'performance_measured': False}
            perm = {'transport': 'SYNTHETIC' if synthetic else 'LIVE_HTTPS',
                    'host_scope': 'HOST_CALLBACK_ALLOWED',
                    'source_and_ci_scopes': 'FRESHLY_RECHECKED',
                    'credential_identity': 'NOT_ATTESTED',
                    'content_endpoint_grants': sorted(set(approved_kinds))}
            payload = {'scope': scope, 'test_evidence': test_evidence,
                       'report_evidence': report_evidence,
                       'classification': classification,
                       'coverage': coverage, 'permission': perm}
            return {'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                    'reason_code': REASON + 'BOUNDED_EVIDENCE_OBSERVED',
                    **payload, 'evidence_sha256': digest(payload),
                    'effects': _effects(n_get, source_get, ci_get, synthetic),
                    'trust_boundary': 'SYNTHETIC_NO_PROVIDER_PROOF' if synthetic else
                    'PROVIDER_LOG_AND_REPORT_CLAIMS_NO_TEST_EXECUTION_OR_ATOMICITY'}
        except EvidenceError as e:
            return _refusal(e.code, e.status, n_get, source_get, ci_get, synthetic)
        except (sha.BindError, ci.CIError, ValueError, TypeError, KeyError,
                AttributeError, OverflowError, RecursionError, MemoryError):
            return _refusal(REASON + 'INVALID_UNTRUSTED_INPUT', 'unavailable',
                            n_get, source_get, ci_get, synthetic)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='EC184 exact CI job-log and bounded report observation')
    p.add_argument('--ci-receipt', required=True)
    p.add_argument('--association-receipt', required=True)
    p.add_argument('--provider', choices=('github', 'gitlab'), required=True)
    p.add_argument('--repository', required=True)
    p.add_argument('--project-id', type=int, required=True)
    p.add_argument('--workflow-id', type=int)
    p.add_argument('--run-id', type=int, required=True)
    p.add_argument('--attempt', type=int)
    p.add_argument('--job-id', type=int, required=True)
    p.add_argument('--branch', required=True)
    p.add_argument('--commit-sha', required=True)
    p.add_argument('--ci-max-age', type=int, required=True)
    p.add_argument('--source-mode', choices=('DeliveredTarget', 'ProposedPR'), required=True)
    p.add_argument('--proposal-number', type=int)
    p.add_argument('--report-kind', choices=sorted(ALLOW_REPORT_KINDS))
    p.add_argument('--gitlab-report-path')
    p.add_argument('--github-artifact-id', type=int)
    p.add_argument('--github-report-entry')
    for flag in ('allow-network', 'allow-ci-recheck', 'allow-source-recheck',
                 'allow-receipt-reuse', 'allow-job-log', 'allow-report'):
        p.add_argument('--' + flag, action='store_true')
    a = p.parse_args(argv)

    def receipt(path: str) -> dict[str, Any]:
        try:
            raw = Path(path).read_bytes()
            if len(raw) > sha.MAX_RECEIPT:
                return {}
            return ci._json_object(raw)
        except (OSError, ci.CIError):
            return {}

    selected = sha.SourceSelection(
        ci.CISelection(a.provider, a.repository, a.project_id,
                       a.workflow_id, a.run_id, a.attempt, a.job_id,
                       a.branch, a.commit_sha, a.ci_max_age),
        a.source_mode, a.proposal_number)
    report = ReportSelection(a.report_kind, a.gitlab_report_path,
                             a.github_artifact_id, a.github_report_entry)
    result = QualityCIEvidence().read(
        selected, report=report, ci_receipt=receipt(a.ci_receipt),
        association_receipt=receipt(a.association_receipt),
        ci_credential=os.environ.get(ci.ENV_TOKENS[a.provider]),
        source_credential=os.environ.get('CES_SOURCE_' + a.provider.upper() + '_TOKEN'),
        allow_network=a.allow_network, allow_ci_recheck=a.allow_ci_recheck,
        allow_source_recheck=a.allow_source_recheck,
        allow_receipt_reuse=a.allow_receipt_reuse, allow_job_log=a.allow_job_log,
        allow_report=a.allow_report,
        authorize_ci=lambda x: a.allow_ci_recheck and
            x.get('operation') == 'GET_CI_METADATA_ONLY',
        authorize_source=lambda x: a.allow_source_recheck and
            x.get('operation') == 'GET_SOURCE_METADATA_ONLY',
        authorize_content=lambda x: (a.allow_job_log and
            (a.allow_report or x.get('read_kind') in ('JOB_LOG', 'SIGNED_JOB_LOG',
                                                    'FINALIZE_EVIDENCE')) and
            x.get('operation') == 'GET_JOB_EVIDENCE_ONLY'))
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
