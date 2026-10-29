#!/usr/bin/env python3
"""EC183: separately authorized, read-only CI/source SHA association.

Only DeliveredTarget remote branch and same-repository ProposedPR open head
are supported. A provider's HTTPS commit metadata is not local verification of
Git object bytes, working-tree contents, runner execution or human identity.
All custom transport results are marked synthetic and cannot authenticate CI.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
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

import quality_read_ci as ci

SCHEMA = 'ces.quality_sha_bind.v1'
REASON = 'QUALITYSHABIND_'
EXIT = {'partial': 2, 'invalid_input': 4, 'unavailable': 5}
DOMAIN = b'CES-EC183-ASSOCIATION-v1\0'
MAX_BODY = 256 * 1024
MAX_RECEIPT = 64 * 1024
MAX_GETS = 7
MAX_REQUEST_TIMEOUT = 8.0
MAX_DURATION = 70.0
SKEW = 30


class BindError(ValueError):
    def __init__(self, name: str, status: str = 'unavailable') -> None:
        super().__init__(REASON + name)
        self.code = REASON + name
        self.status = status


def require(value: bool, reason: str, status: str = 'unavailable') -> None:
    if not value:
        raise BindError(reason, status)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def checksum(value: Any) -> str:
    return hashlib.sha256(DOMAIN + canonical(value)).hexdigest()


@dataclass(frozen=True)
class SourceSelection:
    ci: ci.CISelection
    mode: str  # DeliveredTarget | ProposedPR
    proposal_number: int | None = None
    receipt_max_age_seconds: int = 300


class SourceTransport(Protocol):
    def get(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]: ...


class _RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int,
                         msg: str, headers: Any, newurl: str) -> None:
        return None


class StrictSourceHTTPS:
    """Fixed-host read-only TLS, no redirects, cookies, proxies, retries or body writes."""
    def get(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        parts = urlsplit(url)
        require(type(url) is str and len(url) <= 512 and '\\' not in url and
                parts.scheme == 'https' and parts.port is None and
                parts.username is None and parts.password is None and
                not parts.fragment and not parts.query and
                ((parts.netloc == 'api.github.com' and parts.path.startswith('/repos/')) or
                 (parts.netloc == 'gitlab.com' and parts.path.startswith('/api/v4/projects/'))) and
                re.fullmatch(r'/[A-Za-z0-9_./%~-]+', parts.path) is not None and
                '/../' not in parts.path and not parts.path.endswith('/..') and
                '//' not in parts.path and not re.search(r'%(?![0-9A-Fa-f]{2})', parts.path),
                'ENDPOINT_REJECTED')
        require(type(timeout) in (int, float) and 0 < timeout <= MAX_REQUEST_TIMEOUT,
                'TIMEOUT_INVALID', 'invalid_input')
        opener = build_opener(ProxyHandler({}), _RejectRedirect(),
                              HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(Request(url, headers=headers, method='GET'), timeout=timeout) as response:
                require(response.status == 200 and response.geturl() == url, 'ENDPOINT_REJECTED')
                ctype = response.headers.get('Content-Type', '').split(';', 1)[0].lower().strip()
                require(ctype == 'application/json' or
                        (ctype.startswith('application/') and ctype.endswith('+json')),
                        'SOURCE_CONTENT_TYPE_INVALID')
                length = response.headers.get('Content-Length')
                require(not (length and length.isdecimal() and int(length) > MAX_BODY),
                        'SOURCE_PAYLOAD_TOO_LARGE')
                data = response.read(MAX_BODY + 1)
                require(len(data) <= MAX_BODY, 'SOURCE_PAYLOAD_TOO_LARGE')
                return ci._json_object(data)
        except HTTPError as e:
            if 300 <= e.code < 400:
                raise BindError('REDIRECT_REFUSED') from None
            if e.code in (401, 403):
                raise BindError('SOURCE_PERMISSION_DENIED') from None
            if e.code == 404:
                raise BindError('SOURCE_NOT_FOUND') from None
            if e.code == 429:
                raise BindError('SOURCE_RATE_LIMITED') from None
            raise BindError('SOURCE_HTTP_UNAVAILABLE') from None
        except (URLError, OSError, TimeoutError, socket.timeout, ssl.SSLError):
            raise BindError('SOURCE_NETWORK_UNAVAILABLE') from None
        except ci.CIError:
            raise BindError('SOURCE_PAYLOAD_INVALID') from None


def _scope(value: SourceSelection) -> SourceSelection:
    require(type(value) is SourceSelection, 'SELECTION_INVALID', 'invalid_input')
    try:
        key = ci._selection(value.ci)
    except ci.CIError:
        raise BindError('CI_SELECTION_INVALID', 'invalid_input') from None
    require(type(value.mode) is str and value.mode in ('DeliveredTarget', 'ProposedPR'),
            'SOURCE_MODE_UNSUPPORTED', 'invalid_input')
    if value.mode == 'ProposedPR':
        require(ci._valid_id(value.proposal_number) and value.proposal_number <= 2**31-1,
                'PROPOSAL_NUMBER_REQUIRED', 'invalid_input')
    else:
        require(value.proposal_number is None, 'PROPOSAL_FORBIDDEN_FOR_DELIVERED', 'invalid_input')
    require(type(value.receipt_max_age_seconds) is int and
            60 <= value.receipt_max_age_seconds <= 900,
            'RECEIPT_AGE_INVALID', 'invalid_input')
    return SourceSelection(key, value.mode, value.proposal_number, value.receipt_max_age_seconds)


def _utc(clock: Callable[[], datetime] | None) -> datetime:
    try:
        return ci._now(clock)
    except ci.CIError:
        raise BindError('CLOCK_UNAVAILABLE', 'invalid_input') from None


def _time(value: Any) -> datetime:
    try:
        return ci._time(value)
    except ci.CIError:
        raise BindError('TIME_INVALID') from None


def _sha(value: Any) -> str:
    require(type(value) is str and ci.SHA.fullmatch(value) is not None and
            any(x != '0' for x in value), 'SOURCE_SHA_INVALID')
    return value.lower()


def _endpoint(selection: SourceSelection, kind: str) -> str:
    s = selection.ci
    if s.provider == 'github':
        base = 'https://api.github.com/repos/' + s.repository
        options = {'REPO': base, 'REF': base + '/git/ref/heads/' + quote(s.branch, safe='/'),
                   'OBJECT': base + '/git/commits/' + s.commit_sha,
                   'PR': base + '/pulls/' + str(selection.proposal_number)}
    else:
        base = 'https://gitlab.com/api/v4/projects/' + str(s.project_id)
        options = {'REPO': base, 'REF': base + '/repository/branches/' + quote(s.branch, safe=''),
                   'OBJECT': base + '/repository/commits/' + s.commit_sha,
                   'PR': base + '/merge_requests/' + str(selection.proposal_number)}
    return options[kind]


def _headers(selection: SourceSelection, credential: str) -> dict[str, str]:
    base = {'User-Agent': 'CES-EC183-SHA-Bind/1', 'Accept-Encoding': 'identity'}
    if selection.ci.provider == 'github':
        return {**base, 'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2026-03-10', 'Authorization': 'Bearer ' + credential}
    return {**base, 'Accept': 'application/json', 'PRIVATE-TOKEN': credential}


def _same_name(got: Any, want: str) -> None:
    require(type(got) is str and got.casefold() == want.casefold(),
            'SOURCE_REPOSITORY_NAME_MISMATCH')


def _repository(value: dict[str, Any], selection: SourceSelection) -> tuple[int, str]:
    s = selection.ci
    require(ci._valid_id(value.get('id')) and value['id'] == s.project_id,
            'SOURCE_REPOSITORY_ID_MISMATCH')
    if s.provider == 'github':
        _same_name(value.get('full_name'), s.repository)
        require(value.get('archived') is False and value.get('disabled') is False,
                'SOURCE_REPOSITORY_INACTIVE')
    else:
        _same_name(value.get('path_with_namespace'), s.repository)
        require(value.get('archived') is False and value.get('empty_repo') is False,
                'SOURCE_REPOSITORY_INACTIVE')
    return s.project_id, s.repository.casefold()


def _branch(value: dict[str, Any], selection: SourceSelection) -> tuple[str, str]:
    s = selection.ci
    if s.provider == 'github':
        require(value.get('ref') == 'refs/heads/' + s.branch and
                type(value.get('object')) is dict and
                value['object'].get('type') == 'commit', 'BRANCH_IDENTITY_MISMATCH')
        found = _sha(value['object'].get('sha'))
    else:
        require(value.get('name') == s.branch and type(value.get('commit')) is dict,
                'BRANCH_IDENTITY_MISMATCH')
        found = _sha(value['commit'].get('id'))
    require(found == s.commit_sha, 'SOURCE_CI_SHA_MISMATCH')
    return s.branch, found


def _proposal(value: dict[str, Any], selection: SourceSelection) -> tuple[int, int, str]:
    s = selection.ci
    if s.provider == 'github':
        require(ci._valid_id(value.get('id')) and type(value.get('number')) is int and
                value['number'] == selection.proposal_number and value.get('state') == 'open' and
                value.get('merged_at') is None, 'PROPOSAL_IDENTITY_OR_STATE_MISMATCH')
        head, base = value.get('head'), value.get('base')
        require(type(head) is dict and type(base) is dict and
                type(head.get('repo')) is dict and type(base.get('repo')) is dict,
                'PROPOSAL_REPOSITORY_MISSING')
        require(ci._valid_id(head['repo'].get('id')) and
                ci._valid_id(base['repo'].get('id')) and
                head['repo']['id'] == base['repo']['id'] == s.project_id,
                'CROSS_FORK_NOT_BOUND')
        _same_name(head['repo'].get('full_name'), s.repository)
        _same_name(base['repo'].get('full_name'), s.repository)
        require(head.get('ref') == s.branch, 'PROPOSAL_BRANCH_MISMATCH')
        oid = _sha(head.get('sha'))
    else:
        require(ci._valid_id(value.get('id')) and type(value.get('iid')) is int and
                value['iid'] == selection.proposal_number and
                value.get('state') == 'opened' and
                value.get('project_id') == s.project_id,
                'PROPOSAL_IDENTITY_OR_STATE_MISMATCH')
        require(value.get('target_project_id') == s.project_id and
                value.get('source_project_id') == s.project_id,
                'CROSS_FORK_NOT_BOUND')
        require(value.get('source_branch') == s.branch, 'PROPOSAL_BRANCH_MISMATCH')
        refs = value.get('diff_refs')
        require(type(refs) is dict, 'PROPOSAL_DIFF_HEAD_UNKNOWN')
        oid = _sha(value.get('sha'))
        require(_sha(refs.get('head_sha')) == oid, 'PROPOSAL_DIFF_HEAD_DRIFT')
    require(oid == s.commit_sha, 'PROPOSAL_CI_SHA_MISMATCH')
    return selection.proposal_number, value['id'], oid


def _commit(value: dict[str, Any], selection: SourceSelection) -> str:
    s = selection.ci
    oid = _sha(value.get('sha') if s.provider == 'github' else value.get('id'))
    require(oid == s.commit_sha, 'COMMIT_OBJECT_SHA_MISMATCH')
    if s.provider == 'github':
        tree = value.get('tree')
        require(type(tree) is dict and type(tree.get('sha')) is str and
                ci.SHA.fullmatch(tree['sha']) is not None,
                'COMMIT_OBJECT_TYPE_UNVERIFIED')
    return oid


def _original_receipt(receipt: Any, selection: SourceSelection, now: datetime,
                      synthetic_allowed: bool) -> tuple[dict[str, Any], bool]:
    require(type(receipt) is dict and len(canonical(receipt)) <= MAX_RECEIPT,
            'CI_RECEIPT_INVALID', 'invalid_input')
    require(set(receipt) == {'schema', 'status', 'exit_code', 'reason_code',
                            'source', 'observation', 'permission', 'coverage',
                            'observation_sha256', 'effects', 'trust_boundary'} and
            receipt['schema'] == ci.SCHEMA and receipt['status'] == 'partial' and
            type(receipt['exit_code']) is int and receipt['exit_code'] == 2 and
            receipt['reason_code'] == 'QUALITYREADCI_CI_METADATA_OBSERVED',
            'CI_RECEIPT_INVALID', 'invalid_input')
    source, observed, permission, coverage = (receipt[k] for k in
        ('source', 'observation', 'permission', 'coverage'))
    require(all(type(x) is dict for x in (source, observed, permission, coverage)) and
            type(receipt.get('effects')) is dict and
            type(receipt.get('observation_sha256')) is str and
            re.fullmatch('[a-f0-9]{64}', receipt['observation_sha256']) is not None,
            'CI_RECEIPT_INVALID', 'invalid_input')
    require(ci._hash({'source': source, 'observation': observed,
                      'permission': permission, 'coverage': coverage}) ==
            receipt['observation_sha256'], 'CI_RECEIPT_DIGEST_MISMATCH', 'invalid_input')
    key = selection.ci
    required = {'provider': key.provider, 'repository': key.repository,
                'project_id': key.project_id, 'workflow_id': key.workflow_id,
                'run_id': key.run_id, 'attempt': key.attempt,
                'job_id': key.job_id, 'branch': key.branch, 'commit_sha': key.commit_sha}
    require(all(type(source.get(k)) is type(v) and source.get(k) == v
                for k, v in required.items()) and
            type(source.get('observed_at')) is str and
            type(source.get('api_version')) is str,
            'CI_RECEIPT_SCOPE_MISMATCH')
    synthetic = permission.get('transport') == 'SYNTHETIC'
    require(permission.get('transport') in ('SYNTHETIC', 'LIVE_HTTPS') and
            permission.get('host_scope') == 'HOST_CALLBACK_ALLOWED' and
            permission.get('credential_identity') == 'NOT_ATTESTED' and
            permission.get('provider_read') ==
            ('NOT_PROVEN_SYNTHETIC' if synthetic else 'HTTPS_200_TOKEN_PRESENT'),
            'CI_RECEIPT_PROVENANCE_INVALID')
    require(not synthetic or synthetic_allowed is True,
            'SYNTHETIC_RECEIPT_NOT_PERMITTED', 'invalid_input')
    required_cover = ('exact_project_id', 'exact_repository_path',
                      'workflow_run_identity', 'exact_job_identity',
                      'branch_field_equal', 'commit_field_equal',
                      'run_final', 'job_final', 'within_requested_age',
                      'rechecked_run_for_drift')
    require(all(coverage.get(k) is True for k in required_cover) and
            coverage.get('attempt_bound') is (key.provider == 'github') and
            coverage.get('git_sha_binding_verified') is False and
            coverage.get('test_execution_by_ces') is False and
            coverage.get('cross_request_atomic_snapshot') is False and
            type(observed.get('run')) is dict and type(observed.get('job')) is dict and
            observed['run'].get('conclusion') in ('success', 'failure') and
            observed['job'].get('conclusion') in ('success', 'failure'),
            'CI_RECEIPT_COVERAGE_INVALID')
    stamp = _time(source['observed_at'])
    require(now - timedelta(seconds=selection.receipt_max_age_seconds) <= stamp <=
            now + timedelta(seconds=SKEW) and
            stamp >= now - timedelta(seconds=key.max_result_age_seconds),
            'CI_RECEIPT_STALE')
    require(_time(observed['run'].get('updated_at')) <= stamp + timedelta(seconds=SKEW) and
            _time(observed['job'].get('completed_at')) <= stamp + timedelta(seconds=SKEW),
            'CI_RECEIPT_TIME_INVALID')
    return receipt, synthetic


def _refused(code: str, status: str, source_calls: int, ci_calls: int,
             synthetic: bool) -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': status, 'exit_code': EXIT[status],
            'reason_code': code, 'source': None, 'ci_observation': None,
            'binding': None, 'coverage': None, 'association_sha256': None,
            'permission': {'source_scope': 'NOT_ATTESTED', 'ci_scope': 'NOT_ATTESTED',
                           'transport': 'SYNTHETIC' if synthetic else 'UNDETERMINED',
                           'credential_identity': 'NOT_ATTESTED'},
            'effects': {'read_only': True, 'source_get_calls': source_calls,
                        'ci_get_calls': ci_calls,
                        'live_source_get_requests': 0 if synthetic else source_calls,
                        'live_ci_get_requests': 0 if synthetic else ci_calls,
                        'executed_commands': False, 'git_operations': False,
                        'read_ci_logs': False, 'writes_performed': False},
            'trust_boundary': 'NO_BINDING_ON_REFUSAL'}


class QualitySHABinder:
    def __init__(self, source_transport: SourceTransport | None = None,
                 ci_reader: ci.QualityCIReader | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.source_transport = source_transport if source_transport is not None else StrictSourceHTTPS()
        self.source_synthetic = type(self.source_transport) is not StrictSourceHTTPS
        self.ci_reader = ci_reader if ci_reader is not None else ci.QualityCIReader(clock=clock)
        self.clock = clock

    def bind(self, selected: SourceSelection, *, ci_receipt: dict[str, Any],
             source_credential: str | None, ci_credential: str | None,
             allow_network: bool, allow_ci_read: bool,
             allow_receipt_reuse: bool, allow_source_read: bool,
             authorize_source: Callable[[dict[str, Any]], bool] | None,
             authorize_ci: Callable[[dict[str, Any]], bool] | None,
             allow_synthetic_development: bool = False) -> dict[str, Any]:
        source_calls = 0
        ci_calls = 0
        synthetic = self.source_synthetic or self.ci_reader.synthetic
        try:
            s = _scope(selected)
            require(all(x is True for x in
                        (allow_network, allow_ci_read, allow_receipt_reuse, allow_source_read)),
                    'INDEPENDENT_OPTINS_REQUIRED', 'invalid_input')
            require(callable(authorize_source) and callable(authorize_ci),
                    'INDEPENDENT_GRANTS_REQUIRED', 'invalid_input')
            require(type(source_credential) is str and
                    ci.TOKEN.fullmatch(source_credential) is not None and
                    type(ci_credential) is str and ci.TOKEN.fullmatch(ci_credential) is not None,
                    'TWO_CREDENTIALS_REQUIRED', 'invalid_input')
            require(self.source_synthetic == self.ci_reader.synthetic,
                    'MIXED_TRANSPORT_PROVENANCE', 'invalid_input')
            require(not synthetic or allow_synthetic_development is True,
                    'SYNTHETIC_DEVELOPMENT_NOT_PERMITTED', 'invalid_input')
            beginning = _utc(self.clock)
            original, receipt_synthetic = _original_receipt(
                ci_receipt, s, beginning, allow_synthetic_development)
            require(synthetic == receipt_synthetic, 'CI_RECEIPT_TRANSPORT_MISMATCH')
            deadline = time.monotonic() + MAX_DURATION
            scope = {'provider': s.ci.provider, 'repository': s.ci.repository,
                     'project_id': s.ci.project_id, 'branch': s.ci.branch,
                     'commit_sha': s.ci.commit_sha, 'mode': s.mode,
                     'proposal_number': s.proposal_number, 'workflow_id': s.ci.workflow_id,
                     'run_id': s.ci.run_id, 'attempt': s.ci.attempt,
                     'job_id': s.ci.job_id}
            headers = _headers(s, source_credential)

            def source_grant(kind: str) -> None:
                try:
                    result = authorize_source({**scope, 'operation': 'GET_SOURCE_METADATA_ONLY',
                                               'read_kind': kind})
                except Exception:
                    raise BindError('SOURCE_SCOPE_DENIED') from None
                require(result is True, 'SOURCE_SCOPE_DENIED')

            def read(kind: str, action: str) -> dict[str, Any]:
                nonlocal source_calls
                source_grant(kind)
                require(source_calls < MAX_GETS, 'SOURCE_REQUEST_BUDGET_EXCEEDED')
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'TOTAL_DEADLINE_EXCEEDED')
                source_calls += 1
                try:
                    value = self.source_transport.get(_endpoint(s, action), headers,
                                                      min(MAX_REQUEST_TIMEOUT, remaining))
                except BindError:
                    raise
                except Exception:
                    raise BindError('SOURCE_TRANSPORT_FAILED') from None
                require(type(value) is dict and len(canonical(value)) <= MAX_BODY,
                        'SOURCE_PAYLOAD_INVALID')
                return value

            repo_before = _repository(read('REPOSITORY_BEFORE', 'REPO'), s)
            proposal_before = (_proposal(read('PROPOSAL_BEFORE', 'PR'), s)
                               if s.mode == 'ProposedPR' else None)
            branch_before = _branch(read('BRANCH_BEFORE', 'REF'), s)
            commit_sha = _commit(read('COMMIT_OBJECT', 'OBJECT'), s)

            def ci_grant(info: dict[str, Any]) -> bool:
                try:
                    return authorize_ci({**info, 'ec183_source_mode': s.mode,
                                         'ec183_proposal_number': s.proposal_number}) is True
                except Exception:
                    return False

            fresh = self.ci_reader.read(s.ci, credential=ci_credential,
                                        allow_network=allow_network,
                                        allow_ci_metadata=allow_ci_read,
                                        authorize=ci_grant)
            ci_calls = fresh.get('effects', {}).get('transport_get_calls', 0)
            require(fresh.get('schema') == ci.SCHEMA and fresh.get('status') == 'partial' and
                    fresh.get('reason_code') == 'QUALITYREADCI_CI_METADATA_OBSERVED',
                    'FRESH_CI_RECHECK_FAILED')
            require(fresh['permission']['transport'] ==
                    ('SYNTHETIC' if synthetic else 'LIVE_HTTPS'),
                    'FRESH_CI_PROVENANCE_CHANGED')
            old_src, new_src = original['source'], fresh['source']
            compared = ('provider', 'repository', 'project_id', 'workflow_id',
                        'run_id', 'attempt', 'job_id', 'branch', 'commit_sha', 'api_version')
            require(all(old_src[k] == new_src.get(k) for k in compared) and
                    original['observation'] == fresh.get('observation'),
                    'FRESH_CI_OBSERVATION_DRIFT')
            require(_time(new_src['observed_at']) >=
                    _time(old_src['observed_at']) - timedelta(seconds=SKEW),
                    'FRESH_CI_OBSERVATION_TIME_DRIFT')
            require(time.monotonic() < deadline, 'TOTAL_DEADLINE_EXCEEDED')
            proposal_after = (_proposal(read('PROPOSAL_AFTER', 'PR'), s)
                              if s.mode == 'ProposedPR' else None)
            branch_after = _branch(read('BRANCH_AFTER', 'REF'), s)
            repo_after = _repository(read('REPOSITORY_AFTER', 'REPO'), s)
            require(repo_before == repo_after and proposal_before == proposal_after and
                    branch_before == branch_after, 'SOURCE_DRIFT_DURING_ASSOCIATION')
            source_grant('FINALIZE_SOURCE_BINDING')
            require(ci_grant({**scope, 'operation': 'GET_CI_METADATA_ONLY',
                              'read_kind': 'FINALIZE_CI_BINDING'}),
                    'CI_SCOPE_REVOKED')
            finished = _utc(self.clock)
            require(beginning - timedelta(seconds=SKEW) <= finished <=
                    beginning + timedelta(seconds=MAX_DURATION+SKEW),
                    'CLOCK_DRIFT')
            _original_receipt(original, s, finished, allow_synthetic_development)
            kind = 'SYNTHETIC_DEVELOPMENT' if synthetic else 'LIVE_PROVIDER_METADATA'
            source = {'provider': s.ci.provider, 'repository': s.ci.repository,
                      'project_id': s.ci.project_id, 'source_mode': s.mode,
                      'proposal_number': s.proposal_number,
                      'proposal_object_id': proposal_after[1] if proposal_after else None,
                      'branch': s.ci.branch, 'commit_sha': commit_sha,
                      'observed_at': ci._fmt(finished), 'authority': kind}
            ci_info = {'run_id': s.ci.run_id, 'workflow_id': s.ci.workflow_id,
                       'attempt': s.ci.attempt, 'job_id': s.ci.job_id,
                       'run_conclusion': fresh['observation']['run']['conclusion'],
                       'job_conclusion': fresh['observation']['job']['conclusion'],
                       'original_observation_sha256': original['observation_sha256'],
                       'fresh_observation_sha256': fresh['observation_sha256'],
                       'fresh_observed_at': new_src['observed_at']}
            binding = {'source_commit_sha': commit_sha, 'ci_commit_sha': new_src['commit_sha'],
                       'sha_equal': True,
                       'association_level': 'SYNTHETIC_EQUALITY_ONLY' if synthetic else
                                            'PROVIDER_SOURCE_CI_METADATA_ASSOCIATED',
                       'git_object_bytes_hashed': False, 'working_tree_verified': False,
                       'tests_executed_by_ces': False, 'actor_verified': False}
            permission = {'source_scope': 'HOST_CALLBACK_ALLOWED',
                          'ci_scope': 'HOST_CALLBACK_ALLOWED',
                          'transport': 'SYNTHETIC' if synthetic else 'LIVE_HTTPS',
                          'credential_identity': 'NOT_ATTESTED'}
            coverage = {'exact_repository_id': True, 'repository_rechecked': True,
                        'branch_rechecked': True,
                        'proposal_rechecked': s.mode == 'ProposedPR',
                        'commit_endpoint_read': True,
                        'fresh_ci_rechecked': True,
                        'ci_metadata_unchanged': True, 'receipt_age_checked': True,
                        'ci_source_sha_associated': not synthetic,
                        'git_object_bytes_hashed': False,
                        'working_tree_verified': False, 'test_execution_by_ces': False,
                        'logs_inspected': False, 'atomic_cross_request_snapshot': False}
            payload = {'source': source, 'ci_observation': ci_info,
                       'binding': binding, 'permission': permission, 'coverage': coverage}
            return {'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                    'reason_code': REASON + 'CI_SOURCE_SHA_ASSOCIATED', **payload,
                    'association_sha256': checksum(payload),
                    'effects': {'read_only': True, 'source_get_calls': source_calls,
                                'ci_get_calls': ci_calls,
                                'live_source_get_requests': 0 if synthetic else source_calls,
                                'live_ci_get_requests': 0 if synthetic else ci_calls,
                                'executed_commands': False, 'git_operations': False,
                                'read_ci_logs': False, 'writes_performed': False},
                    'trust_boundary': 'SYNTHETIC_UNVERIFIED' if synthetic else
                                      'PROVIDER_METADATA_ONLY_NO_GIT_BYTES_OR_RUNNER'}
        except BindError as error:
            return _refused(error.code, error.status, source_calls, ci_calls, synthetic)
        except (ci.CIError, TypeError, ValueError, OverflowError, RecursionError,
                KeyError, AttributeError, MemoryError):
            return _refused(REASON + 'INVALID_UNTRUSTED_FIELD', 'unavailable',
                            source_calls, ci_calls, synthetic)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='EC183 exact CI/source SHA provider association')
    p.add_argument('--receipt', required=True)
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
    p.add_argument('--receipt-max-age', type=int, default=300)
    for flag in ('allow-network', 'allow-ci-read', 'allow-receipt-reuse', 'allow-source-read'):
        p.add_argument('--' + flag, action='store_true')
    a = p.parse_args(argv)
    try:
        raw = Path(a.receipt).read_bytes()
        receipt = ci._json_object(raw) if len(raw) <= MAX_RECEIPT else {}
    except (OSError, ci.CIError):
        receipt = {}
    selected = SourceSelection(
        ci.CISelection(a.provider, a.repository, a.project_id, a.workflow_id, a.run_id,
                       a.attempt, a.job_id, a.branch, a.commit_sha, a.ci_max_age),
        a.source_mode, a.proposal_number, a.receipt_max_age)
    # CLI switches are operator declarations; external policy must independently
    # validate who is permitted to read this project/CI run/source.
    result = QualitySHABinder().bind(
        selected, ci_receipt=receipt,
        source_credential=os.environ.get('CES_SOURCE_' + a.provider.upper() + '_TOKEN'),
        ci_credential=os.environ.get(ci.ENV_TOKENS[a.provider]),
        allow_network=a.allow_network, allow_ci_read=a.allow_ci_read,
        allow_receipt_reuse=a.allow_receipt_reuse,
        allow_source_read=a.allow_source_read,
        authorize_source=lambda x: a.allow_source_read and
             x.get('operation') == 'GET_SOURCE_METADATA_ONLY',
        authorize_ci=lambda x: a.allow_ci_read and
             x.get('operation') == 'GET_CI_METADATA_ONLY')
    print(json.dumps(result, sort_keys=True, ensure_ascii=True, separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
