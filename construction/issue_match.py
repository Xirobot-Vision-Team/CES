#!/usr/bin/env python3
"""EC-214: bounded, independently authorized read-only IssueMatch *candidates*.

The input is a manually selected allowlist of 1..8 **pinned** Issues in one
repository, not discovery or a provider search. Every candidate is read by
EC211's actual three-GET reader; EC212's redacted projection is revalidated.
User-supplied evidence anchors are explicitly unverified assertions. Optional
provider-title comparison is performed only in memory, with a separate grant
binding the EXACT request, candidates, privacy classes, and short expiry.
Similarity is a lexical REVIEW HINT, never a duplicate or absence finding.

No provider POST/PATCH/PUT/DELETE, cache, local write, native CES action, Issue
mutation, remote listing, embedding service, or AI/model data egress.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
import re
import sys
import unicodedata
from typing import Any, Callable, Mapping

try:
    from . import issue_provider as ip
    from . import issue_sync as es
except ImportError:
    import issue_provider as ip
    import issue_sync as es

SCHEMA = 'ces.issue_match.v1'
METHOD = 'COMPARE_SELECTED_ISSUE_CANDIDATES'
TITLE_METHOD = 'COMPARE_SELECTED_ISSUE_TITLES_IN_MEMORY'
FINGERPRINT_DOMAIN = b'CES-EC214-ISSUE-MATCH-REQUEST-v1\x00'
MAX_CANDIDATES = 8
MAX_ANCHORS = 16
MAX_GRANT_SECONDS = 300
MAX_AGE_SECONDS = 120
MAX_TITLE_CHARS = 512
PRIVACY_CLASSES = ('STANDARD', 'NOT_REPORTED', 'CONFIDENTIAL')
SHA = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
COMMIT = re.compile(r'(?:[a-f0-9]{40}|[a-f0-9]{64})\Z', re.ASCII)
SAFE_REASON = re.compile(r'ISSUE_[A-Z0-9_]{1,90}\Z', re.ASCII)
TOKENS = re.compile(r'[\w]+', re.UNICODE)


@dataclass(frozen=True)
class EvidenceAnchor:
    """Caller-asserted exact source locator, NOT remotely Issue-authenticated."""
    commit_sha: str
    path: str
    line_start: int
    line_end: int
    evidence_sha256: str


@dataclass(frozen=True)
class MatchCandidate:
    number: int
    expected_provider_issue_id: int  # Stable global provider ID, not local number.
    anchors: tuple[EvidenceAnchor, ...] = ()


@dataclass(frozen=True)
class IssueMatchRequest:
    repository: str
    expected_repository_id: int
    candidates: tuple[MatchCandidate, ...]
    subject_anchors: tuple[EvidenceAnchor, ...] = ()
    subject_title: str | None = None
    # This must be explicitly authorized. Disabled mode never inspects titles.
    title_policy: str = 'DISABLED'  # DISABLED or AUTHORIZED
    # Even a grant cannot silently widen this list; defaults to GL STANDARD only.
    title_privacies: tuple[str, ...] = ('STANDARD',)
    max_observation_age_seconds: int = MAX_AGE_SECONDS


@dataclass(frozen=True)
class IssueMatchGrant:
    method: str
    provider: str
    api_host: str
    account_ref: str
    repository: str
    expected_repository_id: int
    candidate_pins: tuple[tuple[int, int], ...]
    request_sha256: str
    expires_at_utc: str
    authorized: bool
    allow_write: bool = False


@dataclass(frozen=True)
class IssueTitleGrant:
    method: str
    provider: str
    api_host: str
    account_ref: str
    repository: str
    expected_repository_id: int
    candidate_pins: tuple[tuple[int, int], ...]
    request_sha256: str
    allowed_privacies: tuple[str, ...]
    expires_at_utc: str
    authorized: bool
    allow_write: bool = False


class MatchError(ValueError):
    def __init__(self, reason: str, status: str = 'unavailable') -> None:
        super().__init__(reason)  # Stable codes only, no source details.
        self.reason = 'ISSUE_MATCH_' + reason
        self.status = status


def _need(ok: bool, code: str, status: str = 'unavailable') -> None:
    if not ok:
        raise MatchError(code, status)


def _now(clock: Callable[[], datetime] | None) -> datetime:
    try:
        return ip._now(clock)
    except ip.IssueError:
        raise MatchError('CLOCK_UNAVAILABLE') from None


def _timestamp(value: Any) -> datetime:
    try:
        return ip._at_utc(value)
    except ip.IssueError:
        raise MatchError('TIMESTAMP_INVALID', 'invalid_input') from None


def _stamp(value: datetime) -> str:
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _valid_title(title: Any) -> bool:
    return (type(title) is str and 1 <= len(title.strip()) <= MAX_TITLE_CHARS and
            len(title) <= MAX_TITLE_CHARS and not any(
                ord(ch) < 32 or 0x7f <= ord(ch) <= 0x9f or
                0xd800 <= ord(ch) <= 0xdfff for ch in title))


def _anchor_dict(anchor: EvidenceAnchor) -> dict[str, Any]:
    return dict(commit_sha=anchor.commit_sha, path=anchor.path,
                line_start=anchor.line_start, line_end=anchor.line_end,
                evidence_sha256=anchor.evidence_sha256)


def _anchors_valid(anchors: Any) -> bool:
    if type(anchors) is not tuple or len(anchors) > MAX_ANCHORS:
        return False
    seen: set[EvidenceAnchor] = set()
    for a in anchors:
        if type(a) is not EvidenceAnchor:
            return False
        if (type(a.commit_sha) is not str or COMMIT.fullmatch(a.commit_sha) is None or
                type(a.evidence_sha256) is not str or SHA.fullmatch(a.evidence_sha256) is None or
                type(a.path) is not str or not (1 <= len(a.path) <= 240) or
                '\\' in a.path or a.path.startswith('/') or
                any(s in ('', '.', '..') for s in a.path.split('/')) or
                any(ord(c) < 32 or 0x7f <= ord(c) <= 0x9f or
                    0xd800 <= ord(c) <= 0xdfff for c in a.path) or
                type(a.line_start) is not int or type(a.line_end) is not int or
                not (1 <= a.line_start <= a.line_end <= 10000000) or
                a.line_end - a.line_start > 1000):
            return False
        if a in seen:
            return False
        seen.add(a)
    return True


def _pins(request: IssueMatchRequest) -> tuple[tuple[int, int], ...]:
    return tuple((c.number, c.expected_provider_issue_id) for c in request.candidates)


def _validate_request(context: ip.ProviderContext, req: IssueMatchRequest) -> None:
    try:
        ip._validate_context(context)
    except ip.IssueError as e:
        raise MatchError('CONTEXT_INVALID', e.status) from None
    _need(type(req) is IssueMatchRequest, 'REQUEST_INVALID', 'invalid_input')
    _need(ip._positive_id(req.expected_repository_id) and
          type(req.candidates) is tuple and 1 <= len(req.candidates) <= MAX_CANDIDATES,
          'ALLOWLIST_INVALID', 'invalid_input')
    _need(type(req.max_observation_age_seconds) is int and
          1 <= req.max_observation_age_seconds <= MAX_AGE_SECONDS,
          'FRESHNESS_INVALID', 'invalid_input')
    _need(type(req.title_policy) is str and
          req.title_policy in ('DISABLED', 'AUTHORIZED') and
          type(req.title_privacies) is tuple and
          1 <= len(req.title_privacies) <= len(PRIVACY_CLASSES) and
          all(type(x) is str and x in PRIVACY_CLASSES for x in req.title_privacies) and
          req.title_privacies == tuple(x for x in PRIVACY_CLASSES if x in req.title_privacies),
          'TITLE_POLICY_INVALID', 'invalid_input')
    _need(req.subject_title is None or _valid_title(req.subject_title),
          'SUBJECT_TITLE_INVALID', 'invalid_input')
    _need(req.title_policy == 'DISABLED' or _valid_title(req.subject_title),
          'TITLE_COMPARISON_SUBJECT_REQUIRED', 'invalid_input')
    _need(req.title_policy != 'DISABLED' or
          (req.subject_title is None and req.title_privacies == ('STANDARD',)),
          'DISABLED_TITLE_POLICY_NOT_EMPTY', 'invalid_input')
    _need(_anchors_valid(req.subject_anchors), 'SUBJECT_ANCHORS_INVALID', 'invalid_input')
    numbers: list[int] = []
    ids: set[int] = set()
    for c in req.candidates:
        _need(type(c) is MatchCandidate and
              ip._positive_id(c.expected_provider_issue_id) and
              _anchors_valid(c.anchors), 'CANDIDATE_INVALID', 'invalid_input')
        _need(c.expected_provider_issue_id not in ids,
              'DUPLICATE_EXPECTED_ISSUE_ID', 'invalid_input')
        ids.add(c.expected_provider_issue_id)
        numbers.append(c.number)
    _need(numbers == sorted(set(numbers)) and
          all(type(n) is int and 1 <= n <= 2147483647 for n in numbers),
          'ALLOWLIST_INVALID', 'invalid_input')
    try:
        ip._validate_scope(context, ip.IssueSelection(
            req.repository, numbers[0], req.expected_repository_id))
    except ip.IssueError:
        raise MatchError('SCOPE_INVALID', 'invalid_input') from None


def _fingerprint(request: IssueMatchRequest) -> str:
    # Validate input BEFORE calling; method is for matching an exact approved
    # input to grants, not a provider-authenticated or secret-safe signature.
    subject = {
        'repository': request.repository,
        'repository_id': str(request.expected_repository_id),
        'subject_title': request.subject_title,  # hashed, never echoed
        'subject_anchors': [_anchor_dict(a) for a in request.subject_anchors],
        'candidates': [dict(number=c.number, expected_provider_issue_id=str(c.expected_provider_issue_id),
                            anchors=[_anchor_dict(a) for a in c.anchors])
                       for c in request.candidates],
        'title_policy': request.title_policy,
        'title_privacies': list(request.title_privacies),
        'max_observation_age_seconds': request.max_observation_age_seconds,
    }
    return hashlib.sha256(FINGERPRINT_DOMAIN + ip._canonical(subject)).hexdigest()


def request_fingerprint(context: ip.ProviderContext, request: IssueMatchRequest) -> str:
    """Compute a non-secret binding fingerprint for *validated* exact input."""
    _validate_request(context, request)
    return _fingerprint(request)


def _grants(match_grant: IssueMatchGrant | None,
            title_grant: IssueTitleGrant | None,
            read_grants: Mapping[int, ip.IssueReadGrant] | None,
            ctx: ip.ProviderContext, req: IssueMatchRequest,
            digest: str, now: datetime) -> None:
    _need(type(match_grant) is IssueMatchGrant and match_grant.authorized is True and
          match_grant.allow_write is False and match_grant.method == METHOD,
          'MATCH_GRANT_REQUIRED')
    pins = _pins(req)
    _need(match_grant.provider == ctx.provider and
          match_grant.api_host == ctx.api_host and
          match_grant.account_ref == ctx.account_ref and
          match_grant.repository == req.repository and
          type(match_grant.expected_repository_id) is int and
          match_grant.expected_repository_id == req.expected_repository_id and
          type(match_grant.candidate_pins) is tuple and
          match_grant.candidate_pins == pins and
          type(match_grant.request_sha256) is str and
          match_grant.request_sha256 == digest,
          'MATCH_GRANT_SCOPE_MISMATCH')
    limit = _timestamp(match_grant.expires_at_utc)
    _need(now < limit <= now + timedelta(seconds=MAX_GRANT_SECONDS),
          'MATCH_GRANT_EXPIRED_OR_TOO_BROAD')
    if req.title_policy == 'AUTHORIZED':
        _need(type(title_grant) is IssueTitleGrant and
              title_grant.authorized is True and title_grant.allow_write is False and
              title_grant.method == TITLE_METHOD, 'TITLE_GRANT_REQUIRED')
        _need(title_grant.provider == ctx.provider and
              title_grant.api_host == ctx.api_host and
              title_grant.account_ref == ctx.account_ref and
              title_grant.repository == req.repository and
              type(title_grant.expected_repository_id) is int and
              title_grant.expected_repository_id == req.expected_repository_id and
              type(title_grant.candidate_pins) is tuple and
              title_grant.candidate_pins == pins and
              type(title_grant.request_sha256) is str and
              title_grant.request_sha256 == digest and
              type(title_grant.allowed_privacies) is tuple and
              title_grant.allowed_privacies == req.title_privacies,
              'TITLE_GRANT_SCOPE_MISMATCH')
        limit = _timestamp(title_grant.expires_at_utc)
        _need(now < limit <= now + timedelta(seconds=MAX_GRANT_SECONDS),
              'TITLE_GRANT_EXPIRED_OR_TOO_BROAD')
    else:
        _need(title_grant is None, 'TITLE_GRANT_UNEXPECTED', 'invalid_input')
    _need(type(read_grants) is dict and
          all(type(k) is int for k in read_grants) and
          set(read_grants) == {n for n, _ in pins}, 'PROVIDER_GRANTS_REQUIRED')
    for n, _ in pins:
        try:
            ip._validate_grant(read_grants[n], ctx,
                               ip.IssueSelection(req.repository, n,
                                                 req.expected_repository_id), now)
        except ip.IssueError:
            raise MatchError('PROVIDER_GRANT_INVALID') from None


class _CaptureTitleTransport:
    """Pass-through to EC211 reader: keep validated Issue title ephemeral.

    Wrap ONLY after exact title permission preflight. This captures only the
    second of EC211's three GET responses and never exposes a listing, raw
    provider object, token, title, description, or label in the result.
    """
    def __init__(self, delegate: ip.ReadTransport, expected_url: str):
        self._delegate = delegate
        self._url = expected_url
        self._calls = 0
        self.title: str | None = None

    def get_object(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        obj = self._delegate.get_object(url, headers, timeout)
        self._calls += 1
        if self._calls == 2 and url == self._url and type(obj) is dict:
            # EC211 itself validates the title and source before comparison.
            self.title = obj.get('title') if type(obj.get('title')) is str else None
        return obj


def _title_tokens(value: str) -> set[str]:
    # Unicode NFKC/casefold handles CJK width variations; CJK character
    # bigrams make cross-spaced Chinese titles usable without a model/API.
    folded = unicodedata.normalize('NFKC', value).casefold()
    terms: set[str] = set()
    for m in TOKENS.finditer(folded):
        run = m.group(0)
        if any('\u3400' <= c <= '\u9fff' or '\u3040' <= c <= '\u30ff' or
               '\uac00' <= c <= '\ud7af' for c in run):
            if len(run) == 1:
                terms.add('c:' + run)
            else:
                terms.update('c:' + run[i:i + 2] for i in range(len(run) - 1))
        else:
            if len(run) > 1:
                terms.add('w:' + run)
                if len(run) >= 5:
                    terms.update('n:' + run[i:i + 3] for i in range(len(run) - 2))
    return terms


def _title_hint(query: str, candidate: str) -> str:
    a, b = _title_tokens(query), _title_tokens(candidate)
    if not a or not b:
        return 'INSUFFICIENT_LEXICAL_SIGNAL'
    common = len(a & b)
    if common < 2 and a != b:
        return 'LOW_LEXICAL_OVERLAP'
    # Combine Jaccard with a shorter-title overlap measure so word order
    # permutations in CJK and mixed-language titles can still be surfaced.
    overlap = 0.5 * (common / len(a | b) + common / min(len(a), len(b)))
    if overlap >= 0.72:
        return 'HIGH_LEXICAL_OVERLAP'
    if overlap >= 0.35:
        return 'SOME_LEXICAL_OVERLAP'
    return 'LOW_LEXICAL_OVERLAP'


def _flags() -> dict[str, bool]:
    return {
        'potential_duplicate_confirmed': False,
        'no_duplicate_confirmed': False,
        'full_repository_inventory': False,
        'snapshot_atomic': False,
        'evidence_anchors_provider_authenticated': False,
        'organizational_grant_authenticated': False,
        'provider_account_ownership_authenticated': False,
        'title_or_description_disclosed': False,
        'raw_issue_content_persisted': False,
        'external_ai_or_embedding_service_used': False,
        'native_issue_action_registered': False,
        'issue_created': False,
        'issue_or_provider_written': False,
        'business_repository_written': False,
        'knowledge_source_written': False,
        'external_cache_mutated': False,
    }


def _unknown_entry(c: MatchCandidate, code: str) -> dict[str, Any]:
    return {
        'number': c.number, 'expected_provider_issue_id': str(c.expected_provider_issue_id),
        'state': 'UNKNOWN', 'reason_code': code, 'review_hint': 'UNKNOWN',
        'anchor_matches': None, 'title_similarity_hint': 'UNKNOWN',
        'provider_confidentiality': None, 'source': None,
        'confirmed_duplicate': False,
    }


def _refusal(status: str, reason: str, synthetic: bool, reads: int = 0) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': {'invalid_input': 4, 'unavailable': 5}[status],
        'reason_code': reason,
        'read_state': 'UNKNOWN', 'coverage': 'UNKNOWN', 'synthetic': synthetic,
        'scope': None, 'candidate_count': 0, 'observed_count': 0, 'unknown_count': 0,
        'review_candidate_count': 0, 'entries': [],
        'provider_read_invocations': reads, 'maximum_possible_provider_gets': 3 * reads,
        **_flags(),
    }


def _source(projection: dict[str, Any], *, synthetic: bool) -> dict[str, Any]:
    return {
        'identity_sha256': projection['identity_sha256'],
        'snapshot_sha256': projection['snapshot_sha256'],
        'provider_state': projection['provider_state'],
        'provider_updated_at_utc': projection['provider_updated_at_utc'],
        'observed_at_utc': projection['observed_at_utc'],
        # EC211 marks an injected wrapper as synthetic even when the wrapper
        # delegates to its built-in HTTPS transport. EC214 can distinguish
        # its OWN exact delegate selection from caller injection here.
        'origin': 'SYNTHETIC_INJECTED_TRANSPORT_OR_CLOCK' if synthetic
                  else 'FIXED_PROVIDER_HTTPS_VIA_EC211',
    }


def match_issues(context: ip.ProviderContext, request: IssueMatchRequest, *,
                 match_grant: IssueMatchGrant | None = None,
                 title_grant: IssueTitleGrant | None = None,
                 issue_read_grants: Mapping[int, ip.IssueReadGrant] | None = None,
                 allow_network: bool = False,
                 token_supplier: Callable[[], str | None] | None = None,
                 transport: ip.ReadTransport | None = None,
                 clock: Callable[[], datetime] | None = None,
                 timeout: float = ip.MAX_TIMEOUT) -> dict[str, Any]:
    """Review-only candidates; at most 8 * 3 GETs, no title/description output.

    Caller grants are declarations, not verified roles, signatures or revocation.
    Never infer confirmed duplicates, confirmed absence, or full coverage from
    caller anchors, lexical hints, or selected provider metadata.
    """
    synthetic = transport is not None or clock is not None
    reads = 0
    try:
        _validate_request(context, request)
        _need(type(timeout) in (int, float) and not isinstance(timeout, bool) and
              math.isfinite(timeout) and 0 < timeout <= ip.MAX_TIMEOUT,
              'TIMEOUT_INVALID', 'invalid_input')
        _need(type(allow_network) is bool and allow_network,
              'NETWORK_NOT_AUTHORIZED')
        start = _now(clock)
        digest = _fingerprint(request)
        _grants(match_grant, title_grant, issue_read_grants, context, request, digest, start)
        _need(callable(token_supplier), 'CREDENTIALS_UNAVAILABLE')
        try:
            token = token_supplier()  # One explicit call; no env token fallback.
        except Exception:
            raise MatchError('CREDENTIALS_UNAVAILABLE') from None
        _need(type(token) is str and ip.TOKEN.fullmatch(token) is not None,
              'CREDENTIALS_UNAVAILABLE')
        _grants(match_grant, title_grant, issue_read_grants,
                context, request, digest, _now(clock))
        allowed = set(request.title_privacies) if request.title_policy == 'AUTHORIZED' else set()
        # Keep all raw titles in this stack frame only; never copy into JSON.
        observations: list[tuple[MatchCandidate, dict[str, Any] | None, str | None, str]] = []
        for candidate in request.candidates:
            _grants(match_grant, title_grant, issue_read_grants,
                    context, request, digest, _now(clock))
            selected = ip.IssueSelection(request.repository, candidate.number,
                                         request.expected_repository_id)
            delegate = transport if transport is not None else ip.StrictHTTPSIssueTransport()
            wrapper = None
            active: ip.ReadTransport = delegate
            if request.title_policy == 'AUTHORIZED':
                # Canonical expected GET URL determined by EC211 endpoints.
                _, url = ip._endpoints(context, selected, request.expected_repository_id)
                _need(type(url) is str, 'ENDPOINT_INVALID')
                wrapper = _CaptureTitleTransport(delegate, url)
                active = wrapper
            reads += 1
            response = ip.read_issue(
                context, selected, grant=issue_read_grants[candidate.number],
                allow_network=True, token_supplier=lambda: token, transport=active,
                clock=clock, timeout=float(timeout))
            checked_at = _now(clock)
            _grants(match_grant, title_grant, issue_read_grants,
                    context, request, digest, checked_at)
            # Supplied transport is by definition synthetic in EC211; our
            # wrapper also makes EC211 conservatively synthetic in live mode.
            if (type(response) is not dict or response.get('schema') != ip.SCHEMA or
                    response.get('synthetic') is not True or
                    response.get('issue_or_provider_written') is not False or
                    response.get('business_repository_written') is not False or
                    response.get('issue_created') is not False or
                    response.get('metadata_projection_only') is not True or
                    response.get('native_issue_action_registered') is not False):
                observations.append((candidate, None, None, 'ISSUE_MATCH_PROVIDER_RESULT_INVALID'))
                continue
            if response.get('status') != 'partial' or response.get('source') is None:
                observations.append((candidate, None, None, 'ISSUE_MATCH_PROVIDER_UNKNOWN_OR_UNAVAILABLE'))
                continue
            try:
                projection = es._projection(
                    response['source'], context,
                    es.IssueSyncScope(request.repository, request.expected_repository_id,
                                      (candidate.number,)), candidate.number, True)
            except (es.SyncError, TypeError, ValueError):
                observations.append((candidate, None, None, 'ISSUE_MATCH_PROJECTION_REJECTED'))
                continue
            if (projection['identity']['repository_path'] != request.repository or
                    projection['identity']['provider_issue_id'] !=
                    str(candidate.expected_provider_issue_id)):
                observations.append((candidate, None, None, 'ISSUE_MATCH_IDENTITY_UNKNOWN'))
                continue
            observed = _timestamp(projection['observed_at_utc'])
            if not start <= observed <= checked_at:
                observations.append((candidate, None, None, 'ISSUE_MATCH_OBSERVATION_CLOCK_DRIFT'))
                continue
            title = wrapper.title if wrapper is not None else None
            observations.append((candidate, projection, title, 'ISSUE_MATCH_OBSERVED'))
        finish = _now(clock)
        _grants(match_grant, title_grant, issue_read_grants,
                context, request, digest, finish)
        _need(finish >= start, 'CLOCK_ROLLBACK')
        entries: list[dict[str, Any]] = []
        for c, proj, title, code in observations:
            if proj is None:
                entries.append(_unknown_entry(c, code))
                continue
            observed = _timestamp(proj['observed_at_utc'])
            if not (start <= observed <= finish and
                    0 <= (finish - observed).total_seconds() <=
                    request.max_observation_age_seconds):
                entries.append(_unknown_entry(c, 'ISSUE_MATCH_OBSERVATION_STALE'))
                continue
            count = len(set(request.subject_anchors) & set(c.anchors))
            privacy = proj['provider_confidentiality']
            hint = 'NOT_REQUESTED'
            if request.title_policy == 'AUTHORIZED':
                if privacy not in allowed:
                    hint = 'WITHHELD_BY_PRIVACY_POLICY'
                elif not _valid_title(title):
                    # A successful EC211 title parse + correct wrapped GET is
                    # required, otherwise do not improvise similarity.
                    hint = 'UNAVAILABLE'
                else:
                    hint = _title_hint(request.subject_title, title)
            review = (count > 0 or hint in ('HIGH_LEXICAL_OVERLAP',
                                           'SOME_LEXICAL_OVERLAP'))
            entries.append({
                'number': c.number,
                'expected_provider_issue_id': str(c.expected_provider_issue_id),
                'state': 'OBSERVED_SELECTED_METADATA',
                'reason_code': 'ISSUE_MATCH_REVIEW_HINT_ONLY',
                'review_hint': 'REVIEW_CANDIDATE' if review else 'NO_POSITIVE_SIGNAL',
                'anchor_matches': count,
                'title_similarity_hint': hint,
                'provider_confidentiality': privacy,
                'source': _source(proj, synthetic=synthetic),
                'confirmed_duplicate': False,
            })
        observed_count = sum(e['state'] == 'OBSERVED_SELECTED_METADATA' for e in entries)
        coverage = ('COMPLETE_EXPLICIT_SELECTION_NONATOMIC' if observed_count == len(entries)
                    else 'PARTIAL_EXPLICIT_SELECTION_UNKNOWN' if observed_count
                    else 'UNKNOWN')
        result = {
            'schema': SCHEMA,
            'status': 'partial' if observed_count else 'unavailable',
            'exit_code': 2 if observed_count else 5,
            'reason_code': ('ISSUE_MATCH_SELECTED_HINTS_ONLY' if observed_count == len(entries)
                            else 'ISSUE_MATCH_PARTIAL_SELECTION_UNKNOWN' if observed_count
                            else 'ISSUE_MATCH_ALL_SELECTED_UNKNOWN'),
            'read_state': ('SYNTHETIC_OBSERVED' if synthetic else 'PROVIDER_OBSERVED')
                          if observed_count else 'UNKNOWN',
            'coverage': coverage, 'synthetic': synthetic,
            'scope': {
                'provider': context.provider, 'api_host': context.api_host,
                'repository': request.repository,
                'expected_repository_id': str(request.expected_repository_id),
                'candidate_pins': [dict(number=n, expected_provider_issue_id=str(i))
                                   for n, i in _pins(request)],
                'title_policy': request.title_policy,
                'title_privacies': list(request.title_privacies)
                if request.title_policy == 'AUTHORIZED' else [],
                'max_observation_age_seconds': request.max_observation_age_seconds,
            },
            'candidate_count': len(entries), 'observed_count': observed_count,
            'unknown_count': len(entries) - observed_count,
            'review_candidate_count': sum(e['review_hint'] == 'REVIEW_CANDIDATE'
                                          for e in entries),
            'entries': entries,
            'provider_read_invocations': reads,
            'maximum_possible_provider_gets': 3 * reads,
            **_flags(),
        }
        return result
    except MatchError as e:
        return _refusal(e.status, e.reason, synthetic, reads)
    except Exception:
        # Exception from remote, fake transport, clock, grant, or malformed
        # nested types must never leak anything from private Issue fields.
        return _refusal('unavailable', 'ISSUE_MATCH_UNEXPECTED_FAILURE', synthetic, reads)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='EC214 bounded manual Issue candidate comparison; default offline')
    parser.add_argument('--provider', required=True, choices=('github', 'gitlab'))
    parser.add_argument('--host', help='exact public provider API host')
    parser.add_argument('--account-ref', help='host-declared account slot, not a credential')
    parser.add_argument('--repository', required=True)
    parser.add_argument('--expected-repository-id', type=int, required=True)
    parser.add_argument('--candidate', action='append', required=True,
                        help='exact NUMBER:GLOBAL_ISSUE_ID (1..8 sorted); no listings')
    parser.add_argument('--authorize-match', action='store_true')
    parser.add_argument('--authorize-issue-reads', action='store_true')
    parser.add_argument('--authorize-title', action='store_true',
                        help='independent title comparison grant; title read from stdin')
    parser.add_argument('--allow-unclassified-title', action='store_true')
    parser.add_argument('--allow-confidential-title', action='store_true')
    parser.add_argument('--allow-network', action='store_true')
    parser.add_argument('--timeout', type=float, default=ip.MAX_TIMEOUT)
    args = parser.parse_args(argv)
    pins = []
    try:
        for entry in args.candidate:
            a, b = entry.split(':')
            pins.append(MatchCandidate(int(a), int(b)))
    except (ValueError, TypeError):
        pins = []
    ctx = ip.ProviderContext(args.provider, args.host or ip.API_HOST[args.provider],
                             args.account_ref or '')
    privacies = ('STANDARD',)
    if args.allow_unclassified_title:
        privacies += ('NOT_REPORTED',)
    if args.allow_confidential_title:
        privacies += ('CONFIDENTIAL',)
    # Do not put sensitive title text in shell argv, logs, or generated reports.
    title = None
    if args.authorize_title:
        try:
            title = sys.stdin.read(MAX_TITLE_CHARS + 2).rstrip('\r\n')
        except Exception:
            title = None
    req = IssueMatchRequest(args.repository, args.expected_repository_id,
                            tuple(pins), subject_title=title,
                            title_policy='AUTHORIZED' if args.authorize_title else 'DISABLED',
                            title_privacies=privacies)
    try:
        digest = request_fingerprint(ctx, req)
    except MatchError:
        digest = '0' * 64
    expiry = _stamp(datetime.now(timezone.utc) + timedelta(seconds=120))
    mg = (IssueMatchGrant(METHOD, ctx.provider, ctx.api_host, ctx.account_ref,
                          req.repository, req.expected_repository_id,
                          _pins(req), digest, expiry, True)
          if args.authorize_match else None)
    tg = (IssueTitleGrant(TITLE_METHOD, ctx.provider, ctx.api_host, ctx.account_ref,
                          req.repository, req.expected_repository_id,
                          _pins(req), digest, req.title_privacies, expiry, True)
          if args.authorize_title else None)
    rg = ({n: ip.IssueReadGrant(ip.METHOD, ctx.provider, ctx.api_host,
                                ctx.account_ref, req.repository, n, expiry, True)
           for n, _ in _pins(req)} if args.authorize_issue_reads else None)
    supplier = (lambda: os.environ.get(ip.ENV_CREDENTIAL[ctx.provider])
                if args.allow_network else None)
    out = match_issues(ctx, req, match_grant=mg, title_grant=tg,
                       issue_read_grants=rg, allow_network=args.allow_network,
                       token_supplier=supplier, timeout=args.timeout)
    print(json.dumps(out, sort_keys=True, ensure_ascii=True))
    return out['exit_code']


if __name__ == '__main__':
    sys.exit(main())
