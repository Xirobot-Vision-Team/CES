#!/usr/bin/env python3
"""EC215: offline, read-only, human-reviewable Issue *proposal eligibility*.

This module intentionally cannot create an Issue. It consumes the real EC214
request contract and an *untrusted serialized* EC214 result, plus bounded
caller-declared Finding/source/privacy context. An optional detached Ed25519
human review receipt must be verified with independently host-configured public
keys before the soft ELIGIBLE_TO_PROPOSE state can be returned. Even that state
is **only permission to consider a local, redacted EC216 draft**, not human
authorization to create, transmit, or persist anything.

No Git/CI/Issue provider access, network, files, clock writes, AI, or caches.
No claim that JSON, local signer key enrollment, Finding, Git, CI, or the
repository-wide Issue inventory has been independently authenticated.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import sys
from typing import Any, Callable, Mapping

try:
    from . import issue_provider as ip
    from . import issue_match as im
except ImportError:
    import issue_provider as ip
    import issue_match as im

SCHEMA = 'ces.issue_eligibility.v1'
REVIEW_SCHEMA = 'ces.issue_eligibility_review.v1'
REVIEW_METHOD = 'REVIEW_LOCAL_ISSUE_PROPOSAL_ELIGIBILITY'
REQUEST_DOMAIN = b'CES-EC215-ISSUE-ELIGIBILITY-REQUEST-v1\x00'
MATCH_DOMAIN = b'CES-EC215-ISSUE-MATCH-RECEIPT-v1\x00'
SIGN_DOMAIN = b'CES-EC215-HUMAN-REVIEW-RECEIPT-v1\x00'
MAX_SOURCE_AGE_SECONDS = 86400
MAX_REVIEW_SECONDS = 300
MAX_RECEIPT_BYTES = 65536
MAX_SOURCE_OBSERVATIONS = 32
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
OID = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z', re.ASCII)
KEY_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z', re.ASCII)
CODES = re.compile(r'ISSUE_(?:MATCH|ELIGIBILITY)_[A-Z0-9_]{1,90}\Z', re.ASCII)


@dataclass(frozen=True)
class FindingBasis:
    """Only *declared* EC177-180/EC203 references; no private record replay."""
    finding_id: str
    finding_record_sha256: str
    source_binding_sha256: str
    source_mode: str  # DeliveredTarget, WorkingTree, ProposedPR
    source_revision: str | None  # complete immutable Git OID *claim*
    evidence_anchor_set_sha256: str  # binds exact EC214 subject anchors
    positive_anchor_count: int
    counter_anchor_count: int
    assessment_state: str  # REVIEWED, UNVERIFIED, INCONCLUSIVE, REJECTED
    selected_source_count: int
    observed_source_count: int
    source_coverage: str  # COMPLETE_SELECTED, PARTIAL_SELECTED, UNKNOWN
    observed_at_utc: str  # declared source observation time, not a trust proof


@dataclass(frozen=True)
class PrivacyScope:
    classification: str  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, UNKNOWN
    target_visibility: str  # PUBLIC, PRIVATE, UNKNOWN
    decision: str  # ALLOW_REDACTED_LOCAL_REVIEW, NEEDS_REVIEW, DENY, UNKNOWN
    policy_revision_sha256: str | None  # requirement for positive draft eligibility


@dataclass(frozen=True)
class EligibilityRequest:
    repository: str
    expected_repository_id: int
    finding: FindingBasis
    privacy: PrivacyScope
    max_source_age_seconds: int = MAX_SOURCE_AGE_SECONDS
    # Select exactly the EC214 request, including pinned IDs, content & title
    # policy. It is never echoed; only cryptographic request hashes leave API.


@dataclass(frozen=True)
class HumanReviewReceipt:
    schema: str
    method: str
    reviewer_key_id: str
    evaluation_sha256: str
    decision: str  # ACKNOWLEDGE_FOR_LOCAL_PROPOSAL_ONLY
    acknowledges_selected_issues_not_inventory: bool
    acknowledges_duplicate_absence_unproven: bool
    acknowledges_source_and_signer_authority_unverified: bool
    issued_at_utc: str
    expires_at_utc: str
    signature_base64: str


class EligibilityError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = 'ISSUE_ELIGIBILITY_' + code


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise EligibilityError(code)


def _sha(value: Any, domain: bytes) -> str:
    return hashlib.sha256(domain + ip._canonical(value)).hexdigest()


def anchor_set_sha256(anchors: tuple[im.EvidenceAnchor, ...]) -> str:
    """Exact order-bound subject anchors; hashes do not authenticate assertions."""
    _need(im._anchors_valid(anchors), 'ANCHORS_INVALID')
    return _sha([im._anchor_dict(a) for a in anchors], b'CES-EC215-FINDING-ANCHOR-SET-v1\x00')


def _time(raw: Any) -> datetime:
    try:
        return ip._at_utc(raw)
    except (ip.IssueError, TypeError, ValueError):
        raise EligibilityError('TIME_INVALID') from None


def _now(clock: Callable[[], datetime] | None) -> datetime:
    try:
        return ip._now(clock)
    except (ip.IssueError, ValueError, TypeError):
        raise EligibilityError('CLOCK_UNAVAILABLE') from None


def _basis(ctx: ip.ProviderContext, req: EligibilityRequest,
           match_request: im.IssueMatchRequest) -> None:
    _need(type(req) is EligibilityRequest and type(req.finding) is FindingBasis
          and type(req.privacy) is PrivacyScope, 'REQUEST_SHAPE_INVALID')
    try:
        ip._validate_context(ctx)
        im.request_fingerprint(ctx, match_request)
    except (ip.IssueError, im.MatchError):
        raise EligibilityError('ISSUE_SCOPE_INVALID') from None
    _need(type(req.repository) is str and req.repository == match_request.repository
          and type(req.expected_repository_id) is int
          and req.expected_repository_id == match_request.expected_repository_id,
          'TARGET_SCOPE_MISMATCH')
    _need(type(req.max_source_age_seconds) is int and \
          1 <= req.max_source_age_seconds <= MAX_SOURCE_AGE_SECONDS,
          'SOURCE_AGE_LIMIT_INVALID')
    f = req.finding
    for value in (f.finding_id, f.finding_record_sha256,
                  f.source_binding_sha256, f.evidence_anchor_set_sha256):
        _need(type(value) is str and HEX.fullmatch(value) is not None,
              'FINDING_DIGEST_INVALID')
    _need(f.source_mode in ('DeliveredTarget', 'WorkingTree', 'ProposedPR') and \
          type(f.source_mode) is str, 'SOURCE_MODE_INVALID')
    _need(f.source_revision is None or (type(f.source_revision) is str and \
          OID.fullmatch(f.source_revision) is not None), 'SOURCE_REVISION_INVALID')
    _need(f.source_mode != 'DeliveredTarget' or f.source_revision is not None,
          'DELIVERY_REVISION_REQUIRED')
    _need(type(f.positive_anchor_count) is int and \
          0 <= f.positive_anchor_count <= im.MAX_ANCHORS and \
          type(f.counter_anchor_count) is int and \
          0 <= f.counter_anchor_count <= im.MAX_ANCHORS,
          'EVIDENCE_COUNTS_INVALID')
    _need(type(f.assessment_state) is str and f.assessment_state in
          ('REVIEWED', 'UNVERIFIED', 'INCONCLUSIVE', 'REJECTED'),
          'FINDING_REVIEW_STATE_INVALID')
    _need(type(f.selected_source_count) is int and \
          1 <= f.selected_source_count <= MAX_SOURCE_OBSERVATIONS and \
          type(f.observed_source_count) is int and \
          0 <= f.observed_source_count <= f.selected_source_count,
          'SOURCE_COUNTS_INVALID')
    _need(type(f.source_coverage) is str and f.source_coverage in
          ('COMPLETE_SELECTED', 'PARTIAL_SELECTED', 'UNKNOWN'),
          'SOURCE_COVERAGE_INVALID')
    _need(f.source_coverage != 'COMPLETE_SELECTED' or \
          f.observed_source_count == f.selected_source_count,
          'SOURCE_COVERAGE_CONTRADICTION')
    _need(f.source_coverage != 'PARTIAL_SELECTED' or \
          0 < f.observed_source_count < f.selected_source_count,
          'SOURCE_COVERAGE_CONTRADICTION')
    _time(f.observed_at_utc)
    p = req.privacy
    _need(type(p.classification) is str and p.classification in
          ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'UNKNOWN'),
          'PRIVACY_CLASS_INVALID')
    _need(type(p.target_visibility) is str and p.target_visibility in
          ('PUBLIC', 'PRIVATE', 'UNKNOWN'), 'VISIBILITY_INVALID')
    _need(type(p.decision) is str and p.decision in
          ('ALLOW_REDACTED_LOCAL_REVIEW', 'NEEDS_REVIEW', 'DENY', 'UNKNOWN'),
          'PRIVACY_DECISION_INVALID')
    _need(p.policy_revision_sha256 is None or \
          (type(p.policy_revision_sha256) is str and HEX.fullmatch(p.policy_revision_sha256)),
          'PRIVACY_REVISION_INVALID')
    _need(len(match_request.subject_anchors) <= f.positive_anchor_count,
          'ANCHOR_COUNT_MISMATCH')
    _need(f.evidence_anchor_set_sha256 == anchor_set_sha256(match_request.subject_anchors),
          'ANCHOR_BINDING_MISMATCH')
    _need(f.source_revision is None or all(
          a.commit_sha == f.source_revision for a in match_request.subject_anchors),
          'ANCHOR_SOURCE_REVISION_MISMATCH')


def _receipt_digest(match_result: Any) -> str | None:
    """Limit data budget before canonicalizing untrusted caller JSON."""
    if match_result is None:
        return None
    _need(type(match_result) is dict, 'MATCH_RECEIPT_SHAPE_INVALID')
    try:
        raw = ip._canonical(match_result)
        _need(len(raw) <= MAX_RECEIPT_BYTES, 'MATCH_RECEIPT_TOO_LARGE')
        # Strict json finite-number conversion, nested depth and key handling.
        verified = json.loads(raw)
        _need(type(verified) is dict, 'MATCH_RECEIPT_SHAPE_INVALID')
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise EligibilityError('MATCH_RECEIPT_SHAPE_INVALID') from None
    return hashlib.sha256(MATCH_DOMAIN + raw).hexdigest()


def evaluation_fingerprint(ctx: ip.ProviderContext, request: EligibilityRequest,
                           match_request: im.IssueMatchRequest,
                           match_result: dict[str, Any] | None) -> str:
    """Hash all review-relevant scope, evidence, privacy and EC214 result bytes.

    This is a binding hash, NOT a signature, authorization, or source proof.
    """
    _basis(ctx, request, match_request)
    digest = _receipt_digest(match_result)
    doc = {
        'context': {'provider': ctx.provider, 'api_host': ctx.api_host,
                    'account_ref': ctx.account_ref},
        'repository': request.repository,
        'expected_repository_id': str(request.expected_repository_id),
        'finding': request.finding.__dict__,
        'privacy': request.privacy.__dict__,
        'max_source_age_seconds': request.max_source_age_seconds,
        'issue_match_request_sha256': im.request_fingerprint(ctx, match_request),
        'issue_match_result_sha256': digest,
    }
    return _sha(doc, REQUEST_DOMAIN)


def _review_body(receipt: HumanReviewReceipt) -> dict[str, Any]:
    return {k: v for k, v in receipt.__dict__.items() if k != 'signature_base64'}


def review_signing_bytes(receipt: HumanReviewReceipt) -> bytes:
    """Detached signature bytes; signing cannot be done by this module."""
    _need(type(receipt) is HumanReviewReceipt, 'REVIEW_RECEIPT_INVALID')
    return SIGN_DOMAIN + ip._canonical(_review_body(receipt))


def _review_verified(receipt: HumanReviewReceipt | None, fingerprint: str,
                     now: datetime, trusted_review_keys: Mapping[str, bytes] | None) -> bool:
    if type(receipt) is not HumanReviewReceipt:
        return False
    if not (receipt.schema == REVIEW_SCHEMA and receipt.method == REVIEW_METHOD and \
            type(receipt.reviewer_key_id) is str and KEY_ID.fullmatch(receipt.reviewer_key_id)
            and type(receipt.evaluation_sha256) is str and \
            receipt.evaluation_sha256 == fingerprint and \
            receipt.decision == 'ACKNOWLEDGE_FOR_LOCAL_PROPOSAL_ONLY' and \
            receipt.acknowledges_selected_issues_not_inventory is True and \
            receipt.acknowledges_duplicate_absence_unproven is True and \
            receipt.acknowledges_source_and_signer_authority_unverified is True):
        return False
    try:
        issued, expiry = _time(receipt.issued_at_utc), _time(receipt.expires_at_utc)
        if not (issued <= now < expiry <= issued + timedelta(seconds=MAX_REVIEW_SECONDS)
                and now - issued <= timedelta(seconds=MAX_REVIEW_SECONDS)):
            return False
        if type(trusted_review_keys) is not dict or any(
            type(k) is not str or KEY_ID.fullmatch(k) is None or \
            type(v) is not bytes or len(v) != 32 for k, v in trusted_review_keys.items()
        ):
            return False
        public_key = trusted_review_keys.get(receipt.reviewer_key_id)
        if public_key is None or type(receipt.signature_base64) is not str or \
                len(receipt.signature_base64) != 88:
            return False
        raw = base64.b64decode(receipt.signature_base64, validate=True)
        if len(raw) != 64 or base64.b64encode(raw).decode('ascii') != receipt.signature_base64:
            return False
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(public_key).verify(raw, review_signing_bytes(receipt))
        return True
    except Exception:
        # Always safe to deny; never expose cryptographic internals or signature.
        return False


MATCH_ROOT = frozenset({
    'schema', 'status', 'exit_code', 'reason_code', 'read_state', 'coverage', 'synthetic',
    'scope', 'candidate_count', 'observed_count', 'unknown_count',
    'review_candidate_count', 'entries', 'provider_read_invocations',
    'maximum_possible_provider_gets', 'potential_duplicate_confirmed',
    'no_duplicate_confirmed', 'full_repository_inventory', 'snapshot_atomic',
    'evidence_anchors_provider_authenticated', 'organizational_grant_authenticated',
    'provider_account_ownership_authenticated', 'title_or_description_disclosed',
    'raw_issue_content_persisted', 'external_ai_or_embedding_service_used',
    'native_issue_action_registered', 'issue_created', 'issue_or_provider_written',
    'business_repository_written', 'knowledge_source_written',
    'external_cache_mutated',
})
MATCH_FLAGS = MATCH_ROOT - frozenset({
    'schema', 'status', 'exit_code', 'reason_code', 'read_state', 'coverage', 'synthetic',
    'scope', 'candidate_count', 'observed_count', 'unknown_count',
    'review_candidate_count', 'entries', 'provider_read_invocations',
    'maximum_possible_provider_gets',
})


def _match_state(ctx: ip.ProviderContext, mr: im.IssueMatchRequest,
                 observed: dict[str, Any] | None, now: datetime) -> tuple[str, int]:
    """Conservatively classify EC214 SELECTED hint receipt; never absence proof.

    `observed` may be caller-forged; structural checks do not authenticate it.
    For tampering/incompleteness return UNKNOWN, never a clean match result.
    """
    if observed is None or type(observed) is not dict:
        return 'UNKNOWN', 0
    try:
        if set(observed) != MATCH_ROOT or any(observed[k] is not False for k in MATCH_FLAGS):
            return 'UNKNOWN', 0
        if observed['schema'] != im.SCHEMA or observed['status'] != 'partial' or \
                type(observed['exit_code']) is not int or observed['exit_code'] != 2:
            return 'UNKNOWN', 0
        if type(observed['reason_code']) is not str or \
                CODES.fullmatch(observed['reason_code']) is None:
            return 'UNKNOWN', 0
        pins = [(c.number, str(c.expected_provider_issue_id)) for c in mr.candidates]
        scope = observed['scope']
        if type(scope) is not dict or set(scope) != {
            'provider', 'api_host', 'repository', 'expected_repository_id',
            'candidate_pins', 'title_policy', 'title_privacies',
            'max_observation_age_seconds',
        }:
            return 'UNKNOWN', 0
        if (scope['provider'] != ctx.provider or scope['api_host'] != ctx.api_host or \
                scope['repository'] != mr.repository or \
                scope['expected_repository_id'] != str(mr.expected_repository_id) or \
                type(scope['max_observation_age_seconds']) is not int or \
                scope['max_observation_age_seconds'] != mr.max_observation_age_seconds or \
                scope['title_policy'] != mr.title_policy or \
                scope['title_privacies'] !=
                (list(mr.title_privacies) if mr.title_policy == 'AUTHORIZED' else [])):
            return 'UNKNOWN', 0
        candidate_pins = scope['candidate_pins']
        if type(candidate_pins) is not list or len(candidate_pins) != len(pins) or \
                any(type(p) is not dict or set(p) != {
                    'number', 'expected_provider_issue_id'} or \
                    type(p['number']) is not int or \
                    type(p['expected_provider_issue_id']) is not str or \
                    (p['number'], p['expected_provider_issue_id']) != pins[i]
                    for i, p in enumerate(candidate_pins)):
            return 'UNKNOWN', 0
        entries = observed['entries']
        if type(entries) is not list or len(entries) != len(pins):
            return 'UNKNOWN', 0
        observed_count = 0
        hints = 0
        unknown = 0
        withheld = 0
        origins = set()
        for i, entry in enumerate(entries):
            if type(entry) is not dict or entry.get('number') != pins[i][0] or \
                    entry.get('expected_provider_issue_id') != pins[i][1] or \
                    entry.get('confirmed_duplicate') is not False:
                return 'UNKNOWN', 0
            if entry.get('state') == 'UNKNOWN':
                if set(entry) != {'number', 'expected_provider_issue_id', 'state',
                                  'reason_code', 'review_hint', 'anchor_matches',
                                  'title_similarity_hint', 'provider_confidentiality',
                                  'source', 'confirmed_duplicate'} or \
                        entry['source'] is not None or \
                        entry['review_hint'] != 'UNKNOWN':
                    return 'UNKNOWN', 0
                unknown += 1
                continue
            if entry.get('state') != 'OBSERVED_SELECTED_METADATA' or set(entry) != {
                'number', 'expected_provider_issue_id', 'state', 'reason_code',
                'review_hint', 'anchor_matches', 'title_similarity_hint',
                'provider_confidentiality', 'source', 'confirmed_duplicate',
            }:
                return 'UNKNOWN', 0
            observed_count += 1
            if type(entry['anchor_matches']) is not int or \
                    entry['anchor_matches'] < 0 or \
                    entry['anchor_matches'] > len(mr.subject_anchors):
                return 'UNKNOWN', 0
            if entry['anchor_matches'] != len(
                    set(mr.subject_anchors) & set(mr.candidates[i].anchors)) or \
                    entry['reason_code'] != 'ISSUE_MATCH_REVIEW_HINT_ONLY':
                return 'UNKNOWN', 0
            hint = entry['title_similarity_hint']
            if hint not in ('NOT_REQUESTED', 'WITHHELD_BY_PRIVACY_POLICY',
                           'UNAVAILABLE', 'HIGH_LEXICAL_OVERLAP', 'SOME_LEXICAL_OVERLAP',
                           'LOW_LEXICAL_OVERLAP', 'INSUFFICIENT_LEXICAL_SIGNAL'):
                return 'UNKNOWN', 0
            if (mr.title_policy == 'DISABLED' and hint != 'NOT_REQUESTED') or \
                    (mr.title_policy == 'AUTHORIZED' and hint == 'NOT_REQUESTED'):
                return 'UNKNOWN', 0
            withheld += int(hint in ('WITHHELD_BY_PRIVACY_POLICY', 'UNAVAILABLE'))
            calculated_hint = (entry['anchor_matches'] > 0 or hint in
                               ('HIGH_LEXICAL_OVERLAP', 'SOME_LEXICAL_OVERLAP'))
            if entry['review_hint'] != ('REVIEW_CANDIDATE' if calculated_hint
                                       else 'NO_POSITIVE_SIGNAL'):
                return 'UNKNOWN', 0
            hints += int(calculated_hint)
            if (entry['provider_confidentiality'] not in im.PRIVACY_CLASSES or
                    (ctx.provider == 'github' and
                     entry['provider_confidentiality'] != 'NOT_REPORTED')):
                return 'UNKNOWN', 0
            src = entry['source']
            if type(src) is not dict or set(src) != {
                'identity_sha256', 'snapshot_sha256', 'provider_state',
                'provider_updated_at_utc', 'observed_at_utc', 'origin',
            } or any(type(src[k]) is not str or HEX.fullmatch(src[k]) is None
                     for k in ('identity_sha256', 'snapshot_sha256')):
                return 'UNKNOWN', 0
            if src['provider_state'] not in ('OPEN', 'CLOSED'):
                return 'UNKNOWN', 0
            at = _time(src['observed_at_utc'])
            updated_at = _time(src['provider_updated_at_utc'])
            if updated_at > at:
                return 'UNKNOWN', 0
            if not (timedelta(0) <= now - at <= timedelta(
                    seconds=mr.max_observation_age_seconds)):
                return 'UNKNOWN', 0
            origins.add(src['origin'])
        if (observed['reason_code'] != ('ISSUE_MATCH_SELECTED_HINTS_ONLY' if unknown == 0
                                        else 'ISSUE_MATCH_PARTIAL_SELECTION_UNKNOWN')):
            return 'UNKNOWN', 0
        if (type(observed['candidate_count']) is not int or \
                observed['candidate_count'] != len(pins) or \
                type(observed['observed_count']) is not int or \
                observed['observed_count'] != observed_count or \
                type(observed['unknown_count']) is not int or \
                observed['unknown_count'] != unknown or \
                type(observed['review_candidate_count']) is not int or \
                observed['review_candidate_count'] != hints or \
                type(observed['provider_read_invocations']) is not int or \
                observed['provider_read_invocations'] != len(pins) or \
                type(observed['maximum_possible_provider_gets']) is not int or \
                observed['maximum_possible_provider_gets'] != len(pins) * 3):
            return 'UNKNOWN', 0
        if observed_count == 0 or observed['coverage'] != (
                'COMPLETE_EXPLICIT_SELECTION_NONATOMIC' if unknown == 0
                else 'PARTIAL_EXPLICIT_SELECTION_UNKNOWN'):
            return 'UNKNOWN', 0
        if (observed['synthetic'] is True and \
                (observed['read_state'] != 'SYNTHETIC_OBSERVED' or \
                 any(o != 'SYNTHETIC_INJECTED_TRANSPORT_OR_CLOCK' for o in origins))):
            return 'UNKNOWN', 0
        if (observed['synthetic'] is False and \
                (observed['read_state'] != 'PROVIDER_OBSERVED' or \
                 any(o != 'FIXED_PROVIDER_HTTPS_VIA_EC211' for o in origins))):
            return 'UNKNOWN', 0
        if type(observed['synthetic']) is not bool:
            return 'UNKNOWN', 0
        if unknown:
            return 'UNKNOWN', observed_count
        if observed['synthetic'] is True:
            return 'SYNTHETIC_NEEDS_REVIEW', observed_count
        if hints:
            return 'CANDIDATE_NEEDS_REVIEW', observed_count
        if withheld:
            return 'WITHHELD_NEEDS_REVIEW', observed_count
        return 'SELECTED_NO_POSITIVE_HINT', observed_count
    except (TypeError, ValueError, EligibilityError, AttributeError, KeyError, OverflowError):
        return 'UNKNOWN', 0


def _flags() -> dict[str, bool]:
    return {
        'eligibility_is_authorization': False,
        'issue_create_authorized': False,
        'issue_created': False,
        'provider_or_existing_issue_written': False,
        'business_git_or_knowledge_written': False,
        'report_or_issue_content_published': False,
        'title_or_body_generated': False,
        'raw_finding_or_issue_content_disclosed': False,
        'provider_repository_issue_inventory_complete': False,
        'duplicate_confirmed': False,
        'no_duplicate_confirmed': False,
        'original_finding_replayed': False,
        'source_git_byte_evidence_reverified': False,
        'ci_execution_independently_verified': False,
        'match_receipt_source_authenticated': False,
        'reviewer_organizational_role_or_revocation_authenticated': False,
        'native_powershell_issue_route_registered': False,
    }


def _out(verdict: str, reason: str, *, digest: str | None = None,
         match_digest: str | None = None, match_state: str = 'UNKNOWN',
         observed_count: int = 0, reviewed: bool = False,
         source_coverage: str = 'UNKNOWN', source_mode: str | None = None) -> dict[str, Any]:
    status = 'invalid_input' if verdict == 'INVALID_INPUT' else (
        'unavailable' if verdict == 'UNKNOWN' else 'partial')
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': {'invalid_input': 4, 'unavailable': 5, 'partial': 2}[status],
        'reason_code': 'ISSUE_ELIGIBILITY_' + reason,
        'eligibility': verdict,
        'authorization': 'NOT_GRANTED',
        'safe_next_step': ('LOCAL_REDACTED_DRAFT_REVIEW_ONLY'
                           if verdict == 'ELIGIBLE_TO_PROPOSE' else
                           'HUMAN_REVIEW_REQUIRED' if verdict == 'NEEDS_REVIEW' else
                           'DO_NOT_PROPOSE'),
        'evaluation_sha256': digest,
        'issue_match_receipt_sha256': match_digest,
        'issue_match_selection_state': match_state,
        'selected_issues_observed': observed_count,
        'source_mode': source_mode,
        'source_coverage': source_coverage,
        'review_signature_cryptographically_valid': reviewed,
        'finding_or_match_truth_independently_verified': False,
        'unknown_missing_issue_inventory': True,
        **_flags(),
    }


def evaluate_issue_eligibility(
    context: ip.ProviderContext, request: EligibilityRequest,
    match_request: im.IssueMatchRequest, match_result: dict[str, Any] | None, *,
    review_receipt: HumanReviewReceipt | None = None,
    trusted_review_keys: Mapping[str, bytes] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Read-only EC215 decision: positive means only *local proposal eligibility*.

    No access to provider/Git/CI/Finding store. Signed acknowledgment is short
    lived, binds exact EC214 request/result + evidence + privacy + repository,
    and can only elevate an otherwise clean, selected-only, reviewed source.
    """
    try:
        _basis(context, request, match_request)
        fingerprint = evaluation_fingerprint(context, request, match_request, match_result)
        match_digest = _receipt_digest(match_result)
        now = _now(clock)
        f, p = request.finding, request.privacy
        state, observed = _match_state(context, match_request, match_result, now)
        signed = _review_verified(review_receipt, fingerprint, now, trusted_review_keys)
        kwargs = dict(digest=fingerprint, match_digest=match_digest, match_state=state,
                      observed_count=observed, reviewed=signed,
                      source_coverage=f.source_coverage, source_mode=f.source_mode)
        # Hard denials are monotonic and take precedence over unknown feeds.
        if f.assessment_state == 'REJECTED':
            return _out('BLOCKED', 'FINDING_REJECTED', **kwargs)
        if (p.decision == 'DENY' or p.classification == 'RESTRICTED' or \
                p.target_visibility == 'PUBLIC' and \
                p.classification in ('INTERNAL', 'CONFIDENTIAL')):
            return _out('BLOCKED', 'PRIVACY_DISALLOWS_TARGET', **kwargs)
        # Every UNKNOWN is explicit; reviewer signatures cannot waive it.
        source_at = _time(f.observed_at_utc)
        if not (timedelta(0) <= now - source_at <= timedelta(
                seconds=request.max_source_age_seconds)):
            return _out('UNKNOWN', 'SOURCE_OBSERVATION_STALE_OR_FUTURE', **kwargs)
        if p.classification == 'UNKNOWN' or p.target_visibility == 'UNKNOWN' or \
                p.decision == 'UNKNOWN':
            return _out('UNKNOWN', 'PRIVACY_UNKNOWN', **kwargs)
        if (f.positive_anchor_count == 0 or f.source_coverage == 'UNKNOWN' or \
                f.observed_source_count == 0):
            return _out('UNKNOWN', 'SOURCE_EVIDENCE_UNKNOWN', **kwargs)
        if state == 'UNKNOWN':
            return _out('UNKNOWN', 'ISSUE_MATCH_OR_COVERAGE_UNKNOWN', **kwargs)
        if f.source_coverage == 'PARTIAL_SELECTED':
            return _out('NEEDS_REVIEW', 'SOURCE_COVERAGE_PARTIAL', **kwargs)
        if state != 'SELECTED_NO_POSITIVE_HINT':
            return _out('NEEDS_REVIEW', 'ISSUE_MATCH_REVIEW_REQUIRED', **kwargs)
        if (f.source_mode != 'DeliveredTarget' or \
                f.assessment_state != 'REVIEWED' or f.counter_anchor_count > 0 or \
                p.decision != 'ALLOW_REDACTED_LOCAL_REVIEW' or \
                p.policy_revision_sha256 is None or \
                not match_request.subject_anchors):
            return _out('NEEDS_REVIEW', 'SOURCE_OR_PRIVACY_REVIEW_REQUIRED', **kwargs)
        if not signed:
            return _out('NEEDS_REVIEW', 'INDEPENDENT_REVIEW_RECEIPT_REQUIRED', **kwargs)
        return _out('ELIGIBLE_TO_PROPOSE', 'REVIEWED_FOR_LOCAL_DRAFT_ONLY', **kwargs)
    except EligibilityError as exc:
        return _out('INVALID_INPUT', exc.code.removeprefix('ISSUE_ELIGIBILITY_'))
    except Exception:
        return _out('UNKNOWN', 'UNEXPECTED_FAILURE')


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate key')
        out[key] = value
    return out


def main(argv: list[str] | None = None) -> int:
    """Offline only, no reviewer key provisioning through untrusted JSON/CLI.

    The host-integration Python API (not this CLI) can supply independently
    configured reviewer keys, never from the same input being evaluated.
    """
    parser = argparse.ArgumentParser(description='EC215 offline redacted eligibility')
    parser.add_argument('--stdin-json', action='store_true', help='read one bounded JSON request from stdin')
    args = parser.parse_args(argv)
    if not args.stdin_json:
        parser.print_help(sys.stderr)
        return 4
    try:
        raw = sys.stdin.buffer.read(MAX_RECEIPT_BYTES + 1)
        if len(raw) > MAX_RECEIPT_BYTES:
            raise ValueError('too large')
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=_no_duplicates,
                         parse_constant=lambda x: (_ for _ in ()).throw(ValueError('nonfinite')))
        if type(obj) is not dict or set(obj) != {
            'context', 'request', 'match_request', 'match_result'}:
            raise ValueError('shape')
        context = ip.ProviderContext(**obj['context'])
        rr = obj['request']
        if set(rr) != {'repository', 'expected_repository_id', 'finding', 'privacy',
                       'max_source_age_seconds'}:
            raise ValueError('request keys')
        request = EligibilityRequest(rr['repository'], rr['expected_repository_id'],
                                     FindingBasis(**rr['finding']), PrivacyScope(**rr['privacy']),
                                     rr['max_source_age_seconds'])
        mr = obj['match_request']
        candidates = tuple(im.MatchCandidate(c['number'], c['expected_provider_issue_id'],
                           tuple(im.EvidenceAnchor(**a) for a in c['anchors']))
                           for c in mr['candidates'])
        match_request = im.IssueMatchRequest(
            mr['repository'], mr['expected_repository_id'], candidates,
            tuple(im.EvidenceAnchor(**a) for a in mr['subject_anchors']),
            mr['subject_title'], mr['title_policy'], tuple(mr['title_privacies']),
            mr['max_observation_age_seconds'])
        result = evaluate_issue_eligibility(context, request, match_request,
                                           obj['match_result'])
    except Exception:
        result = _out('INVALID_INPUT', 'CLI_REQUEST_INVALID')
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
