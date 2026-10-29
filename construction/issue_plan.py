#!/usr/bin/env python3
"""EC216: fully pinned, metadata-only local IssuePlan preview (never a write).

This module composes the *actual* EC215 eligibility evaluator on a bounded,
private in-memory snapshot, including its EC214 original request/receipt and
short-lived independently host-trusted Ed25519 reviewer key. A supplied EC215
result must byte-for-byte match the newly evaluated result. No inherited soft
eligibility, forged serialized result, or unsigned reviewer can produce a draft.

All human-readable title/body text comes from closed, built-in vocabularies;
no Finding, Git path, provider Issue, repository name/ID, token, user text,
remote Issue title/body, source byte, or reference label is interpolated.
Selected references are explicit indices and SHA-bound to original EC214
anchors; their sensitive locators never leave this module.

This module performs no filesystem, network, provider, Git, AI or native CLI
operations. EC217 one-time approval and EC218 idempotent remote create are
separate, NOT IMPLEMENTED here. The caller is responsible for host key/role
onboarding, review authority, and authenticating Finding/Git/provider inputs.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from typing import Any, Callable, Mapping

try:
    from . import issue_provider as ip
    from . import issue_match as im
    from . import issue_eligibility as ie
except ImportError:
    import issue_provider as ip
    import issue_match as im
    import issue_eligibility as ie

SCHEMA = 'ces.issue_plan.v1'
PLAN_DOMAIN = b'CES-EC216-ISSUE-PLAN-v1\x00'
TARGET_DOMAIN = b'CES-EC216-TARGET-IDENTITY-v1\x00'
SOURCE_DOMAIN = b'CES-EC216-SOURCE-ANCHOR-v1\x00'
REVISION_DOMAIN = b'CES-EC216-SOURCE-REVISION-v1\x00'
ELIGIBILITY_DOMAIN = b'CES-EC216-ELIGIBILITY-RESULT-v1\x00'
REVIEW_DOMAIN = b'CES-EC216-EXACT-REVIEW-RECEIPT-v1\x00'
MAX_REFERENCES = 16
MAX_INPUT_BYTES = 65536
MAX_TITLE_CHARS = 100
MAX_BODY_CHARS = 2400

# Deliberately narrow, cross-product-safe title/body language. The selection
# is a proposal *label* supplied by the caller, NOT a verified finding claim.
TOPICS: dict[str, tuple[str, dict[str, str]]] = {
    'CORRECTNESS': ('correctness', {
        'INCORRECT_RESULT': 'incorrect results',
        'EDGE_CASE': 'boundary-case behavior',
        'INCONSISTENT_STATE': 'inconsistent state',
    }),
    'RELIABILITY': ('reliability', {
        'ERROR_HANDLING': 'error-handling behavior',
        'RECOVERY': 'recovery behavior',
        'NONDETERMINISM': 'nondeterministic behavior',
    }),
    'PERFORMANCE': ('performance', {
        'LATENCY': 'latency behavior',
        'RESOURCE_USAGE': 'resource consumption',
        'SCALABILITY': 'scalability behavior',
    }),
    'ACCESS_CONTROL': ('access control', {
        'PERMISSION_CHECK': 'permission handling',
        'BOUNDARY_CHECK': 'boundary enforcement',
        'DATA_EXPOSURE': 'potential data exposure',
    }),
    'TESTING': ('testing', {
        'COVERAGE_GAP': 'missing test coverage',
        'REGRESSION_RISK': 'regression coverage',
        'ASSERTION_GAP': 'incomplete assertions',
    }),
    'DOCUMENTATION': ('documentation', {
        'CONTRACT_DRIFT': 'contract drift',
        'MISSING_GUIDANCE': 'missing guidance',
        'AMBIGUOUS_BEHAVIOR': 'ambiguous behavior',
    }),
}


@dataclass(frozen=True)
class SelectedSourceRef:
    """Zero-based index in the exact original EC214 subject-anchor tuple.

    The expected hash binds the full original (private) commit/path/lines/
    evidence digest, not a caller-supplied display name or remote Issue link.
    """
    anchor_index: int
    expected_anchor_sha256: str


@dataclass(frozen=True)
class IssuePlanRequest:
    """All pins are independently checked; NEVER copy these into the draft.

    The caller must provide the *same* original EC215 input/receipt/review and
    the full exact serialized EC215 eligibility result as separate parameters.
    Opaque SHA fingerprints are not source/authentication proofs or secrets.
    """
    target_provider: str
    target_repository: str
    expected_repository_id: int
    target_visibility: str
    expected_evaluation_sha256: str
    expected_match_receipt_sha256: str
    expected_eligibility_result_sha256: str
    expected_review_receipt_sha256: str
    finding_record_sha256: str
    source_binding_sha256: str
    source_mode: str
    source_revision: str
    evidence_anchor_set_sha256: str
    policy_revision_sha256: str
    topic: str
    concern: str
    selected_sources: tuple[SelectedSourceRef, ...]


class PlanError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = 'ISSUE_PLAN_' + code


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise PlanError(code)


def _hash(value: Any, domain: bytes) -> str:
    return hashlib.sha256(domain + ip._canonical(value)).hexdigest()


def source_anchor_sha256(anchor: im.EvidenceAnchor) -> str:
    """Binding helper for constructing a selection; no original path output."""
    _need(type(anchor) is im.EvidenceAnchor and
          im._anchors_valid((anchor,)), 'SOURCE_ANCHOR_INVALID')
    return _hash(im._anchor_dict(anchor), SOURCE_DOMAIN)


def eligibility_result_sha256(result: dict[str, Any]) -> str:
    """EC215 result snapshot digest (full result, not just its state)."""
    _need(type(result) is dict, 'ELIGIBILITY_RESULT_INVALID')
    return _hash(_snapshot(result, 'ELIGIBILITY_RESULT'), ELIGIBILITY_DOMAIN)


def review_receipt_sha256(receipt: ie.HumanReviewReceipt) -> str:
    """Binds the full short-lived review, INCLUDING detached signature."""
    _need(type(receipt) is ie.HumanReviewReceipt, 'REVIEW_RECEIPT_INVALID')
    return _hash(receipt.__dict__, REVIEW_DOMAIN)


def _snapshot(source: Any, label: str) -> Any:
    """Defensive private JSON snapshot; never echo raw untrusted contents.

    The snapshot also ensures that mutation of a caller's receipt during a
    later EC215 re-evaluation cannot change the exact bytes being reviewed.
    """
    if source is None:
        return None
    _need(type(source) is dict, label + '_INVALID')
    try:
        raw = ip._canonical(source)
        _need(len(raw) <= MAX_INPUT_BYTES, label + '_OVERSIZED')
        result = json.loads(raw)
        _need(type(result) is dict, label + '_INVALID')
        return result
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        raise PlanError(label + '_INVALID') from None


def _validate_intent(intent: IssuePlanRequest) -> None:
    _need(type(intent) is IssuePlanRequest, 'REQUEST_INVALID')
    _need(type(intent.target_provider) is str and
          intent.target_provider in ip.API_HOST, 'PROVIDER_INVALID')
    _need(type(intent.target_repository) is str and
          3 <= len(intent.target_repository) <= 240 and
          type(intent.expected_repository_id) is int and
          ip._positive_id(intent.expected_repository_id), 'TARGET_ID_INVALID')
    _need(type(intent.target_visibility) is str and
          intent.target_visibility in ('PUBLIC', 'PRIVATE'), 'VISIBILITY_INVALID')
    for value in (
        intent.expected_evaluation_sha256,
        intent.expected_match_receipt_sha256,
        intent.expected_eligibility_result_sha256,
        intent.expected_review_receipt_sha256,
        intent.finding_record_sha256, intent.source_binding_sha256,
        intent.evidence_anchor_set_sha256, intent.policy_revision_sha256,
    ):
        _need(type(value) is str and ie.HEX.fullmatch(value) is not None,
              'PIN_INVALID')
    _need(type(intent.source_mode) is str and
          intent.source_mode in ('DeliveredTarget', 'WorkingTree', 'ProposedPR') and
          type(intent.source_revision) is str and
          ie.OID.fullmatch(intent.source_revision) is not None,
          'SOURCE_REVISION_INVALID')
    _need(type(intent.topic) is str and intent.topic in TOPICS and
          type(intent.concern) is str and
          intent.concern in TOPICS[intent.topic][1], 'DRAFT_CATEGORY_INVALID')
    refs = intent.selected_sources
    _need(type(refs) is tuple and 1 <= len(refs) <= MAX_REFERENCES,
          'SOURCE_SELECTION_INVALID')
    previous = -1
    for ref in refs:
        _need(type(ref) is SelectedSourceRef and
              type(ref.anchor_index) is int and
              previous < ref.anchor_index < im.MAX_ANCHORS and
              type(ref.expected_anchor_sha256) is str and
              ie.HEX.fullmatch(ref.expected_anchor_sha256) is not None,
              'SOURCE_SELECTION_INVALID')
        previous = ref.anchor_index


def _flags() -> dict[str, bool]:
    return {
        'issue_create_authorized': False,
        'issue_created': False,
        'existing_issue_edited': False,
        'provider_or_business_repository_written': False,
        'finding_or_knowledge_written': False,
        'local_files_persisted': False,
        'external_ai_called': False,
        'network_requested': False,
        'report_or_issue_published': False,
        'external_content_disclosed': False,
        'raw_source_path_or_bytes_disclosed': False,
        'raw_finding_or_remote_issue_content_disclosed': False,
        'provider_repository_issue_inventory_complete': False,
        'duplicate_absence_proven': False,
        'finding_source_or_provider_authenticated': False,
        'reviewer_organization_role_authenticated': False,
        'native_issue_action_registered': False,
    }


def _out(state: str, reason: str, *, draft: dict[str, Any] | None = None,
         evaluation_digest: str | None = None,
         eligibility_digest: str | None = None) -> dict[str, Any]:
    status = ('invalid_input' if state == 'INVALID_INPUT' else
              'unavailable' if state == 'UNKNOWN' else 'partial')
    return {
        'schema': SCHEMA,
        'status': status,
        'exit_code': {'invalid_input': 4, 'unavailable': 5, 'partial': 2}[status],
        'reason_code': 'ISSUE_PLAN_' + reason,
        'plan_state': state,
        'draft': draft,
        'draft_generated_locally': draft is not None,
        'approval': 'NOT_GRANTED',
        'delivery_state': 'NOT_ATTEMPTED',
        'safe_next_step': ('HUMAN_REVIEW_OF_LOCAL_DRAFT_ONLY' if draft is not None
                           else 'REVIEW_REQUIRED' if state == 'NEEDS_REVIEW'
                           else 'DO_NOT_DRAFT'),
        'evaluation_sha256': evaluation_digest,
        'eligibility_result_sha256': eligibility_digest,
        **_flags(),
    }


def _body(topic: str, concern: str, source_refs: list[dict[str, Any]],
          candidate_count: int) -> tuple[str, str]:
    area, options = TOPICS[topic]
    risk = options[concern]
    title = f'Investigate potential {risk} ({area})'
    ids = ', '.join(item['reference_id'] for item in source_refs)
    # Built-in content only; no caller/proxy/Issue/source strings are inserted.
    body = (
        '## Proposed investigation\n'
        f'Review a potential {area} concern involving {risk}. '
        'These are caller-selected review categories, not independently established facts.\n\n'
        '## Evidence scope (redacted)\n'
        f'- Explicitly selected source anchors: {ids}. Resolve these identifiers '
        'through separately authorized original evidence access.\n'
        '- Finding/source mode: declared delivered target at an exact pinned revision; '
        'full source, paths and repository identities are withheld from this preview.\n'
        f'- Issue comparison: {candidate_count} explicitly selected previous Issue(s); '
        'not a repository-wide search. Similarity and duplicate absence are unproven.\n'
        '- The Finding, Git delivery, Issue observations and reviewer organizational '
        'authority have not been independently authenticated by this draft.\n\n'
        '## Before a creation request\n'
        '1. Verify the original Finding, evidence and delivered revision using '
        'approved access; reproduce the suspected behavior.\n'
        '2. Check actual repository-wide duplicate Issues and validate privacy '
        'classification at the intended target.\n'
        '3. Add a separately approved, sanitized observed/expected description; '
        'do not paste private paths, titles, tokens or raw source.\n'
        '4. Obtain independent EC217 single-use creation authorization. '
        'This draft gives no permission to create, send, or publish.\n'
    )
    _need(len(title) <= MAX_TITLE_CHARS and len(body) <= MAX_BODY_CHARS,
          'TEMPLATE_BUDGET_EXCEEDED')
    return title, body


def _draft(context: ip.ProviderContext, intent: IssuePlanRequest,
           request: ie.EligibilityRequest, match_request: im.IssueMatchRequest,
           review_digest: str, eligibility_digest: str) -> dict[str, Any]:
    refs: list[dict[str, Any]] = []
    for ref in intent.selected_sources:
        anchor = match_request.subject_anchors[ref.anchor_index]
        _need(source_anchor_sha256(anchor) == ref.expected_anchor_sha256,
              'SOURCE_REFERENCE_STALE')
        refs.append({
            'reference_id': f'E{ref.anchor_index + 1:02d}',
            'anchor_index': ref.anchor_index,
            'anchor_binding_sha256': ref.expected_anchor_sha256,
            'locator_redacted': True,
        })
    title, body = _body(intent.topic, intent.concern, refs,
                        len(match_request.candidates))
    target_digest = _hash({
        'provider': context.provider, 'api_host': context.api_host,
        'account_ref': context.account_ref,
        'repository': request.repository,
        'expected_repository_id': str(request.expected_repository_id),
        'visibility': request.privacy.target_visibility,
    }, TARGET_DOMAIN)
    plan_digest = _hash({
        'intent': {**{k: v for k, v in intent.__dict__.items()
                      if k != 'selected_sources'},
                   'selected_sources': [r.__dict__ for r in intent.selected_sources]},
        'review_receipt_sha256': review_digest,
        'eligibility_result_sha256': eligibility_digest,
        'target_identity_sha256': target_digest,
    }, PLAN_DOMAIN)
    return {
        'target': {
            'provider': context.provider,
            'repository_identity_sha256': target_digest,
            'visibility': request.privacy.target_visibility,
            'repository_name_and_numeric_id_redacted': True,
        },
        'plan_sha256': plan_digest,
        'suggested_title': title,
        'suggested_body': body,
        'references': refs,
        'source': {
            'mode': request.finding.source_mode,
            'pinned_revision_sha256': _hash(request.finding.source_revision,
                                            REVISION_DOMAIN),
            'finding_record_sha256': request.finding.finding_record_sha256,
            'source_binding_sha256': request.finding.source_binding_sha256,
            'anchor_set_sha256': request.finding.evidence_anchor_set_sha256,
            'selected_source_coverage_declared_complete': True,
            'original_bytes_not_replayed': True,
        },
        'privacy': {
            'classification_redacted': True,
            'policy_revision_sha256': request.privacy.policy_revision_sha256,
            'local_redacted_preview_only': True,
        },
        'issue_match_selected_count': len(match_request.candidates),
        'review_receipt_sha256': review_digest,
        'content_source': 'BUILT_IN_CLOSED_VOCABULARY',
        'authorization': 'NOT_GRANTED',
        'issue_created': False,
    }


def draft_issue_plan(
    context: ip.ProviderContext,
    intent: IssuePlanRequest,
    eligibility_request: ie.EligibilityRequest,
    match_request: im.IssueMatchRequest,
    match_result: dict[str, Any] | None,
    eligibility_result: dict[str, Any] | None,
    *,
    review_receipt: ie.HumanReviewReceipt | None = None,
    trusted_review_keys: Mapping[str, bytes] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Generate a redacted in-memory preview only after fresh exact EC215 gate.

    `trusted_review_keys` MUST be independently configured by the host; never
    take it from the caller's matched Issue JSON, the draft intent or Finding.
    A caller controlling both trusted keys and receipts cannot claim real
    organizational review, regardless of cryptographic verification here.
    """
    try:
        _validate_intent(intent)
        # Snapshot untrusted JSON once; all comparisons and signature checks
        # operate on precisely these bounded bytes, never on external mutation.
        result_snapshot = _snapshot(match_result, 'MATCH_RECEIPT')
        eligibility_snapshot = _snapshot(eligibility_result, 'ELIGIBILITY_RESULT')
        now = ie._now(clock)
        current = ie.evaluate_issue_eligibility(
            context, eligibility_request, match_request, result_snapshot,
            review_receipt=review_receipt,
            trusted_review_keys=trusted_review_keys,
            clock=lambda: now,
        )
        if current['eligibility'] != 'ELIGIBLE_TO_PROPOSE':
            return _out(current['eligibility'], 'EC215_' +
                        current['reason_code'].removeprefix('ISSUE_ELIGIBILITY_'),
                        evaluation_digest=current['evaluation_sha256'])
        # A direct caller can supply a forged EC215 serialized verdict; accept
        # only the exact re-evaluated result, not just an eligible string.
        if eligibility_snapshot is None or \
                ip._canonical(eligibility_snapshot) != ip._canonical(current):
            return _out('UNKNOWN', 'EC215_RESULT_DRIFT',
                        evaluation_digest=current['evaluation_sha256'])
        eligibility_digest = eligibility_result_sha256(current)
        if (type(context) is not ip.ProviderContext or
                intent.target_provider != context.provider or
                intent.target_repository != eligibility_request.repository or
                intent.target_repository != match_request.repository or
                intent.expected_repository_id != eligibility_request.expected_repository_id or
                intent.expected_repository_id != match_request.expected_repository_id or
                intent.target_visibility != eligibility_request.privacy.target_visibility):
            return _out('BLOCKED', 'TARGET_REPOSITORY_OR_VISIBILITY_CONFLICT',
                        evaluation_digest=current['evaluation_sha256'],
                        eligibility_digest=eligibility_digest)
        f, p = eligibility_request.finding, eligibility_request.privacy
        if (intent.finding_record_sha256 != f.finding_record_sha256 or
                intent.source_binding_sha256 != f.source_binding_sha256 or
                intent.source_mode != f.source_mode or
                intent.source_revision != f.source_revision or
                intent.evidence_anchor_set_sha256 != f.evidence_anchor_set_sha256 or
                intent.policy_revision_sha256 != p.policy_revision_sha256):
            return _out('UNKNOWN', 'FINDING_SOURCE_OR_POLICY_DRIFT',
                        evaluation_digest=current['evaluation_sha256'],
                        eligibility_digest=eligibility_digest)
        try:
            current_match_digest = ie._receipt_digest(result_snapshot)
        except ie.EligibilityError:
            return _out('UNKNOWN', 'MATCH_RECEIPT_DRIFT')
        if (intent.expected_evaluation_sha256 != current['evaluation_sha256'] or
                intent.expected_match_receipt_sha256 != current_match_digest or
                intent.expected_eligibility_result_sha256 != eligibility_digest or
                type(review_receipt) is not ie.HumanReviewReceipt or
                intent.expected_review_receipt_sha256 !=
                review_receipt_sha256(review_receipt)):
            return _out('UNKNOWN', 'INPUT_REVIEW_OR_RECEIPT_DRIFT',
                        evaluation_digest=current['evaluation_sha256'],
                        eligibility_digest=eligibility_digest)
        if any(ref.anchor_index >= len(match_request.subject_anchors) for ref in
               intent.selected_sources):
            return _out('INVALID_INPUT', 'SOURCE_INDEX_OUT_OF_RANGE',
                        evaluation_digest=current['evaluation_sha256'],
                        eligibility_digest=eligibility_digest)
        if any(source_anchor_sha256(match_request.subject_anchors[ref.anchor_index]) !=
               ref.expected_anchor_sha256 for ref in intent.selected_sources):
            return _out('UNKNOWN', 'SOURCE_REFERENCE_STALE',
                        evaluation_digest=current['evaluation_sha256'],
                        eligibility_digest=eligibility_digest)
        draft = _draft(context, intent, eligibility_request, match_request,
                       intent.expected_review_receipt_sha256, eligibility_digest)
        return _out('DRAFT_READY', 'LOCAL_PREVIEW_REDACTED_ONLY', draft=draft,
                    evaluation_digest=current['evaluation_sha256'],
                    eligibility_digest=eligibility_digest)
    except PlanError as exc:
        return _out('INVALID_INPUT', exc.code.removeprefix('ISSUE_PLAN_'))
    except ie.EligibilityError as exc:
        return _out('INVALID_INPUT', exc.code.removeprefix('ISSUE_ELIGIBILITY_'))
    except Exception:
        # Never echo unknown object/string/exception content into the response.
        return _out('UNKNOWN', 'UNEXPECTED_FAILURE')
