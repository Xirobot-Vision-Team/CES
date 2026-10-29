#!/usr/bin/env python3
"""EC217: independently signed, exact-scope, one-use IssueCreate *attempt* grant.

A local EC216 draft, EC215 reviewed eligibility, or a caller's desire is not
permission to publish. We re-run the unchanged EC216/EC215 gates over the
original evidence, bind the *entire* verified plan and the exact separately
human-reviewed final title/body/labels/citations, then require a fresh,
independently host-trusted Ed25519 issuer with the CREATE_NEW_ISSUE role.

`inspect_issue_create_grant` has no side effects and never authorizes sending.
`reserve_issue_create_grant` only claims a grant ID in a trusted atomic ledger;
there is NO provider POST or edit, and no return value is a remote write result.
The EC218 caller MUST recheck its own current provider/policy/identity/idempotency
and never retry a consumed grant as if it were reusable. A missing/broken ledger
fails closed. The sample SQLite ledger is for a trusted POSIX local disk, not
an authenticated multi-host/cloud ledger or adversarial filesystem.

Authoritative issuer enrollment, role assignment, revocation and separate human
review must be enforced by the host, not supplied by Issue/Finding JSON. The
module does not authenticate Git/CI source or all repository Issues, detect
all sensitive information in prose, or assert a privacy-policy approval.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from typing import Any, Callable, Mapping, Protocol
import unicodedata

try:
    from . import issue_provider as ip
    from . import issue_eligibility as ie
    from . import issue_match as im
    from . import issue_plan as plan
except ImportError:
    import issue_provider as ip
    import issue_eligibility as ie
    import issue_match as im
    import issue_plan as plan

SCHEMA = 'ces.issue_create_grant.v1'
RECEIPT_SCHEMA = 'ces.issue_create_approval.v1'
METHOD = 'EXPLICIT_HUMAN_APPROVAL_OF_ONE_NEW_ISSUE'
ACTION = 'CREATE_NEW_ISSUE'
ROLE = 'ISSUE_CREATE_APPROVER'
CHALLENGE_DOMAIN = b'CES-EC217-ISSUE-CREATE-CHALLENGE-v1\x00'
PLAN_RESULT_DOMAIN = b'CES-EC217-EXACT-PLAN-RESULT-v1\x00'
CONTENT_DOMAIN = b'CES-EC217-FINAL-ISSUE-CONTENT-v1\x00'
SIGN_DOMAIN = b'CES-EC217-DETACHED-CREATE-APPROVAL-v1\x00'
GRANT_ID_DOMAIN = b'CES-EC217-ONE-USE-GRANT-ID-v1\x00'
MAX_APPROVAL_SECONDS = 180
MAX_CONTENT_BYTES = 16384
MAX_TITLE = 100
MAX_BODY = 4000
MAX_LABELS = 6
AUDIENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{2,95}\Z', re.ASCII)
GRANT_ID = re.compile(r'[0-9a-f]{32}\Z', re.ASCII)
LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9 _.-]{0,39}\Z', re.ASCII)


@dataclass(frozen=True)
class Citation:
    """Opaque original EC216 E## plus exact anchor hash, never a path."""
    reference_id: str
    anchor_binding_sha256: str


@dataclass(frozen=True)
class FinalIssueContent:
    """Human-sanitized text. Its authenticity is established ONLY by signature.

    This is real, potentially confidential prose; only digest/length/flags may
    leave this module in machine-readable results. The caller must keep the
    bytes and display *all* of them to the signer before signing the receipt.
    """
    title: str
    body: str
    labels: tuple[str, ...]
    citations: tuple[Citation, ...]


@dataclass(frozen=True)
class IssueCreateIntent:
    """Explicit target, NEW action, reviewed plan/content and policy pins."""
    action: str
    provider: str
    api_host: str
    account_ref: str
    repository: str
    expected_repository_id: int
    visibility: str
    policy_revision_sha256: str
    expected_plan_sha256: str
    expected_plan_result_sha256: str
    expected_final_content_sha256: str
    audience: str


@dataclass(frozen=True)
class PlanEvidence:
    """All original EC216 inputs, not an invented eligible/draft boolean."""
    context: ip.ProviderContext
    plan_intent: plan.IssuePlanRequest
    eligibility_request: ie.EligibilityRequest
    match_request: im.IssueMatchRequest
    match_result: dict[str, Any] | None
    eligibility_result: dict[str, Any] | None
    eligibility_review_receipt: ie.HumanReviewReceipt
    plan_result: dict[str, Any] | None


@dataclass(frozen=True)
class IssuerAuthority:
    """Independently HOST-managed scoped role entry, NEVER request JSON.

    Host must authenticate the organization issuer, track revocations and
    refresh this registry. Self-provided issuer entries are not trust roots.
    """
    public_key: bytes
    role: str
    provider: str
    api_host: str
    account_ref: str
    repository_identity_sha256: str
    visibility: str
    policy_revision_sha256: str
    audience: str
    authority_revision_sha256: str
    valid_from_utc: str
    valid_until_utc: str
    revoked: bool


@dataclass(frozen=True)
class HumanCreateApproval:
    """Externally signed detached human approval; no signing key is accepted."""
    schema: str
    method: str
    action: str
    grant_id: str
    issuer_key_id: str
    authority_revision_sha256: str
    audience: str
    challenge_sha256: str
    plan_result_sha256: str
    final_content_sha256: str
    target_identity_sha256: str
    policy_revision_sha256: str
    decision: str
    confirms_full_final_text_and_citations_reviewed: bool
    confirms_target_visibility_and_privacy_reviewed: bool
    confirms_create_not_edit: bool
    acknowledges_duplicate_absence_not_proven: bool
    issued_at_utc: str
    expires_at_utc: str
    signature_base64: str


class GrantError(ValueError):
    def __init__(self, code: str, state: str = 'INVALID_INPUT') -> None:
        super().__init__(code)
        self.code = code
        self.state = state


def _need(ok: bool, code: str, state: str = 'INVALID_INPUT') -> None:
    if not ok:
        raise GrantError(code, state)


def _canonical(value: Any) -> bytes:
    return ip._canonical(value)


def _digest(value: Any, domain: bytes) -> str:
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _snapshot(value: Any, label: str, limit: int = plan.MAX_INPUT_BYTES) -> dict[str, Any]:
    _need(type(value) is dict, label + '_INVALID')
    try:
        raw = _canonical(value)
        _need(len(raw) <= limit, label + '_TOO_LARGE')
        copied = json.loads(raw)
        _need(type(copied) is dict, label + '_INVALID')
        return copied
    except GrantError:
        raise
    except (TypeError, ValueError, OverflowError, UnicodeError, RecursionError):
        raise GrantError(label + '_INVALID') from None


def _safe_text(value: Any, lo: int, hi: int, label: str, *, multiline: bool) -> None:
    _need(type(value) is str and lo <= len(value) <= hi and
          value == unicodedata.normalize('NFC', value) and
          value == value.strip(), label + '_INVALID')
    for ch in value:
        category = unicodedata.category(ch)
        _need(category not in ('Cc', 'Cf', 'Cs', 'Zl', 'Zp') or
              (multiline and ch in '\n\t'), label + '_CONTROL_CHARACTERS')
    _need(not any(ch in value for ch in ('\x00', '\r', '\u2028', '\u2029')),
          label + '_CONTROL_CHARACTERS')


def _content_bytes(content: FinalIssueContent) -> bytes:
    _need(type(content) is FinalIssueContent, 'CONTENT_INVALID')
    _safe_text(content.title, 8, MAX_TITLE, 'TITLE', multiline=False)
    _safe_text(content.body, 40, MAX_BODY, 'BODY', multiline=True)
    _need(type(content.labels) is tuple and len(content.labels) <= MAX_LABELS,
          'LABELS_INVALID')
    _need(all(type(x) is str and LABEL.fullmatch(x) is not None for x in content.labels)
          and tuple(sorted(set(content.labels))) == content.labels, 'LABELS_INVALID')
    _need(type(content.citations) is tuple and 1 <= len(content.citations) <= plan.MAX_REFERENCES,
          'CITATIONS_INVALID')
    for item in content.citations:
        _need(type(item) is Citation and type(item.reference_id) is str and
              re.fullmatch(r'E(?:0[1-9]|1[0-6])', item.reference_id) is not None and
              type(item.anchor_binding_sha256) is str and
              ie.HEX.fullmatch(item.anchor_binding_sha256) is not None,
              'CITATIONS_INVALID')
    data = {'title': content.title, 'body': content.body,
            'labels': list(content.labels),
            'citations': [x.__dict__ for x in content.citations]}
    try:
        raw = _canonical(data)
        _need(len(raw) <= MAX_CONTENT_BYTES, 'CONTENT_TOO_LARGE')
        return raw
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError):
        raise GrantError('CONTENT_INVALID') from None


def final_content_sha256(content: FinalIssueContent) -> str:
    """Exact UTF-8 JSON text/labels/citations SHA for independent human UI."""
    return hashlib.sha256(CONTENT_DOMAIN + _content_bytes(content)).hexdigest()


def plan_result_sha256(result: dict[str, Any]) -> str:
    return _digest(_snapshot(result, 'PLAN_RESULT'), PLAN_RESULT_DOMAIN)


def new_grant_id() -> str:
    """Cryptographically random one-use ID; host must never reuse an ID."""
    return secrets.token_hex(16)


def approval_signing_bytes(receipt: HumanCreateApproval) -> bytes:
    """Human UI signs precisely these domain-separated bytes, not EC215 bytes."""
    _need(type(receipt) is HumanCreateApproval, 'APPROVAL_INVALID')
    return SIGN_DOMAIN + _canonical({k: v for k, v in receipt.__dict__.items()
                                      if k != 'signature_base64'})


def _out(state: str, reason: str, *, challenge: dict[str, Any] | None = None,
         receipt_fingerprint: str | None = None) -> dict[str, Any]:
    status = ('invalid_input' if state == 'INVALID_INPUT' else
              'unavailable' if state == 'UNKNOWN' else 'partial')
    reserved = state == 'RESERVED_ONE_ATTEMPT'
    return {
        'schema': SCHEMA,
        'status': status,
        'exit_code': {'invalid_input': 4, 'unavailable': 5, 'partial': 2}[status],
        'reason_code': 'ISSUE_CREATE_GRANT_' + reason,
        'grant_state': state,
        'challenge': challenge,
        'approval_receipt_sha256': receipt_fingerprint,
        'approval_method': ('INDEPENDENT_DETACHED_HUMAN_SIGNATURE' if state in
                            ('SIGNED_REVIEW_VALID', 'RESERVED_ONE_ATTEMPT') else 'NOT_ACCEPTED'),
        'one_attempt_reservation': reserved,
        'host_ledger_atomic_claim_recorded': reserved,
        'issue_create_authorized_for_this_one_attempt': reserved,
        'permission_to_edit_existing_issue': False,
        'issue_created': False,
        'issue_create_network_attempted': False,
        'provider_or_business_repository_written': False,
        'finding_or_knowledge_written': False,
        'external_content_disclosed': False,
        'external_ai_called': False,
        'native_issue_action_registered': False,
        'repository_issue_inventory_complete': False,
        'duplicate_absence_proven': False,
        'source_authenticity_independently_verified': False,
        'organizational_issuer_authenticated_by_ces': False,
        'final_prose_safe_by_machine_proof': False,
        'delivery_state': 'NOT_ATTEMPTED',
        'safe_next_step': ('EC218_MUST_REVALIDATE_AND_ATTEMPT_AT_MOST_ONCE' if reserved
                           else 'NO_REMOTE_CREATE_AUTHORIZATION'),
    }


def _challenge(evidence: PlanEvidence, intent: IssueCreateIntent,
               content: FinalIssueContent,
               trusted_eligibility_review_keys: Mapping[str, bytes] | None,
               now: datetime) -> dict[str, Any]:
    _need(type(evidence) is PlanEvidence and type(intent) is IssueCreateIntent,
          'REQUEST_INVALID')
    _need(type(intent.action) is str and intent.action == ACTION,
          'ACTION_MUST_CREATE_NEW_ISSUE', 'BLOCKED')
    _need(type(intent.audience) is str and AUDIENCE.fullmatch(intent.audience) is not None,
          'AUDIENCE_INVALID')
    for digest in (intent.policy_revision_sha256, intent.expected_plan_sha256,
                   intent.expected_plan_result_sha256, intent.expected_final_content_sha256):
        _need(type(digest) is str and ie.HEX.fullmatch(digest) is not None,
              'EXPECTED_PIN_INVALID')
    _need(type(intent.provider) is str and intent.provider in ip.API_HOST and
          type(intent.api_host) is str and
          type(intent.account_ref) is str and
          type(intent.repository) is str and
          type(intent.expected_repository_id) is int and
          ip._positive_id(intent.expected_repository_id) and
          type(intent.visibility) is str and
          intent.visibility in ('PRIVATE', 'PUBLIC'), 'TARGET_INVALID')
    original = _snapshot(evidence.plan_result, 'PLAN_RESULT')
    # One coherent UTC instant across EC215, EC216 and EC217; no soft state is
    # inherited from the caller's untrusted EC216 JSON or eligibility output.
    fresh = plan.draft_issue_plan(
        evidence.context, evidence.plan_intent, evidence.eligibility_request,
        evidence.match_request, evidence.match_result, evidence.eligibility_result,
        review_receipt=evidence.eligibility_review_receipt,
        trusted_review_keys=trusted_eligibility_review_keys,
        clock=lambda: now)
    if fresh['plan_state'] != 'DRAFT_READY':
        _need(False, 'EC216_' + fresh['reason_code'].removeprefix('ISSUE_PLAN_'),
              'BLOCKED' if fresh['plan_state'] == 'BLOCKED' else
              'NEEDS_REVIEW' if fresh['plan_state'] == 'NEEDS_REVIEW' else 'UNKNOWN')
    _need(_canonical(original) == _canonical(fresh), 'EC216_FULL_RESULT_DRIFT', 'UNKNOWN')
    draft = fresh['draft']
    _need(type(draft) is dict and type(draft.get('target')) is dict and
          type(draft.get('privacy')) is dict and
          type(draft.get('references')) is list,
          'EC216_DRAFT_INVALID', 'UNKNOWN')
    ctx, elig = evidence.context, evidence.eligibility_request
    _need(type(ctx) is ip.ProviderContext and type(elig) is ie.EligibilityRequest,
          'EVIDENCE_INVALID')
    _need(intent.provider == ctx.provider == evidence.plan_intent.target_provider and
          intent.api_host == ctx.api_host and
          intent.account_ref == ctx.account_ref and
          intent.repository == evidence.plan_intent.target_repository == elig.repository and
          intent.expected_repository_id == evidence.plan_intent.expected_repository_id == elig.expected_repository_id and
          intent.visibility == evidence.plan_intent.target_visibility == elig.privacy.target_visibility and
          intent.policy_revision_sha256 == evidence.plan_intent.policy_revision_sha256 == elig.privacy.policy_revision_sha256,
          'TARGET_OR_POLICY_DRIFT', 'BLOCKED')
    _need(intent.expected_plan_sha256 == draft['plan_sha256'] and
          intent.expected_plan_result_sha256 == plan_result_sha256(fresh),
          'REVIEWED_PLAN_DRIFT', 'UNKNOWN')
    target_digest = plan._hash({
        'provider': ctx.provider, 'api_host': ctx.api_host,
        'account_ref': ctx.account_ref,
        'repository': elig.repository,
        'expected_repository_id': str(elig.expected_repository_id),
        'visibility': elig.privacy.target_visibility,
    }, plan.TARGET_DOMAIN)
    _need(target_digest == draft['target']['repository_identity_sha256'],
          'TARGET_DIGEST_DRIFT', 'UNKNOWN')
    raw_content = _content_bytes(content)
    content_digest = hashlib.sha256(CONTENT_DOMAIN + raw_content).hexdigest()
    _need(intent.expected_final_content_sha256 == content_digest,
          'REVIEWED_CONTENT_DRIFT', 'BLOCKED')
    expected_citations = tuple(Citation(x['reference_id'], x['anchor_binding_sha256'])
                               for x in draft['references'])
    _need(content.citations == expected_citations, 'SOURCE_CITATION_DRIFT', 'BLOCKED')
    # Signed grant does not prove that raw free-text content is safe. The
    # issuer must independently review *these exact bytes*, not just a hash.
    doc = {
        'action': ACTION, 'audience': intent.audience,
        'target_identity_sha256': target_digest,
        'visibility': intent.visibility,
        'policy_revision_sha256': intent.policy_revision_sha256,
        'plan_sha256': draft['plan_sha256'],
        'plan_result_sha256': intent.expected_plan_result_sha256,
        'eligibility_result_sha256': fresh['eligibility_result_sha256'],
        'evaluation_sha256': fresh['evaluation_sha256'],
        'signed_eligibility_review_sha256': draft['review_receipt_sha256'],
        'source_anchor_set_sha256': draft['source']['anchor_set_sha256'],
        'final_content_sha256': content_digest,
        'citation_bindings': [x.__dict__ for x in expected_citations],
    }
    return {
        'challenge_sha256': _digest(doc, CHALLENGE_DOMAIN),
        'action': ACTION,
        'audience': intent.audience,
        'provider': ctx.provider,
        'visibility': intent.visibility,
        'target_identity_sha256': target_digest,
        'policy_revision_sha256': intent.policy_revision_sha256,
        'plan_sha256': draft['plan_sha256'],
        'plan_result_sha256': intent.expected_plan_result_sha256,
        'final_content_sha256': content_digest,
        'final_title_chars': len(content.title),
        'final_body_chars': len(content.body),
        'citation_count': len(expected_citations),
        'label_count': len(content.labels),
        'human_review_of_full_private_text_required': True,
        'content_sanitization_machine_verified': False,
        'provider_write_authorized': False,
    }


def _safe_run(evidence: PlanEvidence, intent: IssueCreateIntent,
              content: FinalIssueContent,
              trusted_eligibility_review_keys: Mapping[str, bytes] | None,
              clock: Callable[[], datetime] | None) -> tuple[dict[str, Any], datetime]:
    now = ie._now(clock)
    return _challenge(evidence, intent, content, trusted_eligibility_review_keys, now), now


def prepare_issue_create_review(evidence: PlanEvidence, intent: IssueCreateIntent,
                                content: FinalIssueContent, *,
                                trusted_eligibility_review_keys: Mapping[str, bytes] | None,
                                clock: Callable[[], datetime] | None = None) -> dict[str, Any]:
    """Prepare digest-only challenge; NO human approval is inferred or granted."""
    try:
        challenge, _ = _safe_run(evidence, intent, content,
                                 trusted_eligibility_review_keys, clock)
        return _out('NEEDS_REVIEW', 'EXPLICIT_SIGNED_APPROVAL_REQUIRED',
                    challenge=challenge)
    except GrantError as exc:
        return _out(exc.state, exc.code)
    except Exception:
        return _out('UNKNOWN', 'UNEXPECTED_FAILURE')


def _verify_approval(receipt: HumanCreateApproval | None,
                     challenge: dict[str, Any], now: datetime,
                     context: ip.ProviderContext,
                     review: ie.HumanReviewReceipt,
                     trusted_eligibility_review_keys: Mapping[str, bytes] | None,
                     trusted_issuers: Mapping[str, IssuerAuthority] | None) -> tuple[str, str]:
    _need(type(receipt) is HumanCreateApproval, 'EXPLICIT_SIGNED_APPROVAL_MISSING', 'NEEDS_REVIEW')
    _need(receipt.schema == RECEIPT_SCHEMA and receipt.method == METHOD and
          receipt.action == ACTION and
          type(receipt.grant_id) is str and GRANT_ID.fullmatch(receipt.grant_id) is not None and
          type(receipt.issuer_key_id) is str and ie.KEY_ID.fullmatch(receipt.issuer_key_id) is not None and
          type(receipt.authority_revision_sha256) is str and ie.HEX.fullmatch(receipt.authority_revision_sha256) is not None and
          type(receipt.audience) is str and receipt.audience == challenge['audience'] and
          type(receipt.challenge_sha256) is str and
          receipt.challenge_sha256 == challenge['challenge_sha256'] and
          type(receipt.plan_result_sha256) is str and
          receipt.plan_result_sha256 == challenge['plan_result_sha256'] and
          type(receipt.final_content_sha256) is str and
          receipt.final_content_sha256 == challenge['final_content_sha256'] and
          type(receipt.target_identity_sha256) is str and
          receipt.target_identity_sha256 == challenge['target_identity_sha256'] and
          type(receipt.policy_revision_sha256) is str and
          receipt.policy_revision_sha256 == challenge['policy_revision_sha256'] and
          receipt.decision == 'APPROVE_EXACT_NEW_ISSUE_ONCE' and
          receipt.confirms_full_final_text_and_citations_reviewed is True and
          receipt.confirms_target_visibility_and_privacy_reviewed is True and
          receipt.confirms_create_not_edit is True and
          receipt.acknowledges_duplicate_absence_not_proven is True,
          'APPROVAL_SCOPE_OR_CONFIRMATIONS_INVALID', 'BLOCKED')
    _need(type(trusted_issuers) is dict and
          all(type(k) is str and ie.KEY_ID.fullmatch(k) is not None and
              type(v) is IssuerAuthority for k, v in trusted_issuers.items()),
          'HOST_ISSUER_REGISTRY_MISSING', 'BLOCKED')
    authority = trusted_issuers.get(receipt.issuer_key_id)
    _need(type(authority) is IssuerAuthority and
          authority.revoked is False and
          authority.role == ROLE and
          authority.provider == challenge['provider'] and
          authority.visibility == challenge['visibility'] and
          authority.repository_identity_sha256 == challenge['target_identity_sha256'] and
          authority.policy_revision_sha256 == challenge['policy_revision_sha256'] and
          authority.audience == challenge['audience'] and
          authority.authority_revision_sha256 == receipt.authority_revision_sha256 and
          type(authority.public_key) is bytes and len(authority.public_key) == 32,
          'ISSUER_NOT_AUTHORIZED_OR_REVOKED', 'BLOCKED')
    # The entire original EC215 authorizer is a *different* non-creation grant.
    # Do not permit same key material (even under a different key name) here.
    _need(type(review) is ie.HumanReviewReceipt and
          type(trusted_eligibility_review_keys) is dict and
          receipt.issuer_key_id != review.reviewer_key_id and
          authority.public_key not in trusted_eligibility_review_keys.values(),
          'ISSUER_NOT_INDEPENDENT_OF_ELIGIBILITY_REVIEW', 'BLOCKED')
    _need(type(receipt.issued_at_utc) is str and
          type(receipt.expires_at_utc) is str and
          type(authority.valid_from_utc) is str and
          type(authority.valid_until_utc) is str,
          'APPROVAL_CLOCK_INVALID')
    try:
        issued = ie._time(receipt.issued_at_utc)
        expiry = ie._time(receipt.expires_at_utc)
        authority_from = ie._time(authority.valid_from_utc)
        authority_until = ie._time(authority.valid_until_utc)
    except ie.EligibilityError:
        raise GrantError('APPROVAL_CLOCK_INVALID') from None
    _need(authority_from <= issued <= now < expiry <=
          issued + timedelta(seconds=MAX_APPROVAL_SECONDS) and
          now - issued <= timedelta(seconds=MAX_APPROVAL_SECONDS) and
          expiry <= authority_until and now < authority_until,
          'APPROVAL_EXPIRED_OR_OUTSIDE_ISSUER_WINDOW', 'NEEDS_REVIEW')
    # Bind all declared target locators against the *independent host policy*.
    # The target digest is not an identity/authentication proof by itself.
    _need(authority.api_host == context.api_host and
          authority.account_ref == context.account_ref,
          'ISSUER_ACCOUNT_SCOPE_MISMATCH', 'BLOCKED')
    _need(type(receipt.signature_base64) is str and
          len(receipt.signature_base64) == 88, 'APPROVAL_SIGNATURE_INVALID', 'NEEDS_REVIEW')
    try:
        signature = base64.b64decode(receipt.signature_base64, validate=True)
        _need(len(signature) == 64 and
              base64.b64encode(signature).decode('ascii') == receipt.signature_base64,
              'APPROVAL_SIGNATURE_INVALID', 'NEEDS_REVIEW')
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(authority.public_key).verify(
            signature, approval_signing_bytes(receipt))
    except GrantError:
        raise
    except Exception:
        raise GrantError('APPROVAL_SIGNATURE_INVALID', 'NEEDS_REVIEW') from None
    digest = _digest(receipt.__dict__, b'CES-EC217-COMPLETE-APPROVAL-v1\x00')
    return receipt.grant_id, digest


def _inspect(evidence: PlanEvidence, intent: IssueCreateIntent,
             content: FinalIssueContent,
             receipt: HumanCreateApproval | None,
             trusted_eligibility_review_keys: Mapping[str, bytes] | None,
             trusted_issuers: Mapping[str, IssuerAuthority] | None,
             clock: Callable[[], datetime] | None) -> tuple[dict[str, Any], str, str]:
    challenge, now = _safe_run(evidence, intent, content,
                               trusted_eligibility_review_keys, clock)
    # The independent host account locators never enter public challenge/result.
    grant_id, receipt_digest = _verify_approval(
        receipt, challenge, now, evidence.context,
        evidence.eligibility_review_receipt,
        trusted_eligibility_review_keys, trusted_issuers)
    return challenge, grant_id, receipt_digest


def inspect_issue_create_grant(evidence: PlanEvidence, intent: IssueCreateIntent,
                               content: FinalIssueContent,
                               receipt: HumanCreateApproval | None, *,
                               trusted_eligibility_review_keys: Mapping[str, bytes] | None,
                               trusted_issuers: Mapping[str, IssuerAuthority] | None,
                               clock: Callable[[], datetime] | None = None) -> dict[str, Any]:
    """Verify independently signed EXACT consent; not a one-use claim or send."""
    try:
        challenge, _, fingerprint = _inspect(
            evidence, intent, content, receipt,
            trusted_eligibility_review_keys, trusted_issuers, clock)
        return _out('SIGNED_REVIEW_VALID', 'SIGNATURE_VALID_NOT_RESERVED',
                    challenge=challenge, receipt_fingerprint=fingerprint)
    except GrantError as exc:
        return _out(exc.state, exc.code)
    except Exception:
        return _out('UNKNOWN', 'UNEXPECTED_FAILURE')


class AtomicGrantLedger(Protocol):
    """Host must supply a durable GLOBAL-TO-ITS-AUDIENCE atomic claim store.

    `atomic_claim` MUST atomically persist the ID before returning CLAIMED.
    Network failure, uncertainty, rollback or duplicate => NEVER CLAIMED.
    Sharing different stores for one audience defeats one-time protection.
    """
    audience: str

    def atomic_claim(self, grant_id: str, challenge_sha256: str,
                     now: datetime) -> str:
        ...


class SQLiteOneUseLedger:
    """POSIX single-host/local-disk example: durable SQLite UNIQUE ID claim.

    Instantiate ONLY with an independently chosen trusted private (0700)
    directory outside business repos, on a real local disk. Do not use on
    NFS, untrusted/mutating paths, Windows, or separate per-worker DB files.
    Failure to meet the preconditions returns UNAVAILABLE; no fallback memory
    store exists. A host-controlled shared transactional service should back
    production multi-host grants. No raw title, account or issuer key stored.
    """
    def __init__(self, db_path: str | Path, audience: str):
        self.path = Path(db_path)
        self.audience = audience

    def _path_ready(self) -> bool:
        try:
            if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW') or \
                    not self.path.is_absolute() or not AUDIENCE.fullmatch(self.audience):
                return False
            parent = self.path.parent
            if parent.is_symlink():
                return False
            for ancestor in (parent, *parent.parents):
                if ancestor.is_symlink():
                    return False
            pd = os.lstat(parent)
            if not stat.S_ISDIR(pd.st_mode) or pd.st_uid != os.getuid() or \
                    (pd.st_mode & 0o077) != 0:
                return False
            try:
                fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT |
                             os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
            info = os.lstat(self.path)
            return (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                    (info.st_mode & 0o077) == 0 and info.st_nlink == 1)
        except (OSError, ValueError, TypeError):
            return False

    def atomic_claim(self, grant_id: str, challenge_sha256: str,
                     now: datetime) -> str:
        if not (type(grant_id) is str and GRANT_ID.fullmatch(grant_id) is not None
                and type(challenge_sha256) is str and
                ie.HEX.fullmatch(challenge_sha256) is not None and
                type(now) is datetime and now.tzinfo is not None and
                self._path_ready()):
            return 'UNAVAILABLE'
        key = hashlib.sha256(GRANT_ID_DOMAIN + self.audience.encode('ascii') +
                             bytes.fromhex(grant_id)).hexdigest()
        try:
            db = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
            try:
                db.execute('PRAGMA busy_timeout=5000')
                db.execute('PRAGMA synchronous=FULL')
                db.execute('PRAGMA journal_mode=DELETE')
                db.execute('BEGIN IMMEDIATE')
                db.execute('CREATE TABLE IF NOT EXISTS claim ('
                           'grant_key TEXT PRIMARY KEY NOT NULL, '
                           'challenge_sha256 TEXT NOT NULL, '
                           'claimed_at_utc TEXT NOT NULL)')
                try:
                    db.execute('INSERT INTO claim VALUES (?, ?, ?)',
                               (key, challenge_sha256, now.isoformat()))
                except sqlite3.IntegrityError:
                    db.execute('ROLLBACK')
                    return 'ALREADY_CLAIMED'
                db.execute('COMMIT')
                return 'CLAIMED'
            finally:
                db.close()
        except (sqlite3.Error, OSError, ValueError, TypeError):
            return 'UNAVAILABLE'


def reserve_issue_create_grant(evidence: PlanEvidence, intent: IssueCreateIntent,
                               content: FinalIssueContent,
                               receipt: HumanCreateApproval | None, *,
                               trusted_eligibility_review_keys: Mapping[str, bytes] | None,
                               trusted_issuers: Mapping[str, IssuerAuthority] | None,
                               ledger: AtomicGrantLedger | None,
                               clock: Callable[[], datetime] | None = None) -> dict[str, Any]:
    """At-most-once local reservation, not a network IssueCreate operation.

    A verified signature still has NO remote authority until the host-controlled
    atomic ledger wins its one-and-only claim. After a successful reservation,
    only a separate EC218 write path may attempt a POST; no reuse/retry of this
    exact grant is permitted by EC217 even if that subsequent operation fails.
    """
    try:
        challenge, grant_id, fingerprint = _inspect(
            evidence, intent, content, receipt,
            trusted_eligibility_review_keys, trusted_issuers, clock)
        _need(ledger is not None and
              type(getattr(ledger, 'audience', None)) is str and
              ledger.audience == challenge['audience'] and
              callable(getattr(ledger, 'atomic_claim', None)),
              'ATOMIC_HOST_LEDGER_REQUIRED', 'BLOCKED')
        now = ie._now(clock)
        # Re-evaluate the short-lived grant lifetime *again* immediately
        # before committing the ledger; a clock/authority change denies.
        _need(ie._time(receipt.issued_at_utc) <= now < ie._time(receipt.expires_at_utc),
              'APPROVAL_EXPIRED_BEFORE_RESERVATION', 'NEEDS_REVIEW')
        claim = ledger.atomic_claim(grant_id, challenge['challenge_sha256'], now)
        if claim == 'ALREADY_CLAIMED':
            return _out('BLOCKED', 'GRANT_ALREADY_CONSUMED', challenge=challenge)
        if claim != 'CLAIMED':
            return _out('UNKNOWN', 'ATOMIC_LEDGER_UNAVAILABLE', challenge=challenge)
        return _out('RESERVED_ONE_ATTEMPT', 'SINGLE_USE_RESERVATION_RECORDED',
                    challenge=challenge, receipt_fingerprint=fingerprint)
    except GrantError as exc:
        return _out(exc.state, exc.code)
    except Exception:
        return _out('UNKNOWN', 'UNEXPECTED_FAILURE')
