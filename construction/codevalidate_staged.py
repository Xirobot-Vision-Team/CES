#!/usr/bin/env python3
"""EC175: source-pinned, read-only Staged CodeValidate for EC174 AI drafts.

This is a separately authorized *consumer* of a successful (partial/2) EC174
callback candidate, never of EC174 schema_only. Every call independently
reopens the genuine EC172/173 sealed POSIX input and recreates source-line
anchors and the complete EC174 candidate hash. An AI candidate, a matching
SHA256, or a signed manual review does not prove current Git source, remote AI
identity or CI success. No shell, Git, arbitrary draft code or output is run.

Optional manual review is an *external*, pinned HMAC attestation signed with a
separate operator-managed verification key. It only proves possession of that
key and what its holder attested, NOT that any test ran or a model was right.
The key must never come from the candidate, CES staging key or business repo.
No file is written by this module, including CES metadata: EC176 will have to
reauthorize, revalidate and create its own independently guarded saved record.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import sys
from typing import Any, Callable

import ai_handoff_router as ar
import handoff_input as hi
import handoff_lifecycle as lc
import task_staging as st

SCHEMA = "ces.codevalidate_staged_result.v1"
DRAFT_SCHEMA = "ces.codevalidate_staged_draft.v1"
REVIEW_SCHEMA = "ces.codevalidate_manual_review.v1"
DOMAIN_ROUTE = b"CES-EC175-ROUTE-BYTES-v1\x00"
DOMAIN_DRAFT = b"CES-EC175-DRAFT-v1\x00"
DOMAIN_FINDING = b"CES-EC175-FINDING-v1\x00"
DOMAIN_REVIEW = b"CES-EC175-TRUSTED-REVIEW-v1\x00"
DOMAIN_RECEIPT = b"CES-EC175-VALIDATION-RECEIPT-v1\x00"
MAX_ROUTE_BYTES = 384 * 1024
MAX_DRAFT_BYTES = 256 * 1024
MAX_REVIEW_BYTES = 32 * 1024
MAX_VERIFICATION_TTL = 300
MAX_REVIEW_TTL = 300
MAX_REVIEW_NOTE = 1200
EXIT = {"partial": 2, "invalid_input": 4, "unavailable": 5}
TRUST = "LOCAL_EC173_SEAL_NO_LIVE_SOURCE_OR_REMOTE_PROVIDER_IDENTITY"


class ValidateError(st.StageError):
    pass


def _require(ok: bool, code: str, status: str = "invalid_input") -> None:
    if not ok:
        raise ValidateError(code, status)


def _equal(actual: Any, expected: Any) -> bool:
    return type(actual) is type(expected) and st._canonical(actual) == st._canonical(expected)


def _exact(row: Any, keys: set[str], error: str) -> dict[str, Any]:
    _require(type(row) is dict and set(row) == keys, error)
    return row


def _sha(domain: bytes, obj: Any) -> str:
    return hashlib.sha256(domain + st._canonical(obj)).hexdigest()


def _check_op(key: Any) -> None:
    try:
        lc._check_op(key)
    except lc.LifecycleError as exc:
        raise ValidateError("CODEVALIDATE_OPERATION_KEY_INVALID") from exc


def _validate_finding(item: Any, ordinal: int, material: dict[str, Any]) -> dict[str, Any]:
    fields = {"ordinal", "title", "severity", "confidence_claim", "analysis",
              "suggested_action", "anchors", "verification", "business_source_validation"}
    _exact(item, fields, "CODEVALIDATE_DRAFT_FINDING_FIELDS_INVALID")
    _require(type(item["ordinal"]) is int and item["ordinal"] == ordinal,
             "CODEVALIDATE_FINDING_ORDINAL_CHANGED")
    _require(type(item["severity"]) is str and item["severity"] in ar.SEVERITY and
             type(item["confidence_claim"]) is str and
             item["confidence_claim"] in ar.CONFIDENCE,
             "CODEVALIDATE_DRAFT_ENUM_INVALID")
    ar._bounded_text(item["title"], 120, "CODEVALIDATE_TITLE_UNSAFE")
    ar._bounded_text(item["analysis"], ar.MAX_FINDING_TEXT_CHARS,
                     "CODEVALIDATE_ANALYSIS_UNSAFE")
    if item["suggested_action"] is not None:
        ar._bounded_text(item["suggested_action"], ar.MAX_FINDING_TEXT_CHARS,
                         "CODEVALIDATE_ACTION_UNSAFE")
    _require(item["verification"] == "UNVERIFIED_AI_ASSERTION_NOT_PERSISTED_FINDING" and
             item["business_source_validation"] == "NOT_RUN",
             "CODEVALIDATE_MODEL_VERIFICATION_ESCALATION_FORBIDDEN")
    anchors = item["anchors"]
    _require(type(anchors) is list and 1 <= len(anchors) <= ar.MAX_ANCHORS_PER_FINDING,
             "CODEVALIDATE_FINDING_MISSING_SOURCE_ANCHORS")
    for anchor in anchors:
        _exact(anchor, {"segment_index", "segment_label", "item_index", "source_path",
                        "line_number_in_segment_or_item", "quote", "anchor_sha256",
                        "line_number_is_git_file_line", "evidence_provenance"},
               "CODEVALIDATE_ANCHOR_FIELDS_INVALID")
        expected = ar._anchor({
            "segment_index": anchor["segment_index"], "item_index": anchor["item_index"],
            "line_number": anchor["line_number_in_segment_or_item"], "quote": anchor["quote"],
        }, material["segments"])
        _require(_equal(anchor, expected), "CODEVALIDATE_ANCHOR_PROVENANCE_OR_QUOTE_CHANGED")
    _require(len(set(a["anchor_sha256"] for a in anchors)) == len(anchors),
             "CODEVALIDATE_DUPLICATE_ANCHOR")
    return item


def _check_route(outcome: Any, binding: dict[str, Any],
                 coverage: dict[str, Any], material: dict[str, Any],
                 expected_candidate_sha256: str) -> tuple[list[dict[str, Any]], str, str]:
    _require(type(outcome) is dict, "CODEVALIDATE_ROUTE_RESULT_REQUIRED")
    _require(len(st._canonical(outcome)) <= MAX_ROUTE_BYTES,
             "CODEVALIDATE_ROUTE_TOO_LARGE")
    _exact(outcome, {"schema", "status", "exit_code", "reason_code", "action", "route_id",
                     "task_kind", "source_binding", "source", "coverage", "provider",
                     "result", "effects", "trust_boundary"},
           "CODEVALIDATE_ROUTE_FIELDS_INVALID")
    _require(outcome["schema"] == ar.SCHEMA and outcome["route_id"] == ar.ROUTE_ID and
             outcome["task_kind"] == "code_analysis",
             "CODEVALIDATE_UNKNOWN_ROUTE_OR_TASK")
    _require(outcome["action"] == "dispatch" and
             outcome["reason_code"] == "AI_CANDIDATE_RECEIVED_UNVERIFIED" and
             outcome["status"] == "partial" and type(outcome["exit_code"]) is int and
             outcome["exit_code"] == 2,
             "CODEVALIDATE_SCHEMA_ONLY_OR_NONCANDIDATE_NOT_A_DRAFT")
    _require(_equal(outcome["source_binding"], binding),
             "CODEVALIDATE_ROUTE_RUN_SOURCE_REVISION_DRIFT")
    expected_source = {
        "mode": material["source_mode"], "observed_at_utc": material["source_observed_at_utc"],
        "currentness": material["source_currentness"], "source_currentness_proven": False,
        "historical_proposal_only": material["source_mode"] == "ProposedPR",
    }
    _require(_equal(outcome["source"], expected_source) and
             _equal(outcome["coverage"], coverage) and
             outcome["trust_boundary"] ==
             "LOCAL_EC173_SEAL_ONLY_NO_LIVE_SOURCE_OR_REMOTE_ACTOR_PROOF",
             "CODEVALIDATE_ROUTE_SOURCE_OR_COVERAGE_ESCALATION")
    _require(_equal(outcome["effects"], {
        "source_material_released_to_callback": True, "model_output_persisted": False,
        "business_repository_written": False, "git_or_issue_written": False,
        "external_side_effects_excluded": False,
    }), "CODEVALIDATE_ROUTE_EFFECTS_CONFLICT")
    provider = _exact(outcome["provider"], {
        "bridge_id", "provider_claim", "actor_claim", "actor_or_provider_authenticated",
        "external_model_execution_verified", "callback_invoked",
        "candidate_received_and_schema_checked"}, "CODEVALIDATE_ROUTE_PROVIDER_FIELDS_INVALID")
    _require(provider["bridge_id"] == ar.BRIDGE_ID and
             type(provider["provider_claim"]) is str and
             ar.LABEL.fullmatch(provider["provider_claim"]) is not None and
             type(provider["actor_claim"]) is str and
             ar.LABEL.fullmatch(provider["actor_claim"]) is not None and
             provider["actor_or_provider_authenticated"] is False and
             provider["external_model_execution_verified"] is False and
             provider["callback_invoked"] is True and
             provider["candidate_received_and_schema_checked"] is True,
             "CODEVALIDATE_PROVIDER_NOT_AUTHENTICATED_OR_NO_CANDIDATE")
    result = _exact(outcome["result"], {
        "summary", "findings", "candidate_sha256", "semantic_validation",
        "persisted_finding_created"}, "CODEVALIDATE_ROUTE_RESULT_FIELDS_INVALID")
    _require(result["semantic_validation"] == "NOT_PERFORMED" and
             result["persisted_finding_created"] is False,
             "CODEVALIDATE_MODEL_SEMANTIC_VERIFICATION_ESCALATION")
    ar._bounded_text(result["summary"], ar.MAX_SUMMARY_CHARS,
                     "CODEVALIDATE_DRAFT_SUMMARY_UNSAFE", allow_empty=True)
    findings = result["findings"]
    _require(type(findings) is list and len(findings) <= ar.MAX_FINDINGS,
             "CODEVALIDATE_FINDINGS_LIMIT_INVALID")
    for n, finding in enumerate(findings, 1):
        _validate_finding(finding, n, material)
    expected_sha = _sha(ar.DOMAIN_RESULT, {
        "source_binding": binding, "summary": result["summary"], "findings": findings,
        "actor_claim": provider["actor_claim"],
    })
    _require(type(result["candidate_sha256"]) is str and
             type(expected_candidate_sha256) is str and
             hmac.compare_digest(result["candidate_sha256"], expected_sha) and
             hmac.compare_digest(expected_candidate_sha256, expected_sha),
             "CODEVALIDATE_CANDIDATE_UNKNOWN_OR_EDITED")
    return findings, result["summary"], _sha(DOMAIN_ROUTE, outcome)


def _draft_from_route(outcome: dict[str, Any]) -> dict[str, Any]:
    return {"schema": DRAFT_SCHEMA, "source_binding": outcome["source_binding"],
            "candidate_sha256": outcome["result"]["candidate_sha256"],
            "summary": outcome["result"]["summary"],
            "findings": outcome["result"]["findings"],
            "actor_claim": outcome["provider"]["actor_claim"]}


def _check_draft(draft: Any, outcome: dict[str, Any]) -> str:
    _require(type(draft) is dict and len(st._canonical(draft)) <= MAX_DRAFT_BYTES,
             "CODEVALIDATE_DRAFT_TOO_LARGE_OR_INVALID")
    _exact(draft, {"schema", "source_binding", "candidate_sha256", "summary",
                   "findings", "actor_claim"}, "CODEVALIDATE_DRAFT_FIELDS_INVALID")
    _require(draft["schema"] == DRAFT_SCHEMA, "CODEVALIDATE_DRAFT_SCHEMA_INVALID")
    _require(_equal(draft, _draft_from_route(outcome)),
             "CODEVALIDATE_DRAFT_EDITED_OR_MIXED")
    return _sha(DOMAIN_DRAFT, draft)


def _review_and_states(review: Any, *, binding: dict[str, Any],
                       candidate_sha256: str, operation_key: str,
                       findings: list[dict[str, Any]], now: datetime,
                       valid_until: datetime, observed_at: datetime,
                       verifier_id: str, key: bytes,
                       allow_review: bool, review_source_for: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    _require(allow_review is True, "CODEVALIDATE_INDEPENDENT_MANUAL_APPROVAL_REQUIRED")
    _require(type(review_source_for) is str and review_source_for == binding["source_mode"],
             "CODEVALIDATE_MANUAL_REVIEW_SOURCE_SCOPE_MISMATCH")
    _require(type(verifier_id) is str and ar.LABEL.fullmatch(verifier_id) is not None and
             type(key) is bytes and 32 <= len(key) <= 64,
             "CODEVALIDATE_PINNED_VERIFIER_CONFIGURATION_REQUIRED")
    _require(type(review) is dict and len(st._canonical(review)) <= MAX_REVIEW_BYTES,
             "CODEVALIDATE_ATTESTATION_TOO_LARGE_OR_INVALID")
    _exact(review, {"schema", "method", "verifier_id", "source_binding",
                    "candidate_sha256", "validation_operation_key", "reviewed_at_utc",
                    "expires_at_utc", "decisions", "mac_sha256"},
           "CODEVALIDATE_ATTESTATION_FIELDS_INVALID")
    _require(review["schema"] == REVIEW_SCHEMA and
             review["method"] == "independent_manual_source_review" and
             review["verifier_id"] == verifier_id and
             _equal(review["source_binding"], binding) and
             review["candidate_sha256"] == candidate_sha256 and
             review["validation_operation_key"] == operation_key,
             "CODEVALIDATE_ATTESTATION_IDENTITY_OR_CONTEXT_MISMATCH")
    checked = _parse(review["reviewed_at_utc"])
    expires = _parse(review["expires_at_utc"])
    _require(checked >= observed_at and
             checked <= now + timedelta(seconds=st.MAX_SKEW_SECONDS) and
             checked >= now - timedelta(seconds=MAX_REVIEW_TTL) and
             expires > now and expires <= checked + timedelta(seconds=MAX_REVIEW_TTL) and
             expires <= valid_until,
             "CODEVALIDATE_ATTESTATION_STALE_OR_OUTSIDE_INPUT_TTL", "unavailable")
    decisions = review["decisions"]
    _require(type(decisions) is list and len(findings) > 0 and
             len(decisions) == len(findings),
             "CODEVALIDATE_ATTESTATION_REQUIRES_EXACT_FINDING_DECISIONS")
    for n, (item, finding) in enumerate(zip(decisions, findings), 1):
        _exact(item, {"ordinal", "finding_sha256", "verdict", "review_notes"},
               "CODEVALIDATE_REVIEW_DECISION_FIELDS_INVALID")
        _require(type(item["ordinal"]) is int and item["ordinal"] == n and
                 item["finding_sha256"] == _sha(DOMAIN_FINDING, finding) and
                 type(item["verdict"]) is str and
                 item["verdict"] in ("confirm", "reject", "inconclusive"),
                 "CODEVALIDATE_REVIEW_DECISION_OR_FINDING_HASH_MISMATCH")
        ar._bounded_text(item["review_notes"], MAX_REVIEW_NOTE,
                         "CODEVALIDATE_REVIEW_NOTES_UNSAFE")
    mac = review["mac_sha256"]
    _require(type(mac) is str and lc.SHA_RE.fullmatch(mac) is not None,
             "CODEVALIDATE_REVIEW_SIGNATURE_INVALID")
    expected = hmac.new(key, DOMAIN_REVIEW + st._canonical({
        k: v for k, v in review.items() if k != "mac_sha256"
    }), hashlib.sha256).hexdigest()
    _require(hmac.compare_digest(mac, expected),
             "CODEVALIDATE_REVIEW_SIGNATURE_NOT_TRUSTED", "unavailable")
    states = []
    for item in decisions:
        state = {"confirm": "VERIFIED_BY_PINNED_MANUAL_REVIEW_SIGNATURE",
                 "reject": "REJECTED_BY_PINNED_MANUAL_REVIEW",
                 "inconclusive": "UNVERIFIED_REVIEW_INCONCLUSIVE"}[item["verdict"]]
        states.append({"state": state, "manual_review_note_sha256":
                       hashlib.sha256(item["review_notes"].encode("utf-8")).hexdigest()})
    return states, {
        "method": "PINNED_HMAC_MANUAL_ATTESTATION_NOT_TEST_EXECUTION",
        "verifier_id": verifier_id, "attestation_sha256": _sha(DOMAIN_REVIEW, review),
        "reviewed_at_utc": review["reviewed_at_utc"],
        "expires_at_utc": review["expires_at_utc"],
        "verifier_identity_independently_authenticated": False,
        "key_possession_checked": True,
        "actual_test_execution_observed": False,
    }


def _parse(value: Any) -> datetime:
    try:
        return st._parse_stamp(value)
    except st.StageError as exc:
        raise ValidateError("CODEVALIDATE_REVIEW_TIME_INVALID") from exc


def _response(*, status: str, reason: str, operation_key: str | None,
              binding: dict[str, Any] | None, source: dict[str, Any] | None,
              coverage: dict[str, Any] | None, now: str | None, valid_until: str | None,
              route_sha: str | None, draft_sha: str | None,
              candidate_sha: str | None, rows: list[dict[str, Any]],
              attestation: dict[str, Any] | None) -> dict[str, Any]:
    accepted = status == "partial"
    verified_count = sum(r["review_state"] == "VERIFIED_BY_PINNED_MANUAL_REVIEW_SIGNATURE"
                         for r in rows)
    rejected_count = sum(r["review_state"] == "REJECTED_BY_PINNED_MANUAL_REVIEW" for r in rows)
    result = {
        "schema": SCHEMA, "mode": "Staged", "status": status, "exit_code": EXIT[status],
        "reason_code": reason, "validation_operation_key": operation_key,
        "source_binding": binding, "source": source, "coverage": coverage,
        "validated_at_utc": now, "expires_at_utc": valid_until,
        "candidate": {
            "state": "STRUCTURALLY_CHECKED_DRAFT" if accepted else "REJECTED",
            "route_result_sha256": route_sha, "draft_sha256": draft_sha,
            "candidate_sha256": candidate_sha, "findings": rows if accepted else [],
            "findings_count": len(rows) if accepted else 0,
            "manual_verified_count": verified_count,
            "manual_rejected_count": rejected_count,
            "semantic_or_test_execution_verified": False,
        },
        "manual_review": attestation,
        "proof": {
            "source_anchors_rechecked_against_ec173": accepted,
            "ec172_ec173_integrity_and_expiry_rechecked": accepted,
            "source_currentness_proven": False,
            "provider_or_ai_actor_authenticated": False,
            "external_model_execution_proven": False,
            "ci_or_test_execution_observed": False,
            "manual_signature_is_live_source_proof": False,
            "historical_proposal_only": bool(source and source["mode"] == "ProposedPR"),
        },
        "effects": {
            "business_repository_written": False, "git_or_issue_written": False,
            "ces_record_or_finding_saved": False, "source_code_executed": False,
            "codesave_authorized": False, "eligible_for_automatic_codesave": False,
            "third_party_transfer_performed_by_validator": False,
        },
        "trust_boundary": TRUST,
    }
    result["validation_receipt_sha256"] = _sha(DOMAIN_RECEIPT, result)
    return result


class StagedCodeValidator:
    """Unprivileged no-write CodeValidate:Staged, independent of EC174 routing."""

    def __init__(self, root: str, business_repo_root: str, *,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.input = hi.HandoffInput(root, business_repo_root, clock=clock)
        self.clock = clock

    def validate(self, prepared: dict[str, Any], route_result: dict[str, Any], *,
                 expected_parent_pin: str, run_id: str, handoff_id: str,
                 expected_revision: int, expected_event_sha256: str,
                 input_operation_key: str, validation_operation_key: str,
                 authorize_validate: bool, authorize_read: bool,
                 validate_content_for: str, expected_candidate_sha256: str,
                 draft: dict[str, Any] | None = None,
                 allow_historical_proposal: bool = False,
                 max_source_age_seconds: int = hi.DEFAULT_MAX_SOURCE_AGE,
                 manual_review: dict[str, Any] | None = None,
                 authorize_manual_review: bool = False,
                 manual_review_content_for: str | None = None,
                 trusted_verifier_id: str | None = None,
                 trusted_verifier_key: bytes | None = None) -> dict[str, Any]:
        """Check a single EC174 callback candidate under a NEW source-scoped grant.

        A caller-supplied draft is allowed only if byte-canonically identical to
        the normalized EC174 result, with separately pinned candidate digest.
        Manual signatures attest *reviewer declaration*, not objective correctness.
        The output, even manually attested, can NEVER authorize EC176 CodeSave.
        """
        binding = coverage = source = None
        route_sha = draft_sha = candidate_sha = None
        now_text = until_text = None
        op = validation_operation_key if type(validation_operation_key) is str and len(validation_operation_key) <= 128 else None
        try:
            _require(authorize_validate is True,
                     "CODEVALIDATE_INDEPENDENT_VALIDATION_APPROVAL_REQUIRED")
            _require(authorize_read is True,
                     "CODEVALIDATE_INDEPENDENT_INPUT_READ_APPROVAL_REQUIRED")
            _require(type(validate_content_for) is str and
                     validate_content_for in lc.SOURCE_MODES,
                     "CODEVALIDATE_SOURCE_GRANT_INVALID")
            _check_op(input_operation_key)
            _check_op(validation_operation_key)
            _require(validation_operation_key != input_operation_key,
                     "CODEVALIDATE_OPERATION_KEY_MUST_BE_DISTINCT_FROM_INPUT")
            _require(type(expected_candidate_sha256) is str and
                     lc.SHA_RE.fullmatch(expected_candidate_sha256) is not None,
                     "CODEVALIDATE_EXPECTED_CANDIDATE_SHA_REQUIRED")
            has_review_param = (manual_review is not None or authorize_manual_review is True or
                                manual_review_content_for is not None or
                                trusted_verifier_id is not None or trusted_verifier_key is not None)
            _require(not has_review_param or all((manual_review is not None,
                        authorize_manual_review is True,
                        manual_review_content_for is not None,
                        trusted_verifier_id is not None, trusted_verifier_key is not None)),
                     "CODEVALIDATE_MANUAL_REVIEW_PARTIAL_OR_UNAPPROVED")
            loaded = self.input.load_authorized(
                prepared, authorize_read=True, read_content_for=validate_content_for,
                expected_parent_pin=expected_parent_pin, run_id=run_id,
                handoff_id=handoff_id, expected_revision=expected_revision,
                expected_event_sha256=expected_event_sha256,
                operation_key=input_operation_key,
                allow_historical_proposal=allow_historical_proposal,
                max_source_age_seconds=max_source_age_seconds,
            )
            meta, material = loaded["metadata"], loaded["material"]
            _require(meta["task_kind"] == "code_analysis" and
                     meta["source_mode"] == validate_content_for and
                     meta["run_id"] == run_id and meta["handoff_id"] == handoff_id and
                     meta["stage_revision"] == expected_revision,
                     "CODEVALIDATE_INPUT_TASK_OR_STAGE_CHANGED", "unavailable")
            binding = ar._binding(meta, material, expected_event_sha256)
            coverage = ar._coverage(material)
            source = {"mode": material["source_mode"],
                      "source_identity_sha256": binding["source_identity_sha256"],
                      "source_context_sha256": binding["source_context_sha256"],
                      "source_observed_at_utc": material["source_observed_at_utc"],
                      "currentness": material["source_currentness"],
                      "currentness_proven": False,
                      "historical_proposal_only": material["source_mode"] == "ProposedPR"}
            now = st._now(self.clock)
            expires = min(st._parse_stamp(meta["expires_at_utc"]),
                          hi._observed(material["source_observed_at_utc"]) +
                          timedelta(seconds=max_source_age_seconds),
                          now + timedelta(seconds=MAX_VERIFICATION_TTL))
            _require(now < expires, "CODEVALIDATE_VALIDITY_WINDOW_EXPIRED", "unavailable")
            now_text, until_text = st._stamp(now), st._stamp(expires)
            rows, _, route_sha = _check_route(
                route_result, binding, coverage, material, expected_candidate_sha256)
            candidate_sha = route_result["result"]["candidate_sha256"]
            draft_sha = _check_draft(draft if draft is not None else
                                     _draft_from_route(route_result), route_result)
            states = [{"state": "UNVERIFIED_SEMANTIC_ASSERTION",
                       "manual_review_note_sha256": None} for _ in rows]
            reviewed = None
            if has_review_param:
                states, reviewed = _review_and_states(
                    manual_review, binding=binding, candidate_sha256=candidate_sha,
                    operation_key=validation_operation_key, findings=rows,
                    now=now, valid_until=expires,
                    observed_at=hi._observed(material["source_observed_at_utc"]),
                    verifier_id=trusted_verifier_id, key=trusted_verifier_key,
                    allow_review=authorize_manual_review,
                    review_source_for=manual_review_content_for,
                )
            # A valid candidate and a valid review do not freeze the source.
            # Reopen independently and reject any context, grant, event, TTL,
            # content or HMAC change that happened during validation.
            fresh = self.input.load_authorized(
                prepared, authorize_read=True, read_content_for=validate_content_for,
                expected_parent_pin=expected_parent_pin, run_id=run_id,
                handoff_id=handoff_id, expected_revision=expected_revision,
                expected_event_sha256=expected_event_sha256,
                operation_key=input_operation_key,
                allow_historical_proposal=allow_historical_proposal,
                max_source_age_seconds=max_source_age_seconds,
            )
            _require(ar._binding(fresh["metadata"], fresh["material"],
                                 expected_event_sha256) == binding and
                     fresh["material"] == material,
                     "CODEVALIDATE_INPUT_CHANGED_DURING_VALIDATION", "unavailable")
            _require(st._now(self.clock) < expires,
                     "CODEVALIDATE_EXPIRED_AFTER_REVIEW", "unavailable")
            findings = []
            for finding, state in zip(rows, states):
                findings.append({"ordinal": finding["ordinal"],
                                 "finding_sha256": _sha(DOMAIN_FINDING, finding),
                                 "source_anchor_sha256": [a["anchor_sha256"] for a in finding["anchors"]],
                                 "review_state": state["state"],
                                 "manual_review_note_sha256": state["manual_review_note_sha256"],
                                 "text_persisted": False, "live_git_line_proven": False})
            reason = ("CODEVALIDATE_PINNED_MANUAL_REVIEW_RECORDED_NOT_SOURCE_PROOF"
                      if reviewed else
                      "CODEVALIDATE_DRAFT_STRUCTURALLY_CHECKED_SEMANTICS_UNVERIFIED")
            # Rejection of an individual claim is not rejection of the entire
            # sealed draft; no caller may turn a valid partial into success.
            return _response(status="partial", reason=reason,
                             operation_key=op, binding=binding, source=source,
                             coverage=coverage, now=now_text, valid_until=until_text,
                             route_sha=route_sha, draft_sha=draft_sha,
                             candidate_sha=candidate_sha, rows=findings,
                             attestation=reviewed)
        except (ValidateError, ar.RouteError, hi.InputError,
                st.StageError, lc.LifecycleError) as exc:
            error = exc if isinstance(exc, ValidateError) else ValidateError(exc.code, exc.status)
            return _response(status=error.status, reason=error.code,
                             operation_key=op, binding=binding, source=source,
                             coverage=coverage, now=None, valid_until=None,
                             route_sha=None, draft_sha=None, candidate_sha=None,
                             rows=[], attestation=None)
        except (TypeError, ValueError, KeyError, IndexError, OverflowError,
                RecursionError, MemoryError):
            return _response(status="invalid_input", reason="CODEVALIDATE_MALFORMED_UNTRUSTED_OBJECT",
                             operation_key=op, binding=binding, source=source,
                             coverage=coverage, now=None, valid_until=None,
                             route_sha=None, draft_sha=None, candidate_sha=None,
                             rows=[], attestation=None)


def main(argv: list[str] | None = None) -> int:
    """Read-only, metadata-only CLI; no plaintext draft/finding or key on stdout."""
    parser = argparse.ArgumentParser(description="EC175 read-only Staged CodeValidate (no CodeSave)")
    parser.add_argument("--prepared", required=True)
    parser.add_argument("--route-result", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--business-repo-root", required=True)
    parser.add_argument("--parent-pin", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--handoff-id", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--expected-event-sha256", required=True)
    parser.add_argument("--input-operation-key", required=True)
    parser.add_argument("--validation-operation-key", required=True)
    parser.add_argument("--expected-candidate-sha256", required=True)
    parser.add_argument("--allow-content-for", required=True, choices=sorted(lc.SOURCE_MODES))
    parser.add_argument("--approve-validate", action="store_true")
    parser.add_argument("--approve-read", action="store_true")
    parser.add_argument("--allow-historical-proposal", action="store_true")
    parser.add_argument("--max-source-age-seconds", type=int, default=hi.DEFAULT_MAX_SOURCE_AGE)
    args = parser.parse_args(argv)
    try:
        prepared = lc._strict_load(lc._read_bounded(args.prepared, lc.MAX_PREPARED_BYTES),
                                   lc.MAX_PREPARED_BYTES)
        outcome = lc._strict_load(lc._read_bounded(args.route_result, MAX_ROUTE_BYTES),
                                  MAX_ROUTE_BYTES)
        result = StagedCodeValidator(args.root, args.business_repo_root).validate(
            prepared, outcome, expected_parent_pin=args.parent_pin,
            run_id=args.run_id, handoff_id=args.handoff_id,
            expected_revision=args.expected_revision,
            expected_event_sha256=args.expected_event_sha256,
            input_operation_key=args.input_operation_key,
            validation_operation_key=args.validation_operation_key,
            expected_candidate_sha256=args.expected_candidate_sha256,
            authorize_validate=args.approve_validate, authorize_read=args.approve_read,
            validate_content_for=args.allow_content_for,
            allow_historical_proposal=args.allow_historical_proposal,
            max_source_age_seconds=args.max_source_age_seconds,
        )
    except (lc.LifecycleError, OSError, ValueError, TypeError, RecursionError, MemoryError):
        result = _response(status="invalid_input", reason="CODEVALIDATE_CLI_INPUT_INVALID",
                           operation_key=None, binding=None, source=None,
                           coverage=None, now=None, valid_until=None,
                           route_sha=None, draft_sha=None, candidate_sha=None,
                           rows=[], attestation=None)
    # Intentionally only metadata, never raw text or full source anchors.
    print(json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
