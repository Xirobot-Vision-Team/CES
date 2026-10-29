#!/usr/bin/env python3
"""EC177: source-revalidated, in-memory Finding v1 projection (NOT FindingSave).

The EC174 model claim, EC175 local HMAC manual review, EC176 sealed metadata
and actual test/semantic truth are different authorities. Reopen EC172/173 and
rerun the real EC175 validator, optionally verify the genuine EC176 HMAC store,
and emit bounded, deterministic finding identities and separate provenance,
positive/counter-evidence, uncertainty, severity and confidence.

No code/test/CI/Provider execution, source or repository write, Issue update,
Finding persistence, or real human/actor authentication occurs here.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import hmac
import json
from typing import Any, Callable

import ai_handoff_router as ar
import codevalidate_staged as cv
import codesave_staged as cs
import handoff_input as hi
import handoff_lifecycle as lc
import task_staging as st

SCHEMA = "ces.finding_projection.v1"
FINDING_SCHEMA = "ces.finding.v1"
DOMAIN_FINDING_ID = b"CES-EC177-FINDING-STABLE-IDENTITY-v1\x00"
DOMAIN_PROJECTION = b"CES-EC177-FINDING-PROJECTION-v1\x00"
DOMAIN_PATH = b"CES-EC177-SOURCE-PATH-v1\x00"
DOMAIN_LABEL = b"CES-EC177-SEGMENT-LABEL-v1\x00"
DOMAIN_COUNTER = b"CES-EC177-COUNTER-EVIDENCE-v1\x00"
STATES = ("UNVERIFIED", "REVIEWED", "REJECTED", "INCONCLUSIVE", "ACTUALLY_TESTED")
EMIT_STATES = STATES[:4]  # No objective runner, therefore ACTUALLY_TESTED is unreachable.
MAX_ANNOTATION_BYTES = 48 * 1024
MAX_COUNTER_ROWS = 32
MAX_COUNTER_ANCHORS = 3
MAX_INTERPRETATION_CHARS = 800
MAX_OUTPUT_BYTES = 512 * 1024
MAX_VALIDATION_BYTES = cs.MAX_VALIDATION_BYTES
EXIT = {"partial": 2, "invalid_input": 4, "unavailable": 5}
TRUST = "SEALED_LOCAL_SOURCE_AND_OPTIONAL_PRIVATE_HMAC_ONLY_NO_SEMANTIC_TEST_GIT_OR_ACTOR_PROOF"


class FindingError(st.StageError):
    pass


def _require(condition: bool, code: str, status: str = "invalid_input") -> None:
    if not condition:
        raise FindingError(code, status)


def _sha(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + st._canonical(value)).hexdigest()


def _text_sha(value: str | None) -> str | None:
    return None if value is None else hashlib.sha256(value.encode("utf-8")).hexdigest()


def _equal(left: Any, right: Any) -> bool:
    return type(left) is type(right) and st._canonical(left) == st._canonical(right)


def _deny(status: str, reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": status, "exit_code": EXIT[status],
        "reason_code": reason, "findings": [], "findings_count": 0,
        "projection_sha256": None, "source_binding": None, "coverage": None,
        "saved_metadata_link": None,
        "effects": {"findings_persisted": False, "ces_records_written": False,
                    "business_repository_written": False, "git_or_issue_written": False,
                    "source_code_or_tests_executed": False, "external_transfer": False},
        "trust_boundary": TRUST,
    }


def _anchor_view(anchor: dict[str, Any], *, disclose: bool) -> dict[str, Any]:
    """Never expose source_path, even with text grant: its digest is sufficient."""
    return {
        "segment_index": anchor["segment_index"],
        "segment_label_sha256": _sha(DOMAIN_LABEL, anchor["segment_label"]),
        "item_index": anchor["item_index"],
        "source_path_sha256": (None if anchor["source_path"] is None else
                               _sha(DOMAIN_PATH, anchor["source_path"])),
        "line_number_in_segment_or_item": anchor["line_number_in_segment_or_item"],
        "line_number_is_git_file_line": False,
        "anchor_sha256": anchor["anchor_sha256"],
        "evidence_origin": "EXACT_LINE_IN_EC173_SEALED_INPUT",
        "quote_sha256": _text_sha(anchor["quote"]),
        "quote": anchor["quote"] if disclose else None,
        "live_git_currentness_proven": False,
        "semantic_implication_proven": False,
    }


def _counter_annotations(raw: Any, *, findings: list[dict[str, Any]],
                         material: dict[str, Any]) -> dict[int, list[dict[str, Any]]]:
    if raw is None:
        return {}
    _require(type(raw) is list and len(raw) <= MAX_COUNTER_ROWS,
             "FINDING_COUNTER_EVIDENCE_LIMIT_OR_SHAPE")
    _require(len(st._canonical(raw)) <= MAX_ANNOTATION_BYTES,
             "FINDING_COUNTER_EVIDENCE_TOO_LARGE")
    collected: dict[int, list[dict[str, Any]]] = {}
    seen_anchors: set[tuple[int, str]] = set()
    for entry in raw:
        _require(type(entry) is dict and set(entry) == {"ordinal", "anchors", "interpretation"},
                 "FINDING_COUNTER_EVIDENCE_FIELDS")
        ordinal = entry["ordinal"]
        _require(type(ordinal) is int and 1 <= ordinal <= len(findings),
                 "FINDING_COUNTER_EVIDENCE_ORDINAL")
        anchors = entry["anchors"]
        _require(type(anchors) is list and 1 <= len(anchors) <= MAX_COUNTER_ANCHORS,
                 "FINDING_COUNTER_EVIDENCE_ANCHOR_LIMIT")
        interpretation = ar._bounded_text(entry["interpretation"], MAX_INTERPRETATION_CHARS,
                                          "FINDING_COUNTER_INTERPRETATION_UNSAFE")
        verified = [ar._anchor(a, material["segments"]) for a in anchors]
        _require(len({a["anchor_sha256"] for a in verified}) == len(verified),
                 "FINDING_COUNTER_DUPLICATE_ANCHOR")
        _require(len(collected.get(ordinal, [])) < MAX_COUNTER_ANCHORS,
                 "FINDING_COUNTER_PER_FINDING_LIMIT")
        for a in verified:
            ident = (ordinal, a["anchor_sha256"])
            _require(ident not in seen_anchors, "FINDING_COUNTER_DUPLICATE_ANCHOR")
            seen_anchors.add(ident)
        collected.setdefault(ordinal, []).append({
            "anchors": verified, "interpretation": interpretation,
            "annotation_sha256": _sha(DOMAIN_COUNTER, {
                "ordinal": ordinal, "anchors": [a["anchor_sha256"] for a in verified],
                "interpretation": interpretation,
            }),
        })
    return collected


def _review_state(row: dict[str, Any], attestation: dict[str, Any] | None) -> tuple[str, str]:
    state = row["review_state"]
    decisions = {
        "UNVERIFIED_SEMANTIC_ASSERTION": ("UNVERIFIED", "NO_MANUAL_ATTESTATION"),
        "VERIFIED_BY_PINNED_MANUAL_REVIEW_SIGNATURE":
            ("REVIEWED", "LOCAL_HMAC_KEY_HOLDER_CONFIRMED_CLAIM_NOT_TRUTH"),
        "REJECTED_BY_PINNED_MANUAL_REVIEW":
            ("REJECTED", "LOCAL_HMAC_KEY_HOLDER_REJECTED_CLAIM_NOT_OBJECTIVE_TEST"),
        "UNVERIFIED_REVIEW_INCONCLUSIVE":
            ("INCONCLUSIVE", "LOCAL_HMAC_KEY_HOLDER_INCONCLUSIVE_NOT_TEST"),
    }
    _require(type(state) is str and state in decisions,
             "FINDING_UNKNOWN_MANUAL_REVIEW_STATE", "unavailable")
    new, basis = decisions[state]
    _require((attestation is not None) == (new != "UNVERIFIED"),
             "FINDING_MANUAL_REVIEW_ATTESTATION_MISMATCH", "unavailable")
    return new, basis


class FindingProjector:
    """Read-only EC177 Finding builder. Explicit text and saved-link grants."""

    def __init__(self, stage_root: str, business_repo_root: str, *,
                 save_root: str | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.validator = cv.StagedCodeValidator(stage_root, business_repo_root, clock=clock)
        self.input = hi.HandoffInput(stage_root, business_repo_root, clock=clock)
        self.saver = (cs.StagedCodeSaver(stage_root, business_repo_root, save_root, clock=clock)
                      if save_root is not None else None)
        self.clock = clock

    def _link_saved(self, *, expected_save_store_pin: str, save_operation_key: str,
                    source_mode: str, original_receipt: str,
                    expected_parent_pin: str, input_operation_key: str,
                    validation_operation_key: str, fresh: dict[str, Any]) -> dict[str, Any]:
        _require(self.saver is not None, "FINDING_SAVED_LINK_REQUIRES_CONFIGURED_PRIVATE_STORE")
        result = self.saver.read_saved(
            expected_save_store_pin=expected_save_store_pin, save_operation_key=save_operation_key,
            authorize_read=True, read_content_for=source_mode)
        _require(result["status"] == "partial" and result.get("record") is not None,
                 "FINDING_PRIVATE_SAVED_RECORD_UNAVAILABLE_" + result["reason_code"], "unavailable")
        record = result["record"]  # Only from genuine EC176 private HMAC-verified read.
        attestation = fresh["manual_review"]
        rows = fresh["candidate"]["findings"]
        checks = [
            _equal(record["source_binding"], fresh["source_binding"]),
            record["validation_operation_id"] == cs._op_id(validation_operation_key),
            record["input_operation_id"] == cs._op_id(input_operation_key),
            record["stage_parent_pin_sha256"] == cs._sha(
                b"CES-EC176-STAGE-PIN-v1\x00", expected_parent_pin),
            record["candidate_sha256"] == fresh["candidate"]["candidate_sha256"],
            record["route_result_sha256"] == fresh["candidate"]["route_result_sha256"],
            record["draft_sha256"] == fresh["candidate"]["draft_sha256"],
            record["supplied_validation_receipt_sha256"] == original_receipt,
            record["source_coverage_sha256"] == cs._sha(
                b"CES-EC176-COVERAGE-v1\x00", fresh["coverage"]),
            record["coverage_complete_for_selected_source"] is
                fresh["coverage"]["complete_for_selected_source"],
            record["coverage_missing_requirements_count"] ==
                len(fresh["coverage"]["missing_requirements"]),
            record["source_observed_at_utc"] == st._stamp(hi._observed(
                fresh["source"]["source_observed_at_utc"])),
            record["historical_proposal_only"] is fresh["source"]["historical_proposal_only"],
            record["finding_sha256"] == [x["finding_sha256"] for x in rows],
            attestation is not None,
        ]
        if attestation is not None:
            checks.extend([
                record["manual_review_attestation_sha256"] == attestation["attestation_sha256"],
                record["manual_verifier_id"] == attestation["verifier_id"],
                record["manual_reviewed_at_utc"] == attestation["reviewed_at_utc"],
                record["manual_review_expires_at_utc"] == attestation["expires_at_utc"],
                all(r["review_state"] == "VERIFIED_BY_PINNED_MANUAL_REVIEW_SIGNATURE" for r in rows),
            ])
        _require(all(checks), "FINDING_SAVED_METADATA_SOURCE_REVIEW_OR_IDENTITY_MISMATCH",
                 "unavailable")
        local_now = st._now(self.clock)
        _require(st._parse_stamp(record["saved_at_utc"]) <=
                 local_now + timedelta(seconds=st.MAX_SKEW_SECONDS) and
                 local_now < st._parse_stamp(record["valid_until_utc"]),
                 "FINDING_SAVED_METADATA_EXPIRED_OR_CLOCK_ROLLBACK", "unavailable")
        return {
            "source": "EC176_GENUINE_PRIVATE_HMAC_METADATA_READ",
            "save_operation_id": record["save_operation_id"],
            "record_sha256": record["record_sha256"],
            "private_hmac_verified_this_call": True,
            "save_was_only_metadata": True,
            "finding_was_persisted": False,
            "semantic_truth_or_test_proven": False,
            "expires_at_utc": record["valid_until_utc"],
        }

    def project(self, prepared: dict[str, Any], route_result: dict[str, Any],
                validation_result: dict[str, Any], *, expected_parent_pin: str,
                run_id: str, handoff_id: str, expected_revision: int,
                expected_event_sha256: str, input_operation_key: str,
                validation_operation_key: str, finding_operation_key: str,
                expected_candidate_sha256: str, expected_validation_receipt_sha256: str,
                authorize_project: bool, authorize_read: bool, project_content_for: str,
                manual_review: dict[str, Any] | None = None,
                authorize_manual_review: bool = False,
                manual_review_content_for: str | None = None,
                trusted_verifier_id: str | None = None,
                trusted_verifier_key: bytes | None = None,
                counter_evidence: list[dict[str, Any]] | None = None,
                disclose_text: bool = False, authorize_text_disclosure: bool = False,
                disclose_content_for: str | None = None,
                expected_save_store_pin: str | None = None,
                save_operation_key: str | None = None,
                authorize_saved_link: bool = False,
                authorize_saved_record_read: bool = False,
                allow_historical_proposal: bool = False,
                acknowledge_historical_only: bool = False,
                max_source_age_seconds: int = 600) -> dict[str, Any]:
        """Produce only in-memory v1 records; never promote assertions to test truth.

        The original EC175 receipt is unkeyed and is *not* independent authority.
        Every invocation independently recomputes the full v1 source, route,
        draft, anchors, HMAC review and optional EC176 saved-record lineage.
        """
        try:
            _require(authorize_project is True, "FINDING_INDEPENDENT_PROJECTION_APPROVAL_REQUIRED")
            _require(authorize_read is True, "FINDING_SOURCE_READ_APPROVAL_REQUIRED")
            _require(type(project_content_for) is str and
                     project_content_for in lc.SOURCE_MODES,
                     "FINDING_EXACT_SOURCE_SCOPE_REQUIRED")
            _require(project_content_for != "ProposedPR" or
                     (allow_historical_proposal is True and acknowledge_historical_only is True),
                     "FINDING_HISTORICAL_ONLY_SEPARATE_ACKNOWLEDGMENT_REQUIRED")
            for key in (input_operation_key, validation_operation_key, finding_operation_key):
                lc._check_op(key)
            _require(len({input_operation_key, validation_operation_key,
                          finding_operation_key}) == 3,
                     "FINDING_PROJECTION_OPERATION_MUST_BE_INDEPENDENT")
            _require(type(expected_candidate_sha256) is str and
                     lc.SHA_RE.fullmatch(expected_candidate_sha256) is not None and
                     type(expected_validation_receipt_sha256) is str and
                     lc.SHA_RE.fullmatch(expected_validation_receipt_sha256) is not None,
                     "FINDING_SOURCE_AND_VALIDATION_PINS_REQUIRED")
            _require(type(disclose_text) is bool and
                     type(authorize_text_disclosure) is bool,
                     "FINDING_TEXT_PERMISSION_TYPE_INVALID")
            _require(not disclose_text or
                     (authorize_text_disclosure is True and
                      disclose_content_for == project_content_for),
                     "FINDING_EXPLICIT_SOURCE_SCOPED_TEXT_DISCLOSURE_REQUIRED")
            _require(authorize_text_disclosure is not True or
                     (disclose_text is True and disclose_content_for == project_content_for),
                     "FINDING_UNUSED_TEXT_GRANT_NOT_ACCEPTED")
            _require(type(authorize_saved_link) is bool and
                     type(authorize_saved_record_read) is bool,
                     "FINDING_SAVED_LINK_PERMISSION_TYPE_INVALID")
            linking = any(x is not None for x in
                          (expected_save_store_pin, save_operation_key)) or (
                              authorize_saved_link or authorize_saved_record_read)
            if linking:
                _require(authorize_saved_link is True and
                         authorize_saved_record_read is True and
                         self.saver is not None and
                         type(expected_save_store_pin) is str and
                         cs._digest(expected_save_store_pin) and
                         type(save_operation_key) is str,
                         "FINDING_INDEPENDENT_SAVED_LINK_AND_READ_GRANTS_REQUIRED")
                lc._check_op(save_operation_key)
                _require(save_operation_key not in
                         (input_operation_key, validation_operation_key, finding_operation_key),
                         "FINDING_SAVED_LINK_OPERATION_REUSED")
            validation_args = {
                "expected_parent_pin": expected_parent_pin, "run_id": run_id,
                "handoff_id": handoff_id, "expected_revision": expected_revision,
                "expected_event_sha256": expected_event_sha256,
                "input_operation_key": input_operation_key,
                "validation_operation_key": validation_operation_key,
                "authorize_validate": True, "authorize_read": True,
                "validate_content_for": project_content_for,
                "expected_candidate_sha256": expected_candidate_sha256,
                "manual_review": manual_review,
                "authorize_manual_review": authorize_manual_review,
                "manual_review_content_for": manual_review_content_for,
                "trusted_verifier_id": trusted_verifier_id,
                "trusted_verifier_key": trusted_verifier_key,
                "allow_historical_proposal": allow_historical_proposal,
                "max_source_age_seconds": max_source_age_seconds,
            }
            first = self.validator.validate(prepared, route_result, **validation_args)
            _require(first["status"] == "partial" and first["exit_code"] == 2,
                     "FINDING_FRESH_VALIDATION_REFUSED_" + first["reason_code"], "unavailable")
            cs.StagedCodeSaver._verify_original(
                validation_result, first, expected_validation_receipt_sha256, st._now(self.clock))
            # Retrieve source only after independent EC177 authorization, and
            # compare the sealed material binding to the EC175-reconstructed one.
            loaded = self.input.load_authorized(
                prepared, authorize_read=True, read_content_for=project_content_for,
                expected_parent_pin=expected_parent_pin, run_id=run_id,
                handoff_id=handoff_id, expected_revision=expected_revision,
                expected_event_sha256=expected_event_sha256,
                operation_key=input_operation_key,
                allow_historical_proposal=allow_historical_proposal,
                max_source_age_seconds=max_source_age_seconds,
            )
            _require(_equal(ar._binding(loaded["metadata"], loaded["material"],
                                       expected_event_sha256), first["source_binding"]),
                     "FINDING_EC173_SOURCE_BINDING_DRIFT", "unavailable")
            # Own a detached copy of the independently checked normalized
            # candidate: caller-owned dictionaries may change between passes.
            rows = json.loads(st._canonical(route_result["result"]["findings"]))
            annotations = _counter_annotations(counter_evidence, findings=rows,
                                               material=loaded["material"])
            link = None
            if linking:
                link = self._link_saved(
                    expected_save_store_pin=expected_save_store_pin,
                    save_operation_key=save_operation_key, source_mode=project_content_for,
                    original_receipt=expected_validation_receipt_sha256,
                    expected_parent_pin=expected_parent_pin,
                    input_operation_key=input_operation_key,
                    validation_operation_key=validation_operation_key, fresh=first)
            # Final independent pass AFTER annotations and optional HMAC store
            # read, so changed/expired source, review, grants, and anchors fail.
            second = self.validator.validate(prepared, route_result, **validation_args)
            _require(second["status"] == "partial" and second["exit_code"] == 2,
                     "FINDING_POSTFLIGHT_VALIDATION_REFUSED_" + second["reason_code"], "unavailable")
            cs.StagedCodeSaver._verify_original(
                validation_result, second, expected_validation_receipt_sha256, st._now(self.clock))
            for key in ("source_binding", "source", "coverage", "candidate",
                        "manual_review", "proof", "effects"):
                _require(_equal(first[key], second[key]),
                         "FINDING_SOURCE_OR_REVIEW_CHANGED_DURING_PROJECTION", "unavailable")
            _require(len(rows) == second["candidate"]["findings_count"] and
                     all(cv._sha(cv.DOMAIN_FINDING, raw) == checked["finding_sha256"]
                         for raw, checked in zip(rows, second["candidate"]["findings"])),
                     "FINDING_DETACHED_CANDIDATE_CHANGED_DURING_PROJECTION", "unavailable")
            if linking:
                _require(st._now(self.clock) < st._parse_stamp(link["expires_at_utc"]),
                         "FINDING_SAVED_METADATA_EXPIRED_DURING_PROJECTION", "unavailable")
            coverage = second["coverage"]
            _require(type(coverage["missing_requirements"]) is list and
                     len(coverage["missing_requirements"]) <= 1024,
                     "FINDING_MALFORMED_COVERAGE", "unavailable")
            published = []
            for raw, state_row in zip(rows, second["candidate"]["findings"]):
                finding_state, basis = _review_state(state_row, second["manual_review"])
                fid = _sha(DOMAIN_FINDING_ID, {
                    "source_binding": second["source_binding"],
                    "candidate_sha256": second["candidate"]["candidate_sha256"],
                    "finding_sha256": state_row["finding_sha256"], "ordinal": raw["ordinal"],
                })
                coun = annotations.get(raw["ordinal"], [])
                gaps = [
                    "MODEL_CLAIM_SEMANTICS_NOT_OBJECTIVELY_VERIFIED",
                    "CURRENT_LIVE_GIT_SOURCE_NOT_PROVEN",
                    "ACTUAL_TEST_OR_CI_EXECUTION_NOT_OBSERVED",
                    "REMOTE_PROVIDER_AND_REVIEWER_REAL_IDENTITY_NOT_AUTHENTICATED",
                    "COUNTER_EVIDENCE_COMPLETENESS_NOT_ESTABLISHED",
                ]
                if not coverage["complete_for_selected_source"]:
                    gaps.append("SELECTED_SOURCE_COVERAGE_INCOMPLETE")
                if second["source"]["historical_proposal_only"]:
                    gaps.append("HISTORICAL_PROPOSAL_NOT_CURRENT_DELIVERED_CODE")
                if finding_state == "INCONCLUSIVE":
                    gaps.append("PINNED_REVIEW_DECLARATION_INCONCLUSIVE")
                if finding_state == "REJECTED":
                    gaps.append("CLAIM_REJECTED_BY_PINNED_KEY_HOLDER")
                attestation = second["manual_review"]
                published.append({
                    "schema": FINDING_SCHEMA, "finding_id": fid,
                    "identity": {
                        "ordinal": raw["ordinal"],
                        "candidate_sha256": second["candidate"]["candidate_sha256"],
                        "original_finding_sha256": state_row["finding_sha256"],
                        "source_binding": second["source_binding"],
                        "identity_immutable_within_pinned_source": True,
                        "identity_does_not_prove_defect_or_cross_revision_equivalence": True,
                    },
                    "classification": {
                        "severity": {"value": raw["severity"],
                                     "origin": "UNAUTHENTICATED_MODEL_CLAIM_NOT_CALIBRATED"},
                        "confidence": {"value": raw["confidence_claim"],
                                       "origin": "UNAUTHENTICATED_MODEL_CLAIM_NOT_PROBABILITY"},
                    },
                    "assertion": {
                        "origin": "EC174_CALLBACK_MODEL_OR_CALLER_CLAIM_UNAUTHENTICATED",
                        "title_sha256": _text_sha(raw["title"]),
                        "analysis_sha256": _text_sha(raw["analysis"]),
                        "suggested_action_sha256": _text_sha(raw["suggested_action"]),
                        "title": raw["title"] if disclose_text else None,
                        "analysis": raw["analysis"] if disclose_text else None,
                        "suggested_action": raw["suggested_action"] if disclose_text else None,
                        "raw_text_disclosed_under_new_grant": disclose_text,
                    },
                    "evidence": {
                        "positive_anchors": [_anchor_view(a, disclose=disclose_text)
                                             for a in raw["anchors"]],
                        "counter_evidence": [
                            {
                                "annotation_sha256": item["annotation_sha256"],
                                "origin": "CALLER_ASSERTED_COUNTER_EVIDENCE_NOT_VERIFIED_CONTRADICTION",
                                "anchors": [_anchor_view(a, disclose=disclose_text)
                                            for a in item["anchors"]],
                                "interpretation_sha256": _text_sha(item["interpretation"]),
                                "interpretation": (item["interpretation"] if disclose_text else None),
                                "contradiction_semantically_proven": False,
                            } for item in coun
                        ],
                        "counter_evidence_exhaustive": False,
                        "source_line_observed_in_sealed_ec173_input": True,
                        "current_git_file_line_or_test_proven": False,
                    },
                    "assessment": {
                        "state": finding_state, "basis": basis,
                        "key_holder_review_attestation_sha256": (
                            attestation["attestation_sha256"] if attestation else None),
                        "review_verifier_id_sha256": (
                            _text_sha(attestation["verifier_id"]) if attestation else None),
                        "reviewer_real_identity_authenticated": False,
                        "semantically_confirmed_defect": False,
                        "actually_tested": False,
                        "possible_states": list(STATES),
                        "actually_tested_requires_independent_objective_execution_not_supported_in_ec177": True,
                    },
                    "coverage": {
                        "source_mode": project_content_for,
                        "source_quality": coverage["source_quality"],
                        "complete_for_selected_source": coverage["complete_for_selected_source"],
                        "missing_requirements_count": len(coverage["missing_requirements"]),
                        "missing_requirements_sha256": [
                            _text_sha(x) for x in coverage["missing_requirements"]],
                        "source_observed_at_utc": second["source"]["source_observed_at_utc"],
                        "historical_proposal_only": second["source"]["historical_proposal_only"],
                        "source_currentness_proven": False,
                    },
                    "uncertainty": gaps,
                    "saved_metadata_record_sha256": link["record_sha256"] if link else None,
                    "persistent_finding_created": False,
                })
            result = {
                "schema": SCHEMA, "status": "partial", "exit_code": 2,
                "reason_code": "FINDING_IN_MEMORY_ASSERTIONS_NOT_OBJECTIVELY_TESTED",
                "source_binding": second["source_binding"],
                "coverage": {
                    "complete_for_selected_source": coverage["complete_for_selected_source"],
                    "missing_requirements_count": len(coverage["missing_requirements"]),
                    "historical_proposal_only": second["source"]["historical_proposal_only"],
                    "source_currentness_proven": False,
                },
                "findings": published, "findings_count": len(published),
                "saved_metadata_link": link,
                "effects": {
                    "findings_persisted": False, "ces_records_written": False,
                    "business_repository_written": False, "git_or_issue_written": False,
                    "source_code_or_tests_executed": False, "external_transfer": False,
                },
                "trust_boundary": TRUST,
            }
            result["projection_sha256"] = _sha(DOMAIN_PROJECTION, result)
            _require(len(st._canonical(result)) <= MAX_OUTPUT_BYTES,
                     "FINDING_RESULT_SIZE_LIMIT")
            return result
        except (FindingError, cs.CodeSaveError, cv.ValidateError, hi.InputError,
                ar.RouteError, st.StageError, lc.LifecycleError) as exc:
            status = exc.status if exc.status in EXIT else "unavailable"
            return _deny(status, exc.code)
        except (OSError, ValueError, TypeError, KeyError, IndexError, OverflowError,
                RuntimeError, RecursionError, MemoryError):
            return _deny("unavailable", "FINDING_MALFORMED_OR_UNAVAILABLE_SOURCE_REFUSED")
