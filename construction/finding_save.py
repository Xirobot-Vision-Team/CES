#!/usr/bin/env python3
"""EC178 FindingSave: independently reproject EC177, then save sealed CES-only Findings.

One authorized operation atomically publishes one bounded batch containing explicitly
approved Finding IDs. This is a LOCAL provenance ledger for unverified model / reviewer
claims, NOT proof of a defect, human identity, CI run, live Git state, or Issues.

The store is distinct from business repo, EC172 staging, and optional EC176 store.
Only digest-based metadata, severity/confidence, source/review coverage and statuses
are persisted: no source path, source quote, model free text, review notes or secrets.
No operation writes to business code, .git, Providers, or Issues.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from typing import Any, Callable, Iterator

import finding_schema as fs
import handoff_input as hi
import handoff_lifecycle as lc
import task_staging as st

SCHEMA = "ces.finding_save_result.v1"
MANIFEST_SCHEMA = "ces.finding_save_manifest.v1"
RECORD_SCHEMA = "ces.finding_save_batch.v1"  # frozen EC178; readable indefinitely
RECORD_SCHEMA_V2 = "ces.finding_save_batch.v2"  # EC179 exact path digest index on new writes
FINDING_SCHEMA = "ces.finding_save_entry.v1"
ROOT_MANIFEST = "manifest.json"
ROOT_KEY = ".finding-key"
ROOT_LOCK = ".finding-lock"
ROOT_FILES = frozenset((ROOT_MANIFEST, ROOT_KEY, ROOT_LOCK))
DOMAIN_PIN = b"CES-EC178-FINDING-STORE-PIN-v1\x00"
DOMAIN_OPERATION = b"CES-EC178-FINDING-SAVE-OPERATION-v1\x00"
DOMAIN_RECORD = b"CES-EC178-FINDING-BATCH-RECORD-v1\x00"
DOMAIN_MAC = b"CES-EC178-FINDING-BATCH-HMAC-v1\x00"
DOMAIN_PAYLOAD = b"CES-EC178-FINDING-APPROVED-PAYLOAD-v1\x00"
DOMAIN_APPROVAL = b"CES-EC178-FINDING-APPROVAL-AUDIT-v1\x00"
DOMAIN_OPERATOR = b"CES-EC178-FINDING-OPERATOR-DECLARATION-v1\x00"
MAX_BATCHES = 128
MAX_TOTAL_FINDINGS = 512
MAX_RECORD_BYTES = 256 * 1024
MAX_PROJECT_KW_BYTES = 64 * 1024
MAX_TTL_SECONDS = 900
MIN_TTL_SECONDS = 60
FINDING_NAME = re.compile(r"finding_batch_[0-9]{6}_[0-9a-f]{64}\.json\Z")
PENDING_NAME = re.compile(r"\.pending-finding-[0-9a-f]{32}\Z")
OPERATOR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,95}\Z")
STATES = frozenset(fs.EMIT_STATES)
NEEDS_ACK = frozenset(("UNVERIFIED", "REJECTED", "INCONCLUSIVE"))
RESULT_STATUS = {"partial": 2, "invalid_input": 4, "unavailable": 5}
TRUST = "LOCAL_PRIVATE_HMAC_CES_FINDING_DECLARATION_NOT_DEFECT_HUMAN_CI_GIT_OR_ISSUE_PROOF"


class FindingSaveError(st.StageError):
    pass


def _require(ok: bool, reason: str, status: str = "invalid_input") -> None:
    if not ok:
        raise FindingSaveError(reason, status)


def _digest(v: Any) -> bool:
    return type(v) is str and st.HEX.fullmatch(v) is not None


def _sha(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + st._canonical(value)).hexdigest()


def _mac(key: bytes, value: dict[str, Any]) -> str:
    return hmac.new(key, DOMAIN_MAC + st._canonical(value), hashlib.sha256).hexdigest()


def _equal(a: Any, b: Any) -> bool:
    return type(a) is type(b) and st._canonical(a) == st._canonical(b)


def _strict(obj: Any, keys: set[str], code: str, status: str = "unavailable") -> dict[str, Any]:
    _require(type(obj) is dict and set(obj) == keys, code, status)
    return obj


def _op_id(key: str) -> str:
    return hashlib.sha256(DOMAIN_OPERATION + key.encode("utf-8")).hexdigest()


def _pin(manifest: dict[str, Any]) -> str:
    return _sha(DOMAIN_PIN, manifest)


def _refused(status: str, code: str, *, ambiguous: bool = False) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": status, "exit_code": RESULT_STATUS[status],
        "reason_code": code, "save_store_pin": None, "finding_save_operation_id": None,
        "batch_record_sha256": None, "saved_finding_ids": [], "saved_count": 0,
        "committed_at_utc": None, "expires_at_utc": None,
        "idempotent_reentry": False,
        "effects": {
            "ces_finding_commit_state": ("UNCERTAIN_MANUAL_REVIEW_REQUIRED" if ambiguous else "NONE"),
            "ces_finding_batch_committed": None if ambiguous else False,
            "finding_declarations_persisted": None if ambiguous else False,
            "source_or_model_text_persisted": False, "business_repository_written": False,
            "git_or_issue_written": False, "code_or_tests_executed": False,
            "external_transfer": False, "defect_semantically_verified": False,
        }, "trust_boundary": TRUST,
    }


def _accepted(record: dict[str, Any], pin: str, *, replay: bool) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": "partial", "exit_code": 2,
        "reason_code": ("FINDINGSAVE_IDEMPOTENT_REENTRY_NO_NEW_WRITE" if replay else
                        "FINDINGSAVE_SEALED_CES_DECLARATIONS_NOT_OBJECTIVE_PROOF"),
        "save_store_pin": pin, "finding_save_operation_id": record["finding_save_operation_id"],
        "batch_record_sha256": record["record_sha256"],
        "saved_finding_ids": [r["finding_id"] for r in record["findings"]],
        "saved_count": len(record["findings"]),
        "committed_at_utc": record["committed_at_utc"],
        "expires_at_utc": record["expires_at_utc"],
        "idempotent_reentry": replay,
        "stored": {
            "schema": record["schema"], "sequence": record["sequence"],
            "status_counts": {s: sum(r["assessment_state"] == s for r in record["findings"])
                              for s in fs.EMIT_STATES},
            "historical_proposal_only": record["historical_proposal_only"],
            "coverage_complete_for_selected_source": record["coverage"]["complete"],
            "payload_kind": "SOURCE_AND_MODEL_TEXT_FREE_SIGNED_LOCAL_FINDING_METADATA",
            "actual_tests_or_ci_proven": False, "defect_truth_proven": False,
        },
        "effects": {
            "ces_finding_commit_state": "COMMITTED_PRIOR" if replay else "COMMITTED_NEW",
            "ces_finding_batch_committed": True,
            "finding_declarations_persisted": True,
            "source_or_model_text_persisted": False,
            "business_repository_written": False, "git_or_issue_written": False,
            "code_or_tests_executed": False, "external_transfer": False,
            "defect_semantically_verified": False,
        }, "trust_boundary": TRUST,
    }


def _snapshot(item: dict[str, Any]) -> dict[str, Any]:
    """Exact allowlist; no string text/quote/interpretation/path gets persisted."""
    _require(item["schema"] == fs.FINDING_SCHEMA and
             item["assessment"]["state"] in STATES and
             item["persistent_finding_created"] is False and
             item["assessment"]["semantically_confirmed_defect"] is False and
             item["assessment"]["actually_tested"] is False and
             item["coverage"]["source_currentness_proven"] is False,
             "FINDINGSAVE_UNPROVEN_CLAIM_MUST_NOT_BE_ESCALATED", "unavailable")
    _require(item["assertion"]["raw_text_disclosed_under_new_grant"] is False and
             all(item["assertion"][k] is None for k in
                 ("title", "analysis", "suggested_action")),
             "FINDINGSAVE_TEXT_MUST_NOT_BE_DISCLOSED_TO_PERSISTENCE")
    ev = item["evidence"]
    _require(all(a["quote"] is None for a in ev["positive_anchors"]) and
             all(row["interpretation"] is None and
                 all(a["quote"] is None for a in row["anchors"])
                 for row in ev["counter_evidence"]),
             "FINDINGSAVE_RAW_SOURCE_OR_COUNTER_TEXT_NOT_ALLOWED")
    _require(len(ev["positive_anchors"]) <= 32 and len(ev["counter_evidence"]) <= 3,
             "FINDINGSAVE_EVIDENCE_BOUND_EXCEEDED", "unavailable")
    return {
        "schema": FINDING_SCHEMA,
        "finding_id": item["finding_id"],
        "ordinal": item["identity"]["ordinal"],
        "original_finding_sha256": item["identity"]["original_finding_sha256"],
        "severity": item["classification"]["severity"]["value"],
        "confidence_claim": item["classification"]["confidence"]["value"],
        "assessment_state": item["assessment"]["state"],
        "assessment_basis": item["assessment"]["basis"],
        "attestation_sha256": item["assessment"]["key_holder_review_attestation_sha256"],
        "verifier_label_sha256": item["assessment"]["review_verifier_id_sha256"],
        "title_sha256": item["assertion"]["title_sha256"],
        "analysis_sha256": item["assertion"]["analysis_sha256"],
        "suggested_action_sha256": item["assertion"]["suggested_action_sha256"],
        "positive_anchor_sha256": [x["anchor_sha256"] for x in ev["positive_anchors"]],
        "positive_quote_sha256": [x["quote_sha256"] for x in ev["positive_anchors"]],
        "counter_evidence": [{
            "annotation_sha256": c["annotation_sha256"],
            "interpretation_sha256": c["interpretation_sha256"],
            "anchor_sha256": [x["anchor_sha256"] for x in c["anchors"]],
        } for c in ev["counter_evidence"]],
        "uncertainty": item["uncertainty"],
        "semantic_truth_proven": False,
        "actual_test_or_ci_proven": False,
        "current_live_git_proven": False,
        "operator_authenticated": False,
    }


def _record_keys() -> set[str]:
    return {
        "schema", "store_id", "store_pin", "sequence", "previous_record_sha256",
        "finding_save_operation_id", "projection_operation_id", "input_operation_id",
        "validation_operation_id", "source_binding", "candidate_sha256",
        "validation_receipt_sha256", "projection_sha256", "projection_payload_sha256",
        "approved_payload_sha256", "authorization_audit", "source_observed_at_utc",
        "committed_at_utc", "expires_at_utc", "coverage", "historical_proposal_only",
        "saved_metadata_record_sha256", "findings", "verified_actual_ci_or_test",
        "defect_semantically_confirmed", "source_currentness_proven", "contains_raw_text",
        "business_repo_or_git_or_issue_modified", "record_sha256", "mac_sha256",
    }


def _path_index(chosen: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """EC179 write-time path index from the already twice-reverified EC177 anchors.

    Plain source paths are deliberately not persisted. Unpathable anchors are
    recorded as None, not reinterpreted as full coverage. The path SHA is the
    exact EC177 domain-separated source_path_sha256 (not a general path hash).
    """
    result = []
    for item in chosen:
        anchors = item["evidence"]["positive_anchors"]
        _require(type(anchors) is list and 1 <= len(anchors) <= 32,
                 "FINDINGSAVE_EC179_PATH_INDEX_ANCHORS_INVALID", "unavailable")
        path_digests = [a["source_path_sha256"] for a in anchors]
        _require(all(x is None or _digest(x) for x in path_digests),
                 "FINDINGSAVE_EC179_SOURCE_PATH_DIGEST_INVALID", "unavailable")
        result.append({
            "finding_id": item["finding_id"],
            "positive_anchor_path_sha256": path_digests,
            "path_index_complete": all(x is not None for x in path_digests),
        })
    return result


def _validate_path_index(obj: dict[str, Any]) -> None:
    """Sealed EC179 v2 index; legacy v1 is accepted without inferred paths."""
    if obj["schema"] == RECORD_SCHEMA:
        _require("path_index" not in obj,
                 "FINDINGSAVE_V1_MUST_NOT_CLAIM_PATH_INDEX")
        return
    rows = obj["path_index"]
    _require(type(rows) is list and len(rows) == len(obj["findings"]),
             "FINDINGSAVE_V2_PATH_INDEX_SIZE_INVALID")
    for row, finding in zip(rows, obj["findings"]):
        _strict(row, {"finding_id", "positive_anchor_path_sha256", "path_index_complete"},
                "FINDINGSAVE_V2_PATH_INDEX_FIELDS_INVALID")
        paths = row["positive_anchor_path_sha256"]
        _require(row["finding_id"] == finding["finding_id"] and
                 type(paths) is list and len(paths) == len(finding["positive_anchor_sha256"]) and
                 all(x is None or _digest(x) for x in paths) and
                 type(row["path_index_complete"]) is bool and
                 row["path_index_complete"] is all(x is not None for x in paths),
                 "FINDINGSAVE_V2_PATH_INDEX_BINDING_INVALID")


def _load_record(fd: int, filename: str, key: bytes,
                 manifest: dict[str, Any]) -> dict[str, Any]:
    obj = st._strict_stored(st._read_checked(fd, filename, MAX_RECORD_BYTES), MAX_RECORD_BYTES)
    _require(type(obj) is dict and obj.get("schema") in
             (RECORD_SCHEMA, RECORD_SCHEMA_V2),
             "FINDINGSAVE_STORED_RECORD_VERSION_INVALID")
    _strict(obj, _record_keys() | ({"path_index"} if obj["schema"] == RECORD_SCHEMA_V2 else set()),
            "FINDINGSAVE_STORED_FIELDS_OR_VERSION_INVALID")
    _require(obj["store_id"] == manifest["store_id"] and
             obj["store_pin"] == _pin(manifest) and
             type(obj["sequence"]) is int and 1 <= obj["sequence"] <= MAX_BATCHES and
             type(obj["finding_save_operation_id"]) is str and
             filename == f'finding_batch_{obj["sequence"]:06d}_{obj["finding_save_operation_id"]}.json',
             "FINDINGSAVE_STORED_DESTINATION_OR_SEQUENCE_INVALID")
    _require(_digest(obj["record_sha256"]) and _digest(obj["mac_sha256"]) and
             hmac.compare_digest(obj["record_sha256"], _sha(DOMAIN_RECORD, {
                 k: v for k, v in obj.items() if k not in ("record_sha256", "mac_sha256")
             })) and hmac.compare_digest(obj["mac_sha256"], _mac(key, {
                 k: v for k, v in obj.items() if k != "mac_sha256"
             })), "FINDINGSAVE_RECORD_HASH_OR_HMAC_INVALID")
    for k in ("finding_save_operation_id", "projection_operation_id", "input_operation_id",
              "validation_operation_id", "candidate_sha256", "validation_receipt_sha256",
              "projection_sha256", "projection_payload_sha256", "approved_payload_sha256"):
        _require(_digest(obj[k]), "FINDINGSAVE_STORED_PROOF_DIGEST_INVALID")
    _require(obj["previous_record_sha256"] is None or _digest(obj["previous_record_sha256"]),
             "FINDINGSAVE_STORED_PREVIOUS_LINK_INVALID")
    _strict(obj["source_binding"], {
        "run_id", "handoff_id", "stage_revision", "stage_event_sha256", "source_mode",
        "task_kind", "source_context_sha256", "source_identity_sha256", "evidence_hash", "material_sha256"
    }, "FINDINGSAVE_STORED_SOURCE_BINDING_INVALID")
    source = obj["source_binding"]
    _require(type(source["run_id"]) is str and lc.ID_RE.fullmatch(source["run_id"]) is not None and
             type(source["handoff_id"]) is str and lc.ID_RE.fullmatch(source["handoff_id"]) is not None and
             type(source["stage_revision"]) is int and 1 <= source["stage_revision"] <= lc.MAX_EVENTS and
             source["source_mode"] in lc.SOURCE_MODES and source["task_kind"] == "code_analysis" and
             all(_digest(source[k]) for k in ("stage_event_sha256", "source_context_sha256",
                                               "source_identity_sha256", "evidence_hash", "material_sha256")),
             "FINDINGSAVE_STORED_SOURCE_INVALID")
    _strict(obj["coverage"], {"complete", "missing_count", "source_quality"},
            "FINDINGSAVE_STORED_COVERAGE_INVALID")
    _require(type(obj["coverage"]["complete"]) is bool and
             type(obj["coverage"]["missing_count"]) is int and
             0 <= obj["coverage"]["missing_count"] <= 1024 and
             type(obj["coverage"]["source_quality"]) is str and
             len(obj["coverage"]["source_quality"]) <= 128 and
             type(obj["historical_proposal_only"]) is bool and
             obj["historical_proposal_only"] == (source["source_mode"] == "ProposedPR") and
             type(obj["findings"]) is list and 1 <= len(obj["findings"]) <= 32,
             "FINDINGSAVE_STORED_COVERAGE_OR_COUNT_INVALID")
    _strict(obj["authorization_audit"], {
        "declared_operator_label_sha256", "approval_set_sha256", "approved_count",
        "source_mode", "per_finding_grants_checked", "operator_identity_authenticated",
        "explicit_historical_ack", "explicit_partial_coverage_ack",
        "explicit_non_reviewed_ack", "grant_basis",
    }, "FINDINGSAVE_STORED_AUTH_AUDIT_INVALID")
    audit = obj["authorization_audit"]
    _require(_digest(audit["declared_operator_label_sha256"]) and
             _digest(audit["approval_set_sha256"]) and
             type(audit["approved_count"]) is int and
             audit["approved_count"] == len(obj["findings"]) and
             audit["source_mode"] == source["source_mode"] and
             audit["per_finding_grants_checked"] is True and
             audit["operator_identity_authenticated"] is False and
             audit["grant_basis"] == "EXPLICIT_CALLER_APPROVAL_NOT_AUTHENTICATED_ACTOR" and
             all(type(audit[k]) is bool for k in (
                 "explicit_historical_ack", "explicit_partial_coverage_ack",
                 "explicit_non_reviewed_ack")),
             "FINDINGSAVE_STORED_AUDIT_INCONSISTENT")
    ids = []
    for row in obj["findings"]:
        _strict(row, {
            "schema", "finding_id", "ordinal", "original_finding_sha256", "severity",
            "confidence_claim", "assessment_state", "assessment_basis", "attestation_sha256",
            "verifier_label_sha256", "title_sha256", "analysis_sha256",
            "suggested_action_sha256", "positive_anchor_sha256", "positive_quote_sha256",
            "counter_evidence", "uncertainty", "semantic_truth_proven", "actual_test_or_ci_proven",
            "current_live_git_proven", "operator_authenticated",
        }, "FINDINGSAVE_STORED_FINDING_FIELDS_INVALID")
        _require(row["schema"] == FINDING_SCHEMA and _digest(row["finding_id"]) and
                 type(row["ordinal"]) is int and 1 <= row["ordinal"] <= 32 and
                 _digest(row["original_finding_sha256"]) and
                 row["severity"] in ("info", "low", "medium", "high", "critical") and
                 row["confidence_claim"] in ("low", "medium", "high") and
                 row["assessment_state"] in STATES and
                 type(row["assessment_basis"]) is str and len(row["assessment_basis"]) <= 120 and
                 all(row[k] is False for k in (
                     "semantic_truth_proven", "actual_test_or_ci_proven",
                     "current_live_git_proven", "operator_authenticated")) and
                 all(_digest(row[k]) for k in (
                     "title_sha256", "analysis_sha256", "suggested_action_sha256")) and
                 (row["attestation_sha256"] is None or _digest(row["attestation_sha256"])) and
                 (row["verifier_label_sha256"] is None or _digest(row["verifier_label_sha256"])) and
                 type(row["positive_anchor_sha256"]) is list and
                 1 <= len(row["positive_anchor_sha256"]) <= 32 and
                 all(_digest(a) for a in row["positive_anchor_sha256"]) and
                 type(row["positive_quote_sha256"]) is list and
                 len(row["positive_quote_sha256"]) == len(row["positive_anchor_sha256"]) and
                 all(_digest(a) for a in row["positive_quote_sha256"]) and
                 type(row["counter_evidence"]) is list and len(row["counter_evidence"]) <= 3 and
                 type(row["uncertainty"]) is list and 1 <= len(row["uncertainty"]) <= 16 and
                 all(type(x) is str and 1 <= len(x) <= 128 for x in row["uncertainty"]),
                 "FINDINGSAVE_STORED_FINDING_CLAIM_INVALID")
        _require(hmac.compare_digest(row["finding_id"], fs._sha(fs.DOMAIN_FINDING_ID, {
                     "source_binding": source,
                     "candidate_sha256": obj["candidate_sha256"],
                     "finding_sha256": row["original_finding_sha256"],
                     "ordinal": row["ordinal"],
                 })), "FINDINGSAVE_STORED_FINDING_ID_DISCONNECTED_FROM_SOURCE")
        _require((row["attestation_sha256"] is None) ==
                 (row["assessment_state"] == "UNVERIFIED") and
                 (row["verifier_label_sha256"] is None) ==
                 (row["assessment_state"] == "UNVERIFIED"),
                 "FINDINGSAVE_STORED_REVIEW_STATUS_INVALID")
        for counter in row["counter_evidence"]:
            _strict(counter, {"annotation_sha256", "interpretation_sha256", "anchor_sha256"},
                    "FINDINGSAVE_STORED_COUNTER_FIELDS_INVALID")
            _require(_digest(counter["annotation_sha256"]) and
                     _digest(counter["interpretation_sha256"]) and
                     type(counter["anchor_sha256"]) is list and
                     1 <= len(counter["anchor_sha256"]) <= 3 and
                     all(_digest(a) for a in counter["anchor_sha256"]),
                     "FINDINGSAVE_STORED_COUNTER_INVALID")
        ids.append(row["finding_id"])
    _require(len(set(ids)) == len(ids) and
             len({row["ordinal"] for row in obj["findings"]}) == len(ids) and
             ids == sorted(ids) and
             _sha(DOMAIN_APPROVAL, ids) == audit["approval_set_sha256"] and
             all(row["assessment_state"] == "REVIEWED" or
                 audit["explicit_non_reviewed_ack"] for row in obj["findings"]),
             "FINDINGSAVE_STORED_APPROVAL_OR_STATUS_INVALID")
    _validate_path_index(obj)
    _require(type(obj["saved_metadata_record_sha256"]) in (str, type(None)) and
             (obj["saved_metadata_record_sha256"] is None or
              _digest(obj["saved_metadata_record_sha256"])) and
             all(obj[x] is False for x in (
                 "verified_actual_ci_or_test", "defect_semantically_confirmed",
                 "source_currentness_proven", "contains_raw_text",
                 "business_repo_or_git_or_issue_modified")),
             "FINDINGSAVE_STORED_FALSE_PROOF_OR_SAVED_LINK_INVALID")
    _require(type(obj["source_observed_at_utc"]) is str and
             type(obj["committed_at_utc"]) is str and type(obj["expires_at_utc"]) is str,
             "FINDINGSAVE_STORED_TIME_FIELDS_INVALID")
    observed, created, expiry = (st._parse_stamp(obj[x]) for x in (
        "source_observed_at_utc", "committed_at_utc", "expires_at_utc"))
    _require(observed <= created + timedelta(seconds=st.MAX_SKEW_SECONDS) and
             created < expiry <= created + timedelta(seconds=MAX_TTL_SECONDS),
             "FINDINGSAVE_STORED_TIME_CHAIN_INVALID")
    return obj


class FindingSaver:
    """Standalone EC178 CES-only immutable Finding ledger, not native CLI FindingSave."""

    def __init__(self, stage_root: str, business_repo_root: str, finding_store_root: str,
                 *, codesave_root: str | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        st._supported()
        for name, root in (("STAGE", stage_root), ("BUSINESS", business_repo_root),
                           ("STAGE", finding_store_root)):
            st._components(root, name)
        if codesave_root is not None:
            st._components(codesave_root, "STAGE")
        self.stage_root = stage_root
        self.business_repo_root = business_repo_root
        self.finding_store_root = finding_store_root
        self.codesave_root = codesave_root
        self.clock = clock
        self.projector = fs.FindingProjector(stage_root, business_repo_root,
                                              save_root=codesave_root, clock=clock)

    def _roots(self) -> list[tuple[str, str]]:
        roots = [(self.finding_store_root, "STAGE"), (self.stage_root, "STAGE"),
                 (self.business_repo_root, "BUSINESS")]
        if self.codesave_root is not None:
            roots.append((self.codesave_root, "STAGE"))
        return roots

    def _live_pins(self, expected: tuple[tuple[int, int], ...]) -> None:
        with ExitStack() as stack:
            opened = [stack.enter_context(st._open_directory(p, label))
                      for p, label in self._roots()]
            for i, (path, _) in enumerate(self._roots()):
                for j in range(i):
                    st._paths_separate(opened[i][1], opened[j][1], path, self._roots()[j][0])
            _require(tuple(st._identity(x[0]) for x in opened) == expected,
                     "FINDINGSAVE_STAGE_BUSINESS_OR_STORE_PIN_CHANGED", "unavailable")

    @contextmanager
    def _locked(self, *, initialized: bool = True) -> Iterator[tuple[int, dict[str, Any] | None, bytes | None, tuple[tuple[int, int], ...]]]:
        with ExitStack() as stack:
            opened = [stack.enter_context(st._open_directory(p, label))
                      for p, label in self._roots()]
            for i, (path, _) in enumerate(self._roots()):
                for j in range(i):
                    st._paths_separate(opened[i][1], opened[j][1], path, self._roots()[j][0])
            fd = opened[0][0]
            pins = tuple(st._identity(x[0]) for x in opened)
            try:
                st.fcntl.flock(fd, st.fcntl.LOCK_EX)
            except OSError as exc:
                raise FindingSaveError("FINDINGSAVE_STORE_LOCK_UNAVAILABLE", "unavailable") from exc
            try:
                self._live_pins(pins)
                if not initialized:
                    _require(not os.listdir(fd),
                             "FINDINGSAVE_INIT_REQUIRES_EMPTY_PRIVATE_STORE", "unavailable")
                    yield fd, None, None, pins
                else:
                    _require(ROOT_FILES.issubset(set(os.listdir(fd))),
                             "FINDINGSAVE_STORE_NOT_INITIALIZED", "unavailable")
                    key = st._read_checked(fd, ROOT_KEY, 32)
                    _require(len(key) == 32, "FINDINGSAVE_PRIVATE_KEY_INVALID", "unavailable")
                    manifest = st._strict_stored(st._read_checked(fd, ROOT_MANIFEST, 4096), 4096)
                    _require(st._read_checked(fd, ROOT_LOCK, 8) == b"",
                             "FINDINGSAVE_LOCK_SENTINEL_INVALID", "unavailable")
                    self._verify_manifest(manifest, key, pins)
                    yield fd, manifest, key, pins
            except OSError as exc:
                raise FindingSaveError("FINDINGSAVE_PRIVATE_STORAGE_UNAVAILABLE", "unavailable") from exc
            finally:
                st.fcntl.flock(fd, st.fcntl.LOCK_UN)

    def _manifest(self, fd: int, pins: tuple[tuple[int, int], ...], key: bytes) -> dict[str, Any]:
        paths = [x[0] for x in self._roots()]
        return {
            "schema": MANIFEST_SCHEMA, "store_id": "finding_v1_" + secrets.token_hex(16),
            "root_pins": [{"device": dev, "inode": ino,
                           "path_sha256": hashlib.sha256(os.fsencode(path)).hexdigest()}
                          for (dev, ino), path in zip(pins, paths)],
            "finding_root_uid": os.fstat(fd).st_uid,
            "key_sha256": hashlib.sha256(key).hexdigest(),
            "codesave_store_configured": self.codesave_root is not None,
        }

    def _verify_manifest(self, data: Any, key: bytes,
                         pins: tuple[tuple[int, int], ...]) -> None:
        _strict(data, {"schema", "store_id", "root_pins", "finding_root_uid",
                       "key_sha256", "codesave_store_configured"},
                "FINDINGSAVE_MANIFEST_FIELDS_INVALID")
        _require(data["schema"] == MANIFEST_SCHEMA and
                 type(data["store_id"]) is str and
                 re.fullmatch(r"finding_v1_[0-9a-f]{32}", data["store_id"]) is not None and
                 type(data["root_pins"]) is list and
                 len(data["root_pins"]) == len(pins) and
                 type(data["finding_root_uid"]) is int and
                 data["finding_root_uid"] == os.getuid() and
                 data["key_sha256"] == hashlib.sha256(key).hexdigest() and
                 data["codesave_store_configured"] is (self.codesave_root is not None),
                 "FINDINGSAVE_MANIFEST_STORE_ID_OR_KEY_CHANGED", "unavailable")
        for item, (dev, ino), (path, _) in zip(data["root_pins"], pins, self._roots()):
            _strict(item, {"device", "inode", "path_sha256"},
                    "FINDINGSAVE_MANIFEST_PIN_SHAPE_INVALID")
            _require(type(item["device"]) is int and type(item["inode"]) is int and
                     item["device"] == dev and item["inode"] == ino and
                     item["path_sha256"] == hashlib.sha256(os.fsencode(path)).hexdigest(),
                     "FINDINGSAVE_MANIFEST_PIN_MISMATCH", "unavailable")

    def initialize(self, *, approve_init: bool) -> dict[str, Any]:
        """Initialize an EXISTING, empty, owner-private separate CES directory."""
        _require(approve_init is True, "FINDINGSAVE_INDEPENDENT_INIT_APPROVAL_REQUIRED")
        with self._locked(initialized=False) as (fd, _, __, pins):
            key = secrets.token_bytes(32)
            manifest = self._manifest(fd, pins, key)
            created = []
            try:
                self._live_pins(pins)
                for name, raw in ((ROOT_KEY, key), (ROOT_LOCK, b""),
                                  (ROOT_MANIFEST, st._canonical(manifest) + b"\n")):
                    st._write_exclusive(fd, name, raw)
                    created.append(name)
                os.fsync(fd)
            except (OSError, st.StageError) as exc:
                try:
                    for name in reversed(created):
                        os.unlink(name, dir_fd=fd)
                    os.fsync(fd)
                except OSError:
                    raise FindingSaveError("FINDINGSAVE_INIT_DURABILITY_UNCERTAIN", "unavailable") from exc
                raise FindingSaveError("FINDINGSAVE_INIT_REJECTED_NO_STORE", "unavailable") from exc
            return {
                "schema": SCHEMA, "status": "success", "exit_code": 0,
                "reason_code": "FINDINGSAVE_PRIVATE_CES_STORE_INITIALIZED",
                "save_store_pin": _pin(manifest), "store_id": manifest["store_id"],
                "finding_declarations_persisted": False,
                "business_repository_written": False, "trust_boundary": TRUST,
            }

    def _all(self, fd: int, key: bytes, manifest: dict[str, Any]) -> list[dict[str, Any]]:
        names = os.listdir(fd)
        _require(len(names) <= len(ROOT_FILES) + MAX_BATCHES + 1,
                 "FINDINGSAVE_STORE_ENTRY_BOUND_EXCEEDED", "unavailable")
        records = []
        for name in names:
            if name in ROOT_FILES:
                continue
            if PENDING_NAME.fullmatch(name):
                raise FindingSaveError("FINDINGSAVE_UNFINISHED_PUBLISH_REQUIRES_MANUAL_REVIEW", "unavailable")
            _require(FINDING_NAME.fullmatch(name) is not None,
                     "FINDINGSAVE_UNKNOWN_STORE_ENTRY_REFUSED", "unavailable")
            records.append(name)
        _require(len(records) <= MAX_BATCHES,
                 "FINDINGSAVE_BATCH_LIMIT_EXCEEDED", "unavailable")
        try:
            result = [_load_record(fd, f, key, manifest) for f in sorted(records)]
        except FindingSaveError as exc:
            raise FindingSaveError(exc.code, "unavailable") from exc
        _require(sum(len(r["findings"]) for r in result) <= MAX_TOTAL_FINDINGS,
                 "FINDINGSAVE_TOTAL_FINDING_LIMIT_EXCEEDED", "unavailable")
        last = None
        all_ids: set[str] = set()
        all_ops: set[str] = set()
        for seq, record in enumerate(result, start=1):
            _require(record["sequence"] == seq and record["previous_record_sha256"] == last,
                     "FINDINGSAVE_IMMUTABLE_SEQUENCE_OR_PREVIOUS_HASH_BROKEN", "unavailable")
            _require(record["finding_save_operation_id"] not in all_ops and
                     not ({f["finding_id"] for f in record["findings"]} & all_ids),
                     "FINDINGSAVE_STORED_DUPLICATE_ID_OR_OPERATION", "unavailable")
            all_ops.add(record["finding_save_operation_id"])
            all_ids.update(f["finding_id"] for f in record["findings"])
            last = record["record_sha256"]
        return result

    @staticmethod
    def _project(projection_kwargs: dict[str, Any], projector: fs.FindingProjector,
                 prepared: dict[str, Any], route_result: dict[str, Any],
                 validation_result: dict[str, Any]) -> dict[str, Any]:
        result = projector.project(prepared, route_result, validation_result, **projection_kwargs)
        _require(result["status"] == "partial" and result["exit_code"] == 2 and
                 result["effects"]["findings_persisted"] is False and
                 result["effects"]["ces_records_written"] is False,
                 "FINDINGSAVE_INDEPENDENT_EC177_REPROJECT_FAILED_" + result["reason_code"],
                 "unavailable")
        return result

    @staticmethod
    def _approve(projection: dict[str, Any], approved_ids: list[str], *,
                 allow_non_reviewed: bool, acknowledge_non_reviewed: bool,
                 acknowledge_partial_coverage: bool,
                 approve_historical_proposal_save: bool) -> list[dict[str, Any]]:
        _require(type(projection["findings_count"]) is int and
                 1 <= projection["findings_count"] <= 32 and
                 len(projection["findings"]) == projection["findings_count"],
                 "FINDINGSAVE_NO_SUPPORTED_FINDINGS_TO_SAVE")
        listed = {f["finding_id"]: f for f in projection["findings"]}
        _require(type(approved_ids) is list and 1 <= len(approved_ids) <= 32 and
                 all(_digest(x) for x in approved_ids) and
                 len(set(approved_ids)) == len(approved_ids) and
                 set(approved_ids).issubset(listed),
                 "FINDINGSAVE_EXACT_PER_FINDING_APPROVAL_IDS_REQUIRED")
        _require(type(allow_non_reviewed) is bool and type(acknowledge_non_reviewed) is bool and
                 type(acknowledge_partial_coverage) is bool and
                 type(approve_historical_proposal_save) is bool,
                 "FINDINGSAVE_SCOPE_APPROVAL_TYPE_INVALID")
        _require(projection["coverage"]["complete_for_selected_source"] is True or
                 acknowledge_partial_coverage is True,
                 "FINDINGSAVE_INCOMPLETE_SOURCE_REQUIRES_SEPARATE_ACKNOWLEDGMENT")
        _require(projection["coverage"]["historical_proposal_only"] is False or
                 approve_historical_proposal_save is True,
                 "FINDINGSAVE_HISTORICAL_PROPOSAL_REQUIRES_NEW_SAVE_APPROVAL")
        selected = [listed[id_] for id_ in sorted(approved_ids)]
        _require(all(f["assessment"]["state"] == "REVIEWED" for f in selected) or
                 (allow_non_reviewed is True and acknowledge_non_reviewed is True),
                 "FINDINGSAVE_UNREVIEWED_REJECTED_OR_INCONCLUSIVE_REQUIRES_EXPLICIT_ACK")
        _require(all(f["assessment"]["state"] in STATES and
                     f["assessment"]["state"] != "ACTUALLY_TESTED" for f in selected),
                 "FINDINGSAVE_UNSUPPORTED_SEMANTIC_STATE")
        return selected

    def save(self, prepared: dict[str, Any], route_result: dict[str, Any],
             validation_result: dict[str, Any], *, expected_finding_store_pin: str,
             finding_save_operation_key: str, authorized_finding_ids: list[str],
             authorize_save: bool, authorize_source_read: bool, save_content_for: str,
             projection_kwargs: dict[str, Any], operator_label: str,
             expected_projection_sha256: str | None = None,
             allow_non_reviewed: bool = False, acknowledge_non_reviewed: bool = False,
             acknowledge_partial_coverage: bool = False,
             approve_historical_proposal_save: bool = False,
             ttl_seconds: int = 300) -> dict[str, Any]:
        """Actual CES-private FindingSave, no authority from caller projection/receipt.

        Every invocation independently reconstructs EC177 twice, once under the
        immutable store's write lock, and verifies the original EC175 source and
        signed review chain within each EC177 pass (twice per projection).
        """
        try:
            _require(authorize_save is True and authorize_source_read is True,
                     "FINDINGSAVE_SEPARATE_SAVE_AND_SOURCE_READ_APPROVAL_REQUIRED")
            _require(type(save_content_for) is str and save_content_for in lc.SOURCE_MODES,
                     "FINDINGSAVE_SOURCE_SCOPE_INVALID")
            _require(_digest(expected_finding_store_pin),
                     "FINDINGSAVE_NEW_STORE_TARGET_PIN_REQUIRED")
            lc._check_op(finding_save_operation_key)
            _require(type(projection_kwargs) is dict and
                     len(st._canonical({k: v for k, v in projection_kwargs.items()
                                        if k != "trusted_verifier_key"})) <= MAX_PROJECT_KW_BYTES,
                     "FINDINGSAVE_EC177_PROJECTION_ARGUMENTS_INVALID")
            _require(projection_kwargs.get("authorize_project") is True and
                     projection_kwargs.get("authorize_read") is True and
                     projection_kwargs.get("project_content_for") == save_content_for and
                     projection_kwargs.get("disclose_text", False) is False and
                     projection_kwargs.get("authorize_text_disclosure", False) is False,
                     "FINDINGSAVE_FRESH_READ_SCOPED_METADATA_ONLY_PROJECTION_REQUIRED")
            _require(type(operator_label) is str and OPERATOR_RE.fullmatch(operator_label) is not None,
                     "FINDINGSAVE_OPERATOR_DECLARATION_LABEL_INVALID")
            _require(type(ttl_seconds) is int and MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS,
                     "FINDINGSAVE_TTL_RANGE_INVALID")
            _require(expected_projection_sha256 is None or _digest(expected_projection_sha256),
                     "FINDINGSAVE_OPTIONAL_UNKEYED_PROJECTION_PIN_INVALID")
            old_keys = [projection_kwargs.get(k) for k in (
                "input_operation_key", "validation_operation_key", "finding_operation_key",
                "save_operation_key") if projection_kwargs.get(k) is not None]
            _require(all(type(k) is str for k in old_keys),
                     "FINDINGSAVE_OPERATION_KEYS_INVALID")
            for k in old_keys:
                lc._check_op(k)
            _require(finding_save_operation_key not in old_keys and
                     len(set(old_keys)) == len(old_keys),
                     "FINDINGSAVE_OPERATION_REUSES_UPSTREAM_AUTHORITY")
            # Do not allow extra grants to be inferred from the previous projection
            # or a copied unkeyed projection_sha256. The source itself is reopened.
            first = self._project(projection_kwargs, self.projector,
                                  prepared, route_result, validation_result)
            _require(expected_projection_sha256 is None or
                     hmac.compare_digest(first["projection_sha256"], expected_projection_sha256),
                     "FINDINGSAVE_UNKEYED_PROJECTION_PIN_DIFFERS_FROM_REAL_SOURCE", "unavailable")
            selected = self._approve(first, authorized_finding_ids,
                                     allow_non_reviewed=allow_non_reviewed,
                                     acknowledge_non_reviewed=acknowledge_non_reviewed,
                                     acknowledge_partial_coverage=acknowledge_partial_coverage,
                                     approve_historical_proposal_save=approve_historical_proposal_save)
            with self._locked() as (fd, manifest, key, pins):
                assert manifest is not None and key is not None
                store_pin = _pin(manifest)
                _require(hmac.compare_digest(expected_finding_store_pin, store_pin),
                         "FINDINGSAVE_STORE_TARGET_OR_ROOT_PIN_CHANGED", "unavailable")
                records = self._all(fd, key, manifest)
                second = self._project(projection_kwargs, self.projector,
                                       prepared, route_result, validation_result)
                _require(_equal(first, second),
                         "FINDINGSAVE_SEALED_SOURCE_REVIEW_OR_COUNTERS_CHANGED_IN_FLIGHT", "unavailable")
                chosen = self._approve(second, authorized_finding_ids,
                                       allow_non_reviewed=allow_non_reviewed,
                                       acknowledge_non_reviewed=acknowledge_non_reviewed,
                                       acknowledge_partial_coverage=acknowledge_partial_coverage,
                                       approve_historical_proposal_save=approve_historical_proposal_save)
                _require([x["finding_id"] for x in selected] ==
                         [x["finding_id"] for x in chosen],
                         "FINDINGSAVE_APPROVED_FINDING_SELECTION_DRIFT", "unavailable")
                now = st._now(self.clock)
                # Current EC175 prior receipt, EC173 time window, optional EC175
                # signed review, and optionally HMAC-verified EC176 saved metadata.
                limits = [now + timedelta(seconds=ttl_seconds),
                          st._parse_stamp(validation_result["expires_at_utc"]),
                          hi._observed(second["findings"][0]["coverage"]["source_observed_at_utc"]) +
                          timedelta(seconds=projection_kwargs.get("max_source_age_seconds", 600))]
                manual = second["findings"][0]["assessment"]
                if manual["key_holder_review_attestation_sha256"] is not None:
                    limits.append(st._parse_stamp(projection_kwargs["manual_review"]["expires_at_utc"]))
                if second["saved_metadata_link"] is not None:
                    limits.append(st._parse_stamp(second["saved_metadata_link"]["expires_at_utc"]))
                expiry = min(limits)
                _require(expiry > now, "FINDINGSAVE_REVALIDATED_EVIDENCE_ALREADY_EXPIRED", "unavailable")
                snapshots = [_snapshot(x) for x in chosen]
                approved_ids = [x["finding_id"] for x in chosen]
                _require(approved_ids == sorted(approved_ids),
                         "FINDINGSAVE_APPROVALS_NOT_CANONICALLY_ORDERED", "unavailable")
                approval = {
                    "declared_operator_label_sha256": _sha(DOMAIN_OPERATOR, operator_label),
                    "approval_set_sha256": _sha(DOMAIN_APPROVAL, approved_ids),
                    "approved_count": len(approved_ids),
                    "source_mode": save_content_for,
                    "per_finding_grants_checked": True,
                    "operator_identity_authenticated": False,
                    "explicit_historical_ack": approve_historical_proposal_save,
                    "explicit_partial_coverage_ack": acknowledge_partial_coverage,
                    "explicit_non_reviewed_ack": allow_non_reviewed and acknowledge_non_reviewed,
                    "grant_basis": "EXPLICIT_CALLER_APPROVAL_NOT_AUTHENTICATED_ACTOR",
                }
                payload = {
                    "projection_sha256": second["projection_sha256"],
                    "source_binding": second["source_binding"],
                    "candidate_sha256": chosen[0]["identity"]["candidate_sha256"],
                    "approved_findings": snapshots,
                    "authorization_audit": approval,
                    "validation_receipt_sha256": validation_result["validation_receipt_sha256"],
                    "saved_metadata_record_sha256": (
                        second["saved_metadata_link"]["record_sha256"]
                        if second["saved_metadata_link"] else None),
                }
                operation_id = _op_id(finding_save_operation_key)
                new_content_digest = _sha(DOMAIN_PAYLOAD, payload)
                for prior in records:
                    if prior["finding_save_operation_id"] == operation_id:
                        _require(prior["approved_payload_sha256"] == new_content_digest and
                                 prior["findings"] == snapshots and
                                 prior["authorization_audit"] == approval and
                                 prior["source_binding"] == second["source_binding"] and
                                 prior["projection_sha256"] == second["projection_sha256"] and
                                 st._parse_stamp(prior["expires_at_utc"]) <= expiry,
                                 "FINDINGSAVE_SAME_OPERATION_DIFFERENT_SOURCE_GRANTS_OR_FINDINGS")
                        _require(now + timedelta(seconds=st.MAX_SKEW_SECONDS) >=
                                 st._parse_stamp(prior["committed_at_utc"]),
                                 "FINDINGSAVE_CLOCK_ROLLBACK_BLOCKED", "unavailable")
                        _require(now < st._parse_stamp(prior["expires_at_utc"]),
                                 "FINDINGSAVE_EXPIRED_RECORD_CANNOT_BE_REVIVED", "unavailable")
                        return _accepted(prior, store_pin, replay=True)
                    _require(not ({f["finding_id"] for f in prior["findings"]} & set(approved_ids)),
                             "FINDINGSAVE_DUPLICATE_FINDING_DIFFERENT_OPERATION_REFUSED")
                _require(len(records) < MAX_BATCHES and
                         sum(len(r["findings"]) for r in records) + len(snapshots) <= MAX_TOTAL_FINDINGS,
                         "FINDINGSAVE_PRIVATE_LEDGER_CAPACITY_EXHAUSTED", "unavailable")
                record = {
                    "schema": RECORD_SCHEMA_V2, "store_id": manifest["store_id"],
                    "store_pin": store_pin, "sequence": len(records) + 1,
                    "previous_record_sha256": records[-1]["record_sha256"] if records else None,
                    "finding_save_operation_id": operation_id,
                    "projection_operation_id": _sha(DOMAIN_OPERATION,
                                                     projection_kwargs["finding_operation_key"]),
                    "input_operation_id": _sha(DOMAIN_OPERATION,
                                               projection_kwargs["input_operation_key"]),
                    "validation_operation_id": _sha(DOMAIN_OPERATION,
                                                    projection_kwargs["validation_operation_key"]),
                    "source_binding": second["source_binding"],
                    "candidate_sha256": chosen[0]["identity"]["candidate_sha256"],
                    "validation_receipt_sha256": validation_result["validation_receipt_sha256"],
                    "projection_sha256": second["projection_sha256"],
                    "projection_payload_sha256": _sha(DOMAIN_PAYLOAD, {
                        "all_projected_finding_ids": [r["finding_id"] for r in second["findings"]],
                        "coverage": second["coverage"],
                    }),
                    "approved_payload_sha256": new_content_digest,
                    "authorization_audit": approval,
                    "source_observed_at_utc": st._stamp(hi._observed(
                        chosen[0]["coverage"]["source_observed_at_utc"])),
                    "committed_at_utc": st._stamp(now), "expires_at_utc": st._stamp(expiry),
                    "coverage": {
                        "complete": chosen[0]["coverage"]["complete_for_selected_source"],
                        "missing_count": chosen[0]["coverage"]["missing_requirements_count"],
                        "source_quality": chosen[0]["coverage"]["source_quality"],
                    },
                    "historical_proposal_only": chosen[0]["coverage"]["historical_proposal_only"],
                    "saved_metadata_record_sha256": payload["saved_metadata_record_sha256"],
                    "findings": snapshots,
                    "path_index": _path_index(chosen),
                    "verified_actual_ci_or_test": False,
                    "defect_semantically_confirmed": False, "source_currentness_proven": False,
                    "contains_raw_text": False, "business_repo_or_git_or_issue_modified": False,
                }
                record["record_sha256"] = _sha(DOMAIN_RECORD, record)
                self._live_pins(pins)
                _require(st._now(self.clock) < expiry,
                         "FINDINGSAVE_EVIDENCE_EXPIRED_BEFORE_PUBLISH", "unavailable")
                return self._publish(fd, manifest, key, pins, record)
        except (FindingSaveError, fs.FindingError, st.StageError, lc.LifecycleError) as exc:
            status = exc.status if exc.status in RESULT_STATUS else "unavailable"
            return _refused(status, exc.code,
                            ambiguous=exc.code == "FINDINGSAVE_PUBLISH_DURABILITY_UNCERTAIN")
        except (OSError, ValueError, TypeError, KeyError, IndexError, OverflowError,
                RuntimeError, RecursionError, MemoryError):
            return _refused("unavailable", "FINDINGSAVE_UNTRUSTED_INPUT_OR_STORAGE_UNAVAILABLE")

    def _publish(self, fd: int, manifest: dict[str, Any], key: bytes,
                 pins: tuple[tuple[int, int], ...], record: dict[str, Any]) -> dict[str, Any]:
        record["mac_sha256"] = _mac(key, record)
        payload = st._canonical(record) + b"\n"
        _require(len(payload) <= MAX_RECORD_BYTES, "FINDINGSAVE_RECORD_TOO_LARGE")
        target = f'finding_batch_{record["sequence"]:06d}_{record["finding_save_operation_id"]}.json'
        pending = ".pending-finding-" + secrets.token_hex(16)
        pending_exists = linked = False
        try:
            st._write_exclusive(fd, pending, payload)  # new O_EXCL file + file fsync
            pending_exists = True
            self._live_pins(pins)
            os.link(pending, target, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            linked = True  # never replace a committed record
            os.fsync(fd)
            os.unlink(pending, dir_fd=fd)
            pending_exists = False
            os.fsync(fd)
        except (OSError, st.StageError, FindingSaveError) as exc:
            if linked:
                raise FindingSaveError("FINDINGSAVE_PUBLISH_DURABILITY_UNCERTAIN", "unavailable") from exc
            if pending_exists:
                try:
                    os.unlink(pending, dir_fd=fd)
                    os.fsync(fd)
                except OSError:
                    raise FindingSaveError("FINDINGSAVE_PUBLISH_DURABILITY_UNCERTAIN", "unavailable") from exc
            raise FindingSaveError("FINDINGSAVE_PUBLISH_FAILED_NO_RECORDED_COMMIT", "unavailable") from exc
        return _accepted(record, _pin(manifest), replay=False)

    def inspect(self, *, expected_finding_store_pin: str,
                authorize_inspect: bool) -> dict[str, Any]:
        """Local aggregate-only management; EC179 FindingShow intentionally absent."""
        try:
            _require(authorize_inspect is True, "FINDINGSAVE_INSPECT_REQUIRES_SEPARATE_GRANT")
            _require(_digest(expected_finding_store_pin), "FINDINGSAVE_INSPECT_STORE_PIN_REQUIRED")
            with self._locked() as (fd, manifest, key, _):
                assert manifest is not None and key is not None
                _require(hmac.compare_digest(expected_finding_store_pin, _pin(manifest)),
                         "FINDINGSAVE_INSPECT_STORE_PIN_CHANGED", "unavailable")
                records = self._all(fd, key, manifest)
                now = st._now(self.clock)
                _require(all(now + timedelta(seconds=st.MAX_SKEW_SECONDS) >=
                             st._parse_stamp(r["committed_at_utc"]) for r in records),
                         "FINDINGSAVE_INSPECT_CLOCK_ROLLBACK", "unavailable")
                return {
                    "schema": SCHEMA, "status": "success", "exit_code": 0,
                    "reason_code": "FINDINGSAVE_PRIVATE_LEDGER_AGGREGATE_INSPECTED",
                    "save_store_pin": _pin(manifest), "batch_count": len(records),
                    "finding_declarations_count": sum(len(r["findings"]) for r in records),
                    "expired_batch_count": sum(now >= st._parse_stamp(r["expires_at_utc"])
                                               for r in records),
                    "capacity_batches": MAX_BATCHES, "capacity_findings": MAX_TOTAL_FINDINGS,
                    "business_repository_written": False, "trust_boundary": TRUST,
                }
        except (FindingSaveError, st.StageError, lc.LifecycleError) as exc:
            status = exc.status if exc.status in RESULT_STATUS else "unavailable"
            return _refused(status, exc.code)
        except (OSError, ValueError, TypeError, KeyError, IndexError, RuntimeError):
            return _refused("unavailable", "FINDINGSAVE_INSPECT_UNAVAILABLE")


def main(argv: list[str] | None = None) -> int:
    """Operator CLI only initializes/inspects; never passes secrets/model text on argv."""
    parser = argparse.ArgumentParser(description="EC178 CES-private FindingSave store management")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--init", action="store_true")
    modes.add_argument("--inspect", action="store_true")
    parser.add_argument("--stage-root", required=True)
    parser.add_argument("--business-repo-root", required=True)
    parser.add_argument("--finding-store-root", required=True)
    parser.add_argument("--codesave-root")
    parser.add_argument("--approve-init", action="store_true")
    parser.add_argument("--authorize-inspect", action="store_true")
    parser.add_argument("--finding-store-pin")
    opts = parser.parse_args(argv)
    try:
        saver = FindingSaver(opts.stage_root, opts.business_repo_root,
                             opts.finding_store_root, codesave_root=opts.codesave_root)
        if opts.init:
            result = saver.initialize(approve_init=opts.approve_init)
        else:
            result = saver.inspect(expected_finding_store_pin=opts.finding_store_pin,
                                   authorize_inspect=opts.authorize_inspect)
    except (FindingSaveError, st.StageError, lc.LifecycleError) as exc:
        result = _refused(exc.status if exc.status in RESULT_STATUS else "unavailable", exc.code)
    except (OSError, TypeError, ValueError):
        result = _refused("unavailable", "FINDINGSAVE_CLI_INVALID_OR_UNAVAILABLE")
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, allow_nan=False))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
