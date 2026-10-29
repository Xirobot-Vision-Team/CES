#!/usr/bin/env python3
"""EC179 FindingShow: scoped, read-only queries of the *real* EC178 HMAC store.

No caller-supplied receipt, projection, unsworn JSON, path string, or guessed
batch file is accepted as evidence or authority. Every query opens the actual
private store under its existing lock and validates all immutable batches via
EC178's signed, source-bound loader before looking at individual declarations.

One caller-granted *exact source binding* is the mandatory read partition.
A stateless HMAC continuation is a short-lived pagination hint, never an
authorization token or evidence of current Git/CI/semantic truth.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta
import hashlib
import hmac
import re
from typing import Any, Callable

import finding_save as save
import handoff_lifecycle as lc
import task_staging as st

SCHEMA = "ces.finding_show_result.v1"
CURSOR_SCHEMA = "ces.finding_show_cursor.v1"
DOMAIN_QUERY = b"CES-EC179-FINDING-SHOW-QUERY-v1\x00"
DOMAIN_REVISION = b"CES-EC179-FINDING-SHOW-STORE-REVISION-v1\x00"
DOMAIN_CURSOR = b"CES-EC179-FINDING-SHOW-CURSOR-HMAC-v1\x00"
MAX_PAGE_SIZE = 25
DEFAULT_PAGE_SIZE = 10
MAX_CURSOR_AGE_SECONDS = 300
MAX_CURSOR_BYTES = 4096
MAX_RESULTS = save.MAX_TOTAL_FINDINGS
TRUST = "EC178_PRIVATE_HMAC_FINDING_DECLARATION_NOT_SEMANTIC_HUMAN_CI_CURRENT_GIT_OR_ISSUE_PROOF"
SOURCE_KEYS = frozenset({
    "run_id", "handoff_id", "stage_revision", "stage_event_sha256", "source_mode",
    "task_kind", "source_context_sha256", "source_identity_sha256", "evidence_hash",
    "material_sha256",
})
SOURCE_FILTERS = frozenset({
    "run_id", "handoff_id", "stage_revision", "stage_event_sha256",
    "source_context_sha256", "source_identity_sha256", "evidence_hash",
    "material_sha256",
})
ROW_FILTERS = frozenset({"finding_id", "severity", "assessment_state", "confidence_claim"})
BATCH_FILTERS = frozenset({"candidate_sha256", "historical_proposal_only", "coverage_complete"})
PATH_FILTER = "path_identity_sha256"
FILTERS = SOURCE_FILTERS | ROW_FILTERS | BATCH_FILTERS | {PATH_FILTER}
DIGEST_FILTERS = frozenset({
    "stage_event_sha256", "source_context_sha256", "source_identity_sha256",
    "evidence_hash", "material_sha256", "finding_id", "candidate_sha256",
    PATH_FILTER,
})
BOOL_FILTERS = frozenset({"historical_proposal_only", "coverage_complete"})
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,3900}\.[0-9a-f]{64}\Z")


class FindingShowError(save.FindingSaveError):
    pass


def _require(ok: bool, reason: str, status: str = "invalid_input") -> None:
    if not ok:
        raise FindingShowError(reason, status)


def _sha(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + st._canonical(value)).hexdigest()


def _effects() -> dict[str, bool]:
    return {
        "ces_records_written": False, "business_repository_written": False,
        "git_or_issue_written": False, "source_code_or_tests_executed": False,
        "external_transfer": False, "plaintext_source_or_model_released": False,
        "defect_semantically_verified": False, "current_git_verified": False,
        "ci_or_actual_test_verified": False, "human_identity_authenticated": False,
    }


def _refused(status: str, reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": status, "exit_code": {"invalid_input": 4, "unavailable": 5}[status],
        "reason_code": reason, "save_store_pin": None, "scope": None,
        "query_sha256": None, "revision_sha256": None, "matched_count": 0,
        "returned_count": 0, "findings": [], "next_cursor": None,
        "cursor_expires_at_utc": None, "path_index": None,
        "effects": _effects(), "trust_boundary": TRUST,
    }


def _binding(scope: Any, mode: str) -> dict[str, Any]:
    _require(type(scope) is dict and set(scope) == SOURCE_KEYS,
             "FINDINGSHOW_EXACT_SOURCE_BINDING_SCOPE_REQUIRED")
    _require(scope["source_mode"] == mode and mode in lc.SOURCE_MODES and
             scope["task_kind"] == "code_analysis" and
             type(scope["run_id"]) is str and lc.ID_RE.fullmatch(scope["run_id"]) is not None and
             type(scope["handoff_id"]) is str and lc.ID_RE.fullmatch(scope["handoff_id"]) is not None and
             type(scope["stage_revision"]) is int and
             1 <= scope["stage_revision"] <= lc.MAX_EVENTS and
             all(save._digest(scope[k]) for k in SOURCE_KEYS - {
                 "run_id", "handoff_id", "stage_revision", "source_mode", "task_kind"
             }), "FINDINGSHOW_SOURCE_SCOPE_SHAPE_OR_MODE_INVALID")
    return scope


def _filter(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    _require(type(raw) is dict and set(raw).issubset(FILTERS),
             "FINDINGSHOW_UNKNOWN_FILTER_OR_NONOBJECT")
    for key, value in raw.items():
        if key in DIGEST_FILTERS:
            _require(save._digest(value), "FINDINGSHOW_EXACT_SHA256_FILTER_REQUIRED")
        elif key in BOOL_FILTERS:
            _require(type(value) is bool, "FINDINGSHOW_BOOLEAN_FILTER_REQUIRED")
        elif key in ("run_id", "handoff_id"):
            _require(type(value) is str and lc.ID_RE.fullmatch(value) is not None and
                     value.startswith(("run_v1_" if key == "run_id" else "handoff_v1_")),
                     "FINDINGSHOW_ID_FILTER_INVALID")
        elif key == "stage_revision":
            _require(type(value) is int and 1 <= value <= lc.MAX_EVENTS,
                     "FINDINGSHOW_STAGE_REVISION_FILTER_INVALID")
        elif key == "severity":
            _require(type(value) is str and value in
                     ("info", "low", "medium", "high", "critical"),
                     "FINDINGSHOW_SEVERITY_FILTER_INVALID")
        elif key == "assessment_state":
            _require(type(value) is str and value in save.STATES,
                     "FINDINGSHOW_REVIEW_STATE_FILTER_INVALID")
        elif key == "confidence_claim":
            _require(type(value) is str and value in ("low", "medium", "high"),
                     "FINDINGSHOW_CONFIDENCE_FILTER_INVALID")
        else:
            raise FindingShowError("FINDINGSHOW_UNEXPECTED_FILTER", "invalid_input")
    return {k: raw[k] for k in sorted(raw)}


def _b64decode(value: str) -> bytes:
    _require(value and len(value) < MAX_CURSOR_BYTES and
             re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None,
             "FINDINGSHOW_CURSOR_ENCODING_INVALID")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise FindingShowError("FINDINGSHOW_CURSOR_ENCODING_INVALID", "invalid_input") from exc
    _require(base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == value,
             "FINDINGSHOW_CURSOR_NOT_CANONICAL")
    return raw


def _mac_cursor(key: bytes, body: bytes) -> str:
    return hmac.new(key, DOMAIN_CURSOR + body, hashlib.sha256).hexdigest()


def _encode_cursor(key: bytes, item: dict[str, Any]) -> str:
    body = st._canonical(item)
    token = base64.urlsafe_b64encode(body).rstrip(b"=").decode("ascii")
    result = token + "." + _mac_cursor(key, body)
    _require(len(result) <= MAX_CURSOR_BYTES, "FINDINGSHOW_CURSOR_SIZE_EXCEEDED", "unavailable")
    return result


def _read_cursor(key: bytes, token: str, *, now: datetime, pin: str,
                 query_sha256: str, revision_sha256: str,
                 matched_count: int) -> tuple[int, datetime, datetime]:
    _require(type(token) is str and len(token) <= MAX_CURSOR_BYTES and
             TOKEN_RE.fullmatch(token) is not None,
             "FINDINGSHOW_CURSOR_FORMAT_INVALID")
    encoded, supplied_mac = token.split(".")
    body = _b64decode(encoded)
    _require(hmac.compare_digest(supplied_mac, _mac_cursor(key, body)),
             "FINDINGSHOW_CURSOR_HMAC_FAILED", "unavailable")
    obj = st._strict_stored(body + b"\n", MAX_CURSOR_BYTES)
    _require(type(obj) is dict and set(obj) == {
        "schema", "save_store_pin", "query_sha256", "revision_sha256",
        "matched_count", "offset", "issued_at_utc", "expires_at_utc",
    }, "FINDINGSHOW_CURSOR_FIELDS_INVALID")
    _require(obj["schema"] == CURSOR_SCHEMA and
             obj["save_store_pin"] == pin and
             obj["query_sha256"] == query_sha256 and
             obj["revision_sha256"] == revision_sha256 and
             type(obj["matched_count"]) is int and obj["matched_count"] == matched_count and
             type(obj["offset"]) is int and 0 < obj["offset"] < matched_count,
             "FINDINGSHOW_CURSOR_SCOPE_OR_STORE_REVISION_CHANGED", "unavailable")
    issued = st._parse_stamp(obj["issued_at_utc"])
    expiry = st._parse_stamp(obj["expires_at_utc"])
    _require(issued <= now + timedelta(seconds=st.MAX_SKEW_SECONDS) and
             now < expiry and issued < expiry and
             expiry <= issued + timedelta(seconds=MAX_CURSOR_AGE_SECONDS),
             "FINDINGSHOW_CURSOR_EXPIRED_OR_CLOCK_ROLLBACK", "unavailable")
    return obj["offset"], issued, expiry


def _row_matches(record: dict[str, Any], row: dict[str, Any],
                 criteria: dict[str, Any]) -> bool:
    for key, value in criteria.items():
        if key == PATH_FILTER:
            continue
        if key in SOURCE_FILTERS:
            candidate = record["source_binding"][key]
        elif key in ROW_FILTERS:
            candidate = row[key]
        elif key == "coverage_complete":
            candidate = record["coverage"]["complete"]
        else:
            candidate = record[key]
        if candidate != value or type(candidate) is not type(value):
            return False
    return True


def _display(record: dict[str, Any], row: dict[str, Any], path_info: Any,
             *, expired: bool, details: bool) -> dict[str, Any]:
    has_index = path_info is not None
    complete = has_index and path_info["path_index_complete"]
    result = {
        "finding_id": row["finding_id"], "batch_sequence": record["sequence"],
        "saved_at_utc": record["committed_at_utc"],
        "expires_at_utc": record["expires_at_utc"],
        "expired_at_query_time": expired,
        "severity_claim": row["severity"], "confidence_claim": row["confidence_claim"],
        "assessment_state": row["assessment_state"],
        "assessment_is_only_local_key_holder_declaration": True,
        "positive_anchor_count": len(row["positive_anchor_sha256"]),
        "counter_evidence_count": len(row["counter_evidence"]),
        "path_index_state": ("LEGACY_V1_UNAVAILABLE" if not has_index else
                             "COMPLETE" if complete else "PARTIAL_OR_UNPATHED"),
        "source_mode": record["source_binding"]["source_mode"],
        "historical_proposal_only": record["historical_proposal_only"],
        "coverage_complete_for_selected_source": record["coverage"]["complete"],
        "coverage_missing_requirements_count": record["coverage"]["missing_count"],
        "semantic_defect_verified": False, "actual_test_or_ci_verified": False,
        "current_git_verified": False, "real_reviewer_identity_verified": False,
    }
    if details:
        result["digest_details"] = {
            "original_finding_sha256": row["original_finding_sha256"],
            "record_sha256": record["record_sha256"],
            "validation_receipt_sha256": record["validation_receipt_sha256"],
            "positive_anchor_sha256": list(row["positive_anchor_sha256"]),
            "positive_quote_sha256": list(row["positive_quote_sha256"]),
            "positive_anchor_path_sha256": (
                None if not has_index else list(path_info["positive_anchor_path_sha256"])),
            "counter_evidence_sha256": [c["annotation_sha256"] for c in row["counter_evidence"]],
        }
    return result


class FindingShower:
    """Read EC178 owner-private records; never writes, reprojects, or calls a provider."""

    def __init__(self, stage_root: str, business_repo_root: str, finding_store_root: str,
                 *, codesave_root: str | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.ledger = save.FindingSaver(stage_root, business_repo_root, finding_store_root,
                                        codesave_root=codesave_root, clock=clock)
        self.clock = clock

    def query(self, *, expected_finding_store_pin: str,
              authorize_store_read: bool, authorize_query: bool,
              authorized_source_binding: dict[str, Any], query_content_for: str,
              filters: dict[str, Any] | None = None,
              page_size: int = DEFAULT_PAGE_SIZE, cursor: str | None = None,
              include_expired: bool = False, authorize_expired_audit: bool = False,
              authorize_path_digest_query: bool = False,
              include_digest_details: bool = False,
              authorize_digest_details: bool = False,
              acknowledge_historical_proposal_metadata: bool = False) -> dict[str, Any]:
        """Exact-scoped, stable order and HMAC cursor bound to query+ledger revision.

        `authorized_source_binding` is a NEW caller-approved full source binding;
        an old projection/receipt/cursor must never supply its authority. Cursor
        is only an opaque, short-lived hint and all grants are checked EACH page.
        """
        try:
            _require(authorize_store_read is True and authorize_query is True,
                     "FINDINGSHOW_INDEPENDENT_STORE_READ_AND_QUERY_GRANTS_REQUIRED")
            _require(save._digest(expected_finding_store_pin),
                     "FINDINGSHOW_STORE_PIN_REQUIRED")
            _require(type(query_content_for) is str and query_content_for in lc.SOURCE_MODES,
                     "FINDINGSHOW_EXACT_SOURCE_MODE_REQUIRED")
            source = _binding(authorized_source_binding, query_content_for)
            _require(type(page_size) is int and 1 <= page_size <= MAX_PAGE_SIZE,
                     "FINDINGSHOW_PAGE_SIZE_OUT_OF_BOUNDS")
            for flag in (include_expired, authorize_expired_audit,
                         authorize_path_digest_query, include_digest_details,
                         authorize_digest_details, acknowledge_historical_proposal_metadata):
                _require(type(flag) is bool, "FINDINGSHOW_GRANT_FLAG_TYPE_INVALID")
            _require(not include_expired or authorize_expired_audit,
                     "FINDINGSHOW_EXPIRED_AUDIT_NEEDS_SEPARATE_GRANT")
            _require(not include_digest_details or authorize_digest_details,
                     "FINDINGSHOW_HASH_DETAILS_NEED_SEPARATE_GRANT")
            _require(query_content_for != "ProposedPR" or
                     acknowledge_historical_proposal_metadata,
                     "FINDINGSHOW_HISTORICAL_PROPOSAL_REQUIRES_METADATA_ACK")
            criteria = _filter(filters)
            _require(PATH_FILTER not in criteria or authorize_path_digest_query,
                     "FINDINGSHOW_PATH_DIGEST_SEARCH_NEEDS_NEW_GRANT")
            query_spec = {
                "source_binding": source, "source_mode": query_content_for,
                "filters": criteria, "page_size": page_size,
                "include_expired": include_expired,
                "include_digest_details": include_digest_details,
                "path_lookup_granted": authorize_path_digest_query,
                "historical_ack": acknowledge_historical_proposal_metadata,
            }
            query_sha256 = _sha(DOMAIN_QUERY, query_spec)
            with self.ledger._locked() as (fd, manifest, key, pins):
                assert manifest is not None and key is not None
                pin = save._pin(manifest)
                _require(hmac.compare_digest(expected_finding_store_pin, pin),
                         "FINDINGSHOW_STORE_PIN_OR_ROOT_MISMATCH", "unavailable")
                records = self.ledger._all(fd, key, manifest)  # validates EVERY HMAC+SHA link
                now = st._now(self.clock)
                _require(all(now + timedelta(seconds=st.MAX_SKEW_SECONDS) >=
                             st._parse_stamp(r["committed_at_utc"]) for r in records),
                         "FINDINGSHOW_LEDGER_CLOCK_ROLLBACK", "unavailable")
                # Revision binds even unrelated authorized private-store writes;
                # old cursors must fail instead of skipping or duplicating pages.
                revision = _sha(DOMAIN_REVISION, {
                    "store_pin": pin, "batch_count": len(records),
                    "record_shas": [r["record_sha256"] for r in records],
                })
                rows: list[tuple[dict[str, Any], dict[str, Any], Any, bool]] = []
                index_unavailable = 0
                partial_path_indexes = 0
                eligible_expiries: list[datetime] = []
                for record in records:
                    if record["source_binding"] != source:
                        continue
                    expired = now >= st._parse_stamp(record["expires_at_utc"])
                    if expired and not include_expired:
                        continue
                    path_index = record.get("path_index")
                    for i, finding in enumerate(record["findings"]):
                        if not _row_matches(record, finding, criteria):
                            continue
                        p_info = path_index[i] if path_index is not None else None
                        if p_info is None:
                            index_unavailable += 1
                        elif not p_info["path_index_complete"]:
                            partial_path_indexes += 1
                        if PATH_FILTER in criteria:
                            if p_info is None or criteria[PATH_FILTER] not in p_info["positive_anchor_path_sha256"]:
                                continue
                        rows.append((record, finding, p_info, expired))
                        if not expired:
                            eligible_expiries.append(st._parse_stamp(record["expires_at_utc"]))
                _require(len(rows) <= MAX_RESULTS, "FINDINGSHOW_SCOPED_RESULT_LIMIT", "unavailable")
                # Immutable store order, not lexical model text or subjective severity.
                rows.sort(key=lambda pair: (pair[0]["sequence"], pair[1]["finding_id"]))
                start = 0
                established_expiry: datetime | None = None
                established_issue: datetime | None = None
                if cursor is not None:
                    start, established_issue, established_expiry = _read_cursor(
                        key, cursor, now=now, pin=pin, query_sha256=query_sha256,
                        revision_sha256=revision, matched_count=len(rows))
                selected = rows[start:start + page_size]
                more = start + len(selected) < len(rows)
                next_cursor = None
                cursor_expiry = None
                if more:
                    # All matched rows must remain unexpired throughout paging,
                    # otherwise a changing active set could silently omit rows.
                    expires = established_expiry or min(
                        [now + timedelta(seconds=MAX_CURSOR_AGE_SECONDS)] + eligible_expiries)
                    _require(now < expires, "FINDINGSHOW_PAGE_SNAPSHOT_EXPIRED", "unavailable")
                    issued = established_issue or now
                    # Cursor deadline never extends on paging.
                    next_cursor = _encode_cursor(key, {
                        "schema": CURSOR_SCHEMA, "save_store_pin": pin,
                        "query_sha256": query_sha256, "revision_sha256": revision,
                        "matched_count": len(rows), "offset": start + len(selected),
                        "issued_at_utc": st._stamp(issued),
                        "expires_at_utc": st._stamp(expires),
                    })
                    cursor_expiry = st._stamp(expires)
                self.ledger._live_pins(pins)
                gap = index_unavailable + partial_path_indexes
                return {
                    "schema": SCHEMA, "status": "partial", "exit_code": 2,
                    "reason_code": ("FINDINGSHOW_SCOPE_HAS_NO_EXACT_MATCH_NOT_ABSENCE_PROOF"
                                    if not rows else
                                    "FINDINGSHOW_LOCAL_HMAC_DECLARATIONS_NOT_VERIFIED_DEFECTS"),
                    "save_store_pin": pin,
                    "scope": {"source_mode": query_content_for,
                              "source_identity_sha256": source["source_identity_sha256"],
                              "exact_full_source_binding_granted": True,
                              "actor_identity_authenticated": False},
                    "query_sha256": query_sha256, "revision_sha256": revision,
                    "matched_count": len(rows), "returned_count": len(selected),
                    "page_size": page_size, "order": "BATCH_SEQUENCE_ASC_FINDING_ID_ASC",
                    "findings": [_display(r, f, path, expired=x,
                                          details=include_digest_details)
                                 for r, f, path, x in selected],
                    "next_cursor": next_cursor, "cursor_expires_at_utc": cursor_expiry,
                    "path_index": {
                        "path_digest_filter_applied": PATH_FILTER in criteria,
                        "legacy_v1_unindexed_in_authorized_nonpath_scope": index_unavailable,
                        "partial_v2_unpathable_in_authorized_nonpath_scope": partial_path_indexes,
                        "path_filter_exhaustive_for_authorized_records": gap == 0,
                        "path_hash_domain": "EC177_DOMAIN_PATH_NOT_RAW_PATH_OR_GENERAL_SHA256",
                    },
                    "provenance": {
                        "complete_private_manifest_key_and_hash_chain_checked": True,
                        "authorization_only_declared_by_caller": True,
                        "record_hmac_proves_local_key_possession_only": True,
                        "expired_history_included_by_separate_grant": include_expired,
                        "coverage_gaps_and_historical_proposal_not_upgraded": True,
                        "objective_truth_current_git_ci_or_test_proven": False,
                    },
                    "effects": _effects(), "trust_boundary": TRUST,
                }
        except (FindingShowError, save.FindingSaveError, st.StageError,
                lc.LifecycleError) as exc:
            status = exc.status if exc.status in ("invalid_input", "unavailable") else "unavailable"
            return _refused(status, exc.code)
        except (OSError, ValueError, TypeError, KeyError, IndexError, OverflowError,
                RuntimeError, RecursionError, MemoryError):
            return _refused("unavailable", "FINDINGSHOW_UNTRUSTED_INPUT_OR_PRIVATE_LEDGER_UNAVAILABLE")
