#!/usr/bin/env python3
"""EC176: separately authorized, immutable Staged CodeSave of CES metadata ONLY.

The signed EC175 manual review is evidence of a configured HMAC key-holder's
*declaration*, not a verified human, correct finding, live Git or CI. A caller's
EC175 result/receipt SHA is untrusted: this consumer independently reruns the
EC175 validator against the sealed EC173 input, EC172 stage and every EC174
source anchor (twice before commit), verifies the independently configured
review key, and requires an entirely new save authorization and destination.

Only hashes, random run/handoff IDs, conservative coverage flags and times are
stored in a separate, pre-provisioned owner-private POSIX CES directory. The
record contains NO patch, source path, quote, model text, review note, Finding
or business Git mutation. HMAC protects local store consistency, not real
identity or physical crash durability. Same-UID/key compromise is out of scope.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
from typing import Any, Callable, Iterator

import codevalidate_staged as cv
import handoff_lifecycle as lc
import handoff_input as hi
import task_staging as st

SCHEMA = "ces.codesave_staged_result.v1"
MANIFEST_SCHEMA = "ces.codesave_staged_manifest.v1"
RECORD_SCHEMA = "ces.codesave_staged_metadata_record.v1"
DOMAIN_MANIFEST = b"CES-EC176-SAVE-STORE-PIN-v1\x00"
DOMAIN_OPERATION = b"CES-EC176-SAVE-OPERATION-v1\x00"
DOMAIN_RECORD = b"CES-EC176-SAVE-METADATA-RECORD-v1\x00"
DOMAIN_MAC = b"CES-EC176-SAVE-METADATA-HMAC-v1\x00"
ROOT_MANIFEST = "manifest.json"
ROOT_KEY = ".codesave-key"
ROOT_LOCK = ".codesave-lock"
ROOT_FILES = frozenset((ROOT_MANIFEST, ROOT_KEY, ROOT_LOCK))
MAX_RECORDS = 128
MAX_RECORD_BYTES = 8192
MAX_VALIDATION_BYTES = 64 * 1024
SAVE_NAME = re.compile(r"save_[0-9a-f]{64}\.json\Z")
PENDING_NAME = re.compile(r"\.pending-save-[0-9a-f]{32}\Z")
RESULT_STATUS = {"partial": 2, "invalid_input": 4, "unavailable": 5}
TRUST = "LOCAL_OWNER_PRIVATE_HMAC_ONLY_NO_SOURCE_ACTOR_CI_OR_FINDING_PROOF"


class CodeSaveError(st.StageError):
    pass


def _require(ok: bool, reason: str, status: str = "invalid_input") -> None:
    if not ok:
        raise CodeSaveError(reason, status)


def _eq(one: Any, other: Any) -> bool:
    return type(one) is type(other) and st._canonical(one) == st._canonical(other)


def _sha(domain: bytes, obj: Any) -> str:
    return hashlib.sha256(domain + st._canonical(obj)).hexdigest()


def _op_id(operation_key: str) -> str:
    return hashlib.sha256(DOMAIN_OPERATION + operation_key.encode("utf-8")).hexdigest()


def _manifest_pin(manifest: dict[str, Any]) -> str:
    return _sha(DOMAIN_MANIFEST, manifest)


def _mac(key: bytes, record: dict[str, Any]) -> str:
    return hmac.new(key, DOMAIN_MAC + st._canonical(record), hashlib.sha256).hexdigest()


def _strict(obj: Any, keys: set[str], reason: str) -> dict[str, Any]:
    _require(type(obj) is dict and set(obj) == keys, reason)
    return obj


def _digest(s: Any) -> bool:
    return type(s) is str and st.HEX.fullmatch(s) is not None


def _deny(status: str, reason: str, *, ambiguous: bool = False) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": status, "exit_code": RESULT_STATUS[status],
        "reason_code": reason, "mode": "Staged", "save_operation_id": None,
        "save_store_pin": None, "record_sha256": None,
        "committed_at_utc": None, "expires_at_utc": None,
        "idempotent_reentry": False,
        "effects": {
            "ces_metadata_commit_state": "UNCERTAIN_MANUAL_REVIEW_REQUIRED" if ambiguous else "NONE",
            "ces_metadata_record_committed": None if ambiguous else False,
            "finding_created": False, "source_code_executed": False,
            "business_repository_written": False, "git_or_issue_written": False,
            "code_text_or_review_notes_persisted": False,
            "external_transfer_by_saver": False,
        },
        "trust_boundary": TRUST,
    }


def _accepted(record: dict[str, Any], store_pin: str, *, replay: bool) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": "partial", "exit_code": 2, "mode": "Staged",
        "reason_code": ("CODESAVE_IDEMPOTENT_METADATA_REENTRY_NO_NEW_WRITE" if replay else
                        "CODESAVE_PRIVATE_METADATA_COMMITTED_NOT_FINDING_OR_SOURCE_PROOF"),
        "save_operation_id": record["save_operation_id"], "save_store_pin": store_pin,
        "record_sha256": record["record_sha256"],
        "committed_at_utc": record["saved_at_utc"],
        "expires_at_utc": record["valid_until_utc"], "idempotent_reentry": replay,
        "stored": {
            "schema": RECORD_SCHEMA, "task_kind": "code_analysis",
            "source_mode": record["source_binding"]["source_mode"],
            "finding_hashes_count": len(record["finding_sha256"]),
            "payload_kind": "HASHES_AND_CONSERVATIVE_METADATA_NO_MODEL_OR_SOURCE_TEXT",
            "source_currentness_proven": False,
            "manual_key_possession_declaration_recorded": True,
            "reviewer_identity_or_semantic_truth_proven": False,
            "real_ci_or_test_execution_observed": False,
        },
        "effects": {
            "ces_metadata_commit_state": "COMMITTED_PRIOR" if replay else "COMMITTED_NEW",
            "ces_metadata_record_committed": True, "finding_created": False,
            "source_code_executed": False, "business_repository_written": False,
            "git_or_issue_written": False,
            "code_text_or_review_notes_persisted": False,
            "external_transfer_by_saver": False,
        },
        "trust_boundary": TRUST,
    }


def _record_fields() -> set[str]:
    return {
        "schema", "store_id", "store_pin", "save_operation_id", "source_binding",
        "validation_operation_id", "input_operation_id", "stage_parent_pin_sha256",
        "source_observed_at_utc", "saved_at_utc",
        "valid_until_utc", "candidate_sha256", "route_result_sha256",
        "draft_sha256", "supplied_validation_receipt_sha256",
        "fresh_validation_receipt_sha256", "manual_review_attestation_sha256",
        "manual_verifier_id", "manual_reviewed_at_utc", "manual_review_expires_at_utc",
        "finding_sha256", "finding_count", "source_coverage_sha256",
        "coverage_complete_for_selected_source", "coverage_missing_requirements_count",
        "historical_proposal_only", "source_currentness_proven", "verified_ci_or_test",
        "verified_remote_actor_or_git", "contains_source_or_model_text", "finding_created",
        "record_sha256", "mac_sha256",
    }


def _load_record(fd: int, filename: str, key: bytes,
                 manifest: dict[str, Any]) -> dict[str, Any]:
    try:
        obj = st._strict_stored(st._read_checked(fd, filename, MAX_RECORD_BYTES),
                                MAX_RECORD_BYTES)
        _strict(obj, _record_fields(), "CODESAVE_STORED_RECORD_FIELDS_INVALID")
        _require(obj["schema"] == RECORD_SCHEMA and obj["store_id"] == manifest["store_id"] and
                 obj["store_pin"] == _manifest_pin(manifest),
                 "CODESAVE_RECORD_STORE_IDENTITY_CHANGED", "unavailable")
        _require(type(obj["save_operation_id"]) is str and
                 filename == "save_" + obj["save_operation_id"] + ".json" and
                 _digest(obj["save_operation_id"]),
                 "CODESAVE_RECORD_FILENAME_OR_OPERATION_INVALID", "unavailable")
        _require(_digest(obj["record_sha256"]) and _digest(obj["mac_sha256"]) and
                 hmac.compare_digest(obj["record_sha256"], _sha(DOMAIN_RECORD, {
                     k: v for k, v in obj.items() if k not in ("record_sha256", "mac_sha256")
                 })) and
                 hmac.compare_digest(obj["mac_sha256"], _mac(key, {
                     k: v for k, v in obj.items() if k != "mac_sha256"
                 })), "CODESAVE_RECORD_HASH_OR_LOCAL_HMAC_INVALID", "unavailable")
        binding = _strict(obj["source_binding"], {
            "run_id", "handoff_id", "stage_revision", "stage_event_sha256",
            "source_mode", "task_kind", "source_context_sha256", "source_identity_sha256",
            "evidence_hash", "material_sha256",
        }, "CODESAVE_RECORD_SOURCE_BINDING_FIELDS_CHANGED")
        _require(type(binding["run_id"]) is str and lc.ID_RE.fullmatch(binding["run_id"]) is not None and
                 type(binding["handoff_id"]) is str and lc.ID_RE.fullmatch(binding["handoff_id"]) is not None and
                 type(binding["stage_revision"]) is int and 1 <= binding["stage_revision"] <= lc.MAX_EVENTS and
                 binding["source_mode"] in lc.SOURCE_MODES and binding["task_kind"] == "code_analysis" and
                 all(_digest(binding[name]) for name in (
                     "stage_event_sha256", "source_context_sha256", "source_identity_sha256",
                     "evidence_hash", "material_sha256")),
                 "CODESAVE_RECORD_SOURCE_PIN_INVALID", "unavailable")
        for name in ("validation_operation_id", "input_operation_id",
                     "stage_parent_pin_sha256", "candidate_sha256", "route_result_sha256",
                     "draft_sha256", "supplied_validation_receipt_sha256",
                     "fresh_validation_receipt_sha256", "manual_review_attestation_sha256",
                     "source_coverage_sha256"):
            _require(_digest(obj[name]), "CODESAVE_RECORD_PROOF_DIGEST_INVALID", "unavailable")
        _require(type(obj["manual_verifier_id"]) is str and
                 re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", obj["manual_verifier_id"]) is not None,
                 "CODESAVE_RECORD_VERIFIER_LABEL_INVALID", "unavailable")
        _require(type(obj["finding_count"]) is int and
                 1 <= obj["finding_count"] <= 32 and
                 type(obj["finding_sha256"]) is list and
                 len(obj["finding_sha256"]) == obj["finding_count"] and
                 all(_digest(x) for x in obj["finding_sha256"]) and
                 len(set(obj["finding_sha256"])) == len(obj["finding_sha256"]),
                 "CODESAVE_RECORD_FINDING_DIGESTS_INVALID", "unavailable")
        _require(type(obj["coverage_complete_for_selected_source"]) is bool and
                 type(obj["coverage_missing_requirements_count"]) is int and
                 0 <= obj["coverage_missing_requirements_count"] <= 1024 and
                 type(obj["historical_proposal_only"]) is bool and
                 obj["historical_proposal_only"] == (binding["source_mode"] == "ProposedPR") and
                 all(obj[flag] is False for flag in (
                     "source_currentness_proven", "verified_ci_or_test",
                     "verified_remote_actor_or_git", "contains_source_or_model_text", "finding_created")),
                 "CODESAVE_RECORD_CLAIMS_ESCALATED", "unavailable")
        now_time = st._parse_stamp(obj["saved_at_utc"])
        end = st._parse_stamp(obj["valid_until_utc"])
        reviewed = st._parse_stamp(obj["manual_reviewed_at_utc"])
        review_end = st._parse_stamp(obj["manual_review_expires_at_utc"])
        observed = st._parse_stamp(obj["source_observed_at_utc"])
        _require(observed <= reviewed <= now_time + timedelta(seconds=st.MAX_SKEW_SECONDS) and
                 now_time < end <= review_end and
                 end <= now_time + timedelta(seconds=cv.MAX_VERIFICATION_TTL),
                 "CODESAVE_RECORD_INVALID_TIME_CHAIN", "unavailable")
        return obj
    except st.StageError as exc:
        if isinstance(exc, CodeSaveError):
            raise
        raise CodeSaveError(exc.code, exc.status) from exc


class StagedCodeSaver:
    """EC176 isolated metadata store; caller retains all independent keys/grants."""

    def __init__(self, stage_root: str, business_repo_root: str, save_root: str, *,
                 clock: Callable[[], datetime] | None = None) -> None:
        st._supported()
        for name, root in (("STAGE", stage_root), ("BUSINESS", business_repo_root),
                           ("SAVE", save_root)):
            st._components(root, name)
        self.stage_root = stage_root
        self.business_repo_root = business_repo_root
        self.save_root = save_root
        self.clock = clock
        self.validator = cv.StagedCodeValidator(stage_root, business_repo_root, clock=clock)

    @contextmanager
    def _locked(self, *, initialized: bool = True) -> Iterator[tuple[int, dict[str, Any] | None, bytes | None]]:
        """Pinned triple-root, no-follow private-store lock; no business path writes."""
        with st._open_directory(self.save_root, "STAGE") as (fd, save_chain):
            with st._open_directory(self.stage_root, "STAGE") as (stage_fd, stage_chain):
                with st._open_directory(self.business_repo_root, "BUSINESS") as (repo_fd, repo_chain):
                    st._paths_separate(save_chain, stage_chain, self.save_root, self.stage_root)
                    st._paths_separate(save_chain, repo_chain, self.save_root, self.business_repo_root)
                    st._paths_separate(stage_chain, repo_chain, self.stage_root, self.business_repo_root)
                    pins = (st._identity(fd), st._identity(stage_fd), st._identity(repo_fd))
                    try:
                        st.fcntl.flock(fd, st.fcntl.LOCK_EX)
                    except OSError as exc:
                        raise CodeSaveError("CODESAVE_STORE_LOCK_UNAVAILABLE", "unavailable") from exc
                    try:
                        self._pins_alive(fd, pins)
                        if not initialized:
                            _require(not os.listdir(fd), "CODESAVE_INIT_REQUIRES_EMPTY_PRIVATE_DIRECTORY", "unavailable")
                            yield fd, None, None
                        else:
                            _require(ROOT_FILES.issubset(set(os.listdir(fd))),
                                     "CODESAVE_STORE_NOT_INITIALIZED", "unavailable")
                            key = st._read_checked(fd, ROOT_KEY, 32)
                            _require(len(key) == 32, "CODESAVE_LOCAL_KEY_INVALID", "unavailable")
                            manifest = st._strict_stored(st._read_checked(fd, ROOT_MANIFEST, 2048), 2048)
                            self._verify_manifest(manifest, fd, stage_fd, repo_fd, key)
                            _require(st._read_checked(fd, ROOT_LOCK, 8) == b"",
                                     "CODESAVE_LOCK_MARKER_CHANGED", "unavailable")
                            yield fd, manifest, key
                    except OSError as exc:
                        raise CodeSaveError("CODESAVE_FILESYSTEM_UNAVAILABLE", "unavailable") from exc
                    finally:
                        st.fcntl.flock(fd, st.fcntl.LOCK_UN)

    def _pins_alive(self, fd: int, pins: tuple[tuple[int, int], ...]) -> None:
        _require(st._pinned(self.save_root, self.stage_root, fd, pins[0], pins[1]) and
                 st._pinned(self.save_root, self.business_repo_root, fd, pins[0], pins[2]),
                 "CODESAVE_STORE_STAGE_OR_REPO_IDENTITY_CHANGED", "unavailable")

    def _new_manifest(self, fd: int, stage_fd: int, repo_fd: int, key: bytes) -> dict[str, Any]:
        save = os.fstat(fd)
        stage = os.fstat(stage_fd)
        repo = os.fstat(repo_fd)
        return {
            "schema": MANIFEST_SCHEMA, "store_id": "codesave_v1_" + secrets.token_hex(16),
            "save_dev": save.st_dev, "save_ino": save.st_ino, "save_uid": save.st_uid,
            "save_path_sha256": hashlib.sha256(os.fsencode(self.save_root)).hexdigest(),
            "stage_dev": stage.st_dev, "stage_ino": stage.st_ino,
            "stage_path_sha256": hashlib.sha256(os.fsencode(self.stage_root)).hexdigest(),
            "repo_dev": repo.st_dev, "repo_ino": repo.st_ino,
            "repo_path_sha256": hashlib.sha256(os.fsencode(self.business_repo_root)).hexdigest(),
            "key_sha256": hashlib.sha256(key).hexdigest(),
        }

    def _verify_manifest(self, manifest: Any, fd: int, stage_fd: int,
                         repo_fd: int, key: bytes) -> None:
        _strict(manifest, {"schema", "store_id", "save_dev", "save_ino", "save_uid",
                           "save_path_sha256", "stage_dev", "stage_ino",
                           "stage_path_sha256", "repo_dev", "repo_ino",
                           "repo_path_sha256", "key_sha256"},
                "CODESAVE_STORE_MANIFEST_SHAPE_INVALID")
        _require(manifest["schema"] == MANIFEST_SCHEMA and
                 type(manifest["store_id"]) is str and
                 re.fullmatch(r"codesave_v1_[0-9a-f]{32}", manifest["store_id"]) is not None,
                 "CODESAVE_STORE_MANIFEST_ID_INVALID", "unavailable")
        save, stage, repo = os.fstat(fd), os.fstat(stage_fd), os.fstat(repo_fd)
        expected = {
            "schema": MANIFEST_SCHEMA, "store_id": manifest["store_id"],
            "save_dev": save.st_dev, "save_ino": save.st_ino, "save_uid": save.st_uid,
            "save_path_sha256": hashlib.sha256(os.fsencode(self.save_root)).hexdigest(),
            "stage_dev": stage.st_dev, "stage_ino": stage.st_ino,
            "stage_path_sha256": hashlib.sha256(os.fsencode(self.stage_root)).hexdigest(),
            "repo_dev": repo.st_dev, "repo_ino": repo.st_ino,
            "repo_path_sha256": hashlib.sha256(os.fsencode(self.business_repo_root)).hexdigest(),
            "key_sha256": hashlib.sha256(key).hexdigest(),
        }
        _require(_eq(expected, manifest), "CODESAVE_STORE_PIN_OR_KEY_CHANGED", "unavailable")

    def initialize(self, *, approve_init: bool) -> dict[str, Any]:
        """Only initialize an already-created EMPTY owner-private destination."""
        _require(approve_init is True, "CODESAVE_EXPLICIT_STORE_INIT_APPROVAL_REQUIRED")
        with self._locked(initialized=False) as (fd, _, __):
            key = secrets.token_bytes(32)
            with st._open_directory(self.stage_root, "STAGE") as (stage_fd, _):
                with st._open_directory(self.business_repo_root, "BUSINESS") as (repo_fd, __):
                    manifest = self._new_manifest(fd, stage_fd, repo_fd, key)
            created = []
            try:
                self._pins_alive(fd, (st._identity(fd),
                                      (manifest["stage_dev"], manifest["stage_ino"]),
                                      (manifest["repo_dev"], manifest["repo_ino"])))
                for name, raw in ((ROOT_KEY, key), (ROOT_LOCK, b""),
                                  (ROOT_MANIFEST, st._canonical(manifest) + b"\n")):
                    st._write_exclusive(fd, name, raw)
                    created.append(name)
                os.fsync(fd)
            except (st.StageError, OSError) as exc:
                try:
                    for name in reversed(created):
                        os.unlink(name, dir_fd=fd)
                    os.fsync(fd)
                except OSError:
                    raise CodeSaveError("CODESAVE_INIT_ROLLBACK_UNCERTAIN", "unavailable") from exc
                raise CodeSaveError("CODESAVE_INIT_FAILED", "unavailable") from exc
            return {
                "schema": SCHEMA, "status": "success", "exit_code": 0,
                "reason_code": "CODESAVE_PRIVATE_STORE_INITIALIZED_NO_RECORD_SAVED",
                "save_store_pin": _manifest_pin(manifest), "store_id": manifest["store_id"],
                "ces_metadata_record_committed": False, "business_repository_written": False,
            }

    def _all(self, fd: int, key: bytes, manifest: dict[str, Any]) -> list[dict[str, Any]]:
        names = os.listdir(fd)
        _require(len(names) <= len(ROOT_FILES) + MAX_RECORDS + 1,
                 "CODESAVE_STORE_ENTRY_LIMIT", "unavailable")
        files = []
        # First classify every entry. An interrupted publish must fail with
        # one stable reason, regardless of directory enumeration order; never
        # silently skip a pending temp file because a target is already linked.
        for name in names:
            if name in ROOT_FILES:
                continue
            if PENDING_NAME.fullmatch(name):
                raise CodeSaveError("CODESAVE_UNFINISHED_TRANSACTION_MANUAL_REVIEW_REQUIRED", "unavailable")
            _require(SAVE_NAME.fullmatch(name) is not None,
                     "CODESAVE_STORE_UNKNOWN_OR_UNSAFE_ENTRY", "unavailable")
            files.append(name)
        _require(len(files) <= MAX_RECORDS, "CODESAVE_STORE_FULL", "unavailable")
        records = [_load_record(fd, name, key, manifest) for name in sorted(files)]
        _require(len(records) <= MAX_RECORDS, "CODESAVE_STORE_FULL", "unavailable")
        return records

    @staticmethod
    def _verify_original(original: Any, fresh: dict[str, Any],
                         expected_receipt: str, now: datetime) -> None:
        """Prior v1 digest is UNKEYED: check pin and content, then rerun signed review."""
        _require(_digest(expected_receipt), "CODESAVE_EXPECTED_VALIDATION_RECEIPT_REQUIRED")
        _require(type(original) is dict and len(st._canonical(original)) <= MAX_VALIDATION_BYTES,
                 "CODESAVE_PRIOR_VALIDATION_RESULT_INVALID")
        _strict(original, set(fresh), "CODESAVE_PRIOR_VALIDATION_RESULT_FIELDS_INVALID")
        _require(_digest(original["validation_receipt_sha256"]) and
                 hmac.compare_digest(expected_receipt, original["validation_receipt_sha256"]) and
                 hmac.compare_digest(expected_receipt, cv._sha(cv.DOMAIN_RECEIPT, {
                     k: v for k, v in original.items() if k != "validation_receipt_sha256"
                 })), "CODESAVE_PRIOR_VALIDATION_RECEIPT_EDITED_OR_UNPINNED")
        stable_keys = set(fresh) - {
            "validated_at_utc", "expires_at_utc", "validation_receipt_sha256"
        }
        _require(all(_eq(original[k], fresh[k]) for k in stable_keys),
                 "CODESAVE_VALIDATION_SOURCE_CANDIDATE_REVIEW_OR_EFFECTS_CHANGED", "unavailable")
        try:
            start = st._parse_stamp(original["validated_at_utc"])
            end = st._parse_stamp(original["expires_at_utc"])
        except st.StageError as exc:
            raise CodeSaveError("CODESAVE_PRIOR_VALIDATION_TIME_INVALID") from exc
        _require(start <= now + timedelta(seconds=st.MAX_SKEW_SECONDS) and
                 start < end and now < end <= start + timedelta(seconds=cv.MAX_VERIFICATION_TTL),
                 "CODESAVE_PRIOR_VALIDATION_EXPIRED_OR_FUTURE", "unavailable")

    @staticmethod
    def _manual_confirmed(result: dict[str, Any], now: datetime) -> None:
        _require(result["status"] == "partial" and result["exit_code"] == 2 and
                 result["reason_code"] ==
                 "CODEVALIDATE_PINNED_MANUAL_REVIEW_RECORDED_NOT_SOURCE_PROOF" and
                 result["candidate"]["state"] == "STRUCTURALLY_CHECKED_DRAFT" and
                 result["manual_review"] is not None and
                 result["manual_review"]["key_possession_checked"] is True and
                 result["manual_review"]["verifier_identity_independently_authenticated"] is False,
                 "CODESAVE_INDEPENDENT_SIGNED_MANUAL_REVIEW_REQUIRED", "unavailable")
        count = result["candidate"]["findings_count"]
        _require(type(count) is int and 1 <= count <= 32 and
                 result["candidate"]["manual_verified_count"] == count and
                 result["candidate"]["manual_rejected_count"] == 0 and
                 all(row["review_state"] == "VERIFIED_BY_PINNED_MANUAL_REVIEW_SIGNATURE"
                     for row in result["candidate"]["findings"]),
                 "CODESAVE_EACH_FINDING_REQUIRES_EXPLICIT_SIGNED_CONFIRMATION", "unavailable")
        _require(now < st._parse_stamp(result["manual_review"]["expires_at_utc"]),
                 "CODESAVE_MANUAL_REVIEW_EXPIRED", "unavailable")

    @staticmethod
    def _new_record(validated: dict[str, Any], *, original_receipt: str,
                    operation_id: str, store_id: str, store_pin: str,
                    validation_operation_id: str, input_operation_id: str,
                    stage_parent_pin_sha256: str, now: datetime) -> dict[str, Any]:
        review = validated["manual_review"]
        original_until = st._parse_stamp(validated["expires_at_utc"])
        valid_until = min(original_until, st._parse_stamp(review["expires_at_utc"]))
        coverage = validated["coverage"]
        _require(type(coverage["missing_requirements"]) is list and
                 len(coverage["missing_requirements"]) <= 1024,
                 "CODESAVE_COVERAGE_SHAPE_UNSUPPORTED", "unavailable")
        record = {
            "schema": RECORD_SCHEMA, "store_id": store_id, "store_pin": store_pin,
            "save_operation_id": operation_id,
            "source_binding": validated["source_binding"],
            "validation_operation_id": validation_operation_id,
            "input_operation_id": input_operation_id,
            "stage_parent_pin_sha256": stage_parent_pin_sha256,
            "source_observed_at_utc": st._stamp(hi._observed(
                validated["source"]["source_observed_at_utc"])),
            "saved_at_utc": st._stamp(now), "valid_until_utc": st._stamp(valid_until),
            "candidate_sha256": validated["candidate"]["candidate_sha256"],
            "route_result_sha256": validated["candidate"]["route_result_sha256"],
            "draft_sha256": validated["candidate"]["draft_sha256"],
            "supplied_validation_receipt_sha256": original_receipt,
            "fresh_validation_receipt_sha256": validated["validation_receipt_sha256"],
            "manual_review_attestation_sha256": review["attestation_sha256"],
            "manual_verifier_id": review["verifier_id"],
            "manual_reviewed_at_utc": review["reviewed_at_utc"],
            "manual_review_expires_at_utc": review["expires_at_utc"],
            "finding_sha256": [row["finding_sha256"] for row in validated["candidate"]["findings"]],
            "finding_count": validated["candidate"]["findings_count"],
            "source_coverage_sha256": _sha(b"CES-EC176-COVERAGE-v1\x00", coverage),
            "coverage_complete_for_selected_source": coverage["complete_for_selected_source"],
            "coverage_missing_requirements_count": len(coverage["missing_requirements"]),
            "historical_proposal_only": validated["source"]["historical_proposal_only"],
            "source_currentness_proven": False,
            "verified_ci_or_test": False, "verified_remote_actor_or_git": False,
            "contains_source_or_model_text": False, "finding_created": False,
        }
        record["record_sha256"] = _sha(DOMAIN_RECORD, record)
        return record

    def save(self, prepared: dict[str, Any], route_result: dict[str, Any],
             validation_result: dict[str, Any], *, expected_save_store_pin: str,
             expected_parent_pin: str, run_id: str, handoff_id: str,
             expected_revision: int, expected_event_sha256: str,
             input_operation_key: str, validation_operation_key: str,
             save_operation_key: str, expected_candidate_sha256: str,
             expected_validation_receipt_sha256: str,
             authorize_save: bool, authorize_read: bool, save_content_for: str,
             manual_review: dict[str, Any], authorize_manual_review: bool,
             manual_review_content_for: str, trusted_verifier_id: str,
             trusted_verifier_key: bytes, draft: dict[str, Any] | None = None,
             allow_historical_proposal: bool = False,
             approve_historical_proposal_metadata_save: bool = False,
             acknowledge_partial_coverage: bool = False,
             max_source_age_seconds: int = 600) -> dict[str, Any]:
        """Revalidate the complete source/review, then atomically save only hashes.

        Never auto-save EC175 partial results. No temporary file is created until
        all mandatory HMAC, source anchor, review and authorization checks pass.
        The pre-provisioned save store is unrelated to EC172's input store.
        """
        try:
            _require(authorize_save is True, "CODESAVE_INDEPENDENT_EXPLICIT_SAVE_APPROVAL_REQUIRED")
            _require(authorize_read is True, "CODESAVE_INDEPENDENT_SOURCE_READ_APPROVAL_REQUIRED")
            _require(type(save_content_for) is str and save_content_for in lc.SOURCE_MODES,
                     "CODESAVE_EXACT_SOURCE_SCOPE_REQUIRED")
            _require(type(expected_save_store_pin) is str and _digest(expected_save_store_pin),
                     "CODESAVE_EXPECTED_STORE_PIN_REQUIRED")
            for key in (save_operation_key, validation_operation_key, input_operation_key):
                lc._check_op(key)
            _require(len({save_operation_key, validation_operation_key, input_operation_key}) == 3,
                     "CODESAVE_NEW_OPERATION_KEY_MUST_BE_DISTINCT")
            _require(save_content_for != "ProposedPR" or
                     (allow_historical_proposal is True and
                      approve_historical_proposal_metadata_save is True),
                     "CODESAVE_HISTORICAL_PROPOSAL_SEPARATE_SAVE_APPROVAL_REQUIRED")
            _require(authorize_manual_review is True and
                     manual_review_content_for == save_content_for,
                     "CODESAVE_INDEPENDENT_MANUAL_REVIEW_SOURCE_SCOPE_REQUIRED")
            validator_kwargs = dict(
                expected_parent_pin=expected_parent_pin, run_id=run_id,
                handoff_id=handoff_id, expected_revision=expected_revision,
                expected_event_sha256=expected_event_sha256,
                input_operation_key=input_operation_key,
                validation_operation_key=validation_operation_key,
                authorize_validate=True, authorize_read=True,
                validate_content_for=save_content_for,
                expected_candidate_sha256=expected_candidate_sha256,
                draft=draft, allow_historical_proposal=allow_historical_proposal,
                max_source_age_seconds=max_source_age_seconds,
                manual_review=manual_review, authorize_manual_review=True,
                manual_review_content_for=manual_review_content_for,
                trusted_verifier_id=trusted_verifier_id,
                trusted_verifier_key=trusted_verifier_key,
            )
            # This is a fresh, independent CodeValidate invocation, NOT use of
            # the caller's unkeyed v1 validation receipt as authority.
            first = self.validator.validate(prepared, route_result, **validator_kwargs)
            _require(first["status"] == "partial", "CODESAVE_FRESH_VALIDATION_REFUSED_" + first["reason_code"],
                     "unavailable")
            now = st._now(self.clock)
            self._manual_confirmed(first, now)
            self._verify_original(validation_result, first, expected_validation_receipt_sha256, now)
            coverage = first["coverage"]
            _require(coverage["complete_for_selected_source"] is True or
                     acknowledge_partial_coverage is True,
                     "CODESAVE_PARTIAL_COVERAGE_REQUIRES_SEPARATE_ACKNOWLEDGMENT")
            operation_id = _op_id(save_operation_key)
            with self._locked() as (fd, manifest, key):
                assert manifest is not None and key is not None
                store_pin = _manifest_pin(manifest)
                _require(hmac.compare_digest(expected_save_store_pin, store_pin),
                         "CODESAVE_TARGET_STORE_IDENTITY_OR_PIN_CHANGED", "unavailable")
                records = self._all(fd, key, manifest)
                # Recheck sealed source, each line anchor, HMAC manual signature,
                # active grants and TTL AFTER acquisition of the write lock.
                second = self.validator.validate(prepared, route_result, **validator_kwargs)
                _require(second["status"] == "partial", "CODESAVE_PREFLIGHT_VALIDATION_REFUSED_" + second["reason_code"],
                         "unavailable")
                now = st._now(self.clock)
                self._manual_confirmed(second, now)
                self._verify_original(validation_result, second, expected_validation_receipt_sha256, now)
                _require(all(_eq(first[field], second[field]) for field in (
                    "source_binding", "source", "coverage", "candidate", "manual_review", "proof", "effects"
                )), "CODESAVE_SOURCE_OR_REVIEW_CHANGED_DURING_SAVE", "unavailable")
                _require(coverage["complete_for_selected_source"] is True or
                         acknowledge_partial_coverage is True,
                         "CODESAVE_PARTIAL_COVERAGE_REQUIRES_SEPARATE_ACKNOWLEDGMENT")
                _require(now < st._parse_stamp(second["expires_at_utc"]),
                         "CODESAVE_VALIDATION_EXPIRED_BEFORE_PUBLISH", "unavailable")
                new = self._new_record(second, original_receipt=expected_validation_receipt_sha256,
                                       operation_id=operation_id, store_id=manifest["store_id"],
                                       store_pin=store_pin,
                                       validation_operation_id=_op_id(validation_operation_key),
                                       input_operation_id=_op_id(input_operation_key),
                                       stage_parent_pin_sha256=_sha(b"CES-EC176-STAGE-PIN-v1\x00",
                                                                   expected_parent_pin), now=now)
                # Pin the record to the earlier validation window too, which
                # must never be extended by the second validation.
                original_until = st._parse_stamp(validation_result["expires_at_utc"])
                new["valid_until_utc"] = st._stamp(min(st._parse_stamp(new["valid_until_utc"]),
                                                          original_until))
                new["record_sha256"] = _sha(DOMAIN_RECORD, {
                    k: v for k, v in new.items() if k != "record_sha256"
                })
                for old in records:
                    if old["save_operation_id"] == operation_id:
                        # Retry requires all grants and proof to be live again;
                        # it cannot change any bytes of the previous record.
                        without_time = {"saved_at_utc", "valid_until_utc", "record_sha256", "mac_sha256",
                                        "fresh_validation_receipt_sha256"}
                        _require(all(_eq(old[field], new[field]) for field in
                                     set(new) - without_time),
                                 "CODESAVE_IDEMPOTENCY_CONTENT_OR_APPROVAL_CONFLICT")
                        _require(now < st._parse_stamp(old["valid_until_utc"]),
                                 "CODESAVE_PREVIOUS_RECORD_EXPIRED_NO_REUSE", "unavailable")
                        return _accepted(old, store_pin, replay=True)
                    if old["source_binding"] == new["source_binding"] and old["candidate_sha256"] == new["candidate_sha256"]:
                        raise CodeSaveError("CODESAVE_SAME_CANDIDATE_DIFFERENT_OPERATION_CONFLICT")
                _require(len(records) < MAX_RECORDS,
                         "CODESAVE_PRIVATE_STORE_CAPACITY_EXHAUSTED", "unavailable")
                pins = (st._identity(fd), manifest["stage_dev"], manifest["stage_ino"],
                        manifest["repo_dev"], manifest["repo_ino"])
                self._pins_alive(fd, (pins[0], (pins[1], pins[2]), (pins[3], pins[4])))
                return self._publish(fd, manifest, key, new)
        except (CodeSaveError, cv.ValidateError, st.StageError, lc.LifecycleError) as exc:
            status = exc.status if exc.status in RESULT_STATUS else "unavailable"
            return _deny(status, exc.code, ambiguous=exc.code == "CODESAVE_PUBLISH_DURABILITY_UNCERTAIN")
        except (OSError, TypeError, ValueError, KeyError, IndexError, OverflowError,
                RecursionError, MemoryError):
            return _deny("unavailable", "CODESAVE_UNEXPECTED_IO_OR_UNTRUSTED_OBJECT_REFUSED")

    def _publish(self, fd: int, manifest: dict[str, Any], key: bytes,
                 record: dict[str, Any]) -> dict[str, Any]:
        record["mac_sha256"] = _mac(key, record)
        payload = st._canonical(record) + b"\n"
        _require(len(payload) <= MAX_RECORD_BYTES,
                 "CODESAVE_METADATA_RECORD_EXCEEDS_LIMIT")
        target = "save_" + record["save_operation_id"] + ".json"
        pending = ".pending-save-" + secrets.token_hex(16)
        linked = False
        pending_exists = False
        try:
            st._write_exclusive(fd, pending, payload)
            pending_exists = True
            self._pins_alive(fd, (st._identity(fd),
                                  (manifest["stage_dev"], manifest["stage_ino"]),
                                  (manifest["repo_dev"], manifest["repo_ino"])))
            os.link(pending, target, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            linked = True
            os.fsync(fd)
            os.unlink(pending, dir_fd=fd)
            pending_exists = False
            os.fsync(fd)
        except (OSError, st.StageError, CodeSaveError) as exc:
            if linked:
                # A target might exist, but caller cannot assert success.
                # Require operator inspection before another operation.
                raise CodeSaveError("CODESAVE_PUBLISH_DURABILITY_UNCERTAIN", "unavailable") from exc
            if pending_exists:
                try:
                    os.unlink(pending, dir_fd=fd)
                    os.fsync(fd)
                except OSError:
                    raise CodeSaveError("CODESAVE_PUBLISH_DURABILITY_UNCERTAIN", "unavailable") from exc
            if isinstance(exc, st.StageError):
                raise CodeSaveError(exc.code, exc.status) from exc
            raise CodeSaveError("CODESAVE_ATOMIC_PUBLISH_FAILED_NO_COMMIT", "unavailable") from exc
        return _accepted(record, _manifest_pin(manifest), replay=False)

    def read_saved(self, *, expected_save_store_pin: str, save_operation_key: str,
                   authorize_read: bool, read_content_for: str) -> dict[str, Any]:
        """Read HMAC-checked, unexpired *metadata*, never restore an AI Finding."""
        try:
            _require(authorize_read is True, "CODESAVE_RECORD_READ_REQUIRES_NEW_APPROVAL")
            lc._check_op(save_operation_key)
            _require(type(read_content_for) is str and read_content_for in lc.SOURCE_MODES,
                     "CODESAVE_RECORD_READ_SOURCE_SCOPE_INVALID")
            with self._locked() as (fd, manifest, key):
                assert manifest is not None and key is not None
                _require(_digest(expected_save_store_pin) and
                         hmac.compare_digest(expected_save_store_pin, _manifest_pin(manifest)),
                         "CODESAVE_READ_STORE_PIN_MISMATCH", "unavailable")
                rows = self._all(fd, key, manifest)
                name = _op_id(save_operation_key)
                for record in rows:
                    if record["save_operation_id"] == name:
                        _require(record["source_binding"]["source_mode"] == read_content_for,
                                 "CODESAVE_READ_SOURCE_SCOPE_MISMATCH")
                        _require(st._now(self.clock) < st._parse_stamp(record["valid_until_utc"]),
                                 "CODESAVE_STORED_EVIDENCE_EXPIRED", "unavailable")
                        return {
                            "schema": SCHEMA, "status": "partial", "exit_code": 2,
                            "reason_code": "CODESAVE_HMAC_METADATA_READ_NO_LIVE_PROOF",
                            "record": record, "finding_created": False,
                            "business_repository_written": False, "trust_boundary": TRUST,
                        }
                raise CodeSaveError("CODESAVE_RECORD_NOT_FOUND", "unavailable")
        except (st.StageError, lc.LifecycleError) as exc:
            status = exc.status if exc.status in RESULT_STATUS else "unavailable"
            return _deny(status, exc.code)
        except (OSError, TypeError, ValueError, KeyError, RecursionError, MemoryError):
            return _deny("unavailable", "CODESAVE_READ_UNAVAILABLE_OR_MALFORMED")

    def inspect(self, *, expected_save_store_pin: str) -> dict[str, Any]:
        """Only aggregate metadata counts; no source/AI/review text to inspect."""
        try:
            with self._locked() as (fd, manifest, key):
                assert manifest is not None and key is not None
                _require(_digest(expected_save_store_pin) and
                         hmac.compare_digest(expected_save_store_pin, _manifest_pin(manifest)),
                         "CODESAVE_INSPECT_STORE_PIN_MISMATCH", "unavailable")
                records = self._all(fd, key, manifest)
                now = st._now(self.clock)
                _require(all(now + timedelta(seconds=st.MAX_SKEW_SECONDS) >=
                             st._parse_stamp(r["saved_at_utc"]) for r in records),
                         "CODESAVE_LOCAL_CLOCK_ROLLBACK_UNAVAILABLE", "unavailable")
                return {
                    "schema": SCHEMA, "status": "success", "exit_code": 0,
                    "reason_code": "CODESAVE_PRIVATE_METADATA_STORE_INSPECTED",
                    "save_store_pin": _manifest_pin(manifest), "record_count": len(records),
                    "expired_count": sum(now >= st._parse_stamp(r["valid_until_utc"]) for r in records),
                    "capacity": MAX_RECORDS, "finding_created": False,
                    "business_repository_written": False, "trust_boundary": TRUST,
                }
        except (st.StageError, lc.LifecycleError) as exc:
            status = exc.status if exc.status in RESULT_STATUS else "unavailable"
            return _deny(status, exc.code)
        except (OSError, TypeError, ValueError, KeyError, RecursionError, MemoryError):
            return _deny("unavailable", "CODESAVE_INSPECT_UNAVAILABLE_OR_MALFORMED")


def main(argv: list[str] | None = None) -> int:
    """No CLI ingestion of secret review key or untrusted model text."""
    p = argparse.ArgumentParser(description="EC176 owner-private CES-only Staged CodeSave metadata store")
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument("--init", action="store_true")
    modes.add_argument("--inspect", action="store_true")
    modes.add_argument("--read", action="store_true")
    p.add_argument("--stage-root", required=True)
    p.add_argument("--business-repo-root", required=True)
    p.add_argument("--save-root", required=True)
    p.add_argument("--save-store-pin")
    p.add_argument("--save-operation-key")
    p.add_argument("--approve-init", action="store_true")
    p.add_argument("--approve-read", action="store_true")
    p.add_argument("--read-content-for", choices=sorted(lc.SOURCE_MODES))
    a = p.parse_args(argv)
    try:
        tool = StagedCodeSaver(a.stage_root, a.business_repo_root, a.save_root)
        if a.init:
            result = tool.initialize(approve_init=a.approve_init)
        elif a.inspect:
            result = tool.inspect(expected_save_store_pin=a.save_store_pin)
        else:
            result = tool.read_saved(expected_save_store_pin=a.save_store_pin,
                                     save_operation_key=a.save_operation_key,
                                     authorize_read=a.approve_read,
                                     read_content_for=a.read_content_for)
    except (st.StageError, lc.LifecycleError) as exc:
        result = _deny(exc.status if exc.status in RESULT_STATUS else "unavailable", exc.code)
    except (TypeError, ValueError, OSError):
        result = _deny("unavailable", "CODESAVE_CLI_TARGET_UNAVAILABLE_OR_INVALID")
    print(json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
