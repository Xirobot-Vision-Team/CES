#!/usr/bin/env python3
"""EC-165: bounded, reproducible *observation* receipts for GH/GL PR/MR files.

This standalone read-only consumer composes EC162/163/164. A receipt binds
validated commit pins, ordered sanitized pages, count/coverage, selected patch
outcomes, HTTP page validator *claims*, and actual consumption budgets.
The fingerprint is not authenticated and is NEVER a cross-page transaction.

Optional second acquisition compares all pages and, only after explicit EC164
permission, selected patch bytes. It can detect drift but cannot eliminate
concurrent changes or guarantee that different pages existed simultaneously.
Only optional local Git ls-tree binds a *local* single-file blob to the exact
pinned head commit; that is not provider-signed provenance.

No user repository writes, ref resolution, raw-diff endpoints, local caches,
remote merge/write calls or native PowerShell Collect routing exist here.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable

import proposed_pr_identity as identity
import proposed_pr_patch as patch
import proposed_pr_paths as paths
import proposed_pr_source as source

SCHEMA = "ces.proposed_pr_snapshot.v1"
MATERIAL_SCHEMA = "ces.proposed_pr_snapshot_material.v1"
DOMAIN = b"CES-EC165-READONLY-OBSERVATION-RECEIPT-v1\0"
FILES_DOMAIN = b"CES-EC165-VALIDATED-PATHS-v1\0"
PAGE_DOMAIN = b"CES-EC165-PAGE-METADATA-v1\0"
PATCH_DOMAIN = b"CES-EC165-EXPLICIT-PATCH-v1\0"
ETAG_DOMAIN = b"CES-EC165-HTTP-ETAG-CLAIM-v1\0"
MAX_VERIFICATION_FILE_BYTES = 4 * 1024 * 1024
MAX_LOCAL_GIT_OUTPUT_BYTES = 4096


@dataclass(frozen=True)
class SnapshotSelection:
    """Exact paths may be version-observed without authorizing patch output."""
    paths: tuple[str, ...] = ()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      allow_nan=False, separators=(",", ":")).encode("ascii")


def _hash(domain: bytes, value: Any) -> str:
    return "sha256:" + hashlib.sha256(domain + _canonical(value)).hexdigest()


def _bytes_hash(domain: bytes, value: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + value).hexdigest()


def fingerprint(material: dict[str, Any]) -> str:
    return _hash(DOMAIN, material)


def _safe_selected(value: SnapshotSelection) -> tuple[str, ...]:
    if type(value) is not SnapshotSelection or type(value.paths) not in (tuple, list):
        raise source.SourceFailure("SNAPSHOT_SELECTION_INVALID",
                                   "Selected paths have an invalid shape.", "invalid_input")
    if len(value.paths) > patch.MAX_SELECTED_FILES:
        raise source.SourceFailure("SNAPSHOT_SELECTION_INVALID",
                                   "Choose at most five exact changed paths.", "invalid_input")
    clean: list[str] = []
    unique: set[str] = set()
    for candidate in value.paths:
        try:
            safe = paths._safe_path(candidate)
        except source.SourceFailure:
            raise source.SourceFailure("SNAPSHOT_SELECTION_INVALID",
                                       "Selected path is unsafe.", "invalid_input") from None
        if (any(ch in safe for ch in "*?[]{}") or
                safe.casefold() in unique or patch._blocked_path(safe)):
            raise source.SourceFailure("SNAPSHOT_SELECTION_INVALID",
                                       "Selected path is ambiguous or potentially sensitive.", "invalid_input")
        unique.add(safe.casefold())
        clean.append(safe)
    return tuple(clean)


def _empty(status: str, reason: str, message: str, *, synthetic: bool = False) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": status,
        "exit_code": {"success": 0, "partial": 2, "invalid_input": 4, "unavailable": 5}[status],
        "reason_code": reason, "message": message,
        "observation_ref": None, "evidence_material": None,
        "patch_evidence": None,
        "version_consistency": {
            "state": "NOT_ESTABLISHED", "provider_atomic_snapshot": False,
            "provider_immutable_diff_version_id": None, "missing_independent_proofs": [
                "PROVIDER_IMMUTABLE_DIFF_VERSION_OR_ATOMIC_SNAPSHOT_TOKEN",
                "PROVIDER_TRANSACTION_SPANNING_METADATA_AND_ALL_PAGES",
            ],
        },
        "synthetic": synthetic,
        "native_cli_action_registered": False, "diff_snapshot_proven": False,
        "provider_actor_verified": False, "delivery_or_merge_proven": False,
        "write_authorized": False,
    }


def _page_receipt(page_number: int, page: paths.FilePage,
                  clean_items: list[dict[str, Any]], next_page: int | None) -> dict[str, Any]:
    # Do not expose raw response SHA: JSON pages can contain *unselected*
    # sensitive source patches, which would become a public equality oracle.
    etag = page.headers.get("etag")
    strength = "ABSENT" if etag is None else ("WEAK" if etag.startswith("W/") else "STRONG")
    return {
        "page": page_number, "entries": len(clean_items),
        "sanitized_paths_digest": _hash(PAGE_DOMAIN, clean_items),
        "response_bytes_observed": page.byte_count,
        "next_page": next_page,
        "etag_kind": strength,
        "etag_claim_digest": _bytes_hash(ETAG_DOMAIN, etag.encode("ascii")) if etag else None,
        "last_modified_claim_present": "last-modified" in page.headers,
        "raw_response_digest_disclosed": False,
    }


def _patch_claims(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for row in evidence["patches"]:
        text = row["patch_text"]
        records.append({
            "path": row["path"], "availability": row["availability"],
            "emitted_utf8_bytes": row["utf8_bytes"],
            "released_patch_digest": _bytes_hash(PATCH_DOMAIN, text.encode("utf-8"))
            if text is not None else None,
        })
    return records


def _local_git_blob(local_git: str, head_sha: str, file_path: str) -> tuple[str, str | None]:
    """Read exactly one path at the complete commit OID, never a mutable ref."""
    try:
        root = Path(local_git)
        if (type(local_git) is not str or not root.is_absolute() or
                not root.is_dir() or root.is_symlink() or len(local_git) > 4096):
            return "LOCAL_REPOSITORY_UNAVAILABLE", None
        cmd = ["git", "--no-optional-locks", "-C", str(root), "ls-tree",
               "--full-tree", "-r", "-z", head_sha, "--", ":(literal)" + file_path]
        run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, timeout=identity.LOCAL_GIT_TIMEOUT,
                             env=identity._git_environment(), check=False)
        if run.returncode != 0 or len(run.stdout) > MAX_LOCAL_GIT_OUTPUT_BYTES:
            return "LOCAL_OBJECT_UNAVAILABLE", None
        if not run.stdout:
            return "LOCAL_FILE_NOT_IN_PINNED_HEAD", None
        if not run.stdout.endswith(b"\0") or run.stdout.count(b"\0") != 1:
            return "LOCAL_TREE_RESPONSE_UNVERIFIED", None
        header, marker, encoded_path = run.stdout[:-1].partition(b"\t")
        parts = header.split(b" ")
        if (not marker or len(parts) != 3 or parts[0] not in (b"100644", b"100755") or
                parts[1] != b"blob" or encoded_path != file_path.encode("utf-8")):
            return "LOCAL_TREE_RESPONSE_UNVERIFIED", None
        oid = parts[2].decode("ascii")
        if (not source._commit_sha(oid) or len(oid) != len(head_sha) or
                oid != oid.lower()):
            return "LOCAL_TREE_RESPONSE_UNVERIFIED", None
        return "LOCAL_HEAD_COMMIT_TREE_BOUND", oid
    except (OSError, subprocess.TimeoutExpired, UnicodeError, ValueError, TypeError):
        return "LOCAL_OBJECT_UNAVAILABLE", None


def _file_versions(selected: tuple[str, ...], all_files: list[dict[str, Any]],
                   raw_claims: dict[str, str | None], pin: dict[str, Any],
                   local_git: str | None) -> tuple[list[dict[str, Any]], bool]:
    mapped = {row["new_path"] or row["old_path"]: row for row in all_files}
    records: list[dict[str, Any]] = []
    disagreement = False
    for name in selected:
        row = mapped[name]
        provider_blob = raw_claims.get(name) if pin["provider"] == "github" else None
        info: dict[str, Any] = {
            "path": name, "head_commit_oid": pin["head_sha"],
            "provider_declared_blob_oid": provider_blob,
            "provider_blob_membership_independently_verified": False,
            "local_blob_oid": None, "local_git_scope": "NOT_REQUESTED",
            "status": "PROVIDER_BLOB_CLAIM_ONLY" if provider_blob else "FILE_VERSION_UNKNOWN",
        }
        if row["new_path"] is None:
            info["status"] = "DELETED_PATH_NO_HEAD_BLOB"
        elif local_git is not None:
            status, blob = _local_git_blob(local_git, pin["head_sha"], name)
            info["status"] = status
            info["local_git_scope"] = "LOCAL_OBJECT_DATABASE_NOT_PROVIDER_ATTESTATION"
            info["local_blob_oid"] = blob
            if status == "LOCAL_HEAD_COMMIT_TREE_BOUND" and provider_blob is not None and blob != provider_blob:
                disagreement = True
                info["status"] = "PROVIDER_LOCAL_BLOB_CONFLICT"
        records.append(info)
    return records, disagreement


def _capture_once(
    key: source.RequestKey, expected_pin: dict[str, Any] | None, *,
    allow_network: bool, include_patch_content: bool,
    acknowledge_provider_permission: bool, content_policy: patch.ContentPolicy | None,
    selected: tuple[str, ...], token_supplier: Callable[[], str | None] | None,
    transport: paths.PathsTransport | None, timeout: float, per_page: int,
    max_pages: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str | None], dict[str, str | None]]:
    pages: list[dict[str, Any]] = []
    raw_digests: list[str | None] = []  # private: never output to JSON/receipt
    claims: dict[str, str | None] = {}
    wanted = set(selected)

    def page_seen(number: int, actual: paths.FilePage,
                  safe_entries: list[dict[str, Any]], next_page: int | None) -> None:
        pages.append(_page_receipt(number, actual, safe_entries, next_page))
        raw_digests.append(actual.raw_body_sha256)

    def file_seen(rows: list[tuple[dict[str, Any], dict[str, Any]]]) -> None:
        for raw, cleaned in rows:
            name = cleaned["new_path"] or cleaned["old_path"]
            if name not in wanted:
                continue
            if name in claims:
                raise source.SourceFailure("FILE_VERSION_SELECTION_AMBIGUOUS",
                                           "The selected changed file was repeated.")
            if key.provider == "github" and raw.get("sha") is not None:
                sha = raw["sha"]
                if (type(sha) is not str or source._commit_sha(sha) != sha or
                        len(sha) not in (40, 64)):
                    raise source.SourceFailure("PROVIDER_BLOB_CLAIM_INVALID",
                                               "Selected file's provider blob OID was invalid.")
                claims[name] = sha
            else:
                claims[name] = None

    evidence = patch.collect_proposed_pr_patch(
        key, expected_pin=expected_pin, allow_network=allow_network,
        include_patch_content=include_patch_content,
        acknowledge_provider_permission=acknowledge_provider_permission,
        policy=content_policy, token_supplier=token_supplier, transport=transport,
        timeout=timeout, per_page=per_page, max_pages=max_pages,
        _validated_page_receipt_observer=page_seen,
        _validated_file_evidence_observer=file_seen,
    )
    return evidence, pages, raw_digests, claims


def collect_proposed_pr_snapshot(
    key: source.RequestKey, *, expected_pin: dict[str, Any] | None,
    allow_network: bool = False, include_patch_content: bool = False,
    acknowledge_provider_permission: bool = False,
    content_policy: patch.ContentPolicy | None = None,
    selection: SnapshotSelection = SnapshotSelection(),
    local_git: str | None = None,
    recheck_pages: bool = False,
    token_supplier: Callable[[], str | None] | None = None,
    transport: paths.PathsTransport | None = None,
    timeout: float = 8.0, per_page: int = paths.DEFAULT_PAGE_SIZE,
    max_pages: int = paths.DEFAULT_MAX_PAGES,
) -> dict[str, Any]:
    """Create a non-authoritative bound observation, never an atomic snapshot."""
    synthetic = transport is not None
    try:
        # Preflight: never call token/network before discovering invalid flags,
        # selection, basic Git path or patch authorization/size constraints.
        if type(recheck_pages) is not bool or type(include_patch_content) is not bool:
            raise source.SourceFailure("SNAPSHOT_FLAGS_INVALID",
                                       "Snapshot flags must be booleans.", "invalid_input")
        selected = _safe_selected(selection)
        if include_patch_content:
            if type(content_policy) is not patch.ContentPolicy:
                raise source.SourceFailure("PATCH_SELECTION_REQUIRED",
                                           "Explicit patch policy is required.", "invalid_input")
            authorized = patch._safe_selected_paths(content_policy)
            if any(patch._blocked_path(p) for p in authorized):
                raise source.SourceFailure("PATCH_SENSITIVE_PATH_REJECTED",
                                           "Selected patch path is sensitive.", "invalid_input")
            if selected and selected != authorized:
                raise source.SourceFailure("SNAPSHOT_PATCH_SELECTION_CONFLICT",
                                           "Version and patch selections disagree.", "invalid_input")
            selected = authorized
        elif content_policy is not None:
            raise source.SourceFailure("SNAPSHOT_PATCH_POLICY_UNUSED",
                                       "Content policy requires patch-content opt-in.", "invalid_input")
        if local_git is not None and (type(local_git) is not str or not local_git or
                                      not Path(local_git).is_absolute() or len(local_git) > 4096):
            raise source.SourceFailure("SNAPSHOT_LOCAL_REPOSITORY_INVALID",
                                       "Local Git repository must be an absolute directory path.", "invalid_input")
        if local_git is not None and not selected:
            raise source.SourceFailure("SNAPSHOT_LOCAL_SELECTION_REQUIRED",
                                       "Select specific paths for local blob binding.", "invalid_input")
    except source.SourceFailure as exc:
        return _empty(exc.status, exc.reason, exc.message, synthetic=synthetic)

    first, first_pages, first_raw, first_blobs = _capture_once(
        key, expected_pin, allow_network=allow_network,
        include_patch_content=include_patch_content,
        acknowledge_provider_permission=acknowledge_provider_permission,
        content_policy=content_policy, selected=selected, token_supplier=token_supplier,
        transport=transport, timeout=timeout, per_page=per_page, max_pages=max_pages,
    )
    base = first.get("path_evidence")
    if (first["status"] not in ("success", "partial") or
            type(base) is not dict or not base.get("path_metadata_collected")):
        return _empty(first["status"], first["reason_code"],
                      "No bound evidence: prior pin, permissions, pagination or provider read failed.",
                      synthetic=synthetic)
    pin = base["pin"]
    # A provider blob claim must use the exact hash algorithm pinned for this
    # request. A valid-looking SHA-1 on a SHA-256 repository is still drift.
    if any(oid is not None and len(oid) != len(pin["head_sha"])
           for oid in first_blobs.values()):
        return _empty("unavailable", "PROVIDER_BLOB_OBJECT_FORMAT_CONFLICT",
                      "Selected file blob hash format disagrees with the pinned commit format.",
                      synthetic=synthetic)
    # EC163 may return only a subset; that subset can have a receipt, but it
    # must never be mistaken for the full changed-file set or a full diff.
    covered = base["coverage"]["state"] == "COMPLETE"
    available_paths = {f["new_path"] or f["old_path"] for f in base["files"]}
    if covered and any(path not in available_paths or path not in first_blobs for path in selected):
        return _empty("invalid_input", "SNAPSHOT_PATH_NOT_IN_COMPLETE_LIST",
                      "Selected path was not present in the complete validated list.", synthetic=synthetic)
    if len(first_pages) != base["coverage"]["pages_read"] or (
        sum(row["entries"] for row in first_pages) != len(base["files"])
    ):
        return _empty("unavailable", "SNAPSHOT_PAGE_RECEIPT_MISMATCH",
                      "Validated metadata and page receipts disagreed.", synthetic=synthetic)

    replay = {"requested": recheck_pages, "performed": False,
              "matching_pages": 0, "matching_raw_responses": 0,
              "raw_response_comparison_unavailable": 0,
              "bounded_total_response_bytes": sum(p["response_bytes_observed"] for p in first_pages),
              "state": "NOT_REQUESTED" if not recheck_pages else "NOT_ELIGIBLE_INCOMPLETE"}
    if recheck_pages and covered:
        second, later_pages, later_raw, later_blobs = _capture_once(
            key, expected_pin, allow_network=allow_network,
            include_patch_content=include_patch_content,
            acknowledge_provider_permission=acknowledge_provider_permission,
            content_policy=content_policy, selected=selected, token_supplier=token_supplier,
            transport=transport, timeout=timeout, per_page=per_page, max_pages=max_pages,
        )
        after_base = second.get("path_evidence")
        if any(oid is not None and len(oid) != len(pin["head_sha"])
               for oid in later_blobs.values()):
            return _empty("unavailable", "SNAPSHOT_RECHECK_DRIFT_OR_UNAVAILABLE",
                          "Second provider blob format changed; evidence withheld.", synthetic=synthetic)
        if (second["status"] not in ("success", "partial") or
                type(after_base) is not dict or
                after_base.get("coverage", {}).get("state") != "COMPLETE" or
                after_base["pin"] != pin or
                after_base["coverage"] != base["coverage"] or
                after_base["files"] != base["files"] or
                later_pages != first_pages or later_blobs != first_blobs or
                _patch_claims(second) != _patch_claims(first)):
            return _empty("unavailable", "SNAPSHOT_RECHECK_DRIFT_OR_UNAVAILABLE",
                          "Second bounded read differed or could not complete; all initial evidence withheld.",
                          synthetic=synthetic)
        raw_same = 0
        unknown = 0
        if len(first_raw) != len(later_raw):
            return _empty("unavailable", "SNAPSHOT_RECHECK_DRIFT_OR_UNAVAILABLE",
                          "Re-read page count changed; evidence withheld.", synthetic=synthetic)
        for initial, repeat in zip(first_raw, later_raw):
            if initial is None or repeat is None:
                unknown += 1
            elif initial != repeat:
                return _empty("unavailable", "SNAPSHOT_RAW_PAGE_CHANGED",
                              "Provider response bytes changed during re-read; evidence withheld.",
                              synthetic=synthetic)
            else:
                raw_same += 1
        replay = {
            "requested": True, "performed": True, "matching_pages": len(first_pages),
            "matching_raw_responses": raw_same,
            "raw_response_comparison_unavailable": unknown,
            "bounded_total_response_bytes": sum(r["response_bytes_observed"] for r in first_pages + later_pages),
            "state": "OBSERVED_TWO_READS_MATCHED_NOT_ATOMIC",
        }

    if not covered:
        file_versions: list[dict[str, Any]] = []
    else:
        file_versions, conflict = _file_versions(selected, base["files"], first_blobs,
                                                 pin, local_git)
        if conflict:
            return _empty("unavailable", "SNAPSHOT_LOCAL_PROVIDER_BLOB_CONFLICT",
                          "Pinned local head blob conflicts with selected provider blob claim.",
                          synthetic=synthetic)

    counts = {"strong_etags": sum(p["etag_kind"] == "STRONG" for p in first_pages),
              "weak_etags": sum(p["etag_kind"] == "WEAK" for p in first_pages),
              "missing_etags": sum(p["etag_kind"] == "ABSENT" for p in first_pages),
              "last_modified_claims": sum(p["last_modified_claim_present"] for p in first_pages)}
    missing = ["PROVIDER_IMMUTABLE_DIFF_VERSION_OR_ATOMIC_SNAPSHOT_TOKEN",
               "PROVIDER_TRANSACTION_SPANNING_METADATA_AND_ALL_PAGES"]
    if counts["missing_etags"] or counts["weak_etags"]:
        missing.append("STRONG_HTTP_REPRESENTATION_VALIDATOR_FOR_EACH_PAGE")
    if not replay["performed"]:
        missing.append("INDEPENDENT_PAGINATION_RECHECK")
    elif replay["raw_response_comparison_unavailable"]:
        missing.append("RAW_HTTP_RESPONSE_IDENTITY_FOR_EVERY_RECHECKED_PAGE")
    if not covered:
        missing.append("COMPLETE_CHANGED_FILE_PAGINATION")
    if not all(row["status"] == "LOCAL_HEAD_COMMIT_TREE_BOUND" for row in file_versions):
        if selected:
            missing.append("SELECTED_LOCAL_COMMIT_TREE_BLOB_EVIDENCE")

    version = {
        "state": ("INCOMPLETE_OR_UNKNOWN_PATH_COVERAGE" if not covered else
                  "OBSERVATIONS_RECHECKED_NOT_ATOMIC" if replay["performed"] else
                  "OBSERVATION_ONLY_PROVIDER_VERSION_UNKNOWN"),
        "provider_atomic_snapshot": False,
        "provider_immutable_diff_version_id": None,
        "provider_page_validators": counts,
        "replay": replay,
        "single_file_version_scope": "LOCAL_COMMIT_TREE_ONLY" if any(
            row["status"] == "LOCAL_HEAD_COMMIT_TREE_BOUND" for row in file_versions)
            else "PROVIDER_BLOB_CLAIM_OR_UNKNOWN",
        "missing_independent_proofs": missing,
    }
    disclosure = {
        "requested": first["patch_content_requested"],
        "selected_paths": list(selected),
        "content_policy": first["content_policy"],
        "selected_patch_outcomes": _patch_claims(first),
        "withheld_by_policy_or_provider": any(
            item["availability"] != "AVAILABLE" for item in first["patches"]),
    }
    material = {
        "schema": MATERIAL_SCHEMA,
        "pin": pin,
        "pin_fingerprint": base["pin_fingerprint"],
        "synthetic": base["synthetic"],
        "observed_metadata_utc": base["metadata_observations_utc"],
        "path_coverage": base["coverage"],
        "ordered_files_digest": _hash(FILES_DOMAIN, base["files"]),
        "ordered_pages": first_pages,
        "request_budgets": {
            "per_page": per_page, "max_pages": max_pages,
            "max_response_bytes_per_page": paths.MAX_PAGE_BYTES,
            "max_response_bytes_per_pass": paths.MAX_TOTAL_RESPONSE_BYTES,
            "max_files_per_pass": paths.MAX_FILES,
            "pages_read": len(first_pages),
            "response_bytes_observed_first_pass": sum(
                item["response_bytes_observed"] for item in first_pages),
        },
        "patch_disclosure": disclosure,
        "selected_file_versions": file_versions,
        "version_consistency": version,
    }
    output = _empty("partial", "OBSERVATION_BOUND_NONATOMIC",
                    "Recomputable non-authenticating observation; not a provider-atomic diff snapshot.",
                    synthetic=synthetic)
    output["observation_ref"] = fingerprint(material)
    output["evidence_material"] = material
    output["patch_evidence"] = first
    output["version_consistency"] = version
    if not covered:
        output["reason_code"] = "INCOMPLETE_PATH_COVERAGE_RECEIPT"
        output["message"] = "Bounded subset only; unlisted paths or patches may exist."
    elif recheck_pages:
        output["reason_code"] = "NONATOMIC_RECHECKED_OBSERVATIONS"
    # There is deliberately no success/0 code without genuine immutable
    # provider version + across-page atomicity evidence.
    return output


def verify_receipt(data: Any) -> dict[str, Any]:
    """Offline internal cross-check: no truth, permissions or authenticity proof."""
    failures: list[str] = []
    try:
        if type(data) is not dict or data.get("schema") != SCHEMA:
            raise ValueError("SCHEMA_MISMATCH")
        material = data["evidence_material"]
        if (type(material) is not dict or material.get("schema") != MATERIAL_SCHEMA or
                data.get("observation_ref") != fingerprint(material)):
            raise ValueError("MATERIAL_FINGERPRINT_MISMATCH")
        outer = data["patch_evidence"]
        base = outer["path_evidence"]
        if (data["diff_snapshot_proven"] is not False or
                data["write_authorized"] is not False or
                data["native_cli_action_registered"] is not False or
                data["provider_actor_verified"] is not False or
                data["delivery_or_merge_proven"] is not False or
                data["version_consistency"] != material["version_consistency"] or
                material["version_consistency"]["provider_atomic_snapshot"] is not False or
                data["synthetic"] != material["synthetic"] or
                data["status"] != "partial" or data["exit_code"] != 2):
            raise ValueError("BOUNDARY_CLAIM_MISMATCH")
        if (material["pin"] != base["pin"] or
                material["pin_fingerprint"] != base["pin_fingerprint"] or
                identity.fingerprint_of(material["pin"]) != material["pin_fingerprint"] or
                not identity._valid_pin(material["pin"]) or
                material["path_coverage"] != base["coverage"] or
                material["observed_metadata_utc"] != base["metadata_observations_utc"] or
                material["ordered_files_digest"] != _hash(FILES_DOMAIN, base["files"])):
            raise ValueError("PIN_PATH_EVIDENCE_MISMATCH")
        disclosure = material["patch_disclosure"]
        if (disclosure["requested"] != outer["patch_content_requested"] or
                disclosure["content_policy"] != outer["content_policy"] or
                disclosure["selected_patch_outcomes"] != _patch_claims(outer)):
            raise ValueError("PATCH_DISCLOSURE_EVIDENCE_MISMATCH")
        pages = material["ordered_pages"]
        budget = material["request_budgets"]
        if (type(pages) is not list or
                [p["page"] for p in pages] != list(range(1, len(pages) + 1)) or
                sum(p["entries"] for p in pages) != len(base["files"]) or
                len(pages) != base["coverage"]["pages_read"] or
                len(pages) != budget["pages_read"] or
                sum(p["response_bytes_observed"] for p in pages) != budget["response_bytes_observed_first_pass"] or
                any(p["response_bytes_observed"] > budget["max_response_bytes_per_page"] or
                    p["entries"] > budget["per_page"] or
                    p["raw_response_digest_disclosed"] is not False for p in pages) or
                budget["max_response_bytes_per_pass"] != paths.MAX_TOTAL_RESPONSE_BYTES or
                budget["max_response_bytes_per_page"] != paths.MAX_PAGE_BYTES or
                budget["max_files_per_pass"] != paths.MAX_FILES or
                budget["response_bytes_observed_first_pass"] > paths.MAX_TOTAL_RESPONSE_BYTES):
            raise ValueError("PAGE_BUDGET_RECEIPT_MISMATCH")
        # Each page digest can be independently recalculated from the exact
        # ordered public sanitized file rows, without raw/secret patches.
        cursor = 0
        for p in pages:
            section = base["files"][cursor: cursor + p["entries"]]
            if p["sanitized_paths_digest"] != _hash(PAGE_DOMAIN, section):
                raise ValueError("ORDERED_PAGE_DIGEST_MISMATCH")
            cursor += p["entries"]
        if (any((p["next_page"] != p["page"] + 1) for p in pages[:-1]) or
                budget["per_page"] < 1 or budget["per_page"] > paths.MAX_PAGE_SIZE or
                budget["max_pages"] < 1 or budget["max_pages"] > paths.MAX_PAGES or
                len(pages) > budget["max_pages"] or
                not material["version_consistency"]["provider_atomic_snapshot"] is False):
            raise ValueError("PAGE_SEQUENCE_OR_SCOPE_MISMATCH")
        if material["path_coverage"]["state"] == "COMPLETE" and (
            pages and pages[-1]["next_page"] is not None
        ):
            raise ValueError("PAGINATION_COMPLETION_MISMATCH")
    except (KeyError, IndexError, TypeError, ValueError, OverflowError, AttributeError) as exc:
        failures.append(str(exc) if isinstance(exc, ValueError) else "RECEIPT_SHAPE_INVALID")
    return {"status": "INTERNALLY_CONSISTENT_ONLY" if not failures else "INVALID",
            "reason_codes": failures,
            "provider_authenticity_verified": False,
            "cross_page_atomicity_verified": False,
            "remote_source_rechecked_by_verifier": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC165 bounded non-atomic PR/MR observation receipts")
    parser.add_argument("--provider", choices=("github", "gitlab"))
    parser.add_argument("--repository")
    parser.add_argument("--number", type=int)
    parser.add_argument("--expected-pin", metavar="EC162_RESULT_JSON")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--include-patch-content", action="store_true")
    parser.add_argument("--ack-provider-content-permission", action="store_true")
    parser.add_argument("--path", action="append", default=[], metavar="EXACT_FILE")
    parser.add_argument("--max-patch-bytes", type=int, default=patch.DEFAULT_MAX_PATCH_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=patch.DEFAULT_TOTAL_PATCH_BYTES)
    parser.add_argument("--local-git", metavar="ABSOLUTE_READONLY_GIT_PATH")
    parser.add_argument("--recheck-pages", action="store_true")
    parser.add_argument("--per-page", type=int, default=paths.DEFAULT_PAGE_SIZE)
    parser.add_argument("--max-pages", type=int, default=paths.DEFAULT_MAX_PAGES)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--verify-input", metavar="SNAPSHOT_JSON")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.verify_input:
        try:
            blob = Path(args.verify_input).read_bytes()
            if len(blob) > MAX_VERIFICATION_FILE_BYTES:
                raise ValueError("verification input too large")
            result = verify_receipt(source._decode_object(blob))
        except (OSError, ValueError, source.SourceFailure):
            result = {"status": "INVALID", "reason_codes": ["INPUT_UNAVAILABLE_OR_INVALID"],
                      "provider_authenticity_verified": False,
                      "cross_page_atomicity_verified": False,
                      "remote_source_rechecked_by_verifier": False}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["status"] == "INTERNALLY_CONSISTENT_ONLY" else 4
    if not args.provider or not args.repository or args.number is None or not args.expected_pin:
        result = _empty("invalid_input", "SNAPSHOT_REQUEST_REQUIRED",
                        "Provide provider, repository, number and prior EC162 result.")
    else:
        try:
            expected = identity._read_expected(args.expected_pin)
        except Exception:
            result = _empty("invalid_input", "INVALID_EXPECTED_PIN",
                            "Previous EC162 result cannot be validated.")
        else:
            result = collect_proposed_pr_snapshot(
                source.RequestKey(args.provider, args.repository, args.number),
                expected_pin=expected, allow_network=args.allow_network,
                include_patch_content=args.include_patch_content,
                acknowledge_provider_permission=args.ack_provider_content_permission,
                content_policy=patch.ContentPolicy(tuple(args.path), args.max_patch_bytes, args.max_total_bytes)
                if args.include_patch_content else None,
                selection=SnapshotSelection(tuple(args.path)),
                local_git=args.local_git, recheck_pages=args.recheck_pages,
                timeout=args.timeout, per_page=args.per_page, max_pages=args.max_pages,
            )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
