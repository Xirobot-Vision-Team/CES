#!/usr/bin/env python3
"""EC-153: read-only, non-authoritative reconciliation for *candidate* upstream files.

This reports what the received CES package can prove and offers an overlap-only
comparison when a person supplies candidate V3.10 / ROUNDS files. A candidate's
name, content, structure and digest do NOT authenticate its origin. This program
never copies evidence, edits plans, closes blockers, executes Git/PowerShell or
makes claims about native CES acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MAX_INPUT_BYTES = 32 * 1024 * 1024
ROUND_ID = re.compile(r"EC-\d{3}")
DIFF_FIELDS = ("title", "scope", "exit_gate", "depends_on")


class InputError(ValueError):
    """Expected, user-actionable error; do not expose a traceback."""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InputError(f"Cannot parse package evidence {path.name}: {exc}") from exc


def _package_evidence(root: Path) -> dict[str, Any]:
    """Only bounded negative evidence: R150 inventory + historical statement."""
    ledger = _load_json(root / "construction/LEGACY_UPSTREAM_GAP.json")
    inventory = _load_json(root / "construction/LEGACY_SOURCE_INVENTORY.json")
    blockers = _load_json(root / "construction/KNOWN_BLOCKERS.json")
    plan = _load_json(root / "construction/LEGACY_PLAN.json")
    legacy = _load_json(root / "history/legacy-docs/BUILD_STATE-R150.json")
    errors: list[str] = []
    files = inventory.get("files", [])
    paths = {x.get("original_path") for x in files if isinstance(x, dict)}
    relocated = {x.get("located_path") for x in files if isinstance(x, dict)}
    no_original_rounds = "ROUNDS.json" not in paths and "ROUNDS.json" not in relocated
    note = legacy.get("reference_authority_note", "")
    history_declares_missing = all(x in note for x in ("V3.10", "ROUNDS.json", "not present"))
    blocker = next((b for b in blockers.get("blockers", []) if b.get("id") == "B-001"), None)
    blocker_status = blocker.get("state") if blocker else None
    if ledger.get("schema_version") != "ces.ec153.upstream_gap.v1":
        errors.append("Unexpected EC153 gap-ledger schema")
    if inventory.get("counts", {}).get("total_original_paths") != 305 or len(files) != 305:
        errors.append("EC151 original inventory does not contain 305 paths")
    if not no_original_rounds:
        errors.append("Original ROUNDS.json now appears in R150 inventory; recheck provenance")
    if not history_declares_missing:
        errors.append("R150 historical absence declaration is missing or was altered")
    if blocker_status != "OPEN_NON_BLOCKING_FOR_PROVISIONAL_PLAN":
        errors.append("B-001 status changed; must reconcile with source provenance")
    if plan.get("plan_id") != "CES-RECOVERY-100" or "unknown_original" not in plan:
        errors.append("Recovery plan identity/unknown-original disclaimer is missing")
    if ledger.get("blocker_id") != "B-001" or ledger.get("original_inventory_path_count") != 305:
        errors.append("Gap ledger disagrees with original inventory/blocker")
    if (root / "ROUNDS.json").exists():
        errors.append("Top-level ROUNDS.json appeared; do not silently treat it as upstream-authenticated")
    return {
        "evidence_consistent": not errors,
        "evidence_issues": errors,
        "original_inventory_count": len(files),
        "original_rounds_in_inventory": not no_original_rounds,
        "historical_absence_declaration": history_declares_missing,
        "historical_reference": "history/legacy-docs/BUILD_STATE-R150.json:reference_authority_note",
        "recorded_blocker": blocker_status,
        "provisional_plan": "construction/LEGACY_PLAN.json",
        "limits": "Original V3.10 filename is unknown. Inventory absence cannot establish global nonexistence or authenticate later inputs.",
    }


def _read_candidate(path_text: str, role: str) -> tuple[dict[str, Any], bytes]:
    path = Path(path_text).expanduser()
    if path.is_symlink() or not path.is_file():
        raise InputError(f"{role}: provide a regular, non-symlink file")
    try:
        size = path.stat().st_size
        if size > MAX_INPUT_BYTES:
            raise InputError(f"{role}: input is larger than the {MAX_INPUT_BYTES}-byte read-only limit")
        payload = path.read_bytes()
    except OSError as exc:
        raise InputError(f"{role}: cannot read candidate: {exc.strerror}") from exc
    if len(payload) > MAX_INPUT_BYTES:
        raise InputError(f"{role}: input changed size during reading")
    # Do not include raw content or full user paths in report output.
    return {
        "provided": True,
        "source_trust": "USER_SUPPLIED_UNAUTHENTICATED",
        "filename": path.name,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "content_echoed": False,
    }, payload


def _describe_spec(payload: bytes, filename: str) -> dict[str, Any]:
    """A digest and low-disclosure format observation, NOT specification review."""
    suffix = Path(filename).suffix.lower()
    if suffix == ".json":
        try:
            obj = _candidate_json(payload)
        except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
            return {"format": "json", "structural_state": "INVALID_JSON", "semantic_comparison": "NOT_AVAILABLE"}
        return {"format": "json", "structural_state": type(obj).__name__, "semantic_comparison": "NO_AUTHENTICATED_COMPARATOR"}
    if suffix in (".md", ".markdown", ".txt"):
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError:
            return {"format": "text", "structural_state": "NOT_UTF8", "semantic_comparison": "NOT_AVAILABLE"}
        return {
            "format": "text",
            "structural_state": "UTF8_READABLE",
            "heading_count": sum(bool(re.match(r"^\s{0,3}#{1,6}\s", line)) for line in text.splitlines()),
            "mentions_v3_10": "V3.10" in text,
            "semantic_comparison": "NO_AUTHENTICATED_COMPARATOR",
        }
    return {"format": suffix or "unknown", "structural_state": "BINARY_OR_UNRECOGNIZED", "semantic_comparison": "NOT_AVAILABLE"}


def _candidate_json(payload: bytes) -> Any:
    """Reject ambiguous duplicate keys and non-standard JSON constants."""
    def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise ValueError("non-standard JSON constant")

    return json.loads(payload.decode("utf-8-sig"), object_pairs_hook=strict_pairs, parse_constant=reject_constant)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _normalized_rounds(obj: Any) -> tuple[dict[str, dict[str, Any]] | None, dict[str, Any]]:
    """Extract ONLY exact EC identifiers. An unknown schema is not guessed."""
    if isinstance(obj, dict):
        rows = obj.get("rounds")
        shape = "object.rounds"
    else:
        rows = obj
        shape = "array"
    if not isinstance(rows, list):
        return None, {"shape": "UNRECOGNIZED", "comparison_status": "UNRECOGNIZED_SCHEMA"}
    if len(rows) > 10000:
        return None, {"shape": shape, "comparison_status": "OVERSIZE_ROUND_SET", "round_count": len(rows)}
    index: dict[str, dict[str, Any]] = {}
    invalid_rows = 0
    duplicate_ids: list[str] = []
    conflicting_identifiers = 0
    for row in rows:
        if not isinstance(row, dict):
            invalid_rows += 1
            continue
        ec = row.get("ec")
        number = row.get("round")
        if not isinstance(ec, str) or not ROUND_ID.fullmatch(ec):
            invalid_rows += 1
            continue
        if number is not None and (type(number) is not int or f"EC-{number:03d}" != ec):
            conflicting_identifiers += 1
            continue
        if ec in index:
            duplicate_ids.append(ec)
        else:
            index[ec] = row
    details = {
        "shape": shape,
        "round_count": len(rows),
        "recognized_rounds": len(index),
        "invalid_rows": invalid_rows,
        "conflicting_identifiers": conflicting_identifiers,
        "duplicate_ids": sorted(set(duplicate_ids))[:20],
    }
    if invalid_rows or duplicate_ids or conflicting_identifiers:
        details["comparison_status"] = "AMBIGUOUS_IDENTIFIERS_NO_COMPARISON"
        return None, details
    details["comparison_status"] = "STRUCTURAL_OVERLAP_ONLY"
    return index, details


def _compare_rounds(payload: bytes, plan: dict[str, Any]) -> dict[str, Any]:
    try:
        incoming = _candidate_json(payload)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        return {"comparison_status": "INVALID_JSON_NO_COMPARISON"}
    index, details = _normalized_rounds(incoming)
    if index is None:
        return details
    reference = {r["ec"]: r for r in plan["rounds"]}
    overlap = sorted(set(index) & set(reference))
    different: list[dict[str, Any]] = []
    same: list[str] = []
    uncomparable: list[str] = []
    for ec in overlap:
        upstream, current = index[ec], reference[ec]
        fields = [key for key in DIFF_FIELDS if key in upstream and key in current]
        if not fields:
            uncomparable.append(ec)
            continue
        changed = [key for key in fields if _canonical_json(upstream[key]) != _canonical_json(current[key])]
        if changed:
            different.append({"ec": ec, "differing_fields": changed, "fields_checked": fields})
        else:
            same.append(ec)
    return {
        **details,
        "overlap_count": len(overlap),
        "candidate_only_count": len(set(index) - set(reference)),
        "provisional_only_count": len(set(reference) - set(index)),
        "overlapping_same_fields_count": len(same),
        "overlapping_diff_fields": different,
        "overlapping_without_shared_fields": uncomparable,
        "note": (
            "Only matching exact EC identifiers and shared descriptive fields are compared; "
            "not historical source authenticity, requirements equivalence or acceptance. "
            "Zero overlaps is not a successful match."
        ),
    }


def generate_report(root: Path = ROOT, spec: str | None = None, rounds: str | None = None) -> dict[str, Any]:
    """Useful both with no inputs and with explicitly supplied candidate files."""
    evidence = _package_evidence(root)
    report: dict[str, Any] = {
        "schema_version": "ces.ec153.gap_report.v1",
        "scope": "RECEIVED_PACKAGE_AND_USER_SUPPLIED_CANDIDATES_ONLY",
        "release": "V4.63/R153/EC-153",
        "evidence": evidence,
        "candidate_spec": {"provided": False},
        "candidate_rounds": {"provided": False},
        "blocker_id": "B-001",
        "blocker_resolution": "NOT_AUTHORIZED_BY_THIS_TOOL",
        "upstream_acceptance_equivalence": "NOT_PROVEN",
        "native_powershell_verification": "NOT_RUN",
    }
    if spec is not None:
        metadata, payload = _read_candidate(spec, "spec")
        metadata.update(_describe_spec(payload, metadata["filename"]))
        report["candidate_spec"] = metadata
    if rounds is not None:
        metadata, payload = _read_candidate(rounds, "rounds")
        metadata.update(_compare_rounds(payload, _load_json(root / "construction/LEGACY_PLAN.json")))
        report["candidate_rounds"] = metadata
    provided = int(spec is not None) + int(rounds is not None)
    report["state"] = (
        "OPEN_NO_UPSTREAM_CANDIDATES" if provided == 0
        else "OPEN_PARTIAL_UNAUTHENTICATED_CANDIDATES" if provided == 1
        else "OPEN_BOTH_CANDIDATES_UNAUTHENTICATED"
    )
    if not evidence["evidence_consistent"]:
        report["state"] = "EVIDENCE_INCONSISTENT_REVIEW_REQUIRED"
    report["next_step"] = (
        "Obtain original raw files and custody/context from owner; record SHA-256 and "
        "manually review source identity, schema, requirements, any overlap, and plan amendments. "
        "Do not auto-close B-001 or overwrite R150/EC151 hashes."
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", metavar="PATH", help="user-supplied V3.10 candidate; any file, read-only")
    parser.add_argument("--rounds", metavar="PATH", help="user-supplied original ROUNDS.json candidate; read-only")
    parser.add_argument("--json", action="store_true", help="emit machine-readable report; never write on disk")
    args = parser.parse_args(argv)
    try:
        report = generate_report(spec=args.spec, rounds=args.rounds)
    except InputError as exc:
        if args.json:
            print(json.dumps({"schema_version": "ces.ec153.gap_report.v1", "state": "INPUT_ERROR", "error": str(exc), "blocker_resolution": "NOT_AUTHORIZED_BY_THIS_TOOL"}, ensure_ascii=False))
        else:
            print("INPUT_ERROR:", exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("EC-153 upstream gap:", report["state"])
        print("  Original R150 paths:", report["evidence"]["original_inventory_count"])
        print("  Historical absence declaration:", report["evidence"]["historical_absence_declaration"])
        print("  B-001:", report["evidence"]["recorded_blocker"])
        for label in ("candidate_spec", "candidate_rounds"):
            item = report[label]
            print(" ", label, ":", (item.get("sha256", "NOT_PROVIDED")))
            if label == "candidate_rounds" and item["provided"]:
                print("    comparison:", item.get("comparison_status"), "overlap:", item.get("overlap_count", "UNKNOWN"))
        if report["evidence"]["evidence_issues"]:
            print("  Evidence issues:", "; ".join(report["evidence"]["evidence_issues"]))
        print("  Historical acceptance: NOT_PROVEN; no blocker auto-resolution")
    return 0 if report["evidence"]["evidence_consistent"] else 2


if __name__ == "__main__":
    sys.exit(main())
