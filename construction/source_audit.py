#!/usr/bin/env python3
"""EC-151: verify R150 source provenance and map literal PowerShell imports.

This offline, read-only auditor does not run PowerShell, Git, a source repo or
any external integration. --seed is a one-time, explicit EC-151 snapshot step;
normal checks never rewrite evidence. It is NOT a PowerShell AST parser.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
BASELINE_FILE = "construction/LEGACY_SOURCE_INVENTORY.json"
DEPENDENCIES_FILE = "construction/LEGACY_DEPENDENCY_MAP.json"
FINGERPRINTS_FILE = "construction/SOURCE_BASELINE.json"
RELOCATIONS_FILE = "construction/LEGACY_RELOCATIONS.json"

# The ten original reference files not included in the relocated 156 or the
# independently attested script+Smoke fingerprint set. Their bytes are only
# attested by the EC-151 received package, NOT by an original R150 digest list.
RETAINED_REFERENCES = (
    "references/code-compare.md",
    "references/code-findings.md",
    "references/code-insight-draft.md",
    "references/code-overview.md",
    "references/code-recurrence.md",
    "references/code-save.md",
    "references/code-show.md",
    "references/code-trace.md",
    "references/code-triage.md",
    "references/non-code-edit-policy.md",
)

# Only recognize literal, readily resolvable dot-source paths. Never execute
# arbitrary PowerShell to discover dependencies from untrusted source.
DOT_LOCAL = re.compile(
    r"^\s*\.\s*\(\s*Join-Path\s+\$PSScriptRoot\s+['\"](?P<path>[^'\"\r\n]+\.ps1)['\"]\s*\)", re.I
)
DOT_PARENT = re.compile(
    r"^\s*\.\s*\(\s*Join-Path\s+\(\s*Split-Path\s+-Parent\s+\$PSScriptRoot\s*\)\s+['\"](?P<path>[^'\"\r\n]+\.ps1)['\"]\s*\)", re.I
)
TEST_ENTRY = re.compile(
    r"Join-Path\s+\(\s*Split-Path\s+-Parent\s+\$PSScriptRoot\s*\)\s+['\"](?P<path>scripts/ces\.ps1)['\"]", re.I
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MODE_HANDLERS = {
    "List": ("scripts/codeshow.ps1", None),
    "Detail": ("scripts/codeshow.ps1", None),
    "Findings": ("scripts/codefindings.ps1", "Get-CodeShowFindingsPage"),
    "Compare": ("scripts/codecompare.ps1", "Get-CodeShowCompare"),
    "Trace": ("scripts/codetrace.ps1", "Get-CodeShowTracePage"),
    "Overview": ("scripts/codeoverview.ps1", "Get-CodeShowOverviewPage"),
    "Triage": ("scripts/codetriage.ps1", "Get-CodeShowTriagePage"),
    "Recurrence": ("scripts/coderecurrence.ps1", "Get-CodeShowRecurrencePage"),
    "Sequence": ("scripts/codesequence.ps1", "Get-CodeShowSequence"),
}


def load_json(root: Path, relative: str) -> dict:
    return json.loads((root / relative).read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def valid_relative(path: str) -> bool:
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        return False
    p = PurePosixPath(path)
    return not p.is_absolute() and all(segment not in ("", ".", "..") for segment in path.split("/"))


def safe_file(root: Path, relative: str) -> tuple[Path | None, str | None]:
    if not valid_relative(relative):
        return None, f"unsafe relative path: {relative!r}"
    p = root
    for segment in relative.split("/"):
        p = p / segment
        if p.is_symlink():
            return None, f"symlink in provenance path: {relative}"
    if not p.is_file():
        return None, f"missing file: {relative}"
    return p, None


def expected_sources(root: Path) -> tuple[list[dict], list[str]]:
    """Derive canonical 305 original paths from two R150 receipts + 10 refs."""
    issues: list[str] = []
    fingerprints = load_json(root, FINGERPRINTS_FILE)["fingerprints"]
    relocations = load_json(root, RELOCATIONS_FILE)["relocations"]
    rows: list[dict] = []
    for original, digest in sorted(fingerprints.items()):
        current, problem = safe_file(root, original)
        if problem:
            issues.append(problem)
        rows.append({
            "original_path": original,
            "located_path": original,
            "sha256": digest,
            "bytes": current.stat().st_size if current else None,
            "basis": "r150_source_fingerprint",
            "reproducibility": "previous_sha256_recorded",
        })
    for moved in relocations:
        rows.append({
            "original_path": moved["from"],
            "located_path": moved["to"],
            "sha256": moved["sha256"],
            "bytes": moved["bytes"],
            "basis": "archive_relocation_sha256",
            "reproducibility": "previous_sha256_recorded",
        })
    for original in RETAINED_REFERENCES:
        path, problem = safe_file(root, original)
        if problem:
            issues.append(problem)
        rows.append({
            "original_path": original,
            "located_path": original,
            "sha256": sha256(path) if path else None,
            "bytes": path.stat().st_size if path else None,
            "basis": "ec151_current_receipt_only",
            "reproducibility": "no_independent_original_r150_sha256",
        })
    rows.sort(key=lambda r: r["original_path"])
    orig = [r["original_path"] for r in rows]
    resolved = [r["located_path"] for r in rows]
    if len(fingerprints) != 139 or len(relocations) != 156 or len(RETAINED_REFERENCES) != 10:
        issues.append("R150 receipt cardinality disagrees with 139 + 156 + 10")
    if len(rows) != 305 or len(set(orig)) != 305 or len(set(resolved)) != 305:
        issues.append("305-path inventory contains duplicates or count mismatch")
    if any(not SHA256.fullmatch(r["sha256"] or "") for r in rows):
        issues.append("inventory contains a missing or invalid SHA-256")
    return rows, issues


def snapshot_inventory(rows: list[dict]) -> dict:
    return {
        "schema_version": "ces.ec151.source_inventory.v1",
        "baseline": "R150/EC-150",
        "audited_in_ec": "EC-151",
        "counts": {
            "total_original_paths": 305,
            "ps_sources": 124,
            "smoke_suites": 15,
            "archived_originals": 156,
            "retained_unmoved_references": 10,
        },
        "interpretation": {
            "sha256_authorities": [FINGERPRINTS_FILE, RELOCATIONS_FILE],
            "retained_reference_limit": "Ten retained references have EC-151 package digests but no independently supplied original-R150 hashes.",
            "never_overwrite_on_drift": True,
            "runtime_verification": "NOT_RUN",
        },
        "files": rows,
    }


def import_graph(root: Path) -> tuple[dict, list[str]]:
    """Map literal paths plus nine CodeShow dispatches; never eval source."""
    issues: list[str] = []
    edges: list[dict] = []
    unsupported: list[dict] = []
    scripts = sorted((root / "scripts").glob("*.ps1"))
    tests = sorted((root / "tests").glob("*.Smoke.ps1"))
    for src in scripts + tests:
        relative = src.relative_to(root).as_posix()
        lines = src.read_text(encoding="utf-8-sig").splitlines()
        for index, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            a = DOT_LOCAL.match(line)
            b = DOT_PARENT.match(line)
            c = TEST_ENTRY.search(line) if relative.startswith("tests/") else None
            kind, target = None, None
            if a:
                kind, target = "dot_source_local", f"scripts/{a.group('path')}"
            elif b:
                kind, target = "dot_source_parent", b.group("path")
            elif c:
                kind, target = "test_cli_literal", c.group("path")
            elif re.match(r"^\s*\.\s+(?!#)", line):
                unsupported.append({"from": relative, "line": index, "kind": "unclassified_dot_source"})
            if target is not None:
                edge = {"from": relative, "line": index, "to": target, "kind": kind}
                edges.append(edge)
                _, problem = safe_file(root, target)
                if problem:
                    issues.append(f"unresolved {kind} in {relative}:{index}: {problem}")
    # Every shipped PowerShell module except the CLI entry must be dot-sourced
    # by the CLI, otherwise a module might silently disappear from runtime.
    expected = {p.relative_to(root).as_posix() for p in scripts} - {"scripts/ces.ps1"}
    actual = {e["to"] for e in edges if e["from"] == "scripts/ces.ps1" and e["kind"] == "dot_source_local"}
    for path in sorted(expected - actual):
        issues.append(f"unreachable module from CLI: {path}")
    for path in sorted(actual - expected):
        issues.append(f"CLI imported a module outside source module list: {path}")
    if len(actual) != len([e for e in edges if e["from"] == "scripts/ces.ps1" and e["kind"] == "dot_source_local"]):
        issues.append("CLI duplicate literal dot-source detected")
    if unsupported:
        issues.extend(f"unparsed dot source {e['from']}:{e['line']}" for e in unsupported)

    cli_text = (root / "scripts/ces.ps1").read_text(encoding="utf-8-sig")
    show_text = (root / "scripts/codeshow.ps1").read_text(encoding="utf-8-sig")
    if not re.search(r"CodeShow-Local\s+-Envelope\s+\$envelope", cli_text, re.I):
        issues.append("CLI CodeShow-Local dispatch not statically found")
    if not re.search(r"^function\s+CodeShow-Local\b", show_text, re.I | re.M):
        issues.append("CodeShow-Local function not statically found")
    modes = []
    for mode, (module, handler) in MODE_HANDLERS.items():
        if not re.search(r"\$Mode\s+-ieq\s+'" + re.escape(mode) + r"'", show_text, re.I):
            issues.append(f"Mode {mode} condition absent from CodeShow-Local")
        if handler:
            if not re.search(r"\$Envelope\.data\s*=\s*" + re.escape(handler) + r"\b", show_text, re.I):
                issues.append(f"Mode {mode} handler call {handler} absent from CodeShow-Local")
            path, problem = safe_file(root, module)
            if problem:
                issues.append(problem)
            elif not re.search(r"^function\s+" + re.escape(handler) + r"\b", path.read_text(encoding="utf-8-sig"), re.I | re.M):
                issues.append(f"Mode {mode} function definition {handler} absent in {module}")
        elif not re.search(r"mode\s*=\s*'" + re.escape(mode) + r"'", show_text, re.I):
            issues.append(f"Mode {mode} inline result absent in codeshow.ps1")
        modes.append({
            "mode": mode,
            "entry": "scripts/ces.ps1::CodeShow-Local",
            "dispatcher": "scripts/codeshow.ps1::CodeShow-Local",
            "handler_file": module,
            "handler": handler or "inline_in_CodeShow_Local",
            "classification": "static_source_route_only_not_runtime_verified",
        })
    return {
        "schema_version": "ces.ec151.import_graph.v1",
        "baseline": "R150/EC-150",
        "audited_in_ec": "EC-151",
        "limits": [
            "Literal dot-source and test entry locator scan only; not a PowerShell AST, reachability proof, or runtime load test.",
            "Commented or dynamically assembled import paths are not guaranteed to be identified.",
            "CodeShow mode routing confirms source text/definitions only; execution and performance are NOT_RUN.",
        ],
        "external_prerequisites_not_run": ["PowerShell 7+", "git executable and real Git fixtures", "Windows/path behavior"],
        "counts": {
            "scripts_scanned": len(scripts),
            "smoke_suites_scanned": len(tests),
            "cli_imported_modules": len(actual),
            "literal_dependency_edges": len(edges),
            "unclassified_imports": len(unsupported),
            "code_show_modes": len(modes),
        },
        "edges": sorted(edges, key=lambda e: (e["from"], e["line"], e["to"])),
        "unclassified_imports": unsupported,
        "code_show_routes": modes,
    }, issues


def inspect(root: Path, strict_baseline: bool = False, strict_deps: bool = False) -> dict:
    errors: list[str] = []
    warnings: list[str] = []
    expected, problems = expected_sources(root)
    errors += problems
    inv_path, problem = safe_file(root, BASELINE_FILE)
    if problem:
        errors.append(problem)
        recorded: dict = {}
    else:
        try:
            recorded = json.loads(inv_path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            errors.append(f"inventory JSON unreadable: {exc}")
            recorded = {}
    if recorded:
        # Only the ten retained reference digests lack an independent R150
        # receipt. Their frozen EC-151 snapshot stays authoritative after a
        # future *authorized* edit; do not recompute their baseline from the
        # current bytes or overwrite the original ledger.
        frozen_rows = recorded.get("files", [])
        frozen_by_path = {r.get("original_path"): r for r in frozen_rows if isinstance(r, dict)}
        if len(frozen_by_path) != len(frozen_rows):
            errors.append("EC-151 inventory contains duplicate or malformed rows")
        for row in expected:
            if row["basis"] in ("r150_source_fingerprint", "ec151_current_receipt_only"):
                frozen = frozen_by_path.get(row["original_path"], {})
                if not isinstance(frozen, dict) or not isinstance(frozen.get("bytes"), int) or frozen["bytes"] < 0:
                    errors.append("missing frozen EC-151 file size for " + row["original_path"])
                else:
                    row["bytes"] = frozen["bytes"]
                if row["basis"] == "ec151_current_receipt_only":
                    if not isinstance(frozen, dict) or not SHA256.fullmatch(str(frozen.get("sha256", ""))):
                        errors.append("missing frozen EC-151 reference digest for " + row["original_path"])
                    else:
                        row["sha256"] = frozen["sha256"]
        # Check every field, not only row count; independent archived and
        # source hashes cannot be silently changed in the EC-151 snapshot.
        if recorded != snapshot_inventory(expected):
            errors.append("EC-151 inventory differs from independent receipts or its recorded snapshot")

    drift: list[dict] = []
    for row in expected:
        path, problem = safe_file(root, row["located_path"])
        if problem:
            errors.append(problem)
            continue
        if row["bytes"] is not None and path.stat().st_size != row["bytes"]:
            drift.append({"path": row["located_path"], "reason": "bytes_changed", "basis": row["basis"]})
            continue
        if sha256(path) != row["sha256"]:
            drift.append({"path": row["located_path"], "reason": "sha256_changed", "basis": row["basis"]})
    for issue in drift:
        msg = f"baseline byte drift: {issue['path']} ({issue['reason']}; {issue['basis']})"
        if issue["basis"] == "archive_relocation_sha256" or strict_baseline:
            errors.append(msg)
        else:
            warnings.append(msg + " (later EC modifications may be authorized)")

    graph, graph_errors = import_graph(root)
    errors += graph_errors
    graph_path, problem = safe_file(root, DEPENDENCIES_FILE)
    if problem:
        errors.append(problem)
    else:
        try:
            recorded_graph = json.loads(graph_path.read_text(encoding="utf-8"))
            if recorded_graph != graph:
                msg = "literal dependency graph differs from the EC-151 static snapshot"
                if strict_deps:
                    errors.append(msg)
                else:
                    warnings.append(msg + " (re-scan after approved later EC changes)")
        except (ValueError, UnicodeDecodeError) as exc:
            errors.append(f"dependency snapshot unreadable: {exc}")

    return {
        "audit": "EC-151 offline provenance and import map",
        "status": "PASS" if not errors else "FAIL",
        "strict_baseline": strict_baseline,
        "strict_deps": strict_deps,
        "inventory_count": len(expected),
        "inventory_counts_by_basis": dict(sorted(Counter(r["basis"] for r in expected).items())),
        "source_byte_drift_count": len(drift),
        "source_byte_drift": drift,
        "dependency_counts": graph["counts"],
        "errors": errors,
        "warnings": warnings,
        "native_pwsh_runtime": "NOT_RUN",
        "all_15_smoke_suites": "NOT_RUN",
        "final_acceptance": "NOT_STARTED",
    }


def seed(root: Path) -> None:
    targets = (root / BASELINE_FILE, root / DEPENDENCIES_FILE)
    if any(p.exists() for p in targets):
        raise ValueError("EC-151 receipts already exist; --seed cannot overwrite original evidence")
    expected, problems = expected_sources(root)
    if problems:
        raise ValueError("Cannot seed broken original receipts: " + "; ".join(problems))
    # Do not seed a snapshot of already-corrupt R150 bytes.
    for row in expected:
        path, problem = safe_file(root, row["located_path"])
        if problem or sha256(path) != row["sha256"]:
            raise ValueError("Original receipt mismatch: " + row["located_path"])
    graph, issues = import_graph(root)
    if issues:
        raise ValueError("Cannot seed broken dependency references: " + "; ".join(issues))
    for path, value in zip(targets, (snapshot_inventory(expected), graph)):
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="rooted ces/ directory")
    parser.add_argument("--seed", action="store_true", help="ONE-TIME receipt creation; refuses overwriting evidence")
    parser.add_argument("--strict-baseline", action="store_true", help="fail on any R150 source/reference byte drift")
    parser.add_argument("--strict-deps", action="store_true", help="fail when literal graph differs from EC-151 snapshot")
    parser.add_argument("--json", action="store_true", help="print the structured report")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.seed:
            seed(root)
        result = inspect(root, args.strict_baseline, args.strict_deps)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"SOURCE AUDIT ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"SOURCE AUDIT {result['status']}: {result['inventory_count']} original paths, "
              f"{result['dependency_counts']['cli_imported_modules']} CLI modules, "
              f"{result['dependency_counts']['literal_dependency_edges']} literal edges, "
              f"{result['dependency_counts']['code_show_modes']} CodeShow modes")
        for msg in result["errors"]: print("ERROR:", msg)
        for msg in result["warnings"][:15]: print("NOTE:", msg)
        if len(result["warnings"]) > 15: print(f"NOTE: +{len(result['warnings']) - 15} additional warnings")
        print("Native pwsh / 15 Smoke suites / Windows+Git runtime: NOT_RUN")
    return 0 if not result["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
