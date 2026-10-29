#!/usr/bin/env python3
"""EC-160: read-only Phase-A (EC151..160) construction gate.

A PASS_STATIC verdict certifies only consistency between the *supplied local
package* and its recorded, unsigned static review receipts. It cannot certify
upstream custody, native PowerShell behavior, actor identity, write safety,
or final acceptance. The tool never invokes PowerShell, Git or a provider.

Usage: python construction/stage_a_gate.py [--json]
Exit: 0 PASS_STATIC, 2 BLOCKED, 3 GATE_UNAVAILABLE (bad input/runtime).
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable

import plan_guard
import source_audit
import action_registry
import response_contract
import sequence_audit
import trace_actions

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "ces.construction.phase_a_gate.v1"
MAX_METADATA_BYTES = 4 * 1024 * 1024
EXPECTED_CHANGED = frozenset({
    "scripts/ces.ps1", "scripts/reconcile.ps1", "scripts/codevalidate.ps1",
    "scripts/codesave.ps1", "scripts/codeshow.ps1",
})
EXPECTED_MODULE = "scripts/pathidentity.ps1"
EXPECTED_DEPENDENCIES = (
    "construction/LEGACY_SOURCE_INVENTORY.json",
    "construction/LEGACY_DEPENDENCY_MAP.json",
    "construction/ACTION_TRACE.json",
    "construction/LEGACY_UPSTREAM_GAP.json",
    "construction/LEGACY_SEQUENCE_AUDIT.json",
    "references/cli-action-mode-registry.json",
    "references/cli-response-contract.v1.json",
    "construction/SECURITY_BOUNDARIES.json",
    "construction/LEGACY_SECURITY_DRIFT.json",
    "references/schema-compatibility.v1.json",
    "construction/LEGACY_PATH_DRIFT.json",
    "references/path-identity.v1.json",
    "construction/LEGACY_DELIVERY_ANCHOR.json",
)


class GateFailure(Exception):
    """A static gate could not establish its scoped condition."""


def demand(condition: bool, detail: str) -> None:
    if not condition:
        raise GateFailure(detail)


def member(root: Path, relative: str) -> Path:
    """Read only fixed local-package members, rejecting symlink ancestry."""
    demand(bool(re.fullmatch(r"[A-Za-z0-9._/-]+", relative)), "unsafe member name")
    parts = relative.split("/")
    demand(all(x not in ("", ".", "..") for x in parts), "unsafe member path")
    root = root.absolute()
    demand(not root.is_symlink(), "package root is a symlink")
    p = root
    for x in parts:
        p /= x
        demand(not p.is_symlink(), f"linked package member: {relative}")
    demand(p.is_file(), f"required package member missing: {relative}")
    return p


def digest(root: Path, rel: str) -> str:
    p = member(root, rel)
    h = hashlib.sha256()
    with p.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def unique_keys(pairs: list[tuple[str, Any]]) -> dict:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateFailure(f"duplicate JSON key: {key[:80]}")
        result[key] = value
    return result


def no_nonfinite(token: str) -> Any:
    raise GateFailure("non-finite JSON numeric value is forbidden")


def metadata(root: Path, rel: str) -> dict:
    p = member(root, rel)
    demand(p.stat().st_size <= MAX_METADATA_BYTES, f"metadata exceeds static read budget: {rel}")
    try:
        doc = json.loads(p.read_text(encoding="utf-8-sig"),
                         object_pairs_hook=unique_keys, parse_constant=no_nonfinite)
    except (ValueError, UnicodeError) as exc:
        raise GateFailure(f"invalid JSON metadata: {rel}: {type(exc).__name__}") from exc
    demand(isinstance(doc, dict), f"metadata is not a JSON object: {rel}")
    return doc


@dataclass
class Context:
    root: Path
    evidence: dict[str, Any] = field(default_factory=dict)
    dependencies: list[dict[str, str]] = field(default_factory=list)


def package_plan(context: Context) -> dict:
    root = context.root
    active = metadata(root, "BUILD_STATE.json")
    progress = metadata(root, "construction/LEGACY_PROJECT_STATE.json")
    plan = metadata(root, "construction/LEGACY_PLAN.json")
    errors = plan_guard.check_plan(plan, progress, active)
    errors += plan_guard.check_structure(root)
    # This gate is for EC160, not an open-ended future-stage acceptance gate.
    assertions = {
        "release": active.get("version") == "V4.70" and active.get("build") == "R160",
        "completed": active.get("completed_ec") == progress.get("last_completed_ec") == "EC-160",
        "next": active.get("next_ec") == progress.get("next_ec") == "EC-161",
        "round_count": progress.get("completed_replan_rounds") == 10,
        "recorded_release": progress.get("last_delivered_release") == "V4.70/R160",
        "phase": all(e.get("status") == "IMPLEMENTED_PENDING_FINAL_ACCEPTANCE"
                     for e in plan.get("rounds", [])[:10]),
        "future_unadvanced": all(e.get("status") != "IMPLEMENTED_PENDING_FINAL_ACCEPTANCE"
                                 for e in plan.get("rounds", [])[10:]),
        "cli_identity": active.get("shipped_powershell_cli_version") == "V4.60"
                        and active.get("shipped_powershell_cli_build") == "R150",
        "acceptance_not_started": progress.get("final_acceptance") == "NOT_STARTED",
    }
    errors += [f"incorrect phase-A {key}" for key, valid in assertions.items() if not valid]
    demand(not errors, " | ".join(errors[:12]))
    context.evidence["package_identity"] = {"package": "V4.70/R160", "native_cli": "V4.60/R150"}
    return {"implemented_phase_a_rounds": 10, "planned_rounds": 100,
            "next_ec": "EC-161", "contract_scope": "CONSTRUCTION_PACKAGE_ONLY"}


def archived_history(context: Context) -> dict:
    root = context.root
    errors = plan_guard.check_history(root)
    baseline = metadata(root, "construction/SOURCE_BASELINE.json")
    frozen = metadata(root, "construction/LEGACY_DELIVERY_ANCHOR.json")
    receipt = frozen.get("sha256_by_path", {})
    demand(frozen.get("ec") == "EC-159" and frozen.get("construction_package") == "V4.69/R159",
           "R159 delivery receipt is not the expected prior stage")
    demand(isinstance(receipt, dict), "missing R159 digest register")
    pinned = ["construction/SOURCE_BASELINE.json", "construction/LEGACY_SECURITY_DRIFT.json",
              "construction/LEGACY_PATH_DRIFT.json", EXPECTED_MODULE]
    for rel in pinned:
        if not isinstance(receipt.get(rel), str) or receipt[rel] != digest(root, rel):
            errors.append("previous delivery receipt mismatch: " + rel)
    prev = metadata(root, "construction/LEGACY_PATH_DRIFT.json")
    demand(prev.get("preserved_ec157_sha256") == digest(root, "construction/LEGACY_SECURITY_DRIFT.json"),
           "R159 receipt no longer chains to the unchanged EC157 receipt")
    demand(len(baseline.get("fingerprints", {})) == 139, "R150 baseline SHA cardinality changed")
    gap = metadata(root, "construction/LEGACY_UPSTREAM_GAP.json")
    demand(gap.get("schema_version") == "ces.ec153.upstream_gap.v1"
           and gap.get("blocker_id") == "B-001"
           and gap.get("blocker_state_at_delivery") == "OPEN_NON_BLOCKING_FOR_PROVISIONAL_PLAN",
           "upstream gap evidence replaced or missing")
    errors += [f"missing phase-A evidence: {rel}" for rel in EXPECTED_DEPENDENCIES
               if not (root / rel).is_file() or (root / rel).is_symlink()]
    demand(not errors, " | ".join(errors[:12]))
    return {"historic_relocations_sha_checked": 156, "baseline_fingerprints": 139,
            "unchanged_reviewed_receipts": ["EC157_SOURCE_DRIFT", "EC159_SOURCE_DRIFT"],
            "prior_package_digest_register": "EC159_DELIVERY_SHA256",
            "custody_authentication": "NOT_PROVEN_BY_LOCAL_UNSIGNED_RECEIPTS"}


def native_source_scope(context: Context) -> dict:
    root = context.root
    baseline = metadata(root, "construction/SOURCE_BASELINE.json")["fingerprints"]
    old_review = metadata(root, "construction/LEGACY_SECURITY_DRIFT.json")
    review = metadata(root, "construction/LEGACY_PATH_DRIFT.json")
    current = review.get("changed_powershell_sources", {})
    new = review.get("new_powershell_sources", {})
    demand(review.get("ec") == "EC-159" and review.get("native_powershell7") == "NOT_RUN",
           "EC159 reviewed patch boundary changed")
    demand(set(current) == EXPECTED_CHANGED and set(new) == {EXPECTED_MODULE},
           "EC159 changed/new native source allowlist diverged")
    demand(set(old_review.get("changed_powershell_sources", {})) == {
        "scripts/ces.ps1", "scripts/codesave.ps1"}, "EC157 reviewed source list changed")
    demand(set(baseline) and len(baseline) == 139, "R150 139-source baseline missing")
    checked = 0
    legacy_ps = 0
    smoke = 0
    for rel, original_sha in baseline.items():
        observed = digest(root, rel)
        if rel.endswith(".ps1") and rel.startswith("scripts/"):
            legacy_ps += 1
            if rel in EXPECTED_CHANGED:
                row = current[rel]
                demand(row.get("r150_sha256") == original_sha, f"R150 ancestry invalid: {rel}")
                prior = (old_review["changed_powershell_sources"][rel]["current_sha256"]
                         if rel in old_review["changed_powershell_sources"] else original_sha)
                demand(row.get("previous_sha256") == prior, f"EC157->159 drift chain invalid: {rel}")
                demand(row.get("current_sha256") == observed and observed != prior,
                       f"unreviewed/native source drift: {rel}")
                demand(row.get("wire_contract_changed") is False
                       and row.get("native_runtime_test") == "NOT_RUN",
                       f"native source review grade overstated: {rel}")
            else:
                demand(observed == original_sha, f"unreviewed R150 native source drift: {rel}")
            checked += 1
        if rel.startswith("tests/") and rel.endswith(".Smoke.ps1"):
            smoke += 1
            demand(observed == original_sha, f"frozen original Smoke modified: {rel}")
            checked += 1
    demand(legacy_ps == 124 and smoke == 15, "baseline script/Smoke membership no longer matches R150")
    actual_ps = {p.name for p in (root / "scripts").glob("*.ps1")}
    expected_ps = {Path(p).name for p in baseline if p.startswith("scripts/") and p.endswith(".ps1")}
    expected_ps.add("pathidentity.ps1")
    demand(actual_ps == expected_ps, "unreviewed script added/removed from native module inventory")
    demand(digest(root, EXPECTED_MODULE) == new[EXPECTED_MODULE]["sha256"],
           "shared pathidentity module changed without new EC receipt")
    context.evidence["native_scoped_sources"] = sorted(EXPECTED_CHANGED) + [EXPECTED_MODULE]
    return {"unchanged_or_reviewed_original_ps_sources": legacy_ps,
            "original_smoke_unchanged": smoke,
            "reviewed_ec159_original_patches": sorted(EXPECTED_CHANGED),
            "ec159_new_shared_module": EXPECTED_MODULE,
            "native_test_status": "NOT_RUN_NATIVE"}


def module_and_import_edges(context: Context) -> dict:
    root = context.root
    audit = source_audit.inspect(root, strict_baseline=False, strict_deps=False)
    demand(audit.get("status") == "PASS" and not audit.get("errors"),
           "source inventory / static dependency error: " + " | ".join(audit.get("errors", [])[:7]))
    cli = member(root, "scripts/ces.ps1").read_text(encoding="utf-8-sig")
    ident = member(root, EXPECTED_MODULE).read_text(encoding="utf-8-sig")
    dot = re.findall(r"^\s*\.\s*\(Join-Path\s+\$PSScriptRoot\s+'pathidentity\.ps1'\)", cli, re.M)
    demand(len(dot) == 1, "pathidentity must be dot-sourced exactly once from trusted package")
    demand(cli.find("function Git-In") < cli.find(". (Join-Path $PSScriptRoot 'pathidentity.ps1')")
           < cli.find("Resolve-CesUserPath"), "shared source loaded before Git-In or after use")
    exposed = ("Normalize-FullPath", "Paths-Equal", "Read-CommonGitDirectory",
               "Find-VerifiedStableRoot", "Assert-CesNoReparseAncestry", "Resolve-CesEvidencePath",
               "Resolve-CesUserPath", "Assert-CesContainedPath", "Assert-CesVerifiedMainWorktree",
               "Resolve-CesActorIdentity", "Assert-CesVerifiedActor", "Redact-CesKnownPaths")
    for func in exposed:
        demand(len(re.findall(r"^function\s+" + re.escape(func) + r"\b", ident, flags=re.M | re.I)) == 1,
               f"public shared identity function missing/ambiguous: {func}")
    used = {
        "scripts/reconcile.ps1": ("Resolve-CesEvidencePath",),
        "scripts/codevalidate.ps1": ("Resolve-CesEvidencePath",),
        "scripts/codesave.ps1": ("Assert-CesVerifiedMainWorktree", "Assert-CesContainedPath"),
        "scripts/codeshow.ps1": ("Assert-CesVerifiedMainWorktree", "Assert-CesContainedPath"),
    }
    for rel, funcs in used.items():
        code = member(root, rel).read_text(encoding="utf-8-sig")
        for func in funcs:
            demand(re.search(r"\b" + re.escape(func) + r"\s+-", code) is not None,
                   f"shared path/identity call site missing: {rel}:{func}")
    # EC154 frozen public k1..56 keys/order and core module bytes.  EC159
    # reviewed codeshow.ps1 changes make its old SHA differ, but the exact
    # reviewed current digest and identical public Sequence contract are
    # checked separately. Never silently regenerate the frozen snapshot.
    present = sequence_audit.build_audit(root)
    frozen = metadata(root, "construction/LEGACY_SEQUENCE_AUDIT.json")
    drift = sequence_audit.check_snapshot(present, frozen)
    known_reviewed = "source_sha_drift_requires_review:scripts/codeshow.ps1"
    demand(set(drift) in (set(), {known_reviewed}),
           "unreviewed CodeShow k1..56 snapshot delta: " + " | ".join(drift[:7]))
    if known_reviewed in drift:
        reviewed = metadata(root, "construction/LEGACY_PATH_DRIFT.json")
        want = reviewed["changed_powershell_sources"]["scripts/codeshow.ps1"]["current_sha256"]
        demand(want == digest(root, "scripts/codeshow.ps1"),
               "CodeShow revised source does not match the precise EC159 SHA")
    demand(len(present.get("k_chain", [])) == 56, "CodeShow k1..56 cardinality changed")
    return {"source_inventory_paths": audit.get("inventory_count"),
            "import_counts": audit.get("dependency_counts", {}),
            "older_dependency_snapshot": "EC151_REVIEWED_DRIFT_ALLOWED_BY_EXACT_EC159_HASH_CHAIN",
            "codeshow_k_outputs": 56,
            "ec154_sequence_snapshot": "PUBLIC_CONTRACT_MATCH_WITH_REVIEWED_EC159_CODESHOW_SHA" if drift else "UNCHANGED",
            "shared_native_consumers": sorted(used),
            "non_native_analysis": True}


def route_registry(context: Context) -> dict:
    root = context.root
    data = metadata(root, "references/cli-action-mode-registry.json")
    # The reused EC152 trace analyzer has a module-level fixed ROOT. Bind it
    # to the package being checked, including tests using an isolated copy.
    previous_root = trace_actions.ROOT
    try:
        trace_actions.ROOT = root
        outcome = action_registry.check_registry(data, root)
    finally:
        trace_actions.ROOT = previous_root
    demand(outcome.get("verdict") == "STATIC_CONTRACT_MATCH",
           "action route drift: " + " | ".join(outcome.get("problems", [])[:7]))
    action_count = len(data["supported_actions"])
    route_count = len(data["routes"])
    future = data["planned_capabilities"]
    demand((action_count, route_count, len(future)) == (7, 16, 29),
           "action/route/not-implemented cardinalities changed")
    demand(all(x.get("status") == "NOT_IMPLEMENTED" and
               x.get("cli_handler_registered") is False for x in future),
           "future route accidentally promoted from NOT_IMPLEMENTED")
    reject = action_registry.resolve(data, action="ProposedPR")
    demand(reject.get("decision") not in ("routable_unverified", "routable"),
           "unimplemented action unexpectedly routable")
    return {"authored_action_families": action_count, "static_routes": route_count,
            "not_implemented_capabilities": len(future),
            "unknown_action_policy": data["cli_defaults"]["unknown_action"],
            "handler_execution": "NOT_RUN_NATIVE"}


def wire_evidence_fields(context: Context) -> dict:
    root = context.root
    contract = metadata(root, "references/cli-response-contract.v1.json")
    previous_root = response_contract.ROOT
    try:
        response_contract.ROOT = root
        aligned = response_contract.source_alignment(contract)
    finally:
        response_contract.ROOT = previous_root
    demand(aligned.get("aligned") is True,
           "CLI response source mismatch: " + " | ".join(aligned.get("problems", [])[:7]))
    mandatory = contract.get("required_fields", {})
    coverage = contract.get("coverage", {}).get("fields", [])
    statuses = contract.get("statuses", {})
    demand(len(mandatory) == 16 and len(set(mandatory)) == 16, "wire root field count not 16")
    demand(len(coverage) == 31 and len(set(coverage)) == 31,
           "wire coverage evidence bit count not 31")
    demand({k: v.get("exit_code") for k, v in statuses.items()} == {
        "success": 0, "partial": 2, "not_implemented": 3,
        "invalid_input": 4, "unavailable": 5}, "status/exit-code contract drift")
    demand(contract.get("wire_schema_version") == "ces.cli.v1",
           "CLI response schema changed without phase-A review")
    return {"response_schema": "ces.cli.v1", "required_root_fields": len(mandatory),
            "self_reported_coverage_flags": len(coverage),
            "status_exit_codes": {k: v["exit_code"] for k, v in statuses.items()},
            "native_response_captured": False}


def actor_authorization_scope(context: Context) -> dict:
    root = context.root
    state = metadata(root, "references/path-identity.v1.json")
    identity = member(root, EXPECTED_MODULE).read_text(encoding="utf-8-sig")
    entry = member(root, "scripts/ces.ps1").read_text(encoding="utf-8-sig")
    store = member(root, "scripts/codesave.ps1").read_text(encoding="utf-8-sig")
    demand("status = 'declared_unverified'" in identity and "status = 'unknown'" in identity,
           "external actor states no longer fail closed")
    demand("actor_key = $null" in identity and "can_authorize_write = $false" in identity,
           "shared identity module no longer denies derived write authorization")
    demand(bool(re.search(r"function Assert-CesVerifiedActor\b[\s\S]*?throw 'An authenticated", identity)),
           "external actor authentication stub may now approve claims")
    demand("if ($Action -ieq 'CodeSave' -and -not $ApprovePersist.IsPresent)" in entry,
           "CLI independent pre-handler persistence denial missing")
    demand("if (-not $ApprovePersist)" in store and
           "CODE_SAVE_AUTHORIZATION_REQUIRED" in store,
           "CodeSave handler independent authorization denial missing")
    demand("Assert-CesVerifiedMainWorktree" in store and
           "Assert-CesContainedPath" in store,
           "local CodeSave store Git/path gates no longer bound")
    demand(state.get("schema_version") is not None, "path-identity machine policy missing version")
    return {"actor_authentication": "NOT_IMPLEMENTED", "declared_actor_write_eligibility": False,
            "repository_key_global_identity": False, "codesave_approval": "CLI_AND_HANDLER_STATIC_DENIAL_GATES",
            "provenance_level": "SOURCE_SHAPE_AND_PINNED_SHA_ONLY"}


def dependencies_and_acceptance(context: Context) -> dict:
    root = context.root
    blockers = metadata(root, "construction/KNOWN_BLOCKERS.json")
    progress = metadata(root, "construction/LEGACY_PROJECT_STATE.json")
    items = blockers.get("blockers", [])
    demand(isinstance(items, list) and {x.get("id") for x in items} == {"B-001", "B-002", "B-003"},
           "missing or altered authoritative external dependency register")
    states = {x["id"]: x["state"] for x in items}
    demand(states["B-001"] == "OPEN_NON_BLOCKING_FOR_PROVISIONAL_PLAN",
           "missing upstream V3.10/ROUNDS cannot be silently closed")
    demand(states["B-002"] == "DEFERRED_TO_FINAL_USER_ASSISTED_ACCEPTANCE",
           "native/OS/Git acceptance deferred state altered")
    demand(states["B-003"] == "DESIGN_AND_IMPLEMENTATION_DEPENDENCY",
           "remote provider/authorization dependency misrepresented")
    demand(progress.get("final_acceptance") == "NOT_STARTED", "final acceptance improperly started")
    active = metadata(root, "BUILD_STATE.json")
    native = active.get("runtime_validation", {})
    demand(all(native.get(k) == "NOT_RUN" for k in (
        "native_powershell7", "existing_smoke_15", "windows_git", "performance_E63_E66")),
        "a native or OS acceptance claim has no evidence in EC160")
    context.dependencies = [
        {"id": "B-001", "state": "OPEN", "impact": "original_upstream_spec_not_authenticated",
         "phase_a_effect": "NO_BLOCK_PROVISIONAL_PLAN; ORIGINAL_EQUIVALENCE_NOT_PROVEN"},
        {"id": "B-002", "state": "DEFERRED", "impact": "powershell7_smoke_git_os_performance_unexecuted",
         "phase_a_effect": "NOT_RUN_NATIVE"},
        {"id": "B-003", "state": "UNAVAILABLE", "impact": "provider_accounts_and_permissions_not_bound",
         "phase_a_effect": "DO_NOT_ASSUME_REMOTE_SUCCESS"},
    ]
    return {"external_dependency_states": states, "native_verdict": "NOT_RUN_NATIVE",
            "final_acceptance": "NOT_STARTED", "upstream_equivalence": "NOT_PROVEN"}


CHECKS: tuple[tuple[str, str, Callable[[Context], dict]], ...] = (
    ("package_plan", "STAGE_PLAN_INVALID", package_plan),
    ("archived_provenance", "STAGE_RECEIPT_DRIFT", archived_history),
    ("native_source_scope", "STAGE_SOURCE_DRIFT", native_source_scope),
    ("imports_and_evidence_inventory", "STAGE_IMPORT_OR_EVIDENCE_DRIFT", module_and_import_edges),
    ("authored_cli_routes", "STAGE_ROUTE_DRIFT", route_registry),
    ("cli_wire_and_coverage", "STAGE_WIRE_DRIFT", wire_evidence_fields),
    ("actor_and_write_boundaries", "STAGE_IDENTITY_OR_AUTHORIZATION_DRIFT", actor_authorization_scope),
    ("blockers_and_native_deferral", "STAGE_DEPENDENCY_RECORD_INVALID", dependencies_and_acceptance),
)


def evaluate(root: Path = ROOT) -> dict:
    context = Context(root=Path(root))
    checks = []
    for ident, code, check in CHECKS:
        try:
            detail = check(context)
            checks.append({"id": ident, "status": "PASS_STATIC", "reason_code": "STATIC_SCOPE_MATCH",
                           "observed": detail})
        except (GateFailure, OSError, KeyError, TypeError, ValueError, IndexError,
                UnicodeError, action_registry.RegistryError) as exc:
            # Keep processing independent sections. Do not swallow failures into
            # PASS or print opaque data/personal absolute paths in gate output.
            msg = str(exc).replace(str(root), "<package>")[:850]
            checks.append({"id": ident, "status": "BLOCKED", "reason_code": code,
                           "issues": [msg if msg else type(exc).__name__]})
    blocked = [x for x in checks if x["status"] == "BLOCKED"]
    result = {
        "schema_version": SCHEMA,
        "phase": "A", "range": "EC-151..EC-160",
        "construction_package": "V4.70/R160", "embedded_cli": "V4.60/R150",
        "scope": "LOCAL_READ_ONLY_STATIC_PROVENANCE_AND_SOURCE_SHAPE",
        "static_verdict": "BLOCKED" if blocked else "PASS_STATIC",
        "native_verdict": "NOT_RUN_NATIVE", "final_acceptance": "NOT_STARTED",
        "stage_complete": not blocked,
        "stage_complete_meaning": "OFFLINE_STATIC_GATE_ONLY_NOT_FULL_FEATURES_OR_RUNTIME_CERTIFICATION",
        "exit_code": 2 if blocked else 0,
        "summary": {"checked": len(checks), "pass_static": len(checks) - len(blocked),
                    "blocked": len(blocked), "remaining_planned_ec": 90},
        "checks": checks,
        "outstanding_dependencies": context.dependencies,
        "security_and_custody_limit": "Local unsigned SHA receipts, lexical source evidence and checked package metadata are not independent chain-of-custody or runtime proof.",
    }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable stdout; no artifact written")
    args = parser.parse_args(argv)
    try:
        report = evaluate()
    except Exception as exc:
        # An unexpected tool failure cannot be classified as a successful
        # static verification and must not become a native-pass claim.
        report = {"schema_version": SCHEMA, "static_verdict": "BLOCKED",
                  "native_verdict": "NOT_RUN_NATIVE", "final_acceptance": "NOT_STARTED",
                  "exit_code": 3, "reason_code": "STAGE_GATE_UNAVAILABLE",
                  "issue_type": type(exc).__name__}
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"Phase A EC151..160: {report['static_verdict']} (exit {report['exit_code']})")
        print("PowerShell/Git/15 Smoke/E63-E66: NOT_RUN_NATIVE; final acceptance NOT_STARTED")
        for item in report.get("checks", []):
            print(f"  {item['status']:11} {item['id']} [{item['reason_code']}]")
            for issue in item.get("issues", [])[:3]:
                print("    - " + issue)
        if report.get("outstanding_dependencies"):
            print("External/upstream limitations:", ", ".join(
                x["id"] + "=" + x["state"] for x in report["outstanding_dependencies"]))
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
