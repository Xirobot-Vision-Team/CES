#!/usr/bin/env python3
"""EC249: conservative, read-only full-function construction determination.

This is a source/evidence decision, NOT a test runner, approval broker, CLI route,
CI attestation, or business-success certification.  No connector/network/write.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "ces.ec249.full_function_determination.v1"
ALLOWED_AUTHORED = "IMPLEMENTED_PENDING_FINAL_ACCEPTANCE"
EXPECTED_KINDS = {"LEGACY_NATIVE_R150": 16, "CLI": 39, "API": 7, "PREVIEW": 1, "HOST_REQUIRED": 11}


class EvidenceError(Exception):
    """The fixed source/evidence snapshot cannot be trusted for this review."""


def _load(root: Path, rel: str) -> dict:
    try:
        data = (root / rel).read_bytes()
        if len(data) > 5_000_000:
            raise EvidenceError(f"oversized evidence: {rel}")
        obj = json.loads(data)
        if not isinstance(obj, dict):
            raise ValueError("top level not object")
        return obj
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"unreadable evidence {rel}: {type(exc).__name__}") from exc


def _safe_rel(rel: str) -> str:
    if not isinstance(rel, str) or not rel or "\\" in rel or "\x00" in rel:
        raise EvidenceError("unsafe relative source reference")
    p = PurePosixPath(rel.rstrip("/"))
    if p.is_absolute() or ".." in p.parts or p.parts[0] in ("", "."):
        raise EvidenceError("unsafe relative source reference")
    return str(p)


def _exists(root: Path, rel: str) -> bool:
    p = root / _safe_rel(rel)
    # Do not chase symlinks out of the bundle when reviewing a claim.
    if any(part.is_symlink() for part in (p, *p.parents) if part != root.parent):
        return False
    if rel.endswith("/"):
        return p.is_dir() and any(p.iterdir())
    return p.is_file()


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for part in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def _key(row: dict) -> tuple[str, str | None]:
    a = row.get("action")
    m = row.get("mode")
    if not isinstance(a, str) or not a or not (m is None or isinstance(m, str)):
        raise EvidenceError("invalid route identity")
    return (a.casefold(), m.casefold() if m else None)


def _gate(gid: str, category: str, state: str, evidence: list[str], implication: str, closure: str) -> dict:
    return {"id": gid, "category": category, "state": state,
            "evidence": evidence, "implication": implication, "closure": closure}


def review(root: Path = ROOT) -> dict[str, Any]:
    """Review the fixed CES snapshot; when evidence is corrupt, fail closed."""
    plan = _load(root, "construction/LEGACY_PLAN.json")
    progress = _load(root, "construction/LEGACY_PROJECT_STATE.json")
    build = _load(root, "BUILD_STATE.json")
    matrix = _load(root, "construction/CAPABILITY_MATRIX.json")
    catalog = _load(root, "references/route-catalog-ec246.json")
    lock = _load(root, "construction/SECURITY_SOURCE_LOCK.json")
    static = _load(root, "construction/SECURITY_REVIEW.json")
    ec247 = _load(root, "construction/LEGACY_REGRESSION_RESULTS.json")
    ec248 = _load(root, "construction/LEGACY_SEQUENCE_RESULTS.json")
    blockers = _load(root, "construction/KNOWN_BLOCKERS.json")
    smoke_manifest = _load(root, "construction/fixtures/ec247/manifest.json")

    integrity_issues: list[str] = []
    rounds = plan.get("rounds")
    if not isinstance(rounds, list) or len(rounds) != 100:
        raise EvidenceError("100-round plan missing or malformed")
    if [x.get("round") for x in rounds if isinstance(x, dict)] != list(range(151, 251)):
        raise EvidenceError("100-round sequence changed, incomplete or duplicated")
    if plan.get("plan_revision") != progress.get("plan_revision"):
        integrity_issues.append("plan_revision_mismatch")
    if (progress.get("last_completed_ec"), progress.get("next_ec"), progress.get("last_delivered_release")) != ("EC-249", "EC-250", "V5.59/R249"):
        integrity_issues.append("progress_release_out_of_sync")
    if (build.get("completed_ec"), build.get("build"), build.get("version")) != ("EC-249", "R249", "V5.59"):
        integrity_issues.append("build_release_out_of_sync")
    per_round = []
    without_index = []
    missing_artifacts = []
    phase_count = collections.Counter()
    for item in rounds:
        n = item["round"]
        status = item.get("status")
        if item.get("ec") != f"EC-{n}" or not isinstance(item.get("title"), str):
            integrity_issues.append(f"round_{n}_identity_invalid")
        phase_count[str(item.get("phase"))] += 1
        required_status = ALLOWED_AUTHORED if n <= 249 else "PLANNED"
        if status != required_status:
            integrity_issues.append(f"round_{n}_status_inconsistent")
        paths = item.get("implementation_artifacts", item.get("implementation", []))
        if not isinstance(paths, list) or any(not isinstance(p, str) for p in paths):
            integrity_issues.append(f"round_{n}_artifact_index_invalid")
            paths = []
        if n <= 249 and not paths:
            without_index.append(n)
        present, absent = [], []
        for path in paths:
            rel = _safe_rel(path)
            (present if _exists(root, path) else absent).append(rel)
        for p in absent:
            missing_artifacts.append({"ec": f"EC-{n}", "path": p})
        report_rel = f"EC-{n}.md"
        if n <= 249 and not _exists(root, report_rel):
            missing_artifacts.append({"ec": f"EC-{n}", "path": report_rel})
        per_round.append({
            "ec": f"EC-{n}", "phase": item.get("phase"), "title": item.get("title"),
            "reported_state": status,
            "implementation_evidence": "DECLARED_ARTIFACTS_PRESENT_NOT_RUNTIME_PROOF" if paths and not absent
                else "DECLARED_ARTIFACTS_MISSING" if absent else "REPORT_ONLY_NO_EXPLICIT_PLAN_ARTIFACT_INDEX" if n < 250
                else "NOT_STARTED",
            "declared_files": len(paths), "present_files": len(present),
            "missing_files": absent, "report_exists": _exists(root, report_rel),
            "execution_or_external_acceptance_proven": False,
        })
    if dict(phase_count) != {k: 10 for k in "ABCDEFGHIJ"}:
        integrity_issues.append("plan_phase_divergence")

    # SHA is a LOCAL byte consistency lock, not signed source provenance.
    locked = lock.get("source_sha256", {})
    if not isinstance(locked, dict) or len(locked) != 307:
        raise EvidenceError("EC244 307-source lock missing")
    drift = []
    for rel, digest in sorted(locked.items()):
        if not isinstance(digest, str) or len(digest) != 64 or not _exists(root, rel):
            drift.append(rel)
        elif _sha(root / _safe_rel(rel)) != digest:
            drift.append(rel)
    if drift:
        integrity_issues.append("frozen_source_sha_drift")

    # Three independent *local records* of the same frozen route universe.
    cr, mr, lr = catalog.get("routes"), matrix.get("unified_v5_routes"), lock.get("route_registry")
    if any(not isinstance(v, list) or len(v) != 74 for v in (cr, mr, lr)):
        raise EvidenceError("missing 74-route fixed inventory")
    cidx, midx, lidx = ({_key(row): row for row in rows} for rows in (cr, mr, lr))
    if any(len(index) != 74 for index in (cidx, midx, lidx)):
        raise EvidenceError("duplicate Action/Mode identity")
    if set(cidx) != set(midx) or set(cidx) != set(lidx):
        integrity_issues.append("route_identity_source_disagreement")
    route_changes = []
    for route in cr:
        key = _key(route)
        m, frozen = midx.get(key), lidx.get(key)
        if m is None or frozen is None:
            continue
        expected_kind = "LEGACY_NATIVE_ONLY" if route.get("route_kind") == "LEGACY_NATIVE_R150" else route.get("route_kind")
        if m != route or frozen.get("kind") != expected_kind:
            route_changes.append(f"{key[0]}:{key[1] or ''}")
    if route_changes:
        integrity_issues.append("route_kind_or_contract_drift")
    kinds = collections.Counter(r.get("route_kind") for r in cr)
    if dict(kinds) != EXPECTED_KINDS or catalog.get("kinds") != EXPECTED_KINDS:
        integrity_issues.append("route_kind_count_changed")
    host_rows = [r for r in cr if r.get("route_kind") == "HOST_REQUIRED"]
    host_routes = [f"{r['action']}/{r['mode']}" for r in host_rows]
    if any(r.get("invokable_by_new_router") is not False or r.get("exposure_state") != "STANDALONE_ROUTER_ALWAYS_DENIES" for r in host_rows):
        integrity_issues.append("host_entry_claims_executability_without_bridge")

    # Provenance of original 15 test files: source exists != execution result.
    smokes = smoke_manifest.get("native_smokes", [])
    smoke_drift = []
    if not isinstance(smokes, list) or len(smokes) != 15:
        integrity_issues.append("native_smoke_manifest_missing")
        smokes = []
    for smoke in smokes:
        name = smoke.get("file", "")
        if not _exists(root, name) or _sha(root / name) != smoke.get("sha256"):
            smoke_drift.append(name)
    if smoke_drift:
        integrity_issues.append("native_smoke_source_drift")

    flags = {
        "original_15_smoke_executed": ec247.get("native_smokes_executed"),
        "native_powershell7_accepted": build.get("runtime_validation", {}).get("native_powershell7"),
        "ec248_native_codeshow_run": ec248.get("native_codeshow_or_15_smoke_executed"),
        "ec248_E63_E66": ec248.get("perf_E63_E66"),
        "host_bridge_implemented": matrix.get("unified_v5_external_host_bridge_implemented"),
        "source_authority_authenticated": static.get("source_authority_authenticated"),
        "business_repository_nonmutation_proven": static.get("business_repository_mutation_absence_proven"),
        "enterprise_actor_authenticated": static.get("actor_authenticated"),
        "enterprise_host_attested": static.get("broker_or_host_attested"),
        "real_network_native_tested": static.get("real_network_and_native_runtime_tested"),
        "final_acceptance": progress.get("final_acceptance"),
    }
    upstream = next((b for b in blockers.get("blockers", []) if b.get("id") == "B-001"), {})
    gaps = [
        _gate("G249-HOST", "IMPLEMENTATION", "BLOCKED", ["construction/CAPABILITY_MATRIX.json", "references/route-catalog-ec246.json"],
              f"{len(host_routes)} 条依赖独立宿主的 Action/Mode 只能拒绝执行；尚无可信宿主桥接。",
              "另行设计并审核最小权限、独立认证的宿主桥接；本轮绝不授予权限。"),
        _gate("G249-QUALITY", "IMPLEMENTATION", "BLOCKED", ["construction/CAPABILITY_MATRIX.json", "EC-186.md", "EC-187.md"],
              "QualityRun/Execute 属于 HOST_REQUIRED；已有前检/预算代码不等于已接入可执行且获认证的测试运行器。",
              "实现获批的隔离执行代理、真实中断与来源证明，并接入 Quality 结果。"),
        _gate("G249-WRITES", "IMPLEMENTATION", "BLOCKED", ["references/route-catalog-ec246.json", "EC-217.md", "EC-225.md", "EC-228.md", "EC-229.md"],
              "Issue 新建、DeliverySend、ReportPublish、DocsOnlyPublish 均为宿主专属路由；独立 Router 尚无实际外部交付通路。",
              "接入独立且逐次批准的宿主服务，保持已有 Issue 和业务 Git 内容不可修改。"),
        _gate("G249-CYCLE", "IMPLEMENTATION", "BLOCKED", ["EC-233.md", "EC-235.md", "EC-236.md", "EC-239.md", "EC-240.md"],
              "Cycle Next/Resume 主要提供建议和只读核对，缺少经独立批准的实际 AI/CLI 派发、调度器安装和全链路推进。",
              "实施经批准的执行与权限链路，或在用户批准修订计划后明确缩小产品承诺。"),
        _gate("G249-NATIVE", "VERIFICATION", "NOT_RUN", ["construction/fixtures/ec247/manifest.json", "construction/LEGACY_SEQUENCE_RESULTS.json"],
              "原 15 套 PowerShell Smoke 虽源码锁定但未执行，原生 CodeShow/Sequence 和 E63–E66 性能也未实测。",
              "在授权环境运行 PowerShell7、独立临时 Git、原 15 套 Smoke 和原生大图。"),
        _gate("G249-PROVIDER", "INTEGRATION", "NOT_VERIFIED", ["construction/KNOWN_BLOCKERS.json", "construction/SECURITY_REVIEW.json"],
              "GitHub/GitLab 源码、CI、Issue 权限以及交付 Provider/收件人许可均缺少真实认证证据。",
              "使用授权测试账号与平台权限，核对精确 SHA、执行主体、接收方及失败/未知结果。"),
        _gate("G249-OS", "SECURITY_ACCEPTANCE", "NOT_RUN", ["construction/SECURITY_REVIEW.json", "construction/FINAL_ACCEPTANCE.md"],
              "Windows/macOS/POSIX 进程树、Git worktree 管理数据、磁盘/输出限额、NFS 和业务仓不变更尚无现场验收。",
              "由用户辅助完成 OS、Git、源码、权限、保密和资源验收，不能用合成测试冒充。"),
        _gate("G249-UPSTREAM", "SOURCE_AUTHORITY", "OPEN", ["construction/KNOWN_BLOCKERS.json", "construction/LEGACY_UPSTREAM_GAP.json"],
              "原冻结 V3.10 规格与原 ROUNDS.json 来源未获认证，现行 100 轮计划仍属暂定方案。",
              "由所有者提供原始文件与来源链，核对差异并在必要时明确批准修订。"),
    ]
    # Check facts against their underlying sources; inconsistent optimistic flags
    # do not silently become a success in this frozen EC249 evaluation.
    if len(host_rows) != 11 or matrix.get("unified_v5_external_host_bridge_implemented") is not False:
        integrity_issues.append("host_gap_input_changed_manual_review_required")
    if not str(upstream.get("state", "")).startswith("OPEN"):
        integrity_issues.append("upstream_blocker_changed_manual_review_required")
    if ec247.get("native_smokes_executed") != 0 or ec248.get("native_codeshow_or_15_smoke_executed") not in (False, 0):
        integrity_issues.append("native_test_claim_changed_no_signed_acceptance")
    if progress.get("final_acceptance") != "NOT_STARTED":
        integrity_issues.append("final_acceptance_state_changed_unexpectedly")
    if static.get("source_authority_authenticated") is not False or static.get("broker_or_host_attested") is not False:
        integrity_issues.append("source_or_host_proof_claim_changed_without_new_evidence")
    if missing_artifacts:
        integrity_issues.append("declared_implementation_artifact_missing")
    if without_index:
        # Not a proved functional defect: historical plan rows lack direct
        # artifact pointers even though EC reports / sources may exist.
        gaps.append(_gate("G249-INDEX", "TRACEABILITY", "PARTIAL", ["construction/LEGACY_PLAN.json"],
                          f"{len(without_index)} 个已有施工记录的轮次在计划内没有明确实现文件列表（另行检查了 EC 报告是否存在）。",
                          "补充经审核的历史源码引用，但不可因此宣称已实际运行成功。"))

    state = "SOURCE_EVIDENCE_INCONSISTENT_BLOCKED" if integrity_issues else "FULL_FUNCTION_NOT_COMPLETE"
    return {
        "schema": SCHEMA, "package": "V5.59/R249", "ec": "EC-249", "claim_scope": "SOURCE_AND_LOCAL_RECEIPT_ONLY_NO_REMOTE_OR_HOST_ATTESTATION",
        "determination": state, "can_claim_full_function_completion": False,
        "may_enter_final_acceptance": False, "may_freeze_ec250_candidate": False,
        "plan_revision_approved": False, "next_round": "EC-250_PLANNED_BUT_FREEZE_GATE_BLOCKED",
        "meaning": "99 authored EC source/report records, not 99 operationally complete features; one EC250 remains planned. No unapproved replanning.",
        "counts": {
            "total_planned_rounds": len(rounds), "authored_reported_rounds": sum(x.get("status") == ALLOWED_AUTHORED for x in rounds),
            "remaining_planned_rounds": sum(x.get("status") == "PLANNED" for x in rounds),
            "phase_rounds": dict(sorted(phase_count.items())),
            "rounds_without_explicit_artifact_index": len(without_index),
            "missing_declared_artifacts": len(missing_artifacts),
            "source_sha_local_matches": len(locked)-len(drift), "source_sha_total": len(locked),
            "route_inventory": dict(sorted(kinds.items())),
            "route_total": len(cr), "routes_not_invokable_on_standalone_router": 16 + len(host_routes),
            "host_required_denied_routes": len(host_rows), "legacy_smoke_source_matches": len(smokes)-len(smoke_drift),
            "legacy_smoke_source_total": 15, "legacy_smoke_executed": int(ec247.get("native_smokes_executed", 0)),
        },
        "host_required_routes": host_routes,
        "flags_from_prior_source_records_not_independent_proof": flags,
        "integrity_issues": sorted(set(integrity_issues)),
        "missing_declared_artifacts": missing_artifacts,
        "rounds_without_explicit_artifact_index": without_index,
        "gaps": gaps, "per_round": per_round,
        "next_action": "Stop EC250 freeze/acceptance handoff; request explicit owner decision on remaining implementation gaps and provisional-plan revision before resuming the freeze gate.",
        "non_goals": ["no business repo/Issue/provider write", "no host bridge", "no unapproved source authority", "no synthetic acceptance PASS", "no rewrite of EC244 pinned sources"],
    }


def markdown(report: dict) -> str:
    count = report["counts"]
    lines = [
        "# EC249 全功能施工完成判定（V5.59/R249）", "",
        f"**结论：{report['determination']}；不得认定全功能已完成，也不得直接进入 EC250 冻结或最终验收。**", "",
        f"施工记录 {count['authored_reported_rounds']}/{count['total_planned_rounds']}；EC250 尚未施工；本地冻结源码 {count['source_sha_local_matches']}/{count['source_sha_total']}，74 条路由（其中 11 条宿主限定、16 条旧原生）。",
        "", "## 具体未闭合条件", "",
    ]
    for g in report["gaps"]:
        lines.append(f"- **{g['id']} [{g['category']} / {g['state']}]** {g['implication']} 修复/验收：{g['closure']}")
    lines.extend(["", "## 判定约束", "",
                  f"- 未索引源码的历史轮次：{count['rounds_without_explicit_artifact_index']}（不等于未实现）；明示引用丢失：{count['missing_declared_artifacts']}。",
                  f"- 原生 15 套 Smoke：源码比对 {count['legacy_smoke_source_matches']}/15、执行 {count['legacy_smoke_executed']}/15；未据此认定可运行。",
                  "- EC244 源 SHA 是本地字节锁，不是上游身份认证。既有离线测试、静态结果不证明真实企业主体、服务商或 OS 行为。",
                  "- EC250 保持 PLANNED，**冻结门槛未达到**；任何增补轮次/产品范围缩减均需用户批准计划修订。", ""])
    if report["integrity_issues"]:
        lines += ["## 源数据或声明矛盾", "", *[f"- `{i}`" for i in report["integrity_issues"]], ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC249 read-only evidence-grounded full-function determination")
    parser.add_argument("--format", choices=("json", "markdown"), default="json", help="write review to stdout only")
    args = parser.parse_args(argv)
    try:
        result = review()
    except EvidenceError as exc:
        print(json.dumps({"schema": SCHEMA, "determination": "SOURCE_EVIDENCE_INCONSISTENT_BLOCKED", "error": str(exc), "may_enter_final_acceptance": False}, ensure_ascii=False), file=sys.stdout)
        return 4
    if args.format == "markdown":
        print(markdown(result))
    else:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 2  # Intentionally no PASS/exit0 for an unfinished product.


if __name__ == "__main__":
    raise SystemExit(main())
