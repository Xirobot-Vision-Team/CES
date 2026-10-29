#!/usr/bin/env python3
"""EC233: genuine but NON-EXECUTING Cycle Next handler for saved EC231 runs.

A `next_step` is a *source-backed route suggestion*, not a command, runtime
scheduler, successful step, permission, or resumable cursor. EC231 cannot
record completed actions, so only original dependency-free NOT_STARTED roots
may ever be proposed. A dependency is never satisfied by a declared PARTIAL
state, and a repeated call deliberately returns the same root until a later
EC supplies independently verified progress and safe state transitions.

Authoritative routing must come from an implemented, inspectable handler:
- seven native PowerShell Action families / 16 EC152 traced routes verified
  by EC155/EC152 source checks; CodeSave always yields await_permission;
- the existing EC174 `HandoffRouter.route` for `AIHandoff:CodeAnalysis`,
  requiring a separately prepared EC173 input and explicit operator grants.
Planned Action names, package metadata strings, and DAG order alone never
create a route. This module never executes, imports a caller plugin, writes,
grants authorization, or modifies an EC231 immutable record.
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
from pathlib import Path
import stat
import sys
from typing import Any

# Earlier construction modules (EC155/EC174) intentionally use standalone
# absolute sibling imports. When EC233 is imported as `construction.cycle_next`,
# expose only its own package directory so the *existing* implemented router
# and source-trace checks can resolve their dependencies. No caller path or
# arbitrary plugin directory is added, and nothing is executed by this route.
if __package__:
    _sibling_dir = str(Path(__file__).resolve().parent)
    if _sibling_dir not in sys.path:
        sys.path.insert(0, _sibling_dir)

import action_registry as registry
import ai_handoff_router as ai
if __package__:
    from . import cycle_dag as dag
    from . import cycle_run_metadata as md
else:
    import cycle_dag as dag
    import cycle_run_metadata as md

SCHEMA = "ces.cycle_next_result.v1"
DOMAIN_NEXT = b"CES-EC233-CYCLE-NEXT-PROPOSAL-v1\x00"
PROPOSED = "NEXT_PROPOSED_NO_EXECUTION"
OPERATOR = "OPERATOR_HANDOFF_REQUIRED"
BLOCKED = "BLOCKED_NO_NEXT"
UNKNOWN = "UNKNOWN_BLOCKED"
KINDS = frozenset(("cli_action", "ai_handoff", "await_permission", "none"))
# A known EC155 legacy check is stale as newer standalone planned capabilities
# appear in the capability matrix. This mismatch is unrelated to original
# 16 implemented PowerShell route/source anchors. No other problem is waived.
LEGACY_PLAN_MATRIX_DRIFT = "planned capability names/states/ranges differ from capability matrix"
ROOT = Path(__file__).resolve().parent.parent
MAX_HANDLER_SOURCE_BYTES = 1_048_576


class CycleNextError(md.CycleMetadataError):
    """No reliably identified *implemented* handler available."""


def _regular_source(root: Path, relative: str) -> tuple[Path, str]:
    """Read bounded package source, refusing links anywhere along the path."""
    md.require(type(relative) is str and relative.startswith(("scripts/", "construction/"))
               and relative.endswith((".ps1", ".py")),
               "CYCLE_NEXT_HANDLER_PATH_INVALID", "Source path must be an allowed package script")
    parts = relative.split("/")
    md.require(len(parts) == 2 and all(p not in ("", ".", "..") for p in parts),
               "CYCLE_NEXT_HANDLER_PATH_INVALID", "Only fixed package-relative script paths allowed")
    try:
        md.require(root.is_dir() and not root.is_symlink(), "CYCLE_NEXT_PACKAGE_UNAVAILABLE",
                   "Source package must be a real directory")
        parent = root / parts[0]
        path = parent / parts[1]
        md.require(parent.is_dir() and not parent.is_symlink() and not path.is_symlink(),
                   "CYCLE_NEXT_HANDLER_SOURCE_UNAVAILABLE", "Source path must not be a symlink")
        st = path.stat(follow_symlinks=False)
        md.require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= MAX_HANDLER_SOURCE_BYTES,
                   "CYCLE_NEXT_HANDLER_SOURCE_UNAVAILABLE", "Handler must be a bounded regular source file")
        # This is static source inspection, never permission to execute it.
        raw = path.read_bytes()
        md.require(len(raw) == st.st_size, "CYCLE_NEXT_HANDLER_SOURCE_CHANGED",
                   "Source changed during static inspection")
        return path, hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError) as exc:
        if isinstance(exc, md.CycleMetadataError):
            raise
        raise CycleNextError("CYCLE_NEXT_HANDLER_SOURCE_UNAVAILABLE", "Source could not be read") from exc


def _cli_route(root: Path, action: str, mode: str | None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a *real* EC152/EC155 R150 dispatch binding; no execution.

    `check_registry` verifies original CLI Action/Mode gates, actual definitions,
    submode calls, reviewed EC157/159 source deltas, and CodeSave approval
    enforcement. An unrelated frozen planned-capability/matrix comparison is
    explicitly not a native handler gate (see LEGACY_PLAN_MATRIX_DRIFT).
    """
    try:
        routes = registry.read_registry(root)
        check = registry.check_registry(routes, root)
        errors = [p for p in check["problems"] if p != LEGACY_PLAN_MATRIX_DRIFT]
        md.require(not errors and check["details"]["authored_route_count"] == 16,
                   "CYCLE_NEXT_CLI_SOURCE_UNVERIFIED", "Implemented native dispatch cannot be source-verified")
        decision = registry.resolve(routes, action=action, mode=mode)
        md.require(decision["decision"] == registry.ROUTABLE and decision["route"] is not None,
                   "CYCLE_NEXT_ACTION_OR_MODE_UNREGISTERED", "Action/Mode is not an implemented route")
        route = decision["route"]
        path, handler_hash = _regular_source(root, route["handler"]["file"])
        cli, cli_hash = _regular_source(root, "scripts/ces.ps1")
        md.require(path.is_file() and cli.is_file() and route["dispatcher"]["file"] == "scripts/ces.ps1",
                   "CYCLE_NEXT_CLI_SOURCE_UNVERIFIED", "Dispatch and handler files must be real")
        # Registry + trace anchor the exact source-authored symbol. Runtime
        # visibility and command argument validation remain untested.
        binding = {"implementation": "NATIVE_R150_POWERSHELL_SOURCE_AUTHORED_UNVERIFIED",
                   "route_id": route["id"], "entrypoint": "scripts/ces.ps1",
                   "handler_file": route["handler"]["file"],
                   "handler_symbol": route["handler"]["symbol"],
                   "handler_sha256": handler_hash, "entrypoint_sha256": cli_hash,
                   "runtime_verified": False, "read_only": route["effect"] == "READ_ONLY",
                   "operator_parameters_required": list(route["inputs"]["required"]),
                   "operator_parameters_optional": list(route["inputs"]["optional"]),
                   "ec152_primary_smoke": route["primary_smoke"]}
        return decision, binding
    except (registry.RegistryError, KeyError, TypeError, IndexError,
            OSError, ValueError, RuntimeError) as exc:
        if isinstance(exc, md.CycleMetadataError):
            raise
        raise CycleNextError("CYCLE_NEXT_CLI_SOURCE_UNVERIFIED", "Unable to validate native handler") from exc


def _ai_route(root: Path, action: str, mode: str | None) -> dict[str, Any]:
    """Bind only the EC174 already-existing code_analysis input-aware router."""
    md.require(action.casefold() == "aihandoff" and mode is not None and
               mode.casefold() == "codeanalysis", "CYCLE_NEXT_AI_ROUTE_UNREGISTERED",
               "AI task/mode has no registered EC174 input builder")
    md.require(ai.TASK_ROUTES.get("code_analysis") == {
        "route_id": ai.ROUTE_ID, "ec173_input_supported": True,
    } and inspect.isfunction(ai.HandoffRouter.route),
        "CYCLE_NEXT_AI_HANDLER_UNAVAILABLE", "EC174 source-specific router unavailable")
    path, source_sha = _regular_source(root, "construction/ai_handoff_router.py")
    try:
        actual = Path(inspect.getsourcefile(ai.HandoffRouter.route) or "").resolve(strict=True)
    except (OSError, ValueError):
        raise CycleNextError("CYCLE_NEXT_AI_HANDLER_UNAVAILABLE", "Unverifiable EC174 route implementation")
    md.require(path.resolve(strict=True) == actual and callable(ai.HandoffRouter.route),
               "CYCLE_NEXT_AI_HANDLER_UNAVAILABLE", "Source must bind the imported existing EC174 class")
    # Do not point a Next handoff at a replaced/stubbed source that happens
    # to retain the old imported Python callable. The previous complete
    # delivery's per-file digest anchors the unchanged EC174 implementation.
    try:
        prior = registry._load_json(root, "construction/HANDOFF_SOURCE_LOCK.json")
        expected = prior["unchanged_original_sha256"]["construction/ai_handoff_router.py"]
        md.require(type(expected) is str and md.SHA_RE.fullmatch(expected) and
                   source_sha == expected, "CYCLE_NEXT_AI_SOURCE_DRIFT",
                   "Existing EC174 router differs from prior complete package")
    except (registry.RegistryError, KeyError, TypeError, OSError) as exc:
        raise CycleNextError("CYCLE_NEXT_AI_SOURCE_PROVENANCE_UNAVAILABLE",
                             "Cannot establish prior EC174 route source") from exc
    return {"implementation": "EC174_PYTHON_SOURCE_BACKED_UNVERIFIED",
            "route_id": ai.ROUTE_ID, "entrypoint": "construction/ai_handoff_router.py",
            "handler_file": "construction/ai_handoff_router.py",
            "handler_symbol": "HandoffRouter.route", "handler_sha256": source_sha,
            "entrypoint_sha256": source_sha, "runtime_verified": False,
            "read_only": False,
            "operator_parameters_required": ["EC173_AUTHORIZED_PREPARED_INPUT", "EC174_ROUTE_APPROVAL",
                                             "EC174_INPUT_READ_APPROVAL"],
            "operator_parameters_optional": ["SEPARATE_EXTERNAL_TRANSFER_APPROVAL_FOR_DISPATCH"],
            "ec152_primary_smoke": None}


def _empty(run_id: str | None) -> dict[str, Any]:
    return {"schema": SCHEMA, "run_id": run_id, "status": UNKNOWN,
            "next_kind": "none", "reason_code": "CYCLE_RUN_UNAVAILABLE",
            "record_sha256": None, "action_set_sha256": None,
            "input_sha256": None, "graph_sha256": None,
            "proposal_sha256": None, "metadata_run_state": None,
            "ready_root_step_ids": [], "unproven_step_ids": [],
            "blocked_by_step_ids": [], "next_step": None,
            "trust": {"metadata_integrity": "UNSIGNED_LOCAL_SELF_HASH_ONLY",
                      "source_authenticated": False, "actor_verified": False,
                      "handler_runtime_verified": False, "permissions_granted": False,
                      "dependencies_satisfied_by_execution": False},
            "effects": {"steps_executed": False, "handler_invoked": False,
                        "can_dispatch": False, "can_resume": False,
                        "permission_pause_persisted": False, "write_authorized": False,
                        "native_cycle_action_registered": False}}


class CycleNextHandler:
    """Inspect one saved run and offer at most one source-backed Next target.

    No caller-provided route table, execution callback, permission bool or
    durable step cursor. Missing/out-of-band hash drift -> UNKNOWN. Unsupported
    roots and declared partial/unknown states cannot be skipped as success.
    """

    def __init__(self, private_dir: str | Path, *, package_root: str | Path | None = None) -> None:
        self.store = md.CycleMetadataStore(private_dir)
        self.inspector = dag.CycleDagInspector(private_dir)
        self.package_root = Path(package_root) if package_root is not None else ROOT

    def next(self, run_id: str, *, expected_record_sha256: str | None = None,
             expected_action_set_sha256: str | None = None,
             expected_input_sha256: str | None = None) -> dict[str, Any]:
        display_id = run_id if type(run_id) is str and md.RUN_RE.fullmatch(run_id) else None
        result = _empty(display_id)
        graph = self.inspector.check(
            run_id, expected_record_sha256=expected_record_sha256,
            expected_action_set_sha256=expected_action_set_sha256,
            expected_input_sha256=expected_input_sha256)
        if graph["status"] != dag.VALID:
            result.update({"status": BLOCKED if graph["status"] == dag.CYCLIC else UNKNOWN,
                           "reason_code": ("CYCLE_NEXT_DAG_CYCLE_BLOCKED" if graph["status"] == dag.CYCLIC
                                           else graph["reason_code"])})
            return result
        try:
            # Reread after EC232 inspection; any intervening change invalidates
            # the proposal, even if both separately self-hash successfully.
            record = self.store.load(run_id)
            md.require(record["record_sha256"] == graph["record_sha256"] and
                       record["action_set_sha256"] == graph["action_set_sha256"] and
                       record["input"]["sha256"] == graph["input_sha256"],
                       "CYCLE_NEXT_RECORD_CHANGED", "Original run changed after DAG validation")
            md.require(md.digest(dag.DOMAIN_GRAPH, {
                "run_id": record["run_id"], "record_sha256": record["record_sha256"],
                "action_set_sha256": record["action_set_sha256"],
                "nodes": [{"step_id": node["step_id"], "depends_on": sorted(node["depends_on"])}
                          for node in record["action_set"]],
            }) == graph["graph_sha256"], "CYCLE_NEXT_GRAPH_CHANGED", "DAG binding changed")
            result.update({"record_sha256": record["record_sha256"],
                           "action_set_sha256": record["action_set_sha256"],
                           "input_sha256": record["input"]["sha256"],
                           "graph_sha256": graph["graph_sha256"],
                           "metadata_run_state": record["run_state"],
                           "unproven_step_ids": [item["step_id"] for item in record["action_set"]]})
            # These states are ONLY metadata declarations, never a verified
            # dependency completion. EC231 provides no COMPLETED state.
            if record["run_state"] != "NOT_STARTED" or any(
                    item["state"] != "NOT_STARTED" for item in record["steps"]):
                result.update({"status": BLOCKED, "reason_code": "CYCLE_NEXT_UNPROVEN_STEP_STATE",
                               "blocked_by_step_ids": [item["step_id"] for item in record["steps"]
                                                       if item["state"] != "NOT_STARTED"]})
                return result
            roots = graph["topological_layers"][0]
            md.require(len(roots) > 0, "CYCLE_NEXT_INTERNAL_NO_ROOT", "Acyclic run must have a root")
            result["ready_root_step_ids"] = list(roots)
            result["blocked_by_step_ids"] = [x for x in graph["topological_order"] if x not in roots]
            root_id = roots[0]  # fail closed, no silent skipping an unsupported earlier root
            item = next(item for item in record["action_set"] if item["step_id"] == root_id)
            action = item["action"]
            mode = item["mode"]
            if action.casefold() == "aihandoff":
                try:
                    binding = _ai_route(self.package_root, action, mode)
                except md.CycleMetadataError as exc:
                    return self._blocked_route(result, exc.code, root_id)
                kind, status, reason = "ai_handoff", OPERATOR, "CYCLE_NEXT_AI_HANDOFF_ONLY"
                effective_action, effective_mode = "AIHandoff", "CodeAnalysis"
            else:
                try:
                    decision, binding = _cli_route(self.package_root, action, mode)
                except md.CycleMetadataError as exc:
                    return self._blocked_route(result, exc.code, root_id)
                effective_action, effective_mode = decision["canonical_action"], decision["effective_mode"]
                if decision["requires_explicit_persist_authorization"]:
                    kind, status, reason = "await_permission", OPERATOR, "CYCLE_NEXT_PERSIST_PERMISSION_REQUIRED"
                    binding["operator_parameters_required"].append("ApprovePersist (explicit native switch)")
                else:
                    kind, status, reason = "cli_action", PROPOSED, "CYCLE_NEXT_READ_ONLY_HANDLER_PROPOSED"
                # Native CodeSave is the only write route in EC155, and a
                # read-only proposal never grants delegated write authority.
                md.require(kind != "cli_action" or binding["read_only"],
                           "CYCLE_NEXT_WRITE_ROUTE_MISCLASSIFIED", "Write route cannot be a read-only Next")
            candidate = {"step_id": root_id, "action": effective_action,
                         "declared_mode": mode, "effective_mode": effective_mode,
                         "depends_on": [], "handler": binding}
            result.update({"status": status, "next_kind": kind, "reason_code": reason,
                           "next_step": candidate})
            # Non-authenticating, domain-separated suggestion checksum; includes
            # graph and exact route binding, not any permission/execution claim.
            result["proposal_sha256"] = md.digest(DOMAIN_NEXT, {
                "run_id": run_id, "record_sha256": record["record_sha256"],
                "graph_sha256": graph["graph_sha256"], "next_kind": kind,
                "next_step": candidate})
            # One more private reread at response boundary to fail closed on
            # observed concurrent modification; NOT a filesystem snapshot/lock.
            md.require(self.store.load(run_id)["record_sha256"] == record["record_sha256"],
                       "CYCLE_NEXT_RECORD_CHANGED", "Run changed while routing")
            return result
        except (md.CycleMetadataError, OSError, ValueError, TypeError, KeyError) as exc:
            # Drop route/provenance on uncertainty; no stale candidate escapes.
            code = exc.code if isinstance(exc, md.CycleMetadataError) else "CYCLE_NEXT_IO_UNAVAILABLE"
            failed = _empty(display_id)
            failed["reason_code"] = code
            return failed

    @staticmethod
    def _blocked_route(result: dict[str, Any], reason: str, root_id: str) -> dict[str, Any]:
        result.update({"status": BLOCKED, "next_kind": "none", "reason_code": reason,
                       "blocked_by_step_ids": [root_id], "next_step": None,
                       "proposal_sha256": None})
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC233 Cycle Next source-backed HANDOFF ONLY; NEVER executes")
    parser.add_argument("next", choices=["next"], help="inspect next original root of a saved run")
    parser.add_argument("--store", required=True, help="EC231 existing owner-private metadata directory")
    parser.add_argument("--run-id", required=True, help="existing immutable EC231 run ID")
    parser.add_argument("--expected-record-sha256", default=None)
    parser.add_argument("--expected-action-set-sha256", default=None)
    parser.add_argument("--expected-input-sha256", default=None)
    args = parser.parse_args(argv)
    try:
        output = CycleNextHandler(args.store).next(
            args.run_id, expected_record_sha256=args.expected_record_sha256,
            expected_action_set_sha256=args.expected_action_set_sha256,
            expected_input_sha256=args.expected_input_sha256)
    except (OSError, ValueError, RuntimeError):
        output = _empty(args.run_id if md.RUN_RE.fullmatch(args.run_id) else None)
        output["reason_code"] = "CYCLE_NEXT_IO_UNAVAILABLE"
    print(json.dumps(output, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return {PROPOSED: 0, OPERATOR: 2, BLOCKED: 3, UNKNOWN: 5}[output["status"]]


if __name__ == "__main__":
    sys.exit(main())
