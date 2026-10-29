#!/usr/bin/env python3
"""EC232: read-only, bounded DAG analysis of an actual EC231 Cycle run.

Only a successfully loaded, structurally and digest-validated EC231 record is
considered. Stable topological waves (not a task schedule) or precise cyclic
SCCs and a closed witness are returned. All outcomes explicitly forbid
execution, permission, resume and dispatch; no EC231 record is mutated.

Neither the stored unsigned digest nor a caller-supplied expected digest is a
signature: source freshness and identity are NOT authenticated here.
"""
from __future__ import annotations

import argparse
from collections import deque
import json
import os
from pathlib import Path
import sys
from typing import Any

if __package__:
    from . import cycle_run_metadata as md
else:
    import cycle_run_metadata as md

SCHEMA = "ces.cycle_dag_result.v1"
DOMAIN_GRAPH = b"CES-EC232-CYCLE-DAG-v1\x00"
VALID = "DAG_VALID_NO_EXECUTION"
CYCLIC = "DAG_CYCLE_BLOCKED"
UNKNOWN = "UNKNOWN_BLOCKED"


class CycleDagError(md.CycleMetadataError):
    """No executable DAG can be certified; code is safe for untrusted output."""


def _strongly_connected_components(ids: list[str], deps: dict[str, list[str]],
                                   position: dict[str, int]) -> list[list[str]]:
    """Deterministic Tarjan over <=32 declared nodes, with dependent -> prerequisite arcs."""
    counter = 0
    discovery: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal counter
        discovery[node] = low[node] = counter
        counter += 1
        stack.append(node)
        on_stack.add(node)
        for prerequisite in sorted(deps[node], key=position.__getitem__):
            if prerequisite not in discovery:
                visit(prerequisite)
                low[node] = min(low[node], low[prerequisite])
            elif prerequisite in on_stack:
                low[node] = min(low[node], discovery[prerequisite])
        if low[node] == discovery[node]:
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            component.sort(key=position.__getitem__)
            components.append(component)

    for step_id in ids:
        if step_id not in discovery:
            visit(step_id)
    return sorted((c for c in components if len(c) > 1),
                  key=lambda c: position[c[0]])


def _closed_cycle(component: list[str], deps: dict[str, list[str]],
                  position: dict[str, int]) -> list[str]:
    """Show a real closed dependency path starting at the earliest SCC member.

    Select a shortest path back to the earliest member, using source step
    order for ties. A downstream node cannot be misreported as cyclic.
    """
    start = component[0]
    members = set(component)
    shortest: list[str] | None = None
    for neighbour in sorted((x for x in deps[start] if x in members),
                            key=position.__getitem__):
        queue: deque[list[str]] = deque([[neighbour]])
        visited = {neighbour}
        while queue:
            path = queue.popleft()
            current = path[-1]
            if current == start:
                candidate = [start, *path]
                if shortest is None or (len(candidate), [position[x] for x in candidate]) < (
                        len(shortest), [position[x] for x in shortest]):
                    shortest = candidate
                break
            for target in sorted((x for x in deps[current] if x in members),
                                 key=position.__getitem__):
                if target not in visited:
                    visited.add(target)
                    queue.append([*path, target])
    if shortest is None:
        # Tarjan guarantees a directed cycle through every vertex of a
        # multi-node SCC. Never fabricate an illustrative but false path.
        raise CycleDagError("CYCLE_DAG_INTERNAL_INCONSISTENCY", "No closed cycle in cyclic SCC")
    return shortest


def _analyze(actions: list[dict[str, Any]]) -> dict[str, Any]:
    """Fully deterministic; bounded O(V^2 + E + V^3) worst case, V <= 32."""
    declared = md._actions(actions)  # EC231's exact shape/ID/ref/limit rules.
    ids = [item["step_id"] for item in declared]
    position = {name: idx for idx, name in enumerate(ids)}
    dependencies = {item["step_id"]: item["depends_on"] for item in declared}
    dependents: dict[str, list[str]] = {name: [] for name in ids}
    indegree = {name: len(dependencies[name]) for name in ids}
    for node in ids:
        for prerequisite in dependencies[node]:
            dependents[prerequisite].append(node)

    # Wave barrier: a newly freed child enters the NEXT layer. Original
    # declaration order breaks ties, not dictionary/hash-set order.
    remaining = set(ids)
    order: list[str] = []
    layers: list[list[str]] = []
    while remaining:
        ready = [name for name in ids if name in remaining and indegree[name] == 0]
        if not ready:
            break
        layers.append(ready)
        for name in ready:
            remaining.remove(name)
            order.append(name)
        for name in ready:
            for child in dependents[name]:
                indegree[child] -= 1

    if remaining:
        groups = _strongly_connected_components(ids, dependencies, position)
        if not groups:
            raise CycleDagError("CYCLE_DAG_INTERNAL_INCONSISTENCY", "Blocked nodes without cyclic SCC")
        return {"valid": False, "order": [], "layers": [],
                "cycle_components": groups,
                "cycle_witness": _closed_cycle(groups[0], dependencies, position),
                "blocked_step_ids": [name for name in ids if name in remaining],
                "step_count": len(ids), "dependency_edge_count": sum(map(len, dependencies.values()))}
    return {"valid": True, "order": order, "layers": layers,
            "cycle_components": [], "cycle_witness": [], "blocked_step_ids": [],
            "step_count": len(ids), "dependency_edge_count": sum(map(len, dependencies.values()))}


def _base_result(run_id: str | None) -> dict[str, Any]:
    """Fail-closed result skeleton; all effects remain forbidden in every branch."""
    return {
        "schema": SCHEMA, "run_id": run_id, "status": UNKNOWN,
        "reason_code": "CYCLE_RUN_UNAVAILABLE",
        "record_sha256": None, "action_set_sha256": None, "input_sha256": None,
        "graph_sha256": None, "source_ref": None, "actor_origin": None,
        "actor_subject": None, "input_completeness": None,
        "metadata_run_state": None, "metadata_dependency_resolution": None,
        "step_count": None, "dependency_edge_count": None,
        "topological_order": [], "topological_layers": [],
        "cycle_components": [], "cycle_witness": [], "blocked_step_ids": [],
        "trust": {"metadata_integrity": "UNSIGNED_LOCAL_SELF_HASH_ONLY",
                  "input_authenticated": False, "actor_verified": False,
                  "permissions_granted": False},
        "effects": {"steps_executed": False, "can_dispatch": False,
                    "can_resume": False, "write_authorized": False,
                    "native_cycle_action_registered": False},
    }


class CycleDagInspector:
    """Check the *saved* EC231 Cycle run; never create or update any record.

    Expected digests are optional OUT-OF-BAND consistency pins, not
    cryptographic authorizations. Caller must retain them independently if
    detection of same-UID modifications is required; even pinned hashes do
    not authenticate source, actor, completeness, or execution.
    """

    def __init__(self, private_dir: str | Path) -> None:
        self.store = md.CycleMetadataStore(private_dir)

    def check(self, run_id: str, *, expected_record_sha256: str | None = None,
              expected_action_set_sha256: str | None = None,
              expected_input_sha256: str | None = None) -> dict[str, Any]:
        display_id = run_id if type(run_id) is str and md.RUN_RE.fullmatch(run_id) else None
        result = _base_result(display_id)
        try:
            md.token(run_id, md.RUN_RE, "CYCLE_RUN_ID_INVALID")
            for pin in (expected_record_sha256, expected_action_set_sha256, expected_input_sha256):
                if pin is not None:
                    md.token(pin, md.SHA_RE, "CYCLE_DAG_PIN_INVALID")
            record = self.store.load(run_id)  # no create; strict metadata digests and private file.
            for expected, actual, code in (
                (expected_record_sha256, record["record_sha256"], "CYCLE_DAG_RECORD_PIN_MISMATCH"),
                (expected_action_set_sha256, record["action_set_sha256"], "CYCLE_DAG_ACTION_PIN_MISMATCH"),
                (expected_input_sha256, record["input"]["sha256"], "CYCLE_DAG_INPUT_PIN_MISMATCH"),
            ):
                if expected is not None:
                    md.require(expected == actual, code, "Saved Cycle run differs from caller's external pin")
            graph = _analyze(record["action_set"])
            graph_subject = {
                "run_id": record["run_id"],
                "record_sha256": record["record_sha256"],
                "action_set_sha256": record["action_set_sha256"],
                "nodes": [{"step_id": node["step_id"],
                           "depends_on": sorted(node["depends_on"])}
                          for node in record["action_set"]],
            }
            result.update({
                "status": VALID if graph["valid"] else CYCLIC,
                "reason_code": "CYCLE_DAG_ACYCLIC" if graph["valid"] else "CYCLE_DAG_CYCLE_DETECTED",
                "record_sha256": record["record_sha256"],
                "action_set_sha256": record["action_set_sha256"],
                "input_sha256": record["input"]["sha256"],
                "graph_sha256": md.digest(DOMAIN_GRAPH, graph_subject),
                "source_ref": record["input"]["source_ref"],
                "actor_origin": record["actor"]["origin"],
                "actor_subject": record["actor"]["subject"],
                "input_completeness": record["input"]["completeness"],
                "metadata_run_state": record["run_state"],
                "metadata_dependency_resolution": record["dependency_resolution"],
                "step_count": graph["step_count"],
                "dependency_edge_count": graph["dependency_edge_count"],
                "topological_order": graph["order"],
                "topological_layers": graph["layers"],
                "cycle_components": graph["cycle_components"],
                "cycle_witness": graph["cycle_witness"],
                "blocked_step_ids": graph["blocked_step_ids"],
            })
        except (md.CycleMetadataError, OSError) as exc:
            # No partial sort, source/actor info, or validity claim on invalid,
            # missing, unpinned, unreadable, or inconsistent metadata.
            result["reason_code"] = exc.code if isinstance(exc, md.CycleMetadataError) else "CYCLE_RUN_UNAVAILABLE"
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC232 Cycle DAG check only (no task execution/dispatch)")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="read one existing EC231 run; report ordered DAG or explicit cycle")
    check.add_argument("--store", required=True, help="existing private EC231 record directory")
    check.add_argument("--run-id", required=True)
    check.add_argument("--expected-record-sha256", help="optional externally retained EC231 record digest")
    check.add_argument("--expected-action-set-sha256", help="optional externally retained action-set digest")
    check.add_argument("--expected-input-sha256", help="optional externally retained caller input digest")
    args = parser.parse_args(argv)
    result = CycleDagInspector(args.store).check(
        args.run_id, expected_record_sha256=args.expected_record_sha256,
        expected_action_set_sha256=args.expected_action_set_sha256,
        expected_input_sha256=args.expected_input_sha256,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return {VALID: 0, CYCLIC: 3, UNKNOWN: 5}[result["status"]]


if __name__ == "__main__":
    sys.exit(main())
