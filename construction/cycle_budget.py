#!/usr/bin/env python3
"""EC234: actual *in-process* metering for NON-EXECUTING EC233 Cycle Next.

This is not an executor or a token granting one. It enforces hard byte counts
for the bytes it accepts and emits, plus local admission and sliding-window
limits before invoking a source-backed read-only Next inspector. Monotonic
wall/process CPU are checked before and after an inspection; these are
cooperative limits, NOT an OS watchdog for blocking native/remote handlers.
EC231 immutable usage is deliberately never rewritten or represented as
actual execution usage. All declared steps remain unperformed.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any

if __package__:
    from . import cycle_run_metadata as md
    from . import cycle_next as nxt
else:
    import cycle_run_metadata as md
    import cycle_next as nxt

SCHEMA = "ces.cycle_budget_result.v1"
MAX_CALLS = 32
MAX_WINDOW_MS = 60_000
OUTPUT_KINDS = frozenset(("NO_EXECUTION_PROPOSAL", "AWAIT_OPERATOR_ONLY",
                           "NO_EXECUTION_BLOCKED", "UNKNOWN_BLOCKED", "STOPPED_BUDGET"))
OVERRIDE_FIELDS = frozenset(("max_step_inspections", "wall_ms", "cpu_ms", "evidence_bytes",
                             "output_bytes", "material_bytes", "rate_max_calls", "rate_window_ms"))


class CycleBudgetError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CycleBudgetError(code)


def _now() -> tuple[int, int]:
    try:
        wall, cpu = time.monotonic_ns(), time.process_time_ns()
    except Exception as exc:
        raise CycleBudgetError("CYCLE_BUDGET_CLOCK_UNAVAILABLE") from exc
    _require(type(wall) is int and type(cpu) is int and wall >= 0 and cpu >= 0,
             "CYCLE_BUDGET_CLOCK_UNAVAILABLE")
    return wall, cpu


def _ms_ceil(ns: int) -> int:
    return (ns + 999_999) // 1_000_000


@dataclass(frozen=True)
class BudgetMessage:
    """Already metered, ASCII-encoded complete JSON line, or b'' when impossible.

    The host MUST write `payload` exactly once, without another newline or
    logging sensitive result fields; a host ignoring this boundary is not
    constrained by this controller.
    """
    payload: bytes
    status: str
    reason_code: str
    exit_code: int

    def parsed(self) -> dict[str, Any] | None:
        return json.loads(self.payload) if self.payload else None


class CycleBudgetGuard:
    """Read-only, single-process controller bound to one real EC231 RunId.

    `inspect` never invokes a native action, AI, filesystem writer, or external
    executor. Its strict rate/call/byte counters are shared by all threads
    using *this object*; they are not persisted or coordinated among processes.
    No upstream permission, source identity or completed step is asserted.
    """

    def __init__(self, private_dir: str | Path, run_id: str, *,
                 package_root: str | Path | None = None,
                 overrides: dict[str, int] | None = None,
                 expected_record_sha256: str | None = None,
                 expected_action_set_sha256: str | None = None,
                 expected_input_sha256: str | None = None) -> None:
        self.store = md.CycleMetadataStore(private_dir)
        self.next_handler = nxt.CycleNextHandler(private_dir, package_root=package_root)
        original = self.store.load(run_id)  # real private record, not submitted JSON
        self.run_id = original["run_id"]
        self.record_sha256 = original["record_sha256"]
        self.action_set_sha256 = original["action_set_sha256"]
        self.input_sha256 = original["input"]["sha256"]
        self.input_bytes = original["input"]["byte_length"]
        self.remaining_ids = [item["step_id"] for item in original["action_set"]]
        for label, supplied, actual in (("RECORD", expected_record_sha256, self.record_sha256),
                                        ("ACTIONS", expected_action_set_sha256, self.action_set_sha256),
                                        ("INPUT", expected_input_sha256, self.input_sha256)):
            if supplied is not None:
                _require(type(supplied) is str and md.SHA_RE.fullmatch(supplied) is not None
                         and supplied == actual, "CYCLE_BUDGET_" + label + "_PIN_MISMATCH")
        saved = original["budget"]["limits"]
        _require(original["budget"]["enforcement"] == "CAPTURE_ONLY_NO_RUN_ENFORCEMENT" and
                 original["budget"]["usage"]["steps"] == 0,
                 "CYCLE_BUDGET_METADATA_NOT_EXECUTION")
        defaults = {
            "max_step_inspections": saved["max_steps"], "wall_ms": saved["wall_ms"],
            "cpu_ms": min(saved["wall_ms"], 10_000),
            "evidence_bytes": saved["evidence_bytes"],
            "output_bytes": saved["output_bytes"],
            # This is a material ACCOUNTING ceiling, not a process RSS/IO cap.
            "material_bytes": self.input_bytes + saved["evidence_bytes"] + saved["output_bytes"],
            "rate_max_calls": 4, "rate_window_ms": 1_000,
        }
        _require(overrides is None or type(overrides) is dict,
                 "CYCLE_BUDGET_OVERRIDES_INVALID")
        overrides = overrides or {}
        _require(set(overrides).issubset(OVERRIDE_FIELDS) and
                 all(type(v) is int for v in overrides.values()),
                 "CYCLE_BUDGET_OVERRIDES_INVALID")
        upper = {
            "max_step_inspections": saved["max_steps"], "wall_ms": saved["wall_ms"],
            "cpu_ms": saved["wall_ms"], "evidence_bytes": saved["evidence_bytes"],
            "output_bytes": saved["output_bytes"],
            "material_bytes": self.input_bytes + saved["evidence_bytes"] + saved["output_bytes"],
            "rate_max_calls": MAX_CALLS, "rate_window_ms": MAX_WINDOW_MS,
        }
        for key, value in overrides.items():
            _require(1 <= value <= upper[key], "CYCLE_BUDGET_OVERRIDE_OUT_OF_RANGE")
            defaults[key] = value
        # When the operator lowers wall time, auto-lower the default CPU
        # ceiling as well; an explicitly incompatible CPU override is denied.
        if "cpu_ms" not in overrides:
            defaults["cpu_ms"] = min(defaults["cpu_ms"], defaults["wall_ms"])
        _require(defaults["material_bytes"] >= self.input_bytes and
                 defaults["cpu_ms"] <= defaults["wall_ms"],
                 "CYCLE_BUDGET_LIMITS_INCONSISTENT")
        self.limits = {"max_step_inspections": defaults["max_step_inspections"],
                       "wall_ms": defaults["wall_ms"], "cpu_ms": defaults["cpu_ms"],
                       "input_bytes": saved["input_bytes"],
                       "evidence_bytes": defaults["evidence_bytes"],
                       "output_bytes": defaults["output_bytes"],
                       "material_bytes": defaults["material_bytes"],
                       "rate_max_calls": defaults["rate_max_calls"],
                       "rate_window_ms": defaults["rate_window_ms"]}
        self.start_wall_ns, self.start_cpu_ns = _now()
        self.last_wall_ns = self.start_wall_ns
        self.last_cpu_ns = self.start_cpu_ns
        self.owner_pid = os.getpid()
        self.lock = threading.Lock()
        self.window: deque[int] = deque()
        self.attempts = 0
        self.inspections = 0
        self.evidence_bytes = 0
        self.output_bytes = 0
        self.closed_reason: str | None = None

    def _elapsed(self) -> tuple[int, int, int]:
        wall, cpu = _now()
        _require(os.getpid() == self.owner_pid and wall >= self.last_wall_ns and
                 cpu >= self.last_cpu_ns and wall >= self.start_wall_ns and
                 cpu >= self.start_cpu_ns, "CYCLE_BUDGET_CLOCK_OR_PID_CHANGED")
        self.last_wall_ns, self.last_cpu_ns = wall, cpu
        return wall, _ms_ceil(wall - self.start_wall_ns), _ms_ceil(cpu - self.start_cpu_ns)

    def _identity_current(self) -> bool:
        try:
            rec = self.store.load(self.run_id)
            return (rec["record_sha256"] == self.record_sha256 and
                    rec["action_set_sha256"] == self.action_set_sha256 and
                    rec["input"]["sha256"] == self.input_sha256 and
                    rec["input"]["byte_length"] == self.input_bytes)
        except (md.CycleMetadataError, OSError, ValueError):
            return False

    @staticmethod
    def _exit(status: str) -> int:
        return {"NO_EXECUTION_PROPOSAL": 0, "AWAIT_OPERATOR_ONLY": 2,
                "NO_EXECUTION_BLOCKED": 3, "UNKNOWN_BLOCKED": 5,
                "STOPPED_BUDGET": 3}[status]

    def _report(self, status: str, reason: str, decision: dict[str, Any] | None,
                known: bool, elapsed: tuple[int, int, int] | None = None) -> dict[str, Any]:
        if elapsed is None:
            try:
                elapsed = self._elapsed()
            except CycleBudgetError:
                elapsed = (0, self.limits["wall_ms"], self.limits["cpu_ms"])
        return {
            "schema": SCHEMA, "run_id": self.run_id, "status": status,
            "reason_code": reason, "record_sha256": self.record_sha256,
            "remaining_known": known,
            "remaining_step_ids": list(self.remaining_ids) if known else [],
            "unperformed_count": len(self.remaining_ids) if known else None,
            "next_proposal": decision if status in ("NO_EXECUTION_PROPOSAL", "AWAIT_OPERATOR_ONLY") else None,
            "budget_limits": dict(self.limits),
            "usage": {"inspection_attempts": self.attempts,
                      "admitted_inspections": self.inspections,
                      "rate_window_calls": len(self.window),
                      "wall_ms": elapsed[1], "cpu_ms": elapsed[2],
                      "input_bytes": self.input_bytes,
                      "evidence_bytes": self.evidence_bytes,
                      "output_bytes": self.output_bytes,
                      "material_bytes": self.input_bytes + self.evidence_bytes + self.output_bytes},
            "rate_scope": "SINGLE_CONTROLLER_PROCESS_ONLY",
            "enforcement_scope": "READ_ONLY_NEXT_INSPECTION_AND_OWN_SERIALIZED_BYTES_ONLY",
            "trust": {"actor_verified": False, "input_authenticated": False,
                      "execution_verified": False, "global_rate_enforced": False,
                      "external_hard_limits_armed": False},
            "effects": {"steps_executed": False, "handler_invoked": False,
                        "permission_granted": False, "write_authorized": False,
                        "can_resume": False, "pause_persisted": False,
                        "native_cycle_registered": False},
        }

    def _serialize(self, report: dict[str, Any]) -> tuple[bytes, int] | None:
        """Solve actual serialized JSON-line length including its usage counters.

        If even a no-proposal safety report does not fit, caller returns zero
        bytes. No truncated JSON, side-channel spill to stderr or oversized
        stdout is allowed.
        """
        for _ in range(12):
            raw = md.canonical(report) + b"\n"
            total = self.output_bytes + len(raw)
            material = self.input_bytes + self.evidence_bytes + total
            if (report["usage"]["output_bytes"] == total and
                    report["usage"]["material_bytes"] == material):
                if total > self.limits["output_bytes"] or material > self.limits["material_bytes"]:
                    return None
                return raw, total
            report["usage"]["output_bytes"] = total
            report["usage"]["material_bytes"] = material
        raise CycleBudgetError("CYCLE_BUDGET_ENCODING_UNSTABLE")

    def _emit(self, status: str, reason: str, decision: dict[str, Any] | None,
              known: bool) -> BudgetMessage:
        _require(status in OUTPUT_KINDS, "CYCLE_BUDGET_STATUS_INVALID")
        try:
            elapsed = self._elapsed()
            if elapsed[1] >= self.limits["wall_ms"]:
                status, reason, decision = "STOPPED_BUDGET", "CYCLE_BUDGET_WALL_TIME_LIMIT", None
                self.closed_reason = reason
            elif elapsed[2] >= self.limits["cpu_ms"]:
                status, reason, decision = "STOPPED_BUDGET", "CYCLE_BUDGET_CPU_LIMIT", None
                self.closed_reason = reason
        except CycleBudgetError:
            status, reason, decision, known = ("UNKNOWN_BLOCKED", "CYCLE_BUDGET_CLOCK_OR_PID_CHANGED",
                                               None, False)
            self.closed_reason = reason
            elapsed = None
        report = self._report(status, reason, decision, known, elapsed)
        encoded = self._serialize(report)
        if encoded is None:
            # Remove the suggested handler and expose only the remaining steps.
            # The output budget may be too small even for this summary.
            prior_status, prior_reason = status, reason
            status, reason = "STOPPED_BUDGET", "CYCLE_BUDGET_OUTPUT_OR_MATERIAL_LIMIT"
            self.closed_reason = reason
            report = self._report(status, reason, None, known)
            encoded = self._serialize(report)
            if encoded is None:
                # Preserve the earlier, more specific denial if the report
                # itself cannot fit; never print even a partial JSON object.
                denied_reason = prior_reason if prior_status == "STOPPED_BUDGET" else reason
                return BudgetMessage(b"", status, denied_reason, 3)
        raw, consumed = encoded
        # Post-serialization time measurement. Never emit an optimistic Next
        # after observing an elapsed-time breach. No hard timer interrupts.
        try:
            late = self._elapsed()
            if late[1] >= self.limits["wall_ms"] or late[2] >= self.limits["cpu_ms"]:
                reason = ("CYCLE_BUDGET_WALL_TIME_LIMIT" if late[1] >= self.limits["wall_ms"]
                          else "CYCLE_BUDGET_CPU_LIMIT")
                status = "STOPPED_BUDGET"
                self.closed_reason = reason
                report = self._report(status, reason, None, known, late)
                encoded = self._serialize(report)
                if encoded is None:
                    return BudgetMessage(b"", status, reason, 3)
                raw, consumed = encoded
        except CycleBudgetError:
            status, reason = "UNKNOWN_BLOCKED", "CYCLE_BUDGET_CLOCK_OR_PID_CHANGED"
            self.closed_reason = reason
            report = self._report(status, reason, None, False)
            encoded = self._serialize(report)
            if encoded is None:
                return BudgetMessage(b"", status, reason, 5)
            raw, consumed = encoded
        self.output_bytes = consumed
        return BudgetMessage(raw, status, reason, self._exit(status))


    def _validate_next(self, decision: Any) -> bool:
        """Defense in depth against malformed/elevated nested Next results.

        Valid source binding is performed in EC233; EC234 also insists on
        stable shape, bounded bytes, an unproven inventory and NO authority.
        """
        if type(decision) is not dict or decision.get("schema") != nxt.SCHEMA or \
                decision.get("run_id") != self.run_id:
            return False
        try:
            if len(md.canonical(decision)) > 24_576:
                return False
            expected_effects = {"steps_executed", "handler_invoked", "can_dispatch",
                                "can_resume", "permission_pause_persisted",
                                "write_authorized", "native_cycle_action_registered"}
            effects = decision["effects"]
            expected_trust = {"metadata_integrity", "source_authenticated",
                              "actor_verified", "handler_runtime_verified",
                              "permissions_granted", "dependencies_satisfied_by_execution"}
            trust = decision["trust"]
            if (type(effects) is not dict or set(effects) != expected_effects or
                    any(value is not False for value in effects.values()) or
                    type(trust) is not dict or set(trust) != expected_trust or
                    trust["metadata_integrity"] != "UNSIGNED_LOCAL_SELF_HASH_ONLY" or
                    any(value is not False for name, value in trust.items()
                        if name != "metadata_integrity") or
                    decision["status"] not in (nxt.PROPOSED, nxt.OPERATOR, nxt.BLOCKED, nxt.UNKNOWN) or
                    decision["next_kind"] not in ("cli_action", "ai_handoff", "await_permission", "none")):
                return False
            if decision["status"] in (nxt.PROPOSED, nxt.OPERATOR):
                step = decision["next_step"]
                if (type(step) is not dict or step.get("step_id") not in self.remaining_ids or
                        step.get("depends_on") != [] or
                        decision["unproven_step_ids"] != self.remaining_ids or
                        decision["record_sha256"] != self.record_sha256 or
                        decision["action_set_sha256"] != self.action_set_sha256 or
                        decision["input_sha256"] != self.input_sha256 or
                        type(decision["proposal_sha256"]) is not str or
                        md.SHA_RE.fullmatch(decision["proposal_sha256"]) is None or
                        type(step.get("handler")) is not dict or
                        step["handler"].get("runtime_verified") is not False):
                    return False
            elif decision["next_step"] is not None or decision["next_kind"] != "none":
                return False
            return True
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError, md.CycleMetadataError):
            return False

    def inspect(self, *, diagnostic_bytes: bytes = b"") -> BudgetMessage:
        """Meter one real read-only Next inspection; return exact output bytes.

        diagnostic_bytes are local, ephemeral instrumentation material and
        NEVER establish proof, are not echoed, and are not saved. Consumption
        is charged before the call. Repeated proposals DO NOT consume or
        satisfy any EC231 execution/dependency step.
        """
        _require(type(diagnostic_bytes) is bytes, "CYCLE_BUDGET_DIAGNOSTICS_NOT_BYTES")
        with self.lock:
            self.attempts += 1
            if self.closed_reason is not None:
                return self._emit("STOPPED_BUDGET", self.closed_reason, None, True)
            try:
                tick, wall_ms, cpu_ms = self._elapsed()
            except CycleBudgetError:
                self.closed_reason = "CYCLE_BUDGET_CLOCK_OR_PID_CHANGED"
                return self._emit("UNKNOWN_BLOCKED", self.closed_reason, None, False)
            if wall_ms >= self.limits["wall_ms"]:
                self.closed_reason = "CYCLE_BUDGET_WALL_TIME_LIMIT"
            elif cpu_ms >= self.limits["cpu_ms"]:
                self.closed_reason = "CYCLE_BUDGET_CPU_LIMIT"
            elif self.inspections >= self.limits["max_step_inspections"]:
                self.closed_reason = "CYCLE_BUDGET_STEP_INSPECTION_LIMIT"
            elif (self.evidence_bytes + len(diagnostic_bytes) > self.limits["evidence_bytes"]):
                self.closed_reason = "CYCLE_BUDGET_EVIDENCE_LIMIT"
            elif (self.input_bytes + self.evidence_bytes + len(diagnostic_bytes) + self.output_bytes
                  > self.limits["material_bytes"]):
                self.closed_reason = "CYCLE_BUDGET_MATERIAL_LIMIT"
            else:
                cutoff = tick - self.limits["rate_window_ms"] * 1_000_000
                while self.window and self.window[0] <= cutoff:
                    self.window.popleft()
                if len(self.window) >= self.limits["rate_max_calls"]:
                    self.closed_reason = "CYCLE_BUDGET_RATE_LIMIT"
            if self.closed_reason is not None:
                return self._emit("STOPPED_BUDGET", self.closed_reason, None, True)
            if not self._identity_current():
                self.closed_reason = "CYCLE_BUDGET_RECORD_DRIFT"
                return self._emit("UNKNOWN_BLOCKED", self.closed_reason, None, False)
            self.evidence_bytes += len(diagnostic_bytes)
            self.window.append(tick)
            self.inspections += 1
            try:
                decision = self.next_handler.next(
                    self.run_id, expected_record_sha256=self.record_sha256,
                    expected_action_set_sha256=self.action_set_sha256,
                    expected_input_sha256=self.input_sha256)
                _require(self._validate_next(decision), "CYCLE_BUDGET_NEXT_INVALID")
            except Exception:
                # An unexpected local inspector error is UNKNOWN, never a
                # permission grant or a partially serialized proposal.
                decision = None
            if not self._identity_current():
                self.closed_reason = "CYCLE_BUDGET_RECORD_DRIFT"
                return self._emit("UNKNOWN_BLOCKED", self.closed_reason, None, False)
            if decision is None or decision.get("status") == nxt.UNKNOWN:
                return self._emit("UNKNOWN_BLOCKED", "CYCLE_BUDGET_NEXT_UNKNOWN", None, True)
            if decision.get("status") == nxt.BLOCKED:
                return self._emit("NO_EXECUTION_BLOCKED", "CYCLE_BUDGET_NEXT_BLOCKED", None, True)
            if (decision.get("status"), decision.get("next_kind")) in (
                    (nxt.PROPOSED, "cli_action"), (nxt.OPERATOR, "ai_handoff"),
                    (nxt.OPERATOR, "await_permission")) and (
                    decision.get("record_sha256") == self.record_sha256 and
                    decision.get("input_sha256") == self.input_sha256 and
                    decision.get("action_set_sha256") == self.action_set_sha256 and
                    decision.get("proposal_sha256") is not None):
                status = ("NO_EXECUTION_PROPOSAL" if decision["status"] == nxt.PROPOSED
                          else "AWAIT_OPERATOR_ONLY")
                return self._emit(status, "CYCLE_BUDGET_NEXT_INSPECTED_NO_EXECUTION",
                                  decision, True)
            return self._emit("UNKNOWN_BLOCKED", "CYCLE_BUDGET_NEXT_INCONSISTENT", None, True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC234 local, NON-EXECUTING Cycle Next budget controller")
    parser.add_argument("inspect", choices=["inspect"])
    parser.add_argument("--store", required=True, help="existing owner-private EC231 metadata directory")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--checks", type=int, default=1, help="1..32 inspections using ONE in-process rate meter")
    for name in sorted(OVERRIDE_FIELDS):
        parser.add_argument("--" + name.replace("_", "-"), type=int)
    for field in ("record", "action-set", "input"):
        parser.add_argument("--expected-" + field + "-sha256")
    args = parser.parse_args(argv)
    if not (1 <= args.checks <= MAX_CALLS):
        parser.error("--checks must be between 1 and 32")
    overrides = {k: getattr(args, k) for k in OVERRIDE_FIELDS if getattr(args, k) is not None}
    try:
        guard = CycleBudgetGuard(
            args.store, args.run_id, overrides=overrides,
            expected_record_sha256=args.expected_record_sha256,
            expected_action_set_sha256=args.expected_action_set_sha256,
            expected_input_sha256=args.expected_input_sha256)
    except (CycleBudgetError, md.CycleMetadataError, OSError, ValueError) as exc:
        code = getattr(exc, "code", "CYCLE_BUDGET_STORE_UNAVAILABLE")
        # No validated record means no trustworthy output quota or step list.
        print(code, file=sys.stderr)
        return 5
    result = BudgetMessage(b"", "UNKNOWN_BLOCKED", "CYCLE_BUDGET_NOT_STARTED", 5)
    for _ in range(args.checks):
        result = guard.inspect()
        if result.payload:
            sys.stdout.buffer.write(result.payload)  # already newline-inclusive, byte-metered
        if result.status in ("STOPPED_BUDGET", "NO_EXECUTION_BLOCKED", "UNKNOWN_BLOCKED"):
            break
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
