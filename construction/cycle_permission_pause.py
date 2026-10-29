#!/usr/bin/env python3
"""EC235: durable *denial-only* await_permission checkpoint for a real Cycle.

Persist only a permission WAIT/DECLINED record after a fresh, metered EC234
inspection independently derives the EC233 CodeSave:Snapshot route. This is
NEVER a grant, executor, durable completion cursor, approval collector, or
EC236 Resume implementation. No caller-provided proposal is accepted.

The original EC231 metadata remains immutable. The checkpoint is a distinct
private, exclusive-create sidecar; any ambiguous/partial sidecar blocks the
run rather than being overwritten or interpreted as authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import stat
import sys
from typing import Any

if __package__:
    from . import cycle_budget as budget
    from . import cycle_next as nxt
    from . import cycle_run_metadata as md
else:
    import cycle_budget as budget
    import cycle_next as nxt
    import cycle_run_metadata as md

SCHEMA = "ces.cycle_permission_pause.v1"
DOMAIN_PAUSE = b"CES-EC235-CYCLE-PERMISSION-PAUSE-v1\x00"
PAUSE_SUFFIX = ".permission-pause.v1.json"
MAX_PAUSE_BYTES = 16_384
PAUSE_ID_RE = re.compile(r"pause_v1_[0-9a-f]{48}\Z")
RESPONSES = frozenset(("NOT_PROVIDED", "DECLINED"))
STATUS_FOR = {"NOT_PROVIDED": "PAUSED_AWAITING_PERMISSION",
              "DECLINED": "PAUSED_PERMISSION_DECLINED"}
REASON_FOR = {"NOT_PROVIDED": "CYCLE_PAUSE_EXPLICIT_PERSIST_APPROVAL_REQUIRED",
              "DECLINED": "CYCLE_PAUSE_OPERATOR_DECLINED_NO_APPROVAL"}
WAIT_FOR = {"NOT_PROVIDED": "EXPLICIT_CODE_SAVE_APPROVE_PERSIST_REQUIRED",
            "DECLINED": "OPERATOR_DECLINED_NO_DISPATCH"}
ROOT_KEYS = frozenset(("schema", "record_kind", "pause_id", "run_id", "step_id",
                      "status", "reason_code", "wait_reason", "created_at_utc",
                      "clock_trust", "metadata_binding", "route_binding", "budget_observation",
                      "permission_gate", "remaining_step_ids", "trust", "effects", "pause_sha256"))
META_KEYS = frozenset(("record_sha256", "action_set_sha256", "input_sha256",
                      "graph_sha256", "proposal_sha256", "source_ref", "input_byte_length",
                      "actor_origin", "actor_subject"))
ROUTE_KEYS = frozenset(("action", "declared_mode", "effective_mode", "route_id",
                       "entrypoint", "entrypoint_sha256", "handler_file",
                       "handler_symbol", "handler_sha256", "runtime_verified",
                       "read_only", "required_switch"))
BUDGET_KEYS = frozenset(("inspection_result_schema", "inspection_status", "inspection_sha256",
                        "admitted_inspections", "output_bytes", "enforcement_scope"))
GATE_KEYS = frozenset(("operator_response", "observation_trust", "requirement",
                      "independent_approval_verified", "approval_token_issued", "gate_result"))
TRUST_KEYS = frozenset(("metadata_authenticated", "input_authenticated", "actor_verified",
                        "handler_runtime_verified", "permission_verified", "execution_verified"))
EFFECT_KEYS = frozenset(("pause_persisted", "steps_executed", "handler_invoked",
                         "permission_granted", "write_authorized", "can_resume",
                         "dependents_advanced", "native_cycle_registered"))


class CyclePauseError(md.CycleMetadataError):
    """Stable, non-secret denial reason; never implies a grant or task result."""


def _need(yes: bool, code: str) -> None:
    if not yes:
        raise CyclePauseError(code, code)


def _fields(value: Any, keys: frozenset[str], code: str) -> None:
    _need(type(value) is dict and set(value) == keys, code)


def _sha(value: Any, code: str) -> None:
    _need(type(value) is str and md.SHA_RE.fullmatch(value) is not None, code)


def _without_hash(value: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in value.items() if k != "pause_sha256"}


def validate_pause(value: Any, *, expected_run_id: str | None = None) -> dict[str, Any]:
    """Exact saved shape + cross-field fail-closed constraints. Not authentication.

    Do NOT use a caller-supplied valid object as permission. A live saved
    record/source check is mandatory in `CyclePermissionPauseStore.load()`.
    """
    _fields(value, ROOT_KEYS, "CYCLE_PAUSE_SHAPE_INVALID")
    _need(value["schema"] == SCHEMA and value["record_kind"] == "PERMISSION_DENIAL_CHECKPOINT_ONLY",
          "CYCLE_PAUSE_SCHEMA_INVALID")
    md.token(value["run_id"], md.RUN_RE, "CYCLE_PAUSE_RUN_ID_INVALID")
    md.token(value["pause_id"], PAUSE_ID_RE, "CYCLE_PAUSE_ID_INVALID")
    md.token(value["step_id"], md.STEP_RE, "CYCLE_PAUSE_STEP_ID_INVALID")
    if expected_run_id is not None:
        _need(value["run_id"] == expected_run_id, "CYCLE_PAUSE_RUN_ID_MISMATCH")
    moment = md.timestamp(value["created_at_utc"])
    _need(value["clock_trust"] == "UNVERIFIED_HOST_UTC", "CYCLE_PAUSE_TIME_TRUST_INVALID")

    _fields(value["metadata_binding"], META_KEYS, "CYCLE_PAUSE_METADATA_SHAPE_INVALID")
    meta = value["metadata_binding"]
    for key in ("record_sha256", "action_set_sha256", "input_sha256", "graph_sha256", "proposal_sha256"):
        _sha(meta[key], "CYCLE_PAUSE_METADATA_DIGEST_INVALID")
    md.token(meta["source_ref"], md.SOURCE_RE, "CYCLE_PAUSE_SOURCE_REF_INVALID")
    md.token(meta["actor_subject"], md.SUBJECT_RE, "CYCLE_PAUSE_ACTOR_SUBJECT_INVALID")
    _need(type(meta["actor_origin"]) is str and meta["actor_origin"] in md.ACTOR_ORIGINS,
          "CYCLE_PAUSE_ACTOR_ORIGIN_INVALID")
    md.count(meta["input_byte_length"], 1, md.MAX_SNAPSHOT_BYTES, "CYCLE_PAUSE_INPUT_LENGTH_INVALID")

    _fields(value["route_binding"], ROUTE_KEYS, "CYCLE_PAUSE_ROUTE_SHAPE_INVALID")
    route = value["route_binding"]
    _need(route["action"] == "CodeSave" and route["effective_mode"] == "Snapshot" and
          (route["declared_mode"] is None or
           (type(route["declared_mode"]) is str and
            route["declared_mode"].casefold() == "snapshot")) and
          route["route_id"] == "CodeSave:Snapshot" and
          route["entrypoint"] == "scripts/ces.ps1" and
          route["handler_file"] == "scripts/codesave.ps1" and
          type(route["handler_symbol"]) is str and 1 <= len(route["handler_symbol"]) <= 120 and
          all(ch.isascii() and (ch.isalnum() or ch in "-_") for ch in route["handler_symbol"]) and
          route["required_switch"] == "ApprovePersist" and
          route["runtime_verified"] is False and route["read_only"] is False,
          "CYCLE_PAUSE_ROUTE_NOT_PERMISSION_GATED")
    for key in ("handler_sha256", "entrypoint_sha256"):
        _sha(route[key], "CYCLE_PAUSE_HANDLER_HASH_INVALID")

    _fields(value["budget_observation"], BUDGET_KEYS, "CYCLE_PAUSE_BUDGET_SHAPE_INVALID")
    obs = value["budget_observation"]
    _need(obs["inspection_result_schema"] == budget.SCHEMA and
          obs["inspection_status"] == "AWAIT_OPERATOR_ONLY" and
          obs["enforcement_scope"] == "READ_ONLY_NEXT_INSPECTION_AND_OWN_SERIALIZED_BYTES_ONLY",
          "CYCLE_PAUSE_BUDGET_PROOF_ESCALATION")
    _sha(obs["inspection_sha256"], "CYCLE_PAUSE_BUDGET_DIGEST_INVALID")
    md.count(obs["admitted_inspections"], 1, md.MAX_STEPS, "CYCLE_PAUSE_BUDGET_INSPECTIONS_INVALID")
    md.count(obs["output_bytes"], 1, md.LIMIT_MAX["output_bytes"],
             "CYCLE_PAUSE_BUDGET_OUTPUT_INVALID")

    _fields(value["permission_gate"], GATE_KEYS, "CYCLE_PAUSE_GATE_SHAPE_INVALID")
    gate = value["permission_gate"]
    response = gate["operator_response"]
    _need(type(response) is str and response in RESPONSES and
          gate["observation_trust"] == "UNVERIFIED_OPERATOR_DECLARATION" and
          gate["requirement"] == "INDEPENDENT_EXPLICIT_NATIVE_APPROVE_PERSIST" and
          gate["independent_approval_verified"] is False and
          gate["approval_token_issued"] is False and gate["gate_result"] == "DENY",
          "CYCLE_PAUSE_GATE_AUTHORITY_FORBIDDEN")
    _need(value["status"] == STATUS_FOR[response] and
          value["reason_code"] == REASON_FOR[response] and
          value["wait_reason"] == WAIT_FOR[response],
          "CYCLE_PAUSE_RESPONSE_STATE_INCONSISTENT")
    ids = value["remaining_step_ids"]
    _need(type(ids) is list and 1 <= len(ids) <= md.MAX_STEPS,
          "CYCLE_PAUSE_REMAINING_INVALID")
    for step in ids:
        md.token(step, md.STEP_RE, "CYCLE_PAUSE_REMAINING_INVALID")
    _need(len(ids) == len(set(ids)) and value["step_id"] in ids,
          "CYCLE_PAUSE_REMAINING_INVALID")
    _fields(value["trust"], TRUST_KEYS, "CYCLE_PAUSE_TRUST_SHAPE_INVALID")
    _need(all(v is False for v in value["trust"].values()), "CYCLE_PAUSE_TRUST_ESCALATION")
    _fields(value["effects"], EFFECT_KEYS, "CYCLE_PAUSE_EFFECTS_SHAPE_INVALID")
    _need(value["effects"]["pause_persisted"] is True and
          all(v is False for k, v in value["effects"].items() if k != "pause_persisted"),
          "CYCLE_PAUSE_EFFECTS_ESCALATION")
    _sha(value["pause_sha256"], "CYCLE_PAUSE_HASH_INVALID")
    _need(value["pause_sha256"] == md.digest(DOMAIN_PAUSE, _without_hash(value)),
          "CYCLE_PAUSE_HASH_MISMATCH")
    _need(len(md.canonical(value)) <= MAX_PAUSE_BYTES and
          2020 <= moment.year <= 2100, "CYCLE_PAUSE_TOO_LARGE")
    return json.loads(md.canonical(value))


def _read_sidecar(directory_fd: int, run_id: str) -> dict[str, Any]:
    md.token(run_id, md.RUN_RE, "CYCLE_PAUSE_RUN_ID_INVALID")
    try:
        fd = os.open(run_id + PAUSE_SUFFIX,
                     os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                     dir_fd=directory_fd)
    except FileNotFoundError as exc:
        raise CyclePauseError("CYCLE_PAUSE_NOT_FOUND", "CYCLE_PAUSE_NOT_FOUND") from exc
    except OSError as exc:
        raise CyclePauseError("CYCLE_PAUSE_UNAVAILABLE", "CYCLE_PAUSE_UNAVAILABLE") from exc
    try:
        st = os.fstat(fd)
        _need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
              stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and
              0 < st.st_size <= MAX_PAUSE_BYTES, "CYCLE_PAUSE_NOT_PRIVATE")
        chunks: list[bytes] = []
        remaining = MAX_PAUSE_BYTES + 1
        while remaining > 0:
            part = os.read(fd, min(8192, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        raw = b"".join(chunks)
        _need(len(raw) <= MAX_PAUSE_BYTES and len(raw) == st.st_size,
              "CYCLE_PAUSE_LENGTH_CHANGED")
        return validate_pause(md.strict_json(raw, MAX_PAUSE_BYTES), expected_run_id=run_id)
    except OSError as exc:
        raise CyclePauseError("CYCLE_PAUSE_READ_UNAVAILABLE", "CYCLE_PAUSE_READ_UNAVAILABLE") from exc
    finally:
        os.close(fd)


def _match_real_cycle(saved: dict[str, Any], original: dict[str, Any]) -> None:
    meta = saved["metadata_binding"]
    _need(saved["run_id"] == original["run_id"] and
          meta["record_sha256"] == original["record_sha256"] and
          meta["action_set_sha256"] == original["action_set_sha256"] and
          meta["input_sha256"] == original["input"]["sha256"] and
          meta["input_byte_length"] == original["input"]["byte_length"] and
          meta["source_ref"] == original["input"]["source_ref"] and
          meta["actor_origin"] == original["actor"]["origin"] and
          meta["actor_subject"] == original["actor"]["subject"] and
          saved["remaining_step_ids"] == [a["step_id"] for a in original["action_set"]] and
          original["run_state"] == "NOT_STARTED" and
          all(x["state"] == "NOT_STARTED" for x in original["steps"]),
          "CYCLE_PAUSE_CYCLE_BINDING_DRIFT")
    _need(any(a["step_id"] == saved["step_id"] and a["action"].casefold() == "codesave" and
              (a["mode"] is None or (type(a["mode"]) is str and
              a["mode"].casefold() == "snapshot")) and a["depends_on"] == []
              for a in original["action_set"]), "CYCLE_PAUSE_STEP_BINDING_DRIFT")
    _need(md.timestamp(original["created_at_utc"]) <= md.timestamp(saved["created_at_utc"]) <=
          md.timestamp(original["created_at_utc"]) + md.MAX_HORIZON,
          "CYCLE_PAUSE_TIME_OUTSIDE_RUN_HORIZON")


def _match_next(saved: dict[str, Any], decision: dict[str, Any]) -> None:
    """Never trust a suggestion supplied by the caller; compare live EC233."""
    step = decision.get("next_step")
    meta = saved["metadata_binding"]
    route = saved["route_binding"]
    _need(decision.get("status") == nxt.OPERATOR and
          decision.get("next_kind") == "await_permission" and
          decision.get("reason_code") == "CYCLE_NEXT_PERSIST_PERMISSION_REQUIRED" and
          decision.get("record_sha256") == meta["record_sha256"] and
          decision.get("action_set_sha256") == meta["action_set_sha256"] and
          decision.get("input_sha256") == meta["input_sha256"] and
          decision.get("graph_sha256") == meta["graph_sha256"] and
          decision.get("proposal_sha256") == meta["proposal_sha256"] and
          type(step) is dict and step.get("step_id") == saved["step_id"] and
          step.get("action") == route["action"] and
          step.get("declared_mode") == route["declared_mode"] and
          step.get("effective_mode") == route["effective_mode"] and
          step.get("depends_on") == [] and
          type(step.get("handler")) is dict,
          "CYCLE_PAUSE_ROUTE_CHANGED_OR_UNVERIFIED")
    handler = step["handler"]
    for pause_key, live_key in (("route_id", "route_id"), ("entrypoint", "entrypoint"),
                                ("entrypoint_sha256", "entrypoint_sha256"),
                                ("handler_file", "handler_file"), ("handler_symbol", "handler_symbol"),
                                ("handler_sha256", "handler_sha256"),
                                ("read_only", "read_only"), ("runtime_verified", "runtime_verified")):
        _need(route[pause_key] == handler.get(live_key),
              "CYCLE_PAUSE_HANDLER_SOURCE_CHANGED")
    _need("ApprovePersist (explicit native switch)" in handler.get("operator_parameters_required", []) and
          decision.get("ready_root_step_ids") and
          decision["ready_root_step_ids"][0] == saved["step_id"] and
          decision.get("unproven_step_ids") == saved["remaining_step_ids"] and
          decision.get("trust", {}).get("permissions_granted") is False and
          decision.get("effects", {}).get("can_dispatch") is False,
          "CYCLE_PAUSE_AUTHORITY_OR_ROOT_CHANGED")


class CyclePermissionPauseStore:
    """Create/load one immutable DENY checkpoint per real EC231 RunId.

    All writes are confined to `<existing-private-dir>/<RunId>.permission-pause.v1.json`.
    No approval evidence or execution progress can be recorded by this API.
    """

    def __init__(self, private_dir: str | Path, *, package_root: str | Path | None = None) -> None:
        self.path = Path(private_dir)
        self.store = md.CycleMetadataStore(private_dir)
        self.package_root = package_root
        self.next_handler = nxt.CycleNextHandler(private_dir, package_root=package_root)

    def load(self, run_id: str) -> dict[str, Any]:
        """Re-open original+checkpoint; fail closed on drift/untrusted route.

        Can read an actual checkpoint after a process restart. Rechecking the
        live source is read-only but is not an EC234-metered Next inspection.
        """
        md.token(run_id, md.RUN_RE, "CYCLE_PAUSE_RUN_ID_INVALID")
        original = self.store.load(run_id)
        directory_fd = md._safe_dir(self.path, create=False)
        try:
            saved = _read_sidecar(directory_fd, run_id)
        finally:
            os.close(directory_fd)
        _match_real_cycle(saved, original)
        fresh = self.next_handler.next(
            run_id, expected_record_sha256=saved["metadata_binding"]["record_sha256"],
            expected_action_set_sha256=saved["metadata_binding"]["action_set_sha256"],
            expected_input_sha256=saved["metadata_binding"]["input_sha256"])
        _match_next(saved, fresh)
        # Catch an observed swap during independent source check.
        _need(self.store.load(run_id)["record_sha256"] == original["record_sha256"],
              "CYCLE_PAUSE_CYCLE_BINDING_DRIFT")
        return saved

    def inspect(self, run_id: str) -> dict[str, Any]:
        """Pure read: saved WAIT or DECLINED only; no authority transitions."""
        return self.load(run_id)

    def pause(self, run_id: str, *, operator_response: str = "NOT_PROVIDED",
              overrides: dict[str, int] | None = None,
              expected_record_sha256: str | None = None,
              expected_action_set_sha256: str | None = None,
              expected_input_sha256: str | None = None) -> dict[str, Any]:
        """Commit a strictly denial-only pause after one EC234 metered inspection.

        Never accepts Next JSON, a user-provided handler, a permission boolean,
        approval credential or an alleged completed step. Declined consent is
        a declared negative observation only, not an authenticated identity.
        """
        _need(type(operator_response) is str and operator_response in RESPONSES,
              "CYCLE_PAUSE_APPROVAL_NOT_SUPPORTED")
        md.token(run_id, md.RUN_RE, "CYCLE_PAUSE_RUN_ID_INVALID")
        # Never re-issue or overwrite a pause, even a malformed/partial one.
        original = self.store.load(run_id)
        fd = md._safe_dir(self.path, create=False)
        try:
            try:
                os.stat(run_id + PAUSE_SUFFIX, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise CyclePauseError("CYCLE_PAUSE_ALREADY_EXISTS", "CYCLE_PAUSE_ALREADY_EXISTS")
        finally:
            os.close(fd)

        try:
            guard = budget.CycleBudgetGuard(
                self.path, run_id, package_root=self.package_root, overrides=overrides,
                expected_record_sha256=expected_record_sha256,
                expected_action_set_sha256=expected_action_set_sha256,
                expected_input_sha256=expected_input_sha256)
            msg = guard.inspect()
        except (budget.CycleBudgetError, md.CycleMetadataError) as exc:
            raise CyclePauseError("CYCLE_PAUSE_BUDGET_UNAVAILABLE", "CYCLE_PAUSE_BUDGET_UNAVAILABLE") from exc
        _need(msg.status == "AWAIT_OPERATOR_ONLY" and msg.exit_code == 2 and
              bool(msg.payload), "CYCLE_PAUSE_NO_BUDGETED_PERMISSION_STEP")
        observed = msg.parsed()
        _need(type(observed) is dict and observed.get("schema") == budget.SCHEMA and
              observed.get("run_id") == run_id and
              observed.get("status") == "AWAIT_OPERATOR_ONLY" and
              observed.get("record_sha256") == original["record_sha256"] and
              observed.get("remaining_known") is True and
              observed.get("remaining_step_ids") == [x["step_id"] for x in original["action_set"]] and
              observed.get("effects", {}).get("permission_granted") is False and
              observed.get("effects", {}).get("write_authorized") is False and
              observed.get("usage", {}).get("admitted_inspections") == 1 and
              observed.get("usage", {}).get("output_bytes") == len(msg.payload) and
              observed.get("enforcement_scope") ==
              "READ_ONLY_NEXT_INSPECTION_AND_OWN_SERIALIZED_BYTES_ONLY",
              "CYCLE_PAUSE_BUDGET_RESULT_INVALID")
        decision = observed.get("next_proposal")
        _need(type(decision) is dict and decision.get("next_kind") == "await_permission",
              "CYCLE_PAUSE_NOT_A_PERMISSION_STEP")
        # Derive the save boundary only from the actual original run + metered
        # source-backed route, not caller text or a caller fake proposal.
        selected = decision.get("next_step")
        _need(type(selected) is dict and type(selected.get("handler")) is dict,
              "CYCLE_PAUSE_NEXT_NOT_VERIFIED")
        handler = selected["handler"]
        identity = self.store.load(run_id)
        _need(identity["record_sha256"] == original["record_sha256"],
              "CYCLE_PAUSE_CYCLE_CHANGED_DURING_INSPECTION")
        at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        md.timestamp(at)
        saved = {
            "schema": SCHEMA, "record_kind": "PERMISSION_DENIAL_CHECKPOINT_ONLY",
            "pause_id": "pause_v1_" + secrets.token_bytes(24).hex(),
            "run_id": run_id, "step_id": selected["step_id"],
            "status": STATUS_FOR[operator_response], "reason_code": REASON_FOR[operator_response],
            "wait_reason": WAIT_FOR[operator_response],
            "created_at_utc": at, "clock_trust": "UNVERIFIED_HOST_UTC",
            "metadata_binding": {
                "record_sha256": original["record_sha256"],
                "action_set_sha256": original["action_set_sha256"],
                "input_sha256": original["input"]["sha256"],
                "graph_sha256": decision["graph_sha256"],
                "proposal_sha256": decision["proposal_sha256"],
                "source_ref": original["input"]["source_ref"],
                "input_byte_length": original["input"]["byte_length"],
                "actor_origin": original["actor"]["origin"],
                "actor_subject": original["actor"]["subject"],
            },
            "route_binding": {
                "action": selected["action"], "declared_mode": selected["declared_mode"],
                "effective_mode": selected["effective_mode"], "route_id": handler["route_id"],
                "entrypoint": handler["entrypoint"],
                "entrypoint_sha256": handler["entrypoint_sha256"],
                "handler_file": handler["handler_file"],
                "handler_symbol": handler["handler_symbol"],
                "handler_sha256": handler["handler_sha256"],
                "runtime_verified": handler["runtime_verified"],
                "read_only": handler["read_only"], "required_switch": "ApprovePersist",
            },
            "budget_observation": {
                "inspection_result_schema": observed["schema"],
                "inspection_status": observed["status"],
                "inspection_sha256": hashlib.sha256(msg.payload).hexdigest(),
                "admitted_inspections": observed["usage"]["admitted_inspections"],
                "output_bytes": observed["usage"]["output_bytes"],
                "enforcement_scope": observed["enforcement_scope"],
            },
            "permission_gate": {
                "operator_response": operator_response,
                "observation_trust": "UNVERIFIED_OPERATOR_DECLARATION",
                "requirement": "INDEPENDENT_EXPLICIT_NATIVE_APPROVE_PERSIST",
                "independent_approval_verified": False,
                "approval_token_issued": False, "gate_result": "DENY",
            },
            "remaining_step_ids": [a["step_id"] for a in original["action_set"]],
            "trust": {key: False for key in TRUST_KEYS},
            "effects": {key: (key == "pause_persisted") for key in EFFECT_KEYS},
        }
        saved["pause_sha256"] = md.digest(DOMAIN_PAUSE, saved)
        saved = validate_pause(saved, expected_run_id=run_id)
        _match_real_cycle(saved, original)
        # The budget guard validated this route. Check the exact result shape
        # and source binding against the same independently obtained EC233
        # suggestion before creating the filesystem record.
        _match_next(saved, decision)
        raw = md.canonical(saved) + b"\n"
        _need(len(raw) <= MAX_PAUSE_BYTES, "CYCLE_PAUSE_TOO_LARGE")
        fd = md._safe_dir(self.path, create=False)
        try:
            _need(self.store.load(run_id)["record_sha256"] == original["record_sha256"],
                  "CYCLE_PAUSE_CYCLE_CHANGED_BEFORE_COMMIT")
            try:
                outfile = os.open(run_id + PAUSE_SUFFIX,
                                  os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                                  getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=fd)
            except FileExistsError as exc:
                raise CyclePauseError("CYCLE_PAUSE_ALREADY_EXISTS", "CYCLE_PAUSE_ALREADY_EXISTS") from exc
            except OSError as exc:
                raise CyclePauseError("CYCLE_PAUSE_CREATE_UNAVAILABLE", "CYCLE_PAUSE_CREATE_UNAVAILABLE") from exc
            try:
                os.fchmod(outfile, 0o600)
                md._write_all(outfile, raw)
                os.fsync(outfile)
            except (OSError, md.CycleMetadataError) as exc:
                # Keep uncertain/partial sidecar: never delete and retry under
                # the same RunId or silently treat it as a successful commit.
                raise CyclePauseError("CYCLE_PAUSE_WRITE_UNCERTAIN", "CYCLE_PAUSE_WRITE_UNCERTAIN") from exc
            finally:
                os.close(outfile)
            try:
                os.fsync(fd)
                reread = _read_sidecar(fd, run_id)
                _need(reread["pause_sha256"] == saved["pause_sha256"],
                      "CYCLE_PAUSE_READBACK_DIFFERENT")
            except (OSError, md.CycleMetadataError) as exc:
                raise CyclePauseError("CYCLE_PAUSE_COMMIT_UNCERTAIN", "CYCLE_PAUSE_COMMIT_UNCERTAIN") from exc
        finally:
            os.close(fd)
        # Final source/repository readback is separate from EC234's one
        # budgeted suggestion, not a dispatch or authorization inspection.
        return self.load(run_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="EC235 private, durable permission DENIAL checkpoint; never grants, executes or resumes")
    parser.add_argument("command", choices=("pause", "inspect"))
    parser.add_argument("--store", required=True, help="existing EC231 private owner 0700 directory")
    parser.add_argument("--run-id", required=True, help="real saved EC231 RunId")
    parser.add_argument("--operator-response", default="NOT_PROVIDED",
                        choices=sorted(RESPONSES), help="negative/unanswered only, never APPROVED")
    for field in ("record", "action-set", "input"):
        parser.add_argument("--expected-" + field + "-sha256", default=None)
    for field in sorted(budget.OVERRIDE_FIELDS):
        parser.add_argument("--" + field.replace("_", "-"), type=int)
    args = parser.parse_args(argv)
    try:
        service = CyclePermissionPauseStore(args.store)
        if args.command == "pause":
            record = service.pause(
                args.run_id, operator_response=args.operator_response,
                overrides={key: getattr(args, key) for key in budget.OVERRIDE_FIELDS
                           if getattr(args, key) is not None},
                expected_record_sha256=args.expected_record_sha256,
                expected_action_set_sha256=args.expected_action_set_sha256,
                expected_input_sha256=args.expected_input_sha256)
        else:
            # `inspect` has no ability to approve or alter a saved checkpoint.
            _need(args.operator_response == "NOT_PROVIDED" and
                  all(getattr(args, key) is None for key in budget.OVERRIDE_FIELDS) and
                  all(getattr(args, key) is None for key in
                      ("expected_record_sha256", "expected_action_set_sha256", "expected_input_sha256")),
                  "CYCLE_PAUSE_INSPECT_OPTIONS_INVALID")
            record = service.inspect(args.run_id)
        print(json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                         allow_nan=False))
        return 2  # still PAUSED; 2 is not a grant/successful action!
    except (md.CycleMetadataError, budget.CycleBudgetError, OSError, ValueError, TypeError) as exc:
        code = exc.code if isinstance(exc, md.CycleMetadataError) else "CYCLE_PAUSE_UNAVAILABLE"
        print(json.dumps({"schema": "ces.cycle_permission_pause_error.v1", "status": "UNKNOWN_BLOCKED",
                          "reason_code": code, "effects": {"handler_invoked": False,
                          "permission_granted": False, "write_authorized": False, "can_resume": False}},
                         ensure_ascii=True, sort_keys=True))
        return 5


if __name__ == "__main__":
    sys.exit(main())
