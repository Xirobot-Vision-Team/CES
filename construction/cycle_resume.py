#!/usr/bin/env python3
"""EC236: recovery-time *read/check* for an EC231 run + EC235 DENY pause.

This implements real, restart-safe, source-rechecked state *inspection*, not
execution resumption. The caller MUST supply fresh snapshot BYTES (not a hash)
and its declared source reference on each call. If the bytes/source changed,
the old run cannot be re-used: start a fresh EC231 capture/preparation. If
they match, the only restorable state is the durable DENY checkpoint; its
CodeSave permission remains unsatisfied and no step becomes executable.

Never accept approvals, a saved Next JSON, mutable step states or a caller-
asserted permission bool. EC235 persisted sha256 is an UNSIGNED consistency
check, not independent proof of actor, current business source or permission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

if __package__:
    from . import cycle_run_metadata as md
    from . import cycle_permission_pause as pause
else:
    import cycle_run_metadata as md
    import cycle_permission_pause as pause

SCHEMA = "ces.cycle_resume_check.v1"
CHECK_KINDS = frozenset(("PAUSED_PERMISSION_REQUIRED", "REPREPARE_REQUIRED", "UNKNOWN_BLOCKED"))
EFFECT_KEYS = frozenset(("handler_invoked", "steps_executed", "dependencies_advanced",
                         "metadata_written", "pause_written", "new_run_created",
                         "approval_token_issued", "permission_granted", "write_authorized",
                         "can_dispatch", "can_resume", "native_cycle_registered"))
ROOT_KEYS = frozenset(("schema", "status", "reason_code", "next_action", "run_id",
                       "checkpoint_verified", "record_binding", "fresh_input",
                       "saved_input", "restored_checkpoint", "permission_check",
                       "trust", "effects"))
RECORD_KEYS = frozenset(("record_sha256", "action_set_sha256", "graph_sha256",
                         "proposal_sha256", "pause_sha256"))
INPUT_KEYS = frozenset(("source_ref", "sha256", "byte_length"))
FRESH_KEYS = INPUT_KEYS | frozenset(("bytes_match", "source_ref_match"))
CHECKPOINT_KEYS = frozenset(("pause_id", "step_id", "operator_response",
                            "run_state", "remaining_step_ids", "step_states"))
PERMISSION_KEYS = frozenset(("saved_gate", "explicit_native_gate_required",
                             "independent_approval_verified", "native_gate_rechecked"))
TRUST_KEYS = frozenset(("fresh_bytes_supplied", "input_source_authenticated",
                        "actor_authenticated", "metadata_authenticated",
                        "pause_authenticated", "permission_authenticated",
                        "step_execution_proven"))
REASONS = {
    "unchanged_wait": "CYCLE_RESUME_STILL_AWAITING_INDEPENDENT_PERMISSION",
    "unchanged_declined": "CYCLE_RESUME_PRIOR_PERMISSION_DECLINED",
    "input_drift": "CYCLE_RESUME_INPUT_CHANGED_REPREPARE",
    "source_drift": "CYCLE_RESUME_SOURCE_REF_CHANGED_REPREPARE",
    "both_drift": "CYCLE_RESUME_INPUT_AND_SOURCE_CHANGED_REPREPARE",
}


class CycleResumeError(md.CycleMetadataError):
    """Invalid fresh capture or unreliable metadata; never safe to resume."""


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise CycleResumeError(code, code)


def _fingerprint(data: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "byte_length": len(data)}


def _pin(value: str | None, label: str) -> None:
    if value is not None:
        _need(type(value) is str and md.SHA_RE.fullmatch(value) is not None,
              "CYCLE_RESUME_" + label + "_PIN_INVALID")


def _empty_record() -> dict[str, None]:
    return {key: None for key in RECORD_KEYS}


def _empty_input() -> dict[str, None]:
    return {key: None for key in INPUT_KEYS}


def _empty_checkpoint() -> dict[str, Any]:
    return {"pause_id": None, "step_id": None, "operator_response": "UNKNOWN",
            "run_state": "UNKNOWN", "remaining_step_ids": [], "step_states": []}


def _result(*, status: str, reason_code: str, run_id: str | None,
            record: dict[str, Any] | None, checkpoint: dict[str, Any] | None,
            fresh: dict[str, Any] | None, source_ref: str | None,
            bytes_match: bool | None, source_match: bool | None) -> dict[str, Any]:
    verified = record is not None and checkpoint is not None
    saved_input = ({key: record["input"][key] for key in INPUT_KEYS}
                   if verified else _empty_input())
    record_binding = ({"record_sha256": record["record_sha256"],
                       "action_set_sha256": record["action_set_sha256"],
                       "graph_sha256": checkpoint["metadata_binding"]["graph_sha256"],
                       "proposal_sha256": checkpoint["metadata_binding"]["proposal_sha256"],
                       "pause_sha256": checkpoint["pause_sha256"]}
                      if verified else _empty_record())
    restored = ({"pause_id": checkpoint["pause_id"], "step_id": checkpoint["step_id"],
                 "operator_response": checkpoint["permission_gate"]["operator_response"],
                 "run_state": record["run_state"],
                 "remaining_step_ids": list(checkpoint["remaining_step_ids"]),
                 "step_states": [{"step_id": step["step_id"], "state": step["state"]}
                                 for step in record["steps"]]}
                if verified else _empty_checkpoint())
    result: dict[str, Any] = {
        "schema": SCHEMA, "status": status, "reason_code": reason_code,
        "next_action": ("CREATE_FRESH_RUN_AND_REPREPARE" if status == "REPREPARE_REQUIRED" else
                        "REVALIDATE_INDEPENDENT_PERMISSION_OUTSIDE_RESUME" if verified else
                        "MANUAL_REVIEW_NO_RECOVERY"),
        "run_id": run_id, "checkpoint_verified": verified,
        "record_binding": record_binding, "saved_input": saved_input,
        "fresh_input": {"source_ref": source_ref,
                        "sha256": fresh["sha256"] if fresh is not None else None,
                        "byte_length": fresh["byte_length"] if fresh is not None else None,
                        "bytes_match": bytes_match, "source_ref_match": source_match},
        "restored_checkpoint": restored,
        "permission_check": {
            "saved_gate": "DENY" if verified else "UNKNOWN",
            "explicit_native_gate_required": "ApprovePersist" if verified else None,
            "independent_approval_verified": False, "native_gate_rechecked": False,
        },
        "trust": {key: False for key in TRUST_KEYS} | {
            "fresh_bytes_supplied": fresh is not None},
        "effects": {key: False for key in EFFECT_KEYS},
    }
    validate_result(result)
    return result


def validate_result(result: Any) -> dict[str, Any]:
    """Strict output shape and no-permission/no-execution invariants."""
    _need(type(result) is dict and set(result) == ROOT_KEYS, "CYCLE_RESUME_RESULT_SHAPE_INVALID")
    _need(result["schema"] == SCHEMA and result["status"] in CHECK_KINDS,
          "CYCLE_RESUME_RESULT_SCHEMA_INVALID")
    md.token(result["reason_code"], md.REASON_RE, "CYCLE_RESUME_REASON_INVALID")
    if result["run_id"] is not None:
        md.token(result["run_id"], md.RUN_RE, "CYCLE_RESUME_RESULT_RUN_INVALID")
    _need(type(result["checkpoint_verified"]) is bool, "CYCLE_RESUME_RESULT_VERIFIED_INVALID")
    for key, expected in (("record_binding", RECORD_KEYS), ("fresh_input", FRESH_KEYS),
                          ("saved_input", INPUT_KEYS), ("restored_checkpoint", CHECKPOINT_KEYS),
                          ("permission_check", PERMISSION_KEYS), ("trust", TRUST_KEYS),
                          ("effects", EFFECT_KEYS)):
        _need(type(result[key]) is dict and set(result[key]) == expected,
              "CYCLE_RESUME_RESULT_SECTION_INVALID")
    _need(all(type(value) is bool and not value for value in result["effects"].values()),
          "CYCLE_RESUME_EFFECT_ESCALATION")
    _need(all(type(value) is bool for value in result["trust"].values()) and
          all(not value for key, value in result["trust"].items() if key != "fresh_bytes_supplied"),
          "CYCLE_RESUME_TRUST_ESCALATION")
    per = result["permission_check"]
    _need(per["independent_approval_verified"] is False and
          per["native_gate_rechecked"] is False, "CYCLE_RESUME_APPROVAL_ESCALATION")
    fresh, saved = result["fresh_input"], result["saved_input"]
    for obj in (fresh, saved):
        if obj["source_ref"] is not None:
            md.token(obj["source_ref"], md.SOURCE_RE, "CYCLE_RESUME_SOURCE_REF_INVALID")
        if obj["sha256"] is not None:
            md.token(obj["sha256"], md.SHA_RE, "CYCLE_RESUME_INPUT_HASH_INVALID")
        if obj["byte_length"] is not None:
            md.count(obj["byte_length"], 0, md.MAX_SNAPSHOT_BYTES, "CYCLE_RESUME_LENGTH_INVALID")
    if result["trust"]["fresh_bytes_supplied"]:
        _need(fresh["source_ref"] is not None and fresh["sha256"] is not None and
              fresh["byte_length"] is not None, "CYCLE_RESUME_FRESH_CAPTURE_INCOMPLETE")
    else:
        _need(fresh["sha256"] is None and fresh["byte_length"] is None and
              fresh["bytes_match"] is None and fresh["source_ref_match"] is None,
              "CYCLE_RESUME_FRESH_CAPTURE_NOT_SUPPLIED")
    if result["checkpoint_verified"]:
        _need(result["run_id"] is not None and
              result["status"] != "UNKNOWN_BLOCKED" and
              per["saved_gate"] == "DENY" and per["explicit_native_gate_required"] == "ApprovePersist" and
              result["restored_checkpoint"]["run_state"] == "NOT_STARTED" and
              result["restored_checkpoint"]["operator_response"] in pause.RESPONSES and
              bool(result["restored_checkpoint"]["remaining_step_ids"]) and
              all(x["state"] == "NOT_STARTED" for x in result["restored_checkpoint"]["step_states"]) and
              all(type(v) is str and md.SHA_RE.fullmatch(v) for v in result["record_binding"].values()) and
              fresh["bytes_match"] is not None and type(fresh["bytes_match"]) is bool and
              fresh["source_ref_match"] is not None and type(fresh["source_ref_match"]) is bool and
              saved["byte_length"] >= 1 and
              result["trust"]["fresh_bytes_supplied"], "CYCLE_RESUME_VERIFIED_STATE_INVALID")
        _need(fresh["bytes_match"] == (fresh["sha256"] == saved["sha256"] and
                                        fresh["byte_length"] == saved["byte_length"]) and
              fresh["source_ref_match"] == (fresh["source_ref"] == saved["source_ref"]),
              "CYCLE_RESUME_INPUT_COMPARISON_INCONSISTENT")
        restored = result["restored_checkpoint"]
        ids = restored["remaining_step_ids"]
        _need(type(restored["pause_id"]) is str and
              pause.PAUSE_ID_RE.fullmatch(restored["pause_id"]) is not None and
              type(restored["step_id"]) is str and restored["step_id"] in ids and
              all(type(x) is str and md.STEP_RE.fullmatch(x) is not None for x in ids) and
              len(ids) == len(set(ids)) and
              type(restored["step_states"]) is list and
              restored["step_states"] == [{"step_id": x, "state": "NOT_STARTED"} for x in ids],
              "CYCLE_RESUME_STEP_RESTORE_INCONSISTENT")
        matches = fresh["bytes_match"] and fresh["source_ref_match"]
        _need((result["status"] == "PAUSED_PERMISSION_REQUIRED") == matches,
              "CYCLE_RESUME_STATUS_MISMATCH")
        _need(result["next_action"] == (
            "REVALIDATE_INDEPENDENT_PERMISSION_OUTSIDE_RESUME" if matches else
            "CREATE_FRESH_RUN_AND_REPREPARE"), "CYCLE_RESUME_ACTION_MISMATCH")
    else:
        _need(result["status"] == "UNKNOWN_BLOCKED" and
              result["next_action"] == "MANUAL_REVIEW_NO_RECOVERY" and
              per["saved_gate"] == "UNKNOWN" and per["explicit_native_gate_required"] is None and
              all(v is None for v in result["record_binding"].values()) and
              all(v is None for v in saved.values()) and
              result["restored_checkpoint"] == _empty_checkpoint() and
              fresh["bytes_match"] is None and fresh["source_ref_match"] is None,
              "CYCLE_RESUME_UNKNOWN_CLAIM_INVALID")
    _need(len(md.canonical(result)) <= 8192, "CYCLE_RESUME_RESULT_TOO_LARGE")
    return json.loads(md.canonical(result))


class CycleResumeHandler:
    """Recover saved DENY state; return a conservative *decision*, never resume work."""

    def __init__(self, private_dir: str | Path, *, package_root: str | Path | None = None) -> None:
        self.store = md.CycleMetadataStore(private_dir)
        self.pauses = pause.CyclePermissionPauseStore(private_dir, package_root=package_root)

    def restore(self, run_id: str, *, snapshot_bytes: bytes, source_ref: str,
                expected_record_sha256: str | None = None,
                expected_action_set_sha256: str | None = None,
                expected_input_sha256: str | None = None,
                expected_pause_sha256: str | None = None) -> dict[str, Any]:
        """Fresh snapshot content is mandatory; never accept caller-supplied digest as content.

        Digest/source matches are integrity comparisons ONLY. Source/actor
        authentication and independent native `ApprovePersist` verification
        are unavailable; therefore even matched cases remain PAUSED.
        """
        md.token(run_id, md.RUN_RE, "CYCLE_RESUME_RUN_ID_INVALID")
        _need(type(snapshot_bytes) is bytes and len(snapshot_bytes) <= md.MAX_SNAPSHOT_BYTES,
              "CYCLE_RESUME_FRESH_BYTES_REQUIRED")
        md.token(source_ref, md.SOURCE_RE, "CYCLE_RESUME_SOURCE_REF_INVALID")
        for name, value in (("RECORD", expected_record_sha256),
                            ("ACTION_SET", expected_action_set_sha256),
                            ("INPUT", expected_input_sha256),
                            ("PAUSE", expected_pause_sha256)):
            _pin(value, name)
        fresh = _fingerprint(snapshot_bytes)
        try:
            original = self.store.load(run_id)
            _need(expected_record_sha256 is None or
                  original["record_sha256"] == expected_record_sha256,
                  "CYCLE_RESUME_RECORD_PIN_MISMATCH")
            _need(expected_action_set_sha256 is None or
                  original["action_set_sha256"] == expected_action_set_sha256,
                  "CYCLE_RESUME_ACTION_SET_PIN_MISMATCH")
            _need(expected_input_sha256 is None or
                  original["input"]["sha256"] == expected_input_sha256,
                  "CYCLE_RESUME_INPUT_PIN_MISMATCH")
            checkpoint = self.pauses.load(run_id)  # strict EC235 local source+route revalidation
            _need(expected_pause_sha256 is None or
                  checkpoint["pause_sha256"] == expected_pause_sha256,
                  "CYCLE_RESUME_PAUSE_PIN_MISMATCH")
            _need(checkpoint["metadata_binding"]["record_sha256"] == original["record_sha256"] and
                  checkpoint["permission_gate"]["gate_result"] == "DENY" and
                  checkpoint["permission_gate"]["independent_approval_verified"] is False and
                  checkpoint["effects"]["can_resume"] is False and
                  original["run_state"] == "NOT_STARTED" and
                  original["input"]["authenticated"] is False,
                  "CYCLE_RESUME_PERMISSION_OR_RUN_STATE_INVALID")
            # Detect observed replacement in either persisted record after
            # the handler/source check, rather than relying on a stale copy.
            again = self.pauses.load(run_id)
            _need(again["pause_sha256"] == checkpoint["pause_sha256"] and
                  self.store.load(run_id)["record_sha256"] == original["record_sha256"],
                  "CYCLE_RESUME_PERSISTED_CHECKPOINT_CHANGED")
        except (md.CycleMetadataError, OSError, ValueError, TypeError) as exc:
            reason = (exc.code if isinstance(exc, md.CycleMetadataError)
                      else "CYCLE_RESUME_LOCAL_REVALIDATION_UNAVAILABLE")
            return _result(status="UNKNOWN_BLOCKED", reason_code=reason, run_id=run_id,
                           record=None, checkpoint=None, fresh=fresh, source_ref=source_ref,
                           bytes_match=None, source_match=None)
        same_bytes = (fresh["sha256"] == original["input"]["sha256"] and
                      fresh["byte_length"] == original["input"]["byte_length"])
        same_source = source_ref == original["input"]["source_ref"]
        if same_bytes and same_source:
            reason = (REASONS["unchanged_declined"] if
                      checkpoint["permission_gate"]["operator_response"] == "DECLINED" else
                      REASONS["unchanged_wait"])
            status = "PAUSED_PERMISSION_REQUIRED"
        else:
            reason = (REASONS["both_drift"] if not same_bytes and not same_source else
                      REASONS["input_drift"] if not same_bytes else REASONS["source_drift"])
            status = "REPREPARE_REQUIRED"
        return _result(status=status, reason_code=reason, run_id=run_id,
                       record=original, checkpoint=checkpoint, fresh=fresh,
                       source_ref=source_ref, bytes_match=same_bytes, source_match=same_source)


def read_fresh_snapshot(path: Path) -> bytes:
    """Take one bounded fresh file snapshot; no symlink leaf or silent truncation.

    Callers must separately establish that the file represents the live source;
    same-UID mutation/ancestor-path races are not prevented by this function.
    """
    try:
        _need(path.is_absolute(), "CYCLE_RESUME_FILE_MUST_BE_ABSOLUTE")
        before = path.lstat()
        _need(stat.S_ISREG(before.st_mode) and before.st_size <= md.MAX_SNAPSHOT_BYTES,
              "CYCLE_RESUME_FILE_NOT_REGULAR_OR_TOO_LARGE")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            opened = os.fstat(fd)
            _need(stat.S_ISREG(opened.st_mode) and opened.st_dev == before.st_dev and
                  opened.st_ino == before.st_ino and opened.st_size == before.st_size and
                  opened.st_mtime_ns == before.st_mtime_ns and
                  opened.st_ctime_ns == before.st_ctime_ns,
                  "CYCLE_RESUME_FILE_CHANGED")
            chunks: list[bytes] = []
            remaining = md.MAX_SNAPSHOT_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            _need(len(raw) <= md.MAX_SNAPSHOT_BYTES and len(raw) == before.st_size and
                  (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                  (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                   before.st_ctime_ns), "CYCLE_RESUME_FILE_CHANGED")
            return raw
        finally:
            os.close(fd)
    except OSError as exc:
        raise CycleResumeError("CYCLE_RESUME_FILE_UNAVAILABLE", "CYCLE_RESUME_FILE_UNAVAILABLE") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC236 restart-safe DENY pause restore CHECK (never executes)")
    parser.add_argument("command", choices=("restore",), help="read/check, NOT a business action resume")
    parser.add_argument("--store", required=True, help="existing EC231 POSIX owner-private directory")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--snapshot-file", required=True, help="absolute pathname with freshly captured bytes")
    parser.add_argument("--source-ref", required=True, help="current declared source reference")
    for key in ("record", "action-set", "input", "pause"):
        parser.add_argument("--expected-" + key + "-sha256")
    args = parser.parse_args(argv)
    try:
        first = read_fresh_snapshot(Path(args.snapshot_file))
        output = CycleResumeHandler(args.store).restore(
            args.run_id, snapshot_bytes=first, source_ref=args.source_ref,
            expected_record_sha256=args.expected_record_sha256,
            expected_action_set_sha256=args.expected_action_set_sha256,
            expected_input_sha256=args.expected_input_sha256,
            expected_pause_sha256=args.expected_pause_sha256)
        # Read again AFTER live checkpoint/source inspection, to avoid
        # presenting an earlier captured image as a *fresh* match if it has
        # observably changed. Do not downgrade a change to a successful pause.
        second = read_fresh_snapshot(Path(args.snapshot_file))
        if second != first:
            output = _result(status="UNKNOWN_BLOCKED", reason_code="CYCLE_RESUME_FILE_CHANGED_DURING_RESTORE",
                             run_id=args.run_id if md.RUN_RE.fullmatch(args.run_id) else None,
                             record=None, checkpoint=None, fresh=_fingerprint(second),
                             source_ref=args.source_ref if md.SOURCE_RE.fullmatch(args.source_ref) else None,
                             bytes_match=None, source_match=None)
    except (md.CycleMetadataError, OSError, TypeError, ValueError) as exc:
        code = (exc.code if isinstance(exc, md.CycleMetadataError)
                else "CYCLE_RESUME_UNAVAILABLE")
        output = _result(status="UNKNOWN_BLOCKED", reason_code=code,
                         run_id=args.run_id if md.RUN_RE.fullmatch(args.run_id) else None,
                         record=None, checkpoint=None, fresh=None,
                         source_ref=args.source_ref if md.SOURCE_RE.fullmatch(args.source_ref) else None,
                         bytes_match=None, source_match=None)
    print(json.dumps(output, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False))
    # 2: safely restored *only a denial*; 3: must reprepare; 5: unknown/invalid.
    return (2 if output["status"] == "PAUSED_PERMISSION_REQUIRED" else
            3 if output["status"] == "REPREPARE_REQUIRED" else 5)


if __name__ == "__main__":
    sys.exit(main())
