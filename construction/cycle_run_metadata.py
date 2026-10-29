#!/usr/bin/env python3
"""EC231: immutable, provenance-bound Cycle *metadata* creation and inspection.

A successful create allocates a fresh 192-bit OS CSPRNG RunId and commits a
private local metadata record before returning the ID. The record binds the
exact supplied snapshot bytes, declared actor and ordered action set. It
contains no task execution, DAG scheduler, authorization, native CES route,
resume facility or evidence of remote effects. A missing/corrupt record is
UNKNOWN, NEVER a newly NOT_STARTED run. Historical partial declarations are
inspectable but are not authenticated proof that a step executed.

This is a standalone POSIX-local facility; no original CES business source,
CLI, report, issue, publication or other EC implementation is altered.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any

SCHEMA = "ces.cycle_run_metadata.v1"
DOMAIN_RECORD = b"CES-EC231-CYCLE-METADATA-v1\x00"
DOMAIN_ACTIONS = b"CES-EC231-CYCLE-ACTIONS-v1\x00"
MAX_SNAPSHOT_BYTES = 1_048_576
MAX_RECORD_BYTES = 65_536
MAX_TASKS_BYTES = 16_384
MAX_STEPS = 32
MAX_HORIZON = timedelta(days=30)
RUN_RE = re.compile(r"run_v1_[0-9a-f]{48}\Z")
HANDOFF_RE = re.compile(r"handoff_v1_[0-9a-f]{48}\Z")
STEP_RE = re.compile(r"step_[a-z0-9][a-z0-9_-]{0,47}\Z")
ACTION_RE = re.compile(r"[A-Z][A-Za-z0-9]{0,47}\Z")
MODE_RE = re.compile(r"[A-Z][A-Za-z0-9]{0,31}\Z")
SOURCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}\Z")
SUBJECT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}\Z")
REASON_RE = re.compile(r"[A-Z][A-Z0-9_]{2,63}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z\Z")
ACTOR_ORIGINS = frozenset(("human", "service", "external"))
INPUT_COMPLETENESS = frozenset(("UNKNOWN", "DECLARED_PARTIAL", "DECLARED_COMPLETE"))
STEP_STATES = frozenset(("NOT_STARTED", "DECLARED_PARTIAL", "UNKNOWN"))
ROOT_FIELDS = frozenset(("schema", "record_kind", "run_id", "created_at_utc", "updated_at_utc",
                         "clock_trust", "run_state", "input", "actor", "action_set", "action_set_sha256",
                         "steps", "dependency_resolution", "budget", "effects", "record_sha256"))
INPUT_FIELDS = frozenset(("source_ref", "sha256", "byte_length", "completeness", "provenance", "authenticated"))
ACTOR_FIELDS = frozenset(("origin", "subject", "verified", "permissions_granted"))
ACTION_FIELDS = frozenset(("step_id", "action", "mode", "depends_on"))
STEP_FIELDS = frozenset(("step_id", "state", "observed_at_utc", "handoff_id", "evidence_sha256", "reason_code"))
BUDGET_FIELDS = frozenset(("limits", "usage", "enforcement"))
LIMIT_FIELDS = frozenset(("max_steps", "wall_ms", "input_bytes", "evidence_bytes", "output_bytes"))
USAGE_FIELDS = frozenset(("steps", "wall_ms", "input_bytes", "evidence_bytes", "output_bytes"))
EFFECT_FIELDS = frozenset(("executed", "write_authorized", "external_delivery_proven", "resume_authorized"))
LIMIT_MAX = {"max_steps": MAX_STEPS, "wall_ms": 86_400_000, "input_bytes": MAX_SNAPSHOT_BYTES,
             "evidence_bytes": 8_388_608, "output_bytes": 8_388_608}
DEFAULT_LIMITS = {"wall_ms": 600_000, "input_bytes": MAX_SNAPSHOT_BYTES,
                  "evidence_bytes": 65_536, "output_bytes": 65_536}


class CycleMetadataError(ValueError):
    """Fail-closed condition with a stable, non-secret machine reason code."""
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def require(value: bool, code: str, message: str) -> None:
    if not value:
        raise CycleMetadataError(code, message)


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("ascii")
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise CycleMetadataError("CYCLE_JSON_VALUE_INVALID", "Cannot encode canonical metadata JSON") from exc


def digest(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + canonical(value)).hexdigest()


def strict_json(raw: bytes, maximum: int) -> Any:
    require(type(raw) is bytes and 0 < len(raw) <= maximum, "CYCLE_JSON_SIZE_INVALID", "Bounded UTF-8 JSON required")
    require(not raw.startswith(b"\xef\xbb\xbf"), "CYCLE_JSON_BOM_FORBIDDEN", "UTF-8 BOM forbidden")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        seen: set[str] = set()
        for key, value in pairs:
            require(key.casefold() not in seen, "CYCLE_JSON_DUPLICATE_KEY", "Duplicate or case-colliding key")
            seen.add(key.casefold())
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    except (ValueError, UnicodeError, TypeError, OverflowError, RecursionError) as exc:
        if isinstance(exc, CycleMetadataError):
            raise
        raise CycleMetadataError("CYCLE_JSON_MALFORMED", "Malformed UTF-8 JSON") from exc


def fields(value: Any, expected: frozenset[str], code: str) -> None:
    require(type(value) is dict and set(value) == expected, code, "Unrecognized or missing metadata fields")


def token(value: Any, pattern: re.Pattern[str], code: str) -> None:
    require(type(value) is str and pattern.fullmatch(value) is not None, code, "Invalid bounded token")


def count(value: Any, minimum: int, maximum: int, code: str) -> None:
    require(type(value) is int and minimum <= value <= maximum, code, "Counter outside permitted range")


def timestamp(value: Any) -> datetime:
    require(type(value) is str and UTC_RE.fullmatch(value) is not None,
            "CYCLE_TIMESTAMP_INVALID", "Fixed six-digit-microsecond UTC timestamp required")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise CycleMetadataError("CYCLE_TIMESTAMP_INVALID", "Invalid calendar timestamp") from exc
    require(2020 <= parsed.year <= 2100, "CYCLE_TIMESTAMP_OUT_OF_RANGE", "Timestamp outside EC231 declared era")
    return parsed


def _actions(tasks: Any) -> list[dict[str, Any]]:
    require(type(tasks) is list and 1 <= len(tasks) <= MAX_STEPS,
            "CYCLE_ACTION_COUNT_INVALID", "One to 32 declared actions required")
    ids: set[str] = set()
    result: list[dict[str, Any]] = []
    for task in tasks:
        fields(task, ACTION_FIELDS, "CYCLE_ACTION_SHAPE_INVALID")
        step_id = task["step_id"]
        token(step_id, STEP_RE, "CYCLE_STEP_ID_INVALID")
        require(step_id not in ids, "CYCLE_STEP_ID_DUPLICATE", "Duplicate action step ID")
        ids.add(step_id)
        token(task["action"], ACTION_RE, "CYCLE_ACTION_TOKEN_INVALID")
        if task["mode"] is not None:
            token(task["mode"], MODE_RE, "CYCLE_MODE_TOKEN_INVALID")
        deps = task["depends_on"]
        require(type(deps) is list and len(deps) <= MAX_STEPS,
                "CYCLE_DEPENDENCY_SHAPE_INVALID", "Dependencies must be a bounded list")
        for dep in deps:
            token(dep, STEP_RE, "CYCLE_DEPENDENCY_ID_INVALID")
        require(len(deps) == len(set(deps)) and step_id not in deps,
                "CYCLE_DEPENDENCY_DUPLICATE_OR_SELF", "Duplicate/self dependency rejected")
        result.append({"step_id": step_id, "action": task["action"],
                       "mode": task["mode"], "depends_on": list(deps)})
    for item in result:
        require(all(dep in ids for dep in item["depends_on"]),
                "CYCLE_DEPENDENCY_REF_MISSING", "Dependency references an absent step")
    # Intentionally no cycle detection / topological scheduling: EC232.
    return result


def _limits(value: Any, input_bytes: int, action_count: int) -> dict[str, int]:
    fields(value, LIMIT_FIELDS, "CYCLE_BUDGET_LIMITS_INVALID")
    for key, maximum in LIMIT_MAX.items():
        count(value[key], 1, maximum, "CYCLE_BUDGET_LIMIT_INVALID")
    require(value["max_steps"] >= action_count and value["input_bytes"] >= input_bytes,
            "CYCLE_BUDGET_BELOW_INPUT", "Limits cannot be smaller than captured input/action set")
    return dict(value)


def _derived_state(steps: list[dict[str, Any]]) -> str:
    if any(step["state"] == "UNKNOWN" for step in steps):
        return "UNKNOWN"
    if any(step["state"] == "DECLARED_PARTIAL" for step in steps):
        return "PARTIAL"
    return "NOT_STARTED"


def _without_digest(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "record_sha256"}


def validate_record(record: Any, *, expected_run_id: str | None = None) -> dict[str, Any]:
    """Strict syntax, cross-field semantics and UNSIGNED self-integrity.

    A passing validation is not authentication or proof of any task result.
    The returned dict is a deep canonical-JSON copy, not a mutable store handle.
    """
    fields(record, ROOT_FIELDS, "CYCLE_RECORD_SHAPE_INVALID")
    require(record["schema"] == SCHEMA and record["record_kind"] == "CYCLE_METADATA_ONLY",
            "CYCLE_RECORD_SCHEMA_INVALID", "Unsupported metadata schema/kind")
    token(record["run_id"], RUN_RE, "CYCLE_RUN_ID_INVALID")
    if expected_run_id is not None:
        require(record["run_id"] == expected_run_id, "CYCLE_RUN_ID_MISMATCH", "Filename/run ID mismatch")
    require(record["clock_trust"] == "UNVERIFIED_HOST_UTC",
            "CYCLE_CLOCK_TRUST_INVALID", "Host time may not claim attestation")
    start, updated = timestamp(record["created_at_utc"]), timestamp(record["updated_at_utc"])
    require(start <= updated <= start + MAX_HORIZON,
            "CYCLE_TIMESTAMP_ORDER_INVALID", "Updated time outside bounded run horizon")

    inp = record["input"]
    fields(inp, INPUT_FIELDS, "CYCLE_INPUT_SHAPE_INVALID")
    token(inp["source_ref"], SOURCE_RE, "CYCLE_SOURCE_REF_INVALID")
    token(inp["sha256"], SHA_RE, "CYCLE_INPUT_HASH_INVALID")
    count(inp["byte_length"], 1, MAX_SNAPSHOT_BYTES, "CYCLE_INPUT_LENGTH_INVALID")
    require(type(inp["completeness"]) is str and inp["completeness"] in INPUT_COMPLETENESS and
            inp["provenance"] == "CALLER_SUPPLIED_BYTES" and inp["authenticated"] is False,
            "CYCLE_INPUT_PROOF_ESCALATION", "Input provenance is declared, not externally authenticated")

    actor = record["actor"]
    fields(actor, ACTOR_FIELDS, "CYCLE_ACTOR_SHAPE_INVALID")
    require(type(actor["origin"]) is str and actor["origin"] in ACTOR_ORIGINS,
            "CYCLE_ACTOR_ORIGIN_INVALID", "Actor origin not supported")
    token(actor["subject"], SUBJECT_RE, "CYCLE_ACTOR_SUBJECT_INVALID")
    require(actor["verified"] is False and actor["permissions_granted"] is False,
            "CYCLE_ACTOR_AUTHORITY_FORBIDDEN", "Metadata cannot authenticate actor or grant permissions")

    actions = _actions(record["action_set"])
    require(record["action_set_sha256"] == digest(DOMAIN_ACTIONS, actions),
            "CYCLE_ACTION_SET_HASH_MISMATCH", "Declared action-set digest mismatch")
    steps = record["steps"]
    require(type(steps) is list and len(steps) == len(actions),
            "CYCLE_STEP_COUNT_MISMATCH", "Step status inventory must exactly cover action set")
    for item, action in zip(steps, actions):
        fields(item, STEP_FIELDS, "CYCLE_STEP_SHAPE_INVALID")
        require(item["step_id"] == action["step_id"], "CYCLE_STEP_ORDER_MISMATCH", "Step IDs/order must bind action set")
        require(type(item["state"]) is str and item["state"] in STEP_STATES,
                "CYCLE_STEP_STATE_INVALID", "Execution success cannot be declared by metadata")
        obs, hid, evidence, reason = (item[x] for x in
                                      ("observed_at_utc", "handoff_id", "evidence_sha256", "reason_code"))
        if hid is not None:
            token(hid, HANDOFF_RE, "CYCLE_HANDOFF_REF_INVALID")
        if item["state"] == "NOT_STARTED":
            require(obs is None and hid is None and evidence is None and reason is None,
                    "CYCLE_NOT_STARTED_DIRTY", "Unstarted step cannot claim observations or handoff")
        elif item["state"] == "UNKNOWN":
            require(obs is None and evidence is None and type(reason) is str and
                    REASON_RE.fullmatch(reason) is not None,
                    "CYCLE_UNKNOWN_EVIDENCE_FORBIDDEN", "Unknown step must have a reason, never evidence")
        else:  # DECLARED_PARTIAL is only a declaration, never executed/succeeded.
            require(obs is not None and evidence is not None and reason is not None,
                    "CYCLE_PARTIAL_EVIDENCE_REQUIRED", "Partial declaration needs timestamp/digest/reason")
            moment = timestamp(obs)
            require(start <= moment <= updated, "CYCLE_OBSERVATION_TIME_INVALID", "Step observation outside record bounds")
            token(evidence, SHA_RE, "CYCLE_OBSERVATION_HASH_INVALID")
            token(reason, REASON_RE, "CYCLE_OBSERVATION_REASON_INVALID")
    require(record["run_state"] == _derived_state(steps),
            "CYCLE_RUN_STATE_INCONSISTENT", "Run state must be conservatively derived (UNKNOWN before PARTIAL)")
    require(record["dependency_resolution"] == "NOT_EVALUATED_EC232",
            "CYCLE_DAG_CLAIM_FORBIDDEN", "No dependency scheduler exists in EC231")

    budget = record["budget"]
    fields(budget, BUDGET_FIELDS, "CYCLE_BUDGET_SHAPE_INVALID")
    _limits(budget["limits"], inp["byte_length"], len(actions))
    require(budget["enforcement"] == "CAPTURE_ONLY_NO_RUN_ENFORCEMENT",
            "CYCLE_BUDGET_CLAIM_FORBIDDEN", "EC234 run-budget enforcement not implemented")
    usage = budget["usage"]
    fields(usage, USAGE_FIELDS, "CYCLE_USAGE_SHAPE_INVALID")
    for key in USAGE_FIELDS:
        maximum = budget["limits"]["max_steps" if key == "steps" else key]
        count(usage[key], 0, maximum, "CYCLE_USAGE_EXCEEDS_LIMIT")
    require(usage["input_bytes"] == inp["byte_length"],
            "CYCLE_CAPTURE_BYTES_MISMATCH", "Captured input bytes must match usage")
    if record["run_state"] == "NOT_STARTED":
        require(all(usage[k] == 0 for k in ("steps", "wall_ms", "evidence_bytes", "output_bytes")),
                "CYCLE_NOT_STARTED_USAGE_INVALID", "No execution/resource usage for unstarted run")
    else:
        require(usage["steps"] <= len(actions), "CYCLE_STEP_USAGE_INVALID", "Step usage > action count")

    effects = record["effects"]
    fields(effects, EFFECT_FIELDS, "CYCLE_EFFECTS_SHAPE_INVALID")
    require(all(effects[k] is False for k in EFFECT_FIELDS),
            "CYCLE_EFFECT_CLAIM_FORBIDDEN", "No execution, write, remote delivery or resume authority")
    token(record["record_sha256"], SHA_RE, "CYCLE_RECORD_HASH_INVALID")
    require(record["record_sha256"] == digest(DOMAIN_RECORD, _without_digest(record)),
            "CYCLE_RECORD_HASH_MISMATCH", "Unsigned metadata self-hash mismatch")
    require(len(canonical(record)) <= MAX_RECORD_BYTES,
            "CYCLE_RECORD_TOO_LARGE", "Metadata exceeds strict max serialized size")
    return json.loads(canonical(record))


def _safe_dir(path: Path, create: bool) -> int:
    """Open a host-owned 0700 directory by FD, no leaf symlink."""
    require(os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and
            hasattr(os, "geteuid"), "CYCLE_POSIX_REQUIRED", "Secure local storage supported on POSIX hosts only")
    require(path.is_absolute() and str(path) not in ("/", "") and
            ".." not in path.parts and "." not in path.parts,
            "CYCLE_STORE_PATH_INVALID", "A dedicated absolute private directory is required")
    # Ancestor symlinks are not accepted; same-UID parent rename attacks and
    # fsync durability on NFS/multihost are outside this facility's assurances.
    for ancestor in (path, *path.parents):
        require(not ancestor.is_symlink(), "CYCLE_STORE_SYMLINK_FORBIDDEN", "Store path cannot cross a symlink")
    was_created = False
    if create:
        try:
            os.mkdir(path, 0o700)
            was_created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise CycleMetadataError("CYCLE_STORE_UNAVAILABLE", "Could not create private metadata root") from exc
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise CycleMetadataError("CYCLE_STORE_UNAVAILABLE", "Private metadata root unavailable") from exc
    try:
        if was_created:
            os.fchmod(fd, 0o700)  # umask-independent private root mode.
        st = os.fstat(fd)
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
                stat.S_IMODE(st.st_mode) == 0o700,
                "CYCLE_STORE_NOT_PRIVATE", "Root must be owned by caller with exact 0700 mode")
        if was_created:
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        return fd
    except OSError as exc:
        os.close(fd)
        raise CycleMetadataError("CYCLE_STORE_UNAVAILABLE", "Private metadata directory setup uncertain") from exc
    except BaseException:
        os.close(fd)
        raise


def _write_all(fd: int, raw: bytes) -> None:
    pos = 0
    while pos < len(raw):
        written = os.write(fd, raw[pos:])
        require(written > 0, "CYCLE_STORAGE_WRITE_FAILED", "Incomplete metadata write")
        pos += written


def _read_record(dir_fd: int, run_id: str) -> dict[str, Any]:
    token(run_id, RUN_RE, "CYCLE_RUN_ID_INVALID")
    name = run_id + ".cycle.json"
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except FileNotFoundError as exc:
        raise CycleMetadataError("CYCLE_RUN_NOT_FOUND", "No durable record for requested RunId") from exc
    except OSError as exc:
        raise CycleMetadataError("CYCLE_RUN_UNAVAILABLE", "Could not open metadata file") from exc
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
                stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and
                0 < st.st_size <= MAX_RECORD_BYTES,
                "CYCLE_RECORD_NOT_PRIVATE", "Record must be owner-private regular unlinked-by-others file")
        chunks: list[bytes] = []
        remaining = MAX_RECORD_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        require(len(raw) <= MAX_RECORD_BYTES, "CYCLE_RECORD_TOO_LARGE", "Record too large")
    except OSError as exc:
        raise CycleMetadataError("CYCLE_RUN_UNAVAILABLE", "Could not read metadata file") from exc
    finally:
        os.close(fd)
    return validate_record(strict_json(raw, MAX_RECORD_BYTES), expected_run_id=run_id)


class CycleMetadataStore:
    """Create once, inspect many; never import JSON as a live run."""
    def __init__(self, private_dir: str | Path) -> None:
        self.path = Path(private_dir)

    def create(self, *, snapshot_bytes: bytes, source_ref: str,
               actor_origin: str, actor_subject: str,
               actions: list[dict[str, Any]], input_completeness: str = "UNKNOWN",
               limits: dict[str, int] | None = None) -> dict[str, Any]:
        """Persist a new NOT_STARTED Cycle record; return RunId only after fsync.

        Caller supplies actual snapshot bytes (not an unchecked fingerprint).
        Action/actor declarations are not proof of handler registration or
        authorization, and no input content is saved.
        """
        require(type(snapshot_bytes) is bytes and 1 <= len(snapshot_bytes) <= MAX_SNAPSHOT_BYTES,
                "CYCLE_SNAPSHOT_BYTES_INVALID", "Exact nonempty snapshot must be <=1MiB")
        token(source_ref, SOURCE_RE, "CYCLE_SOURCE_REF_INVALID")
        require(type(actor_origin) is str and actor_origin in ACTOR_ORIGINS,
                "CYCLE_ACTOR_ORIGIN_INVALID", "Invalid actor origin")
        token(actor_subject, SUBJECT_RE, "CYCLE_ACTOR_SUBJECT_INVALID")
        require(type(input_completeness) is str and input_completeness in INPUT_COMPLETENESS,
                "CYCLE_COMPLETENESS_INVALID", "Unrecognized non-authoritative completeness declaration")
        action_set = _actions(actions)
        selected = {"max_steps": len(action_set), **DEFAULT_LIMITS}
        if limits is not None:
            require(type(limits) is dict and set(limits) == LIMIT_FIELDS,
                    "CYCLE_BUDGET_LIMITS_INVALID", "Must specify all five budgets")
            selected = dict(limits)
        selected = _limits(selected, len(snapshot_bytes), len(action_set))
        # Inspect all supplied parameters before minting an identity.
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        timestamp(now)
        root_fd = _safe_dir(self.path, create=True)
        try:
            for _ in range(6):
                run_id = "run_v1_" + secrets.token_bytes(24).hex()
                record: dict[str, Any] = {
                    "schema": SCHEMA, "record_kind": "CYCLE_METADATA_ONLY",
                    "run_id": run_id, "created_at_utc": now, "updated_at_utc": now,
                    "clock_trust": "UNVERIFIED_HOST_UTC", "run_state": "NOT_STARTED",
                    "input": {"source_ref": source_ref, "sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
                              "byte_length": len(snapshot_bytes), "completeness": input_completeness,
                              "provenance": "CALLER_SUPPLIED_BYTES", "authenticated": False},
                    "actor": {"origin": actor_origin, "subject": actor_subject,
                              "verified": False, "permissions_granted": False},
                    "action_set": action_set, "action_set_sha256": digest(DOMAIN_ACTIONS, action_set),
                    "steps": [{"step_id": a["step_id"], "state": "NOT_STARTED",
                               "observed_at_utc": None, "handoff_id": None,
                               "evidence_sha256": None, "reason_code": None} for a in action_set],
                    "dependency_resolution": "NOT_EVALUATED_EC232",
                    "budget": {"limits": selected,
                               "usage": {"steps": 0, "wall_ms": 0,
                                         "input_bytes": len(snapshot_bytes), "evidence_bytes": 0,
                                         "output_bytes": 0},
                               "enforcement": "CAPTURE_ONLY_NO_RUN_ENFORCEMENT"},
                    "effects": {k: False for k in EFFECT_FIELDS},
                }
                record["record_sha256"] = digest(DOMAIN_RECORD, record)
                validated = validate_record(record)
                raw = (json.dumps(validated, sort_keys=True, ensure_ascii=True,
                                  indent=2, allow_nan=False) + "\n").encode("ascii")
                require(len(raw) <= MAX_RECORD_BYTES, "CYCLE_RECORD_TOO_LARGE", "Stored JSON exceeds 64KiB")
                try:
                    fd = os.open(run_id + ".cycle.json",
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                                 getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=root_fd)
                except FileExistsError:
                    continue  # Another RunId; NEVER reuse or overwrite an existing file.
                except OSError as exc:
                    raise CycleMetadataError("CYCLE_STORE_WRITE_FAILED", "Could not create new record") from exc
                try:
                    os.fchmod(fd, 0o600)  # Do not inherit a restrictive umask mode.
                    _write_all(fd, raw)
                    os.fsync(fd)
                except (OSError, CycleMetadataError) as exc:
                    # On unknown durability we intentionally leave the file for
                    # operator inspection, and do not return a "real" RunId.
                    raise CycleMetadataError("CYCLE_STORE_WRITE_UNCERTAIN", "Metadata commit uncertain") from exc
                finally:
                    os.close(fd)
                try:
                    os.fsync(root_fd)
                    return _read_record(root_fd, run_id)
                except (OSError, CycleMetadataError) as exc:
                    raise CycleMetadataError("CYCLE_STORE_COMMIT_UNCERTAIN", "Metadata durability/readback uncertain") from exc
            raise CycleMetadataError("CYCLE_RUN_ID_COLLISION", "No unique RunId after bounded attempts")
        finally:
            os.close(root_fd)

    def load(self, run_id: str) -> dict[str, Any]:
        token(run_id, RUN_RE, "CYCLE_RUN_ID_INVALID")
        fd = _safe_dir(self.path, create=False)
        try:
            return _read_record(fd, run_id)
        finally:
            os.close(fd)

    def inspect(self, run_id: str) -> dict[str, Any]:
        """Metadata-only read. Missing/corrupt/uncertain never implies NOT_STARTED."""
        try:
            record = self.load(run_id)
        except (CycleMetadataError, OSError) as exc:
            code = exc.code if isinstance(exc, CycleMetadataError) else "CYCLE_RUN_UNAVAILABLE"
            return {"schema": SCHEMA, "run_id": run_id if type(run_id) is str and
                    RUN_RE.fullmatch(run_id) else None, "run_state": "UNKNOWN",
                    "metadata_valid": False, "record": None, "reason_code": code,
                    "execution_proven": False, "can_resume": False}
        return {"schema": SCHEMA, "run_id": record["run_id"], "run_state": record["run_state"],
                "metadata_valid": True, "record": record, "reason_code": "CYCLE_METADATA_ONLY",
                "execution_proven": False, "can_resume": False}


def _read_input_file(path: Path, size: int) -> bytes:
    try:
        require(path.is_file() and not path.is_symlink(), "CYCLE_INPUT_NOT_REGULAR", "Regular unlinked input required")
        st = path.lstat()
        require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= size,
                "CYCLE_INPUT_FILE_SIZE", "Input file outside bound")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            require(stat.S_ISREG(opened.st_mode) and opened.st_ino == st.st_ino and
                    opened.st_dev == st.st_dev and opened.st_size == st.st_size,
                    "CYCLE_INPUT_FILE_CHANGED", "Input file changed before open")
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                raw = stream.read(size + 1)
        finally:
            if fd >= 0:
                os.close(fd)
        require(0 < len(raw) <= size, "CYCLE_INPUT_FILE_SIZE", "Input file outside bound")
        return raw
    except OSError as exc:
        raise CycleMetadataError("CYCLE_INPUT_UNAVAILABLE", "Input file could not be safely read") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC231 Cycle metadata only (no Cycle executor)")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="create an immutable NOT_STARTED local Cycle record")
    create.add_argument("--store", required=True)
    create.add_argument("--snapshot-file", required=True)
    create.add_argument("--source-ref", required=True)
    create.add_argument("--actor-origin", choices=sorted(ACTOR_ORIGINS), required=True)
    create.add_argument("--actor-subject", required=True)
    create.add_argument("--actions-json", required=True, help="local array of step/action/mode/depends_on")
    create.add_argument("--completeness", choices=sorted(INPUT_COMPLETENESS), default="UNKNOWN")
    inspect = commands.add_parser("inspect", help="inspect existing record; never resume")
    inspect.add_argument("--store", required=True)
    inspect.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    try:
        store = CycleMetadataStore(args.store)
        if args.command == "create":
            snap = _read_input_file(Path(args.snapshot_file), MAX_SNAPSHOT_BYTES)
            tasks = strict_json(_read_input_file(Path(args.actions_json), MAX_TASKS_BYTES), MAX_TASKS_BYTES)
            record = store.create(snapshot_bytes=snap, source_ref=args.source_ref,
                                  actor_origin=args.actor_origin, actor_subject=args.actor_subject,
                                  actions=tasks, input_completeness=args.completeness)
            response = {"status": "metadata_created_not_started", "run_id": record["run_id"],
                        "run_state": record["run_state"], "record_sha256": record["record_sha256"],
                        "execution_proven": False, "native_cycle_action_registered": False}
            code = 0  # Only private metadata storage succeeded; no Cycle work succeeded.
        else:
            response = store.inspect(args.run_id)
            code = 0 if response["metadata_valid"] else 5
    except (CycleMetadataError, OSError) as exc:
        response = {"status": "metadata_not_created", "run_id": None, "run_state": "UNKNOWN",
                    "reason_code": exc.code if isinstance(exc, CycleMetadataError) else "CYCLE_IO_UNAVAILABLE",
                    "execution_proven": False, "native_cycle_action_registered": False}
        code = 4 if isinstance(exc, CycleMetadataError) else 5
    print(json.dumps(response, sort_keys=True, ensure_ascii=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
