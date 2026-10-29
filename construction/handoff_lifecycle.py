#!/usr/bin/env python3
"""EC171 standalone RunId/HandoffId lifecycle model (no external execution).

Only successful create operations mint OS-random identities. The live object is
in-memory; serialized history is **never** promoted to a live session by this
module. An untrusted checkpoint may be structurally inspected, but not resumed
without a future separately trusted persistence/attestation boundary (EC172+).

Events record caller-declared outcomes, not authenticated AI/Provider action.
No Git, network, repository writes, CES store writes, or native CLI registration.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import threading
from typing import Any, Callable

SCHEMA = "ces.handoff_lifecycle.v1"
SOURCE_SCHEMA = "ces.lifecycle_source.v1"
CONTEXT_RESULT_SCHEMA = "ces.code_prepare_multisource.v1"
CONTEXT_SCHEMA = "ces.ai_code_context.v1"
DOMAIN_CONTEXT = b"CES-EC170-AI-CODE-CONTEXT-v1\x00"
DOMAIN_SOURCE = b"CES-EC171-SOURCE-IDENTITY-v1\x00"
DOMAIN_EVENT = b"CES-EC171-LIFECYCLE-EVENT-v1\x00"
STATES = ("CREATED", "READY", "ACTIVE", "COMPLETED", "PARTIAL", "UNAVAILABLE", "FAILED", "CANCELLED")
TERMINAL = frozenset(("COMPLETED", "PARTIAL", "UNAVAILABLE", "FAILED", "CANCELLED"))
TRANSITIONS = {
    "CREATED": frozenset(("READY", "UNAVAILABLE", "CANCELLED")),
    "READY": frozenset(("ACTIVE", "UNAVAILABLE", "CANCELLED")),
    "ACTIVE": TERMINAL,
    "COMPLETED": frozenset(), "PARTIAL": frozenset(),
    "UNAVAILABLE": frozenset(), "FAILED": frozenset(), "CANCELLED": frozenset(),
}
KINDS = frozenset(("RUN_CREATED", "RUN_TRANSITION", "HANDOFF_CREATED", "HANDOFF_TRANSITION"))
SOURCE_MODES = frozenset(("WorkingTree", "DeliveredTarget", "ProposedPR"))
CURRENTNESS_LABELS = frozenset((
    "NATIVE_RESULT_HAD_NO_CHANGES",
    "NATIVE_CODEPREPARE_SCOPE_RECONCILED_AT_PREPARATION_TIME_NOT_AT_EC170_CONSUME_TIME",
    "HISTORICAL_EC165_INVALIDATED_BY_EC166_DRIFT",
    "HISTORICAL_EC165_BOUNDED_OBSERVATION_NOT_CURRENT_ATOMIC_DIFF",
))
ID_RE = re.compile(r"(run|handoff)_v1_[0-9a-f]{48}\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,63}\Z")
REASON_RE = re.compile(r"[A-Z][A-Z0-9_]{2,63}\Z")
SUBJECT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}\Z")
EVENT_FIELDS = frozenset(("seq", "revision", "operation_key", "kind", "run_id", "handoff_id",
                          "task_kind", "from_state", "to_state", "timestamp_utc",
                          "source_context_sha256", "reason_code", "result_sha256", "actor_claim",
                          "acknowledge_partial", "previous_event_sha256", "event_sha256"))
SOURCE_FIELDS = frozenset(("schema_version", "context_sha256", "identity_sha256", "source_mode",
                           "task_kind", "quality", "content_released", "coverage_complete",
                           "source_currentness", "external_proof"))
MAX_EVENTS = 256
MAX_HANDOFFS = 32
MAX_CHECKPOINT_BYTES = 256 * 1024
MAX_PREPARED_BYTES = 4 * 1024 * 1024
EXIT = {"success": 0, "partial": 2, "invalid_input": 4, "unavailable": 5}
_SESSION_CREATION_TOKEN = object()  # Guard against accidental JSON-to-live constructor calls.


class LifecycleError(ValueError):
    def __init__(self, code: str, message: str, status: str = "invalid_input") -> None:
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise LifecycleError(code, message)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise LifecycleError("JSON_VALUE_INVALID", "Value is not bounded canonical JSON.") from exc


def _hash(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _strict_load(raw: bytes, maximum: int) -> dict[str, Any]:
    _require(type(raw) is bytes and len(raw) <= maximum, "INPUT_SIZE_INVALID", "JSON input exceeds its byte limit.")
    _require(not raw.startswith(b"\xef\xbb\xbf"), "INPUT_BOM_FORBIDDEN", "Input JSON BOM is not accepted.")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        folded = set()
        for k, v in pairs:
            if k.casefold() in folded:
                raise ValueError("duplicate/case-colliding key")
            folded.add(k.casefold())
            result[k] = v
        return result

    def finite_float(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("nonfinite")
        return result

    try:
        result = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
                            parse_float=finite_float)
    except (ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise LifecycleError("INPUT_JSON_INVALID", "Input must be one strict UTF-8 JSON object.") from exc
    _require(type(result) is dict, "INPUT_OBJECT_REQUIRED", "Input JSON root must be an object.")
    return result


def _read_bounded(path: str, maximum: int) -> bytes:
    try:
        p = Path(path)
        # TOCTOU-resistant leaf read where O_NOFOLLOW is available; a future
        # storage implementation must secure *all* ancestors/FDs separately.
        st = p.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_size > maximum:
            raise OSError("not regular or too large")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(p, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > maximum or (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                raise OSError("opened file is not the inspected regular file")
            with os.fdopen(fd, "rb") as f:
                fd = -1
                raw = f.read(maximum + 1)
        finally:
            if fd != -1:
                os.close(fd)
        if len(raw) > maximum:
            raise OSError("too large")
        return raw
    except (OSError, ValueError) as exc:
        raise LifecycleError("INPUT_FILE_UNAVAILABLE", "A selected regular input file could not be read within limits.", "unavailable") from exc


def _source(prepared: Any) -> dict[str, Any]:
    """Bind the precise EC170 context bytes; persist no raw source/content."""
    _require(type(prepared) is dict and prepared.get("schema") == CONTEXT_RESULT_SCHEMA,
             "SOURCE_SCHEMA_INVALID", "Expected an EC170 CodePrepare MultiSource result.")
    _require(prepared.get("status") in ("success", "partial"), "SOURCE_NOT_USABLE",
             "Unavailable or invalid EC170 context cannot create a run.")
    ctx = prepared.get("context")
    _require(type(ctx) is dict and ctx.get("schema_version") == CONTEXT_SCHEMA,
             "CONTEXT_INVALID", "Source must contain the versioned AI context.")
    try:
        packed = _canonical(ctx)
        _require(len(packed) <= MAX_PREPARED_BYTES, "SOURCE_TOO_LARGE", "Context exceeds EC171 bound.")
        digest = hashlib.sha256(DOMAIN_CONTEXT + packed).hexdigest()
    except (MemoryError, OverflowError, RecursionError) as exc:
        raise LifecycleError("SOURCE_TOO_LARGE", "Context cannot be safely encoded.") from exc
    _require(prepared.get("context_sha256") == digest, "CONTEXT_HASH_MISMATCH",
             "EC170 context SHA-256 does not match the supplied context.")
    mode = ctx.get("source_mode")
    ident = ctx.get("source_identity")
    coverage = ctx.get("coverage")
    _require(type(mode) is str and mode in SOURCE_MODES and type(ident) is dict and
             ident.get("source_mode") == mode and ctx.get("task_kind") == "code_analysis",
             "CONTEXT_BINDING_INVALID", "Source kind/mode/identity binding is missing or inconsistent.")
    _require(prepared.get("source_mode") == mode and prepared.get("native_cli_multisource_registered") is False,
             "SOURCE_MODE_MISMATCH", "EC170 response and context must agree on the explicit source mode.")
    _require(type(coverage) is dict and prepared.get("coverage") == coverage,
             "COVERAGE_INVALID", "Source coverage is missing or disagrees with the response.")
    for field in ("source_currentness_proven", "remote_delivery_proven", "provider_actor_verified", "write_authorized"):
        _require(coverage.get(field) is False, "SOURCE_PROOF_ESCALATION_FORBIDDEN",
                 "EC170 coverage must not claim independent actor/currentness/delivery/write proof.")
    for field in ("provider_actor_verified", "remote_delivery_proven", "deployment_proven", "write_authorized", "writes_performed"):
        _require(prepared.get(field) is False, "SOURCE_PROOF_ESCALATION_FORBIDDEN",
                 "EC170 result contains an unsupported authority claim.")
    for field in ("content_released", "content_complete_for_selected_source"):
        _require(type(coverage.get(field)) is bool, "COVERAGE_INVALID", "Source content coverage is invalid.")
    _require(type(ctx.get("source_currentness")) is str and ctx["source_currentness"] in CURRENTNESS_LABELS,
             "CURRENTNESS_INVALID", "Source currentness label is invalid.")
    _require(len(_canonical(ident)) <= 8192, "IDENTITY_SIZE_INVALID", "Source identity metadata is too large.")
    return {
        "schema_version": SOURCE_SCHEMA,
        "context_sha256": digest,
        "identity_sha256": _hash(DOMAIN_SOURCE, ident),
        "source_mode": mode,
        "task_kind": "code_analysis",
        "quality": prepared["status"],
        "content_released": coverage["content_released"],
        "coverage_complete": coverage["content_complete_for_selected_source"],
        "source_currentness": ctx["source_currentness"],
        "external_proof": "NOT_AUTHENTICATED",
    }


def _check_source_record(record: Any) -> None:
    _require(type(record) is dict and set(record) == SOURCE_FIELDS and
             record.get("schema_version") == SOURCE_SCHEMA and type(record.get("source_mode")) is str and
             record["source_mode"] in SOURCE_MODES and
             record.get("task_kind") == "code_analysis" and record.get("quality") in ("success", "partial") and
             record.get("external_proof") == "NOT_AUTHENTICATED", "CHECKPOINT_SOURCE_INVALID",
             "Checkpoint source record has an invalid shape or authority label.")
    for k in ("context_sha256", "identity_sha256"):
        _require(type(record.get(k)) is str and SHA_RE.fullmatch(record[k]) is not None,
                 "CHECKPOINT_SOURCE_INVALID", "Checkpoint source hashes must be full SHA-256s.")
    for k in ("content_released", "coverage_complete"):
        _require(type(record.get(k)) is bool, "CHECKPOINT_SOURCE_INVALID", "Checkpoint coverage must be boolean.")
    _require(type(record.get("source_currentness")) is str and record["source_currentness"] in CURRENTNESS_LABELS,
             "CHECKPOINT_SOURCE_INVALID", "Checkpoint currentness label is invalid.")


def _claim(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    _require(type(value) is dict and set(value) == {"origin", "subject", "verified", "write_authorized"} and
             value.get("origin") in ("human", "external") and
             type(value.get("subject")) is str and SUBJECT_RE.fullmatch(value["subject"]) is not None and
             value.get("verified") is False and value.get("write_authorized") is False,
             "ACTOR_CLAIM_INVALID", "Actor may only be declared as unverified and never grants write permission.")
    return copy.deepcopy(value)


def declared_actor(origin: str, subject: str) -> dict[str, Any]:
    """Attach a human/external *label*, not an authenticated principal or grant."""
    claim = {"origin": origin, "subject": subject, "verified": False, "write_authorized": False}
    return _claim(claim)  # type: ignore[return-value]


def _check_op(key: Any) -> None:
    _require(type(key) is str and OP_RE.fullmatch(key) is not None, "OPERATION_KEY_INVALID",
             "Operation key must be 8-64 safe ASCII characters; never a privilege token.")


def _time(text: Any) -> datetime:
    _require(type(text) is str and len(text) == 27 and text.endswith("Z"), "EVENT_TIME_INVALID",
             "Event timestamps must be UTC with fixed microsecond precision.")
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise LifecycleError("EVENT_TIME_INVALID", "Event timestamp cannot be parsed.") from exc


def _validate_outcome(to_state: str, reason: Any, result: Any, partial_ack: Any, source: dict[str, Any]) -> None:
    _require(type(partial_ack) is bool, "ACKNOWLEDGEMENT_INVALID", "Partial-context acknowledgement must be boolean.")
    if to_state == "READY":
        _require(reason is None and result is None and
                 partial_ack == (source["quality"] == "partial"), "PARTIAL_CONTEXT_ACK_REQUIRED",
                 "READY on partial context requires explicit acknowledgement, never silent promotion.")
    else:
        _require(partial_ack is False, "ACKNOWLEDGEMENT_UNEXPECTED", "Acknowledgement is only valid on READY.")
    if to_state == "COMPLETED":
        _require(source["quality"] == "success", "INCOMPLETE_SOURCE_CANNOT_COMPLETE",
                 "Partial source context cannot be promoted into a complete result.")
        _require(reason is None and type(result) is str and SHA_RE.fullmatch(result) is not None,
                 "RESULT_DIGEST_REQUIRED", "A completed state requires a caller-declared result SHA-256; not execution proof.")
    elif to_state in TERMINAL:
        _require(type(reason) is str and REASON_RE.fullmatch(reason) is not None,
                 "TERMINAL_REASON_REQUIRED", "Noncomplete terminal state requires an explicit reason code.")
        _require(result is None or (to_state == "PARTIAL" and type(result) is str and SHA_RE.fullmatch(result) is not None),
                 "RESULT_DIGEST_UNEXPECTED", "Only PARTIAL may carry an optional declared result digest.")
    else:
        _require(reason is None and result is None, "OUTCOME_FIELDS_UNEXPECTED",
                 "Nonterminal transitions may not carry result/reason claims.")


def _id(kind: str) -> str:
    # Real 192-bit CSPRNG output; never time-, counter- or context-derived.
    return f"{kind}_v1_{secrets.token_bytes(24).hex()}"


def _event_hash(event: dict[str, Any]) -> str:
    return _hash(DOMAIN_EVENT, {k: v for k, v in event.items() if k != "event_sha256"})


def _replay(source: dict[str, Any], events: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Replay/cross-check every transition; not an authenticity verification."""
    _check_source_record(source)
    _require(type(events) is list and 1 <= len(events) <= MAX_EVENTS, "EVENT_BOUND_INVALID",
             "Event history is empty or exceeds its non-evicting bound.")
    run: dict[str, Any] | None = None
    handoffs: dict[str, dict[str, Any]] = {}
    seen_keys: set[str] = set()
    previous = None
    last_time: datetime | None = None
    for seq, event in enumerate(events, 1):
        _require(type(event) is dict and set(event) == EVENT_FIELDS and
                 type(event.get("seq")) is int and event["seq"] == seq and
                 type(event.get("revision")) is int and event["revision"] == seq and
                 type(event.get("kind")) is str and event["kind"] in KINDS and
                 event.get("previous_event_sha256") == previous and
                 type(event.get("event_sha256")) is str and SHA_RE.fullmatch(event["event_sha256"]) is not None and
                 event["event_sha256"] == _event_hash(event) and
                 event.get("source_context_sha256") == source["context_sha256"],
                 "EVENT_CHAIN_INVALID", "Event sequence, event hash, or source binding is inconsistent.")
        op = event["operation_key"]
        _check_op(op)
        _require(op not in seen_keys, "EVENT_REPLAY", "An operation key was reused in the history.")
        seen_keys.add(op)
        current_time = _time(event["timestamp_utc"])
        _require(last_time is None or current_time >= last_time, "CLOCK_ROLLBACK",
                 "Event clock moved backwards.")
        last_time = current_time
        _claim(event["actor_claim"])
        from_state = event["from_state"]
        to_state = event["to_state"]
        _require(to_state in STATES and type(event["acknowledge_partial"]) is bool,
                 "EVENT_STATE_INVALID", "Event contains an unsupported target state.")
        kind = event["kind"]
        run_id = event["run_id"]
        hid = event["handoff_id"]
        task_kind = event["task_kind"]
        if kind == "RUN_CREATED":
            _require(seq == 1 and run is None and type(run_id) is str and
                     ID_RE.fullmatch(run_id) is not None and run_id.startswith("run_") and
                     hid is None and task_kind is None and from_state is None and to_state == "CREATED" and
                     event["reason_code"] is None and event["result_sha256"] is None and
                     event["acknowledge_partial"] is False, "RUN_CREATION_INVALID",
                     "A run can only be created as the first event with a newly minted ID.")
            run = {"run_id": run_id, "state": "CREATED", "revision": 1,
                   "created_at_utc": event["timestamp_utc"], "updated_at_utc": event["timestamp_utc"],
                   "outcome_reason": None, "declared_result_sha256": None}
        else:
            _require(run is not None and run_id == run["run_id"], "PARENT_RUN_MISMATCH",
                     "Handoff/run event does not match the single parent run.")
            if kind == "RUN_TRANSITION":
                _require(hid is None and task_kind is None and from_state == run["state"] and
                         to_state in TRANSITIONS[run["state"]], "RUN_TRANSITION_INVALID",
                         "Run transition is skipped, reversed, repeated, or leaves a terminal state.")
                _validate_outcome(to_state, event["reason_code"], event["result_sha256"],
                                  event["acknowledge_partial"], source)
                if to_state in TERMINAL:
                    _require(all(h["state"] in TERMINAL for h in handoffs.values()),
                             "PENDING_HANDOFFS", "A run cannot terminate with unfinished handoffs.")
                    if to_state == "COMPLETED":
                        _require(bool(handoffs) and all(h["state"] == "COMPLETED" for h in handoffs.values()),
                                 "RUN_COMPLETION_UNSUPPORTED", "Completion requires at least one completed handoff and no partial outcomes.")
                run.update(state=to_state, revision=run["revision"] + 1,
                           updated_at_utc=event["timestamp_utc"], outcome_reason=event["reason_code"],
                           declared_result_sha256=event["result_sha256"])
            elif kind == "HANDOFF_CREATED":
                _require(run["state"] == "ACTIVE" and type(hid) is str and ID_RE.fullmatch(hid) is not None and
                         hid.startswith("handoff_") and hid not in handoffs and len(handoffs) < MAX_HANDOFFS and
                         task_kind == source["task_kind"] and from_state is None and to_state == "CREATED" and
                         event["reason_code"] is None and event["result_sha256"] is None and
                         event["acknowledge_partial"] is False, "HANDOFF_CREATION_INVALID",
                         "Handoff creation requires an active parent, a new ID, and the same source/task binding.")
                handoffs[hid] = {"handoff_id": hid, "run_id": run_id, "task_kind": task_kind,
                                 "source_context_sha256": source["context_sha256"], "state": "CREATED",
                                 "revision": 1, "created_at_utc": event["timestamp_utc"],
                                 "updated_at_utc": event["timestamp_utc"], "outcome_reason": None,
                                 "declared_result_sha256": None}
            elif kind == "HANDOFF_TRANSITION":
                handoff = handoffs.get(hid)
                _require(run["state"] == "ACTIVE" and handoff is not None and task_kind == handoff["task_kind"] and
                         from_state == handoff["state"] and to_state in TRANSITIONS[handoff["state"]],
                         "HANDOFF_TRANSITION_INVALID", "Handoff cannot transition out of order or after run termination.")
                _validate_outcome(to_state, event["reason_code"], event["result_sha256"],
                                  event["acknowledge_partial"], source)
                handoff.update(state=to_state, revision=handoff["revision"] + 1,
                               updated_at_utc=event["timestamp_utc"], outcome_reason=event["reason_code"],
                               declared_result_sha256=event["result_sha256"])
            else:
                raise LifecycleError("EVENT_KIND_INVALID", "Unsupported lifecycle event kind.")
        previous = event["event_sha256"]
    assert run is not None  # first event forced to RUN_CREATED
    return run, list(handoffs.values())


def _make_snapshot(source: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    run, handoffs = _replay(source, events)
    last = events[-1]
    result = {
        "schema": SCHEMA,
        "source": source,
        "revision": last["revision"],
        "event_sequence": last["seq"],
        "last_event_sha256": last["event_sha256"],
        "run": run,
        "handoffs": handoffs,
        "events": events,
        "recovery": {
            "checkpoint_revision": last["revision"],
            "checkpoint_event_sha256": last["event_sha256"],
            "last_event_at_utc": last["timestamp_utc"],
            "source_context_sha256": source["context_sha256"],
            "structural_hash_chain_is_authentication": False,
            "restart_is_trusted": False,
            "resume_without_trusted_store": False,
            "required_on_restart": "FUTURE_TRUSTED_STAGING_ATTESTATION_AND_EXPECTED_REVISION",
        },
        "authority": {
            "actor_authenticated": False,
            "external_handoff_executed_verified": False,
            "result_digests_authenticated": False,
            "provider_actor_verified": False,
            "remote_delivery_proven": False,
            "write_authorized": False,
            "writes_performed": False,
            "native_ai_handoff_registered": False,
        },
    }
    _require(len(_canonical(result)) <= MAX_CHECKPOINT_BYTES, "CHECKPOINT_SIZE_LIMIT",
             "Checkpoint exceeds size bound; do not drop old events to continue.")
    return result


def inspect_checkpoint(raw: bytes) -> dict[str, Any]:
    """Validate *structure* only. NEVER instantiate a mutable live run from JSON."""
    checkpoint = _strict_load(raw, MAX_CHECKPOINT_BYTES)
    _require(set(checkpoint) == {"schema", "source", "revision", "event_sequence", "last_event_sha256",
                                 "run", "handoffs", "events", "recovery", "authority"} and
             checkpoint.get("schema") == SCHEMA, "CHECKPOINT_SCHEMA_INVALID",
             "Checkpoint schema or fields are incompatible.")
    reconstructed = _make_snapshot(checkpoint["source"], checkpoint["events"])
    _require(checkpoint == reconstructed, "CHECKPOINT_DRIFT", "Checkpoint projections or recovery/authority flags disagree with replay.")
    return {
        "schema": "ces.handoff_checkpoint_inspection.v1", "status": "unavailable",
        "exit_code": EXIT["unavailable"], "reason_code": "RECOVERY_NOT_ATTESTED",
        "structural_consistency": "PASS_UNAUTHENTICATED",
        "revision": reconstructed["revision"], "event_count": reconstructed["event_sequence"],
        "run_id": None, "handoff_id": None, "live_session_restored": False,
        "resume_allowed": False, "prior_success_authenticated": False,
        "message": "Hash chain is self-consistent but unsigned; resume needs future trusted storage proof.",
    }


class Lifecycle:
    """Thread-safe, bounded, in-memory event-sourced run and handoff session.

    There is deliberately no `load`, `from_json` or `resume` constructor. A
    caller cannot upgrade untrusted JSON into trusted success/permission state.
    """

    def __init__(self, source: dict[str, Any], events: list[dict[str, Any]],
                 clock: Callable[[], datetime] | None = None, *,
                 _creation_guard: object | None = None) -> None:
        _require(_creation_guard is _SESSION_CREATION_TOKEN, "UNTRUSTED_RESTORE_FORBIDDEN",
                 "Use Lifecycle.create; checkpoint JSON cannot construct a live run.")
        self._lock = threading.RLock()
        self._source = copy.deepcopy(source)
        self._events = copy.deepcopy(events)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        _make_snapshot(self._source, self._events)

    @staticmethod
    def preview(prepared: Any) -> dict[str, Any]:
        source = _source(prepared)
        return {"schema": "ces.handoff_run_preview.v1", "status": "success",
                "source": source, "run_id": None, "handoff_id": None,
                "state": "NOT_CREATED", "external_execution_verified": False,
                "writes_performed": False}

    @classmethod
    def create(cls, prepared: Any, operation_key: str, *,
               actor_claim: dict[str, Any] | None = None,
               clock: Callable[[], datetime] | None = None) -> "Lifecycle":
        source = _source(prepared)
        _check_op(operation_key)
        claim = _claim(actor_claim)
        current_clock = clock or (lambda: datetime.now(timezone.utc))
        moment = _utc_now(current_clock)
        rid = _id("run")  # Only after all caller inputs validate.
        event = _new_event(1, operation_key, "RUN_CREATED", rid, None, None, None, "CREATED",
                           moment, source["context_sha256"], None, None, claim, False, None)
        return cls(source, [event], current_clock, _creation_guard=_SESSION_CREATION_TOKEN)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(_make_snapshot(self._source, self._events))

    def checkpoint_json(self) -> bytes:
        return _canonical(self.snapshot())

    def _commit(self, operation_key: str, expected_revision: int, context_sha256: str,
                kind: str, run_id: str, handoff_id: str | None, task_kind: str | None,
                from_state: str | None, to_state: str, reason_code: str | None,
                result_sha256: str | None, actor_claim: dict[str, Any] | None,
                acknowledge_partial: bool) -> dict[str, Any]:
        # Caller holds _lock. Validate before mutating the live event list.
        _check_op(operation_key)
        _require(context_sha256 == self._source["context_sha256"], "SOURCE_CONTEXT_MISMATCH",
                 "An operation may not switch the source context or source mode.")
        claim = _claim(actor_claim)
        prior = {e["operation_key"]: e for e in self._events}
        if operation_key in prior:
            old = prior[operation_key]
            same = (old["kind"] == kind and old["run_id"] == run_id and
                    old["handoff_id"] == handoff_id and old["to_state"] == to_state and
                    old["reason_code"] == reason_code and old["result_sha256"] == result_sha256 and
                    old["source_context_sha256"] == context_sha256 and
                    old["task_kind"] == task_kind and
                    old["acknowledge_partial"] == acknowledge_partial and
                    old["actor_claim"] == claim)
            raise LifecycleError("OPERATION_REPLAY" if same else "OPERATION_CONFLICT",
                                 "A used operation key cannot be applied again; no state was changed.")
        _require(type(expected_revision) is int and expected_revision == len(self._events),
                 "REVISION_CONFLICT", "Expected revision differs from the current in-memory revision.")
        _require(len(self._events) < MAX_EVENTS, "EVENT_LIMIT", "Event capacity is exhausted; no silent log truncation.")
        last_time = _time(self._events[-1]["timestamp_utc"])
        now = _utc_now(self._clock)
        _require(_time(now) >= last_time, "CLOCK_ROLLBACK", "The local clock moved backwards; operation blocked.")
        event = _new_event(len(self._events) + 1, operation_key, kind, run_id, handoff_id,
                           task_kind, from_state, to_state, now, context_sha256,
                           reason_code, result_sha256, claim, acknowledge_partial,
                           self._events[-1]["event_sha256"])
        candidate = self._events + [event]
        projection = _make_snapshot(self._source, candidate)
        self._events = candidate
        return copy.deepcopy(projection)

    def advance_run(self, target: str, *, expected_revision: int, context_sha256: str,
                    operation_key: str, reason_code: str | None = None,
                    result_sha256: str | None = None,
                    acknowledge_partial: bool = False,
                    actor_claim: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            run, _ = _replay(self._source, self._events)
            return self._commit(operation_key, expected_revision, context_sha256, "RUN_TRANSITION",
                                run["run_id"], None, None, run["state"], target,
                                reason_code, result_sha256, actor_claim, acknowledge_partial)

    def create_handoff(self, *, expected_revision: int, context_sha256: str,
                       operation_key: str, task_kind: str = "code_analysis",
                       actor_claim: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            run, handoffs = _replay(self._source, self._events)
            _check_op(operation_key)
            _require(run["state"] == "ACTIVE", "HANDOFF_PARENT_NOT_ACTIVE",
                     "A new handoff requires a live ACTIVE run.")
            _require(task_kind == self._source["task_kind"], "TASK_KIND_NOT_SUPPORTED",
                     "EC171 only models the EC170 code_analysis task kind; routing is future work.")
            _require(len(handoffs) < MAX_HANDOFFS, "HANDOFF_LIMIT", "Handoff capacity reached.")
            _require(type(expected_revision) is int and expected_revision == len(self._events),
                     "REVISION_CONFLICT", "Expected revision differs from the current in-memory revision.")
            _require(context_sha256 == self._source["context_sha256"], "SOURCE_CONTEXT_MISMATCH",
                     "A handoff cannot be bound to another source context.")
            _require(all(e["operation_key"] != operation_key for e in self._events),
                     "OPERATION_REPLAY", "Creation operation key has already been used.")
            _claim(actor_claim)
            _require(len(self._events) < MAX_EVENTS, "EVENT_LIMIT", "Event history capacity reached.")
            hid = _id("handoff")  # No placeholder ID before eligible creation.
            return self._commit(operation_key, expected_revision, context_sha256, "HANDOFF_CREATED",
                                run["run_id"], hid, task_kind, None, "CREATED", None, None, actor_claim, False)

    def advance_handoff(self, handoff_id: str, target: str, *, expected_revision: int,
                        context_sha256: str, operation_key: str, reason_code: str | None = None,
                        result_sha256: str | None = None, acknowledge_partial: bool = False,
                        actor_claim: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            run, handoffs = _replay(self._source, self._events)
            _require(type(handoff_id) is str and ID_RE.fullmatch(handoff_id) is not None and
                     handoff_id.startswith("handoff_"), "HANDOFF_ID_INVALID", "Handoff ID is invalid.")
            matches = [h for h in handoffs if h["handoff_id"] == handoff_id]
            _require(bool(matches), "HANDOFF_NOT_FOUND", "Handoff ID is not part of this run.")
            item = matches[0]
            return self._commit(operation_key, expected_revision, context_sha256, "HANDOFF_TRANSITION",
                                run["run_id"], handoff_id, item["task_kind"], item["state"], target,
                                reason_code, result_sha256, actor_claim, acknowledge_partial)


def _utc_now(clock: Callable[[], datetime]) -> str:
    now = clock()
    _require(type(now) is datetime and now.tzinfo is not None and now.utcoffset() is not None,
             "CLOCK_INVALID", "Clock must return an aware UTC-convertible datetime.")
    try:
        return now.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError) as exc:
        raise LifecycleError("CLOCK_INVALID", "Clock is not UTC-convertible.") from exc


def _new_event(seq: int, op: str, kind: str, run_id: str, hid: str | None,
               task_kind: str | None, from_state: str | None, to_state: str, at: str,
               context: str, reason: str | None, result: str | None,
               claim: dict[str, Any] | None, ack: bool, prev: str | None) -> dict[str, Any]:
    event = {"seq": seq, "revision": seq, "operation_key": op, "kind": kind,
             "run_id": run_id, "handoff_id": hid, "task_kind": task_kind,
             "from_state": from_state, "to_state": to_state, "timestamp_utc": at,
             "source_context_sha256": context, "reason_code": reason,
             "result_sha256": result, "actor_claim": claim,
             "acknowledge_partial": ack, "previous_event_sha256": prev}
    event["event_sha256"] = _event_hash(event)
    return event


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC171 standalone in-memory RunId/HandoffId state model")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--preview", metavar="EC170_JSON", help="Check context; never create an ID")
    group.add_argument("--create-run", metavar="EC170_JSON", help="Create a single in-memory run; JSON to stdout only")
    group.add_argument("--inspect-checkpoint", metavar="SNAPSHOT_JSON", help="Read-only structural inspection; never resume")
    parser.add_argument("--operation-key", help="Caller operation key, required only for --create-run")
    parser.add_argument("--actor-origin", choices=("human", "external"))
    parser.add_argument("--actor-subject")
    args = parser.parse_args(argv)
    try:
        if args.inspect_checkpoint:
            _require(args.operation_key is None and args.actor_origin is None and args.actor_subject is None,
                     "ARGUMENT_COMBINATION_INVALID", "Inspection accepts no creation/actor options.")
            response = inspect_checkpoint(_read_bounded(args.inspect_checkpoint, MAX_CHECKPOINT_BYTES))
        else:
            _require(args.preview is not None or args.operation_key is not None,
                     "OPERATION_KEY_REQUIRED", "Creating a run requires an explicit operation key.")
            _require(not ((args.actor_origin is None) != (args.actor_subject is None)),
                     "ACTOR_CLAIM_INVALID", "Actor origin and subject must be supplied together.")
            if args.preview:
                _require(args.operation_key is None and args.actor_origin is None,
                         "PREVIEW_NO_CREATION_ARGS", "Preview cannot accept operation or actor creation flags.")
            prepared = _strict_load(_read_bounded(args.preview or args.create_run, MAX_PREPARED_BYTES), MAX_PREPARED_BYTES)
            if args.preview:
                response = Lifecycle.preview(prepared)
                response["exit_code"] = 0
            else:
                actor = declared_actor(args.actor_origin, args.actor_subject) if args.actor_origin is not None else None
                session = Lifecycle.create(prepared, args.operation_key, actor_claim=actor)
                response = {"schema": SCHEMA, "status": "success", "exit_code": 0,
                            "reason_code": "RUN_CREATED_IN_MEMORY", "snapshot": session.snapshot(),
                            "persisted": False, "native_handoff_executed": False}
        print(json.dumps(response, ensure_ascii=True, allow_nan=False, sort_keys=True))
        return response["exit_code"]
    except LifecycleError as exc:
        print(json.dumps({"schema": SCHEMA, "status": exc.status, "exit_code": EXIT[exc.status],
                          "reason_code": exc.code, "message": exc.message,
                          "run_id": None, "handoff_id": None, "writes_performed": False}, sort_keys=True))
        return EXIT[exc.status]


if __name__ == "__main__":
    sys.exit(main())
