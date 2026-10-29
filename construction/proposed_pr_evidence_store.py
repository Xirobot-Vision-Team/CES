#!/usr/bin/env python3
"""EC169: explicit, scoped authorization for *local* append-only evidence receipts.

Stand-alone storage consumer for EC166/167/168 read-only *claims*. No upstream
result, however positive, carries storage permission. Neither a local receipt
nor its HMAC authenticates a Provider, a human actor, a target Git repository,
remote delivery, or deployment. No path/file/patch text from input is stored.

Provision a dedicated, empty, owner-private directory first. `init` and every
new receipt append need separate opt-ins. `preview`/`history` are read-only.
Receipt files are created atomically with link-if-absent under a pinned dirfd;
old receipts are never altered. POSIX no-follow and flock are requirements;
unsupported platforms fail closed instead of silently lowering guarantees.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
from typing import Any, Iterator
import uuid

try:
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - fail closed; native portability deferred
    fcntl = None

SCHEMA = "ces.proposed_pr_evidence_store.v1"
RECEIPT_SCHEMA = "ces.proposed_pr_evidence_receipt.v1"
MANIFEST_SCHEMA = "ces.proposed_pr_evidence_store_manifest.v1"
SOURCE_SCHEMAS = frozenset({
    "ces.proposed_pr_reconcile.v1",
    "ces.proposed_pr_merge.v1",
    "ces.proposed_pr_linear.v1",
})
DISCLOSURE = "MINIMAL_SOURCE_LABELS_NO_PATHS_BODIES_OR_OIDS_V1"
MIN_TTL, MAX_TTL, DEFAULT_TTL = 60, 3600, 900
UNKNOWN_MAX_TTL = 300
MAX_EVIDENCE_BYTES = 128 * 1024
MAX_RECORD_BYTES = 8 * 1024
MAX_RECEIPTS = 2048
MAX_REVISIONS_PER_SUBJECT = 128
MAX_ROOT_LENGTH = 1024
MAX_OBSERVATION_AGE = 900
MAX_FUTURE_SKEW = 60
SUBJECT_FILE = re.compile(r"([a-f0-9]{64})\.([0-9]{6})\.json\Z")
NAME = re.compile(r"[a-z][a-z0-9_-]{2,47}\Z")
REASON = re.compile(r"[A-Z][A-Z0-9_]{0,95}\Z")
PIN = re.compile(r"sha256:[a-f0-9]{64}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
RESULT_STATES = {
    "ces.proposed_pr_reconcile.v1": frozenset({"FRESH_OBSERVATION", "STALE_BY_DRIFT", "UNAVAILABLE_UNKNOWN"}),
    "ces.proposed_pr_merge.v1": frozenset({"LOCAL_MERGE_GRAPH_VERIFIED", "UNAVAILABLE_UNKNOWN"}),
    "ces.proposed_pr_linear.v1": frozenset({
        "LOCAL_MERGE_GRAPH_VERIFIED", "LOCAL_GITLAB_SQUASH_TREE_VERIFIED",
        "LOCAL_SINGLE_COMMIT_NET_TREE_VERIFIED_METHOD_UNKNOWN",
        "LOCAL_EXACT_HEAD_GRAPH_VERIFIED_METHOD_UNKNOWN", "UNAVAILABLE_UNKNOWN",
    }),
}
# No positive result is allowed to raise these flags. This is shape checking,
# not third-party authenticity verification or a signature on the JSON input.
ALWAYS_FALSE = ("write_authorized", "provider_actor_verified",
                "delivery_or_merge_proven", "native_cli_action_registered")
DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


class EvidenceGateError(Exception):
    def __init__(self, reason: str, status: str = "unavailable") -> None:
        super().__init__(reason)
        self.reason, self.status = reason, status


def _invalid(reason: str) -> EvidenceGateError:
    return EvidenceGateError(reason, "invalid_input")


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def _decode(data: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, value in items:
            if name in out:
                raise ValueError("duplicate key")
            out[name] = value
        return out
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")))


def _utc(value: Any) -> datetime | None:
    if type(value) is not str or not 20 <= len(value) <= 40:
        return None
    try:
        moment = datetime.fromisoformat(value)
        if moment.tzinfo is None or moment.utcoffset() != timedelta():
            return None
        return moment.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _now(value: datetime | None) -> datetime:
    moment = datetime.now(timezone.utc) if value is None else value
    if not isinstance(moment, datetime) or moment.tzinfo is None or moment.utcoffset() is None:
        raise _invalid("CLOCK_INVALID")
    return moment.astimezone(timezone.utc).replace(microsecond=0)


def _response(status: str, state: str, reason: str, *, details: dict[str, Any] | None = None,
              wrote: bool = False) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": status,
        "exit_code": {"partial": 2, "invalid_input": 4, "unavailable": 5}[status],
        "gate_state": state, "reason_code": reason,
        "details": details or {},
        "local_store_write_performed": wrote,
        "provider_write_performed": False,
        "git_ref_index_or_worktree_write_performed": False,
        "provider_actor_verified": False,
        "target_repository_membership_authenticated": False,
        "provider_merge_or_delivery_proven": False,
        "deployment_proven": False,
        "native_cli_action_registered": False,
        "source_result_authenticated": False,
        "store_hmac_is_external_authority": False,
    }


def _failure(error: EvidenceGateError) -> dict[str, Any]:
    return _response(error.status, "GATE_CLOSED", error.reason)


def _supported_fs() -> None:
    if (os.name != "posix" or fcntl is None or not hasattr(os, "O_NOFOLLOW") or
            not hasattr(os, "O_DIRECTORY") or os.open not in os.supports_dir_fd or
            os.mkdir not in os.supports_dir_fd or
            os.link not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd):
        raise EvidenceGateError("SECURE_POSIX_DIRFD_LOCKS_UNAVAILABLE")


def _root_components(root: str) -> list[str]:
    if (type(root) is not str or not 2 <= len(root) <= MAX_ROOT_LENGTH or
            not root.startswith("/") or root.endswith("/") or "\x00" in root or
            "//" in root or os.path.normpath(root) != root):
        raise _invalid("STORE_ROOT_NOT_CANONICAL_ABSOLUTE_PATH")
    parts = root.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise _invalid("STORE_ROOT_NOT_CANONICAL_ABSOLUTE_PATH")
    return parts


def _private_dir(fd: int, *, reason: str) -> None:
    s = os.fstat(fd)
    if (not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or
            s.st_mode & 0o077):
        raise EvidenceGateError(reason)


@contextmanager
def _opened_root(root: str) -> Iterator[int]:
    _supported_fs()
    parts = _root_components(root)
    fd = -1
    try:
        fd = os.open("/", DIR_FLAGS)
        for part in parts:
            next_fd = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        _private_dir(fd, reason="STORE_ROOT_OWNER_OR_PERMISSIONS_UNSAFE")
        yield fd
    except OSError:
        raise EvidenceGateError("STORE_ROOT_UNAVAILABLE_OR_SYMLINKED") from None
    finally:
        if fd >= 0:
            os.close(fd)


def _root_pinned(root: str, original_fd: int) -> bool:
    # Re-open *all* ancestors without following links to detect replacement
    # before an atomic append. The pinned fd is never reinterpreted as a path.
    try:
        with _opened_root(root) as current:
            a, b = os.fstat(original_fd), os.fstat(current)
            return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)
    except EvidenceGateError:
        return False


def _write_new(dirfd: int, name: str, raw: bytes) -> None:
    fd = os.open(name, CREATE_FLAGS, 0o600, dir_fd=dirfd)
    try:
        view = memoryview(raw)
        while view:
            wrote = os.write(fd, view)
            if wrote <= 0:
                raise OSError("short write")
            view = view[wrote:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_file(fd: int, name: str, limit: int) -> bytes:
    handle = os.open(name, FILE_FLAGS, dir_fd=fd)
    try:
        s = os.fstat(handle)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or
                s.st_mode & 0o077 or s.st_nlink != 1 or s.st_size > limit):
            raise EvidenceGateError("STORE_FILE_TYPE_SIZE_OR_PERMISSIONS_UNSAFE")
        with os.fdopen(os.dup(handle), "rb", closefd=True) as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise EvidenceGateError("STORE_FILE_TOO_LARGE")
        return raw
    finally:
        os.close(handle)


def _load_json(fd: int, name: str, limit: int) -> dict[str, Any]:
    raw = _read_file(fd, name, limit)
    try:
        obj = _decode(raw)
        if type(obj) is not dict or raw != _canonical(obj) + b"\n":
            raise ValueError("noncanonical")
        return obj
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise EvidenceGateError("STORE_RECORD_MALFORMED_OR_TAMPERED") from None


def _load_store(root_fd: int, root: str, store_id: str) -> tuple[dict[str, Any], int, int]:
    if type(store_id) is not str or NAME.fullmatch(store_id) is None:
        raise _invalid("STORE_ID_INVALID")
    if set(os.listdir(root_fd)) != {"manifest.json", "transaction.lock", "records"}:
        raise EvidenceGateError("STORE_LAYOUT_UNKNOWN_OR_NOT_INITIALIZED")
    manifest = _load_json(root_fd, "manifest.json", 2048)
    if set(manifest) != {"schema", "store_id", "root_path", "instance_id", "key_hex", "disclosure"}:
        raise EvidenceGateError("STORE_MANIFEST_INVALID")
    try:
        uuid_value = uuid.UUID(manifest["instance_id"])
    except (ValueError, AttributeError, TypeError):
        raise EvidenceGateError("STORE_MANIFEST_INVALID") from None
    if (manifest["schema"] != MANIFEST_SCHEMA or manifest["store_id"] != store_id or
            manifest["root_path"] != root or manifest["disclosure"] != DISCLOSURE or
            str(uuid_value) != manifest["instance_id"] or uuid_value.version != 4 or
            type(manifest["key_hex"]) is not str or HEX.fullmatch(manifest["key_hex"]) is None):
        raise EvidenceGateError("STORE_IDENTITY_MISMATCH_OR_MANIFEST_INVALID")
    lock = os.open("transaction.lock", FILE_FLAGS, dir_fd=root_fd)
    try:
        s = os.fstat(lock)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or
                s.st_mode & 0o077 or s.st_nlink != 1 or s.st_size != 0):
            raise EvidenceGateError("STORE_LOCK_UNSAFE")
        records = os.open("records", DIR_FLAGS, dir_fd=root_fd)
        try:
            _private_dir(records, reason="STORE_RECORD_DIRECTORY_UNSAFE")
            return manifest, records, lock
        except BaseException:
            os.close(records)
            raise
    except BaseException:
        os.close(lock)
        raise


@contextmanager
def _store(root: str, store_id: str, *, exclusive: bool = False) -> Iterator[tuple[dict[str, Any], int, int]]:
    with _opened_root(root) as root_fd:
        try:
            manifest, records, lock = _load_store(root_fd, root, store_id)
        except OSError:
            raise EvidenceGateError("STORE_COMPONENT_UNAVAILABLE_OR_SYMLINKED") from None
        try:
            fcntl.flock(lock, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            yield manifest, records, root_fd
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            os.close(lock)
            os.close(records)


def _mac(manifest: dict[str, Any], domain: str, obj: Any) -> str:
    key = bytes.fromhex(manifest["key_hex"])
    return hmac.new(key, ("CES-EC169-" + domain + "\0").encode("ascii") + _canonical(obj),
                    hashlib.sha256).hexdigest()


def _read_source(evidence: Any, *, manifest: dict[str, Any]) -> dict[str, Any]:
    """Allowlist projection: never persist arbitrary input nested dictionaries.

    Provider claims, local Git observations and provenance remain distinct,
    explicitly unauthenticated source assertions. An unavailable result may be
    retained historically, but NEVER becomes a successful local association.
    """
    try:
        if type(evidence) is not dict or len(_canonical(evidence)) > MAX_EVIDENCE_BYTES:
            raise _invalid("SOURCE_JSON_INVALID_OR_TOO_LARGE")
        schema = evidence.get("schema")
        if schema not in SOURCE_SCHEMAS:
            raise _invalid("UNSUPPORTED_EVIDENCE_SCHEMA")
        status = evidence.get("status")
        code = evidence.get("exit_code")
        if status not in ("partial", "unavailable") or type(code) is not int or code != (2 if status == "partial" else 5):
            raise _invalid("SOURCE_RESULT_NOT_PARTIAL_OR_UNKNOWN")
        if (type(evidence.get("synthetic")) is not bool or
                any(evidence.get(field) is not False for field in ALWAYS_FALSE)):
            raise _invalid("SOURCE_PROVENANCE_OR_POLICY_INVALID")
        state_field = "reconciliation_state" if schema.endswith("reconcile.v1") else "association_state"
        state = evidence.get(state_field)
        if state not in RESULT_STATES[schema] or (status == "unavailable") != (state == "UNAVAILABLE_UNKNOWN"):
            raise _invalid("SOURCE_STATE_AND_STATUS_INCONSISTENT")
        if schema.endswith("reconcile.v1") and evidence.get("diff_snapshot_proven") is not False:
            raise _invalid("SOURCE_SNAPSHOT_POLICY_INVALID")
        if schema.endswith("linear.v1") and evidence.get("local_association_verified") is not (status == "partial"):
            raise _invalid("SOURCE_LOCAL_VERIFICATION_FLAG_INVALID")
        if schema.endswith("merge.v1") and evidence.get("local_merge_graph_verified") is not (status == "partial"):
            raise _invalid("SOURCE_LOCAL_VERIFICATION_FLAG_INVALID")
        if status == "partial" and schema.endswith("reconcile.v1") and state not in ("FRESH_OBSERVATION", "STALE_BY_DRIFT"):
            raise _invalid("SOURCE_RECONCILIATION_STATE_INVALID")
        reason = evidence.get("reason_code")
        if type(reason) is not str or not REASON.fullmatch(reason):
            raise _invalid("SOURCE_REASON_INVALID")
        if schema.endswith("reconcile.v1"):
            current = evidence.get("current_observation")
            if type(current) is not dict:
                raise EvidenceGateError("SUBJECT_UNKNOWN_NO_PROVIDER_OBSERVATION")
            pin = current.get("pin")
            # Validate full original EC162 pin, not only its loose label.
            import proposed_pr_identity as identity
            if not identity._valid_pin(pin) or current.get("pin_fingerprint") != identity.fingerprint_of(pin):
                raise _invalid("SOURCE_EC162_PIN_OR_FINGERPRINT_INVALID")
            subject = {
                "provider": pin["provider"], "repository": pin["repository_locator"],
                "number": pin["request_number"], "proposal_object_id": pin["proposal_object_id"],
                "target_repository_id": pin["target_repository_id"],
            }
            if any(current.get(k) != value for k, value in (("provider", subject["provider"]),
                      ("repository_locator", subject["repository"]), ("request_number", subject["number"]))):
                raise _invalid("SOURCE_LOCATOR_CONFLICT")
            pin_fingerprint = current["pin_fingerprint"]
            provider_time = current.get("observed_at_utc")
            local_time = None
            provider_kind = current.get("source")
            if provider_kind != ("GITHUB_PULL_METADATA_SINGLE_GET" if pin["provider"] == "github"
                                 else "GITLAB_MERGE_REQUEST_METADATA_SINGLE_GET"):
                raise _invalid("PROVIDER_OBSERVATION_SOURCE_INVALID")
            if current.get("provider_origin_claim") != (
                    "synthetic_fixture" if evidence["synthetic"] else "provider_https_response"):
                raise _invalid("PROVIDER_ORIGIN_AND_SYNTHETIC_FLAG_CONFLICT")
            compare = evidence.get("comparison")
            if status == "partial":
                if type(compare) is not dict:
                    raise _invalid("EC166_COMPARISON_MISSING")
                if state == "STALE_BY_DRIFT":
                    if (type(compare.get("changed_fields")) is not list or
                            not compare["changed_fields"] or
                            compare.get("prior_evidence_invalidated_by_metadata") is not True or
                            evidence.get("reason_code") != "PRIOR_METADATA_EVIDENCE_STALE"):
                        raise _invalid("STALE_BY_DRIFT_NOT_RECORDED")
                else:
                    if (compare.get("pin_state") != "MATCHED" or
                            compare.get("count_state") not in ("NOT_BASELINED", "MATCHED_EXACT_CLAIM") or
                            compare.get("changed_fields") != [] or compare.get("changes") != [] or
                            compare.get("prior_evidence_invalidated_by_metadata") is not False or
                            current.get("provider_count_quality") != "EXACT_PROVIDER_CLAIM" or
                            type(current.get("reported_files")) is not int or
                            current["reported_files"] < 0 or
                            type(evidence.get("prior")) is not dict or
                            evidence["prior"].get("pin_fingerprint") != pin_fingerprint or
                            evidence.get("reason_code") not in (
                                "IDENTITY_OBSERVATION_MATCHED_COUNT_NOT_BASELINED",
                                "METADATA_MATCHED_SNAPSHOT_CONTENT_UNPROVEN")):
                        raise _invalid("EC166_FRESH_COMPARISON_INCONSISTENT")
            local_verified = False
        else:
            scope = evidence.get("identity_scope")
            if type(scope) is not dict:
                raise EvidenceGateError("SUBJECT_UNKNOWN_NO_COMPLETE_IDENTITY_SCOPE")
            if (scope.get("local_target_repository_selected_by_operator_not_verified") is not True or
                    scope.get("object_format") not in ("sha1", "sha256")):
                raise _invalid("SOURCE_LOCAL_TARGET_SCOPE_NOT_EXPLICIT")
            subject = {
                "provider": scope.get("provider"), "repository": scope.get("repository_locator"),
                "number": scope.get("request_number"),
                "proposal_object_id": scope.get("proposal_object_id_claim"),
                "target_repository_id": scope.get("target_repository_id_claim"),
            }
            pin_fingerprint = scope.get("pin_fingerprint")
            observed = evidence.get("observations")
            claim = evidence.get("provider_claim")
            if observed is not None and type(observed) is not dict:
                raise _invalid("SOURCE_OBSERVATIONS_INVALID")
            local_time = (observed.get("local_git_observed_at_utc") if observed else None)
            if schema.endswith("linear.v1"):
                provider_time = observed.get("ec168_provider_observed_at_utc") if observed else None
            else:
                provider_time = observed.get("ec167_provider_observed_at_utc") if observed else None
            if claim is not None and (type(claim) is not dict or
                    claim.get("observed_at_utc") != provider_time or
                    claim.get("provider_origin_claim") != (
                        "synthetic_fixture" if evidence["synthetic"] else "provider_https_response")):
                raise _invalid("SOURCE_PROVIDER_CLAIM_TIME_OR_ORIGIN_CONFLICT")
            if status == "partial":
                expected_local_states = {
                    "LOCAL_MERGE_GRAPH_VERIFIED": "READONLY_OBJECT_TREE_AND_PARENT_GRAPH_VERIFIED",
                    "LOCAL_GITLAB_SQUASH_TREE_VERIFIED": "READONLY_GITLAB_SQUASH_COMMIT_AND_NET_TREE_VERIFIED",
                    "LOCAL_SINGLE_COMMIT_NET_TREE_VERIFIED_METHOD_UNKNOWN": "READONLY_PROVIDER_LINKED_NET_TREE_VERIFIED",
                    "LOCAL_EXACT_HEAD_GRAPH_VERIFIED_METHOD_UNKNOWN": "READONLY_EXACT_HEAD_TARGET_ANCESTRY_AND_TREE_VERIFIED",
                }
                if (type(claim) is not dict or claim.get("provider_reports_merged") is not True or
                        type(evidence.get("local_git")) is not dict or
                        evidence["local_git"].get("state") != expected_local_states.get(state) or
                        local_time is None):
                    raise _invalid("SOURCE_PARTIAL_OBSERVATIONS_INCOMPLETE")
            local_verified = status == "partial"
            if not local_verified:
                # Failed local inspection is not a local Git observation even
                # when the old consumer filled a start-of-attempt timestamp.
                local_time = None
            provider_kind = ("GITHUB_PULL_METADATA_SINGLE_GET" if subject["provider"] == "github"
                             else "GITLAB_MERGE_REQUEST_METADATA_SINGLE_GET")
        if (subject["provider"] not in ("github", "gitlab") or
                type(subject["repository"]) is not str or
                type(subject["number"]) is not int or subject["number"] <= 0 or
                type(subject["proposal_object_id"]) is not str or
                type(subject["target_repository_id"]) is not str or
                not subject["proposal_object_id"].isdigit() or
                not subject["target_repository_id"].isdigit() or
                len(subject["proposal_object_id"]) > 19 or
                len(subject["target_repository_id"]) > 19 or
                type(pin_fingerprint) is not str or not PIN.fullmatch(pin_fingerprint)):
            raise _invalid("SOURCE_SUBJECT_IDENTITY_INVALID")
        import proposed_pr_source as source
        import proposed_pr_identity as identity
        if ((state == "LOCAL_GITLAB_SQUASH_TREE_VERIFIED" and subject["provider"] != "gitlab") or
                (state == "LOCAL_SINGLE_COMMIT_NET_TREE_VERIFIED_METHOD_UNKNOWN" and
                 subject["provider"] != "github")):
            raise _invalid("SOURCE_PROVIDER_AND_ASSOCIATION_METHOD_CONFLICT")
        if not identity._full_id(subject["proposal_object_id"]) or not identity._full_id(subject["target_repository_id"]):
            raise _invalid("SOURCE_SUBJECT_IDENTITY_INVALID")
        try:
            source._validate_key(source.RequestKey(subject["provider"], subject["repository"], subject["number"]))
        except source.SourceFailure:
            raise _invalid("SOURCE_REQUEST_LOCATOR_INVALID") from None
        if provider_time is not None and _utc(provider_time) is None:
            raise _invalid("PROVIDER_OBSERVATION_TIMESTAMP_INVALID")
        if local_time is not None and _utc(local_time) is None:
            raise _invalid("LOCAL_OBSERVATION_TIMESTAMP_INVALID")
        if status == "partial" and provider_time is None:
            raise _invalid("POSITIVE_RESULT_WITHOUT_PROVIDER_OBSERVATION")
        # Include full incoming JSON only as keyed digest. Never save it, any
        # source path, Provider SHA, request locator, token or patch body.
        return {
            "source_schema": schema, "source_status": status,
            "source_state": state, "source_reason": reason,
            "synthetic": evidence["synthetic"],
            "provider": subject["provider"],
            "provider_source": provider_kind if provider_time is not None else "NO_NEW_PROVIDER_OBSERVATION",
            "local_git_source": "OPERATOR_SELECTED_LOCAL_GIT_READ_CLAIM" if local_verified else "NOT_VERIFIED",
            "provider_observed_at_utc": _stamp(_utc(provider_time)) if provider_time else None,
            "local_git_observed_at_utc": _stamp(_utc(local_time)) if local_time else None,
            "local_association_only": local_verified,
            "subject_key": _mac(manifest, "SUBJECT", subject),
            "pin_key": _mac(manifest, "PIN", pin_fingerprint),
            "evidence_key": _mac(manifest, "EVIDENCE", evidence),
            "source_result_authenticated": False,
            "target_repository_membership_authenticated": False,
            "provider_merge_or_delivery_proven": False,
        }
    except EvidenceGateError:
        raise
    except (KeyError, ValueError, TypeError, OverflowError, RecursionError, AttributeError):
        raise _invalid("SOURCE_JSON_OR_IDENTITY_INVALID") from None


def _fresh(projection: dict[str, Any], now: datetime, ttl: int) -> tuple[datetime, str]:
    observations = [v for v in (projection["provider_observed_at_utc"],
                                 projection["local_git_observed_at_utc"]) if v is not None]
    if observations:
        times = [_utc(v) for v in observations]
        if any((t - now).total_seconds() > MAX_FUTURE_SKEW for t in times):
            raise EvidenceGateError("SOURCE_OBSERVATION_IN_FUTURE")
        if any((now - t).total_seconds() > MAX_OBSERVATION_AGE for t in times):
            raise EvidenceGateError("SOURCE_OBSERVATION_STALE_REOBSERVE")
        expiry = min(t + timedelta(seconds=ttl) for t in times)
        if expiry <= now:
            raise EvidenceGateError("SOURCE_OBSERVATION_TTL_ALREADY_EXPIRED")
        return expiry, "PROVIDER_AND_LOCAL_READS" if len(observations) == 2 else "PROVIDER_METADATA_ONLY"
    if projection["source_status"] != "unavailable":
        raise _invalid("MISSING_POSITIVE_OBSERVATION")
    # A permission denial/unknown can be retained only as short-lived context.
    # It is NOT a fresh remote observation; an unchanged old denial cannot
    # be extended by re-saving the same JSON after expiration.
    return now + timedelta(seconds=min(ttl, UNKNOWN_MAX_TTL)), "NO_FRESH_PROVIDER_OBSERVATION"


def _record_id(body: dict[str, Any]) -> str:
    return hashlib.sha256(b"CES-EC169-RECEIPT-ID-V1\0" + _canonical(body)).hexdigest()


def _make_record(manifest: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
    record_id = _record_id(body)
    return {
        "schema": RECEIPT_SCHEMA, "body": body, "record_id": record_id,
        "integrity_mac": _mac(manifest, "RECEIPT", {"body": body, "record_id": record_id}),
    }


def _scan_records(fd: int, manifest: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    names = os.listdir(fd)
    if len(names) > MAX_RECEIPTS:
        raise EvidenceGateError("STORE_RECEIPT_CAPACITY_EXCEEDED")
    per_subject: dict[str, list[dict[str, Any]]] = {}
    for filename in names:
        match = SUBJECT_FILE.fullmatch(filename)
        if match is None:
            raise EvidenceGateError("STORE_UNKNOWN_ENTRY_OR_INTERRUPTED_OPERATION")
        subject, number = match.groups()
        record = _load_json(fd, filename, MAX_RECORD_BYTES)
        if (set(record) != {"schema", "body", "record_id", "integrity_mac"} or
                record["schema"] != RECEIPT_SCHEMA or type(record["body"]) is not dict or
                type(record["record_id"]) is not str or not HEX.fullmatch(record["record_id"]) or
                type(record["integrity_mac"]) is not str or not HEX.fullmatch(record["integrity_mac"])):
            raise EvidenceGateError("STORE_RECEIPT_MALFORMED_OR_TAMPERED")
        body = record["body"]
        expected_keys = {
            "store_id", "store_instance_id", "subject_key", "revision", "prior_receipt_id",
            "prior_state_at_write", "prior_pin_changed", "pin_key", "evidence_key",
            "source_schema", "source_status", "source_state", "source_reason",
            "synthetic", "provider", "provider_source", "local_git_source",
            "provider_observed_at_utc", "local_git_observed_at_utc", "observation_kind",
            "local_association_only", "source_result_authenticated",
            "target_repository_membership_authenticated", "provider_merge_or_delivery_proven",
            "disclosure", "persisted_at_utc", "expires_at_utc", "ttl_seconds",
            "authorization_digest",
        }
        if (set(body) != expected_keys or body.get("store_id") != manifest["store_id"] or
                body.get("store_instance_id") != manifest["instance_id"] or
                body.get("disclosure") != DISCLOSURE or body.get("subject_key") != subject or
                type(body.get("revision")) is not int or body["revision"] != int(number) or
                not 1 <= body["revision"] <= MAX_REVISIONS_PER_SUBJECT or
                type(body.get("evidence_key")) is not str or not HEX.fullmatch(body["evidence_key"]) or
                type(body.get("pin_key")) is not str or not HEX.fullmatch(body["pin_key"]) or
                body.get("source_schema") not in SOURCE_SCHEMAS or
                type(body.get("source_reason")) is not str or not REASON.fullmatch(body["source_reason"]) or
                type(body.get("source_state")) is not str or not REASON.fullmatch(body["source_state"]) or
                type(body.get("authorization_digest")) is not str or not PIN.fullmatch(body["authorization_digest"]) or
                type(body.get("ttl_seconds")) is not int or not MIN_TTL <= body["ttl_seconds"] <= MAX_TTL or
                type(body.get("synthetic")) is not bool or
                type(body.get("local_association_only")) is not bool or
                body.get("source_status") not in ("partial", "unavailable") or
                body.get("source_state") not in RESULT_STATES.get(body.get("source_schema"), ()) or
                (body.get("source_status") == "unavailable") != (body.get("source_state") == "UNAVAILABLE_UNKNOWN") or
                body.get("provider") not in ("github", "gitlab") or
                body.get("disclosure") != DISCLOSURE or
                body.get("provider_source") not in (
                    "GITHUB_PULL_METADATA_SINGLE_GET", "GITLAB_MERGE_REQUEST_METADATA_SINGLE_GET",
                    "NO_NEW_PROVIDER_OBSERVATION") or
                body.get("local_git_source") not in (
                    "OPERATOR_SELECTED_LOCAL_GIT_READ_CLAIM", "NOT_VERIFIED") or
                body.get("observation_kind") not in (
                    "PROVIDER_AND_LOCAL_READS", "PROVIDER_METADATA_ONLY", "NO_FRESH_PROVIDER_OBSERVATION") or
                type(body.get("prior_pin_changed")) is not bool or
                body.get("prior_receipt_id") is not None and (
                    type(body["prior_receipt_id"]) is not str or not HEX.fullmatch(body["prior_receipt_id"])) or
                (body.get("provider_observed_at_utc") is not None and _utc(body["provider_observed_at_utc"]) is None) or
                (body.get("local_git_observed_at_utc") is not None and _utc(body["local_git_observed_at_utc"]) is None) or
                any(body.get(flag) is not False for flag in ("source_result_authenticated",
                    "target_repository_membership_authenticated", "provider_merge_or_delivery_proven")) or
                _utc(body.get("persisted_at_utc")) is None or _utc(body.get("expires_at_utc")) is None or
                _utc(body["expires_at_utc"]) <= _utc(body["persisted_at_utc"]) or
                _record_id(body) != record["record_id"] or
                not hmac.compare_digest(_mac(manifest, "RECEIPT", {"body": body, "record_id": record["record_id"]}),
                                        record["integrity_mac"])):
            raise EvidenceGateError("STORE_RECEIPT_MALFORMED_OR_TAMPERED")
        per_subject.setdefault(subject, []).append(record)
    for chain in per_subject.values():
        chain.sort(key=lambda item: item["body"]["revision"])
        if len(chain) > MAX_REVISIONS_PER_SUBJECT:
            raise EvidenceGateError("STORE_SUBJECT_HISTORY_LIMIT")
        prior = None
        seen = set()
        for index, item in enumerate(chain, 1):
            b = item["body"]
            if (b["revision"] != index or
                    b["prior_receipt_id"] != (prior["record_id"] if prior else None) or
                    b["prior_state_at_write"] not in ({"NONE"} if prior is None else {"ACTIVE", "EXPIRED"}) or
                    b["prior_pin_changed"] is not (prior is not None and b["pin_key"] != prior["body"]["pin_key"]) or
                    (prior and _utc(b["persisted_at_utc"]) < _utc(prior["body"]["persisted_at_utc"])) or
                    b["evidence_key"] in seen):
                raise EvidenceGateError("STORE_REVISION_CHAIN_TAMPERED_OR_AMBIGUOUS")
            if prior:
                should_prior = ("EXPIRED" if _utc(prior["body"]["expires_at_utc"]) <=
                                _utc(b["persisted_at_utc"]) else "ACTIVE")
                if b["prior_state_at_write"] != should_prior:
                    raise EvidenceGateError("STORE_PRIOR_REVISION_STATE_TAMPERED")
            seen.add(b["evidence_key"])
            prior = item
    return per_subject


def _authorization(manifest: dict[str, Any], root: str, projection: dict[str, Any],
                   *, ttl: int, previous_id: str | None) -> str:
    scope = {
        "schema": SCHEMA, "operation": "APPEND_LOCAL_EVIDENCE_ONCE",
        "root_path": root, "store_id": manifest["store_id"],
        "store_instance_id": manifest["instance_id"], "disclosure": DISCLOSURE,
        "subject_key": projection["subject_key"], "evidence_key": projection["evidence_key"],
        "source_schema": projection["source_schema"],
        "ttl_seconds": ttl, "expected_prior_receipt_id": previous_id,
    }
    # This digest binds a caller's *explicit approval*; it is not an actor
    # signature, and it is not returned as evidence of human authorization.
    return "sha256:" + hashlib.sha256(b"CES-EC169-AUTHORIZATION-SCOPE-V1\0" + _canonical(scope)).hexdigest()


def _details(projection: dict[str, Any], manifest: dict[str, Any], *,
             ttl: int, expiry: datetime, observation_kind: str,
             previous: dict[str, Any] | None, now: datetime, root: str) -> dict[str, Any]:
    prior_body = previous["body"] if previous else None
    return {
        "store_id": manifest["store_id"], "store_instance_id": manifest["instance_id"],
        "store_root": root, "disclosure": DISCLOSURE,
        "source_schema": projection["source_schema"], "source_status": projection["source_status"],
        "source_state": projection["source_state"],
        "provider": projection["provider"], "synthetic": projection["synthetic"],
        "subject_key": projection["subject_key"],
        "observation_kind": observation_kind,
        "provider_source": projection["provider_source"], "local_git_source": projection["local_git_source"],
        "provider_observed_at_utc": projection["provider_observed_at_utc"],
        "local_git_observed_at_utc": projection["local_git_observed_at_utc"],
        "ttl_seconds": ttl, "expires_at_utc": _stamp(expiry),
        "next_revision": prior_body["revision"] + 1 if prior_body else 1,
        "prior_receipt_id": previous["record_id"] if previous else None,
        "prior_expired_at_request": bool(prior_body and _utc(prior_body["expires_at_utc"]) <= now),
        "prior_pin_changed": bool(prior_body and prior_body["pin_key"] != projection["pin_key"]),
        "authorization_digest": _authorization(manifest, root, projection, ttl=ttl,
                        previous_id=previous["record_id"] if previous else None),
        "source_authenticated": False, "remote_delivery_proven": False,
    }


def init_evidence_store(root: str, store_id: str, *, allow_initialize: bool = False,
                        now: datetime | None = None) -> dict[str, Any]:
    """Initialize a pre-existing **empty** private directory, explicit opt-in.

    No arbitrary parent directory is created, no write without allow_initialize.
    Subsequent append rights MUST be independently re-authorized.
    """
    try:
        _now(now)
        if type(allow_initialize) is not bool or not allow_initialize:
            return _response("unavailable", "STORE_INIT_DENIED", "EXPLICIT_INIT_PERMISSION_REQUIRED")
        if type(store_id) is not str or NAME.fullmatch(store_id) is None:
            raise _invalid("STORE_ID_INVALID")
        with _opened_root(root) as root_fd:
            if os.listdir(root_fd):
                raise EvidenceGateError("STORE_INIT_REQUIRES_EMPTY_PRIVATE_DIRECTORY")
            instance = str(uuid.uuid4())
            manifest = {
                "schema": MANIFEST_SCHEMA, "store_id": store_id, "root_path": root,
                "instance_id": instance, "key_hex": secrets.token_hex(32),
                "disclosure": DISCLOSURE,
            }
            os.mkdir("records", 0o700, dir_fd=root_fd)
            _write_new(root_fd, "transaction.lock", b"")
            _write_new(root_fd, "manifest.json", _canonical(manifest) + b"\n")
            os.fsync(root_fd)
        return _response("partial", "STORE_INITIALIZED", "STORE_PRIVATE_LAYOUT_CREATED",
                         details={"store_id": store_id, "store_instance_id": instance,
                                  "evidence_append_permission_granted": False}, wrote=True)
    except EvidenceGateError as exc:
        return _failure(exc)
    except OSError:
        return _response("unavailable", "INIT_OUTCOME_UNKNOWN", "STORE_INIT_IO_FAILED_INSPECT_DIRECTORY")


def _plan(evidence: Any, root: str, store_id: str, ttl_seconds: int,
          now: datetime, manifest: dict[str, Any], records: int) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    if type(ttl_seconds) is not int or not MIN_TTL <= ttl_seconds <= MAX_TTL:
        raise _invalid("RECEIPT_TTL_OUT_OF_BOUNDS")
    projection = _read_source(evidence, manifest=manifest)
    chains = _scan_records(records, manifest)
    chain = chains.get(projection["subject_key"], [])
    existing = next((rec for rec in chain if rec["body"]["evidence_key"] == projection["evidence_key"]), None)
    prior = chain[-1] if chain else None
    if existing:
        return projection, {}, prior, existing
    if len(chain) >= MAX_REVISIONS_PER_SUBJECT or sum(map(len, chains.values())) >= MAX_RECEIPTS:
        raise EvidenceGateError("STORE_RECEIPT_CAPACITY_EXCEEDED")
    if prior and now < _utc(prior["body"]["persisted_at_utc"]):
        raise EvidenceGateError("STORE_CLOCK_MOVED_BACKWARDS")
    expiry, kind = _fresh(projection, now, ttl_seconds)
    if prior and prior["body"]["provider_observed_at_utc"] and projection["provider_observed_at_utc"]:
        if _utc(projection["provider_observed_at_utc"]) <= _utc(prior["body"]["provider_observed_at_utc"]):
            raise EvidenceGateError("REFRESH_REQUIRES_NEWER_PROVIDER_OBSERVATION")
    details = _details(projection, manifest, ttl=ttl_seconds, expiry=expiry,
                       observation_kind=kind, previous=prior, now=now, root=root)
    return projection, details, prior, None


def preview_evidence_receipt(evidence: Any, *, root: str, store_id: str,
                             ttl_seconds: int = DEFAULT_TTL,
                             now: datetime | None = None) -> dict[str, Any]:
    """Read-only source/age/history preview. An approval digest is *not* permission."""
    try:
        instant = _now(now)
        with _store(root, store_id) as (manifest, records, _):
            projection, details, prior, existing = _plan(evidence, root, store_id, ttl_seconds,
                                                         instant, manifest, records)
            if existing:
                details = {
                    "store_id": store_id, "subject_key": projection["subject_key"],
                    "receipt_id": existing["record_id"], "revision": existing["body"]["revision"],
                    "expires_at_utc": existing["body"]["expires_at_utc"],
                    "expired": _utc(existing["body"]["expires_at_utc"]) <= instant,
                    "requires_new_source_observation": True,
                }
                return _response("unavailable" if details["expired"] else "partial",
                                 "EXPIRED_DUPLICATE_REOBSERVE" if details["expired"] else "DUPLICATE_NO_WRITE",
                                 "EXPIRED_SOURCE_CANNOT_BE_REAUTHORIZED" if details["expired"] else "RECEIPT_ALREADY_STORED",
                                 details=details)
            return _response("partial", "PREVIEW_READY_NO_PERMISSION_GRANTED", "APPEND_REQUIRES_EXPLICIT_AUTHORIZATION",
                             details=details)
    except EvidenceGateError as exc:
        return _failure(exc)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return _response("unavailable", "GATE_CLOSED", "STORE_READ_UNKNOWN")


def persist_evidence_receipt(evidence: Any, *, root: str, store_id: str,
                             ttl_seconds: int = DEFAULT_TTL,
                             allow_evidence_write: bool = False,
                             authorization_digest: str | None = None,
                             now: datetime | None = None) -> dict[str, Any]:
    """Append exactly one scoped, immutable receipt, or fail without overwrite.

    `allow_evidence_write` is intentionally independent of any previous GH/GL
    or Git permissions. Digest must match a read-only preview for the same
    store, instance, input bytes, TTL and prior receipt. No automatic retry.
    """
    if allow_evidence_write is not True:
        return _response("unavailable", "WRITE_DENIED", "EXPLICIT_EVIDENCE_WRITE_PERMISSION_REQUIRED")
    if type(authorization_digest) is not str or not PIN.fullmatch(authorization_digest):
        return _response("invalid_input", "WRITE_DENIED", "AUTHORIZATION_DIGEST_REQUIRED")
    tmp: str | None = None
    try:
        instant = _now(now)
        with _store(root, store_id, exclusive=True) as (manifest, records, root_fd):
            projection, details, prior, existing = _plan(evidence, root, store_id, ttl_seconds,
                                                         instant, manifest, records)
            if existing:
                old = existing["body"]
                if _utc(old["expires_at_utc"]) <= instant:
                    raise EvidenceGateError("EXPIRED_SOURCE_CANNOT_BE_REAUTHORIZED")
                if old["authorization_digest"] != authorization_digest or old["ttl_seconds"] != ttl_seconds:
                    raise EvidenceGateError("AUTHORIZATION_NOT_BOUND_TO_EXISTING_RECEIPT")
                return _response("partial", "DUPLICATE_NO_WRITE", "RECEIPT_ALREADY_STORED",
                                 details={"receipt_id": existing["record_id"], "revision": old["revision"],
                                          "expires_at_utc": old["expires_at_utc"], "store_id": store_id})
            if details["authorization_digest"] != authorization_digest:
                raise EvidenceGateError("AUTHORIZATION_SCOPE_MISMATCH_OR_HISTORY_CHANGED")
            if not _root_pinned(root, root_fd):
                raise EvidenceGateError("STORE_ROOT_CHANGED_BEFORE_APPEND")
            body = {
                "store_id": store_id, "store_instance_id": manifest["instance_id"],
                "subject_key": projection["subject_key"],
                "revision": details["next_revision"], "prior_receipt_id": details["prior_receipt_id"],
                "prior_state_at_write": ("NONE" if not prior else "EXPIRED" if details["prior_expired_at_request"] else "ACTIVE"),
                "prior_pin_changed": details["prior_pin_changed"],
                "pin_key": projection["pin_key"], "evidence_key": projection["evidence_key"],
                "source_schema": projection["source_schema"], "source_status": projection["source_status"],
                "source_state": projection["source_state"], "source_reason": projection["source_reason"],
                "synthetic": projection["synthetic"], "provider": projection["provider"],
                "provider_source": projection["provider_source"], "local_git_source": projection["local_git_source"],
                "provider_observed_at_utc": projection["provider_observed_at_utc"],
                "local_git_observed_at_utc": projection["local_git_observed_at_utc"],
                "observation_kind": details["observation_kind"],
                "local_association_only": projection["local_association_only"],
                "source_result_authenticated": False,
                "target_repository_membership_authenticated": False,
                "provider_merge_or_delivery_proven": False,
                "disclosure": DISCLOSURE, "persisted_at_utc": _stamp(instant),
                "expires_at_utc": details["expires_at_utc"], "ttl_seconds": ttl_seconds,
                "authorization_digest": authorization_digest,
            }
            record = _make_record(manifest, body)
            raw = _canonical(record) + b"\n"
            if len(raw) > MAX_RECORD_BYTES:
                raise EvidenceGateError("SERIALIZED_RECEIPT_OVER_BUDGET")
            filename = f"{projection['subject_key']}.{body['revision']:06d}.json"
            # Unique private temporary file, then atomic hard-link as the
            # final, predictable revision slot with no replacement possible.
            # Competing writers serialize using transaction.lock; other tools
            # bypassing that lock still cannot overwrite this file name.
            tmp = ".pending-" + secrets.token_hex(16) + ".tmp"
            _write_new(records, tmp, raw)
            if not _root_pinned(root, root_fd):
                raise EvidenceGateError("STORE_ROOT_CHANGED_BEFORE_APPEND")
            os.link(tmp, filename, src_dir_fd=records, dst_dir_fd=records, follow_symlinks=False)
            # Complete the link's single-name publication *under the lock*.
            # Do not report persisted while a second hardlink still exists.
            os.unlink(tmp, dir_fd=records)
            tmp = None
            os.fsync(records)
            return _response("partial", "APPEND_ONLY_RECEIPT_PERSISTED", "LOCAL_MINIMAL_RECEIPT_COMMITTED",
                             details={"store_id": store_id, "subject_key": projection["subject_key"],
                                      "receipt_id": record["record_id"], "revision": body["revision"],
                                      "prior_receipt_id": body["prior_receipt_id"],
                                      "prior_state_at_write": body["prior_state_at_write"],
                                      "prior_pin_changed": body["prior_pin_changed"],
                                      "expires_at_utc": body["expires_at_utc"],
                                      "source_status": body["source_status"],
                                      "observation_kind": body["observation_kind"]}, wrote=True)
    except EvidenceGateError as exc:
        return _failure(exc)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        # IO can fail *after* the no-clobber hard link became durable; caller
        # must inspect before any new action. Never claim no write occurred.
        return _response("unavailable", "APPEND_OUTCOME_UNKNOWN", "STORE_IO_FAILURE_INSPECT_BEFORE_RETRY")
    finally:
        if tmp is not None:
            # Cleanup only the temp filename generated in THIS invocation.
            # A crash may leave an orphan: future writers fail closed and a
            # human must inspect, never auto-delete a foreign temp file.
            try:
                with _store(root, store_id, exclusive=True) as (_, records, __):
                    os.unlink(tmp, dir_fd=records)
                    os.fsync(records)
            except (OSError, EvidenceGateError):
                # An orphan blocks future writes; the operation's receipt
                # state is readable using the fixed revision name, if linked.
                pass


def inspect_evidence_history(evidence: Any, *, root: str, store_id: str,
                             now: datetime | None = None) -> dict[str, Any]:
    """Show bounded, redacted, integrity-checked revision history; no writes."""
    try:
        instant = _now(now)
        with _store(root, store_id) as (manifest, records, _):
            projection = _read_source(evidence, manifest=manifest)
            groups = _scan_records(records, manifest)
            chain = groups.get(projection["subject_key"], [])
            return _response("partial", "HISTORY_READ_ONLY", "HISTORY_NOT_REMOTE_PROOF",
                             details={"store_id": store_id, "subject_key": projection["subject_key"],
                                      "total_subject_revisions": len(chain),
                                      "records": [
                {"receipt_id": rec["record_id"], "revision": rec["body"]["revision"],
                 "prior_receipt_id": rec["body"]["prior_receipt_id"],
                 "source_schema": rec["body"]["source_schema"],
                 "source_status": rec["body"]["source_status"],
                 "source_state": rec["body"]["source_state"],
                 "provider_source": rec["body"]["provider_source"],
                 "local_git_source": rec["body"]["local_git_source"],
                 "synthetic": rec["body"]["synthetic"],
                 "prior_state_at_write": rec["body"]["prior_state_at_write"],
                 "prior_pin_changed": rec["body"]["prior_pin_changed"],
                 "expires_at_utc": rec["body"]["expires_at_utc"],
                 "current_ttl_state": "EXPIRED_HISTORICAL" if _utc(rec["body"]["expires_at_utc"]) <= instant
                                      else "ACTIVE_LOCAL_ONLY"} for rec in chain]})
    except EvidenceGateError as exc:
        return _failure(exc)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return _response("unavailable", "GATE_CLOSED", "STORE_READ_UNKNOWN")


def _read_input(path: str) -> dict[str, Any]:
    if type(path) is not str or not os.path.isabs(path) or "\x00" in path:
        raise _invalid("INPUT_PATH_NOT_ABSOLUTE")
    try:
        fd = os.open(path, FILE_FLAGS)
        try:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_size > MAX_EVIDENCE_BYTES:
                raise _invalid("INPUT_NOT_BOUNDED_REGULAR_FILE")
            with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
                raw = stream.read(MAX_EVIDENCE_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_EVIDENCE_BYTES:
            raise _invalid("INPUT_FILE_TOO_LARGE")
        obj = _decode(raw)
        if type(obj) is not dict:
            raise ValueError("not object")
        return obj
    except (OSError, ValueError, TypeError, RecursionError):
        raise _invalid("INPUT_FILE_INVALID_NO_SYMLINKS") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC169 scoped append-only local PR/MR evidence gate; not native CES CLI")
    sub = parser.add_subparsers(dest="operation", required=True)
    for cmd in ("init", "preview", "commit", "history"):
        section = sub.add_parser(cmd)
        section.add_argument("--root", required=True, metavar="PRECREATED_PRIVATE_ABSOLUTE_DIRECTORY")
        section.add_argument("--store-id", required=True)
        if cmd == "init":
            section.add_argument("--allow-init", action="store_true")
        else:
            section.add_argument("--evidence", required=True, metavar="EC166_167_168_JSON")
            if cmd in ("preview", "commit"):
                section.add_argument("--ttl", type=int, default=DEFAULT_TTL)
            if cmd == "commit":
                section.add_argument("--allow-evidence-write", action="store_true")
                section.add_argument("--authorization-digest")
    args = parser.parse_args(argv)
    try:
        if args.operation == "init":
            result = init_evidence_store(args.root, args.store_id, allow_initialize=args.allow_init)
        else:
            evidence = _read_input(args.evidence)
            if args.operation == "preview":
                result = preview_evidence_receipt(evidence, root=args.root, store_id=args.store_id,
                                                  ttl_seconds=args.ttl)
            elif args.operation == "commit":
                result = persist_evidence_receipt(evidence, root=args.root, store_id=args.store_id,
                                                  ttl_seconds=args.ttl,
                                                  allow_evidence_write=args.allow_evidence_write,
                                                  authorization_digest=args.authorization_digest)
            else:
                result = inspect_evidence_history(evidence, root=args.root, store_id=args.store_id)
    except EvidenceGateError as exc:
        result = _failure(exc)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
