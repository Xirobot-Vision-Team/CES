#!/usr/bin/env python3
"""EC172 private CES task staging, separate from repository files and AI dispatch.

An authorized POSIX owner-private directory is a local trust boundary for an
immutable, HMAC-sealed EC171 lifecycle checkpoint. All namespace operations are
root-dirfd-relative, no-follow, serialized with flock, and published with
link-if-absent after data fsync. A retry for the same operation/source/TTL is
idempotent; no saved checkpoint is promoted to a mutable Lifecycle object.

Limits: private local persistence is not authentication of EC170 source bytes,
actors, external AI output, delivery, or physical crash/power-loss durability.
A same-UID attacker or compromised host can access the key. Unsupported OS/fs,
uncertain transactions, bad permissions or state are explicitly unavailable.
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
from typing import Any, Callable, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - intentionally fail closed
    fcntl = None

import handoff_lifecycle as lc

SCHEMA = "ces.task_staging.v1"
MANIFEST_SCHEMA = "ces.task_staging_manifest.v1"
RECORD_SCHEMA = "ces.task_stage_record.v1"
ROOT_FILE_MANIFEST = "manifest.json"
ROOT_FILE_KEY = ".staging-key"
ROOT_FILE_LOCK = ".staging-lock"
DOMAIN_PIN = b"CES-EC172-STAGE-PARENT-PIN-v1\x00"
DOMAIN_MANIFEST = b"CES-EC172-STAGE-MANIFEST-v1\x00"
DOMAIN_RECORD = b"CES-EC172-STAGE-RECORD-HMAC-v1\x00"
DOMAIN_CHECKPOINT = b"CES-EC172-STAGE-CHECKPOINT-v1\x00"
MAX_ROOT_CHARS = 1024
MAX_RECORD_BYTES = lc.MAX_CHECKPOINT_BYTES + 8192
MAX_STAGE_COUNT = 128
MAX_INPUT_COUNT = 128  # EC173: one sealed input per committed handoff.
MIN_TTL = 60
MAX_TTL = 86400
MAX_PREPARED_BYTES = lc.MAX_PREPARED_BYTES
MAX_SKEW_SECONDS = 30
MAX_PENDING_COUNT = 1  # Never reuse an abandoned transaction in a new process.
STAGE_NAME = re.compile(r"(run_v1_[0-9a-f]{48})\.stage\.json\Z")
INPUT_NAME = re.compile(r"(handoff_v1_[0-9a-f]{48})\.input\.json\Z")
PENDING_NAME = re.compile(r"\.pending-(?:input-)?[0-9a-f]{32}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
ROOT_KEYS = frozenset((ROOT_FILE_MANIFEST, ROOT_FILE_KEY, ROOT_FILE_LOCK))
DIR_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
CREATE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
EXIT = {"success": 0, "invalid_input": 4, "unavailable": 5}


class StageError(ValueError):
    def __init__(self, code: str, status: str = "unavailable") -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def _invalid(code: str) -> StageError:
    return StageError(code, "invalid_input")


def _check(yes: bool, code: str, *, invalid: bool = False) -> None:
    if not yes:
        raise _invalid(code) if invalid else StageError(code)


def _canonical(data: Any) -> bytes:
    try:
        return lc._canonical(data)
    except (lc.LifecycleError, RecursionError, MemoryError) as exc:
        raise _invalid("JSON_NOT_CANONICAL") from exc


def _sha(domain: bytes, data: bytes) -> str:
    return hashlib.sha256(domain + data).hexdigest()


def _mac(key: bytes, data: dict[str, Any]) -> str:
    return hmac.new(key, DOMAIN_RECORD + _canonical(data), hashlib.sha256).hexdigest()


def _now(clock: Callable[[], datetime] | None) -> datetime:
    try:
        value = clock() if clock else datetime.now(timezone.utc)
        _check(type(value) is datetime and value.tzinfo is not None and value.utcoffset() is not None,
               "CLOCK_INVALID", invalid=True)
        moment = value.astimezone(timezone.utc)
        _check(2000 <= moment.year <= 9998, "CLOCK_INVALID", invalid=True)
        return moment.replace(microsecond=0)
    except (ValueError, TypeError, OverflowError) as exc:
        if isinstance(exc, StageError):
            raise
        raise _invalid("CLOCK_INVALID") from exc


def _stamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_stamp(value: Any) -> datetime:
    _check(type(value) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value) is not None,
           "STORED_TIME_INVALID")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise StageError("STORED_TIME_INVALID") from exc


def _supported() -> None:
    required = ("O_NOFOLLOW", "O_DIRECTORY")
    functions = (os.open, os.mkdir, os.stat, os.unlink, os.link)
    _check(os.name == "posix" and fcntl is not None and all(hasattr(os, x) for x in required)
           and all(f in os.supports_dir_fd for f in functions)
           and os.link in os.supports_follow_symlinks,
           "SECURE_POSIX_DIRFD_LOCK_AND_LINK_UNAVAILABLE")


def _components(path: str, label: str) -> list[str]:
    _check(type(path) is str and 2 <= len(path) <= MAX_ROOT_CHARS and
           path.startswith("/") and not path.endswith("/") and "//" not in path and
           "\x00" not in path and all(ord(c) >= 32 and ord(c) != 127 for c in path) and
           os.path.normpath(path) == path, f"{label}_PATH_INVALID", invalid=True)
    parts = path.split("/")[1:]
    _check(all(part not in ("", ".", "..") for part in parts), f"{label}_PATH_INVALID", invalid=True)
    return parts


def _identity(fd: int) -> tuple[int, int]:
    s = os.fstat(fd)
    _check(stat.S_ISDIR(s.st_mode), "DIRECTORY_IDENTITY_INVALID")
    return s.st_dev, s.st_ino


def _private_dir(fd: int, error: str) -> None:
    s = os.fstat(fd)
    _check(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and
           (s.st_mode & 0o077) == 0 and (s.st_mode & 0o700) == 0o700,
           error)


@contextmanager
def _open_directory(path: str, label: str) -> Iterator[tuple[int, list[tuple[int, int]]]]:
    _supported()
    parts = _components(path, label)
    fd = -1
    try:
        try:
            fd = os.open("/", DIR_FLAGS)
            ancestors = [_identity(fd)]
            for i, part in enumerate(parts):
                if i == len(parts) - 1 and label == "STAGE":
                    _private_dir(fd, "STAGING_PARENT_MUST_BE_OWNER_PRIVATE")
                next_fd = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = next_fd
                ancestors.append(_identity(fd))
            if label == "STAGE":
                _private_dir(fd, "STAGING_ROOT_MUST_BE_OWNER_PRIVATE")
        except OSError as exc:
            raise StageError(f"{label}_DIRECTORY_UNAVAILABLE_OR_SYMLINKED") from exc
        yield fd, ancestors
    finally:
        if fd >= 0:
            os.close(fd)


def _paths_separate(stage_chain: list[tuple[int, int]], repo_chain: list[tuple[int, int]],
                    stage_root: str, repo_root: str) -> None:
    _check(stage_chain[-1] not in repo_chain and repo_chain[-1] not in stage_chain and
           os.path.commonpath((stage_root, repo_root)) not in (stage_root, repo_root),
           "BUSINESS_REPOSITORY_OVERLAPS_STAGE", invalid=True)


def _pinned(root: str, repo: str, root_fd: int, root_id: tuple[int, int],
            repo_id: tuple[int, int]) -> bool:
    try:
        with _open_directory(root, "STAGE") as (new_root, stage_chain):
            with _open_directory(repo, "BUSINESS") as (new_repo, repo_chain):
                _paths_separate(stage_chain, repo_chain, root, repo)
                return _identity(new_root) == root_id and _identity(new_repo) == repo_id and _identity(root_fd) == root_id
    except (StageError, OSError):
        return False


def _write_exclusive(fd: int, filename: str, payload: bytes) -> None:
    # O_EXCL guarantees that refusal cannot overwrite a pre-existing entry.
    handle = os.open(filename, CREATE_FLAGS, 0o600, dir_fd=fd)
    try:
        _check(stat.S_ISREG(os.fstat(handle).st_mode), "CREATED_FILE_NOT_REGULAR")
        remaining = memoryview(payload)
        while remaining:
            n = os.write(handle, remaining)
            if n <= 0:
                raise OSError("short write")
            remaining = remaining[n:]
        os.fsync(handle)
    except (OSError, StageError):
        try:
            os.close(handle)
            os.unlink(filename, dir_fd=fd)
            os.fsync(fd)
        except OSError:
            raise StageError("STAGING_EXCLUSIVE_WRITE_ROLLBACK_UNCERTAIN") from None
        raise
    else:
        os.close(handle)


def _read_checked(fd: int, name: str, limit: int) -> bytes:
    try:
        handle = os.open(name, READ_FLAGS, dir_fd=fd)
    except OSError as exc:
        raise StageError("STAGING_FILE_UNAVAILABLE_OR_SYMLINKED") from exc
    try:
        s = os.fstat(handle)
        _check(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and
               (s.st_mode & 0o077) == 0 and s.st_nlink == 1 and 0 <= s.st_size <= limit,
               "STAGE_FILE_PERMISSIONS_TYPE_SIZE_OR_LINK_COUNT_UNSAFE")
        pieces = []
        remaining = limit + 1
        while remaining > 0:
            data = os.read(handle, min(65536, remaining))
            if not data:
                break
            pieces.append(data)
            remaining -= len(data)
        raw = b"".join(pieces)
        _check(len(raw) <= limit, "STAGE_FILE_TOO_LARGE")
        after = os.fstat(handle)
        _check((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns) ==
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
               "STAGE_FILE_CHANGED_WHILE_READING")
        return raw
    finally:
        os.close(handle)


def _strict_stored(raw: bytes, maximum: int) -> dict[str, Any]:
    _check(len(raw) <= maximum and raw.endswith(b"\n"), "STORED_JSON_INVALID")
    try:
        record = lc._strict_load(raw[:-1], maximum)
    except lc.LifecycleError as exc:
        raise StageError("STORED_JSON_INVALID") from exc
    _check(_canonical(record) + b"\n" == raw, "STORED_JSON_NOT_CANONICAL")
    return record


def _entries(root_fd: int) -> tuple[list[str], list[str]]:
    """Recognize immutable EC172 stage and EC173 input names, never skip junk.

    Any interrupted transaction stays a hard store-wide failure; old EC172
    operations continue to work after authorized EC173 inputs are published.
    Input contents are authenticated by the EC173 consumer, not assumed here.
    """
    names = os.listdir(root_fd)
    _check(len(names) <= MAX_STAGE_COUNT + MAX_INPUT_COUNT + len(ROOT_KEYS) + MAX_PENDING_COUNT,
           "STAGING_DIRECTORY_ENTRY_LIMIT")
    stages: list[str] = []
    inputs: list[str] = []
    for name in names:
        if name in ROOT_KEYS:
            continue
        if PENDING_NAME.fullmatch(name):
            raise StageError("INCOMPLETE_STAGING_TRANSACTION_REQUIRES_MANUAL_REVIEW")
        if STAGE_NAME.fullmatch(name):
            stages.append(name)
        elif INPUT_NAME.fullmatch(name):
            inputs.append(name)
        else:
            raise StageError("STAGING_DIRECTORY_UNEXPECTED_ENTRY")
    _check(len(stages) <= MAX_STAGE_COUNT and len(inputs) <= MAX_INPUT_COUNT,
           "STAGING_RECORD_CAPACITY_EXHAUSTED")
    _check(set(names) == ROOT_KEYS | set(stages) | set(inputs),
           "STAGING_STORE_NOT_INITIALIZED")
    return sorted(stages), sorted(inputs)


def _files(root_fd: int) -> list[str]:
    return _entries(root_fd)[0]


def _manifest_pin(manifest: dict[str, Any]) -> str:
    return _sha(DOMAIN_PIN, _canonical({k: manifest[k] for k in (
        "store_id", "root_dev", "root_ino", "root_uid", "root_path_sha256",
        "repo_dev", "repo_ino", "repo_path_sha256", "key_sha256")}))


def _manifest_fields(root: str, repo: str, root_fd: int, repo_fd: int, key: bytes) -> dict[str, Any]:
    a, b = os.fstat(root_fd), os.fstat(repo_fd)
    return {
        "schema": MANIFEST_SCHEMA,
        "store_id": "stage_v1_" + secrets.token_hex(16),
        "root_dev": a.st_dev, "root_ino": a.st_ino, "root_uid": a.st_uid,
        "root_path_sha256": hashlib.sha256(os.fsencode(root)).hexdigest(),
        "repo_dev": b.st_dev, "repo_ino": b.st_ino,
        "repo_path_sha256": hashlib.sha256(os.fsencode(repo)).hexdigest(),
        "key_sha256": hashlib.sha256(key).hexdigest(),
    }


def _check_manifest(value: dict[str, Any], root: str, repo: str, root_fd: int,
                    repo_fd: int, key: bytes) -> None:
    _check(set(value) == {"schema", "store_id", "root_dev", "root_ino", "root_uid",
                          "root_path_sha256", "repo_dev", "repo_ino", "repo_path_sha256", "key_sha256"},
           "STAGING_MANIFEST_SHAPE_INVALID")
    _check(value["schema"] == MANIFEST_SCHEMA and type(value["store_id"]) is str and
           re.fullmatch(r"stage_v1_[0-9a-f]{32}", value["store_id"]) is not None,
           "STAGING_MANIFEST_SHAPE_INVALID")
    expected = {
        "root_dev": os.fstat(root_fd).st_dev, "root_ino": os.fstat(root_fd).st_ino,
        "root_uid": os.fstat(root_fd).st_uid,
        "root_path_sha256": hashlib.sha256(os.fsencode(root)).hexdigest(),
        "repo_dev": os.fstat(repo_fd).st_dev, "repo_ino": os.fstat(repo_fd).st_ino,
        "repo_path_sha256": hashlib.sha256(os.fsencode(repo)).hexdigest(),
        "key_sha256": hashlib.sha256(key).hexdigest(),
    }
    _check(all(type(value[k]) is type(v) and value[k] == v for k, v in expected.items()),
           "STAGING_PARENT_IDENTITY_OR_KEY_CHANGED")


def _read_record(root_fd: int, name: str, key: bytes, manifest: dict[str, Any]) -> dict[str, Any]:
    obj = _strict_stored(_read_checked(root_fd, name, MAX_RECORD_BYTES), MAX_RECORD_BYTES)
    fields = {"schema", "store_id", "parent_pin", "run_id", "operation_key", "source",
              "revision", "last_event_sha256", "created_at_utc", "expires_at_utc",
              "ttl_seconds", "checkpoint_sha256", "checkpoint", "scope", "mac_sha256"}
    _check(set(obj) == fields and obj["schema"] == RECORD_SCHEMA and
           obj["store_id"] == manifest["store_id"] and
           obj["parent_pin"] == _manifest_pin(manifest), "STAGING_RECORD_IDENTITY_INVALID")
    mac = obj["mac_sha256"]
    _check(type(mac) is str and HEX.fullmatch(mac) is not None and
           hmac.compare_digest(mac, _mac(key, {k: v for k, v in obj.items() if k != "mac_sha256"})),
           "STAGING_RECORD_HMAC_INVALID")
    run_id = obj["run_id"]
    _check(type(run_id) is str and name == run_id + ".stage.json" and
           lc.ID_RE.fullmatch(run_id) is not None and run_id.startswith("run_"),
           "STAGING_RECORD_RUN_ID_INVALID")
    try:
        lc._check_op(obj["operation_key"])
    except lc.LifecycleError as exc:
        raise StageError("STAGING_RECORD_OPERATION_KEY_INVALID") from exc
    _check(type(obj["ttl_seconds"]) is int and MIN_TTL <= obj["ttl_seconds"] <= MAX_TTL,
           "STAGING_RECORD_TTL_INVALID")
    start, end = _parse_stamp(obj["created_at_utc"]), _parse_stamp(obj["expires_at_utc"])
    _check(end == start + timedelta(seconds=obj["ttl_seconds"]), "STAGING_RECORD_EXPIRY_INVALID")
    _check(type(obj["revision"]) is int and 1 <= obj["revision"] <= lc.MAX_EVENTS,
           "STAGING_REVISION_INVALID")
    _check(type(obj["last_event_sha256"]) is str and HEX.fullmatch(obj["last_event_sha256"]) is not None,
           "STAGING_RECORD_CHAIN_INVALID")
    _check(obj["scope"] == "PRIVATE_STAGE_ONLY_NO_AI_OR_MUTABLE_RESTORE", "STAGING_SCOPE_INVALID")
    snapshot = obj["checkpoint"]
    _check(type(snapshot) is dict and type(obj["source"]) is dict, "STAGING_RECORD_CHECKPOINT_INVALID")
    raw_snapshot = _canonical(snapshot)
    _check(len(raw_snapshot) <= lc.MAX_CHECKPOINT_BYTES and
           obj["checkpoint_sha256"] == _sha(DOMAIN_CHECKPOINT, raw_snapshot),
           "STAGING_RECORD_CHECKPOINT_HASH_INVALID")
    try:
        reconstructed = lc._make_snapshot(snapshot["source"], snapshot["events"])
    except (KeyError, TypeError, lc.LifecycleError) as exc:
        raise StageError("STAGING_CHECKPOINT_REPLAY_INVALID") from exc
    _check(snapshot == reconstructed and obj["source"] == snapshot["source"] and
           snapshot["run"]["run_id"] == run_id and
           snapshot["revision"] == obj["revision"] and
           snapshot["last_event_sha256"] == obj["last_event_sha256"] and
           snapshot["events"][0]["operation_key"] == obj["operation_key"],
           "STAGING_RECORD_CHECKPOINT_DRIFT")
    return obj


def _check_expiry(record: dict[str, Any], now: datetime) -> None:
    created = _parse_stamp(record["created_at_utc"])
    expires = _parse_stamp(record["expires_at_utc"])
    _check(now + timedelta(seconds=MAX_SKEW_SECONDS) >= created,
           "STAGING_CLOCK_ROLLBACK_UNAVAILABLE")
    _check(now < expires, "STAGING_EXPIRED_NO_REENTRY")


def _response(reason: str, record: dict[str, Any], *, replayed: bool) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": "success", "exit_code": 0, "reason_code": reason,
        "run_id": record["run_id"], "source_context_sha256": record["source"]["context_sha256"],
        "source_identity_sha256": record["source"]["identity_sha256"],
        "source_mode": record["source"]["source_mode"], "task_kind": record["source"]["task_kind"],
        "revision": record["revision"], "last_event_sha256": record["last_event_sha256"],
        "created_at_utc": record["created_at_utc"], "expires_at_utc": record["expires_at_utc"],
        "parent_pin": record["parent_pin"], "operation_key": record["operation_key"],
        "stage_committed": True, "idempotent_reentry": replayed,
        "mutable_lifecycle_restored": False, "prior_ai_success_authenticated": False,
        "ai_dispatched": False, "native_handoff_registered": False,
        "business_repository_written": False, "external_proof_authenticated": False,
    }


class TaskStaging:
    """Explicitly authorized, no-clobber staging; never a native AI handler."""

    def __init__(self, root: str, business_repo_root: str, *,
                 clock: Callable[[], datetime] | None = None) -> None:
        _supported()
        _components(root, "STAGE")
        _components(business_repo_root, "BUSINESS")
        self.root = root
        self.business_repo_root = business_repo_root
        self.clock = clock

    @contextmanager
    def _locked(self, *, initialized: bool = True) -> Iterator[tuple[int, dict[str, Any] | None, bytes | None]]:
        with _open_directory(self.root, "STAGE") as (root_fd, stage_chain):
            with _open_directory(self.business_repo_root, "BUSINESS") as (repo_fd, repo_chain):
                _paths_separate(stage_chain, repo_chain, self.root, self.business_repo_root)
                root_id, repo_id = _identity(root_fd), _identity(repo_fd)
                try:
                    fcntl.flock(root_fd, fcntl.LOCK_EX)
                except OSError as exc:
                    raise StageError("STAGING_DIRECTORY_LOCK_UNAVAILABLE") from exc
                try:
                    _check(_pinned(self.root, self.business_repo_root, root_fd, root_id, repo_id),
                           "STAGING_PARENT_CHANGED_DURING_LOCK")
                    if not initialized:
                        _check(os.listdir(root_fd) == [], "INIT_REQUIRES_EMPTY_PRIVATE_DIRECTORY")
                        yield root_fd, None, None
                    else:
                        _check(set(ROOT_KEYS).issubset(set(os.listdir(root_fd))),
                               "STAGING_STORE_NOT_INITIALIZED")
                        raw_key = _read_checked(root_fd, ROOT_FILE_KEY, 32)
                        _check(len(raw_key) == 32, "STAGING_KEY_INVALID")
                        manifest = _strict_stored(_read_checked(root_fd, ROOT_FILE_MANIFEST, 2048), 2048)
                        _check_manifest(manifest, self.root, self.business_repo_root,
                                        root_fd, repo_fd, raw_key)
                        _check(len(_read_checked(root_fd, ROOT_FILE_LOCK, 8)) == 0,
                               "STAGING_LOCK_MARKER_INVALID")
                        yield root_fd, manifest, raw_key
                except OSError as exc:
                    raise StageError("STAGING_FILESYSTEM_OPERATION_UNAVAILABLE") from exc
                finally:
                    try:
                        fcntl.flock(root_fd, fcntl.LOCK_UN)
                    except OSError as exc:
                        raise StageError("STAGING_DIRECTORY_UNLOCK_UNAVAILABLE") from exc

    def initialize(self, *, approve_init: bool) -> dict[str, Any]:
        _check(approve_init is True, "EXPLICIT_STAGING_INIT_APPROVAL_REQUIRED", invalid=True)
        with self._locked(initialized=False) as (fd, _, __):
            # Root/parent and business repo have already been independently pinned.
            key = secrets.token_bytes(32)
            with _open_directory(self.business_repo_root, "BUSINESS") as (repo_fd, _chain):
                manifest = _manifest_fields(self.root, self.business_repo_root, fd, repo_fd, key)
                _check(_pinned(self.root, self.business_repo_root, fd,
                               (manifest["root_dev"], manifest["root_ino"]),
                               (manifest["repo_dev"], manifest["repo_ino"])),
                       "STAGING_PARENT_CHANGED_BEFORE_INIT")
            created: list[str] = []
            try:
                for filename, raw in ((ROOT_FILE_KEY, key), (ROOT_FILE_LOCK, b""),
                                      (ROOT_FILE_MANIFEST, _canonical(manifest) + b"\n")):
                    _write_exclusive(fd, filename, raw)
                    created.append(filename)
                os.fsync(fd)
            except (OSError, StageError):
                # Only unlink private files that this initializer successfully created.
                # A failed rollback leaves the store unavailable until manual review.
                try:
                    for filename in reversed(created):
                        os.unlink(filename, dir_fd=fd)
                    os.fsync(fd)
                except OSError:
                    raise StageError("STAGING_INIT_ROLLBACK_UNCERTAIN") from None
                raise StageError("STAGING_INIT_FAILED") from None
            return {"schema": SCHEMA, "status": "success", "exit_code": 0,
                    "reason_code": "PRIVATE_STAGING_INITIALIZED", "parent_pin": _manifest_pin(manifest),
                    "store_id": manifest["store_id"], "staged_count": 0,
                    "business_repository_written": False, "ai_dispatched": False}

    @staticmethod
    def _expect_pin(pin: str, manifest: dict[str, Any]) -> None:
        _check(type(pin) is str and HEX.fullmatch(pin) is not None,
               "EXPECTED_PARENT_PIN_REQUIRED", invalid=True)
        _check(hmac.compare_digest(pin, _manifest_pin(manifest)), "STAGING_PARENT_PIN_MISMATCH")

    def _all(self, fd: int, key: bytes, manifest: dict[str, Any]) -> list[dict[str, Any]]:
        return [_read_record(fd, name, key, manifest) for name in _files(fd)]

    @staticmethod
    def _assert_pins(record: dict[str, Any], source: dict[str, Any], revision: int,
                     operation_key: str, ttl_seconds: int | None = None) -> None:
        _check(record["source"] == source and record["revision"] == revision and
               record["operation_key"] == operation_key and
               (ttl_seconds is None or record["ttl_seconds"] == ttl_seconds),
               "STAGING_REENTRY_IDENTITY_REVISION_OR_TTL_CONFLICT", invalid=True)

    def start(self, prepared: dict[str, Any], *, operation_key: str,
              expected_parent_pin: str, authorize_stage: bool,
              expected_revision: int = 1, ttl_seconds: int = 900,
              actor_claim: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create and stage one EC171 run, or safely reenter an immutable record.

        Check op-key before minting another ID. The public ID is only returned
        after local atomic publish and fsync; never return a prior unknown ID.
        """
        _check(authorize_stage is True, "EXPLICIT_LOCAL_STAGING_APPROVAL_REQUIRED", invalid=True)
        lc._check_op(operation_key)
        source = lc._source(prepared)
        claim = lc._claim(actor_claim)
        _check(type(expected_revision) is int and expected_revision == 1,
               "INITIAL_STAGING_REVISION_MUST_BE_ONE", invalid=True)
        _check(type(ttl_seconds) is int and MIN_TTL <= ttl_seconds <= MAX_TTL,
               "STAGING_TTL_OUT_OF_RANGE", invalid=True)
        now = _now(self.clock)
        with self._locked() as (fd, manifest, key):
            assert manifest is not None and key is not None
            self._expect_pin(expected_parent_pin, manifest)
            records = self._all(fd, key, manifest)
            for record in records:
                if record["operation_key"] == operation_key:
                    self._assert_pins(record, source, expected_revision, operation_key, ttl_seconds)
                    _check(record["checkpoint"]["events"][0]["actor_claim"] == claim,
                           "STAGING_REENTRY_ACTOR_LABEL_CONFLICT", invalid=True)
                    _check_expiry(record, now)
                    return _response("STAGING_IDEMPOTENT_REENTRY_READ_ONLY", record, replayed=True)
            _check(len(records) < MAX_STAGE_COUNT, "STAGING_RECORD_CAPACITY_EXHAUSTED")
            session = lc.Lifecycle.create(prepared, operation_key, actor_claim=claim)
            return self._publish(fd, manifest, key, session.snapshot(), now, ttl_seconds)

    def stage_live(self, session: lc.Lifecycle, *, expected_parent_pin: str,
                   expected_revision: int, context_sha256: str,
                   operation_key: str, authorize_stage: bool,
                   ttl_seconds: int = 900) -> dict[str, Any]:
        """Stage an existing EC171 in-memory checkpoint; never import a JSON session."""
        _check(authorize_stage is True, "EXPLICIT_LOCAL_STAGING_APPROVAL_REQUIRED", invalid=True)
        _check(isinstance(session, lc.Lifecycle), "STAGING_REQUIRES_LIVE_EC171_SESSION", invalid=True)
        lc._check_op(operation_key)
        _check(type(expected_revision) is int and 1 <= expected_revision <= lc.MAX_EVENTS,
               "STAGING_REVISION_INVALID", invalid=True)
        _check(type(ttl_seconds) is int and MIN_TTL <= ttl_seconds <= MAX_TTL,
               "STAGING_TTL_OUT_OF_RANGE", invalid=True)
        snap = session.snapshot()
        _check(snap == lc._make_snapshot(snap["source"], snap["events"]),
               "STAGING_LIVE_CHECKPOINT_INCONSISTENT", invalid=True)
        _check(snap["revision"] == expected_revision and
               snap["source"]["context_sha256"] == context_sha256 and
               snap["events"][0]["operation_key"] == operation_key,
               "STAGING_LIVE_REVISION_SOURCE_OR_CREATE_KEY_MISMATCH", invalid=True)
        now = _now(self.clock)
        with self._locked() as (fd, manifest, key):
            assert manifest is not None and key is not None
            self._expect_pin(expected_parent_pin, manifest)
            records = self._all(fd, key, manifest)
            for record in records:
                if record["operation_key"] == operation_key or record["run_id"] == snap["run"]["run_id"]:
                    self._assert_pins(record, snap["source"], expected_revision,
                                      operation_key, ttl_seconds)
                    _check(record["run_id"] == snap["run"]["run_id"] and record["checkpoint"] == snap,
                           "STAGING_IMMUTABLE_CHECKPOINT_CONFLICT", invalid=True)
                    _check_expiry(record, now)
                    return _response("STAGING_IDEMPOTENT_REENTRY_READ_ONLY", record, replayed=True)
            _check(len(records) < MAX_STAGE_COUNT, "STAGING_RECORD_CAPACITY_EXHAUSTED")
            return self._publish(fd, manifest, key, snap, now, ttl_seconds)

    def _publish(self, fd: int, manifest: dict[str, Any], key: bytes,
                 snapshot: dict[str, Any], now: datetime, ttl_seconds: int) -> dict[str, Any]:
        run = snapshot["run"]["run_id"]
        record = {
            "schema": RECORD_SCHEMA, "store_id": manifest["store_id"],
            "parent_pin": _manifest_pin(manifest), "run_id": run,
            "operation_key": snapshot["events"][0]["operation_key"],
            "source": snapshot["source"], "revision": snapshot["revision"],
            "last_event_sha256": snapshot["last_event_sha256"],
            "created_at_utc": _stamp(now),
            "expires_at_utc": _stamp(now + timedelta(seconds=ttl_seconds)),
            "ttl_seconds": ttl_seconds,
            "checkpoint_sha256": _sha(DOMAIN_CHECKPOINT, _canonical(snapshot)),
            "checkpoint": snapshot,
            "scope": "PRIVATE_STAGE_ONLY_NO_AI_OR_MUTABLE_RESTORE",
        }
        record["mac_sha256"] = _mac(key, record)
        data = _canonical(record) + b"\n"
        _check(len(data) <= MAX_RECORD_BYTES, "STAGING_RECORD_SIZE_EXCEEDED", invalid=True)
        target = run + ".stage.json"
        pending = ".pending-" + secrets.token_hex(16)
        linked = False
        tmp_created = False
        try:
            # Always create through a pinned directory descriptor: never open
            # an untrusted path or replace any existing stage file.
            _write_exclusive(fd, pending, data)
            tmp_created = True
            _check(_pinned(self.root, self.business_repo_root, fd,
                           (manifest["root_dev"], manifest["root_ino"]),
                           (manifest["repo_dev"], manifest["repo_ino"])),
                   "STAGING_PARENT_CHANGED_BEFORE_PUBLISH")
            os.link(pending, target, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            linked = True
            os.fsync(fd)
            os.unlink(pending, dir_fd=fd)
            tmp_created = False
            os.fsync(fd)
        except (OSError, StageError) as exc:
            if not linked and tmp_created:
                try:
                    os.unlink(pending, dir_fd=fd)
                    os.fsync(fd)
                except OSError:
                    raise StageError("STAGING_CREATE_ROLLBACK_UNCERTAIN") from None
            if linked:
                # Leave unresolved names in place for a manual, fail-closed
                # review. It is not safe to report a committed run here.
                raise StageError("STAGING_PUBLISH_DURABILITY_UNCERTAIN") from exc
            if isinstance(exc, StageError):
                raise
            raise StageError("STAGING_CREATE_FAILED_NO_ID_COMMITTED") from exc
        return _response("STAGING_CREATED_LOCAL_ONLY", record, replayed=False)

    def reenter(self, prepared: dict[str, Any], *, operation_key: str,
                expected_parent_pin: str, run_id: str, expected_revision: int) -> dict[str, Any]:
        """Reopen an exact saved record read-only, never resume an EC171 object."""
        lc._check_op(operation_key)
        source = lc._source(prepared)
        _check(type(run_id) is str and lc.ID_RE.fullmatch(run_id) is not None and
               run_id.startswith("run_"), "STAGING_RUN_ID_INVALID", invalid=True)
        _check(type(expected_revision) is int and 1 <= expected_revision <= lc.MAX_EVENTS,
               "STAGING_REVISION_INVALID", invalid=True)
        now = _now(self.clock)
        with self._locked() as (fd, manifest, key):
            assert manifest is not None and key is not None
            self._expect_pin(expected_parent_pin, manifest)
            records = self._all(fd, key, manifest)
            for record in records:
                if record["run_id"] == run_id:
                    self._assert_pins(record, source, expected_revision, operation_key)
                    _check_expiry(record, now)
                    return _response("STAGING_IDEMPOTENT_REENTRY_READ_ONLY", record, replayed=True)
            raise StageError("STAGING_RUN_NOT_FOUND")

    def inspect(self, *, expected_parent_pin: str) -> dict[str, Any]:
        """Return only aggregate stage/expired counts (no source or raw content)."""
        now = _now(self.clock)
        with self._locked() as (fd, manifest, key):
            assert manifest is not None and key is not None
            self._expect_pin(expected_parent_pin, manifest)
            records = self._all(fd, key, manifest)
            _check(all(now + timedelta(seconds=MAX_SKEW_SECONDS) >= _parse_stamp(r["created_at_utc"])
                       for r in records), "STAGING_CLOCK_ROLLBACK_UNAVAILABLE")
            expired = sum(1 for r in records if now >= _parse_stamp(r["expires_at_utc"]))
            return {"schema": SCHEMA, "status": "success", "exit_code": 0,
                    "reason_code": "STAGING_STORE_INSPECTED_LOCAL_ONLY",
                    "parent_pin": _manifest_pin(manifest), "staged_count": len(records),
                    "expired_count": expired, "record_capacity": MAX_STAGE_COUNT,
                    "mutable_lifecycle_restored": False, "ai_dispatched": False,
                    "business_repository_written": False}


def _fail(error: StageError | lc.LifecycleError) -> dict[str, Any]:
    return {"schema": SCHEMA, "status": error.status, "exit_code": EXIT[error.status],
            "reason_code": error.code, "run_id": None, "handoff_id": None,
            "stage_committed": False, "business_repository_written": False,
            "mutable_lifecycle_restored": False, "ai_dispatched": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC172 private, offline, no-clobber CES run staging")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--init", action="store_true", help="Initialize an already-provisioned, empty private root")
    modes.add_argument("--start", metavar="EC170_JSON", help="Create and stage or idempotently reenter a run")
    modes.add_argument("--reenter", metavar="EC170_JSON", help="Read-only reenter an existing staged run")
    modes.add_argument("--inspect", action="store_true", help="Read-only inspect stage counts")
    parser.add_argument("--root", required=True, help="Canonical absolute dedicated CES staging root")
    parser.add_argument("--business-repo-root", required=True, help="Canonical absolute analyzed business repo root")
    parser.add_argument("--approve-init", action="store_true")
    parser.add_argument("--approve-stage", action="store_true")
    parser.add_argument("--parent-pin")
    parser.add_argument("--operation-key")
    parser.add_argument("--run-id")
    parser.add_argument("--expected-revision", type=int, default=1)
    parser.add_argument("--ttl-seconds", type=int, default=900)
    args = parser.parse_args(argv)
    try:
        stager = TaskStaging(args.root, args.business_repo_root)
        if args.init:
            _check(not (args.approve_stage or args.parent_pin or args.operation_key or args.run_id)
                   and args.expected_revision == 1 and args.ttl_seconds == 900,
                   "INIT_ARGUMENTS_INVALID", invalid=True)
            response = stager.initialize(approve_init=args.approve_init)
        elif args.inspect:
            _check(not (args.approve_init or args.approve_stage or args.operation_key or args.run_id)
                   and args.expected_revision == 1 and args.ttl_seconds == 900,
                   "INSPECT_ARGUMENTS_INVALID", invalid=True)
            response = stager.inspect(expected_parent_pin=args.parent_pin)
        else:
            _check(not args.approve_init and args.operation_key is not None and
                   args.parent_pin is not None, "STAGING_ARGUMENTS_REQUIRED", invalid=True)
            filepath = args.start or args.reenter
            prepared = lc._strict_load(lc._read_bounded(filepath, MAX_PREPARED_BYTES), MAX_PREPARED_BYTES)
            if args.start:
                _check(args.run_id is None, "START_CANNOT_SELECT_RUN_ID", invalid=True)
                response = stager.start(prepared, operation_key=args.operation_key,
                                        expected_parent_pin=args.parent_pin,
                                        authorize_stage=args.approve_stage,
                                        expected_revision=args.expected_revision,
                                        ttl_seconds=args.ttl_seconds)
            else:
                _check(not args.approve_stage and args.run_id is not None and args.ttl_seconds == 900,
                       "REENTER_ARGUMENTS_INVALID", invalid=True)
                response = stager.reenter(prepared, operation_key=args.operation_key,
                                          expected_parent_pin=args.parent_pin,
                                          run_id=args.run_id, expected_revision=args.expected_revision)
        print(json.dumps(response, sort_keys=True, ensure_ascii=True, allow_nan=False))
        return response["exit_code"]
    except (StageError, lc.LifecycleError) as exc:
        result = _fail(exc)
        print(json.dumps(result, sort_keys=True))
        return result["exit_code"]
    except OSError:
        result = _fail(StageError("STAGING_FILESYSTEM_OPERATION_UNAVAILABLE"))
        print(json.dumps(result, sort_keys=True))
        return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
