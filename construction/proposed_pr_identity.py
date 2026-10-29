#!/usr/bin/env python3
"""EC-162: bind read-only PR/MR candidates to provider object IDs and commit OIDs.

This is deliberately NOT the native CES Collect:ProposedPR action. The "pin"
is an *unauthenticated provider observation*, not a signed identity, a diff
snapshot, a review approval, or write permission. One invocation uses at most
one EC-161 HTTPS metadata GET; no files/patches/commits endpoints are fetched.

A caller can bring back a previous result as expected_pin. A changed repo/PR
identity, SHA, provenance, fork linkage or state invalidates that expectation.
A narrowly-scoped optional local Git probe checks object *presence and type*,
not whether an object really came from the named remote repository.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable

from proposed_pr_source import (
    MAX_TIMEOUT_SECONDS, RequestKey, ReadTransport, _commit_sha, _validate_key,
    fetch_proposed_pr, SourceFailure,
)

SCHEMA = "ces.proposed_pr_identity.v1"
PIN_SCHEMA = "ces.proposed_pr_pin.v1"
PIN_DOMAIN = b"CES-EC162-PROVIDER-METADATA-PIN-v1\0"
MAX_EXPECTED_BYTES = 64 * 1024
LOCAL_GIT_TIMEOUT = 5
DECIMAL_ID = re.compile(r"[1-9][0-9]{0,18}\Z", re.ASCII)
FINGERPRINT = re.compile(r"sha256:[a-f0-9]{64}\Z", re.ASCII)

# The format is explicit and closed. Changes require a new pin schema and
# downstream consumer review, rather than silently trusting new JSON fields.
PIN_FIELDS = frozenset({
    "schema", "provider", "repository_locator", "request_number",
    "target_repository_id", "source_repository_id", "proposal_object_id",
    "source_repository_path", "cross_fork", "object_format",
    "base_sha", "base_semantics", "head_sha", "head_semantics",
    "target_tip_sha", "target_tip_semantics", "provider_state",
    "provider_reports_merged",
})

IDENTITY_FIELDS = (
    "provider", "target_repository_id", "proposal_object_id",
    "source_repository_id", "request_number",
)
# Compare identity *before* any SHA differences so repository transfers and
# accidental PR number reuse aren't mislabeled as mere branch updates.
DRIFT_PRIORITY = (
    ("provider", "PROVIDER_CHANGED"),
    ("target_repository_id", "TARGET_REPOSITORY_ID_CHANGED"),
    ("proposal_object_id", "PROPOSAL_OBJECT_ID_CHANGED"),
    ("source_repository_id", "SOURCE_REPOSITORY_ID_CHANGED"),
    ("request_number", "PROPOSAL_NUMBER_CHANGED"),
    ("repository_locator", "REPOSITORY_PATH_CHANGED"),
    ("source_repository_path", "SOURCE_PATH_CHANGED"),
    ("cross_fork", "FORK_RELATION_CHANGED"),
    ("object_format", "OBJECT_FORMAT_CHANGED"),
    ("head_sha", "HEAD_SHA_CHANGED"),
    ("base_sha", "BASE_SHA_CHANGED"),
    ("target_tip_sha", "TARGET_TIP_SHA_CHANGED"),
    ("base_semantics", "BASE_SEMANTICS_CHANGED"),
    ("head_semantics", "HEAD_SEMANTICS_CHANGED"),
    ("target_tip_semantics", "TARGET_TIP_SEMANTICS_CHANGED"),
    ("provider_state", "PROPOSAL_STATE_CHANGED"),
    ("provider_reports_merged", "MERGE_REPORT_CHANGED"),
)


def _result(status: str, reason: str, message: str, *, pin: dict[str, Any] | None = None,
            fingerprint: str | None = None, synthetic: bool = False,
            drift: dict[str, Any] | None = None, local: dict[str, Any] | None = None,
            observed_at: str | None = None, evidence_level: str = "NONE") -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": status,
        "reason_code": reason,
        "exit_code": {"success": 0, "partial": 2, "invalid_input": 4, "unavailable": 5}[status],
        "message": message,
        "pin": pin,
        "pin_fingerprint": fingerprint,
        "observed_at_utc": observed_at,
        "drift": drift if drift is not None else {"status": "NOT_CHECKED", "changed_fields": []},
        "local_git": local if local is not None else {
            "status": "NOT_REQUESTED", "present_commit_roles": [], "missing_commit_roles": [],
            "scope": "LOCAL_OBJECT_DATABASE_ONLY_NOT_PROVIDER_ATTESTATION",
        },
        "evidence_level": evidence_level,
        "synthetic": synthetic,
        "native_cli_action_registered": False,
        "file_paths_collected": False,
        "patch_content_collected": False,
        "diff_snapshot_proven": False,
        "provider_actor_verified": False,
        "delivery_or_merge_proven": False,
        "write_authorized": False,
    }


def _full_id(value: Any) -> bool:
    return (isinstance(value, str) and DECIMAL_ID.fullmatch(value) is not None
            and int(value) <= 2**63 - 1)


def _canonical_pin(pin: dict[str, Any]) -> bytes:
    return json.dumps(pin, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def fingerprint_of(pin: dict[str, Any]) -> str:
    """Accidental drift fingerprint only; NOT a signature/authentication."""
    return "sha256:" + hashlib.sha256(PIN_DOMAIN + _canonical_pin(pin)).hexdigest()


def _new_pin(source: dict[str, Any]) -> dict[str, Any]:
    """Translate only EC-161's vetted fields, never branch names or raw text."""
    base = source["base"]
    head = source["head"]
    target_tip = source.get("target_tip")
    if source["provider"] == "github":
        # GitHub base.sha is the base BRANCH TIP at observation, NOT merge-base.
        target_tip_sha = base["sha"]
        target_tip_semantics = "github_base_branch_tip_at_observation"
    else:
        # GitLab diff_refs.base_sha is MERGE-BASE and start_sha is the
        # target-tip for that diff version, not necessarily today's tip.
        target_tip_sha = target_tip["sha"]
        target_tip_semantics = "gitlab_diff_refs_start_target_tip_at_diff_version"
    pin: dict[str, Any] = {
        "schema": PIN_SCHEMA,
        "provider": source["provider"],
        "repository_locator": source["requested_repository"],
        "request_number": source["request_number"],
        "target_repository_id": source["provider_repository_id"],
        "source_repository_id": source["provider_source_repository_id"],
        "proposal_object_id": source["provider_object_id"],
        "source_repository_path": source["provider_source_repository_path"],
        "cross_fork": source["provider_repository_id"] != source["provider_source_repository_id"],
        "object_format": "sha1" if len(base["sha"]) == 40 else "sha256",
        "base_sha": base["sha"],
        "base_semantics": base["meaning"],
        "head_sha": head["sha"],
        "head_semantics": head["meaning"],
        "target_tip_sha": target_tip_sha,
        "target_tip_semantics": target_tip_semantics,
        "provider_state": source["provider_state"],
        "provider_reports_merged": source["provider_reports_merged"],
    }
    if not _valid_pin(pin):
        raise ValueError("Internal metadata pin contract failed.")
    return pin


def _valid_pin(pin: Any) -> bool:
    """Validate prior-pin shape and semantics without trusting provenance."""
    if not isinstance(pin, dict) or set(pin) != PIN_FIELDS or pin.get("schema") != PIN_SCHEMA:
        return False
    provider = pin.get("provider")
    if provider not in ("github", "gitlab"):
        return False
    try:
        _validate_key(RequestKey(provider, pin["repository_locator"], pin["request_number"]))
    except (SourceFailure, AttributeError, KeyError, TypeError, ValueError):
        return False
    if not all(_full_id(pin.get(k)) for k in (
        "target_repository_id", "source_repository_id", "proposal_object_id"
    )):
        return False
    if type(pin.get("cross_fork")) is not bool or pin["cross_fork"] != (
        pin["source_repository_id"] != pin["target_repository_id"]
    ):
        return False
    if type(pin.get("provider_reports_merged")) is not bool:
        return False
    if pin.get("object_format") not in ("sha1", "sha256"):
        return False
    oid_len = 40 if pin["object_format"] == "sha1" else 64
    if any(type(pin.get(k)) is not str or _commit_sha(pin[k]) != pin[k]
           or len(pin[k]) != oid_len
           for k in ("base_sha", "head_sha", "target_tip_sha")):
        return False
    if provider == "github":
        if (pin.get("base_semantics") != "base_branch_tip_at_provider_observation"
                or pin.get("head_semantics") != "head_branch_tip_at_provider_observation"
                or pin.get("target_tip_semantics") != "github_base_branch_tip_at_observation"
                or pin["target_tip_sha"] != pin["base_sha"]
                or pin.get("provider_state") not in ("open", "closed")
                or (pin["provider_reports_merged"] and pin["provider_state"] != "closed")):
            return False
        source_path = pin.get("source_repository_path")
        if type(source_path) is not str:
            return False
        try:
            _validate_key(RequestKey("github", source_path, pin["request_number"]))
        except Exception:
            return False
    else:
        if (pin.get("base_semantics") != "gitlab_diff_refs_merge_base_not_target_branch_tip"
                or pin.get("head_semantics") != "gitlab_diff_refs_head_at_provider_observation"
                or pin.get("target_tip_semantics") != "gitlab_diff_refs_start_target_tip_at_diff_version"
                or pin.get("source_repository_path") is not None
                or pin.get("provider_state") not in ("opened", "closed", "merged", "locked")):
            return False
        if pin["provider_reports_merged"] != (pin["provider_state"] == "merged"):
            return False
    return True


def _validate_expected(expected: Any) -> tuple[dict[str, Any], bool] | None:
    if expected is None:
        return None
    if (not isinstance(expected, dict) or expected.get("schema") != SCHEMA
            or expected.get("status") not in ("partial", "success")
            or type(expected.get("synthetic")) is not bool
            or expected.get("write_authorized") is not False
            or expected.get("native_cli_action_registered") is not False
            or expected.get("diff_snapshot_proven") is not False
            or expected.get("delivery_or_merge_proven") is not False):
        raise ValueError("Expected pin must be a prior EC-162 read-only result.")
    pin = expected.get("pin")
    fingerprint = expected.get("pin_fingerprint")
    if (not _valid_pin(pin) or not isinstance(fingerprint, str)
            or not FINGERPRINT.fullmatch(fingerprint)
            or fingerprint_of(pin) != fingerprint):
        raise ValueError("Expected pin format/fingerprint is invalid.")
    return pin, expected["synthetic"]


def _compare(expected: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    changed = [key for key in PIN_FIELDS if expected.get(key) != current.get(key)]
    if changed:
        # Expose field names only, never the old/new OIDs or source response.
        ordered = [name for name, _ in DRIFT_PRIORITY if name in changed]
        return {
            "status": "INVALIDATED", "changed_fields": ordered,
            "reason_code": next(reason for name, reason in DRIFT_PRIORITY if name in changed),
        }
    return {"status": "PIN_MATCHED", "changed_fields": [], "reason_code": "PIN_UNCHANGED"}


def _git_environment() -> dict[str, str]:
    """Disable inherited Git overrides, replacement objects and global config."""
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith("GIT_") and k not in ("XDG_CONFIG_HOME",)}
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    # Partial clones can lazily fetch on a mere cat-file read. Explicitly
    # forbid remote protocols and lazy-fetch, independent of inherited config.
    env["GIT_NO_LAZY_FETCH"] = "1"
    env["GIT_ALLOW_PROTOCOL"] = ""
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def check_local_commit_objects(local_git_repository: str, pin: dict[str, Any]) -> dict[str, Any]:
    """Read-only git cat-file for the exact full SHA set, never a branch/ref.

    Presence is NOT proof that the commit belongs to the claimed repository:
    clones/alternates can contain unrelated objects or shared histories.
    No checkout, fetch, plumbing that writes refs/index, or Git hooks.
    """
    result: dict[str, Any] = {
        "status": "UNAVAILABLE", "present_commit_roles": [], "missing_commit_roles": [],
        "scope": "LOCAL_OBJECT_DATABASE_ONLY_NOT_PROVIDER_ATTESTATION",
    }
    try:
        if not isinstance(local_git_repository, str) or not local_git_repository or len(local_git_repository) > 4096:
            return result
        root = Path(local_git_repository)
        if not root.is_absolute() or not root.is_dir():
            return result
        roles = {"base": pin["base_sha"], "head": pin["head_sha"],
                 "target_tip": pin["target_tip_sha"]}
        unique_shas = list(dict.fromkeys(roles.values()))
        command = ["git", "--no-optional-locks", "-C", str(root),
                   "cat-file", "--batch-check=%(objectname) %(objecttype)"]
        process = subprocess.run(
            command, input="\n".join(unique_shas) + "\n", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=_git_environment(), timeout=LOCAL_GIT_TIMEOUT, check=False,
        )
        if process.returncode != 0 or len(process.stdout) > 4096:
            return result
        lines = process.stdout.splitlines()
        if len(lines) != len(unique_shas):
            return result
        objects = {}
        for sha, line in zip(unique_shas, lines):
            if line not in (f"{sha} commit", f"{sha} missing"):
                return result
            objects[sha] = (line == f"{sha} commit")
        result["present_commit_roles"] = [role for role, sha in roles.items() if objects[sha]]
        result["missing_commit_roles"] = [role for role, sha in roles.items() if not objects[sha]]
        result["status"] = "ALL_COMMIT_OBJECTS_PRESENT" if all(objects.values()) else "INCOMPLETE_COMMIT_OBJECTS"
        return result
    except (OSError, TimeoutError, subprocess.TimeoutExpired, ValueError):
        return result


def confirm_proposed_pr_identity(
    key: RequestKey, *,
    allow_network: bool = False,
    token_supplier: Callable[[], str | None] | None = None,
    transport: ReadTransport | None = None,
    timeout: float = 8.0,
    expected_pin: dict[str, Any] | None = None,
    local_git_repository: str | None = None,
) -> dict[str, Any]:
    """One provider metadata observation + conservative continuity/local checks.

    Invalid caller expectations are rejected before invoking EC-161, hence
    without reading a token. A successful identity check is never authority to
    mutate a repository, merge a PR or approve a delivery.
    """
    synthetic = transport is not None
    try:
        previous = _validate_expected(expected_pin)
    except (ValueError, TypeError, OverflowError):
        return _result("invalid_input", "INVALID_EXPECTED_PIN",
                       "The supplied previous result is not a valid EC-162 pin.", synthetic=synthetic)
    if local_git_repository is not None and (type(local_git_repository) is not str
            or not local_git_repository or len(local_git_repository) > 4096):
        return _result("invalid_input", "INVALID_LOCAL_GIT_PATH",
                       "Local Git location must be a bounded nonempty absolute path.", synthetic=synthetic)
    if local_git_repository is not None and not Path(local_git_repository).is_absolute():
        return _result("invalid_input", "INVALID_LOCAL_GIT_PATH",
                       "Local Git location must be absolute.", synthetic=synthetic)
    source_response = fetch_proposed_pr(
        key, allow_network=allow_network, token_supplier=token_supplier,
        transport=transport, timeout=timeout,
    )
    synthetic = source_response["synthetic"]
    if source_response["status"] != "success":
        return _result(source_response["status"], source_response["reason_code"],
                       source_response["message"], synthetic=synthetic)
    try:
        source = source_response["source"]
        pin = _new_pin(source)
        if previous is None:
            drift = {"status": "NO_PREVIOUS_PIN", "changed_fields": [],
                     "reason_code": "NO_PREVIOUS_PIN"}
        else:
            previous_pin, previous_synthetic = previous
            if previous_synthetic != synthetic:
                return _result("unavailable", "PIN_PROVENANCE_CHANGED",
                               "The previous and current observations have different synthetic/live provenance.",
                               synthetic=synthetic, drift={
                                   "status": "INVALIDATED",
                                   "changed_fields": ["origin"],
                                   "reason_code": "PIN_PROVENANCE_CHANGED",
                               })
            drift = _compare(previous_pin, pin)
            if drift["status"] == "INVALIDATED":
                return _result("unavailable", "PIN_DRIFT_" + drift["reason_code"],
                               "The previously pinned provider facts changed; re-review before acquiring a new pin.",
                               synthetic=synthetic, drift=drift)
        local = (check_local_commit_objects(local_git_repository, pin)
                 if local_git_repository is not None else None)
        local_checked = local is not None and local["status"] == "ALL_COMMIT_OBJECTS_PRESENT"
        matched = drift["status"] == "PIN_MATCHED"
        level = ("SYNTHETIC_NO_PROVIDER_ATTESTATION" if synthetic else
                 "MATCHED_AND_LOCAL_OBJECTS_PRESENT" if matched and local_checked else
                 "TWO_PROVIDER_OBSERVATIONS_MATCHED" if matched else
                 "PROVIDER_DECLARED_IDS_AND_OIDS_ONLY")
        # Injected transports are synthetic by definition; local objects +
        # two identical fixtures must not masquerade as an online attestation.
        if matched and local_checked and not synthetic:
            status = "success"
            reason = "READONLY_PIN_MATCH_AND_LOCAL_OBJECTS_PRESENT"
            message = ("Provider metadata pins match across observations and local commit objects exist; "
                       "remote origin, diff snapshot and delivery remain unproven.")
        else:
            status = "partial"
            reason = ("SYNTHETIC_OBSERVATION_ONLY" if synthetic else
                      "LOCAL_COMMIT_OBJECTS_UNVERIFIED" if local_git_repository is not None and not local_checked else
                      "PRIOR_PIN_NOT_SUPPLIED" if not matched else
                      "MATCHED_PIN_NO_LOCAL_OBJECT_CHECK")
            message = ("Only a bounded, read-only provider identity candidate is available. "
                       "Continuity and local object checks are insufficient for the full EC-162 read-only level.")
        return _result(
            status, reason, message, pin=pin,
            fingerprint=fingerprint_of(pin),
            observed_at=source.get("observed_at_utc"),
            drift=drift, local=local, synthetic=synthetic,
            evidence_level=level,
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return _result("unavailable", "PIN_BINDING_UNAVAILABLE",
                       "Required provider pin facts could not be bound.",
                       synthetic=synthetic)


def _read_expected(path: str) -> dict[str, Any]:
    # JSON input is untrusted. Bound size; reject duplicate keys/NaN/arrays.
    from proposed_pr_source import _decode_object
    with open(path, "rb") as stream:
        raw = stream.read(MAX_EXPECTED_BYTES + 1)
    if len(raw) > MAX_EXPECTED_BYTES:
        raise ValueError("expected pin file over limit")
    return _decode_object(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="EC162 read-only PR/MR immutable-ID and commit pin checks (NOT native CES Collect)")
    parser.add_argument("--provider", required=True, choices=("github", "gitlab"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--number", required=True, type=int)
    parser.add_argument("--allow-network", action="store_true",
                        help="explicit opt-in for one authenticated read-only provider GET")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--expected-pin", metavar="FILE", help="previous EC162 JSON result for drift comparison")
    parser.add_argument("--local-git", metavar="ABSOLUTE_DIR",
                        help="optional read-only local Git commit-object existence check")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    expected = None
    if args.expected_pin is not None:
        try:
            expected = _read_expected(args.expected_pin)
        except Exception:
            output = _result("invalid_input", "INVALID_EXPECTED_PIN",
                             "Previous pin could not be read as bounded valid JSON.")
            print(json.dumps(output, sort_keys=True, ensure_ascii=False))
            return output["exit_code"]
    result = confirm_proposed_pr_identity(
        RequestKey(args.provider, args.repository, args.number),
        allow_network=args.allow_network, expected_pin=expected,
        local_git_repository=args.local_git, timeout=args.timeout,
    )
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
