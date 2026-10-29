#!/usr/bin/env python3
"""EC167: read-only PR/MR merge commit/tree association, not delivery proof.

A trusted operator supplies an EC162 pin, a recent EC166 FRESH_OBSERVATION
record and the path of an independently selected local *target* Git repository.
One newly authorized Provider metadata GET must exactly match both records and
report a complete merge_commit_sha. Only then are local Git objects inspected.

This program never fetches, checks out, writes refs/index, changes a worktree,
updates CES state, or maps squash/rebase commits (EC168). A local object graph
is not cryptographic proof that the objects belong to the Provider project.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable

import proposed_pr_identity as identity
import proposed_pr_reconcile as reconcile
import proposed_pr_source as source

SCHEMA = "ces.proposed_pr_merge.v1"
MAX_EC166_BYTES = 128 * 1024
MAX_EC166_AGE_SECONDS = 15 * 60
MAX_FUTURE_SKEW_SECONDS = 60
MAX_COMMIT_BYTES = 65536
GIT_TIMEOUT_SECONDS = 5
GIT_OID = re.compile(rb"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")


class GateError(ValueError):
    def __init__(self, reason: str, *, status: str = "invalid_input") -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


class GitEvidenceError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_time(value: Any) -> datetime | None:
    if not reconcile._utc_timestamp(value):
        return None
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _result(status: str, state: str, reason: str, message: str, *,
            synthetic: bool = False, identity_scope: dict[str, Any] | None = None,
            observations: dict[str, Any] | None = None,
            provider_claim: dict[str, Any] | None = None,
            local_git: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": status,
        "exit_code": {"partial": 2, "invalid_input": 4, "unavailable": 5}[status],
        "association_state": state,
        "reason_code": reason,
        "message": message,
        "identity_scope": identity_scope,
        "observations": observations,
        "provider_claim": provider_claim,
        "local_git": local_git if local_git is not None else {
            "state": "NOT_VERIFIED", "merge_tree_oid": None, "merge_parent_oids": [],
            "target_lineage_relation": "NOT_CHECKED",
        },
        "evidence_policy": {
            "network_by_default": "DENIED",
            "local_git_read_by_default": "DENIED",
            "provider_merge_claim_independently_authenticated": False,
            "local_objects_prove_provider_repository_membership": False,
            "old_file_pages_or_patches_reused": False,
            "cross_request_atomicity_proven": False,
            "squash_or_rebase_equivalence_mapped": False,
            "deployment_proven": False,
            "release_proven": False,
            "remote_write_performed": False,
        },
        "synthetic": synthetic,
        "local_merge_graph_verified": state == "LOCAL_MERGE_GRAPH_VERIFIED",
        "provider_actor_verified": False,
        "delivery_or_merge_proven": False,
        "target_repository_membership_authenticated": False,
        "native_cli_action_registered": False,
        "write_authorized": False,
    }


def _preflight(key: source.RequestKey, expected_pin: Any,
               ec166_reconciliation: Any, *, synthetic: bool) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Check recorded claims without a token, Git command or network request.

    EC166 data and EC162 fingerprints are *unsigned*; shape and continuity
    checks detect accidents/tampering, not malicious re-fingerprinting.
    """
    if expected_pin is None or ec166_reconciliation is None:
        raise GateError("EC162_AND_EC166_REQUIRED")
    try:
        verified = identity._validate_expected(expected_pin)
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
        raise GateError("EC162_PIN_INVALID") from None
    if verified is None:
        raise GateError("EC162_PIN_INVALID")
    pin, pin_synthetic = verified
    if any((pin["provider"] != key.provider,
            pin["repository_locator"] != key.repository,
            pin["request_number"] != key.number)):
        raise GateError("REQUEST_LOCATOR_MISMATCH")
    if type(ec166_reconciliation) is not dict or ec166_reconciliation.get("schema") != reconcile.SCHEMA:
        raise GateError("EC166_RESULT_INVALID")
    state = ec166_reconciliation.get("reconciliation_state")
    if state != "FRESH_OBSERVATION":
        if state in ("STALE_BY_DRIFT", "UNAVAILABLE_UNKNOWN"):
            raise GateError("EC166_NOT_FRESH", status="unavailable")
        raise GateError("EC166_RESULT_INVALID")

    prev = ec166_reconciliation.get("prior")
    current = ec166_reconciliation.get("current_observation")
    compare = ec166_reconciliation.get("comparison")
    flags = ec166_reconciliation.get("evidence_policy")
    if any((ec166_reconciliation.get("status") != "partial",
            ec166_reconciliation.get("exit_code") != 2,
            type(ec166_reconciliation.get("synthetic")) is not bool,
            ec166_reconciliation.get("synthetic") != pin_synthetic,
            ec166_reconciliation.get("synthetic") != synthetic,
            ec166_reconciliation.get("write_authorized") is not False,
            ec166_reconciliation.get("native_cli_action_registered") is not False,
            ec166_reconciliation.get("delivery_or_merge_proven") is not False,
            ec166_reconciliation.get("diff_snapshot_proven") is not False,
            ec166_reconciliation.get("provider_actor_verified") is not False,
            type(prev) is not dict, type(current) is not dict,
            type(compare) is not dict, type(flags) is not dict)):
        raise GateError("EC166_CHAIN_INVALID")
    fingerprint = identity.fingerprint_of(pin)
    if (prev.get("pin_fingerprint") != fingerprint or
            current.get("pin") != pin or current.get("pin_fingerprint") != fingerprint or
            current.get("provider") != key.provider or
            current.get("repository_locator") != key.repository or
            current.get("request_number") != key.number or
            current.get("source") != ("GITHUB_PULL_METADATA_SINGLE_GET" if key.provider == "github"
                                       else "GITLAB_MERGE_REQUEST_METADATA_SINGLE_GET") or
            current.get("provider_origin_claim") != ("synthetic_fixture" if synthetic else "provider_https_response") or
            prev.get("synthetic") is not synthetic or
            prev.get("receipt_authenticity_verified") is not False or
            prev.get("kind") not in ("EC162_PIN", "EC165_SNAPSHOT", "EC165_SNAPSHOT_AND_EC162_PIN") or
            current.get("raw_provider_json_disclosed") is not False or
            current.get("provider_http_response_headers_disclosed") is not False or
            current.get("file_pages_requested") is not False):
        raise GateError("EC166_CHAIN_INVALID")
    if (compare.get("pin_state") != "MATCHED" or
            compare.get("count_state") not in ("NOT_BASELINED", "MATCHED_EXACT_CLAIM") or
            compare.get("changed_fields") != [] or compare.get("changes") != [] or
            compare.get("prior_evidence_invalidated_by_metadata") is not False or
            current.get("provider_count_quality") != "EXACT_PROVIDER_CLAIM" or
            type(current.get("reported_files")) is not int or
            not 0 <= current["reported_files"] <= (999 if key.provider == "gitlab" else 10_000_000) or
            any(value is not False for value in flags.values() if type(value) is bool)):
        raise GateError("EC166_CHAIN_INVALID")
    if (compare["count_state"] == "MATCHED_EXACT_CLAIM" and
            (prev.get("reported_files") != current["reported_files"] or
             prev.get("provider_count_quality") != "EXACT_PROVIDER_CLAIM")):
        raise GateError("EC166_COUNT_INVALID")
    if (compare["count_state"] == "NOT_BASELINED" and
            (prev.get("reported_files") is not None or prev.get("provider_count_quality") is not None)):
        raise GateError("EC166_COUNT_INVALID")
    expected_reason = ("IDENTITY_OBSERVATION_MATCHED_COUNT_NOT_BASELINED"
                       if compare["count_state"] == "NOT_BASELINED"
                       else "METADATA_MATCHED_SNAPSHOT_CONTENT_UNPROVEN")
    if ec166_reconciliation.get("reason_code") != expected_reason:
        raise GateError("EC166_CHAIN_INVALID")
    observed = _parse_time(current.get("observed_at_utc"))
    if observed is None:
        raise GateError("EC166_OBSERVATION_TIME_INVALID")
    now = datetime.now(timezone.utc)
    age = (now - observed).total_seconds()
    if age < -MAX_FUTURE_SKEW_SECONDS:
        raise GateError("EC166_OBSERVATION_TIME_INVALID")
    if age > MAX_EC166_AGE_SECONDS:
        raise GateError("EC166_OBSERVATION_EXPIRED", status="unavailable")
    first_seen = expected_pin.get("observed_at_utc")
    if first_seen is not None and _parse_time(first_seen) is None:
        raise GateError("EC162_OBSERVATION_TIME_INVALID")
    # Times describe successive observations and are not provider-signed.
    if first_seen is not None and (_parse_time(first_seen) - observed).total_seconds() > MAX_FUTURE_SKEW_SECONDS:
        raise GateError("EC162_AFTER_EC166")
    scope = {
        "provider": key.provider, "repository_locator": key.repository,
        "request_number": key.number,
        "target_repository_id_claim": pin["target_repository_id"],
        "source_repository_id_claim": pin["source_repository_id"],
        "proposal_object_id_claim": pin["proposal_object_id"],
        "object_format": pin["object_format"],
        "pin_fingerprint": fingerprint,
        "local_target_repository_selected_by_operator_not_verified": True,
    }
    times = {
        "ec162_observed_at_utc": first_seen,
        "ec166_observed_at_utc": current["observed_at_utc"],
        "ec167_provider_observed_at_utc": None,
        "local_git_observed_at_utc": None,
        "ec166_source": current["source"],
        "ec166_provider_origin_claim": current["provider_origin_claim"],
    }
    return pin, scope, times


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        # Refname, index, config, credentials and inherited GIT_* overrides
        # are never accepted. Git's partial clone lazy fetching is disabled.
        return subprocess.run(
            ["git", "--no-optional-locks", "-C", str(root), *args],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=identity._git_environment(), timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise GitEvidenceError("LOCAL_GIT_UNAVAILABLE") from None


def _value(root: Path, *args: str, max_bytes: int = 80) -> bytes:
    result = _git(root, *args)
    if result.returncode != 0 or len(result.stdout) > max_bytes:
        raise GitEvidenceError("LOCAL_GIT_OBJECT_UNAVAILABLE")
    return result.stdout.strip()


def _read_commit(root: Path, oid: str, oid_length: int) -> tuple[str, list[str]]:
    try:
        kind = _value(root, "cat-file", "-t", oid)
    except GitEvidenceError:
        raise GitEvidenceError("LOCAL_COMMIT_UNAVAILABLE") from None
    if kind != b"commit":
        raise GitEvidenceError("LOCAL_COMMIT_UNAVAILABLE")
    length = _value(root, "cat-file", "-s", oid)
    if not length.isascii() or not length.isdigit() or len(length) > 8 or int(length) > MAX_COMMIT_BYTES:
        raise GitEvidenceError("LOCAL_COMMIT_UNREADABLE")
    # Content read only after a strict object-size bound. Never report the
    # commit message, signatures or author metadata to the caller.
    raw = _value(root, "cat-file", "-p", oid, max_bytes=MAX_COMMIT_BYTES)
    header = raw.split(b"\n\n", 1)[0]
    lines = header.split(b"\n")
    if not lines or not lines[0].startswith(b"tree "):
        raise GitEvidenceError("LOCAL_COMMIT_MALFORMED")
    tree = lines[0][5:]
    if not GIT_OID.fullmatch(tree) or len(tree) != oid_length:
        raise GitEvidenceError("LOCAL_COMMIT_MALFORMED")
    parents: list[str] = []
    for line in lines[1:]:
        if line.startswith(b"parent "):
            parent = line[7:]
            if not GIT_OID.fullmatch(parent) or len(parent) != oid_length:
                raise GitEvidenceError("LOCAL_COMMIT_MALFORMED")
            parents.append(parent.decode("ascii"))
    if len(set(parents)) != len(parents):
        raise GitEvidenceError("LOCAL_COMMIT_MALFORMED")
    return tree.decode("ascii"), parents


def _ancestor(root: Path, left: str, right: str) -> bool:
    result = _git(root, "merge-base", "--is-ancestor", left, right)
    if result.stdout or result.returncode not in (0, 1):
        raise GitEvidenceError("LOCAL_GIT_ANCESTRY_UNAVAILABLE")
    return result.returncode == 0


def _local_git_scope(path: str, pin: dict[str, Any]) -> tuple[Path, str, int]:
    """Common exact-root/format gate reused by EC168; never resolve refs."""
    root = Path(path)
    # Do not silently accept an arbitrary subdirectory of an unrelated parent
    # worktree as the purported target repository. Both bare and main-root
    # worktree paths are allowed, but path identity is still operator-declared.
    bare = _value(root, "rev-parse", "--is-bare-repository")
    if bare == b"true":
        git_root = _value(root, "rev-parse", "--absolute-git-dir", max_bytes=4096)
    elif bare == b"false":
        git_root = _value(root, "rev-parse", "--show-toplevel", max_bytes=4096)
    else:
        raise GitEvidenceError("LOCAL_GIT_REPOSITORY_SCOPE_UNAVAILABLE")
    try:
        exact_root = Path(git_root.decode("utf-8")).resolve(strict=True)
        selected_root = root.resolve(strict=True)
    except (UnicodeError, OSError, ValueError):
        raise GitEvidenceError("LOCAL_GIT_REPOSITORY_SCOPE_UNAVAILABLE") from None
    if exact_root != selected_root:
        raise GitEvidenceError("LOCAL_GIT_REPOSITORY_SCOPE_MISMATCH")
    # Never dereference caller-controlled refs or assume clone/provider origin.
    object_format = _value(root, "rev-parse", "--show-object-format").decode("ascii", "replace")
    if object_format != pin["object_format"]:
        raise GitEvidenceError("LOCAL_GIT_OBJECT_FORMAT_MISMATCH")
    oid_length = 40 if object_format == "sha1" else 64
    return root, object_format, oid_length


def _local_association(path: str, pin: dict[str, Any], merge_oid: str) -> dict[str, Any]:
    root, object_format, oid_length = _local_git_scope(path, pin)
    tree_oid, parents = _read_commit(root, merge_oid, oid_length)
    if len(parents) != 2:
        raise GitEvidenceError("TWO_PARENT_MERGE_NOT_PROVEN_EC168_DEFERRED")
    if parents[1] != pin["head_sha"] or parents[0] == parents[1]:
        raise GitEvidenceError("MERGE_HEAD_PARENT_MISMATCH")
    # Require every object whose relationship we claim to actually be present.
    _read_commit(root, parents[0], oid_length)
    _read_commit(root, pin["head_sha"], oid_length)
    _read_commit(root, pin["target_tip_sha"], oid_length)
    try:
        tree_type = _value(root, "cat-file", "-t", tree_oid)
    except GitEvidenceError:
        raise GitEvidenceError("MERGE_TARGET_TREE_UNAVAILABLE") from None
    if tree_type != b"tree":
        raise GitEvidenceError("MERGE_TARGET_TREE_UNAVAILABLE")
    if _ancestor(root, pin["target_tip_sha"], parents[0]):
        relation = "TARGET_TIP_ANCESTOR_OF_FIRST_PARENT"
    elif pin["provider"] == "github" and _ancestor(root, merge_oid, pin["target_tip_sha"]):
        relation = "MERGE_ANCESTOR_OF_OBSERVED_GITHUB_TARGET_TIP"
    else:
        raise GitEvidenceError("TARGET_HISTORY_ASSOCIATION_UNPROVEN")
    return {
        "state": "READONLY_OBJECT_TREE_AND_PARENT_GRAPH_VERIFIED",
        "merge_commit_oid": merge_oid,
        "merge_tree_oid": tree_oid,
        "merge_parent_oids": parents,
        "head_parent_matches_pin": True,
        "target_lineage_relation": relation,
        "target_tip_oid": pin["target_tip_sha"],
        "object_format": object_format,
        "git_operations": "READ_ONLY_EXACT_OID_CAT_FILE_AND_ANCESTRY",
        "scope": "OPERATOR_SELECTED_LOCAL_OBJECT_DATABASE_NOT_PROVIDER_REPOSITORY_ATTESTATION",
    }


def associate_merge_commit(
    key: source.RequestKey, *, expected_pin: Any = None,
    ec166_reconciliation: Any = None,
    local_git_repository: str | None = None,
    allow_network: bool = False, allow_local_git: bool = False,
    token_supplier: Callable[[], str | None] | None = None,
    transport: source.ReadTransport | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Proof of local graph + a matching remote merge SHA *claim*, never deployment.

    Token reading and Git commands only happen after both authorizations and
    the complete EC162/EC166 prior-evidence preflight. One metadata GET in
    this run; never automatically reuses EC165 file/diff/patch evidence.
    """
    synthetic = transport is not None
    scope = times = claim = None
    try:
        source._validate_key(key)
        if (type(allow_network) is not bool or type(allow_local_git) is not bool or
                type(timeout) not in (int, float) or not 1 <= timeout <= source.MAX_TIMEOUT_SECONDS):
            raise GateError("INVALID_ASSOCIATION_ARGUMENTS")
        if (type(local_git_repository) is not str or
                not 1 <= len(local_git_repository) <= 4096 or
                not Path(local_git_repository).is_absolute()):
            raise GateError("INVALID_TARGET_GIT_PATH")
        if not Path(local_git_repository).is_dir():
            raise GateError("TARGET_GIT_DIRECTORY_UNAVAILABLE", status="unavailable")
        pin, scope, times = _preflight(key, expected_pin, ec166_reconciliation,
                                       synthetic=synthetic)
    except source.SourceFailure as exc:
        return _result(exc.status, "UNAVAILABLE_UNKNOWN", exc.reason, exc.message, synthetic=synthetic)
    except GateError as exc:
        return _result(exc.status, "UNAVAILABLE_UNKNOWN", exc.reason,
                       "Expected pin, recent EC166 reconciliation or target Git scope is not usable.",
                       synthetic=synthetic)
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError):
        return _result("invalid_input", "UNAVAILABLE_UNKNOWN", "INVALID_PRIOR_EVIDENCE",
                       "Supplied evidence could not be checked safely.", synthetic=synthetic)
    if not allow_network or not allow_local_git:
        missing = "NETWORK_NOT_AUTHORIZED" if not allow_network else "LOCAL_GIT_NOT_AUTHORIZED"
        return _result("unavailable", "UNAVAILABLE_UNKNOWN", missing,
                       "Independent provider and local-Git read permissions are both required.",
                       synthetic=synthetic, identity_scope=scope, observations=times)
    if pin["provider_reports_merged"] is not True:
        return _result("unavailable", "UNAVAILABLE_UNKNOWN", "EC162_PROVIDER_NOT_MERGED",
                       "Previous pin does not claim a merged PR/MR; no merge commit may be inferred.",
                       synthetic=synthetic, identity_scope=scope, observations=times)

    fetched = source.fetch_proposed_pr(
        key, allow_network=True, token_supplier=token_supplier, transport=transport,
        timeout=timeout, include_merge_commit_claim=True,
    )
    if fetched["status"] != "success":
        return _result(fetched["status"], "UNAVAILABLE_UNKNOWN", fetched["reason_code"],
                       "Provider did not supply complete current merge-associated metadata.",
                       synthetic=synthetic, identity_scope=scope, observations=times)
    try:
        metadata = fetched["source"]
        current_pin = identity._new_pin(metadata)
        times["ec167_provider_observed_at_utc"] = metadata["observed_at_utc"]
        # Compare every pinned field, not only head or merge status; file-count
        # continuity is necessary but never proves a current diff snapshot.
        if current_pin != pin:
            drift = identity._compare(pin, current_pin)
            raise GateError("CURRENT_PROVIDER_IDENTITY_DRIFT_" + drift["reason_code"],
                            status="unavailable")
        prev = ec166_reconciliation["current_observation"]
        if (prev["reported_files"] != metadata["provider_reported_changed_files"] or
                prev["provider_count_quality"] != metadata["provider_change_count_quality"]):
            raise GateError("CURRENT_PROVIDER_FILE_COUNT_DRIFT", status="unavailable")
        if metadata["provider_reports_merged"] is not True:
            raise GateError("CURRENT_PROVIDER_NOT_MERGED", status="unavailable")
        merge_oid = metadata["provider_merge_commit_sha"]
        if merge_oid is None:
            raise GateError("MERGE_COMMIT_SHA_NOT_REPORTED", status="unavailable")
        if len(merge_oid) != (40 if pin["object_format"] == "sha1" else 64):
            raise GateError("MERGE_SHA_OBJECT_FORMAT_MISMATCH", status="unavailable")
        claim = {
            "source": "GITHUB_PULL_MERGE_COMMIT_SHA_CLAIM" if key.provider == "github"
                      else "GITLAB_MERGE_REQUEST_MERGE_COMMIT_SHA_CLAIM",
            "provider_origin_claim": metadata["origin"],
            "observed_at_utc": metadata["observed_at_utc"],
            "provider_reports_merged": True,
            "merge_commit_sha": merge_oid,
            "merge_sha_quality": metadata["provider_merge_sha_quality"],
            "head_commit_sha": pin["head_sha"],
            "target_tip_sha": pin["target_tip_sha"],
        }
    except GateError as exc:
        return _result(exc.status, "UNAVAILABLE_UNKNOWN", exc.reason,
                       "Fresh provider claims do not establish the pinned merge association.",
                       synthetic=synthetic, identity_scope=scope, observations=times)
    except (TypeError, KeyError, ValueError, AttributeError):
        return _result("unavailable", "UNAVAILABLE_UNKNOWN", "CURRENT_PROVIDER_METADATA_UNAVAILABLE",
                       "Fresh provider metadata could not be compared safely.",
                       synthetic=synthetic, identity_scope=scope, observations=times)
    times["local_git_observed_at_utc"] = _stamp()
    try:
        local = _local_association(local_git_repository, pin, claim["merge_commit_sha"])
    except GitEvidenceError as exc:
        return _result("unavailable", "UNAVAILABLE_UNKNOWN", exc.reason,
                       "Read-only local Git checks could not establish a two-parent tree association.",
                       synthetic=synthetic, identity_scope=scope, observations=times,
                       provider_claim=claim)
    return _result("partial", "LOCAL_MERGE_GRAPH_VERIFIED", "LOCAL_MERGE_GRAPH_AND_TREE_VERIFIED",
                   "Provider reports a merge SHA and matching pinned identity; the selected local Git graph and tree are readable, not independently tied to the Provider target project or a deployment.",
                   synthetic=synthetic, identity_scope=scope, observations=times,
                   provider_claim=claim, local_git=local)


def _read_json(path: str, byte_limit: int) -> dict[str, Any]:
    with open(path, "rb") as handle:
        raw = handle.read(byte_limit + 1)
    if len(raw) > byte_limit:
        raise ValueError("JSON input exceeds limit")
    return source._decode_object(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC167 local merge-commit association (read only, not native CES Reconcile)")
    parser.add_argument("--provider", choices=("github", "gitlab"), required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--number", type=int, required=True)
    parser.add_argument("--expected-pin", required=True, metavar="EC162_JSON")
    parser.add_argument("--ec166-reconciliation", required=True, metavar="EC166_JSON")
    parser.add_argument("--local-git", required=True, metavar="ABSOLUTE_TARGET_GIT_DIRECTORY")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--allow-local-git", action="store_true")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        prior = _read_json(args.expected_pin, identity.MAX_EXPECTED_BYTES)
        reconciled = _read_json(args.ec166_reconciliation, MAX_EC166_BYTES)
    except (ValueError, OSError, source.SourceFailure, RecursionError):
        result = _result("invalid_input", "UNAVAILABLE_UNKNOWN", "PRIOR_FILE_INVALID",
                         "Input evidence file was missing, oversized or invalid JSON.")
    else:
        result = associate_merge_commit(
            source.RequestKey(args.provider, args.repository, args.number),
            expected_pin=prior, ec166_reconciliation=reconciled,
            local_git_repository=args.local_git, allow_network=args.allow_network,
            allow_local_git=args.allow_local_git, timeout=args.timeout,
        )
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
