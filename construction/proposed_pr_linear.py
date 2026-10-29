#!/usr/bin/env python3
"""EC168: bounded, permission-gated PR/MR squash and linear local association.

This is a standalone read-only evidence consumer, not CES native Reconcile.
Never infer squash/rebase mode from GitHub merge_commit_sha, a merged flag, or
head equality. A matching provider commit *claim* plus strict local Git facts
can establish only the stated local net-tree or ancestry association.

GitLab's effective squash_on_merge plus squash_commit_sha admits a stronger
squash *claim* check; even then local objects do not attest remote target
repository identity, remote refs, a complete rebase mapping, or deployment.
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
import proposed_pr_merge as merge
import proposed_pr_source as source

SCHEMA = "ces.proposed_pr_linear.v1"
MAX_DELTA_BYTES = 4 * 1024 * 1024
MAX_DELTA_PATHS = 4096
MAX_OBJS = 4096
RAW_META = re.compile(rb":(\d{6}) (\d{6}) ([a-f0-9]{40}|[a-f0-9]{64}) ([a-f0-9]{40}|[a-f0-9]{64}) ([ADMT])\Z")


class Unknown(merge.GitEvidenceError):
    """Expected missing/ambiguous evidence. Never expose source or Git stderr."""


def _result(status: str, state: str, reason: str, *,
            synthetic: bool = False,
            identity_scope: dict[str, Any] | None = None,
            observations: dict[str, Any] | None = None,
            provider_claim: dict[str, Any] | None = None,
            local_git: dict[str, Any] | None = None,
            candidate_kind: str = "UNKNOWN") -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": status,
        "exit_code": {"partial": 2, "invalid_input": 4, "unavailable": 5}[status],
        "association_state": state,
        "candidate_kind": candidate_kind,
        "reason_code": reason,
        "message": (
            "Local Git graph/tree association and a scoped Provider commit claim were matched; "
            "the Provider target repository/ref, actual merge method and deployment are not attested."
            if status == "partial" else
            "Evidence is invalid or insufficient to establish a local PR/MR change association."
        ),
        "identity_scope": identity_scope,
        "observations": observations,
        "provider_claim": provider_claim,
        "local_git": local_git if local_git is not None else {"state": "NOT_VERIFIED"},
        "evidence_policy": {
            "network_by_default": "DENIED",
            "local_git_read_by_default": "DENIED",
            "provider_actor_verified": False,
            "provider_commit_claim_authenticated_independently": False,
            "local_objects_prove_provider_target_membership": False,
            "squash_historical_method_authenticated": False,
            "rebase_commit_mapping_complete": False,
            "remote_target_ref_observed_atomically": False,
            "provider_delivery_proven": False,
            "deployment_proven": False,
            "release_proven": False,
            "provider_write_performed": False,
            "git_fetch_checkout_ref_index_or_worktree_write": False,
            "native_cli_action_registered": False,
        },
        "synthetic": synthetic,
        "local_association_verified": status == "partial",
        "local_merge_graph_verified": state == "LOCAL_MERGE_GRAPH_VERIFIED",
        "delivery_or_merge_proven": False,
        "target_repository_membership_authenticated": False,
        "provider_actor_verified": False,
        "native_cli_action_registered": False,
        "write_authorized": False,
    }


def _git_checked_tree(root: Path, oid: str, oid_len: int) -> tuple[str, list[str]]:
    tree, parents = merge._read_commit(root, oid, oid_len)
    if merge._value(root, "cat-file", "-t", tree) != b"tree":
        raise Unknown("LOCAL_COMMIT_TREE_NOT_PRESENT")
    return tree, parents


def _merge_base_one(root: Path, left: str, right: str, oid_len: int) -> str:
    cp = merge._git(root, "merge-base", "--all", left, right)
    if cp.returncode != 0 or len(cp.stdout) > 256:
        raise Unknown("SOURCE_MERGE_BASE_UNAVAILABLE")
    lines = cp.stdout.splitlines()
    if len(lines) != 1 or not merge.GIT_OID.fullmatch(lines[0]) or len(lines[0]) != oid_len:
        raise Unknown("SOURCE_MERGE_BASE_AMBIGUOUS")
    return lines[0].decode("ascii")


def _raw_delta(root: Path, older_tree: str, newer_tree: str, oid_len: int) -> dict[bytes, tuple[bytes, bytes]]:
    """Return exact per-path resulting Git mode/OID for net tree differences.

    No patch-id heuristics, file-name disclosures, regex replacement or
    rename inference. Paths remain opaque byte strings and never leave here.
    Reject submodule gitlinks and over-budget or ambiguous diff records.
    """
    cp = merge._git(root, "diff-tree", "-r", "--raw", "-z", "--no-abbrev",
                    "--no-renames", "--no-ext-diff", "--no-textconv",
                    older_tree, newer_tree)
    if cp.returncode != 0 or len(cp.stdout) > MAX_DELTA_BYTES:
        raise Unknown("LOCAL_TREE_DELTA_UNAVAILABLE_OR_TOO_LARGE")
    if not cp.stdout:
        return {}
    parts = cp.stdout.split(b"\0")
    if parts[-1] != b"" or len(parts) % 2 != 1:
        raise Unknown("LOCAL_TREE_DELTA_MALFORMED")
    changed: dict[bytes, tuple[bytes, bytes]] = {}
    for idx in range(0, len(parts) - 1, 2):
        info = RAW_META.fullmatch(parts[idx])
        filename = parts[idx + 1]
        if (info is None or not filename or filename in changed or
                len(info[3]) != oid_len or len(info[4]) != oid_len or
                len(changed) >= MAX_DELTA_PATHS):
            raise Unknown("LOCAL_TREE_DELTA_MALFORMED_OR_TOO_LARGE")
        old_mode, new_mode, old_oid, new_oid, status = info.groups()
        if b"160000" in (old_mode, new_mode):
            # A gitlink's referenced commit is external to this object store.
            raise Unknown("SUBMODULE_CONTENT_EQUIVALENCE_UNPROVEN")
        if status == b"D" and (new_mode != b"000000" or any(ch != 48 for ch in new_oid)):
            raise Unknown("LOCAL_TREE_DELTA_MALFORMED")
        if status != b"D" and (new_mode not in (b"100644", b"100755", b"120000") or
                                  not any(ch != 48 for ch in new_oid)):
            raise Unknown("LOCAL_TREE_DELTA_MALFORMED")
        changed[filename] = (new_mode, new_oid)
    return changed


def _new_blobs_present(root: Path, *deltas: dict[bytes, tuple[bytes, bytes]]) -> None:
    """Require actual local blob objects for every changed *new* OID."""
    oids = sorted({oid for delta in deltas for mode, oid in delta.values()
                   if mode != b"000000"})
    if len(oids) > MAX_OBJS:
        raise Unknown("LOCAL_CHANGE_BLOB_BUDGET_EXCEEDED")
    if not oids:
        return
    try:
        cp = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(root),
             "cat-file", "--batch-check=%(objectname) %(objecttype)"],
            input=b"\n".join(oids) + b"\n", stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=identity._git_environment(),
            timeout=merge.GIT_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise Unknown("LOCAL_CHANGE_BLOBS_UNAVAILABLE") from None
    expected = [oid + b" blob" for oid in oids]
    if cp.returncode != 0 or cp.stdout.splitlines() != expected:
        raise Unknown("LOCAL_CHANGE_BLOBS_UNAVAILABLE")


def _source_base(root: Path, pin: dict[str, Any], target_parent: str,
                 oid_len: int) -> str:
    """Use GL's pinned diff merge-base or a unique local GH source merge-base.

    GH's base SHA may already point *after* a merge; treating it as the
    original branch-off commits would silently change source scope.
    """
    base = _merge_base_one(root, pin["head_sha"], target_parent, oid_len)
    if pin["provider"] == "gitlab":
        # Diff refs describe one exact proposal version, not arbitrary tips.
        # Tie both its pinned start SHA and the squash's actual parent to the
        # SAME pinned merge-base, even when the squash was created on a
        # staging branch and later merged through a two-parent commit.
        start_base = _merge_base_one(root, pin["head_sha"], pin["target_tip_sha"], oid_len)
        if base != pin["base_sha"] or start_base != pin["base_sha"]:
            raise Unknown("GITLAB_PINNED_DIFF_BASE_MISMATCH")
    return base


def _net_delta_match(root: Path, pin: dict[str, Any], target_parent: str,
                     output_commit: str, oid_len: int) -> dict[str, Any]:
    original_base = _source_base(root, pin, target_parent, oid_len)
    base_tree, _ = _git_checked_tree(root, original_base, oid_len)
    source_tree, _ = _git_checked_tree(root, pin["head_sha"], oid_len)
    target_tree, _ = _git_checked_tree(root, target_parent, oid_len)
    out_tree, parents = _git_checked_tree(root, output_commit, oid_len)
    if len(parents) != 1 or parents[0] != target_parent:
        raise Unknown("LINEAR_COMMIT_PARENT_MISMATCH")
    original = _raw_delta(root, base_tree, source_tree, oid_len)
    applied = _raw_delta(root, target_tree, out_tree, oid_len)
    if not original:
        raise Unknown("SOURCE_NET_DELTA_EMPTY")
    if original != applied:
        raise Unknown("SOURCE_TO_TARGET_NET_BLOB_DELTA_MISMATCH")
    _new_blobs_present(root, original, applied)
    return {
        "source_base_oid": original_base,
        "source_head_oid": pin["head_sha"],
        "source_head_tree_oid": source_tree,
        "target_parent_oid": target_parent,
        "target_parent_tree_oid": target_tree,
        "candidate_commit_oid": output_commit,
        "candidate_tree_oid": out_tree,
        "source_net_changed_paths": len(original),
        "applied_net_changed_paths": len(applied),
        "net_result_mode_and_blob_oids_exactly_equal": True,
        "changed_new_blob_objects_present": True,
        "source_scope": "PINNED_GITLAB_DIFF_MERGE_BASE" if pin["provider"] == "gitlab"
                        else "UNIQUE_LOCAL_MERGE_BASE_NOT_A_PROVIDER_SOURCE_COMMIT_LIST",
    }


def _target_lineage(root: Path, pin: dict[str, Any], output_oid: str,
                    target_parent: str) -> str:
    tip = pin["target_tip_sha"]
    _git_checked_tree(root, tip, 40 if pin["object_format"] == "sha1" else 64)
    if merge._ancestor(root, tip, target_parent):
        return "PINNED_TARGET_TIP_ANCESTOR_OF_CANDIDATE_PARENT"
    if pin["provider"] == "github" and merge._ancestor(root, output_oid, tip):
        return "CANDIDATE_ANCESTOR_OF_OBSERVED_LATER_GITHUB_TARGET_TIP"
    raise Unknown("TARGET_HISTORY_ASSOCIATION_UNPROVEN")


def _squash(root: Path, pin: dict[str, Any], squash_oid: str,
            merge_oid: str | None, oid_len: int) -> dict[str, Any]:
    squash_tree, parents = _git_checked_tree(root, squash_oid, oid_len)
    if len(parents) != 1:
        raise Unknown("SQUASH_COMMIT_NOT_SINGLE_PARENT")
    squash_parent = parents[0]
    # Independently verify exact source->squash net result, using one
    # immutable GL diff_refs version. It may be on a staging source branch.
    delta = _net_delta_match(root, pin, squash_parent, squash_oid, oid_len)
    witness: dict[str, Any] = {
        "state": "READONLY_GITLAB_SQUASH_COMMIT_AND_NET_TREE_VERIFIED",
        **delta,
        "squash_commit_oid": squash_oid,
        "squash_tree_oid": squash_tree,
        "merge_commit_oid": merge_oid,
        "merge_witness": "NONE_REQUIRED_IF_LINEAR_SQUASH_REPORTED",
    }
    if merge_oid is None or merge_oid == squash_oid:
        witness["target_lineage_relation"] = _target_lineage(root, pin, squash_oid, squash_parent)
        return witness
    # Some GL strategies create a separate two-parent merge commit after
    # creating a squash commit. Do not assume it incorporated the squash:
    # require it as the actual second parent and the same exact net blob delta
    # between the merge's first parent and its resulting tree.
    merge_tree, mp = _git_checked_tree(root, merge_oid, oid_len)
    if len(mp) != 2 or mp[1] != squash_oid or mp[0] == mp[1]:
        raise Unknown("SEPARATE_MERGE_DOES_NOT_NAME_SQUASH_PARENT")
    if not merge._ancestor(root, pin["target_tip_sha"], mp[0]):
        raise Unknown("SEPARATE_MERGE_TARGET_LINEAGE_UNPROVEN")
    if not merge._ancestor(root, squash_parent, mp[0]):
        raise Unknown("SEPARATE_MERGE_SQUASH_BASE_UNRELATED")
    first_tree, _ = _git_checked_tree(root, mp[0], oid_len)
    # The merger may resolve conflicts or incorporate independent changes:
    # such cases must not silently become exact tree equivalence.
    out_delta = _raw_delta(root, first_tree, merge_tree, oid_len)
    source_base, _ = _git_checked_tree(root, delta["source_base_oid"], oid_len)
    source_head, _ = _git_checked_tree(root, pin["head_sha"], oid_len)
    src_delta = _raw_delta(root, source_base, source_head, oid_len)
    if out_delta != src_delta:
        raise Unknown("SEPARATE_MERGE_TREE_DELTA_NOT_EQUAL_TO_SOURCE")
    _new_blobs_present(root, out_delta)
    witness.update({
        "merge_tree_oid": merge_tree,
        "merge_parent_oids": mp,
        "merge_witness": "TWO_PARENT_SECOND_IS_SQUASH_SHA_AND_FINAL_TREE_NET_DELTA_MATCHES",
        "target_lineage_relation": "PINNED_TARGET_TIP_ANCESTOR_OF_FINAL_MERGE_FIRST_PARENT",
    })
    return witness


def _exact_head_on_target(root: Path, pin: dict[str, Any],
                          oid_len: int) -> dict[str, Any]:
    tip = pin["target_tip_sha"]
    head = pin["head_sha"]
    head_tree, head_parents = _git_checked_tree(root, head, oid_len)
    tip_tree, _ = _git_checked_tree(root, tip, oid_len)
    if tip == head:
        raise Unknown("SOURCE_HEAD_EQUALS_TARGET_NO_CHANGE_WITNESS")
    if merge._ancestor(root, tip, head):
        relation = "TARGET_TIP_ANCESTOR_OF_EXACT_SOURCE_HEAD"
    elif pin["provider"] == "github" and merge._ancestor(root, head, tip):
        relation = "EXACT_SOURCE_HEAD_ANCESTOR_OF_LATER_GITHUB_TARGET_TIP"
    else:
        raise Unknown("EXACT_HEAD_TARGET_ANCESTRY_UNPROVEN")
    if not head_parents:
        raise Unknown("SOURCE_HEAD_HAS_NO_PARENT")
    if pin["provider"] == "gitlab":
        base = _merge_base_one(root, pin["head_sha"], tip, oid_len)
        if base != pin["base_sha"]:
            raise Unknown("GITLAB_PINNED_DIFF_BASE_MISMATCH")
        if not merge._ancestor(root, pin["base_sha"], head):
            raise Unknown("GITLAB_SOURCE_BASE_UNRELATED")
    else:
        base = _merge_base_one(root, head, tip, oid_len)
    _git_checked_tree(root, base, oid_len)
    if base == head:
        raise Unknown("SOURCE_NET_SCOPE_EMPTY")
    return {
        "state": "READONLY_EXACT_HEAD_TARGET_ANCESTRY_AND_TREE_VERIFIED",
        "head_commit_oid": head, "head_tree_oid": head_tree,
        "target_tip_oid": tip, "target_tip_tree_oid": tip_tree,
        "source_base_oid": base,
        "target_lineage_relation": relation,
        "oid_identity_instead_of_rebase_mapping": True,
        "all_rebase_replacement_commits_mapped": False,
    }


def _local_analyze(path: str, pin: dict[str, Any], claim: dict[str, Any]) -> tuple[str, str, str, dict[str, Any]]:
    root, _, oid_len = merge._local_git_scope(path, pin)
    merge_oid = claim["merge_commit_sha"]
    squash_oid = claim["squash_commit_sha"]
    squash_policy = claim["squash_on_merge"]
    provider = pin["provider"]
    # An effective GitLab policy alone is not a proof of a completed squash;
    # the squash SHA must be a complete distinct provider commit identity.
    if provider == "gitlab" and squash_policy is True:
        if not squash_oid:
            raise Unknown("GITLAB_SQUASH_COMMIT_CLAIM_MISSING")
        return ("LOCAL_GITLAB_SQUASH_TREE_VERIFIED", "GITLAB_SQUASH_COMMIT_AND_NET_TREES_MATCHED",
                "GITLAB_EXPLICIT_SQUASH_CLAIM", _squash(root, pin, squash_oid, merge_oid, oid_len))
    if provider == "gitlab" and squash_oid:
        # False/missing effective policy but a squash oid is contradictory or
        # insufficient context, not permission to infer a completed method.
        raise Unknown("GITLAB_SQUASH_POLICY_AND_SHA_INCONSISTENT")
    if not merge_oid:
        raise Unknown("MERGE_COMMIT_SHA_NOT_REPORTED")
    merge_tree, merge_parents = _git_checked_tree(root, merge_oid, oid_len)
    if len(merge_parents) == 2:
        # Preserve EC167's strict second-parent=head and target lineage path.
        local = merge._local_association(path, pin, merge_oid)
        return "LOCAL_MERGE_GRAPH_VERIFIED", "EC167_TWO_PARENT_MERGE_GRAPH_VERIFIED", "TWO_PARENT_MERGE", local
    if len(merge_parents) != 1:
        raise Unknown("LINEAR_CANDIDATE_PARENT_COUNT_UNSUPPORTED")
    if merge_oid == pin["head_sha"]:
        # Equal OIDs alone never suffice: verify pinned target graph, source
        # base, tree objects and actual ancestry before returning a partial.
        exact = _exact_head_on_target(root, pin, oid_len)
        return ("LOCAL_EXACT_HEAD_GRAPH_VERIFIED_METHOD_UNKNOWN",
                "PROVIDER_CLAIMED_SHA_EQUALS_LOCAL_HEAD_AND_TARGET_ANCESTRY",
                "EXACT_SHA_FAST_FORWARD_OR_INDIRECT_CANDIDATE", exact)
    if provider == "gitlab":
        # No MR field proves a historical rebase/FF method or maps every
        # original source commit to rewritten target commits. Fail closed.
        raise Unknown("GITLAB_REBASE_OR_FAST_FORWARD_MAPPING_NOT_ATTESTED")
    # GH may report the squash commit OR the *last* commit of a rebase.
    # The local single-commit net tree can be compared, but the historical
    # merge method and a one-to-one rebase map must remain unclassified.
    parent = merge_parents[0]
    relation = _target_lineage(root, pin, merge_oid, parent)
    delta = _net_delta_match(root, pin, parent, merge_oid, oid_len)
    return ("LOCAL_SINGLE_COMMIT_NET_TREE_VERIFIED_METHOD_UNKNOWN",
            "GITHUB_PROVIDER_LINKED_SINGLE_COMMIT_NET_TREE_EQUIVALENCE",
            "GITHUB_SINGLE_COMMIT_SQUASH_OR_REBASE_UNCLASSIFIED",
            {"state": "READONLY_PROVIDER_LINKED_NET_TREE_VERIFIED", **delta,
             "target_lineage_relation": relation, "candidate_tree_oid": merge_tree,
             "historical_merge_method": "UNKNOWN", "rebase_commit_map": "NOT_ATTESTED"})


def associate_linear_change(
    key: source.RequestKey, *, expected_pin: Any = None,
    ec166_reconciliation: Any = None, local_git_repository: str | None = None,
    allow_network: bool = False, allow_local_git: bool = False,
    token_supplier: Callable[[], str | None] | None = None,
    transport: source.ReadTransport | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """One new scoped provider metadata GET; local Git reads only if allowed."""
    synthetic = transport is not None
    scope: dict[str, Any] | None = None
    times: dict[str, Any] | None = None
    claim: dict[str, Any] | None = None
    try:
        source._validate_key(key)
        if (type(allow_network) is not bool or type(allow_local_git) is not bool or
                type(timeout) not in (float, int) or
                not 1 <= timeout <= source.MAX_TIMEOUT_SECONDS):
            raise merge.GateError("INVALID_ASSOCIATION_ARGUMENTS")
        if (type(local_git_repository) is not str or
                not 1 <= len(local_git_repository) <= 4096 or
                not Path(local_git_repository).is_absolute()):
            raise merge.GateError("INVALID_TARGET_GIT_PATH")
        if not Path(local_git_repository).is_dir():
            raise merge.GateError("TARGET_GIT_DIRECTORY_UNAVAILABLE", status="unavailable")
        pin, scope, times = merge._preflight(key, expected_pin, ec166_reconciliation,
                                             synthetic=synthetic)
    except source.SourceFailure as exc:
        return _result(exc.status, "UNAVAILABLE_UNKNOWN", exc.reason, synthetic=synthetic)
    except merge.GateError as exc:
        return _result(exc.status, "UNAVAILABLE_UNKNOWN", exc.reason, synthetic=synthetic)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return _result("invalid_input", "UNAVAILABLE_UNKNOWN", "INVALID_PRIOR_EVIDENCE", synthetic=synthetic)
    if not allow_network or not allow_local_git:
        return _result("unavailable", "UNAVAILABLE_UNKNOWN",
                       "NETWORK_NOT_AUTHORIZED" if not allow_network else "LOCAL_GIT_NOT_AUTHORIZED",
                       synthetic=synthetic, identity_scope=scope, observations=times)
    if pin["provider_reports_merged"] is not True:
        return _result("unavailable", "UNAVAILABLE_UNKNOWN", "EC162_PROVIDER_NOT_MERGED",
                       synthetic=synthetic, identity_scope=scope, observations=times)
    fetched = source.fetch_proposed_pr(
        key, allow_network=True, token_supplier=token_supplier,
        transport=transport, timeout=timeout,
        include_merge_commit_claim=True, include_squash_claim=True,
    )
    if fetched["status"] != "success":
        return _result(fetched["status"], "UNAVAILABLE_UNKNOWN", fetched["reason_code"],
                       synthetic=synthetic, identity_scope=scope, observations=times)
    try:
        metadata = fetched["source"]
        assert times is not None
        times["ec168_provider_observed_at_utc"] = metadata["observed_at_utc"]
        current_pin = identity._new_pin(metadata)
        if current_pin != pin:
            drift = identity._compare(pin, current_pin)
            raise merge.GateError("CURRENT_PROVIDER_IDENTITY_DRIFT_" + drift["reason_code"],
                                  status="unavailable")
        prev = ec166_reconciliation["current_observation"]
        if (prev["reported_files"] != metadata["provider_reported_changed_files"] or
                prev["provider_count_quality"] != metadata["provider_change_count_quality"]):
            raise merge.GateError("CURRENT_PROVIDER_FILE_COUNT_DRIFT", status="unavailable")
        if metadata["provider_reports_merged"] is not True:
            raise merge.GateError("CURRENT_PROVIDER_NOT_MERGED", status="unavailable")
        merge_oid = metadata["provider_merge_commit_sha"]
        squash_oid = metadata["provider_squash_commit_sha"]
        required_len = 40 if pin["object_format"] == "sha1" else 64
        if any(oid is not None and len(oid) != required_len for oid in (merge_oid, squash_oid)):
            raise merge.GateError("PROVIDER_CLAIM_OBJECT_FORMAT_MISMATCH", status="unavailable")
        claim = {
            "provider_origin_claim": metadata["origin"],
            "observed_at_utc": metadata["observed_at_utc"],
            "provider_reports_merged": True,
            "merge_commit_sha": merge_oid,
            "squash_commit_sha": squash_oid,
            "squash_on_merge": metadata["provider_squash_on_merge"],
            "squash_evidence_quality": metadata["provider_squash_evidence_quality"],
            "merge_method_claim": metadata["provider_merge_method_claim"],
            "pinned_head_commit_sha": pin["head_sha"],
            "pinned_target_tip_sha": pin["target_tip_sha"],
        }
    except merge.GateError as exc:
        return _result(exc.status, "UNAVAILABLE_UNKNOWN", exc.reason, synthetic=synthetic,
                       identity_scope=scope, observations=times)
    except (ValueError, KeyError, TypeError, AttributeError):
        return _result("unavailable", "UNAVAILABLE_UNKNOWN", "CURRENT_PROVIDER_METADATA_UNAVAILABLE",
                       synthetic=synthetic, identity_scope=scope, observations=times)
    times["local_git_observed_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        state, reason, kind, local = _local_analyze(local_git_repository, pin, claim)
        return _result("partial", state, reason, synthetic=synthetic, candidate_kind=kind,
                       identity_scope=scope, observations=times,
                       provider_claim=claim, local_git=local)
    except (merge.GitEvidenceError, Unknown) as exc:
        return _result("unavailable", "UNAVAILABLE_UNKNOWN", exc.reason,
                       synthetic=synthetic, identity_scope=scope, observations=times,
                       provider_claim=claim)
    except (ValueError, KeyError, TypeError, OSError, UnicodeError):
        return _result("unavailable", "UNAVAILABLE_UNKNOWN", "LOCAL_ASSOCIATION_UNAVAILABLE",
                       synthetic=synthetic, identity_scope=scope, observations=times,
                       provider_claim=claim)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC168 read-only squash/linear PR/MR evidence (not native CES Reconcile)")
    parser.add_argument("--provider", choices=("github", "gitlab"), required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--number", type=int, required=True)
    parser.add_argument("--expected-pin", required=True, metavar="EC162_JSON")
    parser.add_argument("--ec166-reconciliation", required=True, metavar="EC166_JSON")
    parser.add_argument("--local-git", required=True, metavar="ABSOLUTE_TARGET_GIT_ROOT")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--allow-local-git", action="store_true")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        pin = merge._read_json(args.expected_pin, identity.MAX_EXPECTED_BYTES)
        prior = merge._read_json(args.ec166_reconciliation, merge.MAX_EC166_BYTES)
    except (OSError, ValueError, source.SourceFailure, RecursionError):
        result = _result("invalid_input", "UNAVAILABLE_UNKNOWN", "PRIOR_FILE_INVALID")
    else:
        result = associate_linear_change(
            source.RequestKey(args.provider, args.repository, args.number),
            expected_pin=pin, ec166_reconciliation=prior,
            local_git_repository=args.local_git,
            allow_network=args.allow_network, allow_local_git=args.allow_local_git,
            timeout=args.timeout,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
