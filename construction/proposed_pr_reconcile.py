#!/usr/bin/env python3
"""EC-166: one independent, read-only PR/MR metadata re-observation.

Compare a validated EC162 identity pin and/or an internally consistent EC165
observation receipt against one *new* EC161 provider metadata GET. A matching
metadata pin is never a proof that earlier EC165 pages or patch text are current.

No old HTTP validators, local Git objects, cached paths or diff bodies are read
or reused. No provider file page, merge endpoint, write or native CES route.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import json
import sys
from typing import Any, Callable

import proposed_pr_identity as identity
import proposed_pr_snapshot as snapshot
import proposed_pr_source as source

SCHEMA = "ces.proposed_pr_reconcile.v1"
MAX_SNAPSHOT_BYTES = snapshot.MAX_VERIFICATION_FILE_BYTES
COUNT_QUALITIES = frozenset({
    "EXACT_PROVIDER_CLAIM", "NOT_REPORTED", "CAPPED_PROVIDER_CLAIM",
    "CAPPED_OR_UNEXPECTED_PROVIDER_CLAIM",
})


@dataclass(frozen=True)
class Baseline:
    pin: dict[str, Any]
    synthetic: bool
    source_kind: str
    observation_ref: str | None
    observation_times: tuple[str, ...]
    coverage_state: str | None
    reported_files: int | None
    count_quality: str | None


class BaselineError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _utc_timestamp(value: Any) -> bool:
    if type(value) is not str or not 19 <= len(value) <= 40:
        return False
    try:
        parsed = datetime.fromisoformat(value)
        return (parsed.tzinfo is not None and parsed.utcoffset() is not None
                and parsed.utcoffset().total_seconds() == 0)
    except (ValueError, TypeError, OverflowError):
        return False


def _read_baseline(key: source.RequestKey, expected_pin: Any,
                   prior_snapshot: Any) -> Baseline:
    if expected_pin is None and prior_snapshot is None:
        raise BaselineError("PRIOR_EVIDENCE_REQUIRED")
    pin_result = None
    if expected_pin is not None:
        try:
            pin_result = identity._validate_expected(expected_pin)
        except (KeyError, ValueError, TypeError, OverflowError):
            raise BaselineError("INVALID_EXPECTED_PIN") from None
        if pin_result is None:
            raise BaselineError("INVALID_EXPECTED_PIN")
    old_snap = None
    if prior_snapshot is not None:
        # Internal integrity only: the prior receipt is unsigned and its
        # recomputable SHA does NOT authenticate the remote provider.
        checked = snapshot.verify_receipt(prior_snapshot)
        if checked["status"] != "INTERNALLY_CONSISTENT_ONLY":
            raise BaselineError("INVALID_PRIOR_SNAPSHOT")
        try:
            material = prior_snapshot["evidence_material"]
            covered = material["path_coverage"]
            previous_times = material["observed_metadata_utc"]
            provider = material["pin"]["provider"]
            old_count = covered["reported_files"]
            count_quality = covered["provider_count_quality"]
            if (type(previous_times) is not list or len(previous_times) != 2 or
                    any(not _utc_timestamp(t) for t in previous_times) or
                    type(material["synthetic"]) is not bool or
                    covered["state"] not in ("COMPLETE", "INCOMPLETE", "UNKNOWN") or
                    count_quality not in COUNT_QUALITIES):
                raise ValueError("unsupported snapshot metadata")
            if old_count is not None and (
                    type(old_count) is not int or not 0 <= old_count <= 10_000_000):
                raise ValueError("invalid count")
            if (count_quality == "EXACT_PROVIDER_CLAIM") != (old_count is not None):
                raise ValueError("count quality disagrees with count")
            if provider == "gitlab" and old_count is not None and old_count >= 1000:
                raise ValueError("GitLab count is capped at 1000")
            if covered["state"] == "COMPLETE" and count_quality != "EXACT_PROVIDER_CLAIM":
                raise ValueError("complete coverage requires an exact count")
            old_snap = Baseline(
                pin=material["pin"], synthetic=material["synthetic"],
                source_kind="EC165_SNAPSHOT", observation_ref=prior_snapshot["observation_ref"],
                observation_times=tuple(previous_times), coverage_state=covered["state"],
                reported_files=old_count, count_quality=count_quality,
            )
        except (KeyError, ValueError, TypeError, IndexError, OverflowError):
            raise BaselineError("INVALID_PRIOR_SNAPSHOT") from None
    if pin_result is not None:
        pin, pin_synthetic = pin_result
        if old_snap is not None and (old_snap.pin != pin or old_snap.synthetic != pin_synthetic):
            raise BaselineError("PRIOR_EVIDENCE_CONFLICT")
        if old_snap is None:
            time = expected_pin.get("observed_at_utc")
            if time is not None and not _utc_timestamp(time):
                raise BaselineError("INVALID_EXPECTED_PIN_TIME")
            old_snap = Baseline(
                pin=pin, synthetic=pin_synthetic, source_kind="EC162_PIN",
                observation_ref=None, observation_times=(time,) if time else (),
                coverage_state=None, reported_files=None, count_quality=None,
            )
        else:
            old_snap = Baseline(
                pin=old_snap.pin, synthetic=old_snap.synthetic,
                source_kind="EC165_SNAPSHOT_AND_EC162_PIN",
                observation_ref=old_snap.observation_ref,
                observation_times=old_snap.observation_times,
                coverage_state=old_snap.coverage_state,
                reported_files=old_snap.reported_files,
                count_quality=old_snap.count_quality,
            )
    assert old_snap is not None
    if (old_snap.pin["provider"] != key.provider or
            old_snap.pin["repository_locator"] != key.repository or
            old_snap.pin["request_number"] != key.number):
        raise BaselineError("PRIOR_LOCATOR_MISMATCH")
    return old_snap


def _summary(prior: Baseline) -> dict[str, Any]:
    return {
        "kind": prior.source_kind,
        "pin_fingerprint": identity.fingerprint_of(prior.pin),
        "observation_ref": prior.observation_ref,
        "observed_metadata_utc": list(prior.observation_times),
        "coverage_state": prior.coverage_state,
        "reported_files": prior.reported_files,
        "provider_count_quality": prior.count_quality,
        "synthetic": prior.synthetic,
        "receipt_authenticity_verified": False,
    }


def _empty(status: str, state: str, reason: str, message: str, *,
           synthetic: bool = False, prior: dict[str, Any] | None = None,
           current: dict[str, Any] | None = None,
           comparison: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": status,
        "exit_code": {"partial": 2, "invalid_input": 4, "unavailable": 5}[status],
        "reconciliation_state": state, "reason_code": reason, "message": message,
        "prior": prior, "current_observation": current,
        "comparison": comparison if comparison is not None else {
            "pin_state": "NOT_CHECKED", "count_state": "NOT_CHECKED",
            "changed_fields": [], "changes": [],
            "prior_evidence_invalidated_by_metadata": None,
        },
        "evidence_policy": {
            "old_file_pages_reused": False,
            "old_patch_content_reused": False,
            "old_etags_used_as_remote_proof": False,
            "old_local_git_objects_used_as_remote_proof": False,
            "prior_snapshot_currentness_proven": False,
            "cross_page_atomicity_proven": False,
            "provider_immutable_diff_version_proven": False,
            "provider_actor_verified": False,
            "delivery_or_merge_proven": False,
            "write_authorized": False,
        },
        "synthetic": synthetic,
        "native_cli_action_registered": False,
        "diff_snapshot_proven": False,
        "provider_actor_verified": False,
        "delivery_or_merge_proven": False,
        "write_authorized": False,
    }


def _current_observation(key: source.RequestKey, metadata: dict[str, Any],
                         pin: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "GITHUB_PULL_METADATA_SINGLE_GET" if key.provider == "github"
        else "GITLAB_MERGE_REQUEST_METADATA_SINGLE_GET",
        "provider_origin_claim": metadata["origin"],
        "observed_at_utc": metadata["observed_at_utc"],
        "provider": key.provider, "repository_locator": key.repository,
        "request_number": key.number,
        "pin": pin,
        "pin_fingerprint": identity.fingerprint_of(pin),
        "reported_files": metadata["provider_reported_changed_files"],
        "provider_count_quality": metadata["provider_change_count_quality"],
        "raw_provider_json_disclosed": False,
        "provider_http_response_headers_disclosed": False,
        "file_pages_requested": False,
    }


def _comparison(previous: Baseline, current: dict[str, Any]) -> dict[str, Any]:
    new_pin = current["pin"]
    fields = [name for name, _ in identity.DRIFT_PRIORITY
              if previous.pin[name] != new_pin[name]]
    if previous.count_quality is None:
        count_state = "NOT_BASELINED"
    elif (previous.reported_files != current["reported_files"] or
          previous.count_quality != current["provider_count_quality"]):
        count_state = "CHANGED"
        fields.extend(name for name in ("provider_reported_changed_files",
                                        "provider_change_count_quality") if (
            (name == "provider_reported_changed_files" and
             previous.reported_files != current["reported_files"]) or
            (name == "provider_change_count_quality" and
             previous.count_quality != current["provider_count_quality"])
        ))
    elif previous.count_quality != "EXACT_PROVIDER_CLAIM":
        count_state = "INDETERMINATE"
    else:
        count_state = "MATCHED_EXACT_CLAIM"
    changes = []
    for name in fields:
        if name == "provider_reported_changed_files":
            old, now = previous.reported_files, current["reported_files"]
        elif name == "provider_change_count_quality":
            old, now = previous.count_quality, current["provider_count_quality"]
        else:
            old, now = previous.pin[name], new_pin[name]
        changes.append({"field": name, "previous": old, "current": now})
    return {
        "pin_state": "DRIFT" if any(n in identity.PIN_FIELDS for n in fields) else "MATCHED",
        "count_state": count_state,
        "changed_fields": fields, "changes": changes,
        "prior_evidence_invalidated_by_metadata": bool(fields) if count_state != "INDETERMINATE" else None,
    }


def reconcile_proposed_pr(
    key: source.RequestKey, *, expected_pin: dict[str, Any] | None = None,
    prior_snapshot: dict[str, Any] | None = None,
    allow_network: bool = False,
    token_supplier: Callable[[], str | None] | None = None,
    transport: source.ReadTransport | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Observe fresh metadata once; never assert old page/patch currentness.

    STALE_BY_DRIFT means a mandatory old claim visibly differs. An inaccessible
    proposal, indeterminate previous change count, or unavailable credential
    yields UNAVAILABLE_UNKNOWN, not a fabricated fresh claim. No success/0.
    """
    synthetic = transport is not None
    try:
        source._validate_key(key)
        if type(allow_network) is not bool or type(timeout) not in (int, float) or not 1 <= timeout <= 30:
            raise source.SourceFailure("INVALID_RECONCILE_ARGUMENTS",
                                       "Network opt-in and timeout must be valid.", "invalid_input")
        prior = _read_baseline(key, expected_pin, prior_snapshot)
    except BaselineError as exc:
        return _empty("invalid_input", "UNAVAILABLE_UNKNOWN", exc.reason,
                      "Prior evidence cannot be used as an EC162/EC165 baseline.", synthetic=synthetic)
    except source.SourceFailure as exc:
        return _empty(exc.status, "UNAVAILABLE_UNKNOWN", exc.reason, exc.message, synthetic=synthetic)
    except (ValueError, TypeError, KeyError, OverflowError, AttributeError):
        return _empty("invalid_input", "UNAVAILABLE_UNKNOWN", "PRIOR_EVIDENCE_INVALID",
                      "Prior evidence could not be safely parsed.", synthetic=synthetic)

    summary = _summary(prior)
    if prior.synthetic != synthetic:
        return _empty("unavailable", "UNAVAILABLE_UNKNOWN", "PIN_PROVENANCE_CHANGED",
                      "Previous and new observations have incompatible live/synthetic provenance.",
                      synthetic=synthetic, prior=summary)
    if not allow_network:
        return _empty("unavailable", "UNAVAILABLE_UNKNOWN", "NETWORK_NOT_AUTHORIZED",
                      "Remote metadata has not been re-read; opt in explicitly.",
                      synthetic=synthetic, prior=summary)

    fetched = source.fetch_proposed_pr(
        key, allow_network=True, token_supplier=token_supplier,
        transport=transport, timeout=timeout,
    )
    if fetched["status"] != "success":
        return _empty("unavailable", "UNAVAILABLE_UNKNOWN", fetched["reason_code"],
                      "Provider could not supply complete, accessible PR/MR identity metadata.",
                      synthetic=synthetic, prior=summary)
    try:
        metadata = fetched["source"]
        pin = identity._new_pin(metadata)
        current = _current_observation(key, metadata, pin)
        compared = _comparison(prior, current)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return _empty("unavailable", "UNAVAILABLE_UNKNOWN", "NEW_METADATA_BINDING_UNAVAILABLE",
                      "Current metadata could not be bound to a complete identity and count claim.",
                      synthetic=synthetic, prior=summary)

    if compared["changed_fields"]:
        compared["prior_evidence_invalidated_by_metadata"] = True
        return _empty("partial", "STALE_BY_DRIFT", "PRIOR_METADATA_EVIDENCE_STALE",
                      "Pinned identity, OID, state, count claim or count quality changed; old evidence is historical only.",
                      synthetic=synthetic, prior=summary, current=current, comparison=compared)
    if (compared["count_state"] == "INDETERMINATE" or
            (compared["count_state"] == "NOT_BASELINED" and
             current["provider_count_quality"] != "EXACT_PROVIDER_CLAIM")):
        return _empty("unavailable", "UNAVAILABLE_UNKNOWN", "CHANGE_COUNT_NOT_COMPARABLE",
                      "A required exact change-count comparison is unavailable; old snapshot freshness is unknown.",
                      synthetic=synthetic, prior=summary, current=current, comparison=compared)
    reason = ("IDENTITY_OBSERVATION_MATCHED_COUNT_NOT_BASELINED"
              if compared["count_state"] == "NOT_BASELINED"
              else "METADATA_MATCHED_SNAPSHOT_CONTENT_UNPROVEN")
    return _empty("partial", "FRESH_OBSERVATION", reason,
                  "New metadata matched the recorded facts; earlier pages, blobs and patches were not rechecked.",
                  synthetic=synthetic, prior=summary, current=current, comparison=compared)


def _read_bounded(path: str, limit: int) -> dict[str, Any]:
    # Refuse oversized or duplicate-key JSON; never echo untrusted path/content.
    with open(path, "rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("input too large")
    return source._decode_object(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="EC166 PR/MR remote metadata recheck (not native CES Reconcile)")
    parser.add_argument("--provider", choices=("github", "gitlab"), required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--number", required=True, type=int)
    parser.add_argument("--expected-pin", metavar="EC162_JSON")
    parser.add_argument("--prior-snapshot", metavar="EC165_JSON")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        expected = _read_bounded(args.expected_pin, identity.MAX_EXPECTED_BYTES) if args.expected_pin else None
        old = _read_bounded(args.prior_snapshot, MAX_SNAPSHOT_BYTES) if args.prior_snapshot else None
    except (OSError, ValueError, source.SourceFailure, TypeError):
        result = _empty("invalid_input", "UNAVAILABLE_UNKNOWN", "PRIOR_FILE_INVALID",
                        "A supplied baseline file was missing, oversized or invalid JSON.")
    else:
        result = reconcile_proposed_pr(
            source.RequestKey(args.provider, args.repository, args.number),
            expected_pin=expected, prior_snapshot=old,
            allow_network=args.allow_network, timeout=args.timeout,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
