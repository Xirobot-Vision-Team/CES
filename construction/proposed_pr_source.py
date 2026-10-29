#!/usr/bin/env python3
"""EC-161: opt-in, read-only GitHub PR / GitLab MR metadata source.

This independent source adapter is NOT the CES PowerShell Collect:ProposedPR
Action. It collects one narrowly-scoped provider metadata object, never a patch,
file listing, checkout, actor attestation, or stable diff identity. Nothing is
persisted. No network occurs unless explicitly enabled by the caller.

Examples:
  python construction/proposed_pr_source.py --provider github \
      --repository owner/repo --number 12
  CES_GITHUB_TOKEN=<set out of band> python construction/proposed_pr_source.py \
      --provider github --repository owner/repo --number 12 --allow-network
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
import re
import socket
import ssl
import sys
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

SCHEMA = "ces.proposed_pr_source.v1"
MAX_BODY_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 8.0
MAX_TIMEOUT_SECONDS = 30.0
SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\Z", re.ASCII)
SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z", re.ASCII)
TOKEN = re.compile(r"[!-~]{1,4096}\Z", re.ASCII)
ENVIRONMENT_KEYS = {"github": "CES_GITHUB_TOKEN", "gitlab": "CES_GITLAB_TOKEN"}


@dataclass(frozen=True)
class RequestKey:
    provider: str
    repository: str
    number: int


class SourceFailure(Exception):
    """Only fixed, nonsecret public diagnostics should be returned to callers."""

    def __init__(self, reason: str, message: str, status: str = "unavailable") -> None:
        super().__init__(reason)
        self.reason = reason
        self.message = message
        self.status = status


class ReadTransport(Protocol):
    def get_object(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]: ...


class _DenyRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def _decode_object(blob: bytes) -> dict[str, Any]:
    """Reject duplicate JSON keys, constants, invalid UTF-8 and root arrays."""
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def no_constant(_: str) -> None:
        raise ValueError("non-finite numeric value")

    try:
        data = json.loads(blob.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=no_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise SourceFailure("PROVIDER_PAYLOAD_INVALID", "Provider returned invalid JSON metadata.") from None
    if not isinstance(data, dict):
        raise SourceFailure("PROVIDER_PAYLOAD_INVALID", "Provider metadata root must be an object.")
    return data


class StrictHttpsTransport:
    """Single GET; no redirects, env proxy, cookies, retry or secondary URL."""

    def get_object(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        # The caller constructs URLs solely from fixed HTTPS provider hosts and
        # strictly validated path components. Never accept a user-supplied URL.
        if not (url.startswith("https://api.github.com/") or
                url.startswith("https://gitlab.com/api/v4/")):
            raise SourceFailure("PROVIDER_ENDPOINT_REJECTED", "Endpoint is not an approved provider API.")
        request = Request(url, headers=headers, method="GET")
        opener = build_opener(ProxyHandler({}), _DenyRedirect(),
                              HTTPSHandler(context=ssl.create_default_context()))
        try:
            with opener.open(request, timeout=timeout) as response:
                if response.geturl() != url or response.status != 200:
                    raise SourceFailure("PROVIDER_ENDPOINT_REJECTED", "Provider response did not match the requested endpoint.")
                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                if content_type != "application/json" and not (
                    content_type.startswith("application/") and content_type.endswith("+json")
                ):
                    raise SourceFailure("PROVIDER_PAYLOAD_INVALID", "Provider response was not JSON.")
                claimed = response.headers.get("Content-Length")
                if claimed and claimed.isdecimal() and int(claimed) > MAX_BODY_BYTES:
                    raise SourceFailure("PROVIDER_PAYLOAD_TOO_LARGE", "Provider metadata exceeded the byte budget.")
                raw = response.read(MAX_BODY_BYTES + 1)
                if len(raw) > MAX_BODY_BYTES:
                    raise SourceFailure("PROVIDER_PAYLOAD_TOO_LARGE", "Provider metadata exceeded the byte budget.")
                return _decode_object(raw)
        except HTTPError as exc:
            # Never print raw error bodies, redirect Locations, URLs or headers:
            # they may contain secrets or resource names.
            if 300 <= exc.code < 400:
                raise SourceFailure("PROVIDER_REDIRECT_REFUSED", "Provider redirected a credentialed read; refused.") from None
            if exc.code in (401, 403):
                raise SourceFailure("PROVIDER_AUTH_UNAVAILABLE", "Provider denied access; credentials or permissions may be insufficient.") from None
            if exc.code == 404:
                raise SourceFailure("PROVIDER_OBJECT_NOT_ACCESSIBLE", "PR/MR is missing or not accessible; existence cannot be inferred.") from None
            if exc.code == 429:
                raise SourceFailure("PROVIDER_RATE_LIMITED", "Provider rate limit prevents this read.") from None
            if exc.code in (408, 425) or 500 <= exc.code < 600:
                raise SourceFailure("PROVIDER_UNAVAILABLE", "Provider did not supply an available response.") from None
            raise SourceFailure("PROVIDER_HTTP_UNAVAILABLE", "Provider rejected the metadata read.") from None
        except (URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError):
            raise SourceFailure("PROVIDER_NETWORK_UNAVAILABLE", "HTTPS provider metadata could not be reached or verified.") from None


def _validate_key(key: RequestKey) -> RequestKey:
    if not isinstance(key.provider, str) or key.provider not in ENVIRONMENT_KEYS:
        raise SourceFailure("INVALID_PROVIDER", "Supported providers are github and gitlab.", "invalid_input")
    if not isinstance(key.repository, str) or len(key.repository) > 240:
        raise SourceFailure("INVALID_REPOSITORY", "Repository must be a bounded provider path, not a URL.", "invalid_input")
    parts = key.repository.split("/")
    if (len(parts) != 2 if key.provider == "github" else not 2 <= len(parts) <= 12) or any(
        part in (".", "..") or len(part) > 100 or not SEGMENT.fullmatch(part) for part in parts
    ):
        raise SourceFailure("INVALID_REPOSITORY", "Repository must be a bounded provider path, not a URL.", "invalid_input")
    if type(key.number) is not int or not 1 <= key.number <= 2147483647:
        raise SourceFailure("INVALID_PR_NUMBER", "PR/MR number must be a positive integer.", "invalid_input")
    return key


def _endpoint(key: RequestKey) -> str:
    if key.provider == "github":
        owner, repo = key.repository.split("/")
        return f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/pulls/{key.number}"
    return f"https://gitlab.com/api/v4/projects/{quote(key.repository, safe='')}/merge_requests/{key.number}"


def _headers(provider: str, token: str) -> dict[str, str]:
    common = {"Accept-Encoding": "identity", "User-Agent": "CES-EC161-readonly-source/1"}
    if provider == "github":
        return {**common, "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10", "Authorization": "Bearer " + token}
    return {**common, "Accept": "application/json", "PRIVATE-TOKEN": token}


def _positive_id(value: Any) -> bool:
    return type(value) is int and 0 < value <= 2**63 - 1


def _commit_sha(value: Any) -> str | None:
    if isinstance(value, str) and SHA.fullmatch(value) and any(c != "0" for c in value):
        return value.lower()
    return None


def _incomplete() -> SourceFailure:
    return SourceFailure("PROVIDER_METADATA_INCOMPLETE", "Provider metadata lacks an essential PR/MR field or full commit SHA.")


def _reported_change_count(data: dict[str, Any], provider: str) -> tuple[int | None, str]:
    """Only counts advertised by the metadata endpoint; never infer from diffs.

    GitLab's "1000+" means the actual total is unknown, and an empty value
    means the asynchronous calculation has not completed yet.
    """
    field = "changed_files" if provider == "github" else "changes_count"
    value = data.get(field)
    if value is None or (provider == "gitlab" and value == ""):
        return None, "NOT_REPORTED"
    if provider == "github":
        if type(value) is not int or not 0 <= value <= 10_000_000:
            raise _incomplete()
        return value, "EXACT_PROVIDER_CLAIM"
    if value == "1000+":
        return None, "CAPPED_PROVIDER_CLAIM"
    if (type(value) is not str or not value.isascii() or
            not value.isdecimal() or len(value) > 8 or
            (len(value) > 1 and value[0] == "0")):
        raise _incomplete()
    count = int(value)
    if count >= 1000:
        # GitLab documents a 1000+ sentinel and an asynchronously-populated
        # string. We do not turn a surprising un-capped value into proof.
        return None, "CAPPED_OR_UNEXPECTED_PROVIDER_CLAIM"
    return count, "EXACT_PROVIDER_CLAIM"


def _proposal_from_github(data: dict[str, Any], key: RequestKey) -> dict[str, Any]:
    if data.get("number") != key.number or type(data.get("number")) is not int:
        raise SourceFailure("PROVIDER_SOURCE_MISMATCH", "Provider PR number differs from the requested number.")
    if not _positive_id(data.get("id")):
        raise _incomplete()
    base, head = data.get("base"), data.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise _incomplete()
    repo = base.get("repo")
    if not isinstance(repo, dict) or not _positive_id(repo.get("id")) or not isinstance(repo.get("full_name"), str):
        raise _incomplete()
    if repo["full_name"].casefold() != key.repository.casefold():
        raise SourceFailure("PROVIDER_SOURCE_MISMATCH", "Provider base repository differs from the requested repository.")
    # EC-162: a branch name or PR number is never a replacement for the
    # provider's repository/object IDs. A deleted fork may have head.repo=null:
    # fail closed instead of inventing an identity from head.ref.
    head_repo = head.get("repo")
    if not isinstance(head_repo, dict) or not _positive_id(head_repo.get("id")):
        raise _incomplete()
    head_full_name = head_repo.get("full_name")
    if not isinstance(head_full_name, str) or len(head_full_name) > 240:
        raise _incomplete()
    name_parts = head_full_name.split("/")
    if len(name_parts) != 2 or any(
        p in (".", "..") or not 1 <= len(p) <= 100 or not SEGMENT.fullmatch(p)
        for p in name_parts
    ):
        raise _incomplete()
    # A single repository cannot simultaneously have two stable provider IDs,
    # nor can one stable repo ID have two different full names in the same PR
    # response. This flags transient transfer/rename mixtures rather than
    # silently treating them as a valid fork relationship.
    same_repo_id = head_repo["id"] == repo["id"]
    same_repo_path = head_full_name.casefold() == repo["full_name"].casefold()
    if same_repo_id != same_repo_path:
        raise SourceFailure("PROVIDER_METADATA_INCONSISTENT", "Provider repository ID and path relationship disagree.")
    base_sha, head_sha = _commit_sha(base.get("sha")), _commit_sha(head.get("sha"))
    if not base_sha or not head_sha or len(base_sha) != len(head_sha):
        raise _incomplete()
    state = data.get("state")
    if state not in ("open", "closed") or type(data.get("merged")) is not bool:
        raise _incomplete()
    if data["merged"] and state != "closed":
        raise SourceFailure("PROVIDER_METADATA_INCONSISTENT", "Provider reported an impossible open-and-merged PR state.")
    reported_count, count_quality = _reported_change_count(data, "github")
    return {
        "provider_object_id": str(data["id"]),
        "provider_reported_changed_files": reported_count,
        "provider_change_count_quality": count_quality,
        "provider_repository_id": str(repo["id"]),
        "provider_source_repository_id": str(head_repo["id"]),
        "provider_source_repository_path": head_full_name,
        "provider_state": state,
        "provider_reports_merged": data["merged"],
        "base": {"sha": base_sha, "meaning": "base_branch_tip_at_provider_observation"},
        "head": {"sha": head_sha, "meaning": "head_branch_tip_at_provider_observation"},
    }


def _proposal_from_gitlab(data: dict[str, Any], key: RequestKey) -> dict[str, Any]:
    if data.get("iid") != key.number or type(data.get("iid")) is not int:
        raise SourceFailure("PROVIDER_SOURCE_MISMATCH", "Provider MR IID differs from the requested number.")
    if (not _positive_id(data.get("id"))
            or not _positive_id(data.get("target_project_id"))
            or not _positive_id(data.get("source_project_id"))):
        raise _incomplete()
    if data.get("project_id") is not None:
        if not _positive_id(data["project_id"]) or data["project_id"] != data["target_project_id"]:
            raise SourceFailure("PROVIDER_METADATA_INCONSISTENT", "Provider target project identities disagree.")
    # The endpoint's project path is a locator, not an immutable identity.
    # If references.full is available it must agree with the target locator.
    references = data.get("references")
    if references is not None:
        if not isinstance(references, dict):
            raise _incomplete()
        full = references.get("full")
        if full is not None and (
            not isinstance(full, str) or
            full.casefold() != f"{key.repository}!{key.number}".casefold()
        ):
            raise SourceFailure("PROVIDER_SOURCE_MISMATCH", "Provider target path reference differs from the requested project.")
    diff = data.get("diff_refs")
    if not isinstance(diff, dict):
        raise _incomplete()
    base_sha, head_sha = _commit_sha(diff.get("base_sha")), _commit_sha(diff.get("head_sha"))
    start_sha = _commit_sha(diff.get("start_sha"))
    if not base_sha or not head_sha or not start_sha or len({len(base_sha), len(head_sha), len(start_sha)}) != 1:
        raise _incomplete()
    if data.get("sha") is not None:
        latest_sha = _commit_sha(data.get("sha"))
        if not latest_sha or latest_sha != head_sha:
            raise SourceFailure("PROVIDER_METADATA_INCONSISTENT", "Provider head and diff_refs head disagree; retry after source stabilizes.")
    state = data.get("state")
    if state not in ("opened", "closed", "merged", "locked"):
        raise _incomplete()
    reported_count, count_quality = _reported_change_count(data, "gitlab")
    return {
        "provider_object_id": str(data["id"]),
        "provider_reported_changed_files": reported_count,
        "provider_change_count_quality": count_quality,
        "provider_repository_id": str(data["target_project_id"]),
        "provider_source_repository_id": str(data["source_project_id"]),
        "provider_source_repository_path": None,  # Not supplied as an immutable project path by this endpoint.
        "provider_state": state,
        "provider_reports_merged": state == "merged",
        "base": {"sha": base_sha, "meaning": "gitlab_diff_refs_merge_base_not_target_branch_tip"},
        "head": {"sha": head_sha, "meaning": "gitlab_diff_refs_head_at_provider_observation"},
        "target_tip": {"sha": start_sha, "meaning": "gitlab_diff_refs_start_target_tip_at_diff_version"},
    }


def _result(status: str, reason: str, message: str, *, source: dict[str, Any] | None = None,
            synthetic: bool = False) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": status,
        "reason_code": reason,
        "exit_code": {"success": 0, "invalid_input": 4, "unavailable": 5}[status],
        "message": message,
        "source": source,
        "synthetic": synthetic,
        "native_cli_action_registered": False,
        "write_authorized": False,
    }


def fetch_proposed_pr(key: RequestKey, *, allow_network: bool = False,
                      token_supplier: Callable[[], str | None] | None = None,
                      transport: ReadTransport | None = None,
                      timeout: float = DEFAULT_TIMEOUT_SECONDS,
                      include_merge_commit_claim: bool = False,
                      include_squash_claim: bool = False) -> dict[str, Any]:
    """Retrieve only a GH PR / GL MR candidate metadata object.

    A supplied custom transport denotes an isolated/synthetic invocation even
    when it returns a valid-shaped object: it cannot impersonate a live claim.
    The returned SHA values are NOT verified Git objects or stable diff binding.
    EC167 may opt into merge_commit_sha; EC168 separately opts into the GitLab
    squash_on_merge + squash_commit_sha projection. Both options default off,
    preserving EC161 and EC167 legacy projection shapes.
    """
    synthetic = transport is not None
    try:
        _validate_key(key)
        if type(timeout) not in (float, int) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
            raise SourceFailure("INVALID_TIMEOUT", "Timeout must be between 1 and 30 seconds.", "invalid_input")
        if type(include_merge_commit_claim) is not bool:
            raise SourceFailure("INVALID_MERGE_OPTION", "Merge claim opt-in must be a boolean.", "invalid_input")
        if type(include_squash_claim) is not bool:
            raise SourceFailure("INVALID_SQUASH_OPTION", "Squash claim opt-in must be a boolean.", "invalid_input")
        if not allow_network:
            raise SourceFailure("NETWORK_NOT_AUTHORIZED", "Network reads are off by default; explicitly enable a read to use a Provider.")
        if token_supplier is None:
            env_key = ENVIRONMENT_KEYS[key.provider]
            token_supplier = lambda: os.environ.get(env_key)
        try:
            token = token_supplier()
        except Exception:
            raise SourceFailure("CREDENTIALS_UNAVAILABLE", "Credential source did not provide a usable token.") from None
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            raise SourceFailure("CREDENTIALS_UNAVAILABLE", "Credential source did not provide a usable token.")
        active_transport: ReadTransport = transport if transport is not None else StrictHttpsTransport()
        # Deliberately do not log the credential-bearing request or any raw
        # provider response, error body, title, text, patch, files or author.
        data = active_transport.get_object(_endpoint(key), _headers(key.provider, token), float(timeout))
        if not isinstance(data, dict) or ("_ces_fixture" in data and not synthetic):
            raise SourceFailure("PROVIDER_PAYLOAD_INVALID", "Provider did not return a permitted metadata object.")
        proposal = (_proposal_from_github(data, key) if key.provider == "github"
                    else _proposal_from_gitlab(data, key))
        if include_merge_commit_claim:
            # GitHub's merge_commit_sha for an *open* PR can refer to a
            # temporary test merge; never mistake it for an actual merge.
            # GitLab's squash_commit_sha is deliberately not substituted:
            # squash/rebase equivalence is an EC168-only question.
            merge_oid = data.get("merge_commit_sha") if proposal["provider_reports_merged"] else None
            if merge_oid is not None:
                parsed_merge = _commit_sha(merge_oid)
                if not parsed_merge or len(parsed_merge) != len(proposal["head"]["sha"]):
                    raise SourceFailure("PROVIDER_MERGE_SHA_INVALID",
                                        "Provider merge commit SHA is not a complete compatible OID.")
                merge_oid = parsed_merge
            proposal["provider_merge_commit_sha"] = merge_oid
            proposal["provider_merge_sha_quality"] = (
                "COMPLETE_PROVIDER_CLAIM" if merge_oid is not None else "NOT_REPORTED")
        if include_squash_claim:
            # GH PR metadata does not expose an authoritative merge-method
            # result. Never derive "squash" or "rebase" from merge_commit_sha
            # (which is also the last rebased commit for a rebase merge).
            # GL squash_on_merge is effective per-MR intent, while a complete
            # squash_commit_sha is the post-merge commit identity claim.
            squash_on_merge: bool | None = None
            squash_oid: str | None = None
            if key.provider == "gitlab" and proposal["provider_reports_merged"]:
                raw_intent = data.get("squash_on_merge")
                if raw_intent is not None and type(raw_intent) is not bool:
                    raise SourceFailure("PROVIDER_SQUASH_POLICY_INVALID",
                                        "Provider supplied an invalid squash policy claim.")
                squash_on_merge = raw_intent
                raw_oid = data.get("squash_commit_sha")
                if raw_oid not in (None, ""):
                    squash_oid = _commit_sha(raw_oid)
                    if not squash_oid or len(squash_oid) != len(proposal["head"]["sha"]):
                        raise SourceFailure("PROVIDER_SQUASH_SHA_INVALID",
                                            "Provider supplied an invalid squash commit OID.")
            proposal["provider_squash_on_merge"] = squash_on_merge
            proposal["provider_squash_commit_sha"] = squash_oid
            proposal["provider_squash_evidence_quality"] = (
                "GITLAB_EFFECTIVE_SQUASH_TRUE_AND_COMMIT_OID"
                if key.provider == "gitlab" and squash_on_merge is True and squash_oid
                else "NO_COMPLETE_EXPLICIT_SQUASH_WITNESS")
            proposal["provider_merge_method_claim"] = "UNREPORTED"
        proposal.update({
            "provider": key.provider,
            "requested_repository": key.repository,
            "request_number": key.number,
            "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "origin": "synthetic_fixture" if synthetic else "provider_https_response",
            "identity_binding": "NOT_VERIFIED_EC162",
            "diff_snapshot_binding": "NOT_IMPLEMENTED_EC165",
            "provider_actor_verification": "NOT_PERFORMED",
            "file_paths_collected": False,
            "patch_content_collected": False,
            "delivery_or_merge_proven": False,
        })
        return _result("success", "PROVIDER_METADATA_READ", "Provider metadata shape checked; PR/MR identity and diff remain unverified.",
                       source=proposal, synthetic=synthetic)
    except SourceFailure as exc:
        return _result(exc.status, exc.reason, exc.message, synthetic=synthetic)
    except Exception:
        # Defensive boundary: NEVER expose low-level exception strings: some
        # networking packages include Authorization headers and full URLs.
        return _result("unavailable", "PROVIDER_READ_FAILED", "Provider metadata read could not be completed.", synthetic=synthetic)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EC161 read-only GH PR/GL MR source (independent of native CES CLI)")
    parser.add_argument("--provider", required=True, help="github or gitlab")
    parser.add_argument("--repository", required=True, help="owner/repo or group/subgroup/project; never a URL")
    parser.add_argument("--number", required=True, type=int, help="PR number / MR IID")
    parser.add_argument("--allow-network", action="store_true", help="explicitly allow one credentialed HTTPS GET")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--json", action="store_true", help="machine JSON (also the default output format)")
    args = parser.parse_args(argv)
    result = fetch_proposed_pr(RequestKey(args.provider, args.repository, args.number),
                               allow_network=args.allow_network, timeout=args.timeout)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
