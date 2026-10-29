#!/usr/bin/env python3
"""EC-164: explicit, bounded read-only PR/MR patch-content release.

The EC163 path collector remains the only network and identity/pagination
reader. A private page observer sees provider patch/diff fields only after all
independent opt-ins and input gates. Content is buffered only for exact
caller-selected paths and released only after EC163's *post* pin/count check
and COMPLETE path coverage. No raw patch endpoint, cache, filesystem writer,
source-repository operation or native PowerShell route is involved.

WARNING: Syntax/regex screening is defense in depth, NOT guaranteed DLP.
A caller who enables patch output must protect the resulting stdout.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
import unicodedata
from typing import Any, Callable

import proposed_pr_identity as identity
import proposed_pr_paths as paths
import proposed_pr_source as source

SCHEMA = "ces.proposed_pr_patch.v1"
DEFAULT_MAX_PATCH_BYTES = 4096
DEFAULT_TOTAL_PATCH_BYTES = 8192
HARD_MAX_PATCH_BYTES = 8192
HARD_MAX_TOTAL_PATCH_BYTES = 32768
MAX_SELECTED_FILES = 5

# Reject known credential/key locations before either code or token is read.
# This is a conservative blocker, not a claim that every secret path is known.
FORBIDDEN_SEGMENTS = frozenset({
    ".ssh", ".aws", ".gnupg", ".kube", ".git", "secrets", "private", "credentials",
})
FORBIDDEN_BASENAMES = frozenset({
    ".env", ".npmrc", ".netrc", ".pypirc", "id_rsa", "id_ed25519",
    "known_hosts", "credentials.json", "service-account.json", "config.json.key",
})
FORBIDDEN_SUFFIXES = (".pem", ".p12", ".pfx", ".key", ".keystore", ".jks", ".asc")
BINARY_SUFFIXES = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".exe", ".dll", ".so",
    ".zip", ".tar", ".gz", ".7z", ".bin", ".class", ".woff", ".woff2",
})
# Sensitive-pattern refusal is intentionally broad: snippets that resemble
# credentials should not be echoed, even if the key/value is only an example.
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----", re.I),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|glpat-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b"),
    re.compile(r"\b(?:authorization\s*:\s*(?:bearer|basic)\s+\S+|sk-[A-Za-z0-9_-]{12,})", re.I),
    re.compile(r"(?im)^[+\- ]?[ \t]*[\"']?(?:[a-z0-9_\-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key|client[_-]?secret)[a-z0-9_\-]*)[\"']?[ \t]*[:=][ \t]*[\"']?\S+"),
)
# A diff hunk is only treated as complete if its declared old/new line counts
# match all actual +/-/context lines. This does NOT prove a provider snapshot.
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$")


@dataclass(frozen=True)
class ContentPolicy:
    selected_paths: tuple[str, ...] = ()
    max_patch_bytes: int = DEFAULT_MAX_PATCH_BYTES
    max_total_bytes: int = DEFAULT_TOTAL_PATCH_BYTES


def _safe_selected_paths(policy: ContentPolicy) -> tuple[str, ...]:
    if (type(policy.max_patch_bytes) is not int or
            not 1 <= policy.max_patch_bytes <= HARD_MAX_PATCH_BYTES or
            type(policy.max_total_bytes) is not int or
            not 1 <= policy.max_total_bytes <= HARD_MAX_TOTAL_PATCH_BYTES):
        raise source.SourceFailure("PATCH_BUDGET_INVALID", "Patch budgets exceed allowed limits.", "invalid_input")
    requested = policy.selected_paths
    if type(requested) not in (list, tuple) or not 1 <= len(requested) <= MAX_SELECTED_FILES:
        raise source.SourceFailure("PATCH_SELECTION_REQUIRED", "Select 1–5 exact changed paths.", "invalid_input")
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in requested:
        try:
            value = paths._safe_path(raw)
        except source.SourceFailure:
            raise source.SourceFailure("PATCH_SELECTION_INVALID", "Selected file path is unsafe.", "invalid_input") from None
        if any(x in value for x in "*?[]{}") or value.casefold() in seen:
            raise source.SourceFailure("PATCH_SELECTION_INVALID", "Selected paths must be exact and unique.", "invalid_input")
        seen.add(value.casefold())
        normalized.append(value)
    return tuple(normalized)


def _blocked_path(path: str) -> bool:
    components = [p.casefold() for p in path.split("/")]
    base = components[-1]
    return (any(p in FORBIDDEN_SEGMENTS for p in components) or
            base in FORBIDDEN_BASENAMES or
            base.startswith((".env.", "id_rsa.", "id_ed25519.")) or
            any(base.endswith(ext) for ext in FORBIDDEN_SUFFIXES) or
            "secret" in base or "credential" in base)


def _binary_path(path: str) -> bool:
    return any(path.casefold().endswith(suffix) for suffix in BINARY_SUFFIXES)


def _diff_format(text: str) -> str:
    """Conservative hunk syntax check: truncated, unverified or complete.

    A recognized syntactically whole patch is not a cryptographic guarantee of
    completeness: the provider can omit whole hunks without contradicting it.
    """
    have_hunk = False
    old_remaining = new_remaining = 0
    for line in text.splitlines():
        match = HUNK.fullmatch(line)
        if match:
            if have_hunk and (old_remaining or new_remaining):
                return "TRUNCATED"
            old_remaining = int(match.group(2) or "1")
            new_remaining = int(match.group(4) or "1")
            if old_remaining > 1000000 or new_remaining > 1000000:
                return "UNVERIFIED_FORMAT"
            have_hunk = True
            continue
        if not have_hunk:
            if (line.startswith(("diff --git ", "index ", "--- ", "+++ ",
                                 "new file mode ", "deleted file mode ",
                                 "similarity index ", "rename from ", "rename to ",
                                 "old mode ", "new mode "))):
                continue
            return "UNVERIFIED_FORMAT"
        if line.startswith("\\ No newline at end of file"):
            continue
        if not line or line[0] not in " +-":
            return "UNVERIFIED_FORMAT"
        if old_remaining == 0 and new_remaining == 0:
            return "UNVERIFIED_FORMAT"
        if line[0] != "+":
            old_remaining -= 1
        if line[0] != "-":
            new_remaining -= 1
        if old_remaining < 0 or new_remaining < 0:
            return "UNVERIFIED_FORMAT"
    if not have_hunk:
        return "UNVERIFIED_FORMAT"
    return "TRUNCATED" if (old_remaining or new_remaining) else "AVAILABLE"


def _inspect_patch(raw: dict[str, Any], provider: str, path: str,
                   max_bytes: int, remaining: int) -> dict[str, Any]:
    """Never return raw values for anything except explicitly allowed text."""
    def limited(state: str) -> dict[str, Any]:
        return {"path": path, "availability": state, "patch_text": None, "utf8_bytes": None}

    if _blocked_path(path):
        return limited("SENSITIVE_PATH_BLOCKED")
    if _binary_path(path) or raw.get("binary") is True:
        return limited("BINARY_OR_BINARY_SUSPECTED")
    if provider == "gitlab":
        if raw.get("too_large") is True:
            return limited("PROVIDER_TOO_LARGE")
        if raw.get("collapsed") is True:
            return limited("PROVIDER_COLLAPSED")
    name = "patch" if provider == "github" else "diff"
    if name not in raw or raw[name] is None:
        return limited("MISSING_OR_BINARY_UNKNOWN")
    text = raw[name]
    if type(text) is not str:
        return limited("INVALID_PROVIDER_CONTENT")
    if "GIT binary patch" in text or re.search(r"(?m)^Binary files .* differ\s*$", text):
        return limited("BINARY")
    if not text:
        return limited("EMPTY")
    # Check byte length BEFORE any regexes; never inspect arbitrarily long content.
    try:
        nbytes = len(text.encode("utf-8", "strict"))
    except UnicodeError:
        return limited("INVALID_PROVIDER_CONTENT")
    if nbytes > max_bytes:
        return limited("TOO_LARGE")
    if nbytes > remaining:
        return limited("TOTAL_BUDGET_EXHAUSTED")
    if any(unicodedata.category(c) in ("Cc", "Cf", "Cs") and c not in "\t\n\r" for c in text):
        return limited("UNSAFE_TEXT_BLOCKED")
    if any(pat.search(text) for pat in SECRET_PATTERNS):
        return limited("SENSITIVE_CONTENT_BLOCKED")
    syntax_state = _diff_format(text)
    if syntax_state != "AVAILABLE":
        return limited(syntax_state)
    return {"path": path, "availability": "AVAILABLE", "patch_text": text, "utf8_bytes": nbytes}


def _result(status: str, reason: str, message: str, *, base: dict[str, Any] | None = None,
            entries: list[dict[str, Any]] | None = None,
            requested: bool = False, policy: ContentPolicy | None = None) -> dict[str, Any]:
    items = entries if entries is not None else []
    return {
        "schema": SCHEMA,
        "status": status, "exit_code": {"success": 0, "partial": 2, "invalid_input": 4, "unavailable": 5}[status],
        "reason_code": reason, "message": message,
        "path_evidence": base,
        "patch_content_requested": requested,
        "patch_content_collected": any(x["availability"] == "AVAILABLE" for x in items),
        "patches": items,
        "content_policy": {
            "max_selected_files": MAX_SELECTED_FILES,
            "selected_files": len(policy.selected_paths) if policy is not None and requested else 0,
            "max_patch_bytes": policy.max_patch_bytes if policy is not None and requested else 0,
            "max_total_bytes": policy.max_total_bytes if policy is not None and requested else 0,
            "emitted_utf8_bytes": sum(x["utf8_bytes"] or 0 for x in items),
            "caller_permission_acknowledged": requested,
            "provider_permission_independently_verified": False,
        },
        "native_cli_action_registered": False,
        "diff_snapshot_proven": False,
        "delivery_or_merge_proven": False,
        "provider_actor_verified": False,
        "write_authorized": False,
        "synthetic": bool(base["synthetic"]) if base is not None else False,
    }


def collect_proposed_pr_patch(
    key: source.RequestKey, *,
    expected_pin: dict[str, Any] | None,
    allow_network: bool = False,
    include_patch_content: bool = False,
    acknowledge_provider_permission: bool = False,
    policy: ContentPolicy | None = None,
    token_supplier: Callable[[], str | None] | None = None,
    transport: paths.PathsTransport | None = None,
    timeout: float = 8.0,
    per_page: int = paths.DEFAULT_PAGE_SIZE,
    max_pages: int = paths.DEFAULT_MAX_PAGES,
    _validated_page_receipt_observer: Callable[[int, paths.FilePage, list[dict[str, Any]], int | None], None] | None = None,
    _validated_file_evidence_observer: Callable[[list[tuple[dict[str, Any], dict[str, Any]]]], None] | None = None,
) -> dict[str, Any]:
    """Return EC163 metadata by default; release narrow content only if gated.

    The caller's acknowledgement is NOT provider authorization proof. Provider
    response access is separately required via the existing EC163 GET path.
    """
    requested = include_patch_content is True
    selected: tuple[str, ...] = ()
    try:
        if type(include_patch_content) is not bool or type(acknowledge_provider_permission) is not bool:
            raise source.SourceFailure("PATCH_AUTHORIZATION_INVALID", "Patch flags must be boolean.", "invalid_input")
        if include_patch_content:
            if not acknowledge_provider_permission:
                raise source.SourceFailure("PATCH_PERMISSION_ACK_REQUIRED",
                                           "Explicit acknowledgement of provider content permission required.",
                                           "invalid_input")
            if not allow_network:
                raise source.SourceFailure("NETWORK_NOT_AUTHORIZED", "Network access is disabled by default.")
            if type(policy) is not ContentPolicy:
                raise source.SourceFailure("PATCH_SELECTION_REQUIRED", "An explicit content policy is required.",
                                           "invalid_input")
            selected = _safe_selected_paths(policy)
            if any(_blocked_path(p) for p in selected):
                raise source.SourceFailure("PATCH_SENSITIVE_PATH_REJECTED",
                                           "Selected file requires a stronger disclosure process.", "invalid_input")
        elif policy is not None and type(policy) is not ContentPolicy:
            raise source.SourceFailure("PATCH_POLICY_INVALID", "Content policy has an invalid shape.", "invalid_input")
    except source.SourceFailure as exc:
        return _result(exc.status, exc.reason, exc.message)

    # Never even inspect the patch/diff field when content was not requested.
    if not include_patch_content:
        base = paths.collect_proposed_pr_paths(
            key, expected_pin=expected_pin, allow_network=allow_network,
            token_supplier=token_supplier, transport=transport,
            timeout=timeout, per_page=per_page, max_pages=max_pages,
            _validated_page_receipt_observer=_validated_page_receipt_observer,
            _validated_page_observer=_validated_file_evidence_observer,
        )
        return _result(base["status"], base["reason_code"],
                       "Path metadata only; patch content is disabled.", base=base)

    assert policy is not None
    captured: dict[str, dict[str, Any]] = {}
    emitted = 0
    selection = set(selected)

    def capture(validated_page: list[tuple[dict[str, Any], dict[str, Any]]]) -> None:
        nonlocal emitted
        if _validated_file_evidence_observer is not None:
            _validated_file_evidence_observer(validated_page)
        for raw, item in validated_page:
            # Only the canonical changed destination (or deleted origin) is
            # selectable; never release based on an unchecked old/new alias.
            target = item["new_path"] or item["old_path"]
            if target not in selection:
                continue
            if target in captured:
                raise source.SourceFailure("PATCH_SELECTION_AMBIGUOUS", "Changed path repeated.")
            entry = _inspect_patch(raw, key.provider, target, policy.max_patch_bytes,
                                   policy.max_total_bytes - emitted)
            captured[target] = entry
            if entry["availability"] == "AVAILABLE":
                emitted += entry["utf8_bytes"]

    # Reuses EC163: validated pin before/after, path+rename safety, page/count
    # coverage, bounded raw JSON, total-byte budget and fail-closed clearing.
    base = paths.collect_proposed_pr_paths(
        key, expected_pin=expected_pin, allow_network=allow_network,
        token_supplier=token_supplier, transport=transport,
        timeout=timeout, per_page=per_page, max_pages=max_pages,
        _validated_page_observer=capture,
        _validated_page_receipt_observer=_validated_page_receipt_observer,
    )
    # Explicitly discard all captured text for any provider error or drift.
    if base["status"] not in ("success", "partial") or not base["path_metadata_collected"]:
        captured.clear()
        return _result(base["status"], base["reason_code"],
                       "Patch release denied because metadata acquisition failed.", base=base,
                       requested=True, policy=policy)
    if base["coverage"]["state"] != "COMPLETE":
        captured.clear()
        return _result("partial", "PATCH_WITHHELD_INCOMPLETE_COVERAGE",
                       "Incomplete path coverage; no patch content released.", base=base,
                       entries=[{"path": path, "availability": "COVERAGE_INCOMPLETE",
                                 "patch_text": None, "utf8_bytes": None} for path in selected],
                       requested=True, policy=policy)
    # Verify membership against the exact sanitized EC163 file result; even a
    # selected unknown path suppresses ALL released content, not just that row.
    available_paths = {f["new_path"] or f["old_path"] for f in base["files"]}
    if any(path not in available_paths or path not in captured for path in selected):
        captured.clear()
        return _result("invalid_input", "PATCH_PATH_NOT_IN_COMPLETE_LIST",
                       "One or more selected paths are not in the verified changed-file list.", base=base,
                       requested=True, policy=policy)
    entries = [captured[name] for name in selected]
    # Synthetic fixtures are ALWAYS partial, regardless of coverage and content.
    if base["synthetic"]:
        state, reason = "partial", "SYNTHETIC_PATCH_CONTENT_ONLY"
    elif all(entry["availability"] == "AVAILABLE" for entry in entries):
        state, reason = "success", "BOUNDED_PATCH_CONTENT_RELEASED"
    else:
        state, reason = "partial", "PATCH_CONTENT_PARTIALLY_WITHHELD"
    return _result(state, reason,
                   "Explicitly selected bounded patch text only; not a verified atomic diff snapshot.",
                   base=base, entries=entries, requested=True, policy=policy)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="EC164 explicit patch content gate (separate from native CES Collect)")
    parser.add_argument("--provider", required=True, choices=("github", "gitlab"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--number", type=int, required=True)
    parser.add_argument("--expected-pin", required=True, metavar="EC162_RESULT_JSON")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--include-patch-content", action="store_true")
    parser.add_argument("--ack-provider-content-permission", action="store_true")
    parser.add_argument("--path", action="append", default=[], metavar="EXACT_CHANGED_PATH")
    parser.add_argument("--max-patch-bytes", type=int, default=DEFAULT_MAX_PATCH_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_TOTAL_PATCH_BYTES)
    parser.add_argument("--per-page", type=int, default=paths.DEFAULT_PAGE_SIZE)
    parser.add_argument("--max-pages", type=int, default=paths.DEFAULT_MAX_PAGES)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        previous = identity._read_expected(args.expected_pin)
    except Exception:
        result = _result("invalid_input", "INVALID_EXPECTED_PIN", "Previous EC162 result is invalid or unavailable.")
    else:
        result = collect_proposed_pr_patch(
            source.RequestKey(args.provider, args.repository, args.number),
            expected_pin=previous, allow_network=args.allow_network,
            include_patch_content=args.include_patch_content,
            acknowledge_provider_permission=args.ack_provider_content_permission,
            policy=ContentPolicy(tuple(args.path), args.max_patch_bytes, args.max_total_bytes)
                   if args.include_patch_content else None,
            timeout=args.timeout, per_page=args.per_page, max_pages=args.max_pages,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
