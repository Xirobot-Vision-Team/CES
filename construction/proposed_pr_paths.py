#!/usr/bin/env python3
"""EC-163: bounded, read-only PR/MR changed-path metadata; no native CLI route.

A previous EC-162 result is mandatory. Both the pre-read and post-read
provider observations must match that exact pin. Provider file counts and
termination signals must agree before claiming complete *path metadata*.
This does not give a race-free diff snapshot (reserved for EC-165).
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import unicodedata
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

import proposed_pr_identity as identity
import proposed_pr_source as source

SCHEMA = "ces.proposed_pr_paths.v1"
MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_RESPONSE_BYTES = 12 * 1024 * 1024
MAX_FILES = 3000
MAX_PAGES = 30
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 100
DEFAULT_MAX_PAGES = 30
GH_PROVIDER_FILE_CEILING = 3000
MAX_PATH_BYTES = 1024
MAX_SEGMENT_BYTES = 255
MAX_PATH_DEPTH = 128
MAX_LINE_COUNT = 1_000_000_000
LINK_ITEM = re.compile(r'\s*<([^<>]{1,2048})>;\s*rel="?([a-z]+)"?\s*\Z', re.ASCII)
ETAG = re.compile(r'(?:W/)?"[\x21\x23-\x7e]{0,255}"\Z', re.ASCII)
RAW_SHA256 = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)


@dataclass(frozen=True)
class FilePage:
    items: list[Any]
    headers: dict[str, str]
    byte_count: int = 0
    # Raw-body digest stays internal to optional EC165 read-versus-read checks.
    # It is NEVER published: page JSON can contain unselected private patches.
    raw_body_sha256: str | None = None


class PathsTransport(Protocol):
    def get_object(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]: ...
    def get_page(self, url: str, headers: dict[str, str], timeout: float) -> FilePage: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int,
                         msg: str, headers: Any, newurl: str) -> None:
        return None


class StrictPathsTransport:
    """Bounded GET with TLS, disabled redirect/proxy/retry and no body logging.

    Both GitHub and GitLab return patch/diff fields in the files-list JSON.
    Those bytes can be unavoidable on the wire; they are discarded at parsing,
    never written to disk, returned, displayed or inspected as patch content.
    """
    def __init__(self) -> None:
        self._metadata = source.StrictHttpsTransport()

    def get_object(self, url: str, headers: dict[str, str], timeout: float) -> dict[str, Any]:
        return self._metadata.get_object(url, headers, timeout)

    def get_page(self, url: str, headers: dict[str, str], timeout: float) -> FilePage:
        if not (url.startswith("https://api.github.com/") or
                url.startswith("https://gitlab.com/api/v4/")):
            raise source.SourceFailure("PROVIDER_ENDPOINT_REJECTED", "Files API host is not approved.")
        opener = build_opener(ProxyHandler({}), _NoRedirect(),
                              HTTPSHandler(context=ssl.create_default_context()))
        request = Request(url, headers=headers, method="GET")
        try:
            with opener.open(request, timeout=timeout) as response:
                if response.geturl() != url or response.status != 200:
                    raise source.SourceFailure("PROVIDER_ENDPOINT_REJECTED", "Unexpected files API endpoint.")
                ctype = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                if ctype != "application/json" and not (
                    ctype.startswith("application/") and ctype.endswith("+json")
                ):
                    raise source.SourceFailure("PROVIDER_PAYLOAD_INVALID", "Files API did not return JSON.")
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise source.SourceFailure("PROVIDER_PAYLOAD_INVALID", "Unexpected compressed file metadata.")
                claimed = response.headers.get("Content-Length")
                if claimed and claimed.isdecimal() and int(claimed) > MAX_PAGE_BYTES:
                    raise source.SourceFailure("PROVIDER_PAYLOAD_TOO_LARGE", "Files API response exceeded the budget.")
                header_values: dict[str, str] = {}
                for name in ("Link", "X-Next-Page", "X-Page", "X-Per-Page", "X-Total", "ETag", "Last-Modified"):
                    found = response.headers.get_all(name, [])
                    if len(found) > 1 or any(len(v) > 8192 for v in found):
                        raise source.SourceFailure("PROVIDER_PAGINATION_INVALID",
                                                   "Files API pagination headers are ambiguous.")
                    if found:
                        header_values[name.lower()] = found[0]
                raw = response.read(MAX_PAGE_BYTES + 1)
                if len(raw) > MAX_PAGE_BYTES:
                    raise source.SourceFailure("PROVIDER_PAYLOAD_TOO_LARGE", "Files API response exceeded the budget.")
                return FilePage(_decode_array(raw), header_values, len(raw),
                                hashlib.sha256(raw).hexdigest())
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                code = "PROVIDER_REDIRECT_REFUSED"
            elif exc.code in (401, 403):
                code = "PROVIDER_AUTH_UNAVAILABLE"
            elif exc.code == 404:
                code = "PROVIDER_OBJECT_NOT_ACCESSIBLE"
            elif exc.code == 429:
                code = "PROVIDER_RATE_LIMITED"
            elif exc.code in (408, 425) or 500 <= exc.code < 600:
                code = "PROVIDER_UNAVAILABLE"
            else:
                code = "PROVIDER_HTTP_UNAVAILABLE"
            raise source.SourceFailure(code, "Provider did not supply an authorized files-list page.") from None
        except (URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError):
            raise source.SourceFailure("PROVIDER_NETWORK_UNAVAILABLE",
                                       "Provider files-list HTTPS request could not complete.") from None


def _decode_array(raw: bytes) -> list[Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate key")
            obj[key] = value
        return obj

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
        if type(data) is not list:
            raise ValueError("not an array")
        return data
    except (ValueError, UnicodeError, RecursionError):
        raise source.SourceFailure("PROVIDER_PAYLOAD_INVALID",
                                   "Files API supplied invalid, duplicated or non-array JSON.") from None


def _files_url(key: source.RequestKey, page: int, per_page: int) -> str:
    # Never follow a URL from an API response. Every request is independently
    # constructed from the already-validated RequestKey.
    if key.provider == "github":
        owner, repo = key.repository.split("/")
        prefix = (f"https://api.github.com/repos/{quote(owner, safe='')}/"
                  f"{quote(repo, safe='')}/pulls/{key.number}/files")
    else:
        prefix = (f"https://gitlab.com/api/v4/projects/"
                  f"{quote(key.repository, safe='')}/merge_requests/{key.number}/diffs")
    return f"{prefix}?page={page}&per_page={per_page}"


def _safe_path(value: Any) -> str:
    """Preserve exact POSIX path bytes (via UTF-8), but reject unsafe spellings.

    These strings are OUTPUT METADATA ONLY. Never join them to a local path.
    """
    if type(value) is not str or not value or value != unicodedata.normalize("NFC", value):
        raise source.SourceFailure("PROVIDER_PATH_UNSAFE", "Files API reported an unsafe or ambiguous path.")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError:
        raise source.SourceFailure("PROVIDER_PATH_UNSAFE", "Files API reported an invalid path.") from None
    if size > MAX_PATH_BYTES or value.startswith("/") or "\\" in value:
        raise source.SourceFailure("PROVIDER_PATH_UNSAFE", "Files API reported an unsafe or oversized path.")
    parts = value.split("/")
    if len(parts) > MAX_PATH_DEPTH or any(
        part in ("", ".", "..") or len(part.encode("utf-8")) > MAX_SEGMENT_BYTES or
        part.endswith((" ", ".")) or
        any(c in '<>:"|?*' or unicodedata.category(c) in ("Cc", "Cf", "Cs")
            for c in part)
        for part in parts
    ):
        raise source.SourceFailure("PROVIDER_PATH_UNSAFE", "Files API reported an unsafe path segment.")
    # Prevent special Windows device paths; do not attempt canonicalization.
    for part in parts:
        stem = part.split(".", 1)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(COM|LPT)[1-9]", stem):
            raise source.SourceFailure("PROVIDER_PATH_UNSAFE",
                                       "Files API reported a platform-ambiguous file name.")
    return value


def _nonnegative_int(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= MAX_LINE_COUNT:
        raise source.SourceFailure("PROVIDER_FILE_METADATA_INVALID",
                                   "Files API line count was missing or invalid.")
    return value


def _github_entry(item: Any) -> dict[str, Any]:
    if type(item) is not dict:
        raise source.SourceFailure("PROVIDER_FILE_METADATA_INVALID", "Files API entry is not an object.")
    path = _safe_path(item.get("filename"))
    kind = item.get("status")
    if kind not in ("added", "removed", "modified", "renamed", "copied", "changed"):
        raise source.SourceFailure("PROVIDER_FILE_STATUS_INVALID",
                                   "Files API reported an unknown file-change status.")
    prev = item.get("previous_filename")
    if kind in ("renamed", "copied"):
        prior = _safe_path(prev)
        if prior == path:
            raise source.SourceFailure("PROVIDER_FILE_STATUS_CONFLICT",
                                       "File rename/copy does not have two distinct paths.")
    elif prev is not None:
        raise source.SourceFailure("PROVIDER_FILE_STATUS_CONFLICT",
                                   "Unexpected old path on a non-rename file status.")
    else:
        prior = path
    adds = _nonnegative_int(item.get("additions"))
    dels = _nonnegative_int(item.get("deletions"))
    changes = _nonnegative_int(item.get("changes"))
    if adds + dels != changes or changes > MAX_LINE_COUNT:
        raise source.SourceFailure("PROVIDER_FILE_STATS_CONFLICT",
                                   "Provider additions, deletions and changed lines disagree.")
    return {
        "status": kind,
        "old_path": None if kind == "added" else prior,
        "new_path": None if kind == "removed" else path,
        "additions": adds,
        "deletions": dels,
        "changes": changes,
        "stats_available": True,
    }


def _gitlab_entry(item: Any) -> dict[str, Any]:
    if type(item) is not dict:
        raise source.SourceFailure("PROVIDER_FILE_METADATA_INVALID", "Files API entry is not an object.")
    before = _safe_path(item.get("old_path"))
    after = _safe_path(item.get("new_path"))
    names = ("new_file", "deleted_file", "renamed_file")
    if any(type(item.get(name)) is not bool for name in names):
        raise source.SourceFailure("PROVIDER_FILE_STATUS_INVALID", "Files API flags were not booleans.")
    is_added, is_removed, is_renamed = (item[k] for k in names)
    if sum((is_added, is_removed, is_renamed)) > 1 or (is_renamed != (before != after)):
        raise source.SourceFailure("PROVIDER_FILE_STATUS_CONFLICT",
                                   "Files API change flags disagree with old/new paths.")
    for flag in ("too_large", "collapsed"):
        if flag in item and type(item[flag]) is not bool:
            raise source.SourceFailure("PROVIDER_FILE_METADATA_INVALID",
                                       "Files API diff-limit flags were invalid.")
    kind = "added" if is_added else "removed" if is_removed else "renamed" if is_renamed else "modified"
    return {
        "status": kind,
        "old_path": None if is_added else before,
        "new_path": None if is_removed else after,
        "additions": None,
        "deletions": None,
        "changes": None,
        "stats_available": False,
        "provider_patch_limited": bool(item.get("too_large") or item.get("collapsed")),
    }


def _link_next(link: str, key: source.RequestKey, current: int, per_page: int) -> int | None:
    if len(link) > 8192:
        raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Oversized pagination signal.")
    next_page = None
    seen_rels: set[str] = set()
    for piece in link.split(","):
        matched = LINK_ITEM.fullmatch(piece)
        if not matched:
            raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Unrecognized pagination link.")
        url, relation = matched.groups()
        if relation in seen_rels or relation not in ("first", "prev", "next", "last"):
            raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Repeated/unknown pagination link.")
        seen_rels.add(relation)
        parsed = urlsplit(url)
        expected = urlsplit(_files_url(key, current, per_page))
        if (parsed.scheme != "https" or parsed.netloc != expected.netloc or
                parsed.path != expected.path or parsed.fragment or parsed.username or parsed.password):
            raise source.SourceFailure("PROVIDER_PAGINATION_INVALID",
                                       "Pagination link changed API destination.")
        try:
            args = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Pagination URL is malformed.") from None
        if len(args) != 2 or {k for k, _ in args} != {"page", "per_page"}:
            raise source.SourceFailure("PROVIDER_PAGINATION_INVALID",
                                       "Pagination link changed query parameters.")
        values = dict(args)
        if not values["page"].isascii() or not values["page"].isdecimal() or (
            not values["per_page"].isascii() or values["per_page"] != str(per_page)
        ):
            raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Pagination link has invalid page size.")
        dest = int(values["page"])
        if not 1 <= dest <= 10_000:
            raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Pagination destination is out of bounds.")
        if relation == "next":
            if dest != current + 1:
                raise source.SourceFailure("PROVIDER_PAGINATION_INVALID",
                                           "Pagination skipped or repeated a page.")
            next_page = dest
        if relation == "prev" and dest >= current:
            raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Pagination previous page is inconsistent.")
    return next_page


def _page_next(page: FilePage, key: source.RequestKey, current: int,
               per_page: int) -> int | None:
    hdr = {name.lower(): val for name, val in page.headers.items()}
    if any(name not in ("link", "x-next-page", "x-page", "x-per-page", "x-total",
                            "etag", "last-modified")
           or type(value) is not str or len(value) > 8192
           for name, value in hdr.items()):
        raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Unexpected pagination metadata.")
    # HTTP validators describe individual HTTP representations, NOT a shared
    # immutable PR/MR diff version across different page URLs.
    if "etag" in hdr and not ETAG.fullmatch(hdr["etag"]):
        raise source.SourceFailure("PROVIDER_VERSION_HEADER_INVALID",
                                   "Files API ETag was malformed or ambiguous.")
    if "last-modified" in hdr:
        try:
            parsed = parsedate_to_datetime(hdr["last-modified"])
            if (parsed.tzinfo is None or parsed.utcoffset() is None or
                    parsed.utcoffset().total_seconds() != 0 or
                    not hdr["last-modified"].isascii()):
                raise ValueError("non-UTC timestamp")
        except (TypeError, ValueError, OverflowError, IndexError):
            raise source.SourceFailure("PROVIDER_VERSION_HEADER_INVALID",
                                       "Files API Last-Modified was malformed.") from None
    def number(name: str) -> int | None:
        if name not in hdr or hdr[name] == "":
            return None
        if not hdr[name].isascii() or not hdr[name].isdecimal() or len(hdr[name]) > 9:
            raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Invalid numeric pagination header.")
        return int(hdr[name])
    xpage = number("x-page")
    size = number("x-per-page")
    total = number("x-total")
    if total is not None and total > 10_000_000:
        raise source.SourceFailure("PROVIDER_PAGINATION_INVALID",
                                   "Provider pagination total is out of bounds.")
    if (xpage is not None and xpage != current) or (
        size is not None and size != per_page
    ):
        raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Pagination response page or size disagrees.")
    link_next = _link_next(hdr["link"], key, current, per_page) if hdr.get("link") else None
    gl_next = number("x-next-page") if key.provider == "gitlab" else None
    if key.provider == "github" and any(k.startswith("x-") for k in hdr):
        raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Unexpected GitHub pagination headers.")
    if gl_next is not None and gl_next != current + 1:
        raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "GitLab pagination skipped or repeated a page.")
    # An explicit X-Next-Page="" contradicting Link rel=next is a red flag.
    if key.provider == "gitlab" and hdr.get("x-next-page") == "" and link_next:
        raise source.SourceFailure("PROVIDER_PAGINATION_INVALID",
                                   "GitLab pagination termination signals conflict.")
    if link_next and gl_next and link_next != gl_next:
        raise source.SourceFailure("PROVIDER_PAGINATION_INVALID", "Conflicting next-page headers.")
    return link_next or gl_next


def _result(status: str, reason: str, message: str, *, synthetic: bool = False,
            pin: dict[str, Any] | None = None, fingerprint: str | None = None,
            files: list[dict[str, Any]] | None = None,
            coverage: dict[str, Any] | None = None, observations: list[str] | None = None,
            stats: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": status,
        "reason_code": reason,
        "exit_code": {"success": 0, "partial": 2, "invalid_input": 4, "unavailable": 5}[status],
        "message": message,
        "pin": pin,
        "pin_fingerprint": fingerprint,
        "files": files if files is not None else [],
        "coverage": coverage if coverage is not None else {
            "state": "NOT_COLLECTED", "listed_files": 0, "reported_files": None,
            "provider_count_quality": "UNKNOWN", "pages_read": 0,
            "last_page_reached": False, "provider_patch_limited_files": 0,
        },
        "line_stats": stats if stats is not None else {
            "additions": None, "deletions": None, "source": "NOT_COLLECTED",
            "scope": "LISTED_FILES_ONLY",
        },
        "metadata_observations_utc": observations if observations is not None else [],
        "synthetic": synthetic,
        "native_cli_action_registered": False,
        "path_metadata_collected": bool(files is not None),
        "patch_content_collected": False,
        "diff_snapshot_proven": False,
        "provider_actor_verified": False,
        "delivery_or_merge_proven": False,
        "write_authorized": False,
    }


def _same_pin(expected: dict[str, Any], source_data: dict[str, Any]) -> dict[str, Any]:
    pin = identity._new_pin(source_data)
    drift = identity._compare(expected, pin)
    if drift["status"] != "PIN_MATCHED":
        raise source.SourceFailure("PIN_DRIFT_" + drift["reason_code"],
                                   "EC162 identity/OID facts drifted during file acquisition.")
    return pin


def _observation(key: source.RequestKey, allow_network: bool,
                 token_supplier: Callable[[], str | None], transport: PathsTransport,
                 timeout: float, expected_pin: dict[str, Any],
                 expected_synthetic: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    reply = source.fetch_proposed_pr(
        key, allow_network=allow_network, token_supplier=token_supplier,
        transport=transport if expected_synthetic else None,
        timeout=timeout,
    )
    if reply["status"] != "success":
        raise source.SourceFailure(reply["reason_code"], reply["message"], reply["status"])
    if reply["synthetic"] != expected_synthetic:
        raise source.SourceFailure("PIN_PROVENANCE_CHANGED",
                                   "Expected and observed evidence provenance are different.")
    metadata = reply["source"]
    assert metadata is not None
    return metadata, _same_pin(expected_pin, metadata)


def collect_proposed_pr_paths(
    key: source.RequestKey, *,
    expected_pin: dict[str, Any] | None,
    allow_network: bool = False,
    token_supplier: Callable[[], str | None] | None = None,
    transport: PathsTransport | None = None,
    timeout: float = 8.0,
    per_page: int = DEFAULT_PAGE_SIZE,
    max_pages: int = DEFAULT_MAX_PAGES,
    _validated_page_observer: Callable[[list[tuple[dict[str, Any], dict[str, Any]]]], None] | None = None,
    _validated_page_receipt_observer: Callable[[int, FilePage, list[dict[str, Any]], int | None], None] | None = None,
) -> dict[str, Any]:
    """Read changed paths only, requiring an EC162 prior pin and two matching observations.

    Partial page budgets and provider caps retain clearly incomplete files;
    inconsistent, inaccessible or drifting observations suppress the entire list.
    Synthetic transports never produce live success.
    """
    synthetic = transport is not None
    try:
        source._validate_key(key)
        if expected_pin is None:
            raise source.SourceFailure("EXPECTED_PIN_REQUIRED",
                                       "Supply a previous complete EC162 JSON result.", "invalid_input")
        try:
            previous = identity._validate_expected(expected_pin)
        except (ValueError, TypeError, OverflowError, KeyError):
            raise source.SourceFailure("INVALID_EXPECTED_PIN",
                                       "Previous EC162 pin is invalid.", "invalid_input") from None
        if previous is None:
            raise source.SourceFailure("EXPECTED_PIN_REQUIRED",
                                       "Supply a previous EC162 pin.", "invalid_input")
        prior_pin, prior_synthetic = previous
        if (prior_pin["provider"] != key.provider or
                prior_pin["repository_locator"] != key.repository or
                prior_pin["request_number"] != key.number):
            raise source.SourceFailure("EXPECTED_PIN_LOCATOR_MISMATCH",
                                       "Previous pin belongs to another PR/MR locator.", "invalid_input")
        if type(timeout) not in (int, float) or not 1 <= timeout <= 30:
            raise source.SourceFailure("INVALID_TIMEOUT", "Timeout must be 1–30 seconds.", "invalid_input")
        if (type(per_page) is not int or not 1 <= per_page <= MAX_PAGE_SIZE or
                type(max_pages) is not int or not 1 <= max_pages <= MAX_PAGES):
            raise source.SourceFailure("INVALID_PAGE_BUDGET",
                                       "per_page must be 1–100 and max_pages 1–30.", "invalid_input")
        if prior_synthetic != synthetic:
            raise source.SourceFailure("PIN_PROVENANCE_CHANGED",
                                       "Synthetic and real Provider evidence must not be mixed.")
        if not allow_network:
            raise source.SourceFailure("NETWORK_NOT_AUTHORIZED",
                                       "Network access is disabled by default.")
        active_transport: PathsTransport = transport if transport is not None else StrictPathsTransport()
        cached: list[str] = []

        def once_token() -> str | None:
            if not cached:
                supplier = token_supplier
                if supplier is None:
                    supplier = lambda: os.environ.get(source.ENVIRONMENT_KEYS[key.provider])
                try:
                    value = supplier()
                except Exception:
                    raise source.SourceFailure("CREDENTIALS_UNAVAILABLE",
                                               "Token source failed.") from None
                if type(value) is not str or not source.TOKEN.fullmatch(value):
                    raise source.SourceFailure("CREDENTIALS_UNAVAILABLE",
                                               "Credential missing or unusable.")
                cached.append(value)
            return cached[0]

        # EC162 strict pin checks BEFORE any file metadata requests.
        before, pin = _observation(key, True, once_token, active_transport,
                                   float(timeout), prior_pin, synthetic)
        count = before["provider_reported_changed_files"]
        count_quality = before["provider_change_count_quality"]
        all_files: list[dict[str, Any]] = []
        seen_old: set[str] = set()
        seen_new: set[str] = set()
        total_bytes = 0
        patch_limited = 0
        pages_read = 0
        last_page_reached = False
        stop_reason = None
        pagination_total: int | None = None
        for page_num in range(1, max_pages + 1):
            validated_page: list[tuple[dict[str, Any], dict[str, Any]]] = []
            page = active_transport.get_page(
                _files_url(key, page_num, per_page),
                source._headers(key.provider, once_token()), float(timeout))
            if type(page) is not FilePage or type(page.items) is not list or (
                type(page.headers) is not dict or type(page.byte_count) is not int or
                not 0 <= page.byte_count <= MAX_PAGE_BYTES or
                (page.raw_body_sha256 is not None and
                 (type(page.raw_body_sha256) is not str or
                  not RAW_SHA256.fullmatch(page.raw_body_sha256)))
            ):
                raise source.SourceFailure("PROVIDER_PAYLOAD_INVALID", "File page had an invalid transport shape.")
            total_bytes += page.byte_count
            if total_bytes > MAX_TOTAL_RESPONSE_BYTES:
                stop_reason = "RESPONSE_BYTE_BUDGET"
                break
            if len(page.items) > per_page:
                raise source.SourceFailure("PROVIDER_PAGINATION_INVALID",
                                           "Provider returned more entries than requested.")
            pages_read += 1
            for item in page.items:
                normalized = (_github_entry(item) if key.provider == "github"
                              else _gitlab_entry(item))
                for field, registry in (("old_path", seen_old), ("new_path", seen_new)):
                    p = normalized[field]
                    if p is not None:
                        folded = p.casefold()
                        if folded in registry:
                            raise source.SourceFailure("PROVIDER_PATH_CONFLICT",
                                                       "Files API repeated an old/new path.")
                        registry.add(folded)
                if normalized.get("provider_patch_limited"):
                    patch_limited += 1
                # Never propagate GitHub 'patch' or GitLab 'diff', raw content
                # URLs, author, description or other arbitrary response keys.
                all_files.append(normalized)
                if _validated_page_observer is not None:
                    validated_page.append((item, normalized))
            if len(all_files) > MAX_FILES or (count is not None and len(all_files) > count):
                raise source.SourceFailure("PROVIDER_FILE_COUNT_CONFLICT",
                                           "Files-list items exceed the provider count or budget.")
            next_page = _page_next(page, key, page_num, per_page)
            raw_total = page.headers.get("x-total")
            if raw_total is not None and raw_total != "":
                declared_total = int(raw_total)
                if (declared_total < len(all_files) or
                        (pagination_total is not None and declared_total != pagination_total)):
                    raise source.SourceFailure("PROVIDER_PAGINATION_INVALID",
                                               "Provider pagination totals are inconsistent.")
                pagination_total = declared_total
            if (next_page is not None and count is not None and
                    len(all_files) >= count):
                raise source.SourceFailure("PROVIDER_FILE_COUNT_CONFLICT",
                                           "Pagination continues past the claimed file total.")
            # EC164 private visitor is invoked only after EC163 validates each
            # row, path uniqueness, item count and page termination signals.
            # It must never be set by the ordinary EC163 CLI path.
            if _validated_page_observer is not None:
                _validated_page_observer(validated_page)
            if next_page is not None and not page.items:
                raise source.SourceFailure("PROVIDER_PAGINATION_INVALID",
                                           "Provider advertised a next page after an empty page.")
            if next_page is None and len(page.items) == per_page and (
                count is None or len(all_files) < count
            ):
                # Some providers omit next headers. Probe the deterministic
                # following page instead of claiming a full page is the end.
                next_page = page_num + 1
            # EC165 receives only already-validated page metadata and sanitized
            # file rows. Its optional observer never authorizes extra reads.
            if _validated_page_receipt_observer is not None:
                _validated_page_receipt_observer(
                    page_num, page, [clean for _, clean in validated_page]
                    if _validated_page_observer is not None else
                    all_files[-len(page.items):] if page.items else [], next_page)
            if next_page is None:
                last_page_reached = True
                break
            if page_num >= max_pages or len(all_files) == MAX_FILES:
                stop_reason = "PAGE_OR_FILE_BUDGET"
                break
        if not last_page_reached and stop_reason is None:
            stop_reason = "PAGE_OR_FILE_BUDGET"

        # The second EC162 observation must match the *original* EC162 pin
        # and the provider-declared file-count metadata. A push or force-push
        # in the meantime invalidates all previously collected paths.
        after, after_pin = _observation(key, True, once_token, active_transport,
                                        float(timeout), prior_pin, synthetic)
        if pin != after_pin or (
            after["provider_reported_changed_files"] != count or
            after["provider_change_count_quality"] != count_quality
        ):
            raise source.SourceFailure("FILE_COUNT_OR_PIN_DRIFT",
                                       "Provider file count or immutable pin changed during acquisition.")

        gh_ceiling = key.provider == "github" and (
            count is not None and count >= GH_PROVIDER_FILE_CEILING or
            len(all_files) >= GH_PROVIDER_FILE_CEILING
        )
        total_agrees = pagination_total is None or pagination_total == count
        complete = (last_page_reached and count_quality == "EXACT_PROVIDER_CLAIM"
                    and len(all_files) == count and total_agrees and not gh_ceiling)
        if complete:
            coverage_state, coverage_reason = "COMPLETE", "COUNT_AND_PAGINATION_AGREE"
        elif stop_reason is not None:
            coverage_state, coverage_reason = "INCOMPLETE", stop_reason
        elif gh_ceiling:
            coverage_state, coverage_reason = "INCOMPLETE", "GITHUB_3000_FILE_CEILING"
        elif count_quality in ("CAPPED_PROVIDER_CLAIM", "CAPPED_OR_UNEXPECTED_PROVIDER_CLAIM"):
            coverage_state, coverage_reason = "INCOMPLETE", "PROVIDER_COUNT_CAPPED"
        elif count is None:
            coverage_state, coverage_reason = "UNKNOWN", "PROVIDER_COUNT_NOT_AVAILABLE"
        else:
            coverage_state, coverage_reason = "INCOMPLETE", "PROVIDER_COUNT_OR_DIFF_TRUNCATED"

        if key.provider == "github":
            stats = {"additions": sum(f["additions"] for f in all_files),
                     "deletions": sum(f["deletions"] for f in all_files),
                     "source": "GITHUB_FILES_ENDPOINT",
                     "scope": "LISTED_FILES_ONLY"}
        else:
            stats = {"additions": None, "deletions": None,
                     "source": "NOT_PROVIDED_BY_GITLAB_DIFFS_ENDPOINT",
                     "scope": "LISTED_FILES_ONLY"}
        coverage = {
            "state": coverage_state,
            "reason": coverage_reason,
            "listed_files": len(all_files),
            "reported_files": count,
            "provider_count_quality": count_quality,
            "provider_pagination_total": pagination_total,
            "pages_read": pages_read,
            "last_page_reached": last_page_reached,
            "provider_patch_limited_files": patch_limited,
            "github_provider_3000_cap_reached": bool(gh_ceiling),
        }
        if complete and not synthetic:
            status, reason = "success", "PATH_LIST_COMPLETE"
        elif complete:
            status, reason = "partial", "SYNTHETIC_PATH_LIST_ONLY"
        else:
            status, reason = "partial", "PATH_LIST_NOT_PROVEN_COMPLETE"
        message = ("Bounded changed-path metadata only; no patch is emitted, "
                   "and cross-page atomic diff consistency remains unproven.")
        return _result(
            status, reason, message, synthetic=synthetic, pin=pin,
            fingerprint=identity.fingerprint_of(pin), files=all_files,
            coverage=coverage, observations=[
                before["observed_at_utc"], after["observed_at_utc"]],
            stats=stats,
        )
    except source.SourceFailure as exc:
        return _result(exc.status, exc.reason, exc.message, synthetic=synthetic)
    except Exception:
        # No raw provider content, URL, token or runtime exception is emitted.
        return _result("unavailable", "PATH_ACQUISITION_FAILED",
                       "Read-only path acquisition could not complete.", synthetic=synthetic)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="EC163 readonly PR/MR paths; separate from native CES Collect")
    parser.add_argument("--provider", required=True, choices=("github", "gitlab"))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--number", type=int, required=True)
    parser.add_argument("--expected-pin", required=True, metavar="EC162_RESULT_JSON")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--per-page", type=int, default=DEFAULT_PAGE_SIZE)
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        expected = identity._read_expected(args.expected_pin)
    except Exception:
        result = _result("invalid_input", "INVALID_EXPECTED_PIN",
                         "Previous EC162 result is unavailable or invalid.")
    else:
        result = collect_proposed_pr_paths(
            source.RequestKey(args.provider, args.repository, args.number),
            expected_pin=expected, allow_network=args.allow_network,
            timeout=args.timeout, per_page=args.per_page, max_pages=args.max_pages,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
