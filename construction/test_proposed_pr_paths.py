#!/usr/bin/env python3
"""EC163 focused offline development checks; all provider payloads synthetic."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

import proposed_pr_source as source
import proposed_pr_identity as identity
import proposed_pr_paths as paths

HERE = Path(__file__).resolve().parent
F = HERE / "fixtures"


def metadata(provider: str, count: int | str | None) -> dict:
    raw = json.loads((F / "provider_metadata" / f"{provider}.synthetic.json").read_text("utf-8"))
    if count is not None:
        raw["changed_files" if provider == "github" else "changes_count"] = count
    return raw


def file_rows(provider: str) -> list:
    suffix = ("github.synthetic.files.json" if provider == "github"
              else "gitlab.synthetic.diffs.json")
    return json.loads((F / "changed_files" / suffix).read_text("utf-8"))


class Transport:
    def __init__(self, metadata_reads: list[dict], pages: list[paths.FilePage]) -> None:
        self.metadata_reads = copy.deepcopy(metadata_reads)
        self.pages = copy.deepcopy(pages)
        self.calls: list[str] = []

    def get_object(self, url, headers, timeout):
        self.calls.append("META")
        if not self.metadata_reads:
            raise RuntimeError("unexpected metadata request")
        return self.metadata_reads.pop(0)

    def get_page(self, url, headers, timeout):
        self.calls.append("PAGE:" + url.split("page=")[1].split("&")[0])
        if not self.pages:
            raise RuntimeError("unexpected file page")
        return self.pages.pop(0)


def page(entries: list, *, link: str = "", next_page: str = "",
         provider: str = "github", byte_count: int = 200) -> paths.FilePage:
    headers = {}
    if link:
        headers["link"] = link
    if provider == "gitlab":
        headers["x-next-page"] = next_page
    return paths.FilePage(copy.deepcopy(entries), headers, byte_count)


def gh_link(n: int, per_page: int) -> str:
    return (f'<https://api.github.com/repos/example/repo/pulls/8/files?'
            f'per_page={per_page}&page={n}>; rel="next"')


def prior(provider: str, count: int | str | None, target: dict | None = None) -> dict:
    key = source.RequestKey(
        provider, "example/repo" if provider == "github" else "my-group/sub-group/repo", 8)
    tx = Transport([metadata(provider, count) if target is None else target], [])
    result = identity.confirm_proposed_pr_identity(
        key, allow_network=True, transport=tx,
        token_supplier=lambda: "SYNTHETIC-NOT-REAL",
    )
    assert result["pin"] is not None
    return result


def collect(provider="github", count=None, file_pages=None, *, prior_result=None,
            before=None, after=None, allow_network=True, per_page=100, max_pages=30):
    if count is None:
        count = 3 if provider == "github" else "2"
    key = source.RequestKey(
        provider, "example/repo" if provider == "github" else "my-group/sub-group/repo", 8)
    p = prior_result if prior_result is not None else prior(provider, count)
    a = metadata(provider, count) if before is None else before
    b = metadata(provider, count) if after is None else after
    tx = Transport([a, b], file_pages if file_pages is not None else [
        page(file_rows(provider), provider=provider)])
    out = paths.collect_proposed_pr_paths(
        key, expected_pin=p, allow_network=allow_network, transport=tx,
        token_supplier=lambda: "SYNTHETIC-NOT-REAL",
        per_page=per_page, max_pages=max_pages,
    )
    return out, tx


class Ec163PathsTests(unittest.TestCase):
    def test_requires_previous_ec162_pin_before_credentials(self):
        key = source.RequestKey("github", "example/repo", 8)
        out = paths.collect_proposed_pr_paths(
            key, expected_pin=None, allow_network=True,
            token_supplier=lambda: self.fail("token consulted without pin"))
        self.assertEqual((out["status"], out["reason_code"]), ("invalid_input", "EXPECTED_PIN_REQUIRED"))

    def test_offline_stops_before_credentials_and_pages(self):
        out, tx = collect(allow_network=False)
        self.assertEqual((out["status"], out["exit_code"]), ("unavailable", 5))
        self.assertEqual(out["reason_code"], "NETWORK_NOT_AUTHORIZED")
        self.assertEqual(tx.calls, [])

    def test_github_paths_counts_rename_and_patch_never_returned(self):
        out, tx = collect()
        self.assertEqual(out["status"], "partial")  # fixture can never impersonate live
        self.assertEqual(out["reason_code"], "SYNTHETIC_PATH_LIST_ONLY")
        self.assertEqual(out["coverage"]["state"], "COMPLETE")
        self.assertEqual(out["coverage"]["listed_files"], 3)
        self.assertEqual(out["line_stats"]["additions"], 10)
        self.assertEqual(out["line_stats"]["deletions"], 3)
        self.assertEqual(out["files"][1]["old_path"], "src/old.py")
        self.assertEqual(out["files"][1]["new_path"], "src/renamed.py")
        self.assertEqual(out["files"][2]["old_path"], None)
        self.assertEqual(tx.calls, ["META", "PAGE:1", "META"])
        rendered = json.dumps(out)
        self.assertNotIn("SECRET_PATCH", rendered)
        self.assertNotIn("raw_url", rendered)
        self.assertFalse(out["patch_content_collected"])
        self.assertFalse(out["diff_snapshot_proven"])
        self.assertFalse(out["write_authorized"])

    def test_gitlab_renames_and_patch_limited_not_fake_stats(self):
        out, tx = collect("gitlab")
        self.assertEqual(out["coverage"]["state"], "COMPLETE")
        self.assertEqual(out["coverage"]["provider_patch_limited_files"], 1)
        self.assertEqual(out["files"][0]["status"], "renamed")
        self.assertEqual(out["files"][0]["old_path"], "lib/old.py")
        self.assertIsNone(out["files"][0]["additions"])
        self.assertIsNone(out["line_stats"]["deletions"])
        self.assertNotIn("SECRET_DIFF", json.dumps(out))
        self.assertEqual(tx.calls, ["META", "PAGE:1", "META"])

    def test_multipage_next_link_is_verified_not_followed(self):
        rows = file_rows("github")
        out, tx = collect(
            file_pages=[page(rows[:2], link=gh_link(2, 2)), page(rows[2:])],
            per_page=2)
        self.assertEqual(out["coverage"]["state"], "COMPLETE")
        self.assertEqual(out["coverage"]["pages_read"], 2)
        self.assertEqual(tx.calls, ["META", "PAGE:1", "PAGE:2", "META"])

    def test_full_page_without_link_probe_when_count_not_fulfilled(self):
        rows = file_rows("github")
        out, tx = collect(
            file_pages=[page(rows[:2]), page(rows[2:])],
            per_page=2)
        self.assertEqual(out["coverage"]["state"], "COMPLETE")
        self.assertEqual(tx.calls, ["META", "PAGE:1", "PAGE:2", "META"])

    def test_pagination_budget_returns_partial_not_complete(self):
        rows = file_rows("github")
        out, tx = collect(
            file_pages=[page(rows[:1], link=gh_link(2, 1))],
            max_pages=1, per_page=1)
        self.assertEqual(out["coverage"]["state"], "INCOMPLETE")
        self.assertEqual(out["coverage"]["reason"], "PAGE_OR_FILE_BUDGET")
        self.assertEqual(out["status"], "partial")
        self.assertEqual(out["coverage"]["listed_files"], 1)
        self.assertEqual(tx.calls, ["META", "PAGE:1", "META"])

    def test_number_without_page_results_is_not_zero_changes(self):
        out, _ = collect(file_pages=[page([])])
        self.assertEqual(out["coverage"]["state"], "INCOMPLETE")
        self.assertEqual(out["coverage"]["listed_files"], 0)
        self.assertEqual(out["coverage"]["reported_files"], 3)

    def test_count_absent_never_complete_even_with_page_termination(self):
        rows = file_rows("github")
        out, _ = collect(count=3, prior_result=prior("github", None),
                         before=metadata("github", None),
                         after=metadata("github", None),
                         file_pages=[page(rows)])
        self.assertEqual(out["coverage"]["state"], "UNKNOWN")
        self.assertEqual(out["coverage"]["reason"], "PROVIDER_COUNT_NOT_AVAILABLE")

    def test_gl_1000_plus_is_count_capped_not_exact(self):
        out, _ = collect("gitlab", count="1000+")
        self.assertEqual(out["coverage"]["state"], "INCOMPLETE")
        self.assertEqual(out["coverage"]["reason"], "PROVIDER_COUNT_CAPPED")

    def test_github_3000_provider_ceiling_never_claims_complete(self):
        rows = file_rows("github")
        out, _ = collect(count=3000, file_pages=[page(rows)])
        self.assertEqual(out["coverage"]["state"], "INCOMPLETE")
        self.assertEqual(out["coverage"]["listed_files"], 3)

    def test_count_change_during_read_invalidates_all_paths(self):
        out, tx = collect(after=metadata("github", 4))
        self.assertEqual((out["status"], out["reason_code"]),
                         ("unavailable", "FILE_COUNT_OR_PIN_DRIFT"))
        self.assertEqual(out["files"], [])
        self.assertEqual(out["coverage"]["state"], "NOT_COLLECTED")
        self.assertEqual(tx.calls, ["META", "PAGE:1", "META"])

    def test_ec162_head_drift_before_page_suppresses_paths(self):
        changed = metadata("github", 3)
        changed["head"]["sha"] = "d" * 40
        out, tx = collect(before=changed)
        self.assertEqual(out["status"], "unavailable")
        self.assertEqual(out["reason_code"], "PIN_DRIFT_HEAD_SHA_CHANGED")
        self.assertEqual(tx.calls, ["META"])

    def test_ec162_head_drift_after_page_suppresses_paths(self):
        changed = metadata("github", 3)
        changed["head"]["sha"] = "d" * 40
        out, tx = collect(after=changed)
        self.assertEqual(out["status"], "unavailable")
        self.assertEqual(out["reason_code"], "PIN_DRIFT_HEAD_SHA_CHANGED")
        self.assertEqual(out["files"], [])
        self.assertEqual(tx.calls, ["META", "PAGE:1", "META"])

    def test_other_locator_pin_rejected_before_network(self):
        p = prior("gitlab", "1")
        out, tx = collect(prior_result=p)
        self.assertEqual((out["status"], out["reason_code"]),
                         ("invalid_input", "EXPECTED_PIN_LOCATOR_MISMATCH"))
        self.assertEqual(tx.calls, [])

    def test_corrupt_pin_fingerprint_rejected(self):
        p = prior("github", 3)
        p["pin_fingerprint"] = "sha256:" + "0" * 64
        out, tx = collect(prior_result=p)
        self.assertEqual(out["reason_code"], "INVALID_EXPECTED_PIN")
        self.assertEqual(tx.calls, [])

    def test_provenance_mixing_rejected(self):
        real_shaped = prior("github", 3)
        real_shaped["synthetic"] = False
        out, tx = collect(prior_result=real_shaped)
        self.assertEqual(out["reason_code"], "PIN_PROVENANCE_CHANGED")
        self.assertEqual(tx.calls, [])

    def test_duplicate_path_conflict_discard_all(self):
        rows = file_rows("github")
        out, _ = collect(count=4, prior_result=prior("github", 4),
                         file_pages=[page(rows + [rows[0]])])
        self.assertEqual(out["reason_code"], "PROVIDER_PATH_CONFLICT")
        self.assertEqual(out["files"], [])

    def test_conflicting_add_delete_rename_flags_fail(self):
        rows = file_rows("gitlab")
        rows[0]["deleted_file"] = True
        out, _ = collect("gitlab", file_pages=[page(rows, provider="gitlab")])
        self.assertEqual(out["reason_code"], "PROVIDER_FILE_STATUS_CONFLICT")

    def test_safe_path_blocks_escape_and_windows_spelling(self):
        for bad in ("../secrets", "a/./b", "/etc/passwd", "C:/file",
                    "path\\evil", "file\nname", "aux.txt", "a//b", "dir/"):
            with self.subTest(path=bad):
                rows = file_rows("github")
                rows[0]["filename"] = bad
                out, _ = collect(file_pages=[page(rows)])
                self.assertEqual(out["reason_code"], "PROVIDER_PATH_UNSAFE")
                self.assertEqual(out["files"], [])

    def test_casefold_collision_is_conservative(self):
        rows = file_rows("github")
        rows[2]["filename"] = "SRC/SERVICE.PY"
        out, _ = collect(file_pages=[page(rows)])
        self.assertEqual(out["reason_code"], "PROVIDER_PATH_CONFLICT")

    def test_gh_invalid_line_stats_rejected(self):
        rows = file_rows("github")
        rows[0]["changes"] += 1
        out, _ = collect(file_pages=[page(rows)])
        self.assertEqual(out["reason_code"], "PROVIDER_FILE_STATS_CONFLICT")

    def test_gl_headers_paginate_and_validate_next(self):
        rows = file_rows("gitlab")
        out, tx = collect("gitlab", file_pages=[
            page(rows[:1], next_page="2", provider="gitlab"),
            page(rows[1:], next_page="", provider="gitlab")], per_page=1)
        self.assertEqual(out["coverage"]["state"], "COMPLETE")
        self.assertEqual(tx.calls, ["META", "PAGE:1", "PAGE:2", "META"])

    def test_malicious_link_not_followed(self):
        rows = file_rows("github")
        link = '<https://attacker.example/steal?page=2&per_page=2>; rel="next"'
        out, tx = collect(file_pages=[page(rows[:2], link=link)], per_page=2)
        self.assertEqual(out["reason_code"], "PROVIDER_PAGINATION_INVALID")
        self.assertEqual(tx.calls, ["META", "PAGE:1"])

    def test_duplicate_json_keys_fail_decoder(self):
        with self.assertRaises(source.SourceFailure) as caught:
            paths._decode_array(b'[{"filename":"a","filename":"b"}]')
        self.assertEqual(caught.exception.reason, "PROVIDER_PAYLOAD_INVALID")

    def test_metadata_count_validation(self):
        self.assertEqual(source._reported_change_count({"changes_count": "1000+"}, "gitlab"),
                         (None, "CAPPED_PROVIDER_CLAIM"))
        self.assertEqual(source._reported_change_count({"changes_count": ""}, "gitlab"),
                         (None, "NOT_REPORTED"))
        for bad in (True, -1, "5"):
            with self.subTest(value=bad), self.assertRaises(source.SourceFailure):
                source._reported_change_count({"changed_files": bad}, "github")
        with self.assertRaises(source.SourceFailure):
            source._reported_change_count({"changes_count": "2e3"}, "gitlab")

    def test_invalid_page_budget_before_network(self):
        key = source.RequestKey("github", "example/repo", 8)
        result = paths.collect_proposed_pr_paths(
            key, expected_pin=prior("github", 3), allow_network=True, per_page=101,
            token_supplier=lambda: self.fail("token read despite invalid page budget"))
        self.assertEqual((result["status"], result["reason_code"]),
                         ("invalid_input", "INVALID_PAGE_BUDGET"))

    def test_gl_patch_metadata_is_not_content_available(self):
        out, _ = collect("gitlab")
        self.assertFalse(out["patch_content_collected"])
        self.assertGreater(out["coverage"]["provider_patch_limited_files"], 0)
        self.assertIsNone(out["line_stats"]["additions"])

    def test_synthetic_full_coverage_never_live_success(self):
        out, _ = collect()
        self.assertEqual(out["status"], "partial")
        self.assertTrue(out["synthetic"])
        self.assertTrue(out["path_metadata_collected"])
        self.assertFalse(out["delivery_or_merge_proven"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
