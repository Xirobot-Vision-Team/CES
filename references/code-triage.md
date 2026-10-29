# EC-014 / EC-017 — Saved Finding file triage (`CodeShow -Mode Triage`)

`Triage` ranks exact saved Git path groups by historical model-reported
Finding severity, either in **one 24-candidate-record scan page** or an
explicitly chosen **2–24-record selection across SHA pages**.
It is a read-only view of existing `ces.code_insight_saved.v1` records,
**not** a source scan, security-risk assessment, verified defect register,
current-file existence test, issue/fix chronology or store-wide top list.

It inherits CodeShow's verified main Git worktree/HEAD, CES owner marker,
tracked-path and reparse-point safety rules, SHA-256 filename-to-byte equality,
strict JSON and saved record schema verification, late owner recheck, bounded
inventory and read-only execution. No Git branches/index/source content or CES
state is written.

## Commands

```powershell
# Rank historical model-reported file groups in the first verified page.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Triage -RepoPath '/absolute/main-worktree' -TriageTop 15 -Json

# Only working-tree reports: rank up to 5 file groups in a 10-record page.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Triage -RepoPath '/absolute/main-worktree' `
  -TriageSourceMode working_tree_diff -Limit 10 -TriageTop 5 -Json

# Advance to unvisited candidate record names with EXACTLY the same
# TriageSourceMode and TriageTop settings. Do not reuse the token across roots.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Triage -RepoPath '/absolute/main-worktree' `
  -TriageSourceMode working_tree_diff -Limit 10 -TriageTop 5 `
  -AfterTriageCursor '<data.next_after_triage_cursor>' -Json

# EC-017: explicitly compare stored record IDs from different SHA pages.
# Use one quoted comma-delimited string and OMIT both -Limit and the cursor.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Triage -RepoPath '/absolute/main-worktree' `
  -TriageRecordIds 'ci-<first-64hex>,ci-<second-64hex>' `
  -TriageSourceMode working_tree_diff -TriageTop 10 -Json
```

`-Limit` defaults to 50 (allowed range 1–100) and caps **included records**,
not Finding statements or returned file groups. Regardless of that limit,
**no more than 24 candidate records** are read and schema/digest-verified per
invocation. A filtered-out source mode still consumes one checked candidate.
`-TriageTop` defaults to 15 (allowed range 1–30) and caps the **highest-ranked
file groups returned** from this window. Only the historical saved source
mode values `working_tree_diff` and `delivered_target_diff` are accepted as
optional `-TriageSourceMode` filters. Values are case-sensitive and nonempty
when supplied. Selectors from other CodeShow modes are forbidden.

### EC-017: selected-record contract

- `-TriageRecordIds` must be **one comma-separated native-shell-safe
  argument** containing 2–24 unique, full lowercase `ci-<64hex>` IDs,
  without spaces. ID order is normalized with ordinal sorting; IDs can come
  from *different* pages of `List` or other historical review results.
- The selected option is disjoint from both `-Limit` and
  `-AfterTriageCursor`, including an explicitly supplied default Limit of 50.
  Top and exact saved source-mode filter continue to apply; there is no
  `tg1` token or next cursor for the selected set.
- CES checks the complete bounded filename inventory (2,000 maximum),
  confirms **every** ID exists before any selected body is read, and verifies
  every selected file's safe type, SHA/strict v1 schema and stable second read
  before accepting ranked data. A source-mode-excluded selected record is
  *still fully checked*. Unselected record bodies are never read.
- Outputs mark `selection_scope=selected_record_ids`, sorted
  `selected_record_ids[]`, `selected_record_count`, and
  `counts_scope=only_the_explicitly_selected_records_not_the_whole_store`.
  For a selected set, `limit=null`, all cursor fields null,
  `has_more_candidates=false`, and `scan_window_exhausted=false`. The normal
  paged path remains `selection_scope=scan_window`, with `selected_record_ids=[]`
  and page-only counters. `record_count` always counts matching filenames in
  the bounded inventory, **not** all integrity-checked bodies.
- Historical selected paths can be aggregated across different SHA-ID pages,
  but neither SHA order nor model severity proves a date, trend, real issue,
  fix, present source or store-wide ranking. Re-select a different 2–24 ID set
  for another comparison; there is no automatic cumulative merge.

## Group identity, measures and ranking

A file group is the exact triple `(saved source_mode, Git path string,
path_endpoint)`. Paths are **case-sensitive** and remain distinct from their
old-path rename endpoints. Source modes never combine, and separate Git
layers are retained in each group's counters. This key is deliberately less
strict than Compare/Trace's six-field quotation anchor: **several different
quotes and multiple model statements can belong to one path group**.

Each `path_groups[]` entry includes:

- `source_mode`, `path_exact` and `path_endpoint`: literal saved metadata;
  path values may be sensitive even without source code.
- `highest_reported_severity`: the most severe **model-reported statement**
  among this group's included checked records.
- `reporting_record_count`: number of **distinct saved records** in this
  verified scan window or selected set mentioning that exact group (multiple
  statements from one record still count as one).
- `reporting_record_ids`: sorted full IDs of the checked records that
  contributed to this path group, enabling later explicit `Detail` review.
- `finding_statement_count`: number of saved Finding statements on the path
  group in the same page (duplicates are deliberately included).
- `distinct_exact_anchor_count`: unique six-field quotation evidence tuples
  for statements in the group, **within this bounded chosen scope**.
- `cross_record_exact_anchor_count`: those exact anchors seen in at least two
  *different saved record IDs* within the checked scope, not duplicate statements in one
  report and not a confirmed recurring defect.
- `severity_statements`, `layer_statements`, `confidence_statements`:
  explicit zero-filled statement bins.

Ranking is deterministic, in this priority order: **critical → high → medium
→ low → info**, then decreasing distinct reporting-record count, then
decreasing statement count, then ordinal, unambiguous length-prefixed group
key. This is a *review queue heuristic*, not a derived likelihood or risk
score. A self-consistent saved record can still contain inaccurate model
claims. Equal-severity paths do not imply equal real-world impact.

The response also reports `record_count` (safe filenames in the whole
inventory, **not validated unseen bodies**), `scanned_record_count`,
`included_record_count`, `excluded_record_count`, `records_with_findings_count`,
`finding_statement_count`, `path_group_count` (total unique path groups among
included records **in the current page or selection**), `returned_group_count`, and
`omitted_group_count`. `TriageTop` never causes unread groups from the current
page to disappear from those totals. Crucially, omitted group detail is **not
retrievable by a record cursor**, which moves to the NEXT record window;
increase `-TriageTop` and rerun the **same page** to see more groups (up to
30), or use `Findings` for full row-level analysis. As with all paged scans,
the store is not atomically frozen and local bytes may change between pages.

`next_after_triage_cursor` is present only when unvisited candidate record
names exist, even if no included records or groups appeared on this page.
The `tg1` cursor includes a SHA-256 discriminator for the verified root,
exact source-mode filter and `TriageTop`, plus the last scanned record ID;
it is **not a signed token or a cross-page snapshot**. Cursor membership is
checked against the current inventory. SHA record name sorting does not
represent time ordering. `scan_window_exhausted` distinguishes a 24-record
window from reaching the record inclusion limit.

## Privacy, coverage and fail-closed codes

Triage discloses **exact historical Git paths**, source modes, rename
endpoints and aggregate counts. It does **not** return original quotes,
patches, source file contents, line intervals, free-form Finding titles,
reasoning, summaries, impacts or recommendations. Treat path names as
potentially private before sharing. It does not confirm current source, an
actual vulnerability, authenticated model origin, remote PR, CI or deployment.

| Scenario | Envelope / exit |
|---|---|
| No CES-owned local store, no cursor or selected set | `success / CODE_SHOW_EMPTY / 0` with empty ranked groups; no writes |
| Selected IDs but no store, or any requested ID absent | `invalid_input / CODE_SHOW_NOT_FOUND / 4` with no data |
| Malformed, duplicate, empty, nonlowercase, single or over-24 selected IDs | `invalid_input / CODE_SHOW_TRIAGE_RECORD_IDS_INVALID / 4` |
| Selected IDs combined with explicit `-Limit` or Triage cursor | `invalid_input / CODE_SHOW_TRIAGE_SELECTION_CONFLICT / 4` |
| Scan page yields zero groups | `success / CODE_SHOW_NO_MATCHES / 0`; `has_more_candidates` may still be true |
| Explicitly empty or unsupported mode filter | `invalid_input / CODE_SHOW_TRIAGE_FILTER_INVALID / 4` |
| `-TriageTop` outside 1–30 | `invalid_input / CODE_SHOW_TRIAGE_TOP_INVALID / 4` |
| Malformed or explicitly empty cursor | `invalid_input / CODE_SHOW_INVALID_TRIAGE_CURSOR / 4` |
| Cursor used with another root, mode or `TriageTop` | `invalid_input / CODE_SHOW_TRIAGE_CURSOR_MISMATCH / 4` |
| Cursor record removed or store disappears | `partial / CODE_SHOW_CURSOR_STALE / 2`, no ranking |
| Tampered/schema-invalid/changed saved record or inventory | `partial / CODE_SHOW_RECORD_INVALID_OR_CHANGED / 2`, no ranking |
| Inventory above 2,000 or bounded scan failure | `partial / CODE_SHOW_SCAN_LIMIT / 2` or record invalid, no ranking |
| Unsafe/unowned/tracked/colliding state boundary | `unavailable / CODE_SHOW_STORE_UNSAFE_OR_UNAVAILABLE / 5` |
| Cross-mode/unrelated selectors or wrong limit | `invalid_input / CODE_SHOW_SELECTORS_NOT_APPLICABLE / 4` |

Other CodeShow selectors, `-IncludePatches`, source evidence, write consent
switches and arbitrary paths as filenames are never accepted by Triage.

## Deferred host smoke suite

```powershell
pwsh -NoProfile -File './tests/CodeTriage.Smoke.ps1'
```

The independent scratch-fixture exercises a real authorized CodeSave seed and
synthetic hashed saved records, including Unicode/case-sensitive paths,
rename endpoints, severity ordering, statement versus record counts,
truncated Top, source mode filtering, cursor binding and invalidation,
24-record windows, EC-017 cross-page selected-set aggregation, exact
source-mode filtering and checked excluded bodies, selected corruption,
malformed/missing/duplicate/over-limit sets and cursor conflicts, corrupt
inventories, Git HEAD/index non-mutation and source-text disclosure limits.
It is **not passed** until run under
PowerShell 7/Git on an approved host.
