# EC-013 / EC-018 — Saved-report Overview, with selected cross-page records

Use Overview for **high-level historical Finding counts**, not for deciding
whether a defect is real or still present. It reads the existing
`ces.code_insight_saved.v1` CodeSaved records, without rereading Git source or
emitting free-form model prose, filename paths, quote text, patches or new
state. The verified main worktree, unchanged owner marker, Git index/HEAD
boundary and full strict record-digest/schema rules from
[code-show.md](code-show.md) remain mandatory.

## Command

```powershell
# Count this page of saved model reports (all historical saved source modes).
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Overview -RepoPath '/absolute/main-worktree' -Json

# Restrict included records to the *saved* source mode (not a current Git mode).
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Overview -RepoPath '/absolute/main-worktree' `
  -OverviewSourceMode working_tree_diff -Limit 10 -Json

# When data.has_more_candidates is true, use the exact returned token and
# UNCHANGED source-mode filter. Each invocation returns its own page counts.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Overview -RepoPath '/absolute/main-worktree' `
  -OverviewSourceMode working_tree_diff -Limit 10 `
  -AfterOverviewCursor '<data.next_after_overview_cursor>' -Json
```

```powershell
# Explicitly aggregate exactly TWO to TWENTY-FOUR selected saved records
# from arbitrary SHA pages. Supply one comma-delimited argument; no Limit or
# -AfterOverviewCursor with this form.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Overview -RepoPath '/absolute/main-worktree' `
  -OverviewRecordIds 'ci-<first-64hex>,ci-<second-64hex>' `
  -OverviewSourceMode working_tree_diff -Json
```

`-OverviewRecordIds` (EC-018) accepts **2–24 distinct full lowercase
`ci-<64hex>` IDs** in one comma-separated string with no whitespace or empty
item. Obtain actual IDs from a prior `CodeShow -Mode List` or other reviewed
historical output. Inputs are sorted by ordinal ID, independent of caller
order. Selected IDs can span unrelated scan pages; no automatic cross-page
search or store-wide accumulation occurs. Every selected filename must appear
in the initial bounded inventory **before reading any selected body**;
missing ID/store yields `CODE_SHOW_NOT_FOUND` and no statistics. Every named
body must pass the existing full digest/schema/second-read checks, including
bodies subsequently rejected by the saved source-mode filter. Unselected
bodies are **not read**; the whole filename inventory and final directory
membership are still checked. A damaged selected body fails the entire
aggregation, never a partially accepted count.

Explicit selection rejects **any supplied `-Limit`, even `-Limit 50`,** and
`-AfterOverviewCursor`. It has no cursor, `limit=null`,
`has_more_candidates=false`, `scan_window_exhausted=false`, and discloses
`selection_scope=selected_record_ids`, sorted `selected_record_ids[]`,
`selected_record_count` and
`counts_scope=only_the_explicitly_selected_records_not_the_whole_store`.
`record_count` remains the number of bounded valid **filenames** in the
store, while `scanned_record_count` counts exactly the fully checked selected
bodies. `included_record_count` still applies the optional saved-mode filter.
Anchor multiplicity counters span these included selected records, not the
unselected inventory or the underlying Git source.

## Paginated mode (unchanged)

`-OverviewSourceMode` is optional. The only valid nonempty filter values are
`working_tree_diff` and `delivered_target_diff`, **case-sensitive lowercase**.
`-Limit` defaults to 50 and accepts 1–100 **included records**, but a call
reads and verifies **at most 24 candidate records**, even if Limit is 100.
A record excluded by the filter is still fully validated and consumes one
scan-window slot. Saved record IDs are sorted by byte-ordinal SHA-256 ID,
**not save time**. The cursor is a strict `oc1` token bound to the verified
root and filter, not an authenticated signature or atomic snapshot.

## Response fields

- `record_count`: number of structurally correct record **names** in the
  inventory (maximum 2,000); their unseen bodies are **not** validated.
- `scanned_record_count`, `included_record_count`, `excluded_record_count`:
  number of fully checked candidate bodies in this invocation, those admitted
  by the optional saved-mode filter, and those skipped by that filter.
- `records_with_findings_count`: included records containing at least one
  checked Finding statement. A zero-Finding record is counted in included
  records but not here.
- `finding_statement_count`: raw number of saved Finding statements in the
  included records, including repeated models on the same quotation anchor.
- `counts.source_mode_records`: number of *included records* in each saved
  mode. Other `counts` bins (`severity_statements`, `layer_statements`,
  `confidence_statements`) count **statements**, not records or issues.
- `counts.distinct_exact_anchor_count`: different exact six-component
  (`source_mode`, `layer`, case-sensitive `path`, `path_endpoint`,
  `quote_sha256`, `quote_presence`) tuples inside the **checked scope**
  (one page, or selected IDs).
- `counts.repeated_statement_anchor_count`: anchors carrying more than one
  statement inside this checked scope (including multiple IDs in one record).
- `counts.cross_record_anchor_count`: anchors reported in at least two
  different included records **within the checked scope**. A record with two
  statements on one anchor counts as one record for this metric.
- `selection_scope`, `selected_record_ids[]`, `selected_record_count`: `scan_window`
  vs `selected_record_ids`, with sorted concrete selected IDs in the latter.
- `after_overview_cursor`, `next_after_overview_cursor`,
  `has_more_candidates`, `scan_window_exhausted`, `scan_window_records`:
  navigation over **remaining candidate record names**; a page with no
  included records can still have unvisited candidates.
- `counts_scope=this_page_only_not_cumulative_or_store_wide` **for paginated mode**:
  never add individual `distinct_exact_anchor_count` values and claim that
  sum is unique across the store. Cross-page repetition is intentionally
  unmeasured. Even summing statement counts across pages is meaningful only
  if the underlying store remained unchanged, which CES cannot guarantee.
  Selected mode uses the distinct scope literal stated above; chosen records
  from different pages can be counted together, but cannot prove completeness.

All numeric buckets start at zero and exist even for a missing/empty store.
The output includes no raw original quote, path, Finding ID or model prose.
It does include the verified root and opaque SHA IDs in continuation tokens;
review metadata sensitivity before sharing.

## Fail-closed behavior

| Situation | Envelope / exit |
|---|---|
| No CES store, no cursor and no explicit selection | `CODE_SHOW_EMPTY`, success / `0`, zero-filled bins and no writer |
| No CES store or absent selected ID **with explicit selection** | `CODE_SHOW_NOT_FOUND`, invalid_input / `4`, no statistics |
| Invalid 1-ID, duplicate, whitespace, uppercase, empty, over-24 or malformed selection | `CODE_SHOW_OVERVIEW_RECORD_IDS_INVALID`, invalid_input / `4` |
| Selected IDs combined with any explicitly provided `-Limit` or an Overview cursor | `CODE_SHOW_OVERVIEW_SELECTION_CONFLICT`, invalid_input / `4` |
| Store exists but this page includes no records | `CODE_SHOW_NO_MATCHES`, success / `0`, check `has_more_candidates` |
| Unsupported source mode or explicitly empty filter | `CODE_SHOW_OVERVIEW_FILTER_INVALID`, invalid_input / `4` |
| Malformed or explicitly empty `-AfterOverviewCursor` | `CODE_SHOW_INVALID_OVERVIEW_CURSOR`, invalid_input / `4` |
| Cursor used with changed root or filter | `CODE_SHOW_OVERVIEW_CURSOR_MISMATCH`, invalid_input / `4` |
| Cursor's record no longer exists or store disappears | `CODE_SHOW_CURSOR_STALE`, partial / `2`, **no statistics** |
| Bad record, unsafe inventory, directory drift | `CODE_SHOW_RECORD_INVALID_OR_CHANGED` or `CODE_SHOW_SCAN_LIMIT`, partial / `2`, **no statistics** |
| Unsafe/tracked/unowned store | `CODE_SHOW_STORE_UNSAFE_OR_UNAVAILABLE`, unavailable / `5` |
| Record ID, Finding, Trace, Triage, Recurrence or Compare selectors supplied | `CODE_SHOW_SELECTORS_NOT_APPLICABLE`, invalid_input / `4` |

A fully checked local JSON document does not authenticate its author, confirm
original model provenance, verify claimed line ranges, certify the Finding's
meaning, prove source freshness, or prove remote/CI/release state. An exact
quotation anchor is **not** a durable defect identity. The mode does not
mutate project source, index, branches or any CES record.

## Optional scratch fixture

```powershell
pwsh -NoProfile -File './tests/CodeOverview.Smoke.ps1'
```

The suite requires PowerShell 7 and Git; it uses a temporary test repository
with one actual CodeSave seed plus explicitly synthetic, self-hashed examples.
Until run on a compatible machine it is a **pending test**, not a pass.
