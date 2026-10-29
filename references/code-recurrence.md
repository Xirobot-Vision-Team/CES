# EC-015 / EC-016 — Discover recurring saved quotation anchors (read-only)

`CodeShow -Mode Recurrence` discovers **repeated exact quotation anchors in
historical, already verified CodeSave records**. Unlike Trace, the caller
need not first know a seed Finding ID. Unlike Triage, the group is the full
six-field evidence anchor, not merely the saved path. It is strictly scoped
to either one bounded **record page** or an explicitly selected, bounded
**set of 2–24 saved records** that may reside on different SHA pages. Neither
choice is a durable issue index or store-wide search; no source is reread.

## Commands

```powershell
# Discover anchors reported by at least 2 different saved records.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Recurrence -RepoPath '/absolute/main-worktree' -Json

# Narrow to exact source mode and CASE-SENSITIVE Git path; at most 5 groups.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Recurrence -RepoPath '/absolute/main-worktree' `
  -RecurrenceSourceMode working_tree_diff -RecurrencePath 'src/File.cs' `
  -RecurrenceMinRecords 2 -RecurrenceTop 5 -Limit 24 -Json

# Continue ONLY if data.has_more_candidates is true, using the exact rc1
# token from data.next_after_recurrence_cursor. Keep Top, MinRecords and
# both filters identical to those on the prior page.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Recurrence -RepoPath '/absolute/main-worktree' `
  -RecurrenceSourceMode working_tree_diff -RecurrencePath 'src/File.cs' `
  -RecurrenceMinRecords 2 -RecurrenceTop 5 -Limit 24 `
  -AfterRecurrenceCursor '<rc1 token from previous page>' -Json

# EC-016: compare real saved record IDs even across different SHA pages.
# Use ONE quoted, comma-delimited argument (replace both 64-hex values).
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow `
  -Mode Recurrence -RepoPath '/absolute/main-worktree' `
  -RecurrenceRecordIds 'ci-<first-64hex>,ci-<second-64hex>' `
  -RecurrenceMinRecords 2 -RecurrenceTop 10 -Json
```

The backtick continues a command in PowerShell and must be the last character on its line.

## Selector contract

| Parameter | Accepted values | Meaning |
|---|---|---|
| `-Mode` | `Recurrence` | Mandatory; not the default Collect mode |
| `-RepoPath` | explicit local verified main worktree | No guessing, linked/bare state or remote store |
| `-Limit` | 1–100; default 50 | **Page scan only**: maximum included records, independently capped by 24 checked candidate records; omit for selected set |
| `-RecurrenceRecordIds` | Single comma-delimited argument containing 2–24 different full lowercase `ci-<64hex>` IDs, **no spaces** | **Alternative to paging:** check exactly those saved record bodies across SHA windows; incompatible with `-Limit` and `-AfterRecurrenceCursor` |
| `-RecurrenceMinRecords` | 2–24; default 2 | An exact anchor needs that many **distinct saved record IDs in this page**, not that many Finding statements |
| `-RecurrenceTop` | 1–30; default 15 | Maximum eligible exact-anchor groups returned, with counts for omitted groups |
| `-RecurrenceSourceMode` | `working_tree_diff` or `delivered_target_diff` | Optional exact saved record mode; excluded-mode record bodies are still integrity/schema checked |
| `-RecurrencePath` | literal, nonempty, max 4096 UTF-16 chars, no NUL | Optional *case-sensitive* saved Git path; rename origins retain separate endpoints in grouping |
| `-AfterRecurrenceCursor` | `rc1-<64 lowercase hex>-ci-<64 lowercase hex>` | Optional continuation token, never a date/signed receipt |

An explicitly supplied empty filter/cursor, wrong enum case, invalid bounds,
List/Detail/Findings/Compare/Trace/Overview/Triage selector, snapshot input,
content-disclosure request or persistence permission is rejected. Recurrence
is read-only; it does **not** create a cache, mutate Git, or create the CES
state directory if it is absent. The selected-set selector refuses malformed,
duplicate, one-only, above-24 or missing IDs. No partial set is accepted
when a selected record disappears. Different saved source modes may be
selected, but their full anchors remain distinct rather than merging.

## Exact grouping and ordering

The group key concatenates six **length-prefixed, ordinal** fields:

1. Saved `source_mode`
2. Finding `layer`
3. **Case-sensitive** Finding `path`
4. `path_endpoint` (`path` vs `old_path`)
5. `quote_sha256` (quotation digest, **not quotation text**)
6. `quote_presence` (recorded literal-proof category)

Different paths, path case, layers, proof modes or source modes **never** merge.
Within one group, `reporting_record_count` counts distinct saved record IDs;
`finding_statement_count` counts all findings, including multiple same-anchor
IDs from one record. `record_occurrences[]` is sorted by ordinal saved ID,
with its `finding_ids[]` separately sorted and with a per-record strongest
reported severity. The Finding IDs can be used with `CodeShow -Mode Trace`
for an independently seed-verified, bounded exact-anchor search.

Groups are ranked within the checked page or selected set by **descending distinct reporting records**,
then **descending statements**, then **highest model-reported severity**
(critical, high, medium, low, info) and finally **ordinal exact anchor key**.
`varying_reported_severities` means the model reports attached different
severity words to the same anchor, **not** that the actual source severity
changed. `severity_statements` and `confidence_statements` preserve all the
model statements, and `highest_reported_severity` does not override them.

## Results and pagination

`data` includes `record_count`, `scanned_record_count`, `included_record_count`,
`excluded_record_count`, `records_with_findings_count` (at least one statement matching the filters),
`finding_statement_count` (only statements passing optional path/mode filters),
`distinct_exact_anchor_count` (all matching anchors, including singletons),
`eligible_anchor_count` (anchors meeting `MinRecords` in this page),
`returned_anchor_count`, `omitted_eligible_anchor_count`, `anchors[]`,
`scan_window_records=24`, `has_more_candidates`,
`next_after_recurrence_cursor` and explicit historical verification flags.
`selection_scope` states `scan_window` or `selected_record_ids`. In selected
scope, `selected_record_ids[]` is sorted ordinal, `selected_record_count`
is 2–24, `scanned_record_count` equals the requested selected count, both
cursors are null, `has_more_candidates=false` and `counts_scope` explicitly
states only selected records. `record_count` is still the entire bounded
store **filename inventory count**, not a count of read record bodies.
Excluded-mode selected bodies still pass digest and strict schema checks.

At most **24 candidate record bodies** and at most 40 Finding statements per
saved record are checked per request, even when `-Limit 100` is set. A filter
may exclude every checked record; this is **not** proof that later pages have
no matches. With `-Limit 1`, cross-record recurrence cannot be found in that
page. To see omitted groups rerun the **same window from the same cursor**
with a higher `-RecurrenceTop` (up to 30); raising Top invalidates a previously
issued continuation cursor. A cursor binds the verified main root, exact
source-mode and path filters, MinRecords and Top settings, as well as the last
scanned record ID. It does *not* freeze all record contents or authenticate
the prior page. Independent page scans **cannot** detect a repeated anchor
spanning different windows. An explicit selected record set **can** compare
chosen records from those windows, but it does not discover repeats in
unselected bodies. Neither negative page nor negative selected-set results
justify a store-wide conclusion.

Each queried candidate is read under CodeShow's content-addressed and strict
v1 JSON gates: 512-KiB file cap, exact verified root, owner marker, safe Git
boundary, at most 2,000 bounded directory entries, SHA of exact record bytes,
unique keys, schema, proof flags and a second file sample. The inventory is
rechecked after scanning and ancestor/owner types are rechecked by CodeShow.
Unvisited candidates have not been verified. An unsafe or changed record
rejects **all computed page aggregates**, not a partial ranking.

## Result codes

| Code | Meaning |
|---|---|
| `CODE_SHOW_OK` | Verified page has at least one eligible returned anchor |
| `CODE_SHOW_EMPTY` | No local CES store/records; no write |
| `CODE_SHOW_NO_MATCHES` | Valid window has no eligible group; later windows may still match |
| `CODE_SHOW_RECURRENCE_TOP_INVALID` | Top outside 1–30 |
| `CODE_SHOW_RECURRENCE_MIN_INVALID` | Distinct-record threshold outside 2–24 |
| `CODE_SHOW_RECURRENCE_FILTER_INVALID` | Bad/empty saved-mode or path filter |
| `CODE_SHOW_RECURRENCE_RECORD_IDS_INVALID` | Explicit selection has empty, malformed, duplicate or too few/many record IDs |
| `CODE_SHOW_RECURRENCE_SELECTION_CONFLICT` | Explicit selection combined with cursor or `-Limit` |
| `CODE_SHOW_NOT_FOUND` | Selected record or selected-set CES store does not exist |
| `CODE_SHOW_INVALID_RECURRENCE_CURSOR` | Empty/malformed `rc1` token |
| `CODE_SHOW_RECURRENCE_CURSOR_MISMATCH` | Token root/filter/MinRecords/Top differs |
| `CODE_SHOW_CURSOR_STALE` | Token points to a disappeared record or vanished store; partial with no accepted data |
| `CODE_SHOW_RECORD_INVALID_OR_CHANGED` | Candidate/inventory corrupt or raced; partial with no accepted data |
| `CODE_SHOW_SCAN_LIMIT` | More than 2,000 directory entries; partial with no accepted data |
| `CODE_SHOW_STORE_UNSAFE_OR_UNAVAILABLE` | Ownership/path/Git guard failure; no accepted data |

## Interpretation and privacy

This mode reveals **historical Git paths**, digest values, source mode, layer,
severity/confidence words, selected record IDs and Finding IDs. It returns no
literal source quotation, diff, file body, free-form model title/reasoning,
recommendation, or claimed line range. A hash of a short/guessable quotation
is not encrypted text and may still be guessable; review metadata before
sharing. Saved reports and their model provenance are not authenticated by
a filename digest. Repetition can reflect model repetition, copied input or
multiple reports of the same source text; it does **not** prove a genuine
bug, two independent reviewers, issue deduplication, recurrence in current
source, remediation or chronology. SHA-ID sorting is not time order.

## Deferred verification

`pwsh -NoProfile -File './tests/CodeRecurrence.Smoke.ps1'` uses an isolated
scratch repo, a real CodeSave seed and synthetic report variants to exercise
exact anchors, same-record duplicates, case/mode separation, filtering,
MinRecords/Top, 24-record windows, `rc1` binding, bad selectors, tamper
fail-closed, empty store and Git write boundaries. EC-016 extends the same
fixture for explicitly selected records across nonadjacent SHA pages,
reversed selector order, filters, minimum threshold, malformed/duplicate/
missing IDs, cursor/Limit conflicts and selected-body corruption. **Not run**
on this construction host without PowerShell 7. Actual host execution
must be recorded before declaring a native smoke PASS.
