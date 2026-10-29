# EC-010 / EC-020 — Bounded local and selected-record Finding search (`CodeShow -Mode Findings`)

`CodeShow -Mode Findings` is a read-only view over checked Finding metadata in
**existing** local `CodeSave` records. It does not create Findings, refresh Git
source, execute AI, authenticate authors, verify semantic claims, or run CI.
It reuses the EC-009 trusted-root/owner/Git-boundary/record-byte integrity
checks and does not open caller-supplied file paths. It never reads saved raw
source quotes, patches or untracked source bytes. **Finding reasoning, impact,
recommendation, titles and paths can still be sensitive prose.**

## CLI and examples

```powershell
# Inspect available checked Finding metadata across CodeInsight records.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow -Mode Findings `
  -RepoPath '/absolute/main-worktree' -Limit 50 -Json

# Literal, case-sensitive path and enumerated severity/layer/source filters.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow -Mode Findings `
  -RepoPath '/absolute/main-worktree' -FindingSeverity high `
  -FindingLayer unstaged -FindingPath 'src/Service.cs' `
  -FindingSourceMode working_tree_diff -Limit 20 -Json

# Repeat the exact same filters/RepoPath and pass the returned opaque token
# only when data.has_more_candidates is true.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow -Mode Findings `
  -RepoPath '/absolute/main-worktree' -FindingSeverity high `
  -FindingLayer unstaged -FindingPath 'src/Service.cs' `
  -FindingSourceMode working_tree_diff -Limit 20 `
  -AfterFindingCursor '<data.next_after_finding_cursor from prior page>' -Json

# EC-020: selected records may live on arbitrary SHA-ID scan pages.
# Pass one quoted comma-separated literal with 2..24 exact saved IDs.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow -Mode Findings `
  -RepoPath '/absolute/main-worktree' `
  -FindingsRecordIds 'ci-<first-64hex>,ci-<other-64hex>' `
  -FindingSeverity high -Limit 50 -Json
```

- `-Mode Findings` is mandatory. Optional `-Limit` is **1–100**, default 50.
  Matching rows are ordered by **record SHA-ID (ordinal ascending), then
  Finding ID (ordinal ascending)**, not severity, time, claimed code line,
  or original author order. Result rows contain source `record_id`, record
  digest, saved Collect/packet digests, `source_mode`, and one complete saved
  `finding` (ID, title, severity, confidence, layer, literal path, claimed
  lines, quote SHA-256, model reasoning/impact/recommendation). No raw quote.
- `-FindingSeverity`: `critical`, `high`, `medium`, `low`, `info`.
  `-FindingLayer`: `staged`, `unstaged`, `untracked`, `changes`.
  `-FindingSourceMode`: `working_tree_diff`, `delivered_target_diff`.
  `-FindingPath` uses an **exact case-sensitive Git path** including Unicode,
  with no wildcard expansion, filesystem traversal or normalization; up to
  4,096 characters and no NUL. Values for enum filters are exact lowercase.
  Combined filters are logical AND. No filter means include all saved Findings.
  Explicitly present but empty Finding selectors are rejected, not ignored.
- `-AfterFindingCursor` is an opaque version-1 token returned by CES. It
  includes a SHA-256 binding to the verified root and the four **exact filter
  values**, followed by a record ID and Finding ID or internal `~` end-of-record
  marker. **Copy it verbatim; do not construct or edit tokens**. A different
  root/filters returns `CODE_SHOW_FINDING_CURSOR_MISMATCH`. A malformed cursor
  returns `CODE_SHOW_INVALID_FINDING_CURSOR`. A cursor referring to a record
  or Finding no longer present returns `partial / CODE_SHOW_CURSOR_STALE`.
  A digest is NOT a signature or proof that a cursor originated from CES.
- Findings forbids `-LeftRecordId`, `-RightRecordId`, `-RecordId`, `-AfterRecordId` and all source, content,
  evidence, draft and persistence selectors. List/Detail refuse every
  Finding-only selector. Other CES Actions also refuse them. No flags are
  accepted and silently ignored.

## EC-020 explicit saved-record selection

`-FindingsRecordIds` takes **one** strict comma-delimited string with **2–24
unique full lowercase** `ci-<64 hex>` IDs. No spaces, uppercase, empty
pieces, abbreviations or duplicate IDs are accepted. The requested records
can be anywhere in the 2,000-name bounded SHA inventory; the selection and
matching rows are always sorted by **ordinal ID**, not argument order or
time. The existing four Finding filters use exactly the same meaning in
either scope. `-RecordId` / `-AfterRecordId` are never compatible with
Findings. **Any explicitly supplied `-AfterFindingCursor` conflicts** with
the selected set, even an empty value; the `fc1` cursor is for the original
unselected scan route only.

Selected mode **retains `-Limit 1..100` (default 50) as an output row cap**:
every selected record is fully validated and **every matching Finding is
counted**, including those beyond the returned cap. Report
`matched_finding_count = returned_count + omitted_matching_count`, plus
`results_truncated`. The first `-Limit` matching rows are returned in stable
record-ID/Finding-ID order. There is **no selected-set cursor**:
`after_finding_cursor=null`, `next_after_finding_cursor=null`, and
`has_more_candidates=false`. A truncated result is **not a complete returned
match listing**; it is a complete *count of matches in the exact selected
set*. To inspect other rows, refine filters or name a smaller subset, and
never interpret a selected set as a whole-store search.

`selection_scope=selected_record_ids`, `selected_record_ids[]` (ordinal),
`selected_record_count`, and
`counts_scope=only_the_explicitly_selected_records_not_the_whole_store`
distinguish selected from original `selection_scope=scan_window` mode.
`record_count` is the **entire filename inventory**, not the number of
records whose bytes were checked; `scanned_record_count` is **exactly the
number of selected bodies**, and `scanned_finding_count` counts their checked
Finding statements before filters. Selected `scan_window_records` is null;
the original page retains its 32-record window. Page mode does not know an
all-page `matched_finding_count` and reports it as null.

All requested IDs must be present in the first fully enumerated inventory
**before any selected body is opened**. Then **all and only** chosen record
bodies pass full v1 schema, 512-KiB/strict UTF-8, exact SHA-name, second-read
checks, including filtered-out source modes and zero-Finding records. CES
checks inventory membership a second time, ancestor file types and owner
bytes after scanning. Missing IDs or absent store in selected mode produce
`invalid_input / CODE_SHOW_NOT_FOUND` with `data=null`; bad selected records
or inventory mutation produce `partial` with **no accepted result**. Unsafe
owner/tracked boundaries remain `unavailable`. An unselected corrupt *body*
is not read and cannot turn a selected query into an all-store claim. Like
paging, this is not an atomic snapshot, authenticated history or fresh
source/Issue check.

## Work and output bounds

The store directory inventory is limited to **2,000 entries** and each saved
record to **512 KiB**. A paginated call parses and SHA-checks at most **32 records**;
an EC-020 selected call checks **2–24 explicitly chosen records**.
Both count included and filter-excluded saved records, each with at most
40 Findings. The emitted results never exceed `-Limit` (maximum 100). The output envelope
is still `ces.cli.v1`; `read_only=true`, `next_step=none`.

`data` includes `findings[]`, `returned_count`, `record_count`,
`scanned_record_count`, `scanned_finding_count`, `scan_window_records=32`,
`scan_window_exhausted`, `filters`, `after_finding_cursor`,
`next_after_finding_cursor`, `has_more_candidates`, and explicit false flags
for author attribution, semantics, source revalidation and atomicity.
`record_count` counts matching record filenames **not all integrity-checked
records**; digest/schema checks cover only the actual scan window.

**Do not treat a zero-result page as a complete negative search until
`has_more_candidates=false`.** An empty page may exhaust the 32-record scan
window without finding a match. Keep fetching with the returned cursor until
`has_more_candidates` is false. Conversely, `has_more_candidates=true` means
**unvisited candidates are possible**, not a guarantee of more matching rows:
a page that hit the output limit may need one additional empty page to detect
completion. `next_after_finding_cursor` is null only on full exhaustion.

A missing local CES store returns `CODE_SHOW_EMPTY` without creating one.
With a valid store and a fully checked page containing zero matches, status is
`success / CODE_SHOW_NO_MATCHES` even when more candidate records remain;
inspect `has_more_candidates`. With one or more matches status is
`success / CODE_SHOW_OK`. An integrity, schema or directory drift failure
returns `partial` with **no accepted `data`**, not a partial list. A stale
cursor likewise fails closed. Source files, Git index and branches remain
untouched.

## Security and non-guarantees

Before reading, CES verifies a real HEAD, independently verified main Git
worktree, untracked CES ownership boundary (index/HEAD, including Windows
case aliases), exact owner bytes, and ordinary non-reparse directory/file
types. Each scanned record must pass strict UTF-8/JSON, complete v1 schema,
root binding, per-file SHA-256 and second-byte-read checks. Directory entry
membership and owner/ancestor types are sampled again before success.

A cursor is bound to filters, **not a stable historical snapshot**. Manual
additions/deletions/edits between pages can alter search results or invalidate
a cursor. A malicious writer that can forge record bytes and SHA-ID can
fabricate metadata; even a valid Finding is not an authenticated, fresh,
line-verified, semantically proven defect. Recorded paths are local data, not
safe commands to execute. The 32-record window does not provide global
assurance about unseen records. EC-012 `CodeShow -Mode Trace` can search the exact saved anchor from a selected Finding across many local records, but neither mode authenticates an Issue relationship. This is neither a full Finding relationship
database nor a deduplicator: the same observation in two different records
appears twice with separate record IDs.

## Exit/reason summary

| Reason code | Exit/status | Interpretation |
|---|---|---|
| `CODE_SHOW_OK` | `0 / success` | Checked page with one or more Matching Findings |
| `CODE_SHOW_NO_MATCHES` | `0 / success` | Checked current page, no matches; inspect `has_more_candidates` |
| `CODE_SHOW_EMPTY` | `0 / success` | CES store absent or contains no records |
| `CODE_SHOW_FINDING_FILTER_INVALID` | `4 / invalid_input` | Unknown/empty enum, empty selector or invalid literal path |
| `CODE_SHOW_FINDINGS_RECORD_IDS_INVALID` | `4 / invalid_input` | Selected IDs malformed, duplicate, wrong case, outside 2..24 or empty |
| `CODE_SHOW_FINDINGS_SELECTION_CONFLICT` | `4 / invalid_input` | Explicit saved IDs supplied with any `AfterFindingCursor` |
| `CODE_SHOW_NOT_FOUND` | `4 / invalid_input` | Selected record ID missing or no store for selected query |
| `CODE_SHOW_INVALID_FINDING_CURSOR` | `4 / invalid_input` | Malformed opaque cursor token |
| `CODE_SHOW_FINDING_CURSOR_MISMATCH` | `4 / invalid_input` | Cursor filter tuple or repository root changed |
| `CODE_SHOW_CURSOR_STALE` | `2 / partial` | Cursor references a missing saved record/Finding |
| `CODE_SHOW_SELECTORS_NOT_APPLICABLE` | `4 / invalid_input` | Other mode's selectors, source controls or invalid limit |
| `CODE_SHOW_RECORD_INVALID_OR_CHANGED` | `2 / partial` | Saved record or directory sample cannot be verified |
| `CODE_SHOW_SCAN_LIMIT` | `2 / partial` | Store directory enumeration exceeds 2,000 entries |
| `CODE_SHOW_MAIN_WORKTREE_REQUIRED` | `2 / partial` | Main worktree/stable HEAD not verified |
| `CODE_SHOW_STORE_UNSAFE_OR_UNAVAILABLE` | `5 / unavailable` | Unsafe, tracked, corrupt-owner or unreadable CES store boundary |

For an exact historical two-record quotation-anchor comparison (rather
than this bounded store-wide filter), see [code-compare.md](code-compare.md).
It never asserts that a Finding absent on one side was fixed.

## Deferred manual fixture

```powershell
pwsh -NoProfile -File './tests/CodeFindings.Smoke.ps1'
```

The fixture tests real CodeSave records, filter combination, ordinal
pagination, filter-bound cursor reuse rejection, Unicode case-sensitive path
matching, a zero-Finding record, 32-record no-match continuation, stale cursor,
selected cross-page 2/24-record traversal, exact omitted row totals, malformed
IDs/conflicting selectors, missing-before-body membership checks, corrupted
selected vs unselected body behavior, absent-state read-only behavior and
Git HEAD/index non-mutation. It must only be marked passed after a real PowerShell 7 + Git
execution; the source archive alone cannot prove runtime behavior.
