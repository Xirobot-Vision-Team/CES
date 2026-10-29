# EC-009 — Read-only local CodeInsight discovery (`CodeShow`)

`CodeShow` reads **already saved** `ces.code_insight_saved.v1` records from an
explicit, independently verified **main Git worktree**. It introduces no
persistent state, arbitrary path access, source refresh, model call, report
publication or remote lookup. No read mode requests `-ApprovePersist` or
source-disclosure switches. `CodeSave` remains the only local state writer.

## List and Detail

```powershell
# Bounded record inventory; always pass an explicit -Mode.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow -Mode List `
  -RepoPath '/absolute/main-worktree' -Limit 50 -Json

# Continue only if data.has_more is true, passing data.next_after_record_id.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow -Mode List `
  -RepoPath '/absolute/main-worktree' -Limit 50 `
  -AfterRecordId 'ci-<64 lowercase hex of the last returned record>' -Json

# View full saved summary, limitations and checked findings for a single ID.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow -Mode Detail `
  -RepoPath '/absolute/main-worktree' -RecordId 'ci-<64 lowercase hex>' -Json
```

- `List`: `-Limit` is optional, default **50**, allowed **1–100**. It reads no
  unbounded content and returns a stable **ordinal/ascending SHA-256 ID** order
  (not chronological order). Optional `-AfterRecordId` selects strictly higher
  IDs, even when the cursor itself no longer exists. It returns
  `records[]` containing `record_id`, digest, `source_mode`, `finding_count`,
  `summary_preview` (maximum 180 characters plus ellipsis), and the saved
  Collect/packet digests. `record_count` is the count of structurally matching
  filenames **observed**, not a claim that every unreturned record has passed
  content validation. `returned_count`, `has_more` and `next_after_record_id`
  permit bounded pagination. Only returned entries have their bytes and schema
  validated. An empty/no-store list returns `CODE_SHOW_EMPTY` without writing.
- `Detail`: requires exactly one fixed-format `-RecordId`. Returns the complete
  saved `record` plus `record_id`, `record_path` and SHA-256. Full checked
  findings include model-authored reasoning and **quote hashes**, never the
  original `evidence_quote`, raw source patches or original untracked bytes.
  **Model-authored prose may still disclose private material**; review before
  sharing. Nonexistent record is `CODE_SHOW_NOT_FOUND`, not an arbitrary path
  resolution attempt.
- List/Detail do **not** accept `EvidencePath`, `InputPath`, `BaseSha`, `TargetSha`,
  `TargetRef`, `IncludePatches`, `IncludeUntrackedContent`, `ApprovePersist`, or
  each other's selectors. `RecordId`, `AfterRecordId`, `Limit` and the new Finding-specific flags are rejected
  for other CES actions. All results use `ces.cli.v1`, `next_step=none` and
  `read_only=true`.

## Sequence: adjacent comparisons, trajectories, path focus/index, baseline drift, all-pairs profile classes and per-path disagreement atlas (EC-021..EC-033)

EC-033 adds `data.path_focus.profile_journey` for an explicit exact
`-SequencePath`: it enumerates every caller position's saved path-local class,
anchor/statement histograms, every class member, maximal stable runs and every
classified change event. This is **not** a global ranked preview; it is
complete even when `SequenceTop=1` omits the chosen path from global hotspots,
when the path was stable or when none of the selected reports mentioned it
(one unreported class/run, not a missing business file). Original all-path
statistics and `pairwise_profile` are unaffected. No additional saved body,
source or network read, writer, proof of verified chronology or defect fix is
introduced. See [code-sequence.md](code-sequence.md).

EC-032 also returns **`data.pairwise_profile.path_profile_transitions`**. Across all exact saved paths in the same chosen reports it counts adjacent exact-profile transitions, stable runs and returns to a previously seen reported/unreported class separately from merely reporting again after a gap. Complete N-1 adjacent summaries and 0..N-1 transition bins are unaffected by `SequenceTop`; limited ranked path previews preserve *every* run, selected position and change event for each shown path. Reporting paths/profiles are neither current source truth nor verified chronology. No new read or writer is involved. See [code-sequence.md](code-sequence.md).

EC-031 additionally returns `data.pairwise_profile.path_profile_classes`: each ordinal case-sensitive saved path partitions all selected record positions into exact anchor-membership and retained-severity-histogram classes, including one class shared by all positions without a reported path. Full 1..N distinct-class-count bins and stable/diverse/reuse/missing-profile counts reconcile against EC-029 pair rows and EC-030 pair/path-frequency totals. `SequenceTop` caps only ranked diverse-path previews, **not** the displayed path's complete class members; no new read, writer, risk ranking, verified source absence or chronology proof is introduced. See [code-sequence.md](code-sequence.md).

EC-030 also adds `data.pairwise_profile.path_disagreement`: complete
case-sensitive saved-path frequencies over *every* unordered selected-report
pair, full 0..pair-count histogram (including stable paths), category totals
for one-sided paths, retained path anchor churn and severity changes (including
overlap), and frequency-ranked `SequenceTop` path previews listing every
changed pair for each shown path. Its independently recomputed per-pair path,
anchor and statement counts must agree with EC-029's 15 numeric fields and
equality flags. Only hotspot path rows are clipped; the view adds no read,
selector, writer or live-defect/chronology proof. See [code-sequence.md](code-sequence.md).

EC-029 additionally exposes `data.pairwise_profile`: every unordered pair of the same 2–12 fully checked selected reports is compared with the exact saved-anchor plus retained-anchor severity-statement predicate. Complete pair distances, changed-path-count distribution and exact profile equivalence classes are returned without `SequenceTop` clipping. Adjacent overlaps must match EC-025 and first-vs-later overlaps must match EC-027. Equal profile classes ignore prose/IDs/record bytes and are not semantic defect identity, source equality or chronology.

EC-028 additionally exposes `data.baseline_drift.path_persistence` with full first-relative per-path deviation frequency, 0..N-1 distribution (including unchanged paths), severity-only differences, path-profile returns, per-baseline-pair totals and capped deterministic hotspots; it is not a defect lifecycle or chronology claim.

EC-027 also provides `data.baseline_drift`: the first caller-selected saved
report compared with **every** later position, including nonadjacent pairs,
using complete exact-anchor/path/severity-statement counts. Path previews
are independently `SequenceTop`-capped; A/B/A/A shows one profile return
after the immediately prior different position. This is report-profile
comparison, not verified event time, source reversion, or a repaired issue.


`-Mode Sequence -SequenceRecordIds 'ci-<first>,ci-<second>[,...]'` is a
separate **caller-ordered** 2–12-record historical view. It compares each
adjacent pair using the exact six-field saved evidence anchor, reporting
retained/previous-only/next-only counts and differences in the saved severity
statement histogram. `-SequenceTop 1..20` caps only previews per category per
step, default 10; omitted preview counts remain explicit. All named bodies
are integrity/schema checked, including zero-finding records, while
unselected bodies are not opened. All names must exist before reading the
first chosen body. Different source modes, missing IDs or corrupted bodies
never produce accepted comparisons. SHA IDs/caller order are not timestamps;
reported absence is not a fix and reported addition is not a regression.
EC-022 additionally returns `anchor_trajectory` across the **entire**
selected record set: all/once/intermittent support, 1..N support histogram,
reporting-gap reappearances, first/last presence, severity statement histogram
variation and summed adjacent presence transitions. Four preview categories
are capped **independently** by the existing `-SequenceTop` with exact
omission counts and per-position presence bits. They may include saved Git
paths and quote digests but not original evidence, model reasoning or source
text. Neither gap-return nor severity changes prove recurrence of an actual
defect, source history or verified elapsed time. EC-023 adds optional
`-SequencePath 'exact/Case/Sensitive/Git.path'` to return a **separate**
`data.path_focus` with path-local record summaries, adjacent-step changes and
whole-selection trajectory; the original global `steps` and
`anchor_trajectory` do not change. This is a literal saved `anchor.path`
match, not a source read, glob or verified file lifecycle; empty/oversized
paths are refused and unmatched paths return a zero focus. All selected
records are still fully checked. EC-024/025 also return an always-on, complete-count saved-path index with
an N-1-row adjacent path attribution. **EC-026** extends that index with a
`change_profile`: complete path change-step support bins from 0..N-1,
explicit severity-only changed steps, and `SequenceTop`-bounded top paths
ranked by **number of changed steps** (not a risk estimate). Shown hotspots
include all their 1-based changed steps/kinds and longest consecutive run;
all selected records/paths still participate in untruncated totals, and
full per-step arithmetic is checked before acceptance. See
[code-sequence.md](code-sequence.md) for full inputs, outputs and errors.

## Findings selected-record retrieval (EC-020)

For exact historical Finding retrieval across arbitrary SHA-ID pages, use
`CodeShow -Mode Findings -FindingsRecordIds 'ci-<sha>,ci-<sha>'` (replace
both placeholders with valid full IDs). All 2–24 named saved record bodies
are verified, including filter-excluded records; other bodies are not read.
`-Limit 1..100` caps returned rows but not the selected scan.
`matched_finding_count` and `omitted_matching_count` expose trimming.
The old `fc1` page cursor is not supported in selected mode. This is a
historical bounded selection, not an all-store query or a fresh issue check.
See [code-findings.md](code-findings.md) for exact parser, counts, and errors.

## Boundary and integrity checks

Before touching saved records, CodeShow reuses **Inspect** to independently
verify the main Git worktree, its stable root and a real HEAD commit. It reuses
CodeSave's read-only Git boundary guard so the reserved `.codex/ces` path
cannot overlap tracked index/HEAD content, including Windows case aliases.
It does not read a linked worktree's or bare repository's state. It then
requires ordinary (non-symlink/non-junction/non-reparse) `.codex`, `ces`,
`code-insights`, and an owner marker with **exact** fixed `ces.local_store.v1`
bytes. An absent CES store is an empty list; a partial, unmarked, wrong-marker
or unsafe existing store is **not** silently taken over or repaired.

For every returned record, it checks:

1. Filename `ci-<64 lowercase hex>.json` only, with no caller-controlled
   directory selection or path traversal; no reparse-point records.
2. File size at most **512 KiB**, complete strict UTF-8 JSON (no BOM, comments
   or trailing commas), no duplicate/case-colliding keys and a bounded schema.
3. The **exact file-byte SHA-256** equals the filename ID; record is bound
   to this verified main root and contains only the expected v1 checked fields.
4. Finding count and arrays agree, bounded text/enums/digests/claimed lines
   are well formed, and unsupported provenance/semantic/line/CI/delivery proof
   flags remain false.
5. Second byte read has the same size and SHA-256; store ancestor types and
   owner marker are checked again. `List` also rechecks directory membership.

Enumeration is bounded to **2,000 directory entries**; a larger or unexpected
inventory fails visibly. An unsafe, symlinked, unowned or Git-tracked store
returns an unavailable result. A malformed, edited, oversized or changing
record, or an over-limit inventory, returns `partial` **without releasing
unverified results**. Records in another folder or the filename itself are
never an override for owner/root verification.

**Interpretation:** A content hash verifies self-consistency of the observed
bytes and filename; an attacker who controls both can forge them. A valid
record does **not** authenticate its creator, past evidence provenance, model
origin, finding correctness, line attribution, current working tree, CI or
remote delivery. Source is **not revalidated** by CodeShow. Filesystem race
protection is based on repeated samples, **not** an atomic snapshot or OS-level
sandbox, and a user can change records between pages. The store is unencrypted
and inherits local filesystem permissions. Order is by hash, not time.

## Reason codes and result meaning

| Reason code | Exit / status | Behavior |
|---|---|---|
| `CODE_SHOW_OK` | `0 / success` | List page or requested Detail record passed local integrity checks |
| `CODE_SHOW_EMPTY` | `0 / success` | No local store exists; no directory/file created |
| `CODE_SHOW_MODE_REQUIRED` | `4 / invalid_input` | Missing or unsupported `List`/`Detail` selector |
| `CODE_SHOW_SELECTORS_NOT_APPLICABLE` | `4 / invalid_input` | Wrong combination, page limit or disclosure/writing switch |
| `CODE_SHOW_INVALID_RECORD_ID` | `4 / invalid_input` | Invalid fixed-format record ID or pagination cursor |
| `CODE_SHOW_NOT_FOUND` | `4 / invalid_input` | Selected ID not found in an absent/valid store |
| `CODE_SHOW_MAIN_WORKTREE_REQUIRED` | `2 / partial` | Verified main root / HEAD requirement not met |
| `CODE_SHOW_RECORD_INVALID_OR_CHANGED` | `2 / partial` | Record contents or directory membership cannot be trusted |
| `CODE_SHOW_SCAN_LIMIT` | `2 / partial` | Over 2,000 entries in local store; no partial page asserted |
| `CODE_SHOW_STORE_UNSAFE_OR_UNAVAILABLE` | `5 / unavailable` | Unsafe, unmarked, tracked or unreadable CES storage boundary |

`coverage.code_store_checked` and `coverage.code_records_integrity_checked`
are set only after the corresponding checks complete. The latter covers the
**returned** records of a List page, never every unseen file in the store.

## Optional PowerShell 7+Git fixture

```powershell
pwsh -NoProfile -File './tests/CodeShow.Smoke.ps1'
```

Uses isolated scratch repositories and real CodeSave records; includes empty
store, consent/selector safety, two-record pagination, full Detail, tamper and
owner conflict, tracked boundary, linked worktree, and HEAD/index checks. It
has not been executed by an environment that lacks `pwsh`.

## EC-010 extension: Findings mode

`CodeShow -Mode Findings` now offers a **third**, read-only mode over these
same validated saved records. See [code-findings.md](code-findings.md) for exact
filter names, 32-record scan windows, cursor binding, page semantics and
privacy limits. List and Detail keep their EC-009 contracts and selectors.

## EC-012 extension: Trace mode

`CodeShow -Mode Trace -RecordId <ci-id> -FindingId <exact-id>` selects a
validated saved Finding as an anchor seed, then searches other local records
for the identical source-mode/layer/case-sensitive path/endpoint/quotation
SHA-256/proof-category tuple. It preserves multiple same-anchor Finding
statements per record in 24-record scan windows; `-AfterTraceCursor` binds the
verified root, seed Finding and anchor. Hash-sorted pages are not chronological
and empty windows may have unvisited candidates. See
[code-trace.md](code-trace.md) for commands, bounded pagination and limits.

## EC-011 extension: Compare mode

`CodeShow -Mode Compare -LeftRecordId <ci-id> -RightRecordId <ci-id>`
checks two selected saved v1 records and groups historical Findings by their
exact saved source-mode/layer/path/endpoint/quote digest/proof-category tuple.
It does not infer issue identity, chronology or fix status. It never rereads
source, and refuses different source modes. See [code-compare.md](code-compare.md)
for fields, grouping, bounded validation and selector rules.

## EC-019 extension: Bounded selected-record Trace across SHA pages

`CodeShow -Mode Trace` retains the seed `-RecordId`, exact `-FindingId`, and
24-record `tc1` paged search. EC-019 adds one comma-delimited
`-TraceRecordIds` argument containing **2–24 distinct lowercase full saved
record IDs**, **including the seed**. No explicitly provided `-Limit` or
`-AfterTraceCursor` may be mixed with selection. The entire bounded filename
inventory is checked for all selected IDs *before* reading any body. Exactly
the selected bodies, including different-source-mode candidates, receive the
existing strict schema/SHA/second-read checks. Returned exact-anchor matches
include every same-anchor Finding statement; results disclose sorted chosen
IDs, selected scope, `record_count` as inventory filenames, `scanned_record_count`
as checked selected bodies, and no cursor. Missing/corrupt members are
fail-closed; unselected bodies and live source are not read, nor do hashes
establish current defect identity or chronology. See [code-trace.md](code-trace.md).

## EC-013 / EC-018 extension: Overview mode

`CodeShow -Mode Overview` provides verified-page aggregate counts of saved
Finding statements. It scans at most 24 records per invocation, supports an
exact saved-mode filter, and returns counts by severity/layer/confidence plus
exact-anchor repetition **within the checked page only**. It emits no saved
paths, raw source, quote or model prose and does not prove a defect exists.
The `oc1` cursor binds the main root and filter, not a fixed cross-page
snapshot. EC-018 adds `-OverviewRecordIds 'ci-<sha>,ci-<sha>'` to aggregate
2–24 explicitly chosen full lowercase saved IDs from any SHA pages. This
form disallows `-Limit` or a cursor, checks all selected bodies even if
filtered-out, returns selection scope and sorted selected IDs, and does not
read unchosen bodies or claim store-wide completeness. See
[code-overview.md](code-overview.md) for selectors, count units, errors
and deferred host verification.


## EC-014 extension: Triage mode

`CodeShow -Mode Triage` produces **file-oriented historical review hints**
from fully checked saved Finding statements. It groups by exact saved source
mode, case-sensitive Git path and rename endpoint, retains distinct record vs
statement counts, layer/confidence/severity bins and per-group exact anchor
multiplicity. Ranking is highest model-reported severity first, then distinct
report count and statement count, with an ordinal tie-break. It is **not**
validated risk, current source or an all-store priority list.

Only 24 candidate records are verified per request. `-TriageTop` returns at
most 1–30 groups and counts omitted groups; `-TriageSourceMode` filters saved
mode and `-AfterTriageCursor` binds the verified root, exact filter and Top.
The mode discloses exact **Git paths** (possibly sensitive), but no source
quotations, model prose or patches. See [code-triage.md](code-triage.md)
for the full contract, limitations and deferred host smoke fixture.

## EC-017 extension: Explicit historical Triage set

A second, **mutually exclusive** Triage route accepts `-TriageRecordIds`
with one comma-delimited string of **2–24 distinct full lowercase**
`ci-<64hex>` IDs selected from anywhere in the bounded store. Omit
`-Limit` and `-AfterTriageCursor`; `-TriageTop` and an exact
`-TriageSourceMode` filter remain supported. Selected bodies are all
verified, even when filtered out; missing/invalid IDs, bad bytes and unsafe
stores fail without an accepted path ranking. Results contain sorted
`selected_record_ids`, `selected_record_count`, and per-group sorted
`reporting_record_ids`, with scope `selected_record_ids` and no cursor.
Only those selected reports are ranked across pages, not the entire CES
store; no chronological or defect-status inference is permitted. See
[code-triage.md](code-triage.md).

## EC-015 extension: Recurrence mode

`CodeShow -Mode Recurrence` discovers full quotation-anchor tuples repeated
across **different saved record IDs** in one at-most-24-record verified page.
It needs no seed Finding ID and respects optional exact saved-mode/path
filters. `-RecurrenceMinRecords 2..24` decides which groups qualify, and
`-RecurrenceTop 1..30` caps returned group details while reporting omitted
counts. The root/filter/threshold/Top-bound `rc1` cursor advances by scanned
record ID, not by matched group. Cross-page duplicates are **not** gathered;
SHA-ID sorting is not chronology. Paths, quote digests and occurrence IDs
are disclosed, while original source quotations/patches and free-form model
prose are excluded. See [code-recurrence.md](code-recurrence.md) for examples,
selector rejection behavior and exact result fields.

## EC-016 extension: Explicit historical Recurrence set

Supply one `-RecurrenceRecordIds` comma-separated argument with **2–24
distinct full lowercase `ci-<64hex>` IDs** to aggregate selected saved
records that may be separated by `rc1` scan pages. This is an alternative
to paged Recurrence: **omit `-Limit` and `-AfterRecurrenceCursor`**. Every
selected body (even a source-mode-excluded body) is reverified by the existing
SHA/v1 gates; nonexistent, duplicate, malformed or overlarge selections fail
without partial results. Output returns sorted `selected_record_ids[]`,
`selected_record_count`, `selection_scope=selected_record_ids` and no next
cursor. Only selected reports are compared; no automatic cross-page discovery,
store-wide unique-defect finding, fresh source, true issue lifecycle or
authenticated authorship is inferred. See [code-recurrence.md](code-recurrence.md).

## EC-025 Sequence per-step saved-path change attribution

Every successful Sequence index now also contains `path_index.step_deltas[]`:
exactly N-1 adjacent caller-position comparisons, each with complete path
entry/exit/retention counts, retained-path anchor-churn and severity-histogram
change counts, all exact-anchor delta categories and Finding statement totals.
A `changed_paths[]` preview lists only paths with changes to exact-anchor
presence **or** retained-anchor five-severity statement counts. It is ranked
by anchor 0↔1 transitions descending then case-sensitive ordinal path, capped
independently **per step** by `SequenceTop`, with exact omissions. A path can
remain retained despite replacement of all quote anchors; a severity-only
changed path has zero transition score but remains included. All numeric step
counts reconcile to the preexisting unfiltered `steps[]`; step transitions
reconcile to the whole index. No new switches, store reads or writer. This
is historical report metadata, not verified source chronology, fix or risk.
See [code-sequence.md](code-sequence.md).

## EC-024 Sequence ranked saved-path index

`CodeShow -Mode Sequence` always returns a historical `data.path_index`: all
exact case-sensitive checked anchor paths across the 2–12 selected reports,
whole-set coverage/gap, Finding statement counts, path presence transitions
and exact-anchor presence transitions; `SequenceTop` only caps ranked preview
rows with accurate `omitted_paths`. Ties use ordinal path sorting. This is
independent of the optional `SequencePath` filter and never opens unselected
records or actual source paths. A changed anchor with an unchanged reported
path is not treated as a retained anchor, and churn ranking is never a risk
score. See [code-sequence.md](code-sequence.md).
