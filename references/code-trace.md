# EC-012 / EC-019 — Historical exact-anchor tracking, with explicit cross-page selection

Use `Trace` to answer: **which locally saved CodeInsight records reported the same
specific evidence quotation anchor as this Finding?** This is a read-only,
local, paged search over previously `CodeSave`d `ces.code_insight_saved.v1`
records. It is not a lookup of live defects, semantic duplicate Issues, or a
time-ordered audit trail. Nothing is created and no business source is opened.

## Select one real seed Finding

Obtain a `ci-<64 lowercase hex>` saved record ID from `CodeShow -Mode List`
(or `Findings`), then obtain an exact Finding ID via `Detail` or `Findings`:

```powershell
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow -Mode Trace `
  -RepoPath '/absolute/main-git-worktree' `
  -RecordId 'ci-<64 lowercase hex>' -FindingId 'F1' -Limit 20 -Json
```

Both `-RecordId` and `-FindingId` are required; `FindingId` is case-sensitive
and must match `^[A-Za-z][A-Za-z0-9_-]{0,31}$`. A seed that does not exist
or does not contain that exact Finding is rejected, not interpreted as a
zero-match search. The record is byte/SHA-256/schema-checked before deriving
the search anchor. This prevents users from supplying arbitrary paths, source
text, or purported SHA-256 quotation hashes as search criteria.

The anchor is **exactly** the seed's saved tuple:

1. saved `source_mode`;
2. saved `layer`;
3. exact case-sensitive Unicode Git `path`;
4. `path_endpoint` (`path` or `old_path`);
5. `quote_sha256`;
6. `quote_presence`.

The same length-prefixed tuple codec is used by EC-011 Compare; separator-like
characters in paths cannot merge adjacent components. Two Findings in one
record may share an anchor: Trace keeps every distinct Finding statement,
sorted by exact ordinal Finding ID. A record with a different source mode,
even if the quotation hash coincides, is **not** an occurrence. Different
model titles, reasoning, severity or line claims do not prevent a match.

## Bounded search and continuation

A Trace request examines at most **24 candidate records**, validating each
candidate's full saved schema and content-addressed bytes, plus validating the
seed. `-Limit` counts **matching records**, not Finding statements (1–100,
default 50). A matching record is never cut between its same-anchor Findings.
The store inventory is checked twice, refuses unexpected entries and is
bounded at 2,000 entries. Each record is bounded at 512 KiB / 40 Findings.

Trace returns `data.mode=Trace` with:

| Field | Meaning |
|---|---|
| `seed` | Seed record ID/SHA, exact Finding ID and original source mode |
| `anchor` | Exact six-field quotation evidence anchor; **not** raw text |
| `matches[]` | Matching record ID/SHA, saved Collect/packet digests, all matching `findings[]` and `matching_finding_count` |
| `returned_record_count` | Number of matching records in this page |
| `record_count` | Number of known record filenames in the current inventory, including candidates not yet read |
| `scanned_record_count`, `scanned_finding_count` | Number actually examined in this page (not lifetime totals) |
| `scan_window_records`, `scan_window_exhausted` | Bounded 24-record window and whether that bound halted this page |
| `after_trace_cursor`, `next_after_trace_cursor` | Incoming/outgoing opaque continuation tokens; next is null only if no candidates remain |
| `has_more_candidates` | There are **unvisited candidate records**, not necessarily more matches |
| `record_integrity_verified` | Only the seed, returned/scanned records, owner and inventory in this invocation |
| `record_authorship_authenticated`, `source_revalidated`, `finding_semantics_verified`, `claimed_lines_verified`, `snapshot_atomic` | All `false` |

A page can legitimately return `CODE_SHOW_NO_MATCHES` with **zero matches**
while `has_more_candidates=true`. Continue until
`next_after_trace_cursor=null` before concluding that the **saved records**
contained no additional exact anchor occurrence at the times sampled.

To continue, use the **same** `RepoPath`, `RecordId` and `FindingId`, and copy
the exact returned token:

```powershell
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow -Mode Trace `
  -RepoPath '/absolute/main-git-worktree' `
  -RecordId 'ci-<same-seed-id>' -FindingId 'F1' `
  -AfterTraceCursor 'tc1-<64 hex query hash>-ci-<64 hex last record id>' `
  -Limit 20 -Json
```

A `tc1` token binds the verified main-root, seed record, seed Finding ID and
complete six-field anchor. It advances **after a fully scanned record**, never
inside the record. A malformed cursor is invalid input; mismatched query
binding is invalid input; a cursor record missing from the current store
returns partial/stale without results. A returned token is a convenience
locator, **not a signature, snapshot lock, permission token or proof of stable
history**. Record IDs sort by SHA-256 digest, not by creation time. Adding or
removing records between pages can alter what gets visited; there is no
cross-page atomic snapshot or authenticated history.

## EC-019: Select exact saved records across SHA scan windows

Without a cursor, use `-TraceRecordIds` as an alternative to auto-scanning:

```powershell
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow -Mode Trace `
  -RepoPath '/absolute/main-git-worktree' `
  -RecordId 'ci-<seed-64hex>' -FindingId 'F1' `
  -TraceRecordIds 'ci-<seed-64hex>,ci-<other-64hex>' -Json
```

- Supply exactly **one comma-delimited string** of **2–24 distinct full
  lowercase** `ci-<64hex>` identifiers. No spaces, blank items, uppercase or
  duplicate IDs. The seed **must** be one of the selected IDs: this makes it
  possible to guarantee that **only** explicitly selected record bodies are
  read. The selected set is sorted with ordinal case-sensitive comparison,
  independently of the order you type it. An exact seed Finding ID is still
  mandatory and must really exist in the checked seed.
- `-TraceRecordIds` rejects **any explicit** `-Limit` (including the default
  value 50) and any `-AfterTraceCursor`. The original `tc1` cursor pagination
  is unchanged when `-TraceRecordIds` is omitted; the forms cannot mix.
  Trace selectors are rejected by other modes and CES actions.
- CES first enumerates and validates the **entire bounded 2,000-name store
  inventory**, checking every requested ID is present **before opening any
  selected body**. Every selected record (including a record whose source
  mode differs from the seed) is SHA/schema/second-read validated. Unselected
  bodies are never inspected; the directory membership, owner and ancestors
  are checked again. A missing ID returns `CODE_SHOW_NOT_FOUND` / exit 4.
  Changing or damaged selected records/inventory fail closed with `partial`
  and `data=null`, without an incomplete accepted result.
- The selected result includes `selection_scope=selected_record_ids`, sorted
  `selected_record_ids[]`, `selected_record_count`, and
  `counts_scope=only_the_explicitly_selected_records_not_the_whole_store`.
  `record_count` is the filename inventory count, while
  `scanned_record_count` counts **only checked selected bodies**. The result
  sets `limit`, `after_trace_cursor` and `next_after_trace_cursor` to `null`,
  and `has_more_candidates=false`. It retains the same `seed`, exact `anchor`
  and all same-anchor Finding statements for each match, in ordinal record
  order and ordinal Finding ID order. Every selected Finding can contain
  sensitive model-authored text, even though no original source quote is
  returned.

This explicit selection can correlate a chosen seed with reports in other
24-record SHA-ID windows, **without** automatically searching every other
saved record. Neither a matching quote anchor nor multiple interpretations
prove a real defect, authenticated reviewer, chronological recurrence, current
source state, fix, regression or absence of further matches elsewhere.

New reason codes: `CODE_SHOW_TRACE_RECORD_IDS_INVALID` (exit 4, malformed
2..24 selection); `CODE_SHOW_TRACE_SELECTION_SEED_REQUIRED` (exit 4, seed
excluded); `CODE_SHOW_TRACE_SELECTION_CONFLICT` (exit 4, pagination mixed
with selection). All yield no `data`; selected record not found uses existing
`CODE_SHOW_NOT_FOUND` (4), and corrupt selected bodies use existing
`CODE_SHOW_RECORD_INVALID_OR_CHANGED` (2, partial). The source root and Git
index remain read-only.

## Refusal, privacy, and non-guarantees

- Only a verified main Git worktree with real HEAD can read the CES-owned
  store; Git index/HEAD ownership, exact owner marker, no-reparse ancestors,
  strict v1 schema, file SHA and repeated samples are inherited from CodeShow.
  A corrupt seed or candidate aborts the whole page **without accepted data**.
- `-AfterRecordId`, `-AfterFindingCursor`, Finding filters, two-record Compare
  selectors, raw patch/source-disclosure flags, file overrides, Git SHA/ref
  selectors and write approval are **not** valid with Trace. `Trace` selectors
  are not accepted by other CodeShow modes or by other actions.
- The original source quotation/patch/untracked body is not returned. The
  `quote_sha256`, full pathname and free-form model reasoning can nonetheless
  reveal sensitive information, including memorized code fragments or secrets;
  review the result before sharing.
- Exact quotation-anchor overlap does **not** establish issue identity,
  defect correctness, problem persistence, resolution, security exploitability,
  current source presence, or regression. Different anchors do not prove fixes
  or code changes. No model author is authenticated, no source is reread, no
  CI/test result is executed, no PR/release/deployment is checked, and no
  Issue relationship, RunId/HandoffId or CES writable index is created.

## Outcome mapping

| Reason code | Exit/status | Meaning |
|---|---|---|
| `CODE_SHOW_OK` | 0/success | This page contains one or more exact saved-anchor matches |
| `CODE_SHOW_NO_MATCHES` | 0/success | No match **in this scanned window**; check `has_more_candidates` |
| `CODE_SHOW_TRACE_SELECTORS_REQUIRED` | 4/invalid_input | Seed selectors missing, or invalid limit/unsupported record-page selector |
| `CODE_SHOW_TRACE_FINDING_ID_INVALID` | 4/invalid_input | Seed Finding ID does not obey the strict grammar |
| `CODE_SHOW_INVALID_RECORD_ID` | 4/invalid_input | Invalid seed record ID syntax |
| `CODE_SHOW_INVALID_TRACE_CURSOR` | 4/invalid_input | Malformed or explicitly invalid cursor |
| `CODE_SHOW_TRACE_FINDING_NOT_FOUND` | 4/invalid_input | Seed record valid, but specified exact Finding ID absent |
| `CODE_SHOW_TRACE_CURSOR_MISMATCH` | 4/invalid_input | Cursor was minted for a different root/seed/anchor |
| `CODE_SHOW_NOT_FOUND` | 4/invalid_input | No store or selected seed record absent |
| `CODE_SHOW_CURSOR_STALE` | 2/partial | Cursor checkpoint record disappeared; no results |
| `CODE_SHOW_RECORD_INVALID_OR_CHANGED` | 2/partial | Seed/candidate/owner/directory validation failed; no results |
| `CODE_SHOW_SCAN_LIMIT` | 2/partial | Directory entry bound exceeded; no results |
| `CODE_SHOW_MAIN_WORKTREE_REQUIRED` | 2/partial | Root or HEAD cannot be verified as main worktree |
| `CODE_SHOW_STORE_UNSAFE_OR_UNAVAILABLE` | 5/unavailable | Safe CES owner and Git storage boundary unavailable |
| `CODE_SHOW_SELECTORS_NOT_APPLICABLE` | 4/invalid_input | Forbidden Trace/other-mode selector combination |

The existing `ces.cli.v1` envelope keeps `read_only=true`,
`next_step=none` and `can_persist_ces_state=false`. Only `CodeSave` can write
CES-owned local metadata, and Trace cannot edit business source or Git state.

## Optional user-assisted host verification

```powershell
pwsh -NoProfile -File './tests/CodeTrace.Smoke.ps1'
```

The standalone scratch repository test builds a real CodeSave seed and
synthetic self-hashed records to exercise exact-mode matching, multiple
findings per anchor, 24-record scan boundaries, paginated continuation,
malformed/mismatched/stale cursors, missing records/Findings, unsafe selectors,
corruption and Git HEAD/index nonmutation. It must not be reported as passed
until actually run with PowerShell 7 and Git.
