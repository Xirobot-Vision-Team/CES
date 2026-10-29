# EC-011 — Historical Finding evidence comparison (`CodeShow -Mode Compare`)

Compare **two explicit, previously `CodeSave`d** local `ces.code_insight_saved.v1`
records at one independently verified **main Git worktree**. Compare is
read-only: it opens no business source file, working-tree diff, raw source
quotation or patch; it neither edits the repository nor creates CES state.
Both saved records are checked for exact filename/file-byte SHA-256, owner,
verified source root, bounded strict JSON shape and expected proof flags before
any comparison data is accepted.

```powershell
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeShow -Mode Compare `
  -RepoPath '/absolute/main-git-worktree' `
  -LeftRecordId 'ci-<64 lowercase hex>' `
  -RightRecordId 'ci-<64 lowercase hex>' -Json
```

`-LeftRecordId` and `-RightRecordId` are **both mandatory**, may be identical,
and must be exact `ci-` plus 64 lowercase hexadecimal characters. They refer to
stored record IDs, **not** commit SHAs, PRs, branch names or arbitrary files.
Use `CodeShow -Mode List` to obtain IDs. Record-ID order is not chronology:
choose left and right intentionally; Compare does not infer which is newer.

## Matching rule — intentionally narrow

For two records with the **same `source_mode`**, classify each saved Finding by
this complete tuple:

1. exact `source_mode` (`working_tree_diff` or `delivered_target_diff`);
2. exact `layer` (`staged`, `unstaged`, `untracked` or `changes`);
3. exact Unicode `path`, compared **case-sensitively** (no filesystem lookup);
4. `path_endpoint` (`path` or `old_path` for a rename);
5. the stored `quote_sha256` (hash of the model-supplied source quotation);
6. `quote_presence` evidence-category marker.

The tuple is internally encoded with length-prefixed fields so a Unicode
filename containing separators cannot collide with a different tuple. All
anchor groups and their member Finding IDs are emitted in deterministic
ordinal order. Multiple Findings about **one** anchor remain separate entries;
there is no one-to-one pairing based on ID, title, severity or reasoning.

Response data uses `mode=Compare`, `comparable=true`, and:

| Field | Meaning |
|---|---|
| `left_record` / `right_record` | Chosen record SHA-ID, source mode, saved Collect/packet digests, original Finding count and unique anchor count |
| `counts.shared_anchor_count` | Distinct matching anchor tuples found on both sides |
| `counts.left_only_anchor_count` / `right_only_anchor_count` | Distinct tuples mentioned only on one side's **saved Finding list** |
| `counts.shared_anchor_left_finding_count` / `shared_anchor_right_finding_count` | Number of individual Finding statements within shared anchor groups on each side |
| `shared_anchors[]` | Anchor and separately ordered `left_findings[]`, `right_findings[]` (both nonempty) |
| `left_only_anchors[]` / `right_only_anchors[]` | Anchor with Finding statements from only the respective saved record |
| `record_integrity_verified` | True for the two selected records and bounded directory sample, not all stored records |
| `source_revalidated`, `finding_semantics_verified`, `claimed_lines_verified`, `record_authorship_authenticated`, `snapshot_atomic` | All `false`; no additional proof is inferred |

Each returned Finding statement contains its `id`, `title`, `severity`,
`confidence`, *unverified* claimed line interval, `reasoning`, `impact` and
`recommendation`. These are saved model-authored statements, not independently
correct judgments. The source quotation itself is **never returned**.
There are at most 40 Findings on either side, hence at most **80** Finding
statements across the disjoint group partitions in one comparison. The store
filename inventory is capped at 2,000 entries and each record at 512 KiB.

A record with zero Findings compares normally: it has zero anchor groups.
Comparing an ID with itself makes all its anchor groups shared. If no anchors
match, the response may contain two nonempty exclusive sets; this proves
nothing about whether either issue was fixed. Records with different source
modes return `partial / CODE_SHOW_COMPARE_SCOPE_MISMATCH`, with selected
record metadata only and `counts=null`: they are **not treated as a change
lifecycle**. The absence of a Finding in a model's historical report is not
proof of source absence or successful remediation.

## Safety and truthful interpretation

- No `-Limit`, cursors, Finding filters, `-RecordId`, `-EvidencePath`,
  `-InputPath`, `-BaseSha`, `-TargetSha`, `-TargetRef`, content disclosure
  flags or `-ApprovePersist` may be combined with Compare. Compare selectors
  are invalid for every other mode and every other CES action.
- Compare checks the main-worktree/HEAD/index ownership boundary, the fixed
  owner marker, safe non-reparse paths, bounded known record inventory, **two
  complete byte/digest/schema-checked reads per selected distinct record**, a
  second directory membership sample, and the final store-path/owner checks.
  Hostile concurrent filesystem replacement still cannot be ruled out; a
  digest/owner marker is not a signature or authentication of model origin.
- `quote_sha256` may facilitate cross-record linkage of familiar or guessable
  texts. Returned prose, titles and paths may contain sensitive context even
  though original quotations and patches are absent. Review before sharing.
- Same quoted bytes at the same path/layer do **not** establish equivalent
  meaning, source provenance, issue identity or validity. Different quote
  bytes do **not** prove a regression, resolution or changed source. Source
  snapshots may have been incomplete, model interpretations may differ, and
  no timeline, Git ref, CI, PR merge, deployment or current source is checked.
- All counts describe **only the two saved records**. EC-012 `CodeShow -Mode Trace` can scan many saved records for one exact seed anchor, but it still does not establish chronological continuity or authenticated issue identity. No longitudinal Finding
  table or merged Issue, remote report or mutable state is created.

## Exit/response codes

| Reason code | Exit / status | Behavior |
|---|---|---|
| `CODE_SHOW_OK` | `0 / success` | Both records valid, same source mode, bounded exact anchor-group comparison returned |
| `CODE_SHOW_COMPARE_IDS_REQUIRED` | `4 / invalid_input` | Missing or explicitly empty left/right ID |
| `CODE_SHOW_INVALID_RECORD_ID` | `4 / invalid_input` | Record ID syntax invalid; no path interpreted |
| `CODE_SHOW_SELECTORS_NOT_APPLICABLE` | `4 / invalid_input` | Compare combined with unsupported switches or sent to another mode/action |
| `CODE_SHOW_NOT_FOUND` | `4 / invalid_input` | No store or at least one selected valid-format ID is absent |
| `CODE_SHOW_COMPARE_SCOPE_MISMATCH` | `2 / partial` | Both selected records valid but saved source modes differ; no overlap result |
| `CODE_SHOW_RECORD_INVALID_OR_CHANGED` | `2 / partial` | Corrupt/changed selected record, unknown directory item or directory drift; no accepted result |
| `CODE_SHOW_SCAN_LIMIT` | `2 / partial` | Local store has too many directory entries |
| `CODE_SHOW_MAIN_WORKTREE_REQUIRED` | `2 / partial` | Repository/HEAD cannot be proven to be a verified main worktree |
| `CODE_SHOW_STORE_UNSAFE_OR_UNAVAILABLE` | `5 / unavailable` | CES state owner, Git boundary or safe local storage unavailable |

A successful comparison is **historical evidence-index overlap**, not a test
result, fix verdict or source diff. `next_step=none`, `read_only=true` and
`can_persist_ces_state=false` remain unchanged.

## Optional target-host check

```powershell
pwsh -NoProfile -File './tests/CodeCompare.Smoke.ps1'
```

The disposable Git fixture exercises two-record grouping, duplicate anchor
multiplicity, Unicode/separator-bearing paths, changed severity and title,
reversed/self queries, missing/malformed IDs, selector boundaries, source-mode
refusal, tampering, unknown directory entries, no-store/no-write, non-JSON
output, and Git HEAD/index preservation. The test is provided for later joint
PowerShell 7+Git execution; it is **not** claimed to have passed in an
environment without `pwsh`.
