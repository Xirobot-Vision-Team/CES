# EC-008 — Local CodeInsight storage (`CodeSave -Mode Snapshot`)

`CodeSave` is the **first real CES-owned write operation**. It writes a
metadata-only, checked `CodeInsight` record to the explicitly selected local
repository's **independently verified main worktree**. It is not the future
staged RunId/HandoffId handoff service. The invoking user must authorize
persistence for this invocation with `-ApprovePersist`; otherwise, no CES
storage is created. There is no network request or business-source edit.

## Inputs and execution

1. Obtain a **content-complete, user-saved `Collect -Json`** outside CES.
   WorkingTree requires `-IncludePatches` if tracked layers are nonempty and
   `-IncludeUntrackedContent` if untracked files are nonempty; DeliveredTarget
   uses `-IncludePatches` only.
2. Call `CodePrepare -Mode Snapshot` with the same explicit Git content
   disclosure flags. Its successful nonempty result has
   `data.packet_sha256` and `data.preparation.saved_collect_sha256`.
3. Have a model or human write a separate strict
   `ces.code_insight_draft.v1` JSON with those two hashes and valid finding
   anchors; see [code-insight-draft.md](code-insight-draft.md).
4. Review the draft's summary, findings and limitations before authorizing
   storage. Then invoke **one** explicitly authorized local save:

```powershell
# WorkingTree snapshot; both switches are required only if corresponding layers have content.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeSave -Mode Snapshot `
  -RepoPath '/absolute/main-worktree' `
  -EvidencePath '/absolute/saved-collect.json' `
  -InputPath '/absolute/model-review.json' `
  -IncludePatches -IncludeUntrackedContent -ApprovePersist -Json

# DeliveredTarget snapshot with an original fully pinned Collect observation.
pwsh -NoProfile -File './scripts/ces.ps1' -Action CodeSave -Mode Snapshot `
  -RepoPath '/absolute/main-worktree' `
  -EvidencePath '/absolute/saved-delivered.json' `
  -InputPath '/absolute/model-review.json' `
  -IncludePatches -ApprovePersist -Json
```

The tool **re-executes CodeValidate**, which itself rebuilds CodePrepare and
Reconcile; it never trusts a pasted `validated=true` flag. A new Reconcile and
draft-hash check occur before the attempted write. A stale/partial source,
missing content opt-in, wrong packet hash, unmatched quote, invalid draft or
unverified linked worktree **cannot** produce a record. This is sampled,
non-atomic validation, not a durable Git lock.

## The storage boundary

Only the following fixed relative paths may be created:

```text
<verified-main-worktree>/.codex/ces/owner.json
<verified-main-worktree>/.codex/ces/code-insights/ci-<64 lowercase hex>.json
```

- `owner.json` contains a fixed `ces.local_store.v1` marker; an existing
  mismatching marker or a nonempty unmarked directory is **rejected**.
- `.codex`, `.codex/ces` and `code-insights` must be actual directories,
  not symlinks, junctions or reparse points. Existing record files must also
  be regular files. Before and during saving, Git's HEAD **and** index must
  have no tracked entries beneath the CES state boundary, and `.codex` itself cannot be a tracked
  file or gitlink/submodule; a separately pinned
  DeliveredTarget commit tree is checked as well. Windows uses an additional
  bounded case-insensitive tracked-path scan; oversized inventories fail closed.
- The save file name is SHA-256 of the PowerShell-serialized canonical checked
  record JSON, with **no timestamp**, so an identical save is idempotent.
  A new record is created via a same-directory temporary file and a
  no-overwrite rename. An identical existing record is reported as
  `CODE_SAVE_ALREADY_PRESENT`; conflicting content is refused.
- Only CES-owned files are written. The Git index, branch, HEAD, business
  files, `.gitignore` and Codex personal state are never intentionally changed.
- The internal untracked namespace `.codex/ces/**` is **reserved** and excluded
  from `Collect -Mode WorkingTree`'s **untracked Git path probe**, even if
  there is no Git ignore rule. Tracked changes under that path are still
  visible to Collect, and they block CodeSave. This prevents a save from
  invalidating the prior business-source WorkingTree observation and avoids
  mixing CES records with reviewable source. Do not put business files there.

Content includes checked summaries, findings, rationale and their source
path/layer associations, quote **hashes**, digest bindings and verification
limits. The raw `evidence_quote`, collected patches and untracked file bodies
are omitted. **Free-form model prose may nevertheless contain sensitive
material**; CES has no comprehensive secrets filter or encryption. Storage
inherits host file-system protections. Do not share saved records blindly.

## Results and limits

All cases use the standard `ces.cli.v1` envelope with `next_step=none`.
`read_only=false` for the CodeSave action, even if it refuses to write.

| Reason code | Exit/status | What happened |
|---|---|---|
| `CODE_SAVE_OK` | `0 / success` | Created a new checked record; path/ID and SHA-256 returned |
| `CODE_SAVE_ALREADY_PRESENT` | `0 / success` | Identical verified record exists; no overwrite |
| `CODE_SAVE_AUTHORIZATION_REQUIRED` | `4 / invalid_input` | Missing `-ApprovePersist`; no persistence attempted |
| `CODE_SAVE_VALIDATION_FAILED` | upstream exit/status | Fresh draft/source/consent gate failed; no insight record |
| `CODE_SAVE_MAIN_WORKTREE_REQUIRED` | `2 / partial` | Source root is linked or persistent main root unverified |
| `CODE_SAVE_SOURCE_CHANGED` | `2 / partial` | Final source/draft recheck failed before writing |
| `CODE_SAVE_RECORD_TOO_LARGE` | `4 / invalid_input` | Record would exceed 512 KiB |
| `CODE_SAVE_STORE_UNSAFE_OR_UNAVAILABLE` | `5 / unavailable` | Unsafe, conflicting, tracked or unwritable state boundary; no record confirmed |

Successful `data` includes `persisted`, `created`, `record_id`,
`record_path`, `record_sha256`, `source_mode`, and `finding_count`. As of **EC-009**, `CodeShow -Mode List/Detail` can retrieve these saved
records read-only; **EC-010** also adds cross-record `Findings` queries over
checked saved metadata (no source revalidation). **EC-011** adds read-only two-record exact quotation-anchor comparison, never an Issue/fix verdict. EC-008 itself provided no CodeShow. There is still no staged
`RunId`, `HandoffId`, structured Finding database,
semantic validation, trusted model attribution, CI/PR/remote verification,
publication, encryption or safe cleanup operation in EC-008.

Content-addressing detects accidental edits and offers deterministic replay;
it is **not** a cryptographic signature or author authentication. The
owner marker is a namespace marker, not access control. Concurrent hostile
filesystem mutation is not fully prevented by path checks plus atomic rename;
use an access-controlled local repository. Failed storage initialization may
leave an owner marker/empty CES directory, but no business source edits.

## Optional verification on a PowerShell 7 + Git host

```powershell
pwsh -NoProfile -File './tests/CodeSave.Smoke.ps1'
```

Covers read-only prerequisites, missing consent, unbound/stale draft,
working-tree save, repeated save, source inventory unaffected by CES-owned
untracked files, owner-marker conflict, pinned DeliveredTarget and preserved
Git HEAD/index. This smoke test creates only isolated scratch repositories.
