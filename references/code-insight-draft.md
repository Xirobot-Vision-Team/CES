# CodeInsight draft contract — `ces.code_insight_draft.v1` (EC-007)

Use this reference when a **model or a human has already reviewed** a successful
`CodePrepare -Mode Snapshot` packet and wants a read-only evidence-binding check
before any future persistence or publication. CodeValidate never performs a
model inference, never saves a Finding and never authenticates the draft's author.

## Minimal input/output flow

1. Save a complete `Collect -Json` envelope to an explicit user-controlled file.
   For nonempty tracked/untracked layers, collection must explicitly include the
   corresponding content flags.
2. Run `CodePrepare -Mode Snapshot` with fresh explicit source-disclosure switches.
   Require `status=success`, `reason_code=CODE_PREPARE_READY`,
   `data.prepared=true`. Note both `data.packet_sha256` and
   `data.preparation.saved_collect_sha256`. **Keep the complete review packet**
   available to the model/human who is writing the review.
3. Write the review draft as a *separate* UTF-8 JSON file. Copy the above two
   digest strings exactly; neither is a signature. Use a source quote that is
   literally present in the correct source layer.
4. Call `CodeValidate` with that saved Collect file, the draft file and **the
   same explicit consent switches**. CodeValidate reconstructs the packet and
   compares both digests before checking findings.
5. On `CODE_VALIDATE_OK`, inspect `data.checked_findings`. This is checked
   draft **data**, not a verified finding, a trusted author, a saved record, a
   report or a handoff. The output does not include the original quote text.

```powershell
$cli = './scripts/ces.ps1'
$repo = '/absolute/repo'
$collectFile = '/absolute/collect.json'
$draftFile = '/absolute/review-draft.json'

# Capture the hash-bearing packet for review (not a background model call).
$prepared = (& pwsh -NoProfile -File $cli -Action CodePrepare -Mode Snapshot `
  -RepoPath $repo -EvidencePath $collectFile -IncludePatches `
  -IncludeUntrackedContent -Json) | ConvertFrom-Json -Depth 32
if ($prepared.reason_code -ne 'CODE_PREPARE_READY') { throw 'No ready packet' }
$prepared.data.packet_sha256
$prepared.data.preparation.saved_collect_sha256

# Have the model/human inspect $prepared.data.review_packet and create the
# JSON draft below with these digests. CodeValidate does NOT draft it for you.
& pwsh -NoProfile -File $cli -Action CodeValidate -Mode Snapshot `
  -RepoPath $repo -EvidencePath $collectFile -InputPath $draftFile `
  -IncludePatches -IncludeUntrackedContent -Json
```

For `DeliveredTarget`, use `-IncludePatches` but **not**
`-IncludeUntrackedContent` for either call.

## Draft JSON shape

These are example **placeholders**, not actual SHA-256s or verified code:

```json
{
  "schema_version": "ces.code_insight_draft.v1",
  "task_kind": "code_analysis",
  "packet_sha256": "<64-lowercase-hex-from-CodePrepare>",
  "saved_collect_sha256": "<64-lowercase-hex-from-CodePrepare>",
  "summary": "Review the changed timeout branch and validate its failure path.",
  "findings": [
    {
      "id": "F1",
      "title": "Timeout branch may return without cleanup",
      "severity": "medium",
      "confidence": "low",
      "layer": "unstaged",
      "path": "src/worker.ps1",
      "evidence_quote": "+        return $false",
      "reasoning": "The shown return precedes the visible cleanup call.",
      "impact": "A pending resource may survive the early return.",
      "recommendation": "Inspect the caller and put cleanup in a finally block."
    }
  ],
  "limitations": ["No CI execution was observed."]
}
```

`findings` may be `[]` (a model's no-finding assertion is **not** a proof
of correctness). The fields in each finding are required except optional
`line_start` and `line_end`, which must be provided together as positive
bounded integers; they are always labeled `claimed` and **never verified**.
Exactly one of `staged`, `unstaged`, `untracked` or `changes` must be selected
based on the actual packet. Exact case-sensitive Git paths are required.
Renamed/deleted old pathnames may match an `old_path` endpoint.

The draft schema intentionally does **not** admit fields purporting to assert
CI success, merge/deployment proof, signed authorship, handoff IDs or delivery.
Unknown fields, duplicate JSON keys (including alternate-case collisions),
invalid enum values, repeated finding IDs, and malformed UTF-8 are rejected.

## Bounds and verification strength

| Item | Bound/behavior |
|---|---|
| Input draft | Regular, explicitly selected JSON file, strict UTF-8, at most 256 KiB; no leaf symlink/reparse point |
| Findings | Up to 40; unique ASCII IDs, severity `critical/high/medium/low/info`, confidence `high/medium/low` |
| Limitations | Up to 20 short strings |
| Finding strings | Bounded fields (title 180, excerpt 900, reasoning 2400, impact/recommendation 1200 characters) |
| Exact packet binding | `packet_sha256` must equal the **current rebuilt** CodePrepare packet hash; old bytes / another mode / changed source fail closed |
| File anchor | The finding path must belong to the named layer's original inventory (current or rename `old_path`) |
| Untracked quote | Literal byte-decoded substring of that exact untracked file's included text |
| Tracked quote | Literal substring of both the **included whole layer patch** and a fresh bounded, literal **pathspec-scoped Git diff** for the matched entry/rename endpoints; not independently proven to belong to a specific hunk/line |
| Source and draft recheck | A final Reconcile call plus draft file hash re-read; two observations are **not** an atomic snapshot or authorship proof |
| Output | `ces.code_insight_checked.v1` in `data`; original source quotes omitted, their SHA-256 retained; no CES persistence |

**Critical interpretation:** On tracked findings, CodeValidate checks both the stored layer
and a fresh literal pathspec-scoped Git diff limited to the claimed entry and
rename endpoint(s). It therefore rejects quotes belonging only to another
entry in the same layer, but does **not** parse Git hunks to verify an exact
source line or unique line attribution. It also cannot establish that a quoted code branch is reachable, the
reasoning is true, the recommended patch would work, or no secrets occur in the
model-authored summary. Treat a successful draft as **eligible for manual
review**, not as automatically accepted Findings.

`CODE_VALIDATE_SOURCE_NOT_READY` / `CODE_VALIDATE_PACKET_MISMATCH` /
`CODE_VALIDATE_INPUT_CHANGED` / `CODE_VALIDATE_ANCHOR_UNAVAILABLE` return `partial` and no checked findings.
Malformed shape or an unbound finding is `invalid_input`; any one invalid
finding rejects the **whole draft**. No output path, RunId, HandoffId, state
write, remote call, CI claim, `CodeSave` or source mutation is performed.
