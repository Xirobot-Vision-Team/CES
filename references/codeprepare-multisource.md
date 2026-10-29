# EC-170 — Source-explicit multi-source CodePrepare context

**Standalone implementation:** [`construction/codeprepare_multisource.py`](../construction/codeprepare_multisource.py), response schema `ces.code_prepare_multisource.v1`, context schema `ces.ai_code_context.v1`. It unifies **one explicitly selected source at a time** into a bounded read-only AI context. It does not add or pretend to add a native PowerShell `CodePrepare:MultiSource` route.

## Three modes, one selected source, no inference

`--source-mode` is mandatory and is exactly one of `WorkingTree`, `DeliveredTarget`, or `ProposedPR`. The tool never looks at filenames or available inputs to guess a mode. Local modes reject ProposedPR inputs, and ProposedPR rejects a local CodePrepare packet. A grant for one source cannot be reused for another source because `--allow-content-for` names the exact selected mode rather than using a generic boolean.

- **WorkingTree** consumes an already-successful native `CodePrepare:Snapshot` `ces.cli.v1` result whose packet says `working_tree_diff`.
- **DeliveredTarget** consumes an already-successful native `CodePrepare:Snapshot` result whose packet says `delivered_target_diff`.
- **ProposedPR** consumes an EC165 `ces.proposed_pr_snapshot.v1` whose offline receipt verifier returns `INTERNALLY_CONSISTENT_ONLY`. An optional EC166 `ces.proposed_pr_reconcile.v1` must bind to the same EC165 observation and pin.

There is deliberately no input set that merges WorkingTree, DeliveredTarget and ProposedPR into one context. In particular, proposal candidate code is never combined with delivery-association facts and labelled as delivered code.

## Local Snapshot compatibility is preserved, not reimplemented

For WorkingTree and DeliveredTarget, EC170 does **not** consume raw `Collect` or `Reconcile` data. It accepts only a successful existing native `CodePrepare:Snapshot` result (`CODE_PREPARE_READY` or `CODE_PREPARE_EMPTY`). That preserves the old native Reconcile and explicit patch/untracked-content disclosure gate instead of inventing a second, weaker local path.

A ready packet must remain read-only, have a stable project root, valid full Git object IDs for the selected mode, `current_scope_reconciled=true`, `independently_authenticated=false`, `atomic_capture=false`, and all remote/delivery/CI/deployment proof flags false. Paths are strict normalized relative paths; absolute, backslash, traversal, control-character and Windows-device ambiguous paths are rejected. The raw local filesystem root is not copied to the AI context. EC170 derives a domain-separated local scope key from the root plus pinned Git scope, explicitly labelled **not a globally authenticated repository identity**.

`CODE_PREPARE_EMPTY` remains valid and produces a metadata-only empty context, but it must still carry the matching source mode, stable root, valid Git pin and saved Collect hash. Empty therefore does not mean “identity checks may be skipped.”

## ProposedPR is historical, bounded and non-atomic

EC165 already records an observation-bound snapshot rather than an authenticated Provider-atomic diff. EC170 preserves that boundary. It rechecks the EC165 internal receipt shape, complete Provider pin, path inventory, path safety, selected patch membership and byte counts. `path_coverage=COMPLETE` must exactly agree with the bounded file inventory before any raw patch is eligible for release.

Optional EC166 helps only with metadata drift:

- `FRESH_OBSERVATION`: current metadata matched the prior pin, but old EC165 file pages and patch text were **not re-read**, so they remain historical.
- `STALE_BY_DRIFT`: old EC165 raw content is always withheld, even when the operator grants EC170 content access.
- `UNAVAILABLE_UNKNOWN`: current Provider state could not be established; EC165 remains historical only.

No positive ProposedPR context sets `source_currentness_proven`, `provider_actor_verified`, `remote_delivery_proven`, `deployment_proven` or `write_authorized` to true.

## Raw content is denied again by default

Every source must be re-authorized at EC170 before source/patch text is copied into the returned context:

```bash
cd ces

# Existing native Snapshot JSON -> WorkingTree metadata only
python construction/codeprepare_multisource.py \
  --source-mode WorkingTree \
  --local-codeprepare /safe/workingtree-codeprepare.json --json

# Same source, now explicitly allow its already-authorized native content into this AI context
python construction/codeprepare_multisource.py \
  --source-mode WorkingTree \
  --local-codeprepare /safe/workingtree-codeprepare.json \
  --allow-content-for WorkingTree --json

# ProposedPR: EC165 historical snapshot + optional EC166 metadata re-observation
python construction/codeprepare_multisource.py \
  --source-mode ProposedPR \
  --proposed-snapshot /safe/ec165.json \
  --proposed-reconcile /safe/ec166.json \
  --allow-content-for ProposedPR --json
```

The EC164/165 fact that selected patches were previously disclosed does **not** grant EC170 permission. Nor does a native Snapshot's earlier content-release flag, an EC169 persistence consent, CodeSave permission, or any other source. If the path count or byte budget is exceeded, EC170 withholds **all raw content** rather than silently cutting a diff and presenting a misleading fragment as complete. Metadata entries may be bounded to the configured path limit and coverage explicitly reports the gap.

Default content budget is 512 KiB (hard maximum 2 MiB); default path budget is 512 (hard maximum 4096). Inputs themselves also have hard file-size bounds before JSON parsing. Strict JSON decoding rejects BOMs, duplicate/case-colliding keys and non-finite numbers.

## EC169 receipts are only historical labels

An optional EC169 receipt may be attached only to ProposedPR, and only when its source schema is EC166 reconcile. EC167/EC168 receipts are deliberately rejected here because those are local delivery/target-association facts and would blur the proposal-candidate boundary. Without the EC169 store key, EC170 cannot reverify the receipt HMAC and therefore labels the receipt as `bound_to_context_identity=false` and `receipt_integrity_reverified_without_store_key=false`.

A receipt never grants content permission, never proves that its source data is still available/current, and never proves delivery. It is a historical provenance hint only.

## Output and side effects

Successful or partial results return a `ces.ai_code_context.v1` object plus explicit coverage, permission and provenance. The context hash is a domain-separated SHA-256 over canonical JSON. The module writes no files; CLI output is JSON on stdout only. It does not run Git, contact GitHub/GitLab, modify a Provider object, update a worktree/index/ref, touch the CES/EC169 store or publish anything.

Native `CodePrepare:Snapshot` remains the only existing PowerShell CodePrepare route. Native `CodePrepare:MultiSource`, `Collect:ProposedPR`, and remote/delivery Reconcile are still unregistered/`NOT_IMPLEMENTED`; this standalone bridge is not evidence that those routes exist.

Developer checks for this round: 31 EC170 focused cases plus the complete EC165 33 and EC166 25 suites were rerun together, **89/89 passed** in the construction environment. PowerShell 7, the frozen 15 Smoke suites, live GitHub/GitLab, cross-OS Git/filesystem behavior, E63–E66 performance and final user-assisted acceptance remain **NOT_RUN**.
