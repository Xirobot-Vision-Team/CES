# EC-166: read-only remote PR/MR metadata reconciliation

**Construction bundle V4.76/R166; independent Python entrypoint:**
`construction/proposed_pr_reconcile.py` (`ces.proposed_pr_reconcile.v1`).
The native PowerShell `Reconcile:Remote/DeliveryAssociation` and
`Collect:ProposedPR` routes are still **NOT_IMPLEMENTED**. This code performs
one new metadata GET; it neither replays nor fetches EC165 pages or patches.

## Previous evidence is mandatory

Use a complete prior `ces.proposed_pr_identity.v1` JSON (`--expected-pin`), a
previous `ces.proposed_pr_snapshot.v1` JSON (`--prior-snapshot`), or both.
An EC165 receipt must pass its offline cross-field fingerprint/shape check,
and its count claim must be coherent. An EC162 pin must have a valid complete
provider/target/source/proposal identity, full base/head/target-tip OIDs and a
recomputed pin fingerprint. If both inputs are supplied, they must agree
exactly on pin and synthetic provenance. Files are bounded to 64 KiB / 4 MiB,
reject duplicate JSON keys, and are read but never modified.

These hashes are **not signatures**. A forged previous record can be
re-fingerprinted; internal agreement is not independent authentication.
The request locator must match the previous provider/repository/number
exactly. A synthetic previous result cannot be reconciled as a live result,
and an injected test transport always produces synthetic results.

## What the one new read compares

This module reuses EC161's already restricted metadata-only GET for:

- GitHub: `https://api.github.com/repos/{owner}/{repo}/pulls/{number}`;
  target/source `repo.id`, proposal global `id`, complete `base.sha` (target
  branch tip), `head.sha`, state and `merged` claim, `changed_files` count.
- GitLab: `https://gitlab.com/api/v4/projects/{encoded_path}/merge_requests/{iid}`;
  target/source project IDs, proposal global ID, `diff_refs.base_sha`
  (merge-base), `diff_refs.head_sha`, `diff_refs.start_sha` (target tip at
  **the reported diff version**, not necessarily the current target branch
  tip), state/merge claim and `changes_count` quality.

Reused EC161 code requires complete, internally consistent full OIDs; a
missing deleted-fork `head.repo`, GitLab's unready `diff_refs`, unsupported
state, wrong ID, insufficient permissions, 404 or rate limit cannot be
silently replaced by a branch name or previous SHA. No mutable refs, branch
checkout, native Git, extra API endpoints or raw provider payload are read.
Only sanitized, bounded metadata from the newly parsed result is returned.

Each successful read records its exact endpoint family, provider origin
(synthetic fixture or HTTPS response), UTC observation time, new pin and pin
fingerprint, and advertised count/quality. `comparison.changes` lists field
names and earlier/current *sanitized identity/OID/count claims*. It never
returns previous ordered pages, source code, patch content, raw ETags, token,
HTTP error body or untrusted description/title. The `prior` summary includes
only the preceding evidence reference and count/coverage/observation times.

## Decision states

| `reconciliation_state` | `status/exit` | Exact meaning |
| --- | --- | --- |
| `FRESH_OBSERVATION` | `partial/2` | New complete metadata matches prior full pin and, **when an EC165 snapshot was provided**, the previous exact provider file-count claim. With EC162 pin alone, count is observed now but was never baselined. This is a new metadata observation only, **not currentness of old pages/patches**. |
| `STALE_BY_DRIFT` | `partial/2` | At least one required provider/project/proposal ID, GitHub source path, full base/head/target-tip OID, state/merged claim, or old/new EC165 reported file-count/quality differs. `comparison.changes` provides field-level before/after facts. Prior controlled EC165 output must not be reused as current evidence. |
| `UNAVAILABLE_UNKNOWN` | `unavailable/5` | Missing permission or Token, incomplete/unsupported metadata, prior-vs-new provenance mismatch, unknown/capped/unreported counts when comparing EC165, or other read failure; no fresh/stale assertion is possible. |

`invalid_input/4` is emitted for malformed/missing/conflicting prior results,
wrong proposal locator, invalid options or invalid input JSON. Such results
also carry `UNAVAILABLE_UNKNOWN`, but indicate bad inputs, not a provider
conclusion. There is deliberately **no `success/0`** state.

A matched EC165 count can only show that an advertised number did not change;
equal numbers do not prove equal changed files. `FRESH_OBSERVATION` therefore
never upgrades a previous receipt to a current immutable diff snapshot or
allows automatic reuse as a live file list. For a capped count such as GitLab
`1000+`, equal old/new cap claims remain `UNAVAILABLE_UNKNOWN`. If the claim
quality changed, old evidence is invalidated even if the current number is
missing: this signals evidentiary drift, not necessarily a proven file edit.

## Example

```bash
cd ces
# Baseline inspection only; no network without explicit opt-in:
python construction/proposed_pr_reconcile.py --provider github \
  --repository owner/repo --number 12 \
  --prior-snapshot /secure/ec165-response.json --json

# Only after independent authorization and minimal Token configuration:
# export CES_GITHUB_TOKEN=...  # set out-of-band, never save in the ZIP
python construction/proposed_pr_reconcile.py --provider github \
  --repository owner/repo --number 12 \
  --prior-snapshot /secure/ec165-response.json \
  --expected-pin /secure/ec162-result.json --allow-network --json

# Pin-only metadata continuity (no prior file-count comparison):
python construction/proposed_pr_reconcile.py --provider gitlab \
  --repository group/project --number 9 \
  --expected-pin /secure/ec162-result.json --allow-network --json
```

The caller must separately ensure that Provider read permissions and output
access are appropriate. Output containing repository/project IDs and commit
OIDs may itself be sensitive. Even if metadata is unchanged, take a **new**
permission-gated EC165 observation if present-day page/path/patch data is
needed; do not splice in earlier blobs/ETags or assume a multi-page atomic
transaction. EC167 merge-commit evidence, EC168 squash/rebase, EC169 saving,
EC170 orchestration and native Reconcile wiring remain future work.

## Development vs. final acceptance

EC166 has 25 targeted **offline synthetic development cases**, plus inherited
EC165 (33), EC164 (33), EC163 (29), EC162 (27) and EC161 (22) cases. These
checks do not use actual GitHub/GitLab API Tokens. Live credentials, concurrent
remote mutations, cross-platform/PowerShell7/15 legacy Smoke, E63-E66 resource
benchmarks and the final user-assisted integrated acceptance remain `NOT_RUN`.
