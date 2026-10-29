# EC242 cross-domain schema compatibility and migration review — V5.52 / R242

This is a functional **read-only** inspector. It checks an exact local JSON
record against one of the **112 pinned, bundled Draft 2020-12 schemas** spanning
Finding, Quality, Report, Knowledge, Issue, Delivery, Cycle and the shared
router contracts. CodeInsight stays with its **six existing EC158 readers**;
we invoke that legacy checker against the original bytes rather than forge a
universal `schema` field. The additional two/three shared router contracts
are infrastructure, not new enterprise data formats. `jsonschema` 4.x is a
runtime dependency for *positive* Draft 2020-12 structure checks; if absent,
inspect/audit fail closed. This is not a source authenticity checker.

## Run independently

From inside the extracted `ces/` directory:

```sh
python construction/schema_migration_review.py inventory
python construction/schema_migration_review.py audit
python construction/schema_migration_review.py inspect --domain Cycle --input construction/fixtures/schema_review/cycle-v1.json
python construction/schema_migration_review.py inspect --domain CodeInsight --input construction/fixtures/code_insight/ci-example.json --contract code_insight_saved
python construction/schema_migration_review.py inspect --domain Issue --input construction/fixtures/schema_review/issue-unversioned.json --contract issue-create-content.v1
python construction/schema_migration_review.py plan --domain Cycle --input construction/fixtures/schema_review/cycle-v1.json --target-contract cycle-run-metadata.v1
```

For original-byte pinning, supply `--expect-sha256 <64hex>` computed from
*the original file bytes*, not normalized or pretty-printed JSON. For saved
CodeInsight, `--record-id ci-<64hex>` checks that explicitly expected ID through
its existing EC158 reader. Without a hash/record ID, data identity is observed
but not independently pinned. Paths must name stable regular files (no symlink)
or use bounded `--input -` from stdin. Neither access method writes content.

Four new fixed Action/Mode routes in
[`unified_action_router.py`](../construction/unified_action_router.py):
`SchemaReview:Inventory`, `SchemaReview:Audit`, `SchemaReview:Inspect`,
`SchemaReview:Plan`. They are read-only CLI routes with a JSON request:

```json
{"schema":"ces.unified_action_router.request.v1","action":"SchemaReview","mode":"Inspect","argv":["--domain","Cycle","--input","/absolute/path/to/original.json"]}
```

Invoke `python scripts/ces_router.py -Action SchemaReview -Mode Inspect
-RequestPath /absolute/path/to/request.json`, or the existing `ces-v5.ps1`
wrapper on a real PowerShell7 host. These wrapper calls return a routed
handler envelope; **router exit 2 is not a passed schema, business success, or
permission grant**. Inspect the nested handler's own status and exit_code.

## What happens to old data

| Domain | Offline version admission | Unknown / invalid | Migration path |
|---|---|---|---|
| **CodeInsight** | Exact `schema_version` through unchanged EC158 reader; saved file ID from original SHA | Reject future versions, malformed v1, wrong role, mismatched ID | Same-version raw bytes retained; no v2 writer; new attested record required |
| **Finding** | Explicit pinned v1/v2 FindingSave files, v1 in-memory projections and show/correlation shape | Reject stale tags, wrong contract and invalid HMAC-claim shape | v1 → v2 **requires new producer reissue**, original chain/MAC and records kept |
| **Quality** | Versioned result shapes including CI, budget, guard, show and links | Reject unknown version or invalid CI/proof shape | New source-scoped observation, not retagging past CI claims |
| **Report** | Report result/policy shapes, including period and subject related dependencies | Missing/future version cannot be inferred from report title/filename | New reviewed report version/slot with provenance; old published history unchanged |
| **Knowledge** | Candidate, bootstrap, read-policy, save and version-record shapes | Unknown or unbound record rejected | New approved immutable knowledge version; preserve store MAC/version chain |
| **Issue** | Versioned provider, eligibility, plan and write result records; *eight historically unversioned request/grant schemas* require explicit contract | Unversioned data is **shape-only** and never admitted as a versioned migration | Reissue with independently authorized provider/plan/grant, never replay POST |
| **Delivery** | Preview, redaction, identity, authorization, send/status, reconcile, publication shapes | Invalid/old claims do not imply send success | New reviewed outbox/receipt operation; no re-send/re-publish by converter |
| **Cycle** | Run, DAG, next, budget, pause, resume, summary, guard, scheduling and cross-action shape | Unknown run/sidecar tags fail closed; no DAG success inferred | Fresh independently pinned Run and new owner receipts; preserve original evidence |

Validating a contract means **schema structure only**. It never verifies an
Ed25519/HMAC signature, authoritative origin, trusted enterprise identity,
credential permissions, live provider result, source revision, Git state,
semantic correctness, actual execution, quality pass or business completion.
A synthetic signature-shaped string remains synthetic.

The `plan` command has two safe results: known *same contract* gives
`NOOP_KEEP_EXACT_ORIGINAL_BYTES`; otherwise it describes
`BLOCKED_NEW_IMMUTABLE_RECORD_REQUIRED` or `QUARANTINE_NO_TRANSFORM`.
**No migration writes or automatic transcodes exist in this EC.** A different
version requires a separately reviewed producer, exact old-byte identity,
new unique record ID, HMAC/signature/authorization/source rechecks and a
rollback selection method preserving old immutable bytes. Never edit the
old record or reserialize it under a new filename: raw SHA and record MAC
would change and might wrongly promote unverified history to valid authority.

## Actual corpus anomalies: do not silently 'repair'

`audit` currently reports 112 pinned schema contracts and **zero schema-byte
drift**, but intentionally returns `review_required` / exit 2 because:

- FindingSave **v1 and v2 have different version tags but the same `$id`**.
  Runtime resolves by exact pinned local path and tag; `$id`-only selection
  must not be used until a separate reviewed reissue. We did **not** edit
  either historical schema source.
- **Nine** historical Knowledge JSON schemas lack `$id`; explicit local file
  pinning works but network/URI schema discovery is not reliable.
- **Nine** root documents (eight Issue request/grant contracts plus one
  Delivery audit event) have no top-level version marker; they can be
  inspected **only by an explicitly named contract**. Do not auto-upgrade
  these from an inferred version.

The static catalog is `construction/SCHEMA_CATALOG.json`, with an exact
SHA-256 pin for every schema plus existing EC158 policy and reader source. An
unregistered future file, changed schema bytes, unexpected external `$ref`,
invalid JSON Schema, or missing `jsonschema` dependency must not be considered
accepted. Neither a SHA match nor this catalog proves an authentic upstream
release: original frozen V3.10 specs and old ROUNDS provenance (B001) are
still missing. The catalog includes EC242's own result schema and the EC241
router schema, which is now revised to package metadata V5.52/R242.

## Outputs / delegated acceptance

The result is one bounded ASCII JSON object against
[`schema-migration-review-result.v1.schema.json`](schema-migration-review-result.v1.schema.json).
`0` means source bytes conformed **structurally** to an exact known version,
or read-only inventory; `2` means planned migration blocked or legacy debt;
`3/4` indicate hard reject/invalid request; `5` means unavailable or source
pin drift. Nothing grants permissions; all results have
`migration_executed=false`, `original_bytes_rewritten=false`,
`source_authority_verified=false` and `external_network_used=false`.

Local fixture inspection and 22 dedicated focused cases have run. Real saved
enterprise records and authentic signature/provider/CI/code states, native
PowerShell7/15 Smoke, original B001, Windows/macOS, E63–E66 and final
user-assisted acceptance remain **NOT_RUN/UNKNOWN**. See
[`EC-242.md`](../EC-242.md) and
[`FINAL_ACCEPTANCE.md`](../construction/FINAL_ACCEPTANCE.md).
