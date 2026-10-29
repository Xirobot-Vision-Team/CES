# CES schema compatibility: EC-158 v1 admission contract

**Current implementation:** read-only/offline schema admission and upgrade **preview**, not a new PowerShell wire version and not a migration writer. The machine policy is [`schema-compatibility.v1.json`](schema-compatibility.v1.json), the implementation is [`../construction/schema_compat.py`](../construction/schema_compat.py), and the precise provenance/write boundary remains [`../construction/SECURITY_BOUNDARIES.json`](../construction/SECURITY_BOUNDARIES.json).

## Identity is not the construction version

- **Package V4.68/R158/EC-158** describes construction progress; `scripts/ces.ps1` still advertises product `V4.60/R150` over existing **`ces.cli.v1`**. Neither package/build number is a schema selector.
- Saved **Collect** evidence is an entire `ces.cli.v1` envelope with `action=Collect`, not an invented `ces.collect.v1`. Success/partial means a captured local observation, not an immutable or independently authenticated source snapshot.
- `ces.code_packet.v1` is the `data.review_packet` object inside a CodePrepare response. `ces.code_insight_draft.v1` is a separate model-authored JSON file consumed by CodeValidate, not verified business truth.
- `ces.code_insight_checked.v1` is an *output_schema marker in the CodeValidate envelope data*, not a separate saved file format; CodeSave emits `ces.code_insight_saved.v1` only after its own native review gate and explicit authorization.
- `ces.local_store.v1` denotes the exact `owner.json` bytes, not a general permission to write a repository.
- All CodeShow modes, including **Sequence k1..56**, use the same `ces.cli.v1` outer response. Their deep `data` structures are frozen by prior code and must be treated as opaque, not up-converted by the compatibility inspector.

## Read-compatibility table

| Family | Recognized v1 tag | Unknown/missing fields | Read result | Source authority |
|---|---|---|---|---|
| CLI response | `ces.cli.v1` | All 16 outer keys required; `data` may explicitly be null; unknown coverage flags must be boolean; deep data opaque | Offline envelope shape/status/known flags | Native CLI Finish (unexecuted here) |
| Collect evidence | `ces.cli.v1` with `action=Collect` | No implicit selector/hash/atomic defaults; native Reconcile checks source-dependent fields | Offline shape subset; not source match | Native Reconcile |
| CodePrepare packet | `ces.code_packet.v1` | Fixed outer fields; nested source data is untrusted/opaque | Offline shape subset | Native CodePrepare/CodeValidate |
| CodeInsight draft | `ces.code_insight_draft.v1` | Fixed keys; optional claimed start/end provided together only | Offline shape subset; no evidence anchoring | Native CodeValidate |
| CodeInsight saved | `ces.code_insight_saved.v1` | Reject all unknown/missing top-level or checked-finding keys; null is required for unknown claimed-line pair | Offline bounded shape and exact-byte SHA; no verified root | Native CodeShow verified main root + store |
| Store owner marker | `ces.local_store.v1` | Exactly matching fixed three-key UTF-8 byte string; no repair | Exact byte comparison | Native CodeSave/CodeShow owner guard |

The offline envelope inspector also checks only the **shallow version-bearing markers** when present: `CodeValidate.data.output_schema`, `CodePrepare.data.review_packet.schema_version`, and `CodeSave.data.record_schema`/reported ID-to-SHA coherence. CodeShow high-order output remains entirely opaque. These are self-reported structure checks, not independent native validation.

The offline parser is deliberately **stricter** than the plain EC-156 consumer for case-colliding JSON keys. It rejects missing/unrecognized versions, trailing data, duplicate or case-colliding properties, unpaired Unicode surrogates, depth above 32, oversized files, record IDs mismatching the exact original bytes, and saved records that assert unproven provenance/CI/semantic/line correctness. It retains opaque envelope additions only as uninterpreted source data; it **never** applies invented defaults to persisted CodeInsight or patches historical records. Legacy v1 readers keep reading original v1 bytes without a migration.

`CodeSave` builds a deterministic JSON body, takes SHA-256 of the **raw UTF-8 bytes**, and writes `ci-<digest>.json`. The current PowerShell CodeShow checks filename/content digest, shape, owner marker and verified main worktree. Reordering JSON keys, pretty-printing, canonicalizing paths/dates, inferring missing fields, or producing a read-side v2 view does **not** preserve the original content identity. File-name SHA equality is not cryptographic authentication of an author, provenance, current Git state, or a guaranteed atomic read.

## Compatible reading, blocked migration, reversibility

- **Known version:** route by the exact `schema_version` plus family/placement, preserve original byte identity and unrecognized nested `data` without normalization; return only a bounded metadata/issue report. Schema compatibility does not imply native action completion or trusted semantics.
- **Missing or future/unknown version:** fail closed with an explanatory issue. Never sniff the filename or infer `ces.cli.v1` from `product_version`; never downgrade a future record into v1 based on overlapping field names.
- **Missing v1 fields:** saved-record keys and checked finding keys are mandatory even if some values are `null` (line claims) or `false` (proof flags). CLI `data: null` is valid, missing `data` is not. Missing `line_start/line_end` *on a draft* is valid as a pair; that is not a verified line number and not a persisted default.
- **Future evolution:** new **version tag** and separate reviewed reader/adapter plus narrow documented typed defaults for *new read-side views* only. New writer requires versioned migration plan, exact input SHA/ID, reviewed EC-157 authorization boundary and explicit consent. Write a **new** immutable ID using no-clobber operations; never overwrite `owner.json`/legacy records or change business source/Git/Issue. Do not add `schema_version` blindly to historical JSON.
- **Rollback:** EC-158 creates no new artifact and has nothing to roll back. For any later authorized migration, retain all old bytes/IDs; selection should be reversible without changing historical content. **No v2 upgrade, selection switch, rollback mutation or approval mechanism is implemented now.**

## Run the actual offline implementation

Execute from inside `ces/` (Python standard library; does not require Git/pwsh):

```bash
python construction/schema_compat.py policy --json
python construction/schema_compat.py inspect --kind code_insight_saved --input construction/fixtures/ec158/ci-example.json --json
python construction/schema_compat.py inspect --input construction/fixtures/ec158/collect.v1.json --json
python construction/schema_compat.py preview --input construction/fixtures/ec158/ci-example.json --target ces.code_insight_saved.v1 --json
python construction/schema_compat.py preview --input construction/fixtures/ec158/ci-example.json --target ces.code_insight_saved.v2 --json
```

The supplied `ci-example.json` is deliberately **not** named `ci-<digest>.json`, so the reader reports a computed, **unbound** ID. A real captured record at its `ci-<64hex>.json` path is hash-matched automatically; optional `--record-id ci-<64hex>` additionally checks an expected ID. No command writes, changes source, or alters a file. Tool return codes: `0` compatible/identity preview; `1` rejected schema or migration blocked; `2` unreadable/bad JSON/unsafe input. A parse success is **not** the native CodeShow integrity/provenance acceptance or a source inspection.

**Trust and verification limitations:** [`../construction/FINAL_ACCEPTANCE.md`](../construction/FINAL_ACCEPTANCE.md) records PowerShell7, Windows/macOS/Git, the original 15 Smoke suites, E63–E66 and remote end-to-end verification as postponed. The old V3.10/original `ROUNDS.json` source is still missing; this policy is a reviewed current-source contract, not an original frozen specification restoration.
