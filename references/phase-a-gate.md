# EC-160 — Phase A offline static gate contract (v1)

## Entrypoint and outcomes

```text
python construction/stage_a_gate.py
python construction/stage_a_gate.py --json
```

This command reads only files in the **current CES package**. It never runs `pwsh`, Git, Smoke tests, a Provider, external network access or a CES business handler. It prints to stdout; it does not persist a report or mutate the source tree. Only the documented trusted package should supply executable Python: this is not a sandbox for hostile third-party Python.

- Exit **0** with `static_verdict=PASS_STATIC`: all eight offline checks match *local unsigned evidence receipts*. This means **the Phase-A source/contract construction gate** is complete, not the native/runtime/security/final acceptance stage.
- Exit **2** with `static_verdict=BLOCKED`: one or more scoped checks failed. Each item carries `status=BLOCKED` plus an explicit `reason_code` for triage; other checks continue to reveal independent issues. Repair or document a reviewed revision; do **not** auto-baseline drift.
- Exit **3** with `reason_code=STAGE_GATE_UNAVAILABLE`: an unexpected interpreter/tool failure prevents evaluation; it cannot be treated as success.

Independent fields always report `native_verdict=NOT_RUN_NATIVE`, `final_acceptance=NOT_STARTED` and `security_and_custody_limit` even when the static verdict passes. Checks are lexical/string, cross-record SHA and bounded JSON consistency checks, **not** a PowerShell interpreter, cryptographic signature or proof of runtime correctness.

## Scoped checks and stable failure reasons

| Check ID | On failure | What is verified |
|---|---|---|
| `package_plan` | `STAGE_PLAN_INVALID` | V4.70/R160/EC160 current state, EC161 next, 100-round contiguous plan, 10 completed Phase-A reports, original CLI V4.60/R150 and module/Markdown shape |
| `archived_provenance` | `STAGE_RECEIPT_DRIFT` | 156 byte-preserved archived records, 139 SHA ledger members, recorded EC157+EC159 frozen SHA receipt chain, EC153 B-001 absence registration and prior R159 delivery SHA fields |
| `native_source_scope` | `STAGE_SOURCE_DRIFT` | Original 124 PS scripts/15 Smoke digests, exactly five EC159 reviewed PS modifications, unmodified remainder, the one new `pathidentity.ps1`, R150→EC157→EC159 ancestry and no extra modules |
| `imports_and_evidence_inventory` | `STAGE_IMPORT_OR_EVIDENCE_DRIFT` | EC151 305-source inventory, import graph, one trusted dot-source, EC159 cross-module callsites and the EC154 k1..56 public Sequence snapshot (allowing only the precisely reviewed EC159 CodeShow source SHA) |
| `authored_cli_routes` | `STAGE_ROUTE_DRIFT` | EC155 route and source-trace equivalence: 7 Action families, 16 existing routes, 29 proposed items fail-closed as `NOT_IMPLEMENTED` |
| `cli_wire_and_coverage` | `STAGE_WIRE_DRIFT` | `ces.cli.v1` source SHA references, 16 root fields, 31 coverage self-report flags and 0/2/3/4/5 status mapping |
| `actor_and_write_boundaries` | `STAGE_IDENTITY_OR_AUTHORIZATION_DRIFT` | EC159 actor declarations remain unverified; CodeSave retains independent explicit `-ApprovePersist` pre- and post-dispatch gates and main/private-store source calls |
| `blockers_and_native_deferral` | `STAGE_DEPENDENCY_RECORD_INVALID` | B-001 original spec provenance OPEN, B-002 native validation DEFERRED, B-003 Provider permission unavailable; no unsupported native PASS flags |

The source-scope check explicitly **permits only known EC157/EC159 SHA drift**, never arbitrary edits masquerading as Phase A improvements. The historic EC151 literal import map can legitimately differ after reviewed EC159 changes; current import graph must still resolve completely. Unknown files/modules, missing dependency files, symlinked trusted paths, changed original Smoke and changed archive bytes block. JSON is bounded and duplicate metadata keys are rejected in this gate.

## Evidence grades and outstanding obligations

- A local SHA digest identifies *bytes in this copy*. Historic registers are unsigned and sourced from provided packages; a copied/modified manifest is not an independent attestation. B-001 original V3.10/ROUNDS is unresolved (`ORIGINAL_EQUIVALENCE_NOT_PROVEN`) without separately authenticated upstream bytes.
- Source-level evidence may detect removed permission guards or changed declarations; no positive guarantee of authorization or protection from directory swapping/TOCTOU, case-folding quirks, malicious Git configuration or non-atomic path checks is possible without real runtime/platform testing.
- `coverage` bits are the old CLI's self-reported claims; 31 declared keys do not establish executed evidence checks. Partial/unavailable or a synthetic fixture never upgrades an incomplete claim to a true proof.
- The native PowerShell7 CLI, original 15 Smoke, EC157/159 native scenarios, Windows/macOS/Linux Git, E63–E66 resources, real identity/Provider/PR reads and final user-assisted acceptance are intentionally deferred to the full-feature candidate stage under [`FINAL_ACCEPTANCE.md`](../construction/FINAL_ACCEPTANCE.md). The gate does **not** create a new CES Action or grant write permissions.

## Future stages

EC161–250 remain unimplemented/planned until their own rounds. Do not run this fixed Phase-A gate as a universal acceptance gate for future releases: it is deliberately pinned to **V4.70/R160** and reports `BLOCKED` if that scoped checkpoint's state changes. Subsequent stages require their own release-specific evidence and gates or an explicit reviewed revision; reusing `PASS_STATIC` from R160 as an R161+ certificate is invalid.
