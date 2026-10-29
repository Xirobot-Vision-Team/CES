# EC231: Cycle Run metadata v1 — **metadata only**

Release: **V5.41/R231/EC231**. This is a callable **standalone Python**
metadata facility, not the `Cycle` PowerShell Action, a task runner, a DAG
scheduler, a permission gate or a trusted resumption system. Its contract is
[`cycle-run-metadata.v1.schema.json`](cycle-run-metadata.v1.schema.json);
strict cross-field validation is implemented in
[`../construction/cycle_run_metadata.py`](../construction/cycle_run_metadata.py).

## Actual behavior

- `CycleMetadataStore(private_dir).create(snapshot_bytes=..., source_ref=...,
  actor_origin=..., actor_subject=..., actions=...)` first checks the exact
  nonempty **bytes** of a caller-provided input snapshot (max 1 MiB),
  declared actor, ordered 1–32 distinct action/step IDs, dependencies,
  and five budget limits. It does **not** trust a caller-submitted SHA in
  place of bytes, infer a native handler, or issue run/action permissions.
- On a supported local POSIX host, creation allocates an independent,
  cryptographically random 192-bit `run_v1_` ID and writes
  `<private_dir>/<RunId>.cycle.json` using exclusive create, exact
  owner `0700` directory and `0600` regular non-hardlinked file, fsync
  of file and containing directory, then readback. The RunId is only
  returned after local storage succeeds. Existing records are never
  overwritten. The full snapshot bytes are **not stored**: only raw SHA256,
  byte count, declared source label and unverified completeness label.
  No evidence that the caller snapshot matches any live repository/remote
  system is asserted.
- `load(run_id)` reads an exact bounded, private record, verifies the
  unsigned domain-separated canonical record hash and action-set hash,
  structurally checks each step's reference, timestamp, limited usage,
  no-effect flags and status; it cannot authenticate an actor or audit
  against a malicious same-UID writer. `inspect(run_id)` reports an
  invalid/missing/unreadable saved record as `UNKNOWN` and never invents
  `NOT_STARTED` in that case. Both **always** report
  `execution_proven=false`, `can_resume=false` for inspect.
- `validate_record(dict)` also checks historical/transferred metadata:
  permitted states are `NOT_STARTED`, `PARTIAL`, `UNKNOWN`, derived from
  `steps`: any `UNKNOWN` overrides `PARTIAL`; otherwise any
  `DECLARED_PARTIAL` yields `PARTIAL`; otherwise `NOT_STARTED`. A partial
  step must have an untrusted observation digest/reason and a UTC time
  between creation and update; an unknown step must have a reason and **no**
  evidence or timestamp. No `COMPLETED` or `SUCCESS` execution state exists.
  **EC231 creation always starts all steps `NOT_STARTED`;** there is no
  EC231 mutation API to mark steps partial, unknown, complete or ready.
  A handoff ID field may only be a syntax-checked placeholder; provenance
  linkage to the same run is intentionally deferred to EC238.

## Authoring an action set

Each action set entry must contain exactly four keys: `step_id` (safe `step_`
ASCII token), `action` (e.g. `CodePrepare`), nullable `mode`, and
`depends_on` (list of existing other step IDs). Preserve array order.
For example:

```json
[
  {"step_id":"step_code","action":"CodePrepare","mode":"Snapshot","depends_on":[]},
  {"step_id":"step_quality","action":"QualityRun","mode":null,"depends_on":["step_code"]},
  {"step_id":"step_report","action":"ReportPrepare","mode":null,"depends_on":["step_quality"]}
]
```

These are **caller-declared requests**, not proof that the exact action/mode
is implemented, routable, has permissions or succeeded. Missing IDs,
duplicates, self dependencies, invalid tokens or >32 steps are rejected.
Cross-step dependency cycles are **not** checked, sorted or executed in
EC231. Do not feed this metadata directly into a task executor: EC232 must
implement DAG validation first, EC233 must implement registered next-step
routing, and EC235 must handle permission pauses.

## API (Python 3, standard library only)

```python
from pathlib import Path
from construction.cycle_run_metadata import CycleMetadataStore

store = CycleMetadataStore(Path('/host-private/ces-cycle-records'))
record = store.create(
    snapshot_bytes=b'{"my_snapshot":"real caller supplied bytes"}',
    source_ref='host:repo1/sha256-snapshot',
    actor_origin='human', actor_subject='operator-1',
    actions=[{"step_id":"step_code","action":"CodePrepare",
              "mode":"Snapshot","depends_on":[]}],
    input_completeness='UNKNOWN',
)
print(record['run_id'], record['run_state'])  # real stored RunId; NOT_STARTED
print(store.inspect(record['run_id'])['execution_proven'])  # False
```

Pass an **existing** private root or a parent whose child can be safely
created; `/host-private/...` above is an illustrative host-provided path,
not a packaged default. Do not copy secrets into actor/source labels.
Run local CLI with two **local regular input files** (never a network URL):

```bash
python construction/cycle_run_metadata.py create \
  --store /host-private/ces-cycle-records \
  --snapshot-file /host-private/input.snapshot \
  --source-ref host:input.snapshot \
  --actor-origin human --actor-subject operator-1 \
  --actions-json /host-private/actions.json
python construction/cycle_run_metadata.py inspect \
  --store /host-private/ces-cycle-records --run-id run_v1_<48_lowercase_hex_chars>
```

Successful CLI `create` emits `status=metadata_created_not_started`
and exit 0 **for metadata creation only**, not for successful Cycle
execution. `inspect` emits `UNKNOWN` with exit 5 if a run is absent,
unreadable, damaged or ambiguous. API exception codes are stable
`CYCLE_*` strings. The standalone CLI is **not** registered through the
embedded PowerShell `scripts/ces.ps1` (still V4.60/R150).

## Schema and safety boundaries

`created_at_utc`, `updated_at_utc`, and optional partial observation time
use strict UTC microseconds (`YYYY-MM-DDTHH:MM:SS.ffffffZ`), supported years
2020–2100, and a maximum 30-day declared record horizon. The source is
`UNVERIFIED_HOST_UTC`, **not** an authenticated timestamp.

Budget limits: 1–32 `max_steps`, `wall_ms` 1–86,400,000, `input_bytes`
1–1,048,576, `evidence_bytes`/`output_bytes` 1–8,388,608 each.
Initial usage binds the actual captured input bytes; all execution
consumption starts zero. The `CAPTURE_ONLY_NO_RUN_ENFORCEMENT` flag is
mandatory. This is not EC234's runtime time/rate/resource limiter.

An on-disk SHA256 self-hash detects accidental corruption, but **is not**
a MAC, timestamp authority, transaction log, reviewer signature,
source currentness proof or protection against a same-UID adversary able to
rewrite a record and its hash. Local POSIX fsync/exclusive create is not
equivalent to verified power-loss/NFS/multi-host durability; if commit
readback or fsync is uncertain, no RunId is reported and the uncertain
record is intentionally not automatically deleted/retried. The facility
never writes business repositories, mutates existing task/issue/provider
content, runs actions, grants rights or resumes interrupted work.

### Development / deferred checks

The EC231 test module exercises real local temporary metadata storage,
strict parsing, cross-field invariants, malformed data, conservative states,
file permissions, no overwrites, CLI create/inspect and schema. This is
*development evidence*, not enterprise acceptance. Original PowerShell7,
15 Smoke, E63–E66, Windows/macOS, live repositories/actors, multi-host
storage, same-UID attacks, OS power loss and final user-assisted end-to-end
acceptance remain **NOT_RUN**. See [`EC-231.md`](../EC-231.md) and
[`NEXT_ROUND.md`](../construction/NEXT_ROUND.md). EC232 alone will implement
DAG cycle detection/topological ordering; no EC232–EC240 feature was
implemented here.
