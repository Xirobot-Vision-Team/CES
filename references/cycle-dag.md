# EC232 Cycle DAG validation — read-only graph analysis, **not execution**

Release **V5.42/R232/EC232**. Use [`construction/cycle_dag.py`](../construction/cycle_dag.py)
against a **real existing EC231 run** stored by
[`CycleMetadataStore.create()`](../construction/cycle_run_metadata.py).
Machine result contract: [`cycle-dag-result.v1.schema.json`](cycle-dag-result.v1.schema.json).
Original CES PowerShell CLI remains V4.60/R150; there is no native
`Cycle -Mode Next`, task handler dispatch, permission system, resume, or
execution budget enforcement in EC232.

## What the checker does

1. Requires an EC231 `run_v1_<48 lower-hex>` identifier and opens the **existing**
   private `0700` record directory through EC231's strict, read-only loader;
   never creates directories or records. EC231 validates the exact run ID
   against the filename; JSON shape, step list order, all action references,
   independent ActionSet and record SHA-256 digests, anti-claim actor/source
   flags, budgets, and immutable dependency placeholder are rechecked.
   **Self-hashes are not signatures.** Same-UID rewrite-and-rehash, filesystem
   rollback, or altered underlying source cannot be detected without external
   evidence; optional caller pins can detect *divergence* from a separately
   retained byte-for-byte hash, not grant authority.
2. Enforces all EC231 action rules: **1–32 steps**, distinct safe step IDs,
   existing referenced prerequisites, no duplicate prerequisite and no
   self-edge. A malformed/resealed record or missing/unreadable store becomes
   `UNKNOWN_BLOCKED`, with no partial order, digest/provenance disclosure or
   default successful state. EC231's creation of a cyclic action declaration
   remains possible: **only this EC232 inspection detects the cycle**.
3. Runs a deterministic bounded Kahn topological **wave** algorithm. Steps
   with zero outstanding prerequisites appear in each wave, in original
   `action_set` declaration order, and newly freed steps enter the **next**
   wave. `topological_order` is the flattened wave order; it does not change
   with Python set/dict order or the order of `depends_on` entries. For an
   acyclic graph it returns `DAG_VALID_NO_EXECUTION` with ordered waves.
4. If any cycle prevents full ordering, it returns **`DAG_CYCLE_BLOCKED`**
   instead of a partial actionable order. Tarjan strongly connected
   components identify **all** multi-node cycles. `cycle_components` contain
   only genuinely cyclic SCC members, whereas `blocked_step_ids` also includes
   downstream steps held behind cycles. A deterministic shortest closed
   `cycle_witness` contains real dependency arcs in the form
   `dependent -> prerequisite -> ... -> dependent`. Other independent
   components are not falsely marked cyclic.
5. The result binds the source `run_id`, EC231 `record_sha256`, original
   `action_set_sha256`, `input.sha256`, and an EC232 domain-separated
   `graph_sha256`. It carries declared, **unverified** source/actor labels and
   the historical `metadata_run_state` exactly as stored; **nothing** changes
   the EC231 file's `dependency_resolution=NOT_EVALUATED_EC232`. The new
   in-memory graph observation is not an EC231 metadata state transition.

## Example

```python
from pathlib import Path
from construction.cycle_run_metadata import CycleMetadataStore
from construction.cycle_dag import CycleDagInspector

private_dir = Path('/host-private/ces-cycle-records')  # existing host-selected 0700 dir
store = CycleMetadataStore(private_dir)
record = store.create(
    snapshot_bytes=b'{"repo":"host-controlled snapshot"}',
    source_ref='git:repo/snapshot-1',
    actor_origin='human', actor_subject='declared-operator',
    actions=[
        {'step_id':'step_code', 'action':'CodePrepare', 'mode':'Snapshot', 'depends_on':[]},
        {'step_id':'step_quality', 'action':'QualityRun', 'mode':None,
         'depends_on':['step_code']},
        {'step_id':'step_report', 'action':'ReportPrepare', 'mode':None,
         'depends_on':['step_quality']},
    ],
)
result = CycleDagInspector(private_dir).check(
    record['run_id'],
    expected_record_sha256=record['record_sha256'],
    expected_action_set_sha256=record['action_set_sha256'],
    expected_input_sha256=record['input']['sha256'],
)
assert result['status'] == 'DAG_VALID_NO_EXECUTION'
assert result['topological_layers'] == [
    ['step_code'], ['step_quality'], ['step_report']]
assert result['effects']['can_dispatch'] is False
```

`expected_*` digests are **optional**. For meaningful drift checks, they must
come from an independently retained, authenticated provenance workflow;
supplying values read from the same possibly tampered file adds no
protection. No separate digest comparison authenticates the declared actor,
source, provider, permissions, or snapshot currency.

## CLI

```bash
python construction/cycle_dag.py check \
  --store /host-private/ces-cycle-records \
  --run-id run_v1_<48_lower_hex_digits> \
  --expected-record-sha256 <64_lower_hex_digits>
```

The CLI emits **one complete JSON object** described by the schema. Exit
`0` means **only** the DAG is acyclic and all loaded local EC231 structural
checks passed; it does **not** mean Cycle succeeded. Exit `3` means an
explicit cycle, and exit `5` means invalid/unknown/missing/pin-mismatched
metadata or a read failure. Argument usage failures use argparse's exit `2`.
The result's `trust.*` and `effects.*` fields are always conservative: actor
and source unauthenticated, permission absent, `steps_executed=false`,
`can_dispatch=false`, `can_resume=false`, `write_authorized=false`, and no
native Cycle action. Even a valid DAG with `metadata_run_state=NOT_STARTED`
(or historical `PARTIAL`/`UNKNOWN`) is **not** proof of step execution.

### Edge-case behavior

- Two-node or longer cycles: `DAG_CYCLE_BLOCKED` and a real closed witness;
  no `topological_order` or partial layer list is exposed to executors.
- Multiple disjoint cycles: all SCC groups are reported in deterministic
  declaration order; only the first group's closed witness is selected.
- Invalid refs, self-edges and duplicate edges: EC231's strict loader
  rejects the saved record, yielding `UNKNOWN_BLOCKED` with the original
  `CYCLE_DEPENDENCY_*` reason code; malformed declarations were rejected
  before EC231 create. A complete, internally consistent but cyclic EC231
  record produces a **distinct** explicit `DAG_CYCLE_BLOCKED` status.
- Missing, corrupt, non-private, symlink/hardlink, or modified but
  externally pinned mismatching record: `UNKNOWN_BLOCKED`. An unknown
  record is **not** interpreted as a newly unstarted task.
- At the 32-node budget the graph algorithm remains bounded. It performs
  no network call, Git operation, handler invocation or write. External
  source/permission checks, durable execution-state transitions, runtime
  budgets, scheduler, Next and Resume belong to later ECs.

## Development vs final acceptance

The EC232 focused tests exercise real disposable EC231 private records,
multiple cycles/SCCs, deterministic order, bounded 32-step dense graphs,
corrupt/malformed data, anti-privilege flags, independent digest pin mismatch,
file permissions/symlinks, CLI exit codes, and the strict Draft2020-12 result
schema. These are local development checks, **not** native PowerShell7,
original 15 Smoke, enterprise identity/source/permission validation, real
business-source/handler inspection, crash/NFS/multihost/OS hardening, E63–E66,
or final user-assisted acceptance. The upstream B-001 evidence gap remains
OPEN. EC233 alone will decide whether any graph node may be routed to an
**actually registered** handler; EC232 does not answer that question.
