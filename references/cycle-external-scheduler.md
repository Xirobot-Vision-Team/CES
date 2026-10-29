# EC239 — External recurring scheduler invocation boundary (V5.49/R239)

**Feature delivered:** `construction/cycle_external_scheduler.py` is a real callable
`CycleExternalSchedulerBoundary.plan()/invoke()` and CLI. It is **not** an
installed scheduling service, an executor of CES business operations, an
approval service or a proof that any scheduler/trigger actually exists.
`invoke()` invokes **one** existing, real EC237 read-only `CycleSummaryReporter`
inspection of a previously persisted EC231 RunId. Summary in turn checks the
EC232 DAG, live EC233 source-backed Next route and optional EC235 persisted
DENY sidecar. There is no path to native handler dispatch, business writes,
CodeSave, AI handoff execution, delivery or permission elevation.

## Trust contract and explicit preconditions

1. Use an **existing**, dedicated, absolute, owner-private EC231 metadata
   directory and its **genuine persisted** `run_v1_...`. The existing storage
   is POSIX-only (`0700` directory / `0600` regular record, no symlink leaf).
   This EC does **not** add native Windows storage support.
2. Supply all three SHA-256 pins from the prior run, ideally saved outside the
   current private store: `record_sha256`, `action_set_sha256` and `input.sha256`.
   This module compares them to the original loaded record and rereads the
   original before and after inspection. Self-hashes / independently saved
   SHA pins are **not** authoritative source signatures or actor proof.
3. Explicitly state the **caller claim** `--host-state absent` or
   `--host-state claimed_configured`, with declared
   `--scheduler-kind cron|windows_task|orchestrator` and a bounded opaque
   `--schedule-id`. Nothing probes the host, registers a task, installs cron,
   checks the service's identity, reads credentials or establishes actual
   cadence. `claimed_configured` is **not** `VERIFIED_INSTALLED`.
4. Choose a supported UTC **reference cadence**: `hourly` (top of hour),
   `daily` (00:00 UTC), `weekly` (Monday 00:00 UTC). These are exact *tick
   shapes*, not proof a scheduler observed them. The user/operator must
   configure the real external host to the same UTC cadence. Windows DST,
   host timezone mismatch, worker failure and external clock trust are not
   detectable by this module.
5. For `invoke`, the host must explicitly supply an event ID (`evt_` + 12–80
   bounded alphanumeric/underscore/hyphen chars) and a scheduled UTC tick in
   `YYYY-MM-DDTHH:MM:SS.ffffffZ`. The tick must be aligned with the declared
   cadence. Neither field is authenticated or evidence of a real scheduled
   firing, unique delivery, scheduler liveness or on-time arrival. Missing or
   malformed events and declared-absent schedulers are **rejected before**
   any read-only Summary work. An actual direct/manual caller can still lie
   about `claimed_configured`: the output explicitly says so.
6. Keep this boundary **unprivileged**: a caller that needs CodeSave, task
   dispatch, credentials, report publishing, AI execution or a native CES
   `Cycle` route must use the independent later authorization/implementation
   path, **not** a successful EC239 result. Do not reuse a Summary response as
   business success, completed dependency, grant or execution receipt.

## Python API

```python
from construction.cycle_external_scheduler import CycleExternalSchedulerBoundary

b = CycleExternalSchedulerBoundary('/absolute/private/ec231-store')
common = dict(
    cadence='hourly', scheduler_kind='cron',
    host_state='absent', schedule_id='ces-hourly-check',
    expected_record_sha256='<externally-saved-64-hex>',
    expected_action_set_sha256='<externally-saved-64-hex>',
    expected_input_sha256='<externally-saved-64-hex>',
)

# Returns CLI argument-vector instructions; NO job is installed, NO check run.
instructions = b.plan('run_v1_<real-48-hex>', **common)

# A host whose job was configured elsewhere MAY call this read-only inspector.
# Replace the example values with the host's own declared event and UTC tick.
common['host_state'] = 'claimed_configured'
result = b.invoke('run_v1_<real-48-hex>', **common,
    trigger_id='evt_20261024_150000_01',
    scheduled_for_utc='2026-10-24T15:00:00.000000Z')
```

Both operations return the strict
[`cycle-external-scheduler.v1.schema.json`](cycle-external-scheduler.v1.schema.json)
envelope, preserving **false** for `scheduler.external_installation_verified`,
`external_cadence_verified`, `external_trigger_authenticated`,
`trigger.execution_on_schedule_proven`, `trigger.deduplication_checked`,
and **every** business effect. Only `effects.local_read_only_summary_observed`
may be true for an actual validated read-only Summary result.

## CLI: plan first, then let the external host call invoke

```sh
python3 construction/cycle_external_scheduler.py plan \
  --store /absolute/private/ec231-store \
  --run-id run_v1_<real-48-hex> \
  --cadence hourly \
  --scheduler-kind cron \
  --host-state absent \
  --schedule-id ces-hourly-check \
  --expected-record-sha256 <saved-64-hex> \
  --expected-action-set-sha256 <saved-64-hex> \
  --expected-input-sha256 <saved-64-hex>
```

`plan` checks an existing run and its exact SHA pins but **does not** invoke
Summary. With a declared absent host it returns `INSTRUCTIONS_ONLY` and an
`invocation.command_argv_template`, with two **clearly unfilled** arguments:
`--trigger-id` and `--scheduled-for-utc`. The resulting argv is intended to
be put into a separately managed scheduler *after* adapting Python, paths,
permission context and runtime environment on the actual host. Treat the
placeholders as required inputs, never literal successful data. With
`claimed_configured` the same plan returns `CONFIG_CLAIM_ONLY`: no installation
or successful firing has been verified in either case.

Once an **operator** configures and inspects a real scheduler externally, its
entrypoint can call (for example):

```sh
python3 construction/cycle_external_scheduler.py invoke \
  --store /absolute/private/ec231-store \
  --run-id run_v1_<real-48-hex> \
  --cadence hourly \
  --scheduler-kind cron \
  --host-state claimed_configured \
  --schedule-id ces-hourly-check \
  --expected-record-sha256 <saved-64-hex> \
  --expected-action-set-sha256 <saved-64-hex> \
  --expected-input-sha256 <saved-64-hex> \
  --trigger-id evt_20261024_150000_01 \
  --scheduled-for-utc 2026-10-24T15:00:00.000000Z
```

The `--scheduled-for-utc` value is **the host's declared schedule tick**, not
`date` at completion; calculating `now` just before/after a clock boundary can
select the wrong tick. The calling system must pass and retain its own intended
tick and event ID, without asking this boundary to infer or certify arrival.
The module executes **no** returned `argv` with shell or subprocess: it directly
calls the Python EC237 Summary class during a valid `invoke`.

**Host setup references, not registrations performed by CES:**

| Host chosen by operator | Reference schedule | Operator responsibilities |
|---|---|---|
| cron | `0 * * * *` / `0 0 * * *` / `0 0 * * 1` | Verify the actual job uses UTC (cron TZ support differs), add a host-owned wrapper that supplies a unique event ID and the intended UTC tick, verify logs and access controls |
| Windows Task Scheduler | hourly / daily midnight / Monday midnight **UTC** | Configure independently in the GUI or your deployment system; translate local-time/DST semantics to intended UTC tick; native EC231 POSIX private storage cannot run directly on Windows without separately implemented support |
| External orchestrator | same UTC reference cadence | Register and enable the job **outside CES**; inject fixed run pins and per-event ID/tick; verify host identity, liveness and retries using orchestrator features |

Do **not** copy a placeholder template directly into cron or `schtasks` and
expect it to work. There is no `schtasks /Create`, `crontab` edit, daemon,
service, timer, database or host discovery hidden in this delivery.

## Strict status / exit-code semantics

| Status | Exit | Meaning |
|---|---:|---|
| `INSTRUCTIONS_ONLY` | 2 | Host declared absent; valid old run/pins and argv instructions, no check performed |
| `CONFIG_CLAIM_ONLY` | 2 | Host **claims** scheduler configured; not checked, no inspection performed |
| `CHECK_OBSERVED_ONLY` | 2 | One EC237 read-only Summary returned a known, not independently attested view; **not** Cycle success |
| `CHECK_BLOCKED` | 3 | EC237 found known DAG / unsupported handler / unverified progress block; no execution |
| `PLAN_REJECTED` or `TRIGGER_REJECTED` | 3 | Known invalid request, off-cadence event or declared absent host; no Summary |
| `UNKNOWN_BLOCKED` | 5 | Missing/corrupt/drifting/pin-mismatched private record, invalid Summary or uncertain state; redacts summary and record data |

The API always returns a single complete bounded ASCII JSON line via CLI.
`2` is an intentionally **nonzero** observational outcome (so never treat
exit `0` as complete business success). The host wrapper must interpret
`2/3/5` as *inspection status*, not a reason to automatically retry business
writes. Unknown output or interrupted stdout is not a commit or receipt.

**Repeat/overlap:** repeated `invoke` with the same claimed trigger is allowed
and explicitly reported as **not deduplicated**. No durable event receipt,
lock, once-only side effect, overlap protection, restart continuation or
retry-protocol exists in this EC. EC240 owns interrupted, duplicate and
concurrency semantics; EC241 owns native Cycle routing. Do not attach
write-authority to the EC239 entrypoint.

## Scope of observed checks vs deferred acceptance

Local tests create **genuine new EC231 private records with synthetic bytes**,
then run real EC232/233/237 read-only source checks. They test plan-only,
external-claim invoke, UTC cadence alignment, absent/missing/invalid hosts and
events, SHA pin mismatch, corrupt/nonprivate data, summary refusal, CLI
statuses, result JSON Schema and unchanged persisted records. No actual cron,
Windows job, orchestrator, actor/source identity verification, CodeSave grant,
real scheduled firing, external liveness, multi-host replay/lock, Windows or
macOS native implementation, PowerShell7 original 15 Smoke, E63–E66 or final
user-assisted acceptance was run. Upstream V3.10/ROUNDS B001 remains **OPEN**.
