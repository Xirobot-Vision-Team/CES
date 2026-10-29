# EC-240: Cycle invocation / attachment conflict guard (V5.50/R240)

## What actually runs

`construction/cycle_conflict_guard.py` is a **new opt-in POSIX local guarded
entrypoint**, not a replacement for the original PowerShell CLI. It supports:

| Operation | Real covered work | Durable state | Business permission |
|---|---|---|---|
| `scheduled_summary` | Preflights EC239 plan then actually invokes one EC239 `invoke` / EC237 **read-only Summary** on first valid slot | A per-EC231-Run reservation and finalized SHA-only local receipt | **Never** |
| `artifact_attach` | Preflights genuine existing EC238 cross-action owner + live EC172 stage + exact producer bytes, then actually calls EC238 **local-only** `attach` once on first valid slot | Same run-wide ledger; no second local artifact registration for identical slot | **Never** |
| `inspect` | Reads a previously stored local receipt, including quarantined interrupted state | Read-only snapshot; no lock creation | **Never** |
| `business_write_attempt` | Rejects all requests for business mutations/permission grants | No reservation, no underlying writer | **Always denied** |

Input EC231 RunId must exist in the **same owner-private, absolute, 0700
POSIX directory** used by EC231; original EC231 RunId and all three externally
kept SHA pins must match the live immutable record. This does not verify
where external pins came from. It never creates a Cycle Run, grants CodeSave,
resumes a paused task, creates a scheduled job or calls a native PowerShell
business handler. The EC238 *artifact receipt* is CES-local metadata, **not
upload to a remote service or proof that an original producer ran**.

**Opt-in is critical:** calling old `cycle_external_scheduler.py` or
`cycle_cross_action.py` directly is **not protected** by EC240's lock/ledger.
No process outside this wrapper is made cooperative; existing EC238 `link`
and old EC235/other owner files remain separate, not one atomic transaction.
Use the guarded entrypoint wherever its guarantees are needed.

## First invocation and repeat semantics

- Use `scheduled_summary` with the original EC239 UTC cadence, scheduler kind,
  claimed configured state, schedule ID, external event ID and exact UTC tick.
  The local logical slot is **(Run, schedule ID, cadence, tick)**; the stored
  intent additionally binds trigger ID, kind, state and three external pins.
  Even if a caller supplies a *new* event ID for the same tick, that tick
  cannot call Summary a second time through the guard. Reusing an event ID
  for a *different* tick is a conflict. A new valid tick can execute later,
  provided the Run has no interrupted reservations and capacity remains.
- Use `artifact_attach` only **after EC238 `link` completed** and its genuine
  original input snapshot / live HMAC-stage owner is available. The local
  slot is **(Run, handoff ID, family, step ID)**. Its intent also pins exact
  raw artifact SHA/length, EC172 parent pin, caller stage/repo path labels,
  and three original EC231 SHA values. Identical bytes repeated against the
  same slot (even with a new upload ID) are suppressed; a different payload
  or other parameters claiming the same slot conflict. Reusing the original
  upload ID for a different slot conflicts. This prevents a second **guarded
  local EC238 `attach` invocation**, not an upstream network upload performed
  elsewhere. Payload bytes are not written into the EC240 journal.
- A first valid operation is reserved **before** calling the wrapped EC239 or
  EC238 function, then a complete local status/SHA digest is committed
  **after** strict source-result and original-Run rechecks. A successful
  `FINAL` receipt is an observation or CES-local association, never business
  completion. Repeated calls report `REPLAY_SUPPRESSED` **without executing
  the wrapped handler again**; prior result bytes are deliberately not
  returned as a fresh summary or current verification. The receipt stores
  a SHA256 of the complete first result, not an authenticated signature.
- On the same host and cooperating local filesystem, a stable per-Run file
  descriptor and `flock(LOCK_EX|LOCK_NB)` guard **all new guarded operations
  across threads/processes**. Another live guarded invocation returns
  `OVERLAP_BLOCKED`, not a queued/delayed execution. Different completed
  valid ticks/slots can run sequentially. There is no TTL/lease fallback.

The journal is a **single atomic-rename visibility file** so each update
contains the full prior local receipt list; `O_NOFOLLOW`, owner/mode/nlink
checks, exclusive temp creation, `fsync` on files and parent directory, strict
JSON, per-file local self-hash and expected previous-state compare are used.
Paths under EC231's 0700 private store (all per original RunId):

```
<run_id>.ec240.lock          # persistent owner-private advisory lock inode
<run_id>.ec240.ledger.json   # the complete per-Run reservation/finalized journal
<run_id>.ec240.swap          # ONLY if an interrupted atomic rewrite left a temp
```

Limits: at most **1024** original receipt slots and at most **1 MiB** serialized
journal per Run. Expiry, compaction and deletion are deliberately absent: a
full journal is `CONFLICT_BLOCKED`, requiring an independently prepared new
Run under operator control. All timestamp fields are **untrusted host UTC
labels**, never proof of schedule liveness, conflict lease expiration or
enterprise identity. Lock file and CAS-style JSON self-hash are not a secure
anti-rollback mechanism against a malicious actor with the same UID.

## Interruption: recover conservatively, never auto-retry

After a successfully fsynced `RESERVED` journal update, an exception, process
kill, invalid underlying response or failed final `fsync` can leave the first
operation's real effect **unknown**. On every subsequent guarded invocation
for that Run, a persisted `RESERVED` record is interpreted as
`UNKNOWN_BLOCKED` for **all** slots, not as safe-to-repeat work. `inspect`
shows the same quarantine even when the requested event/attachment is not the
one interrupted. An orphan `.ec240.swap`, invalid journal contents, missing or
mismatched EC231 hash pin, unsafe owner/mode or uncertain file IO also blocks.
There is **no** automatic stale-lock removal, wait-until-TTL, resume, undo,
repair, mutation of an existing receipt, approval-token argument or
retry-in-place. In particular, after a partial EC238 local `attach`, the
artifact file may already exist even though the journal is `RESERVED`.

**Human recovery protocol for final acceptance:** independently preserve a
forensic copy of the whole protected owner directory; verify the original
EC231, current EC172 stage and EC238 artifact receipts, and any external
business effects using an *independent approved process*; do **not** delete
ledger/swap/lock to force a retry. If continuation is authorized, prepare a
fresh independently captured EC231 Run and unique new schedule/upload IDs,
following the original CodeSave/other native permission gates. The guard
cannot prove that a killed operation did or did not execute, cannot issue
permissions, and cannot certify rollback. A fresh Run is not itself a
cross-Run exactly-once guarantee; upstream idempotency remains necessary.

## Python API

```python
from pathlib import Path
from construction.cycle_conflict_guard import CycleConflictGuard

guard = CycleConflictGuard(Path('/absolute/owner-private/ec231-store'))
pins = dict(
    expected_record_sha256='<64-lowercase-hex-saved-outside-the-record>',
    expected_action_set_sha256='<64-lowercase-hex-saved-outside-the-record>',
    expected_input_sha256='<64-lowercase-hex-saved-outside-the-record>',
)
observed = guard.scheduled_summary(
    '<genuine-existing-ec231-run-id>', **pins,
    scheduler_kind='cron', schedule_id='approved-hourly', cadence='hourly',
    host_state='claimed_configured',
    trigger_id='evt_unique_event_2026_10_24_15',
    scheduled_for_utc='2026-10-24T15:00:00.000000Z',
)
```

`artifact_attach` accepts the same `run_id`/`**pins`, plus `upload_id`
(`upl_` + 12–80 safe chars), **absolute** `stage_store` and
`business_repo_root`, a genuine linked EC238 `handoff_id`, stage parent pin,
allowed `family`, original `step_id`, and **bytes** `artifact_bytes` (1 B–512
KiB). Its result is **CES-local metadata**, not a user-facing business
upload. No stored record claims a real producer, actor, output or approval.

Use `guard.inspect(run_id, **pins, request_id='evt_...' or 'upl_...')` to read
the local receipt snapshot, or `guard.business_write_attempt(run_id, **pins)`
to receive an explicit **`PERMISSION_DENIED`** for every business mutation.

## CLI (one complete ASCII JSON line, no side-effecting subprocess)

```sh
python construction/cycle_conflict_guard.py scheduled_summary \
  --store /absolute/private/ec231-store \
  --run-id run_v1_<48_lowercase_hex> \
  --expected-record-sha256 <original_record_pin> \
  --expected-action-set-sha256 <original_action_pin> \
  --expected-input-sha256 <original_input_pin> \
  --scheduler-kind cron --host-state claimed_configured \
  --schedule-id approved-hourly --cadence hourly \
  --trigger-id evt_unique_event_2026_10_24_15 \
  --scheduled-for-utc 2026-10-24T15:00:00.000000Z

python construction/cycle_conflict_guard.py artifact_attach \
  --store /absolute/private/ec231-store \
  --run-id run_v1_<48_lowercase_hex> \
  --expected-record-sha256 <original_record_pin> \
  --expected-action-set-sha256 <original_action_pin> \
  --expected-input-sha256 <original_input_pin> \
  --upload-id upl_unique_upload_attempt_01 \
  --stage-store /absolute/separate/ec172-stage \
  --business-root /absolute/separate/readonly-business-root \
  --handoff-id handoff_v1_<48_lowercase_hex> \
  --stage-parent-pin <independently-kept-ec172-pin> \
  --family Code --step-id step_code \
  --artifact-file /absolute/existing/producer-result.json

python construction/cycle_conflict_guard.py inspect \
  --store /absolute/private/ec231-store \
  --run-id run_v1_<48_lowercase_hex> \
  --expected-record-sha256 <original_record_pin> \
  --expected-action-set-sha256 <original_action_pin> \
  --expected-input-sha256 <original_input_pin> \
  --request-id evt_unique_event_2026_10_24_15
```

`--artifact-file` reads an existing **regular, non-symlinked** local input
only. It does not write the input or call a network upload. Shell placeholders
above must be substituted; do not paste them unchanged into a shell.

| Exit code | Status | Meaning |
|---|---|---|
| `2` | `RECORDED_OBSERVATION`, `RECORDED_LOCAL_ATTACHMENT`, `REPLAY_SUPPRESSED`, `RECEIPT_OBSERVED`, `NO_RECEIPT` | Local observation, local metadata or duplicate suppression **only** |
| `3` | `RECORDED_CHECK_BLOCK`, `REJECTED`, `CONFLICT_BLOCKED`, `OVERLAP_BLOCKED`, `PERMISSION_DENIED` | Known non-success, known overlap/conflict, explicit business permission denial |
| `5` | `UNKNOWN_BLOCKED` | Interrupted/untrusted/corrupt/changed/uncertain; **never retry automatically** |

`source_observation.called_now=true` only when a wrapped allowed function
returned a validated local result this time. All results explicitly deny
business execution, business writes, native dispatch and permission grants.
`REPLAY_SUPPRESSED` does not return underlying handler JSON, and **never
claims** another read-only Summary was executed. Output and journal contracts
are [result schema](cycle-conflict-result.v1.schema.json) and
[journal schema](cycle-conflict-ledger.v1.schema.json), Draft 2020-12.

## Unverified boundaries (deferred final assisted acceptance)

A POSIX local `flock` is advisory. It does not coordinate unguarded callers,
remote schedulers, actual business services, alternate UIDs, NFS/multi-host
namespace, reordered writes, same-UID substitution/rollback, malicious
ancestor replacement or power-loss durability. OS process kills and crash
windows have synthetic tests only, no real production fault-injection proof.
No fully atomic transaction spans this journal and EC238's separate artifact
owner file or EC172 staging area. Real cron/Windows Task Scheduler/enterprise
orchestrators, source/actor signatures, CodeSave native grant, real producer
output, upload side effects, PowerShell7/original 15 Smoke, Windows/macOS,
E63–E66 and final E2E acceptance all remain **NOT_RUN**. Original upstream
V3.10/ROUNDS source gap B001 stays **OPEN**; EC241 native routing not built.
