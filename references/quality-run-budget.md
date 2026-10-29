# EC187 — Bounded QualityRun orchestration and interruption

**Release:** construction package V4.97/R187/EC187. **Entry:** [`QualityRunBudgetController.run`](../construction/quality_run_budget.py). **Strict contract:** [`ces.quality_run_budget.v1`](quality-run-budget-result.v1.schema.json). **Previous gate:** [`QualityRunSafetyGate.prepare`](../construction/quality_run_guard.py). The native PowerShell QualityRun/QualityShow actions are still **NOT IMPLEMENTED**. No production broker, runner image, key vault or source sealing service is packaged.

## What the actual Python code implements

- Validate two distinct new `allow_external_execution=True` and `allow_budget_controls=True` opt-ins, plus EC186's three independent opt-ins. Re-run EC186's *real* fresh host-HMAC profile approval/lease and three authorized EC181 POSIX directory identity probes (two internal EC186, one EC187 after final launch permission). Re-check both full ticket MACs and exact previously authenticated receipt digests again **after** two new execution authorizations. Any revocation/drift/expiration prevents broker entry.
- Select ONLY EC186 built-in `python.pytest` / `python.ruff` recipe information. No user `argv`, host shell fallback, repo script, `PATH` executable lookup or synthesized local subprocess. `repo_root` is passed **only** to the separately trusted external broker for snapshotting; it is not executed by CES.
- Clamp user-requested budgets **downward** against code-owned maxima; reject unexpected fields, bools-as-integers, enlarged values or inconsistent CPU/process/wall ceilings. Communicate the exact limits to the broker. Insist that the host receipt matches the source pin, approved profile, signed approval digest, signed lease digest, pinned image and limits *exactly*.
- Consume only bounded host-event frames and cumulative resource telemetry. On timeout, explicit cancel, missing/bad telemetry, memory/CPU/I/O/peak-process breach, output overflow or event-flood limit, request `stop_and_reap` and retain bounded output + metrics + non-PASS `partial/2`. If terminate/reap fails, record **unknown/host-unconfirmed**; never claim a clean shutdown.
- Even `host_reported_exit_code=0` yields `status=partial, exit_code=2, overall_pass_verified=false`. A claimed session seal/actual isolation/cgroup enforcement/lease consumption remains a **host-reported assertion**, not independently verified CES evidence. This enables safe later query/aggregation without confusing fixture runs with proven real tests.

## Conservative budgets

| Field | Hard ceiling | Lower bound | Meaning |
|---|---:|---:|---|
| `wall_ms` | 60,000 | 100 | Monotonic wall time from just before `broker.begin` (includes begin and polling) |
| `cpu_ms` | 40,000 | 100 | Host-reported aggregate CPU time, auto-clamped to `wall_ms × processes` unless explicitly set |
| `memory_peak_bytes` | 268,435,456 | 1,048,576 | Host-reported peak memory |
| `io_bytes` | 67,108,864 | 4,096 | Host-reported cumulative runner I/O |
| `processes` | 32 | 1 | Host-reported peak concurrent process count |
| `capture_bytes` | 12,288 | 0 | Combined stdout/stderr **byte** capture budget; overflow requests stop |
| `poll_wait_ms` | 250 | 1 | Max cooperative host polling slice |

Additional hard limits: each output frame `1..4096` bytes, at most **1024 poll events**, at most **96 KiB result JSON** (including escaped UTF-8 preview text). Byte counts are taken before UTF-8 decoding; terminal control characters are replaced for presentation. If a chunk exceeds capture budget, append only its fitting prefix, count discarded bytes, set `truncated=true`, request stop and return partial. A `capture_bytes=0` selection captures none and stops on the first output chunk. No persistent output logs, file writes or stdout of the analyzed repository are stored by this module. The output SHA256 is merely an integrity convenience for **the observed captured prefix**; it is not a signed evidence digest or complete-stream hash.

## Required trusted broker protocol (not provided)

`run()` accepts a separately supplied, host-controlled `broker` object with:

1. `begin(request) -> session`: **Before launching any untrusted profile**, verify real cgroup/clock/output watchdog enforcement and prohibited mounts/network/privileges; obtain an immutable source snapshot, verify it is the approved source (not merely the same root directory inode), bind the fixed image-owned executable/recipe and atomically consume the exact reservation lease **once**. Handle begin failures by killing/reaping any process and rolling back reservations; never return an unbounded or unisolated session. Bind limits and unique session identity, then return a `session.receipt` with the exact schema `ces.qualityrun.trusted_session.v1`, all scope fields, a valid `sealed_source_sha256`, the exact limit dict and six strictly `true` broker security declarations. A Python dictionary with those values is **not** proof that an OS sandbox exists.
2. `session.poll(wait_ms:int, max_chunk_bytes:int)` returns exactly one of: `{'kind':'heartbeat', 'resources': R}`, `{'kind':'output','stream':'stdout'|'stderr','chunk':bytes,'resources':R}`, or `{'kind':'exit','exit_code':0..255,'resources':R}`. `R` has exactly nonnegative integer `cpu_ms`, `memory_peak_bytes`, `io_bytes`, `processes`, each a **cumulative or peak-since-start** counter which may never decrease. Exit events must mean the trusted host has finished/reaped all descendants and no further output is pending; neither a fake event nor bare `exit_code=0` is adequate to prove that.
3. `session.stop_and_reap(reason)` requests hard-cancel-and-reap; returns the *claimed* exact `{'stop_acknowledged':bool,'reaped':bool}`. The host MUST apply a hard independent deadline/kill and handle exceptions and process-tree escapes. CES records responses as **host assertions only**, never asserts termination when the host raises or does not confirm it.

There is **no safe fallback** when this real broker is unavailable. An arbitrary Python implementation of `broker` or repository-supplied plugin is not a trusted broker. `begin`, `poll` and `stop_and_reap` are synchronous callback boundaries that Python **cannot forcibly interrupt** when a callback blocks; the host must implement independent watchdogs, output drains, hard limits and atomic non-replayable lease state in a privileged boundary outside the analyzed checkout. The bundled fixture broker is intentionally synthetic and does not execute anything. This EC does not ship a verified kernel/container implementation, trust-root provisioning or deployable production runner.

## Result meanings and errors

- **No broker / denied policy / mutated final signed ticket / stale root or opt-in:** `unavailable/5` or `invalid_input/4`, with `execution`, `resources`, `output`, `proof`, `limits` and `profile_id` **null**. If cancellation is already requested after gate checks but before broker entry, `partial/2` with null run fields and no broker call.
- **Reported exit 0 or nonzero:** `partial/2`, `execution.state=exited_host_reported`, `host_reported_exit_code` set, `output.complete=true` only when no truncation and a timely final event was processed. This is not global quality PASS/FAIL evidence.
- **Interrupted/uncertain after begin:** `partial/2`, `execution.state=interrupted_or_unverified`, `host_reported_exit_code=null` unless the event was actually observed, `output.complete=false`, bounded partial stdout/stderr, local observed wall time, last valid host-reported resource counters, termination requested and confirmation distinguished. Expired, cancelled, over-budget, no event, invalid frame, broker failure and refused cleanup cannot be silently upgraded.

All outputs explicitly force `commands_launched_by_ces=false`, `test_execution_verified_by_ces=false`, `kernel_isolation_independently_verified=false`, `quality_pass_verified=false`. An external supervisor running a profile is outside this module's independently demonstrated facts. Do not infer full project coverage or benchmark numbers from fixture receipts. These results can be projected by **future EC188 QualityShow**, but no EC188 interface is shipped now.

## Developer checks vs. deferred acceptance

[`test_quality_run_budget.py`](../construction/test_quality_run_budget.py) uses temporary real EC181 root pins plus synthetic time, independent test-only EC186 HMAC keys, an in-process no-execution host stub and strict Draft2020-12 result validation. It covers runtime budget clamps, both fixed profiles, grant revocation/mutation, lease/scope tamper, output cap, timeout, cancellation, CPU/memory/I/O/peak-process overflow, duplicate/incomplete frames, poll flood, missing/invalid telemetry and denied/partial reporting. These are **development fixtures only**. Production lease custody, actual process tree kill, live kernel sandbox, source byte/hash freeze, cgroup enforcement, hostile callback stalls, PowerShell7+15 Smoke, true GI/CI, Windows/macOS, E63–E66 and final user-assisted acceptance remain **NOT_RUN**.
