# EC257 operator guide — Linux cgroup v2 kernel-measured signed QualityRun session

## Entry and trust boundary

Use the *new* EC257 entrypoint only on an operator-owned, unprivileged Linux host. Supply the original EC253 signed approval/isolation tickets, local fixed image/source TAR, protected policy and secrets, exclusive lease ledger, non-root Podman, rootless systemd/cgroup v2 delegation and a trusted private Unix socket path:

```sh
python3 -B construction/ec257_cgroup_metrics/serve.py serve \
  --policy /operator/private/ec253-policy.json \
  --socket /operator/private/quality-ec257.sock \
  --max-sessions 1
```

The client **remains the original EC254 `TrustedBroker`** pointed at this Unix socket; the client must check the configured server UID and the original EC187 signed scope/deadline/limits receipt. EC257 does *not* accept resource file paths, target PIDs, cgroup root, source path, custom shell or `require_kernel_metrics` from the client.

Use EC257 only if your kernel exports read-accessible `cpu.stat`, `memory.peak`, `pids.peak`, and `io.stat` under the exact `libpod-<full-ID>[.scope]` scope that EC256 already pins. Unsupported kernels/layouts/delegation fail closed, rather than silently falling back to Podman stats. The old EC254 host still samples Podman stats; the old EC256 entry requires cgroup kill but retains Podman metrics. **Do not imply those older entrypoints are automatically EC257 protected.**

## Measured resource fields and ordering

| EC187 resource key | EC257 kernel source | Semantics |
| --- | --- | --- |
| `cpu_ms` | `cpu.stat` `usage_usec` | Cumulative CPU runtime, floored to ms; reject absent/reset/error |
| `memory_peak_bytes` | `memory.peak` | Kernel memory subtree high-watermark, not a sampled current usage surrogate |
| `processes` | `pids.peak` | Kernel process subtree high-watermark, **not** a one-instant PID count |
| `io_bytes` | `io.stat` per-device `rbytes+wbytes` plus worker-observed stdout/stderr | Conservative storage-I/O + output budget; can overcount overlap by design |

All values must fit a signed 63-bit nonnegative integer; samples can only stay flat or increase. Each real sample reuses the single durable `cgroup_bound` record and verifies boot ID and scope inode, with exact leaf files opened without symbolic links. For `io.stat`, an empty but *successfully opened* kernel file means no reported block I/O; a missing file or malformed nonempty report is a hard error, not zero. Counter values above the original `cpu_ms=40000`, `memory_peak_bytes=268435456`, `io_bytes=67108864`, `processes=32` ceilings are rejected. Original Podman OCI creation still requests its own fixed memory/PID/CPU isolation limits; EC257's **observational gate is not an independent kernel enforcement guarantee**, particularly for aggregate CPU or IO.

Session ordering:

```text
signed peer UID/profile/Lease checks
  → EC253 one-use fsynced reservation and EC255 verified full OCI ID
  → EC256 fsynced start_armed and cgroup_bound (boot, scope, dev, inode)
  → EC257 first kernel file sample BEFORE successful begin receipt
  → EC187 poll → signed grant/source recheck → durable cgroup identity recheck
       → kernel counters / bounded stdout-stderr frames → monotonic peaks
  → worker pre-reap final kernel snapshot, through ordered SEQPACKET final_meter
  → EC256 cgroup.kill/populated=0 and EC255 full ID removal/exists absent
  → private staging cleanup, permanent terminal Ledger, worker exit
  → EC187 exit only with final_meter AND verified terminal cleanup
```

If the cgroup already vanished while older output frames are being drained, host may transmit at most four brief heartbeats of the **last genuinely sampled value** while awaiting the ordered pre-reap `final_meter`. This is not a claim of fresh measurement. If no trusted final snapshot arrives, it refuses to return `exit`; cleanup still happens through the EC256 gate. After final snapshot, no further resource file is read, because worker may already have removed the scope; the host waits for terminal cleanup confirmation. On any other missing/invalid counter, inode drift, wrong boot, overflow or observed over-budget value, fail closed and trigger stop/recovery.

## Real-host acceptance queue (all NOT_RUN in construction environment)

1. **Host capabilities**: run a truly rootless pinned Podman image under the operator UID; inspect actual systemd delegated cgroup path, `.State.Pid` and full-ID/Lease label; verify the 4 cgroup files are present with correct permissions and mountinfo root. Repeat on older kernels or delegated subtree mounts and confirm **denial**, not fake fallback.
2. **Measured semantics**: generate known CPU time, memory peaks, nested child/sibling PIDs, block read/write and stdout/stderr, and compare observed EC257 peaks to cgroup v2 real kernfs while session is still live. Check PIDs/peaks don't decrease on process exit, and no cross-container measurements occur.
3. **Final sampling**: complete an authorized run normally, very quickly and under high output; ensure the final IPC watermark is captured before `cgroup.kill`. Check zero/exit0 cannot bypass missing final stats and all outputs remain `partial/2`; compare with actual kernel tree disappearance and stage removal. Missing file after begin must yield unavailable, not success.
4. **Adversarial cases**: replace cgroup dir or stat file with symlink, reuse PID/inode, change boot source, mutate policy/ticket mid-run, stop worker, kill service/watchdog groups, exceed every resource budget and leave terminated or nonterminal journal. Ensure no unbound `rm` and no false terminal closure when group cleanup is uncertain.
5. **Reboot and integration**: force a real host restart under durable EC253 Ledger, confirm exactly one Lease is never replayed; verify CPU/memory/pid/io hard limits at the kernel, systemd delegation, timeouts and actual full-tree kill. Run the unchanged native PowerShell7/15 Smoke and OS/enterprise/Provider/CI/independent Git-TAR authentication separately before any final acceptance.

The local development tests exercise true nonroot temporary files/locks, UID, Unix socket, fork and durable journal, but use **simulated cgroup files and Podman**. They are deliberately *not* real OCI acceptance, independent source provenance or business permission attestation.

## Focused local development commands

```sh
python3 -B construction/ec257_cgroup_metrics/test_metrics.py -q
python3 -B construction/ec257_cgroup_metrics/test_session.py -q
```

Both tests intentionally need non-root Linux for real lease/peer behavior. Historical EC252–256 tests continue to run independently; original native Router `HOST_REQUIRED` modes, EC186/187 business modules and source repository write permissions remain unchanged.
