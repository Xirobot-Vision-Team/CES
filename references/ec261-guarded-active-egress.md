# EC261 — active signed session response backpressure and bounded teardown

## How to use (only the EC260 strict operator host)

No new CLI option, client opcode or authority is introduced. Use the existing
[EC260 strict host](ec260-active-recall-host.md) with the existing original
EC253 operator-owned policy, original two EC186 HMAC tickets, approved exact
Git object allowlist/TAR/receipt, fixed profile, and real rootless Podman +
delegated cgroup-v2 prerequisites. `construction/ec260_active_recall_host/serve.py
serve` now uses the EC261 guarded egress **automatically** because it installs
its trusted `during_session_guard`. Prior EC254/256/257/259 server entrypoints
continue using their original transport and public protocol unchanged.

Use `ec260_active_recall_host.client.ActiveRecallBroker` with the original
EC187 `begin()` / `poll()` / `stop_and_reap()` signatures. A successful server
reply retains the existing `ces.ec254.quality_session_response.v1` single JSON
line and the same host-only evidence semantics (`partial/2`, not quality PASS).

## Semantics and threat boundary

- At the start of each successful `begin`, `poll` and `stop` reply emission, the
  server performs the full trusted EC253 policy/source/UID/ticket and EC259
  local Git/TAR/receipt check. For `poll`, this is **in addition** to the EC260
  check before accepting the request: a revocation occurring during kernel
  metering/output preparation can now block release before the first byte.
- The transport encodes one bounded JSON line (maximum 8192 bytes), moves up
  to 1024 bytes at a time on a nonblocking AF_UNIX socket, and uses select with
  the approved monotonic session deadline. While write-backpressure holds, the
  authority guard repeats on a nominal 1s cadence rather than waiting in
  uninterruptible application-level `sendall()`.
- Revocation/deadline/peer closure leads to the original EC254 stop/recovery
  path, including mandatory original EC253/255/256 durable reaping checks.
  A denial can only try to send its small error frame within 0.25 seconds;
  it never waits indefinitely for a deliberately non-reading client.
- If the server wrote some bytes of a response when a later guard failed,
  the **connection is intentionally terminated mid-frame** and no second error
  JSON may be appended. Treat any truncated frame, timeout or connection close
  as `unavailable`: do not reuse the connection or treat it as a completed
  `stop_and_reap`. Inspect the durable host ledger and prove OCI absence.
- Bytes already accepted by the local kernel send buffer are already sent;
  the server cannot retract them. The periodic cadence is not a certified
  maximum revocation latency. Operator proof scanning, scheduler starvation,
  signals, host process crash, cgroup kernel failures and same-UID/root attack
  remain separate containment/acceptance questions.

## Local functional checks

From `ces/` on an unprivileged Linux account with real `/usr/bin/git`:

```bash
python3 -B construction/ec261_guarded_egress/test_egress.py -q
python3 -B construction/ec261_guarded_egress/test_host.py -q
```

The first is real AF_UNIX socket backpressure / partial-frame semantics. The
second uses real Git objects, EC253 signatures, host AF_UNIX and durable lease,
**but patches OCI/Podman/cgroupfs** as part of the inherited development
fixture; one case forces kernel socket backpressure via a controlled mock
host-side buffer fill. This is not production kernel isolation evidence.
See [EC261 local report](../construction/EC261_LOCAL_REPORT.json) and
[round record](../EC-261.md) for all focused adjacent regressions.

## Accumulate in final user-assisted host validation

On an independent operator-approved nonroot Linux rootless Podman/systemd
cgroup-v2 machine, independently approve real Git/TAR/HMAC origin and a valid
signed session. Use a real client that stops reading while the worker generates
large output and revoke local custody/permission during write backpressure;
verify bounded detection and full OCI ID/cgroup tree reaping and durable journal
closure without treating the socket's absence as proof. Also revoke between
poll preparation and response, exercise deadline and partial response, and
confirm the original EC260 active recall / EC187 client contract. Repeat with
real cgroup CPU/IO/memory/PID, signal/crash/restart, real remote signer/CI,
original PowerShell7/15 smoke, E63–E66, native Router 11 `HOST_REQUIRED`,
OS-specific and external business effect acceptance. All remain NOT_VERIFIED
until operators provide independent real-host evidence.
