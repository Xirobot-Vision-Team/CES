# EC254 — Linux EC187 session host bridge (operator deployment, not OCI certification)

**Version:** CES construction V5.64/R254/EC-254. **Module:** `construction/session_host/broker.py`. This adds a separate, opt-in, single-session-at-a-time Linux AF_UNIX service and an EC187-compatible `TrustedBroker` client. The original EC187 `QualityRunBudgetController` and the EC252/EC253 public service signatures remain unchanged. No original Router HOST_REQUIRED action is enabled.

## What is actually implemented

1. Read the existing EC253 private policy, owner-only HMAC key/ticket files and EC252 operator-pinned immutable source TAR/profile/image/runtime. The host rejects root execution, uses kernel `SO_PEERCRED` for UID and the operator's exact UID/scope/profile grant. On `begin`, it matches the original **two distinct EC186 role-signed tickets**, their receipt hashes and permitted expiration, source pin assertion and image ID. Client input is **only** fixed IDs, checked digests, fixed EC187 default limits and a monotonic deadline; client-provided worktree path, executable, source TAR path, image, arbitrary command and runtime arguments are never used.
2. Fork a single-use worker. First perform EC253's fsynced `O_EXCL` permanent lease reservation and spawn its independent watchdog **before** calling `podman create`. Then require the pinned OCI `start` CLI to have been spawned **and** an initial parseable, actual host-side Podman resource sample before `begin` returns an EC187-compatible `ces.qualityrun.trusted_session.v1` receipt. The source seal returned is the SHA256 of the operator-owned TAR, **not** an independently verified Git-to-TAR binding. The receipt's six security booleans are strictly **host assertions**, not externally audited facts.
3. `poll(wait_ms, max_chunk_bytes)` returns bounded stdout/stderr raw bytes (base64 only in the wire transport), normal heartbeats, bounded host-sampled cumulative/peak telemetry (`cpu_ms`, `memory_peak_bytes`, `io_bytes`, `processes`), and an `exit` **only** after the worker exited and the container/journal cleanup is confirmed. Missing/invalid stats, unexpected frames, permission/ticket/source changes, output overflow, wall deadline and cleanup uncertainty cause failure and forced stop, **never fabricated zero telemetry or PASS**. Output text is suppressed for grants with `allow_output_text=false`, while its byte count remains metered.
4. `stop_and_reap(reason)` sends SIGTERM to the worker, escalates to SIGKILL if necessary, invokes the existing EC253 ledger recovery and OCI force-remove-by-random-generated-name, and returns the exact two-boolean EC187 host **claim**. If SIGKILL was necessary or cleanup/reaping is unconfirmed, it returns `reaped=false`. The server also cleans up on client disconnect, error and deadline. EC253 watchdog is an independently forked best-effort process, **not** proof of cleanup after a power failure or an entire systemd cgroup kill.
5. Only the **unchanged EC187 hard default maxima** are admitted for this round: wall 60s, CPU 40s, memory 256 MiB, processes 32, IO 64 MiB, captured output 12 KiB and maximum poll request wait 250ms. A caller requesting lower limits is rejected before consuming a lease: EC252 has not yet implemented dynamically lower per-run kernel limits. Podman stats uses `{{.CPUNano}}|{{.MemUsageBytes}}|{{.PIDs}}|{{.BlockIO}}`; if any field is missing/unsupported, it fails closed, not to a fallback value. The `poll_wait_ms` control bounds the cooperative select wait; the synchronous Podman stats child may introduce extra latency, which remains a production hardening limitation.

## Linux host use

Preconditions: operator-owned nonroot Linux account, private 0700 directories, 0600 policy/key/ticket/TAR files, real rootless local Podman, fixed preloaded image, root-owned pinned Podman executable, private Socket directory and EC253 journal root. Supply an EC253 policy JSON exactly as documented in [EC253 guide](linux-hmac-lease-host.md). Avoid running the service as root; do not put protected keys, runtime paths or tokens in any client request.

```bash
python3 -B construction/session_host/broker.py serve \
  --policy /absolute/private/operator/policy.json \
  --socket /absolute/private/socket/session.sock \
  --max-sessions 1
```

To call from a separately authorized EC187 controller:

```python
from session_host.broker import TrustedBroker
from quality_run_budget import QualityRunBudgetController

broker = TrustedBroker('/absolute/private/socket/session.sock',
                       expected_host_uid=12345,
                       scope_id='operator-approved-scope')
# controller is the existing EC187 QualityRunBudgetController, created with
# a properly provisioned EC186 QualityRunSafetyGate. Pass broker=broker to
# controller.run(...), along with real EC181 root pin, signed EC186 tickets,
# all EC186+EC187 explicit opt-ins and authorized host callbacks.
```

The UID above is an **illustrative placeholder**, not a pre-authorized UID. The constructor verifies the service's kernel UID, while the server verifies the client's kernel UID. Do not use this in an untrusted client with keys or private source paths embedded in it. Its `begin` method intentionally strips EC187's `repo_root`, source_pin object, fixed recipe and client-provided paths from the wire; only required preauthorized hashes and profile/scope are forwarded. The host reads its own pinned TAR and signed tickets, never the client-provided source directory.

### Session wire

Use the provided `TrustedBroker`, not a custom unaudited wire client. The `begin` request has exactly: `schema=ces.ec254.quality_session_request.v1`, `operation=begin`, `scope_id`, `profile_id`, the exact source/profile/approval/lease/image digests and `lease_id`, `limits`, and `deadline_monotonic_ns`. It receives a host-claim EC187 `receipt`. Subsequent requests on the same AF_UNIX connection are `poll(wait_ms, max_chunk_bytes)` or `stop_and_reap(reason)`. Responses have `schema=ces.ec254.quality_session_response.v1`, `status`, `reason_code`, `exit_code`, explicit false attestation flags, and an operation-specific `receipt`/`event`/`stop`. The service handles one active session at a time, maximum eight sessions before restart, with a private append-only lease journal retained forever for replay denial. Native cli, old route registry and EC186/187 schemas are not changed.

### Development verification vs. deferred verification

Local nonroot Linux EC254 tests use **real** AF_UNIX/UID, `fork`, private permission checks, real EC186 HMAC, fsynced journal and recovery, and a **mock** Podman control/metrics source. 15/15 EC254 cases, prior EC253 20/20 and EC252 24/24 are local development tests only. The development host has no Podman; it **has not** proved actual rootless cgroup/seccomp/network/mount, live Podman stats formats/per-poll timing, systemd/power-loss recovery, independent source provenance, CI identity, enterprise actors, Git provider permission, native PowerShell 15 Smoke, Windows/macOS or E63–E66. Resource fields are sampled and may miss transient peaks; they are **not independently attested** and the remaining end-to-end CPU/I/O kernel enforcement and watchdog failure modes need user-assisted verification.

Original EC249 remains `FULL_FUNCTION_NOT_COMPLETE`, original EC250 freeze remains `BLOCKED`, historical B001 stays `OPEN`, and 11 original Router `HOST_REQUIRED` actions remain denied. A host-reported exit 0 is always **partial/2**, not global Quality PASS. If a user requests a tighter budget or an unsupported runtime, the host refuses rather than silently weaken its controls.
