# EC255 operator guide: durable Podman OCI identity binding and recovery

## Scope and security model

**Linux nonroot operator-owned quality host, signed EC253 lease path only.** Keep EC252/253/254 operator private policies, image digest pins, source TAR, two distinct HMAC secrets, UID restrictions and stage permissions. Clients may not choose the OCI binary, name, label, image, ID, arbitrary argv, execution profile, or policy. EC255 is a Podman-host asserted ownership consistency barrier, **not** an independent cgroup/kernel attestation. Standalone EC252 remains on its original legacy name path (no new guarantees).

## Lifecycle and ordering

```text
validated EC186 approval + isolation lease + operator source/policy pins
 -> EC253 permanent one-use reservation: reserved + lease_label_sha256, fsync directory
 -> EC253 watchdog armed, session ready (reserved only)
 -> EC252 podman create --label=io.ces.lease.sha256=<receipt SHA256> ...
 -> parse complete 64-hex ID returned by create
 -> EC255 unique ps --all --no-trunc label discovery, exact inspect (full ID, name, label, pinned image)
 -> EC253 append created/full ID + fsync, reread durable event
 -> EC254 child emits created/full ID; parent checks its durable ledger event
 -> Podman start --attach <full ID>, EC254 emits start_invoked
 -> Podman stats <full ID> with .ContainerID equality; no telemetry fabricated
 -> Podman inspect/cleanup <full ID>, confirm exists exit 1
 -> private stage cleanup, append terminal ledger event, session exit/reap
```

Fixed OCI label key: `io.ces.lease.sha256`; value is the full 64-hex SHA256 digest of the **already-verified lease receipt**. The marker is correlation to the signed receipt, not a second authentication token; prevent untrusted access to the operator Podman socket and its writable storage.

## Recovery rules

- EC253 `Ledger.recover()` runs before accepting new sessions. Its leader `flock` prevents a second recovery owner, and only nonterminal journals are candidates.
- Journaled `created` ID: discover exact marker, require unique ID equality, inspect label and pinned image, remove by **full ID** even if renamed; require `container exists` exit=1. Marker missing but full ID still exists is **not clean**.
- Reserved but no `created` event (crash between `create` and fsync): search by marker; only if the name equals the recorded reserved name can the unique discovered full ID be removed. Renamed unknown ID causes a **fail-closed quarantine**. If no marker is found, require the reserved name to be absent (even then, unobserved malicious relabeling is beyond this guarantee).
- Multiple matching objects, malformed/truncated IDs, stats ID mismatch, inconsistent image, command timeouts/engine errors, or unconfirmed removal: **no success receipt, no source stage removal, no new session** until operator resolution.
- Old pre-EC255 journals lack marker/created ID and stay on the original historical by-name recovery semantics; treat those as a migration risk, not as proof of EC255 binding.
- During incident response, collect privately the reserved lease filename, `reserved` and `created` events, output of operator-controlled `podman ps --all --no-trunc`, full-ID `podman container inspect` and `podman container exists`, audit policy/image pins and involved UID before manually reconciling. Never authorize deletion by a client-supplied name.

## Deployment and manual acceptance checklist (deferred)

1. Configure the nonroot host with the EC253 operator policy described in `references/ec253-linux-hmac-lease-host.md`, and verify policy Podman executable SHA plus pinned image ID on the target machine.
2. With actual rootless Podman, run the existing approved `python.pytest`/`python.ruff` profile and confirm `create` label, full `ps` ID, `.ID/.Name/.Config.Labels/.Image` inspect fields, and `.ContainerID/.CPUNano/.MemUsageBytes/.PIDs/.BlockIO` stats output on that installed Podman version.
3. Interrupt before/after the `created` append; restart the same host identity; confirm exactly-once lease and that only the labelled matching full ID was removed. Simulate renamed container and competing label as separate negative cases.
4. Verify effective rootless cgroup, memory/PID/CPU, seccomp/no-new-privileges, no-network and read-only mount; ensure cleanup kills every residual process and test host hard interruption/power loss. **The current code has NOT proved these properties.**
5. Run original PowerShell7 15 Smoke, enterprise/Provider/CI/source provenance, all original Router paths and final assisted acceptance separately when a compatible environment is available. Do not mark Quality PASS on the basis of the local mocked 72 cases.

## Focused local development commands

Run from `ces/` as an **unprivileged** Linux user with private writable staging/home, not as root:

```sh
python3 -B construction/ec255_oci_identity/test_binding.py -q
python3 -B construction/ec252_quality_run_host/test_broker.py -q
python3 -B construction/ec253_lease_host/test_broker.py -q
python3 -B construction/ec254_session_host/test_broker.py -q
```

Do not substitute mock success for live Podman validation. This EC does not modify or unlock the 11 original Router HOST_REQUIRED modes.
