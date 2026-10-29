# EC256 operator guide — signed Podman session with kernel cgroup v2 hard-reap barrier

## Authority and entrypoint

EC256 is an **opt-in, separate strict service**, not a new client operation or Router permission grant. Run as an ordinary unprivileged Linux operator UID with *existing* EC253 policy, sealed TAR, signed EC186 approval and isolation lease, pinned Podman binary/image, private keys, grants, socket parent, Ledger and scratch directories:

```sh
python3 -B construction/cgroup_reaper/serve.py serve \
  --policy /operator/private/ec253-policy.json \
  --socket /operator/private/quality-ec256.sock \
  --max-sessions 1
```

Use the **unchanged EC254 `TrustedBroker` client** with the strict endpoint's socket. Do not accept client-specified `require_cgroup`, `podman`, `cgroup_path`, PID, mount, shell, resource overrides, source path or identity evidence. The separate original EC254 `serve` command still has nonstrict compatibility defaults and **must not be described as EC256 protected**.

Before listening, EC256 probes for a cgroup2 mount at `/sys/fs/cgroup` rooted at `/`, checks the kernel boot ID and EC253 private ledger. This is a deliberately narrow target: some real Podman rootless installations mount a delegated **subtree**, use a different cgroup layout, set inaccessible `/proc`, or do not delegate `cgroup.kill`. Such hosts are currently **unsupported**, not proof that protection is active.

## Exact functional ordering

```text
kernel SO_PEERCRED UID + signed EC186 approval & isolation lease
  -> EC253 durable O_EXCL one-use 'reserved' (cgroup_required:true)
  -> EC253 watchdog armed
  -> Podman create --label signed lease digest, no shell / no network
  -> EC255 verify unique full-ID + label + pinned image
  -> EC253 durable 'created' full-ID event
  -> EC256 durable 'start_armed' event BEFORE Podman start --attach spawn
  -> Podman start --attach <verified full ID>
  -> Podman State.Pid/Running + /proc/PID/stat starttime + /proc/PID/cgroup v2
  -> kernel OCI libpod-<full ID>.scope root (not child leaf)
  -> check writable cgroup.kill, 'populated 1', stable PID, fixed ID
  -> EC253 durable cgroup_bound {boot_id,path,dev,ino,pid_starttime}
  -> EC254 session first real Podman stats; begin partial/2 is HOST CLAIM ONLY
  -> output/poll (UID grant & signed ticket continuously rechecked)
  -> normal stop, cancellation, worker failure, watcher deadline or restart
  -> verify current full OCI ID, group binding and Linux cgroup inode
  -> if populated, write cgroup.kill=1; bounded wait for populated=0
  -> EC255 verified rm <full ID> and exists=<absent>
  -> delete private staged TAR, append journal 'closed' / 'recovered'
```

If Podman is already stopped but a durable cgroup binding exists, EC256 still checks the recorded cgroup path, inode and `populated` status, killing a residual group if present. On a reboot (kernel boot ID changed) the previous boot's PIDs are dead, but Podman ID/label and absence checks still apply. If no init PID was ever observed (pre-start or short-lived run), the code does **not** manufacture a cgroup receipt; strict session `begin` rejects any run that cannot obtain a live durable binding.

`podman rm --force` remains a *container-store cleanup step*, not evidence that an arbitrary host process tree was killed. The strict cgroup gate is mandatory before removing a live signed EC256 container. On uncertain `cgroup.kill`, ambiguous cgroup path, PID reuse, inode mismatch, image/label drift, or engine failure, retain private staging and a nonterminal Ledger record for manual incident review.

## Still unproven and target-host acceptance cases

Work through these only on a dedicated target Linux host with real **rootless Podman**, expected immutable image, policy/lease and kernel delegation:

1. Confirm actual `podman container inspect --format '{{.State.Pid}}|{{.State.Running}}' <full-id>` and EC255 existing `.ID/.Image/.Name/label`, EC254 `.ContainerID/.CPUNano/.MemUsageBytes/.PIDs/.BlockIO` fields exactly match this installed Podman. No fake zero resource values, no fallback to container name.
2. Run a fixed authorized profile with an observable long-running init + several child/sibling processes in cgroup descendants; compare `/proc/<pid>/cgroup`, cgroup inode and Podman ID, then cancel and verify `cgroup.kill` removes the **whole libpod scope tree** within the three-second bound. Confirm host operator process and other leases remain running.
3. Run a very short profile that exits before PID binding, and a host without cgroup.kill delegation / with non-v2 or subtree mount; strict host must fail closed without a successful EC187 begin or release of staged source.
4. Inject SIGTERM/SIGKILL, session disconnect, CLI stdout overflow, stale PID/reused PID, a changed container label/name/image, a repeated Lease, a second identical label and a renamed matching full-ID container. Only signed ID may be targeted; ambiguous cases must leave durable pending evidence.
5. Crash separately before/after `reserved`, `created`, `start_armed`, `cgroup_bound`, kernel `cgroup.kill`, Podman removal and terminal journal append. Restart using same signed policy, inspect Ledger and ensure no unverified success. Repeat after an actual host reboot.
6. Verify cgroup v2 delegation and kernel enforcement of memory/PIDs/CPU, `seccomp`, no-network, user namespace, read-only source mount, immutability of TAR vs Git root. Check local rootless Podman/CI/provider paths and the old native PowerShell 15 Smoke separately. **Do not unlock** any Router `HOST_REQUIRED` route or claim overall Quality PASS.

This development environment has **not** performed these live steps. EC256's simulated cgroupfs file writes are not proof of live process-tree termination.

## Targeted local development command

```sh
python3 -B construction/cgroup_reaper/test_supervisor.py -q
```

Original EC252/253/254/255 suites remain runnable separately. Nothing requires/authorizes a change to the original EC186/EC187 modules, native CLI, business repositories, or remote Issue/Report/CI provider state.
