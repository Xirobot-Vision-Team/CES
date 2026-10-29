# EC262 — operator-private HMAC session audit for the EC260/261 strict host

**Deployment status: local code implemented; live rootless Podman/systemd/cgroup-v2 and independent remote Git/enterprise/CI acceptance NOT VERIFIED.** This is not a general CES Router endpoint and does not upgrade the existing PowerShell CLI, EC186/187 wire, or the 11 denied `HOST_REQUIRED` modes.

## What this does

- A new `construction/signed_audit_host/serve.py` **opt-in** server uses the existing EC259 custody gate, EC260 active recall, EC261 monitored egress and EC257 cgroup-v2/kernel metrics. It also requires an operator-selected, locally independent HMAC key and durable audit directory. No new client request fields.
- The parent server writes canonical per-event JSON lines, HMAC links each line to its predecessor, and fsyncs before any further protected work. A separate locally keyed `head.json` seals the last sequence number, file length and last MAC; both are checked at every service startup. It rejects partial records, changed or truncated tails, replaced/log symlink, unsafe ownership/mode, wrong key, concurrent writers, damaged high-water seal and oversized history.
- Events deliberately contain **no output content, user request, source path, Git tree, ticket, key, container ID or sensitive exception text**. `session_tag` is a random local correlation token and `reason_code` must be a bounded stable uppercase code. `begin_authorized` records a local signed check before a worker/lease is committed; `*_egress_attempt` means the host is about to send; `*_egress_enqueued` means only that the entire socket write returned, not that a client received it. `session_cleanup_state` reports `LEDGER_SAFE` or `LEDGER_UNCERTAIN` for the *original EC253 durable ledger*, not certified kernel state.

## Operator deployment (trusted non-root Linux host)

1. Prepare the existing EC259/260 approved immutable policy, real local Git commit allowlist, deterministic TAR, custody receipt, the two original EC253 keys/tickets and a supported rootless Podman/systemd delegated cgroup-v2 host **exactly as required by the previous guides**. Keep all existing source and profile pins fixed.
2. Create a **separate persistent 0700 directory** for the audit log outside the source repository, ledger, OCI scratch/runtime and connection Socket directories. Create a **distinct random 32-byte or longer HMAC key file**, mode `0600`, under its own existing private parent; neither the key nor the log may live in the project worktree or be supplied by a client. Both must be operator-owned. Keep an independent, access-controlled offline copy of the key and any exported audit digests according to your organizational process.
3. Launch only with the operator's explicit parameters:

```bash
python3 construction/signed_audit_host/serve.py serve \
  --policy /operator/secure/policy.json \
  --repo /operator/approved/repo \
  --allowlist /operator/secure/approved-source.json \
  --receipt /operator/secure/source.custody.json \
  --profile-id python.pytest \
  --socket /operator/socket/ces262.sock \
  --audit-root /operator/audit \
  --audit-key /operator/secure/audit.key \
  --max-sessions 1 --accept-timeout 60
```

4. Client usage remains EC187-compatible: use the previous EC260 client with a **signed** `begin` request and `poll` / `stop_and_reap`. There is deliberately no `audit=false`, `source_path`, `profile_override` or `grant` switch in the client wire. A failure to record evidence prevents starting a new session and terminates the strict host after mandatory cleanup.
5. Read-only local integrity verification, e.g. after stopping the host:

```bash
python3 construction/signed_audit_host/serve.py verify-audit \
  --audit-root /operator/audit --audit-key /operator/secure/audit.key
```

A valid chain prints `status=partial`, `exit_code=2`, count and `last_mac`, with explicit `overall_quality_pass_verified=false`. Code `5` or missing/corrupt HMAC/journal/head is a refusal, **not** an invitation to reset the log. On mismatch, stop, preserve `events.jsonl`, `head.json`, any orphan `.head-*` and backups for operator review. A power failure between journal fsync and head replacement can intentionally leave the service blocked; automatic repair would silently erase evidence of lost writes.

## Storage, failure and operational caveats

- The strict logger checks absolute private paths and `O_NOFOLLOW` regular single-link files; the local audit key must differ from both original EC253 keys. The journal is exclusively `flock`-locked, `O_APPEND`, fsynced per event; head is fsynced and atomically replaced, followed by a parent-directory fsync. No network filesystem, hostile same-UID account, root compromise or hardware power-loss guarantee is claimed.
- Size is capped at **32 MiB or 65,536 events**; once full, the service *fails closed*. There is **no silent log rotation, truncation or overwrite**. Future authenticated rollover should be specified separately if deployed at scale.
- HMAC linked events and a *same-account* head detect many local accidental/tampered tails, but they are **not independently anchored, immutable/WORM, or externally timestamped**. A party with the same UID and audit key can regenerate both. This version does not independently authenticate repository origin, human approvers, CI, OCI isolation, OS clock or network providers.
- `fsync`, Git traversal and scheduling can take unbounded time: the EC260 nominal 1-second checks and EC261 nonblocking egress are not a guaranteed 1-second revocation SLA. A complete byte stream already queued in the kernel cannot be unsent. If audit fails after bytes are enqueued, the client may have seen a `begin` ACK; it must not infer session completion or safe cleanup without ledger/host verification.

## Verification backlog for final joint acceptance

Run actual rootless Podman/systemd-delegated cgroup-v2, exact full-ID kill and kernel counters/terminal meter; adverse/idle/revoked/blocked-write paths; crash and restart recovery including journal/head ordering and disk-full; external independent audit anchors and source trust; original PowerShell7/15 Smoke, E63–E66 and Router/Provider/enterprise workflows. Keep original EC249 `FULL_FUNCTION_NOT_COMPLETE`, EC250 `BLOCKED`, B001 `OPEN` and full-system acceptance `NOT_STARTED` until proven otherwise.
