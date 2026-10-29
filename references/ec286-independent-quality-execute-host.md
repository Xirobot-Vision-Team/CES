# EC286 — Deploy and operate the exact independent QualityRun.Execute Host

**Release:** V5.96/R286. This is a rootless Linux, private, separately deployed **optional execution bridge**. It does not implement a new pytest invocation or relax the original router. All input paths below are *operator-owned existing absolute paths*; placeholder strings must be replaced with real private source and signed receipts. Do not place private signing keys, HMAC keys, Git TAR, host policies, credentials or output under the user’s business repository.

## 1. Preconditions — these are real dependencies, not examples silently fabricated by the CLI

1. A private validated **EC281 preflight policy** is already present and its raw SHA256 is independently pinned. It must reference an **original EC181 current `WorkingTree` source pin** and two current **independently originated original EC186 profile/lease HMAC receipts**, two actual HMAC secret files, a fixed approved profile, and the same source repository. EC286 does not mint original EC186 authorizations.
2. An **original EC253 policy** is already present with an authorized **non-root host UID + exact scope/profile** grant. It must bind those *same* original two signed HMAC receipts, the same source pin, a single-use lease, SHA-pinned local exact source TAR, immutable image `sha256:`, Podman runtime hash, independent private ledger and rootless storage/cgroup resources. The private original EC253 service performs the actual lease reservation and consumption. Never retry an unknown lease.
3. **EC258 custody materials** are genuine local Git object/allowlist→TAR checks plus a private verified EC258 receipt; no remote Git origin attestations are implied. Use EC258 to prepare a deterministic TAR consistent with EC253's SHA and receipt, with a clean/durably pinned checkout.
4. A **separately supervised original EC259 strict session daemon** must run on a rootless Linux account and must be the one that enforces `require_cgroup=True` and `require_kernel_metrics=True`, i.e. original EC257 controls, with original EC259 git-custody startup/before-begin guard. The EC286 service checks the socket UID, parent directory permissions and socket inode. **This is not a cryptographic measurement of EC259's code.** Operator must externally audit the actual running service image, kernel cgroup-v2, Podman image/runtime and resource limit enforcement. Old EC254 unguarded service sockets must not be accessible as an authority substitute.
5. The EC286 server process must run **non-root**. Its own policy, HMAC/ticket paths, Git allowlist/receipt and signing private key reside in owner-only `0700` directories and owner-only `0600` files. A socket directory is `0700`. Cryptography (`Ed25519`), Linux AF_UNIX peer credentials and dependencies from the complete `ces/` bundle are required. Three **distinct** EC286 keys are separately retained by source custodian, execution authorizer and Host. Local synthetic three-key fixture is not independent employee/operator authorization.

The original EC259 entrypoint (substitute actual pinned absolute paths, fixed profile and private `0700` socket directory) is:

```sh
python3 -I -B construction/ec259_custody_gated_host/serve.py serve \
  --policy /private/ec253-policy.json \
  --repo /private/checked-out-source \
  --allowlist /private/approved-paths.json \
  --receipt /private/source-custody-receipt.json \
  --profile-id python.pytest \
  --socket /private/ec259-sock/strict.sock --max-sessions 1
```

The socket parent must be owned by the same configured `--session-service-uid` and `0700`; the socket must have no world permissions. This requires a verified *real* EC259 deployment, not an arbitrary process listening on a compatible socket.

## 2. Three offline keys, exact policy and independent votes

Use separate trusted accounts/machines according to your organizational policy. The key generation command never prints the private seed; its result prints **only** `public_hex`. Each `--private-out` target must not exist; its parent must be owner-private. Run three distinct times for the roles:

```sh
python3 -I -B scripts/ces_quality_execute_host.py keygen-offline --private-out /private/roles/custodian.key
python3 -I -B scripts/ces_quality_execute_host.py keygen-offline --private-out /private/roles/executor.key
python3 -I -B scripts/ces_quality_execute_host.py keygen-offline --private-out /private/roles/server.key
```

Admin pins public keys *and* real original input byte SHA values. Prepare the host-only, non-authorizing policy using the real source/custody paths, UID, exact scope and a single exact profile (all these paths are the Host's policy, never client RPC fields):

```sh
python3 -I -B scripts/ces_quality_execute_host.py prepare-policy \
  --preflight-policy-file /private/ec281-preflight.json --preflight-policy-sha256 PRE_SHA256 \
  --lease-policy-file /private/ec253-policy.json --lease-policy-sha256 LEASE_SHA256 \
  --git-repo /private/checked-out-source \
  --allowlist-file /private/approved-paths.json --receipt-file /private/source-custody-receipt.json \
  --session-socket /private/ec259-sock/strict.sock --session-service-uid NONROOT_UID \
  --scope-id approved-run-001 --profile-id python.pytest --allowed-uid CLIENT_UID \
  --custodian-public-hex CUSTODIAN_PUBLIC \
  --executor-public-hex EXECUTOR_PUBLIC --server-public-hex SERVER_PUBLIC \
  --out /private/ec286-execute-policy.json
```

Record the emitted `policy_sha256` securely in the deployment control plane. An allowed client OS UID must correspond to the **kernel** peer UID, not a user-supplied string. Original EC253 authorized server UID and client UID are separate knobs (they may be different).

An operator prepares **one exact short TTL unsigned subject** immediately before approvals (0 < TTL <= 45 seconds); two people review the *same subject SHA* and produce separate domain-separated votes:

```sh
python3 -I -B scripts/ces_quality_execute_host.py prepare-offline \
  --policy-file /private/ec286-execute-policy.json --policy-sha256 POLICY_SHA256 \
  --uid CLIENT_UID --ttl-seconds 40 --out /private/grant-subject.json

python3 -I -B scripts/ces_quality_execute_host.py sign-custodian-offline \
  --subject-file /private/grant-subject.json \
  --private-key-file /private/roles/custodian.key --out /private/custodian-vote.json

python3 -I -B scripts/ces_quality_execute_host.py sign-executor-offline \
  --subject-file /private/grant-subject.json \
  --private-key-file /private/roles/executor.key --out /private/executor-vote.json

python3 -I -B scripts/ces_quality_execute_host.py assemble-offline \
  --subject-file /private/grant-subject.json \
  --custodian-vote /private/custodian-vote.json --executor-vote /private/executor-vote.json \
  --custodian-public-hex CUSTODIAN_PUBLIC --executor-public-hex EXECUTOR_PUBLIC \
  --out /private/two-vote-grant.json
```

Never reuse the source/execute/Host signer key for another role. The example fixed profile is illustrative, and **the other EC186 catalog profile is also a fixed host-approved profile**; there is no client-provided `argv`, `pytest` option, arbitrary test target or shell command.

## 3. Start one separately owned EC286 Host and explicitly invoke the only allowed console command

Start Host (in a `0700` owner-private directory) with a pinned server private key and **already live** EC259 strict service. `--max-requests 1` is the recommended one-request service lifetime, including denied requests; it is *not* a retry authorization.

```sh
python3 -I -B scripts/ces_quality_execute_host.py serve \
  --socket /private/ec286-sock/execute.sock \
  --policy-file /private/ec286-execute-policy.json \
  --policy-sha256 POLICY_SHA256 --server-private-key /private/roles/server.key \
  --max-requests 1
```

Client executes through the **exact** optional console entry, which checks the already-registered Router action/mode but does **not** invoke its `HOST_REQUIRED` handler. The client carries only the grant, pinned policy, pinned server public key and server socket address:

```sh
python3 -I -B scripts/ces_next.py host-execute QualityRun Execute \
  --socket /private/ec286-sock/execute.sock \
  --grant-file /private/two-vote-grant.json \
  --policy-sha256 POLICY_SHA256 --server-public-hex SERVER_PUBLIC
```

Standalone client also exists as `python3 -I -B scripts/ces_quality_execute_host.py execute --socket ... --grant-file ... --policy-sha256 ... --server-public-hex ...`. Output is JSON. Successful Host **communication** and a zero **host-reported process exit** still return `partial`/`2`, `quality_pass_verified=false`; the original EC187 contract deliberately does not attest test correctness or OCI kernel isolation.

## 4. Handling errors and unknown effects

- Before actual original EC253 `begin`, a server-signed explicit permission denial can state `lease_or_container_effect_unknown=false`. This is not authorization to issue a new grant blindly: confirm source/key policy remains eligible.
- After a possible `begin`, **any** Host-level error, dropped reply, untrusted/stale/invalid nonce/signature, truncated response, client timeout/crash, or inconsistent console JSON yields `lease_or_container_effect_unknown=true` or an explicit **signed** Host report that shows the original controller's begin attempt. Never automatically retry because it might start a second process under a new lease.
- For unknowns, inspect the **original EC253 durable one-use lease ledger**, original EC259/257 service and Podman container + cgroup state, session watch/reaper evidence, original EC258 source custody and original receipts. Resolve or revoke the original lease and record a fresh, independently approved authorization before any new execution.
- A valid signed EC187 `partial/2` contains only bounded host-reported exit, counters and digests; stdout/stderr previews are **null**. It never yields verified CI PASS, no-op claim or delivered report. `unavailable`/`5` is not a positive security attestation.
- Revocations and pin rechecks are not atomically bound to each OCI syscall; OS UID/socket ownership and a service-code SHA are not independently authenticated remote build attestation. During combined acceptance, exercise real Podman+cgroup, lease continuity across crashes, revocation during execution, service replacement/same UID attacker, invalid process identity and native PowerShell7/15 Smoke.

## 5. Scoped local development verification (not production validation)

```sh
# Run as an unprivileged Linux UID. Original EC187 path is called;
# the original EC259 service / Podman / cgroup implementation is MOCKED.
PYTHONPATH=construction PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -v \
  construction.ec286_quality_execute_host.test_host
```

`construction/EC286_LOCAL_REPORT.json` records the actual limited outcomes. The full older package, R150 PowerShell, 74 Router registrations/11 original refusals and historic EC151–285 evidence remain intact. EC249 incomplete; EC250 BLOCKED; B001 OPEN; global Quality PASS=false; final joined acceptance not started.
