# EC186 — QualityRun safety configuration gate

**Construction version V4.96 / R186 / EC186.** Standalone Python API: [`QualityRunSafetyGate.prepare`](../construction/quality_run_guard.py). Output contract: strict JSON Schema Draft 2020-12 [`ces.quality_run_guard.v1`](quality-run-guard-result.v1.schema.json). This module **never executes** a test, linter, program, shell, `git`, build step, container, CI job, local hook or other command. It never reads project configuration files or writes business/CES/Provider data. It only consults the EC181 POSIX no-follow *root identity observer* twice. It is **not** the native PowerShell `QualityRun` action; the embedded PowerShell remains V4.60/R150.

## Security model — what the gate actually checks

A permitted outcome requires **all** of the following, not merely a tool hint, `allow=true`, signed old receipt or project-supplied JSON:

1. An **exact local WorkingTree** `repo_root` and recent `QualityDetector.observe_root()` `source_pin`. POSIX absolute normalized path only; lstat/root walk uses EC181 no-follow dirfds. The host separately authorizes the root observer, both at entry and after final host authorization. The source *directory identity* is checked twice. This does **not** hash repository contents, authenticate Git objects, or pin individual files; EC187 must enforce an actual immutable content snapshot or sealed read-only source mount before running untrusted code.
2. A **built-in, immutable-by-convention profile recipe** chosen by exact `profile_id`. EC186 supports only `python.pytest` (purpose TEST; fixed image-owned `python -I -m pytest -q -p no:cacheprovider` intent) and `python.ruff` (purpose LINT; fixed image-owned `python -I -m ruff check . --no-cache` intent). The image-owned runtime and fixed module arguments are descriptive static catalog definitions; no shell or arbitrary project-specified executable, script, command, environment variable, `PATH`, `npm run`, build target, additional argument, local config hint or package hook is a valid plan input. `catalog_entry(profile_id)` returns exact profile/catalog hashes for **policy administrators**, not an execution entitlement. The pytest profile can run hostile repository Python and must *never* run without real isolation. Ruff may still parse hostile files/configuration.
3. A fresh **profile approval ticket** authenticated by a dedicated host-owned **policy HMAC-SHA256 key**, binding profile ID + profile definition hash + source-pin digest + requested `TEST`/`LINT` purpose; plus `allow_profile_approval=True` and explicit independent host-grant callback. A built-in catalog record alone is *not* an approval.
4. A separate, fresh **isolation reservation lease** authenticated using a **different host-owned broker HMAC-SHA256 key**. It binds the exact signed approval receipt hash, source-pin digest and profile hash; requires a pinned image SHA256 and an **exact signed** isolation controls object: reserved/not started, read-only source mount, private ephemeral scratch, deny all network, fixed pinned image-owned executor, unprivileged user and isolated user/mount/PID namespaces, no new privileges, dropped capabilities, seccomp, bounded cgroup, no host home/sockets/credentials/unapproved binds, no shared host network/PID. Every mandatory field must be present and have the correct JSON type; signed `1` is not a substitute for boolean `true`. `allow_isolation_lease=True` and another host-grant step are necessary. Missing, expired, unsigned, improperly isolated or mismatched leases are refused.
5. Separate `allow_prepare=True`, `authorize_root` and `authorize_gate` callbacks, plus host-grant checks at `BEFORE_PROFILE`, `APPROVED_PROFILE`, `ISOLATION_RESERVED` and `FINALIZE`. **Exactly boolean `True`** approves each stage. A final root observation and validity/TTL recheck follow the final authorization, detecting root rebinding/time expiry during callbacks. Any failure clears *all* partial plan/profile/source/isolation output.

**Crucial trust boundary:** The constructor's two independent keys, ticket issuance service, operator authorization callbacks and isolation broker must belong to a *trusted host control plane*, never the scanned repository, an AI suggestion, an arbitrary project input, a prompt, or EC185 output. The MAC proves that a ticket was signed by whoever holds the host-configured key. **It does not independently prove** the broker enforced Linux kernel sandboxing, that a real reserved executor/image exists, that the profile owner is a particular human, that an actual source snapshot is sealed, or that the lease has not been replayed. The caller must independently enforce trusted key custody, audited broker issuance, correct image/namespace/ACL policy and lease single-use. If such a trusted host broker is unavailable, **do not forge a ticket and do not prepare or run anything.** A source pin can drift between probes or after return. EC187 must independently verify actual isolation and source content and atomically consume the reserved lease before any execution; stale/reused leases cannot be authorized from this result alone.

## API and signed ticket wire format

```python
# Import with ces/construction on PYTHONPATH. These are trusted host-side
# inputs only, not values read from a project or produced by a model.
from quality_run_guard import QualityRunSafetyGate, catalog_entry
from quality_detect import QualityDetector

catalog = catalog_entry('python.pytest')  # static recipe and hashes, not approval
pin = QualityDetector.observe_root(
    absolute_repo_path,
    authorize_observation=trusted_root_observation_policy)

# The independent host policy authority and isolation broker MUST securely
# issue both correctly scoped, short-lived, signed tickets ahead of this call.
# Do NOT synthesize them or use unconditional lambda-True policy in production.
gate = QualityRunSafetyGate(
    policy_verification_key=policy_authority_secret_bytes,
    broker_verification_key=isolation_broker_secret_bytes)
result = gate.prepare(
    repo_root=absolute_repo_path,
    source_pin=pin,
    profile_id='python.pytest',
    policy_ticket=trusted_policy_ticket,
    isolation_ticket=trusted_isolation_lease,
    allow_prepare=True,
    allow_profile_approval=True,
    allow_isolation_lease=True,
    authorize_root=trusted_root_observation_policy,
    authorize_gate=trusted_per_stage_authorization,
    ec185_observation=None)  # optional, non-authoritative context only
```

The policy authority signs **canonical JSON** (ASCII, sorted object keys, no spaces, JSON booleans, no NaN) without the `mac_sha256` field, using HMAC-SHA256 over `b'CES-EC186-PROFILE-APPROVAL-v1\0' + canonical_bytes`. The signed envelope must contain **exactly**:

```json
{
  "schema": "ces.qualityrun.profile_approval.v1",
  "ticket_id": "hostpolicy-unique-id001",
  "profile_id": "python.pytest",
  "profile_sha256": "<64-lower-hex-profile-spec-digest>",
  "source_pin_sha256": "<64-lower-hex-EC181-pin-digest>",
  "approved_purpose": "TEST",
  "issued_at_utc": "2026-10-23T12:00:00Z",
  "expires_at_utc": "2026-10-23T12:02:00Z",
  "mac_sha256": "<64-lower-hex-HMAC>"
}
```

The separate host isolation broker signs canonical JSON *without* its MAC over `b'CES-EC186-ISOLATION-LEASE-v1\0' + canonical_bytes` and must provide **exactly**:

```json
{
  "schema": "ces.qualityrun.isolation_lease.v1",
  "ticket_id": "broker-reservation-id001",
  "source_pin_sha256": "<same-EC181-pin-digest>",
  "profile_sha256": "<same-builtin-profile-digest>",
  "approval_receipt_sha256": "<SHA256-of-signed-policy-ticket-with-domain-CES-EC186-RECEIPT-BINDING-v1-NUL>",
  "image_sha256": "<64-lower-hex-approved-image-digest>",
  "controls": {
    "lease_state": "RESERVED_NOT_STARTED",
    "source_mount": "READ_ONLY",
    "scratch_mount": "PRIVATE_EPHEMERAL",
    "network_access": "DENIED",
    "executor": "PINNED_IMAGE_FIXED_PROFILE_ONLY",
    "non_root_user": true,
    "user_namespace_isolated": true,
    "mount_namespace_isolated": true,
    "pid_namespace_isolated": true,
    "no_new_privileges": true,
    "capabilities_dropped": true,
    "seccomp_enforced": true,
    "cgroup_bounds_present": true,
    "host_secrets_mounted": false,
    "host_home_mounted": false,
    "host_sockets_mounted": false,
    "host_docker_socket_mounted": false,
    "host_network_shared": false,
    "host_pid_shared": false,
    "unapproved_bind_mounts": false
  },
  "issued_at_utc": "2026-10-23T12:00:05Z",
  "expires_at_utc": "2026-10-23T12:01:30Z",
  "mac_sha256": "<64-lower-hex-HMAC>"
}
```

The sample timestamps, IDs and placeholders above are **format examples**, not usable production tickets or tested broker attestations. No HMAC keys are shipped in the skill, and the package never issues a permission or runs a broker. Policy ticket age is at most 300 s and lifetime at most 600 s; broker lease age at most 60 s and lifetime at most 120 s; both must be unexpired and the lease cannot outlive approval. Clock future skew at most 30 s; current source root pin age at most 300 s. Issuers must still use shorter actual operational TTLs, independent tenant/authentication controls and revocation checking.

An optional EC185 `ces.quality_observation.v1` is only *context*. Its self-contained SHA256, local pin and 5-minute freshness must match this WorkingTree; `profile_hints` may be displayed as `true/false` but **never** authorize profile selection or attest tool installation, CI tests, project content, isolation or human/runner identity. A forged EC185 digest grants nothing. Local-only configuration hints are not equivalent to an authenticated remote CI commit SHA.

## Output and gate failures

- `status=partial`, `exit_code=2`, `reason_code=QUALITYRUNGUARD_CONFIGURATION_GATED_PLAN_ONLY` means exactly that **code-owned profile, separate signed statements, host callbacks, and root identity were checked**. It returns only a non-executable `plan`, source/profile hashes, redacted path indicators, signed-receipt digests, lease expiry, required control assertions and fixed-negative actual isolation/execution/quality-proof flags. `plan_sha256` is a **non-authenticating digest** of the limited result body, not a capability, command, signature, sandbox proof or usable runner token. EC187 must not execute using this output alone.
- `status=invalid_input/4` or `unavailable/5` means **deny**. All profile, source, authorization, isolation, context, proof, plan, timestamps and digest fields are `null`, with no partial lease/secret/path evidence; safe attempt counters remain. The code makes no shell, network, write or test calls even on refusal.
- This schema has `additionalProperties:false`, has only `partial/invalid_input/unavailable`, forbids executable command properties and fixes `actual_isolation_verified_by_ces=false`, `test_execution_verified=false`, `overall_quality_pass_verified=false`, `lease_consumed=false`. Schema validity **does not** validate real host identities or kernel sandboxing.

## Verification handoff

Run only if local development checks are desired: `cd ces/construction && python -m unittest test_quality_run_guard -q`. The focused synthetic cases exercise real EC181 directory identity calls and sign simulated approvals/leases using *test-only* keys inside this test module. They do not provision a real broker, run a check profile, test a real container, access remote CI or replace the eventual full-system user-assisted acceptance. Additional pending: PowerShell7, original 15 Smoke, Windows/macOS/Git, real hostile-container escapes, live credentials and true E63–E66 measurements. EC187 is next (execution budgets and cancellation semantics) and is **NOT IMPLEMENTED** here.
