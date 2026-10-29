# EC281 — Independent QualityRun.Preflight host (plan only)

**Construction version:** `V5.91 / R281 / EC281`. This is an optional host on
POSIX systems with AF_UNIX + kernel peer UID. **No tests are executed.** It
runs the original EC186 `QualityRunSafetyGate.prepare` using exact pinned
host-controlled materials and returns a signed `partial / 2` *plan*.

## Threat model and boundaries

The existing EC241/243 Router continues to deny `run QualityRun Preflight`
and all **11** `HOST_REQUIRED` requests. `host-preflight QualityRun Preflight`
is a *different* literal-only entry. Nothing can forward arbitrary action
identities, provide a callback, run QualityRun.Execute, select an executable,
write a business repository or consume an isolation lease.

The server owns `repo_root`, private current EC181 root-pin file, two EC186
HMAC verification keys, an EC186 approved-profile ticket and a distinct
isolation-broker reserved-lease ticket. **All five raw files are separately
SHA256-pinned in a private policy**, and each is re-read during the EC186
authorization stages and before returning the plan. The server also rechecks
the full private policy SHA. Clients submit ONLY a dual-signed exact subject.
The two Ed25519 issuers sign independent domain-separated `policy` and
`isolation` approvals of the *same* UID, profile, policy SHA, three ticket/pin
SHAs and at most 120 seconds of eligibility. The kernel UID must match. A
third Ed25519 server signing role signs the nonce, exact original request SHA,
policy SHA, three input-file SHAs, time and full partial/denied body.

The host's own MAC-verification keys are not necessarily *issued* by
independently managed production authorities. HMAC provides shared-secret
origin within the configured host trust domain, **not public-key proof of
issuer personhood**. The kernel identity check is an OS-local access bound,
not a remotely authenticated identity. Co-located synthetic keys in tests
do not qualify as independent physical custody.

## Host-admin preparation

1. Run on a **host-private, trusted checkout**; never let a requester supply
   the repository root. Capture a recent directory identity under the host
   operator's account. This observation is NOT a Git object-content seal:
   ```bash
   python3 -I scripts/ces_quality_preflight_host.py capture-root \
     --repo-root /srv/checked/source --out /srv/private/pin.json
   ```
   The command writes `0600`, exclusive creation, and reports the raw file's
   SHA256. EC181 root pins expire after **300 seconds**. Expired pins must be
   recaptured and the policy/policy SHA/dual signatures replaced.
2. The **profile-authorization HMAC issuer** independently creates an EC186
   `ces.qualityrun.profile_approval.v1` JSON ticket, bound to the EC181
   `detect._sha(DOMAIN_PIN, source_pin)` and the *built-in* profile's
   `guard.catalog_entry(profile_id)['profile_sha256']`. Its HMAC is
   `HMAC-SHA256(policy_verification_key, guard.DOMAIN_APPROVAL +
   guard._canonical(ticket_without_mac))`. ID format matches the existing
   EC186 identifier, `issued_at_utc` and `expires_at_utc` are UTC seconds,
   maximum lifetime 600s, issued at most 300s ago. `approved_purpose`
   equals the built-in profile's `purpose`.
3. A **separately managed isolation broker** creates a `ces.qualityrun.isolation_lease.v1`
   *reserved, not consumed* ticket bound to the same source pin/profile,
   the complete approved ticket's
   `guard._digest(guard.DOMAIN_RECEIPT, approved_ticket)`, code-owned
   `guard.REQUIRED_CONTROLS`, a trusted image SHA256 and a second HMAC
   `HMAC-SHA256(broker_verification_key, guard.DOMAIN_LEASE +
   guard._canonical(lease_without_mac))`. Its lifetime is ≤120s, issue age
   ≤60s, expiry no later than the approved profile ticket. The host
   **does not prove** actual OCI/cgroup readiness from this HMAC statement.
4. Install both **different, private 32–4096 byte keys** as read-only `0600`
   files together with the three JSON files. All are externally controlled
   and trusted (not derived from a request). Provision three separate Ed25519
   signing keys, preferably on physically separate hosts/human devices:
   ```bash
   python3 -I scripts/ces_quality_preflight_host.py keygen-offline --private-out /offline-policy/issuer.key
   python3 -I scripts/ces_quality_preflight_host.py keygen-offline --private-out /offline-broker/issuer.key
   python3 -I scripts/ces_quality_preflight_host.py keygen-offline --private-out /srv/private/server.key
   ```
   These commands create exclusive raw 32-byte private-key files mode 0600,
   returning public hex only. Never copy offline issuer private keys to the
   read host; the server requires only a separate response-signing key.

## Private policy schema

Write the following JSON using **real exact absolute paths and raw file
SHA256 hex**. The three public keys must be distinct; `allowed_uids`
contains only real operator **kernel** UIDs. `allowed_profiles` is a
nonempty subset of `python.pytest` and `python.ruff`.

```json
{
  "schema": "ces.ec281.preflight_host_policy.v1",
  "repo_root": "/srv/checked/source",
  "allowed_profiles": ["python.pytest"],
  "allowed_uids": [1001],
  "source_pin_file": "/srv/private/pin.json",
  "source_pin_sha256": "<64 lowercase hex>",
  "approval_ticket_file": "/srv/private/approval.json",
  "approval_ticket_sha256": "<64 lowercase hex>",
  "lease_ticket_file": "/srv/private/lease.json",
  "lease_ticket_sha256": "<64 lowercase hex>",
  "policy_key_file": "/srv/private/policy.hmac",
  "policy_key_sha256": "<64 lowercase hex>",
  "broker_key_file": "/srv/private/broker.hmac",
  "broker_key_sha256": "<64 lowercase hex>",
  "policy_issuer_public_hex": "<64 lowercase hex>",
  "isolation_issuer_public_hex": "<64 lowercase hex>",
  "server_public_hex": "<64 lowercase hex>"
}
```

The policy itself MUST be `0600`, in a directory not controlled by the
requester. Capture the raw policy file's SHA via a trusted channel, then
start a service as its dedicated low-privilege host identity:

```bash
python3 -I scripts/ces_quality_preflight_host.py serve \
  --socket /run/ces-preflight/preflight.sock \
  --policy-file /srv/private/preflight-policy.json \
  --policy-sha256 '<trusted-policy-raw-sha256>' \
  --server-private-key /srv/private/server.key
```

The socket parent directory must exist and not be world-writable. The
created socket is mode `0660`; OS user/group ownership, ACLs, rotation and
supervisor access are **operator responsibilities**. The host refuses a
pre-existing socket and never deletes an inode it did not create.

## Complete explicit two-offline-signature workflow

The **requester** and both offline issuers must receive the genuine pinned
policy SHA and the three original host-file SHAs by independent trusted
channels; do not let a client invent new hashes or edit a policy.
Create the unsigned request:

```bash
python3 -I scripts/ces_quality_preflight_host.py prepare-offline \
  --profile-id python.pytest --uid 1001 --ttl-seconds 90 \
  --policy-sha256 '<trusted-policy-raw-sha256>' \
  --source-pin-sha256 '<pinned-source-pin-raw-sha256>' \
  --approval-ticket-sha256 '<pinned-approval-raw-sha256>' \
  --lease-ticket-sha256 '<pinned-lease-raw-sha256>' \
  --out /operator/subject.json
```

Each authorized issuer examines the **entire same subject** offline:

```bash
python3 -I scripts/ces_quality_preflight_host.py sign-policy-offline \
  --subject-file /operator/subject.json \
  --private-key-file /offline-policy/issuer.key --out /operator/policy-vote.json
python3 -I scripts/ces_quality_preflight_host.py sign-isolation-offline \
  --subject-file /operator/subject.json \
  --private-key-file /offline-broker/issuer.key --out /operator/isolation-vote.json
```

The operator verifies both signatures before assembling, and the host
verifies them again before touching private source/ticket data:

```bash
python3 -I scripts/ces_quality_preflight_host.py assemble-offline \
  --subject-file /operator/subject.json \
  --policy-vote /operator/policy-vote.json \
  --isolation-vote /operator/isolation-vote.json \
  --policy-public-hex '<trusted-policy-issuer-public-hex>' \
  --isolation-public-hex '<trusted-broker-issuer-public-hex>' \
  --out /operator/grant.json
python3 -I scripts/ces_next.py host-preflight QualityRun Preflight \
  --socket /run/ces-preflight/preflight.sock \
  --grant-file /operator/grant.json \
  --policy-sha256 '<trusted-policy-raw-sha256>' \
  --server-public-hex '<trusted-server-public-hex>' --pretty
```

Alternatively use fixed `scripts/ces_quality_preflight_host.py preflight`
with the same four options. A new plan with newer tickets/source requires
**new policy SHA and both fresh offline votes**.

## Response status and acceptance boundaries

- `2 / partial`: actual EC186 preflight configuration accepted, plan is
  `PREPARED_ONLY_NOT_EXECUTABLE`, real directory root re-observed twice,
  four exact host authorization stages verified, all input MACs verified,
  **no command, tests, network, source write or lease consumption**.
  Read-only receipt is bound to the approved profile and signed host key.
  The underlying code returns `quality_pass_verified: false` and
  `test_execution_verified: false`.
- `3 / permission_denied`: kernel UID, separate approvals, profile
  permission, exact pin/scope or signature time mismatch.
- `4 / invalid_input`: malformed input or invalid client preparation.
- `5 / unavailable`: changed policy, changed private files, unsafe input
  directory, invalid/stale EC186 pin or tickets, backend refusal or host
  failure. No plan is issued.

This is **not** `QualityRun.Execute`: it never instantiates the EC187
external trusted runner, reserves an actual new lease, consumes an EC186
lease, executes pytest, probes delegated cgroups, attests CI, verifies
Git contents or concludes QUALITY_PASS. Production isolation broker and
real externally authentic issuer/CI/Provider sources are still unbuilt
and not covered by this local simulation.

## Cumulative operator-assisted acceptance

The focused synthetic local tests use a genuine AF_UNIX socket, the original
EC186 preflight, real Ed25519/HMAC primitives and signed replies, but all
signing roles and HMAC inputs are synthetic/co-located and the same UID.
Before real usage, validate truly independently provisioned issuer/broker
accounts, host OS account and group ACLs, host/operator clock and expiry,
revocation and key rotation, root replacement/TOCTOU limits, actual
container and lease broker enforcement, restart handling, original R150
PowerShell7 15 Smoke, Windows/macOS variants, original 74-route Router
regression, CI/provider/Git source provenance and complete joined acceptance.

Original EC249 full-function incomplete, EC250 blocked, B001 open,
final acceptance not started and global QUALITY_PASS=false continue.
