# EC266: pinned three-authority source-admission gate (operator workflow)

This optional EC266 service wraps **all** prior EC265 safeguards, EC264/263/262 signed audit history, EC260/261 active recall/guarded output, EC259/258 Git-to-TAR custody, EC253 original dual-HMAC time-limited tickets and EC257 strict Linux cgroup-v2 requirements. No existing PowerShell, Router, EC186 or EC187 entrypoint is modified. The new system verifies signed *assertions* from three independently pinned Ed25519 public keys; it does **not** authenticate a Git forge, approval UI, reviewer employment, CI server, timestamps or physical independence by itself.

## Required roles and their exact claims

| Role | Host-enforced decision | Meaning if the **independent owner** really authenticates its evidence |
|---|---|---|
| `origin` | `commit_recognized` | That origin authority claims to recognize the exact commit in the recorded repository/ref |
| `review` | `approved` | A separate review authority claims to approve the same immutable source subject |
| `ci` | `passed` | A separate CI authority claims to have approved a matching run/evidence artifact |

All three assertions must bind the **same full subject hash**, each role's **own evidence file SHA-256**, and each **distinct, operator-pinned public key**. Assertions have role-separated Ed25519 signing domains, random nonces and exact canonical JSON shapes. Signatures are not interchangeable. The source subject binds the actual EC258 Git commit/tree/object format, source allowlist, source TAR and content receipt, original EC253 policy and dual authenticated ticket receipts, profile digest, container image digest, source pin, operator-recorded remote repository/reference and a fresh nonce. EC253 ticket rotation/expiry intentionally invalidates admission: issue a new subject and have the independent authorities review/re-sign it. The evidence files are never parsed as trusted remote APIs; **issuer-side verification is a mandatory external process**.

## Deployment roles (do not simulate in production)

- **Source operator:** maintains rootless Linux strict host, exact private Git repo/allowlist/EC258 prepared TAR, EC253 approval/lease tickets, EC264 segment chain, EC265 historical custody receipt gate. Generates an *unsigned* subject only.
- **Origin authority:** uses a separate authorized identity/machine to verify remote repository identity and immutable commit/ref via its trusted out-of-band Git/forge records; preserves a concrete bounded evidence file and signs the exact subject + evidence hash with its OWN offline Ed25519 secret.
- **Review authority:** independently verifies a valid review by the required human/approval system against precisely that commit and subject. The separate review key stays off the serving host.
- **CI authority:** independently verifies the actual CI execution result, pipeline identity, source revision, job output and source artifact digest. The separate CI key stays off the serving host.
- **Operator signing governance:** independently distributes SHA-256 of the subject, three evidence files, three signatures, three public keys, **entire canonical EC266 gate config**, as well as EC264 chain and EC265 custody gate pins. Files and all path parents must be private, owned by the nonroot operator where locally installed; gate files are forbidden inside a Git source repository or active/historical audit root. Keep the signing keys exclusively on the independent issuers.

Creating three local test keys on one development workstation **is not** real independent source/reviewer/CI authentication. Anyone controlling an issuing key can assert false facts; the cryptography only makes that exact signed claim and its evidence-byte digest detectable.

## Step 1 - create a new subject on the source operator host

First follow EC258 and EC253 procedures to produce the exact immutable `source.tar`, `source.custody.json`, approved Git allowlist, valid signed policy/tickets; and EC265 procedures to prepare a fully pinned historical chain and verified independent custody receipts. On a nonroot Linux host with cryptography installed:

```sh
python3 -I -B construction/source_provenance_host/serve.py propose \
  --policy /private/policy.json \
  --repo /private/approved-repo \
  --allowlist /private/allowlist.json \
  --receipt /private/source.custody.json \
  --profile-id python.pytest \
  --origin-repository git.example.test/group/repository \
  --origin-ref refs/heads/release \
  --output /private/subject-ec266.json
```

`origin-repository` is an operator-verified **identifier**, not a network fetch or a verified Git remote. Use a 8-240 character ASCII slash-delimited, non-URL repository identifier. `origin-ref` must be a full `refs/heads/...` or `refs/tags/...` reference. The command outputs a SHA-256 subject PIN. Independently review its content and transmit that exact PIN along with a byte-exact subject, never a rewritten JSON document. The command reports `partial`, exit code `2`, not a successful remote provenance certification.

## Step 2 - each of the THREE independent authorities signs its own evidence

On each separate authorized signing system, prepare a real evidence file representing the authority's independently verified external record. Its contents are treated as opaque bytes by CES; preserve the evidence file itself for live re-verification. A new role-specific Ed25519 secret/public pair may be created **offline** using `authority-keygen` and must never reside on the serving host:

```sh
python3 -I -B construction/source_provenance_host/serve.py authority-keygen \
  --signing-key /issuer-only/ci-ed25519.key \
  --public-key /issuer-only/ci-ed25519.pub
python3 -I -B construction/source_provenance_host/serve.py sign-offline \
  --subject /issuer-only/subject-ec266.json \
  --subject-sha256 SUBJECT_SHA256_FROM_SEPARATE_CHANNEL \
  --role ci \
  --evidence /issuer-only/actual-ci-provider-record.json \
  --evidence-sha256 EVIDENCE_SHA256_FROM_SEPARATE_CHANNEL \
  --evidence-id ci-run-1234 \
  --signing-key /issuer-only/ci-ed25519.key \
  --expected-public-sha256 CI_PUBLIC_SHA256_FROM_SEPARATE_CHANNEL \
  --output /issuer-only/ci-attestation.json
```

Repeat for `origin` with its own key and recognized-commit external evidence, and `review` with its own key and actual review record. The `sign-offline` utility checks file/subject/key pins and cryptographically signs a role-specific `decision`, but it **cannot itself investigate whether the claimed CI/review/remote event happened**. Issuing a signature is a human/infrastructure authorization action, not an automatic verification of third-party data.

## Step 3 - assemble ONE independently pinned gate on the serving host

Transfer only the subject, three public keys, three signed assertions and three original evidence files. Never copy the private keys. All files use absolute operator-owned private paths and mode `0600` in private directories. Build one canonical single-line sorted-key UTF-8 JSON object followed by `\n`, without whitespace variation. Example **schema/layout** (replace ALL fake paths and hashes with exact values):

```json
{
  "schema": "ces.ec266.pinned_three_role_admission_gate.v1",
  "subject": "/private/subject-ec266.json",
  "subject_sha256": "REPLACE_64_LOWERCASE_HEX",
  "origin_repository": "git.example.test/group/repository",
  "origin_ref": "refs/heads/release",
  "authorities": [
    {"role": "origin", "public_key": "/private/origin.pub", "public_sha256": "REPLACE_64_LOWERCASE_HEX", "assertion": "/private/origin-attestation.json", "assertion_sha256": "REPLACE_64_LOWERCASE_HEX", "evidence": "/private/origin-evidence.json", "evidence_sha256": "REPLACE_64_LOWERCASE_HEX"},
    {"role": "review", "public_key": "/private/review.pub", "public_sha256": "REPLACE_64_LOWERCASE_HEX", "assertion": "/private/review-attestation.json", "assertion_sha256": "REPLACE_64_LOWERCASE_HEX", "evidence": "/private/review-evidence.json", "evidence_sha256": "REPLACE_64_LOWERCASE_HEX"},
    {"role": "ci", "public_key": "/private/ci.pub", "public_sha256": "REPLACE_64_LOWERCASE_HEX", "assertion": "/private/ci-attestation.json", "assertion_sha256": "REPLACE_64_LOWERCASE_HEX", "evidence": "/private/ci-evidence.json", "evidence_sha256": "REPLACE_64_LOWERCASE_HEX"}
  ]
}
```

**The example above is for shape only and is NOT a runnable gate.** The actual gate must use exactly the sorted compact canonical encoding produced by `json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'`. Pin the exact resulting file SHA separately; never generate both config and operator SHA in the same unreviewed workflow and call it independent trust.

## Step 4 - verify/serve (only after operator pins are approved)

```sh
python3 -I -B construction/source_provenance_host/serve.py verify-gate \
  --chain /private/chain.json --chain-sha256 PINNED_CHAIN_SHA \
  --custody-gate /private/ec265-custody-gate.json \
  --custody-gate-sha256 PINNED_CUSTODY_GATE_SHA \
  --provenance-gate /private/ec266-provenance-gate.json \
  --provenance-gate-sha256 PINNED_PROVENANCE_GATE_SHA \
  --policy /private/policy.json --repo /private/approved-repo \
  --allowlist /private/allowlist.json \
  --receipt /private/source.custody.json --profile-id python.pytest
```

`verify-gate` exits `2` / `partial` and reports **cryptographically verified role signatures and current local source/ticket consistency only**. No immutable remote proof, trusted timestamp, human identity certificate, CI provenance fetch, Quality PASS or OCI live execution is implied. Add `serve` in place of `verify-gate`, with `--socket /private/socket/ces.sock --max-sessions 1 --accept-timeout 60`, only on an already approved EC265 strict host with a real rootless Podman/delegated cgroup-v2 configuration. Startup first recovers existing signed leases, checks EC265 custody, then requires all three role signatures, exact evidence bytes, signed source, signed tickets and approval-profile binding **before any new socket/lease, or the first service-start audit append**. It repeats gate verification on startup, before each begin and throughout live sessions via the inherited active recall/egress monitor. Failure cannot be overridden by the client.

## Mandatory external/final validation backlog

Independent ownership/key ceremony and secure out-of-band PIN distribution; actual forge readback/authentication and commit/ref provenance; true reviewer identity/approval scope; real CI execution, job/image/artifact identity, protected pipeline controls; signer revocation/rotation and expires/compromise governance; EC265 physically separate custody and WORM/retention/time; real rootless Podman/systemd delegated cgroup-v2, kill tree/meter/disk/power and long load; Windows/macOS/native PowerShell7/15 smoke/E63-E66; original Router `HOST_REQUIRED`, business/Provider/Cycle and full acceptance. The development tests use synthetic authority evidence **and mock Podman/cgroup**; no real external acceptance is claimed.
