# EC263 — Ed25519 offline checkpoint for a signed EC262 audit prefix

**Scope:** one new *operator opt-in* strict-host deployment, not a Router endpoint. EC263 authenticates a previously committed **prefix** of the EC262 local journal with an independently managed Ed25519 signing key and two externally pinned SHA-256 digests. Later entries remain under EC262's host-local HMAC; no WORM archive, remote timestamp, tamper-proof clock or remotely attested OCI/source/CI is supplied.

## Security and workflow

The EC262 audit has `events.jsonl` and `head.json`, both dependent on its host HMAC secret. A person with the audit key and local file access could replace **both**. EC263 permits an operator to take an *offline-reviewed checkpoint* of a nonempty, fully HMAC-validated journal, sign that exact prefix with an Ed25519 private key **kept on a separate signing machine**, and configure a new strict session host to refuse startup and further audit writes if the signed prefix or pinned checkpoint/public key changes. The checkpoint signs count, exact prefix byte length, SHA-256 of the prefix, last EC262 MAC, signer-public-key digest and random nonce. Ed25519 signatures use a dedicated domain; file formats must be canonical and are bounded. The server never accepts `--signing-key`.

A physical/administrative separation is a **deployment requirement, not a software proof**. An offline signer must independently review what it signs; signing a malicious proposal merely authenticates that malicious proposal. A checkpoint is a signed historical prefix, not a statement that the underlying Git/CI/enterprise or Podman results are true.

### 1. Prerequisites and initial journal

On the existing trusted **non-root Linux** service host, first deploy the unchanged EC262 `serve` and have it write at least one real audit record, then **stop it and confirm it has exited**. The new EC263 `propose-checkpoint` and `verify-checkpoint` intentionally require an existing journal and its exclusive lock; they never bootstrap a missing log. Reuse the original approved EC259/260/261 source, EC253 dual-HMAC, and EC257 cgroup requirements. Audit key and journal remain 0600 files in 0700 private directories with proper durable backing storage. Keep checkpoint, proposal and public key outside the audit root and in a separate private (0700) directory.

On an **offline signing machine** with Python 3 and `cryptography`/Ed25519 support, generate an independent keypair using private absolute paths with an already-existing operator-private directory:

```bash
python3 construction/ec263_offline_anchor_host/serve.py offline-keygen \
  --signing-key /offline/private/ec263-signing.key \
  --signer-public-key /offline/private/ec263-signer.pub
```

Save the printed `signer_public_sha256` fingerprint through an **independent trusted channel**. Never place the private signing key on the EC263 running host; do not reuse the EC262 audit HMAC secret or either original EC253 HMAC key. Transfer only the 32-byte `ec263-signer.pub` as a private 0600 file into the operator-private host directory. `offline-keygen` creates files with `O_EXCL`, mode 0600 and file/directory fsync; it refuses overwrites. If interrupted between creating the two keys, inspect/remove the incomplete private files manually rather than assuming an atomic pair.

### 2. Propose a journal checkpoint with the host stopped

On the audit host, with the original EC262 host stopped, provide the independently copied public key SHA-256 (not a hash learned only from the audit machine):

```bash
python3 construction/ec263_offline_anchor_host/serve.py propose-checkpoint \
  --audit-root /operator/audit --audit-key /operator/private/audit.key \
  --signer-public-sha256 <64-hex-trusted-public-key-sha256> \
  --output /operator/private/ec263-proposal.json
```

The command checks the entire EC262 chain/head, confirms a nonempty journal, reads its content through the locked FD with bounded streaming SHA-256, and creates a canonical, private, exclusive proposal file. The proposal has *hashes/length/count only*; it never includes requests, source paths, tickets, stdout or the HMAC key. Its output `partial/2` is not a signature. Transfer and review this proposal **offline**. Independently compare the hash, count, nonce and source custody context where available; the signing tool itself cannot attest host truth.

On the **offline machine**:

```bash
python3 construction/ec263_offline_anchor_host/serve.py offline-sign \
  --proposal /offline/private/ec263-proposal.json \
  --signing-key /offline/private/ec263-signing.key \
  --output /offline/private/ec263-checkpoint.json
```

The signature is Ed25519 over a domain-separated canonical JSON payload. The signer checks that the proposal's `signer_public_sha256` is derived from its own signing key. Preserve the exact signed checkpoint bytes plus the printed **`checkpoint_sha256`** in separately controlled/offline records. Transfer the checkpoint file and the independently generated public key to the audit host. The private signing key **never** travels. A host administrator must pin both the public-key SHA-256 and signed checkpoint SHA-256 in trusted, reviewed service configuration. Never auto-learn either pin from a mutable on-host file; changing an intended checkpoint requires a **new explicit offline review and configuration change**. Merely passing an old valid checkpoint with an old stale pin is not detectable without a separately maintained latest-pin record.

### 3. Verify and serve with mandatory checkpoint gate

```bash
python3 construction/ec263_offline_anchor_host/serve.py verify-checkpoint \
  --audit-root /operator/audit \
  --audit-key /operator/private/audit.key \
  --checkpoint /operator/private/ec263-checkpoint.json \
  --checkpoint-sha256 <64-hex-pinned-checkpoint-sha256> \
  --signer-public-key /operator/private/ec263-signer.pub \
  --signer-public-sha256 <64-hex-pinned-public-sha256>
```

The verifier opens the existing journal **read-only**, validates the complete EC262 chain/head, loads protected checkpoint/public-key files from private parents, validates exact SHA pins, canonical structure and Ed25519 signature, then checks the signed prefix bytes/count/last MAC against the live journal. It responds `status=partial`, exit code **2** with both `attested_event_count` and `post_checkpoint_unattested_events`; any missing/mismatched/symlinked file or key fails closed with **5**. Do not interpret `partial/2` as external WORM, overall Quality PASS or independently trusted business execution.

To run a strict signed session, use the **separate EC263** operator entrypoint (not the old EC262 `serve`), with the same EC262 policy/Git custody options plus the four checkpoint arguments:

```bash
python3 construction/ec263_offline_anchor_host/serve.py serve \
  --policy /operator/private/policy.json \
  --repo /operator/repo --allowlist /operator/private/approved-source.json \
  --receipt /operator/private/source.custody.json \
  --profile-id python.pytest --socket /operator/socket/ces263.sock \
  --audit-root /operator/audit --audit-key /operator/private/audit.key \
  --checkpoint /operator/private/ec263-checkpoint.json \
  --checkpoint-sha256 <64-hex-pinned-checkpoint-sha256> \
  --signer-public-key /operator/private/ec263-signer.pub \
  --signer-public-sha256 <64-hex-pinned-public-sha256> \
  --max-sessions 1 --accept-timeout 60
```

The EC263 server **will not** create a missing journal or default to unsigned mode. It checks the signature and signed prefix **before** recording `service_start`, before EC253 recovery, before listener/socket work or any fork/Lease. The original EC259 Git/HMAC gate, active recall, bounded Socket egress, EC257 kernel meter, cleanup and EC262 journal records remain mandatory. For every new `audit.record()` it re-reads the pinned signing material and recomputes the signed prefix SHA-256 from the original locked FD. A checkpoint tamper or in-place prefix alteration poisons the writer: the protected operation cannot continue, original session cleanup runs and the host exits. The original EC262 entrypoint is unchanged; opt-in security is **not** automatically imposed on older deployments.

The verifier/host never silently repairs a broken `events.jsonl`/`head.json`, rotates a journal, removes a checkpoint, resets counters or downgrades verification. Keep the raw files, any `.head-*` remnant and the signed checkpoint for operator investigation. **EC262's hard cap remains 32 MiB / 65,536 entries; rollover and externally pinned archive continuation are not implemented by EC263.** New events after the checkpoint are not independently signed until a new reviewed checkpoint is issued offline and its digest updated in pinned configuration.

**Exit codes:** the four operator utilities report `status=partial` with exit code **2** even when the requested local step succeeds. This is intentionally not a global CES Quality PASS. Exit code **5** denotes refusal/unavailability. Shell automation should explicitly handle successful `partial/2` rather than treating it as a failed key operation.

## Performance and evidence boundaries

- Prefix recheck per required audit event costs O(signed prefix byte length), up to 32 MiB of bounded reads and hashing per event. It deliberately favors fail-closed behavior over latency; **no hard 1-second revocation bound** is established. Deploy and measure on actual operator hardware.
- Tested locally on unprivileged Linux with real Ed25519, private files, HMAC, Git, AF_UNIX, fork and EC253 lease/ledger; **Podman/cgroup-v2 in the signed host integration remains simulated**. The offline signer in developer tests ran on the same test machine; true administrative separation has not been tested.
- A hostile host may lie in a proposal. A compromised offline signer or administrator who replaces both trusted pins can create new forged anchors. The signed prefix does not attest clock, requester identity, human reviewer, remote Git, CI, OCI isolation or an external remote/WORM log. Same-UID/root races, filesystem failure during fsync, and untrusted config deployment still require operator controls.
- Retain the historical incomplete/frozen state: EC249 `FULL_FUNCTION_NOT_COMPLETE`, EC250 `BLOCKED`, B001 `OPEN`, original R150 CLI/R243 Router 11 `HOST_REQUIRED` denied, final full-system acceptance `NOT_STARTED`.
