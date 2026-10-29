# EC267: independent issuer governance, revocation, rotation, and expiring admission

This is a **separate opt-in strict host**. It preserves EC266's three separately
pinned `origin`, `review`, `ci` signatures, EC265 independent custody receipts,
EC264/263/262 complete signed audit chain, EC259 exact local Git/TAR custody,
EC253 original signed approval/lease tickets and EC260/261 continuous recall
and guarded egress. It adds a **fourth independent Ed25519 governance authority**,
not a new Quality PASS mode or any permission to bypass `HOST_REQUIRED`.

The governance owner signs one canonical JSON snapshot of the precise EC266
gate digest, source-subject digest, all three role public-key fingerprints,
cumulative explicitly revoked fingerprints, bounded UTC validity window,
unsigned positive governance epoch and predecessor signed-policy SHA256. The
new host validates the Ed25519 signature under an **operator-pinned separate
public key**, the entire signed snapshot SHA under a second independently
obtained pin, exactly matching current EC266 proof/roles, and a separately
provided `minimum-governance-epoch` and predecessor SHA pin. It refuses a
currently revoked signer, a document not yet valid or expired, and a runtime
clock rollback relative to its own initial wall/monotonic observation.

## Authority model, important limitations

- The **governance root key** must belong to a separate offline authority, not
  to any source/review/CI, audit or custody signer. The host has only its public
  key. The signer's independent identity/security and decisions require actual
  external procedures; the example command can generate development keys.
- The signed role-key list is *not* an independent verification of CI facts,
  reviewer identity or actual remote forge state. EC266 independently checks
  its own signatures and actual evidence bytes. EC267 checks those identities
  remain authorized under a fourth signed policy.
- No single-root clock, signed Unix timestamp or `time.monotonic_ns()` gives
  **trusted global time**. The enforced maximum lifespan is **24 hours from
  issued_at**, the future start is at most 1 hour from issue. During a running
  host, monotonic elapsed time helps prevent a wall-clock rollback from extending
  the window. Reboots, hostile clock administration and resumed/reimaged hosts
  still require independent trusted-time controls at deployment.
- `minimum-governance-epoch` and `expected-previous-governance-sha256` **must
  be kept and raised through an independent operator-controlled channel**.
  They must not be copied unreviewed from the signed document. A signed
  predecessor SHA is a declared link, **not** cryptographic proof that a full
  historic chain was read or is physically immutable. An operator that supplies
  stale pins can reauthorize a still-valid older snapshot. No automatic
  tamper-proof cross-restart anti-rollback is claimed.
- Revocation is a signed **snapshot**. The issuing authority must carry forward
  all earlier revoked fingerprints; local validation only checks that the
  current list is canonical, not that the entire historical revocation series
  was retained. A compromised **governance root** needs independently pinned
  emergency replacement; it cannot self-certify trust in a new root.
- Revocation **during an active session** is effected by removing/replacing the
  pinned governance material or source evidence: the old host denies subsequent
  operations/egress, and runs its inherited lease/cgroup cleanup. **Safe key
  rotation to resume** uses a *new* EC266 role assertion/gate and a new EC267
  governance document with raised epoch and out-of-band pins, on a new host
  run. There is no hidden auto-rotation by changing a mutable signing key.

## Deployment and operator workflow

1. Complete EC266's current source subject, three role key+assertion+evidence
   files, and the separately operator-approved EC266 gate SHA. Complete the
   EC265 historic custody chain. Preserve the original EC253 ticket validity.
   Do not put any authorization material in the source repository or an audit
   tree. Deploy as a nonroot Linux owner with private 0700 parents and private
   regular single-link 0600 files; new outputs use O_EXCL/fsync.
2. On an **independent offline governance issuer**, generate one separate Ed25519
   keypair with `governance-keygen`. Obtain the exact independent governance
   public SHA by an out-of-band channel. Keep the **secret** off the serving
   host (in the development fixture only, it is on one workstation).
3. The source operator creates an **unsigned** candidate. These are example
   paths; actual hashes/times must come from an independently reviewed run:

```sh
python3 -I -B construction/ec267_governed_source_host/serve.py prepare-policy \
  --provenance-gate /private/ec266-gate.json \
  --provenance-gate-sha256 PINNED_EC266_GATE_SHA \
  --epoch 1 --previous-governance-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  --not-before-unix CURRENT_UNIX_SECONDS \
  --expires-at-unix CURRENT_PLUS_AT_MOST_86400 \
  --output /private/issuer-proposal-epoch1.json
```

`--not-before-unix` must be at least actual `issued_at_unix` and no more than
3600 seconds into the future; `expires-at-unix` must be greater than the start
and no later than 86400 seconds after issue. The command captures `issued_at`
and a fresh random nonce, writes one new canonical file, and prints its SHA256.
For revocations, repeat `--revoke-public-sha256 64_HEX_DIGEST` for all
previously and newly revoked signer public-key fingerprints. You may
**intentionally** include a currently active fingerprint to issue an
emergency-deny document. In that case new sessions remain blocked until a
new approved EC266 role is used.

4. After the independent authority reviews the file, its approved scope,
   revoked signers and operator pins, sign on the **offline** machine:

```sh
python3 -I -B construction/ec267_governed_source_host/serve.py governance-keygen \
  --signing-key /issuer/issuer-root.key --public-key /issuer/issuer-root.pub
python3 -I -B construction/ec267_governed_source_host/serve.py sign-offline \
  --proposal /issuer/issuer-proposal-epoch1.json \
  --proposal-sha256 INDEPENDENT_PROPOSAL_SHA \
  --signing-key /issuer/issuer-root.key \
  --expected-governance-public-sha256 INDEPENDENT_ROOT_PUBLIC_SHA \
  --output /issuer/issuer-policy-epoch1.signed.json
```

Transfer **only** the signed policy and public key to the source host. Obtain
out of band: signed file SHA, root public SHA, EC266 gate SHA, minimum epoch
and predecessor SHA. Keys/objects must stay externally separated. All three
EC266 role signers plus the governance root must be distinct from the source
host audit and custody signing identities.

5. Preflight on the source host **before** starting a service (schematic SHA
   values below are placeholders, not a valid credential):

```sh
python3 -I -B construction/ec267_governed_source_host/serve.py verify-gate \
  --chain /private/chain.json --chain-sha256 PINNED_CHAIN_SHA \
  --custody-gate /private/ec265-custody-gate.json \
  --custody-gate-sha256 PINNED_CUSTODY_GATE_SHA \
  --provenance-gate /private/ec266-gate.json \
  --provenance-gate-sha256 PINNED_EC266_GATE_SHA \
  --governance-policy /private/issuer-policy-epoch1.signed.json \
  --governance-policy-sha256 PINNED_SIGNED_POLICY_SHA \
  --governance-public /private/issuer-root.pub \
  --governance-public-sha256 INDEPENDENT_ROOT_PUBLIC_SHA \
  --minimum-governance-epoch 1 \
  --expected-previous-governance-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  --policy /private/ec253-policy.json --repo /private/approved-repo \
  --allowlist /private/allowlist.json --receipt /private/source.custody.json \
  --profile-id python.pytest
```

Only after preflight and live OCI/cgroup readiness should the operator use
`serve` instead of `verify-gate`, adding `--socket /private/socket/ces.sock
--max-sessions 1 --accept-timeout 60`. The binary never accepts signing
private keys on this path. It recovers old leases first, reads and verifies
all EC265 + EC266 + EC267 private authority files before any socket, new
lease or `service_start` append, then rechecks on initial handshake and
continuously during a session. Only completed safe cleanup can close an
already-started lease. Replies remain `partial/2` and never claim successful
external CI or overall Quality PASS.

## Key rotation example (epoch 1 to 2)

- First deploy and independently verify the **new** CI Ed25519 signer;
  have that signer authenticate the original EC266 subject under the new key
  and sign a fresh `ci` role assertion. Reconstruct **a new EC266 gate file**
  with the new CI public-key PIN/assertion SHA and obtain independent new
  operator EC266 gate SHA. On full EC253 ticket or source rotation, first
  re-propose a fresh EC266 source subject and obtain all three new assertions.
- Offline prepare epoch 2 referencing the **full byte SHA of the signed epoch
  1 governance document** as `--previous-governance-sha256`; include the old
  CI SHA in `--revoke-public-sha256`, alongside *every* previously revoked
  signer; update `--provenance-gate-sha256` for the new EC266 gate. Independent
  review, then sign with the separately trusted governance root.
- On a new strict service use independently raised
  `--minimum-governance-epoch 2` and the exact previously trusted epoch 1
  signed file digest for `--expected-previous-governance-sha256`; pin epoch 2
  signed bytes and root public key separately. Old epoch 1 admission must be
  retired from operator service configuration. EC267 will reject an active
  role present in the revoked list, wrong role digest, stale epoch, wrong
  predecessor SHA, bad signature, policy change and expiry.

## Tests run and final acceptance boundary

Local nonroot Linux exercises actual Ed25519 signing/verification, local Git,
original EC253 HMAC tickets, private Unix sockets, fork, lease journaling,
archived audit chain and live session denial. Podman and kernel cgroup
operations are **mocked**, and all four issuers are development fixture keys
on the same machine. There is no real remote Git/CI/review identity or CI job,
root signer physical separation, trusted time or cross-restart hardware epoch
anchor, physical WORM storage, production OCI/cgroup, PowerShell/OS/native
Smoke/E63–E66 or final user acceptance.

See [EC267 implementation record](../EC-267.md),
[EC267 scope](../construction/EC267_SCOPE.json) and
[EC267 local report](../construction/EC267_LOCAL_REPORT.json).
