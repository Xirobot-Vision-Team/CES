# EC272 — independent, two-signature ratified rollover for the EC271 256-record limit

**Construction package V5.82/R272/EC272. This is a new, explicit opt-in protocol.** The original EC271 host continues to verify all <=256 records and has no rollover support. The original EC270–EC253, PowerShell/Router and historical EC plan are unchanged.

## Purpose and core trade-off

After an EC271 receipt segment contains 256 two-of-three signed seals, `append-chain` correctly refuses to append a 257th. EC272 allows an **independently witnessed transfer** to the next 1..256-record segment, **without resetting the global sequence**. Each boundary has a domain-separated, non-overwriting Ed25519 checkpoint signed by two of the same three independent public-key witnesses, ascending by public-key SHA. Both signatures bind the canonical checkpoint, all earlier approvals, full EC271 last signed seal, the sealed segment's **complete SHA256-pinned manifest**, first/last seals, its sequence range, its witness roster, EC270 ratified recovery SHA and recovered-root SHA, and the previous checkpoint's **whole file SHA**.

At **prepare and each signing stage**, all 1..256 receipts in the segment are reopened and signature-verified in order, against the signed current/historical EC267 governance chain and the last receipt of the prior ratified checkpoint. Only a currently live last receipt (<=900s validity) may be checkpointed. Every file is created privately, exclusively (`O_EXCL`) and fsynced; no existing checkpoint or segment is silently truncated or overwritten. Private keys are *never* accepted by the host's `verify-gate` or `serve` commands.

At **runtime**, the EC272 host cryptographically checks *every checkpoint certificate* (up to 16), reopens/checks its SHA-pinned segment manifest, verifies its *embedded* first/last signed seals and cross-checks the segment boundaries, sequence/epoch/role membership, and validates **every member of the live new segment**. Older intermediate receipt bodies are **not re-opened** after a checkpoint: the distinct two-witness checkpoint signatures attest to a prior full readback. This is a deliberate and important **trust-model change**, not equivalent to EC271's full historical per-member runtime checking. Keep all historical receipts in independent immutable custody if forensic readback is required. A malicious quorum capable of signing a false checkpoint can lie about older intermediate members; this protocol does not solve that case.

The bounded limit is **16 signed checkpoints + one live segment of up to 256 seals**; using full segments, up to 4352 sequential receipts (16 sealed segments plus the 17th live one). No implicit wrap/restart or unbounded recursion. After that limit the protocol fails closed; a future separately scoped EC must approve an extension.

## CLI

Run from `ces/`:

```bash
python3 -I -B construction/freshness_rollover_host/serve.py --help
python3 -I -B construction/freshness_rollover_host/serve.py prepare-checkpoint --help
```

For all **offline** operations, define the same signed recovery/governance `$HISTORY_ARGS` and independent 3-key `$FRESH_WITNESSES` Bash arrays documented in [EC271's runbook](quorum-freshness.md), including `--governance-policy`, `--governance-policy-sha256`, three `--council-public` / pins, and any EC268 continuation pair. Do not substitute the literal string `$HISTORY_ARGS` for an array expansion. The 3 witness pins must be listed as separate paired `--freshness-witness-public` / `--freshness-witness-public-sha256` switches. For signing and append operations, additionally specify known independent `--forbidden-public-sha256` role keys, where applicable; strict host independently obtains mandatory custodian/auditor exclusion.

### 1. Checkpoint a complete, still-live EC271 segment

```bash
python3 -I -B construction/freshness_rollover_host/serve.py prepare-checkpoint \
  "${HISTORY_ARGS[@]}" "${FRESH_WITNESSES[@]}" \
  --segment "$OLD_EC271_CHAIN" --segment-sha256 "$OLD_CHAIN_PIN" \
  --output "$CP_DRAFT"
# Offline, first witness uses its independent Ed25519 PRIVATE key:
python3 -I -B construction/freshness_rollover_host/serve.py sign-checkpoint \
  "${HISTORY_ARGS[@]}" "${FRESH_WITNESSES[@]}" \
  --input-path "$CP_DRAFT" --input-sha256 "$CP_DRAFT_SHA" \
  --signing-key "$WITNESS_FIRST_SECRET" --expected-public-sha256 "$WITNESS_FIRST_PIN" \
  --output "$CP_FIRST_SIGNED"
# Second, different listed witness with SHA-sorted pin signs full first-stage SHA:
python3 -I -B construction/freshness_rollover_host/serve.py sign-checkpoint \
  "${HISTORY_ARGS[@]}" "${FRESH_WITNESSES[@]}" \
  --input-path "$CP_FIRST_SIGNED" --input-sha256 "$CP_FIRST_STAGE_SHA" \
  --signing-key "$WITNESS_SECOND_SECRET" --expected-public-sha256 "$WITNESS_SECOND_PIN" \
  --output "$CP_QUORUM_SIGNED"
```

`$CP_DRAFT_SHA`, `$CP_FIRST_STAGE_SHA`, `$CP_PIN` are the complete SHA256 digests returned by the immediately preceding operation, to be separately preserved and reviewed. Sign the checkpoint before the old segment's **final seal expires**; afterwards retroactive signing is prohibited, regardless of whether the last old seal was formerly valid. No command overwrites its output.

### 2. Start the next signed seal with EC271, then append to a *new* EC272 segment

The next seal remains the **same EC271 seal schema and issuance logic**. Use the original EC271 `prepare-freshness` and `sign-freshness` three-stage CLI, passing `--sequence 257 --previous-receipt "$LAST_OLD_SEAL" --previous-receipt-sha256 "$LAST_OLD_SHA"`, and an authenticated new current EC267 governance if the epoch was renewed. The previous receipt file **must still exist while signing the next seal**, because the original signer validates it; a ratified checkpoint is not a shortcut for creating a new EC271 signature without a predecessor.

After the new seal has two independent witness signatures, start the new segment (do **not** call EC271 `append-chain` for it, because the first new entry is *not* genesis):

```bash
python3 -I -B construction/freshness_rollover_host/serve.py append-segment \
  "${HISTORY_ARGS[@]}" "${FRESH_WITNESSES[@]}" \
  --checkpoint "$CP_QUORUM_SIGNED" --checkpoint-sha256 "$CP_PIN" \
  --segment-receipt "$SEAL_257" --segment-receipt-sha256 "$SEAL_257_SHA" \
  --output "$NEW_SEGMENT_1"
```

For additional seals in the same live segment (258, 259, ...), include `--previous-segment "$CURRENT_SEGMENT" --previous-segment-sha256 "$CURRENT_SEGMENT_PIN"`, create the output under a **new** path, and update the separately operator-controlled pins. Every append rechecks **all receipts of the live segment**. Do not delete/mutate the older segment manifest or the signed checkpoint chain. Before the new segment's last live seal expires, sign the next checkpoint by supplying `--previous-checkpoint "$CP_QUORUM_SIGNED" --previous-checkpoint-sha256 "$CP_PIN"` to `prepare-checkpoint`; both checkpoint signing stages recover and verify the complete signed ancestor checkpoint chain and current full segment.

### 3. Verify, serve and revoke

```bash
python3 -I -B construction/freshness_rollover_host/serve.py verify-segment \
  "${HISTORY_ARGS[@]}" "${FRESH_WITNESSES[@]}" \
  --checkpoint "$CP_QUORUM_SIGNED" --checkpoint-sha256 "$CP_PIN" \
  --freshness-chain "$NEW_SEGMENT" --freshness-chain-sha256 "$NEW_SEGMENT_PIN" \
  --minimum-checkpoint-number 1 --minimum-freshness-sequence 257 \
  --expected-previous-receipt-sha256 "$LAST_OLD_SHA"
```

For `verify-gate`/`serve`, pass **all EC271 strict host inputs** documented in its runbook: source provenance, audited signed custody, legacy EC253 policy, authorized Git/TAR/receipts, roots/charter/recovery/closure signatures, current EC267 governance/continuation, OCI profile, signed audit chain, strict cgroup/lease and original `--freshness-chain`/SHA/sequence/predecessor. **Add** `--checkpoint`, `--checkpoint-sha256`, and `--minimum-checkpoint-number` (an independently held floor). The live segment goes into `--freshness-chain`/SHA; the predecessor SHA is the immediately preceding seal SHA in that segment, or for the first new seal, the **checkpoint's last old seal SHA**. Restart the opt-in EC272 host with newly pinned chain/checkpoint SHA on a rollover; no unapproved hot swapping.

The strict new host requires EC270 authenticated closure and inherited EC266 signed local Git custody, EC265/264 signed custodial audit, EC253 durable lease and EC257/260/261 exact-ID OCI+cgroup and active recall. It checks the EC272 ratified chain **before service-start/socket/new lease**, before `begin`, during sessions, and prior to guarded response egress. Missing/altered checkpoint, missing public witness key, changed signed governance, invalid live seal, expired window, or rolled-back independent floors all **deny and trigger inherited cleanup**. Offline verification is **partial** and not proof that those host conditions were met. Original EC271/270 entrypoints do not enforce EC272 conditions.

## Trust and user-assisted acceptance boundaries

- Ed25519 proves control of two private keys, **not** physical independence of witnesses, HSM isolation, legal authority or real approval. Wall times in signatures are self-reported and are **not** a trusted TSA/UTC timestamp.
- The EC272 checkpoint statement is an explicit **witness attestation over the full verified segment at issuance**. The currently sealed manifest remains byte-SHA-checked, but **historical intermediate receipts are not reread at runtime**. A co-signed dishonest checkpoint or two compromised keys is not prevented by software.
- External operator must retain/checkpoint full SHA256, live segment full SHA, **monotonic checkpoint count**, global seal sequence floor, and preceding receipt SHA in a *genuinely external nonrollbackable store*. A rollback of all local bytes **and** locally held floors is not detected across process restarts.
- Actual externally sourced forge/reviewer/CI identity, remote WORM, reliable UTC/TSA, independent physical keys, live rootless Podman/cgroup-v2 resource isolation, 15 native PowerShell Smoke, Windows/macOS/E63–E66 and joined end-to-end acceptance remain **NOT VERIFIED**. EC249 remains incomplete, EC250 BLOCKED, B001 OPEN. No global Quality PASS is claimed.
