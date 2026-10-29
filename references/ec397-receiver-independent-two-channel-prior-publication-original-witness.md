# EC397 — receiver of two independently signed public-head observations (offline, read-only)

**Wire version:** `ces.ec397.*.v1`. **Delivered:** V7.07 / R397 / EC-397, 2026-10-26. No network or private-key use in production. **This is not proof that an independent organization or the public actually received anything when the witness claims it did.** The input still consists of furnished and externally SHA-pinned *original files*.

## Trust inheritance and fixed output meaning

This receiver calls the **real unchanged** `ec396_public_integrity.protocol.audit(**inherited)` on every derive/audit invocation. That verifier itself runs EC395→EC394→EC393→EC392→both EC391. Exact parent status, output fields, count sums, parent original SHA and externally retained parent whole-inventory SHA are verified before any EC397 credit. No `parent_pass` parameter exists. It reopens real parent EC396 log Heads, their Ed25519 signer original, real EC395 independent signer rosters, and the inherited EC394 independent TSA authority. In production each original RFC3161 DER is checked by the existing CMS/X509/furnished-CRL checker, including evaluation and dispute cutoff.

Successful cryptographic evaluation is **always `exit_code=2`, `*_unresolved`**. Invalid or untrusted originals are `3=permission_denied`, `4=invalid_input`, or `5=unavailable`. Derive creates **only an unsigned report**; audit additionally requires a separately retained SHA-256 of that exact unsigned inventory, but never changes the evidence. Neither command writes anything. Both explicitly deny claims about official legal accreditation, global fork absence, physical WORM custody, legal authority of the timestamp, independent public distribution or final Quality.

## CLI

```bash
cd ces
python -I -B scripts/ces_cas_historical_ec339_publication_witness.py derive-historical-ec339-publication-witness-inventory --help
python -I -B scripts/ces_cas_historical_ec339_publication_witness.py audit-historical-ec339-publication-witness --help
python -I -B scripts/ces_next.py audit-historical-ec339-publication-witness DeliveryAudit AuditHistoricalEC339PublicationWitness --help
```

All EC396 `audit` scalars/repeats are mandatory **including** `--expected-retained-historical-ec339-public-integrity-inventory-sha256`; the two new commands accept, additionally:

| One-time scalar (flag is underscores replaced with hyphens) | Purpose |
|---|---|
| `historical_ec339_publication_witness_bundle_file` | Absolute SHA-protected original EC397 bundle path |
| `expected_historical_ec339_publication_witness_bundle_sha256` | Independently retained whole-original SHA |
| `expected_outside_retained_ec397_observer_roster_sha256` | Independently retained roster SHA |
| `expected_outside_retained_ec397_channel_a_public_hex` | Independent first Ed25519 observer raw public key (32 bytes as 64 lowercase hex) |
| `expected_outside_retained_ec397_channel_b_public_hex` | Independent second public key |
| `expected_outside_retained_ec397_first_dispatch_sha256` | Outside-retained epoch 0 signed dispatch original SHA |
| `expected_outside_retained_ec397_first_channel_a_receipt_sha256` | Outside-retained first-channel epoch 0 signed receipt original SHA |
| `expected_outside_retained_ec397_first_channel_b_receipt_sha256` | Outside-retained second-channel epoch 0 signed receipt original SHA |
| `expected_retained_historical_ec339_publication_witness_inventory_sha256` | **Audit only:** independent whole unsigned inventory SHA obtained from derive through a separate trusted channel |

Each `--historical-ec339-channel-delivery-inventory-sha256`, `--historical-ec339-publication-fork-inventory-sha256`, `--minimum-historical-ec339-signed-channel-delivery-count` (0..2), and `--minimum-historical-ec339-two-channel-pair-count` (0..1) repeats once per parent historical epoch (1..3). These SHA and floor values **must** be supplied independently of the on-disk bundle; the derive output can be used to prepare a prospective external-retention operation, not to claim the prior retention already occurred. A count-floor mismatch is an explicit adverse flag, never coerced into success.

### Input schema

All `original` file refs are exact `{"path":"/absolute/normalized/file", "sha256":"64lowercasehex"}`; true bytes are SHA-checked on read and rechecked at completion. No symlink or source/copy alias is trusted. `null` has the precise absence semantics described below.

```json
{
  "schema": "ces.ec397.original_two_channel_publication_bundle.v1",
  "claimed_directory_lineage_id": "LineageIdentifier",
  "parent_ec396_public_integrity_bundle_original": {
    "path": "/abs/true-ec396-bundle.json", "sha256": "64lowercasehex"
  },
  "outside_observer_roster_original": {
    "path": "/abs/two-channel-roster.json", "sha256": "64lowercasehex"
  },
  "epochs": [
    {
      "epoch_index": 0,
      "dispatch": {"signed_original": null, "rfc3161_token_original": null},
      "channels": [
        {"channel_id":"ChannelA", "signed_receipt_original":null,
         "rfc3161_token_original":null, "copied_dispatch_original":null,
         "copied_public_log_head_original":null},
        {"channel_id":"ChannelB", "signed_receipt_original":null,
         "rfc3161_token_original":null, "copied_dispatch_original":null,
         "copied_public_log_head_original":null}
      ],
      "conflicting_heads": []
    }
  ]
}
```

The example contains **intentionally absent** evidence: it can only generate an unresolved/zero-credit observation. Every epoch from 0 through `n-1` must appear contiguously. The external roster schema `ces.ec397.two_outside_publication_observers.v1` contains exactly `schema`, `claimed_directory_lineage_id`, `channels` (two ordered roles). Each channel role contains exactly `role_id`, `site_id`, `channel_id`, `public_hex`, `public_key_original`; exact 32-byte Ed25519 original must equal `public_hex`. Two new independent role/site/key identities cannot reuse any EC393/394/395/396 known identity/key. Channel order in the roster corresponds to the external channel-A/B public-key pins; channel evidence order in epochs may differ, but IDs must match exactly, without duplicates.

### Original dispatch: current actual EC396 log signer

Signed original schema `ces.ec397.original_signed_publication_dispatch.v1`, with exact `{"schema", "claim", "signature_ed25519"}`. Its claim schema is `ces.ec397.signed_publication_dispatch_claim.v1` and signature message is canonical JSON bytes prefixed by this domain **including its final NUL**:

`CES/EC397/PublicHeadDispatch/v1\0`

Exact claim fields:

- `schema`, `directory_lineage_id`, `parent_ec396_bundle_sha256`, `parent_ec396_verified_inventory_sha256`, `epoch_index`, `dispatch_sequence` (= epoch+1), `log_signer_id` (the actual unchanged EC396 signer);
- `public_log_signed_head_original_sha256`, `public_log_merkle_size`, `public_log_merkle_root_sha256` (from **actual EC396 signed Head and its real signature**, reopened now, never supplied by caller as an arbitrary substitute);
- `previous_dispatch_original_sha256` (SHA of preceding epoch's exact signed dispatch **bytes**, epoch zero = 64 zeroes), `claimed_dispatched_utc` (canonical UTC).

The signed original and genuine timestamp must follow the true EC396 Head's validated original-token time, be no earlier than declared dispatch, and be no later than the trusted furnished dispute cutoff and evaluation. A missing dispatch must have null timestamp and destroys subsequent continuous dispatch credit. A signed bad predecessor is a source-binding denial; a gap in genuine chronology is unresolved, never restored.

### Two separate original witness receipts and byte-for-byte copies

Signed original schema `ces.ec397.original_signed_channel_observation.v1`, claim schema `ces.ec397.signed_channel_observation_claim.v1`, Ed25519 domain `CES/EC397/IndependentChannelObserved/v1\0` (final NUL included). Exact claim fields:

- `schema`, `directory_lineage_id`, `parent_ec396_bundle_sha256`, `parent_ec396_verified_inventory_sha256`, `epoch_index`;
- `channel_id`, `observer_id`, `observer_site_id` (**all from independent pinned roster**);
- `public_log_head_original_sha256`, `public_log_merkle_size`, `public_log_merkle_root_sha256` (true Head);
- `dispatch_signed_original_sha256` (true current publisher signed original);
- `previous_channel_receipt_original_sha256` (SHA of **that same observer's** genuine previous-epoch signed receipt, genesis = zeroes);
- `recovered_original_copies_inventory_sha256` and `claimed_observed_utc`.

Each channel evidence supplies an original signed receipt, its own genuine RFC3161 DER timestamp original, and exactly two **separate** source-to-copy byte readback paths: `copied_dispatch_original`, `copied_public_log_head_original`. The signed canonical SHA inventory of these two copies is an array, **in this order**, with exact objects:

```json
[
  {"kind":"dispatch", "original_sha256":"source-signature-sha", "original_copy_path":"/abs/siteA/dispatch-copy", "copy_sha256":"source-signature-sha"},
  {"kind":"public_head", "original_sha256":"signed-head-source-sha", "original_copy_path":"/abs/siteA/head-copy", "copy_sha256":"signed-head-source-sha"}
]
```

The example SHA values above are placeholders, not valid digests. The verifier recomputes the canonical SHA itself, reopens true source and every copy as actual bytes, disallows aliases against any original across **all** epochs and either channel, and confirms full byte equality. Receipts must be signed using the **respective new observer's raw Ed25519 key** and original-channel identity; claimed observed UTC must be after verified dispatch timestamp, and genuine DER token time must be after the claim and before cutoff. A missing receipt must have null token and both copies null; it yields zero credit. No missing or unbounded prior signed receipt may be “repaired” in subsequent epochs.

### Signed conflicting log Head originals

`conflicting_heads` is a 0..2 length array of exactly `{"signed_head_original":ref, "rfc3161_token_original":ref|null}`. Each original is a **real EC396 signed log Head** verified with the same actual parent log signer's key and domain, with every parent/evidence signer/epoch/sequence/predecessor binding field identical to the genuine current Head. It must differ in the signed Merkle root or tree size (only published timestamp text may additionally differ). The same original SHA cannot be counted twice under two filenames. A cryptographically authentic fork is preserved in `observed_genuine_signed_forks`, causes **zero channel credit for that and future epochs**, and sets adverse status; a provided legitimate RFC3161 token may also establish bounded token chronology. An untrusted alternate signature is rejected, not silently treated as either fork or agreement. No furnished set proves every possible unseen global fork was found.

### Count credits, chronology and output

Per epoch, `verified_signed_channel_deliveries` is 0..2; `verified_two_channel_observation_pair` is 0..1; `authentic_signed_conflicting_log_heads` is 0..2. Delivery credit requires: true EC396 parent log inclusion set credited, parent locally coherent, actual parent's genuine signed/retained Head, genuine signed publisher dispatch, both channel-specific genuine signatures if a pair is requested, exact original byte copies, per signer original-SHA predecessor and monotone bounded RFC3161 time, plus no known signed Head fork now or earlier. A genuine fork never receives count credit as a successful publication. A bounded **receipt is not evidence of an independent public portal, preexisting publication, independent corporate operator or absence of unobserved forks**.

Derive returns `unsigned_two_channel_publication_inventory`, its SHA, reviews, signed-fork SHA records and explicit adverse flags. Audit returns the same authenticated SHA, counters, flags, but **not** the unsigned inventory, to force separate expected-retained inventory SHA. Parent full audit and final byte readback run during both operations. All legally evaluable results remain `exit=2/*_unresolved` even when bounded local flags happen to be false; the final three real-world-not-proven flags are invariably true.

### Final unrun acceptance obligations

Full unmocked real EC396→EC395→EC394→EC393→EC392→both EC391 (and prior EC390→EC317/318) DER/X509/CRL history; physically and legally independent two-channel administrators; pre-dispute **third-party** maintained publication logs and historic true distribution, qualified TSA and independently justified cutoff, full external signed equivocation discovery and global revocation/OCSP completeness, government/legal registry accreditation, real independently attested manufacturer WORM/retention and cold retrieval, PowerShell 7 original 15 Smoke, Windows/macOS/Git/CI/Provider E63–E66, performance and final user acceptance are all **NOT_RUN / NOT_PROVEN**. EC249 INCOMPLETE, EC250 BLOCKED, B001 OPEN, Quality=false and native PowerShell V4.60/R150 remain unchanged.
