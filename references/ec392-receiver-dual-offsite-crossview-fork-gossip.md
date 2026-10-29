# EC392 receiver wire contract: independently signed double offsite views

**Offline receiver only.** EC392 accepts independently previously created signed originals and external SHA pins; it does **not** emit a new signed witness, create a timestamp, provision a trust root, prove legal operator identities, or publish evidence. Root and keeper material in this contract is *caller supplied*, not automatically trusted as prior external retention. These specimens are schema demonstrations, not operational credentials.

## Pre-requisites, isolation, and two actual EC391 audits

Supply **all** inherited EC390 and EC391 audit arguments exactly as in the EC391 reference, plus original second EC391 `bundle_file`/SHA, externally pinned secondary keeper roster SHA, secondary TSA trust-registry SHA and retained secondary unsigned inventory SHA. The two EC391 `audit()` calls run separately against the **same** historical parent pins with distinct prior-head/token inventory SHA lists and per-epoch count floors; neither call can be replaced by a supplied JSON claim. Parent-report status remains exit2 unresolved. The actual parent canonical result SHA must match across both.

Supply outside-pinned `expected_outside_retained_ec392_primary_observer_id` and `expected_outside_retained_ec392_secondary_observer_id` distinct IDs (1–96 characters, starting with a letter, `[A-Za-z][A-Za-z0-9_.:-]*`). The two prior EC391 original bundles MUST NOT be byte-identical or use the same pinned path. Keeper IDs, raw Ed25519 public key values, original source paths and TSA DER root SHA sets must be pairwise disjoint. This separation checks presented artifacts, not financial/legal independence of the underlying actors. In addition, neither new original source may reuse any authenticated parent original path.

## Crossview bundle original (JSON exact keys)

```json
{
  "schema": "ces.ec392.dual_offsite_crossview_checkpoint_bundle.v1",
  "claimed_directory_lineage_id": "Lineage388",
  "primary_observer_id": "ObserverNorth",
  "secondary_observer_id": "ObserverSouth",
  "primary_ec391_offsite_bundle_original": {"path": "/offsite-a/prior-bundle.json", "sha256": "<64 real lowercase hex>"},
  "secondary_ec391_offsite_bundle_original": {"path": "/offsite-b/prior-bundle.json", "sha256": "<64 real lowercase hex>"},
  "epochs": [
    {
      "epoch_index": 0,
      "channels": [
        {
          "tsa_channel_id": "<actual authenticated source channel ID>",
          "primary": {
            "signed_crossview_checkpoint_original": {"path": "/offsite-a/cross-checkpoint-0.json", "sha256": "<real SHA>"},
            "rfc3161_crossview_checkpoint_token_original": {"path": "/offsite-a/cross-checkpoint-0.tsr", "sha256": "<real SHA>"},
            "tsa_authority_id": "ActualPrimaryTSA",
            "alternate_signed_crossview_checkpoint_original": null
          },
          "secondary": {
            "signed_crossview_checkpoint_original": {"path": "/offsite-b/cross-checkpoint-0.json", "sha256": "<real SHA>"},
            "rfc3161_crossview_checkpoint_token_original": {"path": "/offsite-b/cross-checkpoint-0.tsr", "sha256": "<real SHA>"},
            "tsa_authority_id": "ActualSecondaryTSA",
            "alternate_signed_crossview_checkpoint_original": null
          }
        }
      ]
    }
  ]
}
```

`<...>` strings MUST be replaced with actual values: the example cannot pass validation. The SHA of the full crossview bundle itself must be passed in both `--historical-ec339-crossview-bundle-file` and `--expected-historical-ec339-crossview-bundle-sha256`, pinned separately in advance. All `ref`s are exact objects with `path` and `sha256`, where path is a normalized absolute local file, SHA is a lowercase 64-char digest of original bytes. No parent original path reuse, no duplicates among crossview originals. Up to 3 epochs and 2 channels, and exactly the channel order produced by *both* EC391 receiver reports. All fields always present, with all 3 checkpoint-dependent fields set to null if there is no signed checkpoint. A signed checkpoint with no RFC3161 original uses null for timestamp and authority ID and **remains adverse/unresolved**.

Optional `alternate_signed_crossview_checkpoint_original` may reference a second, genuinely valid but contradictory signature from *the same keeper for the same epoch/channel/sequence*. Its **own original SHA** is preserved independently and counts as visible equivocation even if either claim contradicts the reopened peer. The alternate checkpoint is not claimed timestamp-authenticated merely because the first checkpoint has a token.

## Domain-separated original cross-checkpoint signature

Original `signed_crossview_checkpoint_original` is strict canonical JSON, exactly:

```json
{
  "schema": "ces.ec392.signed_crossview_observation_original.v1",
  "claim": {
    "schema": "ces.ec392.crossview_observation_claim.v1",
    "directory_lineage_id": "Lineage388",
    "observer_id": "ObserverNorth",
    "peer_observer_id": "ObserverSouth",
    "tsa_channel_id": "<actual source channel>",
    "epoch_index": 0,
    "checkpoint_sequence": 1,
    "offsite_keeper_id": "<actual signed EC391 prior-head keeper>",
    "own_prior_signed_head_original_sha256": "<SHA of actual reopened own signed EC391 prior Head original>",
    "observed_peer_prior_signed_head_original_sha256": "<SHA of actual reopened peer signed EC391 prior Head original>",
    "own_signed_source_snapshot_sha256": "<SHA of canonical JSON of reopened own EC389 signed source pairs>",
    "previous_signed_crossview_checkpoint_original_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "claimed_observed_utc": "2026-10-25T11:40:00Z"
  },
  "signature_ed25519": "<128 lowercase hex of actual Ed25519 signature>"
}
```

Signature message is:

```python
b'CES/EC392/DualOffsite/SignedCrossViewObservation/v1\0' + ec319_canonical_json(claim)
```

The exact `offsite_keeper_id` and raw Ed25519 original key must have been verified as the authentic signer of the corresponding EC391 prior Head; a newly forged observer key cannot be swapped in. `checkpoint_sequence == epoch_index+1`, previous SHA must link the **entire preceding original signed checkpoint SHA** on the same channel/observer (64 zeros at epoch 0). Identifiers, inherited lineage, channel, epoch, timestamps and SHA fields are strictly checked. A **valid signed** but conflicting observed peer/own Head SHA or source snapshot is retained as adverse evidence; bad signatures are rejected (not characterized as valid equivocation).

The RFC3161 token hashes the **raw signed checkpoint original bytes**, not the claim field, not a JSON copy and not another bundle. The same real DER CMS/ESS policy/OID, signer certificate/X.509/EKU, pinned original TSA root and furnished offline CRL verification used by EC391 applies independently to each timestamp. Checkpoint genTime must not precede the signed claimed observation time, its own or peer's reopened prior Head token's genTime, or its immediately preceding authenticated checkpoint on the same channel. A signed claim's `claimed_observed_utc` remains an *untrusted claim*. Supplied offline CRLs do not prove global OCSP or completeness of revoked keys. Verification never sends data to a TSA.

## Derived outside SHA inventories and bounded audits

Run the isolated inventory command first, providing all actual original inherited EC391 arguments plus **all new per-epoch outside SHA/floor arguments**. A derived inventory is explicitly UNSIGNED and may return mismatch flags if the initial per-epoch pins are not yet correctly retained; it exposes newly computed per-epoch values so an independent custodian can externally retain these values before a later audit. It is not prior custody evidence by itself.

```bash
python -I -B scripts/ces_cas_historical_ec339_crossview.py derive-historical-ec339-crossview-inventory --help
python -I -B scripts/ces_cas_historical_ec339_crossview.py audit-historical-ec339-crossview --help
python -I -B scripts/ces_next.py audit-historical-ec339-crossview DeliveryAudit AuditHistoricalEC339CrossView --help
```

EC392 audit-only additional scalar, not needed by derive:

```
--expected-retained-historical-ec339-crossview-inventory-sha256 <externally retained whole inventory SHA>
```

Nine new common scalar flags (all mandatory):

```
--historical-ec339-crossview-bundle-file <absolute original path>
--expected-historical-ec339-crossview-bundle-sha256 <SHA>
--secondary-ec391-prior-offsite-time-bundle-file <absolute original path>
--expected-secondary-ec391-prior-offsite-time-bundle-sha256 <SHA>
--expected-outside-retained-secondary-ec391-keeper-roster-sha256 <SHA>
--expected-outside-retained-secondary-ec391-tsa-registry-sha256 <SHA>
--expected-retained-secondary-ec391-prior-time-inventory-sha256 <SHA>
--expected-outside-retained-ec392-primary-observer-id <ID>
--expected-outside-retained-ec392-secondary-observer-id <different ID>
```

Six mandatory per-epoch repeat flag families; repeat **once per actual epoch** in order:

```
--secondary-ec391-prior-signed-head-inventory-sha256 <SHA>
--secondary-ec391-prior-rfc3161-token-inventory-sha256 <SHA>
--minimum-secondary-ec391-prior-timestamped-head-count <integer 0..2>
--historical-ec339-crossview-signed-checkpoint-inventory-sha256 <SHA>
--historical-ec339-crossview-rfc3161-token-inventory-sha256 <SHA>
--minimum-historical-ec339-crossview-timestamped-checkpoint-count <integer 0..4>
```

These supplement all EC391 primary/inherited flags; the CLI does not infer historical pins or fabricate example original data. The derived final `unsigned_crossview_inventory` includes original SHA references of each observer, each epoch/source snapshot, mutually observed signed checkpoint and timestamp SHA, signed conflicts with both original SHAs, and `receiver_verified_crossview_inventory_sha256` of its canonical serialization. The audit compares this digest with the independently retained expected SHA; mismatch sets a visible **unresolved** flag, rather than silently accepting newer evidence. A per-epoch SHA floor/count mismatch is also adverse.

## Errors, result status, deferred real acceptance

Valid but contradictory or incomplete views, token-order concerns or absent external legal proof: **exit 2 + `_unresolved`**. Invalid identity, original-path reuse, public-key/root reuse, signature, material tamper, malformed strict JSON or compromised TSA CMS chain: **3 permission_denied**, **4 invalid_input**, or **5 unavailable** as applicable. Both signed versions are preserved in output; there is no auto-healing, fork selection, chain rewriting, global census or qualified timestamp-issuance claim. No private key, network, WORM/CAS/CI, or native PowerShell path is written by this receiver.

Final external acceptance must use actual user-provided unmocked EC390→EC369 and deep EC317/318 originals, independent operator/TSA legal identity, site custody/UTC and revocation/hidden-fork coverage; local generated fixture tokens are **not** that acceptance.
