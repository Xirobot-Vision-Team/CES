# EC375 exact receiver-held EC356 signature + EC357 review-original protocol

**Version:** V6.85 / R375 / EC-375. Exactly one new construction EC. Frozen read-only original-archive schema: `ces.ec375.receiver_historic_ec356_custody_original_archive.v1`. All lawful results **exit 2 unresolved**; real historic EC355→EC337 canonical results and externally authenticated custody remain unproven. Original PowerShell V4.60/R150 is not changed.

## Evidence hierarchy and which bytes are authoritative

- **Current verified parent**: every call replays real production `ec374_historical_owner.owner_archive.audit` using the entire exact old argument set. Production EC374 itself replays actual EC373→EC372→EC371→EC370→EC369 detached receiver path; it verifies unchanged domain EC357 source-signed reviews and EC358 reviewer/owner originals. Historic old EC366→EC337 ancestors are **not** reconstructed by this new layer.
- **Old EC356 manifest**, the *actual* historical `ces.ec356.pinned_two_channel_custody_bundle.v1` original: obtained **only** from the new caller-retained receiver-side file plus whole-file SHA, **not** its contents' signed-in-advance `path` strings. It is UNSIGNED, so its exact SHA is tied both to independent outside retention and the genuine old EC357 source-signed reviews' `ec356_custody_bundle_original_sha256`. Its 2 `channels` are fully parsed for their old SHA claims, slot/institution/channel ID and reference inventory. Its embedded historic paths are **labels**, never fetch URLs or filesystem read permissions.
- **Genuine EC356 records**: reopen true SHA-pinned 32-byte root and channel Ed25519 public keys and original root-reference signed with unchanged `ec356.ROOT_DOMAIN`, root-signed channel authorization under unchanged `ec356.AUTH_DOMAIN`, and every channel-signed ACK under unchanged `ec356.ACK_DOMAIN`. Verify exact fields, sizes, SHA, raw Ed25519 signatures, claimed ID/site, validity interval, role separation and signature/key binding. Signatures alone do not prove their real-world institution.
- **Receiver-held original custody bytes**: for each `custodied_originals` ACK, reopen actual copied checkpoint and witness originals and check the exact SHA and byte count signed in ACK, plus SHA in unchanged old EC356 manifest. SHA-only and unavailable signed ACKs cannot smuggle a returned copy and remain explicitly incomplete.
- **Genuine EC357 source-signed reviews**: use already verified EC374 `source_review_signed_original` and key; check its real original EC356 manifest SHA and old claimed parent result SHA. Compare **all** signed `root_records` and `inventory_records` in **both** source-signed reviews against the two actual recovered custody channels, including records about the *opposite* slot and contradictory source testimony. Preserve signed revocations/rotations, site/byte/availability conflicts and cross-epoch disagreements; do not choose a convenient source.

## Canonical exact receiver archive JSON

`--historical-custody-archive-bundle-file` must be an absolute normalized receiver-only regular file. `--expected-historical-custody-archive-bundle-sha256` must be its independently retained whole-file SHA-256. Parse its UTF-8 strict JSON with **no additional keys** and at most 100,000 bytes:

```json
{
  "schema": "ces.ec375.receiver_historic_ec356_custody_original_archive.v1",
  "parent_ec374_canonical_result_sha256": "<SHA256 of canonical JSON from the actual live EC374 audit output>",
  "ec374_historical_owner_epoch_bundle_original_sha256": "<retained original EC374 owner archive SHA256>",
  "claimed_directory_lineage_id": "<same claimed lineage as EC371/EC374>",
  "epochs": [
    {
      "epoch_index": 0,
      "ec356_custody_bundle_original": {
        "path": "/receiver/historical/epoch0/unchanged_old_ec356_bundle.json",
        "sha256": "<independently saved whole-file SHA256>"
      },
      "source_a": {
        "root_public_key_original": {"path": "/receiver/historical/epoch0/a/root.pub", "sha256": "<sha256>"},
        "root_reference_signed_original": {"path": "/receiver/historical/epoch0/a/signed_root.json", "sha256": "<sha256>"},
        "channel_public_key_original": {"path": "/receiver/historical/epoch0/a/channel.pub", "sha256": "<sha256>"},
        "channel_authorization_signed_original": {"path": "/receiver/historical/epoch0/a/signed_authorization.json", "sha256": "<sha256>"},
        "acknowledgements": [
          {
            "acknowledgement_signed_original": {"path": "/receiver/historical/epoch0/a/signed_ack0.json", "sha256": "<sha256>"},
            "checkpoint_original": {"path": "/receiver/historical/epoch0/a/checkpoint.bin", "sha256": "<sha256>"},
            "witness_original": {"path": "/receiver/historical/epoch0/a/witness.bin", "sha256": "<sha256>"}
          }
        ],
        "selected_ack_head_sha256": "<sha256 of one truly signed terminal ACK original>"
      },
      "source_b": "<object with exactly the same source_a keys, using B's own independent original paths and signed records>"
    }
  ]
}
```

**Example placeholders are NOT valid SHA values or ready-to-run documents.** In actual JSON `source_b` is an object of exactly the same shape as `source_a`, and all SHA fields are lower-case 64-character hex. Each epoch has exactly both source slots, epochs indexed 0..N-1 (N is the already-verified historic directory epoch count, 1–3). Every source MUST list every old manifest acknowledgement, 1–24 original ACKs, selected ACK SHA, and all four root/channel signing originals. ACK `checkpoint_original` and `witness_original` are **both `null`** iff the genuine signed ACK status is `sha_claim_only`/`unavailable_claim`; otherwise both must be independent receiver-owned SHA-pinned actual originals. Old EC356 manifest may list physically absent sender or custodian paths; do **not** copy those into receiver JSON. The old manifest's **file hashes** must exactly match the receiver copies, not its obsolete paths. SHA inventory is not a source of independent official authority.

## Additional command-line contract

All **EC374** standalone long options are still mandatory with their original exact values; new options are **additive**:

| Flag | Count | Semantics |
| --- | ---: | --- |
| `--historical-custody-archive-bundle-file` | one | Receiver-only old EC356 original archive JSON file, absolute normalized path |
| `--expected-historical-custody-archive-bundle-sha256` | one | Outside-retained SHA of that archive file |
| `--historical-custody-a-root-key-sha256` | one per epoch | Independent root-key SHA for source A |
| `--historical-custody-b-root-key-sha256` | one per epoch | Independent root-key SHA for source B |
| `--historical-custody-a-ack-head-sha256` | one per epoch | Independent source A signed selected ACK original head SHA |
| `--historical-custody-b-ack-head-sha256` | one per epoch | Independent source B signed selected ACK original head SHA |
| `--minimum-historical-custody-a-ack-count` | one per epoch | Integer 0–24; independently retained A original ACK count floor |
| `--minimum-historical-custody-b-ack-count` | one per epoch | Integer 0–24; independently retained B original ACK count floor |
| `--expected-retained-historical-custody-inventory-sha256` | audit only | Independently retained SHA of deterministic *unsigned* genuine-original SHA inventory; caller must store this **outside** generated bundle |

The long-option spellings derive literally from the names above. The original EC374 options include all EC369–EC373 parent arguments and inherited retained inventory hashes; this release **does not** elide those signed-original parent requirements.

Use `python scripts/ces_cas_historical_custody_archive.py derive-historical-custody-inventory --help` to enumerate all original EC374 flags and new options. Supply fully specified old parent options and new SHA streams to `derive-historical-custody-inventory`, retain `unsigned_verified_historical_custody_inventory` and `receiver_verified_historical_custody_inventory_sha256` independently, then supply the latter under `--expected-retained-historical-custody-inventory-sha256` to `audit-historical-custody-archive` (otherwise repeat previous flags unchanged). Unified fixed read-only route: `python scripts/ces_next.py audit-historical-custody-archive DeliveryAudit AuditHistoricalCustodyArchive --help`. The unified route launches a fixed isolated Python `-I -B` child; client never supplies an executable, shell or alternate route. No network or state writes.

## Results and negative guarantees

`derive` schema: `ces.ec375.unsigned_historic_custody_original_inventory_unresolved.v1`; `audit` schema: `ces.ec375.receiver_historic_ec356_signed_custody_ec357_bridge_unresolved.v1`. Each lawful result has `exit_code=2`, independently bound received archive SHA and actual parent EC374 canonical response SHA, deterministic canonical unsigned inventory SHA, counts of true root signatures, authorization signatures, true ACK signatures and actually reopened copy pairs, plus per-source epoch old-signed SHA and custody review summary. Audits include a **local** `local_pinned_historical_custody_signatures_and_source_inventory_consistent` boolean (not a completion/official trust gate). Conflict flags separately preserve external SHA drift, real ACK forks, incomplete copied originals or signed inventories, signed EC357 source root revoke/rotate/site discrepancy, cross-epoch conflict, stale signed-clock assertions and inherited prior disputes. Every lawful result remains **UNRESOLVED** even when locally consistent.

No reconstructed old EC356/EC357 canonical parent result is claimed. Signed EC356 references to EC355 receipts/requests/gossip/disclosure and EC357 references to an EC356 canonical result are genuine signer claims only, because the full old EC355 and older original inputs are absent. No signer proved independent legal/physical control; no historical origin path labels, signed EC362 copy labels, external provider, WORM, network, or native PowerShell are used. Denials have the strict schema `ces.ec375.receiver_historic_ec356_signed_custody_denial.v1`, codes 3 permission denied, 4 invalid input, 5 unavailable, with **no synthetic success**. The purpose is to make more of the previously unverified *old original* custody chain cryptographically inspectable, not to declare the historical chain complete.

## Observed test scope

`PYTHONPATH=construction python -m unittest ec375_historical_custody.test_custody_archive -q` — **39/39 passed** locally. Three isolated `python -I -B` child cases include two lawful real-production EC374→EC369 parent replays and one true receiver original-byte denial. The fixture intentionally **MOCKS historical EC366→EC337** (zero full old-parent original-inclusive tests). Deferred manual final validation: full historical EC355→EC337 originals and canonical results, broad inherited regression, old EC356 case24/EC366 heavy12, native PS7+15 smoke, Windows/macOS/Git/CI, E63–E66, official authorities/custody, trusted UTC/latest publication and real Provider/CAS/WORM. No user acceptance is asserted.

[New core](../construction/ec375_historical_custody/custody_archive.py) · [CLI](../scripts/ces_cas_historical_custody_archive.py) · [Fixed unified route](../scripts/ces_next.py) · [Test cases](../construction/ec375_historical_custody/test_custody_archive.py) · [EC-375 record](../EC-375.md).
