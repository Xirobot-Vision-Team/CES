# EC381 receiver protocol — authentic original EC349 directory, receipt ancestry and separately signed time witness

**Construction release V6.91 / R381 / EC381.** Receiver-only, offline, SHA-locked original-file inspection. EC381 extends the genuine EC380 signed RFC3161 / CRL / OCSP verifier with **root-authorized original EC349 channel signers** rather than trusting the original receipt's self-advertised signing public key. Every lawful outcome has **exit code 2, unresolved**; a locally verified signature does not establish independent institutions, qualified legal TSA, trusted UTC, durable physical custody or worldwide fork completeness.

## Pre-existing mandatory evidence

Supply every genuine EC369–EC380 source/audit input exactly as required by the [EC380 handoff](ec380-receiver-original-ec350-rfc3161-ec349-receipt-crl-ocsp.md). The implementation invokes **live production EC380.audit()** (transitively EC379→EC369) itself and SHA-binds this fresh result to the new original EC381 archive. It reopens the previously authenticated real EC380 archive (including its **unchanged exact EC349 receipt file and signed RFC3161 token**), genuine EC379 signed EC351 TSA source archive and EC377 old publication log labels. Historical EC353 sender path labels are excluded; they are not alternate receiver originals. An unsigned report claiming success cannot replace the live parent.

## New scalar inputs

| Internal name / CLI flag | Meaning |
| --- | --- |
| `historical_ec349_channel_archive_bundle_file` / `--historical-ec349-channel-archive-bundle-file` | Normalized absolute receiver path to the original EC381 channel archive JSON |
| `expected_historical_ec349_channel_archive_bundle_sha256` / `--expected-historical-ec349-channel-archive-bundle-sha256` | Caller-held whole raw-file digest, not one calculated by accepting the same file as authority |
| `expected_retained_historical_ec349_channel_inventory_sha256` / `--expected-retained-historical-ec349-channel-inventory-sha256` | **audit only**: independently retained canonical digest of the unsigned genuine-original inventory returned from `derive` |

Both `derive` and `audit` also require the following **repeated, epoch-ordered** original-inventory SHA and signed-count floors. Each array has exactly one value per historical epoch, 1–3 epochs total:

| Internal name / CLI flag | Constraint |
| --- | --- |
| `historical_ec349_authority_inventory_shas` / `--historical-ec349-authority-inventory-sha256` | 64-character SHA256 of the actual receiver-derived EC349 root/directory/receipt head/keeper-binding inventory for each epoch |
| `historical_ec349_witness_inventory_shas` / `--historical-ec349-witness-inventory-sha256` | 64-character SHA256 of the actual receiver-derived separately signed time-witness inventory for each epoch |
| `minimum_historical_ec349_signed_receipt_counts` / `--minimum-historical-ec349-signed-receipt-count` | Independent floor for whole-original signed receipts in the epoch, integer 0–12 |
| `minimum_historical_ec349_signed_witness_counts` / `--minimum-historical-ec349-signed-witness-count` | Independent floor for whole-original signed witnesses in the epoch, integer 0–12 |

Caller-supplied outside digests are **comparators**, not endorsements; the receiver recomputes inventories from original bytes, reports contradictions as adverse, and never generates an external independent pin. `derive` still requires per-epoch comparison digests and floors, but not the final retained aggregate inventory digest. Save the unsigned derived inventory SHA independently before invoking `audit`.

## Exact new receiver archive format

The SHA of the JSON file below must be supplied by an independently retained caller pin. All `*_original` descriptors are `{ "path": "/normalized/absolute/receiver/file", "sha256": "<whole-file SHA256>" }`, and the archive rejects additional keys.

```json
{
  "schema": "ces.ec381.receiver_old_ec349_channel_original_archive.v1",
  "parent_ec380_canonical_result_sha256": "<SHA256 of ACTUAL live EC380 audit JSON>",
  "ec380_historical_timestamp_archive_original_sha256": "<actual caller-pinned EC380 archive SHA256>",
  "claimed_directory_lineage_id": "<exact authenticated inherited lineage ID>",
  "epochs": [
    {
      "epoch_index": 0,
      "channels": [
        {
          "tsa_channel_id": "<one actual EC380 signed timestamp TSA channel>",
          "channel_root_public_key_original": {"path": "/receiver/originals/ec349-root-pub.bin", "sha256": "<SHA256>"},
          "signed_channel_directory_original": {"path": "/receiver/originals/ec349-directory.json", "sha256": "<SHA256>"},
          "signed_receipt_predecessor_originals": [],
          "signed_receipt_sibling_originals": [],
          "signed_time_witness_originals": [
            {"path": "/receiver/originals/ec349-signed-time-witness.json", "sha256": "<SHA256>"}
          ],
          "ec348_replay_inputs_original": null
        }
      ]
    }
  ]
}
```

A root public key original must contain exactly **32 raw Ed25519 public-key bytes**, not a PEM subject name or an unsigned string. The original root-signed directory uses the original EC349 `ces.ec349.ed25519_out_of_band_channel_directory.v1` and `CES/EC349/IndependentChannelDirectory/v1\0` signing domain. The receipt actor and time-witness actor are verified against the **actual root-authorized directory**, with distinct signer ID, organization claim and public key; the same signer key cannot masquerade as an EC351 attester or an inherited institution / witness / publication role. The receipt signing domain is the unchanged `CES/EC349/OutOfBandSHAReceipt/v1\0`; the separate time witness uses `CES/EC349/IndependentReceiptTimeWitness/v1\0`.

`tsa_channel_id` must exist in both the reopened genuine EC380 token and the genuine EC379 signed EC351 source; channels in an epoch are sorted by ID with at most two. **There is no new `ec349_receipt_original` field in the EC381 channel row:** its authoritative target is the **exact EC349 receipt pointer from the actual SHA-pinned EC380 timestamp archive**, preserving its original RFC3161 signed raw-byte imprint. EC381 repeats actual original RFC3161 signature/policy/root checks against its old EC379 source root while determining the cryptographically signed `genTime` used for the new separately signed witness comparison.

`predecessor_originals` presents **all** signed original ancestors of the EC380 target, in sequence 1 … target sequence–1. Each successor must sign the exact predecessor SHA **and file path**, have the appropriate claim kind, monotonically claimed time, non-revoked predecessor and unchanged signed keeper inventory. The receiver **never follows `previous_statement_file` as an implicit path**; a predecessor must already have its own externally pinned exact original descriptor. `sibling_originals` contains additional visible signed receipts sorted by `(sequence, SHA)`; every observed sibling's signed predecessor must also be included and valid. Two signed alternatives at any sequence or multiple visible heads are a fork/non-finality dispute, **not** a chosen best head. Whole-object SHA, signature and per-receipt nonce uniqueness are enforced. A receiver-provided archive cannot prove that *no unprovided hidden sibling* exists.

`time_witness_originals` is SHA-ordered by the signed receipt digest, with at most one independent actor-signed time witness for each presented signed receipt. A witness must bind the **exact target receipt SHA, directory SHA, receipt sequence and authorized time-actor signature**, and declare a bounded uncertainty. The target's separately signed observed clock is compared to its signed claimed receipt clock and actual EC380 **signed RFC3161 `TSTInfo.genTime`**. Missing, stale or mutually inconsistent claimed clocks are adverse. Witness signatures are cryptographic *local clock claims only*, never externally calibrated UTC or proof of timestamp-token physical delivery.

Receiver rows may set `ec348_replay_inputs_original` to `null` (the resulting EC348 keeper source link remains **explicitly incomplete**) or present the genuine canonical JSON containing **every exact old EC348 audit input** required by the unchanged original `ec349._replay`. The latter invokes the real EC348→EC347 predecessors; it can be accepted only when the old replay reports actual fully signed history and original keeper directory verification, its actual result/input canonical digests and keeper visible heads/receipt SHA inventories **exactly agree** with the root-signed directory and receipts, and its old signers do not collide with the new root/receipt/witness actors. Paths are receiver-local, normalized and bounded; old sender-origin labels and inherited scalar files are forbidden. There is **no mocked EC348 success option**.

## Epoch continuity, inventory and absence of false acceptance

The implementation joins each epoch against the *actual* EC380 timestamp count and reopened EC379 signed source roster, rejects channel/signature role collisions and requires stable root key, directory raw SHA, signer actor IDs, organizations, time key and receipt key across successive epochs. The current target receipt's **actual signed predecessor chain must include the previous epoch's exact target receipt original**, and its sequence must advance, not merely share the same integer. Separately signed witnessed local times must advance where both are present; a signed alternate branch or reused old receipt signals historical rollback. Independent floor/inventory disagreements and old parent disputes are retained in named flags.

**Command surface:**

```sh
python scripts/ces_cas_historical_ec349_channel_archive.py derive-historical-ec349-channel-inventory --help
python scripts/ces_cas_historical_ec349_channel_archive.py audit-historical-ec349-channel-archive --help
python scripts/ces_next.py audit-historical-ec349-channel-archive DeliveryAudit AuditHistoricalEC349ChannelArchive --help
```

Run the commands with **every** real inherited and new flag; `--help` by itself does not prove an actual archive is present. Unified audit accepts only the fixed Action/Mode and launches the installed child via `python -I -B` with exact argument/result contracts; it is not an arbitrary `--exec` or generic file reader. Exit **2** = genuine local receiver processing but still globally unresolved; **3** = permission denied/contradictory claimed original, **4** = invalid input/shape, **5** = unavailable real ancestor or file. No exit-zero acceptance or new network/CAS/WORM/private-signing path exists.

## Local evidence and deferred material

EC381's 36 **distinct focused test methods** were observed passing in one contiguous Python unittest call (**63 actual executions**, because 27 base true-signature cases also run through the mocked-engine subclass). Old EC349-format **Ed25519 signatures, original directory root authorization, signed predecessor and sibling branching and witnesses are genuinely generated in local temp directories**; the receiver-engine test's **production EC380 parent, EC379 signed source and old RFC3161 X509/CMS validation are deliberately mocked**, and are not an end-to-end actual historical provider test. Three focused receiver-engine cases exercise two successive epochs' original signed receipts and rollback detection with the mocked parent. No real original EC348 source with all old EC347→EC337 materials was furnished here. Legacy deep EC366→337 fixture, official signer independence, physical/offline keeper custody, calibrated UTC, global hidden-fork census, certified legal CA/TSA authority, native PS7/15 smoke, OS/Git/CI/provider checks, remote CAS/WORM, broad inherited regression and user final acceptance remain **NOT_PROVEN/NOT_RUN**.
