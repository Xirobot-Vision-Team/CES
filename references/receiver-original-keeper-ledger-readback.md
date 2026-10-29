# EC382 receiver protocol — old EC348 genuine keeper-signed custody originals, EC347 last readback, real EC349 proof join

**V6.92 / R382 / EC382**. No online calls; read-only and exactly one additional receiver layer on mandatory live EC381→EC369 authenticated parent, not an independent physical-custody claim. Each `original` is an **actual receiver-local, absolute, normalized** `{ "path": "/absolute/receiver-original", "sha256": "<64 lowercase hex>" }`; all bytes are SHA-locked independently before the operator runs the verifier. A SHA supplied by the same collector is a comparator; it does not prove an external retain authority. The true original predecessor EC348→EC337 package may be unavailable: do not fill it using generated data.

## Exact new receiver JSON file

```json
{
  "schema": "ces.ec382.receiver_historic_ec348_keeper_original_archive.v1",
  "parent_ec381_canonical_result_sha256": "<SHA256 of actual live EC381 canonical audit result>",
  "ec381_historical_channel_archive_original_sha256": "<whole SHA of actual EC381 receiver archive original>",
  "claimed_directory_lineage_id": "<authenticated inherited lineage ID>",
  "epochs": [
    {
      "epoch_index": 0,
      "channels": [
        {
          "tsa_channel_id": "<actual EC380/EC381 signed-anchored channel ID>",
          "ec348_full_replay_inputs_original": {"path": "/receiver/originals/old-ec348-all-inputs.json", "sha256": "<SHA256>"},
          "keeper_root_public_key_original": {"path": "/receiver/originals/old-ec348-root-raw32.bin", "sha256": "<SHA256>"},
          "keeper_signed_directory_original": {"path": "/receiver/originals/old-ec348-root-signed-directory.json", "sha256": "<SHA256>"},
          "keeper_signed_receipt_originals": [{"path": "/receiver/originals/old-keeper-receipt-1.json", "sha256": "<SHA256>"}],
          "keeper_signed_ledger_originals": [{"path": "/receiver/originals/old-keeper-ledger-1.json", "sha256": "<SHA256>"}],
          "ec347_latest_signed_challenge_original": {"path": "/receiver/originals/old-readback-challenge.json", "sha256": "<SHA256>"},
          "ec347_latest_signed_response_originals": [{"path": "/receiver/originals/old-readback-reply.json", "sha256": "<SHA256>"}],
          "retested_snapshot_originals": [{"path": "/receiver/originals/old-raw-copy-snapshot.bin", "sha256": "<SHA256>"}],
          "retested_ack_set_originals": [{"path": "/receiver/originals/old-raw-ackset.bin", "sha256": "<SHA256>"}]
        }
      ]
    }
  ]
}
```

The displayed per-type lists are **illustrative**, never an assertion that one receipt or response suffices. On real input, supply **every** exact original that is present in the actual old EC348 original replay inputs, in unchanged order. `keeper_signed_receipt_originals` must cover all original referenced keeper receipt files with exact pinned non-UNPINNED SHA values; `keeper_signed_ledger_originals` must cover all signed ledger originals. The latest EC347 signed responses list must contain **exactly** every signed reply for the final signed challenge round; snapshot/ACK lists must match the genuine old EC348 presented keeper row order. The 32-byte raw root must equal old EC348 source's `expected_directory_root_public_hex`, and original directory signature must verify under old EC348's unchanged `DIRECTORY_SCHEMA` and `CES/EC348/...` Ed25519 signing domain. Historic JSON can be noncanonical on disk: the verifier preserves original-byte SHA and validates the original legacy canonical **claim** signature instead.

**Missing original rule:** an absent authentic `ec348_full_replay_inputs_original` is represented by `null`. Exactly in that case set `keeper_root_public_key_original`, `keeper_signed_directory_original`, `ec347_latest_signed_challenge_original` to `null` and all five repeated original lists to `[]`. This becomes a named unresolved **source-missing** result; partial guessed originals are not accepted as signed proof. Neither `EC381` nor `EC382` is authorized to invent old custodian keys, copy bytes or sender history.

**Historical chain:** epoch indices start at 0, count 1–3, and channel IDs are exactly the already authenticated, sorted EC381 channel roster within real EC380 timestamp originals (at most two). The receiver archive pins both actual EC381 result and EC381 archive original SHA; its lineage must match the inherited signed lineage. Signed EC349 receipt already present in the EC380 token archive is always the keeper target, never an arbitrary later receipt. Original old source must cryptographically replay via unmodified EC349/EC348/EC347, and EC349's signed keeper directory/receipt claims must agree with actual source, result and keeper head original SHA inventory. EC382 separately reconstructs visible old EC348 receipt predecessor/path SHA and detects signing-role collisions, fork, revocation, expiry and cross-epoch rollback. Both EC349 channels in one epoch must report identical old keeper source, directory, originals, and EC347 challenge.

## Command-line flags newly added in this EC

Inherited EC369→EC381 original receiver flags and outside SHA/count floors are *all mandatory*.

| Internal key / flag | Contract |
| --- | --- |
| `historical_ec348_keeper_archive_bundle_file` / `--historical-ec348-keeper-archive-bundle-file` | SHA-pinned, normalized receiver-local archive file (JSON above) |
| `expected_historical_ec348_keeper_archive_bundle_sha256` / `--expected-historical-ec348-keeper-archive-bundle-sha256` | Outside-supplied SHA of whole original EC382 archive |
| `expected_retained_historical_ec348_keeper_inventory_sha256` / `--expected-retained-historical-ec348-keeper-inventory-sha256` | **audit only**: independent caller-retained SHA of complete derived unsigned inventory |
| `historical_ec348_keeper_original_inventory_shas` / `--historical-ec348-keeper-original-inventory-sha256` | Repeated once per epoch; outside SHA for actual verified keeper original inventory |
| `historical_ec347_readback_join_inventory_shas` / `--historical-ec347-readback-join-inventory-sha256` | Repeated once per epoch; outside SHA for actual final signed EC347/readback ledger inventory |
| `minimum_historical_ec348_signed_keeper_receipt_counts` / `--minimum-historical-ec348-signed-keeper-receipt-count` | Repeated per epoch, integer 0–24 original keeper receipts |
| `minimum_historical_ec348_retested_ledger_counts` / `--minimum-historical-ec348-retested-ledger-count` | Repeated per epoch, integer 0–8 reopened keeper ledger/copy byte retests |

Compute outside per-epoch SHA values over `canonical.canonical(inventory)` from the *actual verifier-derived* `unsigned_verified_historical_ec348_keeper_inventory`, retain them separately, and pass into audit. Note that derive **also requires** outside per-epoch inventory SHA/count floors even though it does not require the aggregate audit-only pin. An all-zero SHA pin is invalid; callers must distinguish an independent previously retained digest from one just calculated for testing. Inventory output remains unsigned; it cannot replace original signature or physical custody evidence.

```sh
python scripts/ces_cas_historical_keeper_archive.py derive-historical-ec348-keeper-inventory --help
python scripts/ces_cas_historical_keeper_archive.py audit-historical-ec348-keeper-archive --help
python scripts/ces_next.py audit-historical-ec348-keeper-archive DeliveryAudit AuditHistoricalEC348KeeperArchive --help
```

The fixed unified route accepts only `DeliveryAudit / AuditHistoricalEC348KeeperArchive`, launches exactly the bundled child with isolated `python -I -B`, denies unknown flags and validates resulting status/shape. All **lawful** results must exit **2** with a specific unresolved reason; invalid data yields **4**, attempted forbidden substitution **3**, and absent mandatory live parent or original file **5**. This never yields PASS, final acceptance or creation of a new external authority.

## Local test boundary, external originals to supply at final verification

The locally observed **30/30 EC382 suite** uses truly generated original-format Ed25519 EC348 signed keeper receipts and genuine newly generated EC349 signatures for the key happy/bad-path bindings; the **older EC347→EC337 ancestor in the imported EC348 test fixture is mocked**. The new full-depth EC381→EC369 isolated receiver operation with a genuine third-party production archive is **NOT_RUN**. Required final outside assistance: independent authentic issuer/keeper key provenance, old EC348 input originals and all old EC347→EC337 precursor bytes, true external originally retained SHA/count pins, old RFC3161/CRL/OCSP rooted source, signed cross-epoch history, physical site WORM/CAS and provider identity, qualified UTC/legal authorization, cross-provider/OS/PowerShell regression and final sign-off. Old `EC249 INCOMPLETE / EC250 BLOCKED / B001 OPEN / Quality=false / final NOT_STARTED` are unchanged.
