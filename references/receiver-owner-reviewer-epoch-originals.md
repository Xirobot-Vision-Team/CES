# EC374 receiver-held EC357 source-review + EC358 owner/reviewer originals

Historical record names below are archival references; those files are absent
from this source tree. See [cleanup scope](../docs/CLEANUP.md).

**Frozen for EC374 only — CES V6.84 / R374.** This specification describes one new offline read-only authentication slice on top of EC373. A locally consistent subset always returns **exit 2 unresolved**, not a completed CES / official institution / externally trusted timestamp / full historic old-parent determination. Native PowerShell remains V4.60 / R150.

## New functional evidence and trust boundary

Every **audit and derive** performs `historical_inclusion.inclusion_archive.audit(**parent_inputs)` on the live installed code. This already replays the real EC372→EC371→EC370→EC369 receiver-only originals. It cannot be replaced by a caller-supplied `parent_pass` or cached result. The new independently SHA-pinned bundle contains receiver-side original references only; it cryptographically authenticates **actual, unchanged** EC357 source-review and EC358 owner + reviewer signature domains:

- EC357 `SOURCE_DOMAIN = b'CES/EC357/ImportedRootCustodyReview/v1\x00'` on the complete original signed `ces.ec357.source_signed_root_and_custody_inventory.v1` record, verified with its **original 32-byte source reviewer public key**. The signed `parent_ec356_canonical_result_sha256` and `ec356_custody_bundle_original_sha256` remain historical signed *claims*, not reproduced parent results.
- EC358 `DOMAINS['owner'|'previous'|'current']`, unchanged, on the complete original `ces.ec358.signed_reviewer_epoch_event.v1` record *without any of the three signature fields*. All mandatory owner and predecessor/current reviewer Ed25519 signatures must actually verify. Issue = epoch 0 / null predecessor / no previous reviewer; rotate = genuine previous+new reviewer; revoke = genuine previous reviewer / no current reviewer. The owner signs each event as well.
- EC358 original `parent_source_review_original_sha256` must equal the **SHA of the EC357 signature original actually reopened**. Its signed `parent_ec357_canonical_result_sha256` must equal the epoch's separately retained old result SHA **as a claim only**.
- The selected EC358 event SHA must equal the `parent_owner_head_event_original_sha256` inside the **actual EC359 issuer-signed selected record**, independently validated in live EC373 and reopened by EC374. Owner public key SHA and owner claimed ID must also equal the original EC373 owner source and issuer-signed record. The old `parent_ec358_canonical_result_sha256` contained in EC359 is **not** recreated by this linkage.
- The source review's real signed root-revoked/rotated states, true EC358 fork or revoke, non-terminal selected head, reviewer key mismatch, valid-but-stale/future signature timestamps, signed conflicting historical parent claims, or caller-retained SHA/head/epoch floors are **adverse**. Older genuinely observed revocation and inherited EC373 disputes never become clean through a newer signature. Locally matching signatures alone are not evidence of absence of undisclosed forks.

The verifier reopens real EC371 historical archive/custodian manifests, EC372 authority bundle, EC373 inclusion bundle and the EC359 selected issuer record to retain the prior SHA and source boundaries. Old EC362 `copies` paths, competing signed source-copy labels and old sender-origin path labels are **forbidden to open**. All new originals have exact-field/schema/size/whole-byte SHA checks, fixed signer-role segregation (including old institution/root/witness/issuer/custodian/directory/current sender-receiver-publisher roles), no symlinks, late SHA re-read and same-inode alias rejection. A string `path` in historical original JSON is a label, never an invitation to load its contents.

## Exact bundle wire

`historical_owner_epoch_bundle_file` is an absolute normalized receiver-side path; `expected_historical_owner_epoch_bundle_sha256` is its independently retained lower-case SHA-256 (not derived from its own JSON). The complete canonical JSON document must have these **exact** keys:

```json
{
  "schema": "ces.ec374.receiver_historical_owner_reviewer_originals.v1",
  "parent_ec373_canonical_result_sha256": "<sha256 of actual current EC373 audit JSON canonical bytes>",
  "ec373_historical_inclusion_bundle_original_sha256": "<independently pinned EC373 original bundle sha256>",
  "claimed_directory_lineage_id": "<same old directory claim as EC371..EC373>",
  "epochs": [
    {
      "epoch_index": 0,
      "signed_parent_ec357_canonical_result_sha256": "<old signed EC357 result SHA claim, not recreated>",
      "source_a": { "...": "source structure described below" },
      "source_b": { "...": "same structure" }
    }
  ]
}
```

`epochs` is a complete positional 1–3-epoch list matching the old verified EC371/EC372/EC373 archive. Both source slots are required in every epoch; `epoch_index` starts at 0 and must be contiguous. **Each source has exactly**:

| Field | Meaning |
| --- | --- |
| `owner_public_key_original` | Exact `{path,sha256}` **matching EC373's already bound owner key reference**, 32 bytes |
| `claimed_owner_id`, `claimed_source_id` | Strict signed owner/source identifier claims; the first matches EC373 + genuine EC359 issuer distribution, the second matches EC357 + EC358 signatures |
| `source_review_public_key_original` | `{path,sha256}` for genuine EC357 source-review signing public key, distinct from old issuer/root/custodian/owner and other source keys |
| `source_review_signed_original` | `{path,sha256}` for full genuine EC357 signature original (up to 48 KiB) |
| `signed_parent_ec356_canonical_result_sha256` | Exactly the literal SHA claim in genuine EC357 source-review original, **not** proof of EC356 replay |
| `signed_ec356_custody_bundle_original_sha256` | Exactly the historical signed EC357 EC356-bundle SHA claim |
| `reviewer_epoch_events` | 1–8 complete original EC358 event entries as described below, including adverse original branches |
| `selected_owner_epoch_head_sha256` | Exact original SHA of the authenticated selected EC358 head; must be the genuine EC359 selected issuer's signed owner-head SHA |

Each `reviewer_epoch_events[]` row has exactly `event_original`, `previous_reviewer_public_key_original`, and `current_reviewer_public_key_original`. Every non-null value is a `{ "path": "<absolute normalized receiver-held original>", "sha256": "<lower-case hex>" }` reference. For an `issue`, the previous public key must be `null`; for a `revoke`, the current public key must be `null`; for a `rotate`, both keys are non-null, distinct, 32-byte SHA-pinned originals. Signatures are verified against the original event's `signature_owner_ed25519_hex`, `signature_previous_reviewer_ed25519_hex` and `signature_current_reviewer_ed25519_hex` values, and the signed predecessor/epoch/keys must link exactly. The same signer SHA must not be presented under conflicting public-key *reference paths within one historical source epoch*.

## Independent retained pins, CLI and outcomes

All previous EC373 **audit** inputs are mandatory, including `expected_retained_historical_inclusion_inventory_sha256`. EC374 additionally takes:

| Argument | Bounds / semantics |
| --- | --- |
| `--historical-owner-epoch-bundle-file` and `--expected-historical-owner-epoch-bundle-sha256` | New receiver-side bundle original and independently supplied digest |
| `--historical-owner-a-head-sha256`, `--historical-owner-b-head-sha256` | Repeat **exactly once per historical epoch**; separately retained selected EC358 original SHA for each role |
| `--minimum-historical-owner-a-epoch`, `--minimum-historical-owner-b-epoch` | Repeat once per epoch; 0–7 inclusive, not inferred from the signed bundle |
| `--historical-reviewer-a-key-sha256`, `--historical-reviewer-b-key-sha256` | Repeat once per epoch; outside-retained original SHA of EC357 source-review signer, which must match the currently selected EC358 reviewer signer to be locally coherent |
| `--expected-retained-historical-owner-inventory-sha256` | **Audit only**; independently retained, canonical SHA of a prior receiver-verified unsigned inventory |

Standalone commands (the same long required inherited parameters are omitted here, but not optional to invoke):

```bash
python -I -B scripts/ces_cas_historical_owner_archive.py derive-historical-owner-inventory [all required EC373 audit arguments] [new EC374 arguments except audit-only inventory SHA]
python -I -B scripts/ces_cas_historical_owner_archive.py audit-historical-owner-archive [all required EC373 audit arguments] [all new EC374 arguments]
python -I -B scripts/ces_next.py audit-historical-owner-archive DeliveryAudit AuditHistoricalOwnerArchive [all required EC373 audit arguments] [all new EC374 arguments]
```

`derive` returns the full **unsigned** `unsigned_verified_historical_owner_inventory` and `receiver_verified_historical_owner_inventory_sha256` for **independent outside retention**. The hash returned by the same derive is not automatically independent. `audit` compares the caller's *previously retained* outside digest, with mismatch remaining visibly unresolved instead of being automatically overwritten. Each lawful outcome is `exit_code=2`, and the last outcome is partial recovery, not global acceptance. Explicit integrity/shape/IO denials exit 3/4/5. The fixed unified route validates exact flags, counts, row schemas, external-pin implications, statuses and child process exit code before relaying JSON; the child is a non-symlink `python -I -B` path.

## Precisely excluded evidence / deferred completion

- Old EC356→EC337 historic inputs, old EC357/EC358 canonical result *recomputation*, EC359/EC360 original full canonical result regeneration, signed EC365 global completeness, old EC362 four source copy-role bytes, real institution ownership and source-custodian legal equivalence, physical custody, trusted event UTC, hidden fork absence, globally complete revocations and true latest heads remain **not proven**. The full parent historic fixture in EC374 tests deliberately inherits MOCKED EC366→EC337, even though all newly signed EC357/EC358 and current EC373→EC369 paths are genuinely verified.
- Native PowerShell CLI still V4.60 / R150; EC249 incomplete, EC250 blocked, B001 OPEN, Quality=false, final acceptance NOT_STARTED. Native PS7/15 Smoke, Windows/macOS/Git/CI/Provider E63–E66, EC366 12 heavy true-parent cases, EC356 case24, EC317/318 deep mock replacement, previous broad regressions and real CAS/WORM/Provider acceptance remain for final user-assisted verification.

[EC374 implementation](../construction/historical_owner/owner_archive.py) · [EC374 focused tests](../construction/historical_owner/test_owner_archive.py) · `EC374 scope` · `EC374 local observations`.
