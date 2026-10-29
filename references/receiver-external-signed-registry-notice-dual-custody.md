# EC398 — external signed registry notice, genuine parent revocation cross-check, dual-custodian triple-original recovery

**Wire:** `ces.ec398.*.v1` | **Release:** `V7.08 / R398 / EC398` | **Model:** bounded read-only original verifier, not an official legal accreditation decision.

## What is actually proven locally

Every invocation first calls the **unchanged real EC397 `audit()`** (it calls EC396→EC395→EC394→EC393→EC392→two EC391 and older engines). It validates the complete EC397 report shape/status/counts and independently retained root/unsigned inventory SHA before reading EC398. It re-opens the original EC397 witness bundle, EC396 signed four-role registry, EC395 independent credential roster, all three protected rosters and the trusted parent data. The EC396 registry signer Ed25519 signature is **reverified** on the actual original, not replaced by a client-submitted status report.

For each bounded historical epoch (1–3):

1. A new roster contains **three different raw Ed25519 public keys, role IDs, and site IDs** (registrar + two custodians), distinct from every known EC393–EC397 ancestor. All public key bytes are read back from original files, bound to external independent key pins, and key roles are not silently promoted into legal authorization.
2. The external registrar signs an original *notice claim* (`NOTICE_DOMAIN`) binding the actual parent EC397 bundle SHA, actual parent whole-inventory SHA, **actual EC396 signed registry original SHA**, a SHA of an opaque historical gazette/source original, exactly four genuine EC395 `role_id`/`public_hex` identities, `active|suspended|revoked` + effective UTC, original predecessor SHA, 1-based sequence, epoch and claimed publication UTC. A genuine supplied RFC3161 token is verified with the **unchanged EC394/EC391 CMS/X509/pinned TSA/CRL** code. Notice time follows the authenticated parent registry timestamp and claimed effective times and precedes the externally claimed cutoff. Parent-versus-new signed status or effective-time conflicts, revocation/suspension, retrograde effective time, and revoked→active rollback remain adverse; they never grant four-role active credit.
3. Each **different custodian** signs a separate original (`CUSTODY_DOMAIN`) for *its own real EC397 channel*. The claim identifies the actual EC397 signed observer receipt, registrar's current signed notice, source gazette SHA, 3 exact source→copy SHA/path pairs, the previous custodian's original-byte SHA, issuer role/site/channel, epoch and claimed archive UTC. Three **actual byte-for-byte** copies are reopened per custodian: (a) opaque gazette original, (b) signed registrar notice, (c) true parent channel's signed observer receipt. Source/copy path alias, a shared cross-channel copy path, a copy with the wrong bytes or forged signature is denied. The timestamp follows both the registrar notice token and that parent channel's real observer receipt token; otherwise no credit.
4. Historic absence is represented by `null` signed originals with `null` matching tokens/copies, never by a fabricated signed record. Once the signer predecessor/timestamp chain loses continuity, later file appearances cannot restore prior-credit continuity. Valid signed contradictory states are **reported as adverse**, not erased or used to claim a correct government record.
5. Per epoch two separately retained SHA inventories and two bounded count floors (0–4 role corroborations and 0–2 custodian readbacks) are checked. Four first-original SHA pins (gazette, signed notice, two custodian receipts), an externally pinned three-role roster and the root bundle original SHA are mandatory. `derive` gives an **unsigned** preview and its canonical inventory SHA; **audit** requires the *separately retained SHA* of that same whole inventory, returns only its digest, and never signs or writes anything.

**Exit states:** valid offline evidence always has `exit_code=2`, one of the `ec398_*_unresolved` outcomes; rejected/invalid/unavailable originals are 3/4/5. The `bounded_local_external_notice_and_custody_consistency` Boolean is limited to the local source/signature/timestamp/copy/floor contract. The three final missing-real-world-proof flags remain **true**, and eleven overclaim fields remain **false**, even if locally consistent.

## Fixed commands

```bash
cd ces
python -I -B scripts/ces_cas_historical_external_notice.py derive-historical-ec339-external-notice-inventory --help
python -I -B scripts/ces_cas_historical_external_notice.py audit-historical-ec339-external-notice --help
python -I -B scripts/ces_next.py audit-historical-ec339-external-notice DeliveryAudit AuditHistoricalEC339ExternalNotice --help
```

All **EC397 audit scalars and repeat arguments** remain mandatory, notably `--expected-retained-historical-ec339-publication-witness-inventory-sha256`. Add the following scalar flags (hyphens in command line map to underscores in Python):

| New scalar flag (`--` + key with `_`→`-`) | Semantics |
| --- | --- |
| `historical_ec339_external_notice_bundle_file` | Normalized absolute path to original EC398 input bundle |
| `expected_historical_ec339_external_notice_bundle_sha256` | Separately sourced whole bundle SHA-256 |
| `expected_outside_retained_ec398_notice_roster_sha256` | Independently stored SHA of the 3-role roster original |
| `expected_outside_retained_ec398_registrar_public_hex` | Raw 32-byte registrar Ed25519 public key (64 lowercase hex) |
| `expected_outside_retained_ec398_custodian_a_public_hex` | First custodian raw public key; mirrors EC397 first roster channel |
| `expected_outside_retained_ec398_custodian_b_public_hex` | Second custodian raw public key; mirrors EC397 second channel |
| `expected_outside_retained_ec398_first_source_notice_sha256` | Independently held first epoch's **opaque source original** digest |
| `expected_outside_retained_ec398_first_signed_notice_sha256` | Independently held first signed registrar notice original digest |
| `expected_outside_retained_ec398_first_custodian_a_receipt_sha256` | Independently held first channel-A custodian signed-original digest |
| `expected_outside_retained_ec398_first_custodian_b_receipt_sha256` | Independently held first channel-B custodian signed-original digest |
| `expected_retained_historical_ec339_external_notice_inventory_sha256` | **Audit only:** trusted separately stored **whole unsigned derived inventory SHA** |

Add these **repeated once per inherited historic epoch**:

| Repeat | Limits / meaning |
| --- | --- |
| `--historical-ec339-external-notice-inventory-sha256` | External SHA of that epoch's parsed notice witness summary |
| `--historical-ec339-dual-notice-custody-inventory-sha256` | External SHA of that epoch's two actual custodian receipt summaries |
| `--minimum-historical-ec339-corroborated-active-notice-role-count` | Outside floor integer 0–4; only roles with matching signed parent status, no revocation and bounded time can count |
| `--minimum-historical-ec339-notice-custodian-readback-count` | Outside floor integer 0–2; each requires 3 actual identical source/copy files and true parent pair context |

Each `path/sha256` original is a `{ "path": "/absolute/normalized/record", "sha256": "64-lowercase-hex" }` reference. No symlinks, unbounded files, implicit search paths, ad hoc certificates, online recovery or original mutations. Unsigned derive results are **not** pre-dispute retention receipts; the external SHA retention must be independently established.

## Exact minimum original JSON shapes

Roster (`outside_notice_roster_original`) `schema` = `ces.ec398.external_registrar_and_two_custodians_roster.v1`; exact fields `schema`, `claimed_directory_lineage_id`, `registrar`, `custodians`. `registrar` has exact fields `role_id`, `site_id`, `public_hex`, `public_key_original`. `custodians` is an ordered two-element list of those fields **plus** `channel_id` equal respectively to the two actual EC397 channel IDs.

Root bundle:

```json
{
  "schema": "ces.ec398.original_external_notice_and_dual_custody_bundle.v1",
  "claimed_directory_lineage_id": "OriginalLineage",
  "parent_ec397_publication_bundle_original": {"path":"/abs/parent-ec397.json","sha256":"<64 hex>"},
  "outside_notice_roster_original": {"path":"/abs/roster.json","sha256":"<64 hex>"},
  "epochs": [
    {
      "epoch_index": 0,
      "source_notice_original": null,
      "notice": {"signed_original":null,"rfc3161_token_original":null},
      "custodians": [
        {"channel_id":"ChannelA","signed_receipt_original":null,"rfc3161_token_original":null,"copied_source_notice_original":null,"copied_signed_notice_original":null,"copied_parent_channel_receipt_original":null},
        {"channel_id":"ChannelB","signed_receipt_original":null,"rfc3161_token_original":null,"copied_source_notice_original":null,"copied_signed_notice_original":null,"copied_parent_channel_receipt_original":null}
      ]
    }
  ]
}
```

The `null` illustration is deliberately incomplete and can only yield unresolved zero credit. `epochs` must exactly match the inherited 1–3 parent epochs with indices `0...n-1`.

Registrar signed original has exact fields `schema`, `claim`, `signature_ed25519` and schema `ces.ec398.original_signed_registry_notice.v1`. `claim` exact fields:

`schema` (`ces.ec398.original_signed_registry_notice_claim.v1`), `directory_lineage_id`, `parent_ec397_bundle_sha256`, `parent_ec397_verified_inventory_sha256`, `parent_ec396_signed_registry_snapshot_sha256`, `epoch_index`, `notice_sequence` (=epoch+1), `registrar_id`, `source_notice_original_sha256`, `previous_signed_notice_original_sha256` (first `00..00`), `subjects` (exact **four** ordered `{role_id,public_hex,status,effective_utc}` real EC395 keys), `claimed_published_utc`.

Each custodian signed original has exact fields `schema`, `claim`, `signature_ed25519`, schema `ces.ec398.original_signed_notice_custody_receipt.v1`. `claim` exact fields:

`schema` (`ces.ec398.original_signed_notice_custody_claim.v1`), `directory_lineage_id`, `parent_ec397_bundle_sha256`, `parent_ec397_verified_inventory_sha256`, `epoch_index`, `channel_id`, `custodian_id`, `custodian_site_id`, `signed_notice_original_sha256`, `source_notice_original_sha256`, `parent_signed_channel_receipt_original_sha256`, `previous_custodian_receipt_original_sha256` (first zero digest), `three_original_copy_inventory_sha256`, `claimed_archived_utc`.

The `three_original_copy_inventory_sha256` digests an ordered list of exactly three maps in the order `source_notice`, `signed_notice`, `parent_receipt`:

```json
{
  "kind":"source_notice",
  "source_sha256":"<64 hex>",
  "copy_sha256":"<64 hex>",
  "copy_path":"/absolute/normalized/distinct-copy-path"
}
```

Signatures verify `Ed25519( domain_bytes + canonical_JSON(claim) )`, with domains `CES/EC398/ExternallyPinnedRegistryNotice/v1\\0` and `CES/EC398/IndependentNoticeOriginalCustody/v1\\0`, where `\\0` denotes a single trailing NUL byte. The canonical JSON function is the inherited `offline_transfer_registry.registry.canonical`. Recipients do not generate keys/signatures.

## Independent final-user validation still required

An opaque SHA-pinned “government gazette” file can be made by anybody. Verifying a **new externally pinned local registrar signature** on that file and comparing it to a different EC396 signed snapshot **does not verify a government/official publication signature, a legally authorized registrar, or the completeness of CRLs/OCSP and historical revocations**. Likewise, 2 signed custody manifests, 6 checked file copies and furnished timestamp tokens are not independently proven public internet distribution before the dispute, real distinct external companies, qualified legal UTC, complete hidden-fork census or physical manufacturer-certified WORM retention. Those require truly external trusted roots, official and independent archived evidence, and physical verification; EC398 does not fabricate them.

Local synthetic tests exercise genuine Ed25519 signatures, status disagreements, original-byte copying and denial cases with **MOCKED EC397 real parent audit and RFC3161 DER/CMS/X509/CRLs**. Production source passes those through the **unchanged original receivers**. No full independently sourced EC397→EC317/318 history, native PowerShell 7 / original 15 Smoke, Windows/macOS, Git/CI, provider E63–E66, performance, or final joint acceptance has been run or claimed. The shipped native PowerShell CLI remains V4.60/R150; EC249 incomplete, EC250 blocked, B001 open, Quality=false.
