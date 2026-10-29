# EC396 — externally pinned registry-status history, public-log Merkle originals and claimed physical WORM custody (offline)

**Release:** V7.06 / R396 / EC396. **One EC only. Receiver-only, no network and no write permission.** This receiver is a narrowly bounded cryptographic verification tool, **not** verification of real regulatory authority, government registry authenticity, public internet publication, qualified time services, physical WORM existence, global revocation completeness or dispute-date legal sufficiency. The actual unchanged EC395 audit is always invoked first (EC394→EC393→EC392→both EC391 branches), and a supplied former `PASS` string is never accepted as input. Full deep production acceptance remains outstanding.

## Operator entry points

```bash
cd ces
python -I -B scripts/ces_cas_historical_public_integrity.py derive-historical-ec339-public-integrity-inventory --help
python -I -B scripts/ces_cas_historical_public_integrity.py audit-historical-ec339-public-integrity --help
python -I -B scripts/ces_next.py audit-historical-ec339-public-integrity DeliveryAudit AuditHistoricalEC339PublicIntegrity --help
```

The standalone commands receive **every** original scalar and repeated argument accepted by EC395 `audit-historical-ec339-credential-gossip-archive`; the `derive` command also requires all eight EC396 new scalars and six EC396 new repeated arguments. `audit` adds `--expected-retained-historical-ec339-public-integrity-inventory-sha256`, retained through an independently pre-existing channel (not copied after the fact from one self-generated derive output). All legitimate/evaluable outcomes have `exit_code=2`, status suffix `_unresolved`; invalid/forged/inaccessible sources exit 3/4/5. The router is a **fixed** `DeliveryAudit`/`AuditHistoricalEC339PublicIntegrity` action/mode, not a new native PowerShell action and never a signing or WORM provisioning path.

### Eight new scalar arguments

Each name below is passed as `--` plus its underscores replaced by hyphens.

| Receiver input | Meaning |
|---|---|
| `historical_ec339_public_integrity_bundle_file` | Normalized absolute path to actual EC396 canonical evidence bundle |
| `expected_historical_ec339_public_integrity_bundle_sha256` | Pinned SHA256 of the *exact* EC396 evidence bundle bytes |
| `expected_outside_retained_ec396_role_roster_sha256` | Independent SHA of the new **registry signer, log signer and two device signers** roster |
| `expected_outside_retained_ec396_public_catalog_original_sha256` | SHA of **opaque** purported public catalog / charter bytes; DOES NOT authenticate publication or regulator |
| `expected_outside_retained_ec396_registry_public_hex` | Externally supplied raw Ed25519 registry signing public key (64 lower-hex chars) |
| `expected_outside_retained_ec396_transparency_log_public_hex` | A different externally supplied raw Ed25519 public log signing key |
| `expected_outside_retained_ec396_first_registry_snapshot_sha256` | Independent first *signed registry original* SHA; not the caller's chosen replacement |
| `expected_outside_retained_ec396_first_device_attestation_sha256` | Independent first signed original SHA from roster device operator **A**, not an arbitrary receipt |

### Six new repeated arguments

Every repeated argument occurs **exactly once per existing EC395 1–3 historical epochs**. New SHA inventories are canonical, derived from **actual verified original bytes**; they do not contain private keys. Do not use the derive result as the only independent pin.

| CLI repeated flag | Consumer key | Values |
|---|---|---|
| `--historical-ec339-public-registry-inventory-sha256` | `historical_ec339_public_registry_inventory_shas` | nonzero SHA256 per epoch |
| `--historical-ec339-public-log-inventory-sha256` | `historical_ec339_public_log_inventory_shas` | nonzero SHA256 per epoch |
| `--historical-ec339-device-readback-inventory-sha256` | `historical_ec339_device_readback_inventory_shas` | nonzero SHA256 per epoch |
| `--minimum-historical-ec339-current-registry-role-count` | `minimum_historical_ec339_current_registry_roles` | integer 0–4 (all four EC395 external signer keys, no adverse signed status) |
| `--minimum-historical-ec339-merkle-inclusion-set-count` | `minimum_historical_ec339_merkle_inclusion_sets` | integer 0–1 (all four genuine signed original leaf proofs) |
| `--minimum-historical-ec339-two-device-readback-count` | `minimum_historical_ec339_two_device_readbacks` | integer 0–2 (two separately signed device operator readbacks) |

## Original bundle protocol

All structured original JSON files MUST be byte-for-byte canonical JSON, exact keys (unknown keys rejected), max-sized and have strict normal absolute path/SHA references `{"path":"...","sha256":"..."}`. Signatures are raw Ed25519 over a domain prefix plus canonical `claim` bytes. Other original bytes (opaque catalog, device inventory, DER RFC3161 token, original raw key files) are read with strict size and SHA pins. Canonical functions are inherited from `offline_transfer_registry.registry`; SHA and timestamp reader from unchanged EC394/395/372 and RFC6962 Merkle from `transparency.transparency`.

Root (`ces.ec396.original_registry_log_worm_evidence_bundle.v1`) exact fields:

```json
{
  "schema": "ces.ec396.original_registry_log_worm_evidence_bundle.v1",
  "claimed_directory_lineage_id": "LineageId",
  "parent_ec395_credential_gossip_bundle_original": {"path":"/absolute/ec395","sha256":"..."},
  "outside_authority_roster_original": {"path":"/absolute/new-role-roster","sha256":"..."},
  "purported_public_catalog_original": {"path":"/absolute/catalog","sha256":"..."},
  "epochs": [{
    "epoch_index": 0,
    "registry": {"signed_original": {"path":"/absolute/signed-registry","sha256":"..."},
                 "rfc3161_token_original": {"path":"/absolute/registry-der","sha256":"..."}},
    "log": {"signed_head_original": {"path":"/absolute/signed-head","sha256":"..."},
            "rfc3161_token_original": {"path":"/absolute/log-der","sha256":"..."},
            "leaves": [], "consistency_path_sha256": []},
    "devices": []
  }]
}
```

In this **shape illustration**, `leaves` and `devices` MUST be filled as described below to obtain evidence count credit; empty values are permitted only as adverse/unresolved evidence. Strings `"..."` are illustrative and NOT valid SHA-256 pins. `epochs` count/indices must exactly match the audited EC395 historical epochs, contiguous from 0.

The roster (`ces.ec396.outside_registry_log_and_two_device_operators.v1`) is exactly `schema`, `claimed_directory_lineage_id`, `registry_signer`, `transparency_log_signer`, `device_operators` (array of **two**). Each signer has `role_id`, `site_id`, `public_hex`, `public_key_original`, all distinct in key/role ID/site and disjoint from all EC393/394/395 signer keys, sites and role IDs. Its 32-byte original public key file is **opened and compared to `public_hex`**. First two roles must match both outside-held raw keys; roster SHA itself must match independent retained SHA. This checks bytes and key reuse, not actual distinct corporate owners.

### 1. Signed registry status timeline

Per epoch, `registry` has only `signed_original`, `rfc3161_token_original`. Either both are genuine original refs or both may be null (no count). The original has exactly `schema`, `claim`, `signature_ed25519`. Schema `ces.ec396.original_signed_public_registry_snapshot.v1`, signed claim schema `ces.ec396.signed_public_registry_snapshot_claim.v1`, signature domain (including NUL):

```
CES/EC396/OutsideRegistrySnapshot/v1\0
```

The claim has precisely these fields: `schema`, `directory_lineage_id`, `parent_ec395_bundle_sha256`, `parent_ec395_verified_inventory_sha256`, `public_catalog_original_sha256`, `epoch_index`, `registry_sequence` (epoch+1), `previous_registry_snapshot_sha256` (actual **previous original bytes** SHA, first genesis = 64 zeros), `registry_signer_id`, `subjects`, `claimed_snapshot_utc`. `subjects` must be the exact sorted four actual EC395 credential issuers and archivists, each exactly `role_id`, `public_hex`, `status` (`active`, `revoked`, `suspended`), `effective_utc`. No key substitution, role omission, duplicated role, forged signature or wrong original SHA is accepted.

Prior status is preserved through every epoch. `revoked→active`, nonmonotone effective dates, future-effective status relative to genuine time and stale/missing true RFC3161 DER/CMS/X509/CRL tokens are adverse, **not** restored by later signed claims. A signed `revoked` or `suspended` role never receives an active certification count. The externally supplied catalog is deliberately **opaque**: it cannot turn a local signed status into a government-certified authoritative statement.

### 2. Signed historical log, true RFC6962 inclusion and prefix

`log` contains `signed_head_original`, `rfc3161_token_original`, `leaves`, `consistency_path_sha256`. A missing head requires null token/empty proofs and yields no count. Its original signed schema is `ces.ec396.original_signed_public_transparency_head.v1`, claim schema `ces.ec396.signed_public_transparency_head_claim.v1`, domain:

```
CES/EC396/OutsideMerkleHead/v1\0
```

Claim fields: `schema`, `directory_lineage_id`, `parent_ec395_bundle_sha256`, `parent_ec395_verified_inventory_sha256`, `epoch_index`, `log_signer_id`, `log_sequence` (=epoch+1), `previous_signed_log_head_sha256` (actual prior signed original SHA; genesis zeros), `tree_size` (4–64), `merkle_root_sha256`, `registry_snapshot_original_sha256`, `claimed_published_utc`. Only the outside-pinned independent log signer can sign. Genuine EC394-derived RFC3161 token/CRL must match original signed head bytes and precede declared cutoff.

Exactly **four typed inclusion leaf rows** produce one inclusion-set credit: `registry`, `gossip_confirm`, `archive_a`, `archive_b`, each an exact `kind`, `signed_original` ref, zero-based `index`, and list `path_sha256`. All original refs are reopened and must match the actual **previously audited EC395 source**: the signed EC396 registry, genuine EC395 signed A→B→A `confirm`, and the two genuine signed EC395 archivist receipts (in original EC395 archive order). Unique indices, path hashes (max 32), RFC6962 domain-separated leaf and node hashes, and the actual signed Head root/size are verified; no caller-chosen other signed doc substitutes. The first epoch has an empty consistency path. Later epochs require real RFC6962 old-size/root→new-size/root consistency from the **prior original verified signed Head**; a valid but conflicting signed root results in adverse observation and **zero** bounded inclusion credit. One known path does not prove absence of hidden forks or prior globally distributed publication.

### 3. Two independent claimed device operators and actual byte recovery

Each epoch has exactly **two** `devices` entries, one for each roster device operator (`operator_id` disjoint). Each entry has precisely `operator_id`, `device_inventory_original`, `signed_attestation_original`, `rfc3161_token_original`, `copies`. The device inventory is an independently hash-pinned and byte-read opaque local source, **not** a manufacturer's online hardware attestation. The two device inventory paths may not alias signed originals or each other; site/role keys, and signed `device_serial_id` must differ.

A signed attestation has `schema`, `claim`, `signature_ed25519`. Schema `ces.ec396.original_signed_device_custody_attestation.v1`, claim schema `ces.ec396.signed_device_custody_attestation_claim.v1`, signature domain:

```
CES/EC396/IndependentDeviceReadback/v1\0
```

Claim exact fields: `schema`, `directory_lineage_id`, `parent_ec395_bundle_sha256`, `parent_ec395_verified_inventory_sha256`, `epoch_index`, `device_operator_id`, `device_site_id`, `device_serial_id`, `claimed_storage_mode` (`worm_append_only_claimed` only), `device_inventory_sha256`, `public_log_head_original_sha256`, `previous_epoch_attestation_sha256`, `original_to_device_copy_inventory_sha256`, `claimed_sealed_utc`, `claimed_retention_until_utc`.

The `copies` list has 0–2 rows with exact `source_original` and `device_copy_original` refs. Count credit requires **both** source rows: actual EC395 archivist **signed receipt originals** from this epoch. The source must equal the audited parent path and SHA; independent replica path and SHA must contain exact bytes from the original, with no source path / protected-original / another device-copy path alias. The signed claim binds the canonical sorted path+SHA recovery inventory and previous *actual signed original* attestation SHA from that **same operator**. The true signed-token time must be after the verified current signed public log token, after the claimed signed-seal time and prior to cutoff; claimed retention date after cutoff is only a local **claim**, not physical retention proof. A missing/unbounded earlier epoch permanently destroys this operator's later bounded-count continuity, even if it signs again. The EC396 bundle itself is never copied (avoids an impossible circular SHA dependency).

### Output / cautious interpretation

`derive` includes `unsigned_public_integrity_inventory`, a canonical unsigned source inventory, and SHA. `audit` outputs its SHA **only**; the caller supplies independently retained `expected_retained_*_inventory_sha256`. Both expose verified actual EC395 report SHA/inventory SHA, counts for four active roles / complete log inclusion sets / independently signed two-source readbacks, signed revocations, per-epoch source SHA inventories and explicit adverse flags. **Flags for official public/legal authority, prior actual physical WORM and global completeness always remain true.** A clean local cryptographic path can reduce bounded adverse flags but **never produces `PASS`, validates any regulator, or promotes Quality**.

Production timestamp validation opens **real original DER RFC3161 CMS/X509/CRL** with unchanged EC394 trust root (including its independently pinned SHA), not self-invented timestamps or system trust. The current local focused suite deliberately mocks expensive EC395 parent and timestamp issuance; this is described in `construction/EC396_LOCAL_REPORT.json`. Independent online authoritative licenses, historic publication logs, live revocation endpoints, qualified TSA and hardware WORM sources remain separately required to validate the real-world claims.
