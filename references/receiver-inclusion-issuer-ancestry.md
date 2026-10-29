# EC373 receiver-held EC360 directory inclusion and original EC359 issuer bridge

## Product boundary and original protocol

This new **read-only offline** verifier first calls the real EC372 auditor (which calls EC371→EC370→EC369); a supplied/cached signed PASS report **cannot** replace that parent audit. EC372 already verifies true historical EC360 root-signed delegations, witness-signed origins, root-signed revocation snapshots, and EC362 source-custodian signed manifests. EC371 already verifies the exact historical EC360 directory **Ed25519 signatures**, EC365 old+new dual-signature handoffs and RFC6962 *consistency*. EC373 specifically fills the previously missing **membership/inclusion** of every presented delegation and snapshot in that **same** EC371 checkpoint and verifies actual original **EC359 issuer-signed distribution** evidence referenced by each root delegation.

The signer protocols are unchanged, **not reissued**:

- Historical directory: `CES/EC360/DirectoryCheckpoint/v1\x00`, `authority.DIRECTORY_FIELDS`.
- Historical root delegation and snapshot: `CES/EC360/AuthorityDelegation/v1\x00`, `CES/EC360/AuthorityRevocations/v1\x00`, already verified by EC372.
- Historical issuer-signed owner distribution: `CES/EC359/OwnerDistribution/Issuer/v1\x00`, `distribution.RECORD_FIELDS`, original public issuer key already verified in EC372's root delegation.
- RFC6962 leaf digest is SHA-256(`0x00 || exact original raw bytes`), internal node SHA-256(`0x01 || left || right`); RFC6962 orientations are recomputed by existing `transparency.verify_inclusion`, handling non-perfect trees and rejecting incomplete/extra proof nodes. The original EC371 EC365 dual-signed adjacent-epoch RFC6962 *consistency* proof is still independently checked by its mandatory parent audit.

No new private keys or signatures are produced by production code. Keys are proof-of-possession relative to caller pins only; official issuer identity, legal owner custody, signed source-UTC truth, and the previously missing EC358→EC337 original parent are not inferred.

## Required exact SHA-pinned receiver bundle

A separate independently SHA-pinned `historical_inclusion_bundle_file`, UTF-8 strict JSON **≤52,000 bytes**, exactly:

```json
{
  "schema": "ces.ec373.receiver_historical_inclusion_issuer_originals.v1",
  "parent_ec372_canonical_result_sha256": "<sha of actually replayed EC372 canonical result>",
  "ec371_historical_archive_original_sha256": "<original EC371 receiver archive sha>",
  "ec372_historical_authority_original_sha256": "<original EC372 authority archive sha>",
  "claimed_directory_lineage_id": "ExampleHistoricDirectory",
  "epochs": ["<1-3 chronological epoch objects>"]
}
```

Each epoch contains exactly `epoch_index` (zero-based sequential), `signed_directory_checkpoint_original_sha256` (must equal **EC371 independently pinned original SHA**, signed key, signed Merkle root, two signed source manifest advertisements), `source_a`, `source_b`. Each source has exactly:

| Key | Meaning |
|---|---|
| `delegation_inclusion` | Exact RFC6962 proof of EC372's originally root-signed delegation **bytes** under this EC371 signed checkpoint |
| `snapshot_inclusions` | Ordered RFC6962 proofs for **all** 0–5 EC372 presented signed snapshot originals, including authentic adverse branches; cannot omit a true revoked/forked snapshot |
| `owner_public_key_original` | Strict `{path,sha256}` ref to separate 32-byte raw Ed25519 owner public key, SHA **must equal** the original EC360 root delegation's owner key SHA |
| `claimed_owner_id` | EC359 issuer-signed owner's ID (a claim, not official legal identity) |
| `signed_parent_ec358_canonical_result_sha256` | SHA appearing within each genuine EC359 issuer signature, **not** an EC358 original result recomputed by EC373 |
| `issuer_signed_owner_distribution_originals` | 1–6 SHA-pinned refs to actual original signed EC359 issuer events; includes signed genesis and every presented predecessor/fork branch |
| `selected_owner_distribution_head_sha256` | Must match SHA of a genuinely reopened signed issuer event, and **exactly** the root-signed old EC360 delegation's `parent_distribution_head_original_sha256` |

Each inclusion proof has *exactly* `{"original_sha256":"<exact SHA>","leaf_index":0,"audit_path_sha256":["<0-7 SHA sibling nodes>"]}`. Hashes must be lowercase 64 hex. `leaf_index` is bound to the **actual already signed tree size** (1–64); each used original SHA and leaf index is unique *across both sources within one checkpoint*. A false inclusion under a genuine checkpoint is an explicitly adverse `exit2` finding, not a new signed proof. Missing or misbound original refs, malformed proof entries, reused index, issuer signature forgery, invalid signed predecessor, or delegation↔EC359 original SHA mismatch deny.

All refs are absolute, normalized, bounded, non-symlink receiver-owned ordinary files, with actual **whole-byte SHA256**, inode identity and late rechecks. Path strings in EC369 sender mapping and all old EC362 `copies` structures (including competing custodian-signed source manifests) are **never opened/stat-ed or accepted as aliases**. Shared identical source history originals may be reopened across epochs; distinct roles and source owners cannot reuse keys incorrectly. Two old sources' `claimed_owner_id` or owner raw key collision becomes adverse, while collisions with any already known signer role are denied.

## External independent caller-retained flags

Supply **all audit-mode** EC369/EC370/EC371/EC372 flags, **including** both prior external inventory SHA pins, plus `--historical-inclusion-bundle-file` and `--expected-historical-inclusion-bundle-sha256`. For every historical EC371 epoch (1–3), repeat each:

- `--historical-distribution-a-head-sha256` and `--historical-distribution-b-head-sha256`: separately retained SHA of the *selected actual issuer-signed EC359 original event*, not self-certified by the new bundle;
- `--minimum-historical-distribution-a-sequence` and `--minimum-historical-distribution-b-sequence`: 0–5 minimum *actual signed* event sequence;
- `--minimum-historical-inclusion-tree-size`: externally retained tree-size floor 1–64, checked against the verified **original** signed EC371 checkpoint.

For audit mode (not derive), also supply `--expected-retained-historical-inclusion-inventory-sha256`, a digest independently kept outside the archive. The derivation response includes `unsigned_verified_historical_inclusion_inventory` and `receiver_verified_historical_inclusion_inventory_sha256` for **subsequent outside retention**; it must not be treated as its own externally trusted checkpoint. If a supplied external head/floor/inventory disagrees, the auditor visibly retains an `exit 2` unresolved rollback/disagreement status; it never silently repairs old revoked/forked/blocked evidence.

Example invocations (all inherited and epoch flags must be actually supplied, not literal placeholders):

```bash
# Discover/check exact required arguments (standalone gives explicit usage):
python -I -B scripts/ces_cas_historical_inclusion_archive.py --help

# Recompute original signatures, inclusion paths and unsigned inventory:
python -I -B scripts/ces_cas_historical_inclusion_archive.py \
    derive-historical-inclusion-inventory <ALL_EC369_EC370_EC371_EC372_AUDIT_FLAGS> \
    --historical-inclusion-bundle-file /receiver/old-inclusion.json \
    --expected-historical-inclusion-bundle-sha256 <EXTERNAL_SHA256> \
    <FIVE_REPEATED_DISTRIBUTION_AND_TREE_SIZE_FLAGS_PER_EPOCH>

# Audit adds --expected-retained-historical-inclusion-inventory-sha256 <OUTSIDE_SHA>:
python -I -B scripts/ces_cas_historical_inclusion_archive.py \
    audit-historical-inclusion-archive <ALL_REAL_REQUIRED_AUDIT_FLAGS>

# Fixed isolated unified read-only route, using the same audit inputs:
python -I -B scripts/ces_next.py audit-historical-inclusion-archive \
    DeliveryAudit AuditHistoricalInclusionArchive <ALL_REAL_REQUIRED_AUDIT_FLAGS>
```

Use `python -I -B` with inherited `cryptography` and `asn1crypto` installed. The fixed unified route bounds and checks the child arguments, process, complete JSON fields, logical status and exit, signed original epoch counts and external pins. It never runs a caller-provided child/script path. All lawful reports are `exit_code=2`, `offline_unresolved_exit_code=2`; denial exits 3 permission/integrity, 4 invalid input, 5 unavailable.

## Authenticated observations versus open parent limitations

This layer verifies **actual original** directory Ed25519 checkpoint signatures and exact actual EC359 issuer signature bytes, two-source RFC6962 inclusion, external head/floors, true issuer-signed causal ancestry, terminal revoke/rotate/forks, role and owner collision, SHA/path/inode/late check. It does **not** reconstruct/reproduce any historic EC360/EC359 *canonical result*, does not check EC358→EC337 old owner original inputs or the EC362 other old source copy-role originals, does not authenticate legal issuer/witness key legitimacy, trusted time, global latest signed log or complete revocation, absence of hidden branches or real publication/physical independent custody. Every parent EC372 revoke, EC371 fork, EC370 publication withholding and EC369 original dispute remains adverse.

**27 local EC373 focused cases passed in one uninterrupted run**, with 3 genuine isolated `python -I -B` children and 1 genuine live receiver EC372→369 replay. The **EC366→EC337 deep fixture remains deliberately MOCKED**, so true complete historic EC365→EC337 original-inclusive successes remain zero. Final user-assisted acceptance is pending; do not promote these tests to complete historic trust.
