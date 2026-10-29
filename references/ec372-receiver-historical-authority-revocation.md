# EC372 read-only signed historical authority and revocation archive protocol

## Scope and trust boundary

The new receiver-only auditor **always executes the real EC371→EC370→EC369 audit**, which itself reopens true signed current receiver and historical directory originals, before opening the EC372 authority archive. EC372 uses unmodified **EC360 original Ed25519 domains**:

- `CES/EC360/AuthorityDelegation/v1\x00` for a real root-key-signed delegation (`DELEGATION_FIELDS`);
- `CES/EC360/AnchorOriginWitness/v1\x00` for a separate witness-key-signed origin (`ORIGIN_FIELDS`);
- `CES/EC360/AuthorityRevocations/v1\x00` for a real root-key-signed snapshot (`SNAPSHOT_FIELDS`).

Issuer public keys are exact SHA-pinned raw 32-byte originals, but this is **NOT** proof of an authenticated institutional issuer or a genuine old EC359 ancestor. The signed `parent_ec359_canonical_result_sha256`, source manifest `parent_ec360_canonical_result_sha256`, institutional authority name and witness `origin_reference_id` are verified only as claims *made by those keys*, not source-certified ground truth. The old EC360 directory inclusion proofs for delegations/snapshots and the historic EC365→EC337 parent are not reconstructed. The signature issuer keys, origin witness keys, old source custodians and directory signer keys must be distinct roles. Reused same-slot issuer/witness/root keys across epochs are allowed; unproven authority rotation remains adverse.

## Strict input archive

One receiver-owned SHA-pinned JSON bundle, size ≤48,000 bytes, with **exactly**:

```json
{
  "schema": "ces.ec372.receiver_historical_authority_originals.v1",
  "parent_ec371_canonical_result_sha256": "<SHA256 of actual live EC371 canonical result JSON>",
  "historical_directory_archive_original_sha256": "<external EC371 historical bundle SHA>",
  "claimed_directory_lineage_id": "ExampleHistoricDirectory",
  "epochs": ["<1-3 ordered source epoch objects>"]
}
```

Each epoch has exactly `epoch_index` (starting at 0), `source_a`, `source_b`. Each `source_a/source_b` object has **exactly**:

| Field | Original or meaning |
|---|---|
| `authority_root_public_key_original` | receiver ref to 32 raw bytes; Ed25519 root signer |
| `origin_witness_public_key_original` | receiver ref to different 32 raw bytes; Ed25519 origin witness |
| `issuer_public_key_original` | receiver ref to different 32 raw bytes; original SHA bound to delegation and revocation inventory (old issuer signing ancestry NOT replayed) |
| `root_signed_delegation_original` | receiver ref to unchanged EC360 root-signed `DELEGATION_SCHEMA`, scopes, jurisdictions, parent EC359 claims and root/issuer keys |
| `witness_signed_origin_original` | receiver ref to unchanged EC360 witness-signed `ORIGIN_SCHEMA`, bound to exact delegation SHA/root/witness and jurisdiction |
| `root_signed_revocation_snapshot_originals` | bounded 0–5 receiver refs to unchanged EC360 `SNAPSHOT_SCHEMA`, signed causal sequence, irrevocable revocation evidence and coverage |
| `selected_revocation_head_sha256` | actual included selected snapshot SHA, or `null` **only when explicitly unavailable**, never a substitute for a caller-retained head |
| `source_manifest_original_sha256` | SHA of this same epoch/slot's true EC371 historical source custody-signed EC362 original |
| `source_custodian_key_original_sha256` | SHA of the corresponding actually verified historical custodian key |
| `signed_parent_ec360_canonical_result_sha256` | exact digest the EC362 signed manifest claims for its prior EC360 result; NOT independently recomputed |

Every receiver ref has exactly `{ "path": "<absolute normalized receiver-owned non-symlink regular file>", "sha256": "<SHA256 of raw bytes>" }`. Old sender-source and EC362 `copies` paths are *signed metadata labels only*: they MUST NOT be read, statted, restored or alias any new receiver path. Independent source SHA and current EC371 archive SHA are matched before computing the EC372 result. SHA/inode/late identity checks are reused from the existing inherited verified file loader.

## External caller-retained flags

Supply **all** EC369 + EC370 + EC371 audit flags, **including** `--expected-retained-historical-inventory-sha256`. New scalar flags are `--historical-authority-bundle-file` and `--expected-historical-authority-bundle-sha256`. New repeat flags have one value per EC371 directory epoch, in chronological order:

- `--historical-authority-a-root-sha256` / `--historical-authority-b-root-sha256`: independent original SHA for each authority root;
- `--historical-authority-a-head-sha256` / `--historical-authority-b-head-sha256`: independently retained selected revocation snapshot head SHA (not optional);
- `--minimum-authority-a-revocation-sequence` / `--minimum-authority-b-revocation-sequence`: integer 0–4;
- `--minimum-authority-a-publication-sequence` / `--minimum-authority-b-publication-sequence`: integer 0–2147483647 from actual EC362 source custodian signature.

For `audit-historical-authority-archive`, add `--expected-retained-historical-authority-inventory-sha256` with the SHA of exact **derived** unsigned inventory, retained **outside** the bundle. First run the standalone `derive-historical-authority-inventory` with the same other required arguments to obtain the inventory and its SHA. This helper **does not** create a certified independent external pin. Nonmatching external root SHA, false original signature, malformed fields, missing signed predecessor, symlink/path alias and tampered raw bytes deny; a genuine signed revocation, fork, selected head/sequence mismatch, unproved authority rotation or ancestor conflict **remains adverse in an exit-2 unresolved result**.

Example command structure after extracting `ces/` and supplying complete real flags:

```bash
python -I -B scripts/ces_cas_historical_authority_archive.py derive-historical-authority-inventory \
  <ALL_REQUIRED_EC369_EC370_EC371_FLAGS> \
  --historical-authority-bundle-file /receiver/authority.json \
  --expected-historical-authority-bundle-sha256 <REAL_BUNDLE_SHA> \
  --historical-authority-a-root-sha256 <ROOT_A_EPOCH0_SHA> \
  --historical-authority-b-root-sha256 <ROOT_B_EPOCH0_SHA> \
  --historical-authority-a-head-sha256 <HEAD_A_EPOCH0_SHA> \
  --historical-authority-b-head-sha256 <HEAD_B_EPOCH0_SHA> \
  --minimum-authority-a-revocation-sequence 0 \
  --minimum-authority-b-revocation-sequence 0 \
  --minimum-authority-a-publication-sequence 0 \
  --minimum-authority-b-publication-sequence 0

# Audit: same flags + --expected-retained-historical-authority-inventory-sha256 <OUTSIDE_SHA>
python -I -B scripts/ces_cas_historical_authority_archive.py audit-historical-authority-archive <ALL_REQUIRED_FLAGS>

# Fixed unified read-only route, same audit arguments:
python -I -B scripts/ces_next.py audit-historical-authority-archive \
  DeliveryAudit AuditHistoricalAuthorityArchive <ALL_REQUIRED_FLAGS>
```

The example deliberately shows just epoch 0; repeat every 8 authority flags for each further genuine EC371 epoch (1–3 total). All placeholders must be replaced; the command is **not** a literal ready-to-run acceptance fixture. `python -I -B` requires installed `cryptography` and `asn1crypto` as in inherited historical tools. Exit 2 = unresolved even when all local signed slices cohere; exit 3 permission or integrity denial, 4 invalid input, 5 unavailable. The authoritative original PowerShell CLI V4.60/R150 is unchanged.

## Negative claims and bounded tests

EC372 **does not** reopen historical EC362 extra copy-role originals, verify signed EC360 delegation/snapshot RFC6962 inclusion under an independently authenticated historic public directory root, reproduce EC360 result from EC359/338..337, authenticate official issuer/witness roles, prove physical archival custody or trusted UTC, or demonstrate all hidden forks absent. An inherited genuine EC369/370/371 dispute remains unresolved. No signer/network/writer, no Provider/CAS/WORM and no native PS modification.

26 new focused synthetic cases ran uninterrupted, including genuine EC360 Ed25519 original signatures, authentic signed adverse revocation and forks, absent old source paths, one genuine full current EC371→EC370→EC369 parent replay, three actual `python -I -B` child processes, and negative tamper/rollback/path checks. The *prior* EC366→EC337 historical depth inside the fixture is MOCKED. Remaining native PS7/15 Smoke, older true-parent, full inherited regression, official legal identity, real global custody/issuer/revocation logs, remote provider and final user-assisted checks must be completed separately.
