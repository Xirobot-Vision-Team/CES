# EC371 — Receiver-held historical directory signed-original archive (offline, partial)

## Strict scope

EC371 **always re-runs the actual EC370 publication-accountability auditor** (which really replays EC369's received EC366/367 signatures and EC368/369 original receipts). It then independently opens SHA-pinned **receiver-side** copies of a carefully bounded EC360/EC362/EC365 historical **directory-signing layer**. The new layer verifies authentic Ed25519 signatures, EC365's real dual-signature domain and a real RFC6962 consistency proof. It *never* opens original sender labels embedded in older signed source manifests, silently supplies a missing signer or resurrects deleted sources.

This archive is **not** an execution of `ec365_directory_lineage.audit()` or EC364→EC337 original validators. In particular the true historic EC365 canonical result bytes, EC361/EC360 parent outcomes, original authority revocation snapshots, historical observer receipts, distribution witnesses and original EC317/318 dependent evidence have not been reconstructed here. The receiver's already authentic EC366/369 **claim** of `parent_ec365_canonical_result_sha256` is checked against the new bundle's matching field, but this equality does **not** prove that the newly supplied historic subset is the exact input to that earlier EC365 result. Explicit flags and false negative-capability claims prevent that upgrade.

## External caller-controlled anchors

Every audit requires all **unchanged** EC369 and EC370 arguments (including each independent role key, source map and every signed original SHA stream), plus:

| New scalar flag | Meaning |
| --- | --- |
| `--historical-archive-bundle-file` | Absolute safe path to receiver-owned canonical JSON bundle |
| `--expected-historical-archive-bundle-sha256` | True SHA-256 separately retained outside that bundle |
| `--claimed-historical-directory-lineage-id` | Caller-supplied strict lineage identifier (never legal authority) |
| `--expected-retained-historical-checkpoint-head-sha256` | Separately retained latest historical signed checkpoint ORIGINAL SHA |
| `--minimum-retained-historical-tree-size` | Independently retained minimum presented latest signed tree size, 0..64 |
| `--minimum-retained-historical-root-generation` | Independently retained minimum presented root rotation generation, 0..2 |
| `--expected-retained-historical-inventory-sha256` | Audit-only externally retained hash of the exact **derived** receiver inventory; not self-certified |

In actual epoch order repeat `--historical-directory-root-sha256`, `--historical-signed-checkpoint-sha256`, `--historical-source-a-manifest-sha256`, `--historical-source-b-manifest-sha256` (1–3 values **each**, equal lengths). For each presented signed handoff repeat `--historical-dual-handoff-sha256` (0–2 values in edge order). The inherited parent already requires **eight distinct Ed25519 roles**; historic directory keys may not reuse those roles or new source custodians. Historian-provided source key material cannot automatically be elevated to a trusted official institution.

For a new archive, call the unsigned `derive-historical-directory-inventory` first with **all other** required EC369/EC370/EC371 flags. The command *re-verifies the real archive signatures and parent audit* and returns the full `unsigned_verified_historical_inventory` plus its canonical SHA-256 to retain **outside** the archive. This is a data-preparation aid, **not an attestation, issuance, or trusted external SHA pin**. Then pass that independent expected SHA to `audit-historical-directory-archive`.

## Bundle schema (strict exact fields)

`ces.ec371.receiver_historical_directory_archive.v1` has exactly:

```json
{
  "schema": "ces.ec371.receiver_historical_directory_archive.v1",
  "parent_ec370_canonical_result_sha256": "<canonical SHA of this run's REAL EC370 result>",
  "parent_ec365_canonical_result_sha256": "<matching inherited signed claim; not an EC365 replay>",
  "claimed_directory_lineage_id": "ExampleHistoricDirectory",
  "epochs": ["<1–3 epoch objects below, original chronology>"],
  "transitions": ["<one transition object or null per adjacent epoch pair>"],
  "competing_signed_checkpoints": [],
  "competing_signed_source_manifests": [],
  "competing_signed_handoffs": []
}
```

The string placeholders shown above are descriptive, **not** valid example values. Each epoch has exactly:

- `epoch_index`: consecutive integer 0, 1 or 2;
- `directory_public_key_original`: receiver reference `{ "path": "<absolute copy>", "sha256": "<real caller-pinned SHA>" }`, containing exactly 32-byte raw Ed25519 key;
- `signed_directory_checkpoint_original`: distinct receiver file reference, containing **actual original** `ces.ec360.directory_signed_checkpoint.v1`, verified using its original `CES/EC360/DirectoryCheckpoint/v1\0` Ed25519 signature, lineage ID, claimed time window, Merkle root and tree size 1–64;
- `source_a_manifest_original`, `source_b_manifest_original`: receiver-side file refs containing **authentic** `ces.ec362.signed_offline_directory_publication_copy.v1` originals, validated with source-key Ed25519 `CES/EC362/OfflineDirectoryPublicationCustody/v1\0`, source slot A/B, original SHA of checkpoint, original parent EC361 SHA claim, source publication sequences and copies map;
- `source_a_custodian_public_key_original`, `source_b_custodian_public_key_original`: receiver-side distinct, exact 32-byte public keys. The two source signatures must name their own keys and claim the same ancestor EC361 digest. Cross-source conflicting EC360/checkpoint ancestry and historical sequence regressions remain visible.

Each adjacent `transitions` item is `null` (explicitly **missing**) or has exactly `signed_directory_handoff_original` and `rfc6962_consistency_proof`. The signed original uses the *unchanged* EC365 `ces.ec365.dual_signed_directory_authority_handoff.v1` schema/domain `CES/EC365/DualSignedDirectoryAuthorityHandoff/v1\0`, with both old and new directory Ed25519 signatures covering the exact endpoint key/checkpoint/source SHA pairs, claimed lineage, parent EC361 hashes, action, rotation generation and SHA of **canonical** proof object. The proof has exactly `from_epoch_index`, `to_epoch_index`, `older_checkpoint_original_sha256`, `newer_checkpoint_original_sha256`, `audit_path_sha256`. Its SHA list is bounded; `verify_consistency()` re-computes the actual RFC6962 append relation. The original **source** `copies` paths inside an EC362 signature are treated as **labels only**: the auditor validates their format and checkpoint SHA reference but never attempts their I/O or falsely marks other three copy roles verified.

`competing_signed_checkpoints`: up to four objects `{ "epoch_index": 0, "signed_directory_checkpoint_original": {"path":"...","sha256":"..."} }`; every alternate must authenticate under the **same** pinned epoch key. `competing_signed_source_manifests`: up to four `{ "epoch_index": 0, "source_slot":"a", "signed_source_manifest_original": {"path":"...","sha256":"..."} }`; each must verify under that source's actual Ed25519 key and bound source/lineage/parent. `competing_signed_handoffs`: up to four `{ "edge_index": 0, "signed_directory_handoff_original": {"path":"...","sha256":"..."} }` that are **truly double-signed**, bound to the same actual endpoint/proof, and not already selected. Valid competing originals are never silently discarded to manufacture a favorable branch. An explicitly missing handoff remains incomplete even with plausible endpoint keys.

Every newly opened file must be an absolute normalized regular file, without symlink traversal, with the exact pinned SHA and unchanged late identity. The original `source_original.path` strings from EC369 and the older EC362 signed source copy labels are expressly forbidden as new receiver archive read locations. **The verifier never writes a file, signs an original, obtains a key from a server, or accesses an ambient trust store.**

## Commands

From extracted `ces/`, with Python 3 plus existing `cryptography` and `asn1crypto` dependencies installed:

```bash
# Verifies original bytes and exports only UNSIGNED inventory for outside retention
python -I -B scripts/ces_cas_historical_directory_archive.py \
  derive-historical-directory-inventory \
  <ALL_REQUIRED_EC369_AND_EC370_ARGUMENTS> \
  --historical-archive-bundle-file /receiver/ec371-archive.json \
  --expected-historical-archive-bundle-sha256 <ARCHIVE_ORIGINAL_SHA> \
  --claimed-historical-directory-lineage-id ExampleHistoricDirectory \
  --expected-retained-historical-checkpoint-head-sha256 <LATEST_CHECKPOINT_SHA> \
  --minimum-retained-historical-tree-size 2 \
  --minimum-retained-historical-root-generation 1 \
  --historical-directory-root-sha256 <EPOCH0_ROOT_KEY_SHA> \
  --historical-directory-root-sha256 <EPOCH1_ROOT_KEY_SHA> \
  --historical-signed-checkpoint-sha256 <EPOCH0_SIGNED_CP_SHA> \
  --historical-signed-checkpoint-sha256 <EPOCH1_SIGNED_CP_SHA> \
  --historical-source-a-manifest-sha256 <EPOCH0_SIGNED_A_SHA> \
  --historical-source-a-manifest-sha256 <EPOCH1_SIGNED_A_SHA> \
  --historical-source-b-manifest-sha256 <EPOCH0_SIGNED_B_SHA> \
  --historical-source-b-manifest-sha256 <EPOCH1_SIGNED_B_SHA> \
  --historical-dual-handoff-sha256 <SIGNED_EVENT_SHA>
```

`<...>` syntax above documents required material; replace each placeholder with the **actual value**. For audit, use the same complete flags and additionally `--expected-retained-historical-inventory-sha256 <OUTSIDE_INVENTORY_SHA>`:

```bash
python -I -B scripts/ces_cas_historical_directory_archive.py \
  audit-historical-directory-archive <ALL_REQUIRED_FLAGS>

# Same flags, hard-coded isolated child and strictly checked JSON response:
python -I -B scripts/ces_next.py \
  audit-historical-directory-archive DeliveryAudit AuditHistoricalDirectoryArchive \
  <ALL_REQUIRED_FLAGS>
```

`exit 2` means **unresolved**, *including* a locally matching archive. `exit 3` is permission/integrity denial; `4` invalid input; `5` unavailable I/O/unexpected condition. The response reports SHA streams, true signature counts, verified RFC6962 edge count, signed fork/withholding/retirement/time flags, source path never read and the always-true `historical_archive_only_partially_recovers_ec365_to_ec337`. All full-ancestry/authority/global completeness/final-acceptance proof flags stay false. No successful report is proof of EC365's actual complete historical input ancestry.

## EC371 local observations / deferred acceptance

In the EC371 **synthetic** fixture, 26 focused cases ran uninterrupted with real historic directory, source-custodian, old/new dual-handoff signatures, real RFC6962 roots/proof and deletion/nonexistence of all *historical source labels*. Three cases used **actual** `python -I -B` isolated child processes (valid fixed unified, denial on tampered original, unsigned standalone derive). A separate test also invoked live production EC370→EC369 on the new historical layer. **The inherited EC366→EC337 deep fixture remains deliberately MOCKED**, not retested or repaired; no genuinely full old EC365→EC337 archival replay has passed. Original EC366 heavy 12 parent-inclusive tests, EC356 historic case24, EC317/318 deep nonmock, old global regressions, native PowerShell7/15 Smoke, Windows/macOS/Git/CI/Provider E63–E66, real custodians/trusted UTC/global logs/remote CAS/WORM and final user-assisted acceptance remain pending. Historic roots or external public logs must be provided and certified by the user or separately authorized parties; CES cannot invent them.
