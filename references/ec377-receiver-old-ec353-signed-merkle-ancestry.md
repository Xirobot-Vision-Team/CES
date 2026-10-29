# EC377 — receiver-held genuine historical EC353 signed-log and Merkle ancestry

**Wire authority:** `ces.ec377.receiver_historical_ec353_transparency_original_archive.v1`. Construction package **V6.87/R377**, not a change to the native **V4.60/R150** PowerShell CLI. This is **one bounded EC**, not full recovery of all historical original parents.

## Explicit trust and threat boundary

For **every** `derive` or `audit`, invoke real production `EC376.audit(**all_parent_inputs)` (which itself mandates genuine EC375→EC374→EC373→EC372→EC371→EC370→EC369 receiver original replay). Require `exit_code=2`, the exact old EC376 result schema and `sender_origin_path_required_or_read=false`. Never accept caller-authored parent reports as success evidence. The separate receiver-held EC377 unsigned archive MUST commit to the SHA-256 of the live **canonical EC376 report** and the SHA-256 of the exact old EC376 receiver archive. An inherited adverse condition remains adverse.

The historical EC353 **unsigned** `ces.ec353.pinned_publication_evidence_bundle.v1` manifest is furnished as an independently outside-SHA-pinned **receiver copy**, not as a certificate or an authority to read its embedded sender paths. Each old `{'path','sha256'}` value is compared by hash with a *separate* receiver-controlled `{'path','sha256'}` object; only the receiver path is opened. Every old origin path is added to a denylist. Receiver references use the established regular-file/no-symlink/whole-SHA + inode/late-file recheck machinery. Aliases between receiver files and old sender path labels are denied. The same source-byte SHA does not authorize a new original path. Never fetch HTTPS, consult OS trust, sign, or write to CAS/WORM/Provider.

## New archive structure (exact fields, canonical JSON)

```json
{
  "schema": "ces.ec377.receiver_historical_ec353_transparency_original_archive.v1",
  "parent_ec376_canonical_result_sha256": "<SHA-256 of actual EC376 report>",
  "ec376_historical_disclosure_archive_original_sha256": "<outside pinned EC376 bundle SHA>",
  "claimed_directory_lineage_id": "<exact inherited ID>",
  "epochs": [
    {
      "epoch_index": 0,
      "ec353_publication_bundle_original": {"path":"<receiver absolute file>","sha256":"<whole-file SHA>"},
      "logs": [
        {
          "log_id": "<exact old signed log ID>",
          "log_public_key_original": {"path":"...","sha256":"..."},
          "log_reference_original": {"path":"...","sha256":"..."},
          "witness_public_key_original": {"path":"...","sha256":"..."},
          "witness_reference_original": {"path":"...","sha256":"..."},
          "checkpoints": [
            {
              "signed_checkpoint_original": {"path":"...","sha256":"..."},
              "signed_witness_original": {"path":"...","sha256":"..."},
              "consistency_original": null
            }
          ],
          "inclusions": [
            {
              "proof_original": {"path":"...","sha256":"..."},
              "artifact_original": {"path":"...","sha256":"..."}
            }
          ]
        }
      ]
    }
  ]
}
```

All receiver references are actual filesystem objects and SHA pins, not redacted example strings. Each epoch has **two** logs, sorted by unique `log_id`, corresponding **one-to-one** with the old EC353 manifest `logs`. Every old log has 1–4 checkpoints, each with one signed witness; 1–12 real inclusion proofs per log; every source log key and witness key is independently 32 bytes. Log and witness signer key SHA must be unique within their epoch and distinct from known external/earlier publisher, auditor, custodian, owner, witness, root, directory and transfer key roles. Claimed organization equality is an *adverse flag*; different claimed organization text is **not proof of independence**.

Each receiver checkpoint corresponds one-to-one by original whole SHA to the `checkpoints[].checkpoint` label in the historical EC353 manifest; the independently receiver-furnished witness and consistency files match `witness_statement` and `consistency_proof` old SHA labels. Every receiver inclusion proof matches the historical EC353 `inclusions[]` label. `artifact_original` is an *independent receiver copy* of the exact old EC352 `registry_root_reference` or `registry_event` Merkle leaf. Its file bytes and SHA are bound to the original inclusion proof, but its **old issuer/signing authority is not replayed in EC377**.

## Real, unchanged EC353 cryptography and ancestry

- Verify the original EC353 `CES/EC353/LogReference/v1\0` and `CES/EC353/WitnessReference/v1\0` Ed25519 self-signed references with the *historical* key identities, original signed key SHA, claimed valid UTC and log ID.
- Verify each exact original canonical signed checkpoint with `CES/EC353/LogCheckpoint/v1\0`, including `log_id`, original log-reference SHA, `previous_checkpoint_original_sha256`, `tree_size`, `root_hash_sha256`, issued UTC and log key; witness attestation with `CES/EC353/CheckpointWitness/v1\0`, including exact checkpoint SHA, witness-reference SHA, signed size/root, claimed witnessed UTC and witness key. These call the unchanged genuine EC353 production verifier functions.
- Rebuild the predecessor graph (GENESIS, acyclic, bounded, signed times, head/child relations) from **all supplied checkpoints**. Multiple signed roots, competing children, equal-size conflicting roots, rollback and missing/invalid consistency proofs retain adverse fork/append-only flags, not PASS. For each nongenesic append, use the exact old RFC6962 `consistency_proof` original to recompute `verify_consistency` on the original *signed* old/new roots and sizes. Exact equal-size/root steps may have `null` proof; missing changed-tree proofs are adverse. An invalid proof cannot be counted as successful append-only ancestry.
- Every inclusion proof MUST bind a presented genuine old signed checkpoint plus an actually reopened receiver-original EC352 leaf SHA and bytes, then call the unchanged EC353 `_parse_inclusion` and `verify_inclusion` with RFC6962 `SHA256(0x00 || original_bytes)` leaves and `SHA256(0x01 || left || right)` internal nodes. Truncated, redundant, wrong-leaf, wrong-root or wrong-index proofs are denied. We do **not** claim all leaves of the old external log or all historic EC352 records were supplied.
- Reopen the exact already-authenticated old EC354 signed challenge and gossip replies previously verified by live EC376. Require the challenge's `parent_publication_bundle_original_sha256` to equal the receiver-recovered historical EC353 unsigned bundle SHA; its `log_reference_original_sha256`, `checkpoint_original_sha256`, `tree_size` and `root_hash_sha256` to match genuine old log-signed checkpoint. A `checkpoint_view` reply must likewise match an actually witness-signed checkpoint under the challenged log, not just repeat an unsigned statement.
- Reopen all receiver-held original EC355 signed requests and responses verified by EC376. **Every** furnished checkpoint SHA must name an actually log-signed original; **every** furnished witness SHA must name that exact checkpoint's original witness-signed attestation. EC376's mandatory parent already opens the actual EC355/EC356 copies, lengths, signatures and ACKs; EC377 only *adds* genuine EC353 signature and Merkle ancestry, never claims to recreate the historical EC355/EC356 canonical results.
- Check signed causal publication/witness/challenge/reply/receipt timestamps as *claims* and flag backwards/stale claims as unresolved. Check cross-epoch same log ID key/reference continuity and that an advanced historic head proves previous head ancestry; external SHA/count/tree-head floors and all original SHA lists are separately pinned and retained, not inferred global latest status.

## CLI and required independent pins

Standalone:

```bash
python -I -B scripts/ces_cas_historical_transparency_archive.py derive-historical-transparency-inventory --help
python -I -B scripts/ces_cas_historical_transparency_archive.py audit-historical-transparency-archive --help
```

Fixed unified read-only console:

```bash
python -I -B scripts/ces_next.py audit-historical-transparency-archive DeliveryAudit AuditHistoricalTransparencyArchive --help
```

All previously required EC376 `audit` scalars and repeat lists are mandatory, **including its separately caller-retained `expected_retained_historical_disclosure_inventory_sha256`**. New required scalar inputs:

| Argument | Meaning |
| --- | --- |
| `--historical-transparency-archive-bundle-file` | Complete independent receiver archive, absolute normalized regular path |
| `--expected-historical-transparency-archive-bundle-sha256` | Outside-retained whole archive SHA |
| `--expected-retained-historical-transparency-inventory-sha256` | **Audit only:** independently retained canonical SHA of EC377's unsigned verified inventory |

Required repeated flags, **exactly one each per historical epoch**:

| Argument | Meaning |
| --- | --- |
| `--historical-transparency-publication-bundle-sha256` | Original EC353 unsigned old publication manifest SHA, known outside this archive |
| `--historical-transparency-log-key-inventory-sha256` | SHA of canonical sorted `[{'log_id', 'log_public_key_original_sha256','witness_public_key_original_sha256'}]` rows |
| `--historical-transparency-signed-head-inventory-sha256` | SHA of canonical sorted `[{'log_id', 'signed_head_original_shas': [sorted ...]}]` rows |
| `--minimum-historical-transparency-tree-size` | Independently retained common min signed head tree size (0..64) |
| `--minimum-historical-transparency-inclusion-count` | Independently retained min genuine old leaf inclusion proof count (0..24) |

The derive command outputs a deterministic **unsigned** canonical inventory and its SHA to be *retained by the caller outside the supplied original files*. The derive step **cannot** certify retention. The audit step compares the independently pinned SHA and reports mismatch as adverse; no trusted time, protected external read-only storage or historic institutional root is claimed.

## Result/status and deliberately limited proof

Every lawful result is `exit_code:2` and `<matching outcome>_unresolved`, with 8 deterministic ordered adverse flags, the last permanently true because **genuine old EC352→EC337 historic canonical ancestry is not reconstructed**. Invalid original bytes, wrong signed binding, unsafe origin path mapping and invalid inclusion are denied (`permission_denied/3`, `invalid_input/4` or `unavailable/5`). The fixed router rejects unexpected child response fields/values/sums and child process mismatches. Valid signatures do not repair inherited EC376…EC369 adverse outcomes.

Not certified: all genuine old EC352/351/…/337 parent signed records and their canonical historic results; all old EC353 leaves and missing hidden old heads; old EC353 log-key revocation (not part of the original EC353 checkpoint signature domain); full canonical old EC354/355/356 results; sender-side identities or old EC362 alternate copy locations; physical custody, trusted outside clock, official/legal log and witness independent institutions, global log census/latest status. Inherited 12 historic EC366 heavy tests, EC356 case24, EC317/318 unmocked deep fixtures, native PS7 original 15 Smoke, Windows/macOS/Git/CI/Provider E63–E66, network remote CAS/WORM and final user-assisted acceptance remain deferred. `EC249 INCOMPLETE`, `EC250 BLOCKED`, `B001 OPEN`, `Quality=false`, `NOT_STARTED` are unchanged.
