# EC365 protocol — independently retained directory authority lineage, old/new dual-signatures and cross-root RFC6962

**Construction V6.75 / R365 / EC365, exclusively read-only.** EC364 correctly refuses to declare cross-epoch directory append-only continuity if the actual directory public-key original SHA changes. EC365 does *not* modify EC364's answer or assume the key replacement is authorized. It independently executes **all of EC364's current EC363 and historical EC362…EC337 cryptographic replay**, re-opens the true SHA-pinned source manifests and both directory-signed checkpoint copies in every displayed epoch, and layers a narrow old-and-new-directory-Ed25519 signed delegation/retirement protocol on top. All lawful reports remain `exit_code=2`, `unresolved`. The actual official origin of these caller-pinned roots, physical custody, trusted UTC and global completeness remain **NOT_PROVEN**.

## Entry points

```sh
python -I -B ces/scripts/ces_cas_directory_authority.py derive-directory-authority-handoff \
  [ALL required/optional EC364 audit-cross-epoch flags]

python -I -B ces/scripts/ces_cas_directory_authority.py audit-directory-authority \
  [ALL required/optional EC364 audit-cross-epoch flags] \
  --directory-lineage-evaluation-utc 2026-10-26T07:50:00Z \
  --directory-authority-bundle-file /absolute/external/pinned-handoffs.json \
  --expected-directory-authority-bundle-sha256 <whole-file-SHA256> \
  --epoch-directory-root-sha256 <old-epoch-directory-public-key-whole-SHA256> \
  --epoch-directory-root-sha256 <new-epoch-directory-public-key-whole-SHA256> \
  --epoch-source-a-manifest-sha256 <old-source-a-original-whole-SHA256> \
  --epoch-source-a-manifest-sha256 <new-source-a-original-whole-SHA256> \
  --epoch-source-b-manifest-sha256 <old-source-b-original-whole-SHA256> \
  --epoch-source-b-manifest-sha256 <new-source-b-original-whole-SHA256> \
  --epoch-signed-checkpoint-sha256 <old-verified-copied-checkpoint-whole-SHA256> \
  --epoch-signed-checkpoint-sha256 <new-verified-copied-checkpoint-whole-SHA256> \
  --signed-directory-handoff-sha256 <one-actual-both-signatures-event-whole-SHA256> \
  --minimum-retained-directory-root-generation 1 \
  --expected-retained-initial-directory-root-sha256 <old-directory-root-whole-SHA256> \
  --expected-retained-current-directory-root-sha256 <new-directory-root-whole-SHA256> \
  --minimum-retained-latest-directory-tree-size 6

python -I -B ces/scripts/ces_next.py audit-directory-authority \
  DeliveryAudit AuditDirectoryAuthority [ALL inherited EC364 and new audit flags]
```

The derivation front door replays the **real** EC364 parent and returns an unsigned caller procurement checklist, not a signed delegation. The fixed unified route accepts only `DeliveryAudit AuditDirectoryAuthority`, launches this package's fixed local script under `python -I -B`, and validates its exact single-JSON response, real child exit code, epoch/transition/flag relationships and denial contract. No caller-program path, signer route or remote writer is exposed. `cryptography` and `asn1crypto` are used by inherited true cryptographic auditors. `--help` enumerates all inherited flags; `--directory-lineage-evaluation-utc` is an explicit *caller-claimed* UTC evaluation instant.

## Independent retention and replay boundaries

The EC365 auditor never accepts a claimed parent `PASS` JSON. `cross_epoch.continuity.audit(...)` actually replays fresh EC363 and every caller-SHA-pinned older EC362 parent input snapshot, including their EC361…EC337 signature/proof checks. Then EC365 separately reads the exact old/new directory signer 32-byte public-key originals, source `a`/`b` custodian public-key originals and genuinely signed manifest bytes, and each source's original copied directory checkpoint, verifying both signed checkpoints under the key actually used in that epoch. It verifies these against the returned true EC364 canonical result, actual epoch rows and direct source pub/manifests/copy SHA. The boundary is bounded to at most two historical EC362 snapshots, thus two or three total source+directory epochs.

For each epoch, the *caller must independently retain and pass*, in epoch order, **four SHA streams** (not values learned from the new unsigned handoff bundle): directory key original, source-A signed manifest original, source-B signed manifest original, and actually signed `a`/`b`-agreed checkpoint original. Each stream must cover exactly the same actual epoch count, even where a root stays unchanged for a `carry` edge. A caller's oldest/current directory public-key whole-file SHA, minimum signed latest tree size, and minimum root-change generation protect against a presented rollback; comparisons against *actual replayed originals* are mandatory. A mismatch, insufficient generation, missing stream or higher retained tree-size floor yields explicit unresolved rollback rather than a substituted value from a bundle. Reusing a *retired* signer in a later noncontiguous epoch is a lineage collision even if the newly displayed Ed25519 signatures are cryptographically genuine.

The externally pinned `directory-authority-bundle-file` has **exact fields**:

```json
{
  "schema": "ces.ec365.pinned_directory_authority_handoffs.v1",
  "parent_ec364_canonical_result_sha256": "<SHA256(canonical JSON of genuinely replayed EC364 report)>",
  "claimed_directory_lineage_id": "<directory_id from verified old AND new signed originals>",
  "signed_directory_handoffs": [
    {"path": "/abs/signed-old-new-directory-handoff.json", "sha256": "<actual whole-file SHA256>"}
  ]
}
```

Every referenced event has a separate, ordered whole-file `--signed-directory-handoff-sha256` external pin. Up to **five** signed events may be presented, including multiple contradictory valid ones; for an unambiguous local chain there must be exactly **one genuine event per adjacent epoch edge**. Contradictory old-and-new authentically signed events are all verified and reported as an actual signed fork; no favorable event is selected. Every event is bounded to 9,000 bytes, the bundle to 16,000 bytes.

## Exact domain-separated dual-directory-signer event

A canonical JSON object has **exactly** the following fields and no others:

```json
{
  "schema": "ces.ec365.dual_signed_directory_authority_handoff.v1",
  "claimed_directory_lineage_id": "unofficial_synthetic_directory",
  "from_epoch_index": 0,
  "to_epoch_index": 1,
  "event_kind": "delegate_and_retire",
  "from_root_generation": 0,
  "to_root_generation": 1,
  "from_directory_public_key_original_sha256": "<SHA of actual previously directory-signing old key original>",
  "to_directory_public_key_original_sha256": "<SHA of actual newly directory-signing new key original>",
  "from_parent_ec361_canonical_result_sha256": "<SHA of true old EC361 audit result>",
  "to_parent_ec361_canonical_result_sha256": "<SHA of true new EC361 audit result>",
  "from_checkpoint_original_sha256": "<whole-file SHA of actual old signed checkpoint copy>",
  "to_checkpoint_original_sha256": "<whole-file SHA of actual new signed checkpoint copy>",
  "from_tree_size": 5,
  "to_tree_size": 6,
  "from_merkle_root_sha256": "<old actual directory-signed RFC6962 root SHA>",
  "to_merkle_root_sha256": "<new actual directory-signed RFC6962 root SHA>",
  "from_source_a_manifest_original_sha256": "<actual true old publisher A manifest SHA>",
  "from_source_b_manifest_original_sha256": "<actual true old publisher B manifest SHA>",
  "to_source_a_manifest_original_sha256": "<actual true new publisher A manifest SHA>",
  "to_source_b_manifest_original_sha256": "<actual true new publisher B manifest SHA>",
  "cross_epoch_consistency_proof_canonical_sha256": "<SHA of canonical exact EC364 direct proof object for this edge>",
  "issued_utc": "2026-10-26T07:10:00Z",
  "expires_utc": "2026-10-27T00:00:00Z",
  "signature_old_directory_ed25519_hex": "<128 lowercase hex chars>",
  "signature_new_directory_ed25519_hex": "<128 lowercase hex chars>"
}
```

For both old and new authentic signers, verify Ed25519 signatures over **the same** message:

```python
b"CES/EC365/DualSignedDirectoryAuthorityHandoff/v1\x00" + \
    canonical_json(event_without_both_signature_fields)
```

`canonical_json` is the existing deterministic ASCII JSON canonicalization, with sorted keys, compact separators, ASCII escapes and `allow_nan=False`. The verifier reads actual old and new directory public-key originals and never trusts a key claimed only inside the event. Event edge indexes, root-change generation, parent EC361 canonical hashes, source A/B manifest SHA, *both* signed-checkpoint whole-file SHA, signed tree size/root SHA and the precise direct RFC6962 proof are all bound into those two true signatures. An incorrect endpoint or forged old/new signature is denied (`permission_denied`); a genuinely signed wrong `carry`/generation/terminal characterization remains explicitly unresolved. A changed root must use `delegate_and_retire`; an unchanged root must use `carry`. `terminal_retirement` is irrevocably noncoherent for displayed later publication, even if both signatures are valid.

A directory signer handoff is **not** a source-custodian key rotation (EC364's source transition uses completely different keys/domains). Old and new directory roots cannot be sourced from an unpinned self-signed replacement or a merely favorable issuer/site string. The directory ID remains a signed *claim* checked for consistency, not proof of real official legal authority.

## Proof and failure semantics

Each EC364 adjacent proof is read from the **independently whole-SHA-pinned original EC364 bundle** and independently compared to two source-agreed *actually directory-signed* checkpoints. EC365 directly re-verifies the SHA256-CT/RFC6962 consistency path on exact old/new signed tree sizes/roots even when signer keys differ, and requires strict tree growth and a distinct EC361 canonical parent. The event includes the canonical SHA of precisely that proof, so two signers cannot silently delegate over an unbound alternative proof. All displayed true same-size divergent roots, source signed forks and inherited EC364 history/termination/rollback/role/timeline failures remain unresolved. EC365 may remove **only** EC364's cross-window proof failure caused by different directory signer keys, if every direct cryptographic proof actually works; it never flips EC364's report itself to `PASS`.

`epoch_lineage_reviews`, `signed_directory_handoff_reviews`, true verified proof/event counts, 10 explicit defect flags and an ordered `outcome_counts` for the two inherited channels are returned. `locally_authorized_directory_signer_transition=true` requires a real key change, complete separately retained SHA streams and floors, one dual-signed event per adjacent edge, valid proof for *every* edge, correct generation/roles, no terminal/clock/fork/missing/parent defect. Yet even that result returns **exit code 2**, never 0 or a legal assertion. `permission_denied` / `invalid_input` / `unavailable` produce denial exit 3 / 4 / 5. Signed timestamps are untrusted claims; no key store, internet retrieval, private signing, OS chain bootstrapping or remote Provider/CAS/WORM operations.

**Deferred and NOT_PROVEN:** real institutional ownership/authorized change of public directory signers, legal and physical institutional independence/custody, trusted UTC, globally latest and complete log, no hidden forks, earlier EC356 case24, inherited EC317/318 deep production MOCK replacement, original native PS7/15 Smoke, Windows/macOS/Git/CI/Provider/E63-E66, remote CAS/WORM and final human acceptance. EC249 `INCOMPLETE`, EC250 `BLOCKED`, B001 `OPEN`, Quality=false and final `NOT_STARTED` all remain unchanged.
