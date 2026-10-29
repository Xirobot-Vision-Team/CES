# EC364 - Replayable cross-EC361 publication windows and dual signed continuity

**V6.74 / R364 / EC-364.** This is a bounded, offline **audit**, not a publication operation or authority bootstrap. Every lawful audited outcome remains `unresolved` with exit code 2 even when all locally displayed material is coherent. No private signing key, trust-store lookup, internet or remote Provider/CAS/WORM writer is available to product code.

## Entry points

From the parent directory of the extracted `ces/` tree:

```sh
python -I -B ces/scripts/ces_cas_cross_epoch.py derive-cross-epoch-handoff [ALL EC363 audit-publication-history arguments]

python -I -B ces/scripts/ces_cas_cross_epoch.py audit-cross-epoch [ALL EC363 audit-publication-history arguments] \
  --cross-epoch-evaluation-utc 2026-10-26T18:00:00Z \
  --cross-epoch-bundle-file /absolute/path/cross-epoch-bundle.json \
  --expected-cross-epoch-bundle-sha256 <bundle-file-whole-SHA256> \
  --historical-ec362-snapshot-sha256 <historical-EC362-snapshot-whole-SHA256> \
  --signed-source-epoch-transition-sha256 <first-transition-file-whole-SHA256> \
  --signed-source-epoch-transition-sha256 <second-transition-file-whole-SHA256> \
  --minimum-retained-historical-epoch-count 1 \
  --expected-retained-oldest-ec362-result-sha256 <actual-historical-EC362-result-canonical-SHA256> \
  --expected-retained-current-ec362-result-sha256 <actual-current-EC362-result-canonical-SHA256> \
  --minimum-retained-directory-tree-size 6

python -I -B ces/scripts/ces_next.py audit-cross-epoch DeliveryAudit AuditCrossEpoch \
  [ALL EC363 arguments plus ALL EC364 audit arguments]
```

`derive-cross-epoch-handoff` performs the entire live EC363 true-signature replay, and returns an unsigned list of independently retained material to procure; it never constructs, signs or fabricates the historical windows. The standalone argparse interface copies all actual inherited EC363 audit arguments unchanged rather than maintaining an incomplete manually copied parent interface. The isolated unified interface fixes `DeliveryAudit AuditCrossEpoch` as action and mode, passes the same arguments to a fixed local `python -I -B` child, and revalidates its exact result/denial contract. Run `... audit-cross-epoch --help` to enumerate all inherited flags.

All `--historical-ec362-snapshot-sha256` and `--signed-source-epoch-transition-sha256` occurrences are **ordered SHA pins kept independently by the caller** in the same order as references in the bundle; they must be SHA-256 digests of the actual whole file bytes, not payload claim fields. New bounds: at most 2 earlier historical windows; at most 8 signed transition originals; at most 8 RFC6962 siblings per edge; bundle <=24,000 bytes, one snapshot <=80,000 bytes and one transition <=8,000 bytes. Historical `epoch_index` starts at integer zero and must be contiguous, with current window at `len(historical_parent_snapshots)`. A complete two-window review needs two distinct source transitions (`a`,`b`) and one direct append proof; three windows need four transitions and two proofs. Minimum independently retained historical epoch count must be 1..2; minimum directory tree size 1..64.

## Bundle: exact schema and file format

Bundle is unsigned but independently SHA-pinned as a whole. Every child file must be independently pinned in the matching ordered repeated command-line parameter. JSON files are strict canonical payloads with no duplicate keys or unknown fields.

```json
{
  "schema": "ces.ec364.pinned_cross_epoch_publication_windows.v1",
  "current_ec363_canonical_result_sha256": "<canonical SHA of fresh current EC363 audit result>",
  "historical_parent_snapshots": [
    {"path": "/abs/snapshots/old-ec362-inputs.json", "sha256": "<whole snapshot SHA>"}
  ],
  "signed_source_transitions": [
    {"path": "/abs/bridges/old-new-a.json", "sha256": "<whole signed event SHA>"},
    {"path": "/abs/bridges/old-new-b.json", "sha256": "<whole signed event SHA>"}
  ],
  "directory_window_proofs": [
    {
      "from_epoch_index": 0,
      "to_epoch_index": 1,
      "older_checkpoint_original_sha256": "<older true signed checkpoint whole-file SHA>",
      "newer_checkpoint_original_sha256": "<newer true signed checkpoint whole-file SHA>",
      "audit_path_sha256": ["<one RFC6962 SHA256 consistency proof sibling>"]
    }
  ]
}
```

Proof `audit_path_sha256` entries are actual RFC6962 SHA256-CT sibling hashes from the *same* tree with the exact two verified endpoint sizes and roots; there is no claimed proof validity flag or third-party proof shortcut. For each adjacent window one direct proof is required and its end points must be the two directory-signature-verified `a` checkpoints; source `b` has to agree with those signed heads as part of per-window coherence. Source directory signer SHA must be unchanged across an edge. Directory signer rotation is **not** authorized by a publisher-source custodian `rotate` event and will not produce local coherence.

## Historical snapshot: exact format and replay requirement

```json
{
  "schema": "ces.ec364.historical_ec362_replay_inputs.v1",
  "epoch_index": 0,
  "ec362_audit_inputs": {
    "...": "every required and optional Python keyword used to call the actual EC362 custody.audit, not just a result or pass flag"
  }
}
```

The `ec362_audit_inputs` object must contain **exactly the same set of keyword names** as the current live EC362 audit call extracted from the provided EC363 arguments. Values are that historical epoch's independently held evidence file paths, independent whole-file SHA pins, retained floors and its original caller UTC claim. A bare `PASS`, result JSON, truncated snapshot, or newer same-parent EC363 manifest cannot substitute. The audit actually calls `publication_custody.custody.audit(**historical_inputs)`, re-running EC361 through EC337 true signed originals; then it re-opens each verified custodian key, source-signed manifest, signed checkpoint and both signed observer receipt originals and rechecks their roles. Current EC363 and current EC362 are also separately genuinely rerun. Earlier historical parent result SHA is canonical SHA256 of the actual returned EC362 result. Invalid genuine cryptographic originals are rejected rather than marked success.

Historical material must be provided as independently SHA-pinned absolute regular paths, not symlink paths or symlink ancestors. Previously checked original paths / inode roles and all newly loaded hashes receive final reread checks; a set of separate original files does not guarantee atomic filesystem snapshots or external physical custody.

## Dual-custodian transition signed event: exact fields

```json
{
  "schema": "ces.ec364.dual_custodian_cross_epoch_transition.v1",
  "source_slot": "a",
  "claimed_source_id": "<the exact same unverified source ID at both signed endpoints>",
  "from_epoch_index": 0,
  "to_epoch_index": 1,
  "event_kind": "rotate",
  "from_parent_ec361_canonical_result_sha256": "<true old EC361 parent result SHA>",
  "to_parent_ec361_canonical_result_sha256": "<true new EC361 parent result SHA>",
  "from_manifest_original_sha256": "<true old source-signed manifest whole-file SHA>",
  "to_manifest_original_sha256": "<true new source-signed manifest whole-file SHA>",
  "from_custodian_public_key_original_sha256": "<true old source custodian key file SHA>",
  "to_custodian_public_key_original_sha256": "<true new source custodian key file SHA>",
  "from_checkpoint_original_sha256": "<true old directory-signed checkpoint whole-file SHA>",
  "to_checkpoint_original_sha256": "<true new directory-signed checkpoint whole-file SHA>",
  "issued_utc": "2026-10-26T11:20:00Z",
  "expires_utc": "2026-10-27T11:20:00Z",
  "signature_old_custodian_ed25519_hex": "<128 lower-case hex chars>",
  "signature_new_custodian_ed25519_hex": "<128 lower-case hex chars>"
}
```

**Both** genuine Ed25519 signatures cover exactly the same deterministic message:

```text
b"CES/EC364/DualCustodianCrossEpochTransition/v1\x00" +
  canonical_json(event_without_both_signature_fields)
```

Canonical JSON is `json.dumps(body,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')` as implemented in the inherited canonical helper. Each true endpoint key is read from the actually replayed and SHA-pinned historic/current EC362 originals; no key taken from the event can self-authorize a replacement. The timestamp is a **signed self-claim** over a bounded interval (max 7 days), not a trusted external clock. The auditor compares it with actual presented signed source/observer timeline; discrepancies remain unresolved. `carry` requires unchanged key, `rotate` requires actual key change, and any authenticated `terminate` is terminal for continuity: it cannot silently authorize a later resumed publication. Unexpected edges, false source or parent SHA, and invalid cryptographic signatures are denied; visible duplicate authentically signed events and missing edges cannot be resolved by electing a convenient branch.

## Classification and trust limitations

Result schema `ces.ec364.offline_cross_epoch_publisher_continuity_unresolved.v1`; denial schema `ces.ec364.offline_cross_epoch_publisher_continuity_denial.v1`; handoff schema `ces.ec364.unsigned_cross_epoch_continuity_handoff.v1`. Returned `epoch_reviews` expose the true replayed EC362/EC361 result SHAs, signed checkpoints and actual key/manifests for each epoch. `signed_transition_reviews` expose verified two-key signatures and kind/time anomalies; `adjacent_directory_consistency_proofs_verified` is an actual proof count. Flags report historical replay inconsistency, visible dual-signed forks, external retained-floor rollback, key role collision, real directory-signed forks, missing/invalid proof, signed termination, clock anomaly and missing independently supplied materials. `locally_coherent_cross_epoch_signed_publication` is true only if current EC363 disclosures, every historical EC362 replay, all signed events and all adjacent proofs are locally reconciled **with no displayed flag**. Every lawful result stays `exit_code=2`; denial status `permission_denied / invalid_input / unavailable` exits 3/4/5, never exit 0.

Local pinned Ed25519 keys, even with perfect signatures, can **never establish** real public source identity, authorized official directory root, legally independent custodians/observers, true physical custody, trusted UTC, a globally latest/complete record, all-world revocation completeness or absence of hidden forks. No online validation, source-chain fetching, writes to remote provider/CAS/WORM, private signing or OS institutional trust-store lookup. Native PowerShell V4.60/R150, EC249 INCOMPLETE, EC250 BLOCKED, B001 OPEN, Quality=false and final NOT_STARTED are unchanged. EC356 case24, EC317/318 inherited deep MOCK, native PS7/15 Smoke, Windows/macOS/Git/CI/Provider/E63-E66, external real-root/custody/time and human acceptance remain explicitly deferred.
