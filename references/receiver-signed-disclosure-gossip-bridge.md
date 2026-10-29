# EC376 receiver-only old EC354 gossip / EC355 request–receipt–EC356 ACK bridge

## Objective and authority boundaries

This protocol accepts already possessed, independently SHA-pinned *original historical files* held on the receiver filesystem. It reuses the actual EC354 and EC355 Ed25519 **verification** domains and invokes the actual EC375 production audit first. It does not reissue old signed records or sign with test keys in production. The new archive JSON is **unsigned** and its own SHA is independently supplied by the caller; its job is an exact byte-to-original inventory map, never a trusted attestation. One EC only, offline; lawful status always `*_unresolved`, process exit `2`.

The old EC354 and EC355 unsigned manifests are reopened by their **new receiver-owned file path** and outside pinned original SHA-256. **Embedded `auditor_public_key`, `auditor_reference`, `challenge`, `replies`, `request`, `receipt`, `checkpoint`, `witness_statement`, `consistency_proof` old-manifest object paths remain *untrusted sender labels*.** Their SHA-256 **claims** must equal corresponding receiver-side original pin SHA, but **no sender label is opened**. Every receiver path is subject to the inherited regular-file/no-symlink, normalized path, bounded length, immutable whole-byte SHA, inode/late reread rules. Any historical label aliased to an opened receiver path is invalid.

## CLI contract

```
python -I -B scripts/ces_cas_historical_disclosure_archive.py derive-historical-disclosure-inventory [ALL_REQUIRED_FLAGS]
python -I -B scripts/ces_cas_historical_disclosure_archive.py audit-historical-disclosure-archive [ALL_REQUIRED_FLAGS]
python -I -B scripts/ces_next.py audit-historical-disclosure-archive DeliveryAudit AuditHistoricalDisclosureArchive [ALL_REQUIRED_FLAGS]
```

All commands accept the complete exact EC375 parent scalar/repeat input set (`scripts/ces_cas_historical_custody_archive.py ... --help`), including the *independently retained previous EC375 verified inventory SHA*. In addition, supply:

| Flag | Meaning |
| --- | --- |
| `--historical-disclosure-archive-bundle-file` | Full, normalized absolute path to receiver EC376 archive, local regular file |
| `--expected-historical-disclosure-archive-bundle-sha256` | Externally retained whole-file SHA-256 for it |
| `--historical-disclosure-gossip-bundle-sha256` | Repeat once per historical epoch: outside-original SHA for old EC354 unsigned manifest |
| `--historical-disclosure-request-bundle-sha256` | Repeat once per historical epoch: outside-original SHA for old EC355 unsigned manifest |
| `--historical-disclosure-auditor-key-inventory-sha256` | Repeat per epoch: canonical SHA of sorted signed-auditor ID/key-SHA inventory |
| `--minimum-historical-disclosure-request-count` | Repeat per epoch: independent lower bound, integer 0–24 |
| `--minimum-historical-disclosure-receipt-count` | Repeat per epoch: independent lower bound, integer 0–36 |
| `--expected-retained-historical-disclosure-inventory-sha256` | **Audit only**: independent externally retained hash of canonical derived unsigned verified inventory |

The outer archive is canonical strict JSON with exact fields:

```
{
  "schema": "ces.ec376.receiver_historic_ec355_disclosure_original_archive.v1",
  "parent_ec375_canonical_result_sha256": "<sha256-of-actual-live-EC375-report>",
  "ec375_historical_custody_archive_original_sha256": "<sha256-of-real-prior-EC375-archive>",
  "claimed_directory_lineage_id": "<matches-EC375-receiver-parent-claimed-lineage>",
  "epochs": [{
    "epoch_index": 0,
    "ec354_gossip_bundle_original": {"path":"<receiver-path>","sha256":"<outside-original-sha>"},
    "ec355_disclosure_bundle_original": {"path":"<receiver-path>","sha256":"<outside-original-sha>"},
    "auditors": [{"auditor_id":"<old-id>",
      "public_key_original":{"path":"<receiver-path>","sha256":"<original-sha>"},
      "signed_reference_original":{"path":"<receiver-path>","sha256":"<original-sha>"}}],
    "exchanges": [{"signed_challenge_original":{"path":"<receiver-path>","sha256":"<original-sha>"},
      "signed_reply_originals":[{"path":"<receiver-path>","sha256":"<original-sha>"}]}],
    "disclosure_requests": [{"signed_request_original":{"path":"<receiver-path>","sha256":"<original-sha>"},
      "responses": [{"signed_receipt_original":{"path":"<receiver-path>","sha256":"<original-sha>"},
        "checkpoint_original":{"path":"<receiver-path>","sha256":"<original-sha>"},
        "witness_original":{"path":"<receiver-path>","sha256":"<original-sha>"},
        "consistency_original": null}]}]
  }]
}
```

The above illustrates **structure only**; placeholder values are not executable evidence. Source files themselves supply exact genuine preexisting `ces.ec354.*` and `ces.ec355.*` schema bodies and original historic signing domains; every old manifest element count/order must exactly match the receiver array. The child `--help` is authoritative for inherited upstream flags.

## Signed causality and insufficient proof

An EC354 `auditor_reference` signature is validated against its actual Ed25519 key and historical declared validity. Genuine challenger-signed `challenge`, responder-signed `reply` (including proper challenge SHA), bounded challenge predecessor/nonces, and declared source IDs/UTC are checked. The EC354 `reply` is a signed *checkpoint claim*, not a log signature. EC355 signed `request` must bind the actual EC354 manifest SHA, exact signed reply/claim, challenger identity, respondent or nonparticipant peer role, predecessor chain and declared UTC. Signed `receipt` must bind the actual request SHA and correct historical responder, exact supplied bytes and lengths (or strict nonfurnished nulls), and causal UTC. Optional consistency proof receives byte-SHA validation only, **not** full RFC6962 or old EC353 checkpoint/witness verification.

For every `source_a` and `source_b` authenticated EC356 ACK in the old EC375 archive, EC376 reopens its original unchanged signed body; its EC355 request SHA, receipt SHA, gossip reply SHA, `parent_disclosure_bundle_original_sha256`, role, log ID, checkpoint/witness SHA and lengths **must** equal the actual EC355 cryptographic originals and actual receiver-held original copies. All ACKs must have a linked request/receipt, and distinct custody channels with different disclosure roles must agree on the same checkpoint/witness SHA pair. Claims and receipts outside ACK-selected heads are still inventoried for adverse visibility. External per-epoch SHA pins and count floors cannot be synthesized by the verifier itself.

`derive-historical-disclosure-inventory` exports the **unsigned** `unsigned_verified_historical_disclosure_inventory` and `receiver_verified_historical_disclosure_inventory_sha256`; retain this digest **independently** and supply it back to `audit`. A digest generated and re-used in the same malicious context proves no outside provenance, no global latest, and no absence of omitted historical originals. Signed original claims do not prove official institution independence, physical custody or independently trusted time. Parent EC375 and all deeper adverse flags are retained; no valid new signature can clear a prior signed revoke/dispute. In particular **the full old EC353→EC337 cryptographic ancestral replay and historical EC355/EC356 canonical result reconstruction are NOT provided**.

## Local tested construction boundary

The EC376 focused test suite supplies genuinely newly signed EC354 auditor/challenge/reply and EC355 request/receipt originals using **test-only ephemeral keys**; the production code only calls public-key Ed25519 *verify*. It also exercises false signature bytes, SHA mismatches, malicious receiver/old path roles, wrong cross-ACK joins, outside SHA/count drift and isolated `python -I -B` routes. The two lawful isolated children really execute production EC375→EC369. Older EC366→EC337 fixture is deliberately mocked; no unrun end-to-end assertion is implied. Inspect `construction/EC376_LOCAL_REPORT.json` for exact observed checks.
