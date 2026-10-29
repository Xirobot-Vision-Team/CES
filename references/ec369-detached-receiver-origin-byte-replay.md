# EC369 protocol — detached receiver-only verified copies and dual-signed disclosure

## Goal and exact trust boundary

EC368 historically requires reopening original sender paths and executing its true EC367→EC337 upstream parent. The separate **EC369** offline command deliberately operates when the sender's original files and EC365/EC337-era archive are **not** present. Only the **specified EC366 source and EC367 witness signing layer, their receiver-held byte copies, EC368 signed receipt history and the new EC369 source-map/disclosure layer** are reverified. The old original SHA/path references inside these copied manifests are compared as **signed data labels**; the auditor must not open them. A copied document containing a claimed old directory checkpoint digest does not constitute verification of that original checkpoint's signature, full historical publisher chain, or any legal/custody claim. Even perfect local consistency always ends with exit **2 unresolved**.

This is a read-only verifier. A separate sender/receiver application must **pre-create** the source files and genuinely sign them with the relevant parties' own Ed25519 private keys; this program does **not** generate, accept, store or unlock private key material. To make a missing-original audit possible, copy the bounded set and record original source SHA/path labels **before** those original files disappear. Keep all independent pins outside the delivered bundle and ideally away from the sender who assembles the bundle.

## 1. Exact outer bundle

A bounded UTF-8 strict JSON file, externally SHA-256 pinned by `--expected-detached-bundle-sha256`:

```json
{
  "schema": "ces.ec369.detached_receiver_bundle.v1",
  "signed_copy_map_original": {"path":"/receiver/signed-map.json", "sha256":"<64-hex>"},
  "handoffs": [
    {"sender_dispatch_original":{"path":"/receiver/dispatch.json", "sha256":"<64-hex>"},
     "receiver_ack_original":{"path":"/receiver/receipt.json", "sha256":"<64-hex>"}}
  ],
  "disclosure_challenges": [
    {"receiver_challenge_original":{"path":"/receiver/challenge.json", "sha256":"<64-hex>"},
     "sender_disclosure_original":{"path":"/receiver/answer.json", "sha256":"<64-hex>"}}
  ]
}
```

JSON samples use `<64-hex>` as explanatory placeholders, not executable input. All objects must contain **exactly** their declared fields; no extra aliases. File SHA pins address exact full raw byte representations. `handoffs` holds 1–4 chronological EC368 sender/receiver original pairs; `disclosure_challenges` holds 1–4 chronological EC369 challenge/answer pairs. EC368 handoff wire formats and signature domains are unchanged; see [EC368](ec368-offline-portable-receiver-status-handoff.md).

## 2. Sender-signed source-to-copy map

Exactly these fields:

- `schema`: `ces.ec369.sender_signed_source_to_receiver_copy_map.v1`;
- `claimed_sender_id`, `sender_public_key_original_sha256`, `claimed_receiver_id`, `receiver_public_key_original_sha256`;
- `parent_ec367_canonical_result_sha256`, `parent_ec366_canonical_result_sha256`, `parent_ec365_canonical_result_sha256`;
- `portable_inventory_canonical_sha256`, `witness_head_original_shas` (ordered two slots);
- `institution_root_public_key_original_shas`, `witness_public_key_original_shas`, `institution_claimed_ids`, `witness_claimed_ids` (each an ordered two-slot list);
- `originals`: a bounded, precisely ordered list of **8–52** rows, each with exactly `kind`, `source_original`, `byte_length`, `receiver_copy`, where both references use `{"path":"...", "sha256":"..."}` and the SHA of the source original MUST equal the receiver copy SHA; `byte_length` MUST equal the actually opened receiver file byte length;
- `issued_utc`, `expires_utc` (claimed clock, maximal seven-day window);
- `signature_sender_ed25519_hex` (128 lowercase hex characters), computed over the exact canonical JSON **without the signature field**, prefixed by `b'CES/EC369/DetachedSourceCopyMap/v1\x00'`.

`source_original.path` is a normalized absolute **historical string only**; it may not exist. `receiver_copy.path` must be a separate accessible file, with bounded size and content SHA. The auditor rejects any aliases of origin labels to the current bundle, keys or receiver copies. It reconstructs the precise complete EC368 inventory roles from the **two receiver-copied original EC366 and EC367 manifests**: EC366 bundle, both institution public keys and all their signed source status and provenance originals, EC366 extra checkpoint originals, EC367 distribution bundle, both witness public keys and all their signed witness epochs, and every EC367 additional source-signed status. No sender-selected partial inventory or reordering counts as complete. The EC366 extra checkpoint originals are SHA-checked as bytes, **not** given a fictitious verified directory signature.

The portable inventory canonical SHA comes from the EC368 inventory schema `ces.ec368.portable_receiver_original_byte_inventory.v1` (see implementation's `previous.INVENTORY_SCHEMA`). It binds ordered `{kind, source_original_sha256, byte_length}` items and the EC367 parent result SHA. The independent external expected SHA must match this newly derived digest and the sender signature.

## 3. Receiver challenge and sender answer

The **receiver challenge** has exactly:

- `schema`: `ces.ec369.receiver_signed_detached_disclosure_challenge.v1`;
- `claimed_sender_id`, `sender_public_key_original_sha256`, `claimed_receiver_id`, `receiver_public_key_original_sha256`;
- `sequence` from zero, `previous_challenge_original_sha256`, `previous_answer_original_sha256` (both null at genesis, both equal prior pair's true original SHAs afterward);
- `signed_copy_map_original_sha256`, `portable_inventory_canonical_sha256`, `parent_ec367_canonical_result_sha256`;
- `receiver_nonce_sha256` (SHA-256 formatted 64-hex string; caller must independently retain the latest expected value; **not** a trusted real-time freshness oracle);
- `challenged_source_original_shas`: *entire map inventory source SHA stream in exact order*, no omission;
- `issued_utc`, `expires_utc` as untrusted bounded claimed timestamps;
- `signature_receiver_ed25519_hex`, signing `b'CES/EC369/DetachedReceiverChallenge/v1\x00' + canonical_json(unsigned_challenge)`.

The **sender answer** repeats all parties, keys, `sequence`, both previous hashes, map/inventory/parent SHA and nonce, but uses:

- `schema`: `ces.ec369.sender_signed_detached_disclosure_answer.v1`;
- `receiver_challenge_original_sha256` = **exact current challenge original SHA**;
- `disclosure_state`: must be `provided` to qualify locally; signed withholding/dispute stays visible;
- `disclosed_source_original_shas`: the same **complete ordered original SHA inventory**, with no omission;
- `answered_utc`, `expires_utc` as untrusted claimed timestamps;
- `signature_sender_ed25519_hex`, signing `b'CES/EC369/DetachedSenderAnswer/v1\x00' + canonical_json(unsigned_answer)`.

Both kinds use real Ed25519 public-key-file byte values pre-pinned by the caller; the domains are deliberately different from one another and from EC368. The challenge/answer signed files and original-SHA streams must be independently pinned and supplied oldest-first. Forks, gaps, duplicate nonce, mismatch with the signed map or original request and withheld disclosure prevent a locally consistent result, but are not upgraded to a legal proof just because the signature is authentic.

## 4. Offline read-only command

Run from the extracted `ces/` package root with Python and project dependencies installed. **Every flag listed below is required.** Repeated options must be passed separately and in true original chronological or role order. `none` is permitted *only* for an unavailable source attestation head slot; two slots are always required. Each `<...>` is a descriptive placeholder and must be replaced with an actual value supplied from independently preserved records.

```sh
python -I -B scripts/ces_cas_detached_receiver.py audit-detached-receiver \
  --detached-evaluation-utc 2026-10-26T13:00:00Z \
  --detached-bundle-file /receiver/ec369-bundle.json \
  --expected-detached-bundle-sha256 <BUNDLE_SHA256> \
  --expected-signed-copy-map-sha256 <MAP_SHA256> \
  --expected-portable-inventory-sha256 <INVENTORY_SHA256> \
  --expected-parent-ec367-canonical-result-sha256 <EC367_SHA256> \
  --expected-parent-ec366-canonical-result-sha256 <EC366_SHA256> \
  --expected-parent-ec365-canonical-result-sha256 <EC365_SHA256> \
  --sender-public-key-file /receiver/sender-ed25519.pub \
  --expected-sender-public-key-sha256 <SENDER_KEY_SHA256> \
  --claimed-sender-id SenderClaimOnly \
  --receiver-public-key-file /receiver/receiver-ed25519.pub \
  --expected-receiver-public-key-sha256 <RECEIVER_KEY_SHA256> \
  --claimed-receiver-id ReceiverClaimOnly \
  --expected-retained-sender-dispatch-head-sha256 <SENDER_DISPATCH_HEAD_SHA256> \
  --expected-retained-receiver-ack-head-sha256 <RECEIVER_ACK_HEAD_SHA256> \
  --minimum-retained-sender-dispatch-sequence 0 \
  --minimum-retained-receiver-ack-sequence 0 \
  --expected-retained-challenge-head-sha256 <CHALLENGE_HEAD_SHA256> \
  --expected-retained-answer-head-sha256 <ANSWER_HEAD_SHA256> \
  --expected-retained-challenge-nonce-sha256 <NONCE_SHA256> \
  --minimum-retained-challenge-sequence 0 \
  --institution-root-public-key-sha256 <SOURCE_A_KEY_SHA256> \
  --institution-root-public-key-sha256 <SOURCE_B_KEY_SHA256> \
  --witness-public-key-sha256 <WITNESS_A_KEY_SHA256> \
  --witness-public-key-sha256 <WITNESS_B_KEY_SHA256> \
  --institution-claimed-id SourceAClaimOnly \
  --institution-claimed-id SourceBClaimOnly \
  --witness-claimed-id WitnessAClaimOnly \
  --witness-claimed-id WitnessBClaimOnly \
  --expected-source-status-head-sha256 <SOURCE_A_STATUS_HEAD> \
  --expected-source-status-head-sha256 <SOURCE_B_STATUS_HEAD> \
  --expected-source-attestation-head-sha256 <SOURCE_A_ATTEST_HEAD_OR_none> \
  --expected-source-attestation-head-sha256 <SOURCE_B_ATTEST_HEAD_OR_none> \
  --expected-witness-head-sha256 <WITNESS_A_HEAD> \
  --expected-witness-head-sha256 <WITNESS_B_HEAD> \
  --signed-sender-dispatch-sha256 <DISPATCH_EPOCH0_SHA256> \
  --signed-receiver-ack-sha256 <ACK_EPOCH0_SHA256> \
  --signed-challenge-sha256 <CHALLENGE_EPOCH0_SHA256> \
  --signed-answer-sha256 <ANSWER_EPOCH0_SHA256>
```

For a two-epoch sequence, add a second occurrence of **each of the relevant signed SHA-stream flags**; raise external heads, nonces and sequence floors as independently retained. The fixed consolidated command is:

```text
python -I -B scripts/ces_next.py audit-detached-receiver \
  DeliveryAudit AuditDetachedReceiver [ALL FLAGS ABOVE]
```

The fixed unified route validates the child request and response and invokes only the fixed `python -I -B` standalone script; no caller-controlled interpreter or child executable. The actual original SHA stream and `signed_copy_map_original` SHA must already be separately known; **the map and current bundle are not replacements for independent trust anchors**.

## 5. Results, verification limits, and operator caution

| Exit code | Interpretation |
| --- | --- |
| `2` | Cryptographic inputs are structurally valid; the result reports **unresolved**, including when the local signature/copy/receipt/disclosure checks all agree. Conflict flags remain independently visible. |
| `3` | `permission_denied`: unauthenticated, forbidden, missing/different protected content or mismatched integrity. |
| `4` | `invalid_input`: invalid/unsupported required input or strict wire format. |
| `5` | `unavailable`: an inaccessible I/O dependency or conservative unexpected error. |

A fully matching local presentation sets `locally_detached_signed_copy_inventory_and_dual_receipt_consistent=true`, `original_sender_source_paths_required_or_read=false`, `ec365_through_ec337_historical_parent_or_directory_checkpoint_replay_performed=false`, and `exit_code=2`. The result includes verified signature counts and actual retained-chain heads to aid investigation. All negative-capability flags remain **false as claims of proof**, never a false claim that old history has been reconstructed.

Authentic `revoke` / `rotate`, signed withholding or dispute, a genuine fork, stale source/witness head, an unverifiable legal provenance or claimed timestamp must never be promoted to success. The records prove **only** possession of files and verification against the **supplied** external keys/pins. They do not prove custody of a physical object, real signer identity, whether another hidden status original exists, or a trustworthy global UTC instant.

**Observed focused local evidence:** 23/23 tests use actual new Ed25519 signatures and receiver copy bytes after deletion of all origin files; the EC366 deep prehistory in the fixture was intentionally simulated. No actual EC365→EC337 parent replay or external institutional certification was performed in this EC. See [EC369 report](../construction/EC369_LOCAL_REPORT.json), [source](../construction/ec369_detached_receiver/detached.py), [main release note](../EC-369.md).
