# EC368 — Offline receiver-held portable witness/status handoff protocol

**Release:** V6.78/R368/EC368. **Inherited:** V6.77/R367/EC367; true production `EC367→EC366→…→EC337` signed-original audit remains a mandatory first step. This is a new, narrowly scoped **read-only** capability. It never supplies signing private keys, writes/copies files, accesses a network, establishes a trust root or changes the native PowerShell V4.60/R150 CLI.

## What the protocol proves locally, and what it does not

It verifies that the bytes presented in a **receiver-side copy file for every specified original** exactly equal the genuine SHA-256-pinned and previously authenticated source bytes, and that two **different caller-pinned** Ed25519 public keys cryptographically signed the sender dispatch and receiver acknowledgment of the same parent result, ordered inventory, two witness heads and cross-linked handoff history. Its `accepted` state is an authenticated *claim* by the receiver key, **not** proof of actual custody at signing time, legal identity, certified outside infrastructure, trusted signing time, publication to the world or global completeness.

The receiver copies are portable data artifacts but this **EC368 verifier still needs the inherited parent source files and all inherited arguments** to replay original signatures and compare byte-for-byte. It cannot validate a detached package entirely from receiver copies after the parent paths disappear. That offline detached-verification mode is not implemented. The source SHA inventory uses role, length and SHA rather than absolute paths, so copies may reside at different absolute paths while remaining byte-identical. At exit, the verifier rechecks SHA/file identity within the inherited local read boundary; local mutable filesystems are not an atomic custody snapshot.

## Coverage: nothing can disappear from the claimed original set

A `derive-portable-receiver-handoff` command calls the **real** EC367 auditor, then reopens inherited originals and emits their SHA/size inventory, actual existing source paths for local copying, the SHA-256 of that canonical inventory and the EC367 result hash. The actual inventory is *not* taken from the receiver bundle.

The ordered inventory always contains:

1. The exact original EC366 root-provenance bundle.
2. For **both** source roles (`origin_registry`, `independent_archive`): original 32-byte institution keys, **all** EC366 signed institution status events, **all** EC366 signed provenance attestations; then any EC366 extra directory signed checkpoints included by that root bundle.
3. The original EC367 witness-distribution bundle, the original 32-byte key for each of `registry_distribution` and `archive_distribution`, **every** witnessed signed epoch record on both paths, and **every** additional genuine source-signed status original present in EC367's bundle, including `revoke` or `rotate`.

The exact list is at most 52 entries, determined by source bundles and their validated original references. Every original has a separate receiver file. A missing, extra, reordered or incorrectly labeled receiver copy is **denied** rather than quietly treated as a successful partial handoff. Every copied file is read as an actual **regular, absolute, SHA-pinned source**; same-path/inode alias to original sources and other copies, symlink ancestry, wrong bytes and changed files cause denial. The verifier has no copier or repair writer. It reads existing user-provided copied files.

Canonical inventory hash:

```text
SHA256(canonical_json({
  "schema": "ces.ec368.portable_original_byte_inventory.v1",
  "parent_ec367_canonical_result_sha256": "<SHA of freshly executed EC367 result>",
  "items": [
    {"kind": "<derived stable role>",
     "source_original_sha256": "<sha of REAL original>",
     "byte_length": <actual integer byte length>},
    ...
  ]
}))
```

The independently retained `--expected-portable-inventory-sha256` is **required**. It cannot be silently substituted by the receiver's bundle. The original SHA from the actual parent bundle, the supplied copy SHA and actual received bytes must all match. Source paths are not included in the canonical inventory digest: only the *content* is portable.

## Exact receiver bundle and fully signed records

`--portable-receiver-bundle-file` and `--expected-portable-receiver-bundle-sha256` select a SHA-pinned JSON original with **exactly** the keys:

```json
{
  "schema": "ces.ec368.receiver_portable_copies_and_dual_signed_handoffs.v1",
  "parent_ec367_canonical_result_sha256": "<actual parent SHA>",
  "portable_inventory": [
    {
      "kind": "<derived role>",
      "source_original_sha256": "<derived SHA>",
      "byte_length": 123,
      "receiver_copy": {"path": "/absolute/path/to/existing/copy", "sha256": "<same original SHA>"}
    }
  ],
  "handoffs": [
    {
      "sender_dispatch_original": {"path": "/absolute/sender0.json", "sha256": "<real signed original SHA>"},
      "receiver_ack_original": {"path": "/absolute/receiver0.json", "sha256": "<real signed original SHA>"}
    }
  ]
}
```

`portable_inventory` must have exactly the derivation's full set, in its precise order. `handoffs` contains 1–4 pairs in chronological sequence `0,1,2,3`; each signed file must be a separate, already existing SHA-pinned original. Every dispatch and acknowledgment is independently Ed25519 authenticated, not merely referenced by a hash.

Every **sender dispatch** has exactly:

- `schema`: `ces.ec368.sender_signed_witness_status_dispatch.v1`
- `claimed_sender_id`, `sender_public_key_original_sha256`; `claimed_receiver_id`, `receiver_public_key_original_sha256` (these identities and key SHAs must exactly match externally supplied caller pins)
- `parent_ec367_canonical_result_sha256`, `portable_inventory_canonical_sha256`
- `sequence` (0–3), `previous_sender_dispatch_original_sha256`, `previous_receiver_ack_original_sha256` (both null at genesis, both equal the preceding genuine originals afterwards)
- `witness_head_original_shas`: an ordered length-2 array of actual latest EC367 witness head SHAs, or `null` for an EC367 path with no unambiguous head; an absent/ambiguous witness head does **not** qualify as locally complete
- `issued_utc`, `expires_utc` (claimed, bounded interval of at most 7 days, not trusted time)
- `signature_sender_ed25519_hex` signed on `b'CES/EC368/PortableWitnessStatusDispatch/v1\x00' + canonical_json(dispatch_without_signature)`.

Every **receiver acknowledgement** contains the same common identity, parent, inventory, sequence, previous sender SHA, previous receiver SHA, witness head and expiration fields, but replaces `issued_utc` with `received_utc`, and adds `sender_dispatch_original_sha256`, `receipt_state` (`accepted`, `withheld`, `disputed`), and `signature_receiver_ed25519_hex`. Its **different** Ed25519 signature domain is `b'CES/EC368/PortableWitnessStatusReceiverAck/v1\x00' + canonical_json(ack_without_signature)`.

The acknowledgment must bind the exact sender signed-original SHA of *its own* pair. Both signatures must repeat exactly the same two predecessor SHAs. Each later pair must point to both the previous sender dispatch **and** the matching previous receiver acknowledgement, not to an arbitrary alternate branch. A signed fork, missing predecessor, cross-link mismatch, replay, duplicate sequence or reordered handoff list is reported as unresolved with **no selectively promoted head**.

Each entire ordered sender/receiver original-SHA stream is externally pinned by repeated `--signed-sender-dispatch-sha256` and `--signed-receiver-ack-sha256` arguments, respectively. The independent latest SHA and sequence floor for **both** roles are mandatory. A mismatched external stream or retained SHA/floor blocks local correlation; the verifier never accepts a current bundle's own claim as an external retention witness.

All statements are signature-checked before outcomes are constructed. Forged signatures, altered originals, invalid original fields or missing copies are denied with exit `3/4/5` as appropriate; a **genuinely signed** fork/withholding or a conflicting signature claim remains explicitly visible as exit `2` **unresolved**.

## Local outcome and conflict preservation

`locally_receiver_held_complete_portable_inventory_acknowledged` becomes true only if the true parent EC367 audit reports its two locally current witness paths, the complete exact original copy inventory is present and byte-identical, two different caller-pinned sender/receiver keys have signed correctly bound and SHA-linked epoch pairs, both outside retained streams, heads and floors agree, the latest receiver receipt is signed `accepted`, and **none of the EC368 conflict flags** are active. This is *only* local file and key control verification; **even this positive local result is exit `2` unresolved**.

No signed `accepted` acknowledgment repairs missing EC367 witness agreement, previous signed withholding, a genuine institution-signed `revoke`/`rotate`, conflicting signed source status, stale parent result, missing source provenance or a broken source/witness signature chain. An authentic terminal source status provided to EC367 remains visible as an independent EC368 boolean plus exact SHA lists regardless of how the receiver signs.

## Command line: standalone and fixed unified read-only route

Prerequisites: Python runtime, existing inherited EC367/EC366 original files, `cryptography` (and the complete inherited Python dependencies), caller-retained SHA/identity material. The new CLI also inherits **all** of EC367's complete required parent options, including any EC337-era options; the examples below show **only newly added arguments**, not a runnable replacement for inherited options.

```text
python -I -B scripts/ces_cas_portable_receiver.py derive-portable-receiver-handoff \
  [COMPLETE EC367 FLAGS]

python -I -B scripts/ces_cas_portable_receiver.py audit-portable-receiver \
  [COMPLETE EC367 FLAGS] \
  --portable-receiver-evaluation-utc 2026-10-26T13:00:00Z \
  --portable-receiver-bundle-file /abs/receiver-bundle.json \
  --expected-portable-receiver-bundle-sha256 <REAL_SHA256> \
  --expected-portable-inventory-sha256 <OUTSIDE_RETAINED_REAL_SHA256> \
  --sender-public-key-file /abs/sender.pub \
  --expected-sender-public-key-sha256 <REAL_SHA256> \
  --claimed-sender-id SenderClaimOnly \
  --receiver-public-key-file /abs/receiver.pub \
  --expected-receiver-public-key-sha256 <REAL_SHA256> \
  --claimed-receiver-id ReceiverClaimOnly \
  --expected-retained-sender-dispatch-head-sha256 <REAL_SHA256> \
  --expected-retained-receiver-ack-head-sha256 <REAL_SHA256> \
  --minimum-retained-sender-dispatch-sequence 0 \
  --minimum-retained-receiver-ack-sequence 0 \
  --signed-sender-dispatch-sha256 <REAL_SHA256> \
  --signed-receiver-ack-sha256 <REAL_SHA256>

python scripts/ces_next.py audit-portable-receiver \
  DeliveryAudit AuditPortableReceiver [SAME COMPLETE AUDIT FLAGS]
```

Each `<...>` is a documentation placeholder, not a digest. Each repeated signed-original SHA list must follow the actual chronological `handoffs` order. The unified entrypoint constructs a **fixed** `python -I -B` child, bounds and validates its arguments and enforces an exact conservative JSON response/denial shape; no caller-controlled executable is accepted. A genuine matching local receipt does not produce an exit `0` trust pass.

## This EC's focused verification versus deferred integration

The new 19-case quick suite exercises new **real Ed25519** sender/receiver signatures, real EC367 witness and source signatures, original-by-original byte copying, omission/tamper and file alias denial, two epoch cross-links and signed forks, valid retained heads and rollback, receiver withholding, independently pinned SHA streams, true source-signed revocation, claimed clock discrepancies, and a **mock-child** fixed unified reply contract. For these synthetic fixtures **EC366's deep parent result is deliberately mocked**; the tests do not demonstrate the complete EC366→EC337 historical signature replay. The source code, unlike the fixture, invokes actual EC367.audit on *every production audit*.

Still deferred: an EC368 full inherited signed-original test, EC367 parent-inclusive integration, 12 EC366 parent-inclusive heavy cases, timed-out legacy EC366 case01 and EC356 case24, EC317/318 original deep `MOCK` replacement, native PowerShell 7/15 original Smoke, Windows/macOS/Git/CI/Provider E63–E66, physical custody and independent legal identities, trusted UTC, global complete source/status log, remote CAS/WORM storage and final user-assisted acceptance. Inherited `EC249 INCOMPLETE`, `EC250 BLOCKED`, `B001 OPEN`, `Quality=false`, final `NOT_STARTED` remain unchanged.

[Source](../construction/ec368_portable_receiver/portable.py) · [Focused fixture](../construction/ec368_portable_receiver/test_portable.py) · [EC368 record](../EC-368.md) · [Scope](../construction/EC368_SCOPE.json) · [Observations](../construction/EC368_LOCAL_REPORT.json).
