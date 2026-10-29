# EC370 — Offline detached publication accountability (exact wire contract)

**Release:** V6.80 / R370 / EC370. **Scope:** one functional read-only EC extending EC369; the entire V6.79 package is preserved. All lawful audit and derive results return **exit 2** and an `*_unresolved` status. A coherent *finite*, independently anchored view is **not** a globally complete public log, official publishing authority, trusted time, legal identity, or physical proof of custody. The received EC366/367 copied set is not a full EC365→EC337 original archive.

## What is actually verified

Every `audit-publication-accountability` first calls the production `detached_receiver.detached.audit()` using **all actual EC369 external inputs**, *not* a cached `PASS` JSON. This authentically reopens and checks the receiver-held bytes and signed EC366/367 source/witness records, EC368 dual receipts and EC369 map/challenges/answers. The original sender source path labels are never opened or stat-ed.

EC370 then independently SHA-pins and reads **two different raw 32-byte Ed25519 public-key files**: a claimed publisher and a separately claimed publication observer. Those roles (keys **and** identifiers) must not collide with sender, receiver, two institutions or two witnesses. All eight identities and public-key SHA roles must be distinct, but claimed identity strings and separate physical/legal custody are **not externally attested** by the verifier.

The published disclosure consists of 1–4 consecutive paired, genuine publisher-signed notice and observer-signed inclusion originals. For each epoch, the publisher's original and the observer's original must cryptographically cover the *same canonical inventory*, including:

- all source/witness status, attestation and terminal-event head SHAs actually replayed by EC369;
- the exact canonical SHA of the **current EC369 result**, including the caller-claimed evaluation UTC and adverse flags;
- ordered source-original SHA pairs of EC368 sender dispatch/receiver ack;
- ordered source-original SHA pairs of EC369 receiver challenge/sender disclosure answer;
- external EC367 parent SHA, EC369 detached bundle SHA, EC369 signed copy-map SHA and recomputed portable inventory SHA.

Earlier published epochs can be **bounded prefixes** of the current actual received SHA streams (at least one pair per stream). For every epoch, each disclosed list must be a true prefix, and successive signed lists must extend, never truncate, permute or overwrite, older signed disclosures. The final signed publisher and observer lists must each be **exactly equal** to the entire received EC369 handoff/challenge history. The latest complete canonical inventory SHA must also be held externally by the operator, not inferred solely from the bundle. An actually source-signed adverse EC369 parent result remains adverse even if all new publication statements say `published` and `confirmed`.

Every notice and observation has an exact increasing `sequence` (0–3), the SHA of the *previous* publisher notice **and** previous observation, plus a bounded claimed 7-day window. An observation also signs the exact current publisher notice original SHA. This forms a cross-referenced two-party, append-only **presented** history. Real Ed25519 signing is checked with separate domain prefixes. A verifiable competing publisher/observer original (up to four of each) is not silently removed; same-sequence/predecessor genuine conflicting signatures are surfaced as visible forks. Extra authenticated records not fitting a selected branch are surfaced as unresolved history. Invalid signature, bad file SHA, missing/corrupt bytes, wrong externally pinned signer or malformed schema fail closed with exit 3/4/5.

Outside the bundle, caller retains both complete publisher and observer original SHA lists, both retained latest heads, minimum publication sequence, minimum disclosed challenge count, exact latest full-inventory SHA, publication bundle file SHA, and both signer files+SHA/claimed identifiers. A mismatch with a *validly signed* history is **unresolved**, not magically fixed by selecting the favorable branch.

## File types and signing bytes

All JSON files are strict canonical JSON with **exact field sets**; the original file is fully SHA-256 checked against a `{"path":"/absolute/receiver/path","sha256":"<64 lowercase hex>"}` reference. Raw public keys are SHA-pinned before being parsed as 32-byte Ed25519 keys. Do not use private keys or signature generation inside CES; external custodians generate and sign the documents separately.

### 1. Publication bundle

```json
{
  "schema": "ces.ec370.publication_accountability_bundle.v1",
  "publication_epochs": [
    {"publisher_notice_original":{"path":"/receiver/publisher-0.json","sha256":"<sha>"},
     "publication_observation_original":{"path":"/receiver/observer-0.json","sha256":"<sha>"}}
  ],
  "competing_publisher_notice_originals": [],
  "competing_publication_observation_originals": []
}
```

The bundle file has a separate external SHA pin. Bounded max 9,000 bytes, 1–4 epochs, and 0–4 additional genuine competing originals per signer. Signed originals max 7,500 bytes each. Source reference paths in the EC369 signed map remain metadata only; they may not be repurposed as EC370 read paths.

### 2. Signed publisher notice

Exactly these fields (no aliases or optional omissions):

```json
{
  "schema":"ces.ec370.publisher_signed_disclosure_history.v1",
  "claimed_publisher_id":"ExamplePublisher",
  "publisher_public_key_original_sha256":"<SHA of raw publisher key>",
  "claimed_publication_observer_id":"ExampleObserver",
  "publication_observer_public_key_original_sha256":"<SHA of raw observer key>",
  "claimed_sender_id":"ExampleSender",
  "claimed_receiver_id":"ExampleReceiver",
  "sequence":0,
  "previous_publisher_notice_original_sha256":null,
  "previous_publication_observation_original_sha256":null,
  "detached_bundle_original_sha256":"<outside pinned EC369 bundle SHA>",
  "signed_copy_map_original_sha256":"<outside pinned EC369 map SHA>",
  "parent_ec367_canonical_result_sha256":"<outside pinned parent SHA>",
  "portable_inventory_canonical_sha256":"<EC369 true computed inventory SHA>",
  "publication_inventory_canonical_sha256":"<derived canonical cumulative SHA>",
  "published_handoff_sha_pairs":[
    {"sender_dispatch_original_sha256":"<actual original SHA>",
     "receiver_ack_original_sha256":"<actual original SHA>"}
  ],
  "published_disclosure_sha_pairs":[
    {"receiver_challenge_original_sha256":"<actual original SHA>",
     "sender_disclosure_original_sha256":"<actual original SHA>"}
  ],
  "publication_state":"published",
  "issued_utc":"2026-10-26T12:00:00Z",
  "expires_utc":"2026-10-28T12:00:00Z",
  "signature_publisher_ed25519_hex":"<128 lowercase hex>"
}
```

Allowed publisher states: `published`, `withheld`, `disputed`. `signature_publisher_ed25519_hex` = the real private key's signature of:

```text
b'CES/EC370/PublisherHistory/v1\x00' + canonical_json(notice without signature_publisher_ed25519_hex)
```

For the *next* epoch, `sequence=1`, both `previous_*_original_sha256` are the true two previous original-file SHA values, and lists are at least prefixes of all genuine EC369 received SHA streams; they cannot shrink.

### 3. Signed observer inclusion

All the publisher notice fields are repeated **except** `schema`, `publication_state`, and `signature_publisher_ed25519_hex`. In their places, the observer has exactly:

- `schema`: `ces.ec370.observer_signed_publication_inclusion.v1`;
- `publisher_notice_original_sha256`: SHA of the exact same current signed publisher notice original;
- `observation_state`: `confirmed`, `withheld` or `disputed`;
- `signature_observer_ed25519_hex` signed with `b'CES/EC370/ObserverInclusion/v1\x00' + canonical_json(unsigned observer)`.

Publisher and observer may claim **different** `issued_utc`/`expires_utc` windows; a claimed observer issuance earlier than the claimed publisher issuance is reported as a time anomaly, not silently endorsed. Their other common evidence fields must agree exactly. Claimed times are neither trusted UTC nor proof of actual historic issuance order.

### 4. Canonical cumulative inventory

Use the standalone `derive-publication-inventory` command to obtain an **unsigned** `current_unsigned_canonical_inventory` and its SHA. Its schema is `ces.ec370.cumulative_published_detached_original_sha_inventory.v1`. It is assembled from the **real on-disk EC369 audit**, not the publisher's assertions, and contains the exact actual source/witness heads, genuine signed terminal-status SHA list, the SHA of the entire EC369 result, parent/map/bundle/inventory pins, and the requested ordered handoff and disclosure prefixes. Canonical JSON uses the inherited `offline_transfer_registry.registry.canonical()` function, not `json.dumps()` default formatting. The SHA is the lowercase hex SHA-256 of the resulting canonical bytes.

**Important:** this inventory includes a digest of the entire returned EC369 result, including `detached_evaluation_utc_as_caller_claim`. For a previously signed publication epoch, retain and supply the exact same independently pinned evaluation UTC and parent inputs when replaying its signed digest. A different evaluation epoch can produce a legitimately different parent result and will not be silently mapped back onto an older signed claim. That is a visible binding, *not* a trusted time service.

## Commands

Run from the extracted `ces/` root with Python project dependencies installed. The entire set of **required EC369 options and repeated pins** is unchanged; see [EC369 command and field list](detached-receiver-origin-byte-replay.md). In addition to that same complete set of flags, the `audit` takes these new arguments:

```sh
python -I -B scripts/ces_cas_publication_accountability.py \
  audit-publication-accountability \
  <ALL_REQUIRED_EC369_FLAGS_AND_THEIR_VALUES> \
  --publication-bundle-file /receiver/ec370-publication-bundle.json \
  --expected-publication-bundle-sha256 <EXTERNAL_BUNDLE_SHA> \
  --publisher-public-key-file /receiver/publisher-key.raw \
  --expected-publisher-public-key-sha256 <EXTERNAL_PUBLISHER_KEY_SHA> \
  --claimed-publisher-id ExamplePublisher \
  --publication-observer-public-key-file /receiver/observer-key.raw \
  --expected-publication-observer-public-key-sha256 <EXTERNAL_OBSERVER_KEY_SHA> \
  --claimed-publication-observer-id ExampleObserver \
  --expected-retained-publisher-notice-head-sha256 <EXTERNAL_LATEST_NOTICE_SHA> \
  --expected-retained-publication-observer-head-sha256 <EXTERNAL_LATEST_OBSERVATION_SHA> \
  --expected-latest-publication-inventory-sha256 <EXTERNAL_FULL_CANONICAL_SHA> \
  --minimum-retained-publication-sequence 0 \
  --minimum-retained-published-challenge-count 1 \
  --signed-publisher-notice-sha256 <EPOCH_0_NOTICE_SHA> \
  --signed-publication-observer-sha256 <EPOCH_0_OBSERVATION_SHA>
```

For every additional epoch, repeat each `--signed-publisher-notice-sha256` and `--signed-publication-observer-sha256` in *chronological order*. Max four per signer. `--minimum-retained-publication-sequence` ranges 0–3; `--minimum-retained-published-challenge-count` ranges 0–4.

Use the fixed, isolated unified route with the **same** flags:

```sh
python -I -B scripts/ces_next.py \
  audit-publication-accountability DeliveryAudit AuditPublicationAccountability \
  <ALL_REQUIRED_EC369_AND_EC370_FLAGS_AND_THEIR_VALUES>
```

For the signer-side unsigned preparation step, use **only** the parent EC369 flags and optionally two prefix counts; **no publisher/observer key and no private key** is needed:

```sh
python -I -B scripts/ces_cas_publication_accountability.py \
  derive-publication-inventory \
  <ALL_REQUIRED_EC369_FLAGS_AND_THEIR_VALUES> \
  --published-handoff-prefix-count 1 \
  --published-disclosure-prefix-count 1
```

Omit either prefix flag to include the full corresponding actual stream. The exported unsigned hash is a preparation aid, **not** a signature or new independent pin. The external publisher/observer must create and sign their own records and retain independently trusted values. `audit` re-computes the digest and does not trust the exported result file as a shortcut.

## Actual observed checks and boundaries

Local: **25/25 uninterrupted focused tests passed**, including 3 actual isolated `python -I -B` child subprocess cases (successful unified audit, denied unified tampering, successful standalone unsigned derive), real Ed25519 signatures and deletions of all sender source originals. Tests also cover externally pinned SHA/stream conflict, signed withheld/disputed, first/second signed epoch prefix, accepted and omitted disclosure, broken predecessor, competing genuine signed forks, role-key collision, different valid signer timestamp claims and real SHA/canonical export.

**Explicit limit of the fixture:** the EC366→EC365→EC337 deep parent is deliberately MOCKED in the synthetic inherited fixture; the actual EC366/367 source & witness signatures and newer EC368–EC370 signatures are genuine. The code never claims full old historic signatures checked from EC369's limited copied originals. Not run: the 12 heavy EC366 parent-inclusive tests, EC356 old case24, older complete regression suites, original native PowerShell7/15 Smoke, Windows/macOS/Git/CI/Provider E63–E66, actual independent official/legal signers/physical custody/trusted UTC, full globally published transparency history, remote Provider/CAS/WORM and final user acceptance. `EC249 INCOMPLETE`, `EC250 BLOCKED`, `B001 OPEN`, `Quality=false`, final `NOT_STARTED` remain unchanged.
