# EC393 receiver protocol: countersigned custody originals, RFC6962 and timestamped prior signed Head

Construction release: V7.03/R393/EC393. This is an **offline verifier/receiver** contract, not a signing, time-stamping, external notary, global audit, WORM implementation or final acceptance API.

## Upstream authenticity

EC393 starts by executing the **actual EC392 audit** under exactly the caller's inherited EC392 inputs. EC392 in turn performs two actual EC391 audits with genuine parent pins. The verifier rejects forged user-supplied success reports; it checks EC392 schema/outcome, all inherited original/inventory SHA constraints, and reopens the authentic EC392 crossview bundle with its genuine two observer IDs and EC391 keyed original rosters. Production path never monkeypatches the earlier engine.

The new isolated commands are:

```bash
python -I -B scripts/ces_cas_historical_ec339_custody_anchor.py derive-historical-ec339-custody-anchor-inventory --help
python -I -B scripts/ces_cas_historical_ec339_custody_anchor.py audit-historical-ec339-custody-anchor --help
python -I -B scripts/ces_next.py audit-historical-ec339-custody-anchor DeliveryAudit AuditHistoricalEC339CustodyAnchor --help
```

Use identical EC392 parent flags required by `scripts/ces_cas_historical_ec339_crossview.py`, **plus** the following EC393 flags (no abbreviated names):

| Scalar flag | Source and meaning |
|---|---|
| `--historical-ec339-custody-anchor-bundle-file` | Existing normal absolute path to top-level EC393 original JSON bundle |
| `--expected-historical-ec339-custody-anchor-bundle-sha256` | SHA-256 of **exact** original bundle bytes |
| `--expected-outside-retained-ec393-custody-log-roster-sha256` | Independently archived custody and log public-key roster SHA |
| `--expected-outside-retained-ec393-tsa-registry-sha256` | Independently archived dedicated log timestamp trust registry SHA |
| `--expected-outside-retained-ec393-prior-log-head-sha256` | Independently pinned old **signed log-Head original bytes SHA**; not its Merkle root SHA |
| `--expected-outside-retained-ec393-dispute-cutoff-utc` | Strict UTC string, e.g. `2026-10-25T18:00:00Z`; source must be proven externally or remains caller assertion |
| `--historical-ec339-countersigned-custody-receipt-inventory-sha256` | Repeat **one per historical epoch**; SHA of canonical per-observer/epoch original receipt SHA inventory |
| `--historical-ec339-custody-log-inclusion-inventory-sha256` | Repeat **one per epoch**; SHA of canonical RFC6962 original-inclusion evidence inventory |
| `--minimum-historical-ec339-pre-cutoff-log-anchored-receipt-count` | Repeat **one integer 0-4 per epoch**; independent minimum cryptographically bounded old-Head receipt count |
| `--expected-retained-historical-ec339-custody-anchor-inventory-sha256` | **Audit only**; prior independently archived SHA of full receiver-derived unsigned inventory |

Do not treat SHA pins first generated at audit time as proof of prior custody or independently notarized cutoff. `derive-*` reports the current unsigned canonical inventory for separate custody. The unified router only supports fixed audit `DeliveryAudit/AuditHistoricalEC339CustodyAnchor` and strictly checks the isolated child response before emitting.

## Original path reference format

Every original is an object with **exactly** `{"path":"/absolute/normal/no-symlink/original","sha256":"<64 lowercase hex characters>"}`. Paths must obey inherited canonicality/path and file-size constraints, remain disjoint from earlier audited originals and other new originals, and be retrievable unchanged. A caller cannot replace an original with a filename-only claim or a mismatched hash. `sha256` means SHA-256 over **raw bytes before JSON parsing**. JSON itself is strict (no duplicates and no inexact keys), while signature messages use canonical JSON `ec319_offline_transfer_registry.registry.canonical(claim)` in existing CES canonical encoding. Do **not** sign pretty-printed JSON or a parsed/reserialized original document.

## Bundle and role-roster JSON members (names exact)

The top-level original must have `schema` = `ces.ec393.offsite_custody_and_timestamped_log_anchor_bundle.v1` and:

- `claimed_directory_lineage_id`, `parent_ec392_crossview_bundle_original`, `custody_log_roster_original`, `tsa_trust_registry_original`;
- `prior_signed_log_head_original`, `prior_log_head_rfc3161_token_original`, `current_signed_log_head_original`, `current_log_head_rfc3161_token_original`, `log_tsa_authority_id`, `log_consistency_path_sha256`;
- `epochs` containing each **identical actual EC392** epoch and ordered channel ID; each has `epoch_index` and `channels`, each channel has `tsa_channel_id`, `primary`, `secondary`.

Each observer row requires `signed_custody_handoff_original`, `rfc6962_leaf_index`, `rfc6962_inclusion_path_sha256`, `alternate_signed_custody_handoff_original`, `alternate_rfc6962_leaf_index`, `alternate_rfc6962_inclusion_path_sha256`. The alternate path may be `null` only when the alternate index is also `null`; missing or inconsistent evidence is explicitly adverse. The log-consistency proof is a bounded list of lowercase SHA-256 hex node hashes. Non-null paths/hashes all refer to **already-existing originals**.

Roster schema = `ces.ec393.independent_custody_parties_and_log_roster.v1` with exact `schema`, `claimed_directory_lineage_id`, `log_id`, `log_operator_id`, `log_public_hex`, `log_public_key_original`, `custody_parties`. Exactly four custody parties, one `sender` and one `receiver` for each of the two authentic EC392 observer IDs. Each party has exact `observer_id`, `party_id`, `site_id`, `role`, `public_hex`, `public_key_original`. Require raw 32-byte Ed25519 keys, five distinct public-key values, distinct party/site/operator IDs, unique SHA-pinned original paths, and no reuse of earlier authenticated observer keeper keys. This proves only key-level separation, not registered organizational identity or true historical site custody.

The dedicated timestamp registry reuses the full **EC391 original trust registry** schema and RFC3161 trust semantics, while disallowing reuse of either EC391 observer's TSA root. Actual raw DER RSA/X.509/CMS/ESS, policy, certificate validity, timestamping EKU and furnished CRLs are validated by existing EC350/EC391 code. No query to any online revocation provider occurs.

## Exact Ed25519 handoff signature domain and claim

Handoff original `schema` = `ces.ec393.original_dual_signed_custody_handoff.v1`. Its **only** members are `schema`, `claim`, `sender_signature_ed25519`, `receiver_signature_ed25519`; both signatures are lowercase 64-byte Ed25519 signatures hex-encoded. The claim `schema` = `ces.ec393.original_custody_handoff_claim.v1`, and **exact** fields are:

`schema`, `directory_lineage_id`, `log_id`, `observer_id`, `peer_observer_id`, `tsa_channel_id`, `epoch_index`, `handoff_sequence`, `sender_party_id`, `receiver_party_id`, `sender_site_id`, `receiver_site_id`, `crossview_bundle_original_sha256`, `signed_crossview_checkpoint_original_sha256`, `crossview_rfc3161_token_original_sha256`, `previous_signed_custody_handoff_original_sha256`, `claimed_handoff_utc`.

The two signature messages are distinct (the `\\0` below denotes an actual single NUL byte in the binary message, **not** the two literal characters slash and zero):

```python
sender_message = (b'CES/EC393/IndependentCustody/TwoPartyOriginalHandoff/v1\x00'
                  + b'sender\x00' + canonical(claim))
receiver_message = (b'CES/EC393/IndependentCustody/TwoPartyOriginalHandoff/v1\x00'
                    + b'receiver\x00' + canonical(claim))
```

The receiver checks **both** genuine signatures using the independent roster's exact raw keys and requires the signed EC392 crossview checkpoint **original** SHA, its **original** RFC3161 token SHA and the prior EC392 bundle SHA to be the actual audited originals. Any missing authenticated checkpoint/token or different signed claim is adverse, never a secretly substituted pass. Epoch handoff sequence is `epoch_index + 1`; the previous receipt's original SHA is required for subsequent epochs, with `'0'*64` permitted only when no earlier predecessor is due. A signed *claimed* handoff UTC does not authenticate true signing wall-clock time.

## Exact signed log Head domain, Merkle and RFC3161

Each signed Head original has `schema=ces.ec393.original_signed_custody_log_head.v1`, `claim` and `signature_ed25519`. Claim schema is `ces.ec393.signed_custody_log_head_claim.v1` with exactly `schema`, `directory_lineage_id`, `log_id`, `log_sequence`, `tree_size`, `merkle_root_sha256`, `previous_signed_log_head_original_sha256`, `claimed_integrated_utc`.

Ed25519 verifies over:

```python
message = b'CES/EC393/IndependentCustody/RFC6962SignedLogHead/v1\x00' + canonical(claim)
```

Log sequence 1 is the purported older already-retained Head with ZERO predecessor and **exact outside-pinned original SHA**. Log sequence 2 is the newer signed Head pointing to the *older original-byte SHA*, with strictly larger tree size. Require RFC6962 SHA-256 `SHA256(0x00 || leaf_original_bytes)` for each countersigned receipt, bounded inclusion paths for older Head's authentic tree root, and a valid RFC6962 **consistency proof** from older to newer root. Any missing or wrong prior pin, signature, previous Head SHA, tree size or Merkle proof prevents positive historical anchoring. An observed conflicting alternative receipt retains both SHA originals and appropriate inclusion metadata, never selects an authoritative winner.

Each Head has its **own** actual RFC3161 DER/CMS token whose signed `messageImprint` is the SHA-256 of that Head's **raw signed original bytes**. The old Head's token `genTime` must lie between its signed claimed time and outside asserted dispute cutoff. Both furnished TSA chains must have clean, nonstale, unrevoked *as furnished* CRLs at the relevant time and must satisfy evaluation-time and chronological ordering. **A clean current signed Head without its current token, or a valid tree prefix without an authentic signed predecessor chain, cannot produce a positive anchored handoff count.** Neither token alone proves legally independent TSA, trusted accredited clock or physical retention.

## Results and unresolved dependencies

Every valid, well-formed, even disputed evidence result emits `_unresolved`, `exit_code=2`, `offline_unresolved_exit_code=2`, a source-specific reason from the ten enumerated flags, anchored count, alternate conflict count, per-epoch inventories and the whole derived SHA. Audit omits the entire unsigned inventory body and requires its separately supplied retained digest. Invalid signatures, forged roots/pins, malformed schema, copied evidence paths and unsafe source inputs are denied 3/4/5. This receiver never creates keys, receipts, proofs, Head signatures, RFC3161 tokens, remote records or evidence files.

The returned values deliberately set to `false` claims of legal site independence, independently verified dispute date, qualified trustworthy TSA, global fork finality, physical WORM, comprehensive online revocation, receiver signing/network writes, old EC339 issuer authority promotion, and unmocked production acceptance. Upstream EC249/EC250/B001/Quality/final gates remain blocked or pending. Required final external evidence is tracked at `construction/NEXT_ROUND.md`, not silently manufactured here.
