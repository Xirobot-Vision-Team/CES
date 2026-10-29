# EC391 signed prior offsite log and offline RFC3161 receiver contract

This is an **offline receiver** of pre-existing independent originals; never a TSA issuance, timestamp backdating, key creation, cloud notarization or proof that a particular entity legally operated a TSA. Every object path below means a **real absolute file path** and strict original `{"path":"...","sha256":"<64 lowercase hex>"}`. Replace placeholders with actual original bytes and separately retained SHA pins; the examples are not runnable fixtures. Strict JSON objects have exact fields, canonical UTF-8 bytes, no duplicate keys or excess whitespace, and at most the bounded counts described below. SHA pins, legal identity and source custody must be established by an operator *independent of the current case*.

## Prerequisites and inherited authoritative sources

Invoke full unchanged EC390 audit on all inherited EC390→EC369 canonical path/SHA/minimum and epoch values. The returned parent must be schema `ces.ec390.receiver_independent_signed_archive_heads_receipts_unresolved.v1`, command `audit-historical-ec339-independent-archive-heads`, verified `exit_code=2`, all unresolved sentinel flags and a genuine old EC389 source inventory. The EC391 archive embeds the actual EC390 original SHA and the digest of the just-replayed canonical EC390 output. A caller-provided JSON report **cannot** replace the real parent audit.

Receiver independently reopens previous EC389 signed witness and custody originals, old EC388/387/386 key-origin records and the later EC390 signed snapshot. Source-pair entries use **exactly** the ordered fields `ec339_revoked_status_original_sha256`, `ec389_signed_witness_original_sha256`, `ec389_signed_custody_original_sha256` already validated in EC389. Different signed historical contents are retained as conflicts; mutated or wrongly pinned original source bytes are rejected.

## New original bundle schema

```json
{
 "schema":"ces.ec391.receiver_prior_offsite_signed_heads_timestamp_bundle.v1",
 "parent_ec390_independent_archive_original_sha256":"<actual R390 bundle SHA>",
 "parent_ec390_canonical_result_sha256":"<fresh actual R390 audit canonical-result SHA>",
 "claimed_directory_lineage_id":"<authenticated existing lineage>",
 "offsite_log_keeper_roster_original":{"path":"/absolute/retained/keeper-roster.json","sha256":"<original SHA>"},
 "tsa_trust_registry_original":{"path":"/absolute/retained/tsa-trust.json","sha256":"<original SHA>"},
 "epochs":[{"epoch_index":0,"channels":[{
   "tsa_channel_id":"<authenticated source channel>",
   "signed_prior_offsite_head_original":{"path":"/absolute/retained/prior-head.json","sha256":"<original SHA>"},
   "rfc3161_timestamp_original":{"path":"/absolute/retained/head-tst.der","sha256":"<original SHA>"},
   "tsa_authority_id":"OutsideTSA1"
 }]}]
}
```

Epochs and per-epoch channel order **must exactly match** the authentic EC389 reopened sources and the original EC390 archive; 1–3 epochs and max 2 channels. A channel with no prior evidence has all three nullable fields set to `null`, not omitted. A signed prior Head without a token sets the latter two to `null`; a token without an actual signed prior Head is denied. Missing evidence is visible adverse/unresolved, not a PASS.

The bundle file path+SHA plus the distinct keeper roster SHA and TSA trust registry SHA are supplied **externally** through the CLI. The receiver verifies both original bytes and these outer hashes. A self-declared outer hash does not prove its own prior independent existence.

## Keeper and signature originals

Keeper roster exact fields: `schema` (`ces.ec391.outside_retained_offsite_log_keeper_roster.v1`), `claimed_directory_lineage_id`, `log_keepers` (1–2). Each keeper has exactly `signer_id`, `public_hex` (hex of 32 raw Ed25519 public bytes), and `public_key_original` (path+SHA of exact 32 raw bytes). Distinct ID/key/file, no zero key, no reused old EC338–341, EC389 or EC390 keys/roles.

Signed prior Head original exact fields `schema`, `claim`, `signature_ed25519` (128 lowercase hex), with schema `ces.ec391.signed_prior_offsite_log_head_original.v1`. Claim exact fields are:

```json
{
 "schema":"ces.ec391.prior_offsite_log_head_claim.v1",
 "directory_lineage_id":"<authentic lineage>",
 "tsa_channel_id":"<authenticated source channel>",
 "epoch_index":0,
 "offsite_keeper_id":"OutsideKeeper1",
 "log_sequence":1,
 "previous_signed_offsite_head_original_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
 "ec389_signed_source_pairs":[{
    "ec339_revoked_status_original_sha256":"<real old revoked signed status original SHA>",
    "ec389_signed_witness_original_sha256":"<real signed witness original SHA>",
    "ec389_signed_custody_original_sha256":"<real signed custody original SHA>"
 }],
 "claimed_logged_utc":"2026-10-25T11:26:00Z"
}
```

Ed25519 signature covers **byte-for-byte** the following message, where `canonical_json` means the pre-existing CES EC319 canonical JSON serializer:

```
 b'CES/EC391/IndependentOldEC339Revocation/PriorOffsiteLogHead/v1\0'
 + canonical_json(claim)
```

Sequence for epoch N is `N+1`, prior SHA is the preceding signed original's **entire file SHA** for the same channel (or 64 zeroes in epoch 0), ordered source pairs must extend the preceding epoch's visible prefix. The signed log Head and its time are distinct from the **later EC390 signed archive Head**; comparison of the two does not create an extra authority to select the global winner. `claimed_logged_utc` is only a signed claim, not authenticated UTC.

## Outside-pinned TSA trust and real timestamp token

The TSA trust-registry exact fields are `schema` (`ces.ec391.outside_retained_offline_tsa_trust_registry.v1`), `claimed_directory_lineage_id`, `authorities` (1–2). Each authority has:

```json
{
 "authority_id":"OutsideTSA1",
 "root_certificate_original":{"path":"/absolute/retained/tsa-root.pem","sha256":"<SHA of exact PEM or DER bytes>"},
 "root_certificate_der_sha256":"<SHA of X.509 DER certificate bytes>",
 "expected_tsa_policy_oid":"1.2.3.4.5.391",
 "crl_originals":[{"path":"/absolute/retained/tsa-ca.crl","sha256":"<SHA of exact DER or PEM bytes>"}]
}
```

The declared policy OID above is **illustrative only**, not a certified operational TSA OID. Real registry must contain the third party's authentic policy and legal out-of-band root identity. Roots require exact DER digest; the offline path builder verifies CMS signer signature, ESS signing cert hash and optional issuer serial, signed attributes, `messageImprint` of the **signed prior Head original raw bytes**, timestamp policy OID, TSA certificate EKU/basic constraints/path length and signed generation-time certificate validity. Furnished CRLs (max 4 per authority) are matched to chain issuers and signature/time/coverage are evaluated against the caller-provided `ec391_tsa_evaluation_utc`. Missing, stale, ambiguous, or known-revoked original CRLs set adverse unresolved state; corrupt/forged CMS/chain is rejected. The evaluation clock **is not** a proven trusted current-time service, and no network OCSP or global CRL query takes place. Generation time is signed under *supplied* trust material, not unconditionally a legitimate independently anchored UTC.

Distinct TSA authority ID must refer to the exact registry authority. Keeper, registry, key, root, CRL, signed Head and token original paths cannot replace original parent case sources or protected sender-origin originals. The receiver does not create any keys/tokens.

## Derive, externally retain, then audit

To obtain the unsigned canonical inventory **before** final audit, run:

```
python -I -B scripts/ces_cas_historical_ec339_prior_offsite_time.py derive-historical-ec339-prior-offsite-time-inventory --help
```

Pass every original EC390 argument plus all new scalar/epoch arguments. Parse `unsigned_prior_offsite_time_inventory` and `receiver_verified_prior_offsite_time_inventory_sha256` from the exit-2 JSON, independently retain the inventory SHA and per-epoch `prior_offsite_signed_head_inventory_sha256`, `prior_rfc3161_timestamp_inventory_sha256`, and minimum verified-timestamp count. Derive **never** proves that inventory or external SHA existed earlier than processing. For audit, separately supply the retained SHA as `--expected-retained-historical-ec339-prior-time-inventory-sha256`, and per-epoch:

```
--historical-ec339-prior-signed-head-inventory-sha256 <64 lower hex>
--historical-ec339-prior-rfc3161-token-inventory-sha256 <64 lower hex>
--minimum-historical-ec339-prior-timestamped-head-count <0..2>
```

Repeat each once per epoch; keep all inherited EC390 arguments. Full public fixed route:

```
python -I -B scripts/ces_next.py audit-historical-ec339-prior-offsite-time DeliveryAudit AuditHistoricalEC339PriorOffsiteTime --help
```

Both lawful derive and audit report exit `2` with suffix `_unresolved`. The meaningful flags include signed-source conflicts, later snapshot contradictions, epoch rollback, signed timestamp time order, missing tokens, CRL deficits and external authenticity gaps. Invalid original SHA/path, malformed signed JSON/CMS/certificate or missing required parent audits are rejected (`3` denied, `4` invalid input, `5` unavailable).

## Evidence limitations and no auto-promotion

There is no mechanism to demonstrate that the signed Head/token/SHA was actually stored at a truly independent location before the dispute; the EC391 validator can only authenticate **the presented artifacts against the supplied trust**. Nor can a locally generated test root be treated as a real accredited TSA, or any finite retained CRL set as global non-revocation or unseen-fork exclusion. Neither EC391 nor any predecessor changes the EC339 issuer's authority. Live original EC390→EC369 parent audit and external legal/source validation must be repeated in the final user-assisted acceptance environment; native PowerShell R150 untouched.
