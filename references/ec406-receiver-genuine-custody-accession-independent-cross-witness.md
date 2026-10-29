# EC406 — Signed original custody accession and independently signed cross-witness

**Available in V7.16/R406/EC406.** This receiver is offline and read-only. In production it first runs the *unchanged actual* `ec405_warc_time.protocol.audit`, which in turn runs unchanged real EC404/EC403/EC402/EC401/EC400/EC399/EC398 and all deeper original audits. A compliant **local** result is always **exit 2** and status ending `_unresolved`; a forged/malformed/unavailable input is denied with 3/4/5. It never signs, issues trust roots, retrieves network records, commits to Git/CI/PowerShell, or writes WORM.

## Distinct, useful claim verified

For **each of exactly two EC405 publisher IDs**, independently externally retained custody evidence consists of:

1. One **actual, SHA-pinned Ed25519 custodial accession receipt original**. Its signed canonical JSON claim binds the true inherited EC404 Ed25519 archive receipt SHA, real unchanged EC405 complete WARC original SHA, real signed RFC3161 original SHA, freshly reverified *actual signed token* `genTime`, separate custodian ID, unique archive record ID, epoch and signed predecessor accession SHA.
2. One **separately Ed25519-signed cross-witness original**, under a distinct witness key, binding the *actual* original custody accession file's SHA, the same WARC and RFC3161 originals, independent witness ID, separate unique event ID, epoch and prior witness SHA.
3. Four physically separately supplied 32-byte public-key original files for both custodians and both witnesses. Their SHA256 values are supplied **outside** the new bundle; the four public keys must be unique and must not equal authentic inherited EC399 Ed25519 publisher keys, EC404 archive keys, or any Ed25519 EC405 TSA root key. Identity labels are claims, **not organizational independence**. This receiver never supplies or generates private keys.
4. Exact SHA of new original bundle, outside roster original, both first accessions, both first witnesses, independent per-epoch SHA+joint-count floor and independent whole-inventory SHA. An unpinned or silently recalibrated original cannot earn credit.
5. Signed chronology: real RFC3161 signed `genTime` ≤ *custodian claimed* accession UTC ≤ *witness claimed* UTC ≤ inherited outside dispute cutoff; both claims ≤ caller-provided evaluation UTC. Within each role, both claimed times must be nondecreasing. These signed claims are **not independently calibrated true historic time**.

The signed accession and witness may be **locally cryptographically consistent** without any real independent institution or historic event. No genuine third-party public archival proof, actual custody fact, qualified TSA certification, legally authorized government origin, manufacturer physical WORM, exhaustive fork/CRL discovery or final customer acceptance is inferred from these local cryptographic checks.

## Operator entry points

```bash
cd ces
python -I -B scripts/ces_cas_historical_ec339_custody_witness.py derive-historical-ec339-custody-witness-inventory --help
python -I -B scripts/ces_cas_historical_ec339_custody_witness.py audit-historical-ec339-custody-witness --help
python -I -B scripts/ces_next.py audit-historical-ec339-custody-witness DeliveryAudit AuditHistoricalEC339CustodyWitness --help
```

All *actual* inherited EC405 **audit** scalars and repeats are mandatory, including EC405's own independently retained whole-inventory SHA, and earlier EC404/403/... original SHA pins. EC406 adds:

| New scalar (CLI `--` + underscores converted to hyphens) | Description |
|---|---|
| `historical_ec339_custody_witness_bundle_file` | Absolute normalized JSON path to new original bundle |
| `expected_historical_ec339_custody_witness_bundle_sha256` | Outside exact original bundle SHA-256 |
| `expected_outside_ec406_custody_witness_roster_sha256` | Outside exact roster original SHA-256 |
| `expected_outside_ec406_a_custodian_key_sha256` | Outside *raw 32-byte* custodian A public-key original SHA |
| `expected_outside_ec406_b_custodian_key_sha256` | Custodian B, ordered by inherited lexicographic publisher IDs |
| `expected_outside_ec406_a_witness_key_sha256` | Witness A raw public-key SHA |
| `expected_outside_ec406_b_witness_key_sha256` | Witness B raw public-key SHA |
| `expected_outside_ec406_first_a_accession_sha256` | First genuine signed accession file SHA, publisher A |
| `expected_outside_ec406_first_b_accession_sha256` | First genuine signed accession file SHA, publisher B |
| `expected_outside_ec406_first_a_witness_sha256` | First genuine signed witness file SHA, publisher A |
| `expected_outside_ec406_first_b_witness_sha256` | First genuine signed witness file SHA, publisher B |
| `ec406_custody_evaluation_utc` | Canonical caller-provided `YYYY-MM-DDTHH:MM:SSZ`, not an external authoritative clock |

In addition, for each inherited 1–3 epochs, repeat both `--historical-ec339-custody-witness-epoch-inventory-sha256 SHA` and `--minimum-historical-ec339-joint-custody-witness-publisher-count 0..2`. Only the **audit** command also requires `--expected-retained-historical-ec339-custody-witness-inventory-sha256 SHA`. The **derive** command returns an unsigned digest to compare with an independently retained commitment: it never establishes trust or creates the signed sources. There is no automatic pin rewriting or fallback.

### Original bundle JSON schema

The fields shown are exact; replace placeholders with genuinely retained original absolute normalized paths and externally held matching SHA values. They are examples, **not existing evidence**.

```json
{
  "schema": "ces.ec406.original_custody_witness_bundle.v1",
  "claimed_directory_lineage_id": "<real inherited directory lineage ID>",
  "parent_ec405_original_warc_timestamp_bundle_original": {"path": "/absolute/authentic-ec405-original-bundle.json", "sha256": "<genuine SHA>"},
  "outside_custody_witness_roster_original": {"path": "/absolute/genuine-custody-roster.json", "sha256": "<outside SHA>"},
  "epochs": [{
    "epoch_index": 0,
    "publishers": [
      {"publisher_id": "PublisherA", "custodian_id": "ExternalCustodianA", "witness_id": "ExternalWitnessA", "signed_accession_original": {"path": "/absolute/custodian-A-signed.json", "sha256": "<first A SHA>"}, "signed_cross_witness_original": {"path": "/absolute/witness-A-signed.json", "sha256": "<first A witness SHA>"}},
      {"publisher_id": "PublisherB", "custodian_id": "ExternalCustodianB", "witness_id": "ExternalWitnessB", "signed_accession_original": {"path": "/absolute/custodian-B-signed.json", "sha256": "<first B SHA>"}, "signed_cross_witness_original": {"path": "/absolute/witness-B-signed.json", "sha256": "<first B witness SHA>"}}
    ]
  }]
}
```

The parent EC405 bundle path and SHA must **exactly** equal those already furnished to EC405; parent EC405's original must itself identify the true EC404 original bundle and roster. Each epoch has exactly the two inherited publisher IDs; the first epoch requires both custody and witness signatures per publisher. Later missing originals must be explicitly `null`, never credited or synthesized. A later missing witness with an existing signed accession is independently signature-verified and source-bound but gets **zero joint credit**; after any incomplete epoch for a role, future reappearance is denied rather than skipping the sequence gap.

### Outside roster JSON schema

```json
{
  "schema": "ces.ec406.outside_pinned_custody_witness_roster.v1",
  "claimed_directory_lineage_id": "<same real lineage>",
  "assignments": [
    {"publisher_id": "PublisherA", "custodian_id": "ExternalCustodianA", "witness_id": "ExternalWitnessA", "custodian_public_key_original": {"path": "/absolute/custodian-A.pub.raw", "sha256": "<outside key SHA>"}, "witness_public_key_original": {"path": "/absolute/witness-A.pub.raw", "sha256": "<outside key SHA>"}},
    {"publisher_id": "PublisherB", "custodian_id": "ExternalCustodianB", "witness_id": "ExternalWitnessB", "custodian_public_key_original": {"path": "/absolute/custodian-B.pub.raw", "sha256": "<outside key SHA>"}, "witness_public_key_original": {"path": "/absolute/witness-B.pub.raw", "sha256": "<outside key SHA>"}}
  ]
}
```

All custody/witness IDs are unique, bounded ASCII identifiers (letter followed by up to 63 letters, digits, `_` or `-`); they must match the signed claims. Each **raw** public-key file is 32 bytes, no PEM envelope. Original public-key paths must not alias original bundle/source/sibling/other key paths. Signed accession and witness originals use the same exact `{"path","sha256"}` reference shape; original file size ≤16,000 bytes.

### Custodian accession original

The exact JSON object has `{"schema": "ces.ec406.original_custodian_signed_accession.v1", "claim": {...}, "signature_hex": "<128 lowercase hex characters>"}`. Exact `claim` members:

```json
{
  "schema": "ces.ec406.custodial_accession_claim.v1",
  "directory_lineage_id": "<actual lineage>",
  "publisher_id": "PublisherA",
  "custodian_id": "ExternalCustodianA",
  "epoch_index": 0,
  "sequence": 1,
  "previous_accession_sha256": null,
  "archive_record_id": "OriginalArchiveRecordA0001",
  "original_ec404_signed_capture_receipt_sha256": "<actual original EC404 signed receipt SHA>",
  "original_warc_sha256": "<actual EC405 whole original WARC SHA>",
  "original_rfc3161_sha256": "<actual signed RFC3161 token original SHA>",
  "verified_token_gen_time_utc": "<actual verified EC405 CMS signed genTime as canonical UTC>",
  "claimed_accession_utc": "<custodian's signed claimed canonical UTC>"
}
```

**Signature verification input**, never a request to sign: Ed25519 signature over

`b'CES/EC406/OriginalCustodyAccession/Ed25519/v1\x00' + json.dumps(claim, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')`.

`sequence` must equal `epoch_index + 1`. For every later complete epoch, `previous_accession_sha256` must equal the **actual immediately preceding retained original accession file's SHA** (not an unsigned JSON claim digest). Record ID is unique across all epochs and publishers.

### Separately signed witness original

The exact JSON object has `{"schema":"ces.ec406.original_independent_signed_cross_witness.v1", "claim": {...}, "signature_hex":"<128 lowercase hex characters>"}`. Exact `claim` members:

```json
{
  "schema": "ces.ec406.independent_cross_witness_claim.v1",
  "directory_lineage_id": "<actual lineage>",
  "publisher_id": "PublisherA",
  "witness_id": "ExternalWitnessA",
  "epoch_index": 0,
  "sequence": 1,
  "previous_witness_sha256": null,
  "witness_event_id": "ExternalWitnessEventA0001",
  "signed_accession_original_sha256": "<actual custodian signed original file SHA>",
  "original_warc_sha256": "<real EC405 WARC SHA>",
  "original_rfc3161_sha256": "<real EC405 token SHA>",
  "claimed_witness_utc": "<witness's signed claimed canonical UTC>"
}
```

**Witness signature verification input**: Ed25519 over

`b'CES/EC406/OriginalIndependentCrossWitness/Ed25519/v1\x00' + canonical_json(claim)` using **the independently pinned witness original raw public key**, never the custodian key. `previous_witness_sha256` is the prior actual signed witness file SHA, with the same epoch/sequence and monotone chronology rules. Cross-witness signature cannot be substituted for a custodian accession, or vice versa, due to separate domain separators and two separately pinned keys.

### Original integrity and credit interpretation

- Read via inherited exact SHA/size-bounded, normalized absolute path, no-symlink original reader. Protect the inherited EC405/404, EC399 leaf publisher, EC405 TSA root/CRL and sibling source/key paths. Re-read every opened original by its recorded SHA before output.
- Verify **actual EC399 publisher certificate public keys** to disallow reuse of an Ed25519 publisher key; independently read actual EC404 raw Ed25519 archive keys and EC405 TSA root public keys to disallow their reuse. Different keys do **not** establish distinct employers, ownership, public registration, legal trust or external witnesses.
- Recompute actual genuine RFC3161 signed token `genTime` from the re-opened WARC+token with the inherited pinned EC405 root+policy. The signed accession's `verified_token_gen_time_utc` must equal this value byte-for-byte as a canonical UTC claim. Any missing CRL/adverse old chain or incomplete original EC405 epoch prevents new joint credit.
- Timelines contradicting signed genuine token time, claimed dispute cutoff or monotone signed claims are unresolved with **zero** time-window credit; malformed/forged claim signatures or source linkage are denied.
- Separate outside first original/epoch inventory/whole unsigned inventory SHA mismatches always remain unresolved, never silently recalibrated as successful, and cannot upgrade a bad real parent epoch.

**Validation boundary**: bundled 18 focused local genuine Ed25519/RSA-RFC3161/WARC fixture cases with `EC405.audit` mocked **only inside EC406's child fixture**. The EC405 mocked return was produced by actual local genuine cryptographic EC405 evidence; older EC404 and deeper ancestry are separately synthetic/mock in inherited fixtures. True unmocked external custody, legally qualified TSA, real historic network archive, native PowerShell 7/15 Smoke, OS/Git/CI/Provider/performance, physical WORM and final user acceptance remain **NOT_RUN/NOT_PROVEN**.
