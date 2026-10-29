# EC380 receiver handoff — actual old EC350 RFC3161 original, signed old EC349 receipt and original issuer revocation (unresolved)

**V6.90 / R380 / EC380.** Exact protocol for a purely offline receiver holding original files. No unspecified old sender path is ever followed; no private key, automatic network request, trust-store lookup, Provider/CAS/WORM action or remote clock. **Every lawful response exits 2/unresolved.** EC380 does not reconstitute old EC349→EC337 canonical ancestor reports or assert a qualified real-world TSA.

## Prerequisite originals

Supply every inherited EC369–EC379 **real production parent input**, including the externally pinned original EC379 source bundle, old EC378 signed registry bundle, original old EC377 transparency bundle, independently retained inventory pins and their per-epoch minima. Do not supply a report claiming EC379 succeeded: the program calls its real `audit()` (which calls production EC378→EC369) before processing the new archive, and binds the *canonical digest of that actual result* to the independently pinned new archive.

The old EC379 source bundle must contain signed original old EC351 attester statements, signer public bytes, unmodified policy-source bytes and the SHA-pinned original TSA root X.509 certificate, all with genuine previous EC352 signed registry authorization. These originals remain mandatory; a signed RFC3161 token does not replace an original source signature. Sender-origin strings from the true older EC353 publication manifest are treated as **denylist labels only**.

## New required input names

| Scalar | Meaning |
| --- | --- |
| `historical_timestamp_archive_bundle_file` | Normalized absolute path to locally received EC380 original archive JSON |
| `expected_historical_timestamp_archive_bundle_sha256` | Independently held whole-file SHA256 for that new archive |
| `expected_retained_historical_timestamp_inventory_sha256` | **Audit only:** independently retained SHA256 from a separately reviewed `derive` result; the verifier cannot certify the operator retained it outside the process |

All old scalar/repeated EC369–EC379 args are still required. Four new **ordered, one-per-epoch** repeat options:

| Logical repeat / CLI | Required property |
| --- | --- |
| `historical_timestamp_evidence_inventory_shas` / `--historical-timestamp-evidence-inventory-sha256` | SHA256 of canonical per-epoch token/receipt/cert/registry evidence, calculated from actual cryptography, not caller-declared events |
| `historical_timestamp_revocation_inventory_shas` / `--historical-timestamp-revocation-inventory-sha256` | SHA256 of canonical real signed CRL/OCSP certificate-edge evidence |
| `minimum_historical_verified_timestamp_counts` / `--minimum-historical-verified-timestamp-count` | Outside-retained per-epoch genuine signed-token/receipt imprint floor in `[0,4]` |
| `minimum_historical_signed_revocation_edge_counts` / `--minimum-historical-signed-revocation-edge-count` | Outside-retained per-epoch fully furnished signed CRL + OCSP edge floor in `[0,16]` |

The **derive** command still requires both per-epoch claimed inventory SHA lists and floors (not the final retained entire-inventory digest). It returns a deterministic **unsigned** verified inventory plus its SHA; operators must retain/compare that SHA independently and furnish it to **audit**. Disagreements are **adverse unresolved** rather than being accepted as authority.

## Archive JSON shape

No optional extra fields, unpinned original paths or opaque "trust" annotations:

```json
{
  "schema": "ces.ec380.receiver_old_ec350_timestamp_original_archive.v1",
  "parent_ec379_canonical_result_sha256": "<SHA256 of actual live EC379 audit result>",
  "ec379_historical_source_archive_original_sha256": "<actual EC379 pinned source-bundle SHA256>",
  "claimed_directory_lineage_id": "<exact live inherited directory lineage ID>",
  "epochs": [
    {
      "epoch_index": 0,
      "timestamps": [
        {
          "tsa_channel_id": "<exact signed old EC351 channel ID>",
          "ec349_receipt_original": {"path": "/receiver/originals/ec349-receipt.json", "sha256": "<whole raw SHA256>"},
          "rfc3161_timestamp_original": {"path": "/receiver/originals/tsa.tsr", "sha256": "<whole raw SHA256>"},
          "tsa_signer_certificate_original": {"path": "/receiver/originals/tsa-signer.der", "sha256": "<whole raw SHA256>"},
          "tsa_intermediate_certificate_originals": [],
          "issuer_crl_originals": [
            {"path": "/receiver/originals/issuer.crl", "sha256": "<whole raw SHA256>"}
          ],
          "issuer_ocsp_originals": [
            {
              "signed_ocsp_original": {"path": "/receiver/originals/responder.ocsp", "sha256": "<whole raw SHA256>"},
              "expected_nonce_hex": "NONE"
            }
          ]
        }
      ]
    }
  ]
}
```

The JSON above shows **one historic epoch**, one TSA channel and one signer with its root as the direct CA; a genuine intermediate chain lists each separately received issuer certificate, in signer-to-root order, up to four. Up to three contiguous epochs are supported. Each epoch has at most four timestamp records, strictly ordered by distinct TSA channel IDs. Each record has up to eight signed CRL and eight signed OCSP originals. The TSA root original **must be the authenticated EC379 root**; the new archive may not substitute a preferred CA root.

The receipt must be an **actual Ed25519-signed EC349 envelope** (`ces.ec349.ed25519_channel_sha_anchor_receipt.v1`); the old claim is exact-field checked and its signature verified against its internally asserted original actor public key, under the unchanged `CES/EC349/OutOfBandSHAReceipt/v1\0` domain. This proves *self-claimed original signature bytes*, **not** independent verification of the old EC349 channel directory, EC348 previous originals, legal actor identity or a fork-free receipt sequence. Signed receipt claim time is compared to the real signed `TSTInfo.genTime` within five minutes as an adverse flag, never as trusted UTC. A higher-sequence receipt's claimed predecessor is *not* opened or credited as an established old EC349 chain.

`rfc3161_timestamp_original` may be genuine DER CMS `SignedData` or RFC3161 granted `TimeStampResp`. The original EC350 parser enforces one CMS signer, version and policy OID, actual EC349 receipt **raw byte** imprint SHA256/384/512, signed `messageDigest` and content type, exact ESS signing-certificate hash, canonical signed-attribute set, actual CMS signature, embedded signer identity, X.509 path to **only** the true signed-source SHA-pinned root, CA/key-usage/EKU and certificate validity at signed time. The separate signer and intermediate original certificates must reproduce the exact embedded path. There is no AIA/network/OS-trust-store fallback.

Every furnished CRL must verify under a *unique actual issuer* in the embedded path even if it is a fork/stale CRL. Multiple CRLs for one issuer never choose an arbitrary winner. For OCSP: real DER response, valid signed responder ID/signature/authorized delegated issuer, CertID match on a real path edge, responder window, this/nextUpdate, bounded fresh-status evaluation, nonce matching if independently specified, signed revocation time relative to TSTInfo and CRL disagreement are evaluated. An unmatched response, duplicate original, malformed/forged signature or unsafe role/path alias is denied; a missing CRL/OCSP, stale snapshot, conflict, UNKNOWN, revoked status or conflicting snapshots remains an **adverse unresolved condition** and may not be translated into Good/Pass. CRL+OCSP evidence is never a complete global revocation census.

## Actual exit behaviors

- `python scripts/ces_cas_historical_timestamp_archive.py derive-historical-timestamp-inventory [all required flags]`: real live EC379→EC369 predecessor audit, real signed-original checks and unsigned canonical inventory. Exit **2** on lawful evidence, even when the new local checks look consistent.
- `python scripts/ces_cas_historical_timestamp_archive.py audit-historical-timestamp-archive [same flags plus expected-retained-inventory-SHA]`: SHA/count floor and actual verified inventory comparisons; exit **2** on lawful evidence, and report clearly which signed evidence was missing/contradictory.
- `python scripts/ces_next.py audit-historical-timestamp-archive DeliveryAudit AuditHistoricalTimestampArchive [full audit flags]`: strict-only Action/Mode, fixed offline `python -I -B` child and exact denial/result fields. No other Action/Mode or caller-provided child executable.
- Exit **3** for permission-denied/forged original; **4** for contract/format invalidity; **5** for unavailable parent/module/original. A denial is never disguised as a lawful unresolved result. No exit zero acceptance path exists.

## Unresolved evidence explicitly deferred

Real old EC349 root/receipt-actor directory key *authorized independently* and the complete historical EC349 channel directory/receipt/witness sequence, full old EC348–EC337 original signed parent reproduction, qualified TSA root custody, signed source official issuer identity, global unseen forks/revocation enumeration, independently calibrated trusted UTC, delegated responder independence, CRL/OCSP outside original retention, remote WORM/CAS custody and legacy native PS7/15 smoke + OS/CI/provider checks. Local test-only OpenSSL private keys/Ed25519 signers are **generated and destroyed in test temp directories**, never included in production files and do not prove an independent outside TSA.
