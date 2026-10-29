# EC409 receiver original historically signed ETSI TSL — bounded source contract

## Trust boundary

**Strict profile, not blanket standards compliance.** EC409 adds cryptographic verification of an uploaded original `TrustServiceStatusList` XML for two specific existing EC407 issuer root DER originals. An externally supplied SHA digest and locally valid XMLDSig **do not independently authenticate the TSL operator as an official trust authority**. Official jurisdiction/distribution provenance, approval, legal qualification and public archival history remain explicit unresolved gaps. Never generate fake official material; never silently skip adverse EC408 source constraints.

## Three externally SHA-pinned original manifests

The top-level bundle is an original UTF-8 JSON file, not a source path supplied by its issuer or by arbitrary network lookup:

```json
{
  "schema": "ces.ec409.original_historical_signed_tsl_bundle.v1",
  "claimed_directory_lineage_id": "<the exact actual EC408 lineage>",
  "parent_ec408_original_institutional_ocsp_bundle_original": {"path": "<absolute normalized local original path>", "sha256": "<external SHA256 hex>"},
  "outside_tsl_signer_roster_original": {"path": "<another absolute normalized local original path>", "sha256": "<external SHA256 hex>"},
  "epochs": [
    {"epoch_index": 0, "publishers": [
      {"publisher_id": "<EC407 actual role A>", "original_historical_signed_tsl_xml": {"path": "<original XML>", "sha256": "<SHA256>"}, "original_evaluation_signed_tsl_xml": {"path": "<original XML>", "sha256": "<SHA256>"}},
      {"publisher_id": "<EC407 actual role B>", "original_historical_signed_tsl_xml": {"path": "<original XML>", "sha256": "<SHA256>"}, "original_evaluation_signed_tsl_xml": {"path": "<original XML>", "sha256": "<SHA256>"}}
    ]}
  ]
}
```

The roster is another original JSON file whose content hash is separately pinned:

```json
{
  "schema": "ces.ec409.outside_pinned_tsl_signers.v1",
  "claimed_directory_lineage_id": "<same lineage>",
  "assignments": [
    {"publisher_id": "<actual role A>", "tsl_signer_certificate_original": {"path": "<pinned DER>", "sha256": "<SHA256>"}, "scheme_territory": "GB", "required_service_type_uri": "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"},
    {"publisher_id": "<actual role B>", "tsl_signer_certificate_original": {"path": "<different pinned DER>", "sha256": "<SHA256>"}, "scheme_territory": "FR", "required_service_type_uri": "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC"}
  ]
}
```

The sample territory/role pair is only illustrative: **it does not say any particular institution really holds those designations**. Publisher IDs must be the *actual* two EC407 institutional roles, not fictitious names typed only for this receiver. After epoch zero, a role's whole historical/evaluation pair may both be JSON `null` (unresolved absence, never verified) but a first pair or half-pair cannot be omitted. Missing cannot later reappear; 1–3 total epochs require source-aligned original EC407 CMS statements and the same EC408 evidence chain. Every file path and original content SHA must satisfy EC295/EC372/EC394 hardened reader policy.

## New flags and independent pins

All parent EC408 mandatory scalar and repeat flags are inherited **unaltered**; use the isolated `--help` to enumerate them. New required flags (names shown are the exact CLI spelling):

```text
--historical-ec339-signed-tsl-bundle-file PATH
--expected-historical-ec339-signed-tsl-bundle-sha256 SHA
--expected-outside-ec409-tsl-signer-roster-sha256 SHA
--expected-outside-ec409-a-tsl-signer-certificate-der-sha256 SHA
--expected-outside-ec409-b-tsl-signer-certificate-der-sha256 SHA
--expected-outside-ec409-first-a-historical-tsl-sha256 SHA
--expected-outside-ec409-first-b-historical-tsl-sha256 SHA
--expected-outside-ec409-first-a-evaluation-tsl-sha256 SHA
--expected-outside-ec409-first-b-evaluation-tsl-sha256 SHA
--historical-ec339-signed-tsl-epoch-inventory-sha256 SHA   (repeat once per epoch)
--minimum-historical-ec339-joint-signed-tsl-publisher-count N   (repeat once per epoch; integer 0..2)
--expected-retained-historical-ec339-signed-tsl-inventory-sha256 SHA   (audit only)
```

The seven first original pins (one roster, two signer DER, four first TL XML) must all differ. A bare expected SHA on a file supplied by the same untrusted actor cannot establish independence; its out-of-band provenance is an operational prerequisite, not something EC409 can infer. `derive-...inventory` returns `unsigned_signed_tsl_original_inventory` and its SHA, and each epoch review contains `signed_tsl_epoch_inventory_sha256`. Supply these to the independent hold/store side, then re-supply the retained values for the `audit` command.

## Accepted signed XML subset

- Exactly one root ETSI `http://uri.etsi.org/02231/v2#` `TrustServiceStatusList` with valid `Id`, one `SchemeInformation`, one `TrustServiceProviderList`, one final direct-child XMLDSig `Signature`; no DTD, ENTITY, comments, processing instructions, ambiguous ID, detached reference, XPath/XSLT or unexpected root nodes.
- `<ds:SignedInfo>` uses **exclusive XML Canonicalization** and `rsa-sha256` with RSA >=2048 or `ecdsa-sha256` with P-256, verified using *the exact externally SHA-pinned X509 original DER*. Embedded `<ds:KeyInfo>` X509Certificate must equal that same DER, not an arbitrary self-selected key. X509 digitalSignature key usage and validity at original signed list issuance are enforced.
- Exactly one reference to root ID (or empty same-document URI), with transforms **enveloped-signature then exclusive XML C14N** and SHA256 digest of signed root. Optional XAdES 1.3.2 `QualifyingProperties` must target the actual signature, have one SignedProperties ID and a second independently checked `SignedProperties` SHA256 reference; SigningTime must lie within the signed issue-to-update interval.
- Scheme type `EUgeneric`, pinned two-letter territory, strictly increasing ListIssueDateTime to NextUpdate, nonnegative canonical sequence; service type limited to `CA/QC` or `CA/PKC`. Exact original EC407 issuer root DER must appear exactly once in the typed matching service DigitalId/X509Certificate. Ambiguous duplicate services or bad signed history are denied.
- Required historical UTC equals the **real EC407 CMS signed source's claimed custody UTC**; evaluation UTC equals inherited EC407 evaluator input. A TSL gives granted credit only if claimed snapshot interval covers the required UTC **and** the signed latest eligible service-status event is `granted`. The signed `ServiceHistoryInstance` records are considered; status may not be assumed from a name or unsourced date. Historical/evaluation sequence and issue dates may not roll backwards, including across epochs.
- Bounded original sizes and source counts, exact JSON field sets, two original roles per epoch, SHA original re-read, parent path/key and signer anti-replay checks, independent epoch and entire derived inventory SHA. Adverse parent (including real EC407 CMS/CRL and EC408 OCSP) zeroes parent-joint grant; no source chain may be upgraded by the child's locally good signature.

**Unsupported on purpose**: generic XML signature transforms or c14n other than the strict profile, other EC curve/signature algorithms, multiple signer certificate chains/issuer CRL checks for TSL operators, EU LOTL operator certification, nation-specific TSL policy extensions, full TSL service-qualification interpretation, independent transport provenance, globally complete revocation, qualified independent timestamp and regulatory validation. The strict limitations are part of the interface and may reject otherwise valid ETSI documents; extension requires a separately scoped future EC.

## Result handling and evidence limitations

`derive-historical-ec339-signed-tsl-inventory` is an **unsigned inventory drafting operation**, not an audit proof. `audit-historical-ec339-signed-tsl` returns schema `ces.ec409.original_historical_signed_tsl_unresolved.v1`; successful local cryptographic/issuer matching remains exit **2** with `_unresolved` status and explicit affirmative `...not_proven` flags, never PASS. Malformed/refused sources return controlled 3/4/5 denial schema. The real production chain always executes unmodified `ec408_institutional_ocsp.protocol.audit` and older original audits. Tests use synthetic local signers and mock only EC408 **inside the child fixture**; they do not prove official supervision, public historical retention, true external original access, physical WORM or Windows/CI acceptance.
