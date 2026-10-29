# EC410 original signed LOTL authority chain — bounded receiver contract

## Why this is a separate functional EC

EC409 proves real signatures and source-bound institutional-service status in original national TSL XML, but its independently pinned national signer certificates do **not** say who authorized those signers. EC410 verifies a separately archived **genuine XMLDSig-signed EU list-of-lists**, the signed EU and two national TSL pointers, and a three-certificate issuer-signature path to the actual LOTL signing key. The signed national pointers must contain the **exact original EC409 TSL signer DER** and canonical pinned HTTPS publication locations for the original EC407 territories. Those pointers are verified at the historical EC407 CMS signed-custody UTC and the EC407 evaluation UTC. **Production invokes unmodified real EC409.audit first** (real EC408 OCSP, EC407 CMS/X509/CRL, and every older original audit). A local passed signature never repairs a disputed older receiver.

**Critical distinction:** a certificate *path to a user-pinned trust anchor* is not independent authentication of the anchor's official holder or its historical authority. EC410 does **not** certify any government, Commission/OJEU listing, QTSP, legal qualification, public distribution, independent archival time or a globally valid complete ETSI document. Even all bounded checks consistent return `exit_code:2` and an `_unresolved` status. Local fixture CA keys used for tests are explicitly synthetic and have no external authority.

## Required original local JSON bundles

Each `original` reference is an *exact local original byte file* and independently held SHA-256 digest:

```json
{"path":"/absolute/normalized/archived-original","sha256":"<64 lowercase hex original SHA-256>"}
```

EC410 top bundle: UTF-8 JSON, bounded 135,000 bytes, **exact fields**; parent reference must byte-for-byte refer to the actual original EC409 signed TSL bundle supplied to the inherited EC409 inputs:

```json
{
  "schema":"ces.ec410.original_signed_lotl_bundle.v1",
  "claimed_directory_lineage_id":"<actual inherited EC407 lineage>",
  "parent_ec409_original_signed_tsl_bundle_original":{
    "path":"/archive/ec409/tsl-bundle.json","sha256":"<actual original EC409 bundle SHA>"
  },
  "outside_lotl_operator_roster_original":{
    "path":"/archive/ec410/operator-roster.json","sha256":"<independently stored roster SHA>"
  },
  "epochs":[
    {"epoch_index":0,
     "original_historical_signed_lotl_xml":{
       "path":"/archive/ec410/lotl-historical.xml","sha256":"<true original SHA>"},
     "original_evaluation_signed_lotl_xml":{
       "path":"/archive/ec410/lotl-evaluation.xml","sha256":"<true original SHA>"}}
  ]
}
```

The separately SHA-pinned **original operator roster** is bounded 32,000 bytes. Its two publisher IDs and territories must equal the *actual two* original EC409 `outside_tsl_signer_roster_original` role assignments; the illustrative EU/GB/FR URLs below are not actual official sources:

```json
{
  "schema":"ces.ec410.outside_pinned_lotl_operator_roster.v1",
  "claimed_directory_lineage_id":"<same actual inherited lineage>",
  "lotl_trust_anchor_certificate_original":{
    "path":"/archive/ec410/anchor.der","sha256":"<true anchor DER SHA>"},
  "lotl_intermediate_ca_certificate_original":{
    "path":"/archive/ec410/intermediate.der","sha256":"<true intermediate DER SHA>"},
  "lotl_signer_certificate_original":{
    "path":"/archive/ec410/lotl-signer.der","sha256":"<true end entity DER SHA>"},
  "expected_lotl_distribution_https_uri":"https://lotl.example.test/lotl.xml",
  "assignments":[
    {"publisher_id":"<actual EC409 role A>","scheme_territory":"GB",
     "expected_national_tsl_location_https_uri":"https://tl-a.example.test/original.xml"},
    {"publisher_id":"<actual EC409 role B>","scheme_territory":"FR",
     "expected_national_tsl_location_https_uri":"https://tl-b.example.test/original.xml"}
  ]
}
```

**Do not treat those `example.test` URLs or test-generated certificates as official.** In production the signed EU pointer must bind the exact externally pinned LOTL signer certificate and declared distribution URL; both national pointers must bind the *exact original outside pinned EC409 signer DER*, matching the inherited two national territories and canonical URLs. URL strings are signed identity assertions only: EC410 deliberately makes no network request, receives no HTTP original publication proof and performs no domain-ownership check.

For epochs 1–2 (up to three total), the entire historical/evaluation LOTL original pair may both be `null` to express missing evidence, which forces unresolved flags/count 0; epoch 0 must have both, no half-pairs, no later reappearance after a missing pair. All supplied original XML paths and content digests must be unique and cannot alias inherited source paths. The inherited EC295/372/394 hardened original reader controls path shape and exact bytes and repeats final original readback.

## Signed LOTL accepted cryptographic profile

1. A bounded ETSI-namespace `<TrustServiceStatusList>` with a signed `SchemeInformation` containing exactly EU territory, `TSLType/EUlistofthelists`, canonical increasing sequence, original `ListIssueDateTime` and a later `NextUpdate`. The full document root is SHA-256 referenced through enveloped-signature and exclusive XML C14N. No external URI, DTD/ENTITY, executable XPath/XSLT, duplicate/ambiguous ID, unexpected root element or multi-signature wrapping.
2. Exactly one direct, last-child XMLDSig `Signature` with valid SHA-256 SignedInfo. RSA >=2048 with RSA-SHA256 PKCS#1 v1.5 or P-256 ECDSA-SHA256 (raw r||s) only. The signed `KeyInfo/X509Data/X509Certificate` must be byte-equal to the *outside pinned original LOTL leaf DER*. Optionally XAdES 1.3.2 SignedProperties, but only if explicitly separately SHA-256 referenced, signature-targeted and SigningTime bounded by signed issue/NextUpdate.
3. The SHA-pinned X509 DER chain is **root self-signed → intermediate CA signed by root → LOTL non-CA signer signed by intermediate**. Enforce actual SHA-256 RSA/ECDSA issuer signatures, exact issuer subjects, BasicConstraints CA/leaf, signing/CA key usage, root path capacity, valid chain certificate times at original list issue, SKI/AKI where present, and three distinct public keys also distinct from the two real original EC409 national TSL signer keys. **There is no built-in trusted official root store or independent official trust-anchor provenance**. Unsupported signature algorithms, critical extensions and ambiguous encodings are rejected.
4. A signed `PointersToOtherTSL` area must contain **exactly one matching EU/self pointer and one national pointer per inherited EC409 role**, even if unrelated additional territories appear. The EU/self pointer's signed `ServiceDigitalIdentities/X509Certificate`, `TSLLocation`, pointer type, territory must match LOTL signer DER and the out-of-band pinned original EU location. Each national signed pointer must match original EC409 signer DER, exactly one canonical pinned HTTPS URL, `TSLType/EUgeneric`, and matching country/role. Duplicated matched territories or silently substituted signers fail closed.
5. For both original historical/evaluation LOTL XML files in each available epoch, independently test signed issue/NextUpdate window covers the actual EC407 source-signed CMS custody claim or inherited evaluation UTC, as applicable; source and evaluation signed sequences and issuance may not roll back. An epoch only gets joint publisher credit where both signed LOTL pointers and **real unmodified EC409 parent reports** jointly retain that role at both windows. Source-status disputes, missing pairs or first/epoch/whole outside SHA mismatch set unresolved flags, not PASS.

This is intentionally **not** the complete ETSI TS 119 612/EU LOTL, XMLDSig/XAdES, RSA-PSS or evolving TSLv6 policy validator. It will reject many legitimately formatted real-world LOTL snapshots outside the explicit bounded accepted profile; extending that coverage belongs to a later, separately scoped EC.

## New EC410 required CLI arguments

Every inherited **EC409 audit** scalar and repeated argument stays mandatory and unmodified. See `python -I -B scripts/ces_cas_historical_ec339_signed_tsl.py audit-historical-ec339-signed-tsl --help` for earlier generations, or EC410's `--help` for the entire inherited and new CLI surface. In addition EC410 requires:

```text
--historical-ec339-signed-lotl-bundle-file PATH
--expected-historical-ec339-signed-lotl-bundle-sha256 SHA
--expected-outside-ec410-lotl-operator-roster-sha256 SHA
--expected-outside-ec410-lotl-trust-anchor-der-sha256 SHA
--expected-outside-ec410-lotl-intermediate-ca-der-sha256 SHA
--expected-outside-ec410-lotl-signer-der-sha256 SHA
--expected-outside-ec410-first-historical-lotl-xml-sha256 SHA
--expected-outside-ec410-first-evaluation-lotl-xml-sha256 SHA
--historical-ec339-signed-lotl-epoch-inventory-sha256 SHA    # repeat exactly once/epoch
--minimum-historical-ec339-joint-signed-lotl-publisher-count N # repeat once/epoch; N=0..2
--expected-retained-historical-ec339-signed-lotl-inventory-sha256 SHA # audit only
```

The six independently held SHA pins (operator roster, three cert DER originals, two initial signed LOTL XML originals) must be pairwise distinct. Each signed LOTL epoch records its derived unsigned SHA and expected parent-joint count. The complete inventory SHA must be retained **outside** this receiver before invoking audit. The receiver cannot verify that a supplied outside digest was independently stored; only the user/real auditor can confirm provenance.

## Commands, receiver outputs and denial

Standalone derive (include all inherited EC409 original flags, but omit final retained whole SHA):

```bash
python -I -B scripts/ces_cas_historical_ec339_signed_lotl.py derive-historical-ec339-signed-lotl-inventory --help
```

Standalone source-audit and unified CES router (these have the complete inherited/new options):

```bash
python -I -B scripts/ces_cas_historical_ec339_signed_lotl.py audit-historical-ec339-signed-lotl --help
python -I -B scripts/ces_next.py audit-historical-ec339-signed-lotl DeliveryAudit AuditHistoricalEC339SignedLOTL --help
```

`derive` returns `ces.ec410.unsigned_signed_lotl_inventory_unresolved.v1`, an embedded `unsigned_signed_lotl_original_inventory`, SHA and per-epoch SHA/counts, and `exit_code:2`, **not** evidence of independent holding or final success. Recompute/store the derived SHA independently, require the expected per-epoch digests and count floors and pass the outside retained SHA to `audit`. `audit` returns `ces.ec410.original_signed_lotl_authority_unresolved.v1` with verified old EC409 report/inventory SHA, original input bundle SHA, signed pointer locations, matched original national signer count, joint count and explicit flags. **If bounded inputs are locally consistent, status remains** `ec410_independent_official_lotl_authority_not_authenticated_unresolved` (exit **2**). Invalid/malformed/unavailable sources return denial `ces.ec410.signed_lotl_denial.v1` (exit **3/4/5**). **Never infer official approval, an externally verified qualified time or EC249/EC250/Quality/final acceptance.**

## Deferred final independent verification

Collect genuine archived independent historical and evaluation EU LOTL XML from independently evidenced public/official distribution, authentic external supervising trust-anchor provenance and dated official signer authorization/OJEU references, both actual historical national TSL originals/URLs, independently witnessed SHA pins at relevant dates, full genuine externally issued EC407–409 original ancestry, qualified clock/physical WORM where required, and native PowerShell 7/legacy 15 Smoke and OS/CI/provider integration. Then check an updated standards/profile validator separately if required. None of these facts is fabricated or marked PASS by this round.
