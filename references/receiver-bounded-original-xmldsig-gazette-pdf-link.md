# EC403 restricted *original* XMLDSig receiver — wire contract and security boundaries

Release **V7.13/R403**, exactly one post-EC402 construction increment. This is
**one strict interoperable XMLDSig profile**, not a generic XML signature or
XAdES validator and not a signature generator. All original XML and ancestral
bytes are reopened read-only and SHA-pinned; authentic ancestry runs unchanged.

## Commands

```bash
cd ces
python -I -B scripts/ces_cas_historical_original_xmldsig.py derive-historical-ec339-original-xmldsig-inventory --help
python -I -B scripts/ces_cas_historical_original_xmldsig.py audit-historical-ec339-original-xmldsig --help
python -I -B scripts/ces_next.py audit-historical-ec339-original-xmldsig DeliveryAudit AuditHistoricalEC339OriginalXMLDSig --help
```

Mandatory: **every** previous EC402 `audit-historical-ec339-signed-pdf`
input flag, including its genuine EC401/EC400/EC399/EC398 parents, historical
roots, original outside hashes, all per-epoch pins, and **the EC402 whole
unsigned inventory SHA**. They are all required: an XML child caller cannot
supply a prebuilt successful EC402 report. Production calls the unchanged real
`signed_pdf.protocol.audit()` and checks its entire unresolved status,
report schema, original PDF bundle SHA, receiver inventory SHA, flags, epoch
counts and conservative joint parent PDF/OCSP credit. Synthetic tests mock
*only the call to the parent audit*, with a report actually derived from the
older local crypto fixture; this is **not** proof of an unmocked full ancestry.

EC403 additions (all required, except the last only for `audit`):

| Flag | Meaning |
| --- | --- |
| `--historical-ec339-original-xmldsig-bundle-file` | normalized absolute local JSON bundle path |
| `--expected-historical-ec339-original-xmldsig-bundle-sha256` | independently retained SHA256 of unchanged original JSON bytes |
| `--expected-outside-retained-ec403-first-a-xml-sha256` | original first epoch publisher A XML bytes SHA256 |
| `--expected-outside-retained-ec403-first-b-xml-sha256` | separately retained first epoch publisher B XML bytes SHA256; different from A |
| `--historical-ec339-original-xmldsig-epoch-inventory-sha256` | repeated one per epoch (1–3); derived normalized local inventory fingerprint, held outside |
| `--minimum-historical-ec339-joint-xmldsig-publisher-count` | repeated independently held floor 0..2 per epoch; credit needs all original parent OCSP/PDF validations |
| `--expected-retained-historical-ec339-original-xmldsig-inventory-sha256` | separately retained whole unsigned inventory SHA256; required for `audit` |

`derive` is also a real validator. Its computed inventory hashes are
**not** external evidence until independently held by another custodian.
The scope never silently treats local derived hashes as preexisting pins.
All normal but non-conclusive results return `exit_code=2` and `_unresolved`;
invalid/forged/unavailable results use 3/4/5 with explicit `reason_code`.

## Original bundle shape

The bundle must be a JSON object with **exactly** these fields:

```json
{
  "schema": "ces.ec403.original_xmldsig_bundle.v1",
  "claimed_directory_lineage_id": "ACTUAL_INHERITED_LINEAGE_ID",
  "parent_ec402_signed_pdf_bundle_original": {
    "path": "/actual/absolute/original/ec402-bundle.json",
    "sha256": "ACTUAL_64_LOWERCASE_HEX_SHA256"
  },
  "epochs": [
    {"epoch_index": 0, "publishers": [
      {"publisher_id": "PublisherA", "signed_xml_original": {
        "path": "/actual/absolute/original/PublisherA.xml",
        "sha256": "ACTUAL_64_LOWERCASE_HEX_SHA256"
      }},
      {"publisher_id": "PublisherB", "signed_xml_original": {
        "path": "/actual/absolute/original/PublisherB.xml",
        "sha256": "ACTUAL_64_LOWERCASE_HEX_SHA256"
      }}
    ]}
  ]
}
```

`null` original references may occur in **later** epochs and remain flagged
`missing`; they do not become credited or repaired. Both first epoch signed XML
originals are **mandatory**, and neither may reuse any original PDF, cert,
roster, bundle, signed notice, or ancestor source path. Parent bundle / role /
epoch / issuer ordering must match actual reopened originals. All originally
opened bytes are re-read and SHA256 rechecked before returning a result.

## The only accepted XML syntax / algorithms

- The original is a bounded, well-formed UTF-8 XML 1.0 document with exactly
  one root `{http://www.w3.org/2000/09/xmldsig#}Signature` and four exact
  children in this order: `SignedInfo`, `SignatureValue`, `KeyInfo`, `Object`.
- `SignedInfo` contains `CanonicalizationMethod`, `SignatureMethod`, one
  `Reference` only. Canonicalization is **exclusive XML C14N 1.0 without
  comments** (`http://www.w3.org/2001/10/xml-exc-c14n#`). The only Reference
  URI is `#ces-ec403-original-gazette`; the **only Transform** is exclusive
  C14N (no XPath, XSLT, base64 transform, external URI or document subpath).
  The DigestMethod is SHA256 (`http://www.w3.org/2001/04/xmlenc#sha256`).
- `KeyInfo` contains **one** X509Data / X509Certificate. Base64 canonical DER
  must byte-match the genuine EC399 original externally root/policy/leaf-SPKI
  pinned signer leaf, not merely a matching CN or one supplied by the XML.
  Signature over canonical `SignedInfo` must verify with the real leaf key:
  RFC9231 Ed25519 (`.../2021/04/xmldsig-more#eddsa-ed25519`), XMLDSig
  ECDSA P-256 SHA256 / P-384 SHA384 using fixed-size raw `r || s`, or RSA
  SHA256 PKCS#1 v1.5 with strong 2048–8192-bit key and exponent 65537.
  Weak RSA, SHA1, HMAC, missing/extra signatures, unsupported curves or
  unsupported methods are denied; no algorithm fallback.
- A single `ds:Object Id="ces-ec403-original-gazette"` has a single child
  `{urn:ces:ec403:original-gazette-claim:v1}GazetteClaim`, itself containing
  one `{urn:ces:ec403:original-gazette-claim:v1}SourceBytes` canonical
  base64 element. GazetteClaim has exactly seven attributes:
  `PublisherId`, `DirectoryLineageId`, `EpochIndex`, `PublishedUTC`,
  `SourceSHA256`, `ParentPDFSHA256`, `Encoding=base64`. It contains the actual
  complete EC398 opaque source bytes (max 240 KB), **byte-for-byte equal** to
  the genuine reopened signed EC398 source; parent original PDF SHA must be
  the exact matching **real EC402 publisher role/epoch original**, not a
  caller-provided PDF digest claim. `PublishedUTC` equals the signed EC398
  registrar notice time formatted as `YYYY-MM-DDTHH:MM:SSZ` (with fractions
  only if present in the authentic timestamp); this is a *claimed* time,
  not an independent TSA proof.
- No DTD, external entities, comments, processing instructions, arbitrary
  ID lookup, second SignedInfo, multiple References, unknown elements,
  unsigned extension content, XML wrapping, missing/duplicate roles,
  network/file entity dereferencing or document transformation is permitted.
  Parser: lxml with `resolve_entities=False`, `load_dtd=False`,
  `no_network=True`, `huge_tree=False`, `recover=False`, and strict grammar.

The fixed authenticated Object binds the raw source **and** the source SHA,
role ID, lineage, epoch, parent original PDF SHA and registrar claimed UTC.
Digesting the Object alone is never sufficient: its SHA256 must be in the one
verified SignedInfo signed by the original pinned publisher leaf.

## Results and deliberate legal boundary

`ces.ec403.original_xmldsig_unresolved.v1` provides true local original
XMLDSig checks, `original_xmldsig_epoch_reviews`, the conservative joint
EC402→XML credit and outside inventory fingerprints. Always exit 2; a local
verified cryptographic signature cannot upgrade failed EC402/OCSP/CRL/CMS
credit. Negative-capability fields remain **false**. This is not a general
XMLDSig 1.1 / XAdES / ETSI profile compliance test, official government or
court issuer authorization, independent qualified legal time, visual PDF text
render verification, true prior public archival availability, global OCSP/CRL,
physical manufacturer WORM or final user acceptance. Never imply any of these
from local certificates, hashes or synthetic signed test originals.

Runtime dependencies: Python 3.13, lxml 6.x, cryptography 46.x; EC402 parent
additionally requires pypdf and asn1crypto. The receiver makes no outbound
network requests, does not generate signatures, and does not mutate the
original data or PowerShell/CI/Provider/CAS/WORM state.
