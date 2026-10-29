# EC404 — Externally pinned offline HTTP-capture receipt verifier

**Status:** bounded working receiver, not legal / independent public-archive accreditation. The two archive Ed25519 keys and outside original hashes must be obtained independently before this receiver runs. Signing helpers exist **only in local synthetic test fixtures**; the production code only reads and verifies originals.

## Claim strength and threat model

The receiver establishes, at most, that a retained original Ed25519-signed claim from an externally SHA-pinned supplied archive public key binds three retained **raw HTTP/1.1 200 OK response originals** whose **entire response bytes** are SHA-pinned and whose unencoded bodies match the *actual* EC398 gazette original, EC402 publisher signed PDF original, and EC403 publisher signed XMLDSig original byte-for-byte. It also establishes consistency of signed claimed capture UTC against genuine EC398 registrar **claimed** publication UTC and an **externally furnished claimed** dispute cutoff. It verifies read-only copies and original hashes; it cannot prove that the HTTP response came from a live public server, that the archive key belongs to an institution, that these files were available before a real-world dispute, that timestamps are independent/qualified, or that the issuer had any statutory authority.

Production MUST first invoke the **unchanged real** `ec403_signed_xml.protocol.audit`, which itself invokes unchanged EC402 PDF/CMS, EC401 OCSP, EC400 CMS, EC399 X.509/CRLs, EC398 signed notice and all deep ancestor audits. It rejects a false parent report or missing true original archive bytes; valid new receipts never repair parent evidence. Parent status remains `*_unresolved`. No networking, HTTP fetch, private keys, archive signing, source rewriting, generated original evidence or business writes.

## Original bundle, roster and explicit anchors

`historical_ec339_public_access_bundle_file` points to an original canonical JSON document (whole original bytes pinned by `expected_historical_ec339_public_access_bundle_sha256`):

```json
{
  "schema": "ces.ec404.original_public_access_bundle.v1",
  "claimed_directory_lineage_id": "<the exact inherited EC339 lineage>",
  "parent_ec403_original_xmldsig_bundle_original": {"path": "<absolute original EC403 bundle>", "sha256": "<64 lowercase hex>"},
  "outside_archive_roster_original": {"path": "<absolute original roster>", "sha256": "<64 lowercase hex>"},
  "epochs": [
    {"epoch_index": 0, "publishers": [
      {"publisher_id": "PublisherA", "signed_archive_receipt_original": {"path": "<original receipt A>", "sha256": "<64 lowercase hex>"}, "captures": [
        {"kind": "gazette", "http_response_original": {"path": "<raw HTTP original>", "sha256": "<64 lowercase hex>"}},
        {"kind": "signed_pdf", "http_response_original": {"path": "<raw HTTP original>", "sha256": "<64 lowercase hex>"}},
        {"kind": "signed_xml", "http_response_original": {"path": "<raw HTTP original>", "sha256": "<64 lowercase hex>"}}
      ]},
      {"publisher_id": "PublisherB", "signed_archive_receipt_original": {"path": "<original receipt B>", "sha256": "<64 lowercase hex>"}, "captures": ["<the same exact three-kind structure>"]}
    ]}
  ]
}
```

* `<...>` examples are schematic only, **not** valid evidence. Original file refs use exactly two fields (`path`, `sha256`) and must pass existing symlink/normalization/SHA/size safeguards. Two roles and 1–3 ordered epochs are mandatory, each role must have **both** a real previous PDF and XML original. First-epoch genuine receipts cannot be absent. A missing later receipt must be `null` with no orphan captures: it is **unresolved**, never credit.
* The external archive roster original contains exactly `schema=ces.ec404.externally_pinned_archive_roster.v1`, `claimed_directory_lineage_id`, and two `archives` objects with exactly `{publisher_id, archive_id, archive_public_key_original, allowed_public_origin}`. `archive_public_key_original` is the raw **32-byte Ed25519 public key**; its SHA-256 must match a **separate outside** `expected_outside_retained_ec404_archive_a_key_sha256` or `_b_key_sha256`. Distinct archive IDs/keys/paths required; archive keys may not equal genuine EC399 Ed25519 publisher leaf keys. Roster SHA is independently pinned with `expected_outside_retained_ec404_archive_roster_sha256`. `allowed_public_origin` must be an exact lowercase public-DNS HTTPS origin like `https://public-a.example.org` — it is not contacted or authenticated by TLS in this offline verifier.
* All three response originals per role and each receipt must occupy unique paths, with no aliases to reopened inherited protected originals. The reader checks absolute pinned SHA-256 on first access and reopens all read originals before finishing.

## Signed original receipt wire shape

The receipt itself is a strict JSON object with exactly `schema`, `claim`, and `signature_hex`. The outer schema is `ces.ec404.original_signed_public_access_receipt.v1`; `signature_hex` is 128 lowercase hex characters encoding one real Ed25519 signature over this **exact** deterministic byte message:

```python
b'CES/EC404/OriginalCapturedHTTPReceipt/Ed25519/v1\x00' + json.dumps(
    claim, sort_keys=True, separators=(',', ':'),
    ensure_ascii=True, allow_nan=False
).encode('ascii')
```

This is a **CES-specific signed receipt wire format, not RFC3161, COSE, XAdES, a TLS notarization format, official WARC provenance, or a legally qualified certificate**. No signing code is included in the production receiver. The signed `claim` has exactly:

| Field | Meaning |
| --- | --- |
| `schema` | `ces.ec404.public_access_capture_claim.v1` |
| `directory_lineage_id` | exactly the inherited verified lineage |
| `publisher_id` | genuine EC399 role, exactly one of two |
| `archive_id` | externally pinned roster archival claimant for this role |
| `epoch_index`, `sequence` | strict integer epoch index and sequence = epoch index + 1 |
| `previous_receipt_sha256` | `null` for first epoch; prior *actual original receipt SHA-256* subsequently |
| `claimed_capture_utc` | canonical `YYYY-MM-DDTHH:MM:SSZ`; strictly increasing for each archival claimant and no earlier than genuine EC398 signed claimed publication UTC |
| `source_original_sha256` | reopened genuine EC398 original opaque gazette SHA |
| `signed_pdf_original_sha256` | matching genuine EC402 publisher original signed PDF SHA |
| `signed_xml_original_sha256` | matching genuine EC403 publisher original XMLDSig SHA |
| `captures` | exactly three entries in order: `gazette`, `signed_pdf`, `signed_xml`, each exactly `{kind, public_url, http_response_sha256}` |

Every `public_url` must be an exact bounded HTTPS public-DNS URL on its role's externally pinned `allowed_public_origin`, with distinct unencoded paths and no query/fragment/user info/redirect/HTTP downgrade. Capture UTC after the **user-furnished** `expected_outside_ec404_dispute_cutoff_utc` is recorded as an unresolved conflict, yielding **zero qualifying joint credit** for that role. This is only a signed-claim ordering predicate; it is not independent historical timestamp verification.

Each `http_response_sha256` matches the entire raw response original referenced by its associated capture entry in the unsigned original bundle. The response must use the **restricted subset**:

```text
HTTP/1.1 200 OK\r\n
Content-Type: application/pdf\r\n
Content-Length: <decimal ASCII body octets>\r\n
\r\n
<exact original PDF bytes>
```

`gazette` requires `application/octet-stream`; `signed_xml` requires `application/xml`. Header size ≤8192 bytes, at most 15 header lines, duplicates/folding/control characters forbidden. Optional ASCII `Date`, `ETag`, `Last-Modified`, `Cache-Control`, `Server` are accepted without treating their values as trustworthy time. Any chunking, compression, redirect, TLS transcript, HTTP/2 or HTTP/3, ambiguous content type/length, additional header, body substitution or trailing body is outside this deliberately narrow profile and is rejected. It does **not** claim general-purpose HTTP/WARC conformance.

## Command interface

```bash
cd ces
python -I -B scripts/ces_cas_historical_ec339_public_access.py derive-historical-ec339-public-access-inventory --help
python -I -B scripts/ces_cas_historical_ec339_public_access.py audit-historical-ec339-public-access --help
python -I -B scripts/ces_next.py audit-historical-ec339-public-access DeliveryAudit AuditHistoricalEC339PublicAccess --help
```

Supply every inherited EC403 **audit**, not EC403 derive, scalar/repeated pin unchanged. The EC404 new scalar arguments are the eight names in `ec404_public_access.protocol.NEW_SCALARS` (`--` plus dashes). For each inherited epoch provide exactly one `--historical-ec339-public-access-epoch-inventory-sha256` and one `--minimum-historical-ec339-joint-public-access-publisher-count` (0–2). The audit additionally requires `--expected-retained-historical-ec339-public-access-inventory-sha256`, independently retained outside the current original bundle. Derive emits an **unsigned calculated inventory**, suitable for comparison, not an authorization to trust freshly generated hashes. External pins cannot be invented or silently taken from the signed claim.

Normal answers: exit 2 and one `*_unresolved` schema (`ces.ec404.public_access_capture_unresolved.v1` for audit, `ces.ec404.unsigned_public_access_inventory_unresolved.v1` for derive). Invalid input/forgery/unavailable: exit 3/4/5, explicit denial schema and reason. Per-epoch review gives signed receipt count, signed **claimed** pre-cutoff count, conservative joint inherited credit, external epoch SHA and actual parent joint count. Three standing policy flags are always true; all 11 forbidden-success `NEGATIVES` always false. No final approval is reported.

## Local and final validation boundary

A local focused fixture can construct genuine separate archive Ed25519 signatures and actual HTTP response originals. It mocks only the **EC403.audit return** in the EC404 child tests, returning a synthetic parent report previously verified using genuine locally signed XML/PDF but with still-mocked deeper historical ancestry. Nothing here establishes real external issuer provenance, independent government/court trust, pre-dispute availability, real HTTP server observability, legal qualified time, global OCSP/CRL coverage, hardware WORM, native PowerShell acceptance or complete provider/OS/Git/CI/performance compatibility. These require independent user-supplied original evidence and final manual testing.
