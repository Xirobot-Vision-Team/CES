# EC402 — Offline native signed-PDF/ByteRange/CMS original protocol

This is a **strict, deliberately limited signed PDF profile**, **not** full ETSI PAdES certification, legal CA authorization, PDF page semantic proof, independent public history or qualified time. It must execute the unchanged true EC401 signed OCSP historical/evaluation audit first, which runs EC400 native CMS, EC399 original certificate+CRL, EC398 genuine signed gazette and ancestors. No signing or remote reads occur in production code.

## Commands

```bash
cd ces
python -I -B scripts/ces_cas_historical_signed_pdf.py derive-historical-ec339-signed-pdf-inventory --help
python -I -B scripts/ces_cas_historical_signed_pdf.py audit-historical-ec339-signed-pdf --help
python -I -B scripts/ces_next.py audit-historical-ec339-signed-pdf DeliveryAudit AuditHistoricalEC339SignedPDF --help
```

**All EC401 audit arguments remain required verbatim**, including original EC398 notice/source, EC399 two independent SHA-pinned X.509 leaf/roots and signed historical/evaluation CRLs, EC400 CMS original and its outside inventory, EC401 OCSP original and its outside whole inventory and historical/evaluation signed OCSP constraints. The EC402 receiver cannot be run with a caller-made parent report instead.

### New scalar flags

| Input | Behavior |
| --- | --- |
| `--historical-ec339-signed-pdf-bundle-file` | Normalized absolute path to the JSON original bundle described below |
| `--expected-historical-ec339-signed-pdf-bundle-sha256` | Independent complete bundle JSON file SHA-256 |
| `--expected-outside-retained-ec402-first-a-pdf-sha256` | Outside-held SHA-256 of first genuine EC399 roster publisher's epoch-0 signed PDF original |
| `--expected-outside-retained-ec402-first-b-pdf-sha256` | Same for other independent publisher; must differ |
| `--expected-retained-historical-ec339-signed-pdf-inventory-sha256` | **Audit only:** independently held whole unsigned inventory SHA-256, not merely copied from derive output |

### New repeatable flags

| Input | Behavior |
| --- | --- |
| `--historical-ec339-signed-pdf-epoch-inventory-sha256` | One outside-retained per-epoch SHA over each canonical unsigned PDF review row; repeat 1–3 times exactly matching parent historical epochs |
| `--minimum-historical-ec339-joint-signed-pdf-publisher-count` | One independent 0–2 floor per epoch; counts only genuine PDF signatures with complete two-publisher real EC401 OCSP/CMS/CRL prior credit |

The `derive` command returns the **unsigned** inventory, row hashes, and result hashes with `exit 2`. Its values need independent outside retention and review; a derived SHA from the same runtime is not an independent witness. `audit` compares the supplied separate SHA and minimums, never returning legal PASS. Outside mismatches are preserved as unresolved adverse flags. Invalid originals use `3 permission_denied`, wrong input `4 invalid_input`, unreadable/dependency/parent invalid `5 unavailable`.

## Exact bundle schema and original reference rules

```json
{
  "schema": "ces.ec402.signed_pdf_originals_bundle.v1",
  "claimed_directory_lineage_id": "same-real-EC401-parent-lineage-id",
  "parent_ec401_issuer_ocsp_bundle_original": {
    "path": "/absolute/path/to/real-ec401-original.json",
    "sha256": "64-lowercase-hex-sha"
  },
  "epochs": [
    {
      "epoch_index": 0,
      "publishers": [
        {
          "publisher_id": "exact-real-EC399-roster-first-publisher-id",
          "signed_pdf_original": {
            "path": "/absolute/path/to/first-signed.pdf",
            "sha256": "64-lowercase-hex-sha"
          }
        },
        {
          "publisher_id": "exact-real-EC399-roster-second-publisher-id",
          "signed_pdf_original": {
            "path": "/absolute/path/to/second-signed.pdf",
            "sha256": "64-lowercase-hex-sha"
          }
        }
      ]
    }
  ]
}
```

Replace example placeholder SHA with **actual lowercase 64-hex**. First epoch both original references mandatory. Later epochs may set `signed_pdf_original: null` for missing evidence; this never awards PDF credit and sets unresolved flags. Exactly two real EC399 publisher IDs must be present each epoch; bundle/epoch/publisher keys are strictly exact, `epoch_index` contiguous. Original reference paths may not alias parent bundles, source, notice, signer certs, CRLs, source rosters or already used EC402 originals, including earlier epochs. At end, original opened files are read again byte for byte against originally pinned SHA. Maximum PDF file bytes 18 MB, individual CMS gap 2.4 MB, JSON bundle 140 KB; unknown or path-borrowed original is rejected.

## Supported genuine PDF signature profile

1. PDF original **starts `%PDF-`**, ends near `%%EOF`, is not encrypted, has AcroForm with one and only one `/FT /Sig` signed leaf field and `/V` signature dictionary. No XFA, no PDF open action, no extra name trees; bounded recursion/field count. The certificate-bearing signature dictionary has `/Filter /Adobe.PPKLite`, `/SubFilter /ETSI.CAdES.detached` or `/adbe.pkcs7.detached`, exactly four integer `/ByteRange` values and a hex `/Contents`. Other signatures or unsupported formats are denied, not heuristically accepted.
2. ByteRange must be `[0, left, right, filesize-right]`, with `left < right`, exclude **exactly the complete original** `<hex digits>` `/Contents` token, and cover every other byte from the actual original file, including all later revisions. Therefore appended unsigned material or signature wrapping that leaves bytes uncovered cannot pass this strict profile. The pypdf parsed `/Contents` bytes must equal this exact excluded hex token. Cryptographic content is `raw[:left] + raw[right:]`, never bytes emitted by a PDF writer.
3. CMS `/Contents` is one canonical DER `ContentInfo(SignedData)` object followed by zero padding only. Detached `id-data` content, one original pinned signer leaf, one SignerInfo, canonical signed SET attributes (`contentType=data`, SHA2 `messageDigest` of real PDF ByteRange content, `signingTime` asserted at EC398 original signed notice claimed UTC) are mandatory. No `unsignedAttrs`, no unverified CMS embedded CRLs, unknown signer, SHA1, digest mismatch, extra signature or non-canonical DER. The actual signature on signed attributes must verify against that publisher's EC399 externally pinned original X.509 leaf. EC399 historical/evaluation CRLs and EC401 authentic signed GOOD OCSP continue to constrain joint credit; CMS cannot override adverse status.
4. PDF `/Names` must have exactly one **uncompressed** embedded-file stream, named `CES_EC398_GAZETTE_ORIGINAL.bin`, whose decompressed bytes (no `/Filter` allowed) match **the complete original EC398 gazette source bytes**, independently SHA-reopened and matched to the genuinely signed EC398 registrar notice. This is binary inclusion only: no PDF text extraction/visual content correspondence assertion. The uncompressed-only profile prevents zip-bomb decompression while verifying source equality.
5. Each locally verified PDF adds one role to `verified_actual_signed_pdf_count`. Joint count for an epoch can be positive only when unmodified EC401 cryptographic audit reports **both** original OCSP publishers actually credited (and all ancestor requirements met); incomplete parent cannot be repaired by a newer PDF. Always `*_unresolved`.

**Consciously outside this EC:** interactive/non-detached PDF signatures, multi-signature incremental PAdES, full ETSI signaturePolicy/signingCertificateV2 timestamp/LTV/DSS/VRI verification, PDF rendering/visual layout truth, revoked certificate global census, independent authenticated actual public CA/accreditation, actual government legal publication authority, previous independent internet/court archives, qualified RFC3161 timestamp for PDF itself, XMLDSig and manufacturer-certified hardware WORM. No legal fact may be inferred just because a local synthetic signature cryptographically verifies.

## Environment and bounded observations

Locally used Python 3.13, `pypdf 5.9.0`, `asn1crypto 1.5.1`, `cryptography 46.0.4` for 20/20 focused real synthetic signed-PDF tests. EC401 audit patched in EC402 child tests to a **locally cryptographically generated EC401 report** (with its deeper fixture mock boundary); production `signed_pdf.protocol._engine()` does not mock and genuinely calls `parent.audit(...)`. Prior full unmocked external production lineage, Windows/macOS/native PS7/15 Smoke, provider E63–E66, performance and final user-assisted acceptance all NOT_RUN. External government/legal/qualified TSA/public prior-public record/physical certified WORM NOT_PROVEN.
