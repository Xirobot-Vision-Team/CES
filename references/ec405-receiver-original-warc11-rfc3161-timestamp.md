# EC405 — Genuine WARC/1.1 response record + RFC3161/CMS timestamp receiver

**Implemented scope:** strictly bounded offline read-only **actual WARC bytes**, **actual RFC3161 TimeStampToken or granted TimeStampResp original**, signed actual WARC-blob SHA256/384/512 imprint, CMS signed attributes and signature, X.509 signer/root path, supplied CRLs and signed token generation UTC. The inherited **unchanged real EC404 public-access audit** must complete first in production; thus its inherited EC403 signed XML, EC402 signed PDF, EC401 OCSP, EC400 native CMS, EC399 X.509/CRL, EC398 gazette and older original checks cannot be skipped or repaired.

**Proof limit:** WARC bytes and authentic RFC3161 signature under a *caller-supplied externally SHA-pinned root* are only bounded local cryptographic consistency. They do not establish the existence of an actual historic network capture, independent custody, independently authenticated TSA trust, real calibrated UTC, legally qualified TSA service, governmental issuer authority, PDF page meaning, globally complete revocation or prior immutable WORM storage. Legitimate local evidence remains `exit 2 *_unresolved`. Deny malformed/forged/unavailable evidence with 3/4/5. No network, issuance, private key use, self-signed evidence creation or business writes in production.

## Complete original input contract

Run a **real EC404 audit** for the full inherited scalar/repeated arguments (including the EC404 audit-only independently retained inventory SHA). EC405 adds **10** required scalars:

| Argument (use `--` + name converted to hyphens) | Source / meaning |
| --- | --- |
| `historical_ec339_warc_timestamp_bundle_file` | Absolute normalized path of original JSON described below |
| `expected_historical_ec339_warc_timestamp_bundle_sha256` | Outside supplied whole-file SHA of the new original bundle |
| `expected_outside_ec405_tsa_roster_sha256` | Independently retained SHA of exact outside TSA registry JSON original |
| `expected_outside_ec405_tsa_a_root_der_sha256` | Independently retained SHA of genuine **DER** root certificate of lexicographically first publisher |
| `expected_outside_ec405_tsa_b_root_der_sha256` | Same for second, distinct TSA root |
| `expected_outside_ec405_first_a_warc_sha256` | First original WARC file SHA for first publisher |
| `expected_outside_ec405_first_b_warc_sha256` | First original WARC SHA for second publisher |
| `expected_outside_ec405_first_a_rfc3161_sha256` | First real RFC3161 original token SHA for first publisher |
| `expected_outside_ec405_first_b_rfc3161_sha256` | First genuine signed token SHA for second publisher |
| `ec405_tsa_evaluation_utc` | Caller-supplied canonical `YYYY-MM-DDTHH:MM:SSZ` UTC for bounded offline CRL freshness; **not** trusted present time |

Six external root/first-original SHA anchors must be distinct. All original path references have **exactly** two members `{"path":"/absolute/normalized/file", "sha256":"64-lowercase-hex"}` and pass existing no-symlink, SHA and size bounds. A PEM root is permitted but its **DER fingerprint** is compared against outside root DER SHA, while the ref pins actual original PEM bytes. Neither DER root nor registry SHA establishes institutional trust without independent external custody.

Per inherited 1–3 epochs also require one of each:

- `--historical-ec339-warc-timestamp-epoch-inventory-sha256 <sha256>`
- `--minimum-historical-ec339-joint-warc-timestamp-publisher-count <0..2>`

The `audit-...` command additionally requires `--expected-retained-historical-ec339-warc-timestamp-inventory-sha256 <sha256>` obtained *independently* from the new input bundle. The `derive-...` command only computes an unsigned inventory to compare with separately retained hash commitments. It does not create evidence or provide an authorization to re-anchor mismatches.

### Genuine original JSON bundle (schema `ces.ec405.original_warc_timestamp_bundle.v1`)

```json
{
  "schema": "ces.ec405.original_warc_timestamp_bundle.v1",
  "claimed_directory_lineage_id": "<exact inherited EC339 lineage>",
  "parent_ec404_original_public_access_bundle_original": {
    "path": "/absolute/genuine-ec404-bundle.json", "sha256": "<outside pinned original SHA>"
  },
  "outside_tsa_roster_original": {
    "path": "/absolute/genuine-tsa-roster.json", "sha256": "<retained SHA>"
  },
  "epochs": [{
    "epoch_index": 0,
    "publishers": [{
      "publisher_id": "PublisherA",
      "warc_original": {"path": "/absolute/source-a.warc", "sha256": "<sha>"},
      "rfc3161_original": {"path": "/absolute/source-a.tsr", "sha256": "<sha>"},
      "tsa_authority_id": "ArchiveAThirdPartyTSA"
    }, {
      "publisher_id": "PublisherB",
      "warc_original": {"path": "/absolute/source-b.warc", "sha256": "<sha>"},
      "rfc3161_original": {"path": "/absolute/source-b.tsr", "sha256": "<sha>"},
      "tsa_authority_id": "ArchiveBThirdPartyTSA"
    }]
  }]
}
```

`<...>` and the paths above are **schematic placeholders, not accepted SHA values or evidence**. Publishers/epochs must match the actual real EC404 original roster and bundle. First WARC **and** first signed token are mandatory for both roles. In later epochs a missing WARC and token must be **both null**; a present WARC with missing token is allowed but marked incomplete/uncredited. Missing late originals never improve credit. WARC, token, TSA root and CRLs may not alias their sibling, source or inherited originals. Re-read every used original by its SHA before returning.

### Outside SHA-pinned TSA roster (schema `ces.ec405.outside_pinned_offline_tsa_roster.v1`)

```json
{
  "schema": "ces.ec405.outside_pinned_offline_tsa_roster.v1",
  "claimed_directory_lineage_id": "<exact inherited lineage>",
  "authorities": [{
    "publisher_id": "PublisherA",
    "tsa_authority_id": "ArchiveAThirdPartyTSA",
    "root_certificate_original": {"path": "/absolute/root-A.pem", "sha256": "<raw original SHA>"},
    "root_certificate_der_sha256": "<outside root A DER SHA>",
    "expected_tsa_policy_oid": "1.2.3.4.5",
    "crl_originals": [{"path": "/absolute/actual-signed-A.crl", "sha256": "<original CRL SHA>"}]
  }, {
    "publisher_id": "PublisherB",
    "tsa_authority_id": "ArchiveBThirdPartyTSA",
    "root_certificate_original": {"path": "/absolute/root-B.pem", "sha256": "<raw original SHA>"},
    "root_certificate_der_sha256": "<outside root B DER SHA>",
    "expected_tsa_policy_oid": "1.2.3.4.6",
    "crl_originals": [{"path": "/absolute/actual-signed-B.crl", "sha256": "<original CRL SHA>"}]
  }]
}
```

Exactly two distinct TSA IDs, external DER root fingerprints, protected original root paths and claimed policies (<= 4 CRL originals each); real CMS path is validated against that root with no system store, AIA, OCSP fetch or alternate trust fallback. A valid signed CRL must cover *each chain edge*, be unique for the issuer, unexpired at the caller-supplied evaluation UTC and show no revocation at/before the genuine signed token time. Missing/stale/ambiguous CRLs remain adverse/uncredited, not fabricated GOOD state. A signer that changes between local epochs without independently established rollover is adverse and receives no newly qualified count.

## Strict byte-level WARC 1.1 profile

A **single original `.warc` file per publisher per epoch** contains exactly three uncompressed `WARC/1.1` `response` records, in the inherited signed EC404 order: `gazette`, `signed_pdf`, `signed_xml`. Each record:

```text
WARC/1.1\r\n
WARC-Type: response\r\n
WARC-Target-URI: https://original-archive-host.example.org/path/to/source\r\n
WARC-Date: YYYY-MM-DDTHH:MM:SSZ\r\n
WARC-Record-ID: <urn:uuid:11111111-1111-4111-8111-111111111111>\r\n
WARC-Block-Digest: sha256:<52-character-uppercase-base32-SHA256-of-entire-HTTP-block>\r\n
WARC-Payload-Digest: sha256:<52-character-uppercase-base32-SHA256-of-HTTP-body>\r\n
Content-Type: application/http; msgtype=response\r\n
Content-Length: <exact ASCII number of HTTP response octets>\r\n
\r\n
<exact original complete HTTP/1.1 response bytes>\r\n\r\n
```

`WARC-Payload-Digest` is optional; if present, verify it against the actual full raw HTTP response body. `WARC-Block-Digest` is mandatory and verified. The record's *complete embedded HTTP response* must match byte-for-byte the **actual EC404 pinned original** including original status line and headers, not merely an invented SHA or body copy. `WARC-Target-URI` must equal the verified **Ed25519 signed EC404 receipt's URL**. `WARC-Date` must equal the genuine EC404 receipt's **claimed** capture UTC (which remains only a claim). Each original WARC record UUID must be globally unique and canonical. Per-record header ≤8192 octets; only the field set above, exactly one of each required field, strict CRLF; exactly three records, no trailing data. This is **a valid strict subset, not a general WARC parser**. WARC `request`, `warcinfo`, metadata, compressed `.warc.gz`, HTTP/2/3, chunked response frames, redirect, arbitrary WARC field extensions and multiple WARC segments are intentionally unsupported; a richer WARC bundle should be adapted separately and tested, **not** silently treated as already validated.

## Signed-time boundary and interpretation

Use existing `ec350_tsa_timestamp.timestamp._tsa_token` to verify actual DER CMS/TSTInfo with full-original-WARC-byte imprint, authenticated signedAttrs and signature, ESS signer certificate binding, pinned X.509 root, validity and announced policy. A version-sensitive asn1crypto 1.5 OID reverse-map registration adjustment avoids false DER roundtrip failures when old CMS/PDF modules were imported first. It does **not** suppress or downgrade any signature, canonical DER, imprint, certificate or CRL check.

For local conservative *qualified-inventory counting only*, accept a timestamp when its cryptographically signed `genTime` is **not earlier than** the genuine EC404 archive receipt's *claimed* capture UTC, **not after** the caller-supplied external *claimed* dispute cutoff, **not after** caller-supplied evaluation UTC, and nondecreasing for its archive publisher role. Each role must supply its own distinct pinned root and signer. Even if every predicate passes, the result stays `_unresolved`: no independent accreditation, historic UTC proof, judicial status, public network existence or physical custody follows from such an input set. EC404 original parent joint coverage must be 2 per epoch for **any** EC405 joint credit; later timestamps cannot repair adverse earlier source flags.

## Commands and test limits

```bash
cd ces
python -I -B scripts/ces_cas_historical_ec339_warc_timestamp.py derive-historical-ec339-warc-timestamp-inventory --help
python -I -B scripts/ces_cas_historical_ec339_warc_timestamp.py audit-historical-ec339-warc-timestamp --help
python -I -B scripts/ces_next.py audit-historical-ec339-warc-timestamp DeliveryAudit AuditHistoricalEC339WarcTimestamp --help
```

Pass the inherited full EC404 **audit** arguments and the new scalars/repeats. The console checks fixed `DeliveryAudit / AuditHistoricalEC339WarcTimestamp`, uses isolated `python -I -B` and independently validates the child's exact audit/denial schema, code, flags and per-epoch monotone count envelopes. No legacy PowerShell R150 script or Smoke test has been edited.

Local synthetic functional cases generate two **genuine RSA-signed RFC3161/CMS** tokens from two local test X.509 roots plus original signed CRLs using OpenSSL, and combine them with real WARC 1.1 records carrying actual EC404 fixture's previously verified original response bytes and Ed25519 receipt claims. **Only the EC404.audit return is mocked within the EC405 child tests**; deeper child fixtures also use their separately disclosed mocked ancestors. These fixtures are *not* an independent archival trust anchor or externally witnessed earlier historical event. Full unmocked external-history replay, multiple real epoch corpora, Windows/macOS, native PowerShell 7/15 original Smoke, public capture provenance, qualified TSA, actual government/court roots, physical WORM and final user acceptance remain NOT_RUN/NOT_PROVEN.
