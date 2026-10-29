# EC407 historical outside-pinned institutional X.509/CRL and original detached CMS format

**Status:** Implemented in CES V7.17/R407/EC407 as an **offline-only cryptographic evidence receiver**. This is not a public institutional trust root, an accreditation verifier, independent claim of third-party possession, authority mandate, qualified TSA or legal ruling. Every valid limited-scope audit exits **2 unresolved**, never PASS. The two roles are precisely the two publisher IDs from the true unchanged EC406 originals.

## Original binary evidence required

- Two genuine issuer-root DER X.509 originals, two issuer-signed original DER leaf X.509s, each with RSA (2048..8192 bits), issuer/subject, critical BasicConstraints, signing-appropriate KeyUsage, claimed leaf certificate policy OID, validity at claimed signing and at evaluation. Root certificate is self-signed; leaf chains to the externally SHA-pinned actual root; both roles' four cert SPKIs must all be unique and not reused from original EC399 publisher X.509 or EC405 TSA issuer roots.
- One-to-four issuer-signed **original full DER CRLs** for each root, with monotonically increasing `lastUpdate`, `nextUpdate`, issuer signature and no unsupported delta, indirect, out-of-scope revocation. A clean historical/evaluation window requires CRL coverage and no relevant revocation by the claimed moment. Stale, revoked or uncovered evidence can never earn coverage, and must not get auto-replaced by live network queries.
- One **original signed JSON statement** and one **separately saved original binary DER PKCS#7 detached CMS** per publisher per included epoch. Each statement is one exact original JSON file; signature digest is over those exact **raw bytes**, not over reserialized JSON. CMS embeds exactly the already pinned leaf, has SHA256/RSA PKCS#1 v1.5, `contentType`, `messageDigest`, one authentically signed UTC `signingTime`, no attached data, unsigned attrs or unbound extra CRL. `signingTime` is a signer assertion, not a trusted timestamp.
- The true parent EC406 original accession and separate cross-witness plus EC405 WARC/real CMS-signed RFC3161 originals must already exist and be externally pinned; EC407 re-opens them and checks their source SHA and chronology rather than trusting only an unsigned caller hash.

All paths and SHA values use previous EC372/EC394 strict local original-readers. Each reference has exact fields `{ "path": "...", "sha256": "64 lowercase hex characters" }` and paths must be acceptable existing read-only original files, with anti-alias rules enforced. File lengths and full-bundle shapes are bounded in `protocol.py`. External SHA *pins must have actually been obtained independently in reality* to support a third-party chain-of-custody assertion; merely matching one's own generated pins is NOT independence evidence.

## EC407 new original JSON bundle (plus outside SHA pin)

```json
{
  "schema": "ces.ec407.original_external_custody_cms_bundle.v1",
  "claimed_directory_lineage_id": "same-actual-parent-lineage-id",
  "parent_ec406_original_custody_witness_bundle_original": {"path":"/offline/source/ec406_bundle.json", "sha256":"..."},
  "outside_institutional_certificate_roster_original": {"path":"/offline/source/external_roster.json", "sha256":"..."},
  "epochs": [
    {
      "epoch_index": 0,
      "publishers": [
        {"publisher_id":"PublisherA", "institutional_signer_id":"InstitutionA", "original_custody_statement":{"path":"/offline/source/a.json", "sha256":"..."}, "original_detached_cms":{"path":"/offline/source/a.p7s", "sha256":"..."}},
        {"publisher_id":"PublisherB", "institutional_signer_id":"InstitutionB", "original_custody_statement":{"path":"/offline/source/b.json", "sha256":"..."}, "original_detached_cms":{"path":"/offline/source/b.p7s", "sha256":"..."}}
      ]
    }
  ]
}
```

Paths, IDs and hashes are **schematic placeholders, not shipped original evidence**. The exact prior two publisher IDs must be used, not the placeholders; one to three epochs, each with two distinct roles. First epoch requires both real statement/CMS pairs. Later epochs may omit a paired statement/CMS for a role, which is then flagged unresolved and cannot resume that role at a later epoch. A missing half-pair always denies.

## Independently retained roster JSON

```json
{
  "schema":"ces.ec407.outside_pinned_institutional_certificate_roster.v1",
  "claimed_directory_lineage_id":"same-actual-parent-lineage-id",
  "assignments":[
    {
      "publisher_id":"PublisherA",
      "institutional_signer_id":"InstitutionA",
      "root_certificate_original":{"path":"/offline/source/a-root.der","sha256":"..."},
      "leaf_certificate_original":{"path":"/offline/source/a-leaf.der","sha256":"..."},
      "issuer_crl_originals":[{"path":"/offline/source/a-full.crl","sha256":"..."}],
      "expected_certificate_policy_oid":"1.3.6.1.4.1.55555.407.1"
    },
    {
      "publisher_id":"PublisherB",
      "institutional_signer_id":"InstitutionB",
      "root_certificate_original":{"path":"/offline/source/b-root.der","sha256":"..."},
      "leaf_certificate_original":{"path":"/offline/source/b-leaf.der","sha256":"..."},
      "issuer_crl_originals":[{"path":"/offline/source/b-full.crl","sha256":"..."}],
      "expected_certificate_policy_oid":"1.3.6.1.4.1.55555.407.1"
    }
  ]
}
```

Both SHA and key/SPKI uniqueness are checked. Two artificially created files are not two real organizations. This OID in example is a test fixture policy only; **not a recognized accreditation/trust-list policy**.

## Each exact raw original signed statement

```json
{
  "schema":"ces.ec407.original_institutional_custody_statement.v1",
  "directory_lineage_id":"same-actual-parent-lineage-id",
  "publisher_id":"PublisherA",
  "institutional_signer_id":"InstitutionA",
  "epoch_index":0,
  "sequence":1,
  "previous_cms_original_sha256":null,
  "custody_event_id":"A-unique-signed-custody-event",
  "ec406_original_accession_sha256":"...",
  "ec406_original_witness_sha256":"...",
  "ec405_original_warc_sha256":"...",
  "ec405_original_rfc3161_sha256":"...",
  "claimed_custody_utc":"2026-10-26T12:00:00Z"
}
```

The original bytes can include whitespace/field order (CMS signs **raw bytes**). Requiring all exact keys rejects hiding duplicate roles/unknown fields. `sequence` is epoch + 1; `previous_cms_original_sha256` on first epoch is JSON `null`, otherwise it is the actual immediately preceding CMS original SHA. `custody_event_id` must be unique across roles and epochs. The signed claimed time equals the CMS authenticated `signingTime`, is after the true signed EC406 witness time, within the inherited claimed historical dispute cutoff and before evaluation time, and monotone within each role.

## Receiver invocation and exact externally pinned command inputs

The standalone CLI and console operator both require ALL prior EC406 audit options without changes. See `python -I -B scripts/ces_cas_historical_institutional_cms.py audit-historical-ec339-institutional-cms --help` for previous EC339→EC406 argument spellings. New required scalar names (replace `_` with `-` and prefix `--`):

```
historical_ec339_institutional_cms_bundle_file
expected_historical_ec339_institutional_cms_bundle_sha256
expected_outside_ec407_institutional_roster_sha256
expected_outside_ec407_a_root_certificate_der_sha256
expected_outside_ec407_b_root_certificate_der_sha256
expected_outside_ec407_a_leaf_certificate_der_sha256
expected_outside_ec407_b_leaf_certificate_der_sha256
expected_outside_ec407_first_a_statement_sha256
expected_outside_ec407_first_b_statement_sha256
expected_outside_ec407_first_a_cms_sha256
expected_outside_ec407_first_b_cms_sha256
ec407_institutional_evaluation_utc
expected_retained_historical_ec339_institutional_cms_inventory_sha256  (audit only)
```

Add repeated flags (one occurrence per inherited historical epoch):

```
--historical-ec339-institutional-cms-epoch-inventory-sha256 64hex
--minimum-historical-ec339-joint-institutional-cms-publisher-count 0|1|2
```

Use `derive-historical-ec339-institutional-cms-inventory` to compute the **unsigned** original digest(s) for independent checking, not to create or automatically approve external pins. Audit requires expected first originals, full bundle, roster, root/leaf original SHAs, epoch SHA/floors and independent expected whole inventory SHA. Derive and audit JSON return source report SHA, parent inventory SHA, new original bundle SHA, new inventory SHA and per-epoch verified/joint counts.

Console route: `python -I -B scripts/ces_next.py audit-historical-ec339-institutional-cms DeliveryAudit AuditHistoricalEC339InstitutionalCMS ...` in an isolated child interpreter (`python -I -B`). Any normal, valid limited cryptographic verification exits 2 with `_unresolved` status; forged/invalid/unavailable 3/4/5. No PASS and no issuer signing behavior.

## Evidence boundary and trust model

The actual source of X.509 and signed CRLs is not authenticated against any **official externally distributed trust list**. Without verifiably independent real third-party issuer identity and dated public or qualified institutional certification, there is no support for assuming independence, legal qualification, prior public possession, globally current revocation, real dispute cutoff, protected physical WORM, court/government recognition or finished compliance. `custody_witness.protocol.audit` is mandatory and untouched in production; new positive crypto evidence cannot override adverse parent source/history flags. All new test material is locally generated synthetic original bytes and is not included as real production evidence.
