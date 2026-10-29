# EC412: original X.509 LOTL CA revocation evidence, intentionally strict offline subset

## Required inherited security context

`ec412_lotl_crl.protocol.audit` first calls **unchanged real**
`ec411_xades_certificate.protocol.audit`. That requires all EC411 audit
inputs, including real EC410 original signed EU LOTL XMLDSig/XAdES
SigningCertificateV2, SHA256 of original signer DER and RFC5035 IssuerSerial,
original EU/national signed pointers and outside root/intermediate/signer
X.509 DER pins, per-epoch and retained inventory pins, plus all EC409→EC407
and earlier originals. An EC412 CRL may **not** substitute for any prior audit.

Production inputs for `derive-*` and `audit-*` include the exact inherited
EC411 audit flags and these additional fields:

| New input | Requirement |
|---|---|
| `--historical-ec339-lotl-crl-bundle-file` | Path to existing bounded JSON bundle, read-only |
| `--expected-historical-ec339-lotl-crl-bundle-sha256` | SHA256 of exact original JSON source bytes |
| `--expected-outside-ec412-first-historical-root-crl-sha256` | SHA256 of epoch-0 historical CRL signed by EC410 pinned root |
| `--expected-outside-ec412-first-historical-intermediate-crl-sha256` | Epoch-0 historical CRL signed by EC410 pinned intermediate |
| `--expected-outside-ec412-first-evaluation-root-crl-sha256` | Epoch-0 evaluation root-issued CRL |
| `--expected-outside-ec412-first-evaluation-intermediate-crl-sha256` | Epoch-0 evaluation intermediate-issued CRL |
| `--historical-ec339-lotl-crl-epoch-inventory-sha256` | Repeat exactly one per inherited epoch, 1–3 |
| `--minimum-historical-ec339-joint-lotl-crl-publisher-count` | Repeat exactly one per epoch, integer 0, 1 or 2 |
| `--expected-retained-historical-ec339-lotl-crl-inventory-sha256` | Audit only; complete digest of all original CRL reviews and inherited parent report |

All SHA flags are lowercase 64-digit nonzero hex. Four first-epoch SHA pins
must be distinct, separately retained before interpreting any self-authored
bundle. Derive must still perform mandatory **real EC411 audit** and cannot
produce a successful or authoritative acceptance. Out-of-band pins are
input claims, *not evidence of when or by whom they were externally retained*.

## Exact original JSON bundle

```json
{
  "schema": "ces.ec412.original_lotl_ca_crl_bundle.v1",
  "claimed_directory_lineage_id": "SAME AS EC410",
  "parent_ec410_signed_lotl_bundle_original": {
    "path": "/absolute/original/ec410_bundle.json",
    "sha256": "64 lowercase hex characters"
  },
  "parent_ec410_outside_operator_roster_original": {
    "path": "/absolute/original/ec410_roster.json",
    "sha256": "64 lowercase hex characters"
  },
  "epochs": [
    {
      "epoch_index": 0,
      "historical_root_ca_crl_original": {"path": "/original/root_hist.crl", "sha256": "64 lowercase hex characters"},
      "historical_intermediate_ca_crl_original": {"path": "/original/mid_hist.crl", "sha256": "64 lowercase hex characters"},
      "evaluation_root_ca_crl_original": {"path": "/original/root_eval.crl", "sha256": "64 lowercase hex characters"},
      "evaluation_intermediate_ca_crl_original": {"path": "/original/mid_eval.crl", "sha256": "64 lowercase hex characters"}
    }
  ]
}
```

The example values are **placeholders**, not accepted genuine originals.
File bytes and SHA identities must come from the independently held original
materials. Each non-missing epoch contains four **different** original CRLs,
with historical and evaluation LOTL XML from the exact inherited source. The
first epoch cannot be absent or partial. A later epoch may be all-`null`
only when its inherited EC411 source epoch is already absent; subsequent
reappearance is forbidden.

CRL algorithm profile (strict by design): genuine canonical DER, SHA256
signature with pinned issuer RSA key ≥2048 or ECDSA P-256; certificate
`KeyUsage.keyCertSign` and `KeyUsage.crlSign` both present; CRL issuer DN
equal to pinned issuer cert subject; SHA256 issuer signature verified over
`tbsCertList`; **exactly** CRLNumber and AuthorityKeyIdentifier CRL
extensions; AKI key identifier equals pinned issuer SKI; optional AKI
serial/name must bind same issuer cert; `CRLNumber` integer >0; no delta,
indirect or external-signer variants. Revoked entries are bounded,
nonduplicated, with positive serial and revocation date no later than
`thisUpdate`; only bounded reason/invalidity extensions supported, and
`removeFromCRL` disallowed. Matching target cert serial **denies**.

`thisUpdate <= signingTime, custody/evaluation UTC < nextUpdate` for each
relevant source window; signer-claimed SigningTime is cryptographically
authenticated but not qualified trusted time. Signed CRLNumber and
thisUpdate strictly increase in historical→evaluation and across later
available epochs for the same CA. Freshness is only relative to supplied
signed source timestamps, not the real present/current revocation state.
CRL bytes are SHA-readback verified and never fetched from CDP URLs.

## Outputs and trust semantics

Derive: `ces.ec412.unsigned_lotl_ca_crl_inventory_unresolved.v1` plus
`unsigned_lotl_ca_crl_inventory`. Audit:
`ces.ec412.original_lotl_ca_crl_unresolved.v1`, both **exit 2** only.
Denial: `ces.ec412.lotl_ca_crl_denial.v1`, exit 3/4/5.
The new fixed audit route is `DeliveryAudit /
AuditHistoricalEC339LOTLCARevocation`, forwarded to an isolated
`python -I -B` child. Strict report/denial shape and denied claims are
checked by the router before forwarding to the caller.

The receiver cannot establish that a root represents the Commission or
any independent supervisory institution, that signed CRLs were publicly
distributed at claimed times, that no out-of-band revocation exists, that
a qualified TSA approved the times, or full legal eIDAS/ETSI compliance.
Historical official X509, independently witnessed distribution and
complete original ancestry must be supplied and jointly validated later.
No network, signing, business writes, PowerShell modifications or PASS.
