# EC351 — Offline TSA origin attestation and signed OCSP/CRL reconciliation

**V6.61 / R351 / EC351, one bounded EC.** Run a *read-only* offline verifier after the actual EC350 → EC349 → EC337 signed-original replay. Every supplied trust anchor, statement, policy source and OCSP response remains **caller-selected and separately whole-file SHA-pinned**. A real Ed25519 signature authenticates a statement under a supplied Ed25519 public key; it **does not prove that key belongs to a real external organization**. A legitimate RFC6960 OCSP signature binds a bounded response to an issuer/delegated responder; it is **not a network receipt, a complete revocation search, or a legally qualified time source**.

## What is genuinely implemented

1. Call the complete **EC350 audit** afresh, including every EC349→EC337 signed original, the two channel directories, signed receipts and receipt time witnesses, exact RFC3161 signed CMS token original bytes, pinned root X.509, exact signed receipt `messageImprint`, and all explicitly supplied CRLs. Do not accept a JSON report that merely claims the previous audit succeeded. For channels with an actual unique head and supplied timestamp, reread receipt/token/root byte originals and recompute real signature/imprint facts, again.
2. Accept 0–2 **signed authority source statements**, each bound to one presented EC350 TSA channel. The original is canonical UTF-8 JSON, Ed25519 signed with the domain-separated prefix `CES/EC351/TSA-RootPolicySource/v1\0`. A separately supplied **raw 32-byte Ed25519 public-key file**, original source/policy document of up to 1 MiB and their exact whole-original SHA-256 pins are mandatory for each supplied statement. The signed body binds the channel ID, exact TSA root **original SHA** and **X.509 DER certificate SHA**, exact TST policy OID, complete source-document original SHA, exact attester key-original SHA, claimed organization/HTTPS source URL and caller-facing issuance/expiry UTC window. Verify exact signed fields, absence of ambiguous JSON keys, actual Ed25519 signature, UTC limits, original bytes and late-read drift. The source file is **not** parsed or interpreted as legal authority; the claimed URL is **never fetched**.
3. Accept 0–8 independently pinned actual DER **RFC6960 OCSPResponse** originals, with a corresponding caller-declared expected request nonce (16–32 bytes lowercase hex) or `NONE` for **no independently precommitted nonce**. Verify successful BasicOCSPResponse, bounded DER single-response count, supported critical extensions, actual responder signature RSA SHA-256/384/512, ECDSA SHA-256/384/512 or Ed25519, at least 2048-bit RSA / 256-bit EC public key, signer certificate issuer linkage, actual delegated OCSP_SIGNING EKU/basic constraints/digitalSignature and certificate validity. Do not trust an embedded response signer certificate merely because it is in the response. The signer must be the actual verified EC350 issuer (with suitable KeyUsage) or a valid issuer-signed OCSP delegate. Delegate revocation itself remains **NOT_PROVEN**.
4. Match OCSP issuer-name/key hashes and serial against **real certificate IDs generated from each EC350 verified subject/issuer pair**; SHA-1 can identify a certificate but is never permitted as the response signature digest. Reject unbound extra SingleResponses and duplicate certificate IDs within one response. Verify **all** matching OCSP signatures even when multiple responses are present; never let one forged response hide behind an ambiguous multi-response state. Do not invent a freshest winner among multiple matching originals.
5. Inspect signed `producedAt`, `thisUpdate`, `nextUpdate`, `revocationTime` against caller evaluation UTC; require a bounded, complete <=7-day interval for an OCSP observation to be fresh, not a missing nextUpdate or expired response. Verify matching precommitted nonce if given; a response-embedded nonce without a separately fixed request nonce **does not establish liveness**. Reject signed revocation time after response production/evaluation. Compare each certificate edge with the **actually signed EC350 CRL** status at the same caller evaluation time (including source CRL freshness and future-effective revocation). Signed `good`/`revoked` agreement, `unknown`, expired evidence, no CRL, multiple responder snapshots, or explicit CRL/OCSP disagreement stay separate.
6. **Preserve parent severity**: fork/absent head, missing token, unpinned ancestry, EC350 revoked/stale CRL/signed-time discrepancy **cannot** be repaired by a newly signed origin statement or a favorable OCSP response. Every legitimate report has `exit_code: 2`, `*_unresolved`, with exact negative-authority flags. Cryptographic consistency is not actual outside TSA authorization, institutional independence, qualified status, absolute UTC, worldwide revocation completeness, physical handoff, remote Provider/CAS/WORM or final user acceptance.

## Standalone arguments

For both commands, pass **all** EC350 command arguments as documented in [EC350](offline-rfc3161-tsa-provenance.md), including every old EC349 signed original and all TSA token/root/CRL data.

| New flag (audit only) | Meaning |
| --- | --- |
| `--provenance-evaluation-utc` | Required caller UTC `YYYY-MM-DDTHH:MM:SSZ`; must be >= `--tsa-evaluation-utc` |
| `--authority-channel-id` | 0–2 distinct ascending channel IDs that already have an EC350 TSA token |
| `--authority-statement-file` | Ed25519-signed canonical JSON original for each authority channel |
| `--expected-authority-statement-sha256` | SHA-256 of exact signed JSON bytes |
| `--authority-public-key-file` | Separate **raw 32-byte** Ed25519 public key original (no PEM/SPKI) |
| `--expected-authority-public-key-sha256` | SHA-256 of public-key **file bytes**; not proof of external identity |
| `--authority-source-document-file` | Explicit source/policy document bytes, any nonempty format; never parsed, fetched or interpreted |
| `--expected-authority-source-document-sha256` | SHA-256 of whole document original |
| `--ocsp-response-file` | 0–8 DER RFC6960 original OCSPResponse files |
| `--expected-ocsp-response-sha256` | Aligned actual OCSP file SHA-256 pins |
| `--ocsp-precommitted-request-nonce-hex` | One per OCSP original: lowercase even-length 16–32 bytes hex or `NONE`; `NONE` means no nonce liveness inference |

All repeated authority arrays must have **identical** lengths and ascending channel order; all OCSP arrays must be aligned. Each EC351 original path must be absolute, normalized, nonsymlink and different from all other EC351 paths and EC350/EC349 original paths. Every original is byte-size bounded and re-read at end to detect drift. No search paths, OS trust store, HTTP, AIA, live OCSP, user keys, writer or remote CAS/WORM operation exists.

**Standalone read-only:**

```sh
python -I -B scripts/ces_cas_tsa_provenance.py derive-provenance-handoff <all EC350 args>
python -I -B scripts/ces_cas_tsa_provenance.py audit-provenance-evidence <all EC350 args> --provenance-evaluation-utc 2026-10-25T22:00:00Z [new EC351 flags]
```

**Fixed unified entry (isolated child, no signer):**

```sh
python scripts/ces_next.py audit-tsa-provenance DeliveryAudit AuditOfflineTSASourceAndOCSPProvenance <all EC350 args> --provenance-evaluation-utc 2026-10-25T22:00:00Z [new EC351 flags]
```

Sample time above illustrates strict input syntax **only**. Never infer this example is the actual current time.

## Canonical signed authority source original

The JSON statement has *exactly* these keys, no extras or duplicates. Compute the signature over `DOMAIN + canonical_JSON(body_without_signature_ed25519_hex)` using the **external claimant's** Ed25519 signer. Canonical JSON uses CES's deterministic sorted-key UTF-8 encoding (`reg.canonical`). Submit the public key as a separate independently obtained original; the auditor itself **does not create, sign or enroll authorities**.

```json
{
  "schema": "ces.ec351.signed_tsa_root_policy_source_attestation.v1",
  "channel_id": "channel_0",
  "tsa_root_original_sha256": "<64 lower-case hex of supplied root original>",
  "tsa_root_certificate_der_sha256": "<64 lower-case hex of parsed root certificate DER>",
  "tsa_policy_oid": "1.2.3.4.5.350",
  "source_document_original_sha256": "<64 lower-case hex of complete policy original>",
  "attester_public_key_original_sha256": "<64 lower-case hex of 32-byte Ed25519 key original>",
  "claimed_source_organization": "Example external claimed source",
  "claimed_source_uri": "https://example.org/claimed-source",
  "issued_utc": "2026-10-25T22:00:00Z",
  "expires_utc": "2026-10-26T22:00:00Z",
  "signature_ed25519_hex": "<128 lower-case hex Ed25519 signature over DOMAIN + body>"
}
```

Values in angle brackets are explanatory placeholders, **not valid signed inputs**. The external identity string, URL, policy content and independently pinned source/public key still require genuine human-assisted off-platform provenance. The verifier does not bootstrap real trust by verifying a signature under a key supplied in the same call.

## Outcomes and remaining final checks

Outcomes distinguish EC350 absent/forked head, missing token, all inherited EC350 non-ideal states, signed OCSP revocation/conflict, missing signed statement, incomplete/stale OCSP and matching bounded signed data **without independent real-world authority**. Denial statuses are 3 (`permission_denied`), 4 (`invalid_input`) and 5 (`unavailable`). No status says globally PASS/ACCEPT. Parent EC350 output is replayed, not altered.

Real independent signed publisher key custody and official TSA policy, actual third-party OCSP/CRL fetching and trusted UTC, complete global revocation coverage, real historical EC317/318 production signatures, invisible fork completeness, remote CAS/WORM, native PowerShell7 + 15 Smoke, Windows/macOS/Git/CI/Provider/E63–E66 and final human acceptance remain **NOT_PROVEN/NOT_RUN**. Existing EC249 incomplete, EC250 blocked, B-001 OPEN, global Quality=false and final NOT_STARTED are unchanged. Local tests create RSA/Ed25519 certificates, OCSP and tokens **on the same machine**; never advertise them as independent authority.
