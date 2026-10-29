# EC350 — Offline SHA-pinned RFC3161 timestamp-token provenance verifier

**Release V6.60 / R350 / EC350.** This is a bounded, public-material-only, offline **verifier**. It is not a time-stamping authority, trust-store administrator, external certification bureau, signing service, network client or remote CAS/WORM host. Older native PowerShell remains V4.60/R150.

## Verify a complete real source chain before considering tokens

Supply the *full* EC349 `audit_dual_anchors` argument set as before (including every old EC348→EC337 document, independent SHA pin, both Ed25519-signed channel directories and all visible channel receipt/time-witness originals). EC350 calls the old complete `audit_dual_anchors` again, not a caller-created verified JSON field, and records the recomputed canonical SHA-256 of its result. It preserves both EC349 heads, any fork, old `UNPINNED` ancestry and inherited unresolved states. A token is only accepted for the **single unique latest visible** EC349 head per channel. If a signed head is missing or forked, a token for it is explicitly denied and there is no latest winner selection.

`derive-tsa-handoff` produces an **unsigned** list of exact head original raw SHA values. It does not issue or request a timestamp. The audit accepts zero, one or two **explicitly furnished** tokens; no discovery of unsubmitted tokens, hidden forks or external files is attempted.

## Additional inputs for `audit-tsa-evidence`

Pass the complete old EC349 options and all of these additions:

| Flag | Cardinality / meaning |
| --- | --- |
| `--tsa-evaluation-utc` | Required `YYYY-MM-DDTHH:MM:SSZ` caller-declared evaluation time; must follow `--dual-evaluation-utc` |
| `--tsa-token-channel-id` | 0–2, ascending distinct EC349 channel IDs, aligned with five following repeated arguments |
| `--tsa-token-file` | Matching actual DER RFC3161 CMS TimeStampToken or granted TimeStampResp original, absolute path |
| `--expected-tsa-token-sha256` | **Actual whole file SHA256**, independently furnished; `UNPINNED` NOT allowed |
| `--tsa-root-certificate-file` | Explicit external root X.509 certificate PEM or DER; same count/order as tokens; same root file and SHA can be shared by channels, with shared root reported |
| `--expected-tsa-root-certificate-sha256` | Whole file SHA256 of that root original; must agree when reusing a root path |
| `--tsa-expected-policy-oid` | Exact expected TSTInfo policy OID for that token, caller-declared, **not authenticated TSA legal policy** |
| `--tsa-crl-file` | Optional 0–8 DER or PEM X509 CRL originals, absolute path, independent of per-channel token count |
| `--expected-tsa-crl-sha256` | Aligned whole-file SHA256 for each CRL; CRL is only a bounded supplied revocation source |

Every new original is size-limited, SHA checked and reread at end; never write, copy, sign, fetch, or use private keys. Inherited actual EC349 bytes are independently reread for SHA-256/384/512 `messageImprint`, *not* copied from a precomputed assertion. One token max per channel; no CRL is invented if not presented.

**Standalone audit**: `python -I -B scripts/ces_cas_tsa_evidence.py audit-tsa-evidence <complete EC349 flags> --tsa-evaluation-utc ... --tsa-token-channel-id ... --tsa-token-file ... --expected-tsa-token-sha256 ... --tsa-root-certificate-file ... --expected-tsa-root-certificate-sha256 ... --tsa-expected-policy-oid ... [--tsa-crl-file ... --expected-tsa-crl-sha256 ...]`

**Unsigned handoff**: `python -I -B scripts/ces_cas_tsa_evidence.py derive-tsa-handoff <complete EC349 flags>`.

**Fixed unified readonly**: `python scripts/ces_next.py audit-tsa-evidence DeliveryAudit AuditOfflineRFC3161TSAEvidence <complete old EC349 flags> <new flags>`; it invokes only the fixed standalone `audit-tsa-evidence` via `python -I -B`. There is deliberately **no** token issuer, signer key, `--out`, network, root-store discovery, remote CAS writer or acceptance override.

## Actually checked RFC/CMS semantics

- DER `id-signedData`, exactly one CMS signer, encapsulated `id-ct-TSTInfo` version 1, genuine SHA-256/384/512 message imprint over the **actual** EC349 receipt bytes, externally expected exact policy OID and fully parsed signed `genTime`.
- CMS signed content type, message digest and canonical signed attribute set; correct CMS SignerInfo digest and digestAlgorithms; ESSCertID (legacy SHA1 for **cert identifier only**) or ESSCertIDv2 must hash the **actual signer certificate DER**, and CMS RSA PKCS1/PSS or ECDSA signed-attribute signature must verify. No SHA1 or MD5 timestamp imprint/signature digest accepted.
- X509 cert signer matched by signed identifier; actual cert signatures and chain from TSA leaf to the *only caller-pinned trust root*, cert validity at token genTime, root/intermediate CA, critical BasicConstraints, key usage, path length and known critical extension enforcement. Leaf timestamping EKU must be **critical and exclusive**; RSA keys at least 2048 bits / EC at least 256 bits. No built-in OS CA store, AIA download or OCSP is consulted.
- Provided CRLs are signed and checked against the exact issuer certificate; a single issuer CRL fresh **under caller-declared evaluation UTC** and no revocation at/before token genTime gives a *bounded supplied-CRL observation*. Missing/stale/ambiguous/delta/limited-issuing-distribution CRLs are explicitly unresolved. A CRL signed by a different key despite the same issuer name is refused. CRLs never prove global/realtime revocation, OCSP, qualified legal status or that the external issuer is genuinely trusted.
- Report signed `genTime` difference from EC349 self-claimed receipt time and between the two channels; a difference exceeding 300 seconds is recorded, not automatically “corrected.” Flag a token time later than the caller-supplied evaluation time. Shared root and shared signer original SHA are disclosed, and no independent institution is inferred.

## Meaning of results / final verification backlog

Seven possible `channel_evidence[].outcome` values: `ec349_channel_receipt_absent_or_fork_unresolved`, `rfc3161_token_not_furnished`, `rfc3161_token_with_unpinned_ec349_ancestry`, `rfc3161_tsa_revoked_at_signed_gen_time`, `rfc3161_offline_crl_missing_stale_or_ambiguous`, `rfc3161_signed_time_vs_claim_or_peer_discrepancy`, `rfc3161_token_signature_chain_imprint_and_bounded_crl_valid_but_external_trust_unproven`. All *valid* outputs are `exit_code=2`, `*_unresolved`; deliberately no global ACCEPT/PASS proof. Invalid original pin, invalid algorithm/chain/token/signature/imprint/policy returns denial 3/4/5, not false success.

`cryptography` and `asn1crypto` are required on the target Python path for **real DER verification**. Missing `asn1crypto` fails with `unavailable`, never a best-effort JSON acknowledgment. Local developer suite also uses `openssl` to **create only synthetic RSA tokens**. Actual independently obtained TSA root custody, provider identity and policy OID/qualified timestamp, signed CRL/OCSP provenance, calibrated UTC, production EC317/318 signatures, physically independent SHA custody, complete hidden-fork discovery, remote CAS/WORM, native PowerShell7 + all 15 Smoke, cross-OS / Git / CI / E63–E66 and final human-assisted acceptance remain to be proven with user-provided genuine outside evidence. EC249/EC250/B001/global Quality remain unresolved as before.
