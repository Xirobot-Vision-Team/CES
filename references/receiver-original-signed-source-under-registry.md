# EC379 receiver protocol — real old EC351 signed source + TSA-root DER under authenticated EC352 signed registry

## Trust and file boundary

The accepted source documents are the *original* EC351 `ces.ec351.signed_tsa_root_policy_source_attestation.v1` canonical JSON, with actual separate SHA-pinned attester Ed25519 public key, source/policy document bytes, and X.509 root certificate bytes. EC379 **does not create** replacement historical credentials or trust an issuer name/URL as identity. Every call first executes the actual production **EC378 audit → EC377 → … → EC369**, including real EC352 registry root/operator signs and EC353 signed Merkle ancestry for old registry originals. New source/registry joins are verified separately, never inherited from a caller-created parent success report.

The entire receiver archive must be canonical JSON and whole-SHA pinned on the CLI. Strict field set:

```json
{
  "schema": "ces.ec379.receiver_historical_ec351_source_original_archive.v1",
  "parent_ec378_canonical_result_sha256": "<sha256 of live canonical EC378 result>",
  "ec378_historical_registry_archive_original_sha256": "<independently pinned parent archive sha256>",
  "claimed_directory_lineage_id": "<the exact authenticated EC378 lineage id>",
  "epochs": [{
    "epoch_index": 0,
    "sources": [{
      "tsa_channel_id": "HistoricTsaChannelA",
      "source_attestation_original": {"path":"/receiver/original-attestation.json","sha256":"<real original SHA>"},
      "attester_public_key_original": {"path":"/receiver/attester-public.key","sha256":"<real original SHA>"},
      "policy_source_document_original": {"path":"/receiver/actual-source.pdf","sha256":"<real original SHA>"},
      "tsa_root_certificate_original": {"path":"/receiver/root.der","sha256":"<real original SHA>"}
    }]
  }]
}
```

The placeholder paths and SHA values are **illustrative and not runnable evidence**. `epochs` length exactly matches 1–3 authenticated historical EC378 epochs; indexes are ascending `0..n-1`. `sources` contains 0–4 sorted unique IDs drawn only from actual old EC378 `claimed_tsa_channel_ids`; a missing source is an unresolved missing-coverage finding. A source requires all four independent whole-SHA-pinned real byte originals: exact canonical EC351 signed source (max 24KB), attester public key (32 bytes), source doc (1MB), X.509 TSA root (EC350 bounded cert size). Original receiver files must be normalized absolute paths with no symbolic links, never historic sender-path labels. Any repeated original path must keep the exact same approved role and SHA; a parent archive/new source/old sender role alias is denied. Independently verified old EC353 publication manifest `path` fields are parsed as untrusted labels solely for exclusion, not opened.

## Source/registry join logic

For every source independently verify original signature of the exact EC351 JSON body (without `signature_ed25519_hex`) under `CES/EC351/TSA-RootPolicySource/v1\0` using the **actual pinned attester public key**. Compare body’s original attester key SHA, source document SHA, raw root SHA, normalized `X509.public_bytes(DER)` SHA, policy OID and TSA channel ID against actual receiver originals. Reject forged Ed25519 signatures even with a caller-updated outside SHA. Check original claimed issue/expiry window, root certificate CA usage and self-signature; this proves **local cryptographic consistency**, not qualified TSA root or public official trust. No EC350 signed timestamp genTime is invented to make an EC351 time relation pass.

EC379 independently reopens original signed EC352 root, root public key, operational public key and event history via old EC352 real signature verifiers and calls old EC352 `_observe_registry` **for each** actual signed source and each of two signed registry channels. The expected six-field exact binding is: `source_attestation_original_sha256`, `attester_public_key_original_sha256`, `source_document_original_sha256`, `tsa_root_original_sha256`, `tsa_root_der_sha256`, `tsa_policy_oid`. Exact valid result requires `authorized_claim_exact_binding` from both registries. Signed source issue time must not predate authentic registry authorization; latest signed records and authorization validity must cover evaluation; signed revocations, prior attester rotations, gaps, forks or contradictory statements remain adverse. Cross-epoch source statement rollback/same-UTC mutation, signer role/key reuse and claimed organization collisions remain unresolved or denied, not cleaned by new registry records. An EC353 signed Merkle leaf proves membership of *registry* originals, not signed EC351 source authenticity or genuine legal authority; the source bytes are newly reauthenticated here.

## Command additions

Both standalone commands carry **every exact EC378 audit parent input** and add `--historical-source-archive-bundle-file` and `--expected-historical-source-archive-bundle-sha256`. `audit-historical-source-archive` additionally requires `--expected-retained-historical-source-inventory-sha256`, the SHA of the **previously derived unsigned verified inventory** retained outside the receiver archive. No source original path is inferred from the old sender/publication labels.

Four per-epoch repeated inputs:

- `--historical-source-attestation-inventory-sha256`: SHA of canonical sorted `[{"tsa_channel_id":…, and the six attestation SHA/policy binding fields}, …]`.
- `--historical-source-registry-binding-inventory-sha256`: SHA of canonical sorted `[{"tsa_channel_id":…, "signed_attestation_original_sha256":…, "signed_registry_statuses":[{"registry_channel_id":…, "real_signed_ec352_binding_status":…}, …]}, …]`.
- `--minimum-historical-signed-source-count`: integer 0–4 per epoch.
- `--minimum-historical-authorized-registry-match-count`: integer 0–8 per epoch, requiring two independent verified EC352 signed statements per original source for the clean local state.

The derive inventory hash is a receiver-generated **unsigned digest**, not a trusted external signature or independent custody claim; the audit-only digest must be supplied by the caller from independent retention. Counters and local flags are exact checked by the fixed unified isolated child protocol. Both lawful results exit code **2** with ordered `unresolved` flags; integrity denials remain exit **3 / permission_denied**, **4 / invalid_input** or **5 / unavailable**. No successful final acceptance status is emitted.

## Excluded evidence / verification backlog

EC379 does **not** reproduce the complete originally signed old EC350→EC337 result, old EC350 RFC3161 token and original receipt bind, CRL/OCSP status at signed timestamp, official legal signer/issuer qualification, complete global registry/log/hidden fork census, independent trusted UTC, physical custody, remote CAS/WORM, private key signer, network, OS trust-store or native PowerShell modifications. Inherited historic deep EC366→EC337 fixture is still MOCKED; no full genuine old EC350→EC337 historical canonical reconstruction claimed. Existing EC249/250/B001/Quality/final gates remain unchanged. These are explicit user-assisted/deferred verification items, not blank future success assumptions.
