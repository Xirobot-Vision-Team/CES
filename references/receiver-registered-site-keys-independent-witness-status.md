# EC394 original-wire contract — third-party site registration, key lineages, signed status and visible log forks

**Delivery V7.04/R394/EC394.** Single additional offline, **read-only receiver** on the unchanged EC393 signed custody receiver. Genuine SHA-256 byte identity, Ed25519 original claims and independent RFC3161 DER/CMS timestamps are mandatory for each positive bound. Supplying newly minted registrar/witness/cutoff keys **does not** make an externally licensed notary, a physical independent site, a historic legal dispute, a globally complete key revocation list or historical storage custody.

## Entry points and immutable parent

From `ces/` use `python -I -B scripts/ces_cas_historical_registered_witness.py derive-historical-ec339-registered-witness-inventory --help` or `... audit-historical-ec339-registered-witness --help`. The unified CLI exposes **audit only**, fixed `python -I -B scripts/ces_next.py audit-historical-ec339-registered-witness DeliveryAudit AuditHistoricalEC339RegisteredWitness --help`. Both accept **all** EC393 audit arguments unchanged, and the EC394 additions below. The receiver executes `custody_anchor.custody_anchor.audit(**inherited)` itself. EC393 invokes real EC392, then the two real EC391 audits, and existing parent chains. No supplied parent verdict, cached PASS, or test-only parent mock is accepted in production.

New mandatory scalar switches:

| Switch | Meaning |
|---|---|
| `--historical-ec339-registered-witness-bundle-file` | Absolute, normal, existing EC394 bundle original path |
| `--expected-historical-ec339-registered-witness-bundle-sha256` | SHA-256 of exact original bundle bytes |
| `--expected-outside-retained-ec394-trust-roster-sha256` | Independently held registrar/dispute/witness public-key roster SHA |
| `--expected-outside-retained-ec394-tsa-registry-sha256` | Dedicated witness TSA trust registry original SHA (different root from EC391/EC393) |
| `--expected-outside-retained-ec394-prior-witness-original-sha256` | Externally pre-retained SHA for first genuine signed witness original (epoch 0, first listed witness) |
| `--expected-outside-retained-ec394-dispute-notice-original-sha256` | External SHA pin of original independently signed dispute notice |
| `--expected-outside-retained-ec394-registrar-public-hex` | Exact original raw 32-byte Ed25519 registrar key, lowercase hex |
| `--expected-outside-retained-ec394-dispute-authority-public-hex` | Exact original raw 32-byte Ed25519 dispute-attestor key, lowercase hex |
| `--expected-retained-historical-ec339-registered-witness-inventory-sha256` | **Audit only:** independently retained unsigned whole inventory SHA |

Repeat precisely **one of each per inherited historical epoch** (1–3):

- `--historical-ec339-site-registration-inventory-sha256` (canonical four-role status inventory)
- `--historical-ec339-third-party-witness-inventory-sha256` (two independent observer original inventories)
- `--minimum-historical-ec339-pre-handoff-registered-site-count` (integer 0–4)
- `--minimum-historical-ec339-pre-cutoff-witness-count` (integer 0–2)

The SHA and lower bounds are *caller-supplied outside-retained pins*: they are compared, not minted as proof of prior independent retention. Derive returns the full **unsigned** inventory so it can be reviewed and archived externally; audit outputs digest and summaries, not the unsigned body. Creating a digest and immediately echoing it back has zero historic custody significance.

## SHA-pinned original reference format

All references have **exactly** `{"path":"/normal/absolute/existing/regular","sha256":"<64 lowercase hex>"}`. Hashes refer to **raw bytes**, not pretty-printing or reserialization. Parent EC372 canonical no-symlink, path-length, exact SHA, size bounds and reread checks apply. Independently presented EC394 signed originals / raw keys / tokens / site identities / opaque dispute source must not reuse existing parent original paths or other role originals (same existing old signed log Head may be witnessed by both witnesses). Alternative signed log Heads are also original-path- and digest-pinned, and may be shared by multiple witness observations only when original path and SHA agree. Source paths are never treated as an authority claim.

## Top-level original bundle

`schema = ces.ec394.original_registered_custody_and_witness_bundle.v1`, exact keys:

`schema`, `claimed_directory_lineage_id`, `parent_ec393_custody_bundle_original`, `external_trust_roster_original`, `witness_tsa_registry_original`, `original_dispute_case_file`, `signed_dispute_notice_original`, `dispute_notice_rfc3161_token_original`, `key_status_snapshot_original`, `key_status_snapshot_rfc3161_token_original`, `witness_tsa_authority_id`, `site_key_histories`, `epochs`.

- `parent_ec393_custody_bundle_original` must equal the **actually audited** EC393 original path + digest, not a derived summary.
- `external_trust_roster_original` must contain `schema=ces.ec394.original_external_registrar_dispute_and_witness_roster.v1`, `claimed_directory_lineage_id`, `registrar`, `dispute_authority`, `witnesses` of exactly two. The four roles each have exactly `role_id`, `site_id`, `public_hex`, `public_key_original`. All four keys must be distinct (also separate from EC393 custody/log signers and reopened EC391 keepers); public-key originals are raw **32-byte** Ed25519 keys, not PEM. Signed site/role IDs are claimed metadata only. Registrar/cutoff keys must equal the two separate external command-line public-key pins.
- `witness_tsa_registry_original` is the exact existing EC391 offline TSA trust-registry schema with full DER root certificate, policy and CRL original references. Its root SHA must be distinct from **both** EC391 roots and EC393's log TSA root. The supplied CRLs are checked for cryptographic issuer signature, validity and serial status at token generation time and evaluation time; absence/staleness/revocation cannot yield a locally clean status. The receiver does not call an online OCSP/CRL service.

## Independent site registration and key rotation

`site_key_histories` contains exactly four records matching the **genuine** EC393 roster's `(observer_id, role, party_id, site_id)` pairs. Each has exact `observer_id`, `role`, `party_id`, `site_id`, `registered_site_identity_original` (opaque SHA-pinned institutional registration bytes, reopened but never assumed legally authentic), `generations` (0–3).

Each generation has `signed_site_key_registration_original`, `registered_public_key_original` (raw 32-byte key) and `rfc3161_registration_token_original` (genuine token or null). A signed registration original has:

- `schema=ces.ec394.original_registrar_signed_site_key_registration.v1`, `claim`, `registrar_signature_ed25519`, `previous_key_signature_ed25519`, `new_key_signature_ed25519`.
- Claim exact keys `schema=ces.ec394.original_site_key_registration_claim.v1`, `directory_lineage_id`, `parent_ec393_roster_original_sha256`, `registrar_id`, `observer_id`, `role`, `party_id`, `site_id`, `site_registry_reference_sha256`, `registration_sequence`, `registered_public_hex`, `previous_registration_original_sha256`, `claimed_registered_utc`, `effective_from_utc`, `effective_until_utc`.
- The claimed registration reference SHA **must match an actually reopened site identity original**. Registrar genuinely signs `b'CES/EC394/SiteKeyRegistration/IndependentRegistrar/v1\x00'+canonical(claim)` with the externally registered registrar key.
- First generation uses SHA-256 ZERO predecessor and `null` old/new consent signatures. Subsequent generations need exact predecessor **signed original** SHA, incrementing `registration_sequence`, distinct old/new keys, adjacent effective windows and **both genuine Ed25519 consent signatures** using `b'CES/EC394/SiteKeyRegistration/OldKeyConsent/v1\x00'+canonical(claim)` and `b'CES/EC394/SiteKeyRegistration/NewKeyConsent/v1\x00'+canonical(claim)`. Timestamp monotonicity of the furnished two generations is checked.
- A present latest generation must use the **actual current EC393 party key**; across all four histories no key may be reused, and no generation may use a keeper/log/independent-notary/witness signer key. For a positive per-epoch site-role bound, its latest original registrar-signed registration must have a **real authenticated registration token** generated no later than **every reopened genuine signed EC393 handoff's claimed UTC for that observer**, an effective window covering the claims and a clean furnished key-status snapshot. A locally generated token from after a claimed old handoff is therefore *not counted*. No claims of actual pre-handoff third-party custody result merely from those checks.

Zero generations are not silently filled: they remain a source-specific unresolved registration gap and are never counted.

## Signed dispute, key revocation status and two witnesses

The original signed cutoff notice requires `schema=ces.ec394.original_signed_dispute_notice.v1`, `claim`, `authority_signature_ed25519`. Claim schema `ces.ec394.original_dispute_notice_claim.v1` has exact `directory_lineage_id`, `authority_id`, `parent_ec393_custody_bundle_original_sha256`, `external_dispute_case_file_original_sha256`, `declared_dispute_cutoff_utc`, `claimed_notice_issued_utc`, and `schema`. Its Ed25519 message is `b'CES/EC394/DisputeCutoffThirdPartyNotice/v1\x00'+canonical(claim)`. It must agree with the **unchanged EC393 declared cutoff** and the raw SHA of the reopened external opaque case-file original. The genuine RFC3161 token covers the **raw signed notice bytes**. This does not certify that the claimed dispute was real or that the signer held public authority.

The optional but **required-for-local-clean-status** status snapshot has `schema=ces.ec394.original_signed_independent_key_status_snapshot.v1`, `claim`, `authority_signature_ed25519`, domain `b'CES/EC394/IndependentKeyStatusSnapshot/v1\x00'`. Claim fields: `schema=ces.ec394.original_independent_key_status_claim.v1`, `directory_lineage_id`, `authority_id`, `external_trust_roster_original_sha256`, `ec393_custody_roster_original_sha256`, `signed_dispute_notice_original_sha256`, `declared_status_utc`, `key_statuses`. Rows have exact `subject_id`, `public_hex`, `status` (`active` or `revoked`), `claimed_change_utc`. Full furnished subject set = registrar, dispute authority, both witnesses, and every genuine key generation, using `<party_id>:<sequence>` to distinguish rotations. The separate dispute attestor signs these exact claims; the original has its own genuine DER token and bounded CRL. A signed `revoked` status on a currently relevant signer marks furnished status adverse, removes counts, and is **never** silently resolved to `active`. Older inactive-key revocation is still listed as evidence. An absent status snapshot is `_unresolved`, not an invented clean status. **A single signed snapshot cannot establish global key status, status history completeness, independently authorized registrar or real online revocation.**

Each `epochs[i]` has exact `epoch_index`, `witnesses` of **two** `witness_id` groups (one per separately keyed third-party witness). Each group has an `observations` array of 0–2 (empty = missing evidence). Each observation has `signed_witness_observation_original`, `rfc3161_witness_token_original`, `observed_signed_log_head_original`.

The witness original must have `schema=ces.ec394.original_independent_signed_log_witness.v1`, `claim`, `witness_signature_ed25519`; claim schema `ces.ec394.original_independent_log_witness_claim.v1` with exact `directory_lineage_id`, `witness_id`, `witness_site_id`, `parent_ec393_roster_original_sha256`, `signed_dispute_notice_original_sha256`, `epoch_index`, `observed_log_id`, `observed_signed_log_head_original_sha256`, `observed_log_tree_size`, `observed_log_merkle_root_sha256`, `claimed_observed_utc`, `schema`. The witness signs `b'CES/EC394/ThirdPartySignedLogObservation/v1\x00'+canonical(claim)`. The receiver reopens and genuine-signature-verifies the observed original EC393 log Head under the **actual EC393 log operator key**. An actual third-party raw signed witness original + clean genuine original timestamp **no later than the declared cutoff** can count only for the **actual EC393 prior Head**, with genuine notice and clean status snapshot. Other properly signed old-log-operator Heads with the same sequence/tree size but different Merkle roots remain **visible signed forks**; both original SHAs appear in `visible_signed_log_fork_cases`, without a winner. Missing witness or wrong chronology prevents positive count.

The first epoch's first signed witness original SHA must match the independent retained prior witness SHA pin. Signed notice original SHA and per-epoch site/witness inventories and minimum count floors must match external pins, or an explicit adverse flag is raised. No inferred universe of unobserved witnesses or undisclosed log forks.

## Result, denies and real-world boundary

Success-shaped audit results are **forbidden**. Every well-formed piece of evidence, even locally internally consistent, returns `exit_code=2`, `status=*_unresolved`, domain-specific adverse flags, `receiver_verified_registered_witness_inventory_sha256`, authenticated parent EC393 SHA, per-epoch source inventory digests and visible signed fork SHAs. Locally verifiable signer/timestamp consistency never becomes `Quality=true`, release approval, actual legal registrar authority, physical custody, trusted calibrated UTC, qualified TSA status, or a complete revocation/fork census. `derive` includes the unsigned inventory; `audit` does not. Invalid original SHA/signature/schema/unsafe paths are denied with 3/4/5. The receiver does **not** sign, create credentials/tokens, invoke remote providers, write CAS/WORM, source files, Git, CI or PowerShell; it only reads evidence and emits JSON to stdout.

**Deferred:** real external registrar accreditation, site registrations with admissible independent legal originals and proven prior retention, independently authenticated dispute case origin/time, trusted time/accredited TSA and complete offline+online revocation, full inter-witness gossip/global split-view history, actual physically separate handoff/CAS/WORM readback, full unmocked historical EC390→EC317/318 corpus, native PS7 + original 15 Smoke + Windows/macOS + E63–E66 and user acceptance. These cannot be made true by adding local test-generated keys, tags or timestamps.
