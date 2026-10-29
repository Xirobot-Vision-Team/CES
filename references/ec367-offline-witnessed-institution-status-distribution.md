# EC367 — Dual witnessed institution-status head distribution (offline)

**Version:** CES construction package **V6.77 / R367 / EC367**. Native PowerShell CLI remains **V4.60/R150**. This protocol does not create or confer official or legal trust authority. All legitimate results are `exit_code=2 / unresolved` regardless of local signature coherence. Bad/missing original/signatures or invalid input return `3 / permission_denied`, `4 / invalid_input`, or `5 / unavailable` through a fixed JSON denial response.

## Security goal and inherited evidence

EC367 adds independent *distribution observations* over the two original institution root-status and provenance-head records already verified by EC366. **Every** `audit-witness-distribution` calls `ec366_root_provenance.provenance.audit` (and therefore its real EC365→EC337 parent replay); it never consumes a user-supplied `PASS` parent report. The canonical SHA-256 of that actual parent JSON result is signed into every EC367 witness record, and the EC366 originals are reopened and their Ed25519 institution status signatures reverified. Caller-owned head SHA pins and witness public keys are **outside** the bundle and must agree with its contents.

The two **distribution paths** are `registry_distribution` and `archive_distribution`; each has a separately caller-SHA-pinned **32-byte Ed25519 public key original** and a separate caller-retained claimed witness ID. They cannot reuse a known EC366 institution root or replayed directory root. Reusing any known old signer SHA or claiming the same institutional witness identity is visible. Two different public keys and claimed names are **not** evidence of different legal entities, institutional authorization or physical independent custody.

A source is one of `origin_registry` or `independent_archive` from EC366. **Each signed distribution record contains an ordered snapshot of both sources**. This gives two independently signed views of the *same* pair of institution status heads and provenance heads, rather than a witness signing only its own source. Each observation includes exact source-root SHA, institutional claimed ID/role, whole original SHA of the source status head, signed status sequence, signed action, signed previous-status SHA, EC366 provenance-head original SHA, and the real source-signed terminal status SHA (`revoke`/`rotate`) or `null` for an active status.

## Canonical signatures and original files

All JSON originals are strictly decoded (no duplicate fields or noncanonical constants), read from absolute regular files with original byte SHA-256 externally pinned, denied if symlink/ancestor/file-identity overlaps occur, and rechecked at completion. Witness records are signed by actual Ed25519 verification over

`b'CES/EC367/InstitutionStatusWitnessDistribution/v1\x00' + canonical_json(record_without_signature_witness_ed25519_hex)`.

The **bundle** is a canonical JSON object with exactly these keys:

| Key | Type and meaning |
|---|---|
| `schema` | `ces.ec367.dual_witness_distribution_bundle.v1` |
| `parent_ec366_canonical_result_sha256` | SHA of actual EC366 result; a mismatching self-claim is flagged |
| `distribution_paths` | Exactly 2 entries, in `registry_distribution`, `archive_distribution` order |
| `additional_source_status_originals` | 0–4 `{source_role, original}` entries, maximum 2 per institution |

Each `distribution_paths[]` contains exactly `distribution_path`, `claimed_witness_id`, `witness_public_key_original_sha256`, and `signed_witness_observations`: an ordered list of 1–4 `{path,sha256}` original references. The SHA sequence of both arrays concatenated must exactly match the **independent** repeated CLI `--signed-witness-record-sha256` stream. A file written in the bundle cannot substitute its own pins, identity or latest head.

Each genuine **signed witness record** has schema `ces.ec367.witness_signed_source_status_observation.v1` and exactly:

- `distribution_path`, `claimed_witness_id`, `witness_public_key_original_sha256`
- `parent_ec366_canonical_result_sha256`
- `sequence` (0–8), `previous_witness_original_sha256` (null at epoch 0, exact SHA-linked predecessor at later epochs)
- `disclosure_state`: `published`, `withheld` or `disputed`
- `source_observations`: an **ordered length-two** list of two source observations
- `issued_utc`, `expires_utc`: strict claimed UTC seconds with a bounded maximum seven-day window
- `signature_witness_ed25519_hex`: genuine domain-separated Ed25519 signature

Each **source observation** has exactly:

`claimed_source_role`, `claimed_institution_id`, `institution_public_key_original_sha256`, `source_status_head_original_sha256`, `source_status_sequence`, `source_status_action`, `previous_source_status_original_sha256`, `source_attestation_head_original_sha256`, `source_revocation_proof_original_sha256`.

When the referenced signed source status original is present and authentic, the witness's signed action, sequence, predecessor SHA and required terminal proof must **exactly agree with that original**, not just with the witness's asserted values. Unknown status SHAs, forged status signatures, inaccessible originals and false signed witness claims cannot become proof of an active status. The parent EC366 provenance head must equal the one already cryptographically verified by the true replay, never an unrelated witness-only hash.

## Institution-signed extra revocation originals

`additional_source_status_originals` allows a caller to present *new source-signed* statuses which are **not** in the earlier EC366 bundle. Every extra original must be separately caller-pinned through repeated `--additional-source-status-sha256`, use the **original institution root key**, and pass the actual EC366 `STATUS_DOMAIN` Ed25519 signature verification and exact schema/claimed root ID checks. The verifier builds one SHA-linked source status graph using both the original EC366 status records and the extras; it detects signed sequence forks, missing ancestry, extension after `revoke`/`rotate` and terminal status originals. Every extra source status means the EC366 parent was not the whole displayed set and **blocks EC367 local-current correlation**, even if its action says `renew` or both witnesses report it. Any authentic `revoke`/`rotate` event stays explicitly visible. Unverified or unsigned revocation assertions do not count as actual source-signed revocation proof.

A witness's own `withheld` or `disputed` disclosure state is an **authentic witness declaration** only. It is never silently equated with a source-signed revocation event. A genuinely signed terminal source original is evidence of that signer having signed a terminal statement, but without a complete global registry it does not establish the time or absence of other unseen signed statements.

## Rollback and fork analysis

A path must have exactly one signed witness chain with genesis sequence 0 and complete SHA+sequence links. All supplied signed branches are examined: a signed child fork, skipped predecessor, repeated sequence, monotone source-status regression or incompatible source-SHA ancestry **blocks local correlation**. The exact separately retained latest witness head SHA and minimum epoch sequence floor must match. The verifier never chooses a winning signed branch when genuine witnesses conflict.

The verifier compares the **latest externally retained heads** from both paths. Different status-head SHAs which are both reverified source-signed and have genuine ancestry are reported as witnessed lag; different signed forks are reported as conflicting signed views. Differing provenance-head SHAs are a witnessed disagreement, **not** automatically a confirmed source-originated equivocation without source signatures. Historical witness epochs are checked for monotone SHA-linked source status progression, not naively compared as if every historical view had to be identical.

Local correlation (`locally_two_independently_retained_paths_correlate_on_verified_source_heads`) requires: the true parent EC366 local correlation flag, both distinct witness keys, valid genuine witness signatures on each epoch, uniquely pinned most-current witness heads and floors, two complete `published` source observations per head, **exact** matches to both EC366 verified status+attestation heads, active status, no newly supplied source originals, no visible source termination, fork, withheld record, clock anomaly, mismatched original, head rollback or other EC367 flags. **Local correlation still returns exit 2 / unresolved** and only describes the finite externally supplied originals.

Witness and source signed UTC values are only claims. Neither real official witness appointment, separate physical storage, a complete globally latest root, no unseen branch, historically reliable timestamp, network publication, OS trust store verification, nor Provider/CAS/WORM remote storage can be deduced or performed by EC367.

## Read-only CLI

The fixed standalone entrypoint is `scripts/ces_cas_witness_distribution.py`:

```text
python -I -B scripts/ces_cas_witness_distribution.py derive-witness-distribution-handoff [ALL COMPLETE EC366 PARENT FLAGS]
python -I -B scripts/ces_cas_witness_distribution.py audit-witness-distribution [ALL COMPLETE EC366 PARENT FLAGS] \
  --witness-distribution-evaluation-utc 2026-10-26T12:30:00Z \
  --witness-distribution-bundle-file /absolute/original/witness-bundle.json \
  --expected-witness-distribution-bundle-sha256 <REAL_SHA256> \
  --witness-public-key-file /absolute/registry-witness.pub \
  --witness-public-key-sha256 <REAL_SHA256> --witness-claimed-id RegistryWitness \
  --witness-public-key-file /absolute/archive-witness.pub \
  --witness-public-key-sha256 <REAL_SHA256> --witness-claimed-id ArchiveWitness \
  --minimum-retained-registry-distribution-sequence 0 \
  --minimum-retained-archive-distribution-sequence 0 \
  --expected-retained-registry-distribution-witness-head-sha256 <REAL_SHA256> \
  --expected-retained-archive-distribution-witness-head-sha256 <REAL_SHA256> \
  [REPEATED --signed-witness-record-sha256 AND OPTIONAL --additional-source-status-sha256]
```

`<REAL_SHA256>` is a **placeholder** and not a valid digest. In both commands all formerly required EC366 inputs must be furnished; the handoff derives the *real* parent SHA, not a signature or key. New CLI flags with repeated values must remain ordered as their bundle paths and original references. Fixed consolidated action:

```text
python scripts/ces_next.py audit-witness-distribution DeliveryAudit AuditWitnessDistribution [EXACT SAME REQUIRED OPTIONS AND EXTERNAL PINS]
```

The unified route never executes a caller-supplied program. It creates a fixed `python -I -B` child, validates bounded input flags and strict JSON exit/result fields, denies unrecognized or optimistic responses, and exposes only the read-only offline command.

## Verification currently pending

17 lightweight focused cases using **real Ed25519 witness/source signatures but a deliberately mocked EC366 parent result** passed locally in this construction round, including the new fixed-route response-contract check with a mocked child reply. This is **not** a parent-inclusive proof. Full newly defined true-EC366/EC365→EC337 synthetic replay, inherited EC366 twelve-case suite, EC356 historical case24, EC317/318 deep production MOCK replacement, independent full ancestry regressions, native PS7/15 Smoke/OS/Git/CI/Provider/E63–E66, trusted external official entities and physical custody, remote CAS/WORM and final assisted acceptance remain **NOT_RUN / NOT_PROVEN**. Old `EC249 INCOMPLETE`, `EC250 BLOCKED`, `B001 OPEN`, `Quality=false` and final `NOT_STARTED` are intentionally unchanged.

[Implementation](../construction/ec367_witness_distribution/distribution.py) · [focused test fixture](../construction/ec367_witness_distribution/test_distribution.py) · [scope](../construction/EC367_SCOPE.json) · [local observations](../construction/EC367_LOCAL_REPORT.json).
