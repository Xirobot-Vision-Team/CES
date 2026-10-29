# EC359 Offline Signed Owner Distribution — strict protocol and read-only CLI

## Security and trust boundary

The two distributor public keys must arrive from the **calling operator**, pinned by full-file SHA-256 independently of the distribution bundle. Verification establishes only a locally checkable signature under the supplied key, **not** an official outside institution or chain-of-trust. The program performs no network access, trust-store updates, key creation, signing, or external writes. A positive local comparison is always exit 2 / `unresolved`.

Every call replays genuine EC358→EC357→…→EC337 originals with actual cryptographic validation. A new record binds the freshly reconstructed full EC358 canonical-result SHA, the EC358 signed owner public-key SHA, its signed claimed ID and the operator-retained owner head event SHA. A future revocation or rotation **does not** retrospectively legitimize rejected earlier evidence.

## Inputs

Start from **all arguments** of EC358 `audit-reviewer-epochs` (including the non-optional `reviewer_epoch_evaluation_utc` and every old mandatory ancestor argument and repeated pin). Supply additionally:

| CLI flag | Required | Meaning |
|---|---|---|
| `--distribution-evaluation-utc` | yes | strict claimed `YYYY-MM-DDTHH:MM:SSZ`, must not precede EC358 evaluation |
| `--distribution-bundle-file`, `--expected-distribution-bundle-sha256` | paired optional | one canonical JSON pinned manifest (max 24,000 bytes) |
| `--distributor-a-public-key-file`, `--expected-distributor-a-public-key-sha256` | paired optional | source a issuer 32-byte raw Ed25519 public-key original, SHA pinned outside bundle |
| `--distributor-b-public-key-file`, `--expected-distributor-b-public-key-sha256` | paired optional | source b distinct issuer key original |
| `--minimum-a-distribution-sequence`, `--minimum-b-distribution-sequence` | optional | independently retained external floor, integer 0..5; missing cannot establish local completeness |
| `--expected-a-distribution-head-sha256`, `--expected-b-distribution-head-sha256` | optional | independently retained expected record-original SHA; missing cannot establish local completeness |

All old source, owner and reviewer fields retain EC358 meaning. Missing new material is classified **exit2 unresolved**, unless one side of an explicitly paired pin is supplied (invalid input). A furnished record whose signature, exact fields, SHA, path identity, real predecessor, or parent binding fails is rejected (3/4/5), never converted into "absent".

## New pinned bundle (`ces.ec359.pinned_owner_distribution_bundle.v1`)

Canonical UTF-8 JSON (strict no duplicate keys / no extra keys) with exactly `schema` and `sources` fields. `sources` is a list (at most 2) of exactly:

```json
{
  "slot": "a",
  "distributor_public_key": {"path": "/absolute/issuer-a.pub", "sha256": "<actual-original-sha256>"},
  "records": [
    {"path": "/absolute/a0.json", "sha256": "<actual-signed-original-sha256>"}
  ]
}
```

Pins are SHA-256 of the complete bytes at that path, never of an interpreted JSON object. Paths must be canonical absolute regular files; symlinks in any ancestor and hardlink/inode aliasing any inherited or other newly furnished evidence are denied. Both source public keys must differ and cannot match old signed role keys by byte SHA. New originals and known inherited originals are re-opened for a final SHA/inode check.

## Signed distribution record (`ces.ec359.signed_owner_distribution_record.v1`)

Each bounded, canonical JSON record has **exactly these fields**:

| Field | Description |
|---|---|
| `schema` | `ces.ec359.signed_owner_distribution_record.v1` |
| `scope` | **exact** `ces.reviewer_owner_distribution.v1` |
| `slot` | `a` or `b`, matching containing source |
| `issuer_id` | signed, bounded identifier *claim*; **not** real-world verification |
| `issuer_public_key_original_sha256` | exact full-file SHA of caller-pinned source issuer key |
| `claimed_owner_id` | exact EC358 owner signed claim for that source |
| `owner_public_key_original_sha256` | exact EC358 signed-owner key SHA |
| `parent_ec358_canonical_result_sha256` | SHA of *this invocation's* actual EC358 canonical result |
| `parent_owner_head_event_original_sha256` | actual EC358 caller-pinned selected head event SHA |
| `sequence` | nonnegative integer 0..5, increments exactly by one |
| `previous_record_original_sha256` | null for sequence 0; otherwise complete old signed-record-original SHA |
| `operation` | `authorize`, `revoke`, or `rotate` |
| `replacement_owner_public_key_sha256` | null for `authorize` / `revoke`; required distinct SHA for terminal `rotate` |
| `effective_utc`, `expires_utc` | self-claimed UTC strings, effective strictly before expiry, interval max 90 days |
| `signature_issuer_ed25519_hex` | lowercase 128 hex chars, genuinely verified over the unsigned canonical object |

The signature is `Ed25519Sign(issuer_private_key, b"CES/EC359/OwnerDistribution/Issuer/v1\\x00" + canonical_json(record_without_signature))`. This is a **verification protocol only**, not an embedded signer. One `authorize` at sequence 0 starts each chain. Subsequent `authorize` renewals require a still-authorized signed predecessor. `revoke` and `rotate` are terminal **deauthorizations of the old owner**; a replacement digest is a claim, never implicit grant to the new owner. All provided siblings are signed/checked and kept visible, even if the caller selects one head. Same-parent signed forks, multi-genesis and duplicated self-claimed issuer identities cannot silently become authoritative.

An external expected head absent from presented valid records is denied; a head visibly having later signed descendants or below an external minimum is marked rollback. The statements' UTC values can be checked for internal consistency and caller-relative windows, **but no historical UTC attestation is proven**. Missing documents/keys/floors/heads and issuer legal authority remain unresolved.

## Read-only commands

```bash
python -I -B scripts/ces_cas_owner_distribution.py derive-owner-distribution-handoff \
  <all-EC358-replay-arguments>

python -I -B scripts/ces_cas_owner_distribution.py audit-owner-distribution \
  <all-EC358-replay-arguments> \
  --distribution-evaluation-utc 2026-10-26T12:00:00Z \
  --distribution-bundle-file /absolute/new-bundle.json \
  --expected-distribution-bundle-sha256 <64-hex> \
  --distributor-a-public-key-file /absolute/issuer-a.pub \
  --expected-distributor-a-public-key-sha256 <64-hex> \
  --distributor-b-public-key-file /absolute/issuer-b.pub \
  --expected-distributor-b-public-key-sha256 <64-hex> \
  --expected-a-distribution-head-sha256 <64-hex> \
  --expected-b-distribution-head-sha256 <64-hex> \
  --minimum-a-distribution-sequence 0 \
  --minimum-b-distribution-sequence 0

python -I -B scripts/ces_next.py audit-owner-distribution \
  DeliveryAudit AuditOwnerDistribution <all-the-audit-flags-above>
```

Angle-bracket placeholders are **documentation only**, not executable inputs. Both CLIs yield exactly one JSON object, with fixed success schema `ces.ec359.offline_owner_distribution_claims_unresolved.v1` and denial schema `ces.ec359.offline_owner_distribution_denial.v1`. Return 2 only for legitimate unresolved results; denial 3/4/5 for permission/input/unavailable. Isolated unified router verifies exact response fields, nested record shapes, enumerated outcome counters, absence of success overclaim and fixed false assertions.

## Deferred verification

EC359 local key signatures do not authenticate official trust-anchor ownership, source distribution control, any outside certificate/revocation status, trusted UTC, global fork completeness, genuine legal/physical independence, native PowerShell or final user acceptance. Historical EC356 test24 remains not independently verified. EC317/318 deep mock remains. See `construction/EC359_LOCAL_REPORT.json` for the precise focused test evidence and unresolved gates.
