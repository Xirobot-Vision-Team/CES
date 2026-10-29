# EC342 — Signed, externally pinned conflict-hold governance (offline only)

Release: **V6.52 / R342 / EC-342**. This protocol handles **one already-visible, genuinely signed EC341 sibling successor dispute**. It cannot discover hidden forks, elect a global winner, install a remote hold, grant a signer authority, or certify any real organization. Everything in the successful local result remains **`exit_code=2` / unresolved**.

## Separation of responsibilities

1. **Trust custodian**: independently obtains and seals the existing canonical EC341 lineage manifest whole-original SHA, separately obtains the exact current root SHA / epoch / minimum epoch / evaluation UTC, and *another* separately entrusted canonical EC342 governance-roster whole-original SHA. A hash printed by the tool is not an institutional trust root. Challenge SHA and claimed times likewise need an external protocol.
2. **Initiator**: has only the named initiator private Ed25519 key. Calls `issue-hold`, which **actually replays EC341 signed forks and EC340→EC339→EC338→EC337 originals** before producing a 0600, O_EXCL, canonical, signed request binding exactly the chosen parent/selected successor/alternative successor, external pins, independent challenge, transfer/policy/epoch/floor, and five explicit evidence gaps. It requests a hold on **both** declared successors and selects neither.
3. **Reviewers**: 3–5 separately named issuer/observer-independent keys/declared organizations. Each issues **one** domain-separated `support_hold` or `object_to_hold` Ed25519 review binding the *whole original SHA of the same signed hold*. A reviewer cannot re-use the initiator, approver, a second review slot, or known lineage actor/issuer/observer key or declared organization. Only `support_hold` counts; conflicting or duplicate votes fail closed. Review timestamps are merely signer claims.
4. **Review-set custodian**: creates a canonical no-overwrite `assemble-review` file listing exact separately SHA-pinned original review files and the signed hold (0–5 votes allowed to represent an insufficient quorum). Its whole SHA must be independently pinned before acceptance. Files are *never automatically collected by filename pattern*.
5. **Separate external approver**: may use **only** the distinct roster-listed approver key to sign the precise review-set whole SHA, hold SHA, case, challenge, quorum and count. `issue-approval` refuses insufficient support. The approval signature means a declared approver signed a review record, **not that the institution behind it exists or that it froze a remote resource**. Receiver must also obtain the approval whole SHA independently.
6. **Receiver**: `verify-hold` is read only. It replays EC341 (including all original Ed25519 signed sibling evidence, full EC340→EC337 history and nested ZIP byte verification), checks the governance roster against verified *actual* fork parent+two successors and known actor/issuer/observer identity, validates all initiator/reviewer/approver signatures and whole file SHA pins, checks declared timing/quorum, then re-reads every EC342 original. The unified console only executes isolated `python -I -B ... verify-hold` and validates the result schema/negative authority flags.

## Canonical governance roster: exact fields

The governance roster is **not** self-authorizing. Its entire raw LF JSON byte SHA must be supplied from a distinct trust channel. The object contains precisely:

| Field | Meaning |
|---|---|
| `schema` | `ces.ec342.externally_pinned_conflict_governance_roster.v1` |
| `case_id`, `case_nonce_sha256` | Exact case identity and unique 64-hex nonce, enforced for this provided case only |
| `transfer_id`, `policy_original_raw_sha256` | Fixed EC339/EC341 signed historical policy context |
| `lineage_manifest_original_raw_sha256` | Whole canonical EC341 manifest (independently pinned) |
| `current_root_original_raw_sha256`, `current_root_epoch`, `minimum_acceptable_epoch`, `current_root_evaluation_utc` | Must equal separately supplied receiver roots/floor/time |
| `parent_epoch`, `parent_root_original_raw_sha256` | Exact parent epoch/whole original SHA from one verified EC341 `fork_conflicts` entry |
| `selected_successor_original_raw_sha256`, `alternative_successor_original_raw_sha256` | The two distinct successor SHA values from **that exact fork conflict**, not user-nominated unsigned alternatives |
| `initiator` | `{ "signer_id":..., "public_hex":..., "organization_id":... }` |
| `reviewers` | 3–5 same-shape role records, unique ID/public key/declared organization |
| `required_support_quorum` | Integer **3 to N** reviewers, counted only with distinct valid `support_hold` signatures |
| `external_approver` | One different same-shape key/id/org (never counted in reviewer quorum) |
| `external_approval_required`, `remote_freeze_not_performed` | Exactly `true` and `true` |

All roles must be unique by ID, Ed25519 public key, and declared organization. The receiver rejects any collisions with supplied EC341 lineage actor, issuer or observer identities. This is **a syntactic separation check**, not a test of independent real-world people, devices, legal power, or revocation status.

## Command flow (fill paths, hashes, UTC and keys from independently entrusted evidence)

All file arguments are absolute, normalized, preexisting local private originals unless used as an exclusive `--out`. No command writes to Git, providers, CI or CAS. For readability below, `$LINEAGE_FLAGS` stands for **six separate CLI arguments**, not a single shell-quoted string:

```text
--manifest-file /absolute/lineage.json
--expected-manifest-sha256 <independently-entrusted-64-hex>
--expected-current-root-sha256 <independent-current-root-sha>
--expected-current-root-epoch 4
--minimum-acceptable-epoch 3
--current-root-evaluation-utc 2026-10-25T12:39:00Z
```

### Initiator (one private key)

```bash
python -I -B scripts/ces_cas_issuer_hold_governance.py issue-hold \
  --out /private/new-signed-hold.json --private-key-file /private/initiator.key \
  --governance-roster-file /private/governance.json \
  --expected-governance-roster-sha256 "$GOVERNANCE_SHA" \
  --manifest-file /private/lineage.json --expected-manifest-sha256 "$LINEAGE_SHA" \
  --expected-current-root-sha256 "$ROOT_SHA" --expected-current-root-epoch 4 \
  --minimum-acceptable-epoch 3 --current-root-evaluation-utc 2026-10-25T12:39:00Z \
  --hold-challenge-sha256 "$CHALLENGE_SHA" \
  --issued-utc 2026-10-25T12:43:00Z --expires-utc 2026-10-25T13:20:00Z
```

Signed hold has `schema=ces.ec342.ed25519_initiator_hold_request.v1`; its Ed25519 claim is domain-separated `CES/EC342/OfflineSiblingHoldRequest/v1\0` and includes explicit fixed evidence gaps and `no_winner_declared=true`.

### Reviewers (one key per signer)

```bash
python -I -B scripts/ces_cas_issuer_hold_governance.py sign-review \
  --out /private/review-alice.json --private-key-file /private/alice.key \
  --governance-roster-file /private/governance.json \
  --expected-governance-roster-sha256 "$GOVERNANCE_SHA" \
  --hold-file /private/new-signed-hold.json --expected-hold-sha256 "$HOLD_SHA" \
  --decision support_hold --reviewer-reported-utc 2026-10-25T12:50:00Z
```

`--decision object_to_hold` is also valid and **does not** increment support. Ed25519 review domain: `CES/EC342/IndependentConflictHoldReview/v1\0`.

### Review-set collector (no private key)

```bash
python -I -B scripts/ces_cas_issuer_hold_governance.py assemble-review \
  --out /private/exact-review-set.json \
  --governance-roster-file /private/governance.json \
  --expected-governance-roster-sha256 "$GOVERNANCE_SHA" \
  --hold-file /private/new-signed-hold.json --expected-hold-sha256 "$HOLD_SHA" \
  --attestation-file /private/review-alice.json --expected-attestation-sha256 "$ALICE_SHA" \
  --attestation-file /private/review-bob.json --expected-attestation-sha256 "$BOB_SHA" \
  --attestation-file /private/review-carol.json --expected-attestation-sha256 "$CAROL_SHA"
```

Each `--attestation-file` must be paired with the SHA at the **same position**. `assemble-review` verifies signatures before creating the manifest; it cannot attest future approval or actual lineage on its own. The resulting manifest SHA must be independently pinned. Existing targets are never overwritten.

### Separate approver (after an actual threshold)

```bash
python -I -B scripts/ces_cas_issuer_hold_governance.py issue-approval \
  --out /private/approval.json --private-key-file /private/approver.key \
  --governance-roster-file /private/governance.json \
  --expected-governance-roster-sha256 "$GOVERNANCE_SHA" \
  --review-manifest-file /private/exact-review-set.json \
  --expected-review-manifest-sha256 "$REVIEW_SET_SHA" \
  --approval-reported-utc 2026-10-25T12:55:00Z
```

Approval domain: `CES/EC342/ExternalHoldReviewApproval/v1\0`. An approver cannot act as a reviewer, and a valid approval cannot repair a changed review set or lack of quorum.

### Independent receiver (strictly read only)

```bash
python -I -B scripts/ces_cas_issuer_hold_governance.py verify-hold \
  --manifest-file /private/lineage.json --expected-manifest-sha256 "$LINEAGE_SHA" \
  --expected-current-root-sha256 "$ROOT_SHA" --expected-current-root-epoch 4 \
  --minimum-acceptable-epoch 3 --current-root-evaluation-utc 2026-10-25T12:39:00Z \
  --governance-roster-file /private/governance.json \
  --expected-governance-roster-sha256 "$GOVERNANCE_SHA" \
  --review-manifest-file /private/exact-review-set.json \
  --expected-review-manifest-sha256 "$REVIEW_SET_SHA" \
  --hold-evaluation-utc 2026-10-25T13:00:00Z \
  --approval-file /private/approval.json --expected-approval-sha256 "$APPROVAL_SHA"
```

Omit **both** approval arguments to report `external_approval_missing` once quorum is met. The unified read-only form is exactly:

```bash
python -I -B scripts/ces_next.py audit-issuer-conflict-hold \
  DeliveryAudit VerifyIssuerConflictHold \
  [the same verify-hold option flags above]
```

Neither verifier accepts a private key, output destination, or installer command. Both validate actual cryptographic originals; successful-but-unresolved results retain `exit_code=2` and do **not** become a global Quality PASS.

## Status distinctions

| `status` | Precise local meaning | What is **not** established |
|---|---|---|
| `quorum_insufficient` | Signed initiator and supplied 0..N true reviewer signatures verified, support votes below 3..N quorum | Even a declared review hold is not met |
| `external_approval_missing` | Exact signed fork + hold + support quorum checked; no separately pinned approver original supplied | No approval, no freeze, no winner |
| `hold_verified_unresolved` | Above plus a **separate** true Ed25519 approver signature and a supplied external whole SHA pin covering this exact review-set SHA | The signer is a real authorized institution; remote CAS was frozen; any epoch is globally latest; either fork won |
| `permission_denied`/`invalid_input`/`unavailable` | Malformed, expired, forged, mismatched, changed, untrusted, or unavailable original; command exits 3/4/5 | No accepted hold fact |

## Security and unfinished acceptance

Claims use `issued_utc`, `reviewer_reported_utc`, `approval_reported_utc`, `hold_evaluation_utc` and a max-24-hour signed hold window. The receiver denies use of a vote/approval whose **claimed** timestamp occurs after evaluation or whose approval claims predate a review. It has **no trusted wall clock** or legal identity oracle. Concurrent file replacement is constrained by each pinned SHA and post-read rechecking, but cannot be promoted to an atomic multi-file institutional snapshot.

The project still needs independently institutionalized governance, trusted legal issuer/approver identity and out-of-band SHA custody, globally complete root/branch and revocation information, a real remote CAS/WORM freeze readback and nonexecution evidence, physically separate participants, fully non-MOCK EC317/318 old production provenance, PS7/15 smoke and cross-OS/CI/Provider/E63–E66/final acceptance. These are **not implemented or verified by EC342**. `EC249 FULL_FUNCTION_NOT_COMPLETE`, `EC250 BLOCKED`, `B-001 OPEN`, `Quality=false`, `final NOT_STARTED` remain explicit.
