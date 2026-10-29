# EC343 — Signed receiver receipts and bounded offline hold-request timeline

**Release V6.53/R343/EC-343. Offline-only evidence; every successful result is `exit_code=2` / unresolved.** EC343 starts from a *fully verified, independently SHA-pinned EC342 approval* of an already signed EC341 sibling-fork hold request. It cannot tell whether anybody froze, released, amended or even saw a real remote CAS/WORM/provider object; nor does it know every actual receiver or fork. All timestamps are signer/operator claims, not externally authenticated time.

## Distinct actors and real trust anchors

The trust custodian must independently provide the **whole-original raw SHA** of (1) EC341 canonical lineage manifest, (2) current issuer root SHA/epoch/floor/claimed evaluation UTC, (3) EC342 governance roster, (4) EC342 exact signed review-set manifest, (5) the **EC342 actual signed external approval**, and (6) the separately entrusted EC343 receiver/change roster. At every receive audit, `verify-timeline` **actually calls EC342 `verify_hold`** with approval mandatory; that recursively verifies the true EC341 signed sibling pair and EC340→337 Ed25519/original ZIP evidence before checking EC343. The old EC342 24-hour signed hold window is carried forward, not silently extended or renewed.

The **EC343 roster** is canonical LF JSON, exact schema `ces.ec343.externally_pinned_receiver_and_change_roster.v1`, with precisely:

| Keys | Content |
|---|---|
| `schema`, `case_id`, `case_nonce_sha256` | Same exact EC342 `case_id`, independently unique nonzero 64-hex case nonce |
| `governance_roster_original_raw_sha256`, `hold_original_raw_sha256`, `review_manifest_original_raw_sha256`, `approval_original_raw_sha256` | SHA pins binding immutable EC342 originals; do not put file contents or self-generated trust here |
| `change_proposer`, `change_approver` | **Different** Ed25519 `{signer_id,public_hex,organization_id}` actors |
| `receivers` | **2–4** additional mutually distinct Ed25519 actors, who independently sign receipts |
| `all_receivers_required`, `no_remote_execution_authorized` | Exactly `true` and `true` |

Every new role ID, key and declared organization must be distinct from every other EC343 role and EC342 initiator/reviewer/approver. The **full receiver** additionally checks for reuse against verified EC341 issuer/observer and EC338 actor roles. This remains only a comparison of declared strings/keys, *not proof of legal institutions or physically independent people*. No receipt quorum is substituted for the roster's full receiver list: **all named receivers must acknowledge a parent snapshot before any next signed change may be issued**. Missing receivers remain visible and unresolved.

## Six private candidate commands, one read-only command

Invoke `python -I -B scripts/ces_cas_hold_receipts.py <command> [flags]`. Every candidate writes one canonical exact-schema LF JSON file, mode 0600 with O_EXCL and fsync; any existing `--out` is rejected. Key owner operations are independent of the unified console; **the unified console has no issuance, key input, install, remote CAS or provider write route**.

1. **`assemble-base`** (no key) — `--out /private/base-snapshot.json --roster-file /private/roster.json --expected-roster-sha256 $ROSTER_SHA --governance-roster-file /private/ec342-governance.json --hold-file /private/ec342-hold.json --review-manifest-file /private/ec342-review-set.json --approval-file /private/ec342-approval.json`. It verifies local source SHA, roles, EC342 independent approval signature and review quorum, then references all four immutable originals. EC342 review-set **must reference exactly the same hold path**. An issuer must arrange real original custody separately.
2. **`sign-ack`** (one *registered receiver* private key per invocation) — `--out /private/base-ack-a.json --private-key-file /private/receiver-a.key --roster-file ... --expected-roster-sha256 ... --snapshot-file /private/base-snapshot.json --expected-snapshot-sha256 $BASE_SHA --received-utc 2026-10-25T13:02:00Z`. Ed25519 domain `CES/EC343/IndependentReceiverReceipt/v1\0`; signs case, roster SHA, base EC342 hold/review/approval SHA, snapshot whole SHA, sequence, actor identity and claimed receipt UTC. **Only claims bytes were received**; it does not certify approval, remote state or legal acceptance.
3. **`assemble-ack-set`** (no key) — `--out /private/base-acks.json --roster-file ... --expected-roster-sha256 ... --snapshot-file ... --expected-snapshot-sha256 ... --receipt-file /private/base-ack-a.json --expected-receipt-sha256 $A_SHA --receipt-file /private/base-ack-b.json --expected-receipt-sha256 $B_SHA`. The file/SHA pairs are positional and must represent distinct roster IDs and true signatures. **Zero or partial receipts** are valid evidence of incompleteness, not clearance to advance. The receiver must independently pin this ack-set's *whole original SHA*.
4. **`issue-change`** (one designated change-proposer private key) — `--out /private/change-1.json --private-key-file /private/change-proposer.key --roster-file ... --expected-roster-sha256 ... --previous-snapshot-file /private/base-snapshot.json --expected-previous-snapshot-sha256 $BASE_SHA --previous-ack-set-file /private/base-acks.json --expected-previous-ack-set-sha256 $BASE_ACK_SHA --request-kind request_revision --change-summary-sha256 $SUMMARY_SHA --change-nonce-sha256 $UNIQUE_NONCE --issued-utc 2026-10-25T13:04:00Z`. Supported `--request-kind`: `request_revision`, `request_withdrawal`, `request_supersession`; for `request_revision` and `request_withdrawal` the successor-case argument may be omitted (empty default); `request_supersession` requires a different named `--requested-successor-case-id`. A summary SHA binds an **externally exchanged description** but does *not* prove the summary original is present. The proposal signs previous snapshot SHA, complete parent receipt-set SHA, previous independent approval SHA, case, sequence and nonce. Reused ancestor nonce, expired signed hold window, incomplete parent acknowledgements or repeated version fails closed. Domain `CES/EC343/OfflineHoldChangeRequest/v1\0`.
5. **`approve-change`** (a **different** designated approver private key) — `--out /private/change-approval-1.json --private-key-file /private/change-approver.key --roster-file ... --expected-roster-sha256 ... --previous-snapshot-file ... --expected-previous-snapshot-sha256 ... --previous-ack-set-file ... --expected-previous-ack-set-sha256 ... --change-file /private/change-1.json --expected-change-sha256 $CHANGE_SHA --approval-reported-utc 2026-10-25T13:05:00Z`. Domain `CES/EC343/IndependentChangeReview/v1\0`; signs *exact* proposal SHA, parent snapshot/receipt SHA, predecessor approval SHA, sequence, case and claimed time. It is **only a review of the request**, never a remote release/freeze authority. A previous version's approval cannot be recycled against another proposal.
6. **`assemble-snapshot`** (no key) — `--out /private/snapshot-1.json --roster-file ... --expected-roster-sha256 ... --previous-snapshot-file ... --expected-previous-snapshot-sha256 ... --previous-ack-set-file ... --expected-previous-ack-set-sha256 ... --change-file ... --expected-change-sha256 ... --change-approval-file /private/change-approval-1.json --expected-change-approval-sha256 $APPROVAL_SHA`. Only a correct distinct signed proposer + signed approver and all parent receipts can produce a successor. Maximum **six** requested changes; sequence always `0→1→...`, exact prior whole-original SHA required. After assembling, **repeat steps 2–3 for the new snapshot**, allowing all named receivers to acknowledge that exact version.

All file paths are **absolute and normalized**. Canonical SHA printed by a candidate is a local output, *not* independently entrusted authentication. Signers must protect their own 32-byte Ed25519 key files and separately custody every old original; do not send private keys to receivers.

## Receiver / unified command

`verify-timeline` requires **all** of the following real arguments (example placeholders are not trusted values):

```bash
python -I -B scripts/ces_cas_hold_receipts.py verify-timeline \
  --manifest-file /private/ec341-lineage.json --expected-manifest-sha256 "$LINEAGE_SHA" \
  --expected-current-root-sha256 "$ROOT_SHA" --expected-current-root-epoch 4 \
  --minimum-acceptable-epoch 3 --current-root-evaluation-utc 2026-10-25T12:39:00Z \
  --governance-roster-file /private/ec342-governance.json \
  --expected-governance-roster-sha256 "$EC342_GOV_SHA" \
  --review-manifest-file /private/ec342-review-set.json \
  --expected-review-manifest-sha256 "$EC342_REVIEWS_SHA" \
  --approval-file /private/ec342-approval.json --expected-approval-sha256 "$EC342_APPROVAL_SHA" \
  --hold-evaluation-utc 2026-10-25T13:00:00Z \
  --roster-file /private/ec343-roster.json --expected-roster-sha256 "$EC343_ROSTER_SHA" \
  --head-snapshot-file /private/snapshot-1.json --expected-head-snapshot-sha256 "$HEAD_SHA" \
  --head-ack-set-file /private/head-acks.json --expected-head-ack-set-sha256 "$HEAD_ACK_SHA" \
  --timeline-evaluation-utc 2026-10-25T13:14:00Z
```

Use the **same option flags** behind the fixed privilege-minimal unified entry:

```text
python -I -B scripts/ces_next.py audit-issuer-hold-timeline DeliveryAudit VerifySignedHoldReceiptTimeline [all verify-timeline flags]
```

To observe **two independent, signed successor requests from the same predecessor**, supply *all four* optional flags: `--competing-snapshot-file`, `--expected-competing-snapshot-sha256`, `--competing-ack-set-file`, `--expected-competing-ack-set-sha256`. Both branches are recursively signature-verified and separately SHA-pinned; they must have identical actual predecessor snapshot SHA and sequence but distinct signed proposal SHA. The output is `competing_change_requests_unresolved`, *not* a decision selecting either. One malformed or unrelated sibling is a hard denial.

The local **read-only result statuses**, all `exit_code=2`, are `baseline_acknowledged_unresolved`, `receiver_ack_incomplete_unresolved`, `revision_requested_unresolved`, `withdrawal_requested_unresolved`, `supersession_requested_unresolved`, `competing_change_requests_unresolved`, `hold_window_expired_unresolved`. Incomplete receipt count and original expired-window flag are both visible even when a higher-priority competing-branch status applies. Malformed pins/paths/schema, missing EC342 approval, role reuse, reused nonce/approvals, invalid Ed25519, future-of-evaluation receipt, expired signing window or mismatched historical parent are hard denial **exit3/4/5**. Re-read all referenced EC343 originals after crypto audit; EC342 re-reads older originals.

## What remains explicitly NOT PROVEN

No **actual provider/CAS/WORM freeze, withdrawal or supersession** occurs; the code only creates offline untrusted candidates and verifies presented signed evidence. It has no global recipient register, no unseen fork discovery, no global latest root or revocation registry, no independent trusted wall clock, no trust proof for institutions or physical custody, no remote readback/nonexecution proof. Earlier EC317/318 deep fixture still contains **MOCK**, so a local real Ed25519 EC343→EC337 signature check cannot upgrade the whole historic production chain to "unmocked". Native PS7 / 15 Smoke / cross-OS / Git / CI / Provider / E63–E66 and final joint acceptance are outstanding. EC249 incomplete, EC250 blocked, B-001 open, global Quality PASS false and final NOT_STARTED remain unchanged.

See [implementation](../construction/ec343_hold_receipts/timeline.py), [focused tests](../construction/ec343_hold_receipts/test_timeline.py), [scope](../construction/EC343_SCOPE.json), [local report](../construction/EC343_LOCAL_REPORT.json), [complete original file SHA manifest](../construction/EC343_DELIVERY_SHA256.json) and [next round](../construction/NEXT_ROUND.md).
