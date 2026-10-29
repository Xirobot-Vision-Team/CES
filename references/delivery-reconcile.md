# EC227 — Private delivery audit, status reconciliation and idempotency guard

**Construction release:** V5.37 / R227 / EC227. **Standalone Python component only**, not a registered native PowerShell Action. Dependencies: original EC225 `delivery_send.py` and EC226 `delivery_status.py`. This module does not send or resend messages. It does not publish anything, alter a Provider remote log, or claim exactly-once remote delivery.

## Purpose / precise constraints

- EC225 reserves the EC224 grant-derived **operation ID** in a durable local protected outbox before any network, marks `03_SUBMIT_ATTEMPTED` before any submission POST, and never retries an ambiguous POST. A reservation / attempted marker is **not** signed proof that the Provider accepted or that the inbox received a message.
- EC226 separately verifies original historical EC224/225 signatures, exact original payload byte SHA and test target, the EC225 local attempted marker, a **fresh independent signed <=60s one-use read grant**, challenge-bound Provider state signature, and when delivery is claimed, a **second independent test-inbox observer signature**. EC227 does not bypass these checks or consume EC225 send permits. EC226 read nonces remain spent by EC226 itself.
- EC227 creates a small, fsynced, per-original-operation **append-only local audit**. A repeat status read can run *only with a different freshly signed EC226 read grant + nonce*. A send retry of the original operation is **never** allowed by EC227. A new operation also must not automatically be sent merely because an earlier Provider reported `REJECTED` / `FAILED` / `UNKNOWN`.

## Host configuration and minimal API

Prerequisites: a genuinely trusted private single-target `DeliveryStatusReader`, all EC223–226 host-provisioned credentials/authorities, a precreated **owner 0700 trusted POSIX-local** EC225 `outbox_root`, and a **separate 32-byte secret** from a host-held secure secret facility (never bundled, logged, persisted by CES, or obtained from the signed original message). Host must set an **explicit local audit enable switch**. No real provider, token, recipient, secret, or signing keys ship with CES.

```python
import delivery_reconcile as rc

# reader: existing trustworthy st.DeliveryStatusReader configured by host
# secret: host-provisioned 32 random bytes; NEVER hardcode or commit
reconciler = rc.DeliveryReconciler(
    reader, rc.HostAuditAccess(hmac_secret=secret,
                               enable_local_private_audit=True)
)

# A request with a NEW valid EC226 signed one-use read grant:
status = reconciler.observe_and_record(delivery_status_request)

# Read existing local audit. This NEVER contacts a provider and NEVER yields
# fresh independent remote delivery proof, even if an old event was DELIVERED.
history = reconciler.readback(delivery_status_request.original_send_request)

# Keep the returned head MAC separately in host-controlled tamper-resistant
# storage; present it on future readback to detect an old tail being removed.
checked = reconciler.readback(
    delivery_status_request.original_send_request,
    expected_head_hmac_sha256=status['audit_head_hmac_sha256'],
)

# Explicitly ask if the ORIGINAL approval/operation can be resubmitted.
# If already attempted, this always denies without a network POST.
guard = reconciler.retry_guard(delivery_status_request.original_send_request)
assert guard['original_operation_retry_allowed'] is False
```

Both APIs require the **original historical signed request with exact original payload bytes**; neither accepts arbitrary operator IDs, raw file paths, message recipients or transport URLs. The fixed audit location is under the original pinned sender's EC225 outbox. A missing or tampered original marker, invalid signatures, changed target, unauthorized read, missing secret or invalid filesystem refuses. A readback without existing EC227 audit reports `AUDIT_NOT_YET_RECORDED`, **not** a verified delivery record.

`observe_and_record()` runs:

1. Validate host opt-in, exact historical EC224/225 signed bind + original payload bytes, the original `03_SUBMIT_ATTEMPTED` and current EC226 *read-only* grant; do not interpret historical approvals as new send rights.
2. Acquire nonblocking exclusive `flock()` on an owner-private per-operation audit directory (fail closed if concurrently busy), verify every existing entry and strict sequence/HMAC. Reject missing/reordered/extra/oversized/symlink/hardlinked/malformed entries, stale host clock, reused nonce or exhausted capacity **before** any new status network call.
3. Append `LOOKUP_STARTED` with SHA-bound operation/target/content/read grant, **UNKNOWN** state, `fsync(file)` then `fsync(directory)`; only now invoke EC226 `observe_once()` (which additionally performs its own unique read nonce consumption and independently signed Provider/inbox evidence checks).
4. Append `LOOKUP_RESULT` with the *verified in-process* EC226 classification. If status lookup failed, proof is missing/invalid, or the return is contradictory, write `UNKNOWN_UNCONFIRMED`. Unknown is never upgraded by a successful HTTP status or prior cached result. If a crash happens after START, the unmatched START remains an explicit UNKNOWN. The next separately signed read can run but cannot retry the original POST.
5. Return conservative current outcome and `audit_head_hmac_sha256`; all result paths set `original_operation_retry_allowed=false`, `new_delivery_authorized=false`, `resent=false`, `published=false`, and never call a submit transport.

Every entry has a sequential, six-digit filename like `000001.json` under `ec227-<scope-hash>` and contains **only identifiers' SHA hashes and safe enumerated status metadata**, never the raw payload, recipient handle, credentials or host HMAC key. Each record includes `previous_hmac_sha256`; the current record HMAC covers a domain-separated canonical JSON entry. Existing files are never overwritten, edited, cleaned up, compacted or automatically repaired. Up to **64 entries** are supported per original operation (at most 32 complete reads, fewer after crash-orphan entries); once full, reject before another status call.

## State reconciliation semantics

| Input evidence | Newly reconciled state | Does it authorize a POST? |
| --- | --- | --- |
| No authenticated status / timeout / expired grant / Provider `UNKNOWN` or `PENDING` | `UNKNOWN_UNCONFIRMED` | **No** |
| Signed Provider `ACCEPTED` | `ACCEPTED_PROVIDER_ATTESTED` | **No** |
| Signed Provider `DELIVERED` with no separate signed inbox observation | `ACCEPTED_PROVIDER_ATTESTED` | **No** |
| Signed Provider `DELIVERED` **and** exact independent inbox observation | `DELIVERED_INBOX_OBSERVED` | **No** |
| Signed Provider `REJECTED` or `FAILED` | Provider-specific attested failure, not proof of non-delivery | **No** |
| Inconsistent multiple authenticated outcomes, changed message SHA or `DELIVERED` -> `ACCEPTED` regression | `UNKNOWN_UNCONFIRMED` plus conflict flag | **No** |
| Old local audit readback even if last observed delivered | **Current** `UNKNOWN_UNCONFIRMED` plus historical signed-observation summary | **No** |

An earlier verified state is exposed separately as `last_historical_attested_state`. It is **not current network evidence**. The new current state from `observe_and_record()` corresponds only to the latest completed independently verified EC226 lookup, provided the audit shows no contradictory history. Earlier abandoned START entries remain visible via `incomplete_prior_observation`; a new successfully signed read can still establish a fresh state. Status read operations are never mistaken for new sends.

## Verification / trust and limits

- **Host-relative evidence**: audit HMAC authenticates that this deployment recorded *an EC226-verified result*, **not an archive of the raw remote Provider/observer signatures**. Independent off-box verification of historical delivery is not possible from audit entries alone. Use a new EC226 signed observation for fresh proof. If the host is compromised, all host-relative guarantees fail.
- **No unpinned rollback detection**: an HMAC chain detects changed, reordered, fabricated and internally missing records, but by itself **cannot detect deletion of a complete valid suffix or a restored prior snapshot**. Persist a head HMAC outside the local outbox and pass it to `readback(expected_head_hmac_sha256=...)` to detect mismatch. This is **not** automatically an external notary, and head pinning during writes must be operationally designed by the host.
- **Filesystem**: exclusively for a trusted POSIX-local owner-0700 outbox with `O_NOFOLLOW`, `O_EXCL`, fsync and advisory flock. This is not resistant to a compromised same-UID process, untrusted parent/FS, NFS, multihost split-brain, stale backups or host crashes with weak storage durability. No automatic recovery, deletion, repair, credential lookup or ledger migration. Keys rotated or lost require a reviewed out-of-band migration; never silently re-MAC existing entries.
- **Bounded resource policy**: 64 total per-operation records, each <=4096 bytes. An exhausted, interrupted or tampered journal cannot trigger egress, and results are always fail-closed. Individual lookup and Provider timeout remain those of EC226.
- **Deployed prerequisites NOT PROVIDED**: enterprise trust and key governance, independently verified real test inbox and Provider credential ACL, external HMAC key/strong checkpoint storage, observed real network/recipient behavior, Windows/macOS/Linux cross-platform and true crash/NFS/multihost race validation, native PowerShell7 + 15 Smoke, performance E63–E66 and final user-assisted end-to-end acceptance. Historical upstream B-001 stays OPEN.

## Files / local development verification

- Code: [`../construction/delivery_reconcile.py`](../construction/delivery_reconcile.py)
- Focused local synthetic functional cases: [`../construction/test_delivery_reconcile.py`](../construction/test_delivery_reconcile.py)
- Strict output schema: [`delivery-reconcile-result.v1.schema.json`](delivery-reconcile-result.v1.schema.json)
- Strict audit schema: [`delivery-reconcile-audit.v1.schema.json`](delivery-reconcile-audit.v1.schema.json)
- Fixture boundary: [`../construction/fixtures/README.md`](../construction/fixtures/README.md)
- Historical EC225/EC226 unchanged, originals still at V4.60/R150 CLI; no native action or report publication added.
