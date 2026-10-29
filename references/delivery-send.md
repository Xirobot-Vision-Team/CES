# EC225 — host-controlled, one-use sandbox DeliverySend interface

## Scope and activation

`construction/delivery_send.py` implements **one standalone Python adapter**, not an existing/native PowerShell CES Action. Its **only egress destination** is an independently provisioned, user-controlled **private single-recipient test inbox** behind an HTTPS gateway implementing the protocol below. A `cesda1:` EC224 local receipt is necessary but **never sufficient** for sending. There is **no fallback** to arbitrary email, URLs, Git-author addresses, recipient searches, groups, public channels, production recipients, external privacy declassification, or publishing.

For real use a trusted host (outside user-provided CES/AI/Git content) must provide, in memory:

1. An EC223 identity verifier with **three distinct Ed25519 public keys** pinned to a real directory authority, and an EC224 authorizer with three **different** pinned organization/approver keys.
2. An EC225 `TrustedSideEffectRoots` with **two additional independent pinned Ed25519 public keys**: side-effect authorizer and signed provider-capability issuer. All **eight keys must differ**. Side-effect operator must differ from both EC224 approver and EC223 identity-check operator.
3. A single `HostTestProvider` containing the exact EC223 project/recipient/channel/audience IDs, exact recipient identity SHA, channel kind `CHAT` or `EMAIL`, trusted provider/account IDs, **opaque test-inbox handle**, fixed HTTPS endpoint, and `user_controlled_sandbox=True`. No dynamic resolve from supplied message, author, or unverified contact data.
4. A provider-specific bearer credential from a host secret manager, not from JSON, a source file, the EC224 grant or a ZIP fixture; an existing host-owned 0700 POSIX-local private outbox root that remains durable and is never reset or copied to another server; `enable_live_sandbox_send=True` plus **both** explicit request consents.
5. A newly **independently signed and short-lived** EC225 `SignedAuthorizationStatement` with purpose `SINGLE_PRIVATE_SANDBOX_TEST_DELIVERY_ONLY`; its verified signed scope includes the EXACT EC224 receipt ID, approver grant SHA, revocation checkpoint SHA, source set/payload SHA, route/destination SHA, project, recipient, channel, audience, target binding, send trust root, code revision, one fresh 32-hex-character nonce and a host-controlled nondecreasing send permission epoch. Validity at most 30 seconds; it must be issued after the EC224 exact grant and expire no later than the EC224 approval window.

`DeliverySender.send_once(DeliverySendRequest(...))` is the entrypoint. The request carries the complete **original** EC224 authorization request and a new signed side-effect statement — not a pasted EC224 success JSON. `send_once` invokes the real authorizer, which replays EC223/222/221 private sources, checks all prior signatures and original UTF8 payload byte SHA; after provider probing, it re-runs the **full chain again** before any actual submission.

If any signer, source, redaction, privacy, recipient, provider, network permission, credential, local outbox, code hash or expiry is missing/changed, **no provider submit call occurs**. These controls do not independently prove that a real issuer owns the keys, the source has no unknown sensitive text, or an organization permits any broad disclosure.

## Provider gateway protocol (application-specific, not an existing vendor API)

The default `HTTPSPrivateTestTransport` is executable using Python standard-library HTTPS. It never inherits proxy settings or follows redirects; TLS verifies the configured hostname. Only `POST {fixed_endpoint}/probe` and `POST {fixed_endpoint}/submit` are allowed. The endpoint is host-pinned before request handling and only `https://` without userinfo, query, fragment, IP literal, nondefault port, local host or traversal syntax is accepted. Each request carries a host-only bearer credential and JSON with bounded bodies; the token, original content, URL and inbox handle never appear in the result or outbox. To use a real service, independently operate a gateway implementing this **specific protocol** — no vendor-host/ACL behavior is assumed.

### 1. Probe (after durable outbox claim; before actual submit)

The client sends `ces.delivery_send.provider_probe.v1` JSON with exact provider/account/project/recipient/channel/audience, opaque test inbox handle, EC225 immutable provider-target SHA, SHA of the exact EC224 payload, deterministic approval-derived operation ID and a fresh unpredictable 16-byte nonce encoded as 32 hex characters. The provider must authenticate the token/account **and live test inbox membership/single-target permission**, then answer HTTP 200 with exactly:

```json
{"statement": {"schema": "ces.delivery_send.provider_capability.v1", "provider_id": "...", "account_id": "...", "provider_target_binding_sha256": "...", "project_id": "...", "recipient_id": "...", "recipient_identity_sha256": "...", "channel_id": "...", "audience_id": "...", "channel_kind": "CHAT", "operation_id": "...", "challenge_nonce": "...", "payload_sha256": "...", "permission": "SUBMIT_ONE_TEST_DELIVERY", "state": "ACTIVE", "single_recipient": true, "user_controlled_test_destination": true, "provider_supports_idempotency": true, "issued_at": 1761300000, "expires_at": 1761300010}, "signature_hex": "..."}
```

The signed statement uses domain prefix `CES-EC225-PROVIDER-SIGNED-SANDBOX-TARGET-CAPABILITY-v1\0` concatenated with EC221 `dp.canonical(statement)` JSON bytes, Ed25519 signed with the **independently host-pinned provider capability key**. `expires_at - issued_at <= 20s`, with current-clock freshness, exact challenge nonce, operation, account, target, SHA and test-only constraints. A forged, copied, stale, revoked, broad or multi-recipient permission cannot authorize a POST. This is an application-specific provider authorization claim; actual live ACL integration remains a host/provider responsibility.

### 2. One submit attempt

After `02_PROBE_VERIFIED`, re-running the private EC224 chain, checking sender code SHA, epochs and all deadlines, and fsyncing marker `03_SUBMIT_ATTEMPTED`, POST exactly one bounded `ces.delivery_send.provider_submit.v1` JSON body to `{fixed_endpoint}/submit` with the same `operation_id` as `Idempotency-Key` header. Body contains the exact UTF8 payload `payload_b64`, original payload SHA and media type, fixed account/inbox handle, provider capability and signature, and exact signed side-effect permit SHA. **Do not modify the body on provider retries: retries are not implemented by EC225.** There is NO automatic retry on timeout, connection close, 3xx, 4xx, 5xx, or ambiguous return.

## Durable first-writer-wins outbox

The fixed `outbox_root` must already exist, be owned by the executing POSIX user and have mode 0700; it cannot be a symlink. `DurableGrantOutbox` atomically reserves the SHA-derived `ec225-<operation_sha>` directory under a held root directory file descriptor, `fsync`s the child, parent and empty, non-secret state marker files. The operation key derives from the **EC224 approver exact grant SHA**, organization authorization root and project SHA — **NOT from the EC225 permission nonce**. Consequently, the same EC224 approval can never be sent a second time by obtaining a different EC225 permit. The reservation is committed **before the capability probe** (before any provider request); the submit-intent marker is committed **before** the actual POST.

Outbox slots store **only opaque hash names and empty state marker files**, never source content, recipient details, token, public addresses, paths or JSON. Stages: `00_RESERVED_DURABLE`, `01_PROBE_REQUESTED`, `02_PROBE_VERIFIED`, `03_SUBMIT_ATTEMPTED`, `04_POST_RETURNED` or `05_POST_UNKNOWN`. Interrupted or rejected claims are **never reused**; a new attempt requires a newly signed EC224 approval plus EC225 side-effect permit and a fresh full private review. Do not delete, roll back, restore from stale backup, or independently replicate this outbox. Atomic local directory creation protects a **single trusted POSIX local filesystem**; NFS/distributed hosts, hostile same-UID filesystem attackers, crashes/durability on real disks and Windows/macOS remain **NOT_RUN / not claimed safe**. A central transactional ledger is required for actual multi-host production.

## Output semantics (Draft2020-12)

`references/delivery-send-result.v1.schema.json` rejects unknown fields and encodes:

| Field | Meaning |
| --- | --- |
| `status=partial`, `exit_code=2` | The sandbox provider returned HTTP 200/201/202/204 for one attempted POST; not proof the message was sent, accepted, or delivered. |
| `submission_state=SUBMISSION_UNCONFIRMED` | Only a transport request was attempted and a success-family HTTP code returned. Acceptance and delivery are **outside EC225**. |
| `status=unavailable`, `submission_state=UNKNOWN_UNCONFIRMED` | POST began but failed, timed out, returned an unexpected code, or local outcome evidence failed. **Never blindly retry.** |
| `status=blocked/unavailable`, `NO_SUBMISSION_ATTEMPT` | Signed permission, source, outbox, provider probe or other pre-submit condition failed. Claim may already be irreversibly reserved. |
| `GRANT_ALREADY_USED_NO_REPLAY` | Approval's durable grant-key claim already exists; no network call. |

Every outcome keeps `ready_to_send`, `message_sent`, `delivery_accepted`, `delivered`, `published` **false**. Positive `effects.external_network_requested` means the controlled provider interface was invoked; it does not prove the recipient was contacted. Only metadata hashes, fixed reason codes and a `cesds1:` submission-attempt ID may appear in JSON; never credentials/source/recipient names. `ces_records_written=false` refers to CES business records — the **separate host-owned outbox IS written** when a claim is reserved. No publishing/AI/Git/Issue/business-content mutation.

## Local development without egress

Run `python -m unittest -q test_delivery_send` from `construction/` only in an isolated Python environment with `cryptography` and `jsonschema`. Synthetic cases inject an ephemeral signed `SandboxFakePort` with **`allow_synthetic_transport_for_development=True`**. Default production construction **rejects custom ports** and uses strict HTTPS. Test fixtures are never usable real identities, keys, accounts or contacts.

Not provided in this archive: real enterprise signing roots/credentials, a deployed compliant HTTPS sandbox provider, test inbox ownership proof, live provider permissions, true organizational sensitive-content clearance, secure hardware clock/real-time revocation, permanent central outbox/multi-host consistency, EC226 accepted/delivered evidence, EC227 audit/retry reconciliation, native PowerShell registration or OS/Smoke/performance/final acceptance. All must be explicitly tested before external delivery is enabled by a real host.
