# EC228 — Controlled ReportPublish: immutable EC200 report → one private sandbox attempt

**Construction release:** V5.38/R228/EC228. **Only** a separately opted-in
single-target `ReportPublisher.publish_once()` exists as standalone Python;
there is **no native PowerShell action**, real provisioned provider, public
production publication, DocsOnlyPublish, remote receipt, or retry/resume API.
No key, endpoint, token, target, review statement or approval is shipped.

## Entry points and exact source

`construction/report_publish.py` exports:

- `TrustedPublishRoots`: six **distinct** host-pinned raw Ed25519 public keys:
  independent organization, exact destination route, current revocation,
  content reviewer, one-use publish side effect, and private Provider capability.
  The host must establish issuer/role custody outside this repository; public
  key bytes do not certify who owns the keys.
- `HostPrivatePublishTarget`: immutable single private **sandbox** provider,
  account, project, destination and fixed HTTPS base URL. No guessed target,
  destination search or public broadcast. The real host must verify account
  privacy, destination control and official Provider contract.
- `HostPublishAccess`: host-owned, non-empty credential, pre-existing durable
  local POSIX private outbox (0700, correct UID), and explicitly enabled real
  private-test publishing. Fake adapters require an **independent development
  flag**, never the production default.
- `ReportPublishRequest`: EC200 `storage_root`, exact `slot_key`, `period_id`,
  *full sorted repository members*, EC200 per-repository Markdown read policy,
  exact latest `version` and saved `cesrr1` report + actual EC199 record,
  Markdown, history-entry and version-index SHA pins, five fully signed
  EC228 statements, and separate exact publishing / network consent booleans.
  **There is no caller-provided Markdown, arbitrary path or remote URL field.**
- `ReportPublisher(access, transport=None).publish_once(request)` returns the
  strict `ces.report_publish.v1` envelope, never article/body/credential/URL.

The pinned EC199/EC200 store path is a trusted *host-selected root* (never a
caller-specified report filename). `report_history._selector/_load` and the
actual EC199 `_valid_index` recheck original canonical record bytes, index
chain, every indexed version's `.json` and `.md` and their SHA-256, original
full repository grants and disclosure flag. Exactly the latest immutable
report version can leave this adapter; a new correction requires a new review,
grant and operation. Source SHA proves local bytes, **not** authenticity of
Git/CI events, permission issuers, human identities or content accuracy.

## Six signed boundaries — exact schemas and domains

Each statement must be an EC224 `SignedAuthorizationStatement` with a canonical
ASCII JSON object, signature hex, the **exact** fields listed in
`ReportPublisher._verify` (extra fields fail), its `schema` constant, and a
signature over `DOMAIN + canonical(statement)` using its **own distinct**
Ed25519 root. Domains and constants live in `report_publish.py` and never
reuse EC223–227 delivery domains.

1. `ces.report_publish.organization.v1` (120 s max): organization-signed
   project/issuer, one report slot, provider/destination, exact policy epoch,
   `INTERNAL_PRIVATE_SANDBOX` class and private-only allow decision.
2. `ces.report_publish.route.v1` (120 s max): independent host-directory
   signer attests provider/account/destination, target SHA (includes endpoint
   hash), `PRIVATE_TEST_ONLY`, `INTERNAL_TEST`, and one destination.
3. `ces.report_publish.revocation.v1` (30 s max): independent **current**
   revocation signer binds operator, target, epoch and this exact one-time
   publish grant nonce to `ACTIVE` (never inferred from an old approval).
4. `ces.report_publish.content_review.v1` (120 s max): independent reviewer
   binds exact report slot/ref, version, EC199 record+Markdown+entry SHA and
   `HUMAN_REVIEWED_EXACT_BYTES_FOR_PRIVATE_TEST`. This is an explicit signed
   *claim* requiring genuine human/organization process to make truthful.
5. `ces.report_publish.single_use_grant.v1` (45 s max): independent approver
   binds original report and all pins, private store identity, canonical EC200
   read policy SHA, hashes of the above four statements, target SHA, six-key
   host trust pin, current code revision SHA, epoch, grant nonce and exact
   `PUBLISH_ONCE_IMMUTABLE_PRIVATE_TEST_REPORT` purpose.
6. `ces.report_publish.provider_capability.v1` (20 s max): a *separate*
   provider-signed response to this invocation's random challenge. It binds
   provider/account, operation, exact target, report ref and Markdown SHA,
   `PUBLISH_EXACT_ONE_PRIVATE_TEST_REPORT`, `private_sandbox=true`,
   `single_destination=true`, `create_only=true`, and
   `idempotency_supported=true`. Never conflate a capability with published
   evidence or Provider accepted receipt.

All statements are snapshotted and signature-checked before source content
is read; exact source/read-policy/target/code/epoch pins and active expiry are
checked again after the capability probe. The fresh revocation signature is
only as meaningful as its real trusted issuer and clock. There is no live
revocation API subscription or external checkpoint in this construction.

## Actual private Provider transport and irreversible at-most-once ledger

`HTTPSPrivatePublishTransport` uses system-verified TLS, no proxy inheritance,
no redirect follow, fixed signed/preprovisioned HTTPS path, bounded timeout
(0.5–8 s), 8 KiB read responses and 385 KiB max encoded body. A signed
private `/capability` probe only transmits identifiers and SHA pins; it
**must have read-only semantics** at the actual provider. The one and only
side-effect route is `POST <base>/publish` with fixed create-only JSON and
idempotency-key header. It includes the original EC199 Markdown bytes as
base64, so the provider must explicitly enforce *create-only*, single private
sandbox resource and never update/overwrite an existing remote document.
Provider egress is gated independently from the host signers. No arbitrary
URL, bulk list, path, attachments, public feed or report patch is supported.

Before **either** HTTP request, `PrivatePublishOutbox` claims a host-managed
existing 0700 POSIX local outbox directory using `mkdir('ec228-'+operation_id)`
and fsync on entry and parent. The operation key is bound to **the same
report slot/ref/Markdown SHA + fixed project and target**, *not* the disposable
grant nonce: a new side-effect grant cannot re-publish an uncertain original.
Durable empty markers, each fsynced before moving to the next step, are:
`00_RESERVED_DURABLE`, `01_CAPABILITY_REQUESTED`, `02_CAPABILITY_VERIFIED`,
`03_POST_ATTEMPTED`, then `04_POST_RETURNED` **or** `05_POST_UNKNOWN`.
`03_POST_ATTEMPTED` is written **before** a POST; timeout, HTTP 5xx,
response-parse failure, crash or uncertainty must **never** trigger another
POST for the same report/target. No payload, keys, token, URL, email, or report
text is written in this outbox. Directory slots must never be pruned; this
module cannot safely run on NFS, multihost deployments, snapshots with
rollback, untrusted same-UID filesystems, or without proper FS durability.

**Results** (see `report-publish-result.v1.schema.json`):

- `partial/2`, `SUBMISSION_UNCONFIRMED`: Provider returned allowed HTTP
  200/201/202/204. **Never** claims `published`, accepted, externally visible
  or delivered; it does not provide a publication receipt.
- `blocked/5`, `invalid_input/4` or `unavailable/5`: missing/invalid/stale
  authorization, source bytes, Provider capability, durable ledger, or
  ambiguous transport. If POST started, state remains `UNKNOWN_UNCONFIRMED`.
  `claim_committed` and `publish_post_attempted` describe this local process;
  they are not guarantees of remote acceptance.

## Limitations and final user-assisted validation

The EC199 *original* Markdown says "unpublished internal review" and remains
unaltered; that header's old status is not silently rewritten to imply
publication. Releasing such an artifact outside a single deliberately
private test board is disallowed. EC199/200 source claims and drafts are
still unverified; a signed reviewer is essential but never automatic DLP,
legal/privacy clearance or proof a human truly reviewed anything. The short
obvious-secret filter is only defense in depth. The `create_only` route and
remote privacy promises require real Provider verification; the local schema
cannot prove remote behavior. A successful HTTP response is not an EC230
independent publication receipt; **EC230 remains future work**.

The current package ran local real EC200-store synthetic tests with ephemeral
Ed25519 signatures and a no-network fake Provider. Genuine enterprise
signers/current revocation, real target ACL and TLS, actual provider
create-only/idempotency semantics, receiver visibility, production-safe
DLP/human legal signoff, trusted clock, actual POSIX power-loss/fsync and
multi-process races, OS/NFS/Windows/macOS/Linux, PowerShell7 and original
15 Smoke, E63–E66 and complete end-to-end assisted acceptance are **NOT_RUN**.
No delivery EC225/226/227 or native PowerShell files were modified.
