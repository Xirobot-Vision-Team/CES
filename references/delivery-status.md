# EC226 / V5.36 / R226 — provider acceptance vs independently observed delivery

## Delivered implementation boundary

`construction/delivery_status.py` is a **standalone Python status observer**, not
an executable PowerShell `DeliveryStatus` Action or an alternate sender. It
consumes one original EC225 signed submission context, checks a real EC225
local durable submit-attempt marker and then may make **one** independently
authorized, challenged, status-only HTTPS `POST /status` request. No `submit`,
POST replay, issue/Git/AI/publish mutation or arbitrary recipient discovery.

The most important distinction:

| Evidence obtained | EC226 status | Provider accepted? | Recipient inbox delivery observed? |
|---|---|---|---|
| EC225 durable claim and `03_SUBMIT_ATTEMPTED` only | `UNKNOWN_UNCONFIRMED` | **No proof** | **No proof** |
| EC225 HTTP 200/201/202/204 only | `UNKNOWN_UNCONFIRMED` | **No proof** | **No proof** |
| Signed fresh provider `UNKNOWN` or `PENDING` | `UNKNOWN_UNCONFIRMED` | **No proof** | **No proof** |
| Signed fresh provider `ACCEPTED` with exact message ID hash and accepted timestamp | `ACCEPTED_PROVIDER_ATTESTED` | Yes, as a provider attestation | **No** |
| Signed fresh provider `DELIVERED` without separate valid inbox receipt | `ACCEPTED_PROVIDER_ATTESTED` | Yes, as a provider attestation | **No** |
| Signed fresh provider `DELIVERED` **plus** signed separate exact inbox observation | `DELIVERED_INBOX_OBSERVED` | Yes | Yes, as an observer attestation |
| Signed fresh provider `REJECTED` / `FAILED` | `PROVIDER_REJECTION_ATTESTED` / `PROVIDER_FAILURE_ATTESTED` | No | No; **not** proof of never-delivered |
| Expired/missing/conflicting/forged evidence or read permission | `UNKNOWN_UNCONFIRMED` with blocked/unavailable | No accepted proof returned | No delivery proof |

`recipient_delivery_observed=true` describes **a cryptographically verified
claim from the host-provisioned test-inbox observer**, not independent proof
that an actual real-world user has received/read a message. A malicious or
unvetted recipient-observer signer can lie. Real deployment requires an
independently managed inbox agent that inspects a truly user-controlled single
test inbox and binds its signed claim to the actual message byte digest.
There is no `recipient_read_by_human` state.

## New independent host-controlled security boundaries

The same **eight EC223–225 Ed25519 keys** remain in force. EC226 adds **two
additional distinct** host-pinned public keys: (9) independent status-read
permit issuer and (10) independently managed test-inbox observation issuer;
all **ten** must differ pairwise. None is enrolled from a query, JSON
response, Git contributor or Provider URL. `TrustedStatusRoots` includes
issuer/reader/inbox-observer identities and host-enforced minimum read epoch.
The EC225 provider-capability key signs the **new, disjoint domain-separated**
provider *status evidence* (not an EC225 capability); the inbox-observer key
signs a separate *delivery observation*, with a different signature domain.
The status read token must come from the host, be different from EC225's
send token, and be restricted by the gateway to status-only lookups. Distinct
tokens are checked locally; actual provider token scope needs live review.

One new <=60-second `ces.delivery_status.read_grant.v1` Ed25519 signature
binds the exact original EC224 approval receipt, raw approver grant hash,
original EC225 side-effect signed-permit digest, operation ID, exact original
source payload **byte** SHA256 and source-set SHA, host provider target/account,
private project/recipient/channel/audience/recipient-identity commitment,
EC225 send trust root commitment, EC226 read trust root commitment, epoch,
explicit test-only purpose and **128-bit read nonce**. Caller must separately
set the two boolean opt-ins (`permit_independent_status_read`,
`permit_provider_status_network_egress`) and host must enable live status
read. A new EC226 read permit **never authorizes** a new send.

`DeliveryStatusRequest.original_send_request` provides the original signed
EC224 exact grant, signed org entitlement/revocation, signed directory route,
original signed EC225 side-effect permit and **the original UTF-8 payload
bytes**. The module verifies historic signatures, original entitlement/
revocation/route relationships and payload hash without pretending that
expired EC224/225 permissions are STILL valid for external side effects.
It does **not** reread or disclose original private source stores for the
status query; a missing historic snapshot/input fails closed. Signed historic
claims plus a durable marker do not prove actual delivery, live organization
membership or a completed remote POST. A current, independent status-read
grant is required in any event.

### POSIX local anti-replay guard

Under the existing **host-owned, 0700, POSIX-local** EC225 outbox root:

- A real `ec225-<operation_id>` directory **must** contain trusted empty,
  owner-only `00_RESERVED_DURABLE` and `03_SUBMIT_ATTEMPTED` markers. This is
  necessary but not sufficient to prove the POST actually went out.
- Before status network egress, create `ec226-read-<SHA256>` with atomic
  `mkdir`, directory `fsync` and a separately fsynced zero-byte
  `01_READ_NONCE_SPENT` sentinel. The digest uses the independent status
  trust-root, issuer and signed nonce. A reused nonce (even with a new signed
  grant / changed operation) is denied **without a new provider request**.
- If claim durability fails, do not access the provider. Do not delete read
  claims or EC225 send claims. Read-only describes the **remote provider
  operation and business sources**; a local empty anti-replay record is
  written. There is no EC227 full status/audit history in this EC.

Same-UID adversaries, filesystem rollback, NFS, multi-host locking and
crash-corruption behavior remain host integration risks; an outbox marker is
not a cryptographic attestation that remote submit completed.

## Host Python entrypoint

```python
from construction import delivery_send as ds, delivery_status as st

# Host constructs `sender` from its EC225 actual eight-key authority/target.
# In the test-only synthetic fixture, host additionally constructs:
status_roots = st.TrustedStatusRoots(
    issuer_id='host_status_authority',
    reader_id='host_reader_operator',
    inbox_observer_id='host_private_inbox_observer',
    status_read_public_key=HOST_STATUS_READ_PUBKEY,
    inbox_observation_public_key=HOST_TEST_INBOX_PUBKEY,
    minimum_read_epoch=ACTIVE_HOST_STATUS_READ_EPOCH,
)
access = st.HostStatusAccess(
    roots=status_roots,
    read_credential=HOST_STATUS_ONLY_BEARER_TOKEN,
    enable_live_private_status_read=True,
)
reader = st.DeliveryStatusReader(sender, access)
request = st.DeliveryStatusRequest(
    original_send_request=ORIGINAL_EC225_DELIVERY_SEND_REQUEST,
    exact_read_grant=SIGNED_NEW_ONE_USE_STATUS_READ_GRANT,
    permit_independent_status_read=True,
    permit_provider_status_network_egress=True,
)
result = reader.observe_once(request)
```

All capitalized host values above are **pseudocode placeholders**, not
shipped credentials or signers. The module does not obtain the read grant,
real Provider account, or inbox observer itself. Host must provision them
after independent enterprise/privacy/security review. The default
`HTTPSPrivateStatusTransport` refuses an arbitrary injected network adapter;
`allow_synthetic_transport_for_development=True` exists exclusively for
no-network disposable tests and is unsafe for live recipients.

### Strict provider `/status` protocol

- Endpoint is derived solely from EC225 host-pinned HTTPS base URL:
  `POST {host_provider_endpoint}/status` with `Authorization: Bearer
  {host_status_read_credential}`, JSON, 8-second maximum timeout, disabled
  environment proxies and redirects, normal TLS hostname verification,
  8192-byte maximum request and 16384-byte maximum response.
- `ces.delivery_status.query.v1` JSON has **exact keys** `schema`,
  `provider_id`, `account_id`, `provider_target_binding_sha256`,
  `project_id`, `recipient_id`, `channel_id`, `audience_id`,
  `recipient_identity_sha256`, `operation_id`, `payload_sha256`,
  `approver_exact_grant_sha256`, `send_trust_anchor_binding_sha256`,
  `read_grant_sha256`, `read_nonce`, `challenge_nonce`. Provider sees only
  exact *hash/reference* metadata; the original payload and actual inbox
  handle are **not** sent in status lookup.
- A usable HTTP 200 response must have **exactly** `provider_status` and
  `inbox_observation`. `provider_status` is the `{statement,signature_hex}`
  Ed25519 envelope (not unsigned JSON). `inbox_observation` is either `null`
  or a **separately signed** `{statement,signature_hex}` envelope from the
  host-pinned inbox-observer key. An HTTP status does not certify a delivery
  state and an invalid envelope is unavailable/blocked, not delivered.
- Provider status signed statement schema `ces.delivery_status.provider_state.v1`
  contains **all query fields except its own `schema` value**, the exact
  `state` (`UNKNOWN`, `PENDING`, `ACCEPTED`, `DELIVERED`, `REJECTED`, `FAILED`),
  `provider_message_id_sha256`, `accepted_at`, `delivered_at`,
  `observed_at`, `issued_at`, `expires_at`. Every signed field binds to the
  exact client challenge and one-use read grant. Its signature domain is
  `STATUS_DOMAIN` and the existing EC225 host-pinned Provider key.
  Evidence is valid for <=20s, with no expired read grant.
- For `ACCEPTED` / `DELIVERED`, the provider must supply a non-null
  opaque *SHA256 of the provider message ID* and an explicit ordered
  acceptance timestamp. For `DELIVERED`, it must ALSO provide a plausible
  `delivered_at`; this still does not prove a recipient inbox received it.
  For other states the message ID and both event times must be null. All
  state/timestamp contradictions fail closed.
- The optional `ces.delivery_status.inbox_observation.v1` statement binds
  `observer_id`, `purpose=TEST_INBOX_EXACT_MESSAGE_OBSERVED`,
  `test_destination_only=true`, exact provider/account/target,
  operation, original signed grant, exact recipient identity/channel/
  audience, payload byte hash, provider message SHA, **SHA of the complete
  signed Provider status statement** (domain-separated), read grant SHA,
  exact challenge nonce, `inbox_observed_at`, `issued_at`, `expires_at`.
  It MUST refer to a signed `DELIVERED` provider state; its separately
  signed <=20s window and monotonic accepted/delivered/inbox times must
  validate. A provider signature or a self-asserted inbox flag cannot
  substitute for this separate key.
- No `GET /search`, subscriber enumeration, callback, provider task
  scheduling, retry, `submit`, redirect following or public publication.

Network errors, non-200 status reads, exceeded caps, malformed data,
signature/clock/nonce/read permission mismatch, missing original outbox or
source grant and timeout return **status unavailable/blocked and
`delivery_state=UNKNOWN_UNCONFIRMED`**, with no remote submission retry.
A verified `REJECTED`/`FAILED` is only a provider assertion about its current
state, not mathematically certain evidence that a recipient never received
an earlier message. No locally persisted delivery truth exists until the
later independently scoped EC227 design.

## Development and deferred acceptance

Run from `construction/` with Python, `cryptography` and `jsonschema`:

```sh
python -m unittest -q test_delivery_status
```

24 focused synthetic test methods cover EC225's actual disposable source
chain, response-bound cryptographic evidence, missing/stale/forged provider
and independent inbox proof, distinct read tokens, nonce consumption,
unknown POST observation with **no resend**, historical byte/grant mismatch,
missing outbox, privacy-safe output and strict Draft2020-12 result schema.
These are synthetic development tests, not a certified external delivery.

**NOT_RUN:** real independently vetted ten-key authority and host rotation,
true inbox observer against a user-controlled recipient, provider status
protocol deployment/ACL/token scopes, real authenticated provider responses
and recipient receipt correlation, attacker-controlled input, filesystem
power-loss/NFS/multihost/same-UID concurrency, secure clock/revocation,
Windows/macOS/Linux, original PowerShell7/15 Smoke and E63–E66 performance,
complete user-assisted final acceptance. Historical upstream B-001 remains
OPEN. No real status request or external send took place in this package.

Next and **separate** EC227: complete query/attempt/reconciliation audit and
safe idempotency policy; no automatic resend of unknown attempts is implied.
