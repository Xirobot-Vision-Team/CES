# EC223 — Explicit signed recipient, channel, audience and project verification

**Release:** V5.33 / R223 / EC223. **Implementation:**
`construction/delivery_identity.py`. This is an independently callable,
read-only **local identity-evidence verifier**, not a native PowerShell Action,
address book, delivery authorization, send endpoint, publishing feature or
remote service connector.

## Invariant and threat model

**No receiver may be inferred from Git author/committer names, the contributor
list, issue participants, Report members, PR authors or existing private store
records.** A single, stable, individually selected recipient, channel,
audience **and** project must be present in an explicitly signed directory
route. `EC221.Destination`'s three unverified SHA-256 identity commitments
must match domain-separated commitments computed from exactly that signed
route, including project ID and issuer ID. An SHA supplied by a caller is
never accepted as self-verifying identity evidence.

The host must provision `TrustedIdentityRoots` **out-of-band** in a privileged
configuration, after independently vetting the organization directory issuer.
It contains three mutually different **32-byte Ed25519 public keys** for:

1. The directory route for exactly one project, recipient, channel and
   audience, plus its direct membership assertions.
2. A separate, newly signed revocation checkpoint for that **exact route
   hash**, covering all four subjects.
3. A separate, operator-issued identity-check permit for this exact EC221
   preview, EC222 result, policy, redacted summary hash, project, route,
   revocation checkpoint and EC221 destination binding.

**Never** populate trust roots using values inside a user request, directory
route, public URL, Git history or provider response. The module deliberately
has no default organization key and neither ships nor generates a production
private key. If the host cannot establish those trust roots, do not claim
verified identities. A forged issuer with attacker-pinned keys is only
verified **relative to that forged host trust decision**; this library
cannot itself authenticate a real-world enterprise or natural person.

## Wire-free integration and exact binding

The host first constructs a valid *new* `delivery_redaction.SensitiveReviewRequest`
for one EC221 preview and independently executes EC222. A recipient/channel
verification request is then created with the exact `expected_review_id` and
`expected_redacted_markdown_sha256` from **a genuinely safe EC222 local review**.
The signed identity route must match the three SHA commitments in that EC221
request. The project identifier is required separately and must match all
four signed scopes.

```python
from construction import delivery_identity as identity

verifier = identity.DeliveryIdentityVerifier(
    identity.TrustedIdentityRoots(
        issuer_id=preconfigured_issuer_id,
        directory_public_key=preconfigured_directory_ed25519_key_bytes,
        revocation_public_key=preconfigured_revocations_ed25519_key_bytes,
        verification_public_key=preconfigured_verification_ed25519_key_bytes,
    )
)
result = verifier.verify(identity.DeliveryIdentityRequest(
    sensitive_review_request=exact_existing_ec222_request,
    expected_review_id=exact_known_ec222_review_id,
    expected_redacted_markdown_sha256=exact_known_ec222_redacted_sha256,
    project_id=explicit_project_id,
    directory_route=identity.SignedIdentityStatement(route_document, route_signature_hex),
    revocation_checkpoint=identity.SignedIdentityStatement(revocation_document, revocation_signature_hex),
    verification_permit=identity.SignedIdentityStatement(permit_document, permit_signature_hex),
    permit_independent_identity_verification=True,
))
# result['status'] == 'partial' means a host-pinned local identity check only;
# it never authorizes delivery or external disclosure.
```

Documents must have the **exact** dictionary fields shown below; unknown
fields and unbounded/inferred member lists are rejected. The examples are
*shape explanations*, not actual signing keys or valid identity evidence.
Use canonical `delivery_preview.canonical(document)` bytes, and sign:
`Ed25519.sign(<the module's matching *_DOMAIN constant> + canonical_bytes)`.
Signatures are lowercase 128-character hex. Do not use JSON pretty-printing,
ambiguous Unicode normalization, string substitution, untrusted time or shared
keys to create signatures. If receiving JSON bytes from an untrusted client,
the privileged host must also reject duplicate keys during parsing.

### Directory route (`ROUTE_SCHEMA`)

| Field | Meaning |
|---|---|
| `schema`, `issuer_id` | Fixed schema, exact host-pinned issuer |
| `project` | `{id, status, max_privacy}`; project ID `proj_` + 8–63 ASCII slug characters |
| `recipient` | `{id, kind, project_id, role, status, privacy_ceiling}`; one `MANAGED_HUMAN` or `MANAGED_SERVICE`; one of `REPORT_REVIEWER`, `SECURITY_REVIEWER`, `PROJECT_OWNER` |
| `channel` | `{id, kind, project_id, member_recipient_id, membership, visibility, privacy_ceiling, status}`; EC221 channel kind; `membership=DIRECT_AUTHORITY_ATTESTED` |
| `audience` | `{id, kind, project_id, member_recipient_id, selection, visibility, status}`; `selection=EXPLICIT_SINGLE_RECIPIENT` |
| `directory_epoch` | Positive, authority-controlled monotonically increasing integer (not a hash of a username) |
| `issued_at`, `expires_at` | Integer Unix seconds, lifetime ≤300s; independently checked against local host clock |

All project IDs must match and all four entity statuses must be `ACTIVE`.
Audience/channel `visibility=PROJECT_PRIVATE` and
`audience.kind=INTERNAL_REVIEW` are the only positive targets for current
EC221 sources. Explicit `NAMED_EXTERNAL` and `PUBLIC_DISTRIBUTION` kinds
**cannot** use an internal-only EC222 result for public delivery; identity
selection cannot silently declassify material.

Commitments are SHA256(domain-separated canonical JSON) of
`{issuer_id, project_id, kind, stable_id}`. Use
`delivery_identity.identity_commitment(issuer, project, kind, stable_id)` only in an
**authorized trusted host adapter** when constructing the original EC221
request; do not guess stable IDs from user-provided display names.

### Revocation checkpoint (`REVOCATION_SCHEMA`)

Required exact fields: `schema`, `issuer_id`, `project_id`, `route_sha256`,
`directory_epoch`, `revocation_epoch`, `states`, `issued_at`, `expires_at`.
`states` has exactly `project`, `recipient`, `channel`, `audience` with
`ACTIVE` or rejected status; no missing status is inferred. The checkpoint
is separately signed under `REVOCATION_DOMAIN`, is bound to the **signed
route SHA**, has a directory epoch equal to the route and a revocation epoch
no smaller than it, and has a maximum freshness window of **60 seconds**.
The current check uses only signed status at that time: **an offline check
cannot prove that revocation will not occur a second later**, that the
issuer's upstream directory is complete, or that a host clock is truthful.

### Independent identity-check permit (`PERMIT_SCHEMA`)

Required exact fields: `schema`, `issuer_id`, `project_id`, `route_sha256`,
`revocation_checkpoint_sha256`, `preview_id`, `review_id`,
`policy_revision_sha256`, `redacted_markdown_sha256`,
`destination_binding_sha256`, `purpose`, `operator_id`, `operator_role`,
`issued_at`, `expires_at`. Purpose **exactly**
`EC223_EXACT_IDENTITY_CHECK_NO_SEND`; role **exactly**
`DIRECTORY_IDENTITY_VERIFIER`. Its independently pinned signature is over
`PERMIT_DOMAIN + canonical bytes`; maximum lifetime **120 seconds**.
The permit is for a *read-only recheck*, **not** an EC224 approval, token for
provider APIs, mail address, or EC225 send authority. A caller's permission
boolean without a matching signed permit is insufficient.

## What happens during a call

1. Require an explicit project, three non-null SHA commitments, exact
   EC221 preview and EC222 policy/review/summary hash, and separate identity
   verification consent; reject inconsistent shapes **before private reads**.
2. Verify out-of-band-pinned directory signature; selected subject types,
   project identity, role, per-entity active states, explicit direct
   membership, EC221 destination commitments and selected audience/channel.
3. Verify independent signed, fresh, non-revoked project/recipient/channel/
   audience status; verify separate exact-operator-permit scope and signature.
   Missing cryptography, stale evidence, signature failure, revoke, unknown
   project or unauthorized group/broadcast status fail closed.
4. Re-execute the **actual EC222 review**, which in turn re-reads EC221
   exact versioned EC200 Report or EC179 Finding private stores under their
   own consent. Any `BLOCKED`, unavailable, changed source/store/version,
   changed policy, unknown original Finding text or mismatching hash means
   **no EC223 identity proof**. Never accept a caller-supplied `SAFE` JSON.
5. Enforce selected source's **actual privacy class** against signed
   recipient/channel/project ceilings and role matrix. `REPORT_REVIEWER`
   can review `INTERNAL`; `SECURITY_REVIEWER` may review `CONFIDENTIAL`;
   `PROJECT_OWNER` may also review `RESTRICTED`, provided all ceiling
   assertions agree. No role ever grants sending.
6. Recheck expiration, revocation checkpoint freshness and non-backward
   clock at the **end**. A slow read cannot preserve an expired grant.

## Results and residual risk

See [`delivery-identity-result.v1.schema.json`](delivery-identity-result.v1.schema.json).
A successful `partial/2` binds all of: trust key fingerprints, exact project,
EC221 destination/preview, EC222 review/policy/summary, signed route,
revocation checkpoint, identity permit and ordered selected source hashes
into `cesdi1:`. It exposes **no** recipient, channel, project or operator
IDs, emails, URLs, signatures, PII, source paths or Markdown; IDs above are
represented by SHA commitments only. These deterministic commitments can
remain linkable or guessable if an issuer exposes low-entropy identifiers;
treat them as protected internal metadata, not anonymous identity proofs.
A successful *local directory check*
sets `effects.recipient_identity_verified=true`; every other effect is
`false`. `ready_to_send`, `safe_for_external_send`, `delivery_authorized`,
`message_sent`, `delivered` and `published` are never true.

Denied outcomes (`blocked/5`, `invalid_input/4`, `unavailable/5`) contain no
identity verification payload, only fixed reason codes, and every effect
false. Invalid/stale/unknown/ambiguous identities fail closed; there is no
address enumeration, default target fallback or automatic channel discovery.

**Not solved:** real issuer onboarding, enterprise human identity proof,
cryptographic key rotation, live directory and privilege revocation with
continuity guarantees, authorization to disclose content, real provider
recipient membership/permissions at send time, multi-process atomic reads,
trusted clocks, actual external channels, Windows/macOS/Linux and native
PowerShell7 original Smoke. Final user-assisted end-to-end acceptance remains
`NOT_RUN`. EC224 must issue *new, separate* exact-payload/destination/time
binding for delivery; EC225 must independently verify transport access,
recheck identity and content, and implement actual send semantics.
