# EC217 — one-use, separately approved IssueCreate attempt grant

**Construction package:** V5.27 / R217. **Original native PowerShell CLI:**
V4.60 / R150, unchanged. The implementation is
[`construction/issue_create_grant.py`](../construction/issue_create_grant.py)
(Python API, not a native Action). EC218 remote HTTP POST, idempotency and remote
result reconciliation are **not** implemented here.

## The security boundary

The preceding EC215 `ELIGIBLE_TO_PROPOSE` and EC216 `DRAFT_READY` mean **only**
that a redacted local suggestion may be reviewed. EC217 requires a **different,
explicit human signature** from an independently host-configured
`ISSUE_CREATE_APPROVER` for the exact **NEW Issue** target/action, original
whole EC216 result, original re-evaluated EC215 evidence and its signed
review, actual final title, body, sorted labels, chosen E## source citations,
visibility, privacy policy revision, host audience and one-time random ID.
Every final byte must be separately displayed to the human authorizer and
sanitized under the organization's privacy policy. An approval of a hash
without showing the corresponding title/body/citations is NOT meaningful
human review. The module cannot establish semantic duplicate absence,
prose safety, live credentials, source truth, organizational key enrollment,
or a user's actual intent. **Never** derive the issuer registry, ledger or
approval signature from the submitted Issue/Finding/plan text.

Approval is an externally detached **Ed25519** signature. EC215 uses a
separate domain, decision and keys, so its local-proposal signature cannot
become remote IssueCreate permission. EC217 rejects exactly reusing the
EC215 reviewer key or raw public-key bytes even under a different ID. A new
short-lived EC217 receipt is necessary after *any* change to the target,
policy, final text, labels, citations or original EC216 plan.

## Integration and call flow

The host must maintain the original EC214/215/216 inputs and an independent,
securely enrolled organization issuer registry. The issuer's authority entry
is `IssuerAuthority(public_key, role, provider, api_host, account_ref,
repository_identity_sha256, visibility, policy_revision_sha256, audience,
authority_revision_sha256, valid_from_utc, valid_until_utc, revoked)`.
The host authenticates ownership, role, authority-revision changes and
revocation **outside** this code; passing an issuer entry through the user
request would be circular authentication. The issuer registry must be
rechecked at reservation and again by any future EC218 execution service.

```python
from construction import issue_create_grant as cg

# ctx, original EC214/215 inputs, reviews and EC216 exact original output
# are separately recovered from the authorized local host workflow.
# HOST_REVIEW_KEYS and HOST_ISSUERS are independently provisioned,
# not supplied by the Issue, Finding, content or applicant.
record = cg.PlanEvidence(
    context=ctx,
    plan_intent=original_ec216_intent,
    eligibility_request=original_ec215_request,
    match_request=original_ec214_request,
    match_result=original_ec214_result,
    eligibility_result=original_ec215_result,
    eligibility_review_receipt=original_ec215_review,
    plan_result=original_full_ec216_result,
)

approved_citations = tuple(
    cg.Citation(ref['reference_id'], ref['anchor_binding_sha256'])
    for ref in original_full_ec216_result['draft']['references']
)
final_content = cg.FinalIssueContent(
    title=human_sanitized_final_title,
    body=human_sanitized_final_body,
    labels=tuple(sorted(set(human_reviewed_labels))),
    citations=approved_citations,
)
intent = cg.IssueCreateIntent(
    action='CREATE_NEW_ISSUE', provider=ctx.provider,
    api_host=ctx.api_host, account_ref=ctx.account_ref,
    repository=original_ec215_request.repository,
    expected_repository_id=original_ec215_request.expected_repository_id,
    visibility=original_ec215_request.privacy.target_visibility,
    policy_revision_sha256=original_ec215_request.privacy.policy_revision_sha256,
    expected_plan_sha256=original_full_ec216_result['draft']['plan_sha256'],
    expected_plan_result_sha256=cg.plan_result_sha256(original_full_ec216_result),
    expected_final_content_sha256=cg.final_content_sha256(final_content),
    audience=host_configured_audience,
)
challenge = cg.prepare_issue_create_review(
    record, intent, final_content,
    trusted_eligibility_review_keys=HOST_REVIEW_KEYS,
)
# Must equal NEEDS_REVIEW, challenge contains only nonsecret bindings.
# Show the *entire* private final content, citations and target identity
# to the authorized human in a trusted local review UI. Collect explicit
# authorization to CREATE ONE NEW Issue, NOT edit an existing one.
# After independent organizational issuance, the host receives a
# cg.HumanCreateApproval with signed approval_signing_bytes(receipt).
checked = cg.inspect_issue_create_grant(
    record, intent, final_content, externally_signed_receipt,
    trusted_eligibility_review_keys=HOST_REVIEW_KEYS,
    trusted_issuers=HOST_ISSUERS,
)
# SIGNED_REVIEW_VALID means only cryptographic review; NOT a usable
# one-time claim and NOT permission to send or claim Issue creation.
```

The signed receipt must have `schema=ces.issue_create_approval.v1`,
`method=EXPLICIT_HUMAN_APPROVAL_OF_ONE_NEW_ISSUE`,
`action=CREATE_NEW_ISSUE`, a cryptographically random 128-bit lowercase hex
`grant_id` (`new_grant_id()` is provided), valid and independently hosted
`issuer_key_id`, authority revision, challenge digest, target digest, whole
plan-result digest, final payload digest, audience, policy digest,
`decision=APPROVE_EXACT_NEW_ISSUE_ONCE`, all **four explicit confirmation
booleans true**, the original issued/expiry UTC values and an Ed25519
`signature_base64`. Sign only the bytes from `approval_signing_bytes(receipt)`
using a private key **outside** CES; the signature is omitted from the bytes
being signed. The receipt expires no later than 180 seconds after issuance.
Never put the private signing key in this ZIP or its returned logs.

### Claim exactly once (and nothing else)

```python
from pathlib import Path

# Explicitly provision a private 0700 directory outside business repos,
# e.g. an isolated host-owned local-POSIX volume. All workers for the
# *same audience* MUST share one ledger and must not restore it from backups
# into an already-active instance. Do NOT use SQLite for NFS or multi-host.
ledger = cg.SQLiteOneUseLedger(Path(host_private_data_dir) / 'grant.db',
                               host_configured_audience)
reserved = cg.reserve_issue_create_grant(
    record, intent, final_content, externally_signed_receipt,
    trusted_eligibility_review_keys=HOST_REVIEW_KEYS,
    trusted_issuers=HOST_ISSUERS, ledger=ledger,
)
# Only RESERVED_ONE_ATTEMPT records a durable unique-ID reservation.
# This function performs NO provider network call and creates NO Issue.
# No auto-retry; EC218 will own provider idempotency, fresh authorization
# and remote unknown-result reconciliation in its separate construction.
```

A production multiple-host platform must supply a **trusted transactional
shared** `AtomicGrantLedger` adapter with `audience` and
`atomic_claim(grant_id, challenge_sha256, now)`, returning `CLAIMED` only
**after** durable unique-ID insertion. Its other results must be
`ALREADY_CLAIMED` or `UNAVAILABLE` (uncertain results fail closed). The bundled
`SQLiteOneUseLedger` uses a primary-key UNIQUE insert inside SQLite
`BEGIN IMMEDIATE`/`COMMIT`, `synchronous=FULL`, `DELETE` journal, private
0600 file and 0700 parent checks on a trusted POSIX local disk; it stores only
opaque grant-ID digests, challenge digests and claim timestamps. It rejects
symlinks at checked path components, world/group-accessible directories,
non-regular files and missing atomic storage. This is **not** protection
against malicious same-user inode/path replacement, power-loss filesystems,
NFS, arbitrary OS semantics, database rollback, re-creating another DB for
the same audience, or multiple unshared hosts. A reservation consumes the
permission even if the later network call fails or returns an unknown result;
no release, replay or silent reauthorization is provided.

## State semantics

| State | Exit | Meaning |
|---|---|---|
| `NEEDS_REVIEW` | `partial/2` | Challenge prepared or separate signature missing/expired. No grant. |
| `SIGNED_REVIEW_VALID` | `partial/2` | Correct scoped signed review, but no atomic claim; **no remote permission**. |
| `RESERVED_ONE_ATTEMPT` | `partial/2` | Host ledger atomically reserved one ID for at most one future EC218 attempt; **no Issue created**. |
| `BLOCKED` | `partial/2` | Target/policy/role/issuer or confirmation mismatch, replay or edit attempt. |
| `UNKNOWN` | `unavailable/5` | Stale/falsified prior result, uncertain ledger or internal failure. |
| `INVALID_INPUT` | `invalid_input/4` | Bad dataclass, content shape, forbidden characters or invalid pin. |

No branch reports remote Issue success; `issue_created`,
`issue_create_network_attempted`, `external_content_disclosed`, native action,
source authentication, duplicate absence and organization issuer proof are
always `false`. The only true attempt authorization is
`issue_create_authorized_for_this_one_attempt=true` **after** a successful
atomic claim, and only for the exact signed bindings and audience.

## Trust, confidentiality and deferred acceptance

- **Confidentiality:** title/body/labels are internal inputs, never included in
  challenge/decision output or SQLite. The output includes SHA bindings,
  provider, visibility and coarse lengths/counts. Hashes of guessable data
  are not encryption; do not send this result externally without policy review.
- **Original results:** exact full serialized EC216 output is compared to a
  fresh recomputation invoking unchanged actual EC215 and EC214 consent;
  supplied forged `DRAFT_READY`, `ELIGIBLE_TO_PROPOSE`, positive IssueMatch
  hints or signed EC215 *local proposal* cannot shortcut EC217 approval.
- **Scope:** provider, exact api host/account, repository spelling plus stable
  numeric ID, visibility, privacy policy, source/finding/citations and complete
  content are bound. No `issue_id`, editor route or credential/POST helper is
  accepted. No network and no external AI are invoked.
- **Remaining unknowns:** actual independent organization signer authority and
  revocation, provider account permissions, hidden/private Issues and duplicate
  discovery, truthful source/HMAC/Git/CI and privacy review, confidential prose
  and labels, multi-host one-shot behavior, crash/storage durability and NFS/
  Windows/macOS/Linux variations, original PowerShell7 + 15 Smoke, E63–E66,
  user-assisted final acceptance **NOT_RUN**. Original upstream B-001 still
  **OPEN**.

[Final-content schema](issue-create-content.v1.schema.json),
[signed-approval schema](issue-create-approval.v1.schema.json),
[result schema](issue-create-grant-result.v1.schema.json),
[EC217 report](../EC-217.md) and
[synthetic tests](../construction/test_issue_create_grant.py).
