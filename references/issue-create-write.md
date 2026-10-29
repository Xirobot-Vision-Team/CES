# EC218 — application-idempotent GitHub/GitLab NEW Issue creation

**Construction package:** V5.28 / R218 / EC-218. Standalone Python API:
[`construction/issue_create_write.py`](../construction/issue_create_write.py).
The embedded PowerShell CLI remains **V4.60 / R150**; there is no new native
IssueCreate Action or unattended scheduling. EC219 provider-side unknown-result
reconciliation is **not** part of EC218.

## What can actually write

Unlike EC217 (which only recorded a host-side single-use reservation), EC218
contains an actual narrow HTTPS `POST` boundary for:

- `POST https://api.github.com/repos/{owner}/{repo}/issues`, and
- `POST https://gitlab.com/api/v4/projects/{numeric_project_id}/issues`.

No Issue `PATCH`, `PUT`, `DELETE`, comment, close, edit, assignment,
existing-label mutation or other provider write routes exist. Redirects,
proxies and automatic POST retries are disabled in the built-in HTTPS transport;
only GitHub and GitLab's official fixed API hosts are supported. Token data
is supplied by a host-held callback and never persisted or echoed. The API
sends the **exact** human-approved `title`, `body` and labels. GitLab private
project targets are additionally created as `confidential=true`; no other
post-approval prose or hidden idempotency footer is appended.

Reference: [GitHub official REST Issues](https://docs.github.com/en/rest/issues/issues)
(Requires repository **Issues: write** permission for fine-grained tokens),
[GitLab official Issues API](https://docs.gitlab.com/api/issues/)
(`POST /projects/:id/issues`, including `confidential`). These providers do
**not** promise that a caller-defined `Idempotency-Key` header makes their
IssueCreate endpoint deduplicate requests. **Do not** misrepresent such a
header as a transaction guarantee.

## Required trusted-host sequence

1. Finish the real EC214/215/216 local evidence workflow. Restore the **full
   original** `cg.PlanEvidence`, exact `cg.IssueCreateIntent`, human-approved
   final `cg.FinalIssueContent`, and independent signed
   `cg.HumanCreateApproval` from EC217. Do not accept a guessed result JSON as
   evidence or signer authority.
2. Verify the organization's independent signer key, role/revocation,
   privacy/visibility/policy, exact sensitive full text, citations, Finding/Git
   provenance, and repository-wide duplicate risk *outside CES*.
3. `cg.reserve_issue_create_grant(...)` must already have returned
   `RESERVED_ONE_ATTEMPT` after a real, durable, unique host-ledger insert.
   The EC218 API **does not accept that JSON result** as authorization; it
   independently re-runs EC216 → EC215 → EC214 and verifies the original
   Ed25519 receipt using the currently trusted host registry, then reads the
   exact EC217 grant ID/challenge/timestamp from a **trusted reservation
   reader**. Missing/mismatched/expired reservations fail closed.
4. The host independently issues a fresh `HostCreateAccess` for the precise
   provider/host/account, case-sensitive repository path/numeric ID,
   visibility, privacy-policy revision and audience, with all three opt-in
   booleans true and expiry no more than 120 seconds ahead. This is a
   trusted-host declaration, not an arbitrary serialized applicant field.
   Independently provision a provider credential supplier with creation
   permission and confirm that network/remote disclosure are authorized.
5. EC218 performs one bounded **repository GET** using that credential. It
   checks exact current numeric ID and path spelling, private/public
   visibility, Issue feature enabled and not archived. It then repeats the
   original human authorization/current issuer/revocation check and host
   access check before recording any attempt. A concurrent repository
   transfer/rename *after* this preflight is not atomically preventable by
   GitHub's path-based IssueCreate endpoint.
6. Before any POST, a **separate trusted durable attempt ledger** atomically
   inserts two UNIQUE keys: domain-separated operation SHA and consumed EC217
   grant SHA. Its operation key spans the exact target/account/audience,
   policy revision, plan/result and full final content SHA, **but does not
   include grant ID**. Thus a second signed grant for the same request also
   cannot produce a second POST. An expended ID cannot be repurposed for a
   different operation. `ALREADY_RECORDED` always blocks a new POST.
7. The built-in transport then attempts **a single POST**. Only exact HTTP
   201 plus repository/issue ID, original title/body/labels, provider path
   and privacy correspondence to the signed content, followed by successful
   durable outcome recording, yields `PROVIDER_REPORTED_CREATED`. The returned
   remote issue identity is a digest, not text or token. It remains a
   **provider claim**, not an independent second GET/remote delivery proof.
   Injected transports or clocks always produce `SIMULATED_RESPONSE_MATCHED`
   instead and **never assert an Issue was actually created**.

Example integration (host must supply independently authenticated objects and
review UI; placeholders deliberately cannot create a live Issue):

```python
from pathlib import Path
from construction import issue_create_grant as cg
from construction import issue_create_write as cw

# evidence, intent, final_content, approval, TRUSTED_EC215_KEYS,
# TRUSTED_CREATE_ISSUERS and host token provider all come from the real
# authorized host workflow; no issuer keys are obtained from Issue text.
# EC217's single-use reservation must already be committed in this DB.
reader = cw.SQLiteGrantReservationReader(
    Path(host_private_dir) / 'ec217-grants.db', intent.audience)
writer = cw.SQLiteCreateAttemptLedger(
    Path(host_private_dir) / 'ec218-create-attempts.db', intent.audience)
access = cw.HostCreateAccess(
    provider=intent.provider, api_host=intent.api_host,
    account_ref=intent.account_ref, repository=intent.repository,
    expected_repository_id=intent.expected_repository_id,
    visibility=intent.visibility,
    policy_revision_sha256=intent.policy_revision_sha256,
    audience=intent.audience,
    expires_at_utc=host_fresh_expiry_utc,
    network_opt_in=True, create_new_issue_opt_in=True,
    current_provider_credentials_attested_by_host=True,
)
result = cw.create_new_issue_once(
    evidence, intent, final_content, approval,
    trusted_eligibility_review_keys=TRUSTED_EC215_KEYS,
    trusted_issuers=TRUSTED_CREATE_ISSUERS,
    reserved_grants=reader, attempt_ledger=writer,
    host_access=access, token_supplier=host_secret_provider,
)
```

`host_private_dir` must already exist and be a trusted private owner-owned
`0700` directory outside any business repository. Two private `0600` SQLite
files must remain on **one trusted POSIX local disk**, stable across all
workers for the same audience. **Do not** use these convenience implementations
for NFS, cloud-shared filesystems, separate hosts, hostile same-user storage,
rollback-able snapshots or concurrently replaced DBs. A multi-host platform
MUST replace both with one shared, durable, transactional reservation reader
and attempt-ledger implementation that enforces the same uniqueness globally.
Both adapters have intentionally narrow `audience`-scoped interfaces and
store only digests, state and timestamps; not prose, secrets or repository
paths. They do not detect malicious inode replacement or arbitrary power-loss
filesystem guarantees.

A custom `clock` is supported **only when `transport` is also injected**;
it can never authorize live HTTPS network calls. Tests use synthetic issuer
keys, fabricated provider objects and a fake transport. Neither proves a
real authorized human or a real successful provider POST.

## Result / idempotency and unknown states

| `create_state` | Meaning |
|---|---|
| `BLOCKED` | Failed authorization/repo scope/replay. No newly dispatched POST from this invocation. |
| `INVALID_INPUT` | Malformed input/permission/timeout. No newly dispatched POST. |
| `UNKNOWN` | Preflight/evidence/store uncertain, or POST may have succeeded but result cannot be trusted. **Never retry the same operation.** |
| `REJECTED_UNVERIFIED` | Provider returned an explicit 400/401/403/404/410/422 response to POST. Still no automatic retry, and does not prove absence. |
| `SIMULATED_RESPONSE_MATCHED` | Synthetic test-only payload matched. `issue_created=false` always. |
| `PROVIDER_REPORTED_CREATED` | Strict official HTTP 201 response matched and durable receipt recorded. `issue_created=true` means **provider-reported**, not independently reread. |

All states are `partial/2`, `unavailable/5` or `invalid_input/4` as appropriate;
**no EC218 state claims complete native delivery (`ok/0`)**. No state proves
repository-wide duplicate absence, human approval authenticity beyond the
host-configured keys, valid real source/Git/CI facts or post-creation
continued visibility. A `POSSIBLY_SENT` barrier **must never be removed** merely
because the process crashed *before* calling POST or a timeout/5xx/invalid 201
occurred. An early local crash consumes the one-shot attempt; this intentional
liveness trade-off is safer than creating duplicate Issues.

EC219 will separately design host-authorized read-only remote reconciliation
for uncertain outcomes. EC218 provides no remote look-up/retry mechanism and
**no write on an existing Issue**. A genuine new Issue with materially changed
scope requires all original evidence and independent human permissions to be
freshly authorized; manipulating only a grant ID cannot evade the old barrier.

## Deferred assisted acceptance

Real organization issuer/role/secret/revocation, actual human inspection of
full private prose, GitHub/GitLab rate limits/private/hidden Issues, exact
credentials/scope, case/rename/transfer races, label errors and HTTP response
variations, unknown network results, true source/Finding/CI/privacy, cross-
host/NFS/Windows/macOS/Linux/crash/rollback, native PowerShell7/15 Smoke,
E63–E66 performance and all-task final acceptance remain **NOT_RUN**.
Original missing V3.10/ROUNDS evidence B-001 remains **OPEN**.
