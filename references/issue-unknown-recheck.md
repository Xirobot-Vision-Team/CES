# EC219 — Issue UNKNOWN result bounded read reconciliation (standalone Python)

## Scope and trust boundary

`construction/issue_unknown_recheck.py` implements **only remote read-only
reconciliation** of a previously durably recorded EC218 `POSSIBLY_SENT` or
`POST_UNKNOWN` attempt. It is **not** a PowerShell Action and cannot create,
retry, edit, close, assign, relabel, comment on or otherwise mutate an Issue.
The caller must NOT delete, reset or reissue the EC218 operation barrier based
on the result. An EC218 recorded `PROVIDER_REPORTED_CREATED`, `POST_REJECTED`
or `SYNTHETIC_RESPONSE` is out of this specific UNKNOWN recheck scope.

GitHub/GitLab APIs cannot guarantee that a finite issue list includes hidden,
private, deleted, transferred or concurrently changing Issues. A real unique
Issue with identical title, body, labels, time and repository might have been
created by somebody else: **`REMOTE_EXACT_CANDIDATE_OBSERVED` is not proof of
causation by EC218**, and not proof of repository-wide duplicate absence. No
remote-match state authorizes a second POST. `UNKNOWN` means no positive safe
conclusion, **not** that the original POST failed or nothing was created.

## Required independent inputs

1. Restore the **full original** `cg.PlanEvidence`, `cg.IssueCreateIntent`,
   `cg.FinalIssueContent` and signed `cg.HumanCreateApproval` used in EC218.
   Original private content remains in trusted host memory; it is never emitted
   in the result. Obtain the host's **historical original trusted issuer and
   EC215 reviewer keys**. Never treat a key supplied in Issue content as a
   valid organization issuer or rely on a fabricated local receipt JSON.
2. Use the trusted **actual EC218 attempt DB** through
   `SQLiteCreateAttemptReader`, *read-only*, with the original audience and
   grant ID. The reader requires the exact operation SHA and hashed grant ID;
   it cannot create a missing database or accept a caller-reported state.
   The original `started_at_utc` from that record is used strictly to replay
   original EC214/215/216/217 historical cryptographic authorization and bind
   the actual challenge SHA. It is **not** a replacement current clock and
   **not** a fresh creation or private-read permission.
3. Separately authorize a **new** `HostRecheckAccess` from the host: exact
   provider, official API hostname, account slot, case-sensitive repo path,
   stable numeric repository ID, target visibility, policy revision and
   audience. Host must actively attest network opt-in, metadata read opt-in,
   **entire Issue title/body/labels/private content** read opt-in, current
   provider token access and visibility of confidential/private Issues. The
   short deadline must be within 120 seconds. Recheck this grant at **every**
   GET and before finalizing. Do not reuse the EC217 CREATE approval as a READ
   grant. The host must independently enforce account authorization, issuer
   history and secure policy/credential storage.
4. Supply the credential via a host-owned callback, never in request JSON or
   the returned record. A token is not read implicitly from environment.
   Supply a trusted audience-scoped **distinct** `SQLiteRecheckLedger` for a
   local-only append of real, unambiguous positive remote evidence. It must
   reside in an independently managed owner-only 0700 local POSIX directory,
   with a 0600 DB, stable for all workers, outside business repositories.
   The EC218 attempt ledger is not altered by EC219. On multi-host setups use
   genuinely transactional, durable, consistent shared host adapters instead;
   local SQLite is not adequate for NFS, untrusted storage or independent
   worker volumes. Missing/unavailable stores fail closed.

## Live read algorithm

- Re-evaluate EC217's actual historical `_inspect` using only the immutable
  EC218 attempt timestamp for verifying **past** authorization and the
  original full content. Check the original challenge, grant key and operation
  SHA from the trusted EC218 ledger. Do not re-reserve or re-POST.
- Read the selected repository metadata over HTTPS from **official**
  `api.github.com` or `gitlab.com` and require the approved **stable ID, exact
  path, current PRIVATE/PUBLIC visibility and readable Issues feature**. An
  archived repo may have readable Issues; archive status alone is not proof
  that they disappeared. A private 404, redirect or rename is UNKNOWN.
- Read at most **three pages × 50 entries** of repository Issues ordered by
  creation time descending, with `state=all` (GitHub also includes PRs, which
  are excluded). Candidate discovery is by exact approved title; possible
  matches require a provider issue ID, local number, correct repo identity
  and creation time between attempt start **minus two seconds** for timestamp
  precision and start **plus 120 seconds**. Too many plausible candidates,
  malformed entries or matching titles outside the window keep UNKNOWN.
- For at most **eight candidates**, GET each Issue **individually** and
  require matching provider/global and local IDs, repository identity,
  GitLab confidential flag, creation time, exact human-approved title,
  **entire body/description and sorted labels**. A same-title body/source or
  label mismatch is UNKNOWN. Closing/editing the candidate since creation
  cannot be inferred from this comparison. GET the repository again after
  reads; any ID/path/visibility drift becomes UNKNOWN.
- Maximum **13 GETs** per invocation, each bounded to 8s and 1 MiB JSON;
  strict official-host GET allowlist, TLS verification, no redirects, proxies,
  automatic retries or provider writes. Pagination, token visibility, rate
  limiting, dynamic contents and creation timestamps are not atomic snapshots.
  Never interpret no candidate or a 404 as negative proof.
- If and only if exactly one **real provider** candidate survives **all**
  checks and a distinct durable host ledger records its digests, return
  `REMOTE_EXACT_CANDIDATE_OBSERVED`. The persisted evidence includes only
  operation/grant/Issue identity and observation digests/timestamp, **never
  title, body, labels, account, repo path or token**. Conflicting observations
  are not overwritten; they return UNKNOWN. A synthetic injected transport
  or clock returns `SIMULATED_EXACT_CANDIDATE` without persisting or claiming
  a real candidate. Custom clocks can never drive real HTTPS here.

Implementation-only integration sketch (unconfigured placeholders cannot make
live requests):

```python
from pathlib import Path
from construction import issue_unknown_recheck as rc

# evidence, intent, content, old_approval, old_keys, old_review_keys,
# host_private_dir, host_token_supplier, host_read_deadline all come from
# independently authenticated original + current host workflows.
reader = rc.SQLiteCreateAttemptReader(
    Path(host_private_dir) / 'ec218-attempts.db', intent.audience)
ledger = rc.SQLiteRecheckLedger(
    Path(host_private_dir) / 'ec219-read-observations.db', intent.audience)
access = rc.HostRecheckAccess(
    provider=intent.provider, api_host=intent.api_host,
    account_ref=intent.account_ref, repository=intent.repository,
    expected_repository_id=intent.expected_repository_id,
    visibility=intent.visibility,
    policy_revision_sha256=intent.policy_revision_sha256,
    audience=intent.audience, expires_at_utc=host_read_deadline,
    network_opt_in=True, read_issue_metadata_opt_in=True,
    read_full_issue_content_opt_in=True,
    current_provider_credentials_attested_by_host=True,
    private_content_visibility_attested_by_host=True)
result = rc.recheck_unknown_issue(
    evidence, intent, content, old_approval,
    trusted_eligibility_review_keys=old_review_keys,
    trusted_historical_issuers=old_keys,
    original_attempts=reader, observation_ledger=ledger,
    host_access=access, token_supplier=host_token_supplier)
```

All trust-root references and access permissions above are assertions the
trusted host must genuinely prove, not self-assertions CES can validate from
untrusted caller JSON. Don't turn on full-text GET for real private projects
without lawful need and organizational permission.

## Results and limitations

| `recheck_state` | Meaning and safe action |
|---|---|
| `BLOCKED` | Original attempt not eligible, wrong/lacking fresh permission or malformed grant. No provider data read unless previously attempted earlier in the same invocation. |
| `INVALID_INPUT` | Invalid bounds or input shape. No permission to retry. |
| `UNKNOWN` | No unique candidate in finite pages, possible duplicate/false positive/source mismatch, hidden item, network error, drift or persistence problem. **Cannot infer absence or retry safely**. |
| `SIMULATED_EXACT_CANDIDATE` | Synthetic full-text candidate matched; **not provider evidence**, no durable positive ledger. |
| `REMOTE_EXACT_CANDIDATE_OBSERVED` | New official provider GETs show one exact candidate in the limited observation and an append-only local receipt was committed. **Creation by EC218 not proven**, no write authorized. |

Only `partial/2`, `unavailable/5`, `invalid_input/4` are emitted; no
`success/0`, delivery, native handler or provider-write result. See the
[strict result schema](issue-unknown-recheck-result.v1.schema.json),
[EC219 code](../construction/issue_unknown_recheck.py),
[synthetic tests](../construction/test_issue_unknown_recheck.py) and
[EC219 report](../EC-219.md).

Provider primary API documentation: [GitHub repository Issues list/detail](https://docs.github.com/en/rest/issues/issues),
[GitLab project Issues list/detail](https://docs.gitlab.com/api/issues/).
These describe endpoint and query behavior; neither documents a full hidden-
Issue inventory or safe automatic replay of a preceding create POST.

## Deferred assisted final acceptance — NOT_RUN

Real trusted organizational issuer/reviewer history, original true
source/Finding/Git/CI and privacy approvals, private Issue/hidden visibility
and token scope, GitHub pull-request mixed lists, GitLab confidential Issues,
actual provider pagination/404/401/rate limits, rename/transfer/concurrent
edit races, accurate clock skew and retry-window assumptions, network crashes,
local/multi-host SQLite durability, Windows/macOS/Linux/NFS/hostile storage,
PowerShell7/original 15 Smoke/E63–E66/end-to-end remain NOT_RUN.
The original missing V3.10/ROUNDS baseline B-001 is OPEN. No actual remote
GET or credential was used in package development. Final user-assisted
validation remains deferred until the project is functionally complete.
