# IssueShow (EC213) — one exact, read-only remote Issue observation

**Implemented:** standalone Python `construction/issue_show.py` with
`show_issue`, `IssueShowSelection`, `ShowFilters`, and `IssueShowGrant`.
This module composes **unchanged actual EC211 `issue_provider.read_issue`** and
**unchanged EC212 strict redacted `_projection`**. It intentionally does not
trust or accept an arbitrary client-provided IssueSync result as authenticated
fresh remote truth. The legacy PowerShell V4.60/R150 `IssueShow` command is
**NOT_IMPLEMENTED/NOT_REGISTERED**. IssueMatch, IssueCreate and provider Issue
edits remain out of scope.

## Core request / response

```python
show_issue(context, selection, *,
           show_grant=None, issue_read_grant=None,
           allow_network=False, token_supplier=None,
           transport=None, clock=None, timeout=8.0)
```

- `context` is an EC211 `ProviderContext(provider, api_host, account_ref)`;
  only public `api.github.com` and `gitlab.com` are allowed, with an explicit
  caller-declared opaque account context (not credential/custody proof).
- `selection` is `IssueShowSelection(repository, expected_repository_id,
  number, expected_provider_issue_id, filters=ShowFilters(),
  max_observation_age_seconds=120)`. Both **stable provider numeric IDs** are
  required, distinct from repository path and local Issue number/IID. The
  exact observed canonical repository path must equal the submitted path,
  including casing. Renames/case-only locator variation or a changed stable
  Issue ID return unavailable/unknown; no silent refollowing or rebinding.
- `ShowFilters(state='ANY', confidentiality='ANY',
  updated_not_before_utc=None, updated_before_utc=None)` restricts *one* Issue,
  not an Issue listing or discovery. State: `ANY | OPEN | CLOSED`; privacy:
  `ANY | NOT_REPORTED | STANDARD | CONFIDENTIAL`. Timestamp bounds apply to
  provider `updated_at` in UTC: `updated_not_before_utc` is inclusive and
  `updated_before_utc` is exclusive. When both exist, lower must precede
  upper. Strict canonical UTC input (`YYYY-MM-DDTHH:MM:SS[.fraction]Z`).
  `NOT_REPORTED` is an actual projection enum, **not proof of public access**.
- A separate **EC213 `IssueShowGrant(READ_ISSUE_SHOW)`** is required for the
  exact provider, API host, account context, path, numeric repository ID, local
  number, numeric Issue ID, every filter and maximum observation age; its
  expiry must be strictly future and no more than **300 seconds** from
  preflight, with `authorized=True`, `allow_write=False`. Independently the
  **EC211 `IssueReadGrant(READ_ISSUE_METADATA)`** must approve the same exact
  provider/context/path/number and be valid before and after the read.
  Neither an EC212 batch read grant nor one EC211 read grant alone permits
  IssueShow. The dataclasses are declarations supplied by the host and **do
  not cryptographically verify issuer, actual organizational permission,
  credential ownership or revocation**. Real host approver/key custody and
  auditing must be configured/validated outside this module.
- Callers must also explicitly set `allow_network=True` and provide one
  `token_supplier` callable; the library never accesses environment or
  automatically discovers a credential. It validates both grants **before
  supplier invocation** and revalidates them after the actual read and before
  returning selected data. If either expires, the already-read content is
  discarded; no partial private content is returned. The CLI can read only
  the provider-specific `CES_ISSUE_GITHUB_TOKEN` / `CES_ISSUE_GITLAB_TOKEN`
  environment slot if `--allow-network` is present. CLI approval flags create
  only *in-process declarations*, not trusted organizational approvals.
- Exactly one EC211 read is made, with a maximum of **three credentialed
  HTTPS GETs**: repository → Issue by exact local number or GitLab project
  numeric ID → repository recheck. EC211 enforces strict public TLS endpoint,
  no redirects, ambient proxy, retries or write HTTP verbs, **8-second per-
  GET timeout** and 1 MiB maximum JSON body. No search, pagination,
  repository inventory, comments retrieval, issue modification, Issue
  creation, Git or knowledge write, cache or persistence.

A valid match returns `status=partial`, `exit_code=2`,
`filter_outcome=MATCHED`, read state `SYNTHETIC_OBSERVED` or
`PROVIDER_OBSERVED`, and a **whitelisted redacted** `issue` object with
stable identity, selected state, timestamps, confidentiality and domain-
separated SHA-256 fingerprints. A genuine provider response would carry
`source_origin=provider_https_response`; an injected clock or fake transport
always labels the successful read `synthetic_fixture`, and this delivery
**makes no live provider claim**. The metadata is not atomic nor all of the
Issue's fields. Its SHA may reveal guessable private text equality and must
not be publicly distributed without a separate disclosure decision.

A valid but filter-excluded observation returns `status=partial`,
`filter_outcome=EXCLUDED_BY_FILTER`, `issue=null`, plus requested selection,
observation time, synthetic/provider provenance, and explicit coverage limits.
This means **the observed selected metadata failed this query's filter**; it
never means an Issue does not exist. A successful observation may become
stale immediately after it returns; the **age bound (1–120 seconds)** checks
only the time from EC211's observation timestamp to EC213's completion time.
A provider can concurrently edit/transplant/ABA an Issue undetected by these
non-atomic GETs. No result authenticates the remote host owner, full Issue
contents, comments, semantic duplicates or safe Issue creation eligibility.

When the service is unavailable, token/scope/permission is missing, remote
`401/403/404` is hidden or ambiguous, request/response identity drifts,
result fields are malformed, or a grant/observation is stale, `status=unavailable`
and `exit_code=5` return **`read_state=UNKNOWN`, `issue_existence=UNKNOWN`,
`filter_outcome=UNKNOWN`, `coverage=UNKNOWN`, `scope=null`, `issue=null`**.
Invalid input returns `invalid_input/4`, also UNKNOWN. Original provider error
bodies, transport exceptions, private title/body/labels/actors and tokens are
never included in the result. A missing account can fail *before* the offline
network check and still returns unknown/unavailable, not a false observation.
`maximum_possible_provider_gets` is 3 when the method was invoked (not a
claim that exactly three network responses completed) and zero otherwise.

The following flags are fixed: `metadata_projection_only=true`,
`full_issue_contents=false`, `snapshot_atomic=false`,
`organizational_grant_authenticated=false`, `caller_snapshot_trusted=false`,
`provider_account_ownership_authenticated=false`, and all
`issue_or_provider_written`, `business_repository_written`,
`knowledge_source_written`, `issue_created`, `issue_sync_performed`,
`persisted`, `external_cache_mutated`, `native_issue_action_registered`,
`issue_delivered_or_published` are false.

## Offline usage

From `ces/` (prints an unavailable JSON response; no credentials/network):

```bash
python construction/issue_show.py \
  --provider github --repository example/repo \
  --expected-repository-id 73142 --number 17 \
  --expected-issue-id 500421 --account-ref synthetic-account-slot --json
```

The programmatic interface for an isolated fake EC211 transport:

```python
from datetime import datetime, timedelta, timezone
from construction import issue_provider as ip, issue_show as sh

now = datetime(2026, 10, 24, 9, 0, tzinfo=timezone.utc)
expiry = (now + timedelta(seconds=120)).isoformat().replace('+00:00', 'Z')
ctx = ip.ProviderContext('github', 'api.github.com', 'synthetic-account-slot')
query = sh.IssueShowSelection('example/repo', 73142, 17, 500421,
                             sh.ShowFilters(state='OPEN'))
show_grant = sh.IssueShowGrant(sh.METHOD, ctx.provider, ctx.api_host,
    ctx.account_ref, query.repository, query.expected_repository_id,
    query.number, query.expected_provider_issue_id, query.filters,
    query.max_observation_age_seconds, expiry, True)
read_grant = ip.IssueReadGrant(ip.METHOD, ctx.provider, ctx.api_host,
    ctx.account_ref, query.repository, query.number, expiry, True)

# OFFLINE by default, even with declared grants: UNKNOWN, no token use or GET.
result = sh.show_issue(ctx, query, show_grant=show_grant,
                       issue_read_grant=read_grant)
assert result['status'] == 'unavailable'
assert result['issue_existence'] == 'UNKNOWN'
```

For a genuinely authorized live request, **first** procure the actual numeric
repository and provider Issue IDs through an independently authorized process,
confirm minimal token permissions plus real organizational approval and grant
issuer, and only then explicitly pass `allow_network=True`, the exact grants
and a secure explicit credential supplier. The public CLI also requires
`--authorize-show --authorize-provider-read --allow-network` together with
`--account-ref`; its flags alone cannot establish real authorization.

## Contracts and unfinished acceptance

- `references/issue-show-grant.v1.schema.json`: strict EC213 host-declared
  grant serialization, **not** a signed authorization or network proof.
- `references/issue-show-result.v1.schema.json`: strict output allowlist
  (matched, filtered-out, unknown, provenance/freshness and no-write flags).
- `construction/test_issue_show.py`: synthetic local tests exercising the
  actual EC211/EC212 code path and 404, grant expiry, mismatch, filtering,
  redaction and CLI offline behavior, **not live account tests**.

Deferred user-assisted final acceptance includes real provider/role/token
ownership and revocation, private inaccessible Issues, live issuer controls,
case-only rename behavior, provider time skew and ABA/race, remote resource
limits, Windows/macOS/Linux, native PowerShell7 and original 15 Smoke,
E63–E66 performance and whole-project end-to-end verification. Original
V3.10 frozen spec and `ROUNDS.json` B-001 upstream evidence remain OPEN.

**Next planned single EC: EC214 IssueMatch** (candidate duplicate discovery,
not definite duplicate assertion); not implemented in EC213.
