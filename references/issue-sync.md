# EC-212 — IssueSync: explicit-whitelist read-only snapshot (V5.22/R212)

**Implemented** standalone Python construction adapter: `construction/issue_sync.py`.
**Not implemented**: native PowerShell IssueSync route, IssueShow (EC213),
IssueMatch (EC214), IssueCreate, bulk repository Issue enumeration, remote
subscription or push/pull synchronization, persisted cache, published result,
knowledge source edit, repository changes or any provider write.

## Contract and boundary

`sync_issues(context, scope, *, sync_grant, issue_read_grants, baseline=(),
allow_network=False, token_supplier=None, transport=None, clock=None, timeout=8)`
composes the **actual EC211 `issue_provider.read_issue`** for every explicitly
selected Issue. It does not forge a provider result from caller-supplied hashes.

- `context`: EC211 `ProviderContext` with exact public `api.github.com` or
  `gitlab.com`, explicitly named opaque host account slot.
- `scope`: `IssueSyncScope(repository, expected_repository_id, numbers)` with
  **required stable numeric repository ID**, a valid provider path and a tuple of
  **1–8 unique strictly ascending** repo-local Issue numbers/IIDs. Never scans,
  discovers, paginates, filters or silently adds Issues. Exact endpoint
  selection is inherited from EC211; GitHub PR objects are excluded.
- Independent `IssueSyncGrant` with method `READ_ISSUE_SYNC_SNAPSHOT`, exact
  provider/host/account/path/numeric repository ID/all Issue numbers, `authorized=True`,
  `allow_write=False` and positive UTC expiry no more than **300 s** away.
  Exactly one **distinct EC211 `IssueReadGrant` per selected Issue** must be
  pre-provisioned in a dict keyed by the exact Issue number. The EC211 grant
  method remains `READ_ISSUE_METADATA`. Neither grant conveys the other.
  All batch and per-Issue grants are checked **before any token/GET, between
  reads and at completion**; expiry discards earlier in-memory observations.
- `allow_network=True` **and** a separately provided callable `token_supplier`
  are required before any provider GET. EC212 does **not** automatically load
  ambient credentials or look for historical account data. The CLI explicitly
  reads only the known per-provider `CES_ISSUE_GITHUB_TOKEN` /
  `CES_ISSUE_GITLAB_TOKEN` slot after a network opt-in; local `--authorize-*`
  flags are caller declarations, **not independent cryptographic role approval**.
  In process, the token supplier is invoked only once for a batch and the
  returned value is never printed, hashed into the result or cached.
  An injected token supplier or custom transport is arbitrary caller code;
  the adapter cannot attest to side effects inside callbacks it does not
  control. The no-write claim covers the shipped EC211 strict HTTPS transport
  and EC212 code, not arbitrary hostile injected callbacks.
- All provider operations are **GET only**, implemented by unchanged EC211:
  at most 3 GETs per Issue, 8 Issues and **24 possible GETs**, each limited to
  8 seconds and 1 MiB response; strict HTTPS/public host, no redirects or
  ambient proxy. There is no POST/PATCH/PUT/DELETE and no local file write.
  The batch is **not atomic**. The narrow `observed_at` timestamps are
  observation bookkeeping; remote concurrent modification, unobserved ABA,
  data outside the EC211 selected projection and network failures cannot be
  ruled out. Never interpret a provider `404` as definite absence.
- Stable numeric repo/Issue identities and exact repository locator are
  checked on each EC211 read. Results with inconsistent repository casing/
  locator between Issues, or one global Issue ID used for two selected
  numbers, **reject the entire batch**. Read failures within a consistent
  batch are recorded as `UNKNOWN`, not removed from the allowlist.
  Observations more than **120 seconds old at batch completion**, clock
  rollback and expired authority do not get promoted to current snapshots.
- Optional `baseline=(BaselineFingerprint(...), ...)` provides only
  **caller-submitted, untrusted comparison hints**, keyed to selected Issue
  number; a hash match means *same declared EC211 selected metadata
  projection*, never verified remote equivalence or organizational delivery.
  A hinted stable ID conflict quarantines that entry as `UNKNOWN` rather than
  auto merging or rebinding. Baseline hashes are untrusted and not signatures.
- On successful reads, the adapter **reprojects only a hardcoded safe subset**
  of EC211 fields. It never outputs provider title/body/description, raw
  labels, usernames, comment text, actors, credentials, errors or source
  payloads. It does expose equality-bearing digest and limited metadata;
  hashes may reveal information through equality and guessing, especially
  for private Issues. Treat the whole response as internal data and require
  separate permission for any release or persistence.

## Result semantics

All results have `schema=ces.issue_sync.v1`; exit codes: `2` for a bounded
in-memory observation of at least one selected Issue (`status=partial`),
`5` for `unavailable`, `4` for `invalid_input`. No result is a full provider
Issue inventory or an authenticated statement of remote truth.

- `COMPLETE_EXPLICIT_SELECTION_NONATOMIC` means every explicitly selected
  item was observed as selected metadata with no detected hint conflict
  or observation expiry; it does **not** mean remote Issue inventory,
  atomic snapshot, complete Issue fields or a provider-side sync.
- `PARTIAL_SELECTION_UNKNOWN` retains known selected readings but records
  every failed or conflicted number as `UNKNOWN`. Aggregate snapshot digest is
  **null** so it cannot be mistaken for a complete set.
- `UNKNOWN` is used when nothing is observed, input is refused or authority
  fails; when authority expires, scope/entries are removed entirely.
- `aggregate_snapshot_sha256` exists only for a complete explicit selection.
  It is a domain-separated digest over the exact selected issue number,
  stable IDs and **EC211 metadata projection** digests, not an attestation
  or raw provider JSON hash. It excludes ephemeral observation timestamps
  for reproducible comparison and is not meant for public export.
- `snapshot_collection_performed=true` denotes at least one accepted local
  in-memory read-only observation. Always:
  `snapshot_atomic=false`, `full_repository_inventory=false`,
  `selected_metadata_projection_only=true`, `persisted=false`,
  `external_cache_mutated=false`, `organizational_grant_authenticated=false`,
  `baseline_authenticated=false`, `native_issue_action_registered=false`,
  `issue_created=false`, `issue_delivered_or_published=false`,
  `issue_or_provider_written=false`,
  `business_repository_written=false`, `knowledge_source_written=false`.

**No persistent cache decision:** EC212 returns its in-memory JSON result to
the caller; it implements no store/read/write/backup. A later durable cache
requires a *new independently scoped* permission and storage design.
Do not infer a write capability from IssueSync's read grant.

## Synthetic API example (no network)

```python
from datetime import datetime, timedelta, timezone
from construction import issue_provider as ip, issue_sync as es

now = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
expiry = (now + timedelta(seconds=120)).isoformat().replace("+00:00", "Z")
context = ip.ProviderContext("github", "api.github.com", "local-approval-slot")
scope = es.IssueSyncScope("example/repo", 73142, (17, 18))
batch = es.IssueSyncGrant(es.METHOD, "github", "api.github.com",
    "local-approval-slot", "example/repo", 73142, (17, 18), expiry, True)
reads = {n: ip.IssueReadGrant(ip.METHOD, "github", "api.github.com",
    "local-approval-slot", "example/repo", n, expiry, True)
    for n in scope.numbers}

# Default OFFLINE, even with declarations: no credentials and no GETs.
result = es.sync_issues(context, scope, sync_grant=batch,
                        issue_read_grants=reads)
assert result["status"] == "unavailable"
```

From `ces/`, offline CLI (no grant/credentials and no provider call):

```bash
python construction/issue_sync.py --provider github --repository example/repo \
    --expected-repository-id 73142 --numbers 17,18 --json
```

To exercise a **user-authorized live read** in a controlled environment,
operators must separately secure minimal provider token rights, correct
account identity, issue scope and organization permission, then opt into
`--account-ref`, `--authorize-sync`, `--authorize-issue-reads`,
`--allow-network`. The CLI's in-process declarations do **not** certify
organizational authority, grant revocation, private access or publication.
For offline synthetic tests run `python -m unittest test_issue_sync` from
`ces/construction/`; they use the actual EC211 mapping with a fake GET
transport. All positive observations from a fake transport or injected
clock are labeled `SYNTHETIC_OBSERVED` and never claimed live.

## Schemas, source provenance and acceptance

- [`issue-sync-grant.v1.schema.json`](issue-sync-grant.v1.schema.json):
  strict host-declared EC212 batch grant serialization. Python additionally
  enforces exact scope, ordering, time-window and **separate EC211 grant**.
- [`issue-sync-result.v1.schema.json`](issue-sync-result.v1.schema.json):
  strict redacted in-memory result, `UNKNOWN`/partial coverage and immutable
  no-write flags.
- Test sources: [`../construction/test_issue_sync.py`](../construction/test_issue_sync.py);
  fixtures reused from [`../construction/fixtures/provider_issues/`](../construction/fixtures/provider_issues/).
- This module is **standalone Python only**, and the legacy PowerShell CLI
  remains **V4.60/R150**. `EC211` unchanged; its host-declared grant does not
  establish independent real organization authorization.
- Final acceptance **NOT_RUN**: genuine account scopes, provider read/hidden
  data/rename/rate limit/ABA, signed host role/issuer/revocation/replay,
  multi-OS/NFS, PowerShell 7 + original 15 Smoke, E63–E66 performance and
  external operator sign-off. B-001 original V3.10 freeze remains OPEN.

Next planned single EC: **EC-213 IssueShow**, not built here.
