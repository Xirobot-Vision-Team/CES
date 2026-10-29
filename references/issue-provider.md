# EC-211 — Issue read-only provider boundary (standalone Python)

Release **V5.21 / R211 / EC-211**. Code: [`construction/issue_provider.py`](../construction/issue_provider.py); contracts: [`issue-provider-grant.v1.schema.json`](issue-provider-grant.v1.schema.json) and [`issue-provider-result.v1.schema.json`](issue-provider-result.v1.schema.json). This is **not** PowerShell `IssueSync`, `IssueShow`, `IssueMatch` or `IssueCreate`. Native CLI is still **V4.60/R150**, and all four native Issue actions are **NOT_IMPLEMENTED**.

## Exactly one read scope

`read_issue(context, selection, *, grant=None, allow_network=False, token_supplier=None, transport=None, clock=None, timeout=8)` has three independent inputs:

1. `ProviderContext(provider, api_host, account_ref)`: explicit public provider/account context, *not* a credential or authenticated organizational identity. This EC allows only `github` / `api.github.com` and `gitlab` / `gitlab.com`. No enterprise domains, arbitrary API URLs, redirects or implicit proxy. Missing account slot => `unavailable`.
2. `IssueSelection(repository, number, expected_repository_id=None)`: strict owner/repo or group/subgroup/project pathname; **number is repository-local** GitHub Issue number or GitLab IID. The optional numeric provider repository/project ID is an equality pin, not an authorization grant. No URL, path traversal, arbitrary Issue listing or automatic pagination.
3. `IssueReadGrant(method='READ_ISSUE_METADATA', provider, api_host, account_ref, repository, number, expires_at_utc, authorized=True, allow_write=False)`: independently supplied exact-scope, short-lived **host-declared** read admission; `allow_network=True` is also required. Admission is checked **before** touching credentials and again **after** retrieval; deadline must be in `(now, now+600 seconds]`. The grant is **not cryptographically signed, not proof of a real human/role, not bound to external issuer/revocation and not centrally replay-protected**. A caller can fabricate an instance; the host/operator must provide and enforce real authorization outside this adapter. Credentials come separately from `CES_ISSUE_GITHUB_TOKEN` or `CES_ISSUE_GITLAB_TOKEN`, or a callable from an already authorized host. The adapter never prints token bytes.

A single invocation makes at most **three serial HTTPS GETs**, no retries or writes: (a) repository identity by the selected path, (b) one Issue metadata object, (c) repository identity by the same selected path. GitLab fetches Issue via **numeric project ID** returned by (a). GitHub GET `/issues/<number>` is also used for PRs, so any `pull_request` marker is an explicit refusal. The first and last repository id/path must agree; GitHub Issue `repository_url` or GitLab Issue `project_id` and optional full reference must bind to the observed repository and exact Issue number. This mitigates ordinary rename/transfer races but **does not provide an atomic remote snapshot or rule out ABA**, and it cannot prove a detached Issue truly belongs to a repo by independent cryptographic means.

Transport security: TLS certificate validation, HTTPS and fixed host/path allowlist, `GET` only, no redirects, proxies, cookies, pagination, compressed bodies, retry or secondary endpoint; bounded **1 MiB per response**, **8 seconds per GET** (up to 24 seconds of network waits) and duplicate-key/nonfinite JSON rejection. `401/403` and `404` are `unavailable`, **not** proof of Issue absence; 404 may hide a private object. Failed attempts return sanitized fixed reason codes; neither raw provider error nor credential/Issue content is returned. The chosen `account_ref` is not included in the result.

## Observed identity and snapshot semantics

A valid metadata observation returns `status='partial'`, `exit_code=2`, *never* success/0 or evidence of creation. Result identity contains `provider`, public API host, provider-canonical repository path, numeric provider repository ID, local Issue number and numeric provider Issue object ID. `identity_sha256` hashes **only provider/host/numeric repo ID/numeric Issue ID**, remaining stable across path rename while those IDs stay constant. It is a deterministic identity label, not a provider signed receipt or external identity authentication.

`snapshot_sha256` is SHA-256 over domain-separated, canonical JSON of the observed identity **including mutable path and Issue number**, plus selected provider fields: state, create/update/close instants, locked/confidential state, reason, title, description/body and normalized label names. **Raw title, description/body, labels, comment content and actor records are never output.** The SHA is **not the raw provider JSON hash**, not full-Issue coverage, not an atomic snapshot, and **not a secrecy boundary**: equality and offline-guessing attacks may reveal information about low-entropy private content. Treat snapshot digests as sensitivity-bearing CES-internal metadata; don't expose them publicly without a separate data-release review. Fields not selected (comments, attachments, assignees, reactions, project boards, etc.) may change without modifying the SHA. Title/body/label sizes and counts are bounded; invalid/missing essential fields lead to `unavailable` instead of fabricated placeholders.

`read_state` is `PROVIDER_OBSERVED` only for an actual accepted HTTPS transport read without testing injections, `SYNTHETIC_OBSERVED` when an injected transport/clock is supplied, otherwise `UNKNOWN`. `issue_existence` separates `PROVIDER_REPORTED_PRESENT`, `SYNTHETIC_FIXTURE_PRESENT`, and `UNKNOWN`. Origin is also present in the source. None is external delivery attestation; `issue_delivered_or_published=false`, `issue_sync_performed=false`, `issue_created=false`, `issue_or_provider_written=false`, `organizational_grant_authenticated=false`, `native_issue_action_registered=false` in every case.

## CLI usage and safe offline behavior

From `ces/`:

```bash
# Offline: returns unavailable/5 with null source. Does NOT read credentials.
python construction/issue_provider.py --provider github \
  --repository example/repo --number 17 --json

# Allowed only when your own host/operator has independently approved the
# exact account, repository and Issue read and placed a read-only token in
# CES_ISSUE_GITHUB_TOKEN outside this command/shell history:
python construction/issue_provider.py --provider github --host api.github.com \
  --account-ref approved-local-slot --repository org/project --number 17 \
  --expected-repository-id 73142 --authorize-read --allow-network --json

# GitLab uses --provider gitlab --host gitlab.com --repository group/project,
# CES_ISSUE_GITLAB_TOKEN and GitLab's repo-local IID for --number.
```

`--authorize-read` constructs a local, short-lived **operator-declared grant**, not an audited signed approval. A process with the correct token and command-line controls remains responsible for its permissions; this adapter doesn't discover accounts or bypass provider access control. The CLI only outputs sanitized JSON and exits 2/4/5. To exercise the explicit pure-Python API in unit tests, inject a fake `ReadTransport`; every such result is unmistakably `synthetic`, regardless of fixture shape.

## Reason codes and later construction

Refusals are fixed `ISSUE_*` codes; examples: `ISSUE_ACCOUNT_CONTEXT_UNAVAILABLE`, `ISSUE_NETWORK_NOT_AUTHORIZED`, `ISSUE_READ_GRANT_REQUIRED`, `ISSUE_READ_GRANT_SCOPE_MISMATCH`, `ISSUE_CREDENTIALS_UNAVAILABLE`, `ISSUE_ISSUE_UNKNOWN_OR_INACCESSIBLE`, `ISSUE_REPOSITORY_ID_MISMATCH`, `ISSUE_REPOSITORY_CHANGED_DURING_READ`, `ISSUE_GITHUB_PULL_REQUEST_NOT_ISSUE`, `ISSUE_PROVIDER_METADATA_INCOMPLETE`, `ISSUE_PROVIDER_READ_FAILED`. A positive local synthetic result is **not a real online test**. EC-212 is reserved for independently scoped IssueSync read-only snapshot operations; EC-213 IssueShow, EC-214 matching and later creation require separate ECs and permissions. No issue sync/cache/store, change/write/POST/PATCH/DELETE, CodeSave coupling, knowledge promotion, `DocsOnlyPublish`, provider publication, or native Issue route is implemented here.

**Final user-assisted acceptance still `NOT_RUN`:** real org token scopes and revocation, authorized GitHub/GitLab private/public Issue reads, 401/403/404/rate-limit behavior, project transfers and concurrent changes/ABA, enterprise domain requirements (not supported), proxy/security policy, token logs, genuine publisher or issue-creation controls, PowerShell7 plus 15 original Smoke, Windows/macOS/NFS, E63-E66 resources and full end-to-end signoff. B-001 frozen original V3.10/ROUNDS provenance still OPEN.
