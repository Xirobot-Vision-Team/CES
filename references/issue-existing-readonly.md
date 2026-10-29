# EC-220: existing Issue strictly read-only API and shared HTTP route boundary

**Release:** V5.30 / R220 / EC-220. This is a standalone Python host integration
boundary, **not a registered native CES PowerShell Issue Action**. It does not
publish, change repositories, edit Issues, or create new Issues. Do not infer
final acceptance from synthetic method tests.

## Actual code interfaces

- `construction/issue_existing_readonly.py` provides
  `issue_http_route(method, url, profile=..., headers=...)`, the boolean
  `allow_issue_http(...)`, `HostExistingReadAccess` and
  `read_existing_issue(context, selection, *, access, token_supplier,
  transport=None, clock=None, timeout=8)`.
- HTTP profiles: `EC211_SELECTED` allows official project metadata + one
  selected Issue detail GET; `EC219_RECHECK` also allows only the pre-existing
  exact 3×50 sorted list-page URLs; `EC220_SELECTED` allows project metadata
  and one existing Issue detail GET; `EC218_NEW_CREATE` allows project metadata
  GET and **only** the **NEW** Issue *collection* POST. Route classification is
  **not** create authorization or a way around EC217's human Ed25519 review,
  EC218's fresh host permission, actual durable grant claim or UNIQUE attempt
  ledger. EC218's existing restriction and at-most-one POST are unchanged.
- The shared route guard is wired into the actual strict HTTP transports
  `issue_provider.StrictHTTPSIssueTransport`,
  `issue_create_write.StrictHTTPSIssueCreateTransport`, and
  `issue_unknown_recheck.StrictHTTPSIssueReadTransport`. A second route check
  occurs before the downstream callback transport call in EC211/218/219,
  so a helper cannot accidentally forward an unexpected path to an injected
  transport. EC212/213/214 depend on the EC211 provider read, and EC215–217
  are offline preparation/grant code, with no provider HTTP mutation route.
- The new EC220 full content read is a **separate** host-issued read capability:
  exact provider, official API host, account slot, **case-sensitive** project
  path, stable numeric repository ID, exact local Issue number, stable *global*
  Issue ID, PUBLIC/PRIVATE, 64-hex policy SHA, audience and ≤120s expiration.
  It requires independent authorization plus positive **metadata, full Issue
  content, network, current provider-credential host attestation**. PRIVATE
  repositories require an additional privacy consent; for **all GitLab Issue
  detail reads**, including public projects, the private/confidential opt-in
  must be present *before* reading the detail because a confidential body can
  be returned. A legacy EC211 read grant or consumed EC217/218 CREATE grant
  is not accepted as this capability. The host must provision the token via
  a callback; no token is taken implicitly from environment variables.
- Each of the three possible GETs rechecks the grant and route. Repository
  provider ID, exact path, privacy, and enabled Issues are read **before and
  after** the selected detail GET. GitHub `pull_request` objects from
  `/issues/{number}` are excluded; GitLab numeric `iid` is distinct from
  global `id` and must match the pinned local number, while `project_id`
  must match the pinned repository. State, confidentiality and UTC dates are
  parsed through the existing EC211 parser. All remote responses are bounded,
  expected JSON, HTTPS, no proxy, redirect or automatic retry by the strict
  transport, 8s/1MiB maximum per GET. Output consists only of provider state,
  privacy class, domain-separated identity/content digests and negative
  capability flags; never original title/body/labels, tokens or repository ID.

## Explicitly forbidden HTTP routes and escalation

No `PATCH`, `PUT`, `DELETE`, `HEAD`, HTTP method override, forwarding URL header,
query-based method override, GraphQL, GitHub `/pulls`, Issue comment/label/
assignee/state/lock/reaction endpoints, GitLab Issue notes/resource-label/
discussion endpoints, or any other nested existing-Issue route is permitted.
Read-only profiles also deny `POST` to the new-Issue collection. EC218's special
POST classifier denies **all** per-Issue POST paths including comments and
labels. Even a classifiable NEW collection POST still requires the original
strict separate EC218 authorization and persistent one-use barrier; the
EC220 **read adapter never issues POST**.

**Integration warning:** `StrictHTTPSIssueCreateTransport.post_create()` is a
low-level network primitive. Its URL allowlist does **not** check fresh human
consent, the EC217 signed grant, or the EC218 durable attempt ledger by itself.
A host must expose only `create_new_issue_once()` as the writable business
entrypoint; never pass raw transport methods to untrusted command dispatch.

The boundary does not assert that a caller-provided host grant is externally
signed or that the token's provider permissions have been independently
verified by CES; the trusted host is responsible for those attestations. The
injected clock and/or transport is intended for trusted local synthetic tests,
not as a production security boundary. Read results are **partial/2** observed
provider claims or **unavailable/5** / **invalid_input/4** on denial. Synthetic
observations are explicitly labeled and cannot authenticate a live Issue.
If there is 404, hidden/confidential content, scope drift, PR/IID mismatch,
private visibility change, timeout, duplicate or inaccessible information,
`issue_existence=UNKNOWN` and `absence_proven=false`: a selected GET never
proves *all other Issues* absent, duplicate absence or past EC218 causality.

## Development checks vs final acceptance

`construction/test_issue_existing_readonly.py` exercises the routed HTTP
surface, 201/create exception separation, mutation verb/URL/header traps,
repo/privacy/ID/PR/IID exactness, expired/replayed/scoped grant denial,
redaction, synthetic reads and 404 uncertainty. EC211, EC218, EC219 neighbor
local synthetic suites may also be run for development only. The result
object is constrained by
`references/issue-existing-readonly-result.v1.schema.json` (Draft 2020-12).
There is **no live provider token, real private/confidential Issue, real
organization-host signing, Windows/macOS/PowerShell native/15 Smoke/E63–E66,
NFS/multi-host/storage fault or final assisted user acceptance** in this
construction round. Preserve all as **NOT_RUN**; original upstream B-001 remains
**OPEN**.
