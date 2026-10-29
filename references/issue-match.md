# EC214 — read-only IssueMatch duplicate-candidate **hints**

**Construction release:** `V5.24/R214/EC-214`, standalone `construction/issue_match.py`.
**Native PowerShell IssueMatch:** `NOT_IMPLEMENTED` (native CLI remains V4.60/R150).
**Provider/org/live acceptance:** `NOT_RUN`. There is no Issue creation, edits,
search, repository-wide inventory, cache, sync, AI egress or publication.

## Capability

`match_issues(context, request, ...)` reads **only 1–8 explicitly selected,
ascending Issue numbers** in a **single** pinned GH/GL repository. Each
`MatchCandidate(number, expected_provider_issue_id, anchors)` requires the
repo-local number and distinct stable global numeric provider Issue ID; the
request also pins the stable numeric repository ID and exact case-sensitive
repository locator. No listing, search, branch speculation or inferred
selection. Each candidate uses the **actual EC211 `read_issue`** three-GET
repo/Issue/repo reader (at most **24 bounded GETs for 8**); successful metadata
is revalidated by **EC212 `_projection`**, then checked for pinned IDs,
observation time, provenance and grant expiry. An injected clock/transport
marks EC214 output `synthetic`. With built-in GH/GL HTTPS, the EC214 delegate
still uses EC211's original GET-only, no redirects/proxies, TLS, 8s/1MiB-per-
GET boundary. Because EC214 supplies a transport wrapper to reuse EC211 while
optionally retaining the title in memory, **EC211 internally conservatively
marks those delegated reads as synthetic**; EC214 explicitly records origin
`FIXED_PROVIDER_HTTPS_VIA_EC211` only when it itself built the strict HTTPS
transport and no test clock was supplied. Do not reclassify *injected* reads.

Comparison signals are **caller-asserted exact evidence anchor equality**
(commit SHA-1/SHA-256 + repository-relative path + line range + evidence SHA256)
and independently permitted **title lexical overlap**. Anchors are not read
from Issue descriptions and are **NOT remotely authenticated or checked against
an immutable Git tree**. Exact anchor equality can be a useful review hint
but it does **not** prove that either Issue links to that code. The title
heuristic is bounded Unicode NFKC/casefold plus CJK adjacent character pairs,
Latin word/character n-grams, and weighted token overlap. It is **not** an
embedding model, semantic equivalence test or duplicate determination. No
raw issue title, body, labels, comments, reporter, path or anchor is emitted;
output includes only anchor-match count, a coarse similarity **band**,
selected redacted metadata hashes and exact Issue numeric identifiers.
A similarity band can itself leak limited information and must be reviewed
under the organization's disclosure policy.

Results: `partial/2` when at least one pinned Issue produced qualified
selected metadata; selected coverage is `COMPLETE_EXPLICIT_SELECTION_NONATOMIC`
**only for the 1–8 requested Issue IDs**. Missing/hidden/private/404/renamed,
wrong ID/path, stale or malformed Issue stays `UNKNOWN`, not absent.
`unavailable/5` when none qualified or overall grants/token/availability fail;
`invalid_input/4` for malformed scope/title/anchors. The per-issue hint can
be `REVIEW_CANDIDATE` or `NO_POSITIVE_SIGNAL`; neither is an equality/absence
finding. All results hardcode `potential_duplicate_confirmed=false` and
`no_duplicate_confirmed=false`. `review_candidate_count` counts observed
hints only, never newly discovered/verified duplicates. No issue writing.

## Independent permission layers (all needed **before** credential access)

1. **EC214 `IssueMatchGrant`** — `COMPARE_SELECTED_ISSUE_CANDIDATES` binds
   provider, exact fixed public host, account slot, exact repository+numeric
   ID, exact sorted `(local number, global Issue ID)` allowlist and full
   `request_fingerprint()`. Includes anchors, query-title bytes, title policy,
   privacy policy, and freshness in the request fingerprint. Host declaration
   expires in at most **300s**; not an issuer signature or user authentication.
2. **EC211 `IssueReadGrant` for *each* selected Issue** — separate method
   `READ_ISSUE_METADATA`, with exact repository/local number plus EC211
   resource scope preflight, checked before and after reads. Never reuse a
   batch/Show grant as a per-Issue read grant.
3. **EC214 `IssueTitleGrant`** — separately mandatory **only** when
   `title_policy='AUTHORIZED'`, with `COMPARE_SELECTED_ISSUE_TITLES_IN_MEMORY`,
   the same request fingerprint and exact candidate pins plus explicitly
   declared `allowed_privacies`, expiring in ≤300s. When disabled, an optional
   subject title is **not** silently processed; the request must omit it.
   `STANDARD` (GitLab public/nonconfidential) is the only default. GitHub
   reports `NOT_REPORTED` even for publicly readable Issues; its titles are
   **withheld** unless `NOT_REPORTED` is explicitly in both the validated
   request and independent title grant. GitLab `CONFIDENTIAL` requires an
   explicit `CONFIDENTIAL` entry in both; otherwise the title receives no
   comparison. Descriptions are **never** inspected for matching or exposed.

Grant dataclasses are **caller-host assertions**, not independently validated
signatures, organizational roles/issuer authority, revoked permissions, or
proof of account ownership. Production integration must supply that trust
boundary separately. A custom `transport` is an untrusted Python callback
and cannot be independently attested for side effects; the built-in transport
is the GET-only one. Default API is **offline** (`allow_network=False`);
there is **no implicit token fallback**. Supply a real explicit token source
only after authorization/opt-in. Credentials are requested once for the batch.
No source content is returned after expiry, forward/rollback freshness drift
or grant-scope loss, even if earlier reads succeeded. Observations are not
provider-atomic; races/ABA/current-state changes can still occur.

## Python usage — explicit exact hints (example has **no credentials**)

```python
from datetime import datetime, timedelta, timezone
from construction import issue_match as im, issue_provider as ip

ctx = ip.ProviderContext('github', 'api.github.com', 'host-owned-account-slot')
a = im.EvidenceAnchor('a' * 40, 'src/main.py', 10, 12, 'b' * 64)
req = im.IssueMatchRequest(
    repository='example/repo', expected_repository_id=73142,
    candidates=(im.MatchCandidate(17, 500421, (a,)),),
    subject_anchors=(a,),  # caller assertion, not authenticated Issue evidence
    title_policy='DISABLED')
fingerprint = im.request_fingerprint(ctx, req)
expires = (datetime.now(timezone.utc) + timedelta(seconds=90)).isoformat().replace('+00:00', 'Z')
mg = im.IssueMatchGrant(im.METHOD, ctx.provider, ctx.api_host,
    ctx.account_ref, req.repository, req.expected_repository_id,
    ((17, 500421),), fingerprint, expires, True)
rg = {17: ip.IssueReadGrant(ip.METHOD, ctx.provider, ctx.api_host,
    ctx.account_ref, req.repository, 17, expires, True)}
# Offline safety default: no provider GET and UNKNOWN, not fabricated candidates.
result = im.match_issues(ctx, req, match_grant=mg, issue_read_grants=rg)
assert result['status'] == 'unavailable'
# For authorized live use, explicitly supply allow_network=True and
# token_supplier=<trusted-host-provider-credential-function> (no demo secret).
# To match titles, additionally set authorized title policy and supply the
# independent, exactly matching IssueTitleGrant before any remote read.
```

CLI runs with `python construction/issue_match.py --provider github
--repository example/repo --expected-repository-id 73142 --candidate 17:500421`.
Without three explicit read/network flags it returns offline/unknown JSON.
A limited title comparison CLI mode uses `--authorize-title` and reads the
subject title from **stdin** (not argv), then permits separately opted-in
`--allow-unclassified-title` / `--allow-confidential-title`. These flags merely
create local host declarations for development; **they are not organizational
permission issuance**. For candidate anchors use the Python API. Never pipe
provider token or private Issue title into a visible command argument.

## Artifacts and verification boundary

- Implementation: `construction/issue_match.py`
- Local synthetic suite: `construction/test_issue_match.py`; fixture contract
  `construction/fixtures/ec214/README.md`, extends EC211 fake GET-only data.
- Strict Draft2020-12 definitions:
  `references/issue-match-request.v1.schema.json`,
  `references/issue-match-grant.v1.schema.json`,
  `references/issue-match-result.v1.schema.json`.
- Full construction report: `EC-214.md`.

Local fixture verification establishes *program behavior with synthetic data*,
not real token/provider access, independent grant issuance/revocation, native
PowerShell CLI acceptance, OS portability or real git/evidence anchoring.
Those validations are deferred to final assisted acceptance.
