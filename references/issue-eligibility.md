# EC215 — Issue creation **eligibility** (offline local draft only)

**Release:** `V5.25/R215/EC-215`. Standalone
[`construction/issue_eligibility.py`](../construction/issue_eligibility.py).
**Native IssueEligibility/IssueCreate/IssuePlan:** `NOT_IMPLEMENTED`; original
PowerShell CLI stays V4.60/R150. This EC contains **no provider operations,
Issue POST/PATCH, Issue edits, Git/Knowledge writes, remote publication, AI,
Issue title/body generation, or local persistence.**

## 1. Real EC214 integration and risk boundary

Use `evaluate_issue_eligibility(context, request, match_request, match_result,
review_receipt=None, trusted_review_keys=None, clock=None)`. `match_request`
is an original EC214 `IssueMatchRequest` with 1–8 exact, sorted Issue IDs,
repository case/path, pinned numeric repository/global Issue IDs and policy.
`match_result` is a serialized **caller-supplied** EC214 result; this module
**does not call any provider** or authenticate the original snapshot.

EC215 calls the **actual unchanged EC214 `request_fingerprint()`** and verifies
its exact request inputs, plus checks an EC214 result using a fail-closed
allowlist. The result must have the correct full scope, each selected local and
global Issue pin, matching positive/unknown counters and EC214 false truth/
side-effect flags. It recomputes anchor-match counts directly from the
original `subject_anchors` and each candidate's declared anchor set, rather
than trusting a claimed zero. Observation ages are bounded to **120 s**,
while source declarations default to **24 h** freshness. Missing/hidden/404,
renamed/identity drift, conflicting counts, old observations or incomplete
Issue selection => `UNKNOWN`; a synthetic receipt => `NEEDS_REVIEW`.

Even with all selected Issues observed and **no positive candidate hint**,
coverage means *only the explicitly selected 1–8 Issues*, **never a complete
repository inventory, independently authenticated Issue provenance, or proof
of no duplicate**. A positive anchor or high/some lexical similarity is only
`CANDIDATE_NEEDS_REVIEW`, never verified duplicate; title withheld/unavailable
also requires review. CJK/Latin title comparison remains EC214's independent
privacy-gated operation and EC215 **never reads a raw title**.

`FindingBasis` refers to an original Finding/HMAC record and source by hashes,
source mode, full alleged revision, positive/counter-evidence counts, manual
review assessment and bounded selected-source counts. It only consumes
**caller declarations**; it does **not** independently open EC177/178 private
stores, authenticate reviewer identity or re-hash EC203 Git objects. The
`evidence_anchor_set_sha256` must equal `anchor_set_sha256(match_request.subject_anchors)`;
each subject anchor's declared commit must match the Finding's revision.
For positive eligibility, require `DeliveredTarget`, declared manual `REVIEWED`,
positive evidence, **zero** counter-evidence and complete explicitly selected
source coverage; WorkingTree and ProposedPR are **not** silently promoted to
delivered facts. CI/test PASS is never inferred or invented.

## 2. Four eligibility states versus authorization

| `eligibility` | Interpretation | `status/exit_code` |
|---|---|---|
| `ELIGIBLE_TO_PROPOSE` | Exact reviewed evidence+privacy+selected EC214 no-positive-hint receipt, fresh bounded inputs and independently configured key *cryptographically verified* short signed review; may **consider a redacted local EC216 draft**, not create/publish | `partial/2` |
| `NEEDS_REVIEW` | Missing independent review signature; synthetic receipt, positive Issue candidate hint, privacy/title withheld, counter-evidence, incomplete selected source, historical PR/WorkingTree or unreviewed Finding | `partial/2` |
| `BLOCKED` | Finding explicitly REJECTED, privacy DENY/RESTRICTED, or INTERNAL/CONFIDENTIAL classified data aimed at PUBLIC repository | `partial/2` |
| `UNKNOWN` | Missing/old/mismatched/partial EC214 selected Issue evidence; missing/unknown/stale source evidence, unknown privacy/visibility | `unavailable/5` |

Malformed mandatory scopes, invalid SHA/anchor binding, contradictions and
unsafe type/size are `INVALID_INPUT / invalid_input/4`.

**Every single response**, including `ELIGIBLE_TO_PROPOSE`, returns
`authorization="NOT_GRANTED"`, `issue_create_authorized=false`,
`issue_created=false`, `duplicate_confirmed=false`,
`no_duplicate_confirmed=false`, `unknown_missing_issue_inventory=true`,
`original_finding_replayed=false`, `source_git_byte_evidence_reverified=false`,
`ci_execution_independently_verified=false` and all write/publish/native flags
false. The available `safe_next_step` value never authorizes IssueCreate,
IssuePlan publication or ReportPublish; no non-read action can consume this
response as a single-use grant. Actual creation approvals belong **only to
future EC217**, after EC216 draft review; writing belongs to EC218.

## 3. Privacy: no implicit external permission

`PrivacyScope` has an exact classification (`PUBLIC`, `INTERNAL`,
`CONFIDENTIAL`, `RESTRICTED`, `UNKNOWN`), target visibility (`PUBLIC`,
`PRIVATE`, `UNKNOWN`), a declared privacy-review decision
(`ALLOW_REDACTED_LOCAL_REVIEW`, `NEEDS_REVIEW`, `DENY`, `UNKNOWN`), and a
pinned policy SHA. This is an in-memory **policy claim, not organizational
policy proof**. PUBLIC+INTERNAL/CONFIDENTIAL and all RESTRICTED are
**blocked**, UNKNOWN is **unknown**; PRIVATE+CONFIDENTIAL can only qualify
for the **same metadata-only local draft** after an additional short signed
review. It never permits moving confidential text to a repo, AI or recipient.
No title, body, source path/quote, raw Finding notes, issue labels or token
is present in EC215 output. Input/receipt hashes are binding hints, not
secrets; avoid using low-entropy source text as hashes.

## 4. A signed review is not IssueCreate authorization

`HumanReviewReceipt` (`ces.issue_eligibility_review.v1`) binds
`evaluation_fingerprint(context, eligibility_request, match_request,
match_result)`. The fingerprint incorporates the exact context, repository,
complete Finding/source/privacy declarations, original EC214 full request
fingerprint (including title/anchor policy) and an EC215-domain-separated
hash of the entire bounded, untrusted EC214 receipt. The receipt is Ed25519
signed over `review_signing_bytes(receipt)`, using a fixed independent domain.
It must be issued in the past, expire after issuance and within **300 s**,
match exact approved purpose, signer key ID and digest, and explicitly
acknowledge **selected-only Issue coverage, lack of duplicate absence proof,
and unverified source/reviewer authority**.

Verification uses **only keys separately provisioned by the host** in
`trusted_review_keys`; no key from CLI JSON, environment, match results or
Finding can self-authorize. A caller passing its own key map can still claim
its own approval: EC215 cannot certify real organizational enrollment,
roles, key revocation, policy or authenticity of the read receipts.
`review_signature_cryptographically_valid=true` means precisely that the
**detached bytes verified under the host-configured key**. A signed receipt
cannot override blocked/unknown, nor can it execute anything. If cryptography
is unavailable, receipt verification denies and no eligible state is emitted.

### Example: safe offline API (does NOT issue a real review receipt)

```python
from construction import issue_provider as ip, issue_match as im
from construction import issue_eligibility as ie
from datetime import datetime, timezone

ctx = ip.ProviderContext('github', 'api.github.com', 'approved-account-slot')
a = im.EvidenceAnchor('a'*40, 'src/main.py', 10, 12, 'b'*64)
mr = im.IssueMatchRequest(
    'example/repo', 73142, (im.MatchCandidate(17, 500421),),
    subject_anchors=(a,), title_policy='DISABLED')
requested = ie.EligibilityRequest(
    'example/repo', 73142,
    ie.FindingBasis(
        'f'*64, 'd'*64, 'e'*64, 'DeliveredTarget', 'a'*40,
        ie.anchor_set_sha256(mr.subject_anchors), 1, 0, 'REVIEWED',
        1, 1, 'COMPLETE_SELECTED',
        datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')),
    ie.PrivacyScope('PUBLIC', 'PUBLIC', 'ALLOW_REDACTED_LOCAL_REVIEW', 'c'*64))

# No match result/credential/network -> cannot infer duplicates or eligibility.
out = ie.evaluate_issue_eligibility(ctx, requested, mr, None)
assert out['eligibility'] == 'UNKNOWN'
assert out['authorization'] == 'NOT_GRANTED'

# Positive evaluation needs a REAL, fresh, explicit EC214 selected result,
# plus independently host-provisioned reviewer keys and a signed receipt.
# No credentials, filesystem write, Git/Issue call, or issue draft in EC215.
```

The JSON-only offline CLI accepts **one bounded full input** from stdin:
`python construction/issue_eligibility.py --stdin-json`. It intentionally
**does not load reviewer keys**, so can never emit `ELIGIBLE_TO_PROPOSE`.
Use the host-integrated Python API after independent policy/key onboarding.
Pass no tokens/raw confidential content via shell arguments.

## 5. Schemas, developer test, deferred full acceptance

- `references/issue-eligibility-request.v1.schema.json` is the strict
  `EligibilityRequest` wire shape; context and original EC214 request/result
  have their own contract/API boundary.
- `references/issue-eligibility-review.v1.schema.json` is the strict detached
  Ed25519 review receipt shape (not a grant schema).
- `references/issue-eligibility-result.v1.schema.json` hardcodes all side
  effect/authorization/duplicate-proof claims false and enforces state/exit
  relations.
- `construction/test_issue_eligibility.py` is a 51-case synthetic local
  development suite; its live-shaped fixture is deliberately fabricated
  and is never real-provider evidence. `fixtures/ec215/README.md` explains.
- Construction report: `EC-215.md`.

**NOT_RUN (user-assisted later):** live provider and private/hidden Issues,
trusted reviewer key enrollment/revocation, truthful private/public target
visibility, real Finding HMAC and source-content/Git byte replay, actual
issue-body evidence links, CI/Quality, temporal/ABA and concurrency drift,
PowerShell7/15 smoke, cross-OS/NFS, E63–E66 and end-to-end acceptance.
Historical B-001 still OPEN. EC216 draft formatting and EC217/218 write
permissions remain PLANNED, NOT IMPLEMENTED.
