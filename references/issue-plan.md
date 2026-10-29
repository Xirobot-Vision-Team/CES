# EC-216 — local IssuePlan preview (V5.26 / R216)

`construction/issue_plan.py` constructs a **strictly local, in-memory, closed-
vocabulary Issue title/body proposal** for human review. It does not create or
modify an Issue, perform a provider/Git/source read, call an external AI model,
read credentials, persist a draft, deliver content or register a native
PowerShell action. The native PowerShell CLI stays **V4.60 / R150**.

The strongest result, `DRAFT_READY`, means only that the local preview was
assembled under the **rechecked EC215 gate**. It is **never** EC217 single-use
human approval or EC218 remote Issue creation, and is **not evidence that the
issue is new, the source is authentic or the reviewer has organizational
permission**. The draft must not be uploaded, published or copied to an
external service without a separate privacy and creation authorization.

## 1. Inputs: exact original evidence, not fabricated state

Use the Python API:

```python
from construction import issue_plan as plan
from construction import issue_eligibility as ie

# ctx: original EC211 ProviderContext
# eligibility_request: original EC215 EligibilityRequest
# match_request: original EC214 IssueMatchRequest (not reconstructed from a result)
# match_result: entire original caller-supplied EC214 serialized result
# review_receipt: original detached EC215 HumanReviewReceipt
# trusted_keys: independently HOST-managed reviewer-key map, never user JSON
# eligibility_result: entire ORIGINAL EC215 output, not a 'true' boolean

# All original objects above must be obtained from your authorized host flow.
# This example does not fabricate a provider receipt or issue a reviewer key.
ref = plan.SelectedSourceRef(
    anchor_index=0,
    expected_anchor_sha256=plan.source_anchor_sha256(
        match_request.subject_anchors[0]),
)
intent = plan.IssuePlanRequest(
    target_provider=ctx.provider,
    target_repository=eligibility_request.repository,
    expected_repository_id=eligibility_request.expected_repository_id,
    target_visibility=eligibility_request.privacy.target_visibility,
    expected_evaluation_sha256=eligibility_result['evaluation_sha256'],
    expected_match_receipt_sha256=eligibility_result['issue_match_receipt_sha256'],
    expected_eligibility_result_sha256=plan.eligibility_result_sha256(eligibility_result),
    expected_review_receipt_sha256=plan.review_receipt_sha256(review_receipt),
    finding_record_sha256=eligibility_request.finding.finding_record_sha256,
    source_binding_sha256=eligibility_request.finding.source_binding_sha256,
    source_mode=eligibility_request.finding.source_mode,
    source_revision=eligibility_request.finding.source_revision,
    evidence_anchor_set_sha256=eligibility_request.finding.evidence_anchor_set_sha256,
    policy_revision_sha256=eligibility_request.privacy.policy_revision_sha256,
    topic='RELIABILITY', concern='ERROR_HANDLING',
    selected_sources=(ref,),
)
result = plan.draft_issue_plan(
    ctx, intent, eligibility_request, match_request, match_result,
    eligibility_result, review_receipt=review_receipt,
    trusted_review_keys=trusted_keys,
)
assert result['approval'] == 'NOT_GRANTED'
# result['draft'] is an in-memory, redacted preview ONLY when DRAFT_READY.
```

Supply the EC215 `eligibility_result` exactly, including the original reason,
coverage flags and evidence/review hashes. It cannot be reconstructed from
`ELIGIBLE_TO_PROPOSE` alone. **The evaluator always calls actual unchanged
`evaluate_issue_eligibility()` with an immutable, bounded in-memory snapshot of
the original EC214 receipt**, takes a single UTC instant, and compares the
*entire* newly computed EC215 result with the supplied original (type-exact
canonical JSON). A forged eligible result, modified boolean, omitted field,
source/match receipt change, expired reviewer signature or absent host key
cannot make a draft ready. The host key registry and role/revocation proofs
are NOT read from the request, and **their real trustworthiness is not
established** by the Python function.

The `IssuePlanRequest` redundantly pins exact provider, case-sensitive
repository path and stable numeric ID, target visibility, all original EC215
and EC214 digests, full signed-review-receipt digest, Finding record, source
binding/mode/revision, complete subject anchor-set digest and privacy policy
revision. Pins must equal the original immutable inputs; a changed target
(provider/path/numeric ID/visibility) is blocked, stale/conflicting evidence
returns UNKNOWN. A selected `SelectedSourceRef(anchor_index, anchor SHA)` must
refer to one of **1–16 exact original EC214 subject anchors** in strictly
ascending, unique order; each SHA is recomputed from the complete source
commit, private path, line range and evidence byte digest. No source anchor is
a provider-authenticated truth proof; a SHA binds equality only.

## 2. Draft content and privacy boundary

Six permitted `topic` values, each with three fixed `concern` values:

| topic | permitted concerns |
|---|---|
| `CORRECTNESS` | `INCORRECT_RESULT`, `EDGE_CASE`, `INCONSISTENT_STATE` |
| `RELIABILITY` | `ERROR_HANDLING`, `RECOVERY`, `NONDETERMINISM` |
| `PERFORMANCE` | `LATENCY`, `RESOURCE_USAGE`, `SCALABILITY` |
| `ACCESS_CONTROL` | `PERMISSION_CHECK`, `BOUNDARY_CHECK`, `DATA_EXPOSURE` |
| `TESTING` | `COVERAGE_GAP`, `REGRESSION_RISK`, `ASSERTION_GAP` |
| `DOCUMENTATION` | `CONTRACT_DRIFT`, `MISSING_GUIDANCE`, `AMBIGUOUS_BEHAVIOR` |

No free-text title, summary, source excerpt, issue label, issue body, path,
repository URL, token, reviewer/key ID or remote issue title is accepted for
draft interpolation. The title is at most 100 characters; the body at most
2,400 characters and explicitly asks reviewers to reproduce, validate source
truth, seek actual duplicates and sanitize content **before** EC217. The body
mentions only caller-selected categories, `E01`-style local reference IDs and
the **count of explicitly selected existing Issues**; a zero-positive-hint
selection is never called complete inventory or proof of non-duplication.

The structured result keeps the target **provider**, visibility and a SHA
binding *exact* path, numeric ID, API host and account slot; it **does not
expose** raw repository path or numeric ID. Selected references expose only
source-anchor indices and domain-separated SHA bindings; no path/line number
or source bytes. The source revision is represented by its domain-separated
SHA, not the raw Git OID. The Finding, anchor-set, source-binding and privacy
policy hashes remain as redacted audit bindings; hashes are NOT cryptographic
secrets or independent source verification. Privacy class is intentionally
hidden in output, while eligibility still re-evaluates the original declared
classification and visibility. The full draft remains local; even a PRIVATE
repository/CONFIDENTIAL classification does not authorize disclosure of private
content.

`topic`/`concern` are caller-selected **review categories**, not a verified
classification of the root cause. Do not automatically publish the generated
text as a factual finding: it deliberately lacks observed/expected details,
reproduction steps and independently approved release wording.

## 3. Failure states, result and contracts

| `plan_state` | `status` / `exit_code` | `draft` | Interpretation |
|---|---|---|---|
| `DRAFT_READY` | `partial / 2` | redacted object | Exact fresh EC215 positive soft eligibility + all pins verified, local review only |
| `NEEDS_REVIEW` | `partial / 2` | `null` | EC215 reviewer absent/bad, synthesized selected Issue receipt, positive hint, privacy withholding or evidence review incomplete |
| `BLOCKED` | `partial / 2` | `null` | EC215 hard privacy veto/rejected finding, or target provider/repository/visibility conflict |
| `UNKNOWN` | `unavailable / 5` | `null` | EC215 unknown/stale, incomplete selected Issue evidence, mismatch to original result/signature/Finding/source pins |
| `INVALID_INPUT` | `invalid_input / 4` | `null` | Invalid dataclasses, hash/enum/indices, oversized malformed receipt, impossible source reference |

Every result includes `approval=NOT_GRANTED`,
`delivery_state=NOT_ATTEMPTED`, immutable no-write/no-publish/no-network/no-AI
flags and explicit `draft_generated_locally` (true only for `DRAFT_READY`).
Its draft itself carries `authorization=NOT_GRANTED` and `issue_created=false`.
No success/exit-code 0 is emitted. No EC216 native PowerShell action or JSON
CLI is registered; there is no caller-controlled key injection in a CLI.

Strict Draft2020-12 schemas:

- [`issue-plan-request.v1.schema.json`](issue-plan-request.v1.schema.json): exact
  typed **plan intent** only; the original EC215/EC214 dataclasses and host keys
  enter the separate Python API and MUST not be read from an untrusted JSON
  request as trusted authority.
- [`issue-plan-result.v1.schema.json`](issue-plan-result.v1.schema.json): exact
  state-to-status/exit-code/draft relationships, bounded draft structure,
  closed vocabulary/no-write/no-authorization flags. Its JSON Schema does not
  itself establish source or reviewer authority.

Focused development suite: `python -m unittest -q test_issue_plan` from
`construction/`; fixture caveats: `construction/fixtures/ec216/README.md`.
Synthetic tests deliberately **fake a live-looking EC214 result** to reach
EC215's positive soft-eligibility branch under a local test key. This is not
live-provider verification, and the tests do not prove actual organizational
review, source delivery, privacy policy or repository-wide duplicate absence.

## 4. Deferred final user-assisted validation

**NOT_RUN**: live authorized GitHub/GitLab Issue selection, private/hidden/race
behavior, independent actual Finding/HMAC and Git/delivery/CI provenance,
organizational signer enrollment/role/revocation and independently verified
host key registry, repository visibility/classification and authorized
publishing wording, adversarial privacy side channels, source SHA/low-entropy
fingerprint exposure, timestamp drift/concurrent snapshot, Windows/macOS/Linux
and NFS behavior, native PowerShell7/original 15 Smoke, E63–E66 performance and
full end-to-end user acceptance. Historical B-001 remains OPEN. EC217 one-time
IssueCreate human approval and EC218 idempotent Issue remote write remain
**PLANNED, NOT IMPLEMENTED**.
