# EC-209 — Optimistic KnowledgeSave conflict classification and explicit local retry

**Construction package:** V5.19 / R209 / EC-209. This is a standalone Python-only extension of EC-208's **owner-private immutable CES metadata version store**, not a native PowerShell Action, a live Git/Docs read, or authorized publication. Existing native CLI remains V4.60/R150. All positive results intentionally have `partial / exit_code=2`; the source Markdown, business repository, Issue and provider remain untouched.

## Why a retry requires another review

EC-208 serializes immutable local version appends under a private POSIX lock, checks the exact parent version, current chapter/section SHA-256, actual EC-202 source snapshot and EC-207/206 evidence reads, and requires its own scoped grant plus two distinct locally verifiable human-role Ed25519 signatures. A legitimate concurrent append may move the local parent while leaving another section unchanged. A submitted request is then **stale**; copying its old approval or blindly applying its entire chapter digest to the new parent would break the signed review boundary.

`construction/knowledge_save_retry.py` provides **read-only** `KnowledgeSaveRetry.assess()`, `preview_retry()`, and `prepare_retry()`:

1. Under the existing EC-208 shared lock, replay the complete private version chain and the actual original Markdown manifest/file, re-evaluate the **original EC-207 whole-selection plus every EC-206 candidate content read grant**, and check selected candidate IDs and optional EC-205 original section witness. Never trust a caller-supplied `Handoff` response, saved version receipt, source SHA or identity assertion as independent authority.
2. Find the proposed original parent in the **real immutable chain** (baseline or an earlier version), verify its exact content SHA, then re-run EC-208's complete signed-request transformation (section SHA, replacement bytes, structure, resulting whole-chapter digest) **against that historical parent**. A request that was never valid against an immutable ancestor is **not eligible** for retry.
3. Classify without revealing chapter text: original `save_key` already recorded (inspect; no blind retry), current parent still valid, changed target SHA (requires manual resolution), target changed-and-reverted/ABA (also requires manual resolution), or only other sections changed (disjoint, **still needs re-review**). Report the intervening versions' exact sequence, IDs, parent IDs, whole-chapter digests and modified section ordinals. This classification does **not** guarantee that changes to other sections are semantically independent.
4. For the eligible disjoint case **only**, require an explicit retry intent with the exact observed head ID/SHA, target SHA, complete ordered intervening version ID list, new unused retry `save_key`, **new EC-208 write permission receipt SHA**, distinct human-authored re-review summary and explicit re-review acknowledgment. `preview_retry()` computes a domain-separated binding of the entire intent, original request, current head/history and rebased EC-208 request; it returns **no reviewed bytes** and grants no action.
5. `prepare_retry()` repeats every check *under the same read lock* and additionally requires a **separate EC-209 no-write proposal grant** bound to that exact retry digest, store instance/scope and independent receipt. Additional explicit consent is required before echoing proposed bytes associated with restricted candidates. It returns the complete **unapproved** new EC-208 request JSON with recomputed current parent/whole chapter digests. It never carries forward an old approval/signature/EC-208 write grant, executes AI, changes an original document, appends a version or retries an uncertain write result.
6. Humans must review the **actual intervening content** using their separately authorized process (the EC-209 hash/ordinal receipts alone do not disclose it), independently authorize a **fresh EC-208 grant and two new role-separated signatures** over the *new* request's *new* authorization scope. Call `KnowledgeVersionSave.preview()` and then `KnowledgeVersionSave.save()` for the exact prepared request. That **exclusive-lock** save rechecks the head and original snapshot; another writer between proposal and save causes a new optimistic conflict and **no write**. Do not silently loop.

## Input schemas and executable path

The exact fields and allowed values are in [retry intent](knowledge-save-retry-intent.v1.schema.json), [retry policy](knowledge-save-retry-policy.v1.schema.json) and [result](knowledge-save-retry-result.v1.schema.json); original writer inputs remain in [EC-208 guide](knowledge-version-save.md). Example integration (all variables must originate from an independently authorized local operator; placeholders are **not** usable actor grants/signatures):

```python
from construction.knowledge_save_retry import KnowledgeSaveRetry

coordinator = KnowledgeSaveRetry(existing_ec208_save_api)
existing_gates = dict(
    request_json=original_exact_ec208_request,
    handoff_request_json=original_ec207_request,
    handoff_policy_json=explicit_ec207_handoff_grant,
    candidate_read_policies_json=exact_ec206_per_record_read_grants,
)
inspection = coordinator.assess(**existing_gates)
# If state == DISJOINT_PARENT_MOVED_RE_REVIEW_REQUIRED:
#   1. Independently read/review the intervening version contents.
#   2. Supply retry_intent_json pinning the inspection receipts and a NEW key,
#      EC208 write-receipt and changed human re-review summary.
preview = coordinator.preview_retry(**existing_gates, retry_intent_json=retry_intent_json)
# Obtain an independent EC209 proposal grant bound to the exact returned
# retry_authorization_scope_sha256 (never a save or publish permission).
prepared = coordinator.prepare_retry(**existing_gates,
    retry_intent_json=retry_intent_json, retry_policy_json=ec209_no_write_grant)
if prepared['retry_request_prepared']:
    new_request = prepared['subject']['rebased_request_json']
    new_preview = existing_ec208_save_api.preview(
        request_json=new_request, **{k:v for k,v in existing_gates.items()
                                    if k != 'request_json'})
    # Only after NEW external human review and TWO freshly scoped signatures:
    # existing_ec208_save_api.save(request_json=new_request, ...,
    #   save_policy_json=new_independent_ec208_write_grant,
    #   approvals_json=new_independent_reviewer_and_owner_signatures)
```

### Result classification

| `subject.state` / reason | Treatment |
|---|---|
| `CURRENT_PARENT_VALID_NO_RETRY_NEEDED` | The unchanged original request remains subject to its original EC-208 grant/signature checks; do not create a needless retry. |
| `ALREADY_RECORDED_NO_RETRY` | An immutable record with exactly that request digest already exists. Inspect the record and original I/O result; do **not** reinterpret an uncertain append as permission to write again. Reusing a key for different content is a hard conflict. |
| `CONFLICT_TARGET_SHA_CHANGED_REQUIRES_MANUAL_MERGE` | The target section SHA no longer matches the originally reviewed bytes. **No automatic merge or prepared retry.** |
| `CONFLICT_TARGET_ABA_TOUCHED_REQUIRES_MANUAL_MERGE` | At least one intervening version touched the target, even if the final bytes returned to the old SHA. **No automatic retry.** |
| `DISJOINT_PARENT_MOVED_RE_REVIEW_REQUIRED` | The original request was valid at a historical parent; all intervening versions touched other sections only, but a **new explicitly reviewed request, independent proposal grant, EC-208 grant and two fresh signatures** are still required. |
| `CONFLICT_PARENT_NOT_AN_IMMUTABLE_ANCESTOR`, `OPTIMISTIC_SECTION_FINGERPRINT_CONFLICT`, original chapter SHA mismatch, stale EC-202 snapshot, missing EC-207 grants, HMAC/record/symlink failure | Reject without proposed retry or mutation. Restore externally trusted source/evidence or start a new independent knowledge workflow; never repair the immutable chain by editing existing records. |

An intermediate `preview_retry()` or `prepare_retry()` result is not evidence that the resulting request can still be committed after a later concurrent append. Neither this round nor EC-208 executes a real 2-phase transaction with external organizational signers; all inputs are caller-provided trust roots. A `partial` result does **not** certify current deployed architecture, external approvals, knowledge ownership or source truth. Keys, authorization receipts and public-key roles must not be treated as authoritative organizational enrollment merely because signatures verify locally.

## Boundaries and deferred acceptance

- **No old-approval transference**: changed `save_key`, permission receipt, re-review summary, parent version ID, whole-chapter digest and request binding force a new EC-208 authorization scope and signatures. The EC-209 policy is itself a **no-write** proposal permission, not an EC-208 grant.
- **No auto-retry after unknown I/O**: malformed/incomplete version chains, unsafe paths and reused keys fail closed. Recovery starts with independent read-only inspection and human determination of the original write outcome.
- **No live Git SHA certification**: EC-209 evaluates the immutable *local EC-208 metadata target*, not a freshly attested live EC-203 Git target commit. The EC-202 original knowledge manifest/file must remain byte-for-byte pinned; drift denies same-store retries instead of silently adopting a new target SHA. External repo/knowledge authority must be revisited through upstream authorized steps (future EC-210), not inferred.
- **No silent semantic merge**: disjoint section positions are only a mechanical eligibility gate. The operator must check the intervening document differences and review the complete proposed content; the code cannot prove human comprehension or real-world organizational authority.
- **Deferred**: native PowerShell7/15 Smoke, real organization signer identity/key custody/revocation rotation, OS/NFS/concurrent processes and crashes, real independent source/CI/provider/AI evidence, E63–E66 performance and final assisted end-to-end verification remain `NOT_RUN`.
