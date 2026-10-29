# EC222 — Report / Finding sensitive-content review (local-only)

**Current release:** CES V5.32 / R222 / EC222. **Scope:** a new standalone
Python in-memory policy evaluator, **not** a PowerShell action or an
organization-approved sanitizer/declassification/send/publish function.

## What is actually reviewed

`construction/delivery_redaction.py` exports
`review_sensitive_delivery(SensitiveReviewRequest(...))`. It requires an
**exact pinned EC221 `DeliveryPreviewRequest`**, the EC221 `preview_id`
retrieved by an independent local preview, and
`ACTIVE_POLICY_SHA256`. This policy SHA incorporates the shipped source
implementation bytes; a mismatching or unreadable implementation fails
closed. This is a reproducible **local code/policy commitment**, not a
trusted organizational signature or proof of source correctness.

The new host-controlled permissions are separate from EC221 and the private
store owner:

- `permit_independent_sensitive_policy_review=True` for the **exact**
  content/destination review.
- `permit_exact_report_plaintext_review=True` before any EC200 Markdown
  inspection, **and** EC200 `read_policy.permit_rendered_markdown=True` plus
  that flag on **every** selected repository grant, in addition to the
  original EC200 history read policy and EC221 permissions.
- `permit_exact_finding_plaintext_review=True` for any selected Finding;
  EC179 exact store/source/query/revision HMAC permissions and EC221
  digest-details permission remain required. These booleans are caller
  assertions, **not authenticated organizational approval**.

All argument types, source selectors, separate permissions and optional
witness boundaries are checked **before** opening any private source store.
The EC221 preview is recomputed, and its manifest SHA and exact preview ID
are checked before **additional** plaintext inspection. There is no
atomic snapshot spanning distinct Report and Finding stores. Source versions
must be freshly rechecked at any later separate operation.

### Report

EC200 `ReportHistory.show(include_markdown=True)` reads the **actual**
saved, pinned, hash-verified Markdown. EC222 checks raw UTF-8 SHA against the
selected `rendered_sha256`, record/entry/index/ref/slot/period/member pins
and publication state, enforces a 256 KiB limit, then evaluates the exact
bytes without returning them. The fixed implementation blocks patch/diff,
repository paths and filenames, private keys/tokens/credentials, contact and
person-attributed text, encoded/ambiguous content, and **any line outside a
narrow allowlist of the current deterministic Report renderer**. Changed
renderer formats require a reviewed policy/code revision; unknown text
is **blocked**, not silently emitted as safe.

### Finding

EC178/179 deliberately **do not store original Finding text**, only
HMAC-verified records and the EC175 domain-separated original Finding SHA,
plus field/quote hashes and identity. Therefore a Finding with no original
plaintext cannot truthfully be scanned and is **blocked** with
`FINDING_TEXT_NOT_AVAILABLE_IN_PRIVATE_STORE`.

An optional `FindingTextWitness(source_index, original_finding)` is an
**ephemeral host-supplied original EC175 finding object**, not a replacement
source and never written by EC222. It must match the **exact HMAC-verified
selected EC178 row**, the same EC179 ledger revision, store, batch, record,
finding ID, original EC175 domain SHA, field hashes, anchor quote/identity
hashes and source binding. Expired records and clock rollback are rejected.
Non-`REVIEWED` claims and historical ProposedPR records remain blocked.
Even with a matching witness, only a tiny approved-neutral-word vocabulary
with no paths/credentials/PII/technical source snippets can pass the fixed
policy. Other language or code, including ambiguous/unknown input, is
blocked. A local `REVIEWED` declaration **does not prove a real defect,
real reviewer identity, current Git/CI, or external privacy clearance**.

## Minimal host flow

```python
from dataclasses import replace
from construction import delivery_preview as dp, delivery_redaction as red

# `selected_sources` and `destination` are independently authorized and
# exact-pinned EC221 inputs; see delivery-preview.md for their construction.
local_request = replace(
    existing_ec221_preview_request,
    policy_revision_sha256=red.ACTIVE_POLICY_SHA256,
)
# Selected EC200 read policies must separately authorize raw Markdown.
ec221 = dp.preview_delivery(local_request)
if ec221["status"] != "partial":
    raise RuntimeError("Local preview unavailable")

review = red.review_sensitive_delivery(red.SensitiveReviewRequest(
    preview_request=local_request,
    expected_preview_id=ec221["preview_id"],
    expected_policy_sha256=red.ACTIVE_POLICY_SHA256,
    permit_independent_sensitive_policy_review=True,
    permit_exact_report_plaintext_review=True,
    permit_exact_finding_plaintext_review=False,  # set True for Finding
    finding_text_witnesses=(),   # Finding sources without witness BLOCK
))
```

Host MUST NEVER obtain the `FindingTextWitness` from untrusted arbitrary
text and claim it has source authority. It is only admissible for redaction
inspection after matching the already-verified stored original-finding SHA.
Do not log or serialize witness plaintext. No default recipient lookup,
content send, AI provider, network, Git, Issue/PR or private ledger write is
performed by this function.

## Output meanings

Contract: `references/delivery-redaction-result.v1.schema.json`.

- `status=partial / exit_code=2`, `verdict=SAFE_REDACTED_SUMMARY`: the
  **new fixed-phrase in-memory summary only** passed this narrow local
  policy. Source text itself is never returned. It does **not** mean source
  truth, enterprise privacy compliance, recipient clearance, or send-ready.
- `status=blocked / exit_code=5`, `verdict=BLOCKED`: exact selections were
  rechecked, but some content was missing, risky or unclassifiable. Returns
  only **closed-vocabulary reason codes**; no excerpts or draft payload.
- `status=invalid_input / exit_code=4` or `unavailable / exit_code=5`:
  no review payload, no unsafe fallback, no underlying exception text.
- Every result has `message_sent=false`, `published=false`,
  `ready_to_send=false`, `safe_for_external_send=false` when a review
  exists, and every member of `effects` false. EC223 identity validation,
  EC224 exact authorization, EC225 sending and native ReportPublish remain
  **NOT_IMPLEMENTED**.

`review_id` commits exact EC221 preview, manifest, destination binding,
selected content/source hashes, policy and verdict. It is **not** a signed
authorization token, nor a send receipt. The fixed English summary has its
own exact SHA-256 and never contains raw Report Markdown, Finding witness,
paths, emails, URLs or free-form untrusted strings.

## Validation deferred

Local synthetic developer checks use disposable *real* EC200/EC179 stores
and Draft 2020-12 output validation. Final user-assisted acceptance **NOT_RUN**:
real source/actor identities, company privacy and policy review, actual
recipient/channel, adversarial source, Windows/macOS/Linux/NFS/multiprocess
and crash behavior, PowerShell7 + original 15 Smoke, E63–E66, live
Provider/Git/CI integration, correct declassification and egress review.
Original B-001 V3.10/ROUNDS gap remains OPEN.
