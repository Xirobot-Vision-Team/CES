# EC221 — DeliveryPreview / local version-pinned redacted manifest

**Available:** V5.31 / R221 standalone host-callable
`construction/delivery_preview.py`, `preview_delivery(DeliveryPreviewRequest)`.
**Not a CES native PowerShell Action.** Original embedded CLI remains
**V4.60 / R150**; `DeliverySend`, `ReportPublish`, `DocsOnlyPublish`, external
message delivery and existing-Issue updates are not provided by EC221.

## Exact scope of the new function

One call selects **1–8 already-versioned source records**, in the supplied
order, from ONLY the existing authorized local readers:

| Source | Actual reader and independent local policy | Exact selection pins | Actual format / privacy minimum |
|---|---|---|---|
| Stored report | `ReportHistory.show` (EC200, EC199 private version index and SHA-verified document), with **new read policy**; always `include_markdown=False` | store binding from EC200 grant; slot/period/member set; requested version; `selected_report_ref`, `selected_entry_sha256`, `record_sha256`, `rendered_sha256`, `index_binding_sha256` | `text/markdown;charset=utf-8`; at least `INTERNAL` |
| Stored Finding | `FindingShower.query` (EC179, EC178 private HMAC/hash-chain ledger), with **new source-exact read/query/digest grant**; **exact ID**, page size 1, no cursor, no expired history | store pin; entire authorized source binding; source mode; finding ID; batch sequence; record SHA; original Finding declaration SHA; **full ledger revision SHA** and exact query SHA | Finding **metadata-only** `application/vnd.ces.finding-declaration-metadata+json`; at least `CONFIDENTIAL` |

Arbitrary serialized JSON, unversioned ReportRender drafts, EC216 IssuePlan
previews, EC218 provider-reported Issue creation, EC219 candidate observations,
EC167/168 proposed PR associations, raw file paths and guessed sources are **not**
acceptable input. Nothing about an Issue, PR or local candidate is called
"delivered". If any selected source fails or its version/content/store scope
has drifted, **all** returned source details are withheld (status `unavailable`).
This function does not use raw source snapshots as substitutes for a real
reader or try a second source when a reader fails.

## Permissions: two separate layers

The `DeliveryPreviewRequest` has four **exact `True`** fields:

- `permit_local_preview` — **new EC221** opt-in for a local preview only.
- `permit_private_source_metadata_read` — explicit consent to inspect sensitive
  local source metadata, even though the result is redacted.
- `permit_report_content_read_in_process` — required if any Report selected:
  EC200's *internal* record validation reads original Markdown bytes even
  though `include_markdown=False` withholds Markdown from this result.
- `permit_finding_digest_details_read` — required for a Finding; EC179's
  independent read/query permission and exact-scoped digest-details query
  are still enforced by the genuine reader.

The **original EC200 per-report** `read_policy` (including exact owner-private
store binding, independent repository grants and receipts), or **original
EC179 exact source binding** with owner-private store pin, must also be
supplied. A successful previous ReportRender/FindingSave response, old
cursor or another person's read permit is **not** EC221 authorization.
All callback permission booleans are *local assertions*; this standalone
implementation does **not** verify actual enterprise roles, provider identity,
signatures, recipient ownership or grant revocations. The host must manage
those independently.

The destination accepts **category plus hashes, never free-form addresses**:
`audience_kind` (`INTERNAL_REVIEW`, `NAMED_EXTERNAL`, `PUBLIC_DISTRIBUTION`),
`channel_kind` (`EMAIL`, `CHAT`, `DOCUMENT_PORTAL`, `MANUAL_EXPORT`), and
nullable exact SHA-256 commitments for audience, channel and recipient
identities. Even non-null commitments are **always `UNVERIFIED`**: no recipient
lookup or discovery, and no guarantee that two hashes identify an actual
person. EC223 must independently resolve and authorize identities in a future
round. Use `None` when an identity has not been selected; this creates an
explicit gap instead of inventing an address.

## Integration sketch (host-selected values, no network)

The caller obtains a genuine EC200 version using an independently scoped
`ReportHistory.show(..., include_markdown=False)` and reads the **existing**
`subject` on `status='partial'`. Select the *same exact* slot/period/members,
current EC200 policy and store binding, and pin all five returned values:

```python
from delivery_preview import (
    Destination, ReportSelection, DeliveryPreviewRequest, preview_delivery
)

# `history`, `report_read_policy`, `selected` and `slot_members` were obtained
# by the host from an authorized local EC200 ReportHistory.show() call.
report = ReportSelection(
    reader=history, storage_root=private_report_root,
    slot_key=selected['slot_key'], period_id=selected['period_id'],
    slot_members=slot_members, read_policy=report_read_policy,
    selected_version=selected['selected_version'],
    expected_report_ref=selected['selected_report_ref'],
    expected_entry_sha256=selected['selected_entry_sha256'],
    expected_record_sha256=selected['record_sha256'],
    expected_rendered_sha256=selected['rendered_sha256'],
    expected_index_binding_sha256=selected['index_binding_sha256'],
)
preview = preview_delivery(DeliveryPreviewRequest(
    sources=(report,),
    destination=Destination(
        audience_kind='INTERNAL_REVIEW', channel_kind='MANUAL_EXPORT',
        audience_identity_sha256=None,
        channel_identity_sha256=None,
        recipient_identity_sha256=None,
    ),
    policy_revision_sha256=host_current_policy_sha256,
    requested_privacy_floor='CONFIDENTIAL',
    permit_local_preview=True,
    permit_private_source_metadata_read=True,
    permit_report_content_read_in_process=True,
    permit_finding_digest_details_read=False,
))
# `preview['preview_markdown']` is the IN-MEMORY redacted manifest, NOT the report.
# `preview['preview_id']` is a commitment, not a signed grant or send token.
```

To select a Finding, first call `FindingShower.query` under a new exact source
binding and both store-read/query permissions with
`filters={'finding_id': exact_selected_finding_sha256}, page_size=1,
include_digest_details=True, authorize_digest_details=True,
include_expired=False`; require exactly one matched/returned record. Bind
`expected_revision_sha256` and `expected_query_sha256` **from that exact
query**, plus `finding_id`, batch sequence, store pin, and
`digest_details.record_sha256` and `digest_details.original_finding_sha256`
into `FindingSelection`. EC221 repeats **the same exact query**, not a fuzzy
search. An unrelated cursor/filter cannot be substituted. ProposedPR metadata
requires explicit `acknowledge_historical_proposal_metadata=True` and keeps a
historical/not-delivered warning.

## Output contract and negative guarantees

The strict schema
[`delivery-preview-result.v1.schema.json`](delivery-preview-result.v1.schema.json)
requires, on accepted *local* preview, `status='partial' / exit_code=2` (never
"delivery success"); on unavailable source, `status='unavailable'/5`, and
on malformed input, `status='invalid_input'/4`.

The output contains a canonical bound `preview_id`, a **fixed vocabulary**
Markdown summary and its real UTF-8 SHA-256, a hash of the exact redacted
manifest, source kind, source version, **stored source content hash and record
hash**, format, store-revision commitment, count-only coverage and safe gap
codes. It never includes the source Markdown, Finding text/quote, code
patches, repository paths, full source binding, provider token, recipient
address, or arbitrary vendor error text. Unverified recipient/channel/audience
SHA fields remain in the **local-only** metadata manifest; they are not
identities and may still be sensitive correlation data.

Source privacy is **never reduced** below `INTERNAL` for reports or
`CONFIDENTIAL` for Findings; a higher requested floor is honored. Gaps call
out incomplete/withheld/declared-only Report coverage; unreviewed/local-only,
expired or historical Finding limitations; missing/unverified destination
identities; and unimplemented EC222 content review, EC223 verification, EC224
exact destination+payload approval and EC225 send adapter.

The API does not implement EC222 scanning of raw source text for secrets,
PII, patches or personal content, and does not claim a redacted *deliverable*
Report was created. It deliberately outputs only a redacted **manifest**,
not a sensitive plaintext publication candidate. The source hashes may change
if the local ledger/index changes; even identical source content is not proof
of remote currentness or semantic truth. Multi-source observations are
**not a cross-store atomic snapshot**. A future send **must revalidate every
source, its privacy policy and the destination** and obtain a new independent
exact signed/host-authorized grant. Reusing the preview fingerprint alone
must never authorize sending.

No network, Git, remote Issue mutation, provider write, external AI, local
CES store write, report publishing or PowerShell action is executed by this
module. The underlying EC179 reader uses existing file locking and private
ledger validation; EC200 reads and validates the selected report from its
existing owner-private store (no new directory created). Tests only cover
local synthetic data and do not prove those guarantees against all malicious
hosts, cross-process writers, or untrusted monkey-patched Python classes.

## Final joint acceptance deferred, not claimed

With the owner's authorized real data and test infrastructure: verify actual
Report/Finding private scope and original source hashes/versions, changed
content and concurrent corrections, expired Finding, larger multi-source
snapshots and filesystem conflicts, recipient/content privacy classification,
revoked host permission, direct/indirect network egress tracing, unsafe source
text reflection, and eventual EC222–EC225 integration. On Windows/macOS/Linux
confirm supported and unsupported secure-store behavior; re-run native
PowerShell7, the original 15 Smoke suites, E63–E66 and end-to-end acceptance
only in the planned final user-assisted phase. Real approvals, provider
identity, human review/CI/Git and B-001 original V3.10/ROUNDS materials remain
unverified/unavailable. They are **NOT_RUN / OPEN**, not assumed passing.
