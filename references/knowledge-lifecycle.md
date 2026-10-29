# EC210 — CES Knowledge lifecycle (V5.20 / R210)

**Construction state:** `IMPLEMENTED_PENDING_FINAL_ACCEPTANCE`, local POSIX Python API only. The original PowerShell CLI is still V4.60/R150; **no native `Knowledge` or `DocsOnlyPublish` route is registered**. The word “save” here means *only the independently signed, append-only EC208 private metadata journal*, never rewriting source Markdown or actual publishing.

## Capabilities shipped

`construction/knowledge_lifecycle.py` joins existing real, unchanged EC202/203/204/205/206/207/208/209 implementations behind one host-configured `KnowledgeLifecycle(version_store, chapter_mapper=None)` object. The `version_store` is a previously initialized `KnowledgeVersionSave`; `chapter_mapper` is an actual host-configured `KnowledgeChapters` object, required for candidate intake or reviewed save dispatch. Its repository/knowledge filesystem roots and repository identity must match EC208's pinned candidate/source store.

| Method | Reads & actual authorization | Writes | Never happens |
|---|---|---|---|
| `query_binding_preview(query_request_json=...)` | EC208 private chain replay, exact source snapshot/section/HEAD/content hashes | None | No returned source text or search results |
| `query(query_request_json=...,query_policy_json=...,bootstrap_request_json=None,bootstrap_read_policy_json=None,version_evidence_json=None)` | Exact EC210 query policy; **EC202 per-source content grant** for content; for local-version content, fresh EC207 whole-selection and EC206 candidate/provenance grants for **each** historical writer touching a selected section | None | Cannot disclose local draft text using EC210 permission alone |
| `preview_candidate_intake(source_inputs=...,proposal_json=...)` | Fresh EC205 map replays Git/EC204 and EC202; EC206 exact candidate binding preview | None | Caller-supplied arbitrary EC205 result not accepted |
| `append_candidate(source_inputs=...,proposal_json=...,append_policy_json=...)` | Same fresh EC205 map + **separate** EC206 candidate append grant, restricted claim grant when needed | Only EC206 append-exclusive *quarantine candidate*, or same-key idempotent no-op | No authoritative knowledge/PR/Issue/write or promotion |
| `prepare_update(source_inputs=...,handoff_inputs=...,save_request_json=...)` | Fresh EC205 source chapter/section mapping, actual selected Git path bytes, EC202 original source binding witness, EC207/206 Handoff replay and EC208 optimistic parent preview | None | No automatic review, AI invocation, signers or merge |
| `save_reviewed(...,lifecycle_save_admission_json=...,ec208_save_policy_json=...,ec208_approvals_json=...)` | Fresh entire `prepare_update`, exact independent EC210 dispatch admission, exact independent EC208 write grant and *two* independently provided Ed25519 role approvals. EC208 CAS/load/append locks apply | At most one EC208 **private immutable metadata** version | No blind conflict resolution, original knowledge overwrite, business Git, provider, Issue or `DocsOnlyPublish` |
| `assess_conflict(save_request_json=...,handoff_inputs=...)` | Real EC209 replay historical local parents under EC207/206 grants | None | No automatic retry/append |
| `prepare_retry(save_request_json=...,handoff_inputs=...,ec209_retry_intent_json=...,ec209_retry_policy_json=...)` | EC209 exact re-review intent and separately scoped no-write grant | None | Does not reuse old EC208 signatures; new request still needs fresh chain preview and approval |

For `source_inputs`, supply the nine **original EC205** keyword arguments: `request_json`, `bootstrap_read_policy_json`, `target_read_policy_json`, `impact_read_policy_json`, `chapter_read_policy_json`, `target_statement_json`, `target_signature_base64`, `baseline_statement_json`, `baseline_signature_base64`. The verified target and baseline signature inputs may be `None` only where the original APIs allow it, but no proven EC210 update proceeds without the necessary signed source evidence. For `handoff_inputs`, supply all three **original EC207** parameters: `handoff_request_json`, `handoff_policy_json`, `candidate_read_policies_json`. The caller must not replace them with a previous “success” claim: the underlying APIs reread the actual private records and source/Git bytes.

### 1. Query the snapshot or one immutable metadata version

First obtain the current `head_version_id` and `head_content_sha256` from `KnowledgeVersionSave.inspect()` (hash-only), and the original snapshot SHA from its manifest/EC208 baseline. Pin **both** the chosen content and observed current head.

```json
{
  "schema": "ces.knowledge_lifecycle_query_request.v1",
  "operation": "knowledge.lifecycle.query",
  "view": "source_snapshot",
  "selected_version_id": null,
  "expected_head_version_id": null,
  "expected_chapter_sha256": "REPLACE_WITH_EXACT_SOURCE_SHA256",
  "section_indices": [1],
  "projection": "match_snippets",
  "search_terms": ["API"]
}
```

`selected_version_id` is `null` only for the **original source snapshot**; use a real immutable EC208 version ID for `local_metadata_version`. `expected_head_version_id` is the **current** head even when reading an old version, and may be `null` only when no versions exist. On a changed head or source SHA, restart preview; no blind fallback to latest. `section_indices` are sorted, distinct, 0-based, maximum eight existing parsed Markdown ATX sections. `projection` is `hashes_only`, `match_snippets` (1–4 distinct sorted search strings) or `full_sections` (canonical base64 exact section bytes). Snippets return up to 16 matching lines per selected section, 200 characters each; scans never cross selected section boundaries. Chapter bytes are constrained by EC208's existing 16 KiB cap.

Pass the complete request to `query_binding_preview`; an independent controller supplies `query_policy_json` with **exact** preview `store_instance_id`, `store_scope_binding_sha256`, `query_authorization_scope_sha256`, SHA-shaped `permission_receipt_sha256`, and the positive minimum permissions for the selected projection. Every write/publish flag (including `permit_docs_only_publish`) **must be false**.

For `hashes_only`, no additional content grants are read or accepted. For text/snippet/full section, *also* supply a real **EC202** request and read policy selecting **only** this exact Markdown chapter, exact manifest SHA and original chapter SHA, same repository/space/period/source-policy scope, and both overall and source-level content projection permission. The actual EC202 read result must contain identical bytes; its standalone returned status is only `READ_UNVERIFIED`, not organizational evidence.

Private-version text always requires explicit EC210 `permit_private_version_text=true` **and** `permit_restricted_private_version_text=true` (conservatively all privately signed review text is sensitive), plus an exact `version_evidence_json` bundle. That bundle contains one record for every historical version whose `body.section_index` touched the queried sections, through and including the selected version. Each row has `version_id`, and the *original* three EC207 keyword JSON inputs used to authorize that version's candidates. No extra/missing version IDs allowed. EC207 replays the full selection grant and EC206 independent per-record/restricted permissions; selected candidate keys, record IDs, AI input and selection digests must match the immutable EC208 body. Sections never modified in a local journal require only the original EC202 source-content grant and EC210 private projection grant.

All successful queries return `status=partial`, not `success`, and preserve `source_knowledge_file_written=false`, `published=false`, `docs_only_publish_invoked=false`, `organizational_authority_authenticated=false`. A local metadata version is **not** certified current, delivered or published architecture. Operator-provided read receipts and local signers do not establish real organizational key/role authority.

### 2. Candidate intake and reviewed save

1. Construct `source_inputs` from the exact EC205 signed Git + bounded original CES snapshot inputs, not an untrusted JSON result. `preview_candidate_intake()` returns only the source result commitment and EC206 candidate append authorization scope. Obtain a *new independent* EC206 private append grant. `append_candidate()` reruns the map and writes only a quarantined immutable EC206 candidate. Source result provenance remains an observational pin, not organizational proof.
2. Obtain EC207 Handoff selection preview; separately authorize EC207 full-selection and EC206 candidate read receipts. Draft text is **never automatically passed to AI/provider**. Human-review the proposed complete replacement section (including heading), its provenance, implications and any semantic conflicts. Build a precise EC208 `save_request_json` with original EC202 knowledge source binding SHA, exact EC205 section reference/ordinal, original manifest/chapter pins, optimistic exact parent+section SHA, reviewed replacement bytes and exact record IDs.
3. `prepare_update()` requires that a **currently recomputed actual EC205 map** show this exact existing section and a reviewable selected Git byte change. It must agree with EC208's original EC202 knowledge-source witness; EC208 replays EC207/206 grants. Returns an exact `workflow_authorization_scope_sha256`, **not write permission**. This stricter EC210 path intentionally does not dispatch free-form/manual unlinked revisions; EC208's original manual path remains separate.
4. Obtain a **new independent EC210** `lifecycle_save_admission_json` with exact workflow SHA/store pins and both `permit_evidence_bound_save_dispatch=true` and `permit_local_metadata_append_dispatch=true`. All other write/publish flags must be false. Independently obtain EC208 append policy plus reviewer/owner Ed25519 signatures on the exact EC208 authorization scope, with actual human review performed outside this code.
5. `save_reviewed()` recomputes the entire EC205/EC207/206/EC208 plan and the EC210 admission, then dispatches **one and only one** real EC208 `save()`. EC208's exclusive-lock CAS will deny changed local heads and signatures/permission mismatches. An ambiguous append outcome **must** be inspected; do not blind-retry. Conflicts go to `assess_conflict()` and, only when disjoint and separately authorized, `prepare_retry()`. A retry proposal itself is **not approved** and must be explicitly reviewed again with new EC210 admission, EC208 write grant and two fresh signatures before any subsequent save.

**Authority separation:** The EC205 map is a locally checked **signed Git observation against host-provided public keys**. It does not authenticate employment, permission issuer, knowledge ownership, actual production delivery, target recency or semantic correctness. The EC210 admission receipt is SHA-shaped but is **not a cryptographic verification of organizational approval**. EC208 verifies supplied Ed25519 cryptography against host-configured local key roles, not externally verified authority. There is no automatic publication, remote action, AI instruction execution, or promotions.

## Development verification and deferred joint acceptance

Focused disposable fixture cases include actual temporary Git commits and ephemeral target/baseline/reviewer/owner Ed25519 keys, one real EC205→206→207→208 chain, original EC202 content projections, private version lineage re-authorization, stale head rejection, restricted-read denial, missing EC205 mapper, EC210 forbidden `DocsOnlyPublish`, and no source or business Git mutation. These are **development examples**, not live organization acceptance.

**NOT_RUN:** native PowerShell7 and original 15 Smoke, real organizational signer issuer/key custody/revocation/knowledge-owner receipts, independently authenticated real provider/CI/delivery, cross-process/NFS/Windows/macOS crash/race adversarial scenarios, external AI, semantic chapter review, actual authoritative source publication, E63–E66 resource checks and unified user-assisted acceptance. The original frozen V3.10/ROUNDS evidence B-001 remains OPEN.

Further construction starts at **EC211**, explicitly separate Issue-provider work. Do not infer EC211 is already implemented.
