# EC-208 — KnowledgeSave: independently approved immutable local CES version metadata

**Bundle:** V5.18 / R208 / EC-208 (standalone Python; `scripts/ces.ps1` still V4.60/R150).  **Do not confuse an appended local version with a published, authoritative or factually verified knowledge document.**  This round implements the local version-append functionality and its authorization boundary, **not** a native PowerShell `KnowledgeSave` Action.

## Actual behavior and limits

`construction/knowledge_version_save.py` exposes `KnowledgeVersionSave`. It accepts a reviewed **complete replacement section in exact bytes**, its SHA-256, an exact current chapter baseline and predecessor receipt, the EC-207 Handoff inputs and all original EC-206 candidate-content/provenance read authorizations, an independent EC-208 write grant, and **two Ed25519-signed approval statements** from distinct registered public keys of different roles (`independent_reviewer`, `knowledge_owner`). It replays EC-207 rather than trusting a purported Handoff response, reads the real EC-202-style chapter manifest and Markdown twice with the existing nofollow local snapshot reader, and verifies selected candidate IDs and evidence SHA pins. Source/manifest trust and signer roles are **configured locally**, not certified by any online organizational directory.

For each store exactly one existing Markdown chapter is pinned. It uses a separate owner-private POSIX root **outside** the repository, knowledge source and EC-206 candidate store. Each successful `save()` issues a new `versions/00000001.json` (next `00000002.json`, etc.), created with `O_EXCL`, protected by a private `transaction.lock` (`flock`), canonical SHA-256, local HMAC integrity, fsync and immutable parent-version chain. It keeps the full approved request with exact replacement bytes and two original signed approvals alongside the full resulting chapter bytes (base64). On every read it verifies the complete chain, HMAC, exact rederived request authorization scope, Ed25519 signatures, parent hashes and one-section transformation. Original source Markdown and previous version records are **never rewritten**.

A save is restricted to a **single existing section**: it must retain exactly the original section heading/level, preserve all other section bytes and section count, and match the requested before-section, after-section and whole-chapter SHA-256. A known EC-205 `cesksection1:` reference is checked against the original chapter's section SHA, ordinal, EC-202 scope hash and explicitly presented EC-202 source binding. This is a consistency check, **not** independent proof of the authenticity of a caller-provided EC-202 source binding. For a second version, the original baseline still anchors the reference, while the current private parent version is the optimistic SHA check. If any source baseline/manifest or parent section changes, the operation refuses to append. EC-209 will separately address retry/rebase policies; do **not** automatically retry or reapprove changed content.

A whole-response status of `partial` and exit code `2` is intentional even when the local metadata append succeeded: this adapter has not verified organization authority, deployed architecture, external AI provenance, a business Git commit, a published knowledge file, an Issue or delivery. `unavailable`/`5` is a fail-closed denied/blocked/conflict or unknown I/O outcome; `invalid_input`/`4` means malformed input. The boolean `local_version_metadata_written` is the only local positive write outcome and applies only to this individual call. In case of file creation/interrupted I/O, `local_write_outcome_unknown=true` and the next action is **read-only inspection/human recovery**, not blind replay.

## Integration API

Use absolute, owner-only **existing** directories from a trusted local operator. The constructor accepts an already configured `KnowledgeCandidateStore` from EC-206; see [EC-206 storage guide](knowledge-candidate-store.md) and [EC-207 handoff guide](knowledge-update-handoff.md) for upstream permission setup. No command-line utility and no automatic key generation for a real organization are provided; embedding test keys into an application or ZIP is prohibited.

```python
from construction.knowledge_version_save import KnowledgeVersionSave

save_api = KnowledgeVersionSave(
    root='/private/ces_knowledge_version_metadata',   # precreated empty 0700, outside protected roots
    store_id='chapter_version_journal',
    candidate_store=existing_ec206_candidate_store,
    chapter_path='docs/architecture.md',              # exact existing EC202 manifest path
    trusted_approvers={
        'reviewer-key-id': {'role': 'independent_reviewer', 'public_key': reviewer_raw_ed25519_public_key_32_bytes},
        'owner-key-id': {'role': 'knowledge_owner', 'public_key': owner_raw_ed25519_public_key_32_bytes},
    },
    revoked_approvers=set(),
)

# Initialization is one explicit local write and does NOT grant saving rights.
init_result = save_api.initialize(allow_initialize=True)
# Separate read-only preview; take its exact authorization_scope_sha256 to both human signers.
preview = save_api.preview(request_json=canonical_save_request,
    handoff_request_json=canonical_ec207_request,
    handoff_policy_json=canonical_ec207_grant,
    candidate_read_policies_json=canonical_ec206_read_bundle)
# Only after independently authorized signatures and scoped EC208 save grant exist:
result = save_api.save(request_json=canonical_save_request,
    handoff_request_json=canonical_ec207_request,
    handoff_policy_json=canonical_ec207_grant,
    candidate_read_policies_json=canonical_ec206_read_bundle,
    save_policy_json=canonical_ec208_write_grant,
    approvals_json=canonical_two_human_approval_statements)
read_only_receipts = save_api.inspect()
```

Only `initialize` and **successful** `save` write to the dedicated local metadata root; `preview` and `inspect` make no writes. There is no native `-Action KnowledgeSave` and no AI call. The caller must secure signer private keys, actor identification, revocation updates and any future authority/publish operation independently.

## Strict inputs and cryptographic binding

- `knowledge-save-request.v1.schema.json`: the **complete exact edited section bytes** in `replacement_section_base64` (no patch commands), `replacement_section_sha256`, `expected_new_chapter_sha256`, `expected_section_sha256`, parent and full original manifest/chapter fingerprints, `section_index`, optional matching `section_ref` and `ec202_knowledge_source_binding_sha256`, selected EC-206 candidate keys and immutable record IDs, EC-207 `selection_binding_sha256` and `ai_input_sha256`, one `save_key`, and a review summary. **The reviewed text is separately supplied; EC-207 itself only supplies untrusted draft evidence and cannot auto-generate an approved replacement.**
- `knowledge-save-policy.v1.schema.json`: **exact** local store instance and store scope, matching `authorization_scope_sha256`, receipt SHA and positive `permit_local_version_append` + `permit_reviewed_text_local_persistence`; additionally `permit_restricted_local_persistence=true` when EC-207 selected records are restricted. Source overwrite, business repository, provider/Issue and publish flags **must all be false**.
- `knowledge-save-approvals.v1.schema.json`: exactly two signed statements in order: independent reviewer, knowledge owner, with distinct keys and distinct Ed25519 public bytes. Each statement includes exact authorization scope, a non-promotable explicit approval decision, UTC issuance and expiry (max 24h), and signature of raw bytes `b'CES-EC208-KNOWLEDGE-SAVE-APPROVAL-v1\0' + canonical(statement).encode('ascii')`. The operator must **not** generate approvals on behalf of real human signers. This is not a source of organizational credentials or identity enrollment.
- `knowledge-save-manifest.v1.schema.json` and `knowledge-save-record.v1.schema.json`: immutable local-only metadata format. The registry digest binds the full configured role-to-public-key mapping and revocation set at initialization; if keys/revocation change, the store refuses operations pending an **explicit future migration/authority design**. Do not silently edit stored manifest/records to rotate keys. Both owner-only ACLs and a trusted local host are prerequisites; local HMAC does not protect against a malicious user with control of the metadata root and entire trust configuration.
- `knowledge-save-result.v1.schema.json`: structured read-only receipts, deny reasons and strictly negative claims for external/authoritative effects. It deliberately **does not** project raw reviewed replacement bytes through a result.

Read full content only from an approved version record stored on the private local root with appropriate host filesystem access; the read-only API intentionally returns only SHA/IDs. Each record holds potentially sensitive full chapter text and original approval assertions. Store and back it up accordingly (encryption at rest/backup custody not provided). Obvious embedded credential patterns are refused using the existing EC-207 narrow detection; this is **not certified DLP**. No claim of broadly complete sensitive-data scanning.

## Source assumptions, failure modes and exact status

The knowledge source must have a real `ces-snapshot.v1.json` with `complete_declared` coverage and one exact existing Markdown chapter file, matching its declared size and SHA. All pinned repository/candidate/knowledge/store roots must be stable, disjoint and owner-controlled. POSIX private dirfd/O_NOFOLLOW/flock/fsync and the `cryptography` Ed25519 verifier must be available; an unsupported host fails closed. A source file changing after a double-read or concurrent parent advancing is a **refusal**, not an automatic rebase or resolution. Same `save_key` plus exact request, receipt and approvals can produce an idempotent no-write result; reusing the key with different content or signer assertions is a refusal.

Maximums: **1 chapter per store**, **64 versions**, **16 KiB per chapter**, **1 reviewed section changed per version**, **1–8 EC-206 candidates** via EC-207; bounded request/policy/approval/record bytes. Returns an `unavailable` result if record count or content is too large. No attempt is made to infer a missing authorized chapter, fill factual gaps from the model, discover unrelated knowledge files, or update Git.

`construction/fixtures/ec208/README.md` describes **disposable** end-to-end fixtures and checks. **Final assisted acceptance remains NOT_RUN**: native PowerShell/15 Smoke, real signer identity and revocation authority, production snapshot ownership, cross-process/racy filesystems/OS/NFS, source truth and DLP, performance E63–66 and downstream publish/Issue/provider. EC-209 is a distinct planned change for conflicts/retry; EC-210 plans end-to-end read/update linkage. B-001 upstream V3.10/ROUNDS provenance gap is still open.
