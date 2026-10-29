# EC207 — Locally authorized `knowledge_update` AI draft Handoff

**Scope:** standalone Python `construction/knowledge_update_handoff.py` (V5.17 / R207). It converts **selected, immutable EC206 quarantined candidate records** into a bounded *local-only* AI-ready **unverified draft input**. It does not call an AI provider, invoke legacy EC174's unsupported `knowledge_update` route, save a knowledge version, approve evidence, transfer data outside this process, edit business Git, create an Issue, or publish. A return value is **not** an AI answer. The native PowerShell Knowledge/AIHandoff modes remain unimplemented where previously unimplemented.

## Operator workflow and exact grants

1. Provision and initialize an EC206 owner-only private POSIX candidate store as described in [EC206](knowledge-candidate-store.md). Append EC205 selected chapter/source mapping candidates, EC204 selected Git change candidates, or explicitly marked manual assertions **using their own EC206 append grants**. Every stored record remains `AWAITING_HUMAN_REVIEW`; caller-supplied EC204/205 results and permission receipt SHA do not attest organizational truth.
2. Construct a canonical [request](knowledge-update-handoff-request.v1.schema.json), with exact store repository, knowledge space, period, source policy revision, `task_kind=knowledge_update`, unique operator `handoff_key` and **1–8 sorted unique candidate keys**. No general search, arbitrary relative paths or cross-store aggregation exists.
3. Invoke `KnowledgeUpdateHandoff(store).binding_preview(request_json=...)`. This opens the actual EC206 store and validates immutable records, scope and local HMAC under a shared read lock. It returns an exact selection digest, each record ID/candidate binding/EC206 read-authorization digest, and an EC207 Handoff authorization digest, **without any claim, proposer, sensitivity or source text**. Preview is **not** authorization or a promise that the operator may disclose data; restrict this call to a host-authorized list of known candidate keys.
4. Independently authorize **the entire exact selection** with an [EC207 Handoff policy](knowledge-update-handoff-policy.v1.schema.json): allow draft preparation, selected-record provenance and text; grant `permit_multi_candidate_draft` when more than one; grant `permit_restricted_local_draft` for any restricted record. Set all external AI transfer/execution, KnowledgeSave, knowledge/repository/Issue write and publish intents to `false`. The caller's `permission_receipt_sha256` is just an identifier; only a trusted external host can check human/role/revocation.
5. Independently issue an **EC206 read policy per selected record**, tied to its exact `candidate_binding_sha256`, instance/scope/record-key read authorization digest. Both `permit_claim_content_read` and `permit_provenance_read` must be true. `RESTRICTED` records additionally require separate EC206 restricted claim and restricted provenance grants. Encode the exact policies as a canonical [candidate reads bundle](knowledge-update-handoff-candidate-reads.v1.schema.json), with precisely the selected keys.
6. Call `prepare(request_json=..., handoff_policy_json=..., candidate_read_policies_json=...)`. It repeats all EC206 record integrity/scope checks under **one store lock**, evaluates every per-candidate read grant plus EC207's independent all-selection policy, then emits strict [result](knowledge-update-handoff-result.v1.schema.json) `partial/2`. If any candidate, scope, selected version, grant, restricted scope, or data safety check fails, the entire response has `subject=null`; **no partial disclosure**. It never reads raw knowledge files or repository code.

Illustration (grant issuance intentionally **not** faked or automated):

```python
from knowledge_boundary import canonical
from knowledge_candidate_store import KnowledgeCandidateStore
from knowledge_update_handoff import KnowledgeUpdateHandoff

# Operator must supply an already-initialized EC206 store and real authorized,
# canonical request and policies after host-side identity/revocation checks.
handoff = KnowledgeUpdateHandoff(store)
preview = handoff.binding_preview(request_json=canonical(host_selected_request))
# preview['subject']['candidate_record_pins'] supplies per-record read binding
# info, while EC206's authorized operator supplies provenance/sensitivity rights.
prepared = handoff.prepare(
    request_json=canonical(host_selected_request),
    handoff_policy_json=canonical(host_approved_ec207_policy),
    candidate_read_policies_json=canonical(host_approved_ec206_read_policy_bundle),
)
# Do not send prepared['subject']['ai_input'] to a model automatically.
```

## Draft content semantics

- `ai_input` separates **fixed safety instructions** from **untrusted candidate_evidence** so proposal text cannot configure the action route or execution rights. Each candidate carries an immutable `record_id`, candidate binding, `source_key`, exact upstream `source_result_sha256` (when available), selection type, EC206 observation labels, `AWAITING_HUMAN_REVIEW`, source and quarantine times explicitly marked unverified, bounded claim/reason text and per-record uncertainty flags. Maximum eight records, original EC206 claim <=4 KiB each, reason <=1 KiB, response canonical subject <=64 KiB. A defensive pattern blocks several obvious secret/key formats before any text release, **not** a full DLP guarantee.
- EC205 provides only `cesksection1:<digest>` **section_ref** (computed at the EC205 observed snapshot); it is a local byte-bound fingerprint *reference*, **not** the raw `section_sha256`, currently existing chapter text or a valid destination for overwrite. EC206 did not preserve those bytes. EC204 selected Git provenance does **not** supply chapter mapping, and manual claims lack independently selected Git evidence. Do not invent any.
- Multiple claims about the same `source_key` and `section_ref` are kept separately with `potentially_conflicting_associations` — no silent merger or semantic consensus. All candidates must refer to the **same exact** EC202 `request_binding_sha256` and `scope_binding_sha256`, besides the EC206 store's fixed repository ref, knowledge space, period and source policy. Cross-request/source-scope mixing is denied.
- `ai_input.requested_ai_output` describes *proposed edits for human review*, anchored to candidate/record/source SHA/section refs with open uncertainties. The output has `verified_delivered_facts=[]`, `knowledge_sections_to_update=[]`, `knowledge_update_authorized=false`, `approval_state=AWAITING_INDEPENDENT_HUMAN_REVIEW`, and explicit no-write/no-AI flags. No AI output is received, executed or authenticated by this code.

## Security, limitations and deferred verification

The EC206 HMAC checks local record consistency, not independent creator identity, immutable disk custody against the store owner, or the authenticity of EC204/205 sources. SHA receipts/selection digests bind exact bytes/records but **do not authenticate the authorization issuer**, human review approval or organizational permissions. The host must independently validate identity, role, revocation, source freshness and approved AI egress/sensitivity before *any external transfer*. EC207 explicitly denies external transfer policy, even if an application could manually copy its local output. Reviewers must not treat an AI suggestion as a certified architecture fact or accepted knowledge revision; EC208 KnowledgeSave requires its own independent version pin/approval/save transaction.

Focused development scenarios: `cd construction && python -m unittest -q test_knowledge_update_handoff.py`. These run actual disposable POSIX EC206 records, grants, mixed-scope denials, restricted disclosure, tampered records, exact digest selection, source type handling and strict Draft2020-12 contract samples. They do **not** replace native PowerShell7/original 15 Smoke, real org signer/grant/revocation, live Git delivery or authoritative knowledge ownership, AI/provider/network integration, multi-OS/NFS/hostile concurrent filesystem, E63–E66, or final user-assisted acceptance. **B-001** original V3.10 frozen evidence gap stays open.
