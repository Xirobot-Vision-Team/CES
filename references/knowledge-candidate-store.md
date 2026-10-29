# EC206 — Private quarantined candidate knowledge (standalone Python)

**Only one EC:** this local feature separates draft claims from CES authoritative knowledge; it does **not** implement `knowledge_update` Handoff (EC207), KnowledgeSave/versioned authority (EC208), promotion, publication, Issue edits, remote writes or a native PowerShell Knowledge action. All successful operations return `partial/2`. A reported signed local target is *not* proof of deployment or semantic architecture truth.

## Storage and security model

- Entry: [`KnowledgeCandidateStore`](../construction/knowledge_candidate_store.py). Requires an operator-provisioned **pre-existing empty owner-owned 0700 POSIX directory** at an absolute normalized root. Repository root, CES knowledge root and candidate root are explicit and pinned by device/inode; reject nested/overlapping candidate areas and root replacement. `O_NOFOLLOW`, dirfd-relative `O_EXCL`, file owner/private permissions, single-link records, `flock` and per-store fsync protect ordinary local operations. Unsupported POSIX guarantees fail closed, not emulated insecurely. Never alter any upstream repository or CES knowledge snapshot.
- `initialize(allow_initialize=True)` is the only initializer and **does not grant future append/read permissions**. Stores are fixed to `store_id`, repository/knowledge paths and identities, repository ref, knowledge-space key, period ID and source-policy revision. Re-initialization and unrecognized layouts fail closed. Creation is fail-closed but nontransactional across the three initial files: if it aborts, inspect/move the incomplete private directory manually; never overwrite it automatically.
- `preview(proposal_json=..., source_result_json=...)` is a **read-only grant-binding preview** (candidate body omitted). `append(..., append_policy_json=...)` performs a real local append **only** after a distinct canonical, exact candidate/instance/scope-bound policy grants the candidate origin and private claim storage. Restricted content requires an additional `permit_restricted_claim_store`. Permission-receipt SHA is a **caller/operator assertion, not a verified signature or independent identity proof**; put this API behind an authenticated host authorization service before treating approvals as organizational grants.
- Exactly one immutable file per `candidate_key`; same proposal+same upstream input is an idempotent no-write retry, different text/scope/provenance/observation with the same key is a conflict. To propose a correction or new evidence, use a **new candidate key**, not an overwrite. Records are canonical, bounded (256 per store, 32 KiB per record), owner-private (0600), locally HMAC-guarded and rechecked before read/write. Local HMAC is corruption protection using a local key, **not** an external signature, audit service or protection against the storage owner's intentional alteration. Unexpected records, corrupt MACs, symlinks/hardlinks and modified source-root identities close the store.
- `read(candidate_key=..., read_policy_json=...)`: exact key and immutable record-binding grant. Metadata-only is possible; provenance/source identifiers require an additional grant (and an extra restricted-provenance grant for `RESTRICTED` candidates); text requires `permit_claim_content_read`, and restricted text additionally `permit_restricted_claim_read`. No default text projection. `list_binding_preview()` exposes only the *store*-bound list authorization hash, while `list_keys(list_policy_json=...)` needs a separate explicit list grant and returns keys only. Neither one exposes claims, nor does the store offer generic file/path lookup.

## Proposals and provenance

The canonical JSON proposal schema is [knowledge-candidate-proposal](knowledge-candidate-proposal.v1.schema.json). It requires `candidate_key`, repository/knowledge/period/policy scope, `request_binding_sha256`, `scope_binding_sha256`, `source_key`, optional `section_ref`, `origin`, bounded `claim_text` / `reason_text`, `sensitivity` (`INTERNAL` or `RESTRICTED`), `proposer_key` and declared `proposed_at_utc`.

| `origin` | `source_result_json` | Selection condition | Trust state |
|---|---|---|---|
| `ec205_chapter_mapping` | Complete canonical `ces.knowledge_chapters.v1` partial result from EC205 `map_chapters` | Exact `section_ref` + association `source_key` from a selected, scanned chapter | Existing authored chapter/source association; human review required; not semantic staleness proof |
| `ec204_selected_change` | Complete canonical `ces.knowledge_impact.v1` partial result from EC204 `analyze` | Exact selected repository source-change key; no claimed chapter section | Selected Git change/unknown observation; no chapter effect or deployment claim |
| `manual_proposal` | **None** | Nonempty declared source key and no section ref | Unverified manual assertion; no delivered-source evidence |

The supplied upstream result's top-level canonical subject, schema/status/exit code, asserted limitations, model revision, source/request/period/scope pins and selected entry are checked for **internal consistency**. The full upstream result is **not stored**: only its exact SHA-256, selected observation class/delivery label, and the proposed claim/section/source identifiers are stored. The caller must keep the source result separately if later review needs to reconstruct it. It is still *caller-supplied* input, not an independently authenticated/replayed EC204/205 execution: even a `SUPPLIED_RESULT_REPORTS_SIGNED_LOCAL_TARGET` label never upgrades the candidate to delivered truth. For authoritative provenance, obtain/replay EC204/205 via the existing host-trusted path separately and attach its approved receipt at a later EC.

Every record remains `AWAITING_HUMAN_REVIEW` with explicit `candidate_is_authoritative=false`, `source_result_authenticated_by_store=false` and `publish_or_promotion_performed=false`. No APIs for approving, promoting, replacing or deleting authoritative knowledge are present.

## Operator call sequence

```python
from knowledge_boundary import canonical
from knowledge_candidate_store import KnowledgeCandidateStore

# Provision private_dir yourself, outside both existing roots:
# mkdir -m 700 /private/location/knowledge-candidates
store = KnowledgeCandidateStore(
    root='/private/location/knowledge-candidates',
    store_id='architecture_review',
    repository_root='/absolute/path/to/repository',
    knowledge_root='/absolute/path/to/ces-knowledge',
    repository_ref='cesrepo1:' + '1' * 64,
    knowledge_space_key='architecture', period_id='period2026',
    source_policy_revision='policy-v1')
init = store.initialize(allow_initialize=True)
# Verify init['status'] == 'partial'; this does not permit append.

# Supply a canonical proposal with all required schema fields, using actual
# request/scope bindings and source_key/section_ref from the upstream result.
# For EC204/205 also supply the COMPLETE canonical result JSON (not its subject
# alone). For manual proposals pass source_result_json=None.
preview = store.preview(proposal_json=canonical(proposal),
                        source_result_json=canonical(ec205_result))
# Obtain an independently approved, exact-bound policy from the host/operator;
# the following payload must conform to append policy schema. Do not treat
# the preview hash or a self-declared receipt SHA as authorization by itself.
saved = store.append(proposal_json=canonical(proposal),
                     source_result_json=canonical(ec205_result),
                     append_policy_json=canonical(host_approved_append_policy))
```

In a real integration, host policy issuer must check exact candidate binding, source read/sensitivity rights, operator identity and revocation before filling the append/read policy. See the strict [append](knowledge-candidate-append-policy.v1.schema.json), [read](knowledge-candidate-read-policy.v1.schema.json), [list](knowledge-candidate-list-policy.v1.schema.json) policies and [result contract](knowledge-candidate-result.v1.schema.json). The module does not offer a CLI that could silently invent these permissions.

## Development feedback and deferred assisted acceptance

`cd construction && python -m unittest -q test_knowledge_candidate_store.py` exercises disposable POSIX private directories and a real EC205 temporary Git/snapshot/ephemeral-signer fixture. It verifies actual append/idempotency, content-sensitive reads, source-selection binding, source/knowledge separation, concurrent same-key appends and corruption/symlink denials. This is **development feedback**, not native PowerShell7/15 Smoke, enterprise signer/role/owner/revocation, provider/delivery, OS/NFS/race, E63–E66 performance, or final assisted acceptance. If POSIX/cryptography dependencies are missing, record the unavailable checks as **NOT_RUN**; do not claim a pass.

Do **not** assume a private candidate HMAC authenticates an actor, an approval, a historical CES knowledge version, an EC204/205 result, or actual production delivery. EC207 will take quarantined candidates into a proposed AI handoff; EC208 must independently implement versioned authoritative KnowledgeSave with human approval and conflict controls.
