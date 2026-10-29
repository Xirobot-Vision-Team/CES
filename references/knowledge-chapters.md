# EC205 - Existing knowledge chapters and bounded source differences

**Construction V5.15 / R205 / EC205.** This is a callable **standalone read-only Python implementation**. It is not a registered PowerShell Knowledge action, AI Handoff, candidate store, KnowledgeSave, live organization authorization, or publication mechanism.

## 1. What this actually does

`construction/knowledge_chapters.py` provides `KnowledgeChapters.binding_preview(...)` and `KnowledgeChapters.map_chapters(...)`. Each mapping call:

1. Parses the *exact* EC202 request, EC202/203/204 upstream policies, signed EC203 target document, optional EC204 signed baseline document, and a **separate EC205 chapter read policy**. Checks request, repositories, period, all previous policy byte/domain bindings, roots, host-configured signer registries, and a complete per-selected-source grant table. The SHA receipts are identifiers, **not cryptographically authorized user identities**.
2. Reads the selected knowledge manifest/files twice through EC202, with an **additional reduced local read policy** so EC205's two mapping reads never read business/repository file bodies and do not fetch chapter content denied by the EC205 per-document grant. EC204 still independently replays its **original, unmodified** EC202/203 policies and actual source/Git verification. Both knowledge reads are checked for identical manifest metadata and byte-bound EC202 knowledge source references; drift invalidates chapter associations.
3. Independently reruns the **real EC204 `KnowledgeImpact.analyze()`** (which itself reruns actual signed EC203 verification), never accepts an untrusted caller-provided `changed=true` or previous JSON result. At the end of the extra chapter read, again verifies host root/Git config bindings and the exact Git target ref. If this check fails, all previously verified `source_changes` are downgraded to UNKNOWN before chapter risk classification.
4. Parses only individually authorized, manifest-matched UTF-8 `.md`/`.markdown` snapshot documents (up to 16 KiB each). Splits into exact-byte ATX `#`..`######` sections; no-heading documents produce one preamble section. Ignores fenced code, inline code and multiline HTML comments. The **only** associations recognized are the strict authored annotation below or Markdown hyperlinks to an *exact full selected repository relative path*. Basename, keyword, fuzzy similarity, unselected paths, arbitrary URL, or an AI guess do not qualify.
5. Projects just the explicitly associated sections; unrelated sections are **counted but not disclosed or changed**. Each reported section carries a byte-bound `cesksection1:` reference, optional opt-in heading/hash, exact source keys, EC204 source delta evidence, separately gated source fingerprint comparison, potential staleness signals, and manual-review flags. Reports missing/unauthorized/unknown link coverage without inventing a mapping.

## 2. Existing-document syntax

Within the relevant section in a selected CES knowledge Markdown file, use either an author-supplied explicit annotation:

```markdown
# Architecture

## Module A
<!-- CES-SOURCE source_key=repo_module_a -->
The old description of the module.
```

or an exact Markdown link to one of the already authorized EC202 `repository` source paths:

```markdown
## Module A
See the example module `src/module_a.py` (not a bundled CES source file).
```

A snapshot may additionally contain a **declared, untrusted source digest**:

```markdown
## Module A
<!-- CES-SOURCE source_key=repo_module_a source_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -->
```

The example digest is a placeholder, **not evidence**. This third form enables a `DOCUMENTED_FINGERPRINT_MATCHES_TARGET` / `...DIFFERS_FROM_TARGET` comparison **only if** EC203 `permit_source_digest_projection`, EC204 `permit_change_digest_projection` and EC205 `permit_reference_digest_comparison` all agree. A mismatch proves only that *authored text declares a fingerprint different from actual selected target Git bytes*. It does not establish when the chapter was written, historical Git content, an incorrect architecture statement or an approved edit. The raw asserted digest is never projected by EC205.

Only same-section explicit references are linked; a marker on a parent heading is **not inferred** to apply to every nested heading. Unknown marker keys remain `unresolved_explicit_references`, without echoing unselected or unauthorized keys. Malformed markers and conflicting digests generate uncertainty/review signals, not new source authorizations. Plain Markdown links outside the exact set are unrelated, and example links inside code/HTML comments are ignored. Cross-root relative links such as `../src/foo.py` are intentionally unsupported: provide an explicit `CES-SOURCE` annotation instead.

## 3. Host API and policy issuance

```python
from knowledge_boundary import canonical
from knowledge_chapters import KnowledgeChapters

api = KnowledgeChapters(
    repository_root='/independently-configured/local/repository',
    knowledge_root='/independently-configured/private/knowledge',
    repository_ref='cesrepo1:' + '1' * 64,  # illustrative logical ID
    target_ref='refs/heads/main',
    trusted_target_keys={'delivery-authority': target_ed25519_public_bytes},
    trusted_baseline_keys={'historical-authority': baseline_ed25519_public_bytes},
)

pins = api.binding_preview(
    request_json=canonical(ec202_request),
    bootstrap_read_policy_json=canonical(ec202_read_policy),
    target_read_policy_json=canonical(ec203_target_read_policy),
    impact_read_policy_json=canonical(ec204_impact_read_policy),
    target_statement_json=canonical(ec203_signed_target_statement),
    baseline_statement_json=canonical(ec204_signed_baseline_statement),
)
# Host authorization layer checks real identity/permission independently, then
# issues a strict EC205 policy using all pins and an exact per-source grant list.
result = api.map_chapters(
    request_json=canonical(ec202_request),
    bootstrap_read_policy_json=canonical(ec202_read_policy),
    target_read_policy_json=canonical(ec203_target_read_policy),
    impact_read_policy_json=canonical(ec204_impact_read_policy),
    chapter_read_policy_json=canonical(ec205_chapter_read_policy),
    target_statement_json=canonical(ec203_signed_target_statement),
    target_signature_base64=target_signature_base64,
    baseline_statement_json=canonical(ec204_signed_baseline_statement),
    baseline_signature_base64=baseline_signature_base64,
)
# Bounded observation: status=partial, exit_code=2; not success/delivery/save.
```

See [strict EC205 chapter policy schema](knowledge-chapter-read-policy.v1.schema.json) and [result schema](knowledge-chapters-result.v1.schema.json). Source grants are ordered exactly as EC202 `sources`, with `source_key`, `source_binding_sha256`, `permit_section_mapping`, `permit_repository_association`, and `read_receipt_sha256`. A mapped knowledge source requires all of: original EC202 knowledge+manifest+raw-content permissions, per-document EC202 read/content grant, EC205 per-document grant/receipt, and an exact manifest-valid source. Repository link association requires its own EC205 per-repository grant/receipt. EC205 document title and chapter SHA are separately gated; chapter SHA projection requires EC202 provenance permission. All write/publish/Issue flags must be **false**; no returned metadata confers permission to edit content.

## 4. Reading results and conservative boundaries

- `manual_review_candidate_sections` counts **existing explicitly linked sections** whose selected source changed, documented digest differs, marker claims conflict, or source evidence is UNKNOWN. This is a **triage suggestion**, not a fact of semantic staleness or instructions to rewrite.
- `staleness_signal` distinguishes changed selected Git content, mode-only change, untrusted documented fingerprint mismatch/match, no selected change, and unknown source evidence. **No status says a chapter is objectively stale.** `snapshot_recency_signal` compares the local snapshot's *self-declared* timestamp to the host-key-verified target statement timestamp; it is **not** a certified snapshot capture event.
- `knowledge_snapshot_stable_across_read` and `target_ref_post_chapter_read_state` only describe bounded local read/recheck observations, not future stability. A changed snapshot produces no chapter matches; a changed Git ref removes all verified chapter change classifications.
- `unrelated_sections_not_projected` protects unrelated chapter bodies. `unmapped_changed_selected_source_keys` lists only sources with an independent EC205 repository-association grant and a selected EC204 verified actual source change; it is **not** a list of all changed files.
- `whole_knowledge_space_linkage_complete=false`, `semantic_chapter_differences_verified=false`, `knowledge_update_authorized=false`, `knowledge_sections_to_update=[]`, and `verified_delivered_facts=[]` are invariant. Even a fully observed selected manifest cannot prove complete knowledge coverage or current architecture. No old knowledge version exists in EC202, so there is **no real before/after knowledge text diff** in EC205.

Errors follow existing CES semantics: partial/2 for bounded observations, invalid_input/4 for malformed documents/request shapes, unavailable/5 for insufficient permission/source/binding. Individual unparseable/oversized/changed documents degrade to `UNKNOWN_*` without contaminating separately verified other sections. Unsupported formats are never parsed as Markdown. No write operation, Git fetch, hook execution, external network, model call, candidate isolation, section update or native CLI route is performed.

## 5. Verification scope and remaining work

The included `construction/test_knowledge_chapters.py` uses disposable SHA-1 Git commits, ephemeral local Ed25519 target/baseline signatures, and actual temporary POSIX CES knowledge bytes. It covers explicit/missing/conflicting links, stale pins, content grants, snapshot edits, in-flight Git ref movement, Markdown example exclusion, digest redaction and strict Draft 2020-12 contracts. These are **development tests only**.

The unrun consolidated acceptance remains: real organization signer roles/revocations, independently validated grant issuers, actual delivery history and knowledge governance, provider/AI/CI, malicious filesystem/ref races and non-POSIX behavior, native PowerShell7/original 15 Smoke, E63-E66 resource tests, original frozen-source B-001 provenance and final user-assisted acceptance. EC206 is the **future quarantined candidate store**; EC207 Handoff, EC208 KnowledgeSave, native route and publishing are future work and must not be presented as EC205 capabilities.
