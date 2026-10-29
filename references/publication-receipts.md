# EC230 — independent publication receipt and fail-closed cleanup

**Standalone implementation:** `construction/publication_receipts.py`.
**Output schema:** [`publication-receipt-result.v1.schema.json`](publication-receipt-result.v1.schema.json).
**Build:** V5.40/R230. **Scope:** EC228 single-private-Provider report attempt and EC229 offline-private-Git new-ref operation **only**. **No native PowerShell action**, public release, original POST/push retry, production access, remote mutation or original journal removal.

## 1. Trust model and what it does (and does not) prove

Every inspection first reconstructs the exact **original** operation from its original request, original independently signed documents, original source/target pins, and original code hash. EC228 reopens EC199/EC200 latest version's stored immutable report/read policy and checks the five original signatures under the exact original host keys. EC229 rechecks the exact reviewed Markdown bytes, new-path allowlist, baseline Git root/identity, repo policy, reviewer, revocation and original grant under four original distinct keys. It reads the old `ec228-<op>` or `ec229-<op>` durable journal **without changing it** and rejects missing/extra/inconsistent markers and conflicting commit hashes.

**Important provenance limit:** EC228 and EC229 original journals record operation IDs and stage markers **but no immutable original signed-grant digest or trusted wall-clock at the effect edge**. EC230 can validate the actual old statements' cryptographic consistency and overlapping declared issuance windows; it **cannot independently prove** those exact signed grants were the ones seen at execution time, that their signers were genuine enterprise employees, that the original clock was correct, or that a journal survived snapshot rollback. A different signed grant for the same immutable operation cannot be distinguished solely by the historical journal. `original_grant_sha256` in the EC230 audit means “these revalidated original signed papers,” not a retroactively discovered EC228/229 journal field. Actual full authorization/audit provenance must be externally checked during final acceptance. EC230 **never** fabricates trusted timestamps or overwrites history to fill this gap.

An inspection additionally needs a **fresh independent EC230 read signature**; cleanup needs a **different independent EC230 custodian signature**. These two 32-byte Ed25519 roots must differ from one another **and from all four/six original signing roots** relevant to that operation. The organization, not the package, provisions these real keys and authenticates their owners. Signatures prove byte-consistency with a trusted key, **not** human review or issuer affiliation without that external control. Source code hash pins the running EC230/EC228/EC229 modules and signing/canonicalization helpers; no key or credential is included.

The owner-private **separate** POSIX `0700` EC230 audit root holds fsynced append-once `ec230-read-<inspection_id>` or `ec230-clean-<operation_id>` slots. Each inspection has a fresh signed nonce and a durable claim/attempt marker written **before** Provider GET or local Git read. Audit `02_OBSERVATION` records only SHA-256 identifiers, state and time; never raw Markdown, report content, token or signatures. A crash/ambiguous request consumes that nonce: **no automatic retry**. A fresh independently approved read may have a new nonce, but never resends the original EC228 POST or EC229 push. Audit directories are forbidden from overlapping source, journal, worktree, bare or report store.

## 2. Readable host interface

```python
from construction.publication_receipts import (
    ReceiptRoots, HostReceiptScope, PublicationReceiptService)

host = HostReceiptScope(
    roots=ReceiptRoots(
        read_public_key=b"<independent 32-byte EC230 read root>",
        cleanup_public_key=b"<different independent 32-byte custodian root>",
        minimum_receipt_epoch=10,
    ),
    audit_root="/private/ces-ec230/audit",       # precreated, 0700, durable POSIX
    enable_readback=True,
    enable_clean_linked_worktree=False,
    provider_read_credential="<separate, read-only Provider status token>",
)
service = PublicationReceiptService(host)

# Original reports/access are the exact signed EC228 request and original
# host scope, NOT a new publication request. Both modes need new read_grant.
result = service.inspect_report(original_ec228_request, original_ec228_access,
                                fresh_ec230_read_grant)
# No Provider POST. Fixed authenticated HTTPS GET only.
result = service.inspect_docs(original_ec229_request, original_ec229_access,
                              fresh_ec230_read_grant)
# No Git push or ref mutation. Exact local bare readback only.

# For already independently VERIFIED_PRIVATE_LOCAL_REF_ONLY readback,
# obtain a separately signed custodian grant *after* inspecting exact inode.
# Only then enable host.enable_clean_linked_worktree and call:
result = service.cleanup_docs(original_ec229_request, original_ec229_access,
                              inspection_id, fresh_ec230_cleanup_grant)
```

`b"<...>"` in the example is **not** a working Ed25519 key. To use a real host, supply actual raw keys and real current signatures from independent provisioning. Importing/constructing the service never auto-publishes, deletes or changes Git. Reconciliation/cleanup do not require re-enabling EC228/229 submission switches: the independent fresh EC230 switch and permission control readback/cleanup.

### Fresh read statement

`SignedAuthorizationStatement` (existing EC224 envelope) must have **only**:

| Required field | Value |
| --- | --- |
| `schema` | `ces.publication_receipt.read_grant.v1` |
| `mode` | `EC228_PRIVATE_REPORT` or `EC229_PRIVATE_DOCS` |
| `operation_id`, `target_sha256` | reconstructed immutable original exact operation and exact original private target hash |
| `original_grant_sha256` | canonical SHA-256 of verified original EC228/EC229 one-use statement |
| `inspection_nonce` | unique 32 lowercase hex; its spent audit entry persists |
| `receipt_epoch` | integer at/above host minimum |
| `code_revision_sha256` | `ACTIVE_CODE_SHA256` of *running* EC230 code |
| `permission` | `READ_ONE_PRIVATE_PUBLICATION_RECEIPT` |
| `issued_at`, `expires_at` | POSIX integer seconds; expires within <=40s; current at read edge |

Sign with the **EC230 read root** using `READ_DOMAIN + delivery_preview.canonical(statement)`. This original-operation/target/grant/code-bound read permission **cannot** be repurposed for a new publish, push, report send or cleanup. No user-controlled remote URL, Git path or arbitrary ref is accepted.

## 3. Independent Provider receipt — EC228

The **real** `HTTPSPrivateReceiptReader` performs one bounded GET only to the original host-pinned private endpoint:

`<EC228-approved HTTPS base>/receipts/<64-hex operation>?nonce=<32-hex fresh challenge>`.

A host-scoped *separate read-only credential*, not the original EC228 write/publish token, is required. System TLS trust is checked, redirects/proxies are refused, the timeout is 0.5–8 seconds and payload <=8192 bytes. No arbitrary path, URL, POST or fallback/second GET is allowed. The Provider **must implement this particular read-only route and JSON signed-envelope contract** for real use; CES does not claim a commercial provider already offers it. Strict duplicate-key JSON parsing and the original independent Provider public key protect the response; if the Provider cannot support it, the feature is `unavailable`, not simulated success.

The Provider returns `{"statement": {...}, "signature_hex": "..."}` with an Ed25519 signature over `PROVIDER_DOMAIN + canonical(statement)`. The strict `ces.publication_receipt.provider_observation.v1` statement fields are: `schema`, `provider_id`, `account_id`, `project_id`, `destination_id`, `target_sha256`, `operation_id`, `report_ref`, `rendered_sha256`, `challenge_nonce`, `record_state`, `record_id_sha256`, `private_sandbox`, `create_only`, `issued_at`, `expires_at`. These must exactly match original target, report, operation and this GET's random challenge. `record_state=CREATED_PRIVATE_TEST` requires a 64-hex SHA of the Provider's internal record ID; `NOT_FOUND` requires `null`. Both require `private_sandbox=true`, `create_only=true` and a currently valid <=30s signed window.

- `SIGNED_PROVIDER_PRIVATE_TEST_RECORD_OBSERVED` means one **signed provider assertion** about one created *private test* record, **not** public visibility, external reader confirmation, legal publication or final production release. `partial/2`.
- `UNKNOWN_PROVIDER_REPORTS_NOT_FOUND` means only that the queried Provider **currently reports absence**; it is NOT proof that the original POST never reached its server, and never permits retry. `partial/2` for completed observation, with UNKNOWN state.
- An unsigned, expired, mismatched, conflicting or missing receipt, a timeout, parse error, or no durable `03_POST_ATTEMPTED` marker refuses, retains the old slot and never POSTs again.

No remote/provider deletion is ever implemented, even if a report is rejected or a record is known to exist. EC228's spent operation and stored report are immutable.

## 4. Offline local Git receipt — EC229

EC230 uses the original `RestrictedGit` subprocess wrapper with isolated config, no network protocols beyond local file Git, no hook activation and pinned real Git executable. It reads only `refs/heads/ces-docs-private/<operation>` in the **original pinned local bare test** and checks the commit has precisely the original approved base parent. `git diff-tree` must list *only* added exact reviewed Markdown paths; `git show` must return exactly the original reviewed UTF-8 bytes. The journal's `06_PUSH_ATTEMPTED` marker is required; both historical commit markers must match if present. A returned Git command code alone is **never** remote/public visibility proof.

- Verified ref: `VERIFIED_PRIVATE_LOCAL_REF_ONLY`, `partial/2`. This is a **local bare Git observation**, not a network remote receipt or public document release.
- Missing ref: `UNKNOWN_PRIVATE_REF_ABSENT`, `partial/2`. Absence **cannot** prove a lost/failed earlier push did not occur.
- Conflicting commit, missing/tampered marker, symlink/unsafe Git state or changed signed source: `blocked/4` or `unavailable/5`, with `UNKNOWN_UNCONFIRMED`. No repair, ref rewrite, second push or automatic cleanup.

The original source HEAD/index and worktree files are never changed by inspection. Git pack/objects may have been affected by original EC229 publish; that history is not hidden or removed by EC230.

## 5. Cleanup — conservatively restricted to one owned local worktree

There is **no generic file cleaner**, no arbitrary directory parameter, no provider cleanup and no remote branch/ref deletion. The only implemented deletion is a **separately requested clean Git linked worktree** `original_worktree_root/ec229-<operation>`, and **only after** an EC230 inspection of the exact private local ref has produced a fresh durable `02_OBSERVATION` with `VERIFIED_PRIVATE_LOCAL_REF_ONLY`. This means ambiguous/missing ref, crash during early worktree setup, dirty/staged/untracked worktree or incomplete original journal is **intentionally retained for manual examination**, even if failure cleanup would be convenient.

A custodian (different from read signer and all original keys) signs `CLEAN_DOMAIN + canonical(statement)` with exactly `schema=ces.publication_receipt.cleanup_grant.v1`, `mode=EC229_PRIVATE_DOCS`, original `operation_id`, `target_sha256`, `original_grant_sha256`, `inspection_id`, `observation_sha256`, confirmed `candidate_commit_sha`, **exact `[st_dev, st_ino]` `worktree_inode`**, `cleanup_epoch` >= host minimum, `permission=REMOVE_ONLY_VERIFIED_CLEAN_LOCAL_LINKED_WORKTREE`, current `code_revision_sha256`, `issued_at`, `expires_at` (<=40s). The recorded signed read must be recent (<=60s), consistent with original journal and still-present private ref, and the new cleanup consent must be current. No cleanup key is shipped.

Before effect, verifies all these positive conditions again: original repo clean/approved HEAD, Git config and original index SHA unchanged, exact Git metadata pointer into the original repo's `.git/worktrees`, unique detached matching `git worktree list` entry, exact candidate commit and doc bytes, clean worktree status and **filesystem-wide allowlist** of tracked regular non-hardlinked same-owner files (no ignored files, extra directories, symlinks or unexpected mounts). Then creates one durable **per-operation** cleanup slot and fsyncs its `01_ATTEMPT` **before** `git worktree remove -- <exact operation directory>` **without `--force`**. It checks worktree absence, original source integrity and unchanged private bare ref, then fsyncs `03_REMOVE_COMPLETED`.

It never deletes `ec228-*`, `ec229-*`, `ec230-*` receipts/journals, the private bare ref, any provider record, original source report or shared Git object database. It does remove only the unique linked worktree checkout and associated Git linked-worktree metadata. If any check fails or crash occurs after `01_ATTEMPT`, return UNKNOWN/unavailable and **never auto-retry cleanup**; an actual human must handle ambiguous cases outside this module. A Git worktree removal can make its detached HEAD unreachable from the source's object database, but the checked private bare ref remains a retention anchor for the candidate commit in that test repository.

## 6. Result and final acceptance

Every result conforms to the strict Draft2020-12 [`publication-receipt-result.v1.schema.json`](publication-receipt-result.v1.schema.json), with `status/exit_code` (`partial/2`, `blocked/4`, `invalid_input/4`, `unavailable/5`), `operation_id`, `inspection_id`, `observation_sha256`, conservative receipt state, and explicit boolean effects. **All cases** assert `public_or_production_published=false`, `external_publication_confirmed=false`, `original_post_or_push_retried=false`, `remote_ref_or_provider_content_deleted=false`, `original_journal_deleted=false`.

Local EC230 development exercises disposable real Git / original EC200 saved-report fixtures, synthetic Ed25519 signers and fake signed-GET. It is not a real organization's PKI, official Provider endpoint/ACL, privacy signoff, true Git branch protection, local physical crash/fsync or multi-host durability. A hostile process sharing the same UID, symlink exchange at a time-of-check/time-of-use boundary, network filesystem/snapshot rollback and actor-controlled Git/Provider implementation are **not** formally mitigated; operator must isolate same-UID access and use one local POSIX filesystem under exclusive host control. Before live use, obtain real approvals and inspect actual private Provider signed GET contract and read-only token ACL, no-prior-POST retries, Git history privacy, exhaustive filesystem race/NFS/OS variants, service credentials, error/recovery procedures and true external/public visibility evidence (which EC230 does **not** claim). Original PowerShell7/15 Smoke, E63–E66 and complete user-assisted final acceptance remain `NOT_RUN`. Original B001 V3.10/ROUNDS provenance gap remains OPEN.
