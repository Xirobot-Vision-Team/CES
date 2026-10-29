# EC229 — DocsOnlyPublish: isolated Git worktree and private offline ref

**Implemented:** `construction/docs_only_publish.py`, `DocsOnlyPublisher.publish_once`.
**Result schema:** [`docs-only-publish-result.v1.schema.json`](docs-only-publish-result.v1.schema.json).
**Scope:** one separately approved **new Markdown-only local-sandbox publication**.
**Not implemented:** any public/production network push, existing Git ref or
document replacement, remote-readback/receipt/cleanup (EC230), integrated
PowerShell action, GitHub/GitLab/CI API, or enterprise PKI provisioning.

This is a local Git feature, not an email/report publisher, Git PR/MR approval,
native CLI command, document editing of a customer's source worktree, or
permission inherited from EC228 ReportPublish.

## What actually happens

1. A trusted host supplies a **real POSIX Git repository** with directory and
   `.git` directory both owned by the current user, an **exact approved SHA-1
   commit**, a sorted tuple of **explicit Markdown path names**, and three
   separate existing owner-private `0700` directories: worktree parent,
   one-use journal parent, and a separate offline **bare test repository**.
   The bare test repository must already be initialized by the host. It is
   not a production remote and must not contain active hooks.
2. Four independent, non-overlapping **Ed25519 public keys** are host-pinned:
   repo/path/target privacy policy; separate reviewer of the **exact raw
   Markdown bytes**; current grant-nonce/epoch revocation status; and a
   one-use local Git publication permission. All four signatures use
   domain-separated canonical JSON. `DocsOnlyPublish` uses **EC229 domains**,
   not EC228 ReportPublish or any delivery approval.
3. Input is a tuple of 1–8 `ReviewedDocument(relative_path, content_b64,
   content_sha256)` objects. The path is an exact member of the host allowlist,
   strictly ASCII `docs/.../*.md`, never a source/CI/script/schema path or
   `.git*` path. Files are UTF-8, max 64 KiB each/256 KiB total. New files only:
   any tracked target path or path-parent collision is refused. A narrow
   obvious-credential filter is defense-in-depth, **not DLP certification**;
   independent review of full bytes is indispensable.
4. Before any write, inspect actual Git root, `.git` path and host directory
   identities, clean original worktree/index, exact `HEAD` commit, base tree,
   non-symlink/non-gitlink objects, prohibited attributes and filters, dangerous
   local configuration, and the separate bare repo. Git environment is isolated
   (`GIT_CONFIG_NOSYSTEM`, no user global, no inherited Git variables, hooks/
   fsmonitor/auto-maintenance disabled, **file protocol only**). No Git
   `fetch`, branch switch, rebase, arbitrary remote, remote URL input, force
   overwrite, or source-worktree changes are exposed.
5. Use a fixed **operation key** derived from approved repo/commit, selected
   exact docs manifest and private target, independent of signature nonce.
   Atomically reserve `ec229-<operation>` in the host-private journal, fsync
   its parent/entry and append fsynced phase markers. A crash, timeout, refusal,
   or possible local Git effect spends that operation forever.
6. Pre-create `0700` isolated worktree path; `git worktree add --detach` from
   approved base; write only newly approved Markdown files through nofollow
   directory handles and O_EXCL; compare reviewer/grant, original index+HEAD
   bytes and repository state again. Stage **exact paths**, ensure staged
   diff is only `A docs/.../*.md`, create one detached commit with Git hooks
   and GPG signing disabled, and verify its sole parent, delta and content
   against the approved bytes. The source branch and original index remain
   untouched; linked-worktree metadata and Git object database necessarily
   gain new objects.
7. Recheck original state, all signed approvals and exact pinned runtime source
   before the side-effect edge. Fsync `06_PUSH_ATTEMPTED` **before** calling
   Git push to the **host-fixed local bare sandbox only**. Use one
   `refs/heads/ces-docs-private/<operation>` refspec and an absent-ref
   `--force-with-lease=<ref>:`. An existing ref or a concurrent conflicting
   creation is refused, not reset. A successful command is followed by one
   observation of the exact new local bare ref/commit and source recheck.
   No automatic ref delete, worktree removal, retry, repair, external push,
   upstream merge, or production publishing occurs.

**Important privacy consequence:** the private bare test repository receives
the **Git parent history and objects necessary for the candidate commit**,
not merely the Markdown files. It must be restricted by the host's actual
repository confidentiality policy, even though the *delta* is docs-only.
Do not configure a shared/public test bare repo to receive private history.

## Host-side interface

```python
from construction.docs_only_publish import (
    DocsTrustRoots, HostDocsScope, ReviewedDocument,
    DocsOnlyPublishRequest, DocsOnlyPublisher,
)
# Create four independent Ed25519 public key bytes in DocsTrustRoots,
# with issuer_id, operator_id, project_id, repository_id and minimum epoch.
host = HostDocsScope(
    roots=trusted_roots,                 # trusted host object, not user input
    repository_root="/private/approved/source-repo",
    approved_base_commit="<actual approved 40-hex commit>",
    allowed_exact_paths=("docs/releases/approved-notes.md",),
    worktree_root="/private/ces-docs/worktrees",
    journal_root="/private/ces-docs/journal",
    sandbox_bare_root="/private/ces-docs/test-only.git",
    git_executable="/usr/bin/git",
    enable_private_local_sandbox_publish=True,
)
publisher = DocsOnlyPublisher(host)
# req.documents contain only exact signed raw-reviewed UTF-8 bytes.
# req has independent signed repository_policy, content_review,
# current_revocation and one_use_grant, plus explicit=True consent.
result = publisher.publish_once(req)
```

No secrets, sample private keys, credentials or enterprise signers are
included in this package. The host **must** provision real permissions and
review outside CES. `DocsOnlyPublisher` constructor itself fails when the
host cannot provide a private physical isolation boundary; on Windows,
unsupported Git SHA-256 repositories, symlinks/submodules/filters, dirty Git
trees, uncertain code/path/identity or a non-private local sandbox, fail
closed rather than guessing.

### Exact signed statements (each has `issued_at`, `expires_at`)

Times are POSIX integer seconds. All keys listed are **required**, no extras.

- `repository_policy`: `schema`, `issuer_id`, `project_id`, `repository_id`,
  `base_commit`, `repo_binding_sha256`, `target_binding_sha256`,
  `allowlist_sha256`, `policy_epoch`, `privacy`, `issued_at`, `expires_at`.
  Domain: `POLICY_DOMAIN`. `privacy = INTERNAL_PRIVATE_LOCAL_SANDBOX`.
  A policy epoch must not be below host minimum.
- `content_review`: `schema`, `project_id`, `repository_id`, `base_commit`,
  `manifest_sha256`, `reviewer_id`, `review_state`, `privacy`,
  `issued_at`, `expires_at`. Domain: `REVIEW_DOMAIN`; exact review state:
  `HUMAN_REVIEWED_EXACT_NEW_DOCS_BYTES`. A signature alone does not prove that
  a real human actually reviewed it.
- `current_revocation`: `schema`, `project_id`, `repository_id`,
  `grant_nonce`, `policy_epoch`, `state`, `issued_at`, `expires_at`.
  Domain: `REVOKE_DOMAIN`, state must be `ACTIVE`, signed period ≤30 seconds.
- `one_use_grant`: `schema`, `issuer_id`, `operator_id`, `project_id`,
  `repository_id`, `base_commit`, `manifest_sha256`,
  `repo_binding_sha256`, `target_binding_sha256`, `allowlist_sha256`,
  `repository_policy_sha256`, `content_review_sha256`,
  `revocation_sha256`, `trust_roots_sha256`, `code_revision_sha256`,
  `grant_nonce`, `policy_epoch`, `action`, `issued_at`, `expires_at`.
  Domain: `GRANT_DOMAIN`, signed period ≤45 seconds. `action` must equal
  `CREATE_DOCS_ONLY_ISOLATED_COMMIT_AND_PRIVATE_NEW_REF_ONCE`.
  The four distinct host root keys and running module/helper bytes are
  included in the grant binding. Grant nonce is 32 lowercase hex chars.

Signature: `Ed25519.sign(domain_bytes + canonical_json(statement))`; use
`delivery_preview.canonical` for the exact canonical UTF-8 bytes. Each
statement's SHA is the SHA256 of its canonical JSON; manifest SHA is the
`delivery_preview.sha(MANIFEST_DOMAIN, sorted_path_hash_size_entries)`.
Construct a grant **after** fully resolving host root/target/allowlist pins,
actual approved `HEAD`, reviewed content and current revocation.

## Result semantics and failure/retry policy

- Before journal claim, denied requests return `blocked/4`,
  `invalid_input/4` or `unavailable/5`, without a new worktree or push.
- After journal claim, any crash/failed Git step/lease conflict/remote ref
  ambiguity is **irreversible** for the same repo+base+content+target operation.
  The result is conservative `UNKNOWN_AFTER_EFFECT`; `private_push_attempted`
  is true only after its durable marker and before invoking Git.
- Even after a new private bare ref is observed, `partial/2` and
  `PRIVATE_LOCAL_REF_OBSERVED_ONCE` mean *only* one local test observation.
  `published`, `production_or_public_published`, and
  `external_publication_confirmed` remain **false**. There is no official
  acceptance receipt or public visibility claim.
- Results avoid raw Markdown contents, authorization signatures, private
  filesystem absolute paths and source code. Journal markers include only
  stage names and at most a commit SHA; no private doc bytes or credentials.
- The operation directory and worktree are intentionally **not cleaned up**:
  cleanup/receipts belong to EC230 after explicit independent examination.
  Manual recovery cannot assume ref absence proves a push never happened.

## Limits and later user-assisted acceptance

Focused local synthetic key tests exercise **real ephemeral Git repositories
and a local bare sandbox**; no Internet/production push. They are development
evidence only, not real institutional sign-off. Required final tests include
genuine signer custody/revocation and independent human content approval;
private bare ACLs and history disclosure; Git config, hooks, object
alternates, linked-worktree and partial-clone threats; ref races and unknown
push after interruption; atomic directory/fsync persistence; same-UID,
multi-process, multi-host/NFS, Windows/macOS/Linux; path case-sensitivity,
long Git history, actual enterprise repositories; native PowerShell7 and
original 15 Smoke, E63–E66 performance, and eventual EC230 receipt/cleanup.

Original V3.10/ROUNDS provenance gap B-001 remains OPEN. No embedded
PowerShell CLI changes were made; standalone Python only.
