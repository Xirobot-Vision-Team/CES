# EC-244 — security and permission static source review (V5.54/R244)

**Read-only development tool, not an authorization engine, source authenticator, enterprise permission check or security certification.** It does not call CES business handlers, Git, providers, PowerShell or a privileged broker. The review is meant to make actual source drift and uncovered boundaries visible *before* the final operator-controlled integrated tests.

## Invocation

From the complete CES Skill directory:

```sh
python -I construction/security_permission_audit.py --summary
python -I construction/security_permission_audit.py --route IssueCreate:Create
python -I construction/security_permission_audit.py --route DocsOnlyPublish:LocalSandbox
python -I construction/security_permission_audit.py
python -I construction/test_security_permission_audit.py
```

The full JSON result is `ces.security_permission_audit.v1`. `PASS_STATIC_SOURCE_ONLY` (exit 0) means the bundled source byte pins and enumerated AST/PowerShell review probes match the EC244 *local snapshot*. `BLOCKED_STATIC_REVIEW` (exit 2) means a route, handler, source pin, review constraint or review tool itself requires human re-review. No result means permission has been granted. `--route` narrows the displayed trace; it **does not bypass the global audit**. The 74 route records contain a fixed source, AST symbol/line, route kind, effect class, local imports and **module-level possible sink names, not a proved reachable call graph**. The old 16 routes have no Python execution; native PowerShell remains separately owned and unrun.

The file [`construction/SECURITY_SOURCE_LOCK.json`](../construction/SECURITY_SOURCE_LOCK.json) records the 74 fixed Action/Mode identities plus SHA256 for 307 audited sources, including historical PowerShell and Smoke, registered handler sources, relevant security modules, and identified direct Python main entrypoints. **The pin file is bundled with the source**; it is not externally signed or authenticated and cannot guard against an adversary modifying the entire package, the Python interpreter, memory or the runner. Regeneration after any code change is a *manual source-review operation*, not an automatic acceptance step; do not treat lock changes as ordinary test fixes.

## Traced entrypoints and actual boundaries

| Entry | Source path | Effective execution boundary |
| --- | --- | --- |
| Original native (16) | `scripts/ces-v5.ps1` without `-RequestPath` → `scripts/ces.ps1` → fixed original handlers | Original R150 handler gates, especially `CodeSave -ApprovePersist`, stay authoritative; no new Python dispatch |
| New Python CLI (39) | `scripts/ces-v5.ps1` or `scripts/ces_router.py` → `unified_action_router.dispatch` → fixed Python `main` | Fixed source/module, limited args/size/time; private CES local-write requires explicit opt-in; network opt-in is not provider authorization |
| New Python API (7) | Router → fixed class method | Fixed constructor fields/import origin, but **not** host actor authentication; method-specific checks remain authoritative |
| New typed preview (1) | Router → `delivery_preview.preview_delivery` | Fixed source dataclasses/readers; no send grant or recipient effect |
| Host-only (11) | Router checks `HOST_REQUIRED` **before** execution | `ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED`, no handler invocation, no forged host provider/credential from request JSON |
| Direct Python entrypoints (142) | Local modules with `if __name__ == '__main__'` | Enumerated separately with source pins; **not** automatically governed by the Action router or a complete taint/reachability proof |

The existing 74 fixed routes are **not** changed by EC244. New audit capability has its own standalone offline CLI, **not** an additional business Action/Mode route. Existing R150 CodeSave still may write limited *CES-private metadata only after its original gate*. Its local write is not business-repository mutation permission, and static review cannot prove absence of all OS/Git effects. A source SHA or module-source detection is not evidence that any real upstream artifact was signed by a trusted actor.

### Existing Issues (EC211–EC220)

`issue_existing_readonly.issue_http_route` allows HTTP `GET` for exact selected/read/recheck profiles, and permits `POST` only for `CREATE_NEW_COLLECTION` under a separate create profile; `PATCH`, `PUT`, `DELETE`, edits, comments, labels, assignment and close/reopen are **not** registered as actions. The audit checks the classifier's reviewed AST predicates and rejects literal prohibited mutation methods or direct `post_create/patch/put/delete/submit` calls in the seven reviewed read-only issue modules. `IssueCreate:Create` is host-only in the 74-route CLI; the standalone `issue_create_write.create_new_issue_once` still has independent grant reservation and durable `atomic_start` before the **single** new-collection `post_create`. `issue_unknown_recheck` uses read-only GET and does not authorize POST retries. The transport's low-level `post_create` method is **not** a trusted unprivileged entrypoint. The audit cannot exclude dynamic methods, malicious imported dependencies, host-level network rewriting or actual provider-side changes; packet/permission verification is deferred.

### DocsOnly publication (EC229)

The CLI keeps `DocsOnlyPublish:LocalSandbox` strictly host-required; no user JSON can create the four independent trusted keys. Source checks require exact `docs/.../*.md` path control, separately signed repository policy, byte-exact human review, revocation, one-use side-effect grant, active code hash, and disjoint host-provisioned source/worktree/journal/private-bare paths. Only a local private `file` Git protocol is configured. The reviewed publication code reserves a durable journal *before* the isolated worktree, verifies only new docs staged/committed, then requires an absent private ref and pushes once to `self.bare` with an empty-ref lease. Any unknown Git outcome stays unknown and is never retried automatically.

**Nuance requiring native verification:** `git worktree add` does mutate the source repository's *administrative linked-worktree metadata* even though the source worktree files, index, branch and production refs are intended to remain unchanged. Do not interpret `original_repository_intact_verified` as proof that its entire `.git` directory is untouched. Verify in actual host snapshots before/after; prove the private bare target is not a production path, remote, mount alias or security bypass. `--no-verify`/hook policy and Git configuration/protocol edge cases also require explicit operator review; this audit is not a substitute.

### Independent actor, source and broker chain

The audit's source-level probes locate the following existing enforcement **interfaces**, but do not mint them:

- Separate policy/isolation tickets, source pins, host callbacks and explicit trusted isolated execution broker at `quality_run_guard`/`quality_run_budget`; `QualityRun` routes remain host-only.
- Current target/knowledge binding and independent save-policy/approval signatures in `knowledge_target_binding`/`knowledge_version_save`; `KnowledgeSave` route remains host-only.
- Separate signed grant, current revocation/recipient or private destination identity, durable one-use outbox and actual external host access in `delivery_authorization`/`delivery_send` and `report_publish`; `DeliverySend`/`ReportPublish` remain host-only.
- Independent current actor, repo stable identity, private visibility, source and review trust, host-issued credential/consent, no-harm proof, and spent grant/attempt ledger in the Issue creation path; `IssueCreate:Create` remains host-only.
- Four independent policy/review/revocation/effect keys plus explicit owner-controlled sandbox in `docs_only_publish`; no public or production publication is authorized.

A successful local hash/probe only means **source text contains the reviewed gate at the reviewed function**. It cannot prove every transitive runtime call will obey that gate, identify a genuine enterprise signer, verify current revocation, authenticate provider receipts, or ensure broker isolation.

## Final operator-assisted acceptance queue — all NOT_RUN

1. **Real PowerShell 7 & CLI** — verify existing 15 native Smoke and all old/bridge CodeSave refusal/authorized local metadata flows on Windows/macOS/POSIX as applicable; pin source SHA outside the package and compare old route/output behavior, V2 normalized status and exits.
2. **Business repo & Git mutation** — snapshot source worktree/index/staged entries/refs/object reachability and source `.git` administration before/after representative native and new calls; validate no unintended business code/CI/schema edits, no original tracked file mutation, no Git config inheritance or bypass. Exercise symlink/realpath/reparse, same-UID, path swap/ABA, NFS, crash, multi-host and non-atomic file-system semantics.
3. **Existing Issue no-edit** — on operator-approved sacrificial GH/GL repositories with intercepted outgoing traffic, reject any PATCH/PUT/DELETE/method override/POST-to-existing-instance/comment/label/state change. Read selected exact visible/private/confidential Issue with current independent grant; test rename/transfer, repo global ID vs IID, PR vs Issue, 401/403/404/429/timeout/redirection and changed permissions. Confirm a separate **new Issue** one-use grant has no power to mutate existing Issues, and unknown create cannot cause a retry.
4. **DocsOnly private target** — independently configure keys, code SHA, exact new Markdown review, fresh revocation and one-time grant. Observe real Git worktree metadata/source worktree/index/refs and disjoint bare target *before and after* one private sandbox push; inject race, broken symlinks, path/mount aliases, hooks, malicious config, ref collisions, unknown-POST/crash, and revoke/expiry at edge. Assert no network/production ref push and no automatic retry.
5. **Independent authority & broker** — obtain current enterprise identity and permissions from an external trusted host and real source/CI/provider evidence; exercise missing/wrong/expired/revoked signer keys and audience/policy/actor/source mismatch. For QualityRun, verify actual OS-isolated broker/lease/quota/cancel/kill/cleanup outside the source checkout. Confirm fake JSON credentials/provider callbacks never grant authority.
6. **Redaction, offline, resource and final** — exercise genuine disconnected providers, large/partial/binary/secret outputs and privacy constraints, delivery/report approval and durable outbox unknowns; check E63–E66 performance and resource budgets. This overlaps **planned EC245** only as a future acceptance requirement, not an EC244 implementation. Complete final E63–E66 and full user-assisted end-to-end acceptance only after all rounds.

Historical source evidence blocker **B001 OPEN** (original V3.10 frozen spec and original ROUNDS missing). Native PowerShell7, real network/provider/enterprise trust, OS/NFS/multihost, E63–E66 and final acceptance have **NOT_RUN** status. Source lock and 14 focused local cases must not be reported as those tests.
