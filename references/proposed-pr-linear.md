# EC-168 — read-only squash / linear-tree PR/MR association

**Current scope:** `construction/proposed_pr_linear.py` is a standalone Python API/CLI with schema `ces.proposed_pr_linear.v1`. It **does not implement** native `Collect:ProposedPR` or `Reconcile:Remote/DeliveryAssociation`. It never writes a Provider object, CES state, or a Git worktree/index/ref; it does not fetch or perform a merge. This is an additional evidence consumer, **not** a substitute for the existing EC167 `proposed_pr_merge.py` two-parent route.

## Inputs, example and authorization

Supply a *complete valid merged-state* EC162 identity result plus a coherent EC166 `FRESH_OBSERVATION` generated for exactly that identity **within 15 minutes**. Previous observations, fingerprints and Provider file-count claims are not signatures. Supply an *absolute selected local target Git repository root*. The tool cannot cryptographically associate that local object store with the Provider target repository, remote branch or release.

```bash
cd ces
python construction/proposed_pr_linear.py \
  --provider gitlab \
  --repository group/subgroup/project \
  --number 8 \
  --expected-pin /secure/ec162-merged.json \
  --ec166-reconciliation /secure/ec166-fresh.json \
  --local-git /absolute/path/to/operator-selected-target \
  --allow-network --allow-local-git --json

# GitHub: --provider github --repository owner/repo --number 12
```

Both independent permissions **default denied**; callers must opt in to the **single fixed HTTPS metadata GET** (`--allow-network`), and separately to bounded read-only exact-OID Git operations (`--allow-local-git`). Provider credentials must be injected securely through `CES_GITHUB_TOKEN` or `CES_GITLAB_TOKEN` for live calls. No token, Provider raw body, branch content, commit message or changed path name is returned. If any baseline/gate fails, no Provider request is sent. The new metadata must still match the complete original provider/source/target/proposal identity, base/head/target version OIDs, merged state, and exact reported changed-file count.

## Positive **partial/2** cases (never success/0)

| `association_state` | Conditions established **locally**, beyond a matching Provider claim | What is **not** established |
| --- | --- | --- |
| `LOCAL_GITLAB_SQUASH_TREE_VERIFIED` | GitLab MR's effective `squash_on_merge == true` and a complete `squash_commit_sha`; existing one-parent squash commit/tree; pinned `diff_refs.base_sha` is a unique merge-base of head and target diff-version tip *and* of head and squash parent; exact per-path net resulting Git mode/blob OID equality from source-base→head to squash-parent→squash; new blobs are present; pinned target lineage. If GitLab provides a separate merge SHA, require a readable two-parent merge whose second parent is the squash SHA, first parent is on target lineage, and whose final tree has the same net mode/blob delta. | Signed remote receipt, authenticated target ref, a guaranteed historical merge method or deployment |
| `LOCAL_SINGLE_COMMIT_NET_TREE_VERIFIED_METHOD_UNKNOWN` | GitHub reports a post-merged `merge_commit_sha`, exactly one local parent, unique common source-base, target-tip relation, and exact source-net-to-candidate-parent→candidate resulting per-path mode/blob OIDs with present local blobs | **Not** evidence that GitHub used squash rather than rebase, a complete rebase commit mapping, or remote delivery |
| `LOCAL_EXACT_HEAD_GRAPH_VERIFIED_METHOD_UNKNOWN` | Provider merge SHA **equals pinned head** *and* the selected local target-tip and head have explicit ancestry, readable commit/tree objects and usable source-base identity. GitLab must match its pinned diff-base. | SHA equality alone, historical fast-forward setting, remote target-branch membership or a rebase mapping |
| `LOCAL_MERGE_GRAPH_VERIFIED` | Existing EC167 two-parent merge path preserved: second parent is pinned head, merge tree exists, local target lineage verified | Remote repository/deployment proof |

The exact-mode+blob comparison uses local Git tree deltas. Rename heuristics are **disabled**: Git old/new path results are compared literally, including mode; no file content is printed. Deletes are represented by absent entries. Gitlinks/submodules, unknown or missing blobs, over-budget diffs, ambiguous merge-bases, missing trees, divergent changes and conflict-resolved results that change expected blobs yield `UNAVAILABLE_UNKNOWN`. A local equality of net file content is **not** a proof of commit-level origin or of the historical Provider action.

## Cases that deliberately stay `UNKNOWN`

- **GitHub:** REST `merge_commit_sha` after merge can mean two-parent merge, a squash commit, **or the last commit of a rebase**. The PR metadata does not return an authoritative historical method. A lone SHA, one parent, identical head, or `merged:true` is not enough. For a multi-commit rebase, a last-SHA match cannot stand in for the full old→new ordered commit mapping. If the net tree/delta does not match exactly, report `UNAVAILABLE_UNKNOWN` and do not invent equivalence.
- **GitLab:** `squash` (legacy boolean) alone is not substituted for effective `squash_on_merge`. Require an actual `squash_commit_sha` for explicit-squash association. `squash_on_merge=false` with a distinct single-parent merge SHA is not evidence of a historical fast-forward/rebase mapping; such cases are unknown. With an exact head SHA, verify target ancestry and commit/tree objects before returning the weaker partial state.
- **All providers:** source/base/target/PR identity drift, missing exact file count, stale EC166, absent required permission, unsupported commit graph, inconsistent squash-vs-merge fields, missing local object/changed blob, repository path not a Git root, two or more merge bases, and an unrelated target lineage never become positive. Live credentials or synthetic payloads do not change the `provider_actor_verified=false`, `delivery_or_merge_proven=false`, `target_repository_membership_authenticated=false`, `write_authorized=false` response policy.

## Read-only Git facts and budgets

Only exact selected repository roots (main working-tree root or bare Git dir); object format `sha1`/`sha256` must match the pin. Used commands: `rev-parse` root/format only, `cat-file -t/-s/-p` for complete OIDs, `cat-file --batch-check` for changed new blob OIDs, `merge-base --all/--is-ancestor` on complete fixed OIDs, `diff-tree -r --raw -z --no-abbrev --no-renames --no-ext-diff --no-textconv` on exact tree OIDs. Git subprocesses use a sanitized environment, block lazy fetch/replacements/external protocols, have a 5-second limit, and never checkout, stage, push, update refs or execute repo hooks. Bounded commit 64KiB, delta 4MiB, 4096 paths/new OIDs. File paths remain opaque bytes inside the process.

The same Git repository can have objects from unrelated remotes, alternates or forks. These results therefore establish **only** a matching Provider *claim* against a local graph/tree, not the Provider's delivered branch or immutable merge operation. The HTTP and Git observations are not atomic.

## Developer scenarios, deferred user-assisted validation

`python -m unittest discover -s construction -p 'test_proposed_pr_linear.py'` exercises **28** isolated synthetic Provider/disposable real-Git cases. The inherited EC167 `test_proposed_pr_merge.py` has **19** cases. These are development checks, not live GH/GL or multi-OS acceptance. Defer to final user-assisted run: GH/GL permissions/tokens/rate-limits and concurrent edits; squash/rebase/FF policy variants (including absent/late GitLab squash claims and conflicted merges); Windows/macOS/Linux SHA-256/repos, partial clone/alternates; PowerShell7 and 15 old Smoke; EC157/159 native safety tests; E63–E66 performance; full external workflow/deployment/provenance.

Primary field semantics: [GitHub PR REST API](https://docs.github.com/en/rest/pulls/pulls), [GitHub pull request merges](https://docs.github.com/en/pull-requests/reference/pull-request-merges), [GitLab MR API](https://docs.gitlab.com/api/merge_requests/). These document API claims, not proof that a local Git clone belongs to those services.
