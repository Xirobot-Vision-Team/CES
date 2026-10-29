# EC168 synthetic/disposable Git scenarios

`construction/test_proposed_pr_linear.py` generates actual Git commit/tree DAGs in
new temporary repositories and checks provider metadata using `get_object`
synthetic transports only. No actual provider credentials or external requests,
no native PowerShell CLI execution, and no writes to a user's repository occur.

28 tests cover effective GitLab squash SHA+policy, net per-path blob and mode
matching (including separate merge commit and missing/mismatched blobs),
GitHub one-parent net tree with unknown merge strategy, after-merge base tip,
multi-commit rebase not mapped, exact-head target ancestry, inherited two-parent
EC167 route, false/missing squash flags, contradictory or missing commit SHA,
GitLab diff version merge-base identity, stale EC166 evidence, provider head or
count drift, missing independent permissions, selected local Git root, and
submodule/gitlink exclusion. The prior EC167 19 scenarios are unchanged.

These demonstrate local behavior, not independent provider authenticity,
repository membership, actual remote delivery, deployment, or final acceptance.
