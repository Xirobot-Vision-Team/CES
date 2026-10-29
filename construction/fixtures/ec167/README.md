# EC167 isolated scenarios

`construction/test_proposed_pr_merge.py` creates disposable real local Git
commits (base, head, target, two-parent merge + real tree object). It combines
them with **synthetic** GitHub/GitLab API dictionaries generated from prior
EC161/EC163 fixtures. It never contacts a real Provider, stores credentials,
reads user worktrees or writes any non-temporary Git project.

Cases include before/after GitHub target tips, GitLab target diff-version tip,
missing commit/tree, wrong pinned head, one-parent pseudo-merge, stale EC166,
missing independent permissions, merge-SHA absence, and reported-count drift.

These are development fixtures only: not authenticated evidence of a Provider
merge, target repository membership, delivery, deployment or release. Live and
cross-platform acceptance remain deferred.
