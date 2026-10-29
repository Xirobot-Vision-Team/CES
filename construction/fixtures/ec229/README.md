# EC229 focused local Git fixtures

`test_docs_only_publish.py` constructs new, disposable `git init` and
`git init --bare` repositories inside owner-private temporary directories.
It then makes a real detached linked worktree, stages exact signed new
Markdown, commits, and creates one new bare-private ref. It uses
**ephemeral synthetic Ed25519 keys**, fake human-review metadata and a
private offline test target; no GitHub/GitLab account, public release,
network push, real organization PKI, or customer Git tree is involved.

Examples cover: approval and SHA binding, source dirty/untracked/HEAD drift,
dangerous Git config, original symlinks, active receive hooks, disallowed
CI/schema/source/traversal/existing-doc paths, private target isolation,
fixed-ref collision, a normal configured production remote that is never
called, failed/unknown push, irreversible journal, and a content/code
mutation that fails closed.

These local cases are **not** a durability/failure-injection, concurrency,
NFS, same-UID, Windows, actual enterprise permission, privacy or production
publication acceptance suite. Do not carry a synthetic success label into
the final acceptance register.
