# EC169 ephemeral store scenarios

`construction/test_proposed_pr_evidence_store.py` creates a private temporary
on-disk directory for each scenario. It exercises actual `init`, `preview`,
`commit` and `history` code; v1 manifest, private file modes, stable scope
permissions, append-only no-clobber receipts, HMAC/revision integrity,
expiry/no-revival, bounded `UNKNOWN`, stale pin history and direct
permission-denial/cancel cases. It also generates three real disposable Git
histories with synthetic GH/GL inputs through *existing* EC166, EC167 and
EC168 consumers, then passes those source results into EC169. These do not
connect to GitHub or GitLab; temporary files are removed by tests.

No persistent fixture receipt is shipped, because its per-test instance salt,
path, time and HMAC deliberately vary. This also avoids disguising a fixture as
independently authenticated Provider evidence. The development tests do not
exercise hostile concurrent writers, Windows/macOS filesystems, native CES
PowerShell, old Smoke suites, or final end-to-end acceptance.
