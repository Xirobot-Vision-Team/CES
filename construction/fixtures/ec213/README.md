# EC213 IssueShow fake source fixture policy

EC213 does not store real account data, provider credentials, or returned Issue
snapshots. `test_issue_show.py` reuses `../ec211/github_repository.json`,
`../ec211/github_issue.json`, `../ec211/gitlab_project.json`, and
`../ec211/gitlab_issue.json` through the **actual** EC211
`issue_provider.read_issue` and EC212 `issue_sync._projection` code paths.

Tests inject a fake GET-only transport and fixed UTC clock; every accepted
observation is marked `SYNTHETIC_OBSERVED` and `synthetic_fixture`.
Coverage includes host/repository+stable Issue IDs, independent exact grants,
full three-GET boundaries, private field redaction, state/privacy/update-window
filter exclusions, stale and expired grants after reads, injected malicious
source, error handling and offline CLI. It neither connects to GitHub/GitLab
nor authorizes access to any real issue. Tests do not validate credential
custody, organizational revocation, live remote state or native PowerShell.
