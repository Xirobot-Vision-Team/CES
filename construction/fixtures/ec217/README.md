# EC217 synthetic, local-only developer fixtures

`construction/test_issue_create_grant.py` constructs **FABRICATED** EC214
`PROVIDER_OBSERVED`-shaped JSON and uses known local test-only Ed25519 private
keys. Neither the receipt nor any role in this fixture is a real human's
approval or a connected organization's issuer. Never register these keys,
copy their signatures, or publish these payloads.

The tests exercise two *different* identities: the EC215 local-proposal
reviewer and the EC217 IssueCreate issuer. A separate test-only SQLite database
lives under a private temporary directory, and is destroyed when the test
finishes. No external requests, Git mutations, Issue creation, publisher or
external AI calls are made. A successful SQLite reservation is NOT proof of an
Issue written remotely. All true organization issuer/role revocation, private
GitHub/GitLab repository and Issue state, user privacy review, multiple hosts,
NFS/Windows, crashes, provider duplicate discovery and eventual human end-to-end
acceptance are explicitly deferred.
