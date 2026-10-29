# EC195 synthetic cross-repository scope fixtures (development only)

`test_cross_repository_report_scope.py` builds ephemeral in-memory synthetic
EC192 periods, EC193 repository subjects and EC194 people reports; none of
those strings are real repositories, Git objects, directory accounts,
permissions, contribution observations or signed authorization receipts.

Cases cover: enumerated repository sets only, canonical sorted output, valid
permission intersection across distinct grants, dependency-downscoping,
missing/inaccessible and malformed upstream rows remaining named coverage gaps,
wrong repository/period/report slot and stale EC193/EC194 pins, missing/invalid
per-repository authorization and partial period/path/inventory coverage, no
automatic actor merging by display name or matching identity scope, explicit
link with opt-in permissions and independent identity receipts only, safe
rejected-link redaction, schema consistency and both structural-only and
witness-assisted replay. All positive claims remain `partial/2` and unverified.

No PowerShell7, original 15 native Smoke, live Git/GitHub/GitLab/CI/directory,
real authorization signatures/revocation, Windows/macOS/Linux, E63-E66
performance or final user-assisted acceptance is run by these fixtures.
