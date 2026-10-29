# 1.8.0 cleanup and first formal release scope

## Removed

21 obsolete files (514,198 bytes) were removed: ten historical construction
plan/progress/completion/inventory reports, nine dedicated planning-checker and
test files, and two obsolete checker/readiness reference documents. These
checkers depended on already absent BUILD_STATE.json, round templates and archived
round reports; none is imported by a retained product entrypoint or implementation.
The removed ec249 completion checker evaluated one historical construction
snapshot, not current product correctness.

The exact paths, frozen baseline hashes and reasons are recorded in
tools/legacy_cleanup.json. Deleted bytes remain recoverable from Git commit
0d23182797f757932990371053a3d2c3f8e7e527; the release does not ship duplicate archives.

## Retained and reviewed

Most of construction/ is executable compatibility implementation or useful
tests. Runtime action traces, route catalogs, security checks, source binding
receipts, protocol definitions, test fixtures and source code remain. Do not
interpret this cleanup as removal of independent authorization or evidence gates.

The obsolete entries in CAPABILITY_MATRIX were removed; retained 74 runtime
routes are unchanged. SECURITY_SOURCE_LOCK was explicitly refreshed for the
actual remaining source tree rather than accepting missing files. Two legacy
regression files now distinguish the current 1.0 baseline from older drift
receipts and use the current 124 native-import count while retaining the 56-step
Sequence contract and negative mutation tests.

The immutable historical BASELINE_SHA256.json stays unchanged. Product integrity
uses an explicit ledger of reviewed removals and exact modifications: arbitrary
missing files, subsequent drift or reintroduced retired files still fail.
No global ignore or silent rebaseline was added.

## Release boundary

The operator version is 1.8.0; the retained wire/protocol version remains 1.0.0.
This is the first formal GitHub release, not a claim that all experimental
legacy hosts, Sequence deep queries or real hardware workflows are certified.
Known limitations, per-project authorization gates, external data/credential
boundaries and Apache-2.0 terms remain in force.

Source-only archives are built by tools/build_release.py with SHA256SUMS. The
manifest controls every archived file; .git, environments, project profiles,
logs, caches and ledgers are not included. CI must pass and an AI maintainer PR
review is recorded before merging and publishing from main. Under the owner's
AI-maintenance delegation, no second-account approval is required; all CI and
other branch protections remain. See ../GOVERNANCE.md. Release preparation does
not bypass these protections.
