# Synthetic fixtures and disposable test state

This directory contains input data for retained compatibility regression tests.
Functional directory names identify the input category; these files are not
production run logs. The old per-round README pages were consolidated here.
Their historical coverage prose and one-time pass counts are recoverable in Git,
but are not current release acceptance evidence.

## Retained data

- `cli_responses`, `code_insight`: CLI/evidence and schema examples, including deliberately
  invalid or future versions used by rejection tests.
- `provider_metadata`: synthetic GitHub/GitLab provider responses, marked as fixtures; no
  live commit, identity, availability or authorization evidence.
- `changed_files`, `patches`: synthetic changed-file and patch responses for provider
  read/rejection tests; they are not actual source repository changes.
- `handoff_inputs`: authorized/denied/historical handoff examples used by input-contract
  tests; those embedded claims do not authorize a production handoff.
- `provider_issues`: synthetic Issue/provider observations used by matching and lifecycle
  tests. Titles and actor values are invented test input, not verified identities.
- `schema_review`: versioned schema examples consumed by the schema-review tests. Some
  filenames are constructed dynamically; lack of a literal name reference does
  not make them unused.
- `negative_scenarios`, `cross_module`: bounded negative-case and cross-module/native-smoke manifests.
  These manifests select isolated tests and do not establish production acceptance.

The remaining files are intentionally retained under descriptive paths with their original input
bytes. Tests may construct other cases dynamically in memory or private temporary
directories; a directory containing only a historical explanatory page is not
required to run those tests.

## Test safety and evidence boundaries

Run the relevant test module in a disposable supported environment, with the
optional dependencies it actually needs. POSIX private-store tests require the
real permission/file APIs and must not be downgraded on Windows. Test code is the
current authority for assertions and command examples; see `../test_*.py` and
the applicable `../<functional-package>/test_*.py` modules rather than old round pass counts.

Private keys, HMAC values, run IDs and paths created by tests are ephemeral.
Never reuse fixture keys, fabricated callbacks or accepting mock transports in
production. No real project credentials, source snapshots, notification receipts,
private issue text, persistent scheduler or business-run output belongs here.

A synthetic passed case, hash match or signed test fixture proves only the
bounded behavior exercised. It does not authenticate an external actor, source,
provider, historical network event or organization approval; it does not prove
production delivery, current repository HEAD, hardware behavior, all-platform
isolation or that every historical host works. Keep denial/partial outcomes and
all independent authorization gates intact. Use current CI/test output for actual
run results and record skipped/unsupported tests as such.
