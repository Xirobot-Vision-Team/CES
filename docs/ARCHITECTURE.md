# Architecture and compatibility

CES has three maintained layers:

1. `operator/` orchestrates repository evidence, report archives, GitHub routing,
   opt-in test runs, ownership registration and managed documentation. Its
   standard-library tests use disposable fixtures and mocked providers.
2. `scripts/ces.ps1` implements the native read/validate/save evidence Actions.
   The wrappers locate it relative to the CES installation. PowerShell 7 and Git
   are separate prerequisites.
3. `construction/`, the remaining `scripts/` and `references/` retain the 1.0
   protocol core, schemas and explicitly limited POSIX host extensions. Internal
   names are retained because imports, schema IDs and hash domains depend on them.

## Evidence flow

The assistant reads actual source and authors conclusions. Python/PowerShell
collect inputs, validate literal citations and source bindings, preserve run
receipts, render reports and perform separately authorized publication. CES does
not contain a model API client that independently invents analysis. A hash match
is a local consistency observation, not proof of semantic correctness.

All project-specific facts live in an external profile: repository and account
identity, build/test commands, recipients, execution policy and data roots.
`operator/profile.example.json` disables all execution/publication by default.
Profiles, raw evidence, knowledge versions, notification ledgers and secrets are
not part of this source distribution.

## Independent authorization lanes

- Native collection is read-only unless an explicit CES state-save gate is used.
- Repository synchronization is opt-in and fast-forward only.
- Lifecycle build steps do not run project binaries.
- Project testing has separate enable/execute/publish gates and source-reviewed
  result contracts. Failure ownership is an explicit registry, not blame.
- GitHub creation, mentions and assignments use durable dedup/readback. Unknown
  POSTs are not blindly retried.
- Documentation publication is restricted to manifest-owned files using an
  isolated index and normal push. It is not a permission to commit business code.
- Issue fixed/regression evidence and close/reopen permissions remain separate
  from report publication and passing builds.

## Versions and retained source

`PRODUCT.json` carries the operator version; root `VERSION` remains the legacy
1.0 protocol version. `PRODUCT_SHA256.json` verifies the current source.
`BASELINE_SHA256.json` preserves the historical baseline and independently pins
the protected `scripts/`, `construction/` and `references/` implementation. It is
not rewritten to conceal changes.

The public release preserves these protected bytes. Deployment-only verification
records are removed from the public view and listed in `RELEASE.json`. The
released source has its own regenerated current manifest; this is a disclosed
source-package projection, not an assertion that historical runs were repeated.

The large legacy tree includes experimental protocols and tests. Its presence
does not imply production support, working external hosts or universal test
coverage. See KNOWN_ISSUES.md and historical VALIDATION.md.
