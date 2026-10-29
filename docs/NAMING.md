# Source names and path migration

Source directories describe a function rather than a construction round. Python
modules and packages use `snake_case`; prose guides and catalogs use descriptive
names. Existing PowerShell public entrypoints retain their established verb and
action names. A long, precise cryptographic protocol name is preferable to an
ambiguous abbreviation; length alone is not grounds for renaming a public API.

The functional-name migration replaces 169 numbered package directories, ten
fixture directories, numbered reference guides and 34 script filenames. For
example, `construction/finding_host/` implements the finding host,
`construction/negative_scenarios/` holds negative contract scenarios, and
`construction/route_documentation/` validates route help. Native boundary tests
are `tests/CodeSecurity.Boundaries.ps1` and `tests/PathIdentity.Guards.ps1`.
Source inventories now use `NATIVE_DEPENDENCIES.json`, `PATH_REVIEW.json`,
`SECURITY_REVIEW_CHAIN.json` and `SEQUENCE_SOURCE_AUDIT.json`.

`construction/` remains the parent of the compatibility implementation and
tests. It contains executable modules, not construction logs. Renaming this
shared root would add installation churn without clarifying the individual
modules. See its [directory guide](../construction/README.md).

## Compatibility boundary

Direct Python imports and direct script/reference paths change. There are no
old-name forwarding packages. Consumers that invoke internal files must migrate
their paths using [the complete old-to-new inventory](../tools/path_migrations.json).
The ordinary product/native/POSIX CLI entrypoints remain unchanged. Schema IDs,
wire fields, CLI flags, signature/hash domains and byte literals keep their
existing values, including historical round identifiers used as protocol data.
Those identifiers are not filenames and must not be mechanically renamed.

Before the migration, 731 runtime Python modules were compared with the parent
commit using ASTs normalized only for import/path names and documentation
strings. Their logic, byte literals, protocol and CLI constants matched. This
is bounded refactor evidence, not production acceptance or proof of every
experimental host. CI checks the path inventory, rejects numbered source names
and old imports, and pins the reviewed protocol/CLI/byte constants.

## Integrity and history

The original `BASELINE_SHA256.json` is immutable. Exact old and new paths and
hashes are recorded as reviewed `moved` entries in
`tools/legacy_cleanup.json`; intentional edits to files that keep their names
remain explicit `modified` entries. Missing targets, unexpected old-file
returns, unsafe/duplicate targets and subsequent byte drift fail validation.
The current product manifest and security source lock bind the actual new tree.

History maps and the frozen baseline intentionally retain old path names so
that changes can be audited. Archived prose can mention historical rounds;
new executable paths and current navigation use functional names. Future work
should add files to the appropriate functional module rather than create a
numbered round directory.
