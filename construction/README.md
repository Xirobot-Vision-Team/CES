# Compatibility implementation, not a log directory

This directory contains real protocol implementations and tests used by the
retained CLI/POSIX entrypoints. It must not be deleted wholesale because its
name resembles a historical construction log.

The 1.8.0 cleanup removes obsolete plans, status/completion reports and dedicated
one-time checkers that depended on already absent build-state/round archives.
Their source is recoverable in Git history. Runtime action traces, source locks,
security boundary records, schemas and behavioral tests remain where consumed.

See [cleanup scope](../docs/CLEANUP.md) and tools/legacy_cleanup.json for the
reviewed removal/replacement inventory. Tests here are platform-specific;
not every experimental host is part of the supported operator release.

Round-specific fixture notes have also been consolidated into [one test-data guide](fixtures/README.md); executable implementations/tests and actual fixture data remain. There are no tracked execution logs here.

Numbered package directories now use functional names, such as `finding_host/`,
`negative_scenarios/` and `cross_module_regression/`. Source inventories and
fixture paths use descriptive names as well. See [source naming and migration](../docs/NAMING.md)
before updating integrations that import these modules directly; wire identifiers
and the normal CLI entrypoints retain their existing contracts.
