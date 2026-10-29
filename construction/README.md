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
