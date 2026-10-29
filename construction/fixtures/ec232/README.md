# EC232 development fixture boundary

All fixtures in `construction/test_cycle_dag.py` are **synthetic** and created
in temporary local directories using the unchanged EC231
`CycleMetadataStore.create()` and actual readable `0600` private records.
They cover a CodePrepare -> QualityRun -> ReportPrepare example; independent
roots, stable wave ordering, 2/3-node and disjoint SCC cycles, downstream
blocked vs cyclic membership, 32-node dense DAG, wrong/changed pins,
resealed malformed metadata, unsafe file links and CLI outcomes. These
records do not represent customer repositories, verified actors, real task
execution, permissions, or production Cycle progress.

No secret signing keys, Provider credentials, source files, real RunId
fixtures, or external metadata are bundled. The EC232 result's independent
domain SHA is an **unsigned checksum**, not a timestamp/signature/approval.
EC231 metadata stores are never modified by the checker. Test-only records
may be deliberately changed in disposable directories to verify rejection.

Deferred `NOT_RUN`: PowerShell7/15 Smoke, Windows/macOS, real source/actor
custody and permission, POSIX crash/fdatasync/power loss, NFS/multihost,
E63–E66 performance, all-feature end-to-end acceptance and B-001 upstream
source reconstruction. See `../../FINAL_ACCEPTANCE.md`.
