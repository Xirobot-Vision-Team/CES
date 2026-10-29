# EC231 development fixture provenance

No production RunId, private actor identity, actual enterprise snapshot,
credentials, approvals, Git repositories or host storage are included.

`construction/test_cycle_run_metadata.py` creates POSIX temporary 0700 roots,
caller-supplied synthetic input bytes and declared action sets, then exercises
real exclusive 0600 file writes/fsync/readback and untrusted-corruption cases.
It also models one untrusted, syntactically valid PARTIAL/UNKNOWN metadata
state; this is NOT proof of a real executed step or live scheduled run.

Schema tests optionally use installed `jsonschema`; the implementation uses
only the Python standard library. The native PowerShell CLI, original
15 Smoke, live snapshot/actor approval and final end-to-end acceptance
are NOT_RUN. Synthetic fixtures must never be used as real authority evidence.
