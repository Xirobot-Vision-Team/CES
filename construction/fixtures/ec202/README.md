# EC202 local-source development fixtures

From `construction/`, run `python -m unittest -q test_knowledge_bootstrap.py`.

These fixtures create isolated temporary *real local files and directories* with
repository bytes and a canonical `ces-snapshot.v1.json` CES snapshot. Tests
cover bounded file access, manifest version/hash/scope, missing/empty/unindexed
stores, exact source and root-binding grants, raw/provenance opt-ins, source
byte/manifest mismatch, unselected/missing/denied coverage, target/period
uncertainty, symlink/traversal refusal and four Draft2020-12 schema contracts.

None of the fixtures points to a real organization repository, performs a
trusted Git object/delivery comparison, obtains an actual auth authority
signature, calls a provider, creates/saves a knowledge record or exercises the
native PowerShell route. The only code exercised is the standalone POSIX Python
read adapter. Final multi-OS and integration acceptance are deferred.
