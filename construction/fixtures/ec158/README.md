# EC-158: synthetic read-only compatibility fixtures

These are **illustrative JSON objects**, not captured PowerShell/CES/CodeSave/Git output and **not** records copied from a real user repository. They do not attest model provenance, source hashes or business correctness. Do not install them into a real `.codex/ces/code-insights` directory.

- `ci-example.json`: complete, zero-finding saved-v1 *schema illustration* with synthetic source root and SHA references. File has a non-content-addressed name on purpose. The offline reader derives the exact raw-byte `ci-<sha256>` identity but reports it as **unbound**, not a real record from a verified CES store.
- `collect.v1.json`: partial `ces.cli.v1` Collect response based on the legacy EC-156 illustrative envelope. Minimal data demonstrates schema **classification only**; it does not satisfy all native Reconcile evidence checks and contains no observed source content.
- `owner.json`: exact owner-marker bytes as authored in CodeSave v1; existence by itself is not permission to use or write an arbitrary directory.
- `future-version.json`: a deliberately unsupported future `ces.code_insight_saved.v2` to demonstrate fail-closed rejection. EC-158 has no v2 decoder or converter.

All commands below are read-only and print metadata or issues, not source bodies:

```bash
python construction/schema_compat.py inspect --input construction/fixtures/ec158/ci-example.json --json
python construction/schema_compat.py inspect --input construction/fixtures/ec158/collect.v1.json --json
python construction/schema_compat.py inspect --input construction/fixtures/ec158/owner.json --json
python construction/schema_compat.py inspect --input construction/fixtures/ec158/future-version.json --json
python construction/schema_compat.py preview --input construction/fixtures/ec158/ci-example.json --target ces.code_insight_saved.v2 --json
```
