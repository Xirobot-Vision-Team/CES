# EC204 synthetic local Git / ephemeral-key development fixtures

`construction/test_knowledge_impact.py` creates temporary **real** local Git repositories, committed blob changes and ephemeral Ed25519 signer keys during each local test; no live repository, key, private data or Git object fixture is packaged. It starts from EC203's test-local helper and recomputes EC202/EC203/EC204 policies and signatures. Both Git SHA-1 and SHA-256 are exercised.

Checks cover actual modified/added/mode-only/unchanged selected Git blobs, signed baseline ancestry and commit-object hashes, separately authorized per-source comparisons, absent/forged target or baseline signatures, ref/worktree drift, dangerous old symlink, deleted target path kept UNKNOWN due the EC203 source-bytes gate, trust-key registry and upstream-policy replay, output digest redaction, retained CES snapshot coverage gaps, rejected writes and three Draft2020-12 schemas.

Tests are *development checks*, not organizational key provenance, live delivery authority, true snapshot completeness, PowerShell native actions, E63-E66, multi-OS security or final user-assisted acceptance. No test assets create or mutate the delivered CES package's original business sources.
