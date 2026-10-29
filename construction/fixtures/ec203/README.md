# EC203 local Git and ephemeral signer fixtures

`construction/test_knowledge_target_binding.py` creates its fixtures at run time in
isolated `TemporaryDirectory` paths. **No private Ed25519 key or signed
organizational artifact is distributed with this ZIP.** Each successful
fixture is an actual local `git init` / `git add` / `git commit` repository
and Ed25519 signature from an ephemeral **development-only** key; it is
not an organization-authorized delivery event.

Run from `ces/construction` with `python -m unittest -q
test_knowledge_target_binding.py` if the local POSIX host provides Git and
Python `cryptography`. The suite covers SHA-1 and optional SHA-256 real Git
object formats, verified Git blob byte matching, detached signature/replay,
request and host-root binding, rejected caller PR OIDs, moved branches,
working-tree drift, permissions, signed manifest SHA, unknowns and security
boundaries. Schema tests require the optional `jsonschema` library.

These are **development checks only**. A real owner-managed Git repository,
real delivery signer/key authorization and revocation, provider events,
filesystem concurrency, NFS/Windows/macOS, 15 native PowerShell Smoke,
E63–E66 and final human-assisted acceptance remain to be verified separately.
