# EC207 local test fixture conventions

`construction/test_knowledge_update_handoff.py` creates disposable real EC206
POSIX owner-private stores under per-test `TemporaryDirectory` and uses the
EC206 test fixture to append immutable records with test-only receipts. It
covers manual/selected Git/existing chapter refs, exact sha-pinned provenance,
`RESTRICTED` independent disclosure, scope/request mixing denial, duplicated
candidate-source review warnings, tampered MAC, obvious credential blocking,
untrusted prompt text, and local-only no-write outcomes. No fixture has live
organization grants, production target signatures or a real AI call.

Run from `construction/`: `python -m unittest -q test_knowledge_update_handoff.py`.
All final native PowerShell7/15 Smoke, signer/revocation, cross-platform
OS/NFS, real delivery and final assisted end-to-end checks remain deferred.
