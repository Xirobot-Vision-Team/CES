# EC164 synthetic-only content fixtures

`github.synthetic.patches.json` and `gitlab.synthetic.patches.json` contain fabricated PR/MR file rows; no real credentials, private source, repository ownership or live provider trace. They exercise the standalone patch-content gate with EC161 synthetic metadata/EC162 pin fixtures. Never treat a fixture's complete coverage or emitted synthetic patch as proof of live-provider authorization, cross-page atomicy, or delivery.

Tests also generate refusal cases locally for secrets, oversized content, binary files, missing snippets, provider-limited results, incomplete hunks, drift and pagination failure. No patches are written to disk by the implementation.
