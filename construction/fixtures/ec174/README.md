# EC174 synthetic route/output fixtures — not live AI output

The 28 executable scenarios in [`../../test_ai_handoff_router.py`](../../test_ai_handoff_router.py)
construct independently authorized synthetic EC170 sources, a genuine EC171
in-memory lifecycle, an HMAC-sealed EC172 POSIX stage and an EC173 private
input. This avoids hard-coding fake RunIds, HMAC keys or source digests in
shareable fixtures.

1. `schema_only`: metadata-only `partial/2`, no callback, no source leaked into JSON response.
2. `dispatch`: a local in-memory callback accepts only the explicitly authorized source and returns a **synthetic** candidate with exact bound source hashes/RunId/epoch, one quote+line anchor and an unverified actor claim. **No network or model is used.**
3. Denials: unknown task, report/knowledge/finding tasks without an EC173 builder, missing approval, source-mode drift, invalid immutable input/stage, wrong run/handoff/event/revision/operation, expired observations.
4. Bad candidate: invented source hash/identity, forged quoted code, patch item substitution, quality upgrade, nonunique JSON keys, unregistered fields/status injection, oversized response, invalid evidence type.
5. Adversarial callback: source/permission mutation, simulated expiry, exception with secret-looking content; these prove only that local validator refuses and records **already-released** disclosure honestly.

Run (development-only): `cd construction && python -m unittest -q test_ai_handoff_router.py`.
PowerShell7, live Provider/actor credentials, true OS/network timeout, filesystem
races and final feature acceptance remain deliberately untested.
