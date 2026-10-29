# EC188 development fixtures (no live systems)

These tests are in [`../../test_quality_show.py`](../../test_quality_show.py) (55 unittest cases); a separate permanent JSON fixture ledger is intentionally **not** bundled. The tests create receipts in memory using the actual EC181-186 producer checksum algorithms plus non-attestable EC187 output. No provider network, analyzed repository code execution or persistent CES/source write occurs.

Coverage: exact WorkingTree/remote/ProposedPR source pin and ack, separate per-scope and per-receipt grant checks with final revocation, all seven producer kinds, conservative CI `success`/test `pass`/host exit0, run interruption and stdout truncation, metrics opt-in, sensitive text redaction, filter/no-match semantics, stable three-page sort, HMAC cursor tamper/expiry/rotation/cross-scope/revision invalidation, forged proof/modified checksum, resource bounds, original producer integration and Draft2020-12 result acceptance for success/refusal.

The *real* source implementations run only with **offline fake HTTPS responses and temporary POSIX roots**: EC181 selected local config/root, EC182 GH metadata, EC183 GH field-SHA binding, EC184 parsed provider job log, EC185 local and remote observation, EC186 signed test-only safety preflight and EC187 fake-broker reported exit0/pre-broker cancellation. These are not live GitHub/GitLab or production runner tests, and their reported `pass` is not CES's proven quality success.

Command: `cd ces/construction && python -m unittest test_quality_show -q`.

To accept the future native end-to-end product, separately arrange PowerShell7+original15 Smoke, real pinned source/CI/runner rights, authentic provider execution and auth, Windows/macOS adversarial tests, E63-E66 load/perf and final user-assisted acceptance. The current interface is intentionally **standalone Python**, not the native PowerShell command.
