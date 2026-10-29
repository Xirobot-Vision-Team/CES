# EC190 developer fixtures (NOT production evidence)

No repository/Git/CI snapshot or secret is stored here. The 34 in-memory
examples are built by `construction/test_quality_mode_flow.py` from the original
EC188 synthetic original-producer receipt factory, the immutable EC158
`ci-example.json` **schema illustration**, and locally constructed source
relation/revocation JSON bytes. These are synthetic and never obtained from a
live provider, real signed host, CodeSave, or trusted CI runner.

Real SHA256 is calculated on the synthetic bytes so the tests exercise the
production digest checks, per-mode scope binding, proof field binding,
CodeInsight v1 inspector, multiple EC188 HMAC cursor pages, re-authorizations,
record replacement/revocation, contradicting events and temporal ordering.
`authorize_*` / `verify_*` callbacks are accepting fakes, never acceptable
production source authorities. The parser MUST continue to label positive
results `partial/2` and all git/currentness/test/defect proof flags false.

Run `cd ces/construction && python -m unittest -q test_quality_mode_flow`.
The native PowerShell and full-source real-system acceptance are deferred.
