# EC215 development fixtures — synthetic only

The 51 local methods in `../test_issue_eligibility.py` exercise EC215 offline
eligibility classification using **actual EC214 request/result shape**.
`base()` invokes the existing EC214 implementation with its **real unchanged
EC211 three-GET control flow** against EC211's injected `FakeBatch` transport.
EC212 redacted projection remains in the original EC214 code. These are all
synthetic, untrusted provider and Finding assertions.

The `model_live_shaped()` helper **deliberately edits the synthetic receipt's
provenance fields to look like a fixed-provider read**. This is a test fixture
for EC215's result-gate branch only. It is **not evidence of a live provider
request, authenticated source, security, integrity, or actual Issue state**.
The verifier explicitly marks its own inability to authenticate serialized
EC214 receipts. Positive classification requires a separate Ed25519 review
receipt that acknowledges this limitation, exact repository/candidate selection
and the lack of duplicate absence proof. The deterministic Ed25519 seed in
the tests is PUBLIC SYNTHETIC DATA and MUST NEVER BE USED IN PRODUCTION.

Cases cover GH/GL, 1/2 selected Issues, stable local/global pins, case/path/
SHA/anchor tampering, synthetic provenance, no-match-hint review, suggested
candidate conflict, partial/unknown Issue observations, source/counter-evidence
review, privacy PUBLIC/PRIVATE+INTERNAL/CONFIDENTIAL/RESTRICTED, signed review
scope/freshness/signer binding, expiry, offline-only CLI/duplicate JSON keys,
JSON Schema request/review/result constraints, no Issue/Git/knowledge writes
and hard `eligibility != authorization` flags.

**NOT_RUN:** live GH/GL accounts, real private/hidden Issues, independently
verified organizational reviewer enrolment/role/revocation, actual EC177/178
HMAC Finding store and EC203 local Git target byte replay, real CI/Quality,
origin authentication of serialized EC214 results, PowerShell7/15 native Smoke,
Windows/macOS/Linux/NFS, E63–E66 and final assisted acceptance. B-001 OPEN.
