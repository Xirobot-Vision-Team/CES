# EC177 synthetic, non-production Finding Schema fixture cases

Entry: `python3 -m unittest -q test_finding_schema` from `ces/construction/` (POSIX Python environment with same dependencies as EC172–176).

Real fixture creators build EC170 selected source + EC171 READY Run/Handoff + EC172 staged seal + EC173 sealed input + EC174 dispatched synthetic candidate + real EC175 validation. Optionally reuse real EC176 no-clobber private HMAC metadata store.

Coverage: default-only hashes/no code/paths/notes; immutable source+candidate-specific IDs; split severity vs confidence; actual test truth never asserted; HMAC reviewer confirm/reject/inconclusive vs unsigned; strict re-validation of prior unkeyed receipt and stale source; exact source-line counter-evidence; independent scoped text disclosure; genuine EC176 saved HMAC association and tamper/expiry/grant denial; historical ProposedPR guarded and still not-current; no source/business writes, idempotent in-memory projection, empty findings valid.

Expected local result this round: **25/25 passed**; JSON Schema 2020-12 validated structurally against both plain and private-save-link positive projections. Those results are local developer synthetic observations only, not CI/Git/Provider/human/native PowerShell/15 Smoke or final acceptance.
