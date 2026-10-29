# EC201 focused synthetic knowledge-boundary development fixtures

Run in the `construction/` directory: `python -m unittest -q test_knowledge_boundary.py`.

The unit tests create only in-memory canonical request + independent policy
JSON. They cover (1) an empty unknown knowledge scope, (2) exact caller-byte
SHA matching without delivery promotion, (3) different/null declared target
revisions, (4) ProposedPR same-OID candidate, (5) WorkingTree, AI, CI and
unknown isolation, (6) shared claim aggregation and contradictory target
content, (7) exact UTC half-open/unknown period, (8) read, byte-digest and
provenance permissions and per-observation bindings, (9) write-intent denials,
(10) digest mismatch, malformed base64, duplicate/noncanonical JSON, source
field escalation, (11) strict request, policy and output JSON Schemas.

They do NOT verify a real Git target commit, accepted delivery, CI job,
identity/permission issuer, original PowerShell CLI, real knowledge store,
external Provider, multi-OS behavior or end-to-end acceptance. Do not use
these fixtures as evidence that any statement is actual current architecture.
