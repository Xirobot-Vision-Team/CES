# EC228 — synthetic development only

`construction/test_report_publish.py` uses the **real** EC192–EC200
ReportRender/ReportHistory fixture flow to create an actual private immutable
versioned report, then six distinct **ephemeral test-only Ed25519 keys**, a
host-like private local outbox and a fake in-memory Provider. It signs the
complete EC228 organization, destination, current revocation, exact Markdown
content review, independent publish grant, and challenged Provider capability
without any network, production credentials or report publication.

These tests exercise the code path for once-only reserve/probe/post, actual
Markdown hash and store provenance, independent expiry and target/content
binding, corrupt index/Markdown refusal, probe-time mutation, private host
outbox mode, opaque attempted-state output, create-only semantics and
fail-closed provider errors. All fake identity, review, revocation and
Provider claims are **synthetic assertions**, not actual PKI, privacy
certification, Provider publication, legal clearance or OS crash proof.

Final multi-environment tests and genuine human verification are intentionally
deferred under `construction/FINAL_ACCEPTANCE.md`.
