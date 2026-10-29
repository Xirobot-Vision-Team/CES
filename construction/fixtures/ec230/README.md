# EC230 fixture provenance and boundaries

`construction/test_publication_receipts.py` creates its fixtures in system
owner-private temporary directories at test runtime; there are no static real
provider responses, private company repositories, enterprise keys or actual
organizational read/cleanup credentials in the ZIP.

- `test_docs_only_publish.DocsOnlyGitCases` builds a **real disposable SHA-1
  local Git repository**, an isolated EC229 linked worktree and one local
  bare test ref with ephemeral Ed25519 keypairs, then exercises EC230 readback
  and tightly scoped worktree deletion, conflict, unknown and no-retry rules.
- `test_report_publish.ReportPublishCases` uses **real EC199/EC200 local
  immutable report-store fixtures** and a mocked EC228 private report POST;
  the new EC230 `FakeGET` signs a nonce-bound, create-only, private record
  assertion with an ephemeral Ed25519 key. It sends **no HTTP request**.
- EC230's fresh read and custodian grants are freshly generated **synthetic**
  independent Ed25519 signatures, not genuine human/legal approvals.
- Live HTTPS read-only Provider contract, credentials, ACL, actual publication,
  branch policy, crash-durability/same-UID/NFS/races, native PowerShell/Smoke,
  E63-E66 and final enterprise user-assisted acceptance remain **NOT_RUN**.
