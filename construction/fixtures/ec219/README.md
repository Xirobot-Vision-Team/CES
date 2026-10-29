# EC219 — fabricated UNKNOWN-create remote recheck fixtures

`construction/test_issue_unknown_recheck.py` builds fresh *synthetic* EC217
Ed25519 receipts, an EC218 local POSIX durable attempt entry, and fake GH/GL
list/detail/repository GET objects with a local fixed test clock. Known demo
Ed25519 key bytes, `TEST_TOKEN`, source titles, body and repo IDs are not
real issuer/permission/provider/account facts and must never be used live.

Scenarios cover original `POSSIBLY_SENT` / `POST_UNKNOWN`, missing/wrong grant,
replay/approval content tampering, real-table read-only probes, current
independent opt-ins and expired access, bounded list/detail, multiple/same-
title source-mismatch, private GitLab confidentiality, repo drift before/after,
private 404 uncertainty, timing bounds, no negative absence conclusion,
synthetic results never claiming live creation, and append-only local
observation conflict durability.

The actual official GitHub/GitLab API, real credential, organization issuer,
NFS/multi-host, original PowerShell, source data and final user-assisted
acceptance are NOT_RUN. No `POST` or existing Issue mutation is executed.
