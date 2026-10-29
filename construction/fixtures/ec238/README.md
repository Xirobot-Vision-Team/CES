# EC238 — local scenario boundaries and inputs

`construction/test_cycle_cross_action.py` produces **fresh** private EC171/172
lifecycle/HMAC stage data, original EC231 RunId records and immutable owner
receipts inside isolated temporary directories. It does not re-use pretend IDs
as historical evidence. The six JSON payloads are deliberately **synthetic
records labelled with existing producer schema names**; their role is to
challenge the cross-action context and exact-byte ownership controls, not to
prove the six underlying production workflows ran or were source-authenticated.

Coverage includes: genuine cycle/stage linking, distinct real RunIds,
multiple-family exact-byte replay, foreign run/handoff/context in nested JSON,
wrong step/family, duplicate or re-used blob, unknown/unlinked IDs, strict
JSON, 0700/0600 private receipts, symlink/tamper, expiry/revision replay,
batch atomic error visibility and CLI exit status 2/3/5 and strict Draft2020-12 result/snapshot schemas.

External acceptance stays NOT_RUN: real enterprise origin and signer, actual
production records from six workflows, permission grants, manual approval,
PowerShell7/15 native Smoke, OS crash/NFS/concurrent multi-process race,
Windows/macOS, E63–E66 and end-to-end execution.
