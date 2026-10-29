# EC241 local/synthetic validation fixture notes

The request examples in `references/unified-action-routing.md` are **synthetic**.
Never treat local generated Run metadata, pre-supplied CI/Issue facts, boolean
`authorize_*` fields, trusted event IDs, or a mocked provider response as an
enterprise approval, original producer attestation, true git review, signed
credential or actual business write.

The `construction/test_unified_action_router.py` focus checks the real
`construction/unified_action_router.py` dispatch, real EC231 persisted Cycle
Run Create+Inspect and EC237 Summary, pure calendar evaluation, Issue
eligibility computation, missing/unknown input and fail-closed host-gated
write and schema paths. It does not test a live Issue POST or DeliverySend.

Native PowerShell 7 and R150 original 15 Smoke require a compatible external
Windows/Linux host; include them in **final** user-assisted acceptance.
