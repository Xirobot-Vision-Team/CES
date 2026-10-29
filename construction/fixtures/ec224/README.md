# EC224 Synthetic Fixture — NOT a real signed organization approval

Code: `construction/test_delivery_authorization.py`. It creates **ephemeral**
Ed25519 private keys per test and uses the genuine disposable EC200 private
Report store through actual EC221, EC222 and EC223 APIs before invoking the
new EC224 authorizer. All identity, operator, project and channel names are
synthetic, with fixed deterministic **test-only** time. No persistent private
keys, live organization auth, Git, Provider, contact lookup, sending, publish,
PowerShell CLI or real-world privacy release.

Success requires distinct pinned organization entitlement, grant, revocation
and EC223 identity roots, org-signed exact approver scope, signed eligible
pre-grant revocation checkpoint, separate approver-signed exact payload,
recipient, channel, audience, project, source versions, policy and time.
Swapping even a newer **ACTIVE** checkpoint requires a fresh grant signature;
revoked/missing/expired permission and payload changes fail closed.

From `ces/construction/`, with `cryptography` and `jsonschema` installed:

`python -m unittest test_delivery_authorization -v`

Targeted checks only; actual enterprise provisioning, keys, compromised clock,
revocation online propagation, case-sensitive paths, source concurrency,
Windows/macOS/Linux, original PowerShell smoke, Provider and final acceptance
remain NOT_RUN.
