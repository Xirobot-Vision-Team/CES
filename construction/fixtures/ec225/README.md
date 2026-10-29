# EC225 synthetic development fixtures — never a real recipient

`construction/test_delivery_send.py` provisions **ephemeral test-only** EC223
three-key directory roots, EC224 three-key organization/approver roots, EC225
independent side-effect signer and provider capability signer. It uses a real
disposable EC200 private ReportHistory -> EC221 preview -> EC222 exact source
review -> EC223 directory identity -> EC224 precise local authorization chain
and a separately signed EC225 sandbox-only test-send grant. The synthetic
provider is an in-process `SandboxFakePort`; it DOES NOT open any network
socket or deliver any message. The endpoint uses the reserved `.invalid` TLD.

An isolated POSIX 0700 temporary outbox is created to show atomic grant-keyed
first-writer-wins claim, fsync state files and no-replay after timeout or
uncertainty. No raw source, token or recipient identity is stored in the
outbox or response. All tests are development checks, not provider/integration,
crash/NFS/disk durability, live revocation or final joint acceptance.

For the real HTTPS wire protocol, host binding and safe default behavior see
[`references/delivery-send.md`](../../../references/delivery-send.md). The
real protected host outbox and real Ed25519 signing trust roots must never be
packaged in the CES ZIP.
