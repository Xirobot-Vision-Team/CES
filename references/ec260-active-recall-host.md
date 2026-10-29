# EC260: active revocation watch on signed strict Git-custody sessions

This is an **independent optional operator host**, not an update automatically
applied to EC259, legacy EC257 or the original Router. Keep the whole CES
construction package present; do not run business project code on the host.

## Trusted nonroot Linux deployment (example shape only)

Prerequisites are EC252–259 original constraints: an operator-owned private
0700 policy/source/root tree with 0600 SHA-pinned TAR, approved exact local
Git object allowlist, custody receipt, two different EC186 HMAC keys and valid
unexpired signed approval/lease tickets; operator-pinned image and root-owned
Podman binary. Target host additionally needs actual delegated systemd cgroup
v2 and rootless Podman. No downgrade to naked host execution is allowed.

From `ces/` with Python 3.11+ (3.13 local development):

```bash
python3 -B construction/ec260_active_recall_host/serve.py probe \
  --policy /trusted/private/ec253-policy.json \
  --repo /trusted/private/approved-git \
  --allowlist /trusted/private/allowed-paths.json \
  --receipt /trusted/private/source.custody.json \
  --profile-id python.pytest
```

The command exits **2/partial** if the *operator-local source custody and
two tickets* are consistent; it does NOT create a socket, verify real OCI,
check runtime revocation, or produce a quality PASS. Failures exit 5/unavailable
with a bounded static reason.

```bash
python3 -B construction/ec260_active_recall_host/serve.py serve \
  --policy /trusted/private/ec253-policy.json \
  --repo /trusted/private/approved-git \
  --allowlist /trusted/private/allowed-paths.json \
  --receipt /trusted/private/source.custody.json \
  --profile-id python.pytest \
  --socket /trusted/private/socket/session.sock \
  --max-sessions 1 --accept-timeout 60
```

`serve` first attempts durable recovery of older sessions (even if new
source custody fails), then validates the original signed startup/source
policy before binding AF_UNIX. For every signed `begin`, it validates the
original EC253 UID/scope/lease/profile and EC259 Git custody **before**
worker fork, then checks again before `begin` ACK. While that session remains
connected, it rechecks at a **1-second nominal cadence independent of the
client**, and prior to returning any new frame. It also monitors a partial
JSON request: a client cannot disable checking by never ending a line.
Either successful `poll` or `stop_and_reap` uses the original EC254/187 wire.

If proof changes, new disclosure is withheld; the server replies unavailable
where possible, stops/reaps through EC253/255/256 and retains uncertain
ledger entries for later operator recovery. The session may already be
running during a source/trust revocation; the check cadence and exact cleanup
time are not a hard real-time guarantee. Only the original worker deadline
and verified cleanup semantics bound execution; a dead or wedged kernel/Podman
can still cause an explicit `unavailable`, never a PASS.

## EC187-compatible client for slow real-Git checks

For approved EC187 controllers using this opt-in host, prefer the new local
transport-only adapter. It delegates exact original signed `begin`/receipt
checks, leaves the session request and response wire untouched, and sets a
longer **bounded local socket read timeout** because repeatedly rebuilding
real Git contents can exceed the original EC254 client's 2-second limit.

```python
from ec260_active_recall_host.client import ActiveRecallBroker

controller_host = ActiveRecallBroker(
    "/trusted/private/socket/session.sock",
    expected_host_uid=1000,    # replace with the actual approved owner UID
    scope_id="approved-scope"   # replace with the approved signed scope
)
# Existing EC187 caller continues using controller_host.begin(...),
# Session.poll(...), and Session.stop_and_reap(...), unchanged.
```

The adapter does not extend signed deadlines, OCI execution, memory,
resource ceilings or trust grants. A slow/unavailable host can still time out,
and an unsuccessful read is not proof of safe cleanup; inspect the journal.

## Safety, cost and one-client-at-a-time behavior

- No `--no-watch`, unsafe mode or client path/profile selection. Use original
  EC259 `serve.py` only if intentionally choosing the old pre-begin-only
  behavior; do not mistake it for the active EC260 host.
- Each periodic custody check reconstructs Git object content and checks
  SHA/HMAC/private policy; large approved source manifests impose overhead.
  The nominal 1 second is a **cadence**, not a latency guarantee.
- The original service accepts one active session at a time, up to the
  operator's bounded `max-sessions`; it does not multiplex OCI sessions.
- If a client sends `stop_and_reap` after revocation, the host can have already
  rejected that frame and triggered cleanup itself. The only acceptable
  confirmation is the durable closed journal and proven container absence;
  don't infer cleanup from a socket error.
- Do not trust a forged tool hash/source SHA/receipt as remote provenance.
  The original signed `authorized_source_pin_sha256` is *not* derived from
  Git commit by this feature. Production remote Git origin, commit signer,
  source approval chain, enterprise CI and actor authorization remain separate
  trust requirements.

## Development and final operator acceptance

Developer smoke checks (real nonroot Linux UID; OCI and cgroup still mocked):
```bash
python3 -B construction/ec260_active_recall_host/test_monitor.py -q
python3 -B construction/ec260_active_recall_host/test_host.py -q
python3 -B construction/ec260_active_recall_host/test_client.py -q
```
Additional original EC254/257/259 regressions are recorded in the EC260 local
report. The user's later unified acceptance needs an actually provided trusted
rootless Podman host: start a real signed Git-pinned session, revoke the
allowlist/receipt/HMAC while never polling and while slowly sending a partial
request; independently inspect full cgroup-v2 kernel usage, full process-tree
kill, `final_meter` before reaping, OCI absence, ledger closure and reboot
recovery. Also run all original PowerShell7/15 Smoke, E63–E66, Provider/CI,
remote-origin/enterprise/source-pin, native Router, cross-OS and full business
workflows. Until then: **NOT_VERIFIED / NOT_STARTED**, never Quality PASS.
