# EC251: Linux operator-private `QualityShow/Query` host endpoint

**Bundle:** V5.61/R251/EC-251. This is a standalone, real local read-only entrypoint for the existing EC188 `QualityShow.query` code, not registration of a previously blocked Router Action. It cannot run tests or CI, verify source authorship, prove PASS, create Findings or write the analyzed repository. This is one user-directed post-250 EC; no candidate freeze has been approved.

## What actually runs

`construction/ec251_quality_host/broker.py` launches an AF_UNIX server on Linux, reads a kernel `SO_PEERCRED` UID for each accepted connection and matches that UID together with a local `scope_id` against a separately installed host policy. It opens a host-owned 0600 JSON evidence snapshot and raw cursor HMAC key, checks their exact SHA256 against the policy, and calls **the real existing** `construction/quality_show.py:QualityShow.query` to produce a bounded read-only projection. The client does not send evidence, source scopes, paths, UIDs, credential bytes, callback targets or permit flags.

The EC188 receipts are **caller/host-supplied historical claims**. Their shape and deterministic checksums are checked by EC188 but are not signatures or origin authentication. `partial/2` means an authorized, locally bounded *projection of claims* only; it is never a Quality PASS or independent CI/run/source proof.

## Host operator prerequisites

1. Deploy on a Linux host with Python3 and working `AF_UNIX` / `SO_PEERCRED`. The CES bundle remains read-only; host operator config/snapshot/key **must be outside `ces/` and outside the analyzed business repository**. The server will reject non-Linux hosts.
2. Obtain valid EC181-187 result objects through an independently authorized collection workflow, for **one exact EC188 source scope**. Treat every receipt as an unverified claim. Build a pinned, operator-owned snapshot; no arbitrary client-submitted receipts are accepted. Do not combine WorkingTree and remote target receipts or mix repository/commit/proposal scope.
3. Put `policy.json`, `snapshot.json` and `cursor.key` in an owner-only **0700** directory. All three must be single-link 0600 regular files, no symlinks; ancestors must not be insecurely writable. `cursor.key` must hold 32 to 128 secret random **raw bytes**; never paste its value into a policy, command or log. Provision these files only from trusted host/operator context. For multiple source scopes, install separately configured host instances.
4. Compute `sha256sum` of the **exact snapshot bytes** and **exact key bytes**, store these digests in the private policy, and verify the precise source scope separately. SHA256 only pins bytes; it cannot independently certify real providers, roles, CI artifacts, Git objects or content truth. Restart/recheck host policy on every deployment change.
5. Provision a separate owner-controlled socket directory; service binds a new socket (no unlinking a pre-existing socket) with permissions at most 0660. Clients must have actual OS path/socket access and a policy grant for their exact kernel UID and `scope_id`. A UID alone does not authenticate an enterprise actor or a specific binary. Credentials/organizational revocation remain a separate operator responsibility.

## Operator-owned snapshot JSON

This is the shape, not a complete live sample. Replace the placeholders with an exact authorized EC188 `source_scope`, original EC181-187 results, and their capture times. One immutable snapshot should be treated as a complete **selected input batch** but is not guaranteed to contain all existing evidence.

```json
{
  "schema": "ces.ec251.quality_evidence_snapshot.v1",
  "source_scope": {
    "source_mode": "WorkingTree",
    "root_pin_sha256": "<real verified 64-character lowercase SHA256>"
  },
  "evidence": [
    {
      "kind": "config",
      "source_scope": {
        "source_mode": "WorkingTree",
        "root_pin_sha256": "<the exact same root pin>"
      },
      "recorded_at_utc": "2026-10-24T12:00:00Z",
      "result": {"<the entire genuine EC181 result object>": "..."}
    }
  ]
}
```

Snapshot size: at most 2 MiB, up to 96 receipts; each EC188 individual receipt has an independent 256 KiB bound. Allowed `kind` values: `config`, `ci_metadata`, `sha_binding`, `ci_evidence`, `observation`, `run_preflight`, `run_session`. The original EC188 schema/receipt validator decides which kinds match WorkingTree vs DeliveredTarget/ProposedPR and rejects malformed or contradictory claims. A zero-record snapshot is permitted and is **not an absence-of-defects certificate**.

## Private host policy

The server accepts only these exact fields. Set absolute host-private paths and real trusted SHA256 digests; a request may not override any of them. `allowed_kinds` must be nonempty, sorted, unique, and drawn from the list above.

```json
{
  "schema": "ces.ec251.quality_host_policy.v1",
  "source_scope": {
    "source_mode": "WorkingTree",
    "root_pin_sha256": "<exact real 64-character lowercase SHA256>"
  },
  "snapshot_path": "/operator/private/quality/snapshot.json",
  "expected_snapshot_sha256": "<sha256 of exact snapshot bytes>",
  "cursor_key_path": "/operator/private/quality/cursor.key",
  "expected_cursor_key_sha256": "<sha256 of secret raw key bytes>",
  "grants": [{
    "uid": 1001,
    "scope_id": "approved_quality_1",
    "allowed_kinds": ["config", "run_preflight"],
    "allow_numeric_metrics": false,
    "acknowledge_historical_proposal": false
  }]
}
```

`uid` is checked by the **server** using the peer's kernel credentials, never read from a client JSON. Matching `scope_id` is a lookup handle, not an access token. Numerical test-count or coverage **provider claims** require `allow_numeric_metrics:true` plus a request opt-in; this does not verify the measurements. ProposedPR requires explicit `acknowledge_historical_proposal:true` and always remains historical, not delivered/current.

## Client request and commands

```json
{
  "schema": "ces.ec251.quality_host_query.v1",
  "scope_id": "approved_quality_1",
  "filters": {},
  "page_size": 10,
  "cursor": null,
  "include_numeric_metrics": false
}
```

`filters` is null or an EC188 filter object containing `kinds`, `classification`, `from_utc`, `until_utc`. With no explicit `kinds`, the host automatically limits the query to the grant's allowed kinds. An attempt to explicitly query any ungranted kind returns `permission_denied/3`; all evidence and source roots remain host-controlled. Supply `next_cursor` from the result in the **next authorized client request** to page; a cursor is not permission, and a change to snapshot, source/filter/key/authorization invalidates it.

```sh
# Server: separate operator OS account, private absolute paths, start one-request instance
python3 -I -B construction/ec251_quality_host/broker.py serve \
  --policy /operator/private/quality/policy.json \
  --socket /operator/private/quality-socket/quality.sock \
  --max-requests 1 --accept-timeout 60

# Client: actual permitted OS user; request.json is a local client file
python3 -I -B construction/ec251_quality_host/broker.py query \
  --socket /operator/private/quality-socket/quality.sock \
  --request-file /client/private/quality-request.json \
  --expect-host-uid 1000
```

The client verifies the socket peer UID **before sending** the request; the server verifies the client kernel UID **before authorization**. A valid QualityShow result is `partial/2`; permission refusal `permission_denied/3`, malformed input `invalid_input/4`, private host/snapshot/key/evidence unavailable `unavailable/5`. `partial` exits the command with process exit code 2 by design. The server serially handles up to 100 requests/process; request 8 KiB, response 128 KiB, each connection 5-second I/O timeout, bounded startup accept timeout. No general Router bridge and no network connector is implemented.

## Consistency and security limits

- Every query freshly opens the private policy, evidence snapshot and HMAC key with `O_NOFOLLOW`, directory-fd traversal and owner/mode/link checks. Before returning a projected page, the server re-reads and matches their bytes/pins; an observed revoke or change drops the output. Owner-level malicious ABA swaps, compromised host, interrupted access revocation and multi-host synchronization are **not** solved.
- The policy grants exact UID/scope/evidence kind and controls optional numeric disclosure. Per-record EC188 callbacks bind source scope, captured receipt digest and record digest, including a final source reauthorization. No raw stdout/source lines should be projected by the inherited EC188 allowlisted view; actual production data still needs independent privacy review.
- This is only a Linux local host entrypoint for a fixed known domain. It does **not** modify original `ces.ps1`, 15 PowerShell Smoke files, EC242 112 schemas, EC243 74 fixed Router routes or any of the 11 original `HOST_REQUIRED` refusals. There is still no live QualityRun broker, trusted provider/CI/actor authority, external Issue/Delivery/Report/DocsOnly write, real Cycle execution, candidate freeze or final acceptance.
- Local functional evidence: 18/18 focused EC251 tests, including cross-process CLI AF_UNIX, real EC188 projection, cursor/snapshot change, UID revoke and unauthorized metric/kind disclosure. These use **synthetic EC181-187 receipt objects**; the upstream providers/CI/tests/enterprise/Windows/macOS/NFS/E63-E66/PowerShell7/native 15 Smoke and final operator-assisted acceptance were **NOT_RUN**. Existing B001 source gap stays **OPEN**.

Run focused local development cases with `python3 -I -B construction/ec251_quality_host/test_broker.py`. See [EC251](../EC-251.md), [EC251 scope](../construction/EC251_SCOPE.json), [progress](../construction/LEGACY_PROJECT_STATE.json) and [final acceptance](../construction/FINAL_ACCEPTANCE.md).
