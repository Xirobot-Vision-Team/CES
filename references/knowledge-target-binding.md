# EC203 — Knowledge target Git commit/SHA and independently signed delivery binding

**V5.13 / R203 / EC-203 — independent, bounded POSIX/Python local adapter.** This module is not wired into the R150 PowerShell CLI and does not implement EC204 impact computation. It performs real local Git object/commit/ref/blob reads and Ed25519 delivery-statement verification **only** when an independent host supplies the repository identity, directories, target ref, verification keys and scoped read policies.

## Trust boundary and inputs

`construction/knowledge_target_binding.py` exposes:

```python
from knowledge_target_binding import KnowledgeTargetBinding
from knowledge_boundary import canonical

# The host provisions these values, never copies them from a request payload.
reader = KnowledgeTargetBinding(
    repository_root='/absolute/host-controlled/repo',
    knowledge_root='/absolute/host-controlled/ces-namespace',
    repository_ref='cesrepo1:' + '<64 hex digits>',
    target_ref='refs/heads/main',
    trusted_ed25519_keys={'org-delivery-key-1': raw_32_byte_public_key},
)
pins = reader.binding_preview(request_json=canonical(ec202_request))
# Create a separate EC202 read policy (as documented in knowledge-bootstrap.md)
# AND an EC203 target-read policy from pins, with review by the host's authorizer.
result = reader.verify(
    request_json=canonical(ec202_request),
    bootstrap_read_policy_json=canonical(ec202_read_policy),
    target_read_policy_json=canonical(ec203_target_read_policy),
    delivery_statement_json=canonical(signed_delivery_statement),
    delivery_signature_base64=detached_ed25519_signature_base64,
)
```

`ec202_request` is the unmodified strict EC202 request with a `scope.target.revision` containing the **full** SHA-1 or SHA-256 commit OID. An arbitrary revision from a caller is **only a selector**. `repository_ref` is independently host pinned: a request for any other logical repository fails. The host-pinned `target_ref` accepts full `refs/heads/...` or `refs/remotes/...` paths (not `main`, SHA-only pseudo-refs or PR head aliases). A ref is mutable: matching a full object OID is only a **sampled** observation, not a guarantee of future ref stability.

The host's `trusted_ed25519_keys` maps identifiers to raw 32-byte public keys (not private keys). The module never loads signing keys from request fields, disk paths or the certificate. Provision, authorize and revoke keys in a real organization-owned trust service **outside** this bundle. A user-generated/self-signed statement is not independent delivery evidence unless the trusted host has deliberately authorized that signer to attest actual deliveries for this repository. Positive fixture tests use a temporary test-only key and prove functionality, not production authorization.

## Signed statement contract

Use [`knowledge-target-delivery-statement.v1.schema.json`](knowledge-target-delivery-statement.v1.schema.json). Sign the **exact canonical JSON bytes**, with the domain separator as an explicit prefix:

```python
payload = b'CES-EC203-DELIVERY-STATEMENT-v1\0' + canonical(statement).encode('ascii')
# signature_base64 = base64.b64encode(trusted_release_signer.sign(payload)).decode('ascii')
```

Example shape (illustrative digest placeholders **must be real values** and are not an authenticated receipt):

```json
{
  "schema": "ces.knowledge_target_delivery_statement.v1",
  "purpose": "knowledge_delivered_target_commit",
  "signer_key_id": "org-delivery-key-1",
  "repository_ref": "cesrepo1:<64 hex digits>",
  "knowledge_space_key": "architecture",
  "source_policy_revision": "policy-v1",
  "period_id": "oct-2026",
  "request_binding_sha256": "<64 hex digits from EC203 preview>",
  "scope_binding_sha256": "<64 hex digits from EC203 preview>",
  "target_ref": "refs/heads/main",
  "target_revision": {"algorithm": "sha1", "oid": "<40 hex commit OID>"},
  "delivered_at_utc": "2026-10-12T12:00:00Z",
  "knowledge_manifest_sha256": null
}
```

The signed document must match the **complete original EC202 request digest**, exact scope digest, repository identity, knowledge namespace/source policy/period, host target ref and full target OID. `delivered_at_utc` must lie within a finite `[start_utc, end_utc)` period. A signature without all bindings is not evidence. `knowledge_manifest_sha256` may pin one separately observed snapshot manifest; it never certifies semantic knowledge truth or that all chapters were selected.

## Independent authorization and policy

[`knowledge-target-read-policy.v1.schema.json`](knowledge-target-read-policy.v1.schema.json) requires exact `request_binding_sha256`, `scope_binding_sha256`, EC202 repository+knowledge root inode pins, Git directory inode pin, host target configuration digest, host verification-key registry digest, and **the exact EC202 read-policy SHA** via the domain `CES-EC202-READ-POLICY-v1`. Its own purpose is `knowledge_target_git_read_only` and it carries an explicit read receipt plus source-by-source grants, **not a cryptographic authorization certificate**.

- `permit_target_read`: required. `permit_delivery_signature_verification` controls examining the signed evidence.
- `permit_git_object_read`: must be true to consult Git. `permit_source_blob_compare` plus each `source_grants[].permit_git_blob_compare` authorizes selecting individual **repository** paths (not snapshot knowledge paths). Denied paths are not read from Git.
- EC202 must already authorize reading the exact repository paths. `permit_provenance_projection` on EC202 must be true for actual byte-SHA comparison; if absent, return `BOOTSTRAP_PROVENANCE_NOT_GRANTED` instead of guessing.
- `permit_knowledge_manifest_bind` additionally requires the original EC202 manifest permission, a real observed manifest SHA, a signature containing exactly that digest, and a valid sampled target. `SIGNED_MANIFEST_DIGEST_MATCH` means only that **a manifest digest was signed**, not that knowledge is complete/current.
- `permit_target_oid_projection` and `permit_source_digest_projection` independently limit output; defaults can be false. Never echo original source bytes or a detached signature. All write/publish permissions must be **false**; this adapter has no write path.

**Host responsibilities:** authenticate the requester; enforce organizational ACL and key authorization/revocation before minting the permission statements; protect the Git repository, `.git/config`, key registry and roots from untrusted mutation; decide whether a signed delivery event actually happened. A caller-controlled `permit_*`, receipt SHA or public key must never be treated as independent permission or authority.

## Actual Git verification and response interpretation

- Walk the configured repository and `.git` directory with nofollow handles; reject symlinked Git dir, worktree `commondir`, alternate object stores, grafts, shallow histories and invalid/unsafe roots. Use a host-chosen local Git executable, no shell/remote commands, scrub Git environment, disable replacement refs and lazy fetch, bound Git output sizes and command duration.
- Resolve the configured **full** target ref, verify Git's object format (`sha1` / `sha256`), read the exact commit object, independently recompute its Git object hash, and sample ref before/after. A branch-name match without an exact OID never succeeds. If the ref moves, or now references a different commit, `TARGET_DELIVERY_UNKNOWN` remains.
- For each authorized EC202 `repository` path, look up the regular-file Git blob (not symlink/submodule), independently recompute the Git blob's object hash and SHA-256 of the **actual** blob bytes, and compare that SHA-256 to EC202's actual read bytes. A working-tree difference gets `WORKTREE_DIFFERS_FROM_TARGET_BLOB`; missing/untracked path yields `PATH_NOT_IN_TARGET_TREE`; unverified local SHA still cannot qualify as delivered.
- A real Git commit/blob match **without a verified, exact, independently host-trusted Ed25519 delivery statement** is explicitly `LOCAL_GIT_BLOB_MATCH_DELIVERY_UNVERIFIED`; it is not DeliveredTarget evidence. Bad/unknown signer, wrong period, changed source request, mismatched target, absent object and moved ref all remain unknown.
- With a valid signed statement **and** actual verified commit, stable ref samples, and matching authorized bytes, the source is `SIGNED_DELIVERY_TARGET_BLOB_MATCH`. The summary flag `eligible_for_ec204_source_diff` requires at least one selected repository source and **all** selected repository sources matching. It is an **input eligibility signal only**, not an EC204 diff or verified architecture fact. Any EC202 coverage gaps remain copied in `bootstrap_coverage_gaps`, including unselected manifest entries and incomplete snapshots.

Every valid report is still `partial` / exit code `2`, `verified_delivered_facts=[]`, `current_architecture_state=UNKNOWN_NOT_SEMANTICALLY_VERIFIED`, and `no_write_actions_performed=true`. No inference from PR head/working tree, CI pass, AI text or a caller-supplied SHA to current architecture is allowed.

## Resources, limits and remaining validation

Three strict Draft2020-12 schemas: [policy](knowledge-target-read-policy.v1.schema.json), [signed statement](knowledge-target-delivery-statement.v1.schema.json), [result](knowledge-target-binding-result.v1.schema.json). The deterministic positive/negative local Git fixture is [`test_knowledge_target_binding.py`](../construction/test_knowledge_target_binding.py). Dependencies: POSIX filesystem and a trusted local Git executable; Python `cryptography` with Ed25519 support is needed to verify positive delivery attestations (if absent, fail closed). The EC202 original source budget remains 32 sources × 16 KiB each and ≤256 KiB combined, including 64 KiB manifest. EC203 caps commit contents at 128 KiB, individual Git blobs at 16 KiB, Ed25519 signer keys at 16 and Git stdout by command. It never performs a Git fetch, push, write, knowledge save or publication.

**Deferred to assisted acceptance:** real enterprise signer enrollment/authorization/revocation and delivery-event logs; actual repository/Provider Git ref ownership and trust; malicious concurrent filesystem changes/hardlink/NFS; Git local configuration and multi-user filesystem integrity; multiple platforms; original 15 native PowerShell Smoke; E63–E66; actual Git/CI/AI/knowledge provider integrations; end-to-end production acceptance. The original B-001 provenance gap is still open. EC204 impact, EC206 candidate isolation, EC208 save, and native PowerShell routing remain not implemented this round.
